// Native VM and vCPU objects — the authoritative virtualization objects.
//
// The KVM compatibility layer (core.virt.kvm) translates Linux ioctls into
// operations on these objects; it never bypasses them.  A VMM that wants
// virtualization without the Linux ABI would use these directly.
//
// Design points:
//   - Objects live in the central object table as ObjType.Vm / ObjType.Vcpu
//     (impl points at the records below, which live in static pools —
//     address-stable, so the object mirror never orphans).
//   - Stale-handle protection: every VM/vCPU carries a generation, mirrored
//     in ObjHeader.version_.  Handles are (objId, generation) pairs; a lookup
//     fails if the slot was freed and reused (generation mismatch) or reused
//     for another type (type mismatch).  Generations never reuse 0.
//   - Lifecycle: Empty -> Active -> Dying -> Empty.  Teardown is idempotent
//     and reclaims: EPT tables, pinned guest pages, the untyped-memory
//     charge, vCPU records, and finally the object-table slot.
//   - Ceilings are hard and fail-closed: bounded VMs, vCPUs/VM, memslots,
//     and guest pages per VM / system-wide.
//   - Guest memory: KVM_SET_USER_MEMORY_REGION validates the slot, pre-faults
//     each userspace page through the REAL page-fault path
//     (core.addrspace.handlePageFault), translates VA->phys, and PINS each
//     page (physPageRefInc) so the VMM cannot free/reuse the backing while
//     the EPT points at it.  The untyped budget of the creating task is
//     charged per page and released on teardown — guest RAM is never ambient.
//   - The EPT is the source of truth for pinned pages: unpin walks the EPT
//     (GPA->HPA), never re-translates the userspace VA (which the VMM could
//     have remapped concurrently).  See core.virt.ept.
//   - EPT is built eagerly at region registration (fail fast) and updated on
//     removal.
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.vm;

import core.objmgr : ObjType, ObjHeader, objAlloc, objGet, objRelease;
import core.io : klog, klog_hex;
import core.addrspace : userVirtToPhys, userPageMapped, handlePageFault;
import core.exports : g_current_task_id, phys_to_virt;
import core.task : g_tasks, MAX_TASKS;
import core.untyped : untypedRetype, untypedRelease;
import memory.mm : alloc_phys_page, free_phys_page, physPageRefInc, physPageRefDec;
import core.virt.ept;
import core.virt.kvmabi : KVM_MEM_READONLY;

extern (C) @nogc nothrow:

// ---------------------------------------------------------------------------
// Ceilings (hard, fail-closed)
// ---------------------------------------------------------------------------
enum uint  VIRT_MAX_VMS          = 16;
enum uint  VIRT_MAX_VCPUS_PER_VM = 64;
enum uint  VIRT_MAX_MEMSLOTS     = 32;    // also reported via KVM_CAP_NR_MEMSLOTS
enum ulong VIRT_MAX_PAGES_PER_VM = 262144;  // 1 GiB per VM
enum ulong VIRT_MAX_PAGES_TOTAL  = 1048576; // 4 GiB system-wide for guests

// ---------------------------------------------------------------------------
// Lifecycle states
// ---------------------------------------------------------------------------
enum VmState : ubyte {
    Empty  = 0,  // free pool slot
    Active = 1,  // created; accepts ioctls
    Dying  = 2,  // teardown in progress; new ioctls rejected
}

enum VcpuState : ubyte {
    Empty   = 0,
    Created = 1,  // KVM_CREATE_VCPU done; no state programmed yet
    Runnable= 2,  // state programmed; KVM_RUN may enter
    Running = 3,  // currently inside KVM_RUN (transient)
    Exited  = 4,  // guest exited (HLT/SHUTDOWN); KVM_RUN re-entry rejected
    Dead    = 5,  // torn down
}

// ---------------------------------------------------------------------------
// Records (static pools — address-stable for the object-table mirror)
// ---------------------------------------------------------------------------
struct VmMemSlot {
    bool  used;
    uint  slotId;
    uint  flags;        // 0 or KVM_MEM_READONLY
    ulong guestPhys;    // guest-physical base (page-aligned)
    ulong pages;        // length in pages
    ulong userBase;     // userspace VA base in the creator task (informational)
}

struct Vcpu {
    VcpuState state;
    uint  objId;        // ObjType.Vcpu mirror (0 = none)
    uint  gen;          // generation (mirrors ObjHeader.version_)
    uint  index;        // vCPU index within the VM
    uint  vmObj;        // parent VM's ObjType.Vm id (stale-checked on use)
    uint  vmGen;        // parent VM's generation
    uint  mpState;      // KVM mp_state
    uint  fdRefs;       // open fd views (dup/fork bump; 0 => release)
    ulong runPhys;      // host-phys of the shared kvm_run page (0 = none)
    ulong cachePhys;    // host-phys of the KVM state-cache page (0 = not set yet)
    ulong cpuidPhys;    // host-phys of the cached CPUID2 page (0 = not set yet)
    bool  lapicSet;     // KVM_SET_LAPIC seen (split-irqchip bookkeeping)
    ulong[18] regs;     // KvmRegs order: rax..rflags (cached SET_REGS)
    bool  regsSet;
    bool  sregsSet;
    // (sregs/fpu/msr/cpuid blobs live in the KVM layer's per-vCPU cache;
    //  the native object keeps only scheduling-relevant state.)
}

struct Vm {
    VmState state;
    uint  objId;        // ObjType.Vm id
    uint  gen;          // generation (mirrors ObjHeader.version_)
    int   creatorTid;
    uint  fdRefs;       // open fd views + live vCPUs (0 => release)
    uint  untypedObjId; // budget charged for guest pages (0 = none)
    ulong pagesCharged; // pages currently charged
    VmMemSlot[VIRT_MAX_MEMSLOTS] slots;
    Vcpu[VIRT_MAX_VCPUS_PER_VM] vcpus;
    uint  vcpuCount;
    Ept   ept;          // EPT state (pml4Phys 0 = not built)
    ulong tssAddr;      // KVM_SET_TSS_ADDR value (recorded)
    ulong identityMapAddr; // KVM_SET_IDENTITY_MAP_ADDR value
    bool  splitIrqchip; // KVM_ENABLE_CAP(SPLIT_IRQCHIP) seen
    uint  gsiRoutes;    // KVM_SET_GSI_ROUTING entry count (accounting)
    bool  memLock;      // region registration/teardown serialization
}

__gshared Vm[VIRT_MAX_VMS] g_vmPool;
__gshared uint g_vmGen = 0;        // VM generations; 0 never used
__gshared uint g_vcpuGen = 0;      // vCPU generations; 0 never used
__gshared ulong g_virtPagesTotal = 0; // system-wide guest pages pinned

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
private uint nextVmGen() {
    if (++g_vmGen == 0) g_vmGen = 1; // skip 0 on wrap
    return g_vmGen;
}

private uint nextVcpuGen() {
    if (++g_vcpuGen == 0) g_vcpuGen = 1;
    return g_vcpuGen;
}

// Serialize region registration/removal/teardown per VM.  The syscall layer
// is per-task serial, but two threads of the VMM share the VM.
private bool vmLockMem(Vm* vm) {
    if (vm.memLock) return false;
    vm.memLock = true;
    return true;
}

private void vmUnlockMem(Vm* vm) { vm.memLock = false; }

// ---------------------------------------------------------------------------
// VM lifecycle
// ---------------------------------------------------------------------------

// Allocate a native VM object.  Returns the object id, or 0 on exhaustion.
// The VM starts Active.
public uint vmAlloc() {
    int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return 0;

    Vm* vm = null;
    foreach (ref s; g_vmPool) {
        if (s.state == VmState.Empty) { vm = &s; break; }
    }
    if (vm is null) {
        klog("[virt] vmAlloc: VM ceiling reached\n");
        return 0;
    }

    *vm = Vm.init;
    vm.state = VmState.Active;
    vm.creatorTid = tid;
    vm.fdRefs = 1; // the creating fd's view
    vm.untypedObjId = g_tasks[tid].untypedObjId;
    vm.gen = nextVmGen();

    uint id = objAlloc(ObjType.Vm, cast(void*)vm);
    if (id == 0) {
        vm.state = VmState.Empty;
        return 0;
    }
    auto h = objGet(id);
    h.version_ = vm.gen; // mirror generation for stale-handle checks
    vm.objId = id;
    eptInit(&vm.ept);
    return id;
}

// Validated lookup: (objId, generation) -> live Vm, or null if stale.
// This is THE stale-handle gate — every KVM fd ioctl goes through it.
public Vm* vmCheck(uint objId, uint gen) {
    if (gen == 0) return null;
    auto h = objGet(objId);
    if (h is null || h.type != ObjType.Vm) return null;
    if (h.version_ != gen) return null; // slot reused: stale handle
    Vm* vm = cast(Vm*)h.impl;
    if (vm is null || vm.objId != objId || vm.gen != gen) return null;
    if (vm.state != VmState.Active) return null;
    return vm;
}

// Look up a vCPU by (vmObj, vmGen, index) with full stale checks.
public Vcpu* vcpuCheck(uint vmObj, uint vmGen, uint index) {
    Vm* vm = vmCheck(vmObj, vmGen);
    if (vm is null) return null;
    if (index >= VIRT_MAX_VCPUS_PER_VM) return null;
    Vcpu* vc = &vm.vcpus[index];
    if (vc.state == VcpuState.Empty || vc.state == VcpuState.Dead) return null;
    if (vc.objId != 0) {
        auto h = objGet(vc.objId);
        if (h is null || h.type != ObjType.Vcpu) return null;
        if (h.version_ != vc.gen) return null;
    }
    return vc;
}

// Look up a vCPU directly by its own (objId, generation) — the handle the
// vCPU fd carries.  The parent VM is resolved separately via vc.vmObj/vmGen.
public Vcpu* vcpuCheckObj(uint objId, uint gen) {
    if (gen == 0) return null;
    auto h = objGet(objId);
    if (h is null || h.type != ObjType.Vcpu) return null;
    if (h.version_ != gen) return null; // slot reused: stale handle
    Vcpu* vc = cast(Vcpu*)h.impl;
    if (vc is null || vc.objId != objId || vc.gen != gen) return null;
    if (vc.state == VcpuState.Empty || vc.state == VcpuState.Dead) return null;
    return vc;
}

// Create a vCPU on a live VM.  Returns the vCPU index, or -1 on failure.
public int vmCreateVcpu(Vm* vm) {
    if (vm is null || vm.state != VmState.Active) return -1;
    if (vm.vcpuCount >= VIRT_MAX_VCPUS_PER_VM) return -1;
    foreach (i; 0 .. VIRT_MAX_VCPUS_PER_VM) {
        if (vm.vcpus[i].state != VcpuState.Empty) continue;
        Vcpu* vc = &vm.vcpus[i];
        *vc = Vcpu.init;
        vc.state = VcpuState.Created;
        vc.index = i;
        vc.gen = nextVcpuGen();
        vc.mpState = 0; // KVM_MP_STATE_RUNNABLE
        vc.fdRefs = 1;  // the creating fd's view
        vc.vmObj = vm.objId;
        vc.vmGen = vm.gen;
        uint id = objAlloc(ObjType.Vcpu, cast(void*)vc);
        if (id == 0) { vc.state = VcpuState.Empty; return -1; }
        auto h = objGet(id);
        h.version_ = vc.gen;
        vc.objId = id;
        // Shared kvm_run page: one host page, zeroed, owned by the vCPU.
        ulong rp = alloc_phys_page();
        if (rp == 0) {
            objRelease(id);
            vc.state = VcpuState.Empty;
            vc.objId = 0;
            return -1;
        }
        auto runp = cast(ubyte*)phys_to_virt(rp);
        foreach (j; 0 .. 4096) runp[j] = 0;
        vc.runPhys = rp;
        ++vm.fdRefs; // the vCPU pins its parent VM (Linux: VM outlives vCPU fds)
        ++vm.vcpuCount;
        return cast(int)i;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Guest memory registration
// ---------------------------------------------------------------------------

// Unpin/unmap every page the EPT maps for [guestPhys, guestPhys+pages*4K).
// The EPT is the source of truth — no userspace VA re-translation.
private void vmUnpinRange(Vm* vm, ulong guestPhys, ulong pages) {
    for (ulong i = 0; i < pages; ++i) {
        ulong gpa = guestPhys + (i << 12);
        ulong hpa = eptLookup(&vm.ept, gpa);
        eptUnmap(&vm.ept, gpa);
        if (hpa != 0) physPageRefDec(hpa);
    }
}

// Validate + register a guest-physical -> userspace memory slot.
// Pre-faults each userspace page through the real fault path, translates
// VA->phys, pins each page, charges the creator's untyped budget, and maps
// the range into the VM's EPT.  Returns 0 or a negative errno.
public long vmSetMemoryRegion(Vm* vm, uint slotId, uint flags,
                              ulong guestPhys, ulong memSize, ulong userAddr) {
    if (vm is null || vm.state != VmState.Active) return -9;  // EBADF
    if (slotId >= VIRT_MAX_MEMSLOTS) return -22;              // EINVAL
    if ((flags & ~KVM_MEM_READONLY) != 0) return -22;
    if ((guestPhys & 0xFFF) != 0 || (userAddr & 0xFFF) != 0) return -22;
    if (!vmLockMem(vm)) return -16; // EBUSY: concurrent region op

    long rc = -22;
    ulong pages = 0; // hoisted above all goto-fail checks (D forbids skipping it)
    // Removal: size 0 deletes the slot.
    if (memSize == 0) {
        rc = vmRemoveMemoryRegionLocked(vm, slotId);
        vmUnlockMem(vm);
        return rc;
    }
    if ((memSize & 0xFFF) != 0) goto fail;
    if ((memSize >> 12) == 0) goto fail;
    if (guestPhys + memSize < guestPhys) goto fail; // overflow
    if (userAddr + memSize < userAddr) goto fail;
    pages = memSize >> 12;
    if (pages > VIRT_MAX_PAGES_PER_VM) { rc = -12; goto fail; } // ENOMEM
    if (g_virtPagesTotal + pages > VIRT_MAX_PAGES_TOTAL) { rc = -12; goto fail; }

    // Overlap check against live slots (guest-physical).
    {
        ulong gEnd = guestPhys + memSize;
        foreach (ref s; vm.slots) {
            if (!s.used || s.slotId == slotId) continue;
            ulong sEnd = s.guestPhys + (s.pages << 12);
            if (guestPhys < sEnd && s.guestPhys < gEnd) goto fail; // EEXIST->EINVAL
        }
    }

    // Charge the untyped budget BEFORE touching pages (fail fast, no
    // partial pin on budget exhaustion).
    if (vm.untypedObjId != 0 && !untypedRetype(vm.untypedObjId, pages)) {
        klog("[virt] memRegion: untyped budget exhausted\n");
        rc = -12;
        goto fail;
    }

    // Same-slot re-registration: replace semantics (remove first).
    if (vm.slots[slotId].used) {
        rc = vmRemoveMemoryRegionLocked(vm, slotId);
        if (rc != 0) {
            if (vm.untypedObjId != 0) untypedRelease(vm.untypedObjId, pages);
            goto fail;
        }
    }

    // Pre-fault + translate + pin + EPT-map, page by page.  Any failure
    // unwinds via the EPT (source of truth for what got pinned).
    {
        int tid = vm.creatorTid;
        bool writable = (flags & KVM_MEM_READONLY) == 0;
        uint prot = 1 | 4; // R|X
        if (writable) prot |= 2; // W
        ulong done = 0;
        for (; done < pages; ++done) {
            ulong va = userAddr + (done << 12);
            if (!userPageMapped(tid, va)) {
                if (!handlePageFault(tid, va, writable) || !userPageMapped(tid, va))
                    break;
            }
            ulong pa = userVirtToPhys(tid, va) & ~0xFFFUL;
            if (pa == 0) break;
            physPageRefInc(pa); // pin: the EPT will point here
            if (!eptMap(&vm.ept, guestPhys + (done << 12), pa, prot)) {
                physPageRefDec(pa);
                break;
            }
        }
        if (done != pages) {
            vmUnpinRange(vm, guestPhys, done);
            if (vm.untypedObjId != 0) untypedRelease(vm.untypedObjId, pages);
            rc = -14; // EFAULT
            goto fail;
        }
    }

    {
        VmMemSlot* s = &vm.slots[slotId];
        s.used = true;
        s.slotId = slotId;
        s.flags = flags;
        s.guestPhys = guestPhys;
        s.pages = pages;
        s.userBase = userAddr;
    }
    vm.pagesCharged += pages;
    g_virtPagesTotal += pages;
    rc = 0;
fail:
    vmUnlockMem(vm);
    return rc;
}

private long vmRemoveMemoryRegionLocked(Vm* vm, uint slotId) {
    if (slotId >= VIRT_MAX_MEMSLOTS) return -22;
    VmMemSlot* s = &vm.slots[slotId];
    if (!s.used) return -2; // ENOENT
    vmUnpinRange(vm, s.guestPhys, s.pages);
    if (vm.untypedObjId != 0) untypedRelease(vm.untypedObjId, s.pages);
    vm.pagesCharged -= s.pages;
    g_virtPagesTotal -= s.pages;
    *s = VmMemSlot.init;
    return 0;
}

public long vmRemoveMemoryRegion(Vm* vm, uint slotId) {
    if (vm is null || vm.state != VmState.Active) return -9;
    if (!vmLockMem(vm)) return -16;
    long rc = vmRemoveMemoryRegionLocked(vm, slotId);
    vmUnlockMem(vm);
    return rc;
}

// ---------------------------------------------------------------------------
// Teardown — idempotent, reclaims everything.
// ---------------------------------------------------------------------------
public void vmTeardown(Vm* vm) {
    if (vm is null || vm.state != VmState.Active) return;
    // Take the mem lock; if already held the VM is mid-teardown elsewhere —
    // fail closed (the holder will complete it).
    if (!vmLockMem(vm)) return;
    vm.state = VmState.Dying;

    // 1. vCPUs: release kvm_run/state pages and object mirrors.
    foreach (ref vc; vm.vcpus) {
        if (vc.state == VcpuState.Empty || vc.state == VcpuState.Dead) continue;
        vc.state = VcpuState.Dead;
        if (vc.runPhys != 0) { free_phys_page(vc.runPhys); vc.runPhys = 0; }
        if (vc.cachePhys != 0) { free_phys_page(vc.cachePhys); vc.cachePhys = 0; }
        if (vc.cpuidPhys != 0) { free_phys_page(vc.cpuidPhys); vc.cpuidPhys = 0; }
        if (vc.objId != 0) { objRelease(vc.objId); vc.objId = 0; }
    }
    vm.vcpuCount = 0;

    // 2. Memory slots: EPT is the source of truth for pinned pages.
    foreach (ref s; vm.slots) {
        if (!s.used) continue;
        vmUnpinRange(vm, s.guestPhys, s.pages);
        if (vm.untypedObjId != 0) untypedRelease(vm.untypedObjId, s.pages);
        g_virtPagesTotal -= s.pages;
        s = VmMemSlot.init;
    }
    vm.pagesCharged = 0;

    // 3. EPT tables.
    eptFree(&vm.ept);

    // 4. Object-table slot.  The pool record is re-initialized by the next
    //    vmAlloc; the generation in ObjHeader.version_ already stales old
    //    handles (never reuse 0).
    uint id = vm.objId;
    vm.objId = 0;
    vm.state = VmState.Empty;
    vmUnlockMem(vm);
    objRelease(id);
}

// Release one vCPU: free its kvm_run page and object mirror, then drop the
// reference it holds on its parent VM (which may release the VM itself).
// The caller must not touch `vc` afterwards — it may point into a freed Vm.
public void vcpuRelease(Vcpu* vc) {
    if (vc is null) return;
    uint vmObj = vc.vmObj, vmGen = vc.vmGen;
    if (vc.runPhys != 0) { free_phys_page(vc.runPhys); vc.runPhys = 0; }
    if (vc.cachePhys != 0) { free_phys_page(vc.cachePhys); vc.cachePhys = 0; }
    if (vc.cpuidPhys != 0) { free_phys_page(vc.cpuidPhys); vc.cpuidPhys = 0; }
    if (vc.objId != 0) { objRelease(vc.objId); vc.objId = 0; }
    vc.state = VcpuState.Dead;
    vc.fdRefs = 0;
    // Drop the vCPU's pin on the parent VM.
    Vm* vm = vmCheck(vmObj, vmGen);
    if (vm !is null && vm.fdRefs > 0 && --vm.fdRefs == 0)
        vmTeardown(vm);
}

// --- fd lifecycle ----------------------------------------------------------
// The KVM fd layer (core.virt.kvm) stores a packed (objId, generation) handle
// in the fd and calls these on dup/fork/close.  Packing: (objId << 32) | gen.

// A VM-fd view was duplicated (dup/dup2/fork): the VM outlives the new fd.
public void kvmVmFdDuped(uint objId, uint gen) {
    Vm* vm = vmCheck(objId, gen);
    if (vm !is null) ++vm.fdRefs;
}

// A VM-fd view closed: release the VM when the last view goes away.
public void kvmVmFdClosed(uint objId, uint gen) {
    Vm* vm = vmCheck(objId, gen);
    if (vm !is null && vm.fdRefs > 0 && --vm.fdRefs == 0)
        vmTeardown(vm);
}

// A vCPU-fd view was duplicated.
public void kvmVcpuFdDuped(uint objId, uint gen) {
    Vcpu* vc = vcpuCheckObj(objId, gen);
    if (vc !is null) ++vc.fdRefs;
}

// A vCPU-fd view closed: release the vCPU (and its VM pin) at zero.
public void kvmVcpuFdClosed(uint objId, uint gen) {
    Vcpu* vc = vcpuCheckObj(objId, gen);
    if (vc !is null && vc.fdRefs > 0 && --vc.fdRefs == 0)
        vcpuRelease(vc);
}

// Unpack a packed fd handle.
public void kvmUnpackHandle(ulong packed, out uint objId, out uint gen) {
    objId = cast(uint)(packed >> 32);
    gen   = cast(uint)(packed & 0xFFFF_FFFF);
}
public ulong kvmPackHandle(uint objId, uint gen) {
    return (cast(ulong)objId << 32) | gen;
}

// ---------------------------------------------------------------------------
// Accounting
// ---------------------------------------------------------------------------
public uint virtVmLive() {
    uint n = 0;
    foreach (ref s; g_vmPool) if (s.state == VmState.Active) ++n;
    return n;
}
