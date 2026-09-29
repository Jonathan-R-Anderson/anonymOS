// VIRT: KVM compatibility ABI — ioctl dispatch over native VM objects.
//
// This is the COMPATIBILITY layer, not the authority.  Every ioctl resolves
// its fd to a native (objId, generation) handle and goes through the
// stale-checked lookups in core.virt.vm; the KVM numbers are just names for
// operations on those objects.  A Linux VMM (Cloud Hypervisor) runs as an
// ordinary confined anonymOS task: it opens /dev/kvm (DEVCLASS_VIRT,
// never in a default device mask), gets a system fd with VM_CREATE only,
// and each VM/vCPU fd carries exactly the rights its kind needs.
//
// Layout: posix.d owns the fd table and the capability checks.  This module
// owns ioctl semantics.  The two meet at:
//   kvmRequiredRight(kind, cmd)  — extra CAP_RIGHT_VM_* beyond CAP_RIGHT_IOCTL
//   kvmSystemIoctl / kvmVmIoctl / kvmVcpuIoctl — the dispatch (return -errno)
//   kvmCreateVm / kvmCreateVcpu  — return packed (objId,gen) handles; posix.d
//                                  allocates the fd around them
//   kvmVcpuMmap                  — vCPU fd mmap (kvm_run page)
//   kvmVmFdDuped/Closed, kvmVcpuFdDuped/Closed — refcount hooks for dup/fork/close
//
// Constraints: -betterC, @nogc nothrow.  No userspace pointer is dereferenced
// without kvmUserOk (canonical low-half + per-page resolvability); a bad
// pointer is -EFAULT, never a kernel fault.
module core.virt.kvm;

import core.virt.kvmabi;
import core.virt.vm;
import core.virt.vmm_policy : vmmMayCreateVm, vmmAuditCreate, vmmAuditDeny,
                              VMM_DENY_VM_CEILING, VMM_DENY_POOL_EXHAUSTED;
import core.virt.backend : virtEnter, virtBackendAvailable, virtFpuXsaveMask,
    virtFpuMxcsrMask, VIRT_FPU_UNSUPPORTED;
import core.virt.vmexit : virtDispatchExit, VirtExitInfo, VirtExitKind, VmExitAction,
    virtValidateSRegs, virtValidateRegs, virtValidateMsrs;
import core.task : g_tasks, findRegion, MAX_TASKS;
import core.objmgr : objGet;
import core.addrspace : userPageMapped, userPageWritable, handlePageFault;
import core.exports : phys_to_virt;
import core.cap : CAP_RIGHT_VM_CREATE, CAP_RIGHT_VM_MEM,
                  CAP_RIGHT_VM_RUN, CAP_RIGHT_VM_CONTROL;
import core.io : klog, klog_hex, klog_dec;
import memory.mm : alloc_phys_page, free_phys_page;

extern (C) @nogc nothrow:

// --- errno (negative returns, Linux numbers) --------------------------------
private enum long E_OK    = 0;
private enum long E_PERM  = -1;
private enum long E_NOENT = -2;
private enum long E_INTR  = -4;   // EINTR: KVM_RUN handed back without a guest-visible exit
private enum long E_BADF  = -9;
private enum long E_NOMEM = -12;
private enum long E_ACCES = -13;
private enum long E_FAULT = -14;
private enum long E_BUSY  = -16;
private enum long E_EXIST = -17;  // EEXIST (duplicate registration)
private enum long E_NODEV = -19;
private enum long E_INVAL = -22;
private enum long E_IO    = -5;   // Linux -EIO (e.g. KVM_GET_TSC_KHZ w/o TSC)
private enum long E_NOTTY = -25;
private enum long E_NOSPC = -28;
private enum long E_BIG   = -7;  // E2BIG

// --- fd kinds (posix.d maps FileType -> these) -------------------------------
enum KvmFdKind : ubyte { System = 0, Vm = 1, Vcpu = 2 }

// Extra capability right required for an ioctl, beyond CAP_RIGHT_IOCTL which
// the generic ioctl path already checked.  0 = no extra right.  posix.d calls
// this BEFORE dispatch and enforces with fdRequireCap.
uint kvmRequiredRight(KvmFdKind kind, ulong cmd) {
    switch (kind) {
        case KvmFdKind.System:
            if (cmd == KVM_CREATE_VM) return CAP_RIGHT_VM_CREATE;
            return 0;
        case KvmFdKind.Vm:
            switch (cmd) {
                case KVM_CREATE_VCPU:        return CAP_RIGHT_VM_CONTROL;
                case KVM_SET_USER_MEMORY_REGION: return CAP_RIGHT_VM_MEM;
                case KVM_SET_TSS_ADDR:       return CAP_RIGHT_VM_CONTROL;
                case KVM_SET_IDENTITY_MAP_ADDR: return CAP_RIGHT_VM_CONTROL;
                case KVM_CREATE_IRQCHIP:     return CAP_RIGHT_VM_CONTROL;
                case KVM_CREATE_PIT2:        return CAP_RIGHT_VM_CONTROL;
                case KVM_SET_GSI_ROUTING:    return CAP_RIGHT_VM_CONTROL;
                case KVM_IRQ_LINE:           return CAP_RIGHT_VM_CONTROL;
                case KVM_SIGNAL_MSI:         return CAP_RIGHT_VM_CONTROL;
                case KVM_IRQFD:              return CAP_RIGHT_VM_CONTROL;
                case KVM_IOEVENTFD:          return CAP_RIGHT_VM_CONTROL;
                case KVM_SET_CLOCK:          return CAP_RIGHT_VM_CONTROL;
                case KVM_GET_CLOCK:          return CAP_RIGHT_VM_CONTROL;
                case KVM_ENABLE_CAP:         return CAP_RIGHT_VM_CONTROL;
                case KVM_GET_DIRTY_LOG:      return CAP_RIGHT_VM_CONTROL;
                case ANONVM_GET_VM_STATE:    return CAP_RIGHT_VM_CONTROL;
                default: break;
            }
            return 0;
        case KvmFdKind.Vcpu:
            switch (cmd) {
                case KVM_RUN:                return CAP_RIGHT_VM_RUN;
                default:                     return CAP_RIGHT_VM_CONTROL;
            }
        default: return 0;
    }
}

// --- userspace guards --------------------------------------------------------
// Validate a userspace range before touching it: non-zero, no wrap, inside the
// low canonical half, and every page resolvable in the caller's address space
// (present, or demand-fillable via the same path a userspace fault would take).
// forWrite=true resolves pages for write (CoW break / dirty); a read-only
// mapping fails the write guard.  A bad pointer is -EFAULT at the ioctl
// boundary, never a kernel #PF.
//
// SMAP convention (mirrors core.syscalls.posix): every direct userspace
// dereference below runs inside kvmSmapBegin/kvmSmapEnd.  The bodies are
// no-ops until SMAP (CLAC/STAC) enablement lands; the call sites are in place
// so that is a one-spot change.
private void kvmSmapBegin() @nogc nothrow {}
private void kvmSmapEnd() @nogc nothrow {}

private bool kvmUserOk(int tid, ulong addr, ulong len, bool forWrite) {
    if (addr == 0 || len == 0 || len > 0x10_0000) return false; // 1 MiB sanity cap
    ulong end = addr + len;
    if (end < addr) return false;                              // wrap
    if (end > 0x0000_8000_0000_0000UL) return false;            // low half only
    if (tid < 0 || tid >= MAX_TASKS) return false;
    for (ulong p = addr & ~0xFFFUL; ; ) {
        bool present = forWrite ? userPageWritable(tid, p)
                                : userPageMapped(tid, p);
        if (!present) {
            // Same resolution a userspace touch would get (demand-zero, CoW…).
            // A write fault on a CoW page resolves writable here; a genuinely
            // read-only mapping stays unwritable and fails the guard below.
            if (!handlePageFault(tid, p, forWrite)) return false;
            present = forWrite ? userPageWritable(tid, p)
                               : userPageMapped(tid, p);
            if (!present) return false;
        }
        if (p + 0x1000 < p) break;                             // overflow guard
        p += 0x1000;
        if (p >= end) break;
    }
    return true;
}

private T kvmUserRead(T)(ulong addr) {
    kvmSmapBegin();
    T v = *cast(T*)addr;
    kvmSmapEnd();
    return v;
}
private void kvmUserWrite(T)(ulong addr, T v) {
    kvmSmapBegin();
    *cast(T*)addr = v;
    kvmSmapEnd();
}
private void kvmUserCopyOut(ulong dst, const(void)* src, size_t n) {
    kvmSmapBegin();
    auto d = cast(ubyte*)dst;
    auto s = cast(const(ubyte)*)src;
    foreach (i; 0 .. n) d[i] = s[i];
    kvmSmapEnd();
}
private void kvmUserCopyIn(void* dst, ulong src, size_t n) {
    kvmSmapBegin();
    auto d = cast(ubyte*)dst;
    auto s = cast(const(ubyte)*)src;
    foreach (i; 0 .. n) d[i] = s[i];
    kvmSmapEnd();
}

// Self-test hook: expose the userspace guard for the boot proof
// (core.virt.selftest).  Not part of the ABI.
public bool kvmTestUserOk(int tid, ulong addr, ulong len) {
    return kvmUserOk(tid, addr, len, false);
}
public bool kvmTestUserOkWrite(int tid, ulong addr, ulong len) {
    return kvmUserOk(tid, addr, len, true);
}

// --- /dev/kvm (system) fd -----------------------------------------------------

private long kvmCheckExtension(ulong cap) {
    switch (cap) {
        // --- boolean features we implement ---
        case KVM_CAP_USER_MEMORY:      return 1;
        case KVM_CAP_SET_TSS_ADDR:     return 1;
        case KVM_CAP_EXT_CPUID:        return 1;
        case KVM_CAP_MP_STATE:         return 1;
        case KVM_CAP_USER_NMI:         return 1;
        case KVM_CAP_HLT:              return 1;
        case KVM_CAP_NOP_IO_DELAY:     return 1;
        case KVM_CAP_IRQ_ROUTING:      return 1; // routing stored + resolved to a
                                                     // vector (MSI routes) and
                                                     // injected via the VMX entry
                                                     // backend (KVM_IRQ_LINE /
                                                     // KVM_SIGNAL_MSI below).
        case KVM_CAP_IRQFD:            return 1; // eventfd->GSI bridge live: a
                                                     // signaled eventfd raises the
                                                     // bound GSI, resolves, injects
                                                     // (see vmIrqfdSignal).
        case KVM_CAP_IOEVENTFD:        return 1; // MMIO doorbell -> eventfd: a
                                                     // matching guest write signals
                                                     // the eventfd and the guest
                                                     // resumes without a userspace
                                                     // exit (MMIO write fast-path).
        case KVM_CAP_SET_IDENTITY_MAP_ADDR: return 1;
        case KVM_CAP_ADJUST_CLOCK:     return 1;
        case KVM_CAP_VCPU_EVENTS:      return 1;
        case KVM_CAP_XSAVE:            return 1;
        case KVM_CAP_XCRS:             return 1;
        case KVM_CAP_DEBUGREGS:        return 1;
        case KVM_CAP_ENABLE_CAP:       return 1;
        case KVM_CAP_GET_TSC_KHZ:      return 1;
        case KVM_CAP_TSC_CONTROL:      return 1;
        case KVM_CAP_TSC_DEADLINE_TIMER: return 1;
        case KVM_CAP_SIGNAL_MSI:       return 1; // synchronous MSI inject (resolve
                                                     // dest+vector -> VMX entry inject)
        case KVM_CAP_READONLY_MEM:     return 1;
        case KVM_CAP_IMMEDIATE_EXIT:   return 1;
        // --- Cloud Hypervisor's hard probe gate: answered 1 even though
        //     KVM_CREATE_IRQCHIP itself is rejected (split irqchip only).
        //     See KVM_API_TRACE.md §2.2 / design.md §"Split irqchip only". ---
        case KVM_CAP_IRQCHIP:          return 1;
        // --- valued queries ---
        case KVM_CAP_NR_VCPUS:         return VIRT_MAX_VCPUS_PER_VM; // 64
        case KVM_CAP_MAX_VCPUS:        return VIRT_MAX_VCPUS_PER_VM; // 64
        case KVM_CAP_NR_MEMSLOTS:      return VIRT_MAX_MEMSLOTS;     // 32
        case KVM_CAP_SPLIT_IRQCHIP:    return 24; // #GSIs, nonzero = supported
        // --- anonymOS-specific (never in UAPI numbering) ---
        case KVM_CAP_ANON_VM_PROFILE:  return 1; // KVM_ENABLE_CAP sets VmProfile
        case KVM_CAP_ANON_VM_STATE:    return 1; // ANONVM_GET_VM_STATE supported
        // --- explicitly not implemented ---
        case KVM_CAP_PIT:              return 0;
        case KVM_CAP_PIT2:             return 0;
        case KVM_CAP_SET_GUEST_DEBUG:  return 0;
        case KVM_CAP_DISABLE_QUIRKS:   return 0;
        case KVM_CAP_MULTI_ADDRESS_SPACE: return 0;
        default:                       return 0;
    }
}

// Create a VM.  Returns a packed (objId, generation) handle >= 0, or -errno.
// posix.d allocates the fd and stores the handle in f.fileSize.
long kvmCreateVm(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return E_INVAL;
    const uint dom = g_tasks[tid].domainObjId;
    // VMM confinement (core.virt.vmm_policy): a VMM-confined domain has its own
    // VM budget inside the global pool — creating over it is -ENOSPC, audited.
    // Tasks with no domain (or outside a VMM domain) are decided by the
    // existing gates: the DEVCLASS_VIRT device grant, the fd rights, and the
    // global pool ceiling below.
    if (!vmmMayCreateVm(dom)) {
        vmmAuditDeny(dom, VMM_DENY_VM_CEILING);
        klog("[virt] kvmCreateVm: VMM domain VM ceiling reached\n");
        return E_NOSPC;
    }
    uint objId = vmAlloc(); // uses g_current_task_id
    if (objId == 0) {
        // Global pool exhausted — for a VMM domain this is the "second VMM
        // over the ceiling" denial; audit it as such.
        if (dom != 0) vmmAuditDeny(dom, VMM_DENY_POOL_EXHAUSTED);
        return E_NOSPC; // VM ceiling reached
    }
    auto h = objGet(objId);
    if (h is null) return E_NOENT;
    vmmAuditCreate(objId, dom);
    return cast(long)kvmPackHandle(objId, h.version_);
}

// System-fd ioctl dispatch.
long kvmSystemIoctl(int tid, ulong cmd, ulong arg) {
    switch (cmd) {
        case KVM_GET_API_VERSION:
            return KVM_API_VERSION; // 12
        case KVM_CHECK_EXTENSION:
            return kvmCheckExtension(arg);
        case KVM_CREATE_VM:
            // arg is the VM type: only KVM_X86_DEFAULT_VM (0) is supported.
            // Anything else (SEV/TDX types) is a clean EINVAL, not silent.
            if (arg != 0) return E_INVAL;
            return kvmCreateVm(tid);
        case KVM_GET_VCPU_MMAP_SIZE:
            return 4096; // one page: struct kvm_run
        case KVM_GET_SUPPORTED_CPUID: {
            // arg -> struct kvm_cpuid2 { u32 nent, pad; struct kvm_cpuid_entry2 entries[] } with
            // 40-byte entries (KvmCpuidEntry2).  Honest minimal list: the host leaves we vouch for,
            // with REAL host values (never faked).  It used to write 32-byte entries, put the NEXT
            // leaf number in `index` and swap ECX/EDX in leaf 0, so Cloud Hypervisor saw no leaf 1
            // and panicked in configure_vcpu (assert!(apic_id_patched)).
            if (!kvmUserOk(tid, arg, 8, true)) return E_FAULT;
            const uint nent = kvmUserRead!uint(arg);
            enum uint PROVIDE = 4;
            static immutable uint[PROVIDE] fns = [0x0000_0000, 0x0000_0001, 0x8000_0000, 0x8000_0001];
            if (nent < PROVIDE) {
                kvmUserWrite!uint(arg, PROVIDE);
                return E_BIG; // tell caller to retry with a bigger buffer
            }
            enum ulong ESZ = KvmCpuidEntry2.sizeof;   // 40
            if (!kvmUserOk(tid, arg, 8 + PROVIDE * ESZ, true)) return E_FAULT;
            kvmUserWrite!uint(arg, PROVIDE);
            kvmUserWrite!uint(arg + 4, 0);
            foreach (i; 0 .. PROVIDE) {
                KvmCpuidEntry2 e;                     // index=0, flags=0, padding=0
                e.func = fns[i];
                kvmHostCpuid(fns[i], &e.eax, &e.ebx, &e.ecx, &e.edx);
                kvmUserCopyOut(arg + 8 + i * ESZ, &e, ESZ);
            }
            return 0;
        }
        case KVM_GET_MSR_INDEX_LIST: {
            // Minimal honest list: the MSRs our SET/GET_MSRS cache understands.
            if (!kvmUserOk(tid, arg, 8, true)) return E_FAULT;
            uint nent = kvmUserRead!uint(arg);
            enum uint PROVIDE = 8;
            static immutable uint[8] idx = [
                0x00000010, // IA32_TSC
                0x00000174, // IA32_SYSENTER_CS
                0x00000175, // IA32_SYSENTER_ESP
                0x00000176, // IA32_SYSENTER_EIP
                0xC0000080, // IA32_EFER
                0xC0000081, // IA32_STAR
                0xC0000082, // IA32_LSTAR
                0xC0000083, // IA32_FMASK
            ];
            if (nent < PROVIDE) {
                kvmUserWrite!uint(arg, PROVIDE);
                return E_BIG;
            }
            if (!kvmUserOk(tid, arg, 8 + PROVIDE * 4, true)) return E_FAULT;
            kvmUserWrite!uint(arg, PROVIDE);
            kvmUserWrite!uint(arg + 4, 0);
            foreach (i; 0 .. PROVIDE)
                kvmUserWrite!uint(arg + 8 + i*4, idx[i]);
            return 0;
        }
        default:
            return E_INVAL;
    }
}

// Host CPUID (subleaf 0) for KVM_GET_SUPPORTED_CPUID.  Same safe form as vmx.d x64Cpuid: NO
// `push RBX` (LDC may address params/locals RSP-relative, so a push skews every access and cpuid
// runs a garbage leaf) and never inlined; LDC preserves RBX across inline asm that clobbers it.
private void kvmHostCpuid(uint leaf, uint* a, uint* b, uint* c, uint* d) {
    pragma(inline, false);
    uint ra, rb, rc, rd;
    asm @nogc nothrow {
        mov EAX, leaf;
        xor ECX, ECX;
        cpuid;
        mov ra, EAX;
        mov rb, EBX;
        mov rc, ECX;
        mov rd, EDX;
    }
    *a = ra; *b = rb; *c = rc; *d = rd;
}

// Host TSC rate in kHz for KVM_GET_TSC_KHZ.  The kernel's own PIT calibration (core.ticks) lands
// only after a quiet 250 ms window, which is later than a VMM started at boot asks, so fall back to
// what the CPU reports: CPUID 0x15 (crystal Hz * TSC/crystal ratio), 0x16 (base MHz — the invariant
// TSC runs at the nominal frequency), then the hypervisor leaf 0x40000010 (TSC kHz, provided by
// nested hypervisors).  0 = unknown.  The chosen source is logged once.
private __gshared bool g_kvmTscSrcLogged = false;
private uint kvmHostTscKhz() {
    import core.ticks : tscCalibrated, tscHz;
    uint khz = 0;
    const(char)* src = null;
    if (tscCalibrated()) {
        const ulong k = tscHz() / 1000;                       // TSC ticks per ms == kHz
        khz = k > 0xFFFF_FFFF ? 0xFFFF_FFFF : cast(uint)k;
        src = "calibrated";
    }
    uint a, b, c, d;
    kvmHostCpuid(0, &a, &b, &c, &d);
    const uint maxBasic = a;
    if (khz == 0 && maxBasic >= 0x15) {
        kvmHostCpuid(0x15, &a, &b, &c, &d);                   // EAX=denominator EBX=numerator ECX=crystal Hz
        if (a != 0 && b != 0 && c != 0) {
            const ulong hz = (cast(ulong)c * b) / a;
            if (hz >= 100_000_000UL && hz <= 10_000_000_000UL) { khz = cast(uint)(hz / 1000); src = "cpuid 0x15"; }
        }
    }
    if (khz == 0 && maxBasic >= 0x16) {
        kvmHostCpuid(0x16, &a, &b, &c, &d);                   // EAX[15:0] = base frequency MHz
        const uint mhz = a & 0xFFFF;
        if (mhz >= 100 && mhz <= 10_000) { khz = mhz * 1000; src = "cpuid 0x16"; }
    }
    if (khz == 0) {
        kvmHostCpuid(1, &a, &b, &c, &d);
        if (c & (1u << 31)) {                                  // running under a hypervisor
            kvmHostCpuid(0x4000_0000, &a, &b, &c, &d);
            if (a >= 0x4000_0010) {
                kvmHostCpuid(0x4000_0010, &a, &b, &c, &d);    // EAX = TSC frequency in kHz
                if (a >= 100_000 && a <= 10_000_000) { khz = a; src = "cpuid 0x40000010"; }
            }
        }
    }
    if (!g_kvmTscSrcLogged) {
        g_kvmTscSrcLogged = true;
        klog("[kvm] TSC frequency for guests: ");
        if (khz != 0) { klog_dec(khz); klog(" kHz ("); klog(src); klog(")\n"); }
        else klog("unknown (not calibrated, no CPUID source)\n");
    }
    return khz;
}

private void kvmResetSeg(KvmSegment* g, ushort sel, ulong base, ubyte type, ubyte sflag) {
    *g = KvmSegment.init;
    g.base = base; g.limit = 0xFFFF; g.selector = sel; g.type = type; g.s = sflag; g.present = 1;
}
// x86 power-on segment/control state, as Linux reports it before any KVM_SET_SREGS (vmx_vcpu_reset).
private void kvmResetSRegs(KvmSRegs* s, bool bsp) {
    *s = KvmSRegs.init;
    kvmResetSeg(&s.cs, 0xF000, 0xFFFF_0000, 0xB, 1);          // AR 0x9b
    kvmResetSeg(&s.ds, 0, 0, 0x3, 1); kvmResetSeg(&s.es, 0, 0, 0x3, 1);
    kvmResetSeg(&s.fs, 0, 0, 0x3, 1); kvmResetSeg(&s.gs, 0, 0, 0x3, 1);
    kvmResetSeg(&s.ss, 0, 0, 0x3, 1);                          // AR 0x93
    kvmResetSeg(&s.ldt, 0, 0, 0x2, 0);                         // AR 0x82
    kvmResetSeg(&s.tr,  0, 0, 0xB, 0);                         // AR 0x8b
    s.gdt.limit = 0xFFFF; s.idt.limit = 0xFFFF;
    s.cr0 = 0x6000_0010;
    s.apicBase = 0xFEE0_0000 | 0x800 | (bsp ? 0x100 : 0);      // enabled (+BSP)
}
// --- VM fd -------------------------------------------------------------------
// Create a vCPU on the VM at the requested KVM vCPU id (the ioctl arg).
// Returns a packed (objId, generation) handle >= 0, or -errno.  posix.d
// allocates the fd and stores the handle in f.fileSize.
long kvmCreateVcpu(uint vmObj, uint vmGen, uint vcpuId) {
    Vm* vm = vmCheck(vmObj, vmGen);
    if (vm is null) return E_BADF; // stale VM handle
    int idx = vmCreateVcpu(vm, vcpuId);
    if (idx < 0) return E_NOSPC;   // id taken/out of range, or ceiling reached
    Vcpu* vc = &vm.vcpus[idx];
    return cast(long)kvmPackHandle(vc.objId, vc.gen);
}

// VM-fd ioctl dispatch.
long kvmVmIoctl(int tid, uint vmObj, uint vmGen, ulong cmd, ulong arg) {
    Vm* vm = vmCheck(vmObj, vmGen);
    if (vm is null) return E_BADF; // stale handle: the VM is gone
    switch (cmd) {
        case KVM_CREATE_VCPU:
            // The ioctl arg IS the vCPU id (a ulong, not a pointer).
            // Reject ids that don't fit in 32 bits instead of truncating.
            if (arg > uint.max) return E_INVAL;
            return kvmCreateVcpu(vmObj, vmGen, cast(uint)arg);
        case KVM_SET_USER_MEMORY_REGION: {
            if (!kvmUserOk(tid, arg, KvmUserspaceMemoryRegion.sizeof, false)) return E_FAULT;
            KvmUserspaceMemoryRegion r;
            kvmUserCopyIn(&r, arg, KvmUserspaceMemoryRegion.sizeof);
            return vmSetMemoryRegion(vm, r.slot, r.flags, r.guestPhysAddr,
                                     r.memorySize, r.userspaceAddr);
        }
        case KVM_SET_TSS_ADDR: {
            // arg is the address itself (a u64), not a pointer.
            vm.tssAddr = arg;
            return 0;
        }
        case KVM_SET_IDENTITY_MAP_ADDR: {
            if (!kvmUserOk(tid, arg, 8, false)) return E_FAULT;
            vm.identityMapAddr = kvmUserRead!ulong(arg);
            return 0;
        }
        case KVM_CREATE_IRQCHIP:
        case KVM_CREATE_PIT2:
            // Split irqchip is the only first-tier model: no in-kernel
            // PIC/IOAPIC/PIT.  ENOTTY = "not implemented here", clean probe.
            return E_NOTTY;
        case KVM_ENABLE_CAP: {
            if (!kvmUserOk(tid, arg, KvmEnableCap.sizeof, false)) return E_FAULT;
            KvmEnableCap c;
            kvmUserCopyIn(&c, arg, KvmEnableCap.sizeof);
            // 7.4: profile switching.  Profiles are policy bundles over one
            // substrate: this changes defaults/advertised policy only, never
            // the security or lifecycle of the VM.
            if (c.cap == KVM_CAP_ANON_VM_PROFILE) {
                if (c.args[0] > 1) return E_INVAL; // 0=Lightweight, 1=Compatibility
                vm.profile = cast(VmProfile)c.args[0];
                // Compatibility pre-enables the split-irqchip policy it
                // implies; Lightweight opts out.
                vm.splitIrqchip = (vm.profile == VmProfile.Compatibility);
                return 0;
            }
            if (c.cap == KVM_CAP_SPLIT_IRQCHIP) {
                // Lightweight opts out of the compat policy bundle.
                if (vm.profile == VmProfile.Lightweight) return E_INVAL;
                if (c.args[0] > 24) return E_INVAL;
                vm.splitIrqchip = true;
                return 0;
            }
            if (c.cap == KVM_CAP_DISABLE_QUIRKS) return E_INVAL; // not implemented
            return E_INVAL;
        }
        case KVM_SET_GSI_ROUTING: {
            // struct kvm_irq_routing { u32 nr; u32 flags; entries[nr] }.  Copy
            // the header, then each 48-byte entry straight into the VM's table
            // (validated in-kernel = no TOCTOU, no large stack temp); fail-closed
            // leaves the table empty on any bad entry (see vmSetGsiRouting).
            if (!kvmUserOk(tid, arg, KvmIrqRouting.sizeof, false)) return E_FAULT;
            KvmIrqRouting hdr;
            kvmUserCopyIn(&hdr, arg, KvmIrqRouting.sizeof);
            if (hdr.flags != 0) return E_INVAL;
            if (hdr.nr > VIRT_MAX_GSI_ROUTES) return E_NOSPC;
            const ulong entriesBase = arg + KvmIrqRouting.sizeof;
            const ulong sz = KvmIrqRoutingEntry.sizeof;
            const ulong totalBytes = cast(ulong)hdr.nr * sz;
            if (totalBytes != 0 && !kvmUserOk(tid, entriesBase, totalBytes, false))
                return E_FAULT;
            foreach (i; 0 .. hdr.nr)
                kvmUserCopyIn(&vm.gsiRoutes[i], entriesBase + i * sz, sz);
            const int rc = vmSetGsiRouting(vm, vm.gsiRoutes.ptr, hdr.nr);
            return rc; // 0 / -EINVAL / -ENOSPC
        }
        case KVM_IRQ_LINE: {
            // struct kvm_irq_level { u32 irq(=GSI); u32 level }.  Assert resolves
            // the GSI via the routing table to a vector and injects on the target
            // vCPU's next entry; de-assert is a no-op (edge model).
            if (!kvmUserOk(tid, arg, KvmIrqLevel.sizeof, false)) return E_FAULT;
            KvmIrqLevel k;
            kvmUserCopyIn(&k, arg, KvmIrqLevel.sizeof);
            return vmRaiseIrqLine(vm, k.irq, k.level); // 0 / -EINVAL (no route)
        }
        case KVM_SIGNAL_MSI: {
            // struct kvm_msi: inject an MSI message directly (split-irqchip's
            // synchronous inject path).  Dest LAPIC + vector -> queue on the vCPU.
            if (!kvmUserOk(tid, arg, KvmMsi.sizeof, false)) return E_FAULT;
            KvmMsi m;
            kvmUserCopyIn(&m, arg, KvmMsi.sizeof);
            if (m.flags & KVM_MSI_VALID_DEVID) return E_INVAL; // devid routing unsupported
            if (m.flags != 0) return E_INVAL;
            return vmSignalMsi(vm, m.addressLo, m.addressHi, m.data); // 0 / -EINVAL
        }
        case KVM_IRQFD: {
            // struct kvm_irqfd { u32 fd; u32 gsi; u32 flags; u32 resamplefd; ... }.
            // Bind the eventfd to a GSI: a signaled eventfd raises the GSI, which
            // resolves via the routing table and injects (the bridge lives in the
            // eventfd write path, core.syscalls.posix -> vmIrqfdSignal).
            if (!kvmUserOk(tid, arg, KvmIrqfd.sizeof, false)) return E_FAULT;
            KvmIrqfd k;
            kvmUserCopyIn(&k, arg, KvmIrqfd.sizeof);
            if (k.flags & KVM_IRQFD_FLAG_RESAMPLE) return E_INVAL; // unsupported
            if (k.flags & ~(KVM_IRQFD_FLAG_DEASSIGN | KVM_IRQFD_FLAG_RESAMPLE))
                return E_INVAL; // unknown flags
            import core.syscalls.posix : posixEventfdEidForFd;
            const int eid = posixEventfdEidForFd(cast(int)k.fd);
            if (eid < 0) return E_BADF; // fd is not a live eventfd
            if (k.flags & KVM_IRQFD_FLAG_DEASSIGN)
                return vmIrqfdDeassign(vm, cast(uint)eid, k.gsi);
            return vmIrqfdAssign(vm, cast(uint)eid, k.gsi); // 0 / -EEXIST / -ENOSPC / -EINVAL
        }
        case KVM_IOEVENTFD: {
            // struct kvm_ioeventfd { u64 datamatch; u64 addr; u32 len; s32 fd;
            //   u32 flags; ... }.  Bind an MMIO doorbell address to an eventfd:
            // a matching guest write signals it (the MMIO write fast-path in
            // kvmVcpuRun) so the guest resumes without a userspace exit.
            if (!kvmUserOk(tid, arg, KvmIoeventfd.sizeof, false)) return E_FAULT;
            KvmIoeventfd k;
            kvmUserCopyIn(&k, arg, KvmIoeventfd.sizeof);
            if (k.flags & KVM_IOEVENTFD_FLAG_PIO) return E_INVAL; // port-I/O doorbells unsupported
            if (k.flags & ~(KVM_IOEVENTFD_FLAG_DATAMATCH | KVM_IOEVENTFD_FLAG_PIO
                            | KVM_IOEVENTFD_FLAG_DEASSIGN)) return E_INVAL;
            if (k.len != 0 && k.len != 1 && k.len != 2 && k.len != 4 && k.len != 8)
                return E_INVAL;
            const bool hasDm = (k.flags & KVM_IOEVENTFD_FLAG_DATAMATCH) != 0;
            if (k.flags & KVM_IOEVENTFD_FLAG_DEASSIGN)
                return cast(long) vmIoeventfdDeassign(vm, k.addr, cast(ubyte)k.len, hasDm, k.datamatch);
            import core.syscalls.posix : posixEventfdEidForFd;
            const int eid = posixEventfdEidForFd(k.fd);
            if (eid < 0) return E_BADF; // fd is not a live eventfd
            return cast(long) vmIoeventfdAssign(vm, k.addr, cast(ubyte)k.len, hasDm,
                                                k.datamatch, cast(uint)eid);
        }
        case KVM_SET_CLOCK: {
            // 7.4: kvmclock is part of the Compatibility bundle only.
            if (vm.profile == VmProfile.Lightweight) return E_NOTTY;
            if (!kvmUserOk(tid, arg, KvmClockData.sizeof, false)) return E_FAULT;
            return 0; // accepted; kvmclock is a later tier
        }
        case KVM_GET_CLOCK: {
            // 7.4: kvmclock is part of the Compatibility bundle only.
            if (vm.profile == VmProfile.Lightweight) return E_NOTTY;
            if (!kvmUserOk(tid, arg, KvmClockData.sizeof, true)) return E_FAULT;
            KvmClockData c;
            // Zeroed clock: honest "no kvmclock" rather than fake timestamps.
            foreach (i; 0 .. KvmClockData.sizeof) (cast(ubyte*)&c)[i] = 0;
            kvmUserCopyOut(arg, &c, KvmClockData.sizeof);
            return 0;
        }
        case KVM_GET_DIRTY_LOG:
            return E_INVAL; // no dirty tracking yet (later tier)
        case ANONVM_GET_VM_STATE: {
            // 8.1: kernel-side AppVM interface — native state + named
            // diagnostic.  Uses vmCheckQuery (not vmCheck) so a Dying VM
            // still yields its post-mortem; a fully torn-down VM (stale
            // handle) is -EBADF like any other fd use.
            Vm* qvm = vmCheckQuery(vmObj, vmGen);
            if (qvm is null) return E_BADF;
            if (!kvmUserOk(tid, arg, AnonVmState.sizeof, true)) return E_FAULT;
            AnonVmState st;
            st.magic = ANONVM_STATE_MAGIC;
            st.vmState = cast(ubyte)qvm.state;
            st.profile = cast(ubyte)qvm.profile;
            st.vcpuCount = cast(ushort)qvm.vcpuCount;
            st.diag = cast(uint)qvm.diag;
            st.diagInfo = qvm.diagInfo;
            st.pagesCharged = qvm.pagesCharged;
            foreach (i; 0 .. VIRT_MAX_VCPUS_PER_VM)
                st.vcpuState[i] = cast(ubyte)qvm.vcpus[i].state;
            kvmUserCopyOut(arg, &st, AnonVmState.sizeof);
            return 0;
        }
        default:
            return E_INVAL;
    }
}

// --- vCPU state cache ---------------------------------------------------------
// Two lazily-allocated host pages per vCPU: cachePhys (fixed regs + MSRs) and
// cpuidPhys (CPUID2 list).  Freed by vcpuRelease/vmTeardown.
private KvmVcpuFixed* kvmCacheFor(Vcpu* vc, bool create) {
    if (vc.cachePhys == 0) {
        if (!create) return null;
        ulong p = alloc_phys_page();
        if (p == 0) return null;
        auto c = cast(ubyte*)phys_to_virt(p);
        foreach (i; 0 .. 4096) c[i] = 0;
        vc.cachePhys = p;
    }
    return cast(KvmVcpuFixed*)phys_to_virt(vc.cachePhys);
}

private KvmCpuidPage* kvmCpuidFor(Vcpu* vc, bool create) {
    if (vc.cpuidPhys == 0) {
        if (!create) return null;
        ulong p = alloc_phys_page();
        if (p == 0) return null;
        auto c = cast(ubyte*)phys_to_virt(p);
        foreach (i; 0 .. 4096) c[i] = 0;
        vc.cpuidPhys = p;
    }
    return cast(KvmCpuidPage*)phys_to_virt(vc.cpuidPhys);
}

// Lazily-allocated XSAVE area (struct kvm_xsave, 4096 bytes).  The legacy
// region defaults match a freshly-reset FPU (FCW=0x37f, MXCSR=0x1f80).
// This page IS the vCPU's live FPU image: the backends load it before every
// guest entry and store the guest's registers back into it after every exit
// (core.virt.backend virtFpuPrepare).  Page-aligned, so it satisfies FXRSTOR's
// 16-byte and XRSTOR's 64-byte alignment.  Public for that backend path.
public KvmXsave* kvmXsaveFor(Vcpu* vc, bool create) {
    if (vc.xsavePhys == 0) {
        if (!create) return null;
        ulong p = alloc_phys_page();
        if (p == 0) return null;
        auto x = cast(KvmXsave*)phys_to_virt(p);
        foreach (i; 0 .. KvmXsave.sizeof) (cast(ubyte*)x)[i] = 0;
        // x87 state (bytes 0..159): FCW and MXCSR reset values.
        (cast(ushort*)x)[0] = 0x37f;             // fcw
        *cast(uint*)(cast(ubyte*)x + 24) = 0x1f80; // mxcsr
        vc.xsavePhys = p;
    }
    return cast(KvmXsave*)phys_to_virt(vc.xsavePhys);
}

// KVM_GET/SET_FPU <-> the vCPU FPU image.  Its first 512 bytes are the FXSAVE64 legacy layout:
// fcw@0 fsw@2 ftw(abridged)@4 fop@6 fip@8 fdp@16 mxcsr@24 st0-7@32 (16 B each) xmm0-15@160.
private void kvmFxToFpu(const(ubyte)* fx, KvmFpu* f) {
    auto fpr = cast(ubyte*)f.fpr.ptr;
    auto xmm = cast(ubyte*)f.xmm.ptr;
    foreach (i; 0 .. 128) fpr[i] = fx[32 + i];
    f.fcw        = *cast(const(ushort)*)(fx + 0);
    f.fsw        = *cast(const(ushort)*)(fx + 2);
    f.ftwx       = fx[4];
    f.lastOpcode = *cast(const(ushort)*)(fx + 6);
    f.lastIp     = *cast(const(ulong)*)(fx + 8);
    f.lastDp     = *cast(const(ulong)*)(fx + 16);
    foreach (i; 0 .. 256) xmm[i] = fx[160 + i];
    f.mxcsr      = *cast(const(uint)*)(fx + 24);
}
private void kvmFpuToFx(const(KvmFpu)* f, ubyte* fx) {
    auto fpr = cast(const(ubyte)*)f.fpr.ptr;
    auto xmm = cast(const(ubyte)*)f.xmm.ptr;
    foreach (i; 0 .. 128) fx[32 + i] = fpr[i];
    *cast(ushort*)(fx + 0)  = f.fcw;
    *cast(ushort*)(fx + 2)  = f.fsw;
    fx[4]                   = f.ftwx;
    *cast(ushort*)(fx + 6)  = f.lastOpcode;
    *cast(ulong*)(fx + 8)   = f.lastIp;
    *cast(ulong*)(fx + 16)  = f.lastDp;
    *cast(uint*)(fx + 24)   = f.mxcsr;
    foreach (i; 0 .. 256) fx[160 + i] = xmm[i];
    // XSAVE header XSTATE_BV |= x87|SSE: an XRSTOR-form switch then loads these registers rather
    // than the init state (FXRSTOR ignores the header).
    *cast(ulong*)(fx + 512) |= 3;
}

// An image the in-kernel FXRSTOR64/XRSTOR64 can load without faulting — checked at SET time on an
// in-kernel copy (no TOCTOU), since a #GP there is a kernel fault at the next entry:
//   - MXCSR carries no bit outside the CPU's MXCSR_MASK;
//   - XRSTOR form only: a standard-form header — XSTATE_BV within the switched XCR0 features,
//     XCOMP_BV (bytes 520..527) and the reserved header bytes (528..575) zero.
private bool kvmFpuImageValid(const(ubyte)* img) {
    if ((*cast(const(uint)*)(img + 24) & ~virtFpuMxcsrMask()) != 0) return false;
    const ulong mask = virtFpuXsaveMask();
    if (mask != 0 && mask != VIRT_FPU_UNSUPPORTED) {
        if ((*cast(const(ulong)*)(img + 512) & ~mask) != 0) return false;
        foreach (i; 520 .. 576) if (img[i] != 0) return false;
    }
    return true;
}

// Fixed part of the cache (fits one page with 64 MSRs).
private struct KvmVcpuFixed {
    KvmSRegs sregs;
    KvmFpu fpu;           // unused: the FPU state lives in the XSAVE page (kvmXsaveFor); kept so
                          // the cache layout is unchanged
    KvmVcpuEvents events;
    uint mpState;
    uint tscKhz;
    ulong[2] xcrs;        // XCR0 (+1); KVM_GET/SET_XCRS
    ulong[4] dr;          // DB0..DB3; KVM_GET/SET_DEBUGREGS
    ulong dr6;
    ulong dr7;
    bool xcrsSet;
    bool debugSet;
    uint msrCount;
    uint pad_;
    KvmMsrEntry[KVM_CACHE_MAX_MSRS] msrs;
}
private static assert(KvmVcpuFixed.sizeof <= 4096);

private struct KvmCpuidPage {
    uint count;
    uint pad_;
    KvmCpuidEntry2[KVM_CACHE_MAX_CPUID] entries;
}
private static assert(KvmCpuidPage.sizeof <= 4096);

// --- vCPU fd -------------------------------------------------------------------

// vCPU-fd mmap: only offset 0 (the shared kvm_run page) is mappable.
// Returns 0 and writes the host-physical page; posix.d maps it.
long kvmVcpuMmap(uint vcpuObj, uint vcpuGen, ulong offset, ulong* physOut) {
    if (physOut is null) return E_INVAL;
    Vcpu* vc = vcpuCheckObj(vcpuObj, vcpuGen);
    if (vc is null) return E_BADF;
    if (offset != 0) return E_NODEV;
    if (vc.runPhys == 0) return E_NODEV;
    *physOut = vc.runPhys;
    return 0;
}

// Enter the guest (KVM_RUN).  Without virtualization hardware this fails
// cleanly with -ENODEV AFTER doing the full state dance (stale checks,
// kvm_run mapping, immediate_exit, state transitions) so the [HW] phase only
// Pending MMIO-read completion, per vCPU, kept in a SIDE table (not the Vcpu
// struct — growing Vcpu trips a size-dependent boot regression).  Set when an
// MMIO read exits to userspace; applied on the next KVM_RUN (userspace has
// filled run.u.mmio.data): the value is written into the destination register
// and RIP is advanced past the load.
private struct MmioReadPend {
    bool  active;
    ubyte reg;       // x86 GPR number
    ubyte size;      // 1/2/4/8
    ubyte insnLen;
    bool  zeroExt;   // MOVZX
    bool  signExt;   // MOVSX
}
private __gshared MmioReadPend[VIRT_MAX_VMS * VIRT_MAX_VCPUS_PER_VM] g_mmioReadPend;

// Pending port-input (IN) completion, per vCPU, in a SIDE table (same reason as
// g_mmioReadPend — growing Vcpu trips a size-dependent boot regression).  Set when a
// port IN exits to userspace; applied on the next KVM_RUN (userspace filled the I/O
// data area): the value is written into the guest accumulator (AL/AX/EAX — port IN
// always targets RAX).  Unlike the MMIO case, the guest RIP was ALREADY advanced at
// the IO exit (Linux advances RIP before returning to the VMM), so completion only
// writes the register, never touches RIP.
private struct IoReadPend {
    bool  active;
    ubyte size;      // 1/2/4
}
private __gshared IoReadPend[VIRT_MAX_VMS * VIRT_MAX_VCPUS_PER_VM] g_ioReadPend;

// has to fill in the backend call.
long kvmVcpuRun(int tid, uint vcpuObj, uint vcpuGen) {
    Vcpu* vc = vcpuCheckObj(vcpuObj, vcpuGen);
    if (vc is null) return E_BADF; // stale vCPU handle
    Vm* vm = vmCheck(vc.vmObj, vc.vmGen);
    if (vm is null) return E_NODEV; // parent VM gone
    if (vc.state != VcpuState.Created && vc.state != VcpuState.Runnable)
        return E_INVAL; // Running re-entry or Exited/Dead
    if (vc.runPhys == 0) return E_NODEV;

    // 8.1: fresh attempt, fresh story.  The diagnostic describes the
    // outcome of THIS run (or the last setup call): stale failures from
    // before are cleared here and re-recorded below if they recur.
    vmSetDiag(vm, VirtDiag.None, 0);

    KvmRun* run = cast(KvmRun*)phys_to_virt(vc.runPhys);
    // Complete a pending MMIO read from the previous exit: userspace has filled
    // run.u.mmio.data; write it into the destination register and advance RIP
    // past the load before running the guest again.
    {
        import core.virt.mmio : mmioWriteRegValue;
        auto pend = &g_mmioReadPend[vmFlatVcpuIndex(vm, vc)];
        if (pend.active) {
            pend.active = false;
            ulong val = 0;
            foreach (k; 0 .. pend.size) val |= (cast(ulong) run.u.mmio.data[k]) << (8 * k);
            mmioWriteRegValue(cast(KvmRegs*)&vc.regs[0], pend.reg, val,
                              pend.size, pend.zeroExt, pend.signExt);
            vc.regs[16] += pend.insnLen; // KvmRegs index 16 = rip
        }
    }
    // Complete a pending port IN from the previous exit: userspace filled the I/O data
    // area (right after the kvm_run struct); write it into the guest accumulator.  RIP
    // was already advanced when the IN exited, so this only writes RAX (index 0), with
    // x86 IN width semantics (AL/AX preserve upper bits; EAX zero-extends to RAX).
    {
        import core.virt.mmio : mmioWriteRegValue;
        import core.virt.vmexit : KVM_RUN_IO_DATA_OFF;
        auto iop = &g_ioReadPend[vmFlatVcpuIndex(vm, vc)];
        if (iop.active) {
            iop.active = false;
            const(ubyte)* iodata = (cast(const(ubyte)*)run) + KVM_RUN_IO_DATA_OFF;
            ulong val = 0;
            foreach (k; 0 .. iop.size) val |= (cast(ulong) iodata[k]) << (8 * k);
            mmioWriteRegValue(cast(KvmRegs*)&vc.regs[0], 0 /*RAX*/, val, iop.size, false, false);
        }
    }
    // immediate_exit: userspace asked for an immediate KVM_EXIT_INTR.  Linux answers it with
    // -EINTR (Cloud Hypervisor maps EINTR to "ignore, re-run"; a 0 return with KVM_EXIT_INTR is
    // an "unexpected exit reason" there, i.e. fatal).
    if (run.immediateExit != 0) {
        run.immediateExit = 0;
        run.exitReason = KVM_EXIT_INTR;
        return E_INTR;
    }

    vc.state = VcpuState.Running;
    // Fail-soft availability BEFORE guest-state validation: without a ready
    // backend there is nothing to enter, and the VMM gets -ENODEV exactly
    // like Linux without /dev/kvm — regardless of the cached guest state.
    // (virtEnter re-validates; this is the fail-soft short-circuit.)
    if (!virtBackendAvailable()) {
        vc.state = VcpuState.Runnable;
        return E_NODEV;
    }
    // The guest FPU image the backends switch in/out around every entry (core.virt.backend
    // virtFpuPrepare).  Allocated up front so a shortage is a clean -ENOMEM, not a false -ENODEV.
    if (kvmXsaveFor(vc, true) is null) {
        vc.state = VcpuState.Runnable;
        return E_NOMEM;
    }
    // Build the guest state the backend programs into the VMCS/VMCB from
    // the vCPU's cached SET_REGS/SET_SREGS/SET_MSRS values.
    KvmRegs regs;
    foreach (i; 0 .. 18) (&regs.rax)[i] = vc.regs[i];
    auto cache = kvmCacheFor(vc, false);
    const(KvmSRegs)* sregs = (cache !is null && vc.sregsSet) ? &cache.sregs : null;
    const(KvmMsrEntry)* msrs = (cache !is null && cache.msrCount > 0) ? &cache.msrs[0] : null;
    uint nmsrs = (cache !is null) ? cache.msrCount : 0;

    // Entry/dispatch loop: normally one iteration.  An MMIO write that a
    // registered ioeventfd claims is handled entirely in-kernel (signal the
    // eventfd, advance guest RIP past the doorbell store, re-enter) so the guest
    // resumes without a userspace round-trip.  Bounded to avoid a runaway guest.
    import core.virt.mmio : mmioEnrichMmioExit, MmioAccess;
    import core.virt.vm : vmIoeventfdMatch;
    import core.syscalls.posix : posixEventfdSignal;
    foreach (iter; 0 .. 65536) {
        VirtExitInfo xi;
        int rc = virtEnter(vm, vc, &regs, sregs, msrs, nmsrs, &xi);
        if (rc == E_NODEV) {
            // Fail-soft: back out to Runnable, no exit reason written (we never
            // entered).  The VMM sees -ENODEV, exactly like Linux without /dev/kvm.
            vmSetDiag(vm, VirtDiag.NoHardware, 0);
            klog("[virt] kvmVcpuRun: no virtualization hardware (ENODEV)\n");
            vc.state = VcpuState.Runnable;
            return E_NODEV;
        }
        if (rc != 0) {
            // -EINVAL: pre-entry validation failed (bad guest state) or the VM
            // has no registered memory.
            klog("[virt] kvmVcpuRun: entry rejected (EINVAL)\n");
            vc.state = VcpuState.Runnable;
            return E_INVAL;
        }
        // Persist the post-exit guest registers so KVM_GET_REGS and MMIO decode
        // see the current state (the entry loaded them into the local `regs`).
        foreach (i; 0 .. 18) vc.regs[i] = (&regs.rax)[i];
        VmExitAction act = virtDispatchExit(xi, run, vm, vc);
        // A HOST interrupt forced this exit (VMX external-interrupt exiting).  It was not
        // acknowledged, so it is still pending in the host LAPIC/PIC.  Hand control back the way
        // Linux does for a signal — -EINTR with KVM_EXIT_INTR (Cloud Hypervisor re-runs on EINTR)
        // — and do NOT re-enter here: the syscall return re-enables IF, the host takes the
        // interrupt through its normal path (tick, EOI, preemption), and only then does the VMM
        // issue the next KVM_RUN.  That is what stops a guest spinning with IF=0 (`cli; jmp $`)
        // from pinning the CPU, and host timer/keyboard/mouse IRQs from going to the guest IDT.
        if (xi.kind == VirtExitKind.Intr) {
            vc.state = VcpuState.Runnable;
            return E_INTR;
        }
        // MMIO enrichment: the dispatcher emits KVM_EXIT_MMIO with len=0 (address
        // + direction only).  Decode the faulting instruction to fill len + write
        // data so the VMM / an ioeventfd sees a complete access.
        if (run.exitReason == KVM_EXIT_MMIO) {
            MmioAccess acc;
            mmioEnrichMmioExit(vm, vc, &regs, sregs, run, acc);
            // ioeventfd fast-path: a matching doorbell write is consumed here.
            if (acc.valid && acc.isWrite && run.u.mmio.len != 0) {
                ulong val = 0;
                foreach (k; 0 .. run.u.mmio.len)
                    val |= (cast(ulong) run.u.mmio.data[k]) << (8 * k);
                const long eid = vmIoeventfdMatch(vm, run.u.mmio.physAddr,
                                                  cast(ubyte) run.u.mmio.len, val);
                if (eid >= 0) {
                    posixEventfdSignal(cast(int) eid, 1);
                    regs.rip += acc.insnLen;          // advance past the doorbell store
                    vc.regs[16] = regs.rip;           // KvmRegs index 16 = rip
                    continue;                          // resume the guest, no userspace exit
                }
            }
            // MMIO READ: remember what to complete on re-entry (userspace fills
            // run.u.mmio.data), then exit to userspace.
            if (acc.valid && !acc.isWrite) {
                auto pend = &g_mmioReadPend[vmFlatVcpuIndex(vm, vc)];
                pend.active  = true;
                pend.reg     = acc.reg;
                pend.size    = acc.size;
                pend.insnLen = acc.insnLen;
                pend.zeroExt = acc.zeroExtend;
                pend.signExt = acc.signExtend;
            }
        }
        // KVM_EXIT_IO: advance the guest RIP past the I/O instruction before returning
        // to the VMM (Linux advances RIP in-kernel here).  Without it the guest re-runs
        // the same IN/OUT on the next KVM_RUN forever — the reason a trivial guest could
        // not make progress.  For IN, remember to write the input the VMM supplies into
        // the accumulator on re-entry (see the g_ioReadPend completion at the top).
        if (run.exitReason == KVM_EXIT_IO) {
            vc.regs[16] += xi.insnLen;                       // KvmRegs index 16 = rip
            if (run.u.io.direction == KVM_EXIT_IO_IN) {
                auto iop = &g_ioReadPend[vmFlatVcpuIndex(vm, vc)];
                iop.active = true;
                iop.size   = cast(ubyte) run.u.io.size;
            }
        }
        if (act == VmExitAction.VmContained)
            return E_IO; // contained failure; VM is Dying, never re-entered
        // The run is over.  An exit to the VMM (I/O, MMIO, hypercall, unknown) leaves the vCPU
        // Runnable so the next KVM_RUN can re-enter — it used to stay Running, which made every
        // re-entry -EINVAL.  HLT/SHUTDOWN already moved it to Exited.
        if (act == VmExitAction.ToUserspace) vc.state = VcpuState.Runnable;
        return 0;
    }
    // Loop budget exhausted (in-kernel ioeventfd resumes only): hand control back re-runnable.
    run.exitReason = KVM_EXIT_INTR;
    vc.state = VcpuState.Runnable;
    return E_INTR;
}

// vCPU-fd ioctl dispatch.
long kvmVcpuIoctl(int tid, uint vcpuObj, uint vcpuGen, ulong cmd, ulong arg) {
    Vcpu* vc = vcpuCheckObj(vcpuObj, vcpuGen);
    if (vc is null) return E_BADF; // stale handle
    switch (cmd) {
        case KVM_RUN:
            return kvmVcpuRun(tid, vcpuObj, vcpuGen);
        case KVM_GET_REGS: {
            if (!kvmUserOk(tid, arg, KvmRegs.sizeof, true)) return E_FAULT;
            KvmRegs r;
            foreach (i; 0 .. 18) (&r.rax)[i] = vc.regs[i];
            kvmUserCopyOut(arg, &r, KvmRegs.sizeof);
            return 0;
        }
        case KVM_SET_REGS: {
            if (!kvmUserOk(tid, arg, KvmRegs.sizeof, false)) return E_FAULT;
            KvmRegs r;
            kvmUserCopyIn(&r, arg, KvmRegs.sizeof);
            if (virtValidateRegs(&r) != 0) return E_INVAL; // non-canonical RIP etc.
            foreach (i; 0 .. 18) vc.regs[i] = (&r.rax)[i];
            vc.regsSet = true;
            if (vc.state == VcpuState.Created) vc.state = VcpuState.Runnable;
            return 0;
        }
        case KVM_GET_SREGS: {
            if (!kvmUserOk(tid, arg, KvmSRegs.sizeof, true)) return E_FAULT;
            auto c = kvmCacheFor(vc, false);
            KvmSRegs s;
            // Until the VMM has set sregs, report the x86 power-on state as Linux does (the cache
            // page may already exist from SET_MSRS, zeroed).  A VMM that edits GET_SREGS output and
            // never touches LDT (Cloud Hypervisor's setup_sregs) otherwise enters with a zeroed,
            // "usable" LDTR and VM entry fails.
            if (c !is null && vc.sregsSet) s = c.sregs;
            else kvmResetSRegs(&s, vc.index == 0);
            kvmUserCopyOut(arg, &s, KvmSRegs.sizeof);
            return 0;
        }
        case KVM_SET_SREGS: {
            if (!kvmUserOk(tid, arg, KvmSRegs.sizeof, false)) return E_FAULT;
            KvmSRegs tmp;
            kvmUserCopyIn(&tmp, arg, KvmSRegs.sizeof);
            // Validate BEFORE committing: hostile control state (VMX/SMX in
            // guest CR4, non-canonical EFER, bad CR0/CR3/CR8) is rejected.
            if (virtValidateSRegs(&tmp) != 0) return E_INVAL;
            auto c = kvmCacheFor(vc, true);
            if (c is null) return E_NOMEM;
            c.sregs = tmp;
            vc.sregsSet = true;
            return 0;
        }
        case KVM_GET_FPU: {
            // Read from the vCPU's live FPU image (the XSAVE page the backends switch in/out
            // around every entry), so it reflects the guest's registers as of the last exit.
            if (!kvmUserOk(tid, arg, KvmFpu.sizeof, true)) return E_FAULT;
            KvmFpu f;
            foreach (i; 0 .. KvmFpu.sizeof) (cast(ubyte*)&f)[i] = 0;
            auto x = kvmXsaveFor(vc, false);
            if (x !is null) kvmFxToFpu(cast(const(ubyte)*)x, &f);
            else { f.fcw = 0x37f; f.mxcsr = 0x1f80; }   // same reset state as a fresh image
            kvmUserCopyOut(arg, &f, KvmFpu.sizeof);
            return 0;
        }
        case KVM_SET_FPU: {
            // Write into the same image, so it takes effect at the next entry (it used to land in
            // a cache nothing ever loaded).  MXCSR is validated first: a reserved bit would #GP
            // the in-kernel FXRSTOR64/XRSTOR64.
            if (!kvmUserOk(tid, arg, KvmFpu.sizeof, false)) return E_FAULT;
            KvmFpu f;
            kvmUserCopyIn(&f, arg, KvmFpu.sizeof);
            if ((f.mxcsr & ~virtFpuMxcsrMask()) != 0) return E_INVAL;
            auto x = kvmXsaveFor(vc, true);
            if (x is null) return E_NOMEM;
            kvmFpuToFx(&f, cast(ubyte*)x);
            return 0;
        }
        case KVM_GET_VCPU_EVENTS: {
            if (!kvmUserOk(tid, arg, KvmVcpuEvents.sizeof, true)) return E_FAULT;
            auto c = kvmCacheFor(vc, false);
            KvmVcpuEvents e;
            if (c !is null) e = c.events;
            else foreach (i; 0 .. KvmVcpuEvents.sizeof) (cast(ubyte*)&e)[i] = 0;
            kvmUserCopyOut(arg, &e, KvmVcpuEvents.sizeof);
            return 0;
        }
        case KVM_SET_VCPU_EVENTS: {
            if (!kvmUserOk(tid, arg, KvmVcpuEvents.sizeof, false)) return E_FAULT;
            auto c = kvmCacheFor(vc, true);
            if (c is null) return E_NOMEM;
            kvmUserCopyIn(&c.events, arg, KvmVcpuEvents.sizeof);
            return 0;
        }
        case KVM_GET_MP_STATE: {
            if (!kvmUserOk(tid, arg, 4, true)) return E_FAULT;
            auto c = kvmCacheFor(vc, false);
            uint s = (c !is null) ? c.mpState : vc.mpState;
            kvmUserWrite!uint(arg, s);
            return 0;
        }
        case KVM_SET_MP_STATE: {
            if (!kvmUserOk(tid, arg, 4, false)) return E_FAULT;
            uint s = kvmUserRead!uint(arg);
            if (s > 6) return E_INVAL; // KVM_MP_STATE_SIPI_RECEIVED max
            auto c = kvmCacheFor(vc, true);
            if (c is null) return E_NOMEM;
            c.mpState = s;
            vc.mpState = s;
            return 0;
        }
        case KVM_GET_LAPIC: {
            // Later tier: local-APIC state lives in the kernel APIC model.
            // Return zeros (honest "not modeled") rather than fake state.
            if (!kvmUserOk(tid, arg, 1024, true)) return E_FAULT;
            foreach (i; 0 .. 1024) kvmUserWrite!ubyte(arg + i, 0);
            return 0;
        }
        case KVM_SET_LAPIC: {
            if (!kvmUserOk(tid, arg, 1024, false)) return E_FAULT;
            vc.lapicSet = true;
            return 0; // accepted; applied when the APIC model lands
        }
        case KVM_SET_CPUID2: {
            if (!kvmUserOk(tid, arg, 8, false)) return E_FAULT;
            uint nent = kvmUserRead!uint(arg);
            if (nent > KVM_CACHE_MAX_CPUID) return E_BIG;
            if (!kvmUserOk(tid, arg, 8 + cast(ulong)nent * 40, false)) return E_FAULT;
            auto p = kvmCpuidFor(vc, true);
            if (p is null) return E_NOMEM;
            p.count = nent;
            kvmUserCopyIn(p.entries.ptr, arg + 8, cast(size_t)(nent * 40));
            return 0;
        }
        case KVM_SET_MSRS: {
            if (!kvmUserOk(tid, arg, 8, false)) return E_FAULT;
            uint n = kvmUserRead!uint(arg);
            if (n > KVM_CACHE_MAX_MSRS) return E_BIG;
            if (!kvmUserOk(tid, arg, 8 + cast(ulong)n * 16, false)) return E_FAULT;
            // Validate before committing: VMX MSRs, FEATURE_CONTROL,
            // microcode and bad EFER are never valid guest state.
            KvmMsrEntry[KVM_CACHE_MAX_MSRS] tmp;
            if (n > 0) kvmUserCopyIn(tmp.ptr, arg + 8, cast(size_t)(n * 16));
            if (virtValidateMsrs(n ? tmp.ptr : null, n) != 0) return E_INVAL;
            auto fx = kvmCacheFor(vc, true);
            if (fx is null) return E_NOMEM;
            fx.msrCount = n;
            foreach (i; 0 .. n) fx.msrs[i] = tmp[i];
            return cast(long)n; // Linux returns the number applied
        }
        case KVM_GET_MSRS: {
            if (!kvmUserOk(tid, arg, 8, true)) return E_FAULT;
            uint n = kvmUserRead!uint(arg);
            auto c = kvmCacheFor(vc, false);
            uint have = (c !is null) ? c.msrCount : 0;
            if (n > KVM_CACHE_MAX_MSRS) return E_BIG;
            if (!kvmUserOk(tid, arg, 8 + cast(ulong)n * 16, true)) return E_FAULT;
            // Fill what we have; unknown indices read back as 0 (honest:
            // the MSR was never programmed through us).
            foreach (i; 0 .. n) {
                uint idx = kvmUserRead!uint(arg + 8 + i*16);
                ulong data = 0;
                if (c !is null) {
                    foreach (j; 0 .. c.msrCount) {
                        if (c.msrs[j].index == idx) { data = c.msrs[j].data; break; }
                    }
                }
                kvmUserWrite!uint(arg + 8 + i*16 + 4, 0); // reserved
                kvmUserWrite!ulong(arg + 8 + i*16 + 8, data);
            }
            return cast(long)n;
        }
        case KVM_NMI: {
            vc.lapicSet = vc.lapicSet; // no-op marker: NMI queued when APIC lands
            return 0;
        }
        case KVM_SET_TSC_KHZ: {
            // arg is the kHz value itself (_IO, no pointer).
            if (arg == 0 || arg > 0xFFFF_FFFF) return E_INVAL;
            auto c = kvmCacheFor(vc, true);
            if (c is null) return E_NOMEM;
            c.tscKhz = cast(uint)arg;
            return 0;
        }
        case KVM_GET_TSC_KHZ: {
            // An explicit KVM_SET_TSC_KHZ wins; otherwise report the host TSC rate, as Linux does
            // (the guest reads the host TSC — no scaling).  -EIO only if the TSC is genuinely
            // uncalibrated.  Returning -EIO by default was fatal to Cloud Hypervisor: its "EIO =>
            // no TSC frequency" fallback never fires because kvm-ioctls builds the error from the
            // ioctl's -1 return value rather than errno, so CH saw "os error -1" and aborted VmBoot.
            auto c = kvmCacheFor(vc, false);
            uint khz = (c !is null) ? c.tscKhz : 0;
            if (khz == 0) khz = kvmHostTscKhz();
            return khz == 0 ? E_IO : cast(long)khz;
        }
        case KVM_GET_XSAVE: {
            if (!kvmUserOk(tid, arg, KvmXsave.sizeof, true)) return E_FAULT;
            auto x = kvmXsaveFor(vc, false);
            KvmXsave tmp;
            if (x !is null) tmp = *x;
            else {
                // Same reset defaults as the lazily-allocated page.
                foreach (i; 0 .. KvmXsave.sizeof) (cast(ubyte*)&tmp)[i] = 0;
                (cast(ushort*)&tmp)[0] = 0x37f;
                *cast(uint*)(cast(ubyte*)&tmp + 24) = 0x1f80;
            }
            kvmUserCopyOut(arg, &tmp, KvmXsave.sizeof);
            return 0;
        }
        case KVM_SET_XSAVE: {
            // Copy in, validate, THEN commit: this page is loaded by FXRSTOR64/XRSTOR64 in kernel
            // mode at the next entry, and a malformed image would #GP the kernel there.
            if (!kvmUserOk(tid, arg, KvmXsave.sizeof, false)) return E_FAULT;
            KvmXsave tmp;
            kvmUserCopyIn(&tmp, arg, KvmXsave.sizeof);
            if (!kvmFpuImageValid(cast(const(ubyte)*)&tmp)) return E_INVAL;
            auto x = kvmXsaveFor(vc, true);
            if (x is null) return E_NOMEM;
            *x = tmp;
            return 0;
        }
        case KVM_GET_XCRS: {
            if (!kvmUserOk(tid, arg, KvmXcrs.sizeof, true)) return E_FAULT;
            auto c = kvmCacheFor(vc, false);
            KvmXcrs x;
            foreach (i; 0 .. KvmXcrs.sizeof) (cast(ubyte*)&x)[i] = 0;
            if (c !is null && c.xcrsSet) {
                x.nrXcrs = 2;
                x.xcrs[0].xcr = 0; x.xcrs[0].value = c.xcrs[0];
                x.xcrs[1].xcr = 1; x.xcrs[1].value = c.xcrs[1];
            } else {
                // XCR0 reset value: x87 only.
                x.nrXcrs = 2;
                x.xcrs[0].xcr = 0; x.xcrs[0].value = 1;
                x.xcrs[1].xcr = 1; x.xcrs[1].value = 0;
            }
            kvmUserCopyOut(arg, &x, KvmXcrs.sizeof);
            return 0;
        }
        case KVM_SET_XCRS: {
            if (!kvmUserOk(tid, arg, KvmXcrs.sizeof, false)) return E_FAULT;
            KvmXcrs x;
            kvmUserCopyIn(&x, arg, KvmXcrs.sizeof);
            if (x.nrXcrs > 16) return E_INVAL;
            auto c = kvmCacheFor(vc, true);
            if (c is null) return E_NOMEM;
            c.xcrs[0] = 0; c.xcrs[1] = 0;
            foreach (i; 0 .. x.nrXcrs) {
                if (x.xcrs[i].xcr == 0) c.xcrs[0] = x.xcrs[i].value;
                else if (x.xcrs[i].xcr == 1) c.xcrs[1] = x.xcrs[i].value;
                else return E_INVAL; // unknown XCR
            }
            c.xcrsSet = true;
            return 0;
        }
        case KVM_GET_DEBUGREGS: {
            if (!kvmUserOk(tid, arg, KvmDebugregs.sizeof, true)) return E_FAULT;
            auto c = kvmCacheFor(vc, false);
            KvmDebugregs d;
            foreach (i; 0 .. KvmDebugregs.sizeof) (cast(ubyte*)&d)[i] = 0;
            if (c !is null && c.debugSet) {
                foreach (i; 0 .. 4) d.db[i] = c.dr[i];
                d.dr6 = c.dr6; d.dr7 = c.dr7;
            } else {
                d.dr6 = 0xFFFF0FF0; // DR6 reset value
            }
            kvmUserCopyOut(arg, &d, KvmDebugregs.sizeof);
            return 0;
        }
        case KVM_SET_DEBUGREGS: {
            if (!kvmUserOk(tid, arg, KvmDebugregs.sizeof, false)) return E_FAULT;
            KvmDebugregs d;
            kvmUserCopyIn(&d, arg, KvmDebugregs.sizeof);
            auto c = kvmCacheFor(vc, true);
            if (c is null) return E_NOMEM;
            foreach (i; 0 .. 4) c.dr[i] = d.db[i];
            c.dr6 = d.dr6; c.dr7 = d.dr7;
            c.debugSet = true;
            return 0;
        }
        default:
            return E_INVAL;
    }
}
