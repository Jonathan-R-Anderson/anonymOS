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
import core.virt.vmx : vmxIsReady, vmxEnter, VMX_NOHW;
import core.virt.vmexit : vmxDispatchExit, VmExitInfo, VmExitAction,
    vmxValidateSRegs, vmxValidateRegs, vmxValidateMsrs;
import core.virt.svm : svmAvailable, svmEnter;
import core.task : g_tasks, findRegion, MAX_TASKS;
import core.objmgr : objGet;
import core.addrspace : userPageMapped, userPageWritable, handlePageFault;
import core.exports : phys_to_virt;
import core.cap : CAP_RIGHT_VM_CREATE, CAP_RIGHT_VM_MEM,
                  CAP_RIGHT_VM_RUN, CAP_RIGHT_VM_CONTROL;
import core.io : klog, klog_hex;
import memory.mm : alloc_phys_page, free_phys_page;

extern (C) @nogc nothrow:

// --- errno (negative returns, Linux numbers) --------------------------------
private enum long E_OK    = 0;
private enum long E_PERM  = -1;
private enum long E_NOENT = -2;
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
                case KVM_IRQFD:              return CAP_RIGHT_VM_CONTROL;
                case KVM_IOEVENTFD:          return CAP_RIGHT_VM_CONTROL;
                case KVM_SET_CLOCK:          return CAP_RIGHT_VM_CONTROL;
                case KVM_GET_CLOCK:          return CAP_RIGHT_VM_CONTROL;
                case KVM_ENABLE_CAP:         return CAP_RIGHT_VM_CONTROL;
                case KVM_GET_DIRTY_LOG:      return CAP_RIGHT_VM_CONTROL;
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
        case KVM_CAP_IRQ_ROUTING:      return 0; // routing stored, but no
        case KVM_CAP_IRQFD:            return 0; // interrupt/eventfd delivery
        case KVM_CAP_IOEVENTFD:        return 0; // not yet implemented — fail
                                                     // fast rather than claim
                                                     // and hang.  Split-irqchip
                                                     // delivery is the next tier.
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
        case KVM_CAP_SIGNAL_MSI:       return 0; // not used by any VMM we target
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
    uint objId = vmAlloc(); // uses g_current_task_id
    if (objId == 0) return E_NOSPC; // VM ceiling reached
    auto h = objGet(objId);
    if (h is null) return E_NOENT;
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
            // arg -> struct kvm_cpuid2 { nent, pad, entries[] }.
            // Honest minimal list: the host leaves we actually vouch for.
            // Cloud Hypervisor reads host CPUID itself; this satisfies the probe.
            if (!kvmUserOk(tid, arg, 8, true)) return E_FAULT;
            uint nent = kvmUserRead!uint(arg);
            enum uint PROVIDE = 4;
            if (nent < PROVIDE) {
                kvmUserWrite!uint(arg, PROVIDE);
                return E_BIG; // tell caller to retry with a bigger buffer
            }
            if (!kvmUserOk(tid, arg, 8 + PROVIDE * 32, true)) return E_FAULT;
            kvmUserWrite!uint(arg, PROVIDE);
            kvmUserWrite!uint(arg + 4, 0);
            // Leaf 0: max basic leaf + vendor.  Leaf 1: feature flags with the
            // VMX bit (ECX[5]) reflecting REAL hardware, never faked.
            static immutable uint[8][4] leaves = [
                [0x00000000, 0x00000001, 0x00000000, 0, 0,0,0,0],
                [0x00000001, 0x00000000, 0x00000000, 0, 0,0,0,0],
                [0x80000000, 0x80000001, 0x00000000, 0, 0,0,0,0],
                [0x80000001, 0x00000000, 0x00000000, 0, 0,0,0,0],
            ];
            // Fill feature words from the real CPUID at call time (see below).
            ulong base = arg + 8;
            foreach (i; 0 .. PROVIDE) {
                kvmUserWrite!uint(base + i*32 + 0, leaves[i][0]);
                kvmUserWrite!uint(base + i*32 + 4, leaves[i][1]);
                kvmUserWrite!uint(base + i*32 + 8, 0);
                foreach (j; 0 .. 5) kvmUserWrite!uint(base + i*32 + 12 + j*4, 0);
            }
            kvmFillCpuidFeatures(base);
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

// Fill the feature words of the 4 CPUID leaves written above from the REAL
// host CPUID.  Never claims VMX/SVM the hardware lacks.
private void kvmFillCpuidFeatures(ulong base) {
    uint eax, ebx, ecx, edx;
    // Leaf 1: EAX=1
    asm @nogc nothrow {
        push RBX;
        mov EAX, 1;
        cpuid;
        mov eax, EAX; mov ebx, EBX; mov ecx, ECX; mov edx, EDX;
        pop RBX;
    }
    // entry 1 (leaf 1): eax..edx at +32
    kvmUserWrite!uint(base + 32 + 12, eax);
    kvmUserWrite!uint(base + 32 + 16, ebx);
    kvmUserWrite!uint(base + 32 + 20, ecx);
    kvmUserWrite!uint(base + 32 + 24, edx);
    // Leaf 0x80000001
    asm @nogc nothrow {
        push RBX;
        mov EAX, 0x80000001;
        cpuid;
        mov eax, EAX; mov ebx, EBX; mov ecx, ECX; mov edx, EDX;
        pop RBX;
    }
    // entry 3 (leaf 0x80000001): at +96
    kvmUserWrite!uint(base + 96 + 12, eax);
    kvmUserWrite!uint(base + 96 + 16, ebx);
    kvmUserWrite!uint(base + 96 + 20, ecx);
    kvmUserWrite!uint(base + 96 + 24, edx);
    // Vendor string for leaf 0 (entry 0): copy EBX/EDX/ECX from real CPUID.0
    asm @nogc nothrow {
        push RBX;
        mov EAX, 0;
        cpuid;
        mov eax, EAX; mov ebx, EBX; mov ecx, ECX; mov edx, EDX;
        pop RBX;
    }
    kvmUserWrite!uint(base + 12, eax); // max basic leaf
    kvmUserWrite!uint(base + 16, ebx);
    kvmUserWrite!uint(base + 20, edx);
    kvmUserWrite!uint(base + 24, ecx);
    // Max extended leaf for entry 2 (leaf 0x80000000)
    asm @nogc nothrow {
        push RBX;
        mov EAX, 0x80000000;
        cpuid;
        mov eax, EAX;
        pop RBX;
    }
    kvmUserWrite!uint(base + 64 + 12, eax);
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
            if (c.cap == KVM_CAP_SPLIT_IRQCHIP) {
                if (c.args[0] > 24) return E_INVAL;
                vm.splitIrqchip = true;
                return 0;
            }
            if (c.cap == KVM_CAP_DISABLE_QUIRKS) return E_INVAL; // not implemented
            return E_INVAL;
        }
        case KVM_SET_GSI_ROUTING: {
            // Not yet: routing without delivery is a fake claim.  The GSI
            // table structs stay (the delivery tier consumes them); the
            // ioctl fails fast until interrupt injection exists.
            return E_NOTTY;
        }
        case KVM_IRQ_LINE: {
            // Not yet: acking without LAPIC injection would hang guests.
            // Fail fast until the delivery backend exists.
            return E_NOTTY;
        }
        case KVM_IRQFD: {
            // Not yet: no eventfd bridge, no injection.  Fail fast.
            return E_NOTTY;
        }
        case KVM_IOEVENTFD: {
            // Not yet: no MMIO-bus matching without the exit backend.
            // Fail fast.
            return E_NOTTY;
        }
        case KVM_SET_CLOCK: {
            if (!kvmUserOk(tid, arg, KvmClockData.sizeof, false)) return E_FAULT;
            return 0; // accepted; kvmclock is a later tier
        }
        case KVM_GET_CLOCK: {
            if (!kvmUserOk(tid, arg, KvmClockData.sizeof, true)) return E_FAULT;
            KvmClockData c;
            // Zeroed clock: honest "no kvmclock" rather than fake timestamps.
            foreach (i; 0 .. KvmClockData.sizeof) (cast(ubyte*)&c)[i] = 0;
            kvmUserCopyOut(arg, &c, KvmClockData.sizeof);
            return 0;
        }
        case KVM_GET_DIRTY_LOG:
            return E_INVAL; // no dirty tracking yet (later tier)
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
private KvmXsave* kvmXsaveFor(Vcpu* vc, bool create) {
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

// Fixed part of the cache (fits one page with 64 MSRs).
private struct KvmVcpuFixed {
    KvmSRegs sregs;
    KvmFpu fpu;
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
// has to fill in the backend call.
long kvmVcpuRun(int tid, uint vcpuObj, uint vcpuGen) {
    Vcpu* vc = vcpuCheckObj(vcpuObj, vcpuGen);
    if (vc is null) return E_BADF; // stale vCPU handle
    Vm* vm = vmCheck(vc.vmObj, vc.vmGen);
    if (vm is null) return E_NODEV; // parent VM gone
    if (vc.state != VcpuState.Created && vc.state != VcpuState.Runnable)
        return E_INVAL; // Running re-entry or Exited/Dead
    if (vc.runPhys == 0) return E_NODEV;

    KvmRun* run = cast(KvmRun*)phys_to_virt(vc.runPhys);
    // immediate_exit: userspace asked for an immediate KVM_EXIT_INTR.
    if (run.immediateExit != 0) {
        run.immediateExit = 0;
        run.exitReason = KVM_EXIT_INTR;
        return 0;
    }

    vc.state = VcpuState.Running;
    uint exitReason = 0;
    int rc;
    if (vmxIsReady())
        rc = vmxEnter(vm.objId, vm.gen, vc.index, &exitReason);
    else if (svmAvailable())
        rc = svmEnter(vm.gen);
    else
        rc = VMX_NOHW; // -ENODEV: no virtualization hardware

    if (rc == VMX_NOHW) {
        // Fail-soft: back out to Runnable, no exit reason written (we never
        // entered).  The VMM sees -ENODEV, exactly like Linux without /dev/kvm.
        vc.state = VcpuState.Runnable;
        return E_NODEV;
    }
    // Real exit path: the backend filled exitReason (+ qualification/GPA in
    // the [HW] phase); the HW-pure dispatcher populates struct kvm_run.
    VmExitInfo xi;
    xi.reason = exitReason;
    xi.qual   = 0;
    xi.gpa    = 0;
    xi.data   = 0;
    xi.count  = 0;
    // [HW]: vmxEnter extracts qual/gpa/data/count from the VMCS and guest
    // registers before returning.  Until then only synthetic exits flow here.
    VmExitAction act = vmxDispatchExit(xi, run, vm, vc);
    if (act == VmExitAction.VmContained)
        return E_IO; // contained failure; VM is Dying, never re-entered
    return 0;
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
            if (vmxValidateRegs(&r) != 0) return E_INVAL; // non-canonical RIP etc.
            foreach (i; 0 .. 18) vc.regs[i] = (&r.rax)[i];
            vc.regsSet = true;
            if (vc.state == VcpuState.Created) vc.state = VcpuState.Runnable;
            return 0;
        }
        case KVM_GET_SREGS: {
            if (!kvmUserOk(tid, arg, KvmSRegs.sizeof, true)) return E_FAULT;
            auto c = kvmCacheFor(vc, false);
            KvmSRegs s;
            if (c !is null) s = c.sregs;
            else foreach (i; 0 .. KvmSRegs.sizeof) (cast(ubyte*)&s)[i] = 0;
            kvmUserCopyOut(arg, &s, KvmSRegs.sizeof);
            return 0;
        }
        case KVM_SET_SREGS: {
            if (!kvmUserOk(tid, arg, KvmSRegs.sizeof, false)) return E_FAULT;
            KvmSRegs tmp;
            kvmUserCopyIn(&tmp, arg, KvmSRegs.sizeof);
            // Validate BEFORE committing: hostile control state (VMX/SMX in
            // guest CR4, non-canonical EFER, bad CR0/CR3/CR8) is rejected.
            if (vmxValidateSRegs(&tmp) != 0) return E_INVAL;
            auto c = kvmCacheFor(vc, true);
            if (c is null) return E_NOMEM;
            c.sregs = tmp;
            vc.sregsSet = true;
            return 0;
        }
        case KVM_GET_FPU: {
            if (!kvmUserOk(tid, arg, KvmFpu.sizeof, true)) return E_FAULT;
            auto c = kvmCacheFor(vc, false);
            KvmFpu f;
            if (c !is null) f = c.fpu;
            else foreach (i; 0 .. KvmFpu.sizeof) (cast(ubyte*)&f)[i] = 0;
            kvmUserCopyOut(arg, &f, KvmFpu.sizeof);
            return 0;
        }
        case KVM_SET_FPU: {
            if (!kvmUserOk(tid, arg, KvmFpu.sizeof, false)) return E_FAULT;
            auto c = kvmCacheFor(vc, true);
            if (c is null) return E_NOMEM;
            kvmUserCopyIn(&c.fpu, arg, KvmFpu.sizeof);
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
            if (vmxValidateMsrs(n ? tmp.ptr : null, n) != 0) return E_INVAL;
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
            auto c = kvmCacheFor(vc, false);
            uint khz = (c !is null) ? c.tscKhz : 0;
            // Linux returns -EIO when the TSC frequency is unknown; Cloud
            // Hypervisor treats EIO as "no TSC frequency", not fatal.
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
            if (!kvmUserOk(tid, arg, KvmXsave.sizeof, false)) return E_FAULT;
            auto x = kvmXsaveFor(vc, true);
            if (x is null) return E_NOMEM;
            kvmUserCopyIn(x, arg, KvmXsave.sizeof);
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
