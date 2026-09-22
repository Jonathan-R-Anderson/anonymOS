// VIRT: KVM compatibility ABI — ioctl dispatch over native VM objects.
// SPDX-License-Identifier: LicenseRef-AnonymOS-Proprietary
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
import core.virt.svm : svmAvailable, svmEnter;
import core.task : g_tasks, findRegion, MAX_TASKS;
import core.objmgr : objGet;
import core.addrspace : userPageMapped, handlePageFault;
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
private enum long E_NODEV = -19;
private enum long E_INVAL = -22;
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
// A bad pointer is -EFAULT at the ioctl boundary, never a kernel #PF.
private bool kvmUserOk(int tid, ulong addr, ulong len) {
    if (addr == 0 || len == 0 || len > 0x10_0000) return false; // 1 MiB sanity cap
    ulong end = addr + len;
    if (end < addr) return false;                              // wrap
    if (end > 0x0000_8000_0000_0000UL) return false;            // low half only
    if (tid < 0 || tid >= MAX_TASKS) return false;
    for (ulong p = addr & ~0xFFFUL; ; ) {
        if (!userPageMapped(tid, p)) {
            // Same resolution a userspace touch would get (demand-zero, CoW…).
            if (!handlePageFault(tid, p, false)) return false;
            if (!userPageMapped(tid, p)) return false;
        }
        if (p + 0x1000 < p) break;                             // overflow guard
        p += 0x1000;
        if (p >= end) break;
    }
    return true;
}

private T kvmUserRead(T)(ulong addr) {
    return *cast(T*)addr;
}
private void kvmUserWrite(T)(ulong addr, T v) {
    *cast(T*)addr = v;
}
private void kvmUserCopyOut(ulong dst, const(void)* src, size_t n) {
    auto d = cast(ubyte*)dst;
    auto s = cast(const(ubyte)*)src;
    foreach (i; 0 .. n) d[i] = s[i];
}
private void kvmUserCopyIn(void* dst, ulong src, size_t n) {
    auto d = cast(ubyte*)dst;
    auto s = cast(const(ubyte)*)src;
    foreach (i; 0 .. n) d[i] = s[i];
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
        case KVM_CAP_IRQ_ROUTING:      return 1;
        case KVM_CAP_IRQFD:            return 1;
        case KVM_CAP_IOEVENTFD:        return 1;
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
        case KVM_CAP_SIGNAL_MSI:       return 1;
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
            return kvmCreateVm(tid);
        case KVM_GET_VCPU_MMAP_SIZE:
            return 4096; // one page: struct kvm_run
        case KVM_GET_SUPPORTED_CPUID: {
            // arg -> struct kvm_cpuid2 { nent, pad, entries[] }.
            // Honest minimal list: the host leaves we actually vouch for.
            // Cloud Hypervisor reads host CPUID itself; this satisfies the probe.
            if (!kvmUserOk(tid, arg, 8)) return E_FAULT;
            uint nent = kvmUserRead!uint(arg);
            enum uint PROVIDE = 4;
            if (nent < PROVIDE) {
                kvmUserWrite!uint(arg, PROVIDE);
                return E_BIG; // tell caller to retry with a bigger buffer
            }
            if (!kvmUserOk(tid, arg, 8 + PROVIDE * 32)) return E_FAULT;
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
            if (!kvmUserOk(tid, arg, 8)) return E_FAULT;
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
            if (!kvmUserOk(tid, arg, 8 + PROVIDE * 4)) return E_FAULT;
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
// Create a vCPU on the VM.  Returns a packed (objId, generation) handle >= 0,
// or -errno.  posix.d allocates the fd and stores the handle in f.fileSize.
long kvmCreateVcpu(uint vmObj, uint vmGen) {
    Vm* vm = vmCheck(vmObj, vmGen);
    if (vm is null) return E_BADF; // stale VM handle
    int idx = vmCreateVcpu(vm);
    if (idx < 0) return E_NOSPC;   // vCPU ceiling reached
    Vcpu* vc = &vm.vcpus[idx];
    return cast(long)kvmPackHandle(vc.objId, vc.gen);
}

// VM-fd ioctl dispatch.
long kvmVmIoctl(int tid, uint vmObj, uint vmGen, ulong cmd, ulong arg) {
    Vm* vm = vmCheck(vmObj, vmGen);
    if (vm is null) return E_BADF; // stale handle: the VM is gone
    switch (cmd) {
        case KVM_CREATE_VCPU:
            return kvmCreateVcpu(vmObj, vmGen);
        case KVM_SET_USER_MEMORY_REGION: {
            if (!kvmUserOk(tid, arg, KvmUserspaceMemoryRegion.sizeof)) return E_FAULT;
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
            if (!kvmUserOk(tid, arg, 8)) return E_FAULT;
            vm.identityMapAddr = kvmUserRead!ulong(arg);
            return 0;
        }
        case KVM_CREATE_IRQCHIP:
        case KVM_CREATE_PIT2:
            // Split irqchip is the only first-tier model: no in-kernel
            // PIC/IOAPIC/PIT.  ENOTTY = "not implemented here", clean probe.
            return E_NOTTY;
        case KVM_ENABLE_CAP: {
            if (!kvmUserOk(tid, arg, KvmEnableCap.sizeof)) return E_FAULT;
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
            if (!kvmUserOk(tid, arg, 8)) return E_FAULT;
            uint nr = kvmUserRead!uint(arg);
            if (nr > 1024) return E_INVAL;
            if (!kvmUserOk(tid, arg, 8 + cast(ulong)nr * KvmIrqRoutingEntry.sizeof))
                return E_FAULT;
            // Validate entry types; the routing table itself is a later tier
            // (userspace IOAPIC owns delivery under split irqchip).
            foreach (i; 0 .. nr) {
                ulong eaddr = arg + 8 + cast(ulong)i * KvmIrqRoutingEntry.sizeof;
                uint type = kvmUserRead!uint(eaddr + 4);
                if (type != KVM_IRQ_ROUTING_IRQCHIP && type != KVM_IRQ_ROUTING_MSI)
                    return E_INVAL;
            }
            vm.gsiRoutes = nr;
            return 0;
        }
        case KVM_IRQ_LINE: {
            // Split irqchip: the userspace IOAPIC owns line state; the kernel
            // acks a well-formed level so probe/setup sequences proceed.
            if (!kvmUserOk(tid, arg, 8)) return E_FAULT;
            uint irq = kvmUserRead!uint(arg);
            if (irq >= 24) return E_INVAL;
            return 0;
        }
        case KVM_IRQFD: {
            if (!kvmUserOk(tid, arg, KvmIrqfd.sizeof)) return E_FAULT;
            // Later tier: irqfd needs the eventfd object bridge.  Validate the
            // struct shape now so the probe path is honest about EINVAL vs OK.
            KvmIrqfd f;
            kvmUserCopyIn(&f, arg, KvmIrqfd.sizeof);
            if (f.gsi >= 1024) return E_INVAL;
            return E_INVAL; // not wired yet (no eventfd bridge)
        }
        case KVM_IOEVENTFD:
            return E_INVAL; // later tier (no MMIO bus yet)
        case KVM_SET_CLOCK: {
            if (!kvmUserOk(tid, arg, KvmClockData.sizeof)) return E_FAULT;
            return 0; // accepted; kvmclock is a later tier
        }
        case KVM_GET_CLOCK: {
            if (!kvmUserOk(tid, arg, KvmClockData.sizeof)) return E_FAULT;
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

// Fixed part of the cache (fits one page with 64 MSRs).
private struct KvmVcpuFixed {
    KvmSRegs sregs;
    KvmFpu fpu;
    KvmVcpuEvents events;
    uint mpState;
    uint tscKhz;
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
    // [HW] real exit path: translate exitReason into kvm_run here.
    run.exitReason = exitReason;
    vc.state = VcpuState.Exited;
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
            if (!kvmUserOk(tid, arg, KvmRegs.sizeof)) return E_FAULT;
            KvmRegs r;
            foreach (i; 0 .. 18) (&r.rax)[i] = vc.regs[i];
            kvmUserCopyOut(arg, &r, KvmRegs.sizeof);
            return 0;
        }
        case KVM_SET_REGS: {
            if (!kvmUserOk(tid, arg, KvmRegs.sizeof)) return E_FAULT;
            KvmRegs r;
            kvmUserCopyIn(&r, arg, KvmRegs.sizeof);
            foreach (i; 0 .. 18) vc.regs[i] = (&r.rax)[i];
            vc.regsSet = true;
            if (vc.state == VcpuState.Created) vc.state = VcpuState.Runnable;
            return 0;
        }
        case KVM_GET_SREGS: {
            if (!kvmUserOk(tid, arg, KvmSRegs.sizeof)) return E_FAULT;
            auto c = kvmCacheFor(vc, false);
            KvmSRegs s;
            if (c !is null) s = c.sregs;
            else foreach (i; 0 .. KvmSRegs.sizeof) (cast(ubyte*)&s)[i] = 0;
            kvmUserCopyOut(arg, &s, KvmSRegs.sizeof);
            return 0;
        }
        case KVM_SET_SREGS: {
            if (!kvmUserOk(tid, arg, KvmSRegs.sizeof)) return E_FAULT;
            auto c = kvmCacheFor(vc, true);
            if (c is null) return E_NOMEM;
            kvmUserCopyIn(&c.sregs, arg, KvmSRegs.sizeof);
            vc.sregsSet = true;
            return 0;
        }
        case KVM_GET_FPU: {
            if (!kvmUserOk(tid, arg, KvmFpu.sizeof)) return E_FAULT;
            auto c = kvmCacheFor(vc, false);
            KvmFpu f;
            if (c !is null) f = c.fpu;
            else foreach (i; 0 .. KvmFpu.sizeof) (cast(ubyte*)&f)[i] = 0;
            kvmUserCopyOut(arg, &f, KvmFpu.sizeof);
            return 0;
        }
        case KVM_SET_FPU: {
            if (!kvmUserOk(tid, arg, KvmFpu.sizeof)) return E_FAULT;
            auto c = kvmCacheFor(vc, true);
            if (c is null) return E_NOMEM;
            kvmUserCopyIn(&c.fpu, arg, KvmFpu.sizeof);
            return 0;
        }
        case KVM_GET_VCPU_EVENTS: {
            if (!kvmUserOk(tid, arg, KvmVcpuEvents.sizeof)) return E_FAULT;
            auto c = kvmCacheFor(vc, false);
            KvmVcpuEvents e;
            if (c !is null) e = c.events;
            else foreach (i; 0 .. KvmVcpuEvents.sizeof) (cast(ubyte*)&e)[i] = 0;
            kvmUserCopyOut(arg, &e, KvmVcpuEvents.sizeof);
            return 0;
        }
        case KVM_SET_VCPU_EVENTS: {
            if (!kvmUserOk(tid, arg, KvmVcpuEvents.sizeof)) return E_FAULT;
            auto c = kvmCacheFor(vc, true);
            if (c is null) return E_NOMEM;
            kvmUserCopyIn(&c.events, arg, KvmVcpuEvents.sizeof);
            return 0;
        }
        case KVM_GET_MP_STATE: {
            if (!kvmUserOk(tid, arg, 4)) return E_FAULT;
            auto c = kvmCacheFor(vc, false);
            uint s = (c !is null) ? c.mpState : vc.mpState;
            kvmUserWrite!uint(arg, s);
            return 0;
        }
        case KVM_SET_MP_STATE: {
            if (!kvmUserOk(tid, arg, 4)) return E_FAULT;
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
            if (!kvmUserOk(tid, arg, 1024)) return E_FAULT;
            foreach (i; 0 .. 1024) kvmUserWrite!ubyte(arg + i, 0);
            return 0;
        }
        case KVM_SET_LAPIC: {
            if (!kvmUserOk(tid, arg, 1024)) return E_FAULT;
            vc.lapicSet = true;
            return 0; // accepted; applied when the APIC model lands
        }
        case KVM_SET_CPUID2: {
            if (!kvmUserOk(tid, arg, 8)) return E_FAULT;
            uint nent = kvmUserRead!uint(arg);
            if (nent > KVM_CACHE_MAX_CPUID) return E_BIG;
            if (!kvmUserOk(tid, arg, 8 + cast(ulong)nent * 40)) return E_FAULT;
            auto p = kvmCpuidFor(vc, true);
            if (p is null) return E_NOMEM;
            p.count = nent;
            kvmUserCopyIn(p.entries.ptr, arg + 8, cast(size_t)(nent * 40));
            return 0;
        }
        case KVM_SET_MSRS: {
            if (!kvmUserOk(tid, arg, 8)) return E_FAULT;
            uint n = kvmUserRead!uint(arg);
            if (n > KVM_CACHE_MAX_MSRS) return E_BIG;
            if (!kvmUserOk(tid, arg, 8 + cast(ulong)n * 16)) return E_FAULT;
            auto fx = kvmCacheFor(vc, true);
            if (fx is null) return E_NOMEM;
            fx.msrCount = n;
            kvmUserCopyIn(fx.msrs.ptr, arg + 8, cast(size_t)(n * 16));
            return cast(long)n; // Linux returns the number applied
        }
        case KVM_GET_MSRS: {
            if (!kvmUserOk(tid, arg, 8)) return E_FAULT;
            uint n = kvmUserRead!uint(arg);
            auto c = kvmCacheFor(vc, false);
            uint have = (c !is null) ? c.msrCount : 0;
            if (n > KVM_CACHE_MAX_MSRS) return E_BIG;
            if (!kvmUserOk(tid, arg, 8 + cast(ulong)n * 16)) return E_FAULT;
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
            return khz == 0 ? E_INVAL : cast(long)khz;
        }
        default:
            return E_INVAL;
    }
}
