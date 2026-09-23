// virt backend — vendor-neutral dispatch over Intel VMX / AMD SVM.
//
// This module is the single decision point for "which hardware backend runs
// this guest".  Detection is by CPU vendor (CPUID.0); readiness is per
// backend (vmxIsReady / svmAvailable).  All guest entry flows through
// virtEnter(), which validates guest state ONCE (common rules in
// core.virt.vmexit) and then calls the active backend's narrow entry
// wrapper.  The backend programs its own control structure (VMCS / VMCB),
// executes the single entry instruction (VMLAUNCH/VMRESUME / VMRUN),
// decodes the hardware exit into a VirtExitInfo, and returns.
//
// Fail-closed is structural: if no backend is available, virtEnter returns
// -ENODEV before touching any hardware.  A backend that is detected but
// not initialized (e.g. VMXON failed, firmware-locked SVM) also returns
// -ENODEV from its own entry wrapper — never a synthetic success.
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.backend;

import core.virt.vm : Vm, Vcpu;
import core.virt.vmx : vmxBootInit, vmxCpuInit, vmxIsReady, vmxEnter,
    vmxDecodeExit;
import core.virt.svm : svmBootInit, svmCpuInit, svmAvailable, svmEnter,
    svmDecodeExit;
import core.virt.vmexit : VirtExitInfo, virtValidateGuestState;
import core.virt.slat : slatRootPhys;
import core.virt.kvmabi : KvmRegs, KvmSRegs, KvmMsrEntry;
import core.io : klog;

extern (C) @nogc nothrow:

enum VirtBackendKind : ubyte {
    None = 0, // no recognized virtualization hardware
    Vmx  = 1, // Intel VMX (VMCS / EPT / VMLAUNCH)
    Svm  = 2, // AMD SVM (VMCB / NPT / VMRUN)
}

private void cpuid0(out uint ebx, out uint edx, out uint ecx) {
    uint a;
    asm @nogc nothrow {
        mov EAX, 0;
        cpuid;
        mov a, EAX;
        mov ebx, EBX;
        mov edx, EDX;
        mov ecx, ECX;
    }
}

private bool cpuIsAmd() {
    uint ebx, edx, ecx;
    cpuid0(ebx, edx, ecx);
    // "AuthenticAMD" in EBX,EDX,ECX order.
    return ebx == 0x68747541 && edx == 0x69746e65 && ecx == 0x444d4163;
}

private bool cpuIsIntel() {
    uint ebx, edx, ecx;
    cpuid0(ebx, edx, ecx);
    // "GenuineIntel" in EBX,EDX,ECX order.
    return ebx == 0x756e6547 && edx == 0x49656e69 && ecx == 0x6c65746e;
}

// The hardware backend for THIS machine.  Pure detection — does not imply
// the backend is initialized or usable (see virtBackendAvailable).
// Unknown vendors -> None (fail closed): never assume VMX.
public VirtBackendKind virtBackendKind() {
    if (cpuIsAmd()) return VirtBackendKind.Svm;
    if (cpuIsIntel()) return VirtBackendKind.Vmx;
    return VirtBackendKind.None;
}

// True when the active backend finished per-CPU initialization and can
// actually enter a guest.
public bool virtBackendAvailable() {
    auto k = virtBackendKind();
    if (k == VirtBackendKind.Svm) return svmAvailable();
    if (k == VirtBackendKind.Vmx) return vmxIsReady();
    return false;
}

// Boot-time initialization of the active backend (BSP).  Called once from
// kernel_main before the VMM selftest.  Never touches the *other* vendor's
// MSRs/instructions: on AMD hardware no VMX MSR is ever read, on Intel
// hardware no SVM MSR is ever read.
public void virtBootInit() {
    auto k = virtBackendKind();
    if (k == VirtBackendKind.Svm) {
        svmBootInit();
    } else if (k == VirtBackendKind.Vmx) {
        vmxBootInit();
    }
    klog("[virt] backend=");
    klog(k == VirtBackendKind.Svm ? "svm" : k == VirtBackendKind.Vmx ? "vmx" : "none");
    klog(" available=");
    klog(virtBackendAvailable() ? "yes\n" : "no\n");
}

// Per-CPU initialization for application processors.  The active backend
// enables itself on the calling CPU (VMXON / EFER.SVME + HSAVE + VMCB
// area).  Must be called with the target CPU executing this code.
public void virtCpuInit(uint cpuId) {
    auto k = virtBackendKind();
    if (k == VirtBackendKind.Svm) svmCpuInit(cpuId);
    else if (k == VirtBackendKind.Vmx) vmxCpuInit(cpuId);
}

// Enter the guest once.  On return:
//   0  -> *xi holds the decoded vendor-neutral exit (caller dispatches it
//         via virtDispatchExit and populates kvm_run)
//   <0 -> entry failed; *xi is undefined.  -ENODEV = backend not ready,
//         -EINVAL = bad guest state or misconfigured VM.
public int virtEnter(Vm* vm, Vcpu* vc, KvmRegs* regs, const KvmSRegs* sregs,
                     const KvmMsrEntry* msrs, uint nmsrs, VirtExitInfo* xi) {
    if (vm is null || vc is null || xi is null) return -22; // -EINVAL
    int rc = virtValidateGuestState(regs, sregs, msrs, nmsrs);
    if (rc != 0) return rc;
    return virtEnterBackend(vm, vc, regs, sregs, xi);
}

private int virtEnterBackend(Vm* vm, Vcpu* vc, KvmRegs* regs,
                             const KvmSRegs* sregs, VirtExitInfo* xi) {
    if (slatRootPhys(&vm.slat) == 0)
        return -22; // -EINVAL: VM has no registered memory
    auto k = virtBackendKind();
    if (k == VirtBackendKind.Svm)
        return svmEnter(vm, vc, regs, sregs, xi);
    if (k == VirtBackendKind.Vmx)
        return vmxEnter(vm, vc, regs, sregs, xi);
    return -19; // -ENODEV
}
