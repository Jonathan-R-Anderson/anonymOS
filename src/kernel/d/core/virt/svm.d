// VIRT: AMD SVM detection backend — fail-closed, no execution path yet.
// SPDX-License-Identifier: LicenseRef-AnonymOS-Proprietary
//
// anonymOS is its own OS: the kernel owns the privileged virtualization
// substrate.  This module detects AMD SVM (CPUID.8000_0001:ECX[2]) and reports
// availability to the KVM compatibility layer.  Actual VMRUN-based guest entry
// is a LATER TIER: this file deliberately contains no VMRUN, no VMCB layout,
// no NPT code.  Claiming SVM support without a verified execution path would
// be a fake-hardware claim; `svmAvailable()` gates everything behind the real
// CPUID bit and `svmEnter()` fails closed with ENODEV until the backend lands.
//
// Tier roadmap (NOT implemented here):
//   1. VMCB layout + physical allocation, ASID management
//   2. NPT builder (mirrors core.virt.ept, different encodings)
//   3. VMRUN/#VMEXIT handler with the same exit-reason ABI as VMX
// Until then every SVM ioctl surface reports "not available".
module core.virt.svm;

extern (C) @nogc nothrow:

// --- detection --------------------------------------------------------------

private uint x64CpuidExtEcx() {
    uint v;
    asm @nogc nothrow {
        push RBX;
        mov EAX, 0x80000001;
        cpuid;
        mov v, ECX;
        pop RBX;
    }
    return v;
}

// True only when the CPU actually reports SVM (CPUID.8000_0001:ECX[2]).
// Pure CPUID read: safe to call anywhere, never enables anything.
bool svmHwPresent() {
    return (x64CpuidExtEcx() & (1u << 2)) != 0;
}

// Fail-closed availability: hardware present AND the kernel SVM backend
// compiled in.  The backend is not compiled in yet (SVM_BACKEND_READY=false),
// so this is always false for now — every SVM guest-entry attempt fails closed
// at the KVM layer.  Detection stays honest: svmHwPresent() reports the real
// CPUID bit independently of backend readiness.
private enum bool SVM_BACKEND_READY = false; // set true when the VMRUN path lands
bool svmAvailable() {
    return SVM_BACKEND_READY && svmHwPresent();
}

// --- stubs (fail closed, never fake) -----------------------------------------

// Attempt guest entry on the SVM path.  Always ENODEV until the VMRUN backend
// exists.  The KVM layer translates this into "hardware unavailable".
int svmEnter(uint /*vmGen*/) {
    return -19; // ENODEV (see core.virt.kvm.KvmIoctlErr)
}
