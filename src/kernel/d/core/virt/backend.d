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

import core.virt.vm : Vm, Vcpu, VIRT_MAX_CPUS;
import core.virt.vmx : vmxBootInit, vmxCpuInit, vmxIsReady, vmxEnter,
    vmxDecodeExit, vmxCapProbe, vmxReleaseVmcs;
import core.virt.svm : svmBootInit, svmCpuInit, svmAvailable, svmEnter,
    svmDecodeExit;
import core.virt.vmexit : VirtExitInfo, virtValidateGuestState;
import core.virt.slat : slatRootPhys;
import core.virt.kvmabi : KvmRegs, KvmSRegs, KvmMsrEntry;
import core.io : klog;
import core.exports : phys_to_virt;
import memory.mm : alloc_phys_page, free_phys_page;

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

// True when the active backend can actually enter a guest.  (VMX: in VMX
// operation, or enable-able lazily by the next vmxEnter — see vmxIsReady.)
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
    // BOOT-HANG FIX (2026-09-27): do NOT enable the backend (VMXON / EFER.SVME) at boot.
    // Enabling it here bricks the boot before the desktop comes up: VMXON hangs under some
    // nested-virt hypervisors (observed on VirtualBox), and svmCpuInit on a CPU that reports
    // AuthenticAMD without real SVM (QEMU's qemu64) faults.  "Fail-soft" only covers a clean
    // VMXON/VMRUN failure, not a hang.  Guest entry (vmxEnter/svmEnter) is not implemented yet,
    // so boot-time enablement provides NO capability today — KVM_RUN is -ENODEV either way.
    // When guest entry lands, enable the backend LAZILY on first VM creation (with proper
    // fault handling), not unconditionally at boot.  Detection + honest logging only here.
    klog("[virt] backend=");
    klog(k == VirtBackendKind.Svm ? "svm" : k == VirtBackendKind.Vmx ? "vmx" : "none");
    klog("; boot-time enable deferred (guest-entry not yet implemented)\n");
    // Report the VMX capability set so we know whether this environment exposes the EPT that guest
    // entry requires (nested hypervisors may withhold it).  Detection-only; no VMXON.
    if (k == VirtBackendKind.Vmx) vmxCapProbe();
}

// Per-CPU initialization for application processors.  The active backend
// enables itself on the calling CPU (VMXON / EFER.SVME + HSAVE + VMCB
// area).  Must be called with the target CPU executing this code.
public void virtCpuInit(uint cpuId) {
    // BOOT-HANG FIX (2026-09-27): the APs must not VMXON / enable SVME at boot either — the same
    // hang that bricks the BSP in virtBootInit applies per-AP here (apKernelLoopBody).  No-op until
    // per-CPU enablement is wired lazily alongside guest entry.  (svmCpuInit/vmxCpuInit remain for
    // that future path.)
    cast(void) cpuId;
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

// Release a vCPU's backend control page (VMCS on VMX, VMCB on SVM) before vm.d frees it.
// VMX: VMCLEAR it first (vmxReleaseVmcs) — an active VMCS can be written back to its region after
// the page was reused.  SVM keeps no cached-current control state.  Returns true when the page may
// be freed (false = keep/leak it rather than risk that write-back).
public bool virtReleaseCtrl(ulong phys) {
    if (phys == 0) return true;
    if (virtBackendKind() == VirtBackendKind.Vmx) return vmxReleaseVmcs(phys);
    return true;
}

// ---------------------------------------------------------------------------
// Guest/host FPU switch — shared by the VMX and SVM entry wrappers.
// ---------------------------------------------------------------------------
// Neither VMLAUNCH/VMRESUME nor VMRUN switches x87/SSE/AVX state: without a switch the guest runs
// on whatever FPU contents the KVM_RUN syscall had live (kernel SSE temporaries), loses its own at
// every exit, and can leave e.g. an unmasked MXCSR behind for host SSE code.  Each entry wrapper
// therefore, ADJACENT to the entry instruction (no compiled, SSE-using code in between), saves the
// host image into a per-CPU page, loads the vCPU's image, and after the exit saves the guest's back
// and restores the host's.  The vCPU image is the per-vCPU XSAVE page (core.virt.kvm kvmXsaveFor /
// Vcpu.xsavePhys): KVM_SET_FPU/SET_XSAVE write it and KVM_GET_FPU/GET_XSAVE read it, so it is the
// one source of truth and Vcpu does not grow.  Both pages are page-aligned (FXSAVE needs 16 B,
// XSAVE 64 B) and start zeroed (XSAVE never writes XCOMP_BV / the reserved header bytes).
enum ulong VIRT_FPU_UNSUPPORTED = ulong.max;

private __gshared ulong g_virtFpuMask = 0;
private __gshared bool  g_virtFpuMaskProbed = false;
private __gshared uint  g_virtMxcsrMask = 0;                 // 0 = not probed yet
private __gshared ulong[VIRT_MAX_CPUS] g_virtHostFpuPhys;    // per-CPU host save page (0 = none yet)

private ulong virtReadCR4() {
    ulong v;
    asm @nogc nothrow { mov RAX, CR4; mov v, RAX; }
    return v;
}

private ulong virtXgetbv0() {
    uint lo, hi;
    asm @nogc nothrow {
        xor ECX, ECX;
        db 0x0F; db 0x01; db 0xD0;              // XGETBV (XCR0 -> EDX:EAX)
        mov lo, EAX;
        mov hi, EDX;
    }
    return (cast(ulong)hi << 32) | lo;
}

// CPUID.(EAX=0DH,ECX=0):EBX — size of the standard-form XSAVE area for the features XCR0 enables.
private uint virtXsaveAreaSize() {
    pragma(inline, false);                      // same LDC inline-asm caution as vmx.d x64Cpuid
    uint a, b, c, d;                            // all four named: cpuid writes EAX..EDX
    asm @nogc nothrow {
        mov EAX, 0xD;
        xor ECX, ECX;
        cpuid;
        mov a, EAX;
        mov b, EBX;
        mov c, ECX;
        mov d, EDX;
    }
    return b;
}

// The switch form, probed once: 0 => FXSAVE64/FXRSTOR64 (x87 + SSE + MXCSR).  That is ALL the FPU
// state a guest can have while the host leaves CR4.OSXSAVE clear (XSAVE then #UDs, XCR0 stays
// x87-only and a guest XSETBV exits).  With CR4.OSXSAVE set: the live XCR0 as the XSAVE64/XRSTOR64
// RFBM, provided XCR0 manages x87+SSE and its standard-form area fits the 4 KiB vCPU image (an
// x87-only XCR0 keeps the FXSAVE form); otherwise VIRT_FPU_UNSUPPORTED (fail closed — never a
// partial switch that leaves AVX/AMX state shared with the host).  XCR0 itself is not switched (on
// VMX a guest XSETBV exits unconditionally and is not emulated).
public ulong virtFpuXsaveMask() {
    if (g_virtFpuMaskProbed) return g_virtFpuMask;
    ulong m = 0;
    if ((virtReadCR4() & (1UL << 18)) != 0) {                // CR4.OSXSAVE
        const ulong xcr0 = virtXgetbv0();
        const uint size = virtXsaveAreaSize();
        if (xcr0 == 1) m = 0;                                // x87-only XCR0: FXSAVE covers x87+SSE
        else if ((xcr0 & 3) == 3 && size != 0 && size <= 4096) m = xcr0;
        else {
            m = VIRT_FPU_UNSUPPORTED;
            klog("[virt] host XSAVE layout unsupported by the 4 KiB vCPU FPU image — guest entry refused\n");
        }
    }
    g_virtFpuMask = m;
    g_virtFpuMaskProbed = true;
    return m;
}

// MXCSR bits the CPU accepts (FXSAVE image offset 28; 0 there means the default 0xFFBF).  A value
// with other bits set makes FXRSTOR/XRSTOR #GP — in kernel mode, at the next entry — so
// KVM_SET_FPU/SET_XSAVE reject it up front.
public uint virtFpuMxcsrMask() {
    if (g_virtMxcsrMask != 0) return g_virtMxcsrMask;
    const ulong p = alloc_phys_page();
    if (p == 0) return 0xFFBF;                               // conservative default; re-probe later
    ubyte* b = cast(ubyte*)phys_to_virt(p);
    foreach (i; 0 .. 512) b[i] = 0;
    asm @nogc nothrow {
        mov RCX, b;
        db 0x48; db 0x0F; db 0xAE; db 0x01;                  // FXSAVE64 [RCX]
    }
    uint m = *cast(uint*)(b + 28);
    free_phys_page(p);
    if (m == 0) m = 0xFFBF;
    g_virtMxcsrMask = m;
    return m;
}

// Resolve the FPU-switch operands for one entry on `cpuId`: the XSAVE RFBM (0 = FXSAVE64 form) and
// the VIRTUAL addresses of the per-CPU host save page and the vCPU's image (allocated on demand).
// False = refuse the entry (allocation failure, or a host XSAVE layout the image cannot hold).
public bool virtFpuPrepare(Vcpu* vc, uint cpuId, out ulong mask, out ulong hostVa, out ulong guestVa) {
    import core.virt.kvm : kvmXsaveFor;      // function-local: core.virt.kvm imports this module
    if (vc is null || cpuId >= VIRT_MAX_CPUS) return false;
    const ulong m = virtFpuXsaveMask();
    if (m == VIRT_FPU_UNSUPPORTED) return false;
    if (g_virtHostFpuPhys[cpuId] == 0) {
        const ulong p = alloc_phys_page();
        if (p == 0) return false;
        ubyte* b = cast(ubyte*)phys_to_virt(p);
        foreach (i; 0 .. 4096) b[i] = 0;
        g_virtHostFpuPhys[cpuId] = p;
    }
    auto img = kvmXsaveFor(vc, true);
    if (img is null) return false;
    mask = m;
    hostVa = phys_to_virt(g_virtHostFpuPhys[cpuId]);
    guestVa = cast(ulong)img;
    return true;
}
