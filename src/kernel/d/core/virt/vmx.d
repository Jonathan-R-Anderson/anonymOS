// VMX backend — Intel hardware virtualization.
//
// What is REAL here (runs on any x86_64, verified by reading CPUID):
//   - vmxDetect(): CPUID.1:ECX[5] — true iff the CPU has VMX.
//   - vmxBootInit(): fail-soft boot-time init.  Checks IA32_FEATURE_CONTROL,
//     enables VMXON outside SMX if the BIOS left it unlocked, sets CR4.VMXE,
//     allocates the VMXON region with the correct revision ID, and executes
//     VMXON.  Any failure (or no VMX at all) latches g_vmxReady=false and the
//     boot continues — virtualization is simply unavailable.
// What is NOT here yet:
//   - vCPU entry (VMCS programming + VMLAUNCH) is declared as vmxEnter() but
//     returns VMX_NOHW until the [HW] phase implements it against real
//     hardware.  KVM_RUN on a VMX-less boot fails cleanly with ENODEV
//     instead of pretending to enter the guest.
//
// The kernel owns ALL privileged operations: VMXON, VMCS, EPTP, host-state
// safety.  Device models stay in userspace; the VMM never touches these.
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.vmx;

import core.io : klog, klog_hex;
import core.exports : phys_to_virt;
import memory.mm : alloc_phys_page, free_phys_page;

extern (C) @nogc nothrow:

// MSRs
enum uint IA32_FEATURE_CONTROL = 0x3A;
enum uint IA32_VMX_BASIC       = 0x480;

// IA32_FEATURE_CONTROL bits
enum ulong FEATURE_LOCK        = 1UL << 0;
enum ulong FEATURE_VMXON_SMX   = 1UL << 1;
enum ulong FEATURE_VMXON_NOSMX = 1UL << 2;

// CR4.VMXE
enum ulong CR4_VMXE = 1UL << 13;

// vmxEnter results
enum int VMX_OK   = 0;   // guest ran; exit reason in *exitReason
enum int VMX_NOHW = -19; // ENODEV: VMX not ready / entry not implemented

__gshared bool g_vmxSupported = false; // CPUID says VMX exists
__gshared bool g_vmxReady     = false; // VMXON succeeded on the BSP
__gshared ulong g_vmxonPhys   = 0;      // VMXON region (4K, revision ID set)
__gshared uint  g_vmcsRevId   = 0;      // from IA32_VMX_BASIC[30:0]

// ---------------------------------------------------------------------------
// Low-level primitives (same asm idiom as core.kmain)
// ---------------------------------------------------------------------------
private void x64Cpuid(uint leaf, uint sub, uint* eax, uint* ebx,
                      uint* ecx, uint* edx) {
    uint a, b, c, d;
    asm @nogc nothrow {
        push RBX;
        mov EAX, leaf;
        mov ECX, sub;
        cpuid;
        mov a, EAX;
        mov b, EBX;
        mov c, ECX;
        mov d, EDX;
        pop RBX;
    }
    if (eax !is null) *eax = a;
    if (ebx !is null) *ebx = b;
    if (ecx !is null) *ecx = c;
    if (edx !is null) *edx = d;
}

private ulong x64Rdmsr(uint msr) {
    ulong v;
    asm @nogc nothrow {
        mov ECX, msr;
        rdmsr;
        shl RDX, 32;
        or RAX, RDX;
        mov v, RAX;
    }
    return v;
}

private void x64Wrmsr(uint msr, ulong v) {
    ulong lo = cast(uint)v;
    ulong hi = v >> 32;
    asm @nogc nothrow {
        mov ECX, msr;
        mov RAX, lo;
        mov RDX, hi;
        wrmsr;
    }
}

// Named vmx*, NOT x64*: D `private` is access control only — it does not give
// internal linkage, so LDC still emits a global symbol.  An x64ReadCR4 here
// collides with the .global one in arch/x86_64/asm.S once --whole-archive
// pulls both objects into kernel.elf.
private ulong vmxReadCR4() {
    ulong v;
    asm @nogc nothrow { mov RAX, CR4; mov v, RAX; }
    return v;
}

private void vmxWriteCR4(ulong v) {
    asm @nogc nothrow { mov RAX, v; mov CR4, RAX; }
}

// ---------------------------------------------------------------------------
// Detection + boot init (REAL, runs anywhere)
// ---------------------------------------------------------------------------

// True iff CPUID.1:ECX[5] (VMX) is set.
public bool vmxDetect() {
    uint a, b, c, d;
    x64Cpuid(1, 0, &a, &b, &c, &d);
    return (c & (1u << 5)) != 0;
}

// Fail-soft boot init, called once on the BSP.  Never panics: any problem
// leaves g_vmxReady=false and the boot continues without virtualization.
public void vmxBootInit() {
    g_vmxSupported = vmxDetect();
    if (!g_vmxSupported) {
        klog("[vmx] no VMX (CPUID.1:ECX[5] clear) — hardware virtualization unavailable\n");
        return;
    }

    // IA32_FEATURE_CONTROL: locked without VMXON-outside-SMX => the BIOS
    // forbids VMX; fail closed (do NOT try to bypass the lock).
    ulong fc = x64Rdmsr(IA32_FEATURE_CONTROL);
    if ((fc & FEATURE_LOCK) != 0) {
        if ((fc & FEATURE_VMXON_NOSMX) == 0) {
            klog("[vmx] IA32_FEATURE_CONTROL locked without VMXON — VMX disabled by firmware\n");
            return;
        }
    } else {
        x64Wrmsr(IA32_FEATURE_CONTROL, fc | FEATURE_LOCK | FEATURE_VMXON_NOSMX);
        klog("[vmx] IA32_FEATURE_CONTROL: enabled VMXON outside SMX, locked\n");
    }

    // CR4.VMXE
    ulong cr4 = vmxReadCR4();
    if ((cr4 & CR4_VMXE) == 0)
        vmxWriteCR4(cr4 | CR4_VMXE);

    // VMXON region: 4K page, revision ID in the low 31 bits.
    ulong basic = x64Rdmsr(IA32_VMX_BASIC);
    g_vmcsRevId = cast(uint)(basic & 0x7FFFFFFF);
    g_vmxonPhys = alloc_phys_page();
    if (g_vmxonPhys == 0) {
        klog("[vmx] VMXON region allocation failed\n");
        return;
    }
    auto p = cast(uint*)phys_to_virt(g_vmxonPhys);
    foreach (i; 0 .. 1024) p[i] = 0;
    p[0] = g_vmcsRevId;

    // VMXON (rflags.CF/ZF => failure; Intel SDM vol 3C §30.3).
    // LDC's inline assembler has no `vmxon` mnemonic, so the encoding is emitted
    // as raw bytes: F3 0F C7 /6 = VMXON m64; ModRM 0x30 = [RAX].  Verified with
    // objdump: `f3 0f c7 30` disassembles to `vmxon (%rax)`.
    bool ok = false;
    ulong phys = g_vmxonPhys;
    asm @nogc nothrow {
        mov RAX, phys;
        db 0xF3; db 0x0F; db 0xC7; db 0x30; // VMXON [RAX]
        jbe vmxon_fail;
        mov ok, 1;
        jmp vmxon_done;
    vmxon_fail:;
        mov ok, 0;
    vmxon_done:;
    }
    if (!ok) {
        klog("[vmx] VMXON failed — virtualization unavailable\n");
        free_phys_page(g_vmxonPhys);
        g_vmxonPhys = 0;
        return;
    }
    g_vmxReady = true;
    klog("[vmx] VMXON ok (rev=");
    klog_hex(g_vmcsRevId);
    klog(")\n");
}

public bool vmxIsReady() { return g_vmxReady; }

// ---------------------------------------------------------------------------
// vCPU entry — [HW] phase.  Structured signature, fail-closed body.
// ---------------------------------------------------------------------------
// Programs the VMCS from the native Vcpu record + EPT root and executes
// VMLAUNCH/VMRESUME.  Implemented in the [HW] phase against real hardware;
// until then it returns VMX_NOHW so KVM_RUN fails cleanly with ENODEV
// instead of entering a half-initialized guest.
//
// [HW] verification boundary: docs/hw-bringup/VMX_SMOKE.md
public int vmxEnter(uint vmObj, uint vmGen, uint vcpuIndex, uint* exitReason) {
    if (exitReason !is null) *exitReason = 0;
    if (!g_vmxReady) return VMX_NOHW;
    // [HW] VMCS programming + VMLAUNCH goes here.  Deliberately not stubbed
    // with fake encodings — a wrong constant here would be a silent guest-
    // corruption bug, not a clean failure.
    if (exitReason !is null) *exitReason = 0;
    return VMX_NOHW;
}
