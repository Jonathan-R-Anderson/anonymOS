// VMX backend — Intel hardware virtualization.
//
// What is REAL here (runs on any x86_64, verified by reading CPUID):
//   - vmxDetect(): CPUID.1:ECX[5] — true iff the CPU has VMX.
//   - vmxCpuInit(cpuId): fail-soft per-CPU init.  Checks IA32_FEATURE_CONTROL,
//     enables VMXON outside SMX if the BIOS left it unlocked, sets CR4.VMXE,
//     allocates the VMXON region with the correct revision ID, and executes
//     VMXON.  Any failure (or no VMX at all) latches that CPU's ready=false
//     and the boot continues — virtualization is simply unavailable.
//   - vmxBootInit(): BSP wrapper -> vmxCpuInit(0).
//   - vmxDecodeExit(): translates a VMX basic exit reason + qualification
//     into the vendor-neutral VirtExitInfo the common dispatcher consumes.
// What is NOT here yet:
//   - vCPU entry (VMCS programming + VMLAUNCH) is declared as vmxEnter() but
//     returns -ENODEV until the [HW] phase implements it against real
//     hardware.  KVM_RUN on a VMX-less boot fails cleanly with ENODEV
//     instead of pretending to enter the guest.
//
// The kernel owns ALL privileged operations: VMXON, VMCS, EPTP, host-state
// safety.  Device models stay in userspace; the VMM never touches these.
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.vmx;

import core.io : klog, klog_hex;
import core.exports : phys_to_virt, g_current_task_id;
import memory.mm : alloc_phys_page, free_phys_page;
import core.virt.vm : Vm, Vcpu, VIRT_MAX_CPUS, vmCheck, vcpuCheckObj, kvmUnpackHandle;
import core.virt.vmexit : VirtExitInfo, VirtExitKind;
import core.virt.kvmabi : KvmRegs, KvmSRegs, KvmSegment;
import core.virt.slat : slatRootPhys, slatMap;

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

// --- VMX capability MSRs (used to clamp the control words + fixed CR bits) --------------------
enum uint IA32_VMX_PINBASED_CTLS   = 0x481;
enum uint IA32_VMX_PROCBASED_CTLS  = 0x482;
enum uint IA32_VMX_EXIT_CTLS       = 0x483;
enum uint IA32_VMX_ENTRY_CTLS      = 0x484;
enum uint IA32_VMX_CR0_FIXED0      = 0x486;
enum uint IA32_VMX_CR0_FIXED1      = 0x487;
enum uint IA32_VMX_CR4_FIXED0      = 0x488;
enum uint IA32_VMX_CR4_FIXED1      = 0x489;
enum uint IA32_VMX_PROCBASED_CTLS2 = 0x48B;
enum uint IA32_VMX_EPT_VPID_CAP    = 0x48C;
enum uint IA32_VMX_TRUE_PINBASED   = 0x48D;
enum uint IA32_VMX_TRUE_PROCBASED  = 0x48E;
enum uint IA32_VMX_TRUE_EXIT       = 0x48F;
enum uint IA32_VMX_TRUE_ENTRY      = 0x490;
enum uint MSR_IA32_EFER            = 0xC000_0080;
enum uint MSR_IA32_FS_BASE         = 0xC000_0100;
enum uint MSR_IA32_GS_BASE         = 0xC000_0101;
enum uint MSR_IA32_SYSENTER_CS     = 0x174;
enum uint MSR_IA32_SYSENTER_ESP    = 0x175;
enum uint MSR_IA32_SYSENTER_EIP    = 0x176;

// --- control-word desired bits ----------------------------------------------------------------
enum uint PROC_INTERRUPT_WINDOW    = 1u << 2;   // exit when the guest can take an interrupt
enum uint PROC_HLT_EXITING         = 1u << 7;
enum uint PROC_UNCOND_IO_EXITING   = 1u << 24;
enum uint PROC_ACTIVATE_SECONDARY  = 1u << 31;
enum uint SEC_ENABLE_EPT           = 1u << 1;
enum uint SEC_UNRESTRICTED_GUEST   = 1u << 7;
enum uint EXIT_HOST_ADDR_SPACE_SIZE = 1u << 9;
enum uint EXIT_SAVE_EFER           = 1u << 20;
enum uint EXIT_LOAD_EFER           = 1u << 21;
enum uint ENTRY_IA32E_MODE_GUEST   = 1u << 9;
enum uint ENTRY_LOAD_EFER          = 1u << 15;

// --- VMCS field encodings (Intel SDM vol 3D App. B) -------------------------------------------
// control (16/32/64/natural)
enum ulong VMCS_PIN_BASED          = 0x4000;
enum ulong VMCS_PROC_BASED         = 0x4002;
enum ulong VMCS_EXCEPTION_BITMAP   = 0x4004;
enum ulong VMCS_CR3_TARGET_COUNT   = 0x400A;
enum ulong VMCS_EXIT_CONTROLS      = 0x400C;
enum ulong VMCS_EXIT_MSR_STORE_CNT = 0x400E;
enum ulong VMCS_EXIT_MSR_LOAD_CNT  = 0x4010;
enum ulong VMCS_ENTRY_CONTROLS     = 0x4012;
enum ulong VMCS_ENTRY_MSR_LOAD_CNT = 0x4014;
enum ulong VMCS_ENTRY_INTR_INFO    = 0x4016;
enum ulong VMCS_PROC_BASED2        = 0x401E;
enum ulong VMCS_EPT_POINTER        = 0x201A;   // (verify fix: NOT 0x201C = EOI-exit-bitmap)
enum ulong VMCS_LINK_POINTER       = 0x2800;
enum ulong VMCS_CR0_GH_MASK        = 0x6000;
enum ulong VMCS_CR4_GH_MASK        = 0x6002;
enum ulong VMCS_CR0_READ_SHADOW    = 0x6004;
enum ulong VMCS_CR4_READ_SHADOW    = 0x6006;
// exit info (read-only)
enum ulong VMCS_INSTRUCTION_ERROR  = 0x4400;
enum ulong VMCS_EXIT_REASON        = 0x4402;
enum ulong VMCS_EXIT_QUALIFICATION = 0x6400;
enum ulong VMCS_GUEST_PHYS_ADDR    = 0x2400;
enum ulong VMCS_EXIT_INSTR_LEN     = 0x440C;
// guest state
enum ulong VMCS_GUEST_CR0          = 0x6800;
enum ulong VMCS_GUEST_CR3          = 0x6802;
enum ulong VMCS_GUEST_CR4          = 0x6804;
enum ulong VMCS_GUEST_DR7          = 0x681A;
enum ulong VMCS_GUEST_RSP          = 0x681C;
enum ulong VMCS_GUEST_RIP          = 0x681E;
enum ulong VMCS_GUEST_RFLAGS       = 0x6820;
enum ulong VMCS_GUEST_EFER         = 0x2806;
enum ulong VMCS_GUEST_DEBUGCTL     = 0x2802;
enum ulong VMCS_GUEST_ACTIVITY     = 0x4826;
enum ulong VMCS_GUEST_INTERRUPT    = 0x4824;
enum ulong VMCS_GUEST_SYSENTER_CS  = 0x482A;
enum ulong VMCS_GUEST_SYSENTER_ESP = 0x6824;
enum ulong VMCS_GUEST_SYSENTER_EIP = 0x6826;
// guest segment field bases (add index*2: ES,CS,SS,DS,FS,GS,LDTR,TR)
enum ulong VMCS_GUEST_ES_SEL       = 0x0800;  // +2 per segment
enum ulong VMCS_GUEST_ES_LIMIT     = 0x4800;
enum ulong VMCS_GUEST_ES_AR        = 0x4814;
enum ulong VMCS_GUEST_ES_BASE      = 0x6806;
enum ulong VMCS_GUEST_GDTR_LIMIT   = 0x4810;
enum ulong VMCS_GUEST_IDTR_LIMIT   = 0x4812;
enum ulong VMCS_GUEST_GDTR_BASE    = 0x6816;
enum ulong VMCS_GUEST_IDTR_BASE    = 0x6818;
// host state
enum ulong VMCS_HOST_CR0           = 0x6C00;
enum ulong VMCS_HOST_CR3           = 0x6C02;
enum ulong VMCS_HOST_CR4           = 0x6C04;
enum ulong VMCS_HOST_FS_BASE       = 0x6C06;
enum ulong VMCS_HOST_GS_BASE       = 0x6C08;
enum ulong VMCS_HOST_TR_BASE       = 0x6C0A;
enum ulong VMCS_HOST_GDTR_BASE     = 0x6C0C;
enum ulong VMCS_HOST_IDTR_BASE     = 0x6C0E;
enum ulong VMCS_HOST_RSP           = 0x6C14;
enum ulong VMCS_HOST_RIP           = 0x6C16;
enum ulong VMCS_HOST_ES_SEL        = 0x0C00;
enum ulong VMCS_HOST_CS_SEL        = 0x0C02;
enum ulong VMCS_HOST_SS_SEL        = 0x0C04;
enum ulong VMCS_HOST_DS_SEL        = 0x0C06;
enum ulong VMCS_HOST_FS_SEL        = 0x0C08;
enum ulong VMCS_HOST_GS_SEL        = 0x0C0A;
enum ulong VMCS_HOST_TR_SEL        = 0x0C0C;
enum ulong VMCS_HOST_EFER          = 0x2C02;
enum ulong VMCS_HOST_SYSENTER_CS   = 0x4C00;

// vmxEnter results
enum int VMX_OK   = 0;   // guest ran; decoded exit in *xi
enum int VMX_NOHW = -19; // ENODEV: VMX not ready / entry not implemented

// VMX basic exit reasons (Intel SDM vol 3C §"Basic VM-Exit Information").
// These live here — in the Intel backend — not in the common dispatcher.
enum ulong EXIT_REASON_EXTERNAL_INTERRUPT = 0;
enum ulong EXIT_REASON_TRIPLE_FAULT       = 2;
enum ulong EXIT_REASON_INIT               = 3;
enum ulong EXIT_REASON_SIPI               = 4;
enum ulong EXIT_REASON_IO_SMI             = 5;
enum ulong EXIT_REASON_OTHER_SMI          = 6;
enum ulong EXIT_REASON_INTERRUPT_WINDOW   = 7;
enum ulong EXIT_REASON_NMI_WINDOW         = 8;
enum ulong EXIT_REASON_TASK_SWITCH        = 9;
enum ulong EXIT_REASON_CPUID              = 10;
enum ulong EXIT_REASON_GETSEC             = 11;
enum ulong EXIT_REASON_HLT                = 12;
enum ulong EXIT_REASON_INVD               = 13;
enum ulong EXIT_REASON_INVLPG             = 14;
enum ulong EXIT_REASON_RDPMC              = 15;
enum ulong EXIT_REASON_RDTSC              = 16;
enum ulong EXIT_REASON_RSM                = 17;
enum ulong EXIT_REASON_VMCALL             = 18;
enum ulong EXIT_REASON_VMCLEAR            = 19;
enum ulong EXIT_REASON_VMLAUNCH           = 20;
enum ulong EXIT_REASON_VMPTRLD            = 21;
enum ulong EXIT_REASON_VMPTRST            = 22;
enum ulong EXIT_REASON_VMREAD             = 23;
enum ulong EXIT_REASON_VMRESUME           = 24;
enum ulong EXIT_REASON_VMWRITE            = 25;
enum ulong EXIT_REASON_VMXOFF             = 26;
enum ulong EXIT_REASON_VMXON              = 27;
enum ulong EXIT_REASON_CR_ACCESS          = 28;
enum ulong EXIT_REASON_MOV_DR             = 29;
enum ulong EXIT_REASON_IO_INSTRUCTION     = 30;
enum ulong EXIT_REASON_RDMSR              = 31;
enum ulong EXIT_REASON_WRMSR              = 32;
enum ulong EXIT_REASON_INVALID_GUEST_STATE = 33;
enum ulong EXIT_REASON_MSR_LOADING        = 34;
enum ulong EXIT_REASON_MWAIT               = 36;
enum ulong EXIT_REASON_MTF                = 37;
enum ulong EXIT_REASON_MONITOR            = 39;
enum ulong EXIT_REASON_PAUSE              = 40;
enum ulong EXIT_REASON_MCE_DURING_ENTRY   = 41;
enum ulong EXIT_REASON_TPR_BELOW_THRESHOLD = 43;
enum ulong EXIT_REASON_APIC_ACCESS        = 44;
enum ulong EXIT_REASON_VIRTUALIZED_EOI    = 45;
enum ulong EXIT_REASON_GDTR_IDTR_ACCESS   = 46;
enum ulong EXIT_REASON_LDTR_TR_ACCESS     = 47;
enum ulong EXIT_REASON_EPT_VIOLATION      = 48;
enum ulong EXIT_REASON_EPT_MISCONFIG      = 49;
enum ulong EXIT_REASON_INVEPT             = 50;
enum ulong EXIT_REASON_RDTSCP             = 51;
enum ulong EXIT_REASON_VMX_PREEMPTION     = 52;
enum ulong EXIT_REASON_INVVPID            = 53;
enum ulong EXIT_REASON_WBINVD             = 54;
enum ulong EXIT_REASON_XSETBV             = 55;
enum ulong EXIT_REASON_APIC_WRITE         = 56;
enum ulong EXIT_REASON_RDRAND             = 57;
enum ulong EXIT_REASON_INVPCID            = 58;
enum ulong EXIT_REASON_VMFUNC             = 59;
enum ulong EXIT_REASON_ENCLS              = 60;
enum ulong EXIT_REASON_RDSEED             = 61;
enum ulong EXIT_REASON_PML_FULL           = 62;
enum ulong EXIT_REASON_XSAVES             = 63;
enum ulong EXIT_REASON_XRSTORS            = 64;

// Per-CPU VMX state.  Indexed by the kernel's per-CPU index
// (0 = BSP).  Size from core.virt.vm.VIRT_MAX_CPUS.
struct VmxCpuState {
    bool  ready;     // VMXON succeeded on this CPU
    ulong vmxonPhys; // this CPU's VMXON region (4K, revision ID set)
}
__gshared VmxCpuState[VIRT_MAX_CPUS] g_vmxCpu;
__gshared bool g_vmxSupported = false; // CPUID says VMX exists (any CPU)
__gshared uint g_vmcsRevId   = 0;      // from IA32_VMX_BASIC[30:0] (global)

// ---------------------------------------------------------------------------
// Low-level primitives (same asm idiom as core.kmain)
// ---------------------------------------------------------------------------
private void x64Cpuid(uint leaf, uint sub, uint* eax, uint* ebx,
                      uint* ecx, uint* edx) {
    pragma(inline, false);   // never inline: when inlined into a high-register-pressure caller LDC
                             // mis-resolves `mov EAX, leaf` (the param), so cpuid ran with a wrong
                             // leaf and returned ecx=0 — breaking vmxDetect only at some call sites.
    uint a, b, c, d;
    // NB: no `push RBX` here.  Pushing shifts RSP by 8, and LDC may address `leaf`/`sub` and the
    // a/b/c/d locals RSP-relative — so a push before them makes every access 8 bytes off (cpuid then
    // ran with a garbage leaf and returned ecx=0).  x64VendorIsIntel proves the no-push form is fine:
    // LDC preserves RBX across a function that clobbers it in inline asm.
    asm @nogc nothrow {
        mov EAX, leaf;
        mov ECX, sub;
        cpuid;
        mov a, EAX;
        mov b, EBX;
        mov c, ECX;
        mov d, EDX;
    }
    if (eax !is null) *eax = a;
    if (ebx !is null) *ebx = b;
    if (ecx !is null) *ecx = c;
    if (edx !is null) *edx = d;
}

private ulong vmxRdmsr(uint msr) {
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

private void vmxWrmsr(uint msr, ulong v) {
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

// True iff the vendor string is "GenuineIntel".  VMX must be vendor-gated:
// some configurations (e.g. QEMU -cpu qemu64,+svm on an AMD host) set the
// CPUID.1:ECX[5] bit even though the CPU has no VMX and none of the VMX MSRs —
// rdmsr(IA32_FEATURE_CONTROL) there raises #GP and would kill the boot.
private bool x64VendorIsIntel() {
    uint b, d, c;
    asm @nogc nothrow {
        mov EAX, 0;
        cpuid;
        mov b, EBX;
        mov d, EDX;
        mov c, ECX;
    }
    return b == 0x756e6547u && d == 0x49656e69u && c == 0x6c65746eu; // "GenuineIntel"
}

// True iff the CPU vendor is Intel AND CPUID.1:ECX[5] (VMX) is set.
public bool vmxDetect() {
    if (!x64VendorIsIntel()) return false;
    uint a, b, c, d;
    x64Cpuid(1, 0, &a, &b, &c, &d);
    return (c & (1u << 5)) != 0;
}

// Report the VMX capability set (no VMXON needed — these are capability-reporting MSRs).  Guest
// entry here is EPT-mandatory, and a nested hypervisor may withhold EPT from its guest; if so, no
// guest can enter regardless of VMCS correctness.  Reads are guarded so an unsupported MSR never
// #GPs the boot (IA32_VMX_PROCBASED_CTLS2 only exists when activate-secondary is allowed; the EPT
// cap MSR only when EPT is allowed).
public void vmxCapProbe() {
    if (!vmxDetect()) { klog("[vmx] caps: no VMX on this CPU\n"); return; }
    const ulong basic = vmxRdmsr(IA32_VMX_BASIC);
    const ulong pctls = vmxRdmsr(0x482);                    // IA32_VMX_PROCBASED_CTLS
    const bool secOK  = ((pctls >> 32) & (1u << 31)) != 0;  // activate-secondary controls allowed-1
    klog("[vmx] caps: vmx=Y basic="); klog_hex(basic);
    klog(" secondary="); klog(secOK ? "Y" : "N");
    if (secOK) {
        const ulong ctls2 = vmxRdmsr(0x48B);                // IA32_VMX_PROCBASED_CTLS2
        const bool eptOK  = ((ctls2 >> 32) & (1u << 1)) != 0;  // Enable-EPT allowed-1
        const bool urgOK  = ((ctls2 >> 32) & (1u << 7)) != 0;  // Unrestricted-guest allowed-1
        klog(" ept="); klog(eptOK ? "Y" : "N");
        klog(" unrestricted="); klog(urgOK ? "Y" : "N");
        if (eptOK) { const ulong eptcap = vmxRdmsr(0x48C); klog(" ept_vpid_cap="); klog_hex(eptcap); }
    }
    klog("\n");
}

// Fail-soft per-CPU init.  Must run ON the target CPU (it sets that CPU's
// CR4.VMXE and executes VMXON there).  Never panics: any problem leaves
// this CPU's ready=false and the boot continues without virtualization.
public void vmxCpuInit(uint cpuId) {
    if (cpuId >= VIRT_MAX_CPUS) return;
    g_vmxSupported = vmxDetect();
    if (!g_vmxSupported) {
        if (!x64VendorIsIntel())
            klog("[vmx] vendor is not GenuineIntel — VMX unavailable (AMD path: core.virt.svm)\n");
        else
            klog("[vmx] no VMX (CPUID.1:ECX[5] clear) — hardware virtualization unavailable\n");
        return;
    }

    // IA32_FEATURE_CONTROL: locked without VMXON-outside-SMX => the BIOS
    // forbids VMX; fail closed (do NOT try to bypass the lock).
    ulong fc = vmxRdmsr(IA32_FEATURE_CONTROL);
    if ((fc & FEATURE_LOCK) != 0) {
        if ((fc & FEATURE_VMXON_NOSMX) == 0) {
            klog("[vmx] IA32_FEATURE_CONTROL locked without VMXON — VMX disabled by firmware\n");
            return;
        }
    } else {
        vmxWrmsr(IA32_FEATURE_CONTROL, fc | FEATURE_LOCK | FEATURE_VMXON_NOSMX);
        klog("[vmx] IA32_FEATURE_CONTROL: enabled VMXON outside SMX, locked\n");
    }

    // CR4.VMXE
    ulong cr4 = vmxReadCR4();
    if ((cr4 & CR4_VMXE) == 0)
        vmxWriteCR4(cr4 | CR4_VMXE);

    // CR0 must satisfy the VMX fixed bits (IA32_VMX_CR0_FIXED0/1 — e.g. NE, bit5) or VMXON #GPs.
    // The kernel's CR0 may lack NE, which is exactly what faulted VMXON here.
    ulong cr0 = vmxReadCR0();
    const ulong ncr0 = (cr0 | vmxRdmsr(IA32_VMX_CR0_FIXED0)) & vmxRdmsr(IA32_VMX_CR0_FIXED1);
    if (ncr0 != cr0) vmxWriteCR0(ncr0);
    klog("[vmx] pre-VMXON cr0="); klog_hex(ncr0); klog(" cr4="); klog_hex(cr4 | CR4_VMXE);
    klog(" fc="); klog_hex(fc); klog("\n");

    // VMXON region: 4K page, revision ID in the low 31 bits.
    ulong basic = vmxRdmsr(IA32_VMX_BASIC);
    // The revision id is IA32_VMX_BASIC[30:0].  It was declared (g_vmcsRevId) and used for the VMXON
    // region + every VMCS, but never assigned — so VMXON/VMPTRLD/VMLAUNCH validated against 0 and
    // VMfail'd on real silicon.  Set it from the MSR before first use.
    g_vmcsRevId = cast(uint)(basic & 0x7FFFFFFF);
    ulong vmxonPhys = alloc_phys_page();
    if (vmxonPhys == 0) {
        klog("[vmx] VMXON region allocation failed\n");
        return;
    }
    auto p = cast(uint*)phys_to_virt(vmxonPhys);
    foreach (i; 0 .. 1024) p[i] = 0;
    p[0] = g_vmcsRevId;

    // VMXON (rflags.CF/ZF => failure; Intel SDM vol 3C §30.3).
    // LDC's inline assembler has no `vmxon` mnemonic, so the encoding is emitted
    // as raw bytes: F3 0F C7 /6 = VMXON m64; ModRM 0x30 = [RAX].  Verified with
    // objdump: `f3 0f c7 30` disassembles to `vmxon (%rax)`.
    bool ok = false;
    ulong phys = vmxonPhys;
    asm @nogc nothrow {
        lea RAX, phys;                      // RAX = &phys — VMXON's operand is a POINTER to the
        db 0xF3; db 0x0F; db 0xC7; db 0x30; // region phys, not the phys itself.  (`mov RAX, phys`
                                            // dereferenced the phys as a virtual address → #GP.)
        jbe vmxon_fail;
        mov ok, 1;
        jmp vmxon_done;
    vmxon_fail:;
        mov ok, 0;
    vmxon_done:;
    }
    if (!ok) {
        klog("[vmx] VMXON failed — virtualization unavailable\n");
        free_phys_page(vmxonPhys);
        return;
    }
    g_vmxCpu[cpuId].vmxonPhys = vmxonPhys;
    g_vmxCpu[cpuId].ready = true;
    klog("[vmx] VMXON ok (rev=");
    klog_hex(g_vmcsRevId);
    klog(")\n");
}

// Boot-time init: the BSP's share of the per-CPU init above.
public void vmxBootInit() { vmxCpuInit(0); }

public bool vmxIsReady() { return g_vmxCpu[0].ready; }

// ---------------------------------------------------------------------------
// Exit decoder: VMX basic exit reason -> vendor-neutral VirtExitInfo.
// Pure function of the VMCS exit fields the [HW] phase will extract.
// ---------------------------------------------------------------------------
public void vmxDecodeExit(uint reason, ulong qual, ulong gpa, ulong data,
                          uint count, VirtExitInfo* xi) {
    xi.qual = qual;
    xi.gpa = gpa;
    xi.data = data;
    xi.count = count;
    xi.hardwareReason = reason;
    xi.ioPort = 0; xi.ioSize = 0; xi.ioIsIn = 0; xi.ioIsString = 0;
    xi.slatIsWrite = 0;
    switch (reason) {
        case EXIT_REASON_HLT:
            xi.kind = VirtExitKind.Hlt;
            break;
        case EXIT_REASON_TRIPLE_FAULT:
            xi.kind = VirtExitKind.Shutdown;
            break;
        case EXIT_REASON_IO_INSTRUCTION: {
            // Exit qualification (Intel SDM vol 3C, "Exit Qualification for
            // I/O Instructions"): [2:0] size (0=1B, 1=2B, 3=4B; other values
            // reserved), [3] direction (1=IN), [4] string, [31:16] port.
            // A reserved size encoding decodes to ioSize=0, which the common
            // dispatcher contains (fail-closed, never a guessed length).
            xi.kind = VirtExitKind.Io;
            switch (qual & 7) {
                case 0: xi.ioSize = 1; break;
                case 1: xi.ioSize = 2; break;
                case 3: xi.ioSize = 4; break;
                default: xi.ioSize = 0; break;
            }
            xi.ioIsIn = (qual & 8) ? 1 : 0;
            xi.ioIsString = (qual & 16) ? 1 : 0;
            xi.ioPort = cast(ushort)((qual >> 16) & 0xFFFF);
            break;
        }
        case EXIT_REASON_VMCALL:
            xi.kind = VirtExitKind.Hypercall; // data = guest RAX
            break;
        case EXIT_REASON_EPT_VIOLATION:
            // EPT-violation qualification bit 1: 1 = write access.
            xi.kind = VirtExitKind.SlatFault;
            xi.slatIsWrite = (qual & 2) ? 1 : 0;
            break;
        default:
            xi.kind = VirtExitKind.Unknown;
            break;
    }
}

// ---------------------------------------------------------------------------
// vCPU entry — [HW] phase.  Fail-closed body behind the virtEnter contract.
// ---------------------------------------------------------------------------
// --- VMX instruction wrappers (LDC has no VMX mnemonics: raw bytes, as vmxCpuInit does) ---------
private void vmxWrite(ulong field, ulong val) {
    asm @nogc nothrow {
        mov RAX, val;
        mov RDX, field;
        db 0x0F; db 0x79; db 0xD0;               // VMWRITE RDX(field) <- RAX(val)
    }
}
private ulong vmxRead(ulong field) {
    ulong v;
    asm @nogc nothrow {
        mov RDX, field;
        db 0x0F; db 0x78; db 0xD0;               // VMREAD RAX <- RDX(field)
        mov v, RAX;
    }
    return v;
}
// VMPTRLD/VMCLEAR take a POINTER to the 8-byte region phys; lea the local that holds it.
private bool vmxPtrld(ulong phys) {
    ulong p = phys; bool ok = false;
    asm @nogc nothrow {
        lea RAX, p;
        db 0x0F; db 0xC7; db 0x30;               // VMPTRLD [RAX]
        jbe Lptrld_fail;
        mov ok, 1;
        jmp Lptrld_done;
    Lptrld_fail:; mov ok, 0;
    Lptrld_done:;
    }
    return ok;
}
private bool vmxClear(ulong phys) {
    ulong p = phys; bool ok = false;
    asm @nogc nothrow {
        lea RAX, p;
        db 0x66; db 0x0F; db 0xC7; db 0x30;      // VMCLEAR [RAX]
        jbe Lclear_fail;
        mov ok, 1;
        jmp Lclear_done;
    Lclear_fail:; mov ok, 0;
    Lclear_done:;
    }
    return ok;
}
private ulong vmxReadCR0() { ulong v; asm @nogc nothrow { mov RAX, CR0; mov v, RAX; } return v; }
private ulong vmxReadCR3() { ulong v; asm @nogc nothrow { mov RAX, CR3; mov v, RAX; } return v; }
private void  vmxWriteCR0(ulong v) { asm @nogc nothrow { mov RAX, v; mov CR0, RAX; } }

// Clamp a desired control word: force allowed-0 (low dword, must-be-1) then AND allowed-1 (high).
private uint vmxClampCtl(uint desired, uint msr) {
    const ulong m = vmxRdmsr(msr);
    const uint lo = cast(uint)(m & 0xFFFF_FFFF);   // bits that MUST be 1
    const uint hi = cast(uint)(m >> 32);           // bits that MAY be 1
    return (desired | lo) & hi;
}

// VMX segment access-rights: 16 attribute bits + the 'unusable' bit at bit16 (NOT the SVM attrib=0).
private uint vmxSegAr(const(KvmSegment)* s) {
    if (s.unusable) return 0x0001_0000u;
    return (s.type & 0xF)
         | (cast(uint)s.s   << 4)  | (cast(uint)s.dpl << 5) | (cast(uint)s.present << 7)
         | (cast(uint)s.avl << 12) | (cast(uint)s.l   << 13)
         | (cast(uint)s.db  << 14) | (cast(uint)s.g   << 15);
}
// Program one guest segment by index (0=ES,1=CS,2=SS,3=DS,4=FS,5=GS,6=LDTR,7=TR).
private void vmxWriteSeg(uint idx, const(KvmSegment)* s) {
    vmxWrite(VMCS_GUEST_ES_SEL   + idx * 2, s.selector);
    vmxWrite(VMCS_GUEST_ES_LIMIT + idx * 2, s.limit);
    vmxWrite(VMCS_GUEST_ES_AR    + idx * 2, vmxSegAr(s));
    vmxWrite(VMCS_GUEST_ES_BASE  + idx * 2, s.base);
}

// Program the whole VMCS from the vCPU's guest state + the running host + the VM's EPT root.  The
// control words are stable (clamped once against the capability MSRs); guest/host state is written
// every entry.  Returns false if a required control bit was clamped away (fail-closed).
private bool vmxProgramVmcs(Vm* vm, Vcpu* vc, KvmRegs* regs, const KvmSRegs* sregs) {
    // ---- controls (clamped) ----
    const bool useTrue = (vmxRdmsr(IA32_VMX_BASIC) & (1UL << 55)) != 0;
    const uint pin  = vmxClampCtl(0, useTrue ? IA32_VMX_TRUE_PINBASED : IA32_VMX_PINBASED_CTLS);
    const bool guestLong = (sregs.efer & (1UL << 10)) != 0;   // EFER.LMA
    // Resolve the LAPIC IRR into an entry injection: inject the highest pending
    // vector iff the guest is interruptible; otherwise arm interrupt-window
    // exiting so we exit — and inject — the moment it becomes interruptible.
    // (Interruptibility-state is 0 in this model, so the gate is RFLAGS.IF.)
    const InjectPlan plan = vmxPlanInjection(vc, regs.rflags, 0);
    const uint procExtra = plan.wantWindow ? PROC_INTERRUPT_WINDOW : 0;
    const uint proc = vmxClampCtl(PROC_HLT_EXITING | PROC_UNCOND_IO_EXITING
                                  | PROC_ACTIVATE_SECONDARY | procExtra,
                                  useTrue ? IA32_VMX_TRUE_PROCBASED : IA32_VMX_PROCBASED_CTLS);
    uint sec = vmxClampCtl(SEC_ENABLE_EPT | (guestLong ? 0 : SEC_UNRESTRICTED_GUEST),
                           IA32_VMX_PROCBASED_CTLS2);
    const uint exitc = vmxClampCtl(EXIT_HOST_ADDR_SPACE_SIZE | EXIT_SAVE_EFER | EXIT_LOAD_EFER,
                                   useTrue ? IA32_VMX_TRUE_EXIT : IA32_VMX_EXIT_CTLS);
    const uint entryc = vmxClampCtl((guestLong ? ENTRY_IA32E_MODE_GUEST : 0) | ENTRY_LOAD_EFER,
                                    useTrue ? IA32_VMX_TRUE_ENTRY : IA32_VMX_ENTRY_CTLS);
    // fail-closed: the mandatory bits must have survived the clamp
    if (!(proc & PROC_ACTIVATE_SECONDARY) || !(sec & SEC_ENABLE_EPT)
        || !(exitc & EXIT_HOST_ADDR_SPACE_SIZE)) {
        klog("[vmx] required control bit clamped away — EPT/secondary/host-addr-size unavailable\n");
        return false;
    }
    vmxWrite(VMCS_PIN_BASED, pin);
    vmxWrite(VMCS_PROC_BASED, proc);
    vmxWrite(VMCS_PROC_BASED2, sec);
    vmxWrite(VMCS_EXIT_CONTROLS, exitc);
    vmxWrite(VMCS_ENTRY_CONTROLS, entryc);
    vmxWrite(VMCS_EXCEPTION_BITMAP, 0);
    // explicit zeros (VMCS is opaque — do NOT rely on page-zeroing for checked fields)
    vmxWrite(VMCS_CR3_TARGET_COUNT, 0);
    vmxWrite(VMCS_EXIT_MSR_STORE_CNT, 0);
    vmxWrite(VMCS_EXIT_MSR_LOAD_CNT, 0);
    vmxWrite(VMCS_ENTRY_MSR_LOAD_CNT, 0);
    // VM-entry event injection: the resolved highest-priority pending vector
    // (or 0 = none when nothing is deliverable this entry — see vmxPlanInjection).
    // The CPU delivers it through the guest IDT on entry.
    vmxWrite(VMCS_ENTRY_INTR_INFO, plan.info);
    vmxWrite(VMCS_LINK_POINTER, ~0UL);
    // EPTP = root | WB(6) | walk-length-1(3<<3)
    vmxWrite(VMCS_EPT_POINTER, (slatRootPhys(&vm.slat) & 0x000F_FFFF_FFFF_F000UL) | 6 | (3 << 3));

    // ---- guest control regs (fixed-bit adjusted; VMXE forced but hidden via read-shadow) ----
    ulong cr0f0 = vmxRdmsr(IA32_VMX_CR0_FIXED0);
    const ulong cr0f1 = vmxRdmsr(IA32_VMX_CR0_FIXED1);
    if (sec & SEC_UNRESTRICTED_GUEST) cr0f0 &= ~((1UL << 0) | (1UL << 31));  // PE/PG free under URG
    const ulong gcr0 = (sregs.cr0 | cr0f0) & cr0f1;
    const ulong cr4f0 = vmxRdmsr(IA32_VMX_CR4_FIXED0);       // forces CR4.VMXE
    const ulong cr4f1 = vmxRdmsr(IA32_VMX_CR4_FIXED1);
    const ulong gcr4 = (sregs.cr4 | cr4f0) & cr4f1;
    vmxWrite(VMCS_GUEST_CR0, gcr0);
    vmxWrite(VMCS_GUEST_CR3, sregs.cr3);
    vmxWrite(VMCS_GUEST_CR4, gcr4);
    // hide the forced bits from the guest
    vmxWrite(VMCS_CR0_GH_MASK, (1UL << 0) | (1UL << 31));
    vmxWrite(VMCS_CR0_READ_SHADOW, sregs.cr0);
    vmxWrite(VMCS_CR4_GH_MASK, CR4_VMXE);
    vmxWrite(VMCS_CR4_READ_SHADOW, sregs.cr4);

    // ---- guest segments / tables ----
    vmxWriteSeg(0, &sregs.es); vmxWriteSeg(1, &sregs.cs); vmxWriteSeg(2, &sregs.ss);
    vmxWriteSeg(3, &sregs.ds); vmxWriteSeg(4, &sregs.fs); vmxWriteSeg(5, &sregs.gs);
    vmxWriteSeg(6, &sregs.ldt); vmxWriteSeg(7, &sregs.tr);
    vmxWrite(VMCS_GUEST_GDTR_BASE, sregs.gdt.base);  vmxWrite(VMCS_GUEST_GDTR_LIMIT, sregs.gdt.limit);
    vmxWrite(VMCS_GUEST_IDTR_BASE, sregs.idt.base);  vmxWrite(VMCS_GUEST_IDTR_LIMIT, sregs.idt.limit);

    // ---- guest misc + RIP/RSP/RFLAGS ----
    vmxWrite(VMCS_GUEST_EFER, sregs.efer);
    vmxWrite(VMCS_GUEST_DR7, 0x400);
    vmxWrite(VMCS_GUEST_DEBUGCTL, 0);
    vmxWrite(VMCS_GUEST_ACTIVITY, 0);       // active
    vmxWrite(VMCS_GUEST_INTERRUPT, 0);
    vmxWrite(VMCS_GUEST_SYSENTER_CS, 0);
    vmxWrite(VMCS_GUEST_SYSENTER_ESP, 0);
    vmxWrite(VMCS_GUEST_SYSENTER_EIP, 0);
    vmxWrite(VMCS_GUEST_RSP, regs.rsp);
    vmxWrite(VMCS_GUEST_RIP, regs.rip);
    vmxWrite(VMCS_GUEST_RFLAGS, regs.rflags | 0x2);   // reserved bit1 must be 1

    // ---- host state (captured from the running kernel) ----
    vmxWrite(VMCS_HOST_CR0, vmxReadCR0());
    vmxWrite(VMCS_HOST_CR3, vmxReadCR3());
    vmxWrite(VMCS_HOST_CR4, vmxReadCR4());
    vmxWrite(VMCS_HOST_EFER, vmxRdmsr(MSR_IA32_EFER));
    vmxWrite(VMCS_HOST_FS_BASE, vmxRdmsr(MSR_IA32_FS_BASE));
    vmxWrite(VMCS_HOST_GS_BASE, vmxRdmsr(MSR_IA32_GS_BASE));
    vmxWrite(VMCS_HOST_SYSENTER_CS, vmxRdmsr(MSR_IA32_SYSENTER_CS));
    // host selectors: kernel CS=0x08, data=0x10, TR=0x28 (RPL/TI must be 0 — they are)
    ushort hcs, hss, hds, hes, hfs, hgs, htr;
    asm @nogc nothrow {
        mov AX, CS; mov hcs, AX;  mov AX, SS; mov hss, AX;  mov AX, DS; mov hds, AX;
        mov AX, ES; mov hes, AX;  mov AX, FS; mov hfs, AX;  mov AX, GS; mov hgs, AX;
        db 0x0F; db 0x00; db 0xC8; mov htr, AX;              // STR AX
    }
    vmxWrite(VMCS_HOST_CS_SEL, hcs & 0xFFF8);  vmxWrite(VMCS_HOST_SS_SEL, hss & 0xFFF8);
    vmxWrite(VMCS_HOST_DS_SEL, hds & 0xFFF8);  vmxWrite(VMCS_HOST_ES_SEL, hes & 0xFFF8);
    vmxWrite(VMCS_HOST_FS_SEL, hfs & 0xFFF8);  vmxWrite(VMCS_HOST_GS_SEL, hgs & 0xFFF8);
    vmxWrite(VMCS_HOST_TR_SEL, htr & 0xFFF8);
    // host GDTR/IDTR/TR bases via SGDT/SIDT into scratch pseudo-descriptors
    ubyte[10] gdtr = void, idtr = void;
    asm @nogc nothrow {
        lea RAX, gdtr; db 0x0F; db 0x01; db 0x00;           // SGDT [RAX]
        lea RAX, idtr; db 0x0F; db 0x01; db 0x08;           // SIDT [RAX]
    }
    const ulong hgdtBase = *cast(ulong*)(&gdtr[2]);
    const ulong hidtBase = *cast(ulong*)(&idtr[2]);
    vmxWrite(VMCS_HOST_GDTR_BASE, hgdtBase);
    vmxWrite(VMCS_HOST_IDTR_BASE, hidtBase);
    // host TR base: walk the GDT entry named by the TR selector
    const uint trIdx = (htr & 0xFFF8);
    ulong htrBase = 0;
    if (trIdx != 0) {
        auto d = cast(uint*)(hgdtBase + trIdx);
        const ulong lo = (cast(ulong)(d[0] >> 16) & 0xFFFF) | ((cast(ulong)(d[1] & 0xFF)) << 16)
                       | ((cast(ulong)(d[1] & 0xFF00_0000)) >> 8);
        const ulong hi = cast(ulong)d[2];                    // upper 32 bits of a 64-bit TSS base
        htrBase = lo | (hi << 32);
    }
    vmxWrite(VMCS_HOST_TR_BASE, htrBase);
    return true;
}

// Programs the VMCS from the native Vcpu record + EPT root and executes VMLAUNCH/VMRESUME.
// [HW] verification: scripts/virt-hw-test.sh + a nested-VMX host (VirtualBox exposes EPT).
public int vmxEnter(Vm* vm, Vcpu* vc, KvmRegs* regs, const KvmSRegs* sregs,
                    VirtExitInfo* xi) {
    if (vm is null || vc is null || xi is null || regs is null || sregs is null) return -22;
    // Lazy per-CPU enable (boot no longer VMXONs; do it on first entry).
    if (!g_vmxCpu[0].ready) { vmxCpuInit(0); if (!g_vmxCpu[0].ready) return VMX_NOHW; }

    // Allocate + initialize this vCPU's VMCS on first entry.
    bool freshVmcs = false;
    if (vc.hwCtrlPhys == 0) {
        const ulong phys = alloc_phys_page();
        if (phys == 0) return VMX_NOHW;
        auto p = cast(uint*)phys_to_virt(phys);
        foreach (i; 0 .. 1024) p[i] = 0;
        p[0] = g_vmcsRevId;                       // dword0 = revision id, bit31 (shadow) clear
        vc.hwCtrlPhys = phys;
        freshVmcs = true;
    }
    if (freshVmcs && !vmxClear(vc.hwCtrlPhys)) { klog("[vmx] VMCLEAR failed\n"); return VMX_NOHW; }
    if (!vmxPtrld(vc.hwCtrlPhys))              { klog("[vmx] VMPTRLD failed\n"); return VMX_NOHW; }

    if (!vmxProgramVmcs(vm, vc, regs, sregs)) return VMX_NOHW;

    // --- the transition: VMLAUNCH (first) / VMRESUME (subsequent) --------------------------------
    // HOST_RSP/RIP are VMWRITTEN from INSIDE the asm (RSP after pushes, RIP = resume label).  On a
    // VM-exit the CPU returns to the resume label; the instruction after VMLAUNCH is entry-failure.
    int entryFail = 0;
    {
        KvmRegs* r = regs;
        const ulong launchInsn = vc.launched ? 0xC3 : 0xC2;   // VMRESUME=0F01C3 / VMLAUNCH=0F01C2
        asm @nogc nothrow {
            mov RBX, r;                 // RBX = regs (callee-saved across the guest via stack below)
            // save host GPRs
            push RBP; push RBX; push RCX; push RDX; push RSI; push RDI;
            push R8; push R9; push R10; push R11; push R12; push R13; push R14; push R15;
            // HOST_RSP = current RSP; HOST_RIP = Lresume
            mov RDX, 0x6C14; mov RAX, RSP;      db 0x0F; db 0x79; db 0xD0;   // VMWRITE HOST_RSP
            lea RAX, Lresume; mov RDX, 0x6C16;  db 0x0F; db 0x79; db 0xD0;   // VMWRITE HOST_RIP
            // load guest GPRs from *regs (KvmRegs: rax@0 rbx@8 rcx@16 rdx@24 rsi@32 rdi@40 rbp@56
            //  r8@64 r9@72 r10@80 r11@88 r12@96 r13@104 r14@112 r15@120)
            mov R15, RBX;               // R15 = regs
            mov RBX, launchInsn;        // RBX = launch/resume opcode — read the D local NOW, while
                                        // RBP is still the HOST frame pointer.  (Reading it after the
                                        // guest-RBP load below faulted: the compiler addresses the
                                        // local RBP-relative, and RBP would then be the guest value.)
            mov RAX, [R15 + 0];
            mov RCX, [R15 + 16];
            mov RDX, [R15 + 24];
            mov RSI, [R15 + 32];
            mov RDI, [R15 + 40];
            mov RBP, [R15 + 56];        // guest RBP — NO RBP-relative D-local access past this point
            mov R8,  [R15 + 64];
            mov R9,  [R15 + 72];
            mov R10, [R15 + 80];
            mov R11, [R15 + 88];
            mov R12, [R15 + 96];
            mov R13, [R15 + 104];
            mov R14, [R15 + 112];
            // choose VMLAUNCH vs VMRESUME by the register (not a D local); load guest RBX+R15 LAST.
            cmp RBX, 0xC2;
            jne Ldo_resume;
            mov RBX, [R15 + 8];         // guest RBX
            mov R15, [R15 + 120];       // guest R15 (LAST — clobbers the regs base)
            db 0x0F; db 0x01; db 0xC2;  // VMLAUNCH
            jmp Lentry_fail;
        Ldo_resume:;
            mov RBX, [R15 + 8];         // guest RBX
            mov R15, [R15 + 120];       // guest R15 (LAST)
            db 0x0F; db 0x01; db 0xC3;  // VMRESUME
            jmp Lentry_fail;            // fall-through after either = ENTRY FAILURE
        Lentry_fail:;
            // host RSP is intact here (entry failed before guest ran); pop host GPRs
            pop R15; pop R14; pop R13; pop R12; pop R11; pop R10; pop R9; pop R8;
            pop RDI; pop RSI; pop RDX; pop RCX; pop RBX; pop RBP;
            mov entryFail, 1;
            jmp Ltrans_done;
        Lresume:;
            // VM-exit landed here (HOST_RIP).  All GPRs hold GUEST values; HOST_RSP restored RSP.
            // Free a scratch: push guest RAX, get regs ptr from the saved host RBX on the stack.
            push RAX;                   // [RSP] = guest RAX
            // saved host GPRs are below: after the 14 pushes + this push, host RBX is at a fixed
            // offset.  Order pushed: RBP,RBX,RCX,RDX,RSI,RDI,R8..R15 then (here) RAX.
            // From RSP: RAX@0, R15@8, R14@16, R13@24, R12@32, R11@40, R10@48, R9@56, R8@64,
            //           RDI@72, RSI@80, RDX@88, RCX@96, RBX@104(host RBX=regs), RBP@112.
            mov RAX, [RSP + 104];       // RAX = regs (saved host RBX)
            mov [RAX + 8],   RBX;
            mov [RAX + 16],  RCX;
            mov [RAX + 24],  RDX;
            mov [RAX + 32],  RSI;
            mov [RAX + 40],  RDI;
            mov [RAX + 56],  RBP;
            mov [RAX + 64],  R8;
            mov [RAX + 72],  R9;
            mov [RAX + 80],  R10;
            mov [RAX + 88],  R11;
            mov [RAX + 96],  R12;
            mov [RAX + 104], R13;
            mov [RAX + 112], R14;
            mov [RAX + 120], R15;
            pop RCX;                    // RCX = guest RAX (popped)
            mov [RAX + 0], RCX;
            // restore host GPRs
            pop R15; pop R14; pop R13; pop R12; pop R11; pop R10; pop R9; pop R8;
            pop RDI; pop RSI; pop RDX; pop RCX; pop RBX; pop RBP;
            mov entryFail, 0;
        Ltrans_done:;
        }
    }

    if (entryFail) {
        const uint err = cast(uint)vmxRead(VMCS_INSTRUCTION_ERROR);
        klog("[vmx] VM-entry failed, instruction-error="); klog_hex(err); klog("\n");
        return VMX_NOHW;
    }
    vc.launched = true;
    // The injected vector (if any) was consumed from the IRR at plan time
    // (vmxPlanInjection), so nothing to clear here.
    // decode the VM-exit
    const uint reason = cast(uint)vmxRead(VMCS_EXIT_REASON) & 0xFFFF;
    const ulong qual  = vmxRead(VMCS_EXIT_QUALIFICATION);
    const ulong gpa   = vmxRead(VMCS_GUEST_PHYS_ADDR);
    const ulong ilen  = vmxRead(VMCS_EXIT_INSTR_LEN);
    vmxDecodeExit(reason, qual, gpa, 0, cast(uint)ilen, xi);
    // sync guest RIP/RSP/RFLAGS back for the caller
    regs.rip    = vmxRead(VMCS_GUEST_RIP);
    regs.rsp    = vmxRead(VMCS_GUEST_RSP);
    regs.rflags = vmxRead(VMCS_GUEST_RFLAGS);
    return VMX_OK;
}

// A flat 32-bit segment (code/data) for the first-light guest.
private KvmSegment vmxFlatSeg(ushort sel, ubyte type, ubyte sbit, ubyte dbit, ubyte gbit, uint limit) {
    KvmSegment g;
    g.selector = sel; g.base = 0; g.limit = limit;
    g.type = type; g.s = sbit; g.dpl = 0; g.present = 1;
    g.db = dbit; g.l = 0; g.g = gbit; g.avl = 0; g.unusable = 0;
    return g;
}

// FIRST-LIGHT boot proof: build a minimal unpaged 32-bit guest whose only instruction is CPUID
// (which VM-exits unconditionally), EPT-map it, and VMLAUNCH it.  A clean exit with reason=10 proves
// the whole guest-entry path (VMCS programming + VMLAUNCH + host-resume) works.  Needs nested EPT
// (VirtualBox exposes it); otherwise it reports the failure honestly.  Runs once at boot.
__gshared bool g_vmxFirstLightDone = false;
public void vmxFirstLightProof() @nogc nothrow {
    if (g_vmxFirstLightDone) return;
    g_vmxFirstLightDone = true;
    if (!vmxDetect()) {
        uint a, b, c, d; x64Cpuid(1, 0, &a, &b, &c, &d);
        klog("[vmx] first-light: vmxDetect=false intel=");
        klog(x64VendorIsIntel() ? "Y" : "N");
        klog(" cpuid1.ecx="); klog_hex(c); klog("\n");
        return;
    }
    import core.virt.kvm : kvmCreateVm, kvmCreateVcpu;

    const int tid = cast(int)g_current_task_id;
    const long vh = kvmCreateVm(tid);
    if (vh < 0) { klog("[vmx] first-light: kvmCreateVm failed\n"); return; }
    uint vo, vg; kvmUnpackHandle(cast(ulong)vh, vo, vg);
    Vm* vm = vmCheck(vo, vg);
    if (vm is null) { klog("[vmx] first-light: vmCheck null\n"); return; }

    const long ch = kvmCreateVcpu(vo, vg, 0);
    if (ch < 0) { klog("[vmx] first-light: kvmCreateVcpu failed\n"); return; }
    uint co, cg; kvmUnpackHandle(cast(ulong)ch, co, cg);
    Vcpu* vc = vcpuCheckObj(co, cg);
    if (vc is null) { klog("[vmx] first-light: vcpuCheckObj null\n"); return; }

    // guest RAM: one page at GPA 0 holding `CPUID ; HLT`.
    const ulong gpage = alloc_phys_page();
    if (gpage == 0) { klog("[vmx] first-light: no guest page\n"); return; }
    auto gp = cast(ubyte*)phys_to_virt(gpage);
    foreach (i; 0 .. 4096) gp[i] = 0;
    gp[0] = 0x0F; gp[1] = 0xA2;   // CPUID
    gp[2] = 0xF4;                 // HLT (in case CPUID somehow doesn't exit)
    if (!slatMap(&vm.slat, 0, gpage, 1 | 2 | 4)) { klog("[vmx] first-light: slatMap failed\n"); return; }

    // Minimal unpaged 32-bit flat protected-mode guest, RIP=0.
    KvmRegs regs;
    regs.rsp = 0x0FF0; regs.rip = 0; regs.rflags = 0x2;
    KvmSRegs s;
    s.cr0 = 0x1;                                     // PE=1, PG=0 (unpaged → needs unrestricted-guest)
    s.cs = vmxFlatSeg(0x08, 0xB, 1, 1, 1, 0xFFFFFFFF);   // code: exec/read/accessed
    s.ds = vmxFlatSeg(0x10, 0x3, 1, 1, 1, 0xFFFFFFFF);   // data: read/write/accessed
    s.es = s.ss = s.fs = s.gs = s.ds;
    s.tr = vmxFlatSeg(0x18, 0xB, 0, 0, 0, 0x67);         // busy 32-bit TSS (system, byte-granular)
    s.ldt.unusable = 1;
    s.gdt.limit = 0xFFFF; s.idt.limit = 0xFFFF;

    VirtExitInfo xi;
    const int rc = vmxEnter(vm, vc, &regs, &s, &xi);
    if (rc == VMX_OK && xi.hardwareReason == EXIT_REASON_CPUID) {
        klog("[vmx] FIRST LIGHT PASS: guest entered and exited on CPUID (reason=10) — VMLAUNCH works\n");
    } else {
        klog("[vmx] first-light: no clean CPUID exit; rc=");
        klog_hex(cast(ulong)cast(uint)rc);
        klog(" reason="); klog_hex(xi.hardwareReason); klog("\n");
    }
}

// Queue an external interrupt (vector) for this vCPU by setting its IRR bit.
// A raised GSI / signaled irqfd / SIGNAL_MSI resolves TO a vector, which lands
// here.  Delivery is deferred to VM-entry, where vmxPlanInjection picks the
// highest pending vector and injects it only when the guest is interruptible
// (else it arms interrupt-window exiting) — so unlike a raw entry-info write,
// this honors guest RFLAGS.IF.
public void vmxInjectExtInt(Vcpu* vc, ubyte vector) @nogc nothrow {
    if (vc is null) return;
    // single-slot pending: keep the highest-priority (highest vector) pending.
    if ((vc.pendingIntrInfo & 0x8000_0000u) == 0 || vector >= (vc.pendingIntrInfo & 0xFF))
        vc.pendingIntrInfo = 0x8000_0000u | vector;
}

struct InjectPlan { uint info; bool wantWindow; }

// Resolve the vCPU's pending interrupt into a VM-entry injection decision.
//   - nothing pending             -> {info:0, wantWindow:false}
//   - pending & interruptible     -> consume it,
//                                    {info: valid|external|vector, wantWindow:false}
//   - pending & NOT interruptible -> {info:0, wantWindow:true} (arm window exit;
//                                     the pending slot is kept for next time)
// Interruptible = guest RFLAGS.IF set AND no STI/MOV-SS interrupt shadow.
private InjectPlan vmxPlanInjection(Vcpu* vc, ulong guestRflags, uint interruptibility) @nogc nothrow {
    InjectPlan p;
    p.info = 0; p.wantWindow = false;
    if (vc is null) return p;
    if ((vc.pendingIntrInfo & 0x8000_0000u) == 0) return p; // nothing pending
    const bool shadowed = (interruptibility & 0x3) != 0; // STI(1) / MOV-SS(2) blocking
    const bool interruptible = ((guestRflags & (1UL << 9)) != 0) && !shadowed; // RFLAGS.IF
    if (interruptible) {
        p.info = vc.pendingIntrInfo;   // valid | type=external(0) | vector
        vc.pendingIntrInfo = 0;        // consume
    } else {
        p.wantWindow = true;
    }
    return p;
}

// INTERRUPT-INJECTION FIRST-LIGHT boot proof.  This proves the *delivery*
// mechanism the whole interrupt tier depends on: that a vector queued by the
// host is actually delivered into the guest and runs the guest's handler.
//
// The guest is one unpaged 32-bit page at GPA 0 with a real IDT + GDT:
//   0x000  fallback: hlt ; jmp $         (never reached if injection works)
//   0x040  handler:  mov byte [0x800],0xA5 ; hlt
//   0x400  IDT (limit 0x1FF): entry 0x30 -> handler @0x040, selector 0x08, 0x8E
//   0x600  GDT (limit 0x17): null / flat code32 (0x08) / flat data32 (0x10)
//   0x800  sentinel byte (init 0; handler writes 0xA5)
// We queue vector 0x30 and enter.  The CPU delivers it through IDT[0x30] BEFORE
// executing RIP=0, runs the handler (which writes the sentinel then HLTs), and
// VM-exits on HLT (reason 12).  PASS = sentinel==0xA5 AND reason==HLT: the CPU
// really vectored our injected interrupt into the guest and ran its code.
__gshared bool g_vmxIntrFirstLightDone = false;
public void vmxInterruptFirstLightProof() @nogc nothrow {
    if (g_vmxIntrFirstLightDone) return;
    g_vmxIntrFirstLightDone = true;
    if (!vmxDetect()) return;   // first-light (CPUID) proof already reported why
    import core.virt.kvm : kvmCreateVm, kvmCreateVcpu;

    const int tid = cast(int)g_current_task_id;
    const long vh = kvmCreateVm(tid);
    if (vh < 0) { klog("[vmx] intr-first-light: kvmCreateVm failed\n"); return; }
    uint vo, vg; kvmUnpackHandle(cast(ulong)vh, vo, vg);
    Vm* vm = vmCheck(vo, vg);
    if (vm is null) { klog("[vmx] intr-first-light: vmCheck null\n"); return; }

    const long ch = kvmCreateVcpu(vo, vg, 0);
    if (ch < 0) { klog("[vmx] intr-first-light: kvmCreateVcpu failed\n"); return; }
    uint co, cg; kvmUnpackHandle(cast(ulong)ch, co, cg);
    Vcpu* vc = vcpuCheckObj(co, cg);
    if (vc is null) { klog("[vmx] intr-first-light: vcpuCheckObj null\n"); return; }

    const ulong gpage = alloc_phys_page();
    if (gpage == 0) { klog("[vmx] intr-first-light: no guest page\n"); return; }
    auto gp = cast(ubyte*)phys_to_virt(gpage);
    foreach (i; 0 .. 4096) gp[i] = 0;

    // 0x000 fallback: hlt ; jmp $-1  (F4 EB FD) — reached only if delivery fails.
    gp[0x000] = 0xF4; gp[0x001] = 0xEB; gp[0x002] = 0xFD;
    // 0x040 handler: mov byte ptr [0x800],0xA5 ; hlt  (C6 05 00 08 00 00 A5 F4)
    gp[0x040] = 0xC6; gp[0x041] = 0x05; gp[0x042] = 0x00; gp[0x043] = 0x08;
    gp[0x044] = 0x00; gp[0x045] = 0x00; gp[0x046] = 0xA5; gp[0x047] = 0xF4;
    // 0x580 = IDT[0x30]: offset15:0=0x0040, sel=0x08, ist/rsvd=0, type=0x8E, offset31:16=0
    gp[0x580] = 0x40; gp[0x581] = 0x00; gp[0x582] = 0x08; gp[0x583] = 0x00;
    gp[0x584] = 0x00; gp[0x585] = 0x8E; gp[0x586] = 0x00; gp[0x587] = 0x00;
    // 0x608 = GDT[1] flat code32 (sel 0x08): FF FF 00 00 00 9B CF 00
    gp[0x608] = 0xFF; gp[0x609] = 0xFF; gp[0x60A] = 0x00; gp[0x60B] = 0x00;
    gp[0x60C] = 0x00; gp[0x60D] = 0x9B; gp[0x60E] = 0xCF; gp[0x60F] = 0x00;
    // 0x610 = GDT[2] flat data32 (sel 0x10): FF FF 00 00 00 93 CF 00
    gp[0x610] = 0xFF; gp[0x611] = 0xFF; gp[0x612] = 0x00; gp[0x613] = 0x00;
    gp[0x614] = 0x00; gp[0x615] = 0x93; gp[0x616] = 0xCF; gp[0x617] = 0x00;
    // 0x800 sentinel already 0.
    if (!slatMap(&vm.slat, 0, gpage, 1 | 2 | 4)) { klog("[vmx] intr-first-light: slatMap failed\n"); return; }

    KvmRegs regs;
    regs.rsp = 0x0FF0; regs.rip = 0; regs.rflags = 0x202;  // IF=1 (bit9) + reserved bit1
    KvmSRegs s;
    s.cr0 = 0x1;                                          // PE=1, PG=0 (unpaged → unrestricted-guest)
    s.cs = vmxFlatSeg(0x08, 0xB, 1, 1, 1, 0xFFFFFFFF);
    s.ds = vmxFlatSeg(0x10, 0x3, 1, 1, 1, 0xFFFFFFFF);
    s.es = s.ss = s.fs = s.gs = s.ds;
    s.tr = vmxFlatSeg(0x18, 0xB, 0, 0, 0, 0x67);         // busy 32-bit TSS
    s.ldt.unusable = 1;
    s.gdt.base = 0x600; s.gdt.limit = 0x17;              // real GDT (CS reload on delivery reads it)
    s.idt.base = 0x400; s.idt.limit = 0x1FF;             // real IDT (delivery reads IDT[0x30])

    vmxInjectExtInt(vc, 0x30);                           // queue the interrupt
    VirtExitInfo xi;
    const int rc = vmxEnter(vm, vc, &regs, &s, &xi);
    const ubyte sentinel = gp[0x800];
    if (rc == VMX_OK && xi.hardwareReason == EXIT_REASON_HLT && sentinel == 0xA5) {
        klog("[vmx] INTR FIRST LIGHT PASS: injected vector 0x30 delivered — guest handler ran (sentinel=0xA5, HLT exit)\n");
    } else {
        klog("[vmx] intr-first-light: FAIL rc=");
        klog_hex(cast(ulong)cast(uint)rc);
        klog(" reason="); klog_hex(xi.hardwareReason);
        klog(" sentinel="); klog_hex(sentinel); klog("\n");
        // diagnostic dump: raw exit reason (bit31 = entry-failure), qualification,
        // VM-instruction error, guest RIP, and the entry-interruption-info readback.
        klog("[vmx]   rawReason="); klog_hex(vmxRead(VMCS_EXIT_REASON));
        klog(" qual="); klog_hex(vmxRead(VMCS_EXIT_QUALIFICATION));
        klog(" instrErr="); klog_hex(vmxRead(VMCS_INSTRUCTION_ERROR));
        klog(" gRIP="); klog_hex(vmxRead(VMCS_GUEST_RIP));
        klog(" entryInfo="); klog_hex(vmxRead(VMCS_ENTRY_INTR_INFO)); klog("\n");
    }
}

// INTERRUPT-WINDOW / IF-GATING proof.  Two parts:
//  (1) unit-test vmxPlanInjection: IF-gating (IF=0 -> window, not injected),
//      priority (highest vector first), and consume-once semantics.
//  (2) hardware: a guest that starts with interrupts DISABLED (RFLAGS.IF=0),
//      runs `sti; nop; hlt`, with vector 0x30 queued.  On the first entry the
//      interrupt is NOT injectable (IF=0) so interrupt-window exiting is armed;
//      once the guest enables interrupts the CPU exits (reason 7), we re-enter,
//      and now-interruptible the vector is injected -> the handler runs.
//      PASS = the handler ran (sentinel) after the window opened, proving
//      delivery respects guest IF and the window mechanism works.
__gshared bool g_vmxIntrWindowDone = false;
public void vmxInterruptWindowProof() @nogc nothrow {
    if (g_vmxIntrWindowDone) return;
    g_vmxIntrWindowDone = true;
    if (!vmxDetect()) return;

    // (1) logic unit-test — no hardware needed.
    {
        Vcpu tv; tv.pendingIntrInfo = 0;
        const InjectPlan e = vmxPlanInjection(&tv, 0x202, 0);           // empty -> nothing
        tv.pendingIntrInfo = 0x8000_0000u | 0x41;
        const InjectPlan w = vmxPlanInjection(&tv, 0x0002, 0);          // pending, IF=0 -> window
        const InjectPlan hi = vmxPlanInjection(&tv, 0x202, 0);          // IF=1 -> inject 0x41
        const InjectPlan em = vmxPlanInjection(&tv, 0x202, 0);          // consumed -> empty
        Vcpu tv2; tv2.pendingIntrInfo = 0x8000_0000u | 0x20;           // IF=1 but STI-shadow
        const InjectPlan sh = vmxPlanInjection(&tv2, 0x202, 0x1);       // shadow bit0 -> blocked
        const bool ok = e.info == 0 && !e.wantWindow
                     && w.info == 0 && w.wantWindow
                     && hi.info == (0x8000_0000u | 0x41) && !hi.wantWindow
                     && em.info == 0 && !em.wantWindow
                     && sh.info == 0 && sh.wantWindow;
        klog(ok ? "[vmx] inject-plan logic PASS (IF-gate + consume + STI-shadow)\n"
                : "[vmx] inject-plan logic FAIL\n");
    }

    // (2) hardware interrupt-window test.
    import core.virt.kvm : kvmCreateVm, kvmCreateVcpu;
    const int tid = cast(int)g_current_task_id;
    const long vh = kvmCreateVm(tid);
    if (vh < 0) { klog("[vmx] intr-window: kvmCreateVm failed\n"); return; }
    uint vo, vg; kvmUnpackHandle(cast(ulong)vh, vo, vg);
    Vm* vm = vmCheck(vo, vg);
    if (vm is null) { klog("[vmx] intr-window: vmCheck null\n"); return; }
    const long ch = kvmCreateVcpu(vo, vg, 0);
    if (ch < 0) { klog("[vmx] intr-window: kvmCreateVcpu failed\n"); return; }
    uint co, cg; kvmUnpackHandle(cast(ulong)ch, co, cg);
    Vcpu* vc = vcpuCheckObj(co, cg);
    if (vc is null) { klog("[vmx] intr-window: vcpuCheckObj null\n"); return; }

    const ulong gpage = alloc_phys_page();
    if (gpage == 0) { klog("[vmx] intr-window: no guest page\n"); return; }
    auto gp = cast(ubyte*)phys_to_virt(gpage);
    foreach (i; 0 .. 4096) gp[i] = 0;
    // 0x000: sti ; nop ; hlt  (FB 90 F4) — enable interrupts, clear the STI shadow, halt
    gp[0x000] = 0xFB; gp[0x001] = 0x90; gp[0x002] = 0xF4;
    // 0x040 handler: mov byte [0x800],0xA5 ; hlt
    gp[0x040] = 0xC6; gp[0x041] = 0x05; gp[0x042] = 0x00; gp[0x043] = 0x08;
    gp[0x044] = 0x00; gp[0x045] = 0x00; gp[0x046] = 0xA5; gp[0x047] = 0xF4;
    // IDT[0x30] -> handler, GDT[1]/[2] flat code/data (same as intr-first-light)
    gp[0x580] = 0x40; gp[0x581] = 0x00; gp[0x582] = 0x08; gp[0x583] = 0x00;
    gp[0x584] = 0x00; gp[0x585] = 0x8E; gp[0x586] = 0x00; gp[0x587] = 0x00;
    gp[0x608] = 0xFF; gp[0x609] = 0xFF; gp[0x60A] = 0x00; gp[0x60B] = 0x00;
    gp[0x60C] = 0x00; gp[0x60D] = 0x9B; gp[0x60E] = 0xCF; gp[0x60F] = 0x00;
    gp[0x610] = 0xFF; gp[0x611] = 0xFF; gp[0x612] = 0x00; gp[0x613] = 0x00;
    gp[0x614] = 0x00; gp[0x615] = 0x93; gp[0x616] = 0xCF; gp[0x617] = 0x00;
    if (!slatMap(&vm.slat, 0, gpage, 1 | 2 | 4)) { klog("[vmx] intr-window: slatMap failed\n"); return; }

    KvmRegs regs;
    regs.rsp = 0x0FF0; regs.rip = 0; regs.rflags = 0x2;   // IF=0 — interrupts DISABLED at start
    KvmSRegs s;
    s.cr0 = 0x1;
    s.cs = vmxFlatSeg(0x08, 0xB, 1, 1, 1, 0xFFFFFFFF);
    s.ds = vmxFlatSeg(0x10, 0x3, 1, 1, 1, 0xFFFFFFFF);
    s.es = s.ss = s.fs = s.gs = s.ds;
    s.tr = vmxFlatSeg(0x18, 0xB, 0, 0, 0, 0x67);
    s.ldt.unusable = 1;
    s.gdt.base = 0x600; s.gdt.limit = 0x17;
    s.idt.base = 0x400; s.idt.limit = 0x1FF;

    vmxInjectExtInt(vc, 0x30);   // queue while IF=0 -> must be withheld until the window opens
    VirtExitInfo xi;
    bool delivered = false, sawWindow = false;
    int lastReason = -1;
    foreach (iter; 0 .. 8) {
        const int rc = vmxEnter(vm, vc, &regs, &s, &xi);
        if (rc != VMX_OK) { lastReason = -2; break; }
        lastReason = cast(int)xi.hardwareReason;
        if (xi.hardwareReason == EXIT_REASON_INTERRUPT_WINDOW) { sawWindow = true; continue; } // re-enter
        if (xi.hardwareReason == EXIT_REASON_HLT) break;
        break; // unexpected exit
    }
    delivered = (gp[0x800] == 0xA5);
    if (delivered && sawWindow) {
        klog("[vmx] INTR WINDOW PASS: IF=0 held the interrupt; window opened -> delivered (handler ran)\n");
    } else {
        klog("[vmx] intr-window: FAIL delivered=");
        klog_hex(delivered ? 1 : 0);
        klog(" sawWindow="); klog_hex(sawWindow ? 1 : 0);
        klog(" lastReason="); klog_hex(cast(ulong)cast(uint)lastReason); klog("\n");
    }
}

// MMIO first-light proof: a guest whose only instruction is a store to an
// UNMAPPED guest-physical address faults with an EPT violation (SLAT fault).
// We run the real dispatch (-> KVM_EXIT_MMIO with len=0) and then the MMIO
// enrichment (instruction decode) and assert it recovered the access width and
// the written value.  This proves the EPT-violation -> decode -> fill-data path
// that device MMIO and ioeventfd depend on.
__gshared bool g_vmxMmioDone = false;
public void vmxMmioFirstLightProof() @nogc nothrow {
    if (g_vmxMmioDone) return;
    g_vmxMmioDone = true;
    if (!vmxDetect()) return;
    import core.virt.kvm : kvmCreateVm, kvmCreateVcpu;
    import core.virt.kvmabi : KvmRun, KVM_EXIT_MMIO;
    import core.virt.vmexit : virtDispatchExit;
    import core.virt.mmio : mmioEnrichMmioExit;

    const int tid = cast(int)g_current_task_id;
    const long vh = kvmCreateVm(tid);
    if (vh < 0) { klog("[vmx] mmio: kvmCreateVm failed\n"); return; }
    uint vo, vg; kvmUnpackHandle(cast(ulong)vh, vo, vg);
    Vm* vm = vmCheck(vo, vg);
    if (vm is null) { klog("[vmx] mmio: vmCheck null\n"); return; }
    const long ch = kvmCreateVcpu(vo, vg, 0);
    if (ch < 0) { klog("[vmx] mmio: kvmCreateVcpu failed\n"); return; }
    uint co, cg; kvmUnpackHandle(cast(ulong)ch, co, cg);
    Vcpu* vc = vcpuCheckObj(co, cg);
    if (vc is null) { klog("[vmx] mmio: vcpuCheckObj null\n"); return; }

    const ulong gpage = alloc_phys_page();
    if (gpage == 0) { klog("[vmx] mmio: no guest page\n"); return; }
    auto gp = cast(ubyte*)phys_to_virt(gpage);
    foreach (i; 0 .. 4096) gp[i] = 0;
    // mov dword [0x2000], 0x12345678  (C7 05 <disp32=0x2000> <imm32>) ; hlt
    gp[0] = 0xC7; gp[1] = 0x05; gp[2] = 0x00; gp[3] = 0x20; gp[4] = 0x00; gp[5] = 0x00;
    gp[6] = 0x78; gp[7] = 0x56; gp[8] = 0x34; gp[9] = 0x12;
    gp[10] = 0xF4;                                        // hlt (unreached: the store faults)
    if (!slatMap(&vm.slat, 0, gpage, 1 | 2 | 4)) { klog("[vmx] mmio: slatMap failed\n"); return; }
    // GPA 0x2000 is deliberately left UNMAPPED -> the store EPT-violates.

    KvmRegs regs;
    regs.rsp = 0x0FF0; regs.rip = 0; regs.rflags = 0x2;
    KvmSRegs s;
    s.cr0 = 0x1;                                          // PE=1, PG=0 (unpaged flat)
    s.cs = vmxFlatSeg(0x08, 0xB, 1, 1, 1, 0xFFFFFFFF);
    s.ds = vmxFlatSeg(0x10, 0x3, 1, 1, 1, 0xFFFFFFFF);
    s.es = s.ss = s.fs = s.gs = s.ds;
    s.tr = vmxFlatSeg(0x18, 0xB, 0, 0, 0, 0x67);
    s.ldt.unusable = 1;
    s.gdt.limit = 0xFFFF; s.idt.limit = 0xFFFF;

    VirtExitInfo xi;
    const int rc = vmxEnter(vm, vc, &regs, &s, &xi);
    if (rc != VMX_OK || xi.hardwareReason != EXIT_REASON_EPT_VIOLATION) {
        klog("[vmx] mmio: FAIL no EPT-violation exit rc=");
        klog_hex(cast(ulong)cast(uint)rc); klog(" reason="); klog_hex(xi.hardwareReason); klog("\n");
        return;
    }
    // Persist post-exit regs (as kvmVcpuRun does) so the decode reads current state.
    foreach (i; 0 .. 18) vc.regs[i] = (&regs.rax)[i];
    const ulong rpage = alloc_phys_page();
    if (rpage == 0) { klog("[vmx] mmio: no run page\n"); return; }
    auto run = cast(KvmRun*)phys_to_virt(rpage);
    foreach (i; 0 .. KvmRun.sizeof) (cast(ubyte*)run)[i] = 0;
    cast(void) virtDispatchExit(xi, run, vm, vc);         // -> KVM_EXIT_MMIO, physAddr=0x2000, len=0
    const bool enriched = mmioEnrichMmioExit(vm, vc, &regs, &s, run);

    ulong wr = 0; foreach (k; 0 .. 4) wr |= (cast(ulong)run.u.mmio.data[k]) << (8 * k);
    if (enriched && run.exitReason == KVM_EXIT_MMIO && run.u.mmio.physAddr == 0x2000
        && run.u.mmio.len == 4 && run.u.mmio.isWrite == 1 && wr == 0x12345678) {
        klog("[vmx] MMIO FIRST LIGHT PASS: EPT-violation store decoded (gpa=0x2000 len=4 data=0x12345678)\n");
    } else {
        klog("[vmx] mmio: FAIL enriched="); klog_hex(enriched ? 1 : 0);
        klog(" gpa="); klog_hex(run.u.mmio.physAddr);
        klog(" len="); klog_hex(run.u.mmio.len);
        klog(" data="); klog_hex(wr); klog("\n");
    }
    free_phys_page(rpage);
}
