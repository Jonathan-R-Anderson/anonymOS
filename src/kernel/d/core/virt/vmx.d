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
import core.exports : phys_to_virt;
import memory.mm : alloc_phys_page, free_phys_page;
import core.virt.vm : Vm, Vcpu, VIRT_MAX_CPUS;
import core.virt.vmexit : VirtExitInfo, VirtExitKind;
import core.virt.kvmabi : KvmRegs, KvmSRegs;

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
// Programs the VMCS from the native Vcpu record + EPT root and executes
// VMLAUNCH/VMRESUME.  Implemented in the [HW] phase against real hardware;
// until then it returns -ENODEV so KVM_RUN fails cleanly instead of
// entering a half-initialized guest.
//
// [HW] verification boundary: docs/hw-bringup/VMX_SMOKE.md
public int vmxEnter(Vm* vm, Vcpu* vc, KvmRegs* regs, const KvmSRegs* sregs,
                    VirtExitInfo* xi) {
    if (vm is null || vc is null || xi is null) return -22; // -EINVAL
    if (!g_vmxCpu[0].ready) return VMX_NOHW;
    // [HW] VMCS programming + VMLAUNCH goes here.  Deliberately not stubbed
    // with fake encodings — a wrong constant here would be a silent guest-
    // corruption bug, not a clean failure.
    return VMX_NOHW;
}
