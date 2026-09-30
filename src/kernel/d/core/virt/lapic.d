// In-kernel local APIC + per-vCPU hypervisor state for a Linux-capable guest.
//
// Cloud Hypervisor runs guests with a SPLIT irqchip (KVM_CAP_SPLIT_IRQCHIP): the IOAPIC and PIC
// are emulated in the VMM, and only each vCPU's LOCAL APIC lives in the kernel.  Device interrupts
// reach it as MSIs (irqfd + GSI routes, or KVM_SIGNAL_MSI); the guest programs it through the
// x2APIC MSRs (0x800..0x8FF) or the xAPIC MMIO page; its timer (TSC-deadline, one-shot or
// periodic) is the guest's clock-event device.  Without it a Linux guest has no timer interrupt
// at all, so this is what stands between "a test guest prints a string" and "Linux boots".
//
// The per-vCPU hypervisor page (VcpuHv) also carries everything a VM exit must not lose that the
// VMCS/KVM caches did not: the MSR store and the VMX MSR load/store areas (syscall MSRs are
// switched by hardware on entry/exit), CR2, the interrupt shadow, SYSENTER, DR7, a pending
// exception, the event a VM exit cut off mid-delivery (IDT-vectoring info), and kvmclock.
//
// One page per vCPU, allocated lazily and indexed by vmFlatVcpuIndex -- a SIDE table, because
// growing the Vcpu struct trips a size-dependent boot regression (see core.virt.vm).
module core.virt.lapic;

import core.io : klog, klog_hex, klog_dec;
import core.exports : phys_to_virt;
import memory.mm : alloc_phys_page, free_phys_page;
import core.virt.vm : Vm, Vcpu, vmFlatVcpuIndex, VIRT_MAX_VMS, VIRT_MAX_VCPUS_PER_VM;
import core.virt.slat : slatLookup;

// ── xAPIC register offsets (the kvm_lapic_state image uses the same layout) ──────────────────
enum uint APIC_ID = 0x20, APIC_LVR = 0x30, APIC_TASKPRI = 0x80, APIC_ARBPRI = 0x90,
          APIC_PROCPRI = 0xA0, APIC_EOI = 0xB0, APIC_RRR = 0xC0, APIC_LDR = 0xD0, APIC_DFR = 0xE0,
          APIC_SPIV = 0xF0, APIC_ISR = 0x100, APIC_TMR = 0x180, APIC_IRR = 0x200, APIC_ESR = 0x280,
          APIC_LVTCMCI = 0x2F0, APIC_ICR = 0x300, APIC_ICR2 = 0x310, APIC_LVTT = 0x320,
          APIC_LVTTHMR = 0x330, APIC_LVTPC = 0x340, APIC_LVT0 = 0x350, APIC_LVT1 = 0x360,
          APIC_LVTERR = 0x370, APIC_TMICT = 0x380, APIC_TMCCT = 0x390, APIC_TDCR = 0x3E0,
          APIC_SELF_IPI = 0x3F0;
enum uint LVT_MASKED = 1u << 16;
enum ulong APIC_BASE_BSP = 1UL << 8, APIC_BASE_EXTD = 1UL << 10, APIC_BASE_EN = 1UL << 11;
enum ulong APIC_DEFAULT_BASE = 0xFEE0_0000UL;

// VMX MSR load/store area entry (SDM 24.7.2): 16 bytes, 16-byte aligned.
struct VmxMsrEnt { uint index; uint reserved; ulong value; }

// MSRs the hardware switches on entry/exit (guest value loaded at entry, stored at exit; host
// value reloaded at exit).  The guest runs SYSCALL/SWAPGS/RDTSCP natively, so these must hold the
// GUEST's values while it runs -- and the host's the moment it stops (this kernel uses them too).
enum uint MSR_STAR = 0xC0000081, MSR_LSTAR = 0xC0000082, MSR_CSTAR = 0xC0000083,
          MSR_SFMASK = 0xC0000084, MSR_KERNEL_GS_BASE = 0xC0000102, MSR_TSC_AUX = 0xC0000103;
immutable uint[6] HV_SWAP_MSRS = [MSR_STAR, MSR_LSTAR, MSR_CSTAR, MSR_SFMASK, MSR_KERNEL_GS_BASE,
                                  MSR_TSC_AUX];

struct VLapic {
    uint[256] regs;        // 1024-byte kvm_lapic_state image: the register at offset o is regs[o/4]
    ulong apicBase;        // IA32_APIC_BASE
    ulong tscDeadline;     // IA32_TSC_DEADLINE (TSC-deadline mode), 0 = disarmed
    ulong timerExpiry;     // one-shot/periodic expiry in host TSC, 0 = disarmed
    ulong timerPeriod;     // periodic reload in TSC ticks (0 = one-shot)
    ulong timerStart;      // TSC when TMICT was written (for TMCCT)
}

struct VcpuHv {
    VmxMsrEnt[8] guestMsrs;   // VM-entry MSR-load AND VM-exit MSR-store area: the live guest values
    VmxMsrEnt[8] hostMsrs;    // VM-exit MSR-load area: host values, captured at each entry
    uint  nSwap;
    bool  inited;
    bool  lapicOn;            // this vCPU has an in-kernel LAPIC (split irqchip)
    bool  halted;             // HLT executed; waiting for an interrupt
    bool  nmiPending;
    VLapic lapic;
    // guest state the VMCS holds but the KVM cache (KvmSRegs) does not
    ulong cr2;
    uint  interruptibility;   // STI / MOV-SS blocking, carried across exits
    ulong dr7;
    ulong sysenterCs, sysenterEsp, sysenterEip;
    ulong pat;
    ulong debugctl;
    ulong xcr0;
    // an event a VM exit interrupted mid-delivery, re-injected at the next entry
    uint  reinjectInfo;       // IDT-vectoring info (bit 31 = valid)
    uint  reinjectErr;
    uint  reinjectLen;
    // an exception the in-kernel emulation raised (e.g. #GP for an unknown MSR)
    uint  excInfo;            // VM-entry interruption info form (bit 31 = valid)
    uint  excErr;
    // level-triggered EOI to hand to the VMM's IOAPIC (KVM_EXIT_IOAPIC_EOI), -1 = none
    int   eoiExitVector;
    // generic MSR store: values the guest wrote that need no side effect (MTRRs, MISC_ENABLE...)
    uint  nStore;
    uint[40]  storeIdx;
    ulong[40] storeVal;
    // kvmclock
    ulong kvmSystemTime;      // MSR_KVM_SYSTEM_TIME(_NEW) value (GPA | enable)
    ulong kvmWallClock;       // last MSR_KVM_WALL_CLOCK(_NEW) GPA
    ulong bootTsc;            // TSC at this vCPU's first entry (kvmclock system_time origin)
}
static assert(VcpuHv.sizeof <= 4096);

private __gshared ulong[VIRT_MAX_VMS * VIRT_MAX_VCPUS_PER_VM] g_hvPhys;

ulong hvRdtsc() @nogc nothrow {
    uint lo, hi;
    asm @nogc nothrow { rdtsc; mov lo, EAX; mov hi, EDX; }
    return (cast(ulong)hi << 32) | lo;
}

/// The vCPU's hypervisor page (null = none and !create, or allocation failed).
VcpuHv* hvFor(Vm* vm, Vcpu* vc, bool create) @nogc nothrow {
    if (vm is null || vc is null) return null;
    const uint fi = vmFlatVcpuIndex(vm, vc);
    if (g_hvPhys[fi] == 0) {
        if (!create) return null;
        const ulong p = alloc_phys_page();
        if (p == 0) return null;
        auto b = cast(ubyte*)phys_to_virt(p);
        foreach (i; 0 .. 4096) b[i] = 0;
        g_hvPhys[fi] = p;
        auto hv = cast(VcpuHv*)b;
        hv.eoiExitVector = -1;
        hv.dr7 = 0x400;
        hv.pat = 0x0007_0406_0007_0406UL;          // power-on PAT
        hv.xcr0 = 1;
        foreach (i, idx; HV_SWAP_MSRS) {
            hv.guestMsrs[i].index = idx; hv.guestMsrs[i].value = 0;
            hv.hostMsrs[i].index = idx;
        }
        hv.nSwap = HV_SWAP_MSRS.length;
        // TSC_AUX exists only with RDTSCP; loading a missing MSR at VM exit is a VMX abort.
        if (!hvHaveRdtscp()) hv.nSwap = HV_SWAP_MSRS.length - 1;   // TSC_AUX is last
        lapicReset(&hv.lapic, vc.index);
        hv.inited = true;
    }
    return cast(VcpuHv*)phys_to_virt(g_hvPhys[fi]);
}

/// Host-physical address of the vCPU's page (the VMX MSR areas are at its start), 0 = none.
ulong hvPhysOf(Vm* vm, Vcpu* vc) @nogc nothrow {
    if (vm is null || vc is null) return 0;
    return g_hvPhys[vmFlatVcpuIndex(vm, vc)];
}

ulong hvRdmsr(uint idx) @nogc nothrow {
    uint lo, hi;
    asm @nogc nothrow { mov ECX, idx; rdmsr; mov lo, EAX; mov hi, EDX; }
    return (cast(ulong)hi << 32) | lo;
}

/// The host's values of the switched MSRs, reloaded by the CPU at every VM exit.
void hvHostMsrsCapture(VcpuHv* hv) @nogc nothrow {
    foreach (i; 0 .. hv.nSwap) hv.hostMsrs[i].value = hvRdmsr(hv.hostMsrs[i].index);
}

private bool hvHaveRdtscp() @nogc nothrow {
    uint a = 0x8000_0000, b, c, d;
    asm @nogc nothrow { mov EAX, a; cpuid; mov a, EAX; }
    if (a < 0x8000_0001) return false;
    a = 0x8000_0001;
    asm @nogc nothrow { mov EAX, a; xor ECX, ECX; cpuid; mov d, EDX; }
    return (d & (1u << 27)) != 0;
}

/// Release the page when the vCPU goes away.
void hvRelease(Vm* vm, Vcpu* vc) @nogc nothrow {
    if (vm is null || vc is null) return;
    const uint fi = vmFlatVcpuIndex(vm, vc);
    if (g_hvPhys[fi] != 0) { free_phys_page(g_hvPhys[fi]); g_hvPhys[fi] = 0; }
}

// ── LAPIC model ───────────────────────────────────────────────────────────────────────────────

private uint* reg(VLapic* l, uint off) @nogc nothrow { return &l.regs[(off >> 2) & 0xFF]; }

void lapicReset(VLapic* l, uint id) @nogc nothrow {
    foreach (ref r; l.regs) r = 0;
    *reg(l, APIC_ID) = id << 24;
    *reg(l, APIC_LVR) = 0x0005_0014;               // version 0x14, max LVT 5 (6 LVTs incl. CMCI)
    *reg(l, APIC_DFR) = 0xFFFF_FFFF;
    *reg(l, APIC_SPIV) = 0xFF;                     // software-disabled, spurious vector 0xFF
    foreach (o; [APIC_LVTT, APIC_LVTTHMR, APIC_LVTPC, APIC_LVT0, APIC_LVT1, APIC_LVTERR, APIC_LVTCMCI])
        *reg(l, o) = LVT_MASKED;
    l.apicBase = APIC_DEFAULT_BASE | APIC_BASE_EN | (id == 0 ? APIC_BASE_BSP : 0);
    l.tscDeadline = 0; l.timerExpiry = 0; l.timerPeriod = 0; l.timerStart = 0;
}

bool lapicX2(const(VLapic)* l) @nogc nothrow { return (l.apicBase & APIC_BASE_EXTD) != 0; }
bool lapicEnabled(const(VLapic)* l) @nogc nothrow { return (l.apicBase & APIC_BASE_EN) != 0; }
uint lapicId(VLapic* l) @nogc nothrow { return lapicX2(l) ? *reg(l, APIC_ID) : (*reg(l, APIC_ID) >> 24); }

private bool vecBit(VLapic* l, uint base, uint v) @nogc nothrow {
    return (*reg(l, base + ((v >> 5) << 4)) & (1u << (v & 31))) != 0;
}
private void setVecBit(VLapic* l, uint base, uint v, bool on) @nogc nothrow {
    uint* r = reg(l, base + ((v >> 5) << 4));
    if (on) *r |= (1u << (v & 31)); else *r &= ~(1u << (v & 31));
}
private int highestVec(VLapic* l, uint base) @nogc nothrow {
    foreach_reverse (w; 0 .. 8) {
        const uint r = *reg(l, base + (w << 4));
        if (r == 0) continue;
        foreach_reverse (b; 0 .. 32) if (r & (1u << b)) return w * 32 + b;
    }
    return -1;
}
private uint ppr(VLapic* l) @nogc nothrow {
    const uint tpr = *reg(l, APIC_TASKPRI) & 0xFF;
    const int isrv = highestVec(l, APIC_ISR);
    const uint isrc = isrv < 0 ? 0 : (cast(uint)isrv & 0xF0);
    return ((tpr & 0xF0) >= isrc) ? tpr : isrc;
}

/// An interrupt arrives (MSI / LVT / self-IPI): set it pending; `level` records the trigger mode
/// so its EOI can be forwarded to the VMM's IOAPIC.
void lapicAccept(VcpuHv* hv, uint vector, bool level) @nogc nothrow {
    if (vector < 16) return;                        // vectors 0-15 are illegal for fixed delivery
    auto l = &hv.lapic;
    setVecBit(l, APIC_IRR, vector, true);
    setVecBit(l, APIC_TMR, vector, level);
    hv.halted = false;
}

/// The vector to inject now, or -1: the highest pending one above the processor priority, with the
/// APIC software-enabled.
int lapicPending(VcpuHv* hv) @nogc nothrow {
    auto l = &hv.lapic;
    if (!lapicEnabled(l) || (*reg(l, APIC_SPIV) & 0x100) == 0) return -1;
    const int v = highestVec(l, APIC_IRR);
    if (v < 0) return -1;
    if ((cast(uint)v & 0xF0) <= (ppr(l) & 0xF0)) return -1;
    return v;
}

/// The CPU takes vector `v` (injected at entry): IRR -> ISR.
void lapicAck(VcpuHv* hv, uint v) @nogc nothrow {
    auto l = &hv.lapic;
    setVecBit(l, APIC_IRR, v, false);
    setVecBit(l, APIC_ISR, v, true);
}

private void lapicEoi(VcpuHv* hv) @nogc nothrow {
    auto l = &hv.lapic;
    const int v = highestVec(l, APIC_ISR);
    if (v < 0) return;
    setVecBit(l, APIC_ISR, v, false);
    if (vecBit(l, APIC_TMR, v)) hv.eoiExitVector = v;   // level-triggered: tell the VMM's IOAPIC
}

private ulong timerDivide(VLapic* l) @nogc nothrow {
    const uint d = *reg(l, APIC_TDCR) & 0xB;
    const uint code = (d & 3) | ((d >> 1) & 4);         // bits 0,1,3 -> 0..7
    return code == 7 ? 1 : (2UL << code);
}

// The APIC timer counts the TSC divided by TDCR (the "bus clock" is the TSC here: the guest learns
// the TSC rate from kvmclock, and Linux prefers TSC-deadline mode anyway).
private void armTimer(VLapic* l) @nogc nothrow {
    const uint icr = *reg(l, APIC_TMICT);
    const uint mode = (*reg(l, APIC_LVTT) >> 17) & 3;
    if (icr == 0 || mode == 2) { l.timerExpiry = 0; l.timerPeriod = 0; return; }
    const ulong ticks = cast(ulong)icr * timerDivide(l);
    l.timerStart = hvRdtsc();
    l.timerExpiry = l.timerStart + ticks;
    l.timerPeriod = (mode == 1) ? ticks : 0;
}

/// Fire the timer if it is due (called before every entry and on every halted-vCPU poll).
void lapicPollTimer(VcpuHv* hv) @nogc nothrow {
    auto l = &hv.lapic;
    const uint lvtt = *reg(l, APIC_LVTT);
    const uint mode = (lvtt >> 17) & 3;
    const ulong now = hvRdtsc();
    if (mode == 2) {                                  // TSC-deadline
        if (l.tscDeadline != 0 && now >= l.tscDeadline) {
            l.tscDeadline = 0;
            if (!(lvtt & LVT_MASKED)) lapicAccept(hv, lvtt & 0xFF, false);
        }
        return;
    }
    if (l.timerExpiry != 0 && now >= l.timerExpiry) {
        if (l.timerPeriod != 0) {
            while (l.timerExpiry <= now) l.timerExpiry += l.timerPeriod;
        } else {
            l.timerExpiry = 0;
        }
        if (!(lvtt & LVT_MASKED)) lapicAccept(hv, lvtt & 0xFF, false);
    }
}

/// Anything that should wake a halted vCPU (after polling the timer).
bool lapicWakeable(VcpuHv* hv) @nogc nothrow {
    lapicPollTimer(hv);
    return hv.nmiPending || lapicPending(hv) >= 0;
}

/// Register read (xAPIC offset form).
uint lapicRead(VcpuHv* hv, uint off) @nogc nothrow {
    auto l = &hv.lapic;
    switch (off) {
        case APIC_PROCPRI: return ppr(l);
        case APIC_TMCCT: {
            if (l.timerExpiry == 0) return 0;
            const ulong now = hvRdtsc();
            if (now >= l.timerExpiry) return 0;
            return cast(uint)((l.timerExpiry - now) / timerDivide(l));
        }
        case APIC_EOI, APIC_SELF_IPI: return 0;
        default: return *reg(l, off);
    }
}

/// Register write.  Returns false for a write the architecture rejects (the caller #GPs in x2APIC).
bool lapicWrite(VcpuHv* hv, uint off, uint val) @nogc nothrow {
    auto l = &hv.lapic;
    switch (off) {
        case APIC_ID:      if (!lapicX2(l)) *reg(l, off) = val & 0xFF00_0000; return true;
        case APIC_TASKPRI: *reg(l, off) = val & 0xFF; return true;
        case APIC_EOI:     lapicEoi(hv); return true;
        case APIC_LDR:     if (!lapicX2(l)) *reg(l, off) = val & 0xFF00_0000; return true;
        case APIC_DFR:     if (!lapicX2(l)) *reg(l, off) = val | 0x0FFF_FFFF; return true;
        case APIC_SPIV:    *reg(l, off) = val & 0x13FF; return true;
        case APIC_ESR:     *reg(l, off) = 0; return true;
        case APIC_ICR2:    if (!lapicX2(l)) *reg(l, off) = val & 0xFF00_0000; return true;
        case APIC_ICR:     *reg(l, off) = val & ~(1u << 12); lapicSendIpi(hv, val, *reg(l, APIC_ICR2)); return true;
        case APIC_LVTT:
            *reg(l, off) = val & 0x0007_10FF;
            if (((val >> 17) & 3) != 2) l.tscDeadline = 0;
            return true;
        case APIC_LVTTHMR, APIC_LVTPC, APIC_LVT0, APIC_LVT1, APIC_LVTERR, APIC_LVTCMCI:
            *reg(l, off) = val & 0x0001_F7FF; return true;
        case APIC_TMICT:   *reg(l, off) = val; armTimer(l); return true;
        case APIC_TDCR:    *reg(l, off) = val & 0xB; return true;
        case APIC_SELF_IPI: lapicAccept(hv, val & 0xFF, false); return true;
        default:
            return false;   // read-only or reserved
    }
}

// IPIs.  One vCPU per guest today: fixed-mode IPIs to ourselves (and the self shorthand) are
// delivered; INIT/SIPI/other destinations are recorded for the multi-vCPU tier.
private void lapicSendIpi(VcpuHv* hv, uint lo, uint hi) @nogc nothrow {
    const uint vector = lo & 0xFF;
    const uint mode = (lo >> 8) & 7;
    const uint shorthand = (lo >> 18) & 3;
    const uint dest = lapicX2(&hv.lapic) ? hi : (hi >> 24);
    const bool toSelf = shorthand == 1 || shorthand == 2
                     || (shorthand == 0 && dest == lapicId(&hv.lapic));
    if (!toSelf) return;
    if (mode == 0) lapicAccept(hv, vector, false);
    else if (mode == 4) hv.nmiPending = true;
}

/// x2APIC MSR access (0x800..0x8FF).  false = #GP.
bool lapicMsrRead(VcpuHv* hv, uint msr, ref ulong val) @nogc nothrow {
    auto l = &hv.lapic;
    if (!lapicX2(l)) return false;
    const uint off = (msr - 0x800) << 4;
    if (off == APIC_ICR) { val = (cast(ulong)*reg(l, APIC_ICR2) << 32) | *reg(l, APIC_ICR); return true; }
    if (off == APIC_EOI || off == APIC_SELF_IPI || off == APIC_ICR2 || off == APIC_DFR) return false;
    if (off == APIC_LDR) {           // x2APIC logical ID: cluster (id >> 4) : bit (id & 15)
        const uint id = *reg(l, APIC_ID);
        val = ((id >> 4) << 16) | (1u << (id & 15));
        return true;
    }
    val = lapicRead(hv, off);
    return true;
}
bool lapicMsrWrite(VcpuHv* hv, uint msr, ulong val) @nogc nothrow {
    auto l = &hv.lapic;
    if (!lapicX2(l)) return false;
    const uint off = (msr - 0x800) << 4;
    if (off == APIC_ICR) {
        *reg(l, APIC_ICR2) = cast(uint)(val >> 32);
        return lapicWrite(hv, APIC_ICR, cast(uint)val);
    }
    if (off == APIC_ID || off == APIC_LDR || off == APIC_DFR || off == APIC_ICR2) return false;
    return lapicWrite(hv, off, cast(uint)val);
}

/// IA32_APIC_BASE write (enable / x2APIC switch).  false = #GP (illegal transition).
bool lapicSetBase(VcpuHv* hv, ulong val) @nogc nothrow {
    auto l = &hv.lapic;
    const bool wasX2 = lapicX2(l);
    const bool x2 = (val & APIC_BASE_EXTD) != 0;
    const bool en = (val & APIC_BASE_EN) != 0;
    if (x2 && !en) return false;                     // EXTD without EN is invalid
    if (wasX2 && !x2 && en) return false;            // x2APIC -> xAPIC must go through disabled
    const uint id = lapicId(l);
    l.apicBase = (val & 0xFFFF_F000UL) | (val & (APIC_BASE_EN | APIC_BASE_EXTD)) | (l.apicBase & APIC_BASE_BSP);
    if (x2 && !wasX2) {
        *reg(l, APIC_ID) = id;                       // x2APIC ID is the full 32-bit value
        *reg(l, APIC_LDR) = ((id >> 4) << 16) | (1u << (id & 15));
    } else if (!x2 && wasX2) {
        *reg(l, APIC_ID) = id << 24;
    }
    return true;
}

/// The xAPIC MMIO page this vCPU decodes (0 = none: x2APIC mode or APIC disabled).
ulong lapicMmioBase(VcpuHv* hv) @nogc nothrow {
    auto l = &hv.lapic;
    if (!hv.lapicOn || !lapicEnabled(l) || lapicX2(l)) return 0;
    return l.apicBase & 0x000F_FFFF_FFFF_F000UL;
}

// ── MSI delivery ──────────────────────────────────────────────────────────────────────────────

/// Deliver an MSI (address/data as the device or the VMM's IOAPIC wrote it) to its vCPU's LAPIC.
/// Returns false when the target has no in-kernel LAPIC (caller falls back to the legacy path).
bool lapicDeliverMsi(Vm* vm, uint addressLo, uint addressHi, uint data) @nogc nothrow {
    if (vm is null || vm.vcpuCount == 0) return false;
    uint dest = (addressLo >> 12) & 0xFF;
    dest |= addressHi & 0xFFFF_FF00;                  // x2APIC extended destination
    const uint vector = data & 0xFF;
    const uint mode = (data >> 8) & 7;
    const bool level = (data & (1u << 15)) != 0;
    // physical destination = vCPU index (Cloud Hypervisor assigns APIC ids that way); anything
    // else (logical / broadcast / out of range) goes to vCPU 0.
    uint target = dest < vm.vcpuCount ? dest : 0;
    auto hv = hvFor(vm, &vm.vcpus[target], false);
    if (hv is null || !hv.lapicOn) return false;
    if (mode == 4) { hv.nmiPending = true; hv.halted = false; return true; }
    if (mode == 0 || mode == 1) lapicAccept(hv, vector, level);
    return true;
}

// ── kvmclock (pvclock) ────────────────────────────────────────────────────────────────────────

private bool writeGuest(Vm* vm, ulong gpa, const(void)* src, size_t len) @nogc nothrow {
    auto s = cast(const(ubyte)*)src;
    size_t done = 0;
    while (done < len) {
        const ulong hpa = slatLookup(&vm.slat, (gpa + done) & ~0xFFFUL);
        if (hpa == 0) return false;
        auto page = cast(ubyte*)phys_to_virt(hpa);
        ulong off = (gpa + done) & 0xFFF;
        while (off < 4096 && done < len) { page[off++] = s[done++]; }
    }
    return true;
}

// ns = ((tsc_delta << shift) * mul) >> 32 (the guest's pvclock_scale_delta) -- a port of KVM's
// kvm_get_time_scale(NSEC_PER_SEC, tscHz): the guest computes time with exactly these numbers.
private void pvclockScale(ulong tscHz, out uint mul, out byte shift) @nogc nothrow {
    ulong scaled64 = 1_000_000_000UL;
    ulong tps64 = tscHz;
    int sh = 0;
    while (tps64 > scaled64 * 2 || (tps64 & 0xFFFF_FFFF_0000_0000UL) != 0) { tps64 >>= 1; --sh; }
    uint tps32 = cast(uint)tps64;
    while (tps32 <= scaled64 || (scaled64 & 0xFFFF_FFFF_0000_0000UL) != 0) {
        if ((scaled64 & 0xFFFF_FFFF_0000_0000UL) != 0 || (tps32 & 0x8000_0000u) != 0) scaled64 >>= 1;
        else tps32 <<= 1;
        ++sh;
    }
    mul = cast(uint)((scaled64 << 32) / tps32);
    shift = cast(byte)sh;
}

private struct PvclockVcpuTime {
    uint  ver;
    uint  pad0;
    ulong tscTimestamp;
    ulong systemTime;
    uint  tscToSystemMul;
    byte  tscShift;
    ubyte flags;
    ubyte[2] pad;
}
private struct PvclockWallClock { uint ver; uint sec; uint nsec; }

/// Publish this vCPU's pvclock (MSR_KVM_SYSTEM_TIME_NEW): system_time counts ns from the vCPU's
/// first entry at the host TSC rate, flagged TSC-stable so the guest never needs another update.
void kvmclockPublish(Vm* vm, VcpuHv* hv, ulong tscHz) @nogc nothrow {
    if (vm is null || hv is null || (hv.kvmSystemTime & 1) == 0 || tscHz == 0) return;
    PvclockVcpuTime t;
    const ulong now = hvRdtsc();
    if (hv.bootTsc == 0) hv.bootTsc = now;
    uint mul; byte sh;
    pvclockScale(tscHz, mul, sh);
    t.ver = 2;
    t.tscTimestamp = now;
    const ulong delta = now - hv.bootTsc;
    t.systemTime = (delta / tscHz) * 1_000_000_000UL + ((delta % tscHz) * 1_000_000_000UL) / tscHz;
    t.tscToSystemMul = mul;
    t.tscShift = sh;
    t.flags = 1;                                      // PVCLOCK_TSC_STABLE_BIT
    writeGuest(vm, hv.kvmSystemTime & ~1UL, &t, PvclockVcpuTime.sizeof);
}

/// MSR_KVM_WALL_CLOCK_NEW: the wall-clock time at kvmclock time 0.
void kvmclockWallClock(Vm* vm, VcpuHv* hv, ulong gpa, ulong tscHz, ulong epochSec, ulong epochNsec) @nogc nothrow {
    if (vm is null || hv is null) return;
    hv.kvmWallClock = gpa;
    const ulong now = hvRdtsc();
    if (hv.bootTsc == 0) hv.bootTsc = now;
    // wall at boot = now - (time since boot)
    ulong sinceNs = 0;
    if (tscHz) {
        const ulong d = now - hv.bootTsc;
        sinceNs = (d / tscHz) * 1_000_000_000UL + ((d % tscHz) * 1_000_000_000UL) / tscHz;
    }
    ulong total = epochSec * 1_000_000_000UL + epochNsec;
    total = total > sinceNs ? total - sinceNs : 0;
    PvclockWallClock w;
    w.ver = 2;
    w.sec = cast(uint)(total / 1_000_000_000UL);
    w.nsec = cast(uint)(total % 1_000_000_000UL);
    writeGuest(vm, gpa, &w, PvclockWallClock.sizeof);
}

// ── generic MSR store ─────────────────────────────────────────────────────────────────────────

bool hvStoreGet(VcpuHv* hv, uint idx, ref ulong val) @nogc nothrow {
    foreach (i; 0 .. hv.nStore) if (hv.storeIdx[i] == idx) { val = hv.storeVal[i]; return true; }
    return false;
}
void hvStorePut(VcpuHv* hv, uint idx, ulong val) @nogc nothrow {
    foreach (i; 0 .. hv.nStore) if (hv.storeIdx[i] == idx) { hv.storeVal[i] = val; return; }
    if (hv.nStore < hv.storeIdx.length) { hv.storeIdx[hv.nStore] = idx; hv.storeVal[hv.nStore] = val; ++hv.nStore; }
}

/// Swapped-MSR slot for `idx` in the guest area, or -1.
int hvSwapSlot(VcpuHv* hv, uint idx) @nogc nothrow {
    foreach (i; 0 .. hv.nSwap) if (hv.guestMsrs[i].index == idx) return cast(int)i;
    return -1;
}
