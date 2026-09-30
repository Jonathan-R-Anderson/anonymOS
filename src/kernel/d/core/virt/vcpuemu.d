// In-kernel emulation of the VM exits a real OS takes all the time: CPUID, RDMSR/WRMSR, XSETBV,
// MOV CR8 (and the CR0/CR4 bits the VMCS masks), HLT, MONITOR/MWAIT, VMCALL, and the xAPIC MMIO
// page.  Before this each of them went to the VMM as KVM_EXIT_UNKNOWN -- fine for a test guest that
// only prints to a port, fatal for Linux, which executes CPUID and MSR accesses by the hundred
// before it prints its first line.  With a split irqchip Cloud Hypervisor expects exactly these to
// be handled in the kernel (as Linux KVM does), and never sees them.
//
// VMX only (the basic exit reasons below are Intel's); an SVM backend would map its own.
module core.virt.vcpuemu;

import core.io : klog, klog_hex, klog_dec;
import core.virt.vm : Vm, Vcpu;
import core.virt.kvmabi : KvmRegs, KvmSRegs, KvmRun, KvmCpuidEntry2, KVM_EXIT_MMIO;
import core.virt.vmexit : VirtExitInfo;
import core.virt.lapic;

enum EmuResult { NotHandled, Resume, Halt, EoiExit }

private enum uint XR_EXCEPTION_NMI = 0, XR_TRIPLE_FAULT = 2, XR_INTERRUPT_WINDOW = 7, XR_CPUID = 10,
                  XR_HLT = 12, XR_VMCALL = 18, XR_CR_ACCESS = 28, XR_RDMSR = 31, XR_WRMSR = 32,
                  XR_MWAIT = 36, XR_MONITOR = 39, XR_PAUSE = 40, XR_EPT_VIOLATION = 48,
                  XR_XSETBV = 55, XR_WBINVD = 54, XR_INVD = 13;

private enum ulong EFER_SCE = 1, EFER_LME = 1UL << 8, EFER_LMA = 1UL << 10, EFER_NXE = 1UL << 11;

// KvmRegs order: rax rbx rcx rdx rsi rdi rsp rbp r8..r15 rip rflags
private ulong* gpr(KvmRegs* r, uint n) @nogc nothrow {
    // x86 GPR number -> KvmRegs slot
    static immutable ubyte[16] map = [0, 2, 3, 1, 6, 7, 5, 4, 8, 9, 10, 11, 12, 13, 14, 15];
    return &(&r.rax)[map[n & 15]];
}

private void raiseGp(VcpuHv* hv) @nogc nothrow {
    hv.excInfo = 0x8000_0000u | (3u << 8) | (1u << 11) | 13;   // valid | hw exception | errcode | #GP
    hv.excErr = 0;
}
private void raiseUd(VcpuHv* hv) @nogc nothrow {
    hv.excInfo = 0x8000_0000u | (3u << 8) | 6;                 // #UD, no error code
}

private bool canonical(ulong v) @nogc nothrow {
    const long sv = cast(long)(v << 16) >> 16;
    return cast(ulong)sv == v;
}

// ── CPUID ────────────────────────────────────────────────────────────────────────────────────

private void cpuidEmulate(VcpuHv* hv, const(KvmSRegs)* sregs, const(KvmCpuidEntry2)* ents, uint n,
                          uint leaf, uint sub, ref uint a, ref uint b, ref uint c, ref uint d) @nogc nothrow {
    a = b = c = d = 0;
    bool found = false;
    foreach (i; 0 .. n) {
        const e = &ents[i];
        if (e.func != leaf) continue;
        if ((e.flags & 1) != 0 && e.index != sub) continue;   // KVM_CPUID_FLAG_SIGNIFCANT_INDEX
        a = e.eax; b = e.ebx; c = e.ecx; d = e.edx;
        found = true;
        break;
    }
    if (!found) return;
    const uint id = hv.lapicOn ? lapicId(&hv.lapic) : 0;
    if (leaf == 1) {
        c &= ~(1u << 27);
        if (sregs !is null && (sregs.cr4 & (1UL << 18)) != 0) c |= 1u << 27;   // OSXSAVE mirrors CR4
        b = (b & 0x00FF_FFFF) | ((id & 0xFF) << 24);
    } else if (leaf == 7 && sub == 0) {
        c &= ~(1u << 4);
        if (sregs !is null && (sregs.cr4 & (1UL << 22)) != 0) c |= 1u << 4;    // OSPKE mirrors CR4
    } else if (leaf == 0xB || leaf == 0x1F) {
        d = id;
    }
}

// ── MSRs ─────────────────────────────────────────────────────────────────────────────────────

/// Read an MSR as the guest sees it.  false = #GP (host-initiated reads report 0 instead).
bool emuMsrRead(Vm* vm, Vcpu* vc, VcpuHv* hv, KvmSRegs* sregs, uint idx, ref ulong val) @nogc nothrow {
    val = 0;
    if (idx >= 0x800 && idx <= 0x8FF) return lapicMsrRead(hv, idx, val);
    const int slot = hvSwapSlot(hv, idx);
    if (slot >= 0) { val = hv.guestMsrs[slot].value; return true; }
    switch (idx) {
        case 0x10:  val = hvRdtsc(); return true;                           // IA32_TSC
        case 0x1B:  val = hv.lapic.apicBase; return true;                   // IA32_APIC_BASE
        case 0x3A:  val = 1; return true;                                   // FEATURE_CONTROL: locked, no VMX
        case 0x6E0: val = hv.lapic.tscDeadline; return true;                // IA32_TSC_DEADLINE
        case 0x174: val = hv.sysenterCs; return true;
        case 0x175: val = hv.sysenterEsp; return true;
        case 0x176: val = hv.sysenterEip; return true;
        case 0x1D9: val = hv.debugctl; return true;
        case 0x277: val = hv.pat; return true;
        case 0x1A0: if (!hvStoreGet(hv, idx, val)) val = 1 | (1UL << 11) | (1UL << 12); return true;  // MISC_ENABLE
        case 0xC0000080: val = sregs !is null ? sregs.efer : 0; return true;
        case 0xC0000100: val = sregs !is null ? sregs.fs.base : 0; return true;
        case 0xC0000101: val = sregs !is null ? sregs.gs.base : 0; return true;
        case 0x4b564d00, 0x11: val = hv.kvmWallClock; return true;          // kvmclock wall clock
        case 0x4b564d01, 0x12: val = hv.kvmSystemTime; return true;         // kvmclock system time
        // architectural MSRs a VM has no real counterpart for: read as 0 (writes ignored below)
        case 0xFE, 0x2FF, 0x8B, 0x17, 0xCE, 0x179, 0x17A, 0x48, 0x10A, 0xE7, 0xE8, 0x34, 0x140,
             0xDA0, 0x3B, 0x1B0, 0x19A, 0x19B, 0x19C, 0x1A2, 0x122:
            hvStoreGet(hv, idx, val); return true;
        default:
            if (idx >= 0x200 && idx <= 0x26F) { hvStoreGet(hv, idx, val); return true; }  // MTRRs
            if (idx >= 0x400 && idx <= 0x47F) return true;                  // MCi_* banks
            return false;
    }
}

/// Write an MSR.  false = #GP.
bool emuMsrWrite(Vm* vm, Vcpu* vc, VcpuHv* hv, KvmSRegs* sregs, uint idx, ulong val) @nogc nothrow {
    if (idx >= 0x800 && idx <= 0x8FF) return lapicMsrWrite(hv, idx, val);
    const int slot = hvSwapSlot(hv, idx);
    if (slot >= 0) {
        if ((idx == MSR_LSTAR || idx == MSR_CSTAR || idx == MSR_KERNEL_GS_BASE) && !canonical(val)) return false;
        if (idx == MSR_TSC_AUX && (val >> 32) != 0) return false;
        hv.guestMsrs[slot].value = val;
        return true;
    }
    switch (idx) {
        case 0x10: return true;                                             // TSC write: ignored
        case 0x1B: return lapicSetBase(hv, val);
        case 0x6E0: hv.lapic.tscDeadline = val; return true;
        case 0x174: hv.sysenterCs = val & 0xFFFF; return true;
        case 0x175: if (!canonical(val)) return false; hv.sysenterEsp = val; return true;
        case 0x176: if (!canonical(val)) return false; hv.sysenterEip = val; return true;
        case 0x1D9: return true;                                            // DEBUGCTL: LBR etc. not offered
        case 0x277: {                                                       // PAT: each entry must be a valid type
            foreach (k; 0 .. 8) {
                const ubyte t = cast(ubyte)((val >> (8 * k)) & 0xFF);
                if (t == 2 || t == 3 || t > 7) return false;
            }
            hv.pat = val; return true;
        }
        case 0xC0000080: {                                                  // EFER: SCE LME NXE writable
            if ((val & ~(EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE)) != 0) return false;
            if (sregs is null) return true;
            sregs.efer = (val & (EFER_SCE | EFER_LME | EFER_NXE)) | (sregs.efer & EFER_LMA);
            return true;
        }
        case 0xC0000100: if (!canonical(val)) return false; if (sregs) sregs.fs.base = val; return true;
        case 0xC0000101: if (!canonical(val)) return false; if (sregs) sregs.gs.base = val; return true;
        case 0x4b564d01, 0x12: {
            import core.ticks : tscHz;
            hv.kvmSystemTime = val;
            kvmclockPublish(vm, hv, tscHz());
            return true;
        }
        case 0x4b564d00, 0x11: {
            import core.ticks : tscHz;
            import core.syscalls.posix : sys_clock_gettime, timespec;
            timespec ts;
            ulong sec = 0, nsec = 0;
            if (sys_clock_gettime(0, &ts) == 0) { sec = cast(ulong)ts.tv_sec; nsec = cast(ulong)ts.tv_nsec; }
            kvmclockWallClock(vm, hv, val, tscHz(), sec, nsec);
            return true;
        }
        case 0x1A0, 0x2FF, 0x3B, 0x48, 0x179, 0x17A, 0x140, 0x1B0, 0x19A, 0x19B, 0x1A2:
            hvStorePut(hv, idx, val); return true;
        case 0x49, 0x10B, 0x79, 0x8B, 0x122: return true;                  // PRED_CMD, FLUSH_CMD, microcode
        case 0xDA0: return val == 0;                                        // XSS: nothing offered
        default:
            if (idx >= 0x200 && idx <= 0x26F) { hvStorePut(hv, idx, val); return true; }
            if (idx >= 0x400 && idx <= 0x47F) return true;
            return false;
    }
}

// ── the exits ────────────────────────────────────────────────────────────────────────────────

private __gshared uint g_emuUnknownLog, g_emuHltLog;

/// Handle an exit in the kernel.  `sregs` is the vCPU's state cache (mutable: EFER/FS/GS/CRn).
EmuResult vcpuEmulate(Vm* vm, Vcpu* vc, KvmRegs* regs, KvmSRegs* sregs, const ref VirtExitInfo xi,
                      const(KvmCpuidEntry2)* cpuid, uint ncpuid, KvmRun* run) @nogc nothrow {
    auto hv = hvFor(vm, vc, false);
    if (hv is null || regs is null) return EmuResult.NotHandled;
    const uint len = xi.insnLen;
    switch (xi.hardwareReason) {
        case XR_CPUID: {
            uint a, b, c, d;
            cpuidEmulate(hv, sregs, cpuid, ncpuid, cast(uint)regs.rax, cast(uint)regs.rcx, a, b, c, d);
            regs.rax = a; regs.rbx = b; regs.rcx = c; regs.rdx = d;
            regs.rip += len;
            return EmuResult.Resume;
        }
        case XR_RDMSR: {
            ulong v;
            if (emuMsrRead(vm, vc, hv, sregs, cast(uint)regs.rcx, v)) {
                regs.rax = v & 0xFFFF_FFFF; regs.rdx = v >> 32;
                regs.rip += len;
            } else {
                if (g_emuUnknownLog < 24) { ++g_emuUnknownLog; klog("[vcpu] rdmsr #GP 0x"); klog_hex(regs.rcx & 0xFFFF_FFFF); klog("\n"); }
                raiseGp(hv);
            }
            return EmuResult.Resume;
        }
        case XR_WRMSR: {
            const uint idx = cast(uint)regs.rcx;
            const ulong v = (regs.rdx << 32) | (regs.rax & 0xFFFF_FFFF);
            if (emuMsrWrite(vm, vc, hv, sregs, idx, v)) {
                regs.rip += len;
                if (hv.eoiExitVector >= 0) return EmuResult.EoiExit;
            } else {
                if (g_emuUnknownLog < 24) { ++g_emuUnknownLog; klog("[vcpu] wrmsr #GP 0x"); klog_hex(idx); klog("\n"); }
                raiseGp(hv);
            }
            return EmuResult.Resume;
        }
        case XR_XSETBV: {
            // XCR0 only; x87 must stay on, AVX needs SSE, and nothing beyond what the host enabled
            // (XCR0 is not switched: the guest runs under the host's, a superset of what it asked).
            const ulong v = (regs.rdx << 32) | (regs.rax & 0xFFFF_FFFF);
            ulong hostXcr0 = 0;
            ulong hcr4;
            asm @nogc nothrow { mov RAX, CR4; mov hcr4, RAX; }
            if ((hcr4 & (1UL << 18)) == 0) { raiseUd(hv); return EmuResult.Resume; }   // XSAVE not offered
            {   uint lo, hi;
                asm @nogc nothrow { xor ECX, ECX; db 0x0F; db 0x01; db 0xD0; mov lo, EAX; mov hi, EDX; }   // XGETBV
                hostXcr0 = (cast(ulong)hi << 32) | lo; }
            if ((regs.rcx & 0xFFFF_FFFF) != 0 || (v & 1) == 0 || (v & ~hostXcr0) != 0
                || ((v & 4) != 0 && (v & 2) == 0)) {
                raiseGp(hv);
                return EmuResult.Resume;
            }
            hv.xcr0 = v;
            regs.rip += len;
            return EmuResult.Resume;
        }
        case XR_CR_ACCESS: {
            const ulong q = xi.qual;
            const uint cr = cast(uint)(q & 0xF), type = cast(uint)((q >> 4) & 3), reg = cast(uint)((q >> 8) & 0xF);
            if (sregs is null) return EmuResult.NotHandled;
            if (cr == 8) {
                if (type == 0) { if (hv.lapicOn) lapicWrite(hv, APIC_TASKPRI, cast(uint)((*gpr(regs, reg) & 0xF) << 4)); }
                else if (type == 1) *gpr(regs, reg) = hv.lapicOn ? (lapicRead(hv, APIC_TASKPRI) >> 4) & 0xF : 0;
                regs.rip += len;
                return EmuResult.Resume;
            }
            if (type == 0 && cr == 0) {                // MOV to CR0 touching a masked bit (PE/PG)
                const ulong v = *gpr(regs, reg);
                sregs.cr0 = v;
                if ((v & (1UL << 31)) && (sregs.efer & EFER_LME)) sregs.efer |= EFER_LMA;
                else if (!(v & (1UL << 31))) sregs.efer &= ~EFER_LMA;
                regs.rip += len;
                return EmuResult.Resume;
            }
            if (type == 0 && cr == 4) { sregs.cr4 = *gpr(regs, reg); regs.rip += len; return EmuResult.Resume; }
            if (type == 2) { sregs.cr0 &= ~8UL; regs.rip += len; return EmuResult.Resume; }   // CLTS
            return EmuResult.NotHandled;
        }
        case XR_HLT: {
            if (!hv.lapicOn) return EmuResult.NotHandled;
            regs.rip += len;
            hv.halted = true;
            if (lapicWakeable(hv)) { hv.halted = false; return EmuResult.Resume; }
            // An idle guest halts with IF=1 all the time; IF=0 means it stopped for good (a panic,
            // Linux's early-exception halt_loop) -- say where, once.
            if (!(regs.rflags & 0x200) && g_emuHltLog < 4) {
                ++g_emuHltLog;
                klog("[vcpu] HLT with IF=0 rip=0x"); klog_hex(regs.rip); klog(" rflags=0x"); klog_hex(regs.rflags);
                klog(" lvtt=0x"); klog_hex(hv.lapic.regs[0x320 / 4]); klog(" dl=0x"); klog_hex(hv.lapic.tscDeadline);
                klog(" exp=0x"); klog_hex(hv.lapic.timerExpiry); klog(" svr=0x"); klog_hex(hv.lapic.regs[0xF0 / 4]);
                klog(" cr0=0x"); klog_hex(sregs.cr0); klog(" rsp=0x"); klog_hex(regs.rsp); klog("\n");
                // IF=0 HLT this early is Linux's early-exception halt_loop: dump the stack so the
                // pt_regs of the faulting context (vector, error, RIP, CS, RFLAGS) can be read out.
                if (g_emuHltLog == 1) {
                    import core.virt.mmio : guestTranslate, mmioReadGuestPhys;
                    foreach (q; 0 .. 96) {
                        ulong gpa; ulong v = 0;
                        const ulong va = regs.rsp + q * 8;
                        if (!guestTranslate(vm, sregs.cr3, va, true, gpa)) { klog("[vcpu] stack: unmapped\n"); break; }
                        mmioReadGuestPhys(vm, gpa, cast(ubyte*)&v, 8);
                        if ((q & 3) == 0) { klog("[vcpu] stk+"); klog_hex(q * 8); klog(":"); }
                        klog(" "); klog_hex(v);
                        if ((q & 3) == 3) klog("\n");
                    }
                    klog("[vcpu] cr2=0x"); klog_hex(hv.cr2); klog(" cr3=0x"); klog_hex(sregs.cr3);
                    klog(" cr4=0x"); klog_hex(sregs.cr4); klog(" efer=0x"); klog_hex(sregs.efer); klog("\n");
                }
            }
            return EmuResult.Halt;
        }
        case XR_INTERRUPT_WINDOW:
            return EmuResult.Resume;                   // the planner injects at the re-entry
        case XR_MWAIT, XR_MONITOR, XR_WBINVD, XR_INVD:
            regs.rip += len;                           // not offered in CPUID; a NOP if used anyway
            return EmuResult.Resume;
        case XR_VMCALL:
            regs.rax = cast(ulong)-1000L;              // -KVM_ENOSYS: no hypercalls offered
            regs.rip += len;
            return EmuResult.Resume;
        case XR_EPT_VIOLATION: {
            const ulong base = lapicMmioBase(hv);
            if (base == 0 || xi.gpa < base || xi.gpa >= base + 0x1000 || run is null) return EmuResult.NotHandled;
            import core.virt.mmio : mmioEnrichMmioExit, mmioWriteRegValue, MmioAccess;
            const uint savedReason = run.exitReason;
            run.exitReason = KVM_EXIT_MMIO;
            run.u.mmio.physAddr = xi.gpa;
            run.u.mmio.isWrite = xi.slatIsWrite;
            run.u.mmio.len = 0;
            MmioAccess acc;
            const bool ok = mmioEnrichMmioExit(vm, vc, regs, sregs, run, acc) && acc.valid;
            run.exitReason = savedReason;
            if (!ok) return EmuResult.NotHandled;
            const uint off = cast(uint)(xi.gpa - base);
            const uint regOff = off & 0xFF0;
            if (acc.isWrite) {
                ulong v = 0;
                foreach (k; 0 .. acc.size) v |= (cast(ulong)run.u.mmio.data[k]) << (8 * k);
                if ((off & 0xF) == 0) lapicWrite(hv, regOff, cast(uint)v);
            } else {
                ulong v = lapicRead(hv, regOff);
                v >>= 8 * (off & 3);
                mmioWriteRegValue(regs, acc.reg, v, acc.size, acc.zeroExtend, acc.signExtend);
            }
            regs.rip += acc.insnLen;
            if (hv.eoiExitVector >= 0) return EmuResult.EoiExit;
            return EmuResult.Resume;
        }
        default:
            return EmuResult.NotHandled;
    }
}
