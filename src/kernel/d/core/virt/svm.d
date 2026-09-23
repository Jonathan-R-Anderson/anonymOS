// VIRT: AMD SVM backend — real AMD-V implementation.
//
// What is REAL here (software-complete; [HW] marks what needs real AMD
// hardware to verify):
//   - svmHwPresent(): CPUID.8000_0001:ECX[2] — true iff the CPU has SVM.
//   - svmCpuInit(cpuId): fail-soft per-CPU init.  Checks the SVM feature,
//     honors MSR_VM_CR (SVMDIS set => fail closed, never bypassed), gates
//     CPUID.8000_000A on the max extended leaf, requires
//     CPUID.8000_000A:EDX[NPT,NRIPS,VMCBCLEAN,DECODEASSISTS]
//     (fail closed without NPT — there is no shadow-paging fallback),
//     sets EFER.SVME, allocates the per-CPU HSAVE area AND the per-CPU host
//     VMLOAD/VMSAVE area, programs MSR_VM_HSAVE_PA.  Any failure leaves this
//     CPU's ready=false.
//   - svmBootInit(): BSP wrapper -> svmCpuInit(0).
//   - ASID allocator: ASID 0 is the host and is never handed out; guests
//     get 1..EBX-1, then wrap with TLB_CONTROL=FLUSH_ALL.
//     wrap with a full TLB flush.
//   - VMCB allocation/programming (core.virt.vmcb exact layout): per-vCPU
//     page, intercept vector (HLT/CPUID/IOIO/MSR/SHUTDOWN/VMRUN/VMMCALL/
//     VMLOAD/VMSAVE), all-ones IOPM/MSRPM (default-deny), NPT enable + nCR3,
//     guest save area synced from KVM regs/sregs.
//   - svmRunVmcb(): thin VMRUN transition wrapper — saves all host GPRs,
//     VMSAVE host, VMLOAD guest, swaps GPRs, VMRUN, then reverses on #VMEXIT.
//     STGI after #VMEXIT (GIF is cleared by #VMEXIT; the kernel runs with
//     GIF=1 from boot).
//   - svmDecodeExit(): full software decode — HLT, SHUTDOWN, IOIO (EXITINFO1
//     per APM Vol.2 §15.10.2), MSR (surfaced Unknown for VMM emulation),
//     VMMCALL, NPF (EXITINFO1/2 per §15.25.6).
//   - svmEnter(): validates, programs the VMCB, runs, picks up guest state,
//     decodes.  Returns 0 with *xi filled, or -errno.
// What is [HW] (implemented, but cannot be verified without AMD SVM
// hardware — the host harness never executes VMRUN):
//   - The VMRUN wrapper's register dance, VMLOAD/VMSAVE pairing, HSAVE
//     restore, and every EXITCODE/EXITINFO value read from a real VMCB.
//   - scripts/virt-hw-test.sh's AMD leg must run on the user's machine.
//
// Fail-closed is structural: svmAvailable() is false until per-CPU init
// succeeds, and svmEnter() returns -ENODEV without it.  No exit is ever
// synthesized.
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.svm;

import core.io : klog;
import core.exports : phys_to_virt;
import memory.mm : alloc_phys_page, free_phys_page;
import core.virt.vm : Vm, Vcpu, VIRT_MAX_CPUS;
import core.virt.vmexit : VirtExitInfo, VirtExitKind;
import core.virt.kvmabi : KvmRegs, KvmSRegs, KvmSegment;
import core.virt.slat : slatRootPhys;
import core.virt.vmcb;

extern (C) @nogc nothrow:

// --- MSRs -----------------------------------------------------------------
enum uint MSR_EFER        = 0xC0000080;
enum uint MSR_VM_CR       = 0xC0010114; // SVM control: LOCK[3], SVMDIS[4]
enum uint MSR_VM_HSAVE_PA = 0xC0010117; // host save-area phys (VMRUN requirement)

enum ulong EFER_SVME   = 1UL << 12;
enum ulong VM_CR_LOCK   = 1UL << 3;
enum ulong VM_CR_SVMDIS = 1UL << 4;

// --- SVM exit codes (Linux uapi/asm/svm.h; AMD APM Vol.2) -------------------
enum ulong SVM_EXIT_CPUID    = 0x72;
enum ulong SVM_EXIT_HLT      = 0x78;
enum ulong SVM_EXIT_IOIO     = 0x7B;
enum ulong SVM_EXIT_MSR      = 0x7C;
enum ulong SVM_EXIT_SHUTDOWN = 0x7F;
enum ulong SVM_EXIT_VMRUN    = 0x80;
enum ulong SVM_EXIT_VMMCALL  = 0x81;
enum ulong SVM_EXIT_NPF      = 0x400;
enum ulong SVM_EXIT_INVALID  = 0xFFFF_FFFF_FFFF_FFFFUL; // = -1: bad guest state

// Default guest PAT: all-WB (matches the reset PAT).
enum ulong SVM_DEFAULT_GPAT = 0x0007040600070406UL;

// --- per-CPU state ------------------------------------------------------------
struct SvmCpuState {
    bool  ready;         // EFER.SVME set + HSAVE + host-save programmed
    ulong hsavePhys;     // this CPU's HSAVE area (4 KiB)
    ulong hostSavePhys;  // this CPU's host VMLOAD/VMSAVE area (4 KiB)
    uint  nextAsid;      // next ASID to hand out on this CPU (0 = uninit)
    uint  maxAsids;      // EBX-1 (largest guest ASID; 0 = unknown/uninit)
}
__gshared SvmCpuState[VIRT_MAX_CPUS] g_svmCpu;

// --- low-level primitives -------------------------------------------------------
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

private uint x64MaxExtendedLeaf() {
    uint m;
    asm @nogc nothrow {
        push RBX;
        mov EAX, 0x80000000;
        cpuid;
        mov m, EAX;
        pop RBX;
    }
    return m;
}

private void x64CpuidSvmLeaf(out uint ebx, out uint edx) {
    uint b, d;
    asm @nogc nothrow {
        push RBX;
        mov EAX, 0x8000000A;
        cpuid;
        mov b, EBX;
        mov d, EDX;
        pop RBX;
    }
    ebx = b; edx = d;
}

private ulong x64Rdmsr(uint msr) {
    uint lo, hi;
    asm @nogc nothrow {
        mov ECX, msr;
        rdmsr;
        mov lo, EAX;
        mov hi, EDX;
    }
    return (cast(ulong)hi << 32) | lo;
}

private void x64Wrmsr(uint msr, ulong v) {
    uint lo = cast(uint)v;
    uint hi = cast(uint)(v >> 32);
    asm @nogc nothrow {
        mov ECX, msr;
        mov EAX, lo;
        mov EDX, hi;
        wrmsr;
    }
}

// --- detection ------------------------------------------------------------------

// True only when the CPU actually reports SVM (CPUID.8000_0001:ECX[2]).
// Pure CPUID read: safe to call anywhere, never enables anything.
public bool svmHwPresent() {
    return (x64CpuidExtEcx() & (1u << 2)) != 0;
}

// --- per-CPU init -----------------------------------------------------------------
// Fail-soft.  Must run ON the target CPU (it sets that CPU's EFER.SVME and
// HSAVE pointer).  Never panics: any problem leaves this CPU's ready=false
// and the boot continues without virtualization.  Never touches Intel MSRs.
public void svmCpuInit(uint cpuId) {
    if (cpuId >= VIRT_MAX_CPUS) return;
    if (!svmHwPresent()) {
        klog("[svm] no SVM (CPUID.8000_0001:ECX[2] clear) — AMD virtualization unavailable\n");
        return;
    }

    // MSR_VM_CR: the firmware setting.  SVMDIS alone disables SVM (every
    // SVM instruction #UD); LOCK additionally freezes the register until
    // RESET.  Either way we fail closed — we never clear a firmware bit.
    ulong vmcr = x64Rdmsr(MSR_VM_CR);
    if ((vmcr & VM_CR_SVMDIS) != 0) {
        klog("[svm] MSR_VM_CR SVMDIS set — SVM disabled by firmware\n");
        return;
    }

    // The 0x8000000A leaf is architecturally present on any CPU reporting
    // SVM, but gate it explicitly: CPUID never faults on an unsupported
    // leaf, it returns the max leaf's data instead, which would silently
    // misreport NASID/feature bits.
    if (x64MaxExtendedLeaf() < 0x8000000A) {
        klog("[svm] CPUID.8000000A absent — cannot validate SVM features\n");
        return;
    }

    // CPUID.8000_000A:EDX feature gate.  NPT is mandatory (no shadow-paging
    // fallback exists); NRIPS/VMCBCLEAN/DECODEASSISTS are required per the
    // bring-up checklist (openspec change add-amd-svm-npt-backend).
    uint nasid, edx;
    x64CpuidSvmLeaf(nasid, edx);
    enum uint NEED = SVM_FEAT_NPT | SVM_FEAT_NRIP_SAVE |
                     SVM_FEAT_VMCB_CLEAN | SVM_FEAT_DECODE_ASSISTS;
    if ((edx & NEED) != NEED) {
        klog("[svm] CPUID.8000_000A:EDX missing required SVM features — fail closed\n");
        return;
    }

    // EFER.SVME: enable SVM on this CPU.
    ulong efer = x64Rdmsr(MSR_EFER);
    if ((efer & EFER_SVME) == 0)
        x64Wrmsr(MSR_EFER, efer | EFER_SVME);

    // HSAVE area: VMRUN requires MSR_VM_HSAVE_PA to point at a 4 KiB host
    // save area.  Allocated per CPU, never guest-visible.
    ulong hsave = alloc_phys_page();
    if (hsave == 0) {
        klog("[svm] HSAVE area allocation failed\n");
        x64Wrmsr(MSR_EFER, efer); // restore: leave no half-enabled state
        return;
    }
    // Host VMLOAD/VMSAVE area: parks host FS/GS/TR/LDTR/SYSENTER/etc across
    // VMRUN (same 4 KiB layout, state at offset 0x400 per the APM).
    ulong hostSave = alloc_phys_page();
    if (hostSave == 0) {
        klog("[svm] host save area allocation failed\n");
        free_phys_page(hsave);
        x64Wrmsr(MSR_EFER, efer);
        return;
    }
    auto p = cast(ubyte*)phys_to_virt(hsave);
    foreach (i; 0 .. 4096) p[i] = 0;
    p = cast(ubyte*)phys_to_virt(hostSave);
    foreach (i; 0 .. 4096) p[i] = 0;
    x64Wrmsr(MSR_VM_HSAVE_PA, hsave);

    // ASID space: CPUID.8000_000A:EBX reports the COUNT of ASIDs, including
    // ASID 0 (the host).  Guests get 1..EBX-1; ASID EBX does not exist —
    // VMRUN with it is a #VMEXIT(INVALID).  Same rule as KVM
    // (max_asid = EBX-1, min_asid = 1).
    uint maxAsid = (nasid == 0) ? 0 : nasid - 1; // pathological: fail closed

    g_svmCpu[cpuId].hsavePhys = hsave;
    g_svmCpu[cpuId].hostSavePhys = hostSave;
    g_svmCpu[cpuId].nextAsid = 1;
    g_svmCpu[cpuId].maxAsids = maxAsid;
    g_svmCpu[cpuId].ready = true;
    klog("[svm] SVM enabled (EFER.SVME, HSAVE, host-save area, ");
    klog(maxAsid > 1 ? "multi-ASID)\n" : "single-ASID)\n");
}

// Boot-time init: the BSP's share of the per-CPU init above.
public void svmBootInit() { svmCpuInit(0); }

// Fail-closed availability: hardware present AND this CPU finished
// svmCpuInit.  Detection stays honest: svmHwPresent() reports the real
// CPUID bit independently of backend readiness.
// [HW-SMP]: currently BSP-centric (g_svmCpu[0]); wire the real CPU id when
// SMP vCPU entry exists.
public bool svmAvailable() {
    return svmHwPresent() && g_svmCpu[0].ready;
}

// --- ASID allocator ---------------------------------------------------------------
// Returns 0 on failure.  *needFlush is set when the ASID is fresh on this
// CPU (first use or generation wrap): the caller must TLB_CONTROL=FLUSH_ALL.
private uint svmAllocAsid(uint cpuId, out bool needFlush) {
    needFlush = false;
    if (cpuId >= VIRT_MAX_CPUS) return 0;
    SvmCpuState* st = &g_svmCpu[cpuId];
    if (!st.ready || st.maxAsids == 0) return 0;
    if (st.nextAsid == 0 || st.nextAsid > st.maxAsids) {
        st.nextAsid = 1;
        needFlush = true; // generation wrap: stale entries may alias
    }
    uint asid = st.nextAsid++;
    needFlush = true; // every fresh ASID binding flushes once (conservative)
    return asid;
}

// --- VMCB programming ------------------------------------------------------------------
// Translate one KVM segment into a VMCB segment entry.
private void svmWriteSeg(VmcbSeg* d, const KvmSegment* s) {
    if (d is null || s is null) return;
    if (s.unusable) { vmcbWriteSeg(d, 0, 0, 0, 0); return; }
    vmcbWriteSeg(d, s.selector,
                 vmcbSegAttrib(s.type, s.s, s.dpl, s.present,
                               s.avl, s.l, s.db, s.g, 0),
                 s.limit, s.base);
}

// Allocate (first entry) and program the vCPU's VMCB.  The control area is
// programmed once at alloc; the save area is re-synced from regs/sregs on
// every entry (KVM_SET_REGS/KVM_SET_SREGS may have changed guest state
// between runs).  The VMLOAD/VMSAVE-only fields (STAR/LSTAR/CSTAR/SFMASK,
// KernelGsBase, SYSENTER_*) are programmed once and thereafter preserved by
// the VMSAVE/VMLOAD dance — never clobbered by the re-sync.
// Returns 0 or -errno.
private int svmProgramVmcb(Vm* vm, Vcpu* vc, const KvmRegs* regs,
                           const KvmSRegs* sregs, uint cpuId) {
    bool fresh = (vc.hwCtrlPhys == 0);
    Vmcb* vmcb;
    if (fresh) {
        ulong phys = alloc_phys_page();
        if (phys == 0) return -12; // -ENOMEM
        vmcb = cast(Vmcb*)phys_to_virt(phys);
        ulong* q = cast(ulong*)vmcb;
        foreach (i; 0 .. Vmcb.sizeof / 8) q[i] = 0;

        // --- control area (stable for the vCPU's lifetime) ---
        vmcbSetIntercept(&vmcb.control, SVM_INT_CPUID);
        vmcbSetIntercept(&vmcb.control, SVM_INT_HLT);
        vmcbSetIntercept(&vmcb.control, SVM_INT_IOIO);
        vmcbSetIntercept(&vmcb.control, SVM_INT_MSR);
        vmcbSetIntercept(&vmcb.control, SVM_INT_SHUTDOWN);
        vmcbSetIntercept(&vmcb.control, SVM_INT_VMRUN);
        vmcbSetIntercept(&vmcb.control, SVM_INT_VMMCALL);
        vmcbSetIntercept(&vmcb.control, SVM_INT_VMLOAD);
        vmcbSetIntercept(&vmcb.control, SVM_INT_VMSAVE);
        vmcb.control.iopmBasePa = vm.svmIopmPhys;   // 12 KiB, all-ones
        vmcb.control.msrpmBasePa = vm.svmMsrpmPhys; // 8 KiB, all-ones
        vmcb.control.tscOffset = 0;
        bool needFlush;
        uint asid = svmAllocAsid(cpuId, needFlush);
        if (asid == 0) { free_phys_page(phys); return -12; }
        vmcb.control.asid = asid;
        vmcb.control.tlbControl = SVM_TLB_FLUSH_ALL; // fresh ASID binding
        vmcb.control.eventinj = 0;
        vmcb.control.miscCtl = SVM_MISC_ENABLE_NP;    // nested paging on
        vmcb.control.cleanBits = 0; // all dirty: CPU reloads every field
        // VMLOAD/VMSAVE-only state: zero at bring-up; the guest programs it
        // via (intercepted) MSRs and the VMSAVE/VMLOAD dance preserves it.
        vmcb.save.star = 0; vmcb.save.lstar = 0; vmcb.save.cstar = 0;
        vmcb.save.sfmask = 0; vmcb.save.kernelGsBase = 0;
        vmcb.save.sysenterCs = 0; vmcb.save.sysenterEsp = 0;
        vmcb.save.sysenterEip = 0;
        vc.hwCtrlPhys = phys;
    } else {
        vmcb = cast(Vmcb*)phys_to_virt(vc.hwCtrlPhys);
        vmcb.control.tlbControl = SVM_TLB_NONE; // ASID binding is stable
    }
    // nCR3 every entry: the SLAT root page itself never moves, but this
    // keeps the VMCB honest if the SLAT is ever rebuilt.
    ulong ncr3 = slatRootPhys(&vm.slat);
    if (ncr3 == 0) return -22; // -EINVAL: VM has no registered memory
    vmcb.control.ncr3 = ncr3;

    // --- save area: full re-sync from cached KVM state ---
    svmWriteSeg(&vmcb.save.es, &sregs.es);
    svmWriteSeg(&vmcb.save.cs, &sregs.cs);
    svmWriteSeg(&vmcb.save.ss, &sregs.ss);
    svmWriteSeg(&vmcb.save.ds, &sregs.ds);
    svmWriteSeg(&vmcb.save.fs, &sregs.fs);
    svmWriteSeg(&vmcb.save.gs, &sregs.gs);
    vmcbWriteSeg(&vmcb.save.gdtr, 0, 0, sregs.gdt.limit, sregs.gdt.base);
    svmWriteSeg(&vmcb.save.ldtr, &sregs.ldt);
    vmcbWriteSeg(&vmcb.save.idtr, 0, 0, sregs.idt.limit, sregs.idt.base);
    svmWriteSeg(&vmcb.save.tr, &sregs.tr);
    vmcb.save.cpl = cast(ubyte)(sregs.cs.dpl & 3);
    vmcb.save.efer = sregs.efer;
    vmcb.save.cr4 = sregs.cr4;
    vmcb.save.cr3 = sregs.cr3;
    vmcb.save.cr0 = sregs.cr0;
    vmcb.save.dr7 = 0x400;
    vmcb.save.dr6 = 0xFFFF0FF0;
    vmcb.save.cr2 = sregs.cr2;
    vmcb.save.gpat = SVM_DEFAULT_GPAT;
    vmcb.save.rflags = regs.rflags;
    vmcb.save.rip = regs.rip;
    vmcb.save.rsp = regs.rsp;
    vmcb.save.rax = regs.rax;
    return 0;
}

// --- VMRUN transition wrapper --------------------------------------------------------------
// Thin, narrow, [HW].
//
// Contract (SysV ABI): RDI = vmcbPhys, RSI = hostSavePhys, RDX = regs
// (KvmRegs*).  Saves every host GPR, parks host FS/GS/TR/LDTR/SYSENTER/etc
// with VMSAVE, loads the guest's with VMLOAD, swaps the GPRs to the guest's
// values, VMRUNs, and on #VMEXIT reverses the whole sequence: VMSAVE guest,
// VMLOAD host, STGI (GIF was cleared by #VMEXIT; the kernel runs with GIF=1
// from boot), write guest GPRs back to *regs, restore host GPRs.
//
// Guest RAX/RSP/RIP/RFLAGS are NOT round-tripped here — they live in the
// VMCB save area (save.rax/rsp/rip/rflags); the D caller picks them up after
// return.  Guest RBX-R15/RBP/RSI/RDI/RCX/RDX are written back to *regs.
//
// Stack discipline: 16 pushes (15 GPRs + 1 dummy) keep RSP 16-byte aligned;
// every access after the pushes is RSP-relative.  RBP is NOT used as a frame
// pointer because the guest's RBP is loaded into RBP before VMRUN.  The
// pushes/pops are exactly balanced, so the D epilogue runs normally (no
// ret inside the asm).
private void svmRunVmcb(ulong vmcbPhys, ulong hostSavePhys, KvmRegs* regs) {
    asm @nogc nothrow {
        // Materialize the SysV args (belt-and-braces: the caller already
        // passed them in RDI/RSI/RDX).
        mov RDI, vmcbPhys;
        mov RSI, hostSavePhys;
        mov RDX, regs;

        // --- save all host GPRs ----------------------------------
        // After these 16 pushes: dummy@[RSP+0], R15@[RSP+8], R14@[RSP+16],
        // R13@[RSP+24], R12@[RSP+32], R11@[RSP+40], R10@[RSP+48],
        // R9@[RSP+56], R8@[RSP+64], RDI@[RSP+72]=vmcbPhys,
        // RSI@[RSP+80]=hostSavePhys, RDX@[RSP+88]=regs, RCX@[RSP+96],
        // RBX@[RSP+104], RAX@[RSP+112], RBP@[RSP+120].
        push RBP;
        push RAX;
        push RBX;
        push RCX;
        push RDX;
        push RSI;
        push RDI;
        push R8;
        push R9;
        push R10;
        push R11;
        push R12;
        push R13;
        push R14;
        push R15;
        push RAX;               // dummy: keeps RSP 16-byte aligned

        // --- VMSAVE host: park host FS/GS/TR/LDTR/SYSENTER/etc ------
        mov RAX, [RSP + 80];    // hostSavePhys
        db 0x0F; db 0x01; db 0xDB; // VMSAVE RAX

        // --- VMLOAD guest: load guest FS/GS/TR/LDTR/SYSENTER/etc -----
        mov RAX, [RSP + 72];    // vmcbPhys
        db 0x0F; db 0x01; db 0xDA; // VMLOAD RAX

        // --- load guest GPRs (host values are safe on the stack) -----
        // KvmRegs: rax@0 rbx@8 rcx@16 rdx@24 rsi@32 rdi@40 rsp@48 rbp@56
        //          r8@64 r9@72 r10@80 r11@88 r12@96 r13@104 r14@112 r15@120
        // Guest RSP comes from VMCB save.rsp; guest RAX from save.rax —
        // VMRUN takes the VMCB address in RAX, so neither is loaded here.
        mov R14, [RSP + 88];    // R14 = regs
        mov RBX, [R14 + 8];
        mov RCX, [R14 + 16];
        mov RDX, [R14 + 24];
        mov RSI, [R14 + 32];
        mov RDI, [R14 + 40];
        mov RBP, [R14 + 56];
        mov R8,  [R14 + 64];
        mov R9,  [R14 + 72];
        mov R10, [R14 + 80];
        mov R11, [R14 + 88];
        mov R12, [R14 + 96];
        mov R13, [R14 + 104];
        mov R15, [R14 + 120];
        mov R14, [R14 + 112];    // LAST R14-relative load (clobbers base)

        // --- VMRUN ----------------------------------------------------
        mov RAX, [RSP + 72];    // vmcbPhys
        db 0x0F; db 0x01; db 0xD8; // VMRUN RAX
        // --- #VMEXIT lands here ----------------------------------------
        // GIF is 0 (cleared by #VMEXIT).  Keep it 0 through the
        // VMSAVE/VMLOAD pair: no interrupt may observe guest FS/GS/TR/
        // LDTR/syscall state.

        // --- VMSAVE guest: write FS/GS/etc back to the VMCB -----------
        mov RAX, [RSP + 72];    // vmcbPhys
        db 0x0F; db 0x01; db 0xDB; // VMSAVE RAX

        // --- VMLOAD host: restore host FS/GS/etc -----------------------
        mov RAX, [RSP + 80];    // hostSavePhys
        db 0x0F; db 0x01; db 0xDA; // VMLOAD RAX

        // Host segment/syscall state is fully restored; only now is it
        // safe to take interrupts again (GIF was cleared by #VMEXIT).
        db 0x0F; db 0x01; db 0xDC; // STGI

        // --- write guest GPRs back to *regs ------------------------------
        // RAX is free scratch now (host RAX is at [RSP+112]).
        mov RAX, [RSP + 88];    // RAX = regs
        mov [RAX + 8],  RBX;
        mov [RAX + 16], RCX;
        mov [RAX + 24], RDX;
        mov [RAX + 32], RSI;
        mov [RAX + 40], RDI;
        mov [RAX + 56], RBP;
        mov [RAX + 64], R8;
        mov [RAX + 72], R9;
        mov [RAX + 80], R10;
        mov [RAX + 88], R11;
        mov [RAX + 96], R12;
        mov [RAX + 104], R13;
        mov [RAX + 112], R14;   // guest R14 still live in R14
        mov [RAX + 120], R15;

        // --- restore host GPRs -------------------------------------------
        add RSP, 8;             // drop dummy
        pop R15;
        pop R14;
        pop R13;
        pop R12;
        pop R11;
        pop R10;
        pop R9;
        pop R8;
        pop RDI;
        pop RSI;
        pop RDX;
        pop RCX;
        pop RBX;
        pop RAX;
        pop RBP;
        // (no ret: the D epilogue runs normally)
    }
}

// --- vCPU entry ----------------------------------------------------------------------
// Programs the VMCB, runs the guest once via VMRUN, picks up guest state,
// and decodes the exit into *xi.
//   0  -> *xi holds the decoded exit (caller dispatches via virtDispatchExit)
//   <0 -> -ENODEV (backend not ready) or -EINVAL (bad VM/guest state) or
//         -ENOMEM (VMCB alloc failed).  *xi is undefined.
public int svmEnter(Vm* vm, Vcpu* vc, KvmRegs* regs, const KvmSRegs* sregs,
                    VirtExitInfo* xi) {
    if (vm is null || vc is null || regs is null || sregs is null || xi is null)
        return -22; // -EINVAL
    // [HW-SMP]: BSP state for now; wire the real CPU id with SMP entry.
    enum uint cpuId = 0;
    if (!g_svmCpu[cpuId].ready)
        return -19; // -ENODEV
    if (vm.svmIopmPhys == 0 || vm.svmMsrpmPhys == 0)
        return -22; // -EINVAL: VM was not created on the SVM path

    int rc = svmProgramVmcb(vm, vc, regs, sregs, cpuId);
    if (rc != 0) return rc;

    // [HW] The next line executes VMRUN.  Untestable without AMD SVM
    // hardware; the host harness never reaches it (svmAvailable() is false
    // there — svmEnter returns -ENODEV above).
    svmRunVmcb(vc.hwCtrlPhys, g_svmCpu[cpuId].hostSavePhys, regs);

    Vmcb* vmcb = cast(Vmcb*)phys_to_virt(vc.hwCtrlPhys);
    ulong exitcode = vmcb.control.exitcode;
    ulong info1 = vmcb.control.exitinfo1;
    ulong info2 = vmcb.control.exitinfo2;
    if (exitcode == SVM_EXIT_INVALID)
        return -22; // -EINVAL: VMRUN consistency failure (host VMCB bug)

    // Guest RAX/RSP/RIP/RFLAGS live in the VMCB save area (the wrapper only
    // round-trips the other GPRs through *regs).
    regs.rax = vmcb.save.rax;
    regs.rsp = vmcb.save.rsp;
    regs.rip = vmcb.save.rip;
    regs.rflags = vmcb.save.rflags;

    svmDecodeExit(exitcode, info1, info2, regs.rax, xi);
    // Register-dependent fields the pure decoder cannot fill.
    if (xi.kind == VirtExitKind.Io) {
        if (xi.ioIsIn == 0 && xi.ioIsString == 0)
            xi.data = regs.rax; // low ioSize bytes are the OUT payload
        if (xi.ioIsString != 0)
            xi.count = ((info1 >> 3) & 1) != 0 ? cast(uint)regs.rcx : 1; // REP?
    }
    return 0;
}

// --- exit decoder ---------------------------------------------------------------------
// Translates an SVM EXITCODE (+EXITINFO1/2) into the vendor-neutral
// VirtExitInfo.  Pure function — fully testable on the host.
//   IOIO per APM Vol.2 §15.10.2: EXITINFO1[31:16]=port, [12:10]=seg,
//     b9=A64 b8=A32 b7=A16, b6=SZ32 b5=SZ16 b4=SZ8, b3=REP b2=STR,
//     b0=TYPE (0=OUT,1=IN); EXITINFO2=RIP after the instruction.
//   NPF per §15.25.6: EXITINFO2=faulting GPA; EXITINFO1: b0=P, b1=RW,
//     b2=US(always 1), b3=RSV, b4=ID(code fetch), b32/b33=walk/final.
//   MSR: EXITINFO1 b0: 0=RDMSR,1=WRMSR (ECX held the MSR number).
public void svmDecodeExit(ulong exitCode, ulong exitInfo1, ulong exitInfo2,
                          ulong guestRax, VirtExitInfo* xi) {
    if (xi is null) return;
    *xi = VirtExitInfo.init;
    xi.hardwareReason = exitCode;
    xi.qual = exitInfo1;
    switch (exitCode) {
        case SVM_EXIT_HLT:
            xi.kind = VirtExitKind.Hlt;
            break;
        case SVM_EXIT_SHUTDOWN:
            xi.kind = VirtExitKind.Shutdown;
            break;
        case SVM_EXIT_IOIO: {
            xi.kind = VirtExitKind.Io;
            xi.ioPort = cast(ushort)((exitInfo1 >> 16) & 0xFFFF);
            // Size: exactly one of SZ8/SZ16/SZ32 must be set; 0 or
            // ambiguous -> ioSize 0 -> the dispatcher contains the exit.
            uint sz = 0;
            if ((exitInfo1 & (1UL << 4)) != 0) sz = 1;
            if ((exitInfo1 & (1UL << 5)) != 0) sz = (sz == 0) ? 2 : 0;
            if ((exitInfo1 & (1UL << 6)) != 0) sz = (sz == 0) ? 4 : 0;
            xi.ioSize = cast(ubyte)sz;
            xi.ioIsIn = cast(ubyte)(exitInfo1 & 1UL);
            xi.ioIsString = cast(ubyte)((exitInfo1 >> 2) & 1UL);
            break;
        }
        case SVM_EXIT_MSR:
            // Intercepted RDMSR/WRMSR (MSRPM is default-deny: every MSR
            // access exits).  Surfaced as Unknown -> KVM_EXIT_UNKNOWN so
            // the VMM emulates; in-kernel MSR emulation is a later tier.
            // Direction is EXITINFO1[0] (0=RDMSR,1=WRMSR); the MSR number
            // was in ECX (regs.rcx at exit time).
            xi.kind = VirtExitKind.Unknown;
            break;
        case SVM_EXIT_VMMCALL:
            xi.kind = VirtExitKind.Hypercall;
            xi.data = guestRax; // VMMCALL number convention: guest RAX
            break;
        case SVM_EXIT_NPF:
            xi.kind = VirtExitKind.SlatFault;
            xi.gpa = exitInfo2; // faulting guest-physical address
            xi.slatIsWrite = cast(ubyte)((exitInfo1 >> 1) & 1UL); // RW bit
            break;
        default:
            xi.kind = VirtExitKind.Unknown;
            break;
    }
}
