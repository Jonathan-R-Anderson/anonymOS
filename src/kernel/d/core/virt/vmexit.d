// VM-exit dispatch — vendor-neutral exit -> struct kvm_run + action.
//
// PURE WITH RESPECT TO HARDWARE: this module never executes VMLAUNCH/
// VMRESUME/VMRUN and never touches the VMCS/VMCB.  It takes a *decoded,
// vendor-neutral* exit — produced by the Intel decoder
// (core.virt.vmx:vmxDecodeExit) or the AMD decoder
// (core.virt.svm:svmDecodeExit) from the raw hardware exit — and fills the
// shared struct kvm_run, updates vCPU/VM lifecycle state, and returns what
// the KVM_RUN path should do next.  Fully testable on host with synthetic
// exits; the actual guest entry stays in the thin HW-only wrappers.
//
// Also owns guest-state *validation*: the checks that hostile SREG/MSR/REG
// values are rejected with -EINVAL at SET time, before they can ever reach
// VMCB/VMCS programming.  These are generic x86 rules (hence the `virt`
// naming), not VMX-specific.
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.vmexit;

import core.virt.vm : Vm, Vcpu, VmState, VcpuState, VirtDiag, vmSetDiag;
import core.virt.kvmabi : KvmRun, KvmExitIo, KvmExitMmio, KvmMsrEntry,
    KvmRegs, KvmSRegs,
    KVM_EXIT_UNKNOWN, KVM_EXIT_IO, KVM_EXIT_HYPERCALL, KVM_EXIT_HLT,
    KVM_EXIT_MMIO, KVM_EXIT_SHUTDOWN, KVM_EXIT_INTERNAL_ERROR,
    KVM_EXIT_IO_IN, KVM_EXIT_IO_OUT;
import core.io : klog, klog_dec;

extern (C) @nogc nothrow:

enum : int {
    VIRT_EINVAL = -22,
    VIRT_EIO    = -5,
}

// ---------------------------------------------------------------------------
// Vendor-neutral exit representation.
//
// A hardware exit (Intel VMX basic exit reason, AMD SVM EXITCODE) is first
// translated by the vendor-specific decoder into this form; the common
// dispatcher below only ever sees VirtExitInfo.  Common code therefore
// reasons about "SLAT fault" and "I/O", never about EPT_VIOLATION=48 or
// SVM_EXIT_NPF=0x400.
// ---------------------------------------------------------------------------
enum VirtExitKind : uint {
    Unknown   = 0, // -> KVM_EXIT_UNKNOWN (hardwareReason preserved)
    Hlt       = 1, // -> KVM_EXIT_HLT
    Shutdown  = 2, // -> KVM_EXIT_SHUTDOWN (triple fault etc.)
    Io        = 3, // -> KVM_EXIT_IO
    Hypercall = 4, // -> KVM_EXIT_HYPERCALL
    SlatFault = 5, // -> KVM_EXIT_MMIO (EPT violation / nested page fault)
}

struct VirtExitInfo {
    VirtExitKind kind;

    // Raw vendor exit qualification / data, kept for debugging.  The
    // dispatcher decodes from the normalized fields below, not from these.
    ulong qual;           // raw exit qualification (vendor bit layout)
    ulong gpa;            // SlatFault: faulting guest-physical address
    ulong data;           // Io OUT: data bytes (<=8, little-endian from the
                          //   guest register); Hypercall: hypercall number
    uint  count;          // Io: REP count for string I/O
    ulong hardwareReason; // original vendor exit code (KVM_EXIT_UNKNOWN/debug)

    // Decoded I/O fields (valid when kind == Io).  Filled by the vendor
    // decoder from the VMX exit qualification or the SVM IOIO EXITINFO1.
    ushort ioPort;
    ubyte  ioSize;        // 1, 2, or 4
    ubyte  ioIsIn;        // 0 = OUT, 1 = IN
    ubyte  ioIsString;    // 0 = non-string, 1 = string (INS/OUTS)

    // Decoded SLAT-fault fields (valid when kind == SlatFault).
    ubyte  slatIsWrite;   // 0 = read/execute, 1 = write
}

// What KVM_RUN should do after the dispatch populated kvm_run.
enum VmExitAction : ubyte {
    ToUserspace = 0, // kvm_run populated; return 0 to the VMM
    VcpuStopped = 1, // HLT/SHUTDOWN: vCPU -> Exited; kvm_run populated; return 0
    VmContained = 2, // fatal: VM -> Dying, vCPU -> Dead; return -EIO; never re-enter
}

// I/O data for KVM_EXIT_IO OUT goes right after the struct inside the same
// 4 KiB kvm_run page (Linux does the same; the page is 4096 bytes).
enum ulong KVM_RUN_IO_DATA_OFF = KvmRun.sizeof;
static assert(KVM_RUN_IO_DATA_OFF + 8 <= 4096); // worst-case OUT copy fits

private VmExitAction vmContained(Vm* vm, Vcpu* vc, KvmRun* run, const(char)* why) {
    if (vm !is null) {
        vm.state = VmState.Dying;
        vmSetDiag(vm, VirtDiag.Contained, 0); // 8.1: named post-mortem
    }
    if (vc !is null) vc.state = VcpuState.Dead;
    if (run !is null) {
        run.exitReason = KVM_EXIT_INTERNAL_ERROR;
        run.u.hwReason = 0;
    }
    // 8.2: the boot-failure diagnostic contract.  This line names the cause;
    // a VMM reads it from the klog ring (/run/klog).  Formats are stable:
    //   "[vmexit] contained failure: <why>"
    klog("[vmexit] contained failure: ");
    klog(why);
    klog("\n");
    return VmExitAction.VmContained;
}

// ---------------------------------------------------------------------------
// Guest console tap (8.2): guest 1-byte OUTs to COM1 (0x3f8, the serial port
// every x86 guest firmware/OS knows) are mirrored into the klog ring as
// "[guest<N>] ..." lines, where N is the vCPU index.  The KVM_EXIT_IO exit
// still reaches the VMM unchanged — this is a read-only tap, and the
// kernel never interprets the bytes.  A VMM (AppVM) reads guest serial
// output from the existing klog consumer path (/run/klog -> Logs app),
// exactly like any other kernel log line.  Vendor-neutral: fires for both
// VMX I/O exits and SVM IOIO exits.
// ---------------------------------------------------------------------------
__gshared char[256] g_guestSerLine;
__gshared uint g_guestSerLen = 0;
__gshared uint g_guestSerVcpu = uint.max; // forces the prefix on the first byte

private void guestSerFlush() {
    if (g_guestSerLen == 0) return;
    klog("\n");
    g_guestSerLen = 0;
}

private void guestSerByte(uint vcpuIdx, ubyte b) {
    if (vcpuIdx != g_guestSerVcpu || g_guestSerLen >= g_guestSerLine.length) {
        guestSerFlush();           // vCPU switch or line full: end the line
        g_guestSerVcpu = vcpuIdx;
    }
    if (g_guestSerLen == 0) {
        klog("[guest");
        klog_dec(vcpuIdx);
        klog("] ");
    }
    if (b == '\n') { guestSerFlush(); return; }
    g_guestSerLine[g_guestSerLen++] = cast(char)b;
}

// Decode one vendor-neutral VM exit into the shared kvm_run page.
// Returns the action for the KVM_RUN path.  Never touches hardware.
VmExitAction virtDispatchExit(const ref VirtExitInfo info, KvmRun* run, Vm* vm, Vcpu* vc) {
    if (run is null || vc is null || vm is null)
        return vmContained(vm, vc, run, "null run/vcpu/vm");

    switch (info.kind) {
        case VirtExitKind.Hlt:
            run.exitReason = KVM_EXIT_HLT;
            vc.state = VcpuState.Exited;
            return VmExitAction.VcpuStopped;

        case VirtExitKind.Shutdown:
            run.exitReason = KVM_EXIT_SHUTDOWN;
            vc.state = VcpuState.Exited;
            return VmExitAction.VcpuStopped;

        case VirtExitKind.Io: {
            ulong size = info.ioSize;
            if (size != 1 && size != 2 && size != 4)
                return vmContained(vm, vc, run, "I/O with bad access size");
            uint count  = info.ioIsString ? info.count : 1;
            if (info.ioIsString && count == 0)
                return vmContained(vm, vc, run, "string I/O with zero count");

            run.exitReason = KVM_EXIT_IO;
            run.u.io.direction  = info.ioIsIn ? KVM_EXIT_IO_IN : KVM_EXIT_IO_OUT;
            run.u.io.size       = cast(ubyte)size;
            run.u.io.port       = info.ioPort;
            run.u.io.count      = count;
            run.u.io.dataOffset = KVM_RUN_IO_DATA_OFF;
            // 8.2: guest console tap — 1-byte OUT to COM1 mirrors to klog.
            if (!info.ioIsIn && !info.ioIsString && size == 1 && info.ioPort == 0x3f8)
                guestSerByte(vc.index, cast(ubyte)info.data);
            // OUT data: the vendor decoder put the guest register bytes in
            // info.data.  String-OUT data lives in guest memory; copying it
            // is the HW wrapper's job (it walks the guest SLAT).
            if (!info.ioIsIn && !info.ioIsString) {
                ubyte* dst = (cast(ubyte*)run) + KVM_RUN_IO_DATA_OFF;
                foreach (i; 0 .. size)
                    dst[i] = cast(ubyte)((info.data >> (8 * i)) & 0xFF);
            }
            return VmExitAction.ToUserspace;
        }

        case VirtExitKind.SlatFault: {
            // KVM semantics: the fault becomes an MMIO exit so the VMM
            // can emulate or kill the guest.  The access length is NOT in
            // the exit info; reporting a guessed length would be a fake
            // hardware claim, so len=0 means "unknown".
            // 8.1: record the faulting GPA as the named diagnostic
            // (informational — not every SLAT fault is terminal).
            vmSetDiag(vm, VirtDiag.SlatViolation, info.gpa);
            run.exitReason = KVM_EXIT_MMIO;
            run.u.mmio.physAddr = info.gpa;
            run.u.mmio.isWrite  = info.slatIsWrite;
            run.u.mmio.len      = 0;
            foreach (i; 0 .. 8) run.u.mmio.data[i] = 0;
            return VmExitAction.ToUserspace;
        }

        case VirtExitKind.Hypercall: {
            run.exitReason = KVM_EXIT_HYPERCALL;
            run.u.hypercall.nr = info.data; // guest RAX, via the vendor decoder
            foreach (i; 0 .. 6) run.u.hypercall.args[i] = 0; // HW fills from regs
            run.u.hypercall.ret = 0;
            run.u.hypercall.longMode = 0;
            run.u.hypercall.pad = 0;
            return VmExitAction.ToUserspace;
        }

        default: {
            // Unknown exit: contained by definition — a well-formed
            // KVM_EXIT_UNKNOWN reaches the VMM, which decides the guest's
            // fate.  Host state is never at risk.  hardwareReason carries
            // the original vendor exit code for diagnosis.
            run.exitReason = KVM_EXIT_UNKNOWN;
            run.u.hwReason = info.hardwareReason;
            return VmExitAction.ToUserspace;
        }
    }
}

// ---------------------------------------------------------------------------
// Guest-state validation.  Called at SET time so hostile values are
// rejected with -EINVAL before they can ever reach VMCB/VMCS programming.
// These are generic x86 architectural rules, not VMX-specific.
// ---------------------------------------------------------------------------

// MSR indices that are never valid guest state.
enum uint MSR_IA32_FEATURE_CONTROL = 0x3A;
enum uint MSR_IA32_VMX_BASIC       = 0x480; // block: 0x480..0x48F
enum uint MSR_IA32_MICROCODE       = 0x79;
enum uint MSR_IA32_EFER            = 0xC0000080;
// AMD SVM MSRs: never guest state (the host owns the virtualization substrate).
enum uint MSR_AMD_VM_CR            = 0xC0010114;
enum uint MSR_AMD_VM_HSAVE_PA      = 0xC0010117;

private int checkEfer(ulong efer) {
    if ((efer >> 32) != 0) return VIRT_EINVAL;         // upper 32 reserved
    if ((efer & ~0xD01UL) != 0) return VIRT_EINVAL;    // only SCE|LME|LMA|NXE
    if ((efer & (1UL << 10)) != 0 && (efer & (1UL << 8)) == 0)
        return VIRT_EINVAL;                           // LMA requires LME
    return 0;
}

// Guest CR4: allow the bits a normal 64-bit guest needs; deny VMX/SMX/LA57
// and everything reserved.  (Our SLAT is 4-level; LA57 guests are refused
// rather than half-supported.)
enum ulong GUEST_CR4_VALID = 0xF70FFFUL; // bits 0-11,16,17,18,20,21,22,23

int virtValidateSRegs(const KvmSRegs* s) {
    if (s is null) return VIRT_EINVAL;
    if ((s.cr0 >> 32) != 0) return VIRT_EINVAL;
    if ((s.cr0 & 0x80000000UL) != 0 && (s.cr0 & 1) == 0)
        return VIRT_EINVAL;                           // PG without PE
    if ((s.cr3 >> 52) != 0) return VIRT_EINVAL;        // high bits reserved
    if ((s.cr4 & ~GUEST_CR4_VALID) != 0) return VIRT_EINVAL; // VMX/SMX/LA57/reserved
    if (checkEfer(s.efer) != 0) return VIRT_EINVAL;
    if ((s.efer & (1UL << 8)) != 0 && (s.cr4 & (1UL << 5)) == 0)
        return VIRT_EINVAL;                           // LME requires CR4.PAE
    if (s.cr8 > 15) return VIRT_EINVAL;                // TPR is 4 bits
    if ((s.apicBase & 0xFF) != 0) return VIRT_EINVAL;  // bits 7:0 reserved
    if ((s.apicBase & 0x200) != 0) return VIRT_EINVAL; // bit 9 reserved
    if ((s.apicBase >> 52) != 0) return VIRT_EINVAL;
    return 0;
}

int virtValidateRegs(const KvmRegs* r) {
    if (r is null) return VIRT_EINVAL;
    ulong hi = r.rip >> 47;
    if (hi != 0 && hi != 0x1FFFF) return VIRT_EINVAL;  // non-canonical RIP
    return 0;
}

int virtValidateMsrs(const KvmMsrEntry* msrs, uint n) {
    if (n > 0 && msrs is null) return VIRT_EINVAL;
    foreach (i; 0 .. n) {
        uint idx = msrs[i].index;
        if (idx == MSR_IA32_FEATURE_CONTROL) return VIRT_EINVAL;
        if (idx >= MSR_IA32_VMX_BASIC && idx <= MSR_IA32_VMX_BASIC + 0xF)
            return VIRT_EINVAL;                         // VMX MSRs never guest state
        if (idx == MSR_AMD_VM_CR || idx == MSR_AMD_VM_HSAVE_PA)
            return VIRT_EINVAL;                         // SVM MSRs never guest state
        if (idx == MSR_IA32_MICROCODE) return VIRT_EINVAL;
        if (idx == MSR_IA32_EFER && checkEfer(msrs[i].data) != 0)
            return VIRT_EINVAL;
    }
    return 0;
}

// Full pre-entry gate: validate everything cached for the vCPU before the
// backend programs the VMCB/VMCS.  Returns 0 or -EINVAL.
int virtValidateGuestState(const KvmRegs* regs, const KvmSRegs* sregs,
                           const KvmMsrEntry* msrs, uint nmsrs) {
    int rc = virtValidateRegs(regs);
    if (rc != 0) return rc;
    if (sregs !is null) {
        rc = virtValidateSRegs(sregs);
        if (rc != 0) return rc;
    }
    return virtValidateMsrs(msrs, nmsrs);
}
