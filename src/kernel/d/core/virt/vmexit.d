// VM-exit dispatch — VMX basic exit reason -> struct kvm_run + action.
//
// PURE WITH RESPECT TO HARDWARE: this module never executes VMLAUNCH/
// VMRESUME and never touches the VMCS.  It takes a *decoded* exit — the
// basic reason plus the qualification/data the HW wrapper (vmxEnter in
// core.virt.vmx) extracted from the VMCS — and fills the shared
// struct kvm_run, updates vCPU/VM lifecycle state, and returns what the
// KVM_RUN path should do next.  Fully testable on host with synthetic
// exits; the actual guest entry stays in the thin HW-only wrapper.
//
// Also owns guest-state *validation* (task 6.3): the checks that hostile
// SREG/MSR/REG values are rejected with -EINVAL at SET time, before they
// can ever reach VMCS programming.
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.vmexit;

import core.virt.vm : Vm, Vcpu, VmState, VcpuState;
import core.virt.kvmabi : KvmRun, KvmExitIo, KvmExitMmio, KvmMsrEntry,
    KvmRegs, KvmSRegs,
    KVM_EXIT_UNKNOWN, KVM_EXIT_IO, KVM_EXIT_HYPERCALL, KVM_EXIT_HLT,
    KVM_EXIT_MMIO, KVM_EXIT_SHUTDOWN, KVM_EXIT_INTERNAL_ERROR,
    KVM_EXIT_IO_IN, KVM_EXIT_IO_OUT;
import core.io : klog;

extern (C) @nogc nothrow:

enum : int {
    VMX_EINVAL = -22,
    VMX_EIO    = -5,
}

// ---------------------------------------------------------------------------
// VMX basic exit reasons (Intel SDM Vol 3C, Appendix C)
// ---------------------------------------------------------------------------
enum uint EXIT_REASON_EXCEPTION_NMI  = 0;
enum uint EXIT_REASON_TRIPLE_FAULT   = 2;
enum uint EXIT_REASON_HLT            = 12;
enum uint EXIT_REASON_VMCALL         = 18;
enum uint EXIT_REASON_IO_INSTRUCTION = 30;
enum uint EXIT_REASON_EPT_VIOLATION  = 48;

// ---------------------------------------------------------------------------
// Decoded exit input.  The HW wrapper fills every field from the VMCS /
// guest state after a real exit; host tests fill it synthetically.
// ---------------------------------------------------------------------------
struct VmExitInfo {
    uint  reason; // VMX basic exit reason
    ulong qual;   // exit qualification
    ulong gpa;    // guest-physical address (EPT violation)
    ulong data;   // I/O OUT data bytes (<=8, from guest RAX) / VMCALL nr (guest RAX)
    uint  count;  // REP count for string I/O (from guest RCX)
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
    if (vm !is null) vm.state = VmState.Dying;
    if (vc !is null) vc.state = VcpuState.Dead;
    if (run !is null) {
        run.exitReason = KVM_EXIT_INTERNAL_ERROR;
        run.u.hwReason = 0;
    }
    klog("[vmexit] contained failure: ");
    klog(why);
    klog("\n");
    return VmExitAction.VmContained;
}

// Decode one VM exit into the shared kvm_run page.
// Returns the action for the KVM_RUN path.  Never touches hardware.
VmExitAction vmxDispatchExit(const ref VmExitInfo info, KvmRun* run, Vm* vm, Vcpu* vc) {
    if (run is null || vc is null || vm is null)
        return vmContained(vm, vc, run, "null run/vcpu/vm");

    switch (info.reason) {
        case EXIT_REASON_HLT:
            run.exitReason = KVM_EXIT_HLT;
            vc.state = VcpuState.Exited;
            return VmExitAction.VcpuStopped;

        case EXIT_REASON_TRIPLE_FAULT:
            run.exitReason = KVM_EXIT_SHUTDOWN;
            vc.state = VcpuState.Exited;
            return VmExitAction.VcpuStopped;

        case EXIT_REASON_IO_INSTRUCTION: {
            // Exit qualification (SDM): [2:0] size-1 (0=1B,1=2B,2=4B),
            // [3] direction (0=OUT,1=IN), [4] string, [5] REP,
            // [6] operand encoding, [31:16] port.
            ulong size = (info.qual & 7) + 1;
            if (size != 1 && size != 2 && size != 4)
                return vmContained(vm, vc, run, "I/O with bad access size");
            uint dirIn  = cast(uint)((info.qual >> 3) & 1);
            uint str    = cast(uint)((info.qual >> 4) & 1);
            uint port   = cast(uint)((info.qual >> 16) & 0xFFFF);
            uint count  = str ? info.count : 1;
            if (str && count == 0)
                return vmContained(vm, vc, run, "string I/O with zero count");

            run.exitReason = KVM_EXIT_IO;
            run.u.io.direction  = dirIn ? KVM_EXIT_IO_IN : KVM_EXIT_IO_OUT;
            run.u.io.size       = cast(ubyte)size;
            run.u.io.port       = cast(ushort)port;
            run.u.io.count      = count;
            run.u.io.dataOffset = KVM_RUN_IO_DATA_OFF;
            // OUT data: the HW wrapper put the guest register bytes in
            // info.data.  String-OUT data lives in guest memory; copying it
            // is the HW wrapper's job (it walks the guest EPT).
            if (!dirIn && !str) {
                ubyte* dst = (cast(ubyte*)run) + KVM_RUN_IO_DATA_OFF;
                foreach (i; 0 .. size)
                    dst[i] = cast(ubyte)((info.data >> (8 * i)) & 0xFF);
            }
            return VmExitAction.ToUserspace;
        }

        case EXIT_REASON_EPT_VIOLATION: {
            // KVM semantics: the violation becomes an MMIO exit so the VMM
            // can emulate or kill the guest.  The access length is NOT in
            // the qualification; reporting a guessed length would be a fake
            // hardware claim, so len=0 means "unknown".
            run.exitReason = KVM_EXIT_MMIO;
            run.u.mmio.physAddr = info.gpa;
            run.u.mmio.isWrite  = cast(ubyte)((info.qual >> 1) & 1);
            run.u.mmio.len      = 0;
            foreach (i; 0 .. 8) run.u.mmio.data[i] = 0;
            return VmExitAction.ToUserspace;
        }

        case EXIT_REASON_VMCALL: {
            run.exitReason = KVM_EXIT_HYPERCALL;
            run.u.hypercall.nr = info.data; // guest RAX, via the HW wrapper
            foreach (i; 0 .. 6) run.u.hypercall.args[i] = 0; // HW fills from regs
            run.u.hypercall.ret = 0;
            run.u.hypercall.longMode = 0;
            run.u.hypercall.pad = 0;
            return VmExitAction.ToUserspace;
        }

        default: {
            // Unknown exit reason: contained by definition — a well-formed
            // KVM_EXIT_UNKNOWN reaches the VMM, which decides the guest's
            // fate.  Host state is never at risk.
            run.exitReason = KVM_EXIT_UNKNOWN;
            run.u.hwReason = info.reason;
            return VmExitAction.ToUserspace;
        }
    }
}

// ---------------------------------------------------------------------------
// Guest-state validation (task 6.3).  Called at SET time so hostile values
// are rejected with -EINVAL before they can reach VMCS programming.
// ---------------------------------------------------------------------------

// MSR indices that are never valid guest state.
enum uint MSR_IA32_FEATURE_CONTROL = 0x3A;
enum uint MSR_IA32_VMX_BASIC       = 0x480; // block: 0x480..0x48F
enum uint MSR_IA32_MICROCODE       = 0x79;
enum uint MSR_IA32_EFER            = 0xC0000080;

private int checkEfer(ulong efer) {
    if ((efer >> 32) != 0) return VMX_EINVAL;          // upper 32 reserved
    if ((efer & ~0xD01UL) != 0) return VMX_EINVAL;     // only SCE|LME|LMA|NXE
    if ((efer & (1UL << 10)) != 0 && (efer & (1UL << 8)) == 0)
        return VMX_EINVAL;                            // LMA requires LME
    return 0;
}

// Guest CR4: allow the bits a normal 64-bit guest needs; deny VMX/SMX/LA57
// and everything reserved.  (Our EPT is 4-level; LA57 guests are refused
// rather than half-supported.)
enum ulong GUEST_CR4_VALID = 0xF7FFFUL; // bits 0-11,16,17,18,20,21,22,23

int vmxValidateSRegs(const KvmSRegs* s) {
    if (s is null) return VMX_EINVAL;
    if ((s.cr0 >> 32) != 0) return VMX_EINVAL;
    if ((s.cr0 & 0x80000000UL) != 0 && (s.cr0 & 1) == 0)
        return VMX_EINVAL;                            // PG without PE
    if ((s.cr3 >> 52) != 0) return VMX_EINVAL;         // high bits reserved
    if ((s.cr4 & ~GUEST_CR4_VALID) != 0) return VMX_EINVAL; // VMX/SMX/LA57/reserved
    if (checkEfer(s.efer) != 0) return VMX_EINVAL;
    if ((s.efer & (1UL << 8)) != 0 && (s.cr4 & (1UL << 5)) == 0)
        return VMX_EINVAL;                            // LME requires CR4.PAE
    if (s.cr8 > 15) return VMX_EINVAL;                 // TPR is 4 bits
    if ((s.apicBase & 0xFF) != 0) return VMX_EINVAL;   // bits 7:0 reserved
    if ((s.apicBase & 0x200) != 0) return VMX_EINVAL;  // bit 9 reserved
    if ((s.apicBase >> 52) != 0) return VMX_EINVAL;
    return 0;
}

int vmxValidateRegs(const KvmRegs* r) {
    if (r is null) return VMX_EINVAL;
    ulong hi = r.rip >> 47;
    if (hi != 0 && hi != 0x1FFFF) return VMX_EINVAL;   // non-canonical RIP
    return 0;
}

int vmxValidateMsrs(const KvmMsrEntry* msrs, uint n) {
    if (n > 0 && msrs is null) return VMX_EINVAL;
    foreach (i; 0 .. n) {
        uint idx = msrs[i].index;
        if (idx == MSR_IA32_FEATURE_CONTROL) return VMX_EINVAL;
        if (idx >= MSR_IA32_VMX_BASIC && idx <= MSR_IA32_VMX_BASIC + 0xF)
            return VMX_EINVAL;                          // VMX MSRs never guest state
        if (idx == MSR_IA32_MICROCODE) return VMX_EINVAL;
        if (idx == MSR_IA32_EFER && checkEfer(msrs[i].data) != 0)
            return VMX_EINVAL;
    }
    return 0;
}

// Full pre-entry gate: validate everything cached for the vCPU before the
// [HW] wrapper programs the VMCS.  Returns 0 or -EINVAL.
int vmxValidateGuestState(const KvmRegs* regs, const KvmSRegs* sregs,
                          const KvmMsrEntry* msrs, uint nmsrs) {
    int rc = vmxValidateRegs(regs);
    if (rc != 0) return rc;
    if (sregs !is null) {
        rc = vmxValidateSRegs(sregs);
        if (rc != 0) return rc;
    }
    return vmxValidateMsrs(msrs, nmsrs);
}
