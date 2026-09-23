// HOST TEST 3: targeted VM-exit decode + dispatch tests.
//
// Drives the vendor decoders (core.virt.vmx/svm) and the common
// dispatcher (core.virt.vmexit) with synthetic exits:
//
// The boot selftest covers this path too; this binary is the host-runnable
// double with one assertion per behavior:
//   HLT -> KVM_EXIT_HLT + VcpuStopped + vCPU Exited
//   IO OUT/IN -> field population incl. data bytes
//   EPT violation -> KVM_EXIT_MMIO
//   VMCALL -> KVM_EXIT_HYPERCALL
//   triple fault -> KVM_EXIT_SHUTDOWN + vCPU Exited
//   unknown reason -> KVM_EXIT_UNKNOWN, VM untouched
//   bad IO size -> VmContained + VM Dying + KVM_EXIT_INTERNAL_ERROR
//
// Constraints: -betterC, @nogc nothrow.  Prints "[virt] dispatch PASS".
module run_dispatch;

import core.virt.vm : Vm, Vcpu, VmState, VcpuState,
    kvmUnpackHandle, kvmVmFdClosed, kvmVcpuFdClosed, vmCheck, vcpuCheckObj;
import core.virt.kvm : kvmCreateVm, kvmCreateVcpu;
import core.virt.vmexit : virtDispatchExit, VirtExitInfo, VirtExitKind,
    VmExitAction;
import core.virt.vmx : vmxDecodeExit,
    EXIT_REASON_HLT, EXIT_REASON_TRIPLE_FAULT, EXIT_REASON_IO_INSTRUCTION,
    EXIT_REASON_EPT_VIOLATION, EXIT_REASON_VMCALL;
import core.virt.svm : svmDecodeExit,
    SVM_EXIT_HLT, SVM_EXIT_IOIO, SVM_EXIT_SHUTDOWN, SVM_EXIT_VMMCALL,
    SVM_EXIT_NPF;
import core.virt.kvmabi : KvmRun,
    KVM_EXIT_UNKNOWN, KVM_EXIT_IO, KVM_EXIT_HYPERCALL, KVM_EXIT_HLT,
    KVM_EXIT_MMIO, KVM_EXIT_SHUTDOWN, KVM_EXIT_INTERNAL_ERROR,
    KVM_EXIT_IO_IN, KVM_EXIT_IO_OUT;
import core.exports : phys_to_virt;
import memory.mm : alloc_phys_page, free_phys_page;
import core.stdc.stdio : printf;

extern (C) @nogc nothrow:

__gshared uint d_fails = 0;

private void dCheck(bool ok, const(char)* name) {
    if (!ok) {
        ++d_fails;
        printf("[dispatch] FAIL: %s\n", name);
    }
}

private void zeroRun(KvmRun* run) {
    auto b = cast(ubyte*)run;
    foreach (i; 0 .. KvmRun.sizeof) b[i] = 0;
}

extern (C) int main() {
    int tid = 0;

    long h = kvmCreateVm(tid);
    dCheck(h >= 0, "vm-alloc");
    if (h < 0) { printf("[virt] dispatch FAILURES\n"); return 1; }
    uint vo, vg;
    kvmUnpackHandle(cast(ulong)h, vo, vg);
    Vm* vm = vmCheck(vo, vg);
    dCheck(vm !is null, "vm-live");

    ulong rp = alloc_phys_page();
    dCheck(rp != 0, "runpage");
    KvmRun* run = cast(KvmRun*)phys_to_virt(rp);

    uint[4] co; uint[4] cg;
    bool ok = true;
    foreach (i; 0 .. 4) {
        long vh = kvmCreateVcpu(vo, vg, i);
        if (vh < 0) { ok = false; break; }
        kvmUnpackHandle(cast(ulong)vh, co[i], cg[i]);
    }
    dCheck(ok, "vcpus");
    if (!ok) { printf("[virt] dispatch FAILURES\n"); return 1; }

    VirtExitInfo xi;

    // --- HLT -> KVM_EXIT_HLT, VcpuStopped, vCPU Exited -----------------------
    zeroRun(run);
    vmxDecodeExit(EXIT_REASON_HLT, 0, 0, 0, 0, &xi);
    dCheck(xi.kind == VirtExitKind.Hlt, "hlt-kind");
    Vcpu* vc0 = vcpuCheckObj(co[0], cg[0]);
    dCheck(virtDispatchExit(xi, run, vm, vc0) == VmExitAction.VcpuStopped,
           "hlt-action");
    dCheck(run.exitReason == KVM_EXIT_HLT, "hlt-reason");
    dCheck(vc0.state == VcpuState.Exited, "hlt-vcpu-exited");

    // --- I/O OUT: outb 0xAB -> port 0x10 ------------------------------------
    zeroRun(run);
    Vcpu* vc1 = vcpuCheckObj(co[1], cg[1]);
    vmxDecodeExit(EXIT_REASON_IO_INSTRUCTION, 0x10UL << 16, 0, 0xAB, 0, &xi);
    dCheck(xi.kind == VirtExitKind.Io && xi.ioSize == 1 && xi.ioIsIn == 0,
           "io-out-kind");
    dCheck(virtDispatchExit(xi, run, vm, vc1) == VmExitAction.ToUserspace,
           "io-out-action");
    dCheck(run.exitReason == KVM_EXIT_IO, "io-out-reason");
    dCheck(run.u.io.direction == KVM_EXIT_IO_OUT, "io-out-dir");
    dCheck(run.u.io.size == 1 && run.u.io.port == 0x10, "io-out-port-size");
    dCheck(run.u.io.count == 1, "io-out-count");
    dCheck(run.u.io.dataOffset == KvmRun.sizeof, "io-out-dataoff");
    dCheck((cast(ubyte*)run)[KvmRun.sizeof] == 0xAB, "io-out-data");

    // --- I/O OUT size=4: data byte order (little-endian guest RAX) ------------
    zeroRun(run);
    vmxDecodeExit(EXIT_REASON_IO_INSTRUCTION, 3 | (0x20UL << 16), 0,
                  0xAABBCCDDUL, 0, &xi); // size enc 3 -> 4B, OUT, port 0x20
    dCheck(xi.ioSize == 4, "io-out4-size");
    dCheck(virtDispatchExit(xi, run, vm, vc1) == VmExitAction.ToUserspace,
           "io-out4-action");
    ubyte* db = (cast(ubyte*)run) + KvmRun.sizeof;
    dCheck(db[0] == 0xDD && db[1] == 0xCC && db[2] == 0xBB && db[3] == 0xAA,
           "io-out4-bytes");

    // --- I/O IN: in ax, 0x3F8 (size=2) ---------------------------------------
    zeroRun(run);
    vmxDecodeExit(EXIT_REASON_IO_INSTRUCTION,
                  1 | (1UL << 3) | (0x3F8UL << 16), 0, 0, 0, &xi);
    dCheck(xi.ioSize == 2 && xi.ioIsIn == 1 && xi.ioPort == 0x3F8,
           "io-in-kind");
    dCheck(virtDispatchExit(xi, run, vm, vc1) == VmExitAction.ToUserspace,
           "io-in-action");
    dCheck(run.u.io.direction == KVM_EXIT_IO_IN, "io-in-dir");
    dCheck(run.u.io.size == 2 && run.u.io.port == 0x3F8, "io-in-port-size");

    // --- EPT violation (write) -> KVM_EXIT_MMIO --------------------------------
    zeroRun(run);
    vmxDecodeExit(EXIT_REASON_EPT_VIOLATION, 1UL << 1, 0xFEC0_0000UL, 0, 0,
                  &xi); // write access
    dCheck(xi.kind == VirtExitKind.SlatFault && xi.slatIsWrite == 1,
           "ept-kind");
    dCheck(virtDispatchExit(xi, run, vm, vc1) == VmExitAction.ToUserspace,
           "ept-action");
    dCheck(run.exitReason == KVM_EXIT_MMIO, "ept-reason");
    dCheck(run.u.mmio.physAddr == 0xFEC0_0000UL, "ept-gpa");
    dCheck(run.u.mmio.isWrite == 1 && run.u.mmio.len == 0, "ept-flags");

    // --- VMCALL -> hypercall ----------------------------------------------------
    zeroRun(run);
    vmxDecodeExit(EXIT_REASON_VMCALL, 0, 0, 0x1234, 0, &xi);
    dCheck(xi.kind == VirtExitKind.Hypercall && xi.data == 0x1234, "vmcall-kind");
    dCheck(virtDispatchExit(xi, run, vm, vc1) == VmExitAction.ToUserspace,
           "vmcall-action");
    dCheck(run.exitReason == KVM_EXIT_HYPERCALL, "vmcall-reason");
    dCheck(run.u.hypercall.nr == 0x1234, "vmcall-nr");

    // --- triple fault -> SHUTDOWN, vCPU Exited -----------------------------------
    zeroRun(run);
    vmxDecodeExit(EXIT_REASON_TRIPLE_FAULT, 0, 0, 0, 0, &xi);
    Vcpu* vc2 = vcpuCheckObj(co[2], cg[2]);
    dCheck(virtDispatchExit(xi, run, vm, vc2) == VmExitAction.VcpuStopped,
           "tf-action");
    dCheck(run.exitReason == KVM_EXIT_SHUTDOWN, "tf-reason");
    dCheck(vc2.state == VcpuState.Exited, "tf-vcpu-exited");

    // --- unknown reason -> KVM_EXIT_UNKNOWN, VM untouched -------------------------
    zeroRun(run);
    vmxDecodeExit(0xFF, 0, 0, 0, 0, &xi);
    dCheck(xi.kind == VirtExitKind.Unknown && xi.hardwareReason == 0xFF,
           "unk-kind");
    Vcpu* vc3 = vcpuCheckObj(co[3], cg[3]);
    dCheck(virtDispatchExit(xi, run, vm, vc3) == VmExitAction.ToUserspace,
           "unk-action");
    dCheck(run.exitReason == KVM_EXIT_UNKNOWN, "unk-reason");
    dCheck(run.u.hwReason == 0xFF, "unk-hwreason");
    dCheck(vm.state == VmState.Active, "unk-vm-still-active");
    dCheck(vc3.state != VcpuState.Dead, "unk-vcpu-alive");

    // --- SVM decoder spot-checks (vendor B of the same common dispatcher) ---
    // Decoding is the vendor-specific part; Hlt/Shutdown dispatch is already
    // covered by the VMX cases above, so only the decode is asserted for
    // those two (dispatching HLT here would mark vc3 Exited).
    zeroRun(run);
    svmDecodeExit(SVM_EXIT_HLT, 0, 0, 0, &xi);
    dCheck(xi.kind == VirtExitKind.Hlt, "svm-hlt-kind");

    zeroRun(run);
    svmDecodeExit(SVM_EXIT_VMMCALL, 0, 0, 0x5678, &xi);
    dCheck(xi.kind == VirtExitKind.Hypercall && xi.data == 0x5678,
           "svm-vmmcall-kind");
    dCheck(virtDispatchExit(xi, run, vm, vc3) == VmExitAction.ToUserspace,
           "svm-vmmcall-action");
    dCheck(run.u.hypercall.nr == 0x5678, "svm-vmmcall-nr");

    zeroRun(run);
    svmDecodeExit(SVM_EXIT_SHUTDOWN, 0, 0, 0, &xi);
    dCheck(xi.kind == VirtExitKind.Shutdown, "svm-shutdown-kind");

    // IOIO: EXITINFO1 per APM Vol.2 §15.10.2 — OUT to 0x3F8, 1 byte.
    // info1 = port[31:16] | SZ8[4].
    zeroRun(run);
    svmDecodeExit(SVM_EXIT_IOIO, (0x3F8UL << 16) | (1UL << 4), 0, 0, &xi);
    dCheck(xi.kind == VirtExitKind.Io, "svm-ioio-kind");
    dCheck(xi.ioPort == 0x3F8 && xi.ioSize == 1, "svm-ioio-port-size");
    dCheck(xi.ioIsIn == 0 && xi.ioIsString == 0, "svm-ioio-dir");
    dCheck(virtDispatchExit(xi, run, vm, vc3) == VmExitAction.ToUserspace,
           "svm-ioio-action");
    dCheck(run.exitReason == KVM_EXIT_IO, "svm-ioio-reason");

    // IOIO: IN from 0x60, 2 bytes (SZ16[5] | TYPE[0]).
    zeroRun(run);
    svmDecodeExit(SVM_EXIT_IOIO, (0x60UL << 16) | (1UL << 5) | 1UL, 0, 0, &xi);
    dCheck(xi.kind == VirtExitKind.Io && xi.ioSize == 2 && xi.ioIsIn == 1,
           "svm-ioio-in");

    // IOIO: ambiguous size (SZ8|SZ16) -> ioSize 0 -> contained.
    zeroRun(run);
    svmDecodeExit(SVM_EXIT_IOIO, (0x3F8UL << 16) | (1UL << 4) | (1UL << 5),
                  0, 0, &xi);
    dCheck(xi.ioSize == 0, "svm-ioio-badsize");

    // NPF: EXITINFO1 per §15.25.6 — b1=RW(write), b2=US; EXITINFO2=GPA.
    zeroRun(run);
    svmDecodeExit(SVM_EXIT_NPF, 0x6, 0xFEC0_0000UL, 0, &xi);
    dCheck(xi.kind == VirtExitKind.SlatFault, "svm-npf-kind");
    dCheck(xi.gpa == 0xFEC0_0000UL && xi.slatIsWrite == 1, "svm-npf-fields");

    // --- reserved I/O size encoding -> contained, VM Dying (LAST: kills it) --
    zeroRun(run);
    vmxDecodeExit(EXIT_REASON_IO_INSTRUCTION, 2, 0, 0, 0, &xi); // bits[2:0]=2: reserved
    dCheck(xi.ioSize == 0, "badio-size");
    dCheck(virtDispatchExit(xi, run, vm, vc3) == VmExitAction.VmContained,
           "badio-contained");
    dCheck(vm.state == VmState.Dying, "badio-vm-dying");
    dCheck(vc3.state == VcpuState.Dead, "badio-vcpu-dead");
    dCheck(run.exitReason == KVM_EXIT_INTERNAL_ERROR, "badio-reason");

    free_phys_page(rp);
    // NOTE: the VM is Dying by design here; handles are stale by construction.
    // (kvmVmFdClosed on a non-Active VM is a deliberate no-op.)

    if (d_fails == 0) printf("[virt] dispatch PASS\n");
    else printf("[virt] dispatch FAILURES: %u\n", d_fails);
    return d_fails == 0 ? 0 : 1;
}
