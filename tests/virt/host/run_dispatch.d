// HOST TEST 3: targeted VM-exit dispatch tests (core.virt.vmexit).
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
import core.virt.vmexit : vmxDispatchExit, VmExitInfo, VmExitAction,
    EXIT_REASON_HLT, EXIT_REASON_TRIPLE_FAULT, EXIT_REASON_IO_INSTRUCTION,
    EXIT_REASON_EPT_VIOLATION, EXIT_REASON_VMCALL;
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

    VmExitInfo xi;
    xi.gpa = 0; xi.data = 0; xi.count = 0;

    // --- HLT -> KVM_EXIT_HLT, VcpuStopped, vCPU Exited -----------------------
    zeroRun(run);
    xi.reason = EXIT_REASON_HLT; xi.qual = 0;
    Vcpu* vc0 = vcpuCheckObj(co[0], cg[0]);
    dCheck(vmxDispatchExit(xi, run, vm, vc0) == VmExitAction.VcpuStopped,
           "hlt-action");
    dCheck(run.exitReason == KVM_EXIT_HLT, "hlt-reason");
    dCheck(vc0.state == VcpuState.Exited, "hlt-vcpu-exited");

    // --- I/O OUT: outb 0xAB -> port 0x10 ------------------------------------
    zeroRun(run);
    Vcpu* vc1 = vcpuCheckObj(co[1], cg[1]);
    xi.reason = EXIT_REASON_IO_INSTRUCTION;
    xi.qual = (0x10UL << 16); // size=1, OUT, port 0x10
    xi.data = 0xAB;
    dCheck(vmxDispatchExit(xi, run, vm, vc1) == VmExitAction.ToUserspace,
           "io-out-action");
    dCheck(run.exitReason == KVM_EXIT_IO, "io-out-reason");
    dCheck(run.u.io.direction == KVM_EXIT_IO_OUT, "io-out-dir");
    dCheck(run.u.io.size == 1 && run.u.io.port == 0x10, "io-out-port-size");
    dCheck(run.u.io.count == 1, "io-out-count");
    dCheck(run.u.io.dataOffset == KvmRun.sizeof, "io-out-dataoff");
    dCheck((cast(ubyte*)run)[KvmRun.sizeof] == 0xAB, "io-out-data");

    // --- I/O OUT size=4: data byte order (little-endian guest RAX) ------------
    zeroRun(run);
    xi.qual = 3 | (0x20UL << 16); // size-1=3 -> size=4, OUT, port 0x20
    xi.data = 0xAABBCCDDUL;
    dCheck(vmxDispatchExit(xi, run, vm, vc1) == VmExitAction.ToUserspace,
           "io-out4-action");
    ubyte* db = (cast(ubyte*)run) + KvmRun.sizeof;
    dCheck(db[0] == 0xDD && db[1] == 0xCC && db[2] == 0xBB && db[3] == 0xAA,
           "io-out4-bytes");

    // --- I/O IN: in ax, 0x3F8 (size=2) ---------------------------------------
    zeroRun(run);
    xi.qual = 1 | (1UL << 3) | (0x3F8UL << 16); // size=2, IN, port 0x3F8
    dCheck(vmxDispatchExit(xi, run, vm, vc1) == VmExitAction.ToUserspace,
           "io-in-action");
    dCheck(run.u.io.direction == KVM_EXIT_IO_IN, "io-in-dir");
    dCheck(run.u.io.size == 2 && run.u.io.port == 0x3F8, "io-in-port-size");

    // --- EPT violation (write) -> KVM_EXIT_MMIO --------------------------------
    zeroRun(run);
    xi.reason = EXIT_REASON_EPT_VIOLATION;
    xi.qual = (1UL << 1); xi.gpa = 0xFEC0_0000UL; xi.data = 0;
    dCheck(vmxDispatchExit(xi, run, vm, vc1) == VmExitAction.ToUserspace,
           "ept-action");
    dCheck(run.exitReason == KVM_EXIT_MMIO, "ept-reason");
    dCheck(run.u.mmio.physAddr == 0xFEC0_0000UL, "ept-gpa");
    dCheck(run.u.mmio.isWrite == 1 && run.u.mmio.len == 0, "ept-flags");

    // --- VMCALL -> hypercall ----------------------------------------------------
    zeroRun(run);
    xi.reason = EXIT_REASON_VMCALL; xi.qual = 0; xi.gpa = 0; xi.data = 0x1234;
    dCheck(vmxDispatchExit(xi, run, vm, vc1) == VmExitAction.ToUserspace,
           "vmcall-action");
    dCheck(run.exitReason == KVM_EXIT_HYPERCALL, "vmcall-reason");
    dCheck(run.u.hypercall.nr == 0x1234, "vmcall-nr");

    // --- triple fault -> SHUTDOWN, vCPU Exited -----------------------------------
    zeroRun(run);
    xi.reason = EXIT_REASON_TRIPLE_FAULT; xi.data = 0;
    Vcpu* vc2 = vcpuCheckObj(co[2], cg[2]);
    dCheck(vmxDispatchExit(xi, run, vm, vc2) == VmExitAction.VcpuStopped,
           "tf-action");
    dCheck(run.exitReason == KVM_EXIT_SHUTDOWN, "tf-reason");
    dCheck(vc2.state == VcpuState.Exited, "tf-vcpu-exited");

    // --- unknown reason -> KVM_EXIT_UNKNOWN, VM untouched -------------------------
    zeroRun(run);
    xi.reason = 0xFF;
    Vcpu* vc3 = vcpuCheckObj(co[3], cg[3]);
    dCheck(vmxDispatchExit(xi, run, vm, vc3) == VmExitAction.ToUserspace,
           "unk-action");
    dCheck(run.exitReason == KVM_EXIT_UNKNOWN, "unk-reason");
    dCheck(run.u.hwReason == 0xFF, "unk-hwreason");
    dCheck(vm.state == VmState.Active, "unk-vm-still-active");
    dCheck(vc3.state != VcpuState.Dead, "unk-vcpu-alive");

    // --- bad I/O size (5 bytes) -> contained, VM Dying (LAST: kills the VM) -------
    zeroRun(run);
    xi.reason = EXIT_REASON_IO_INSTRUCTION; xi.qual = 4; // size = 5: invalid
    dCheck(vmxDispatchExit(xi, run, vm, vc3) == VmExitAction.VmContained,
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
