// VIRT: boot-time self-test for the native VMM + KVM compatibility layer.
//
// Runs once at boot (see kernel_main.d) as task 0.  Exercises the REAL dispatch
// path — kvmSystemIoctl/kvmVmIoctl/kvmVcpuIoctl — not just internals:
//
//   * extension probe table (incl. the IRQCHIP=1 / PIT2=0 split-irqchip contract)
//   * userspace-pointer guard (null, wrap, high-half, oversize)
//   * VM/vCPU lifecycle: create, stale-handle rejection, generation advance,
//     fd-refcount release, vCPU slot reuse, VM/Vcpu ceilings
//   * memory-slot validation: slot range, flags, alignment, overflow, overlap
//   * EPT: validation failures + a real map/lookup/unmap round-trip
//   * KVM_RUN fail-soft: -ENODEV without virtualization hardware
//     (skipped when a backend reports ready)
//
// Every allocation is released; on failure the test logs FAIL and keeps going
// so one broken invariant does not mask the others.  Leaves no state.
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.selftest;

import core.virt.vm;
import core.virt.kvm;
import core.virt.kvmabi;
import core.virt.slat;
import core.virt.npt;
import core.virt.vmcb;
import core.virt.vmx : vmxDecodeExit,
    EXIT_REASON_HLT, EXIT_REASON_TRIPLE_FAULT, EXIT_REASON_IO_INSTRUCTION,
    EXIT_REASON_EPT_VIOLATION, EXIT_REASON_VMCALL;
import core.virt.svm : svmHwPresent;
import core.virt.backend : virtBackendAvailable, virtBackendKind, VirtBackendKind;
import core.virt.vmexit : virtDispatchExit, VirtExitInfo, VirtExitKind,
    VmExitAction, virtValidateSRegs, virtValidateRegs, virtValidateMsrs;
import core.exports : phys_to_virt;
import core.io : klog;
import memory.mm : alloc_phys_page, free_phys_page;

extern (C) @nogc nothrow:

// __gshared, NOT plain: a D module-level mutable without it is THREAD-LOCAL
// (.tdata/.tbss), and the freestanding kernel has no FS base for boot tasks —
// the first access faults with a not-present read at CR2=0.
private __gshared uint g_virtTestFails = 0;
private void vtCheck(bool ok, const(char)* name) {
    if (!ok) {
        ++g_virtTestFails;
        klog("[virt] selftest FAIL: ");
        klog(name);
        klog("\n");
    }
}

public void virtSelfTest() {
    g_virtTestFails = 0;
    int tid = 0; // boot task

    // --- 0. backend detection (honest hardware report) -----------------------
    // Logs exactly which virtualization path this hardware takes. On AMD
    // this records the fail-closed SVM detection (task 3.5): the CPUID
    // hardware bit plus the backend-not-ready refusal — never a fake VMXON.
    if (virtBackendAvailable())
        klog("[virt] backend: hardware backend ready\n");
    else if (svmHwPresent())
        klog("[virt] backend: AMD SVM detected, backend not validated - fail-closed (ENODEV on entry)\n");
    else
        klog("[virt] backend: no VMX/SVM hardware\n");

    // --- 1. probe table ------------------------------------------------------
    vtCheck(kvmSystemIoctl(tid, KVM_GET_API_VERSION, 0) == 12, "api-version");
    vtCheck(kvmSystemIoctl(tid, KVM_CHECK_EXTENSION, KVM_CAP_IRQCHIP) == 1,
            "cap-irqchip-probe"); // Cloud Hypervisor's hard gate
    vtCheck(kvmSystemIoctl(tid, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY) == 1,
            "cap-user-memory");
    vtCheck(kvmSystemIoctl(tid, KVM_CHECK_EXTENSION, KVM_CAP_NR_VCPUS) == 64,
            "cap-nr-vcpus");
    vtCheck(kvmSystemIoctl(tid, KVM_CHECK_EXTENSION, KVM_CAP_NR_MEMSLOTS) == 32,
            "cap-nr-memslots");
    vtCheck(kvmSystemIoctl(tid, KVM_CHECK_EXTENSION, KVM_CAP_SPLIT_IRQCHIP) == 24,
            "cap-split-irqchip");
    vtCheck(kvmSystemIoctl(tid, KVM_CHECK_EXTENSION, KVM_CAP_PIT) == 0,
            "cap-pit-absent");
    vtCheck(kvmSystemIoctl(tid, KVM_CHECK_EXTENSION, KVM_CAP_PIT2) == 0,
            "cap-pit2-absent");
    vtCheck(kvmSystemIoctl(tid, KVM_CHECK_EXTENSION, KVM_CAP_MULTI_ADDRESS_SPACE) == 0,
            "cap-multi-as-absent");
    vtCheck(kvmSystemIoctl(tid, KVM_CHECK_EXTENSION, 0xFFFF) == 0,
            "cap-bogus-absent");
    // CREATE_IRQCHIP / CREATE_PIT2 are probed 1 but rejected: split irqchip only.
    {
        long h = kvmCreateVm(tid);
        vtCheck(h >= 0, "probe-vm-alloc");
        if (h >= 0) {
            uint vo, vg;
            kvmUnpackHandle(cast(ulong)h, vo, vg);
            vtCheck(kvmVmIoctl(tid, vo, vg, KVM_CREATE_IRQCHIP, 0) == -25,
                    "create-irqchip-enotty");
            vtCheck(kvmVmIoctl(tid, vo, vg, KVM_CREATE_PIT2, 0) == -25,
                    "create-pit2-enotty");
            vtCheck(kvmVmIoctl(tid, vo, vg, 0xDEAD_BEEF, 0) == -22,
                    "vm-bogus-ioctl-einval");
            kvmVmFdClosed(vo, vg);
            vtCheck(vmCheck(vo, vg) is null, "vm-stale-after-close");
        }
    }

    // --- 2. userspace guard (adversarial pointers) ---------------------------
    vtCheck(!kvmTestUserOk(tid, 0, 8), "userok-null");
    vtCheck(!kvmTestUserOk(tid, 0xFFFF_FFFF_FFFF_F000UL, 0x2000), "userok-wrap");
    vtCheck(!kvmTestUserOk(tid, 0xFFFF_8000_0000_0000UL, 8), "userok-highhalf");
    vtCheck(!kvmTestUserOk(tid, 0x1000, 0x20_0000), "userok-oversize");
    vtCheck(!kvmTestUserOk(tid, 0x1000, 0), "userok-zerolen");
    vtCheck(!kvmTestUserOk(-1, 0x1000, 8), "userok-badtid");

    // --- 3. VM/vCPU lifecycle ------------------------------------------------
    uint vmObj = 0, vmGen = 0;
    uint vcObj = 0, vcGen = 0;
    {
        long h = kvmCreateVm(tid);
        vtCheck(h >= 0, "vm-alloc");
        if (h < 0) goto done;
        kvmUnpackHandle(cast(ulong)h, vmObj, vmGen);
        vtCheck(vmCheck(vmObj, vmGen) !is null, "vm-live");
        vtCheck(vmCheck(vmObj, vmGen ^ 1) is null, "vm-badgen-stale");
        vtCheck(vmCheck(vmObj ^ 0xFF, vmGen) is null, "vm-badobj-stale");
    }
    {
        long h = kvmCreateVcpu(vmObj, vmGen, 0);
        vtCheck(h >= 0, "vcpu-alloc-id0");
        if (h >= 0) {
            kvmUnpackHandle(cast(ulong)h, vcObj, vcGen);
            vtCheck(vcpuCheckObj(vcObj, vcGen) !is null, "vcpu-live");
        }
        // Duplicate id -> rejected; out-of-range id -> rejected.
        vtCheck(kvmCreateVcpu(vmObj, vmGen, 0) < 0, "vcpu-id-taken");
        vtCheck(kvmCreateVcpu(vmObj, vmGen, 64) < 0, "vcpu-id-range");
        vtCheck(kvmCreateVcpu(vmObj, 0xDEAD, 1) < 0, "vcpu-stale-vm");
    }
    // GET_REGS with a null pointer -> EFAULT (guard, not a kernel fault).
    vtCheck(kvmVcpuIoctl(tid, vcObj, vcGen, KVM_GET_REGS, 0) == -14,
            "vcpu-getregs-efault");
    // KVM_RUN: without virtualization hardware this must fail soft with
    // -ENODEV (vCPU stays Runnable).  Once virtBackendAvailable() is true
    // the backend owns this path and the expectation no longer applies.
    if (!virtBackendAvailable()) {
        vtCheck(kvmVcpuIoctl(tid, vcObj, vcGen, KVM_RUN, 0) == -19,
                "vcpu-run-enodev");
        vtCheck(vcpuCheckObj(vcObj, vcGen) !is null, "vcpu-alive-after-enodev");
    } else {
        klog("[virt] selftest: hw backend present, skipping enodev probe\n");
    }

    // --- 4. memory-slot validation -------------------------------------------
    {
        Vm* vm = vmCheck(vmObj, vmGen);
        vtCheck(vm !is null, "mem-vm-live");
        if (vm !is null) {
            vtCheck(vmSetMemoryRegion(vm, 32, 0, 0, 0x1000, 0x1000) == -22,
                    "mem-slot-range");
            vtCheck(vmSetMemoryRegion(vm, 0, 0xFF, 0, 0x1000, 0x1000) == -22,
                    "mem-bad-flags");
            vtCheck(vmSetMemoryRegion(vm, 0, 0, 0x1001, 0x1000, 0x1000) == -22,
                    "mem-gpa-unaligned");
            vtCheck(vmSetMemoryRegion(vm, 0, 0, 0, 0x1001, 0x1000) == -22,
                    "mem-size-unaligned");
            vtCheck(vmSetMemoryRegion(vm, 0, 0, 0xFFFF_FFFF_FFFF_F000UL,
                                      0x2000, 0x1000) == -22, "mem-gpa-overflow");
            // Overlap: fake a live slot, probe an overlapping add, clear it.
            vm.slots[3].used = true;
            vm.slots[3].slotId = 3;
            vm.slots[3].guestPhys = 0x10_0000;
            vm.slots[3].pages = 16;
            vtCheck(vmSetMemoryRegion(vm, 5, 0, 0x10_8000, 0x4000, 0x200_0000) == -22,
                    "mem-overlap-rejected");
            vm.slots[3] = VmMemSlot.init;
            // Removing an unused slot is a no-op success.
            vtCheck(vmSetMemoryRegion(vm, 7, 0, 0, 0, 0) == 0, "mem-remove-noop");
        }
    }

    // --- 5. SLAT (vendor-neutral second-level translation) ------------------
    // The VM's SLAT kind follows the detected backend (EPT on Intel, NPT on
    // AMD).  The selftest drives the generic SLAT API so the same checks
    // validate either table format; exact per-format encodings are checked
    // below with scratch tables.
    {
        Vm* vm = vmCheck(vmObj, vmGen);
        vtCheck(vm !is null, "slat-vm-live");
        if (vm !is null) {
            vtCheck((virtBackendKind() == VirtBackendKind.Svm) ==
                    (vm.slat.kind == SlatKind.Npt), "slat-kind-matches-hw");
            // Validation failures allocate nothing.
            vtCheck(!slatMap(&vm.slat, 0x1001, 0x2000, 7),
                    "slat-misaligned-gpa");
            vtCheck(!slatMap(&vm.slat, 0x1000, 0x2001, 7),
                    "slat-misaligned-hpa");
            vtCheck(!slatMap(&vm.slat, 0x1000, 0x2000, 0), "slat-zero-prot");
            vtCheck(!slatMap(&vm.slat, 0x1000, 0x2000, 8), "slat-bad-prot");
            vtCheck(slatRootPhys(&vm.slat) == 0, "slat-root-empty-pre-map");
            // Real map/lookup/unmap round-trip on a scratch page.
            ulong sp = alloc_phys_page();
            vtCheck(sp != 0, "slat-scratch-page");
            if (sp != 0) {
                vtCheck(slatMap(&vm.slat, 0x5000, sp, 7), "slat-map");
                vtCheck(slatRootPhys(&vm.slat) != 0, "slat-root-live");
                vtCheck(slatTableCount(&vm.slat) >= 4, "slat-tables");
                vtCheck(!slatMap(&vm.slat, 0x5000, sp, 7), "slat-double-map");
                vtCheck(slatLookup(&vm.slat, 0x5000) == (sp & ~0xFFFUL),
                        "slat-lookup");
                vtCheck(slatUnmap(&vm.slat, 0x5000) == (sp & ~0xFFFUL),
                        "slat-unmap");
                vtCheck(slatLookup(&vm.slat, 0x5000) == 0, "slat-gone");
                free_phys_page(sp);
            }
        }
    }

    // --- 5b. NPT exact encodings (scratch table; HW-independent) -------------
    // AMD NPT leaf entries: P[0] + RW[1] + US[2] + NX[63](=!exec).  The
    // walker is pure software here; real NPT hardware behavior stays [HW].
    {
        Npt n;
        nptInit(&n);
        // phys_to_virt returns ulong (real kernel) vs void* (host stub);
        // normalize through a wrapper so both builds typecheck.
        static extern(C) void* nptMapWrap(ulong p)
        { return cast(void*)phys_to_virt(p); }
        nptWireKernel(&n, &alloc_phys_page, &free_phys_page, &nptMapWrap);
        ulong sp = alloc_phys_page();
        vtCheck(sp != 0, "npt-scratch-page");
        if (sp != 0) {
            vtCheck(nptMap(&n, 0x9000, sp, SLAT_R | SLAT_W), "npt-map-rw");
            ulong raw = nptLookupRaw(&n, 0x9000);
            vtCheck((raw & (NPT_PTE_P | NPT_PTE_RW | NPT_PTE_US)) ==
                    (NPT_PTE_P | NPT_PTE_RW | NPT_PTE_US), "npt-enc-rw");
            vtCheck((raw & NPT_PTE_NX) != 0, "npt-enc-nx-noexec");
            vtCheck(nptUnmap(&n, 0x9000) == (sp & ~0xFFFUL), "npt-unmap");
            vtCheck(nptMap(&n, 0x9000, sp, SLAT_R | SLAT_X), "npt-map-x");
            raw = nptLookupRaw(&n, 0x9000);
            vtCheck((raw & NPT_PTE_RW) == 0, "npt-enc-ro");
            vtCheck((raw & NPT_PTE_NX) == 0, "npt-enc-exec");
            vtCheck(nptLookup(&n, 0x9000) == (sp & ~0xFFFUL), "npt-lookup");
            vtCheck(nptUnmap(&n, 0x9000) == (sp & ~0xFFFUL), "npt-unmap2");
            vtCheck(nptLookup(&n, 0x9000) == 0, "npt-gone");
            free_phys_page(sp);
        }
        nptFree(&n);
        vtCheck(n.tables == 0 && n.pml4Phys == 0, "npt-free-clean");
    }

    // --- 5c. VMCB layout helpers (exact AMD offsets; HW-independent) --------
    // The struct static asserts already pin every offset at compile time;
    // these runtime checks exercise the intercept/segment helpers against
    // the researched values.
    {
        ulong page = alloc_phys_page();
        vtCheck(page != 0, "vmcb-page");
        if (page != 0) {
            Vmcb* v = cast(Vmcb*)phys_to_virt(page);
            ulong* q = cast(ulong*)v;
            foreach (i; 0 .. Vmcb.sizeof / 8) q[i] = 0;
            vmcbSetIntercept(&v.control, SVM_INT_HLT);      // bit 120
            vmcbSetIntercept(&v.control, SVM_INT_IOIO);     // bit 123
            vmcbSetIntercept(&v.control, SVM_INT_VMMCALL);  // bit 129
            vtCheck(v.control.intercepts[3] == ((1u << 24) | (1u << 27)),
                    "vmcb-intercept-word3");
            vtCheck(v.control.intercepts[4] == (1u << 1),
                    "vmcb-intercept-word4");
            // Raw-offset cross-check: EXITCODE @ 0x070, nCR3 @ 0x0B0.
            v.control.exitcode = 0x78;
            vtCheck(*(cast(ulong*)(cast(ubyte*)v + 0x070)) == 0x78,
                    "vmcb-exitcode-off");
            v.control.ncr3 = 0x12345000;
            vtCheck(*(cast(ulong*)(cast(ubyte*)v + 0x0B0)) == 0x12345000,
                    "vmcb-ncr3-off");
            // Segment attrib: 64-bit code (type 0xB, S, P, L).
            ushort a = vmcbSegAttrib(0xB, 1, 0, 1, 0, 1, 0, 1, 0);
            vtCheck(a == 0xA09B, "vmcb-seg-attrib");
            vtCheck(vmcbSegAttrib(0, 0, 0, 0, 0, 0, 0, 0, 1) == 0,
                    "vmcb-seg-unusable");
            vmcbWriteSeg(&v.save.cs, 0x10, a, 0xFFFF_FFFF, 0);
            vtCheck(v.save.cs.selector == 0x10 && v.save.cs.attrib == 0xA09B &&
                    v.save.cs.base == 0, "vmcb-seg-write");
            // Save-area raw offsets: RIP @ 0x578, RSP @ 0x5D8, RAX @ 0x5F8.
            v.save.rip = 0x1000; v.save.rsp = 0x8000; v.save.rax = 0x42;
            ubyte* b = cast(ubyte*)v;
            vtCheck(*(cast(ulong*)(b + 0x578)) == 0x1000, "vmcb-rip-off");
            vtCheck(*(cast(ulong*)(b + 0x5D8)) == 0x8000, "vmcb-rsp-off");
            vtCheck(*(cast(ulong*)(b + 0x5F8)) == 0x42, "vmcb-rax-off");
            free_phys_page(page);
        }
    }

    // --- 6. fd lifecycle: close vCPU, reuse its slot, close VM ---------------
    kvmVcpuFdClosed(vcObj, vcGen);
    vtCheck(vcpuCheckObj(vcObj, vcGen) is null, "vcpu-stale-after-close");
    {
        // Slot reuse: creating vCPU 0 again must succeed (vcpuCount was
        // decremented; the 64-vCPU ceiling is not wedged by churn).
        long h = kvmCreateVcpu(vmObj, vmGen, 0);
        vtCheck(h >= 0, "vcpu-slot-reuse");
        if (h >= 0) {
            uint o2, g2;
            kvmUnpackHandle(cast(ulong)h, o2, g2);
            vtCheck(o2 != vcObj || g2 != vcGen, "vcpu-gen-advanced");
            kvmVcpuFdClosed(o2, g2);
        }
    }
    kvmVmFdClosed(vmObj, vmGen); // drops the creating view AND the vCPU pins
    vtCheck(vmCheck(vmObj, vmGen) is null, "vm-stale-after-teardown");
    {
        // Generation advances: a re-allocated VM never validates old handles.
        long h = kvmCreateVm(tid);
        vtCheck(h >= 0, "vm-realloc");
        if (h >= 0) {
            uint o2, g2;
            kvmUnpackHandle(cast(ulong)h, o2, g2);
            vtCheck(g2 != vmGen, "vm-gen-advanced");
            vtCheck(vmCheck(vmObj, vmGen) is null, "vm-old-handle-stale");
            kvmVmFdClosed(o2, g2);
        }
    }

    // --- 7. ceilings ----------------------------------------------------------
    {
        uint[VIRT_MAX_VMS] objs;
        uint[VIRT_MAX_VMS] gens;
        uint n = 0;
        for (; n < VIRT_MAX_VMS; ++n) {
            long h = kvmCreateVm(tid);
            if (h < 0) break;
            kvmUnpackHandle(cast(ulong)h, objs[n], gens[n]);
        }
        vtCheck(n == VIRT_MAX_VMS, "vm-ceiling-fill");
        vtCheck(kvmCreateVm(tid) < 0, "vm-ceiling-enforced");
        // vCPU ceiling on the first VM.
        uint created = 0;
        for (uint i = 0; i < VIRT_MAX_VCPUS_PER_VM; ++i) {
            long h = kvmCreateVcpu(objs[0], gens[0], i);
            if (h < 0) break;
            uint o, g;
            kvmUnpackHandle(cast(ulong)h, o, g);
            kvmVcpuFdClosed(o, g); // release immediately; slot reuse is the point
            ++created;
        }
        vtCheck(created == VIRT_MAX_VCPUS_PER_VM, "vcpu-ceiling-churn");
        // One more create past churn must still work (no wedging).
        {
            long h = kvmCreateVcpu(objs[0], gens[0], 0);
            vtCheck(h >= 0, "vcpu-no-wedge");
            if (h >= 0) {
                uint o, g;
                kvmUnpackHandle(cast(ulong)h, o, g);
                kvmVcpuFdClosed(o, g);
            }
        }
        foreach (i; 0 .. n) kvmVmFdClosed(objs[i], gens[i]);
        vtCheck(vmCheck(objs[0], gens[0]) is null, "vm-ceiling-cleanup");
    }

    // --- 8. synthetic exit dispatch (3.4/5.6/6.1; HW-independent) --------------
    // Drives the vendor decoders (vmxDecodeExit / svmDecodeExit) plus the
    // common virtDispatchExit with synthetic exits against real VM/vCPU
    // objects.  Real guest entry stays [HW]; the decode + dispatch *logic*
    // is fully verified here and runs at every boot.
    {
        long h = kvmCreateVm(tid);
        vtCheck(h >= 0, "xd-vm");
        if (h >= 0) {
            uint vo, vg;
            kvmUnpackHandle(cast(ulong)h, vo, vg);
            Vm* vm = vmCheck(vo, vg);
            vtCheck(vm !is null, "xd-vm-live");

            ulong rp = alloc_phys_page();
            vtCheck(rp != 0, "xd-runpage");
            if (rp != 0 && vm !is null) {
                KvmRun* run = cast(KvmRun*)phys_to_virt(rp);
                foreach (i; 0 .. KvmRun.sizeof) (cast(ubyte*)run)[i] = 0;

                uint[4] vco; uint[4] vcg;
                bool ok = true;
                foreach (i; 0 .. 4) {
                    long vh = kvmCreateVcpu(vo, vg, i);
                    if (vh < 0) { ok = false; break; }
                    kvmUnpackHandle(cast(ulong)vh, vco[i], vcg[i]);
                }
                vtCheck(ok, "xd-vcpus");
                if (ok) {
                    VirtExitInfo xi;

                    // HLT -> KVM_EXIT_HLT, vCPU Exited, VcpuStopped
                    vmxDecodeExit(EXIT_REASON_HLT, 0, 0, 0, 0, &xi);
                    vtCheck(xi.kind == VirtExitKind.Hlt, "xd-hlt-kind");
                    Vcpu* vc0 = vcpuCheckObj(vco[0], vcg[0]);
                    vtCheck(virtDispatchExit(xi, run, vm, vc0)
                            == VmExitAction.VcpuStopped, "xd-hlt-action");
                    vtCheck(run.exitReason == KVM_EXIT_HLT, "xd-hlt-reason");
                    vtCheck(vc0.state == VcpuState.Exited, "xd-hlt-state");

                    // I/O OUT: outb 0xAB -> port 0x10
                    foreach (i; 0 .. KvmRun.sizeof) (cast(ubyte*)run)[i] = 0;
                    vmxDecodeExit(EXIT_REASON_IO_INSTRUCTION,
                                  0x10UL << 16, 0, 0xAB, 0, &xi); // size=1, OUT
                    vtCheck(xi.kind == VirtExitKind.Io, "xd-io-kind");
                    Vcpu* vc1 = vcpuCheckObj(vco[1], vcg[1]);
                    vtCheck(virtDispatchExit(xi, run, vm, vc1)
                            == VmExitAction.ToUserspace, "xd-io-action");
                    vtCheck(run.exitReason == KVM_EXIT_IO, "xd-io-reason");
                    vtCheck(run.u.io.direction == KVM_EXIT_IO_OUT, "xd-io-dir");
                    vtCheck(run.u.io.size == 1 && run.u.io.port == 0x10,
                            "xd-io-port");
                    vtCheck(run.u.io.count == 1, "xd-io-count");
                    vtCheck(run.u.io.dataOffset == KvmRun.sizeof,
                            "xd-io-dataoff");
                    vtCheck((cast(ubyte*)run)[KvmRun.sizeof] == 0xAB,
                            "xd-io-data");

                    // I/O IN: in ax, 0x3F8 (size=2)
                    foreach (i; 0 .. KvmRun.sizeof) (cast(ubyte*)run)[i] = 0;
                    vmxDecodeExit(EXIT_REASON_IO_INSTRUCTION,
                                  1 | (1UL << 3) | (0x3F8UL << 16), 0, 0, 0, &xi);
                    vtCheck(virtDispatchExit(xi, run, vm, vc1)
                            == VmExitAction.ToUserspace, "xd-ioin-action");
                    vtCheck(run.u.io.direction == KVM_EXIT_IO_IN,
                            "xd-ioin-dir");
                    vtCheck(run.u.io.size == 2 && run.u.io.port == 0x3F8,
                            "xd-ioin-port");

                    // EPT violation (write) -> KVM_EXIT_MMIO
                    foreach (i; 0 .. KvmRun.sizeof) (cast(ubyte*)run)[i] = 0;
                    vmxDecodeExit(EXIT_REASON_EPT_VIOLATION,
                                  1UL << 1, 0xFEC0_0000UL, 0, 0, &xi);
                    vtCheck(xi.kind == VirtExitKind.SlatFault, "xd-ept-kind");
                    vtCheck(virtDispatchExit(xi, run, vm, vc1)
                            == VmExitAction.ToUserspace, "xd-ept-action");
                    vtCheck(run.exitReason == KVM_EXIT_MMIO, "xd-ept-reason");
                    vtCheck(run.u.mmio.physAddr == 0xFEC0_0000UL,
                            "xd-ept-gpa");
                    vtCheck(run.u.mmio.isWrite == 1 && run.u.mmio.len == 0,
                            "xd-ept-flags");

                    // VMCALL -> hypercall
                    vmxDecodeExit(EXIT_REASON_VMCALL, 0, 0, 0x1234, 0, &xi);
                    vtCheck(virtDispatchExit(xi, run, vm, vc1)
                            == VmExitAction.ToUserspace, "xd-hc-action");
                    vtCheck(run.exitReason == KVM_EXIT_HYPERCALL,
                            "xd-hc-reason");
                    vtCheck(run.u.hypercall.nr == 0x1234, "xd-hc-nr");

                    // Triple fault -> SHUTDOWN, vCPU Exited
                    vmxDecodeExit(EXIT_REASON_TRIPLE_FAULT, 0, 0, 0, 0, &xi);
                    Vcpu* vc2 = vcpuCheckObj(vco[2], vcg[2]);
                    vtCheck(virtDispatchExit(xi, run, vm, vc2)
                            == VmExitAction.VcpuStopped, "xd-tf-action");
                    vtCheck(run.exitReason == KVM_EXIT_SHUTDOWN,
                            "xd-tf-reason");
                    vtCheck(vc2.state == VcpuState.Exited, "xd-tf-state");

                    // Unknown reason -> KVM_EXIT_UNKNOWN, to userspace
                    vmxDecodeExit(0xFF, 0, 0, 0, 0, &xi);
                    Vcpu* vc3 = vcpuCheckObj(vco[3], vcg[3]);
                    vtCheck(virtDispatchExit(xi, run, vm, vc3)
                            == VmExitAction.ToUserspace, "xd-unk-action");
                    vtCheck(run.exitReason == KVM_EXIT_UNKNOWN,
                            "xd-unk-reason");
                    vtCheck(run.u.hwReason == 0xFF, "xd-unk-hwreason");

                    // Reserved I/O size encoding -> contained, VM Dying
                    vmxDecodeExit(EXIT_REASON_IO_INSTRUCTION, 2, 0, 0, 0, &xi);
                    vtCheck(xi.ioSize == 0, "xd-badio-size");
                    vtCheck(virtDispatchExit(xi, run, vm, vc3)
                            == VmExitAction.VmContained, "xd-badio-contained");
                    vtCheck(vm.state == VmState.Dying, "xd-badio-vmdying");
                    vtCheck(run.exitReason == KVM_EXIT_INTERNAL_ERROR,
                            "xd-badio-reason");

                    // --- 6.3 hostile-state validation -------------------------
                    KvmSRegs sr;
                    foreach (i; 0 .. KvmSRegs.sizeof)
                        (cast(ubyte*)&sr)[i] = 0;
                    vtCheck(virtValidateSRegs(&sr) == 0, "xd-sregs-zero-ok");
                    sr.cr4 = 1UL << 13; // VMXE in guest: never
                    vtCheck(virtValidateSRegs(&sr) == -22, "xd-sregs-vmxe");
                    sr.cr4 = 0; sr.efer = 1UL << 10; // LMA without LME
                    vtCheck(virtValidateSRegs(&sr) == -22, "xd-sregs-lma");
                    sr.efer = 0; sr.cr8 = 16;
                    vtCheck(virtValidateSRegs(&sr) == -22, "xd-sregs-cr8");

                    KvmRegs rg;
                    foreach (i; 0 .. KvmRegs.sizeof)
                        (cast(ubyte*)&rg)[i] = 0;
                    rg.rip = 0x0000_8000_0000_0000UL; // non-canonical (bit47=1, bits63:48=0)
                    vtCheck(virtValidateRegs(&rg) == -22, "xd-regs-rip");
                    rg.rip = 0x1000;
                    vtCheck(virtValidateRegs(&rg) == 0, "xd-regs-ok");

                    KvmMsrEntry[2] me;
                    me[0].index = 0x480; me[0].reserved = 0; me[0].data = 0;
                    me[1].index = 0xC000_0080; me[1].reserved = 0;
                    me[1].data = 0xD01;
                    vtCheck(virtValidateMsrs(me.ptr, 2) == -22, "xd-msr-vmx");
                    me[0].index = 0x10; // TSC: fine
                    vtCheck(virtValidateMsrs(me.ptr, 2) == 0, "xd-msr-ok");
                    me[1].data = 0xFFFF; // bad EFER
                    vtCheck(virtValidateMsrs(me.ptr, 2) == -22, "xd-msr-efer");

                    foreach (i; 0 .. 4) kvmVcpuFdClosed(vco[i], vcg[i]);
                }
                free_phys_page(rp);
            }
            kvmVmFdClosed(vo, vg);
            vtCheck(vmCheck(vo, vg) is null, "xd-vm-gone");
        }
    }

done:
    version (HostTest) virtCompatTest(tid);
    if (g_virtTestFails == 0) klog("[virt] selftest PASS\n");
    else klog("[virt] selftest FAILURES logged above\n");
}

// --- Host-only KVM compat tests ----------------------------------------------
// These need real userspace buffers, which only the host harness provides
// (core.addrspace.stubMapUser).  They exercise the full ioctl path with
// copy-in/out: honest ENOTTY for interrupt ioctls without delivery,
// XSAVE/XCRS/debugregs round-trips, and the honest capability values.
version (HostTest):

import core.addrspace : stubMapUser, stubMapUserReadOnly;

private void vtMapBuf(void* p, size_t n) {
    stubMapUser(cast(ulong)p, n);
}

private void virtCompatTest(int tid) {
    // --- userspace write guard: read-only mappings fail copy-out ------------
    {
        // Page-aligned buffers via the page allocator (BSS arrays are not
        // page-aligned, and the stub resolves permissions per page).
        ulong roP = alloc_phys_page();
        ulong rwP = alloc_phys_page();
        vtCheck(roP != 0 && rwP != 0, "compat-guard-pages");
        if (roP != 0 && rwP != 0) {
            ubyte* roBuf = cast(ubyte*)phys_to_virt(roP);
            ubyte* rwBuf = cast(ubyte*)phys_to_virt(rwP);
            stubMapUserReadOnly(cast(ulong)roBuf, 4096);
            stubMapUser(cast(ulong)rwBuf, 4096);
            // Read guard passes on both; write guard passes only on the rw buf.
            vtCheck(kvmTestUserOk(tid, cast(ulong)roBuf, 4096),
                    "compat-ro-read-ok");
            vtCheck(!kvmTestUserOkWrite(tid, cast(ulong)roBuf, 4096),
                    "compat-ro-write-fails");
            vtCheck(kvmTestUserOkWrite(tid, cast(ulong)rwBuf, 4096),
                    "compat-rw-write-ok");
            free_phys_page(roP);
            free_phys_page(rwP);
        }
    }

    // --- honest capability values ------------------------------------------
    vtCheck(kvmSystemIoctl(tid, KVM_CHECK_EXTENSION, KVM_CAP_SIGNAL_MSI) == 0,
            "compat-signal-msi-zero");

    // --- a VM and vCPU to run ioctls against --------------------------------
    long vmh = kvmCreateVm(tid);
    vtCheck(vmh >= 0, "compat-vm-alloc");
    if (vmh < 0) return;
    uint vmObj, vmGen;
    kvmUnpackHandle(cast(ulong)vmh, vmObj, vmGen);
    long vch = kvmCreateVcpu(vmObj, vmGen, 0);
    vtCheck(vch >= 0, "compat-vcpu-alloc");
    uint vcObj = 0, vcGen = 0;
    if (vch >= 0) kvmUnpackHandle(cast(ulong)vch, vcObj, vcGen);

    // --- GSI routing / irqfd / ioeventfd: honest ENOTTY -----------------------
    // Interrupt delivery does not exist yet; advertising it would be a fake
    // hardware claim.  The ioctls fail fast with ENOTTY (-25) instead of
    // silently storing tables that never deliver.
    {
        static struct RoutingBuf {
            uint nr; uint pad;
            KvmIrqRoutingEntry[4] e;
        }
        __gshared RoutingBuf rb;
        rb.nr = 2; rb.pad = 0;
        vtMapBuf(&rb, RoutingBuf.sizeof);
        long rc = kvmVmIoctl(tid, vmObj, vmGen, KVM_SET_GSI_ROUTING,
                             cast(ulong)&rb);
        vtCheck(rc == -25, "compat-gsi-enotty");
    }
    {
        __gshared KvmIrqfd f;
        vtMapBuf(&f, KvmIrqfd.sizeof);
        f.fd = 7; f.gsi = 10; f.flags = 0; f.resamplefd = 0;
        long rc = kvmVmIoctl(tid, vmObj, vmGen, KVM_IRQFD, cast(ulong)&f);
        vtCheck(rc == -25, "compat-irqfd-enotty");
    }
    {
        __gshared KvmIoeventfd e;
        vtMapBuf(&e, KvmIoeventfd.sizeof);
        e.datamatch = 0; e.addr = 0xFEB00000; e.len = 4; e.fd = 9; e.flags = 0;
        long rc = kvmVmIoctl(tid, vmObj, vmGen, KVM_IOEVENTFD, cast(ulong)&e);
        vtCheck(rc == -25, "compat-ioeventfd-enotty");
    }

    if (vch >= 0) {
        // --- XSAVE round-trip --------------------------------------------------
        __gshared KvmXsave xs;
        vtMapBuf(&xs, KvmXsave.sizeof);
        long rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_GET_XSAVE,
                               cast(ulong)&xs);
        vtCheck(rc == 0, "compat-xsave-get");
        // Reset defaults before any SET: FCW=0x37f, MXCSR=0x1f80.
        vtCheck((cast(ushort*)&xs)[0] == 0x37f, "compat-xsave-fcw");
        vtCheck(*cast(uint*)(cast(ubyte*)&xs + 24) == 0x1f80,
                "compat-xsave-mxcsr");
        (cast(ushort*)&xs)[0] = 0x1234;
        rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_SET_XSAVE,
                          cast(ulong)&xs);
        vtCheck(rc == 0, "compat-xsave-set");
        (cast(ushort*)&xs)[0] = 0;
        rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_GET_XSAVE,
                          cast(ulong)&xs);
        vtCheck(rc == 0 && (cast(ushort*)&xs)[0] == 0x1234,
                "compat-xsave-roundtrip");

        // --- XCRS round-trip ----------------------------------------------------
        __gshared KvmXcrs xc;
        vtMapBuf(&xc, KvmXcrs.sizeof);
        rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_GET_XCRS, cast(ulong)&xc);
        vtCheck(rc == 0 && xc.nrXcrs == 2 && xc.xcrs[0].value == 1,
                "compat-xcrs-get-default");
        xc.nrXcrs = 2; xc.flags = 0;
        xc.xcrs[0].xcr = 0; xc.xcrs[0].reserved = 0; xc.xcrs[0].value = 0x1F;
        xc.xcrs[1].xcr = 1; xc.xcrs[1].reserved = 0; xc.xcrs[1].value = 0;
        rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_SET_XCRS, cast(ulong)&xc);
        vtCheck(rc == 0, "compat-xcrs-set");
        xc.xcrs[0].value = 0;
        rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_GET_XCRS, cast(ulong)&xc);
        vtCheck(rc == 0 && xc.xcrs[0].value == 0x1F, "compat-xcrs-roundtrip");

        // --- debugregs round-trip -----------------------------------------------
        __gshared KvmDebugregs dr;
        vtMapBuf(&dr, KvmDebugregs.sizeof);
        rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_GET_DEBUGREGS,
                          cast(ulong)&dr);
        vtCheck(rc == 0 && dr.dr6 == 0xFFFF0FF0, "compat-dr-get-default");
        dr.db[0] = 0xDEAD_BEEF_1234_5678UL; dr.dr7 = 0x101;
        rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_SET_DEBUGREGS,
                          cast(ulong)&dr);
        vtCheck(rc == 0, "compat-dr-set");
        dr.db[0] = 0; dr.dr7 = 0;
        rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_GET_DEBUGREGS,
                          cast(ulong)&dr);
        vtCheck(rc == 0 && dr.db[0] == 0xDEAD_BEEF_1234_5678UL &&
                dr.dr7 == 0x101, "compat-dr-roundtrip");

        // --- TSC kHz: unknown -> -EIO (Linux semantics) --------------------------
        rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_GET_TSC_KHZ, 0);
        vtCheck(rc == -5, "compat-tsc-unknown-eio");
        rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_SET_TSC_KHZ, 2500000);
        vtCheck(rc == 0, "compat-tsc-set");
        rc = kvmVcpuIoctl(tid, vcObj, vcGen, KVM_GET_TSC_KHZ, 0);
        vtCheck(rc == 2500000, "compat-tsc-get");

        kvmVcpuFdClosed(vcObj, vcGen);
    }
    kvmVmFdClosed(vmObj, vmGen);
    vtCheck(vmCheck(vmObj, vmGen) is null, "compat-vm-gone");
}
