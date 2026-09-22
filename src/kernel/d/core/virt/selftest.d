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
import core.virt.ept;
import core.virt.vmx : vmxIsReady;
import core.virt.svm : svmAvailable;
import core.exports : phys_to_virt;
import core.io : klog;
import memory.mm : alloc_phys_page, free_phys_page;

extern (C) @nogc nothrow:

private uint g_virtTestFails = 0;
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
    // -ENODEV (vCPU stays Runnable).  Once vmxIsReady()/svmAvailable() is true
    // the backend owns this path and the expectation no longer applies.
    if (!vmxIsReady() && !svmAvailable()) {
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

    // --- 5. EPT --------------------------------------------------------------
    {
        Vm* vm = vmCheck(vmObj, vmGen);
        vtCheck(vm !is null, "ept-vm-live");
        if (vm !is null) {
            // Validation failures allocate nothing.
            vtCheck(!eptMap(&vm.ept, 0x1001, 0x2000, 7), "ept-misaligned-gpa");
            vtCheck(!eptMap(&vm.ept, 0x1000, 0x2001, 7), "ept-misaligned-hpa");
            vtCheck(!eptMap(&vm.ept, 0x1000, 0x2000, 0), "ept-zero-prot");
            vtCheck(!eptMap(&vm.ept, 0x1000, 0x2000, 8), "ept-bad-prot");
            // Real map/lookup/unmap round-trip on a scratch page.
            ulong sp = alloc_phys_page();
            vtCheck(sp != 0, "ept-scratch-page");
            if (sp != 0) {
                vtCheck(eptMap(&vm.ept, 0x5000, sp, 7), "ept-map");
                vtCheck(!eptMap(&vm.ept, 0x5000, sp, 7), "ept-double-map");
                vtCheck(eptLookup(&vm.ept, 0x5000) == (sp & ~0xFFFUL),
                        "ept-lookup");
                vtCheck(eptUnmap(&vm.ept, 0x5000) == (sp & ~0xFFFUL),
                        "ept-unmap");
                vtCheck(eptLookup(&vm.ept, 0x5000) == 0, "ept-gone");
                free_phys_page(sp);
            }
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
