// HOST TEST 2: deterministic fuzzer for the virt/KVM layer.
//
// xorshift64 with a fixed seed — every run explores the same space:
//   * random KVM_CHECK_EXTENSION caps (0..1024): rc >= 0, never crashes
//   * random unknown ioctls on system/VM/vCPU fds: -EINVAL, never crashes
//     (plus the known interrupt ioctls: honest -ENOTTY)
//   * memslot chaos: slot/flags/gpa/size/userAddr — rc in the valid errno
//     set, VM never corrupted
//   * EPT/NPT/SLAT map/unmap/lookup chaos against scratch tables: validity
//     matches the documented contract, round-trips are exact
//   * vCPU id chaos: valid ids succeed, the rest fail with a valid errno
//   * synthetic exit fuzz: random VMX reasons/SVM codes through the vendor
//     decoders into virtDispatchExit — action is always a valid
//     VmExitAction, unknown exits leave the VM Active
//
// Constraints: -betterC, @nogc nothrow.  Prints "[virt] fuzz PASS".
module run_fuzz;

import core.virt.kvm : kvmSystemIoctl, kvmVmIoctl, kvmVcpuIoctl,
    kvmCreateVm, kvmCreateVcpu;
import core.virt.vm : Vm, Vcpu, VmState, VcpuState,
    vmCheck, vcpuCheckObj, kvmUnpackHandle, kvmVmFdClosed, kvmVcpuFdClosed;
import core.virt.vmexit : virtDispatchExit, VirtExitInfo, VirtExitKind,
    VmExitAction;
import core.virt.vmx : vmxDecodeExit;
import core.virt.svm : svmDecodeExit;
import core.virt.ept : Ept, eptInit, eptWireKernel,
    eptMap, eptUnmap, eptLookup, eptFree;
import core.virt.npt : Npt, nptInit, nptWireKernel,
    nptMap, nptUnmap, nptLookup, nptFree, nptLookupRaw,
    NPT_PTE_P, NPT_PTE_RW, NPT_PTE_US, NPT_PTE_NX;
import core.virt.slat : Slat, SlatKind, slatInit, slatWireKernel,
    slatMap, slatUnmap, slatLookup, slatFree, slatRootPhys,
    SLAT_R, SLAT_W, SLAT_X;
import core.virt.kvmabi : KvmRun, KvmUserspaceMemoryRegion,
    KVM_CHECK_EXTENSION, KVM_CREATE_IRQCHIP, KVM_SET_GSI_ROUTING,
    KVM_IRQFD, KVM_IOEVENTFD, KVM_SET_USER_MEMORY_REGION, KVM_MEM_READONLY,
    KVM_EXIT_UNKNOWN, KVM_EXIT_HLT, KVM_EXIT_SHUTDOWN;
import core.addrspace : stubMapUser, stubMapUserReadOnly;
import core.exports : phys_to_virt;
import memory.mm : alloc_phys_page, free_phys_page;
import core.stdc.stdlib : aligned_alloc, free;
import core.stdc.stdio : printf;

extern (C) @nogc nothrow:

// --- deterministic RNG -------------------------------------------------------
__gshared ulong fz_state = 0x9E3779B97F4A7C15UL;

private ulong fzNext() {
    ulong x = fz_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    fz_state = x;
    return x;
}

private ulong fzPick(const ulong* table, size_t n) {
    return table[fzNext() % n];
}

// --- failure accounting --------------------------------------------------------
__gshared uint fz_fails = 0;

private void fzCheck(bool ok, const(char)* name) {
    if (!ok) {
        ++fz_fails;
        printf("[fuzz] FAIL: %s\n", name);
    }
}

// --- scratch EPT allocators (malloc-backed, zeroed) ------------------------------
private ulong fzAlloc() {
    void* p = aligned_alloc(4096, 4096);
    if (p is null) return 0;
    auto b = cast(ubyte*)p;
    foreach (i; 0 .. 4096) b[i] = 0;
    return cast(ulong)p;
}
private void fzFree(ulong phys) {
    if (phys != 0) free(cast(void*)phys);
}
private void* fzMap(ulong phys) {
    return cast(void*)phys;
}

// --- helpers ----------------------------------------------------------------------
private void fzMapBuf(void* p, size_t n) {
    stubMapUser(cast(ulong)p, n);
}

private void fzZeroRun(KvmRun* run) {
    auto b = cast(ubyte*)run;
    foreach (i; 0 .. KvmRun.sizeof) b[i] = 0;
}

// Create a VM + one vCPU; returns false on failure (already reported).
private bool fzMkVm(int tid, uint* vo, uint* vg, uint* co, uint* cg) {
    long h = kvmCreateVm(tid);
    if (h < 0) { fzCheck(false, "mkvm-vm"); return false; }
    kvmUnpackHandle(cast(ulong)h, *vo, *vg);
    long vh = kvmCreateVcpu(*vo, *vg, 0);
    if (vh < 0) {
        kvmVmFdClosed(*vo, *vg);
        fzCheck(false, "mkvm-vcpu");
        return false;
    }
    kvmUnpackHandle(cast(ulong)vh, *co, *cg);
    return true;
}

// --- section A: extension caps -------------------------------------------------------
private void fzCaps() {
    foreach (i; 0 .. 2000) {
        ulong cap = fzNext() % 1025;
        long rc = kvmSystemIoctl(0, KVM_CHECK_EXTENSION, cap);
        fzCheck(rc >= 0, "cap-nonneg");
    }
}

// --- section B: unknown ioctls ----------------------------------------------------------
private void fzUnknownIoctls() {
    uint vo, vg, co, cg;
    if (!fzMkVm(0, &vo, &vg, &co, &cg)) return;
    foreach (i; 0 .. 200) {
        // 0xDEADxxxx can never collide with a real KVM ioctl (0xAExx).
        ulong cmd = 0xDEAD_0000UL | (fzNext() & 0xFFFF);
        ulong arg = fzNext();
        fzCheck(kvmSystemIoctl(0, cmd, arg) == -22, "sys-unknown-einval");
        fzCheck(kvmVmIoctl(0, vo, vg, cmd, arg) == -22, "vm-unknown-einval");
        fzCheck(kvmVcpuIoctl(0, co, cg, cmd, arg) == -22, "vcpu-unknown-einval");
    }
    // Known interrupt ioctls: honest ENOTTY (no delivery backend), no crash.
    fzCheck(kvmVmIoctl(0, vo, vg, KVM_CREATE_IRQCHIP, 0) == -25, "irqchip-enotty");
    fzCheck(kvmVmIoctl(0, vo, vg, KVM_SET_GSI_ROUTING, 0) == -25, "gsi-enotty");
    fzCheck(kvmVmIoctl(0, vo, vg, KVM_IRQFD, 0) == -25, "irqfd-enotty");
    fzCheck(kvmVmIoctl(0, vo, vg, KVM_IOEVENTFD, 0) == -25, "ioeventfd-enotty");
    kvmVcpuFdClosed(co, cg);
    kvmVmFdClosed(vo, vg);
}

// --- section C: memslot chaos ----------------------------------------------------------------
__gshared ubyte[1 << 20] fz_rwScratch;
__gshared ubyte[1 << 20] fz_roScratch;
__gshared KvmUserspaceMemoryRegion fz_reg;

private void fzMemslots() {
    fzMapBuf(fz_rwScratch.ptr, fz_rwScratch.length);
    stubMapUserReadOnly(cast(ulong)fz_roScratch.ptr, fz_roScratch.length);
    fzMapBuf(&fz_reg, KvmUserspaceMemoryRegion.sizeof);

    uint vo, vg, co, cg;
    if (!fzMkVm(0, &vo, &vg, &co, &cg)) return;

    static immutable ulong[5] slotTab  = [0, 3, 31, 32, 39];
    static immutable ulong[5]  flagTab  = [0, KVM_MEM_READONLY, 2, 3, 0xFF];
    static immutable ulong[4] gpaTab   = [0x10_0000, 0x10_0001, 0, 0xFFFF_FFFF_FFFF_F000UL];
    static immutable ulong[8] sizeTab  = [0, 0x1000, 0x5000, 0x1001,
                                          0x100000, 0x4000000, 0x100000000UL,
                                          0xFFFF_FFFF_FFFF_F000UL];
    foreach (i; 0 .. 300) {
        ulong rwBase = cast(ulong)fz_rwScratch.ptr;
        ulong roBase = cast(ulong)fz_roScratch.ptr;
        ulong off = (fzNext() % 256) << 12;
        static immutable ulong[4] uaKind = [0, 1, 2, 3];
        ulong ua;
        switch (fzPick(uaKind.ptr, uaKind.length)) {
            case 0:  ua = rwBase + off; break;   // mapped writable
            case 1:  ua = roBase + off; break;   // mapped read-only
            case 2:  ua = 0x6000_0000UL; break;  // unmapped (demand-zero)
            default: ua = 0; break;              // null: must fail
        }
        fz_reg.slot = cast(uint)fzPick(slotTab.ptr, slotTab.length);
        fz_reg.flags = cast(uint)fzPick(flagTab.ptr, flagTab.length);
        fz_reg.guestPhysAddr = fzPick(gpaTab.ptr, gpaTab.length);
        if ((fzNext() & 7) == 0)
            fz_reg.guestPhysAddr = fzNext() & ~0xFFFUL; // random aligned GPA
        fz_reg.memorySize = fzPick(sizeTab.ptr, sizeTab.length);
        fz_reg.userspaceAddr = ua;

        long rc = kvmVmIoctl(0, vo, vg, KVM_SET_USER_MEMORY_REGION,
                             cast(ulong)&fz_reg);
        bool errnoOk = rc == 0 || rc == -22 || rc == -12 || rc == -14 ||
                       rc == -9 || rc == -16;
        fzCheck(errnoOk, "memslot-errno-range");
        fzCheck(vmCheck(vo, vg) !is null, "memslot-vm-live");

        // Occasionally remove the slot again (size 0).
        if ((i % 7) == 3) {
            fz_reg.memorySize = 0;
            long r2 = kvmVmIoctl(0, vo, vg, KVM_SET_USER_MEMORY_REGION,
                                 cast(ulong)&fz_reg);
            fzCheck(r2 == 0 || r2 == -22, "memslot-remove");
        }
    }
    kvmVcpuFdClosed(co, cg);
    kvmVmFdClosed(vo, vg);
    fzCheck(vmCheck(vo, vg) is null, "memslot-vm-gone");
}

// --- section D: EPT chaos --------------------------------------------------------------------
private void fzEpt() {
    Ept e;
    eptInit(&e);
    eptWireKernel(&e, &fzAlloc, &fzFree, &fzMap);

    static immutable ulong[4] addrTab = [0, 0x5000, 0x5001, 1UL << 48];
    foreach (i; 0 .. 500) {
        ulong gpa = fzPick(addrTab.ptr, addrTab.length);
        ulong hpa = fzPick(addrTab.ptr, addrTab.length);
        if ((fzNext() & 3) == 0) gpa = (fzNext() & 0xFFFF_FFFFUL) & ~0xFFFUL;
        if ((fzNext() & 3) == 0) hpa = (fzNext() & 0xFFFF_FFFFUL) & ~0xFFFUL;
        uint prot = cast(uint)(fzNext() & 15);

        eptUnmap(&e, gpa & ~0xFFFUL); // start clean (misaligned unmap is a no-op)
        bool valid = ((gpa & 0xFFF) == 0) && ((hpa & 0xFFF) == 0) &&
                     ((prot & ~7u) == 0) && ((prot & 7u) != 0) &&
                     ((gpa >> 48) == 0) && ((hpa >> 48) == 0);
        bool got = eptMap(&e, gpa, hpa, prot);
        fzCheck(got == valid, "ept-map-validity");
        if (got) {
            fzCheck(eptLookup(&e, gpa) == (hpa & ~0xFFFUL), "ept-lookup");
            fzCheck(!eptMap(&e, gpa, hpa, prot), "ept-double-map");
            ulong uh = eptUnmap(&e, gpa);
            fzCheck(uh == (hpa & ~0xFFFUL), "ept-unmap");
            fzCheck(eptLookup(&e, gpa) == 0, "ept-gone");
        }
    }
    eptFree(&e);
    fzCheck(e.tables == 0 && e.pml4Phys == 0, "ept-free-clean");
}

// --- section D2: NPT chaos (mirrors the EPT chaos; AMD encodings) ---------
private void fzNpt() {
    Npt n;
    nptInit(&n);
    nptWireKernel(&n, &fzAlloc, &fzFree, &fzMap);

    static immutable ulong[4] addrTab = [0, 0x5000, 0x5001, 1UL << 48];
    foreach (i; 0 .. 500) {
        ulong gpa = fzPick(addrTab.ptr, addrTab.length);
        ulong hpa = fzPick(addrTab.ptr, addrTab.length);
        if ((fzNext() & 3) == 0) gpa = (fzNext() & 0xFFFF_FFFFUL) & ~0xFFFUL;
        if ((fzNext() & 3) == 0) hpa = (fzNext() & 0xFFFF_FFFFUL) & ~0xFFFUL;
        uint prot = cast(uint)(fzNext() & 15);

        nptUnmap(&n, gpa & ~0xFFFUL); // start clean (misaligned unmap is a no-op)
        bool valid = ((gpa & 0xFFF) == 0) && ((hpa & 0xFFF) == 0) &&
                     ((prot & ~7u) == 0) && ((prot & 7u) != 0) &&
                     ((gpa >> 48) == 0) && ((hpa >> 48) == 0);
        bool got = nptMap(&n, gpa, hpa, prot);
        fzCheck(got == valid, "npt-map-validity");
        if (got) {
            fzCheck(nptLookup(&n, gpa) == (hpa & ~0xFFFUL), "npt-lookup");
            // Exact NPT encodings: P|US always; RW iff writable; NX iff !exec.
            ulong raw = nptLookupRaw(&n, gpa);
            fzCheck((raw & NPT_PTE_P) != 0 && (raw & NPT_PTE_US) != 0,
                    "npt-enc-p-us");
            fzCheck(((raw & NPT_PTE_RW) != 0) == ((prot & SLAT_W) != 0),
                    "npt-enc-rw");
            fzCheck(((raw & NPT_PTE_NX) != 0) == ((prot & SLAT_X) == 0),
                    "npt-enc-nx");
            fzCheck(!nptMap(&n, gpa, hpa, prot), "npt-double-map");
            ulong uh = nptUnmap(&n, gpa);
            fzCheck(uh == (hpa & ~0xFFFUL), "npt-unmap");
            fzCheck(nptLookup(&n, gpa) == 0, "npt-gone");
        }
    }
    nptFree(&n);
    fzCheck(n.tables == 0 && n.pml4Phys == 0, "npt-free-clean");
}

// --- section D3: SLAT chaos (vendor-neutral layer over EPT and NPT) --------
private void fzSlat() {
    foreach (k; 0 .. 2) {
        Slat sl;
        slatInit(&sl, k == 0 ? SlatKind.Ept : SlatKind.Npt);
        slatWireKernel(&sl, &fzAlloc, &fzFree, &fzMap);
        fzCheck(slatRootPhys(&sl) == 0, "slat-root-empty");

        static immutable ulong[4] addrTab = [0, 0x5000, 0x5001, 1UL << 48];
        foreach (i; 0 .. 250) {
            ulong gpa = fzPick(addrTab.ptr, addrTab.length);
            ulong hpa = fzPick(addrTab.ptr, addrTab.length);
            if ((fzNext() & 3) == 0) gpa = (fzNext() & 0xFFFF_FFFFUL) & ~0xFFFUL;
            if ((fzNext() & 3) == 0) hpa = (fzNext() & 0xFFFF_FFFFUL) & ~0xFFFUL;
            uint prot = cast(uint)(fzNext() & 15);

            slatUnmap(&sl, gpa & ~0xFFFUL);
            bool valid = ((gpa & 0xFFF) == 0) && ((hpa & 0xFFF) == 0) &&
                         ((prot & ~7u) == 0) && ((prot & 7u) != 0) &&
                         ((gpa >> 48) == 0) && ((hpa >> 48) == 0);
            bool got = slatMap(&sl, gpa, hpa, prot);
            fzCheck(got == valid, "slat-map-validity");
            if (got) {
                fzCheck(slatLookup(&sl, gpa) == (hpa & ~0xFFFUL),
                        "slat-lookup");
                fzCheck(slatRootPhys(&sl) != 0, "slat-root-live");
                ulong uh = slatUnmap(&sl, gpa);
                fzCheck(uh == (hpa & ~0xFFFUL), "slat-unmap");
            }
        }
        // SlatKind.None fail-closes every operation.
        Slat none;
        slatInit(&none, SlatKind.None);
        fzCheck(!slatMap(&none, 0x5000, 0x6000, SLAT_R), "slat-none-map");
        fzCheck(slatLookup(&none, 0x5000) == 0, "slat-none-lookup");
        fzCheck(slatUnmap(&none, 0x5000) == 0, "slat-none-unmap");
        fzCheck(slatRootPhys(&none) == 0, "slat-none-root");

        slatFree(&sl);
        fzCheck(slatRootPhys(&sl) == 0, "slat-free-clean");
    }
}

// --- section E: vCPU id chaos --------------------------------------------------------------------
private void fzVcpuIds() {
    uint vo, vg, co, cg;
    long h = kvmCreateVm(0);
    if (h < 0) { fzCheck(false, "vcpu-vm"); return; }
    kvmUnpackHandle(cast(ulong)h, vo, vg);
    static immutable ulong[5] idTab = [0, 1, 63, 64, 0xFFFF_FFFFUL];
    foreach (i; 0 .. 200) {
        uint id = cast(uint)fzPick(idTab.ptr, idTab.length);
        if ((fzNext() & 3) == 0) id = cast(uint)(fzNext() % 80);
        long rc = kvmCreateVcpu(vo, vg, id);
        if (rc >= 0) {
            kvmUnpackHandle(cast(ulong)rc, co, cg);
            kvmVcpuFdClosed(co, cg);
        } else {
            // -ENOSPC(-28): id taken / out of range / ceiling; -EBADF(-9): stale VM.
            fzCheck(rc == -28 || rc == -9, "vcpuid-errno");
        }
        fzCheck(vmCheck(vo, vg) !is null, "vcpuid-vm-live");
    }
    kvmVmFdClosed(vo, vg);
}

// --- section F: decode + dispatch fuzz ------------------------------------------------------------
// Random VMX reasons / SVM exit codes through the vendor decoders into the
// common dispatcher.  Invariants are checked on the decoded VirtExitKind,
// never on vendor numbers: unknown exits reach userspace cleanly, HLT/
// shutdown stop the vCPU, containment always marks the VM Dying.
private void fzDispatch() {
    static immutable ulong[4] vmxReasonTab = [0, 12, 0xFF, 0xFFFF_FFFFUL];
    static immutable ulong[5] svmCodeTab = [0x72, 0x78, 0x7B, 0x81, 0x400];

    foreach (iter; 0 .. 1500) {
        uint vo, vg, co, cg;
        if (!fzMkVm(0, &vo, &vg, &co, &cg)) return;
        Vm* vm = vmCheck(vo, vg);
        Vcpu* vc = vcpuCheckObj(co, cg);
        fzCheck(vm !is null && vc !is null, "dispatch-live");
        if (vm is null || vc is null) return;

        ulong rp = alloc_phys_page();
        fzCheck(rp != 0, "dispatch-runpage");
        KvmRun* run = cast(KvmRun*)phys_to_virt(rp);
        fzZeroRun(run);

        VirtExitInfo xi;
        ulong qual = fzNext();
        ulong gpa = fzNext();
        ulong data = fzNext();
        uint count = cast(uint)(fzNext() & 0xFF);
        if ((iter & 1) == 0) {
            // Intel: random basic exit reason through the VMX decoder.
            uint reason = cast(uint)fzPick(vmxReasonTab.ptr, vmxReasonTab.length);
            if ((fzNext() & 3) == 0) reason = cast(uint)(fzNext() % 64);
            vmxDecodeExit(reason, qual, gpa, data, count, &xi);
        } else {
            // AMD: random exit code through the SVM decoder.
            ulong code = fzPick(svmCodeTab.ptr, svmCodeTab.length);
            if ((fzNext() & 3) == 0) code = fzNext() % 0x410;
            svmDecodeExit(code, qual, gpa, data, &xi);
        }

        // Null-run probe once: contained, never a crash.  The probe marks
        // the VM Dying / vCPU Dead by design, so this iteration ends here.
        if (iter == 0) {
            fzCheck(virtDispatchExit(xi, null, vm, vc) == VmExitAction.VmContained,
                    "dispatch-null-run");
            free_phys_page(rp);
            kvmVcpuFdClosed(co, cg);
            kvmVmFdClosed(vo, vg);
            continue;
        }

        VmExitAction act = virtDispatchExit(xi, run, vm, vc);
        fzCheck(act <= VmExitAction.VmContained, "dispatch-action-range");

        if (xi.kind == VirtExitKind.Unknown) {
            // Unknown exits must reach userspace cleanly: the VM is
            // never corrupted by something the dispatcher doesn't know.
            fzCheck(act == VmExitAction.ToUserspace, "dispatch-unk-action");
            fzCheck(run.exitReason == KVM_EXIT_UNKNOWN, "dispatch-unk-reason");
            fzCheck(run.u.hwReason == xi.hardwareReason, "dispatch-unk-hwreason");
            fzCheck(vm.state == VmState.Active, "dispatch-unk-vm-active");
            fzCheck(vc.state != VcpuState.Dead, "dispatch-unk-vc-alive");
        }
        if (xi.kind == VirtExitKind.Hlt)
            fzCheck(act == VmExitAction.VcpuStopped &&
                    run.exitReason == KVM_EXIT_HLT, "dispatch-hlt");
        if (xi.kind == VirtExitKind.Shutdown)
            fzCheck(act == VmExitAction.VcpuStopped &&
                    run.exitReason == KVM_EXIT_SHUTDOWN, "dispatch-tf");
        if (act != VmExitAction.VmContained)
            fzCheck(vm.state == VmState.Active, "dispatch-vm-active");
        else
            fzCheck(vm.state == VmState.Dying, "dispatch-contained-dying");

        free_phys_page(rp);
        kvmVcpuFdClosed(co, cg);
        kvmVmFdClosed(vo, vg);
    }
}

extern (C) int main() {
    fzCaps();
    fzUnknownIoctls();
    fzMemslots();
    fzEpt();
    fzNpt();
    fzSlat();
    fzVcpuIds();
    fzDispatch();

    if (fz_fails == 0) printf("[virt] fuzz PASS\n");
    else printf("[virt] fuzz FAILURES: %u\n", fz_fails);
    return fz_fails == 0 ? 0 : 1;
}
