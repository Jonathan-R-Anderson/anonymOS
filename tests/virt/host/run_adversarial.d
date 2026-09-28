// HOST TEST 4: adversarial vCPU-state tests (task 6.3).
//
// Drives hostile SET_SREGS / SET_REGS / SET_MSRS through the REAL
// kvmVcpuIoctl with stub userspace buffers.  Every hostile value must be
// rejected with -EINVAL (-22); valid values are accepted.
//
// NOTE on SET_MSRS: Linux returns the number of MSRs applied on success,
// and so does this implementation — the valid case asserts rc == n (2),
// not 0.  SET_REGS/SET_SREGS return 0 on success.
//
// Constraints: -betterC, @nogc nothrow.  Prints "[virt] adversarial PASS".
module run_adversarial;

import core.virt.vm : Vm, Vcpu, kvmUnpackHandle, kvmVmFdClosed, kvmVcpuFdClosed,
    vmCheck, vcpuCheckObj;
import core.virt.kvm : kvmCreateVm, kvmCreateVcpu, kvmVcpuIoctl;
import core.virt.kvmabi : KvmRegs, KvmSRegs, KvmMsrEntry,
    KVM_SET_REGS, KVM_SET_SREGS, KVM_SET_MSRS;
import core.addrspace : stubMapUser;
import core.stdc.stdio : printf;

extern (C) @nogc nothrow:

__gshared uint a_fails = 0;

private void aCheck(bool ok, const(char)* name) {
    if (!ok) {
        ++a_fails;
        printf("[adversarial] FAIL: %s\n", name);
    }
}

private void aMap(void* p, size_t n) {
    stubMapUser(cast(ulong)p, n);
}

extern (C) int main() {
    int tid = 0;

    long h = kvmCreateVm(tid);
    aCheck(h >= 0, "vm-alloc");
    if (h < 0) { printf("[virt] adversarial FAILURES\n"); return 1; }
    uint vo, vg;
    kvmUnpackHandle(cast(ulong)h, vo, vg);

    long vh = kvmCreateVcpu(vo, vg, 0);
    aCheck(vh >= 0, "vcpu-alloc");
    if (vh < 0) { printf("[virt] adversarial FAILURES\n"); return 1; }
    uint co, cg;
    kvmUnpackHandle(cast(ulong)vh, co, cg);

    // --- hostile SET_SREGS ---------------------------------------------------
    {
        __gshared KvmSRegs sr;
        aMap(&sr, KvmSRegs.sizeof);

        // Baseline: zeroed sregs are valid guest state.
        foreach (i; 0 .. KvmSRegs.sizeof) (cast(ubyte*)&sr)[i] = 0;
        aCheck(kvmVcpuIoctl(tid, co, cg, KVM_SET_SREGS, cast(ulong)&sr) == 0,
               "sregs-zero-ok");

        // CR4.VMXE (bit 13): the guest must never see VMX.
        foreach (i; 0 .. KvmSRegs.sizeof) (cast(ubyte*)&sr)[i] = 0;
        sr.cr4 = 1UL << 13;
        aCheck(kvmVcpuIoctl(tid, co, cg, KVM_SET_SREGS, cast(ulong)&sr) == -22,
               "sregs-cr4-vmxe-einval");

        // EFER.LMA without EFER.LME: non-canonical long-mode transition.
        foreach (i; 0 .. KvmSRegs.sizeof) (cast(ubyte*)&sr)[i] = 0;
        sr.efer = 1UL << 10;
        aCheck(kvmVcpuIoctl(tid, co, cg, KVM_SET_SREGS, cast(ulong)&sr) == -22,
               "sregs-efer-lma-without-lme-einval");

        // CR8/TPR is 4 bits: 16 is out of range.
        foreach (i; 0 .. KvmSRegs.sizeof) (cast(ubyte*)&sr)[i] = 0;
        sr.cr8 = 16;
        aCheck(kvmVcpuIoctl(tid, co, cg, KVM_SET_SREGS, cast(ulong)&sr) == -22,
               "sregs-cr8-16-einval");
    }

    // --- hostile SET_REGS ----------------------------------------------------
    {
        __gshared KvmRegs rg;
        aMap(&rg, KvmRegs.sizeof);

        // Non-canonical RIP.
        foreach (i; 0 .. KvmRegs.sizeof) (cast(ubyte*)&rg)[i] = 0;
        rg.rip = 0x0000_8000_0000_0000UL; // truly non-canonical (bit47=1, bits63:48=0)
        aCheck(kvmVcpuIoctl(tid, co, cg, KVM_SET_REGS, cast(ulong)&rg) == -22,
               "regs-rip-noncanonical-einval");

        // Valid: canonical low-half RIP.
        foreach (i; 0 .. KvmRegs.sizeof) (cast(ubyte*)&rg)[i] = 0;
        rg.rip = 0x1000;
        aCheck(kvmVcpuIoctl(tid, co, cg, KVM_SET_REGS, cast(ulong)&rg) == 0,
               "regs-ok");
    }

    // --- hostile SET_MSRS ----------------------------------------------------
    {
        // Buffer layout the ioctl expects: { uint n; uint pad; entries[] }.
        struct MsrBuf {
            uint n;
            uint pad;
            KvmMsrEntry[4] e;
        }
        __gshared MsrBuf mb;
        aMap(&mb, MsrBuf.sizeof);

        // VMX MSR 0x480: never valid guest state.
        mb.n = 1; mb.pad = 0;
        mb.e[0].index = 0x480; mb.e[0].reserved = 0; mb.e[0].data = 0;
        aCheck(kvmVcpuIoctl(tid, co, cg, KVM_SET_MSRS, cast(ulong)&mb) == -22,
               "msr-vmx-0x480-einval");

        // IA32_FEATURE_CONTROL: never valid guest state.
        mb.e[0].index = 0x3A;
        aCheck(kvmVcpuIoctl(tid, co, cg, KVM_SET_MSRS, cast(ulong)&mb) == -22,
               "msr-feature-control-einval");

        // Bad EFER (reserved bits set).
        mb.e[0].index = 0xC000_0080; mb.e[0].data = 0xFFFF;
        aCheck(kvmVcpuIoctl(tid, co, cg, KVM_SET_MSRS, cast(ulong)&mb) == -22,
               "msr-bad-efer-einval");

        // Valid: TSC + EFER(SCE|LME) — Linux returns the count applied.
        mb.n = 2;
        mb.e[0].index = 0x10; mb.e[0].reserved = 0; mb.e[0].data = 0;
        mb.e[1].index = 0xC000_0080; mb.e[1].reserved = 0; mb.e[1].data = 0xD01;
        aCheck(kvmVcpuIoctl(tid, co, cg, KVM_SET_MSRS, cast(ulong)&mb) == 2,
               "msr-valid-count");
    }

    kvmVcpuFdClosed(co, cg);
    kvmVmFdClosed(vo, vg);
    aCheck(vmCheck(vo, vg) is null, "vm-gone");

    if (a_fails == 0) printf("[virt] adversarial PASS\n");
    else printf("[virt] adversarial FAILURES: %u\n", a_fails);
    return a_fails == 0 ? 0 : 1;
}
