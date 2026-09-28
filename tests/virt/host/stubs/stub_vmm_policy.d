// HOST STUB for core.virt.vmm_policy — used only by tests/virt/host.
//
// The real vmm_policy.d is NOT compiled here: it imports core.domain,
// core.identity and core.namespace (the kernel's domain/subsystem model),
// which have no host meaning.  This stub keeps the exact ABI surface
// core.virt.kvm imports and matches the real policy's behavior for the
// only case the harness can produce: domainObjId == 0 (no domain), for
// which the real vmmMayCreateVm returns true unconditionally.
//
// Per-domain VM ceilings are therefore NOT under test in this harness;
// that policy is exercised on hardware where domains exist.
module core.virt.vmm_policy;

extern (C) @nogc nothrow:

enum uint VMM_DENY_VM_CEILING     = 1; // matches real vmm_policy.d
enum uint VMM_DENY_POOL_EXHAUSTED = 2; // matches real vmm_policy.d

public bool vmmMayCreateVm(uint domObjId) {
    // Real behavior for domObjId == 0: always true.
    // The stub task table never sets domainObjId, so this is exact here.
    cast(void)domObjId;
    return true;
}

public void vmmAuditCreate(uint vmObjId, uint domObjId) {
    cast(void)vmObjId; cast(void)domObjId;
}

public void vmmAuditDeny(uint domObjId, uint reason) {
    cast(void)domObjId; cast(void)reason;
}
