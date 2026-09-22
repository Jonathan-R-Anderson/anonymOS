// HOST STUB for core.audit — used only by tests/virt/host.
//
// core.virt.vm logs VM teardown directly to the audit ring (it cannot
// import core.virt.vmm_policy — import cycle).  The harness keeps no audit
// ring; the call is accepted and dropped so selftest output stays clean.
module core.audit;

extern (C) @nogc nothrow:

enum AuditKind : uint {
    VirtVmTeardown = 0, // stub: only the kind vm.d references is modeled
}

public void auditLog(AuditKind kind, uint objId, ulong detail) {
    cast(void)kind; cast(void)objId; cast(void)detail;
}
