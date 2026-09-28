// HOST STUB for core.untyped — used only by tests/virt/host.
//
// Trivial: the harness has no untyped budget objects (untypedObjId is always
// 0 in the stub task table, so core.virt.vm skips these calls anyway).
module core.untyped;

extern (C) @nogc nothrow:

public bool untypedRetype(uint untypedObjId, ulong pages) {
    cast(void)untypedObjId; cast(void)pages;
    return true;
}

public void untypedRelease(uint untypedObjId, ulong pages) {
    cast(void)untypedObjId; cast(void)pages;
}
