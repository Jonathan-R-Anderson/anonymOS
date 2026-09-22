// HOST STUB for core.objmgr — used only by tests/virt/host.
//
// Array-backed fake of the kernel object table.  Provides exactly the
// symbols core.virt.* imports: ObjType (Vm/Vcpu), ObjHeader
// (id/type/version_/impl), objAlloc/objGet/objRelease.  Refcount model
// mirrors the real one (alloc -> 1, release -> 0 -> free); the generation
// (version_) survives release so stale-handle checks keep working, exactly
// like the real table.
//
// Constraints: -betterC, @nogc nothrow.
module core.objmgr;

extern (C) @nogc nothrow:

enum ObjType : uint {
    Invalid = 0,
    Vm      = 1, // stub: a native virtual machine (core.virt.vm)
    Vcpu    = 2, // stub: a native virtual CPU (core.virt.vm)
}

struct ObjHeader {
    uint    id;
    ObjType type;
    uint    refCount;
    uint    version_; // generation mirror; survives release (stale checks)
    void*   impl;
}

enum uint STUB_OBJ_MAX = 512;

__gshared ObjHeader[STUB_OBJ_MAX] stub_objects;
__gshared uint stub_objNext = 1; // 0 is never a valid id

public uint objAlloc(ObjType t, void* impl) {
    // Linear scan from a rotating cursor: simple, deterministic.
    for (uint n = 0; n < STUB_OBJ_MAX; ++n) {
        uint id = stub_objNext;
        if (++stub_objNext >= STUB_OBJ_MAX) stub_objNext = 1;
        auto h = &stub_objects[id];
        if (h.refCount == 0 && h.type == ObjType.Invalid) {
            h.id = id;
            h.type = t;
            h.refCount = 1;
            h.impl = impl;
            // version_ is left alone: fresh slots start 0, reused slots keep
            // the last generation until the caller mirrors the new one.
            return id;
        }
    }
    return 0; // table full
}

public ObjHeader* objGet(uint id) {
    if (id == 0 || id >= STUB_OBJ_MAX) return null;
    auto h = &stub_objects[id];
    return (h.refCount == 0) ? null : h;
}

public void objRelease(uint id) {
    auto h = objGet(id);
    if (h is null) return;
    if (h.refCount > 0 && --h.refCount == 0) {
        h.type = ObjType.Invalid;
        h.impl = null;
        // version_ intentionally NOT cleared: a re-allocated slot must fail
        // old (id, generation) handles until the new owner mirrors its gen.
    }
}
