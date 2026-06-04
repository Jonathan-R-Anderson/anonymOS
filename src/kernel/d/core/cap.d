// Capability Manager — Phase 6 of roadmap/OBJECT_OS_ROADMAP.md.
//
// This is the first capability table backing the Linux fd view.  For this phase
// the existing File[] table remains the backend payload store; each fd index is
// also a capability handle with rights and an object id.  Phase 7+ can then
// delegate capabilities over IPC without passing raw backend pointers.
module core.cap;

import core.io;
import core.objmgr : objGet, objAlloc, objRelease, objCountType, ObjType; // ORG P7.2 self-test
import core.audit : auditLog, AuditKind; // ORG P8.2: attributable revocations

extern (C) @nogc nothrow:

enum int CAP_MAX = 2048;
enum int CAPTAB_COUNT = 64;
enum uint CAP_INVALID = uint.max;

enum uint CAP_RIGHT_READ  = 1u << 0;
enum uint CAP_RIGHT_WRITE = 1u << 1;
enum uint CAP_RIGHT_CLOSE = 1u << 2;
enum uint CAP_RIGHT_STAT  = 1u << 3;
enum uint CAP_RIGHT_IOCTL = 1u << 4;
enum uint CAP_RIGHT_MMAP  = 1u << 5;
enum uint CAP_RIGHT_DUP   = 1u << 6;
enum uint CAP_RIGHT_PASS  = 1u << 7;
enum uint CAP_RIGHT_RETYPE = 1u << 8; // Untyped-memory retype (§1.4), not an fd right
enum uint CAP_RIGHT_CALL  = 1u << 9; // Endpoint/service call (§2.3), not an fd right
enum uint CAP_RIGHT_ALL   = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_CLOSE |
                            CAP_RIGHT_STAT | CAP_RIGHT_IOCTL | CAP_RIGHT_MMAP |
                            CAP_RIGHT_DUP | CAP_RIGHT_PASS;
enum uint CAP_RIGHT_UNIVERSE = CAP_RIGHT_ALL | CAP_RIGHT_RETYPE | CAP_RIGHT_CALL;

struct Capability {
    uint objId;
    uint rights;
    uint deriveParent; // parent handle in the same table; CAP_INVALID for roots
    uint revoked;      // non-zero means the handle was explicitly revoked
    uint capObjId;     // ObjType.Capability identity for this live handle
}

struct CapTable {
    Capability[CAP_MAX] caps;
}

__gshared CapTable[CAPTAB_COUNT] g_capTabs;
__gshared Capability* g_capTable;
__gshared int g_activeCapTabId = 0;

__gshared ulong g_capInstallTotal = 0;
__gshared ulong g_capDeriveTotal  = 0;
__gshared ulong g_capRevokeTotal  = 0;
__gshared ulong g_capRequireTotal = 0;
__gshared ulong g_capDenyTotal    = 0;

private bool validTable(int tableId) {
    return tableId >= 0 && tableId < CAPTAB_COUNT;
}

private bool validHandle(uint handle) {
    return handle < CAP_MAX;
}

private void capInit() {
    if (g_capTable is null)
        g_capTable = &g_capTabs[0].caps[0];
}

public void capTableSetActive(int tableId) {
    if (!validTable(tableId)) tableId = 0;
    g_activeCapTabId = tableId;
    g_capTable = &g_capTabs[tableId].caps[0];
}

public Capability* capGet(uint handle) {
    capInit();
    if (!validHandle(handle)) return null;
    return &g_capTable[handle];
}

public Capability* capGetIn(int tableId, uint handle) {
    if (!validTable(tableId) || !validHandle(handle)) return null;
    return &g_capTabs[tableId].caps[handle];
}

public bool capUsable(Capability* cap) {
    if (cap is null || cap.revoked != 0 || cap.objId == 0) return false;
    return objGet(cap.objId) !is null;
}

private void capReleaseObject(Capability* cap) {
    if (cap is null || cap.capObjId == 0) return;
    if (objGet(cap.capObjId) !is null) objRelease(cap.capObjId);
    cap.capObjId = 0;
}

private bool capEnsureObject(Capability* cap) {
    if (cap is null) return false;
    if (cap.capObjId != 0) {
        auto h = objGet(cap.capObjId);
        if (h !is null && h.type == ObjType.Capability &&
            h.impl is cast(void*)cap)
            return true;
        if (h !is null) objRelease(cap.capObjId);
        cap.capObjId = 0;
    }
    cap.capObjId = objAlloc(ObjType.Capability, cast(void*)cap);
    return cap.capObjId != 0;
}

public bool requireCap(int tid, uint capId, uint rights) {
    ++g_capRequireTotal;
    auto cap = capGet(capId);
    if (!capUsable(cap) || (cap.rights & rights) != rights) {
        ++g_capDenyTotal;
        return false;
    }
    return true;
}

public bool requireCapIn(int tableId, uint capId, uint rights) {
    ++g_capRequireTotal;
    auto cap = capGetIn(tableId, capId);
    if (!capUsable(cap) || (cap.rights & rights) != rights) {
        ++g_capDenyTotal;
        return false;
    }
    return true;
}

public uint capInstallIn(int tableId, uint handle, uint objId, uint rights,
                         uint deriveParent) {
    auto cap = capGetIn(tableId, handle);
    if (cap is null || objId == 0 || objGet(objId) is null) return CAP_INVALID;
    if (!capEnsureObject(cap)) return CAP_INVALID;
    cap.objId = objId;
    cap.rights = rights & CAP_RIGHT_UNIVERSE;
    cap.deriveParent = deriveParent;
    cap.revoked = 0;
    ++g_capInstallTotal;
    return handle;
}

public uint capInstall(uint handle, uint objId, uint rights, uint deriveParent) {
    capInit();
    return capInstallIn(g_activeCapTabId, handle, objId, rights, deriveParent);
}

public void capClearIn(int tableId, uint handle) {
    auto cap = capGetIn(tableId, handle);
    if (cap is null) return;
    capReleaseObject(cap);
    *cap = Capability.init;
}

public void capClear(uint handle) {
    capInit();
    capClearIn(g_activeCapTabId, handle);
}

public void capTableClear(int tableId) {
    if (!validTable(tableId)) return;
    foreach (i; 0 .. CAP_MAX)
        capClearIn(tableId, cast(uint)i);
}

public uint capDerive(uint capId, uint subsetRights) {
    capInit();
    auto src = capGet(capId);
    if (!capUsable(src)) return CAP_INVALID;
    uint rights = subsetRights & src.rights;
    if (rights != subsetRights) return CAP_INVALID;
    for (uint i = 0; i < CAP_MAX; ++i) {
        auto dst = &g_capTable[i];
        if (dst.objId == 0 && dst.revoked == 0) {
            ++g_capDeriveTotal;
            return capInstall(i, src.objId, rights, capId);
        }
    }
    return CAP_INVALID;
}

public uint capDeriveObjectTo(uint srcHandle, uint dstHandle, uint objId,
                              uint subsetRights) {
    capInit();
    auto src = capGet(srcHandle);
    if (!capUsable(src)) return CAP_INVALID;
    uint rights = subsetRights & CAP_RIGHT_UNIVERSE;
    if ((rights & src.rights) != rights) return CAP_INVALID;
    ++g_capDeriveTotal;
    return capInstall(dstHandle, objId, rights, srcHandle);
}

public uint capDeriveObjectToIn(int tableId, uint srcHandle, uint dstHandle,
                                uint objId, uint subsetRights) {
    auto src = capGetIn(tableId, srcHandle);
    if (!capUsable(src)) return CAP_INVALID;
    uint rights = subsetRights & CAP_RIGHT_UNIVERSE;
    if ((rights & src.rights) != rights) return CAP_INVALID;
    ++g_capDeriveTotal;
    return capInstallIn(tableId, dstHandle, objId, rights, srcHandle);
}

// ORG P7.2 (I7 revocation closure): revoking a capability invalidates the entire
// forward derive-DAG, not just its direct children.  Iterates to a fixpoint over
// the deriveParent edges so a grandchild (and deeper) cap is rendered unusable too.
public void capRevokeIn(int tableId, uint capId) {
    if (!validTable(tableId) || !validHandle(capId)) return;
    auto caps = &g_capTabs[tableId].caps[0];
    capReleaseObject(&caps[capId]);
    caps[capId].objId = 0;
    caps[capId].rights = 0;
    caps[capId].revoked = 1;
    ++g_capRevokeTotal;
    auditLog(AuditKind.Revocation, capId, cast(ulong)tableId); // P8.2: attributable

    // Transitive closure: a cap whose deriveParent has been revoked is itself
    // revoked.  Repeat until no further cap changes (depth ≤ derive-chain length).
    bool changed = true;
    while (changed) {
        changed = false;
        foreach (i; 0 .. CAP_MAX) {
            auto child = &caps[i];
            if (child.objId != 0 && child.deriveParent < CAP_MAX &&
                caps[child.deriveParent].revoked != 0) {
                capReleaseObject(child);
                child.objId = 0;
                child.rights = 0;
                child.revoked = 1;
                changed = true;
            }
        }
    }
}

public void capRevoke(uint capId) {
    capInit();
    capRevokeIn(g_activeCapTabId, capId);
}

public void capTableCloneNarrowing(int srcTableId, int dstTableId, uint rightsMask) {
    if (!validTable(srcTableId) || !validTable(dstTableId) ||
        srcTableId == dstTableId) return;
    foreach (i; 0 .. CAP_MAX) {
        auto src = &g_capTabs[srcTableId].caps[i];
        if (capUsable(src)) {
            uint narrowed = src.rights & rightsMask;
            if (narrowed != 0)
                capInstallIn(dstTableId, cast(uint)i, src.objId,
                             narrowed, cast(uint)i);
            else
                capClearIn(dstTableId, cast(uint)i);
        } else {
            capClearIn(dstTableId, cast(uint)i);
        }
    }
}

public uint capLiveCount(int tableId) {
    if (!validTable(tableId)) return 0;
    uint n = 0;
    foreach (i; 0 .. CAP_MAX)
        if (capUsable(&g_capTabs[tableId].caps[i])) ++n;
    return n;
}

// ORG P7.2 self-test (I7 revocation closure): on a scratch capability table, a
// root → child → grandchild derive chain is built; revoking the root must render
// *all three* unusable.  Guarded on the scratch table being idle, cleared after,
// so it never disturbs a live process's capabilities.
__gshared bool g_capRevTested = false;
public void capRevokeClosureSelfTest() {
    if (g_capRevTested) return;
    g_capRevTested = true;
    int st = CAPTAB_COUNT - 1; // scratch table (highest id)
    if (capLiveCount(st) != 0) return; // table in use by a real task — skip safely
    uint to = objAlloc(ObjType.File, null);
    if (to == 0) return;

    capInstallIn(st, 10, to, CAP_RIGHT_ALL, CAP_INVALID);    // root cap
    capDeriveObjectToIn(st, 10, 11, to, CAP_RIGHT_READ);     // child  ← root
    capDeriveObjectToIn(st, 11, 12, to, CAP_RIGHT_READ);     // grandchild ← child
    bool before = capUsable(capGetIn(st, 10)) && capUsable(capGetIn(st, 11)) &&
                  capUsable(capGetIn(st, 12));

    capRevokeIn(st, 10);                                     // revoke the root
    bool closed = !capUsable(capGetIn(st, 10)) && !capUsable(capGetIn(st, 11)) &&
                  !capUsable(capGetIn(st, 12));              // grandchild dies too

    capTableClear(st);
    objRelease(to);

    if (before && closed) klog("[cap] revclosure PASS\n");
    else                  klog("[cap] revclosure FAIL\n");
}

public void capStats() {
    klog("[cap] table="); klog_hex(cast(ulong)g_activeCapTabId);
    klog(" live=");      klog_hex(cast(ulong)capLiveCount(g_activeCapTabId));
    klog(" install=");   klog_hex(g_capInstallTotal);
    klog(" derive=");    klog_hex(g_capDeriveTotal);
    klog(" revoke=");    klog_hex(g_capRevokeTotal);
    klog(" require=");   klog_hex(g_capRequireTotal);
    klog(" deny=");      klog_hex(g_capDenyTotal);
    klog(" capobj=");    klog_hex(cast(ulong)objCountType(ObjType.Capability));
    klog("\n");
}
