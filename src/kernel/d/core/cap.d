// Capability Manager — Phase 6 of roadmap/OBJECT_OS_ROADMAP.md.
//
// This is the first capability table backing the Linux fd view.  For this phase
// the existing File[] table remains the backend payload store; each fd index is
// also a capability handle with rights and an object id.  Phase 7+ can then
// delegate capabilities over IPC without passing raw backend pointers.
module core.cap;

import core.io;
import core.objmgr : objGet;

extern (C) @nogc nothrow:

enum int CAP_MAX = 1024;
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
enum uint CAP_RIGHT_ALL   = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_CLOSE |
                            CAP_RIGHT_STAT | CAP_RIGHT_IOCTL | CAP_RIGHT_MMAP |
                            CAP_RIGHT_DUP | CAP_RIGHT_PASS;

struct Capability {
    uint objId;
    uint rights;
    uint deriveParent; // parent handle in the same table; CAP_INVALID for roots
    uint revoked;      // non-zero means the handle was explicitly revoked
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
    cap.objId = objId;
    cap.rights = rights & CAP_RIGHT_ALL;
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
    *cap = Capability.init;
}

public void capClear(uint handle) {
    capInit();
    capClearIn(g_activeCapTabId, handle);
}

public void capTableClear(int tableId) {
    if (!validTable(tableId)) return;
    foreach (i; 0 .. CAP_MAX)
        g_capTabs[tableId].caps[i] = Capability.init;
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
    uint rights = subsetRights & CAP_RIGHT_ALL;
    if (capUsable(src)) {
        if ((rights & src.rights) != rights) return CAP_INVALID;
    }
    ++g_capDeriveTotal;
    return capInstall(dstHandle, objId, rights, srcHandle);
}

public uint capDeriveObjectToIn(int tableId, uint srcHandle, uint dstHandle,
                                uint objId, uint subsetRights) {
    auto src = capGetIn(tableId, srcHandle);
    uint rights = subsetRights & CAP_RIGHT_ALL;
    if (capUsable(src)) {
        if ((rights & src.rights) != rights) return CAP_INVALID;
    }
    ++g_capDeriveTotal;
    return capInstallIn(tableId, dstHandle, objId, rights, srcHandle);
}

public void capRevoke(uint capId) {
    capInit();
    if (!validHandle(capId)) return;
    auto cap = &g_capTable[capId];
    cap.objId = 0;
    cap.rights = 0;
    cap.revoked = 1;
    ++g_capRevokeTotal;

    // Revocation is intentionally local to the active table in this phase.  It
    // still cascades to handles explicitly derived from this handle.
    foreach (i; 0 .. CAP_MAX) {
        auto child = &g_capTable[i];
        if (child.objId != 0 && child.deriveParent == capId) {
            child.objId = 0;
            child.rights = 0;
            child.revoked = 1;
        }
    }
}

public void capTableCloneNarrowing(int srcTableId, int dstTableId, uint rightsMask) {
    if (!validTable(srcTableId) || !validTable(dstTableId) ||
        srcTableId == dstTableId) return;
    foreach (i; 0 .. CAP_MAX) {
        auto src = &g_capTabs[srcTableId].caps[i];
        auto dst = &g_capTabs[dstTableId].caps[i];
        if (capUsable(src)) {
            dst.objId = src.objId;
            dst.rights = src.rights & rightsMask;
            dst.deriveParent = cast(uint)i;
            dst.revoked = 0;
        } else {
            *dst = Capability.init;
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

public void capStats() {
    klog("[cap] table="); klog_hex(cast(ulong)g_activeCapTabId);
    klog(" live=");      klog_hex(cast(ulong)capLiveCount(g_activeCapTabId));
    klog(" install=");   klog_hex(g_capInstallTotal);
    klog(" derive=");    klog_hex(g_capDeriveTotal);
    klog(" revoke=");    klog_hex(g_capRevokeTotal);
    klog(" require=");   klog_hex(g_capRequireTotal);
    klog(" deny=");      klog_hex(g_capDenyTotal);
    klog("\n");
}
