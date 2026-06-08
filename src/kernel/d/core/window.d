// Window objects (display as objects) — Phase 11 of roadmap/OBJECT_OS_ROADMAP.md.
//
// Turns the in-kernel compositor's display state into first-class objects:
// **Output** (a display/screen), **Window** (a managed top-level), and
// **Surface** (a window's pixel buffer).  All three live in the central object
// table as the `ObjType.Window` display family (distinguished by a `WinKind`
// discriminator, the same way core/device.d folds every device under
// `ObjType.Device`).  Each carries an `ownerObjId` — the object that holds it,
// the seam through which display objects become "owned via caps" — and a
// `parentObjId` linking Surface→Window→Output.
//
// In the additive spirit of the earlier phases this establishes display-object
// *identity* and a create/destroy registration surface.  The primary Output (the
// firmware framebuffer) is live; the in-kernel WindowManager/compositor is
// currently dormant on the Hyprland boot (its `d_display_heartbeat` has no caller
// yet — the live compositor is userspace Hyprland), so Window/Surface registration
// is "ready the moment the in-kernel compositor runs," exactly like the Phase 8
// AHCI Driver registering with zero probed disks.  Migrating the compositor to a
// user-space service (GUI_ROADMAP.md) is the next step on this seam.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module core.window;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objRelease, objCountType;
import core.identity : IdentityId, IdentityColor, GuiContextId; // IDENTITY_DOMAIN §1/§6

extern (C) @nogc nothrow:

enum WinKind : uint { Output = 0, Window, Surface }

enum int WIN_MAX = 128;

struct WinRec {
    bool    inUse;
    uint    objId;       // ObjType.Window (display object family)
    WinKind kind;
    ulong   localId;     // compositor-side id (output index / window id / surface id)
    uint    ownerObjId;  // owning object (Process/User/Service) — the cap holder
    uint    parentObjId; // Surface→Window, Window→Output linkage
    uint    width;
    uint    height;
    void*   impl;        // backing struct, when available
    // IDENTITY_DOMAIN §1/§6: the owning process's security-domain, STAMPED BY THE
    // KERNEL at winRegister (never app-supplied), so the trusted compositor can
    // draw an unspoofable colored border.  All 0 until the GUI phase (§6) stamps
    // them — Phase 1 only reserves the fields.
    IdentityId    identityObjId; // = owner process's Task.identityObjId
    IdentityColor identityColor; // snapshot of IdentityRec.color (0xAARRGGBB)
    GuiContextId  guiContextId;  // groups this identity's windows/surfaces
}

__gshared WinRec[WIN_MAX] g_wins;

__gshared ulong g_winRegTotal = 0;
__gshared ulong g_winRelTotal = 0;
__gshared uint  g_winLive      = 0;
__gshared bool  g_winInited    = false;
__gshared bool  g_winSelfTested = false;

private WinRec* winFind(WinKind kind, ulong localId) {
    foreach (ref w; g_wins)
        if (w.inUse && w.kind == kind && w.localId == localId) return &w;
    return null;
}

// Register (idempotently) a display object of `kind` with compositor id `localId`.
// Re-registration updates geometry/owner in place.  Returns the object id, 0 on
// table exhaustion.
public uint winRegister(WinKind kind, ulong localId, uint ownerObjId,
                        uint parentObjId, uint width, uint height, void* impl) {
    auto existing = winFind(kind, localId);
    if (existing !is null) {
        existing.ownerObjId = ownerObjId;
        existing.parentObjId = parentObjId;
        existing.width = width;
        existing.height = height;
        existing.impl = impl;
        return existing.objId;
    }
    foreach (ref w; g_wins) {
        if (w.inUse) continue;
        uint id = objAlloc(ObjType.Window, cast(void*)&w);
        if (id == 0) return 0;
        w = WinRec.init;
        w.inUse = true;
        w.objId = id;
        w.kind = kind;
        w.localId = localId;
        w.ownerObjId = ownerObjId;
        w.parentObjId = parentObjId;
        w.width = width;
        w.height = height;
        w.impl = impl;
        ++g_winRegTotal;
        ++g_winLive;
        return id;
    }
    return 0;
}

// Convenience wrappers for the three display object kinds.
public uint outputRegister(ulong index, uint width, uint height, void* impl) {
    return winRegister(WinKind.Output, index, 0, 0, width, height, impl);
}
public uint windowRegister(ulong winId, uint outputObjId, uint width, uint height) {
    return winRegister(WinKind.Window, winId, 0, outputObjId, width, height, null);
}
public uint surfaceRegister(ulong surfId, uint windowObjId, uint width, uint height) {
    return winRegister(WinKind.Surface, surfId, 0, windowObjId, width, height, null);
}

public void winReleaseLocal(WinKind kind, ulong localId) {
    auto w = winFind(kind, localId);
    if (w is null) return;
    objRelease(w.objId);
    *w = WinRec.init;
    ++g_winRelTotal;
    if (g_winLive > 0) --g_winLive;
}

public uint winByLocal(WinKind kind, ulong localId) {
    auto w = winFind(kind, localId);
    return (w is null) ? 0 : w.objId;
}

public WinRec* winRecByObj(uint objId) {
    if (objId == 0) return null;
    foreach (ref w; g_wins)
        if (w.inUse && w.objId == objId) return &w;
    return null;
}

// Assign the owning object (the cap holder) of a display object — the hook
// through which a window/surface/output becomes owned via a capability.
public void winSetOwner(uint objId, uint ownerObjId) {
    auto w = winRecByObj(objId);
    if (w !is null) w.ownerObjId = ownerObjId;
}

private uint winCountKind(WinKind kind) {
    uint n = 0;
    foreach (ref w; g_wins) if (w.inUse && w.kind == kind) ++n;
    return n;
}

// Register the primary Output for the firmware framebuffer (live even under the
// userspace compositor).  Idempotent.
public void windowRegistryInit(uint fbWidth, uint fbHeight) {
    if (g_winInited) return;
    g_winInited = true;
    if (fbWidth != 0 && fbHeight != 0)
        outputRegister(0, fbWidth, fbHeight, null);
}

// --- Boot self-test (Phase 11 runtime proof) ----------------------------------
// Builds an Output → Window → Surface object tree, checks the parent linkage and
// liveness, assigns an owner (cap-holder) to the window, then tears the surface
// down and confirms it is released while the window/output survive.
public void windowSelfTest() {
    if (g_winSelfTested) return;
    g_winSelfTested = true;

    uint outp = outputRegister(0xF00, 1280, 800, null);
    uint win  = windowRegister(0xF01, outp, 640, 480);
    uint surf = surfaceRegister(0xF02, win, 640, 480);

    winSetOwner(win, outp); // stand-in owner: any live object id

    auto wo = winRecByObj(win);
    auto so = winRecByObj(surf);
    bool ok = (outp != 0 && win != 0 && surf != 0 &&
               outp != win && win != surf &&
               objGet(outp) !is null && objGet(win) !is null && objGet(surf) !is null &&
               wo !is null && wo.parentObjId == outp && wo.ownerObjId == outp &&
               so !is null && so.parentObjId == win);

    winReleaseLocal(WinKind.Surface, 0xF02);
    ok = ok && (winByLocal(WinKind.Surface, 0xF02) == 0 &&  // surface gone
                objGet(win) !is null && objGet(outp) !is null); // window/output live

    // Clean up the self-test objects.
    winReleaseLocal(WinKind.Window, 0xF01);
    winReleaseLocal(WinKind.Output, 0xF00);

    if (ok) klog("[win] selftest PASS\n");
    else    klog("[win] selftest FAIL\n");
}

public void windowStats() {
    klog("[win] live=");    klog_hex(cast(ulong)g_winLive);
    klog(" reg=");          klog_hex(g_winRegTotal);
    klog(" freed=");        klog_hex(g_winRelTotal);
    klog(" winobj=");       klog_hex(cast(ulong)objCountType(ObjType.Window));
    klog(" outputs=");      klog_hex(cast(ulong)winCountKind(WinKind.Output));
    klog(" windows=");      klog_hex(cast(ulong)winCountKind(WinKind.Window));
    klog(" surfaces=");     klog_hex(cast(ulong)winCountKind(WinKind.Surface));
    klog("\n");
}
