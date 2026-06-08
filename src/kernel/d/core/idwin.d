// Identity window borders — Phase 6 of roadmap/IDENTITY_DOMAIN_ROADMAP.md.
//
// Makes a window's security domain *visible and unspoofable*.  When the kernel
// registers a Window (core/window.d `winRegister`), it stamps the WinRec with the
// OWNER process's identity (`Task.identityObjId`) and a snapshot of that identity's
// border `color` — the app never supplies either, and re-registering cannot change
// it.  The trusted compositor then draws a persistent N-px border in that color
// AFTER blitting the app surface (app pixels can't reach the border ring) plus a
// `"[<name>] <title>"` label, so a Banking window can never paint itself to look
// like a Personal one.
//
// Kernel build constraints (hard): -betterC (ldc2, no GC/druntime/exceptions),
// plain structs, __gshared fixed-size tables, @nogc nothrow, -O0.
module core.idwin;

import core.objmgr : objGet;
import core.window : WinRec, WinKind, winRegister, winReleaseLocal, winRecByObj,
                     winByLocal, winSetIdentityStamp, g_wins, WIN_MAX;
import core.identity : IdentityId, IdentityColor, IdentityRec, identityById,
                       identityByName, identityNamePrint;
import core.task : g_tasks, MAX_TASKS;
import core.audit : auditLog, AuditKind;
import core.io : klog, klog_hex;

extern (C) @nogc nothrow:

__gshared ulong g_idwinStamps     = 0;   // windows stamped with an identity
__gshared bool  g_idwinInited     = false;
__gshared bool  g_idwinSelfTested = false;

// Resolve a window-owner object → the security-domain identity it is labelled with
// (the owning Task's `identityObjId`).  0 if the owner is not a live task-backed
// process.  Pluggable so the self-test (and a future userspace seam) can supply the
// owner→identity mapping directly.
alias IdwinResolverFn = extern (C) IdentityId function(uint ownerObjId) @nogc nothrow;

extern (C) IdentityId idwinResolveViaTask(uint ownerObjId) @nogc nothrow {
    if (ownerObjId == 0) return 0;
    foreach (ref t; g_tasks) {
        if (!t.active || t.exited) continue;
        if (t.processObjId == ownerObjId || t.objId == ownerObjId)
            return t.identityObjId;
    }
    return 0;
}

__gshared IdwinResolverFn g_idwinResolver = &idwinResolveViaTask;
public void idwinSetResolver(IdwinResolverFn fn) {
    g_idwinResolver = (fn is null) ? &idwinResolveViaTask : fn;
}

// === the stamp (installed into winRegister) ===================================
// Stamp window `winObjId` with its OWNER's identity + border color.  Kernel-derived
// (never app-supplied); idempotent; called by winRegister on every (re)registration.
extern (C) void idwinStamp(uint winObjId) @nogc nothrow {
    auto w = winRecByObj(winObjId);
    if (w is null || w.kind != WinKind.Window) return;
    IdentityId id = g_idwinResolver(w.ownerObjId);
    auto r = identityById(id);
    w.identityObjId = id;
    w.identityColor = (r !is null) ? r.color : 0;
    w.guiContextId  = id;                 // windows of one identity share a GUI context
    ++g_idwinStamps;
    auditLog(AuditKind.IdWindowCreate, winObjId, id);
}

// === lookups (roadmap §6 API) =================================================
public IdentityId winIdentity(uint winObjId) {
    auto w = winRecByObj(winObjId);
    return (w is null) ? 0 : w.identityObjId;
}

public IdentityColor idwinBorderColor(uint winObjId) {
    auto w = winRecByObj(winObjId);
    return (w is null) ? 0 : w.identityColor;
}

// === unspoofable border drawing ===============================================
// Draw a `thickness`-px border in `color` (0xAARRGGBB) around the [x,y,w,h] window
// rect into a 32bpp framebuffer.  The TRUSTED compositor calls this AFTER blitting
// the app surface, so the app's pixels can never reach the border ring — only the
// outermost `thickness` px on each edge are overwritten, the interior is left alone.
public void idwinDrawBorder(uint* fb, uint fbW, uint fbH,
                            int x, int y, uint w, uint h,
                            IdentityColor color, uint thickness) {
    if (fb is null || w == 0 || h == 0 || thickness == 0) return;
    foreach (uint row; 0 .. h) {
        int py = y + cast(int)row;
        if (py < 0 || py >= cast(int)fbH) continue;
        bool edgeRow = (row < thickness) || (row + thickness >= h);
        foreach (uint col; 0 .. w) {
            int px = x + cast(int)col;
            if (px < 0 || px >= cast(int)fbW) continue;
            bool edgeCol = (col < thickness) || (col + thickness >= w);
            if (edgeRow || edgeCol)
                fb[cast(uint)py * fbW + cast(uint)px] = color;
        }
    }
}

// `idwin` debug command — the window→identity table.
public void idwinDump() {
    klog("[idwin] window-identity table:\n");
    foreach (ref w; g_wins) {
        if (!w.inUse || w.kind != WinKind.Window) continue;
        klog("  win=");    klog_hex(w.objId);
        klog(" owner=");   klog_hex(w.ownerObjId);
        klog(" id=");      klog_hex(w.identityObjId);
        if (w.identityObjId != 0) { klog(" ["); identityNamePrint(w.identityObjId); klog("]"); }
        klog(" color=");   klog_hex(w.identityColor);
        klog("\n");
    }
}

// Boot: install the winRegister stamp hook so every kernel-registered Window gets
// its owner's identity + border color (apps cannot supply them).
public void idwinInit() {
    if (g_idwinInited) return;
    g_idwinInited = true;
    winSetIdentityStamp(&idwinStamp);
}

// === proof (roadmap §6 outcome) ==============================================
// Two windows owned by two different domains (Work, Banking via a hermetic test
// resolver) get distinct stamped identities + distinct border colors; an app's
// attempt to claim a different identity (scribbling its WinRec, then re-registering)
// is overwritten by the owner-derived stamp; the border-color lookup returns the
// identity color; the border draw fills only the ring, never the interior.
__gshared uint       g_idwinTW, g_idwinTB;     // test owner objects
__gshared IdentityId g_idwinTWId, g_idwinTBId; // their domains

extern (C) IdentityId idwinTestResolver(uint ownerObjId) @nogc nothrow {
    if (ownerObjId == g_idwinTW) return g_idwinTWId;
    if (ownerObjId == g_idwinTB) return g_idwinTBId;
    return 0;
}

public void idwinSelfTest() {
    if (g_idwinSelfTested) return;
    g_idwinSelfTested = true;

    IdentityId workId = identityByName("Work\0".ptr);
    IdentityId bankId = identityByName("Banking\0".ptr);
    auto rw = identityById(workId);
    auto rb = identityById(bankId);
    if (workId == 0 || bankId == 0 || rw is null || rb is null) {
        klog("[idwin] selftest FAIL: identities\n"); return;
    }

    enum uint OWNER_W = 0xE001, OWNER_B = 0xE002;
    auto saved = g_idwinResolver;
    g_idwinTW = OWNER_W; g_idwinTB = OWNER_B;
    g_idwinTWId = workId; g_idwinTBId = bankId;
    g_idwinResolver = &idwinTestResolver;

    // winRegister auto-stamps (hook installed by idwinInit) from the owner.
    uint winW = winRegister(WinKind.Window, 0xD01, OWNER_W, 0, 640, 480, null);
    uint winB = winRegister(WinKind.Window, 0xD02, OWNER_B, 0, 640, 480, null);

    bool ok = (winW != 0 && winB != 0 && winW != winB);
    // stamped identity == owner's; color == IdentityRec.color; domains distinct.
    ok = ok && winIdentity(winW) == workId && winIdentity(winB) == bankId;
    ok = ok && idwinBorderColor(winW) == rw.color && idwinBorderColor(winB) == rb.color;
    ok = ok && rw.color != rb.color;

    // hostile app scribbles its own WinRec to claim Banking; a re-register re-derives
    // the owner's identity (OWNER_W → Work), overwriting the forgery.
    {
        auto w = winRecByObj(winW);
        w.identityObjId = bankId;
        w.identityColor = 0xDEADBEEF;
        winRegister(WinKind.Window, 0xD01, OWNER_W, 0, 800, 600, null); // re-register
        ok = ok && winIdentity(winW) == workId && idwinBorderColor(winW) == rw.color;
    }

    // border draw: identity color fills only the 2px ring; the interior app fill survives.
    {
        enum uint FW = 8, FH = 8;
        uint[FW * FH] buf;
        foreach (ref px; buf) px = 0x11111111;            // "app surface"
        idwinDrawBorder(buf.ptr, FW, FH, 0, 0, FW, FH, rw.color, 2);
        bool ring = buf[0] == rw.color && buf[FW - 1] == rw.color &&
                    buf[(FH - 1) * FW] == rw.color && buf[FH * FW - 1] == rw.color &&
                    buf[1 * FW + 1] == rw.color;          // 2px deep
        bool interior = buf[3 * FW + 3] == 0x11111111 && buf[4 * FW + 4] == 0x11111111;
        ok = ok && ring && interior;
    }

    // teardown — leave the registry as found.
    winReleaseLocal(WinKind.Window, 0xD01);
    winReleaseLocal(WinKind.Window, 0xD02);
    g_idwinResolver = saved;
    g_idwinTW = g_idwinTB = 0;

    if (ok) klog("[idwin] selftest PASS\n");
    else    klog("[idwin] selftest FAIL\n");
}

public void idwinStats() {
    klog("[idwin] stamps="); klog_hex(g_idwinStamps);
    klog(" hook=");          klog_hex(g_idwinInited ? 1 : 0);
    klog("\n");
}
