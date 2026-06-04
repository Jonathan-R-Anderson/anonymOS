// User objects — Phase 10 of roadmap/OBJECT_OS_ROADMAP.md.
//
// Introduces first-class **User** objects so process identity (uid/gid) and
// process identity stop being the hardcoded ambient `0` scattered through
// posix.d.  A User object carries {uid, gid, name, home, shell} plus an
// initial session rights.  Administrative actions are separate typed caps in
// core.admin, never "am I root".  The synthetic `/etc/passwd` and `/etc/group`
// providers now derive their content from this registry.
//
// IMMUTABLE_ROOTLESS §3 flips the default running identity to the non-root user.
// PID1 may still hold explicit admin capabilities, but `getuid()`/SO_PEERCRED
// report the task's User object, not ambient UID 0.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module core.user;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objCountType;

extern (C) @nogc nothrow:

enum int USER_MAX      = 16;
enum int USER_NAME_MAX = 32;
enum int USER_PATH_MAX = 48;

// Session rights. Syscall administrative authority lives in core.admin typed caps.
enum uint USER_RIGHT_LOGIN = 1u << 0; // may own a login session
enum uint USER_RIGHT_SPAWN = 1u << 1; // may spawn processes
enum uint USER_RIGHT_ADMIN = 1u << 2; // registry marker only; not a syscall gate
enum uint USER_RIGHT_ALL   = USER_RIGHT_LOGIN | USER_RIGHT_SPAWN | USER_RIGHT_ADMIN;

struct UserRec {
    bool inUse;
    uint objId;                 // ObjType.User
    uint uid;
    uint gid;
    uint rights;                // administrative authority bits
    uint nameLen;
    char[USER_NAME_MAX] name;
    char[USER_PATH_MAX] home;
    char[USER_PATH_MAX] shell;
}

__gshared UserRec[USER_MAX] g_users;

// The identity selected by the scheduler/dispatcher for the current task.
__gshared uint g_currentUserObjId = 0;
__gshared uint g_rootUserObjId    = 0;
__gshared uint g_defaultUserObjId = 0;

__gshared ulong g_userRegTotal   = 0;
__gshared bool  g_userInited      = false;
__gshared bool  g_userSelfTested  = false;

// Generated /etc/passwd and /etc/group buffers (derived from the registry).
__gshared char[512] g_passwdBuf;
__gshared uint      g_passwdLen = 0;
__gshared char[256] g_groupBuf;
__gshared uint      g_groupLen  = 0;

// --- helpers (uniquely named: extern(C) gives even private fns C linkage) -----
private uint uStrLen(const(char)* s) {
    if (s is null) return 0;
    uint n = 0;
    while (s[n] != 0) ++n;
    return n;
}

private void uCopy(char[] dst, const(char)* src, uint cap) {
    uint i = 0;
    if (src !is null)
        for (; src[i] != 0 && i < cap; ++i) dst[i] = src[i];
    if (i < dst.length) dst[i] = 0;
}

// Append a NUL-terminated string to buf at *pos (bounded); returns bytes written.
private void uAppendStr(char[] buf, ref uint pos, const(char)* s) {
    if (s is null) return;
    for (uint i = 0; s[i] != 0 && pos < buf.length; ++i) buf[pos++] = s[i];
}

private void uAppendSlice(char[] buf, ref uint pos, const(char)[] s) {
    foreach (c; s) { if (pos >= buf.length) break; buf[pos++] = c; }
}

private void uAppendUint(char[] buf, ref uint pos, uint v) {
    char[10] tmp;
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v > 0 && n < 10) { tmp[n++] = cast(char)('0' + (v % 10)); v /= 10; }
    while (n > 0 && pos < buf.length) buf[pos++] = tmp[--n];
}

// --- registry -----------------------------------------------------------------

public uint userRegister(uint uid, uint gid, const(char)* name,
                         const(char)* home, const(char)* shell, uint rights) {
    // Idempotent by uid.
    foreach (ref u; g_users)
        if (u.inUse && u.uid == uid) return u.objId;
    foreach (ref u; g_users) {
        if (u.inUse) continue;
        uint id = objAlloc(ObjType.User, cast(void*)&u);
        if (id == 0) return 0;
        u = UserRec.init;
        u.inUse = true;
        u.objId = id;
        u.uid = uid;
        u.gid = gid;
        u.rights = rights & USER_RIGHT_ALL;
        u.nameLen = uStrLen(name);
        uCopy(u.name[], name, USER_NAME_MAX - 1);
        uCopy(u.home[], home, USER_PATH_MAX - 1);
        uCopy(u.shell[], shell, USER_PATH_MAX - 1);
        ++g_userRegTotal;
        return id;
    }
    return 0;
}

public UserRec* userByObj(uint objId) {
    if (objId == 0) return null;
    foreach (ref u; g_users)
        if (u.inUse && u.objId == objId) return &u;
    return null;
}

public UserRec* userByUid(uint uid) {
    foreach (ref u; g_users)
        if (u.inUse && u.uid == uid) return &u;
    return null;
}

public UserRec* userByGid(uint gid) {
    foreach (ref u; g_users)
        if (u.inUse && u.gid == gid) return &u;
    return null;
}

public uint userRootObjId() {
    if (g_rootUserObjId != 0) return g_rootUserObjId;
    auto u = userByUid(0);
    return (u is null) ? 0 : u.objId;
}

public uint userDefaultObjId() {
    if (g_defaultUserObjId != 0) return g_defaultUserObjId;
    auto u = userByUid(1000);
    if (u !is null) return u.objId;
    return userRootObjId();
}

public bool userSetActiveSubject(uint objId) {
    if (objId != 0 && userByObj(objId) !is null) {
        g_currentUserObjId = objId;
        return true;
    }
    uint d = userDefaultObjId();
    g_currentUserObjId = d;
    return d != 0;
}

// The User the active task acts as (non-root default / root fallback).
public UserRec* userCurrent() {
    auto u = userByObj(g_currentUserObjId);
    if (u !is null) return u;
    u = userByObj(userDefaultObjId());
    if (u !is null) return u;
    return userByUid(0);
}

public uint userCurrentUid() {
    auto u = userCurrent();
    return (u is null) ? 0 : u.uid;
}

public uint userCurrentGid() {
    auto u = userCurrent();
    return (u is null) ? 0 : u.gid;
}

// Does the current identity hold a registry/session right? This is not used for
// syscall administration; privileged actions require core.admin typed caps.
public bool userHasRight(uint right) {
    auto u = userCurrent();
    return u !is null && (u.rights & right) == right;
}

public bool userIsAdmin() { return userHasRight(USER_RIGHT_ADMIN); }

// --- /etc/passwd & /etc/group derivation --------------------------------------

private void userRebuildPasswd() {
    uint pos = 0;
    foreach (ref u; g_users) {
        if (!u.inUse) continue;
        // name:x:uid:gid:name:home:shell
        uAppendStr(g_passwdBuf[], pos, u.name.ptr);
        uAppendSlice(g_passwdBuf[], pos, ":x:");
        uAppendUint(g_passwdBuf[], pos, u.uid);
        uAppendSlice(g_passwdBuf[], pos, ":");
        uAppendUint(g_passwdBuf[], pos, u.gid);
        uAppendSlice(g_passwdBuf[], pos, ":");
        uAppendStr(g_passwdBuf[], pos, u.name.ptr);
        uAppendSlice(g_passwdBuf[], pos, ":");
        uAppendStr(g_passwdBuf[], pos, u.home.ptr);
        uAppendSlice(g_passwdBuf[], pos, ":");
        uAppendStr(g_passwdBuf[], pos, u.shell.ptr);
        uAppendSlice(g_passwdBuf[], pos, "\n");
    }
    g_passwdLen = pos;

    pos = 0;
    foreach (ref u; g_users) {
        if (!u.inUse) continue;
        uAppendStr(g_groupBuf[], pos, u.name.ptr);
        uAppendSlice(g_groupBuf[], pos, ":x:");
        uAppendUint(g_groupBuf[], pos, u.gid);
        uAppendSlice(g_groupBuf[], pos, ":\n");
    }
    g_groupLen = pos;
}

// Content for the synthetic /etc/passwd (empty slice if the registry is empty so
// the caller can fall back to its static entry).
public const(char)[] userPasswdContent() {
    if (g_passwdLen == 0) return null;
    return g_passwdBuf[0 .. g_passwdLen];
}

public const(char)[] userGroupContent() {
    if (g_groupLen == 0) return null;
    return g_groupBuf[0 .. g_groupLen];
}

// --- boot registration --------------------------------------------------------
public void userRegistryInit() {
    if (g_userInited) return;
    g_userInited = true;

    uint root = userRegister(0, 0, "root\0".ptr, "/root\0".ptr, "/bin/sh\0".ptr,
                             USER_RIGHT_ALL);
    // A non-root user matching the XDG_RUNTIME_DIR=/run/user/1000 the bring-up
    // env advertises; carries login/spawn but not admin authority.
    uint user = userRegister(1000, 1000, "user\0".ptr, "/home/user\0".ptr, "/bin/sh\0".ptr,
                             USER_RIGHT_LOGIN | USER_RIGHT_SPAWN);

    g_rootUserObjId = root;
    g_defaultUserObjId = (user != 0) ? user : root;
    g_currentUserObjId = g_defaultUserObjId;
    userRebuildPasswd();
}

// --- proof --------------------------------------------------------------------
public void userSelfTest() {
    if (g_userSelfTested) return;
    g_userSelfTested = true;

    auto root = userByUid(0);
    auto user = userByUid(1000);
    userSetActiveSubject(user !is null ? user.objId : 0);

    bool ok = (root !is null && user !is null &&
               objGet(root.objId) !is null && objGet(user.objId) !is null &&
               userCurrentUid() == 1000 &&         // default subject is non-root
               !userIsAdmin() &&                   // admin is not inherited by uid
               (root.rights & USER_RIGHT_ADMIN) != 0 &&
               (user.rights & USER_RIGHT_ADMIN) == 0 &&
               userPasswdContent().length > 0);    // passwd derives from objects

    if (ok) klog("[user] selftest PASS\n");
    else    klog("[user] selftest FAIL\n");
}

public void userStats() {
    klog("[user] reg=");    klog_hex(g_userRegTotal);
    klog(" userobj=");      klog_hex(cast(ulong)objCountType(ObjType.User));
    klog(" curuid=");       klog_hex(cast(ulong)userCurrentUid());
    klog(" admin=");        klog_hex(userIsAdmin() ? 1 : 0);
    klog(" passwdlen=");    klog_hex(cast(ulong)g_passwdLen);
    klog("\n");
}
