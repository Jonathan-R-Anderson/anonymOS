// Typed administrative capabilities — IMMUTABLE_ROOTLESS_ROADMAP §3.2.
//
// Administrative authority is represented as capabilities to ObjType.Admin
// objects, one narrow action per fixed non-fd handle.  UID 0 is not consulted:
// syscall gates call adminRequire* and therefore require a live cap in the active
// task's cap table with the matching action bit.
module core.admin;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objCountType;
import core.cap : CAPTAB_COUNT, CAP_INVALID,
                  CAP_RIGHT_ADMIN_MOUNT, CAP_RIGHT_ADMIN_REBOOT,
                  CAP_RIGHT_ADMIN_UPDATE, CAP_RIGHT_ADMIN_USER,
                  CAP_RIGHT_ADMIN_DEVICE, CAP_RIGHT_ADMIN_INSPECT,
                  capGetIn, capInstallIn, capLiveCount, capTableClear, capUsable,
                  g_activeCapTabId;

extern (C) @nogc nothrow:

enum uint ADMIN_CAP_MOUNT_HANDLE  = 1032;
enum uint ADMIN_CAP_REBOOT_HANDLE = 1033;
enum uint ADMIN_CAP_UPDATE_HANDLE = 1034;
enum uint ADMIN_CAP_USER_HANDLE   = 1035;
enum uint ADMIN_CAP_DEVICE_HANDLE = 1036;
enum uint ADMIN_CAP_INSPECT_HANDLE = 1037;

enum int ADMIN_MAX = 6;

struct AdminRec {
    bool inUse;
    uint objId;
    uint right;
    uint handle;
}

__gshared AdminRec[ADMIN_MAX] g_admin;
__gshared bool  g_adminInited = false;
__gshared bool  g_adminSelfTested = false;
__gshared ulong g_adminInstallTotal = 0;
__gshared ulong g_adminDenyTotal = 0;

private uint handleForRight(uint right) {
    switch (right) {
        case CAP_RIGHT_ADMIN_MOUNT:   return ADMIN_CAP_MOUNT_HANDLE;
        case CAP_RIGHT_ADMIN_REBOOT:  return ADMIN_CAP_REBOOT_HANDLE;
        case CAP_RIGHT_ADMIN_UPDATE:  return ADMIN_CAP_UPDATE_HANDLE;
        case CAP_RIGHT_ADMIN_USER:    return ADMIN_CAP_USER_HANDLE;
        case CAP_RIGHT_ADMIN_DEVICE:  return ADMIN_CAP_DEVICE_HANDLE;
        case CAP_RIGHT_ADMIN_INSPECT: return ADMIN_CAP_INSPECT_HANDLE;
        default: return CAP_INVALID;
    }
}

private AdminRec* recForRight(uint right) {
    foreach (ref a; g_admin)
        if (a.inUse && a.right == right) return &a;
    return null;
}

private AdminRec* recForObj(uint objId) {
    foreach (ref a; g_admin)
        if (a.inUse && a.objId == objId) return &a;
    return null;
}

private bool addAdmin(uint right) {
    uint handle = handleForRight(right);
    if (handle == CAP_INVALID) return false;
    foreach (ref a; g_admin) {
        if (a.inUse) continue;
        uint id = objAlloc(ObjType.Admin, cast(void*)&a);
        if (id == 0) return false;
        a = AdminRec.init;
        a.inUse = true;
        a.objId = id;
        a.right = right;
        a.handle = handle;
        return true;
    }
    return false;
}

public void adminInit() {
    if (g_adminInited) return;
    g_adminInited = true;
    addAdmin(CAP_RIGHT_ADMIN_MOUNT);
    addAdmin(CAP_RIGHT_ADMIN_REBOOT);
    addAdmin(CAP_RIGHT_ADMIN_UPDATE);
    addAdmin(CAP_RIGHT_ADMIN_USER);
    addAdmin(CAP_RIGHT_ADMIN_DEVICE);
    addAdmin(CAP_RIGHT_ADMIN_INSPECT);
}

public bool adminInstallCapIn(int tableId, uint right) {
    adminInit();
    auto a = recForRight(right);
    if (a is null) return false;
    if (capInstallIn(tableId, a.handle, a.objId, right, CAP_INVALID) == CAP_INVALID)
        return false;
    ++g_adminInstallTotal;
    return true;
}

// PID1/init gets only the concrete administrative actions the current kernel
// compatibility layer still needs.  There is no single "all admin" cap.
public bool adminInstallInitCaps(int tableId) {
    bool ok = true;
    ok = adminInstallCapIn(tableId, CAP_RIGHT_ADMIN_MOUNT) && ok;
    ok = adminInstallCapIn(tableId, CAP_RIGHT_ADMIN_REBOOT) && ok;
    ok = adminInstallCapIn(tableId, CAP_RIGHT_ADMIN_INSPECT) && ok;
    return ok;
}

public bool adminRequireIn(int tableId, uint right) {
    adminInit();
    uint handle = handleForRight(right);
    if (handle == CAP_INVALID) {
        ++g_adminDenyTotal;
        return false;
    }
    auto cap = capGetIn(tableId, handle);
    if (!capUsable(cap) || (cap.rights & right) != right) {
        ++g_adminDenyTotal;
        return false;
    }
    auto h = objGet(cap.objId);
    auto a = recForObj(cap.objId);
    if (h is null || h.type != ObjType.Admin || a is null || a.right != right) {
        ++g_adminDenyTotal;
        return false;
    }
    return true;
}

public bool adminRequire(uint right) {
    return adminRequireIn(g_activeCapTabId, right);
}

public void adminSelfTest() {
    if (g_adminSelfTested) return;
    g_adminSelfTested = true;
    int st = CAPTAB_COUNT - 2; // leave CAPTAB_COUNT-1 for cap/ipc selftests
    if (capLiveCount(st) != 0) return;

    bool denied = !adminRequireIn(st, CAP_RIGHT_ADMIN_MOUNT);
    bool installMount = adminInstallCapIn(st, CAP_RIGHT_ADMIN_MOUNT);
    bool mountOk = adminRequireIn(st, CAP_RIGHT_ADMIN_MOUNT);
    bool rebootDenied = !adminRequireIn(st, CAP_RIGHT_ADMIN_REBOOT);
    bool installReboot = adminInstallCapIn(st, CAP_RIGHT_ADMIN_REBOOT);
    bool rebootOk = adminRequireIn(st, CAP_RIGHT_ADMIN_REBOOT);

    capTableClear(st);

    if (denied && installMount && mountOk && rebootDenied &&
        installReboot && rebootOk)
        klog("[admin] selftest PASS\n");
    else
        klog("[admin] selftest FAIL\n");
}

public void adminStats() {
    klog("[admin] obj=");     klog_hex(cast(ulong)objCountType(ObjType.Admin));
    klog(" install=");        klog_hex(g_adminInstallTotal);
    klog(" deny=");           klog_hex(g_adminDenyTotal);
    klog("\n");
}
