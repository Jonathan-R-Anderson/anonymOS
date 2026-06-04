// Device / Driver objects — Phase 8 of roadmap/OBJECT_OS_ROADMAP.md.
//
// Wraps the kernel's free-standing driver globals as first-class **Driver** and
// **Device** objects in the central object table, and gives the synthetic
// `/dev/*` namespace a real object behind each node.  A Driver object manages a
// class of Devices; a Device object carries an ops table and a back-pointer to
// the driver-owned payload (e.g. an `AHCIDeviceInfo`, the input rings, the DRM
// device, a `NetworkDevice`).
//
// In the additive spirit of the earlier phases this layer establishes *identity*
// and *resolution* (every `/dev/*` open resolves to a Device object) plus an
// in-kernel ops table; it does not yet route block-device I/O through a File fd
// or gate access behind a capability — exposing `/dev/sd*` as a g_objOps-backed
// fd and "reachable only via caps" land with the Linux-object/rootless phases.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module core.device;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objRelease, objCountType;
import drivers.block.ahci   : g_ahciDevices, AHCIDeviceInfo;
import drivers.network.network : g_netDevice, NetworkDevice;

extern (C) @nogc nothrow:

// Broad device families — the "kind" a Driver manages and a Device belongs to.
enum DriverClass : uint {
    None = 0,
    Console,   // /dev/console, /dev/tty
    Drm,       // /dev/dri/card0, renderD128
    Input,     // /dev/input/event*
    Block,     // AHCI SATA disks
    Net,       // NIC (NetIf objects)
    Mem,       // /dev/zero
    Rng,       // /dev/random, /dev/urandom
    Count
}

enum int DEV_NAME_MAX = 48;
enum int DRIVER_MAX   = 16;
enum int DEVICE_MAX   = 64;

// Optional in-kernel block-style ops (Phase 8 "Device object ops table").  The
// File-like fd exposure that routes these through g_objOps is deferred; for now
// they are callable directly by kernel subsystems holding the Device object.
alias DevReadFn  = long function(void* impl, ulong lba, void* buf, ulong nbytes) @nogc nothrow;
alias DevWriteFn = long function(void* impl, ulong lba, const(void)* buf, ulong nbytes) @nogc nothrow;

struct DriverRecord {
    bool        inUse;
    uint        objId;       // ObjType.Driver
    DriverClass cls;
    uint        deviceCount;
    uint        nameLen;
    char[DEV_NAME_MAX] name; // e.g. "ahci", "drm", "input"
}

struct DeviceRecord {
    bool        inUse;
    uint        objId;       // ObjType.Device, or ObjType.NetIf for Net
    uint        driverObjId; // owning Driver object
    DriverClass cls;
    uint        minor;       // unit index (port / event index / card)
    void*       impl;        // driver-owned payload backing this device
    DevReadFn   read;
    DevWriteFn  write;
    ulong       opens;       // /dev fd opens resolved to this device
    uint        nameLen;
    char[DEV_NAME_MAX] name; // e.g. "/dev/dri/card0"
}

__gshared DriverRecord[DRIVER_MAX] g_drivers;
__gshared DeviceRecord[DEVICE_MAX] g_devices;

__gshared ulong g_devDriverReg     = 0;
__gshared ulong g_devDeviceReg     = 0;
__gshared ulong g_devOpenResolved  = 0;
__gshared ulong g_devOpenMiss      = 0;
__gshared bool  g_devInited        = false;
__gshared bool  g_devSelfTested    = false;

// --- small string helpers (no libc) ------------------------------------------
private uint cstrLen(const(char)* s) {
    if (s is null) return 0;
    uint n = 0;
    while (s[n] != 0 && n < DEV_NAME_MAX) ++n;
    return n;
}

private bool nameEq(ref const(char[DEV_NAME_MAX]) a, uint aLen,
                    const(char)* b, uint bLen) {
    if (aLen != bLen) return false;
    foreach (i; 0 .. aLen)
        if (a[i] != b[i]) return false;
    return true;
}

private void nameCopy(ref char[DEV_NAME_MAX] dst, const(char)* src, uint len) {
    if (len > DEV_NAME_MAX) len = DEV_NAME_MAX;
    foreach (i; 0 .. len) dst[i] = src[i];
}

// --- Driver registry ----------------------------------------------------------

public uint driverRegister(const(char)* name, DriverClass cls) {
    uint len = cstrLen(name);
    if (len == 0) return 0;
    foreach (ref d; g_drivers)
        if (d.inUse && d.cls == cls && nameEq(d.name, d.nameLen, name, len))
            return d.objId; // idempotent
    foreach (ref d; g_drivers) {
        if (d.inUse) continue;
        uint id = objAlloc(ObjType.Driver, cast(void*)&d);
        if (id == 0) return 0;
        d.inUse = true;
        d.objId = id;
        d.cls = cls;
        d.deviceCount = 0;
        d.nameLen = len;
        nameCopy(d.name, name, len);
        ++g_devDriverReg;
        return id;
    }
    return 0;
}

private DriverRecord* driverByObj(uint objId) {
    if (objId == 0) return null;
    foreach (ref d; g_drivers)
        if (d.inUse && d.objId == objId) return &d;
    return null;
}

// --- Device registry ----------------------------------------------------------

public uint deviceRegister(uint driverObjId, DriverClass cls, uint minor,
                           void* impl, const(char)* name,
                           DevReadFn rd, DevWriteFn wr) {
    uint len = cstrLen(name);
    if (len == 0) return 0;
    // Re-registration of the same name updates the backing payload in place.
    foreach (ref dev; g_devices) {
        if (dev.inUse && nameEq(dev.name, dev.nameLen, name, len)) {
            dev.impl = impl;
            dev.read = rd;
            dev.write = wr;
            return dev.objId;
        }
    }
    foreach (ref dev; g_devices) {
        if (dev.inUse) continue;
        ObjType ot = (cls == DriverClass.Net) ? ObjType.NetIf : ObjType.Device;
        uint id = objAlloc(ot, cast(void*)&dev);
        if (id == 0) return 0;
        dev.inUse = true;
        dev.objId = id;
        dev.driverObjId = driverObjId;
        dev.cls = cls;
        dev.minor = minor;
        dev.impl = impl;
        dev.read = rd;
        dev.write = wr;
        dev.opens = 0;
        dev.nameLen = len;
        nameCopy(dev.name, name, len);
        auto drv = driverByObj(driverObjId);
        if (drv !is null) ++drv.deviceCount;
        ++g_devDeviceReg;
        return id;
    }
    return 0;
}

private DeviceRecord* deviceByName(const(char)* name, uint len) {
    foreach (ref dev; g_devices)
        if (dev.inUse && nameEq(dev.name, dev.nameLen, name, len)) {
            if (objGet(dev.objId) is null) return null; // object reaped
            return &dev;
        }
    return null;
}

// Resolve a /dev path to its Device object id (0 if unknown).
public uint deviceLookupByName(const(char)* name) {
    auto dev = deviceByName(name, cstrLen(name));
    return (dev is null) ? 0 : dev.objId;
}

public DeviceRecord* deviceRecordByObj(uint objId) {
    if (objId == 0) return null;
    foreach (ref dev; g_devices)
        if (dev.inUse && dev.objId == objId) return &dev;
    return null;
}

// Called by posix.d when a `/dev/*` node is opened: ties the new fd to its
// persistent Device object and counts the resolution.  Returns the Device object
// id, or 0 when the path names no registered device (then it is a plain
// synthetic node, e.g. /dev/null).  This is the "/dev/* resolves to Device
// objects" proof.
public uint deviceNoteOpen(const(char)* path) {
    auto dev = deviceByName(path, cstrLen(path));
    if (dev is null) { ++g_devOpenMiss; return 0; }
    ++dev.opens;
    ++g_devOpenResolved;
    return dev.objId;
}

// --- Boot-time registration of the standard device tree -----------------------
// Registers the synthetic `/dev/*` nodes that actually exist at runtime (the
// ones Hyprland/musl open) plus identity objects for the AHCI block and NIC
// driver globals.  Idempotent.
public void deviceRegistryInit() {
    if (g_devInited) return;
    g_devInited = true;

    uint consoleDrv = driverRegister("console", DriverClass.Console);
    deviceRegister(consoleDrv, DriverClass.Console, 0, null, "/dev/console", null, null);
    deviceRegister(consoleDrv, DriverClass.Console, 0, null, "/dev/tty",     null, null);

    uint memDrv = driverRegister("mem", DriverClass.Mem);
    deviceRegister(memDrv, DriverClass.Mem, 0, null, "/dev/zero", null, null);

    uint rngDrv = driverRegister("rng", DriverClass.Rng);
    deviceRegister(rngDrv, DriverClass.Rng, 0, null, "/dev/random",  null, null);
    deviceRegister(rngDrv, DriverClass.Rng, 1, null, "/dev/urandom", null, null);

    uint drmDrv = driverRegister("drm", DriverClass.Drm);
    deviceRegister(drmDrv, DriverClass.Drm, 0, null, "/dev/dri/card0",      null, null);
    deviceRegister(drmDrv, DriverClass.Drm, 0, null, "/dev/dri/renderD128", null, null);

    uint inputDrv = driverRegister("input", DriverClass.Input);
    deviceRegister(inputDrv, DriverClass.Input, 0, null, "/dev/input/event0", null, null);
    deviceRegister(inputDrv, DriverClass.Input, 1, null, "/dev/input/event1", null, null);

    // AHCI: wrap the block-driver global as a Driver object, and any probed SATA
    // disk as a Block Device.  In the current boot the controller is not probed,
    // so this registers the Driver identity with zero present disks — honest, and
    // ready to populate the moment initAHCI()/probePorts() runs.
    uint ahciDrv = driverRegister("ahci", DriverClass.Block);
    static immutable char[3] sdBase = ['s','d','a'];
    foreach (i; 0 .. g_ahciDevices.length) {
        if (!g_ahciDevices[i].present) continue;
        char[DEV_NAME_MAX] nm;
        // "/dev/sd<x>" with x = 'a' + port (clamped); NUL-terminated.
        const(char)[8] pre = "/dev/sd\0";
        foreach (k; 0 .. 7) nm[k] = pre[k];
        nm[7] = cast(char)('a' + (g_ahciDevices[i].port & 0x1F));
        nm[8] = 0;
        deviceRegister(ahciDrv, DriverClass.Block, cast(uint)g_ahciDevices[i].port,
                       cast(void*)&g_ahciDevices[i], nm.ptr, null, null);
    }

    // NIC: wrap the network global as a NetIf object when a device was found.
    uint netDrv = driverRegister("net", DriverClass.Net);
    if (g_netDevice.initialized)
        deviceRegister(netDrv, DriverClass.Net, 0, cast(void*)&g_netDevice,
                       "/dev/net0", null, null);
}

// --- Boot self-test (Phase 8 runtime proof) -----------------------------------
// Confirms a driver + device register, the device resolves by its /dev name to
// the same object id, and the object is live in the central table.
public void deviceSelfTest() {
    if (g_devSelfTested) return;
    g_devSelfTested = true;

    uint card = deviceLookupByName("/dev/dri/card0");
    uint ev0  = deviceLookupByName("/dev/input/event0");
    bool ok = (card != 0 && ev0 != 0 && card != ev0 &&
               objGet(card) !is null && objGet(ev0) !is null &&
               deviceLookupByName("/dev/does/not/exist") == 0);

    if (ok) klog("[dev] selftest PASS\n");
    else    klog("[dev] selftest FAIL\n");
}

public void deviceStats() {
    klog("[dev] drivers=");  klog_hex(g_devDriverReg);
    klog(" devices=");       klog_hex(g_devDeviceReg);
    klog(" devobj=");        klog_hex(cast(ulong)objCountType(ObjType.Device));
    klog(" drvobj=");        klog_hex(cast(ulong)objCountType(ObjType.Driver));
    klog(" netif=");         klog_hex(cast(ulong)objCountType(ObjType.NetIf));
    klog(" opens=");         klog_hex(g_devOpenResolved);
    klog(" openmiss=");      klog_hex(g_devOpenMiss);
    klog("\n");
}
