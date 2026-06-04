// Linux compatibility as objects (the LinuxObject tree) — Phase 12 of
// roadmap/OBJECT_OS_ROADMAP.md.
//
// Demotes the Linux personality from "the OS" to an object *subtree* sitting on
// top of the native objects built in Phases 3–11.  The five identities the
// roadmap names exist here:
//
//   LinuxSyscallObject       — the translator.  The big `dispatchLinuxSyscall`
//                              switch in kernel_main.d is now reached *only*
//                              through this object's gate; when the subtree is
//                              disabled, Linux syscalls return -ENOSYS and the
//                              native kernel is untouched (Milestone 2 property).
//   LinuxProcessObject       — per native Process: the Linux pid view wrapper.
//   LinuxVFSObject           — the Linux path/fd view over Namespace + File/Dir.
//   LinuxELFLoaderObject     — wraps loadElf/execve.
//   LinuxDeviceAdapterObject — presents native Device objects as /dev/* nodes.
//
// In the additive spirit of the earlier phases this establishes the subtree's
// object *identity*, a real master switch the dispatcher routes through, and
// per-process wrappers — while the existing posix.d/kernel_main bodies remain the
// *implementation* the translator delegates to (those bodies already call the
// native object ops from Phases 3–11).  Physically relocating the ~1000-line
// switch would be pure churn against the highest-regression surface in the tree;
// owning and gating it through LinuxSyscallObject achieves the same demotion.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module core.linuxobj;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objRelease, objCountType;

extern (C) @nogc nothrow:

// Singleton identities of the Linux-compat subtree (0 = not yet built).
__gshared uint g_linuxSyscallObj    = 0;
__gshared uint g_linuxVfsObj        = 0;
__gshared uint g_linuxElfLoaderObj  = 0;
__gshared uint g_linuxDevAdapterObj = 0;

// The whole subtree's master switch.  The dispatcher consults `linuxEnabled()`
// before translating any Linux syscall, so the personality can be removed without
// touching the native kernel.
__gshared bool g_linuxEnabled = false;

enum int LXPROC_MAX = 64;
struct LinuxProcRec {
    bool inUse;
    uint objId;        // ObjType.LinuxProcess
    uint processObjId; // the native Process object this wraps
    int  pid;          // Linux pid view
}
__gshared LinuxProcRec[LXPROC_MAX] g_linuxProcs;

__gshared ulong g_lxTranslateTotal = 0; // Linux syscalls routed through the object
__gshared ulong g_lxBlockedTotal   = 0; // syscalls refused while subtree disabled
__gshared ulong g_lxProcReg        = 0;
__gshared ulong g_lxElfLoads       = 0;
__gshared bool  g_lxInited         = false;
__gshared bool  g_lxSelfTested     = false;

// Build the Linux-compat subtree and enable the personality.  Idempotent.
public void linuxObjectInit() {
    if (g_lxInited) return;
    g_lxInited = true;
    g_linuxSyscallObj    = objAlloc(ObjType.LinuxSyscall, null);
    g_linuxVfsObj        = objAlloc(ObjType.LinuxVFS, null);
    g_linuxElfLoaderObj  = objAlloc(ObjType.LinuxELFLoader, null);
    g_linuxDevAdapterObj = objAlloc(ObjType.LinuxDeviceAdapter, null);
    g_linuxEnabled = true;
}

// The dispatcher gate: true iff the Linux personality subtree is present & live.
public bool linuxEnabled() {
    return g_linuxEnabled && g_linuxSyscallObj != 0 &&
           objGet(g_linuxSyscallObj) !is null;
}

// Toggle the whole personality (used by the self-test; the bring-up path leaves
// it enabled).
public void linuxSetEnabled(bool on) { g_linuxEnabled = on; }

// Account one translated syscall (called by the dispatcher after the gate).
public void linuxNoteTranslate() { ++g_lxTranslateTotal; }
public void linuxNoteBlocked()   { ++g_lxBlockedTotal; }
public void linuxNoteElfLoad()   { ++g_lxElfLoads; }

private LinuxProcRec* lxProcByProcess(uint processObjId) {
    if (processObjId == 0) return null;
    foreach (ref p; g_linuxProcs)
        if (p.inUse && p.processObjId == processObjId) return &p;
    return null;
}

// Ensure a LinuxProcessObject wraps the given native Process object.  Idempotent;
// updates the cached pid view.
public uint linuxProcEnsure(uint processObjId, int pid) {
    if (processObjId == 0 || objGet(processObjId) is null) return 0;
    auto existing = lxProcByProcess(processObjId);
    if (existing !is null) { existing.pid = pid; return existing.objId; }
    foreach (ref p; g_linuxProcs) {
        if (p.inUse) continue;
        uint id = objAlloc(ObjType.LinuxProcess, cast(void*)&p);
        if (id == 0) return 0;
        p.inUse = true;
        p.objId = id;
        p.processObjId = processObjId;
        p.pid = pid;
        ++g_lxProcReg;
        return id;
    }
    return 0;
}

// Release LinuxProcess wrappers whose native Process object is gone.
public void linuxProcSweep() {
    foreach (ref p; g_linuxProcs) {
        if (!p.inUse) continue;
        if (objGet(p.processObjId) is null) {
            objRelease(p.objId);
            p = LinuxProcRec.init;
        }
    }
}

private uint lxProcLive() {
    uint n = 0;
    foreach (ref p; g_linuxProcs) if (p.inUse) ++n;
    return n;
}

// --- Boot self-test (Phase 12 runtime proof) ----------------------------------
// Confirms the four subtree singletons are live, the master gate actually gates
// (disabling it makes linuxEnabled() false without disturbing the native object
// table), and a LinuxProcess wrapper binds to a live native object id.
public void linuxSelfTest() {
    if (g_lxSelfTested || !g_lxInited) return;
    g_lxSelfTested = true;

    bool singletonsLive =
        g_linuxSyscallObj != 0 && objGet(g_linuxSyscallObj) !is null &&
        g_linuxVfsObj != 0 && objGet(g_linuxVfsObj) !is null &&
        g_linuxElfLoaderObj != 0 && objGet(g_linuxElfLoaderObj) !is null &&
        g_linuxDevAdapterObj != 0 && objGet(g_linuxDevAdapterObj) !is null;

    // The gate must flip the personality off and back on.
    bool wasEnabled = linuxEnabled();
    linuxSetEnabled(false);
    bool gatedOff = !linuxEnabled();
    linuxSetEnabled(true);
    bool gatedOn = linuxEnabled();

    // A LinuxProcess wrapper binds to a live native object (reuse the syscall
    // object id as a stand-in live Process id for the test, then release it).
    uint wrap = linuxProcEnsure(g_linuxSyscallObj, 1);
    auto pr = lxProcByProcess(g_linuxSyscallObj);
    bool procOk = (wrap != 0 && pr !is null && pr.objId == wrap &&
                   objGet(wrap) !is null);
    if (pr !is null) { objRelease(pr.objId); *pr = LinuxProcRec.init; }

    bool ok = singletonsLive && wasEnabled && gatedOff && gatedOn && procOk;
    if (ok) klog("[lx] selftest PASS\n");
    else    klog("[lx] selftest FAIL\n");
}

public void linuxStats() {
    klog("[lx] enabled=");  klog_hex(linuxEnabled() ? 1 : 0);
    klog(" lxproc=");       klog_hex(cast(ulong)lxProcLive());
    klog(" translate=");    klog_hex(g_lxTranslateTotal);
    klog(" blocked=");      klog_hex(g_lxBlockedTotal);
    klog(" elfloads=");     klog_hex(g_lxElfLoads);
    klog(" syscallobj=");   klog_hex(cast(ulong)objCountType(ObjType.LinuxSyscall));
    klog(" procobj=");      klog_hex(cast(ulong)objCountType(ObjType.LinuxProcess));
    klog("\n");
}
