module core.syscalls.posix;

import core.io : inb;
import core.console : console_putchar, console_serial_putchar, console_backspace, g_fbConsoleEnabled, console_framebuffer_write, g_desktopClaimedFb;
import core.syscalls.socket : sockaddr, sockaddr_un, msghdr, iovec, cmsghdr,
                              AF_UNIX, AF_INET, AF_NETLINK, SOCK_STREAM, SOCK_DGRAM,
                              SOL_SOCKET, SCM_RIGHTS;
import core.exports : g_module_count, g_mboot_modules, phys_to_virt,
                      g_current_task_id, d_store_task_fsbase;
import core.random;
import core.io;
import core.stdc.string : memcpy;
import core.task : g_tasks, MAX_TASKS, linuxPidForTask, linuxTidForTask,
                   objEnsureNamespace, taskIdFromLinuxPid,
                   g_taskPgid, g_taskSigCustom, deliverSignalToGroup, g_taskExecName,
                   g_sigHandler, g_sigRestorer, domainRecordWrite;   // DOMAIN_MANAGER DM6.2
import core.objmgr : ObjType, ObjHeader, objAlloc, objRetain, objRelease, objGet,
                     g_objOps, g_objOpsDispatch; // Phase 2/5 object mgr
import core.cap : Capability, CAP_INVALID,
                  CAP_RIGHT_READ, CAP_RIGHT_WRITE, CAP_RIGHT_CLOSE,
                  CAP_RIGHT_STAT, CAP_RIGHT_IOCTL, CAP_RIGHT_MMAP,
                  CAP_RIGHT_DUP, CAP_RIGHT_PASS, CAP_RIGHT_ALL,
                  CAP_RIGHT_ADMIN_MOUNT, CAP_RIGHT_ADMIN_REBOOT,
                  CAP_RIGHT_ADMIN_USER, CAP_RIGHT_ADMIN_DEVICE,
                  CAP_RIGHT_ADMIN_INSPECT,
                  capTableSetActive, capTableClear, capGet, capGetIn,
                  capInstall, capInstallIn, capClear, capClearIn,
                  capDeriveObjectTo, capDeriveObjectToIn,
                  capTableCloneNarrowing, requireCap, requireCapIn;
import core.ipc : IpcCapDesc, ipcDelegateCap, ipcAcceptCap; // Phase 7 IPC router
import core.device : deviceNoteOpen; // Phase 8: /dev resolves to Device objects
import core.namespace : nsResolveWithRights, nsResolveCheck; // Phase 9/IR-P2 + DM2 (deny vs not-found)
import core.domain : domainControlWrite,                     // DM10.3: /config/domain.action control-write executor
                     domainDeviceAllowed, domainSetDevice, domainByName, domainById, DomainId; // DM10.7
import core.identity : identityDeviceAllowed, identityByName, // DM8: §7 device-class enforcement
                       DEVCLASS_INPUT, DEVCLASS_GPU, DEVCLASS_CAMERA,
                       DEVCLASS_MIC, DEVCLASS_AUDIO, DEVCLASS_USB, DEVCLASS_NET;
import core.user : userCurrentUid, userCurrentGid, userPasswdContent,
                   userGroupContent, userByUid, userByGid,
                   userSetActiveSubject, userDefaultNameContent; // Phase 10 / IR-P3 User objects
import core.admin : adminRequire; // IR-P3 typed admin caps
import core.org : edgeEnsure, orgPruneDeadOut, edgeAdd, edgeRemove, EdgeKind,
                  orgDotContent, orgStatsContent; // ORG P3/P9/P10: edges + graph export
import arch.x86_64.limine : limine_framebuffer;
extern(C) @nogc nothrow:

// Minimal stubs if any underlying C code still references these.
// Based on previous grep, nothing outside of posix.d referenced PosixKernelShim.
// We might need to keep some symbols if they were exported and used elsewhere, 
// but the grep search for 'PosixKernelShim' was empty.

// If the linker complains about missing symbols later, we will add them here.

alias pid_t = int;
alias ssize_t = long;

extern __gshared limine_framebuffer* g_fb;

enum O_RDONLY = 0;
enum O_WRONLY = 1;
enum O_RDWR = 2;
enum O_CREAT = 64;
enum O_EXCL = 0x80;
enum O_TRUNC = 0x200;
enum O_APPEND = 0x400;
enum TCGETS = 0x5401;
enum TCSETS = 0x5402;

private enum ushort ps2DataPort = 0x60;
private enum ushort ps2StatusPort = 0x64;
private enum ubyte ps2StatusOutputFull = 0x01;

__gshared bool g_consoleShift = false;
__gshared bool g_consoleExtended = false;

// Canonical console line buffer (cooked-mode line editing in the kernel).
__gshared char[1024] g_conLine;
__gshared size_t      g_conLineLen;
__gshared bool        g_conLineReady;

// Minimal POSIX compatibility state:
// 0,1,2 are stdio; synthetic descriptors start at 3.
// __gshared int g_nextPseudoFd = 3; // Deprecated
__gshared ulong g_linuxBrk = 0x600000UL;

enum FileType {
    FD_NONE = 0,
    FD_CONSOLE,
    FD_FILE,
    FD_SOCKET,
    FD_BUNDLE,
    FD_BOOT_MODULE,
    FD_PIPE_READ,        // read end of a pipe
    FD_PIPE_WRITE,       // write end of a pipe
    FD_EPOLL,            // epoll instance
    FD_EVENTFD,          // eventfd counter
    FD_DRM,              // DRM/KMS device (/dev/dri/card0)
    FD_INPUT_EVENT,      // input event device (/dev/input/event*)
    FD_MEMFD,            // anonymous memory fd (memfd_create), mmap-able
    FD_TIMERFD,          // timerfd_create timer
    FD_ZERO,
    FD_NULL,             // /dev/null — read EOF, writes discarded
    FD_RANDOM,
    FD_URANDOM,
    FD_RTFILE,           // writable runtime-overlay (rtfs) regular file
    FD_RTDIR,            // runtime-overlay directory, enumerable with getdents64
    FD_PTY_MASTER,       // pseudo-terminal master (/dev/ptmx)
    FD_PTY_SLAVE,        // pseudo-terminal slave  (/dev/pts/N)
    FD_DOMAIN_CTL,       // DM10.3: /config/domain.action — writes are domain control commands
    FD_INSTALL_CTL,      // INSTALLER §D: /config/install.action — writes drive the in-OS installer
    FD_INSTALL_PROGRESS, // INSTALLER §D: /config/install.progress — reads return 0..1000 permille
    FD_HW_DETECT,        // DRIVERS: /config/hardware.detect — reads return the detected driver codes (PCI)
    FD_FB,               // /dev/fb0 — read the composited framebuffer (screenshot); FBIOGET_VSCREENINFO
    FD_KLOG,             // /run/klog — live read-only view of the kernel log RAM ring (core.io g_klogRing)
    FD_UPDATE_CTL,       // UPDATE U1: /config/update.action — writes drive the A/B update engine
    FD_UPDATE_STATUS,    // UPDATE U1: /config/update.status — reads return the update-engine JSON
}

struct File {
    FileType type;
    int flags;
    ulong offset;
    void* backend; // Generic pointer for driver-specific data
    ulong fileSize; // Size for bundle files or others
    uint  objId;    // Phase 2: id of the core.objmgr Object mirroring this fd (0 = none)
}

private struct BootModuleRecord {
    ulong mod_start;   // 64-bit phys: must match boot_module_record_t (modules can load >4 GiB)
    ulong mod_end;
    char[112] name;
}

static assert(BootModuleRecord.sizeof == 128);

// Per-process file-descriptor tables.  fork() must give the child an INDEPENDENT
// copy (POSIX semantics): e.g. libseat's embedded seatd forks a server and each
// side close()s only its own copy of the socketpair — with a single shared table
// those closes would tear down the connection (the seat "Could not flush" bug).
// Threads (CLONE_VM) share their process's table.  `g_fdTable` points at the
// active process's table; the syscall dispatcher selects it per task each call
// via fdtabSetActive().  FDTAB_COUNT must be >= MAX_TASKS (task.d): fdTabId is
// assigned as the task id, so a task id past this bound has NO table of its own —
// fdtabSetActive() would clamp it onto table 0 and the task would silently operate
// on the COMPOSITOR's live fds (FW13 wifi-connect freeze: MAX_TASKS was bumped to
// 256 for the NM stack, tids crossed 64, the panel forked wl-wifi-menu as tid 65,
// whose exec/fd churn closed weston's epoll out from under it -> clean exit(0)).
enum int FDTAB_COUNT = 256;
static assert(FDTAB_COUNT >= MAX_TASKS,
              "every task id must map to its own fd table (see fdtabSetActive)");
__gshared File[1024][FDTAB_COUNT] g_fdTabs;
// Active table pointer; set by fdtabSetActive() before each syscall is serviced
// (and defensively to process 0's table on first use).  &g_fdTabs[0][0] is not a
// compile-time constant, so it can't be used as a static initializer.
__gshared File* g_fdTable;

// openat() dirfd support: record the (absolute) path each fd was opened with, so openat(dirfd, relpath)
// can reconstruct dirpath + "/" + relpath.  Previously openat ignored dirfd entirely, which broke any
// program using directory-relative openat (e.g. NM's nmp_utils_sysctl_open_netdir -> openat(netdir,
// "ifindex"/"uevent") to classify wlan0 as wifi).  Parallel to g_fdTabs (not in File, to avoid bloating
// the fork-copied struct); best-effort (cleared/overwritten per open; not fork-propagated).
__gshared int g_activeFdTabId = 0;
enum int FDPATH_MAX = 160;
// '\0'-init, NOT char.init: D's char.init is 0xFF, which emits this whole array
// as ~40 MiB of initialized .data in kernel.elf — Limine's high-memory allocator
// OOMs loading the file.  Zero-filled it lands in .bss (and empty-string slots
// beat 0xFF garbage anyway).
__gshared char[FDPATH_MAX][1024][FDTAB_COUNT] g_fdPath = '\0';
__gshared char[256] g_pendingOpenPath;   // set at open() entry, stored into g_fdPath on success

// Point g_fdTable at process `fdTabId`'s table.  Called from the syscall
// dispatcher with the current task's fdTabId before each syscall is serviced.
public void fdtabSetActive(int fdTabId) {
    if (fdTabId < 0 || fdTabId >= FDTAB_COUNT) {
        // Must never happen (static assert ties FDTAB_COUNT to MAX_TASKS).  If it
        // does, clamping to table 0 aliases the task onto the compositor's fds —
        // a freeze that looks like weston exiting for no reason.  Scream first.
        if (g_fdtabRangeLogged < 8) {
            ++g_fdtabRangeLogged;
            klog("[fdtab] BUG: fdTabId out of range: "); klog_dec(cast(ulong)fdTabId);
            klog(" (clamping to 0 — task now ALIASES table 0!)\n");
        }
        fdTabId = 0;
    }
    g_activeFdTabId = fdTabId;
    g_fdTable = &g_fdTabs[fdTabId][0];
}
__gshared uint g_fdtabRangeLogged = 0;

// Bump the backing-INSTANCE refcount for fd types whose kernel instance is shared
// across fd-table copies (fork) and dups: epoll instances, eventfds, memfd records.
// Without this, ANY copy closing (e.g. a short-lived forked child exiting and
// taskCloseAllFds'ing its copied table) destroyed the instance out from under the
// parent — a forked child of the compositor killed the compositor's wayland-event-loop
// EPOLL (clients were accepted but never dispatched: no configure, dead registry) and
// reclaimed its aliased scanout MEMFDs.  Sockets/pipes already had refcounts; this
// closes the gap for the instance-table-backed types.  (Timerfds have no close-time
// destroy at all, so they are not affected.)
public void fdInstanceRef(File* f) @nogc nothrow {
    if (f is null) return;
    if (f.type == FileType.FD_EPOLL) {
        int eid = cast(int)cast(size_t)f.backend;
        if (eid >= 0 && eid < EPOLL_MAX_INSTANCES && g_epollTable[eid].inUse) ++g_epollTable[eid].refs;
    } else if (f.type == FileType.FD_EVENTFD) {
        int eid = cast(int)cast(size_t)f.backend;
        if (eid >= 0 && eid < EVENTFD_MAX && g_eventfd_inUse[eid]) ++g_eventfd_refs[eid];
    } else if (f.type == FileType.FD_MEMFD) {
        int mid = cast(int)cast(size_t)f.backend;
        if (mid >= 0 && mid < MEMFD_MAX && g_memfds[mid].inUse) ++g_memfds[mid].refs;
    } else if (f.type == FileType.FD_TIMERFD) {
        int tid = cast(int)cast(size_t)f.backend;
        if (tid >= 0 && tid < TIMERFD_MAX && g_timerfds[tid].inUse) ++g_timerfds[tid].refs;
    }
}

// fork(): copy the parent process's fd table to the child's, bumping the
// refcounts of shared kernel objects (sockets/pipes) so the child holds its own
// reference and the parent closing its copy doesn't destroy them.
public void fdtabForkCopy(int srcTabId, int dstTabId) {
    if (srcTabId < 0 || srcTabId >= FDTAB_COUNT ||
        dstTabId < 0 || dstTabId >= FDTAB_COUNT) {
        // Must never happen (static assert ties FDTAB_COUNT to MAX_TASKS).  A silent
        // return here left a forked child with NO fd table of its own; combined with
        // the fdtabSetActive clamp it then lived inside table 0 (the compositor's).
        klog("[fdtab] BUG: fork copy out of range src=");
        klog_dec(cast(ulong)srcTabId); klog(" dst="); klog_dec(cast(ulong)dstTabId); klog("\n");
        return;
    }
    if (dstTabId == srcTabId) return;
    capTableCloneNarrowing(srcTabId, dstTabId, CAP_RIGHT_ALL);
    foreach (i; 0 .. 1024) {
        g_fdTabs[dstTabId][i] = g_fdTabs[srcTabId][i];
        File* f = &g_fdTabs[dstTabId][i];
        f.objId = 0; // copied slots get child-local File objects/capabilities
        if (f.type == FileType.FD_SOCKET) {
            auto s = fileSocket(f);
            if (s !is null) ++s.refCount;
        } else if (f.type == FileType.FD_PIPE_READ) {
            auto p = getPipe(cast(size_t)pipeIdFromFd(f));
            if (p !is null) ++p.readers;
        } else if (f.type == FileType.FD_PIPE_WRITE) {
            auto p = getPipe(cast(size_t)pipeIdFromFd(f));
            if (p !is null) ++p.writers;
        } else {
            fdInstanceRef(f);   // epoll/eventfd/memfd instance refs (see helper)
        }
        if (f.type != FileType.FD_NONE)
            publishFdInTable(dstTabId, cast(int)i, f, srcTabId, cast(int)i);
    }
}
__gshared bool g_fdTableInitialized = false;
__gshared pid_t g_nextSyntheticPid = 100;

// --- Pipe infrastructure ---
private enum size_t PIPE_MAX = 64;
private enum size_t PIPE_CAPACITY = 65536;

private struct PipeBuf {
    bool inUse;
    int  readers;
    int  writers;
    size_t head;     // write position (monotonically increasing)
    size_t tail;     // read position  (monotonically increasing)
    ubyte[PIPE_CAPACITY] data;
}

__gshared PipeBuf[PIPE_MAX] g_pipes;

// --- Epoll infrastructure ---
private enum int EPOLL_MAX_INSTANCES = 16;
private enum int EPOLL_MAX_WATCHES   = 256;
private enum uint EPOLLIN_F    = 0x001;
private enum uint EPOLLOUT_F   = 0x004;
private enum uint EPOLLERR_F   = 0x008;
private enum uint EPOLLHUP_F   = 0x010;
private enum uint EPOLLRDHUP_F = 0x2000;
private enum uint EPOLLET_F    = 0x80000000;
private enum uint EPOLLONESHOT_F = 0x40000000;
private enum int  EPOLL_CTL_ADD = 1;
private enum int  EPOLL_CTL_DEL = 2;
private enum int  EPOLL_CTL_MOD = 3;
private enum int  EPOLL_MAX_NEST = 5;  // ORG 3.3 / T3: bound epoll-watching-epoll depth
private enum int  ELOOP = 40;          // returned when the nesting bound is exceeded

// Userspace struct epoll_event is PACKED on x86-64 (kernel ABI): the 8-byte
// `data` (the source pointer) is at offset 4, immediately after the 4-byte
// `events`, with NO padding.  Without align(1) D would place `data` at offset 8,
// corrupting the pointer round-trip → wl_event_loop_dispatch() then calls a
// garbage/NULL callback and faults (rip=0).
private struct EpollEvent {
align(1):                 // pack: `data` at offset 4 (right after the 4-byte
    uint  events;         // `events`), matching the x86-64 kernel epoll_event ABI.
    ulong data;           // (struct-level align(1) alone does NOT pack the fields.)
}
static assert(EpollEvent.sizeof == 12);
private struct EpollWatch { bool active; int watchFd; uint events; ulong data; }
private struct EpollInst  { bool inUse; ubyte nestDepth; uint refs; EpollWatch[EPOLL_MAX_WATCHES] watches; }

__gshared EpollInst[EPOLL_MAX_INSTANCES] g_epollTable;

// --- Eventfd infrastructure ---
private enum int EVENTFD_MAX   = 32;
private enum int EFD_SEMAPHORE = 1;
private enum int EFD_NONBLOCK  = 0x800;
private enum int EFD_CLOEXEC   = 0x80000;

__gshared ulong[EVENTFD_MAX] g_eventfd_counters;
__gshared uint[EVENTFD_MAX]  g_eventfd_refs;    // fd-copy refcount (fork/dup); destroy at 0
__gshared int[EVENTFD_MAX]   g_eventfd_flags;
__gshared bool[EVENTFD_MAX]  g_eventfd_inUse;

// ── Input event ring buffers ─────────────────────────────────────────────────
// Linux struct input_event (64-bit ABI): timeval(16) + type(2) + code(2) + value(4) = 24 bytes.
struct InputEvent {
    align(1):
    ulong  tv_sec;
    ulong  tv_usec;
    ushort type;
    ushort code;
    int    value;
}
static assert(InputEvent.sizeof == 24);

private enum size_t INPUT_RING_SIZE = 128;

struct InputRing {
    InputEvent[INPUT_RING_SIZE] events;
    uint head;  // next write slot (mod INPUT_RING_SIZE)
    uint tail;  // next read  slot (mod INPUT_RING_SIZE)
}

__gshared InputRing g_kbd_ring;    // /dev/input/event0
__gshared InputRing g_mouse_ring;  // /dev/input/event1

// R1 input-drop profiling: events enqueued / dropped (ring full) / read by clients.
__gshared ulong g_inKbdEnq, g_inKbdDrop, g_inKbdRead;
__gshared ulong g_inMouseEnq, g_inMouseDrop, g_inMouseRead;
// R2 latency: pitMs when a kbd event was read by the compositor; cleared + logged at
// the next present → the full input→screen latency, one line per input burst.
__gshared ulong g_pendingInputMs;
public void inputStats() @nogc nothrow {
    klog("[input] kbd enq="); klog_dec(g_inKbdEnq);
    klog(" drop="); klog_dec(g_inKbdDrop);
    klog(" read="); klog_dec(g_inKbdRead);
    klog(" | mouse enq="); klog_dec(g_inMouseEnq);
    klog(" drop="); klog_dec(g_inMouseDrop);
    klog(" read="); klog_dec(g_inMouseRead);
    klog("\n");
}

// Event types (from linux/input-event-codes.h)
enum ushort EV_SYN = 0;
enum ushort EV_KEY = 1;
enum ushort EV_REL = 2;
enum ushort EV_ABS = 3;
enum ushort SYN_REPORT = 0;
enum ushort REL_X = 0;
enum ushort REL_Y = 1;
enum ushort ABS_X = 0;
enum ushort ABS_Y = 1;
enum ushort BTN_LEFT   = 0x110;
enum ushort BTN_RIGHT  = 0x111;
enum ushort BTN_MIDDLE = 0x112;

public void input_enqueue(bool isKeyboard, ushort type, ushort code, int value) @nogc nothrow {
    auto ring = isKeyboard ? &g_kbd_ring : &g_mouse_ring;
    uint next = (ring.head + 1) % INPUT_RING_SIZE;
    if (next == ring.tail) {                      // full — drop event
        if (isKeyboard) ++g_inKbdDrop; else ++g_inMouseDrop;
        return;
    }
    ring.events[ring.head].tv_sec  = 0;
    ring.events[ring.head].tv_usec = 0;
    ring.events[ring.head].type    = type;
    ring.events[ring.head].code    = code;
    ring.events[ring.head].value   = value;
    ring.head = next;
    if (isKeyboard) ++g_inKbdEnq; else ++g_inMouseEnq;
}

// ── PS/2 scan-code-set-1 → Linux keycode ─────────────────────────────────────
// Scan-code-set-1 is identity-mapped to the Linux KEY_* codes for all
// standard keys (0x01–0x58), so a direct cast suffices.
public ushort g_sc1_keycode(ubyte sc) @nogc nothrow {
    if (sc >= 0x01 && sc <= 0x58) return cast(ushort)sc;
    if (sc == 0x57) return 87;  // KEY_F11
    if (sc == 0x58) return 88;  // KEY_F12
    return 0;
}

// ── Pseudo-terminal (PTY) subsystem (GUI roadmap G4) ─────────────────────────
// A minimal /dev/ptmx + /dev/pts/N implementation with a termios line
// discipline — just enough to host an interactive busybox `sh` behind the
// software terminal client. The terminal holds the master; the shell's
// stdin/stdout/stderr are the slave.
//   master write  → input discipline → echo to master-read + cooked to slave-read
//   slave write   → output discipline (ONLCR) → master-read
//   master read   ← echo + program output       slave read ← cooked input
private enum size_t PTY_MAX = 8;
private enum size_t PTY_BUF = 8192;

struct PtyRing {
    ubyte[PTY_BUF] data;
    uint head;   // write index (mod PTY_BUF)
    uint tail;   // read index
}

private bool ptyRingPush(ref PtyRing r, ubyte b) @nogc nothrow {
    uint next = cast(uint)((r.head + 1) % PTY_BUF);
    if (next == r.tail) return false; // full — drop
    r.data[r.head] = b;
    r.head = next;
    return true;
}
private int ptyRingPop(ref PtyRing r) @nogc nothrow {
    if (r.head == r.tail) return -1;
    ubyte b = r.data[r.tail];
    r.tail = cast(uint)((r.tail + 1) % PTY_BUF);
    return cast(int)b;
}

// termios flag bits we honor
private enum uint TIO_INLCR = 0x40, TIO_IGNCR = 0x80, TIO_ICRNL = 0x100;
private enum uint TIO_OPOST = 0x1,  TIO_ONLCR = 0x4;
private enum uint TIO_ICANON = 0x2, TIO_ECHO = 0x8, TIO_ISIG = 0x1;

struct Pty {
    bool      inUse;
    uint      iflag, oflag, cflag, lflag;
    ubyte[19] cc;
    ushort    rows, cols, xpix, ypix;
    int       fgPgid;      // A4: foreground process group (TIOCSPGRP) for ^C/^\ delivery
    int       lastReader;  // A4: tid of the last task to read the slave (fg job fallback)
    ubyte[PTY_BUF] line;   // canonical line accumulator
    uint      lineLen;
    PtyRing   toMaster;    // master read queue (echo + slave output)
    PtyRing   toSlave;     // slave read queue (cooked input)
}
__gshared Pty[PTY_MAX] g_ptys;

private void ptyInit(ref Pty p) @nogc nothrow {
    p = Pty.init;
    p.inUse = true;
    p.iflag = 0x0500;  // ICRNL|IXON
    p.oflag = 0x0005;  // OPOST|ONLCR
    p.cflag = 0x04bf;  // B38400|CS8|CREAD|HUPCL
    p.lflag = 0x8a3b;  // ICANON|ECHO|ECHOE|ECHOK|ISIG|IEXTEN
    p.cc[0]=3; p.cc[1]=28; p.cc[2]=127; p.cc[3]=21; p.cc[4]=4; p.cc[6]=1;
    p.cc[8]=17; p.cc[9]=19; p.cc[10]=26; p.cc[11]=255; p.cc[12]=18;
    p.cc[14]=23; p.cc[15]=22; p.cc[16]=255;
    p.rows=24; p.cols=80; p.xpix=640; p.ypix=384;
}

private int ptyAlloc() @nogc nothrow {
    foreach (i; 0 .. PTY_MAX)
        if (!g_ptys[i].inUse) { ptyInit(g_ptys[i]); return cast(int)i; }
    return -1;
}

// one byte of program output (slave → master) through output processing
private void ptyOut(ref Pty p, ubyte b) @nogc nothrow {
    if ((p.oflag & TIO_OPOST) && (p.oflag & TIO_ONLCR) && b == '\n') {
        ptyRingPush(p.toMaster, '\r');
        ptyRingPush(p.toMaster, '\n');
    } else {
        ptyRingPush(p.toMaster, b);
    }
}

private void ptyEchoErase(ref Pty p) @nogc nothrow {
    ptyRingPush(p.toMaster, '\b');
    ptyRingPush(p.toMaster, ' ');
    ptyRingPush(p.toMaster, '\b');
}

// A4: the foreground process group for ^C/^\ — the kernel-set tcsetpgrp group if the
// shell drives job control, else the effective group of the last task to read the
// slave (the running command, or the shell itself at the prompt).
private int ptyFgGroup(ref Pty p) @nogc nothrow {
    if (p.fgPgid != 0) return p.fgPgid;
    int t = p.lastReader;
    if (t <= 0 || t >= MAX_TASKS) return 0;
    return g_taskPgid[t] != 0 ? g_taskPgid[t] : linuxPidForTask(t);
}

// one byte of terminal input (master write) through the input discipline
private void ptyInputByte(ref Pty p, ubyte b) @nogc nothrow {
    if (b == '\r') {
        if (p.iflag & TIO_IGNCR) return;
        if (p.iflag & TIO_ICRNL) b = '\n';
    } else if (b == '\n' && (p.iflag & TIO_INLCR)) {
        b = '\r';
    }
    // A4: ISIG — terminal-generated signals to the foreground process group.  ^C/^\
    // discard the pending input line, echo a newline, and signal the fg job (the shell
    // and apps that catch the signal are skipped by deliverSignalToGroup).
    if (p.lflag & TIO_ISIG) {
        if (b == p.cc[0]) {            // VINTR (^C) → SIGINT (2)
            p.lineLen = 0; ptyOut(p, '\n');
            deliverSignalToGroup(ptyFgGroup(p), 2);
            return;
        }
        if (b == p.cc[1]) {            // VQUIT (^\) → SIGQUIT (3)
            p.lineLen = 0; ptyOut(p, '\n');
            deliverSignalToGroup(ptyFgGroup(p), 3);
            return;
        }
    }
    const bool canon = (p.lflag & TIO_ICANON) != 0;
    const bool echo  = (p.lflag & TIO_ECHO) != 0;
    if (canon) {
        if (b == p.cc[2] /*VERASE*/ || b == 8) {
            if (p.lineLen > 0) { p.lineLen--; if (echo) ptyEchoErase(p); }
            return;
        }
        if (b == p.cc[3] /*VKILL*/) {
            while (p.lineLen > 0) { p.lineLen--; if (echo) ptyEchoErase(p); }
            return;
        }
        if (p.lineLen < PTY_BUF - 1) p.line[p.lineLen++] = b;
        if (echo) ptyOut(p, b);
        if (b == '\n') {
            foreach (i; 0 .. p.lineLen) ptyRingPush(p.toSlave, p.line[i]);
            p.lineLen = 0;
        }
    } else {
        ptyRingPush(p.toSlave, b);
        if (echo) ptyOut(p, b);
    }
}

// termios ioctls on either PTY end operate on the shared per-pty state.
private long ptyIoctl(int idx, ulong cmd, ulong arg) @nogc nothrow {
    if (idx < 0 || idx >= PTY_MAX || !g_ptys[idx].inUse) return negErrno(EBADF);
    Pty* p = &g_ptys[idx];
    // musl's ioctl() takes a signed int request, so high-bit requests like
    // TIOCGPTN (0x80045430) arrive sign-extended to 64 bits — mask to 32.
    cmd &= 0xFFFFFFFFUL;
    switch (cmd) {
        case 0x80045430: // TIOCGPTN
            if (arg != 0) *cast(uint*)arg = cast(uint)idx;
            return 0;
        case 0x40045431: // TIOCSPTLCK (unlockpt) — always succeed
            return 0;
        case 0x5401: case 0x5405: case 0x542a: { // TCGETS / TCGETA / TCGETS2
            if (arg == 0) return negErrno(14);
            auto t = cast(uint*)arg;
            t[0] = p.iflag; t[1] = p.oflag; t[2] = p.cflag; t[3] = p.lflag;
            auto cc = cast(ubyte*)(arg + 17); // c_cc follows c_line at offset 17
            foreach (i; 0 .. 19) cc[i] = p.cc[i];
            return 0;
        }
        case 0x5402: case 0x5403: case 0x5404: case 0x542b: { // TCSETS{,W,F} / TCSETS2
            if (arg == 0) return negErrno(14);
            auto t = cast(uint*)arg;
            p.iflag = t[0]; p.oflag = t[1]; p.cflag = t[2]; p.lflag = t[3];
            auto cc = cast(ubyte*)(arg + 17);
            foreach (i; 0 .. 19) p.cc[i] = cc[i];
            return 0;
        }
        case 0x5413: // TIOCGWINSZ
            if (arg != 0) {
                auto ws = cast(ushort*)arg;
                ws[0] = p.rows; ws[1] = p.cols; ws[2] = p.xpix; ws[3] = p.ypix;
            }
            return 0;
        case 0x5414: // TIOCSWINSZ
            if (arg != 0) {
                auto ws = cast(ushort*)arg;
                p.rows = ws[0]; p.cols = ws[1]; p.xpix = ws[2]; p.ypix = ws[3];
            }
            return 0;
        case 0x540f: // TIOCGPGRP
            if (arg != 0) *cast(int*)arg = (p.fgPgid != 0) ? p.fgPgid : 1;
            return 0;
        case 0x5410: // TIOCSPGRP — set the foreground process group (for ^C/^\)
            if (arg != 0) p.fgPgid = *cast(int*)arg;
            return 0;
        case 0x540e: case 0x5422: // TIOCSCTTY / TIOCNOTTY
            return 0;
        default:
            return negErrno(25); // ENOTTY
    }
}

// True when fd is a PTY end opened in blocking mode with no data ready, so the
// syscall dispatcher should rewind+yield instead of returning EAGAIN.
public bool ptyBlockingReadFd(ulong fd) @nogc nothrow {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return false;
    auto f = &g_fdTable[ifd];
    if (f.type != FileType.FD_PTY_MASTER && f.type != FileType.FD_PTY_SLAVE) return false;
    return (f.flags & 0x800 /*O_NONBLOCK*/) == 0;
}

// True when fd is the read end of a blocking pipe that is currently empty but still
// has live writers — so the dispatcher should rewind+yield (exactly like a blocking
// PTY read) instead of surfacing EAGAIN.  zsh's fork/job-control coordination
// (exec.c execcmd_fork) does a blocking read_loop() on a `synch` pipe waiting for the
// child to report its process-group leader, and treats EAGAIN as fatal — which wedged
// every external command.  Yielding lets the forked child run and write the pipe; the
// parent's read transparently completes when it is rescheduled.  When the last writer
// closes (or the child dies, dropping its fds) writers hits 0 and the read returns EOF
// instead of blocking, so this can't spin forever.
public bool pipeBlockingReadFd(ulong fd) @nogc nothrow {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return false;
    auto f = &g_fdTable[ifd];
    if (f.type != FileType.FD_PIPE_READ) return false;
    if (f.flags & 0x800 /*O_NONBLOCK*/) return false;   // genuine non-blocking pipe: real EAGAIN
    auto pipe_ = getPipe(cast(size_t)pipeIdFromFd(f));
    if (pipe_ is null) return false;
    return (pipe_.head - pipe_.tail) == 0 && pipe_.writers > 0;
}

// ── DRM / KMS infrastructure ─────────────────────────────────────────────────
private enum size_t GEM_MAX = 64;

private struct GemBuf {
    bool   inUse;
    uint   handle;
    ulong  physAddr;   // physical address of buffer data
    uint   width;
    uint   height;
    uint   pitch;      // stride in bytes
    uint   bpp;
    ulong  size;       // total size in bytes
    uint   vmoObjId;   // Phase 3: VMO identity for mmap/PRIME aliases
}

__gshared GemBuf[GEM_MAX] g_gemBufs;
__gshared uint g_nextGemHandle = 1;

private int allocPipeId() {
    foreach (i, ref p; g_pipes) {
        if (!p.inUse) {
            p = PipeBuf.init;
            p.inUse  = true;
            p.readers = 1;
            p.writers = 1;
            return cast(int)i;
        }
    }
    return -1;
}

private PipeBuf* getPipe(size_t id) {
    if (id >= PIPE_MAX) return null;
    return g_pipes[id].inUse ? &g_pipes[id] : null;
}

private int pipeIdFromFd(File* f) {
    return cast(int)(cast(size_t)f.backend) - 1;
}

// --- CWD ---
__gshared char[4096] g_cwd_buf = "/\0";
__gshared size_t g_cwd_len = 1;

// --- Umask ---
__gshared uint g_umask = 18; // Octal 022

private enum int EPERM  = 1;
private enum int ENOENT = 2;
private enum int EINTR  = 4;
private enum int ENODEV = 19;
private enum int ENXIO  = 6;
private enum int EBADF  = 9;
private enum int ENOMEM = 12;
private enum int EEXIST = 17;
private enum int EAGAIN = 11;
private enum int EFAULT = 14;
private enum int EACCES = 13;
private enum int ENOSPC = 28;
private enum int EISDIR = 21;
private enum int EINVAL = 22;
private enum int EMFILE = 24;
private enum int EPIPE  = 32;
private enum int ENOSYS = 38;
private enum int ENAMETOOLONG = 36;
private enum int ENOTSUP = 95; // same value as EOPNOTSUPP
private enum int ERANGE  = 34;
private enum int ENOTDIR = 20;
private enum int EBUSY = 16;
private enum int ENOTEMPTY = 39;

private enum int F_ADD_SEALS = 1033;
private enum int F_GET_SEALS = 1034;
private enum int F_SEAL_SEAL = 0x0001;
private enum int F_SEAL_SHRINK = 0x0002;
private enum int F_SEAL_GROW = 0x0004;
private enum int F_SEAL_WRITE = 0x0008;
private enum int F_SEAL_FUTURE_WRITE = 0x0010;
private enum int F_SEAL_VALID_MASK = F_SEAL_SEAL | F_SEAL_SHRINK |
                                     F_SEAL_GROW | F_SEAL_WRITE |
                                     F_SEAL_FUTURE_WRITE;

private enum ulong MFD_CLOEXEC = 0x0001;
private enum ulong MFD_ALLOW_SEALING = 0x0002;
private enum ulong MFD_NOEXEC_SEAL = 0x0008;
private enum ulong MFD_EXEC = 0x0010;
private enum ulong MFD_SUPPORTED_MASK = MFD_CLOEXEC | MFD_ALLOW_SEALING |
                                        MFD_NOEXEC_SEAL | MFD_EXEC;

// --- Allocate next free FD (starting from 3) ---
private int allocFd() @nogc nothrow {
    for (int i = 3; i < 1024; i++)
        if (g_fdTable[i].type == FileType.FD_NONE) return i;
    return -1;
}

private void registerFdObjOps(ObjType t) {
    g_objOps[t].read  = &fileObjRead;
    g_objOps[t].write = &fileObjWrite;
    g_objOps[t].close = &fileObjClose;
    g_objOps[t].stat  = &fileObjStat;
    g_objOps[t].ioctl = &fileObjIoctl;
    g_objOps[t].mmap  = &fileObjMmap;
}

// One-time registration of the per-ObjType method tables (Phase 5).  Idempotent.
__gshared bool g_objOpsInited = false;
private void initObjOps() {
    if (g_objOpsInited) return;
    g_objOpsInited = true;
    registerFdObjOps(ObjType.File);
    registerFdObjOps(ObjType.Directory);
    registerFdObjOps(ObjType.Device);
    registerFdObjOps(ObjType.Vmo);
    registerFdObjOps(ObjType.Endpoint);
}

// Phase 5: fd backends still keep File.type as their Linux-compat backend tag,
// but object identity now reflects the broad object family used for dispatch.
private ObjType objTypeForFile(File* f) {
    if (f is null || f.type == FileType.FD_NONE) return ObjType.Invalid;
    if (fileIsSyntheticDirectory(f)) return ObjType.Directory;
    switch (f.type) {
        case FileType.FD_SOCKET:
            return ObjType.Endpoint;
        case FileType.FD_DRM:
        case FileType.FD_INPUT_EVENT:
        case FileType.FD_CONSOLE:
        case FileType.FD_ZERO:
        case FileType.FD_NULL:
        case FileType.FD_RANDOM:
        case FileType.FD_URANDOM:
        case FileType.FD_PTY_MASTER:
        case FileType.FD_PTY_SLAVE:
            return ObjType.Device;
        case FileType.FD_MEMFD:
            return ObjType.Vmo;
        default:
            break;
    }
    return ObjType.File;
}

private File* fileFromObj(ObjHeader* oh) {
    if (oh is null || oh.impl is null) return null;
    auto f = cast(File*)oh.impl;
    if (f.type == FileType.FD_NONE || f.objId != oh.id) return null;
    return f;
}

private ObjHeader* ensureFileObject(File* f) {
    if (f is null || f.type == FileType.FD_NONE) return null;
    initObjOps();
    ObjType want = objTypeForFile(f);
    if (want == ObjType.Invalid) return null;
    auto h = (f.objId != 0) ? objGet(f.objId) : null;
    if (h !is null && h.impl is cast(void*)f && h.type == want) return h;
    if (h !is null && h.impl is cast(void*)f) objRelease(f.objId);
    f.objId = objAlloc(want, cast(void*)f);
    return objGet(f.objId);
}

private ObjHeader* fdObjectByIndex(int fd) {
    initFdTable();
    if (fd < 0 || fd >= 1024) return null;
    File* f = &g_fdTable[fd];
    if (f.type == FileType.FD_NONE) return null;
    if (!publishActiveFd(fd)) return null;
    auto h = objGet(f.objId);
    return (h !is null && h.impl is cast(void*)f) ? h : null;
}

private ObjHeader* fdObjectByIndexWithRights(int fd, uint rights) {
    auto h = fdObjectByIndex(fd);
    if (h is null) return null;
    if (!requireCap(cast(int)g_current_task_id, cast(uint)fd, rights)) return null;
    return h;
}

private int fdIndexForFile(File* f) {
    if (f is null || g_fdTable is null) return -1;
    foreach (i; 0 .. 1024)
        if (&g_fdTable[i] is f) return cast(int)i;
    return -1;
}

private uint capRightsForFile(File* f) {
    if (f is null || f.type == FileType.FD_NONE) return 0;
    uint rights = CAP_RIGHT_CLOSE | CAP_RIGHT_STAT | CAP_RIGHT_DUP | CAP_RIGHT_PASS;
    switch (f.type) {
        case FileType.FD_INPUT_EVENT:
            // evdev: read events + EVIOC* ioctls (libinput/libevdev query the
            // device's capabilities via ioctl — without CAP_RIGHT_IOCTL every
            // EVIOC fails EBADF and libinput rejects the keyboard/mouse).
            rights |= CAP_RIGHT_READ | CAP_RIGHT_IOCTL;
            break;
        case FileType.FD_PIPE_READ:
        case FileType.FD_ZERO:
        case FileType.FD_RANDOM:
        case FileType.FD_URANDOM:
            rights |= CAP_RIGHT_READ;
            break;
        case FileType.FD_TIMERFD:
        case FileType.FD_NULL:        // /dev/null is read+write (bg-job stdin and stdout/stderr)
            rights |= CAP_RIGHT_READ | CAP_RIGHT_WRITE;
            break;
        case FileType.FD_PIPE_WRITE:
            rights |= CAP_RIGHT_WRITE;
            break;
        case FileType.FD_DRM:
            rights |= CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_IOCTL | CAP_RIGHT_MMAP;
            break;
        case FileType.FD_MEMFD:
            rights |= CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_MMAP;
            break;
        case FileType.FD_CONSOLE:
            if ((f.flags & 3) == O_WRONLY) rights |= CAP_RIGHT_WRITE;
            else rights |= CAP_RIGHT_READ | CAP_RIGHT_WRITE;
            rights |= CAP_RIGHT_IOCTL;
            break;
        case FileType.FD_PTY_MASTER:
        case FileType.FD_PTY_SLAVE:
            rights |= CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_IOCTL;
            break;
        default:
            // Preserve current Linux-shim behaviour: most compatibility
            // backends tolerate both reads and writes even when synthetic.
            rights |= CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_MMAP;
            break;
    }
    return rights & CAP_RIGHT_ALL;
}

private bool capIsRevoked(Capability* cap) {
    return cap !is null && cap.revoked != 0;
}

private bool publishFdInTable(int tableId, int fd, File* f,
                              int parentTableId, int parentFd) {
    if (fd < 0 || fd >= 1024 || f is null || f.type == FileType.FD_NONE) {
        capClearIn(tableId, cast(uint)fd);
        return false;
    }
    auto oh = ensureFileObject(f);
    if (oh is null) {
        capClearIn(tableId, cast(uint)fd);
        return false;
    }

    uint rights = capRightsForFile(f);
    if (parentTableId >= 0 && parentFd >= 0) {
        auto parent = capGetIn(parentTableId, cast(uint)parentFd);
        if (parent !is null && parent.objId != 0 && parent.revoked == 0)
            rights &= parent.rights;
    }
    capInstallIn(tableId, cast(uint)fd, oh.id, rights,
                 parentFd >= 0 ? cast(uint)parentFd : CAP_INVALID);
    return true;
}

private bool publishActiveFd(int fd) {
    if (fd < 0 || fd >= 1024 || g_fdTable is null) return false;
    auto f = &g_fdTable[fd];
    if (f.type == FileType.FD_NONE) {
        capClear(cast(uint)fd);
        return false;
    }
    auto cap = capGet(cast(uint)fd);
    if (capIsRevoked(cap)) return false;
    auto oh = ensureFileObject(f);
    if (oh is null) {
        capClear(cast(uint)fd);
        return false;
    }
    // ORG P10: keep each socket's backing object id current, so the peer Weak edge
    // and the SCM in-flight StrongRef edge can name it.
    if (f.type == FileType.FD_SOCKET) {
        auto sk = fileSocket(f);
        if (sk !is null) sk.fdObjId = oh.id;
    }
    uint rights = capRightsForFile(f);
    if (cap is null || cap.objId != oh.id || (cap.rights & rights) != rights)
        capInstall(cast(uint)fd, oh.id, rights, CAP_INVALID);
    return true;
}

private int publishActiveFdReturn(int fd) {
    publishActiveFd(fd);
    // openat() support: remember the path this fd was opened with (see g_fdPath).
    if (fd >= 0 && fd < 1024 && g_activeFdTabId >= 0 && g_activeFdTabId < FDTAB_COUNT) {
        char* dst = g_fdPath[g_activeFdTabId][fd].ptr;
        int i = 0;
        while (i < FDPATH_MAX - 1 && g_pendingOpenPath[i] != 0) { dst[i] = g_pendingOpenPath[i]; ++i; }
        dst[i] = 0;
    }
    return fd;
}

private bool deriveActiveFd(int dstFd, int srcFd) {
    if (dstFd < 0 || dstFd >= 1024 || srcFd < 0 || srcFd >= 1024 ||
        g_fdTable is null) return false;
    auto dst = &g_fdTable[dstFd];
    dst.objId = 0;
    auto oh = ensureFileObject(dst);
    if (oh is null) {
        capClear(cast(uint)dstFd);
        return false;
    }
    uint rights = capRightsForFile(dst);
    auto src = capGet(cast(uint)srcFd);
    if (src !is null && src.objId != 0 && src.revoked == 0)
        rights &= src.rights;
    capDeriveObjectTo(cast(uint)srcFd, cast(uint)dstFd, oh.id, rights);
    return true;
}

public bool fdRequireCap(ulong fd, uint rights) {
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return false;
    if (!publishActiveFd(ifd)) return false;
    return requireCap(cast(int)g_current_task_id, cast(uint)ifd, rights);
}

// Phase 2 (roadmap/OBJECT_OS_ROADMAP.md): mirror every fd of the *active*
// process's table as a core.objmgr Object, so "every fd is an entry in
// g_objects" holds without hooking each of the many fd creation/copy/close
// sites.  Reconciliation self-heals every path (open, dup, SCM_RIGHTS whole-File
// copy, fork copy, close) because it validates the object's `impl` points back
// at this exact slot: a copied/stale objId never matches, so the slot is
// re-registered, and only an object that truly backs a now-dead slot is freed.
// Called amortized from the syscall dispatcher; not on the I/O path.
public void objReconcileFds() {
    initFdTable();
    initObjOps();
    foreach (i; 0 .. 1024) {
        File* f = &g_fdTable[i];
        if (f.type == FileType.FD_NONE) {
            if (f.objId != 0) {
                auto h = objGet(f.objId);
                if (h !is null && h.impl is cast(void*)f) objRelease(f.objId);
                f.objId = 0;
            }
            capClear(cast(uint)i);
        } else {
            // Re-register if the slot is unowned, the object moved/copied away
            // (impl mismatch), or the fd's backend kind changed ObjType.
            ObjType want = objTypeForFile(f);
            auto h = (f.objId != 0) ? objGet(f.objId) : null;
            if (h is null || h.impl !is cast(void*)f || h.type != want) {
                if (h !is null && h.impl is cast(void*)f) objRelease(f.objId);
                f.objId = objAlloc(want, cast(void*)f);
            }
            publishActiveFd(cast(int)i);
        }
    }
}

// ORG P3 (ORG_ARCHITECTURE.md E6, E11): mirror the active process's fd table into
// the object reference graph as typed edges, driven from the amortized reconcile:
//   Process →(Cap, rights) fd-object               — the fd handle is a capability
//   epoll-object →(Observer) watched fd-object      — weak watch edge (depth-bounded)
// Stale Cap edges (closed fds) are pruned so the process's out-set tracks its live
// handles.  Off the I/O hot path; runs every 256 syscalls from dispatchSyscall.
public void orgReconcileFdEdges() {
    initFdTable();
    int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return;
    uint proc = g_tasks[tid].processObjId;
    if (proc == 0) return;
    for (int fd = 0; fd < 1024; fd++) {
        auto f = &g_fdTable[fd];
        if (f.type == FileType.FD_NONE || f.objId == 0) continue;
        edgeEnsure(proc, f.objId, EdgeKind.Cap, capRightsForFile(f));
        if (f.type == FileType.FD_EPOLL) {
            int eid = cast(int)cast(size_t)f.backend;
            if (eid >= 0 && eid < EPOLL_MAX_INSTANCES) {
                auto inst = &g_epollTable[eid];
                for (int i = 0; i < EPOLL_MAX_WATCHES; i++) {
                    if (!inst.watches[i].active) continue;
                    int wfd = inst.watches[i].watchFd;
                    if (wfd >= 0 && wfd < 1024 && g_fdTable[wfd].objId != 0)
                        edgeEnsure(f.objId, g_fdTable[wfd].objId, EdgeKind.Observer, 0);
                }
            }
            orgPruneDeadOut(f.objId); // drop observer edges to closed watched fds
        }
        // ORG P10: prune a socket object's stale in-flight StrongRef / peer Weak
        // edges (to senders/peers that have since closed).
        if (f.type == FileType.FD_SOCKET) orgPruneDeadOut(f.objId);
    }
    orgPruneDeadOut(proc); // drop Cap edges to fds that have since closed
}
private enum int ENOTSOCK = 88;
private enum int EDESTADDRREQ = 89;
private enum int ENOPROTOOPT = 92;
private enum int EPROTONOSUPPORT = 93;
private enum int EOPNOTSUPP = 95;
private enum int EAFNOSUPPORT = 97;
private enum int EADDRINUSE = 98;
private enum int ECONNREFUSED = 111;
private enum int EISCONN = 106;
private enum int ENOTCONN = 107;

private enum size_t localSocketMax = 128;
private enum size_t localSocketBufferCapacity = 16384;
private enum size_t localSocketPendingCapacity = 16;
private enum size_t scmRightsCapacity = 16;

private enum LocalSocketState : ubyte
{
    unused,
    created,
    bound,
    listener,
    connected,
    closed,
}

private enum int SOCK_SEQPACKET = 5;
private enum int SO_TYPE = 3;
private enum int SO_ERROR = 4;
private enum int SO_PEERCRED = 17;
private enum int SO_ACCEPTCONN = 30;
private enum int SO_PROTOCOL = 38;
private enum int SO_DOMAIN = 39;

private struct LinuxUcred {
    int pid;
    uint uid;
    uint gid;
}

private struct LocalSocketBuffer
{
    size_t head;
    size_t tail;
    ubyte[localSocketBufferCapacity] bytes;
}

private struct LocalSocket
{
    bool inUse;
    int domain;
    int type;
    int refCount;     // number of fds referencing this socket (dup-aware close)
    LocalSocketState state;
    size_t backlog;
    int peerId;
    bool peerClosed;
    // Credentials captured when this endpoint is created.  SO_PEERCRED must
    // report the PEER endpoint's owner, not whichever task happens to execute
    // getsockopt (the latter made dbus-daemon attribute every client to itself).
    int ownerPid;
    uint ownerUid;
    uint ownerGid;
    char[108] path;
    size_t pathLength;
    int[localSocketPendingCapacity] pending;
    size_t pendingHead;
    size_t pendingTail;
    LocalSocketBuffer rx;
    // SCM_RIGHTS: File structs passed to this socket via sendmsg ancillary data,
    // waiting to be picked up by the peer's recvmsg.  Each entry is a full copy
    // of the sender's File (so the backend id survives even if the sender closes
    // its own fd).  Queued on the *receiver* socket's rx side.  The parallel
    // `passedCaps` ring carries the delegated **capability descriptor**
    // ({objId, rights}) routed through the Phase 7 IPC router — fd passing is now
    // capability delegation, not a raw Capability-struct copy.
    File[scmRightsCapacity] passedFiles;
    IpcCapDesc[scmRightsCapacity] passedCaps;
    size_t passedHead;
    size_t passedTail;
    // ORG P10: the object id of the fd backing this socket (for the peer Weak edge
    // E9 and the SCM in-flight StrongRef edge E10).  0 until the fd is published.
    uint fdObjId;
}

__gshared LocalSocket[localSocketMax] g_localSockets;

private void resetLocalSocket(ref LocalSocket sock)
{
    sock = LocalSocket.init;
    sock.peerId = -1;
    foreach (i; 0 .. sock.pending.length)
    {
        sock.pending[i] = -1;
    }
}

private LocalSocket* localSocketById(int id)
{
    if (id < 0 || id >= cast(int)localSocketMax)
    {
        return null;
    }

    auto sock = &g_localSockets[id];
    return sock.inUse ? sock : null;
}

private int allocLocalSocket(int domain, int type)
{
    foreach (i, ref sock; g_localSockets)
    {
        if (!sock.inUse)
        {
            resetLocalSocket(sock);
            sock.inUse = true;
            sock.domain = domain;
            sock.type = type;
            sock.state = LocalSocketState.created;
            sock.ownerPid = linuxPidForTask(cast(int)g_current_task_id);
            sock.ownerUid = userCurrentUid();
            sock.ownerGid = userCurrentGid();
            return cast(int)i;
        }
    }
    return -1;
}

private int fileSocketId(File* f)
{
    if (f is null || f.type != FileType.FD_SOCKET || f.backend is null)
    {
        return -1;
    }

    const size_t raw = cast(size_t)f.backend;
    if (raw == 0)
    {
        return -1;
    }
    return cast(int)(raw - 1);
}

private LocalSocket* fileSocket(File* f)
{
    return localSocketById(fileSocketId(f));
}

private int allocSocketFd(int socketId, int flags)
{
    initFdTable();
    for (int i = 3; i < 1024; ++i)
    {
        if (g_fdTable[i].type == FileType.FD_NONE)
        {
            g_fdTable[i].type = FileType.FD_SOCKET;
            g_fdTable[i].flags = flags;
            g_fdTable[i].offset = 0;
            g_fdTable[i].backend = cast(void*)(cast(size_t)socketId + 1);
            g_fdTable[i].fileSize = 0;
            auto s = localSocketById(socketId);
            if (s !is null) ++s.refCount;   // dup-aware lifetime
            return i;
        }
    }
    return -1;
}

private size_t unixPathLength(const(sockaddr_un)* addr, uint addrlen)
{
    if (addr is null || addrlen <= ushort.sizeof)
    {
        return 0;
    }

    size_t maxLen = addrlen - ushort.sizeof;
    if (maxLen > addr.sun_path.length)
    {
        maxLen = addr.sun_path.length;
    }

    size_t len = 0;
    while (len < maxLen && addr.sun_path[len] != 0)
    {
        ++len;
    }
    return len;
}

private void copyUnixPath(ref LocalSocket sock, const(sockaddr_un)* addr, size_t len)
{
    sock.pathLength = len;
    foreach (i; 0 .. len)
    {
        sock.path[i] = addr.sun_path[i];
    }
    if (len < sock.path.length)
    {
        sock.path[len] = 0;
    }
}

private bool unixPathEquals(ref const(LocalSocket) sock, const(sockaddr_un)* addr, size_t len)
{
    if (sock.pathLength != len)
    {
        return false;
    }

    foreach (i; 0 .. len)
    {
        if (sock.path[i] != addr.sun_path[i])
        {
            return false;
        }
    }
    return true;
}

private bool unixAddrEqualsLiteral(const(sockaddr_un)* addr, size_t len, string literal)
{
    if (addr is null || len != literal.length) return false;
    foreach (i; 0 .. literal.length)
    {
        if (addr.sun_path[i] != literal[i]) return false;
    }
    return true;
}

private bool unixPathInUse(const(sockaddr_un)* addr, size_t len)
{
    foreach (ref sock; g_localSockets)
    {
        if (!sock.inUse || sock.pathLength != len)
        {
            continue;
        }
        if (sock.state == LocalSocketState.bound || sock.state == LocalSocketState.listener)
        {
            if (unixPathEquals(sock, addr, len))
            {
                return true;
            }
        }
    }
    return false;
}

private LocalSocket* findUnixListenerExact(const(sockaddr_un)* addr, size_t len)
{
    foreach (ref sock; g_localSockets)
    {
        if (!sock.inUse || sock.state != LocalSocketState.listener || sock.domain != AF_UNIX)
        {
            continue;
        }
        if (unixPathEquals(sock, addr, len))
        {
            return &sock;
        }
    }
    return null;
}

private LocalSocket* findUnixListenerCString(const(char)* path)
{
    if (path is null) return null;

    size_t len = 0;
    while (path[len] != 0) ++len;
    if (len == 0) return null;

    foreach (ref sock; g_localSockets)
    {
        if (!sock.inUse || sock.state != LocalSocketState.listener ||
            sock.domain != AF_UNIX || sock.pathLength != len)
        {
            continue;
        }

        bool match = true;
        foreach (i; 0 .. len)
        {
            if (sock.path[i] != path[i])
            {
                match = false;
                break;
            }
        }
        if (match) return &sock;
    }
    return null;
}

private LocalSocket* findUnixListener(const(sockaddr_un)* addr, size_t len)
{
    // Hyprland intentionally starts its display search at wayland-1. Keep the
    // boot environment stable for first clients by aliasing wayland-0 to that
    // live listener when it is the compositor's chosen socket. Prefer this
    // alias over the kernel bring-up bridge's wayland-0 listener; GUI clients
    // need Hyprland's registry, not the legacy bridge.
    if (unixAddrEqualsLiteral(addr, len, "/run/user/1000/wayland-0")) {
        auto hyprland = findUnixListenerCString("/run/user/1000/wayland-1\0".ptr);
        if (hyprland !is null) return hyprland;
    }

    auto exact = findUnixListenerExact(addr, len);
    if (exact !is null) return exact;

    return null;
}

public bool unixSocketListenerReady(const(char)* path)
{
    if (cstrEq(path, "/run/user/1000/wayland-0"))
        return findUnixListenerCString("/run/user/1000/wayland-1\0".ptr) !is null;
    if (findUnixListenerCString(path) !is null) return true;
    return false;
}

private bool pendingQueueEmpty(ref LocalSocket sock)
{
    return sock.pendingHead == sock.pendingTail;
}

private bool pendingQueuePush(ref LocalSocket sock, int value)
{
    const size_t nextTail = (sock.pendingTail + 1) % localSocketPendingCapacity;
    if (nextTail == sock.pendingHead)
    {
        return false;
    }

    const size_t active = (sock.pendingTail + localSocketPendingCapacity - sock.pendingHead) % localSocketPendingCapacity;
    if (sock.backlog != 0 && active >= sock.backlog)
    {
        return false;
    }

    sock.pending[sock.pendingTail] = value;
    sock.pendingTail = nextTail;
    return true;
}

private int pendingQueuePop(ref LocalSocket sock)
{
    if (pendingQueueEmpty(sock))
    {
        return -1;
    }

    const int value = sock.pending[sock.pendingHead];
    sock.pending[sock.pendingHead] = -1;
    sock.pendingHead = (sock.pendingHead + 1) % localSocketPendingCapacity;
    return value;
}

private size_t socketBufferReadable(ref LocalSocketBuffer buf)
{
    return buf.head - buf.tail;
}

private size_t socketBufferWritable(ref LocalSocketBuffer buf)
{
    return localSocketBufferCapacity - socketBufferReadable(buf);
}

private size_t socketBufferWrite(ref LocalSocketBuffer buf, const(ubyte)* src, size_t len)
{
    size_t written = len;
    const size_t freeBytes = socketBufferWritable(buf);
    if (written > freeBytes)
    {
        written = freeBytes;
    }

    foreach (i; 0 .. written)
    {
        buf.bytes[buf.head % localSocketBufferCapacity] = src[i];
        ++buf.head;
    }
    return written;
}

private size_t socketBufferRead(ref LocalSocketBuffer buf, ubyte* dst, size_t len)
{
    size_t read = len;
    const size_t available = socketBufferReadable(buf);
    if (read > available)
    {
        read = available;
    }

    foreach (i; 0 .. read)
    {
        dst[i] = buf.bytes[buf.tail % localSocketBufferCapacity];
        ++buf.tail;
    }
    return read;
}

private void releaseLocalSocket(int socketId)
{
    auto sock = localSocketById(socketId);
    if (sock is null)
    {
        return;
    }
    resetLocalSocket(*sock);
}

private void closeLocalSocket(File* f)
{
    auto sock = fileSocket(f);
    const int socketId = fileSocketId(f);
    if (sock is null || socketId < 0)
    {
        return;
    }

    // Dup-aware: only really close when the last fd referencing this socket goes
    // away.  Otherwise a dup (e.g. libseat's embedded seatd duplicating its
    // connection fd and closing the original) would tear down the live connection.
    if (sock.refCount > 0) --sock.refCount;
    if (sock.refCount > 0)
        return;

    if (sock.state == LocalSocketState.listener || sock.state == LocalSocketState.bound || sock.state == LocalSocketState.created)
    {
        releaseLocalSocket(socketId);
        return;
    }

    if (sock.peerId >= 0)
    {
        auto peer = localSocketById(sock.peerId);
        if (peer !is null)
        {
            peer.peerClosed = true;
        }
    }

    sock.state = LocalSocketState.closed;
    sock.peerClosed = true;
    sock.peerId = -1;
    sock.pathLength = 0;
}

private ssize_t localSocketRead(File* f, void* buffer, size_t length)
{
    auto sock = fileSocket(f);
    if (sock is null)
    {
        return negErrno(EBADF);
    }
    if (buffer is null && length != 0)
    {
        return negErrno(EFAULT);
    }
    if (sock.state != LocalSocketState.connected && sock.state != LocalSocketState.closed)
    {
        return negErrno(ENOTCONN);
    }

    const size_t available = socketBufferReadable(sock.rx);
    if (available == 0)
    {
        if (sock.peerClosed || sock.state == LocalSocketState.closed)
        {
            return 0;
        }
        return negErrno(EAGAIN);
    }

    const size_t read = socketBufferRead(sock.rx, cast(ubyte*)buffer, length);
    return cast(ssize_t)read;
}

private ssize_t localSocketWrite(File* f, const(void)* buffer, size_t length)
{
    auto sock = fileSocket(f);
    if (sock is null)
    {
        return negErrno(EBADF);
    }
    if (buffer is null && length != 0)
    {
        return negErrno(EFAULT);
    }
    if (sock.state != LocalSocketState.connected)
    {
        return negErrno(ENOTCONN);
    }
    if (sock.peerId < 0)
    {
        return negErrno(EPIPE);
    }

    auto peer = localSocketById(sock.peerId);
    if (peer is null || peer.state == LocalSocketState.closed)
    {
        return negErrno(EPIPE);
    }

    const size_t written = socketBufferWrite(peer.rx, cast(const(ubyte)*)buffer, length);
    if (written == 0 && length != 0)
    {
        return negErrno(EAGAIN);
    }
    return cast(ssize_t)written;
}

private long copySockoptInt(ulong val, ulong len, int outValue)
{
    if (val == 0 || len == 0) return negErrno(EFAULT);
    auto optLen = cast(uint*)len;
    if (*optLen < int.sizeof) return negErrno(EINVAL);
    *cast(int*)val = outValue;
    *optLen = cast(uint)int.sizeof;
    return 0;
}

private long copySockoptUcred(ulong val, ulong len, LocalSocket* sock = null)
{
    if (val == 0 || len == 0) return negErrno(EFAULT);
    auto optLen = cast(uint*)len;
    if (*optLen < LinuxUcred.sizeof) return negErrno(EINVAL);
    auto cred = cast(LinuxUcred*)val;
    auto peer = (sock !is null && sock.peerId >= 0) ? localSocketById(sock.peerId) : null;
    if (peer !is null) {
        cred.pid = peer.ownerPid;
        cred.uid = peer.ownerUid;
        cred.gid = peer.ownerGid;
    } else {
        cred.pid = linuxPidForTask(cast(int)g_current_task_id);
        cred.uid = userCurrentUid();
        cred.gid = userCurrentGid();
    }
    *optLen = cast(uint)LinuxUcred.sizeof;
    return 0;
}

// Install console stdin/stdout/stderr (fds 0/1/2) into a specific process fd table.
// Used for kernel-spawned processes (for example, the GUI G1 wl-probe) so their
// write(1)/(2) reach the serial console without going through initFdTable().
public void fdtabSetupConsoleStdio(int tableId) {
    if (tableId < 0 || tableId >= g_fdTabs.length) return;

    g_fdTabs[tableId][0] = File.init;
    g_fdTabs[tableId][0].type = FileType.FD_CONSOLE;
    g_fdTabs[tableId][0].flags = O_RDONLY;
    publishFdInTable(tableId, 0, &g_fdTabs[tableId][0], -1, -1);

    g_fdTabs[tableId][1] = File.init;
    g_fdTabs[tableId][1].type = FileType.FD_CONSOLE;
    g_fdTabs[tableId][1].flags = O_WRONLY;
    publishFdInTable(tableId, 1, &g_fdTabs[tableId][1], -1, -1);

    g_fdTabs[tableId][2] = File.init;
    g_fdTabs[tableId][2].type = FileType.FD_CONSOLE;
    g_fdTabs[tableId][2].flags = O_WRONLY;
    publishFdInTable(tableId, 2, &g_fdTabs[tableId][2], -1, -1);
}

void initFdTable() {
    if (g_fdTable is null) g_fdTable = &g_fdTabs[0][0];   // process 0's table
    if (g_fdTableInitialized) return;
    g_fdTable[0].type = FileType.FD_CONSOLE;
    g_fdTable[0].flags = O_RDONLY;
    
    g_fdTable[1].type = FileType.FD_CONSOLE;
    g_fdTable[1].flags = O_WRONLY;
    
    g_fdTable[2].type = FileType.FD_CONSOLE;
    g_fdTable[2].flags = O_WRONLY;

    // Mark initialised BEFORE rtInit so the rtfs builders (rtSymlinkCreate etc.) that
    // call initFdTable() re-enter as a no-op instead of recursively re-running setup
    // and tripping the self-test before /bin is fully seeded.
    g_fdTableInitialized = true;

    rtInit();   // build the writable runtime-filesystem skeleton (/run, /tmp, /bin, …)

    publishActiveFd(0);
    publishActiveFd(1);
    publishActiveFd(2);

    rtfsSelfTest();   // Track A A2/A3: one-shot RT-filesystem self-test (now safe: init done)
}

private int negErrno(int n) {
    return -n;
}

private bool consoleDataReady() {
    return (inb(ps2StatusPort) & ps2StatusOutputFull) != 0;
}

// True if fd refers to the console (tty).  Used by the syscall dispatcher to
// decide whether a read() returning EAGAIN should be restarted+yielded.
public bool isConsoleFd(ulong fd) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return false;
    return g_fdTable[ifd].type == FileType.FD_CONSOLE;
}

private ubyte consoleReadScancode() {
    return inb(ps2DataPort);
}

private char translateConsoleScancode(ubyte code) {
    switch (code) {
        case 0x1C: return '\n';
        case 0x39: return ' ';
        case 0x0E: return '\b';
        case 0x0F: return '\t';

        case 0x10: return g_consoleShift ? 'Q' : 'q';
        case 0x11: return g_consoleShift ? 'W' : 'w';
        case 0x12: return g_consoleShift ? 'E' : 'e';
        case 0x13: return g_consoleShift ? 'R' : 'r';
        case 0x14: return g_consoleShift ? 'T' : 't';
        case 0x15: return g_consoleShift ? 'Y' : 'y';
        case 0x16: return g_consoleShift ? 'U' : 'u';
        case 0x17: return g_consoleShift ? 'I' : 'i';
        case 0x18: return g_consoleShift ? 'O' : 'o';
        case 0x19: return g_consoleShift ? 'P' : 'p';
        case 0x1A: return g_consoleShift ? '{' : '[';
        case 0x1B: return g_consoleShift ? '}' : ']';

        case 0x1E: return g_consoleShift ? 'A' : 'a';
        case 0x1F: return g_consoleShift ? 'S' : 's';
        case 0x20: return g_consoleShift ? 'D' : 'd';
        case 0x21: return g_consoleShift ? 'F' : 'f';
        case 0x22: return g_consoleShift ? 'G' : 'g';
        case 0x23: return g_consoleShift ? 'H' : 'h';
        case 0x24: return g_consoleShift ? 'J' : 'j';
        case 0x25: return g_consoleShift ? 'K' : 'k';
        case 0x26: return g_consoleShift ? 'L' : 'l';
        case 0x27: return g_consoleShift ? ':' : ';';
        case 0x28: return g_consoleShift ? '"' : '\'';
        case 0x2B: return g_consoleShift ? '|' : '\\';

        case 0x2C: return g_consoleShift ? 'Z' : 'z';
        case 0x2D: return g_consoleShift ? 'X' : 'x';
        case 0x2E: return g_consoleShift ? 'C' : 'c';
        case 0x2F: return g_consoleShift ? 'V' : 'v';
        case 0x30: return g_consoleShift ? 'B' : 'b';
        case 0x31: return g_consoleShift ? 'N' : 'n';
        case 0x32: return g_consoleShift ? 'M' : 'm';
        case 0x33: return g_consoleShift ? '<' : ',';
        case 0x34: return g_consoleShift ? '>' : '.';
        case 0x35: return g_consoleShift ? '?' : '/';

        case 0x02: return g_consoleShift ? '!' : '1';
        case 0x03: return g_consoleShift ? '@' : '2';
        case 0x04: return g_consoleShift ? '#' : '3';
        case 0x05: return g_consoleShift ? '$' : '4';
        case 0x06: return g_consoleShift ? '%' : '5';
        case 0x07: return g_consoleShift ? '^' : '6';
        case 0x08: return g_consoleShift ? '&' : '7';
        case 0x09: return g_consoleShift ? '*' : '8';
        case 0x0A: return g_consoleShift ? '(' : '9';
        case 0x0B: return g_consoleShift ? ')' : '0';
        case 0x0C: return g_consoleShift ? '_' : '-';
        case 0x0D: return g_consoleShift ? '+' : '=';
        case 0x29: return g_consoleShift ? '~' : '`';

        default: return '\0';
    }
}

private char consolePollChar(bool block) {
    while (true) {
        if (!consoleDataReady()) {
            if (block) {
                asm @nogc nothrow { nop; }
                continue;
            }
            return '\0';
        }

        // Bit 5 (0x20) of the PS/2 status register set => the pending byte came
        // from the auxiliary device (mouse), not the keyboard.  Phase 2 enabled
        // the mouse, whose packets share port 0x60; drain and discard them here
        // so they aren't mistranslated as scancodes (which flooded the console
        // with garbage).  Real mouse handling lives in the IRQ12 path.
        if (inb(ps2StatusPort) & 0x20) {
            consoleReadScancode(); // discard mouse byte to clear the buffer
            if (!block) return '\0';
            asm @nogc nothrow { nop; }
            continue;
        }

        const ubyte code = consoleReadScancode();
        if (code == 0xE0) {
            g_consoleExtended = true;
            continue;
        }

        if (g_consoleExtended) {
            g_consoleExtended = false;
            continue;
        }

        if (code == 0x2A || code == 0x36) {
            g_consoleShift = true;
            continue;
        }
        if (code == 0xAA || code == 0xB6) {
            g_consoleShift = false;
            continue;
        }
        if ((code & 0x80) != 0) {
            continue;
        }

        const char c = translateConsoleScancode(code);
        if (c != '\0') {
            return c;
        }
    }
}


private long fileObjRead(ObjHeader* oh, void* _buf, ulong _count) {
    File* f = fileFromObj(oh);
    if (f is null) return negErrno(EBADF);
    ++g_objOpsDispatch;

    if (f.type == FileType.FD_NULL) {
        return 0;   // /dev/null always reads EOF
    }

    if (f.type == FileType.FD_ZERO) {
        auto buffer = cast(ubyte*)_buf;

        foreach (i; 0 .. _count)
        {
            buffer[i] = 0;
        }
        return cast(ssize_t)_count;
    }

    if (f.type == FileType.FD_URANDOM || f.type == FileType.FD_RANDOM) {
        random_get_bytes(_buf, cast(ulong)_count);
        return cast(ssize_t)_count;
    }

    // /dev/fb0 — stream the composited framebuffer as width*height*4 XRGB8888 bytes, row by row
    // (skipping any scanline padding so the logical stride is exactly width*4).  Used by the
    // Screenshot app: it reads the whole thing and PNG-encodes it.
    if (f.type == FileType.FD_FB) {
        import display.framebuffer : g_fb;
        if (_buf is null || g_fb.addr is null) return 0;
        const ulong rowLog = cast(ulong)g_fb.width * 4;               // logical bytes per row (no padding)
        const ulong total  = rowLog * g_fb.height;
        if (f.offset >= total) return 0;                              // EOF
        ulong want = _count;
        if (f.offset + want > total) want = total - f.offset;
        auto dst = cast(ubyte*)_buf;
        ulong done = 0;
        while (done < want) {
            const ulong pos  = f.offset + done;
            const ulong row  = pos / rowLog;
            const ulong col  = pos % rowLog;                          // byte within the row
            ulong chunk = rowLog - col;                               // rest of this row
            if (chunk > want - done) chunk = want - done;
            auto src = g_fb.addr + row * g_fb.pitch + col;            // pitch = real (padded) stride
            foreach (i; 0 .. chunk) dst[done + i] = src[i];
            done += chunk;
        }
        f.offset += done;
        return cast(ssize_t)done;
    }

    // INSTALLER §D: /config/install.progress — the install progress as a decimal string (then
    // EOF), polled by the installer GUI: -1 = FAILED, 0 = never started, 1..1000 permille.
    if (f.type == FileType.FD_INSTALL_PROGRESS) {
        import drivers.veracrypt_impl : installProgressPermille;
        if (f.offset > 0 || _buf is null) return 0;
        char[8] d; int n = 0;
        const int sv = installProgressPermille();
        uint v = (sv < 0) ? cast(uint)(-sv) : cast(uint)sv;
        if (sv < 0) d[n++] = '-';
        if (v == 0) { d[n++] = '0'; }
        else { char[8] r; int rn = 0; uint x = v; while (x > 0) { r[rn++] = cast(char)('0' + x % 10); x /= 10; } while (rn > 0) d[n++] = r[--rn]; }
        d[n++] = '\n';
        ulong w = (cast(ulong)n < _count) ? cast(ulong)n : _count;
        auto buffer = cast(ubyte*)_buf;
        foreach (i; 0 .. w) buffer[i] = cast(ubyte)d[cast(size_t)i];
        f.offset += w;
        return cast(ssize_t)w;
    }

    // UPDATE U1: /config/update.status — render the update-engine JSON once, stream on
    // successive reads (offset-based), EOF at end.  Small (<512B), so a static buffer.
    if (f.type == FileType.FD_UPDATE_STATUS) {
        import core.sysupdate : updateStatusRender;
        if (_buf is null) return negErrno(EFAULT);
        __gshared char[512] ubuf;
        __gshared long ulen = -1;
        if (f.offset == 0) ulen = updateStatusRender(ubuf.ptr, ubuf.length);
        if (ulen < 0) return 0;
        if (f.offset >= cast(ulong)ulen) return 0;               // caught up → EOF
        const ulong avail = cast(ulong)ulen - f.offset;
        const ulong want  = (_count < avail) ? _count : avail;
        auto dst = cast(ubyte*)_buf;
        foreach (i; 0 .. want) dst[i] = cast(ubyte)ubuf[cast(size_t)(f.offset + i)];
        f.offset += want;
        return cast(ssize_t)want;
    }

    // DRIVERS: /config/hardware.detect — return the comma-separated Linux driver codes for the PCI
    // devices present, streamed by f.offset so any buffer size works, then EOF.
    if (f.type == FileType.FD_HW_DETECT) {
        import drivers.pci : detectDriverCodes;
        if (_buf is null) return negErrno(EFAULT);
        char[256] hb;
        size_t hn = detectDriverCodes(hb.ptr, hb.length);
        if (f.offset >= hn) return 0;   // EOF
        size_t avail = hn - cast(size_t)f.offset;
        ulong w = (cast(ulong)avail < _count) ? cast(ulong)avail : _count;
        auto buffer = cast(ubyte*)_buf;
        foreach (i; 0 .. w) buffer[i] = cast(ubyte)hb[cast(size_t)f.offset + cast(size_t)i];
        f.offset += w;
        return cast(ssize_t)w;
    }

    // /run/klog — the kernel log RAM ring (klog + all FD_CONSOLE stdout/stderr + *.log mirrors),
    // streamed live so the desktop Logs viewer shows the full boot + iwlwifi bring-up.  f.offset is
    // a MONOTONIC stream coordinate; we serve [offset, head) and skip any bytes already overwritten
    // by the drop-oldest ring (a lagging reader loses the oldest data, it never blocks).
    if (f.type == FileType.FD_KLOG) {
        import core.io : g_klogRing, g_klogHead, KLOG_RING_SIZE;
        if (_buf is null) return negErrno(EFAULT);
        const ulong head   = g_klogHead;                                   // live end (snapshot)
        const ulong oldest = (head > KLOG_RING_SIZE) ? head - KLOG_RING_SIZE : 0;
        if (f.offset < oldest) f.offset = oldest;                          // reader lagged → skip lost bytes
        if (f.offset >= head) return 0;                                    // caught up → EOF-for-now (viewer re-polls)
        const ulong avail = head - f.offset;
        const ulong want  = (_count < avail) ? _count : avail;
        auto dst = cast(ubyte*)_buf;
        foreach (i; 0 .. want)
            dst[i] = g_klogRing[cast(size_t)((f.offset + i) & (KLOG_RING_SIZE - 1))];
        f.offset += want;
        return cast(ssize_t)want;
    }

    if (f.type == FileType.FD_SOCKET) {
        return localSocketRead(f, _buf, _count);
    }

    if (fileIsSyntheticDirectory(f)) {
        return negErrno(EISDIR);
    }
    
    if (f.type == FileType.FD_CONSOLE) {
        if (_buf is null) return negErrno(14);
        if (_count == 0) return 0;

        // Canonical (cooked) line discipline.  Accumulate a line in a kernel
        // buffer, handling backspace (0x08) / DEL (0x7f) by erasing the last
        // character, and only deliver bytes to userspace once Enter is pressed.
        // busybox/ash relies on the kernel for echo + line editing; without this
        // a backspace was stored as a literal 0x08 byte in the command line
        // (e.g. "/opos\b\b\b\bcompositor"), so corrected typos produced bogus
        // paths.  While no complete line is ready we return EAGAIN; the syscall
        // dispatcher rewinds RIP and yields so other tasks still run (the
        // cooperative scheduler must not spin in-kernel with IF masked).
        // consolePollChar(false) also drains mouse (aux) bytes so they are never
        // mistaken for keystrokes.
        if (!g_conLineReady) {
            while (true) {
                const char c = consolePollChar(false);
                if (c == '\0') break;                  // no more input right now
                if (c == '\b' || c == 0x7f) {           // backspace / DEL → erase
                    if (g_conLineLen > 0) {
                        g_conLineLen--;
                        console_backspace();
                    }
                    continue;
                }
                if (g_conLineLen < g_conLine.length - 1)
                    g_conLine[g_conLineLen++] = c;
                console_putchar(c);
                if (c == '\n') { g_conLineReady = true; break; }
            }
        }
        if (!g_conLineReady) return negErrno(EAGAIN);

        // Deliver the buffered line, possibly across several read() calls.
        char* bufPtr = cast(char*)_buf;
        size_t n = 0;
        while (n < _count && n < g_conLineLen) {
            bufPtr[n] = g_conLine[n];
            n++;
        }
        if (n >= g_conLineLen) {
            g_conLineLen   = 0;
            g_conLineReady = false;
        } else {
            for (size_t i = 0; i + n < g_conLineLen; i++)
                g_conLine[i] = g_conLine[i + n];
            g_conLineLen -= n;
        }
        return cast(ssize_t)n;
    }
    
    if (f.type == FileType.FD_BUNDLE) {
        long read = bundleRead(cast(ulong)f.backend, f.fileSize, f.offset, _buf, _count);
        if (read > 0) {
            f.offset += read;
        }
        return cast(ssize_t)read;
    }

    if (f.type == FileType.FD_BOOT_MODULE) {
        long read = bootModuleRead(cast(ulong)f.backend, f.fileSize, f.offset, _buf, _count);
        if (read > 0) {
            f.offset += read;
        }
        return cast(ssize_t)read;
    }

    // Virtual file (backend > 2 is a pointer into static string data)
    if (f.type == FileType.FD_FILE && cast(size_t)f.backend > fileBackendDirectory) {
        auto content = cast(const(ubyte)*)f.backend;
        size_t fsize = f.fileSize;
        if (f.offset >= fsize) return 0; // EOF
        size_t remaining = fsize - cast(size_t)f.offset;
        size_t toRead = _count < remaining ? cast(size_t)_count : remaining;
        auto dst = cast(ubyte*)_buf;
        for (size_t i = 0; i < toRead; ++i)
            dst[i] = content[f.offset + i];
        f.offset += toRead;
        return cast(ssize_t)toRead;
    }

    if (f.type == FileType.FD_RTFILE) {
        const int idx = cast(int)cast(size_t)f.backend;
        if (idx < 0 || idx >= RT_MAX_NODES || g_rt[idx].kind != RT_REG)
            return negErrno(EBADF);
        const uint sz = g_rt[idx].size;
        if (f.offset >= sz) return 0;                       // EOF
        size_t remaining = sz - cast(size_t)f.offset;
        size_t toRead = _count < remaining ? cast(size_t)_count : remaining;
        auto dst = cast(ubyte*)_buf;
        for (size_t i = 0; i < toRead; ++i) dst[i] = g_rt[idx].data[f.offset + i];
        f.offset += toRead;
        return cast(ssize_t)toRead;
    }

    if (f.type == FileType.FD_PIPE_READ) {
        auto pipe_ = getPipe(cast(size_t)pipeIdFromFd(f));
        if (pipe_ is null) return negErrno(EBADF);
        size_t avail = pipe_.head - pipe_.tail;
        if (avail == 0) {
            if (pipe_.writers <= 0) return 0; // EOF
            return negErrno(EAGAIN);
        }
        size_t toRead = _count < avail ? cast(size_t)_count : avail;
        auto dst = cast(ubyte*)_buf;
        for (size_t i = 0; i < toRead; ++i)
            dst[i] = pipe_.data[pipe_.tail++ % PIPE_CAPACITY];
        return cast(ssize_t)toRead;
    }

    if (f.type == FileType.FD_EVENTFD) {
        int eid = cast(int)cast(size_t)f.backend;
        if (eid < 0 || eid >= EVENTFD_MAX || !g_eventfd_inUse[eid]) return negErrno(EBADF);
        if (_count < 8) return negErrno(EINVAL);
        ulong val = g_eventfd_counters[eid];
        if (val == 0) return negErrno(EAGAIN);
        if (g_eventfd_flags[eid] & EFD_SEMAPHORE) {
            g_eventfd_counters[eid]--;
            val = 1;
        } else {
            g_eventfd_counters[eid] = 0;
        }
        *cast(ulong*)_buf = val;
        return 8;
    }

    if (f.type == FileType.FD_INPUT_EVENT) {
        int devIdx = cast(int)cast(size_t)f.backend;
        auto ring = (devIdx == 1) ? &g_mouse_ring : &g_kbd_ring;
        if (ring.head == ring.tail) return negErrno(EAGAIN); // no events yet
        // Drain as many whole InputEvents as the buffer allows
        size_t evtSz = InputEvent.sizeof;
        size_t n = 0;
        auto dst = cast(InputEvent*)_buf;
        while (ring.tail != ring.head && (n + 1) * evtSz <= _count) {
            dst[n++] = ring.events[ring.tail];
            ring.tail = (ring.tail + 1) % INPUT_RING_SIZE;
        }
        if (devIdx == 1) g_inMouseRead += n; else {
            g_inKbdRead += n;
            if (n > 0 && g_pendingInputMs == 0) g_pendingInputMs = pitMs(); // R2 latency start
        }
        return cast(ssize_t)(n * evtSz);
    }

    // GW2: deliver queued DRM page-flip completion events. Weston's event loop
    // reads the card fd and parses struct drm_event_vblank records (type +
    // length header, then user_data, timestamp, sequence, crtc_id) = 32 bytes.
    if (f.type == FileType.FD_DRM) {
        int myfd = fdIndexForFile(f);
        enum size_t evSz = 32;
        if (_count < evSz)
            return drmEventPending(myfd) ? negErrno(EINVAL) : negErrno(EAGAIN);
        // R2: real monotonic ms (PIT-only), NOT getTickCount (which increments per
        // call → a fake clock).  Weston paces its next repaint off this flip
        // timestamp vs clock_gettime, so both MUST be the same real clock.
        ulong ticks = pitMs();
        uint tvSec  = cast(uint)(ticks / 1000);
        uint tvUsec = cast(uint)((ticks % 1000) * 1000);
        auto dst = cast(ubyte*)_buf;
        size_t n = 0;
        while (g_drmEvTail != g_drmEvHead && n + evSz <= _count) {
            DrmEvent* ev = &g_drmEvents[g_drmEvTail];
            *cast(uint*)(dst + n + 0)  = DRM_EVENT_FLIP_COMPLETE;
            *cast(uint*)(dst + n + 4)  = cast(uint)evSz;
            *cast(ulong*)(dst + n + 8) = ev.userData;
            *cast(uint*)(dst + n + 16) = tvSec;
            *cast(uint*)(dst + n + 20) = tvUsec;
            *cast(uint*)(dst + n + 24) = ev.seq;
            *cast(uint*)(dst + n + 28) = ev.crtcId;
            g_drmEvTail = (g_drmEvTail + 1) % DRM_EVENT_QUEUE_MAX;
            n += evSz;
            ++g_flipRead;
        }
        if (n == 0) return negErrno(EAGAIN);
        return cast(ssize_t)n;
    }

    if (f.type == FileType.FD_PTY_MASTER || f.type == FileType.FD_PTY_SLAVE) {
        int idx = cast(int)cast(size_t)f.backend;
        if (idx < 0 || idx >= PTY_MAX || !g_ptys[idx].inUse) return negErrno(EBADF);
        // A4: the task reading the slave is the de-facto foreground process (the shell
        // at the prompt, or the running command). Record it so ^C can target it when
        // the shell doesn't drive tcsetpgrp.
        if (f.type == FileType.FD_PTY_SLAVE)
            g_ptys[idx].lastReader = cast(int)g_current_task_id;
        auto ring = (f.type == FileType.FD_PTY_MASTER) ? &g_ptys[idx].toMaster
                                                       : &g_ptys[idx].toSlave;
        auto dst = cast(ubyte*)_buf;
        size_t n = 0;
        while (n < _count) {
            int c = ptyRingPop(*ring);
            if (c < 0) break;
            dst[n++] = cast(ubyte)c;
        }
        if (n == 0) return negErrno(EAGAIN);
        return cast(ssize_t)n;
    }

    if (f.type == FileType.FD_TIMERFD) {
        int tid = cast(int)cast(size_t)f.backend;
        if (tid < 0 || tid >= TIMERFD_MAX || !g_timerfds[tid].inUse) return negErrno(EBADF);
        if (_count < 8) return negErrno(EINVAL);
        timerfdRefresh(g_timerfds[tid]);
        if (g_timerfds[tid].pending == 0) return negErrno(EAGAIN);
        *cast(ulong*)_buf = g_timerfds[tid].pending;
        g_timerfds[tid].pending = 0;
        g_tfdRead++;
        return 8;
    }

    return 0; // EOF for others
}

public ssize_t sys_read(int fd, void* _buf, size_t _count) {
    ObjHeader* oh = fdObjectByIndexWithRights(fd, CAP_RIGHT_READ);
    if (oh is null) return negErrno(EBADF);
    auto rop = g_objOps[oh.type].read;
    if (rop is null) return negErrno(EBADF);
    return cast(ssize_t)rop(oh, _buf, _count);
}

private long fileObjWrite(ObjHeader* oh, const(void)* buf, ulong count) {
    File* f = fileFromObj(oh);
    if (f is null) return negErrno(EBADF);
    ++g_objOpsDispatch;
    if (buf is null && count != 0) return cast(ssize_t)negErrno(EFAULT);

    if (f.type == FileType.FD_SOCKET) {
        return localSocketWrite(f, buf, count);
    }

    if (fileIsSyntheticDirectory(f)) {
        return cast(ssize_t)negErrno(EISDIR);
    }

    if (f.type == FileType.FD_CONSOLE) {
        const(char)* chars = cast(const(char)*)buf;
        const bool isCmp = (g_presenterTid >= 0 && cast(int)g_current_task_id == g_presenterTid);
        foreach (i; 0 .. count) {
            if (isCmp) cmpLogTap(chars[i]);   // capture the compositor's stderr → its exit reason
            console_serial_putchar(chars[i]);
        }
        return cast(ssize_t)count;
    }

    if (f.type == FileType.FD_PTY_MASTER || f.type == FileType.FD_PTY_SLAVE) {
        int idx = cast(int)cast(size_t)f.backend;
        if (idx < 0 || idx >= PTY_MAX || !g_ptys[idx].inUse) return cast(ssize_t)negErrno(EBADF);
        auto src = cast(const(ubyte)*)buf;
        if (f.type == FileType.FD_PTY_MASTER)
            foreach (i; 0 .. count) ptyInputByte(g_ptys[idx], src[i]); // terminal keystrokes
        else
            foreach (i; 0 .. count) ptyOut(g_ptys[idx], src[i]);       // shell output
        return cast(ssize_t)count;
    }

    if (f.type == FileType.FD_PIPE_WRITE) {
        auto pipe_ = getPipe(cast(size_t)pipeIdFromFd(f));
        if (pipe_ is null || pipe_.readers <= 0) return cast(ssize_t)negErrno(EPIPE);
        size_t space = PIPE_CAPACITY - (pipe_.head - pipe_.tail);
        if (space == 0) return cast(ssize_t)negErrno(EAGAIN);
        size_t toWrite = count < space ? cast(size_t)count : space;
        auto src = cast(const(ubyte)*)buf;
        for (size_t i = 0; i < toWrite; ++i)
            pipe_.data[pipe_.head++ % PIPE_CAPACITY] = src[i];
        return cast(ssize_t)toWrite;
    }

    if (f.type == FileType.FD_EVENTFD) {
        int eid = cast(int)cast(size_t)f.backend;
        if (eid < 0 || eid >= EVENTFD_MAX || !g_eventfd_inUse[eid]) return cast(ssize_t)negErrno(EBADF);
        if (count < 8) return cast(ssize_t)negErrno(EINVAL);
        ulong inc = *cast(ulong*)buf;
        if (inc == ulong.max) return cast(ssize_t)negErrno(EINVAL);
        g_eventfd_counters[eid] += inc;
        return 8;
    }

    if (f.type == FileType.FD_RTFILE) {
        const int idx = cast(int)cast(size_t)f.backend;
        if (idx < 0 || idx >= RT_MAX_NODES || g_rt[idx].kind != RT_REG)
            return cast(ssize_t)negErrno(EBADF);
        if (f.flags & O_APPEND) f.offset = g_rt[idx].size;
        const ulong end = f.offset + count;
        if (end > uint.max) return cast(ssize_t)negErrno(ENOSPC);
        if (!rtEnsureCap(g_rt[idx], cast(uint)end)) return cast(ssize_t)negErrno(ENOSPC);
        auto src = cast(const(ubyte)*)buf;
        for (size_t i = 0; i < count; ++i) g_rt[idx].data[f.offset + i] = src[i];
        // Mirror runtime *.log writes (e.g. Hyprland's hyprland.log, which it
        // redirects to once it disables stdout logging) onto serial so the log
        // stays complete without repainting the slow framebuffer text console.
        if (rtNameEndsWith(g_rt[idx], ".log"))
            for (size_t i = 0; i < count; ++i) console_serial_putchar(cast(char)src[i]);
        f.offset += count;
        if (cast(uint)f.offset > g_rt[idx].size) g_rt[idx].size = cast(uint)f.offset;
        f.fileSize = g_rt[idx].size;
        return cast(ssize_t)count;
    }

    // DM10.3: a write to /config/domain.action is a domain control command.  Parse + execute
    // via the (deny-by-default) executor; the write always "succeeds" at the fd level so the
    // client's write() returns the byte count (the command's accept/reject is observable in the
    // domain state it then re-reads from /config/domains.json).
    if (f.type == FileType.FD_DOMAIN_CTL) {
        domainControlWrite(cast(const(char)*)buf, cast(size_t)count);
        return cast(ssize_t)count;
    }

    // INSTALLER §D: a write to /config/install.action drives the in-OS installer (the desktop
    // "Install to Disk" button writes "install" here).  Like domain.action, the fd-level write
    // always succeeds; the outcome is observable in the [install] serial log / the target disk.
    if (f.type == FileType.FD_INSTALL_CTL) {
        import drivers.veracrypt_impl : installControlWrite;
        installControlWrite(cast(const(char)*)buf, cast(size_t)count);
        return cast(ssize_t)count;
    }

    // UPDATE U1: a write to /config/update.action drives the A/B update engine (Settings
    // System Update page).  Like install.action the fd-level write always succeeds; the
    // verb's accept/reject is observable in /config/update.status + the [update] log.
    if (f.type == FileType.FD_UPDATE_CTL) {
        import core.sysupdate : updateControlWrite;
        updateControlWrite(cast(const(char)*)buf, cast(size_t)count);
        return cast(ssize_t)count;
    }

    // Simulate success for others (e.g. /dev/null)
    return cast(ssize_t)count;
}

// ── On-screen LKL console (real-hardware) ─────────────────────────────────────
// LKL's stdout/stderr (iwlwifi probe, driver messages) go to fd 1/2 → serial, which
// is invisible on the serial-less laptop.  Mirror lkl-boot's fd 1/2 writes into a small
// scrolling text grid rendered at the bottom of the desktop (bypasses g_desktopClaimedFb,
// re-stamped after each present) so WiFi bring-up is actually readable on the panel.
private enum int LKLLOG_ROWS = 30;
private enum int LKLLOG_COLS = 96;
__gshared char[LKLLOG_COLS + 1][LKLLOG_ROWS] g_lklLines;
__gshared int  g_lklRow = 0, g_lklCol = 0;
__gshared bool g_lklLogActive = false;
private void lklLogByte(char c) @nogc nothrow {
    g_lklLogActive = true;
    if (c == '\r') return;
    if (c == '\n' || g_lklCol >= LKLLOG_COLS) {
        g_lklLines[g_lklRow][g_lklCol] = 0;
        if (g_lklRow >= LKLLOG_ROWS - 1) {
            for (int r = 1; r < LKLLOG_ROWS; r++) g_lklLines[r - 1] = g_lklLines[r];
        } else g_lklRow++;
        g_lklCol = 0;
        g_lklLines[g_lklRow][0] = 0;
        if (c == '\n') return;
    }
    if (c >= 32 && c < 127) {
        g_lklLines[g_lklRow][g_lklCol++] = c;
        g_lklLines[g_lklRow][g_lklCol] = 0;
    }
}
public void lklLogWrite(const(char)* b, size_t n) @nogc nothrow {
    for (size_t i = 0; i < n; i++) lklLogByte(b[i]);
}
// Re-stamp the LKL console at the bottom of the screen (called from drmPresentFb).
public void lklLogRepaint() @nogc nothrow {
    import arch.x86_64.bootstrap : fb_draw_hud_row, g_fb;
    if (!g_lklLogActive || g_fb is null) return;
    uint h = cast(uint)g_fb.height;
    uint baseY = (h > LKLLOG_ROWS * 16 + 24) ? (h - LKLLOG_ROWS * 16 - 8) : 32;
    for (int r = 0; r < LKLLOG_ROWS; r++)
        fb_draw_hud_row(baseY + cast(uint)(r * 16), g_lklLines[r].ptr);
}

// USB-LOG on-screen status — reported by lkl-boot's epin_usblog_thread via the 0x4100 bridge (op11) so
// the user can SEE whether the /run/klog dump is reaching the USB stick, without a serial cable.
__gshared int   g_usblogState = -1;   // -1=nothing yet, 0=searching, 1=found/mounting, 2=WRITING, 3=gave up
__gshared ulong g_usblogBytes = 0;    // bytes written to hoslog.txt so far (state 2)
__gshared ulong g_usblogKB    = 0;    // size of the target device in KB
__gshared int   g_usblogSd    = 0;    // sd letter index (0='a', 1='b', ...)
public void usblogStatusRepaint() @nogc nothrow {
    import arch.x86_64.bootstrap : fb_draw_hud_row, g_fb;
    if (g_usblogState < 0 || g_fb is null) return;      // nothing reported yet
    char[100] b; int n = 0;
    void put(string s) @nogc nothrow { foreach (ch; s) if (n < 99) b[n++] = ch; }
    void dec(ulong v) @nogc nothrow { char[20] t; int m=0; if(v==0)t[m++]='0'; while(v&&m<20){t[m++]=cast(char)('0'+v%10);v/=10;} while(m&&n<99)b[n++]=t[--m]; }
    void sd() @nogc nothrow { put("/dev/sd"); if (n<99) b[n++] = cast(char)('a' + (g_usblogSd & 0x1F)); }
    put("USB LOG: ");
    if      (g_usblogState == 0) put("searching for a drive...");
    else if (g_usblogState == 1) { put("found "); sd(); put(" ("); dec(g_usblogKB/1024); put(" MB) - mounting..."); }
    else if (g_usblogState == 2) { put("WRITING "); sd(); put(" -> hoslog.txt  "); dec(g_usblogBytes/1024); put(" KB written"); }
    else                         put("NO writable drive found - attach a FAT32/exFAT stick");
    b[n]=0;
    fb_draw_hud_row(128, b.ptr);   // below the LOG UPLOAD row (112); freeze-probe rows are 0-96
}

// LOG-UPLOAD on-screen status — the kernel taps hos-log-upload's fd1/fd2 writes in sys_write (by
// exec name, same idiom as the lkl-boot console tap above) and re-stamps its LAST stderr line over
// the desktop every present.  This is the "did my debug log reach the host?" answer without opening
// the Logs app: Wi-Fi wait -> "scp attempt N -> user@ip:path" -> "upload complete ... (N KB)".
// Once the completion line is seen the row FREEZES on it (the uploader exits right after anyway).
// '\0'-init both buffers: D's char.init is 0xFF, which would leave g_logupLast without a
// terminator — the repaint's empty-check would pass garbage and its copy loop would walk
// past the array (boot-killing bounds assert; same trap as g_fdPath above).
__gshared char[144] g_logupLast = '\0'; __gshared char[144] g_logupCur = '\0';
__gshared int g_logupCurN = 0;
__gshared bool g_logupComplete = false;
void logupTap(char c) {
    if (c == '\n' || g_logupCurN >= 143) {
        if (g_logupCurN > 0 && !g_logupComplete) {
            g_logupCur[g_logupCurN] = 0;
            // strip the uniform "[log-upload] " stderr prefix for the on-screen row
            int s = 0;
            if (cstrEqPrefix(g_logupCur.ptr, "[log-upload] ")) s = 13;
            int k = 0;
            while (s + k < 143 && g_logupCur[s + k]) { g_logupLast[k] = g_logupCur[s + k]; ++k; }
            g_logupLast[k] = 0;
            for (int i = 0; i < 143 && g_logupLast[i]; ++i)
                if (cstrEqPrefix(&g_logupLast[i], "upload complete")) { g_logupComplete = true; break; }
        }
        g_logupCurN = 0;
    } else if (c >= 32 && c < 127) {
        g_logupCur[g_logupCurN++] = c;
    }
}
public void logupStatusRepaint() @nogc nothrow {
    import arch.x86_64.bootstrap : fb_draw_hud_row, g_fb;
    if (g_fb is null || g_logupLast[0] == 0) return;   // uploader hasn't said anything yet
    char[160] b; int n = 0;
    void put(string s) @nogc nothrow { foreach (ch; s) if (n < 159) b[n++] = ch; }
    put(g_logupComplete ? "LOG UPLOAD OK: " : "LOG UPLOAD: ");
    { int k = 0; while (k < 143 && g_logupLast[k] && n < 159) b[n++] = g_logupLast[k++]; }
    b[n] = 0;
    fb_draw_hud_row(112, b.ptr);   // below the freeze-probe rows (0-96), below the top bar
}

public ssize_t sys_write(int fd, const(void)* buf, size_t count) {
    // Real-HW: mirror lkl-boot's stdout/stderr to the on-screen LKL console, and
    // hos-log-upload's status lines to the LOG UPLOAD desktop row (logupStatusRepaint).
    if ((fd == 1 || fd == 2) && buf !is null && count > 0) {
        const int t = cast(int)g_current_task_id;
        const(char)* nm = (t >= 0 && t < MAX_TASKS) ? g_taskExecName[t] : null;
        if (nm !is null && nm[0] == 'l' && nm[1] == 'k' && nm[2] == 'l')
            lklLogWrite(cast(const(char)*)buf, count);
        else if (nm !is null && cstrEqPrefix(nm, "hos-log")) {
            const(char)* p = cast(const(char)*)buf;
            for (size_t i = 0; i < count; i++) logupTap(p[i]);
        }
    }
    ObjHeader* oh = fdObjectByIndexWithRights(fd, CAP_RIGHT_WRITE);
    if (oh is null) return cast(ssize_t)negErrno(EBADF);
    auto wop = g_objOps[oh.type].write;
    if (wop is null) return cast(ssize_t)negErrno(EBADF);
    return cast(ssize_t)wop(oh, buf, count);
}

private uint openRightsForFlags(int flags) {
    uint rights = 0;
    switch (flags & 3) {
        case O_WRONLY:
            rights = CAP_RIGHT_WRITE;
            break;
        case O_RDWR:
            rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
            break;
        default:
            rights = CAP_RIGHT_READ;
            break;
    }
    if ((flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0)
        rights |= CAP_RIGHT_WRITE;
    return rights;
}

// Phase 2.4: absolute opens must resolve through the calling process's Namespace
// object, and the matching binding must grant the requested open rights. The
// default "/" binding grants all rights, preserving current boot behavior while
// restricted namespaces can deny access before the legacy backing resolver runs.
private int namespaceCheckOpen(const(char)* path, int flags) {
    if (path is null || path[0] != '/') return 0; // relative paths still use cwd shim
    int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return negErrno(ENOENT);
    objEnsureNamespace(tid);
    const(char)* rest;
    uint rights;
    bool denied;
    uint target = nsResolveCheck(g_tasks[tid].namespaceObjId, path, rest, rights, denied);
    // DM2: an explicit deny binding → EACCES; an unbound path in a restricted namespace
    // (no "/" mount) → ENOENT.  Both deny; the distinction is for the errno/audit.
    if (target == 0) return negErrno(denied ? EACCES : ENOENT);
    uint need = openRightsForFlags(flags);
    if ((rights & need) != need) return negErrno(EACCES);
    return 0;
}

// DM8 §7: map a /dev path to its brokered device class (0 = not a brokered device node).
private uint devClassForPath(const(char)* path) {
    if (cstrEqPrefix(path, "/dev/input/event")) return DEVCLASS_INPUT;
    if (cstrEqPrefix(path, "/dev/dri/"))         return DEVCLASS_GPU;
    if (cstrEqPrefix(path, "/dev/video"))        return DEVCLASS_CAMERA;
    if (cstrEqPrefix(path, "/dev/bus/usb/"))     return DEVCLASS_USB;
    if (cstrEqPrefix(path, "/dev/snd/"))         return DEVCLASS_AUDIO;
    return 0;
}

// DM8: gate a device open against the calling task's identity device policy (§7).  A task with
// no identity (identityObjId==0, e.g. the kernel/compositor before any domain bind) is
// unrestricted; a known identity with the class bit clear is denied (EACCES).  Wired into the
// open() path so a `usb:false`/`gpu:false`/etc. domain physically cannot open that device node.
private int deviceClassGate(const(char)* path) {
    const uint cls = devClassForPath(path);
    if (cls == 0) return 0;                       // not a brokered device → no gate
    int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return 0;
    const uint dom = g_tasks[tid].domainObjId;
    if (dom != 0)                                 // DM10.7: a domain-bound task → the domain's mask
        return domainDeviceAllowed(dom, cls) ? 0 : negErrno(EACCES);
    const uint idObj = g_tasks[tid].identityObjId;
    if (idObj == 0) return 0;                     // no identity → unrestricted (kernel/desktop)
    if (!identityDeviceAllowed(idObj, cls)) return negErrno(EACCES);
    return 0;
}

// DM8 boot proof: a Banking-identity task is allowed input+gpu but DENIED camera+usb, enforced
// through the real deviceClassGate (the exact gate the open() path calls).  Leaves no state.
__gshared bool g_domDeviceProofDone = false;
public void domDeviceProof() {
    if (g_domDeviceProofDone) return;
    g_domDeviceProofDone = true;
    const uint bank = identityByName("Banking\0".ptr);
    bool ok = (bank != 0);
    // §7 policy bits + path→class mapping
    ok = ok && identityDeviceAllowed(bank, DEVCLASS_INPUT) && identityDeviceAllowed(bank, DEVCLASS_GPU);
    ok = ok && !identityDeviceAllowed(bank, DEVCLASS_CAMERA) && !identityDeviceAllowed(bank, DEVCLASS_USB);
    ok = ok && (devClassForPath("/dev/input/event0\0".ptr) == DEVCLASS_INPUT);
    ok = ok && (devClassForPath("/dev/dri/card0\0".ptr) == DEVCLASS_GPU);
    ok = ok && (devClassForPath("/dev/video0\0".ptr) == DEVCLASS_CAMERA);
    ok = ok && (devClassForPath("/etc/passwd\0".ptr) == 0);
    // end-to-end: run a spare task slot AS Banking and gate its device opens
    int tid = -1;
    for (int i = MAX_TASKS - 1; i > 0; --i) if (!g_tasks[i].active) { tid = i; break; }
    if (bank != 0 && tid > 0) {
        const uint savedId  = g_tasks[tid].identityObjId;
        const uint savedDom = g_tasks[tid].domainObjId;
        const savedCur = g_current_task_id;
        g_tasks[tid].identityObjId = bank;
        g_tasks[tid].domainObjId   = 0;   // identity-path test: no domain override
        g_current_task_id = cast(typeof(g_current_task_id))tid;
        ok = ok && (deviceClassGate("/dev/input/event0\0".ptr) == 0);            // input allowed
        ok = ok && (deviceClassGate("/dev/dri/card0\0".ptr) == 0);               // gpu allowed
        ok = ok && (deviceClassGate("/dev/video0\0".ptr) == negErrno(EACCES));   // camera DENIED
        ok = ok && (deviceClassGate("/dev/bus/usb/001/002\0".ptr) == negErrno(EACCES)); // usb DENIED
        // DM10.7: the per-domain mask + a GUI device toggle (devon/devoff → domainSetDevice)
        const DomainId bdom = domainByName("Banking\0".ptr);
        if (bdom != 0) {
            g_tasks[tid].domainObjId = bdom;
            ok = ok && (deviceClassGate("/dev/video0\0".ptr) == negErrno(EACCES)); // domain mask denies camera
            domainSetDevice(bdom, DEVCLASS_CAMERA, true);                          // GUI toggles camera ON
            ok = ok && (deviceClassGate("/dev/video0\0".ptr) == 0);               // now allowed
            domainSetDevice(bdom, DEVCLASS_CAMERA, false);                        // toggle OFF (restore)
            ok = ok && (deviceClassGate("/dev/video0\0".ptr) == negErrno(EACCES));
        } else ok = false;
        g_tasks[tid].domainObjId = savedDom;
        g_current_task_id = savedCur;
        g_tasks[tid].identityObjId = savedId;
    } else ok = false;
    klog(ok ? "[domain] device proof PASS (per-domain mask: camera EACCES, GUI toggle ON→allowed→OFF→EACCES; input+gpu OK)\n"
            : "[domain] device proof FAIL\n");
}

// True if `path` exactly names an entry in the virtual-file table (g_vfs).
private bool pathIsExactVfsFile(const(char)* path) @nogc nothrow {
    foreach (ref vfe; g_vfs)
        if (cstrEq(path, vfe.path)) return true;
    return false;
}

// ── F1: /objects live views — /objects/<kind>/<obj> over the kernel tables ─────
import core.hoscall : objfsKindId, objfsEnum, objfsFieldId, objfsField,
                      configfsId, configfsEnum, configfsRender,
                      sysGenList, sysGenMeta;
import core.objstore : objstoreMounted, objstoreBootCount, objstoreAppCount,
                       objstoreAppEnum, objstoreAppByName, objstoreApp, objstoreReadBlob,
                       ObjAppEntry;
private enum ulong SYNTHDIR_OBJ_BASE  = 0x0B1EC700;  // + kind id => /objects/<kind> dir
private enum ulong SYNTHDIR_OBJ_ENTRY = 0x0B1ED700;  // F5: /objects/<kind>/<obj> object dir
__gshared int g_objectsDirIdx = -1;                  // RT node index of /objects

// F5: parse "/objects/<kind>/<obj>/<field>". Returns kind (>0); `obj`=null at the
// /objects/<kind> level; `field` ∈ {0=object dir, 1=meta, 2=capabilities,
// 3=relationships}.  0 if not an objfs path (apps/processes handled elsewhere).
private int objfsParseDeep(const(char)* path, out const(char)* obj, out size_t objLen, out int field) {
    obj = null; objLen = 0; field = 0;
    static immutable string pre = "/objects/";
    foreach (i; 0 .. pre.length) if (path[i] != pre[i]) return 0;
    const(char)* p = path + pre.length;
    size_t klen = 0; while (p[klen] != 0 && p[klen] != '/') ++klen;
    const int kid = objfsKindId(p, klen);
    if (kid == 0) return 0;
    p += klen;
    if (*p == 0) return kid;                      // /objects/<kind>
    if (*p != '/') return 0;
    ++p;
    if (*p == 0) return kid;                       // /objects/<kind>/
    obj = p;
    size_t ol = 0; while (p[ol] != 0 && p[ol] != '/') ++ol;
    objLen = ol;
    const(char)* q = p + ol;
    if (*q == 0) return kid;                       // /objects/<kind>/<obj>  (object dir, field=0)
    if (*q != '/') return 0;
    ++q;
    if (*q == 0) return kid;                       // trailing slash → object dir
    size_t fl = 0; while (q[fl] != 0) ++fl;
    foreach (i; 0 .. fl) if (q[i] == '/') return 0;   // no deeper than the field
    field = objfsFieldId(q, fl);
    if (field == 0) return 0;
    return kid;                                    // /objects/<kind>/<obj>/<field>
}

// DOMAIN_MANAGER DM0.d: one-shot end-to-end proof of the /objects/domains READ path —
// the exact parse+render the open/read syscalls run (see the dispatch ~line 2520).
// Proves objfsParseDeep routes "domains" + objfsField renders it; headless (no shell).
__gshared bool g_domReadProofDone = false;
public void domReadPathProof() {
    if (g_domReadProofDone) return;
    g_domReadProofDone = true;
    const(char)* obj; size_t objLen; int field;
    const int kind = objfsParseDeep("/objects/domains/Development/meta\0".ptr, obj, objLen, field);
    long n = -1;
    if (kind == 5 /*OBJFS_DOMAINS*/ && field == 1 /*meta*/)
        n = objfsField(kind, obj, objLen, field, g_procBuf.ptr, g_procBuf.length - 1);
    klog("[domain] read-path /objects/domains/Development/meta: kind=");
    klog_hex(cast(ulong)kind); klog(" field="); klog_hex(cast(ulong)field);
    if (n > 0) { klog(" -> OK "); klog_hex(cast(ulong)n); klog(" bytes\n"); }
    else klog(" -> FAIL\n");
}

// ── F4: /objects/apps persisted app objects (on the SATA object store) ─────────
private enum ulong SYNTHDIR_APPS     = 0x0A99D100;   // /objects/apps dir
private enum ulong SYNTHDIR_APP_BASE = 0x0A99D200;   // + appIdx => /objects/apps/<app> dir
private enum ulong SYNTHDIR_STOR_BASE= 0x0A99D300;   // + appIdx => /objects/apps/<app>/storage dir
__gshared char[8192] g_appsBuf;                      // rendered app blob/metadata (open→read)

// Classify a /objects/apps path. Returns a kind code (0=not apps) and the app index.
//   1=/objects/apps  2=/objects/apps/<app>  3=manifest.json  4=permissions.json
//   5=identity-binding.json  6=executable  7=/storage  8=/storage/data
private int appsfsParse(const(char)* path, out int appIdx) {
    appIdx = -1;
    static immutable string pre = "/objects/apps";
    foreach (i; 0 .. pre.length) if (path[i] != pre[i]) return 0;
    const(char)* p = path + pre.length;
    if (*p == 0) return 1;                       // /objects/apps
    if (*p != '/') return 0;
    ++p;
    if (*p == 0) return 1;                        // /objects/apps/
    // app name component
    size_t nlen = 0; while (p[nlen] != 0 && p[nlen] != '/') ++nlen;
    appIdx = objstoreAppByName(p, cast(uint)nlen);
    if (appIdx < 0) return 0;
    const(char)* q = p + nlen;
    if (*q == 0) return 2;                         // /objects/apps/<app>
    if (*q != '/') return 0;
    ++q;
    if (*q == 0) return 2;                         // /objects/apps/<app>/
    if (cstrEq(q, "manifest.json"))         return 3;
    if (cstrEq(q, "permissions.json"))      return 4;
    if (cstrEq(q, "identity-binding.json")) return 5;
    if (cstrEq(q, "executable"))            return 6;
    static immutable string st = "storage";
    foreach (i; 0 .. st.length) if (q[i] != st[i]) return 0;
    q += st.length;
    if (*q == 0) return 7;                         // /objects/apps/<app>/storage
    if (*q != '/') return 0;
    ++q;
    if (*q == 0) return 7;
    if (cstrEq(q, "data")) return 8;               // /objects/apps/<app>/storage/data
    return 0;
}

// Render an app's identity-binding.json (derived from the directory entry).
private int appsRenderIdentity(ObjAppEntry* e, ubyte* dst, uint cap) {
    size_t pos = 0;
    void put(const(char)* s) { while (*s && pos + 1 < cap) dst[pos++] = *s++; }
    void hexb(uint v) {
        put("0x".ptr); bool st = false;
        for (int sh = 28; sh >= 0; sh -= 4) {
            uint nib = (v >> sh) & 0xF;
            if (nib || st || sh == 0) { st = true; if (pos+1<cap) dst[pos++] = cast(ubyte)(nib<10?('0'+nib):('a'+nib-10)); }
        }
    }
    put("{\n  \"identity\": \"".ptr);
    foreach (i; 0 .. e.identityLen) if (pos+1<cap) dst[pos++] = e.identity[i];
    put("\",\n  \"rights\": \"".ptr); hexb(e.rights);
    put("\"\n}\n".ptr);
    return cast(int)pos;
}

// ── F2: /config declarative JSON views over the kernel tables ─────────────────
__gshared int g_configDirIdx = -1;                   // RT node index of /config
__gshared char[8192] g_configBuf;                    // rendered JSON (sequential open→read)

// ── F3: /system immutable base views over the active Generation + components ───
private enum ulong SYNTHDIR_SYSCUR = 0x59CC0700;     // tags the /system/current synthetic dir
private enum ulong SYNTHDIR_SYSSTATE = 0x59CC0800;   // tags the /system/state synthetic dir
__gshared int g_systemDirIdx = -1;                   // RT node index of /system
__gshared char[4096] g_sysBuf;                       // rendered /system text (sequential open→read)

bool installConfigPresent();

// Parse "/config/<name>". Returns the config id (>0) for a known *.json file, 0
// otherwise. No subdirectories — /config is a flat set of generated documents.
private int configfsParse(const(char)* path) {
    static immutable string pre = "/config/";
    foreach (i; 0 .. pre.length) if (path[i] != pre[i]) return 0;
    const(char)* p = path + pre.length;
    size_t nlen = 0;
    while (p[nlen] != 0) ++nlen;
    foreach (i; 0 .. nlen) if (p[i] == '/') return 0;   // no subdirs
    return configfsId(p, nlen);
}

// F3 text builders over g_sysBuf (component metadata is assembled kernel-side because
// the boot-module table lives here, not in hoscall.d).
private void sbStr(ref size_t pos, const(char)* s) {
    while (*s != 0 && pos < g_sysBuf.length - 1) g_sysBuf[pos++] = *s++;
}
private void sbNum(ref size_t pos, ulong n) {
    char[24] tmp = void; int ti = 0;
    if (n == 0) tmp[ti++] = '0';
    while (n > 0) { tmp[ti++] = cast(char)('0' + n % 10); n /= 10; }
    while (ti > 0 && pos < g_sysBuf.length - 1) g_sysBuf[pos++] = tmp[--ti];
}
private void sbHex(ref size_t pos, ulong v) {
    sbStr(pos, "0x".ptr);
    bool started = false;
    for (int sh = 60; sh >= 0; sh -= 4) {
        const uint nib = cast(uint)((v >> sh) & 0xF);
        if (nib != 0 || started || sh == 0) {
            started = true;
            if (pos < g_sysBuf.length - 1)
                g_sysBuf[pos++] = cast(char)(nib < 10 ? ('0' + nib) : ('a' + nib - 10));
        }
    }
}

// Classify a base component into the roadmap's {kernel,servers,drivers,interfaces}.
private const(char)* sysComponentKind(const(char)* name) {
    if (cstrEq(name, "kernel.elf")) return "kernel".ptr;
    if (cstrLooksLikeSo(name))      return "interface".ptr;
    size_t n = 0; while (name[n] != 0) ++n;
    if (n >= 5 && name[n-5]=='.' && name[n-4]=='b' && name[n-3]=='l' && name[n-2]=='o' && name[n-1]=='b') return "data".ptr;
    if (n >= 5 && name[n-5]=='.' && name[n-4]=='c' && name[n-3]=='o' && name[n-2]=='n' && name[n-1]=='f') return "data".ptr;
    return "server".ptr;   // init / shells / wayland clients / drivers
}

// Nth boot-module basename -> nameBuf (for getdents over /system/current); -1 past end.
private int sysComponentEnum(int logical, char* nameBuf, size_t cap) {
    if (g_mboot_modules is null || g_module_count <= 0) return -1;
    if (logical < 0 || logical >= g_module_count) return -1;
    auto records = cast(BootModuleRecord*)g_mboot_modules;
    const(char)* base = cstrLastComponent(records[logical].name.ptr, 120);
    size_t l = 0; while (base[l] != 0 && l < cap) { nameBuf[l] = base[l]; ++l; }
    return cast(int)l;
}

// Render /system/current/<name> component metadata into g_sysBuf; len or -2 (ENOENT).
private long sysComponentMeta(const(char)* name, size_t nameLen) {
    if (g_mboot_modules is null || g_module_count <= 0) return -2;
    auto records = cast(BootModuleRecord*)g_mboot_modules;
    foreach (i; 0 .. cast(size_t)g_module_count) {
        const(char)* base = cstrLastComponent(records[i].name.ptr, 120);
        size_t j = 0;
        while (j < nameLen && base[j] != 0 && base[j] == name[j]) ++j;
        if (j != nameLen || base[j] != 0) continue;
        const ulong sz = cast(ulong)records[i].mod_end - cast(ulong)records[i].mod_start;
        size_t pos = 0;
        sbStr(pos, "type=Component\nname=".ptr); sbStr(pos, base);
        sbStr(pos, "\nkind=".ptr);  sbStr(pos, sysComponentKind(base));
        sbStr(pos, "\nsize=".ptr);  sbNum(pos, sz);
        sbStr(pos, "\nphys=".ptr);  sbHex(pos, cast(ulong)records[i].mod_start);
        sbStr(pos, "\nimmutable=true\n".ptr);
        return cast(long)pos;
    }
    return -2;
}

private long sysStateInstalled(char* buf, size_t buflen) {
    const(char)[] s = installConfigPresent() ? "true\n" : "false\n";
    size_t n = s.length;
    if (n > buflen) n = buflen;
    foreach (i; 0 .. n) buf[i] = s[i];
    return cast(long)n;
}

// Classify a /system path: 0=not under /system; 1=/system; 2=/system/generations;
// 3=/system/current (dir); 4=/system/current/generation; 5=/system/current/<comp>;
// 6=/system/state (dir); 7=/system/state/installed.
private int sysfsParse(const(char)* path, out const(char)* comp, out size_t compLen) {
    comp = null; compLen = 0;
    static immutable string pre = "/system";
    foreach (i; 0 .. pre.length) if (path[i] != pre[i]) return 0;
    const(char)* p = path + pre.length;
    if (*p == 0) return 1;                       // /system
    if (*p != '/') return 0;
    ++p;
    if (cstrEq(p, "generations")) return 2;
    if (cstrEq(p, "state")) return 6;
    static immutable string state = "state";
    bool isState = true;
    foreach (i; 0 .. state.length) if (p[i] != state[i]) { isState = false; break; }
    if (isState) {
        p += state.length;
        if (*p == '/') {
            ++p;
            if (*p == 0) return 6;
            if (cstrEq(p, "installed")) return 7;
        }
        return 0;
    }
    static immutable string cur = "current";
    foreach (i; 0 .. cur.length) if (p[i] != cur[i]) return 0;
    p += cur.length;
    if (*p == 0) return 3;                        // /system/current
    if (*p != '/') return 0;
    ++p;
    if (*p == 0) return 3;                        // /system/current/
    if (cstrEq(p, "generation")) return 4;        // /system/current/generation
    comp = p; while (p[compLen] != 0) ++compLen;
    foreach (i; 0 .. compLen) if (comp[i] == '/') return 0;   // no deeper
    return 5;                                     // /system/current/<component>
}


// ── A4: dynamic /proc/<pid> for ps/top ───────────────────────────────────────
private enum ulong SYNTHDIR_PROC = 0x9120C400;
private enum ulong SYNTHDIR_DRMDIR = 0xD12D2300;  // R3: /sys/dev/char/226:*/device/drm (lists card0+renderD128)
private enum ulong SYNTHDIR_DEVDRI = 0xD12D2400;  // R3: /dev/dri (lists card0+renderD128 char nodes for libdrm)
__gshared char[1024] g_procBuf;     // synthesised content (sequential open→read use)

// Parse "/proc/<digits>[/<sub>]". Returns the pid (>0) and the component after it
// (`sub`=null when the path is the pid directory itself); -1 if not such a path.
private int procParsePid(const(char)* path, out const(char)* sub, out size_t subLen) {
    sub = null; subLen = 0;
    static immutable string pre = "/proc/";
    foreach (i; 0 .. pre.length) if (path[i] != pre[i]) return -1;
    const(char)* p = path + pre.length;
    if (*p < '0' || *p > '9') return -1;
    int pid = 0;
    while (*p >= '0' && *p <= '9') { pid = pid * 10 + (*p - '0'); ++p; }
    if (*p == 0) return pid;            // /proc/<pid>
    if (*p != '/') return -1;
    ++p;
    if (*p == 0) return pid;            // /proc/<pid>/  (trailing slash → still the dir)
    sub = p;
    while (p[subLen] != 0) ++subLen;
    return pid;
}

private bool subEq(const(char)* sub, size_t subLen, string lit) {
    if (subLen != lit.length) return false;
    foreach (i; 0 .. lit.length) if (sub[i] != lit[i]) return false;
    return true;
}
private void pbStr(ref size_t pos, const(char)* s) {
    while (*s != 0 && pos < g_procBuf.length - 1) g_procBuf[pos++] = *s++;
}
private void pbNum(ref size_t pos, long n) {
    if (n < 0) { if (pos < g_procBuf.length - 1) g_procBuf[pos++] = '-'; n = -n; }
    char[24] tmp = void; int ti = 0;
    if (n == 0) tmp[ti++] = '0';
    while (n > 0) { tmp[ti++] = cast(char)('0' + n % 10); n /= 10; }
    while (ti > 0 && pos < g_procBuf.length - 1) g_procBuf[pos++] = tmp[--ti];
}

// Build /proc/<pid>/<sub> into g_procBuf; returns length, or 0 if pid/sub unhandled.
private size_t procSynth(int pid, const(char)* sub, size_t subLen) {
    const int tid = taskIdFromLinuxPid(pid);
    if (tid < 0 || tid >= MAX_TASKS || !g_tasks[tid].active || g_tasks[tid].exited) return 0;
    const(char)* comm = (g_taskExecName[tid] !is null) ? g_taskExecName[tid] : "task".ptr;
    const int ppid = (g_tasks[tid].parentId >= 0) ? linuxPidForTask(g_tasks[tid].parentId) : 0;
    const char state = g_tasks[tid].waiting ? 'S' : 'R';
    size_t pos = 0;
    if (subEq(sub, subLen, "stat")) {
        // pid (comm) state ppid pgrp ... utime stime ... vsize rss <tail zeros>
        pbNum(pos, pid); pbStr(pos, " (".ptr); pbStr(pos, comm); pbStr(pos, ") ".ptr);
        if (pos < g_procBuf.length - 1) g_procBuf[pos++] = state; pbStr(pos, " ".ptr);
        pbNum(pos, ppid); pbStr(pos, " ".ptr); pbNum(pos, pid);
        pbStr(pos, " 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 4194304 256 ".ptr);
        pbStr(pos, "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n".ptr);
    } else if (subEq(sub, subLen, "comm")) {
        pbStr(pos, comm); if (pos < g_procBuf.length - 1) g_procBuf[pos++] = '\n';
    } else if (subEq(sub, subLen, "cmdline")) {
        pbStr(pos, comm); if (pos < g_procBuf.length - 1) g_procBuf[pos++] = 0;
    } else if (subEq(sub, subLen, "status")) {
        pbStr(pos, "Name:\t".ptr); pbStr(pos, comm);
        pbStr(pos, "\nState:\t".ptr); if (pos < g_procBuf.length - 1) g_procBuf[pos++] = state;
        pbStr(pos, " (running)\nTgid:\t".ptr); pbNum(pos, pid);
        pbStr(pos, "\nPid:\t".ptr); pbNum(pos, pid);
        pbStr(pos, "\nPPid:\t".ptr); pbNum(pos, ppid);
        pbStr(pos, "\nVmRSS:\t1024 kB\nThreads:\t1\n".ptr);
    } else return 0;
    return pos;
}

public int sys_open(const(char)* path, int flags) {
    initFdTable();
    if (path is null) {
        return negErrno(EFAULT);
    }
    // openat() support: remember this open's path so publishActiveFdReturn can stash it per-fd (for a
    // later openat(thisfd, relpath)).  Absolute paths (incl. openat-reconstructed ones) are captured
    // correctly; relative cwd-based opens store as-is (best-effort, those fds are rarely used as dirfds).
    {
        int i = 0; while (i < 255 && path[i] != 0) { g_pendingOpenPath[i] = path[i]; ++i; } g_pendingOpenPath[i] = 0;
    }

    // A4: resolve a relative path against the current working directory (busybox top
    // chdir's into /proc/<pid> then opens "stat").  The cwd is global (single shim),
    // so this is best-effort but correct for the common foreground-tool case.
    char[1024] _cwdAbs = void;
    if (path[0] != '/' && path[0] != 0) {
        size_t cl = 0;
        for (; cl < g_cwd_len && cl < 1022; ++cl) _cwdAbs[cl] = g_cwd_buf[cl];
        if (cl == 0 || _cwdAbs[cl - 1] != '/') _cwdAbs[cl++] = '/';
        size_t pi = 0;
        while (path[pi] != 0 && cl < 1023) _cwdAbs[cl++] = path[pi++];
        _cwdAbs[cl] = 0;
        path = _cwdAbs.ptr;
    }

    // F1: /objects/processes is the live process view = /proc. Rewrite the prefix so
    // per-pid paths (/objects/processes/<pid>/stat) resolve through the procfs handler
    // (the dir symlink alone only covers the final component / synthetic /proc target).
    char[1024] _objp = void;
    if (cstrEqPrefix(path, "/objects/processes")) {
        const(char)* rest = path + 18;            // char after "/objects/processes"
        if (*rest == 0 || *rest == '/') {
            size_t pos = 0;
            foreach (c; "/proc") _objp[pos++] = c;
            while (*rest != 0 && pos + 1 < _objp.length) _objp[pos++] = *rest++;
            _objp[pos] = 0;
            path = _objp.ptr;
        }
    }

    // M3: NM opens its wifi device plugin at NMPLUGINDIR/libnm-device-plugin-wifi.so, but the plugin
    // ships as the boot module /libnm-device-plugin-wifi.so.  Rewrite to the boot module so we DON'T copy
    // it into the synthetic /usr/lib/... dir (a copy creates a shadowing rtfs node that breaks the
    // SYNTHDIR_NMPLUGIN getdents listing).  Also used by the stat path (nm_utils_validate_plugin).
    if (cstrEq(path, "/usr/lib/NetworkManager/1.44.2/libnm-device-plugin-wifi.so"))
        path = "/libnm-device-plugin-wifi.so".ptr;

    // Track A A2: resolve a leading RT-overlay symlink chain so open() follows
    // symlinks (e.g. /bin/ls -> /busybox).  No-op unless the path ends at an RT_LNK.
    char[1024] _lnkA = void;
    char[1024] _lnkB = void;
    path = rtFollowSymlinks(path, _lnkA.ptr, _lnkB.ptr, 1024);

    int nsOpen = namespaceCheckOpen(path, flags);
    if (nsOpen < 0) return nsOpen;

    // Find free FD — POSIX: the lowest-numbered free descriptor, INCLUDING 0/1/2 when those
    // have been explicitly closed (matches dup()/pipe(), which already scan from 0).  This is
    // what makes the classic "close fd 0, reopen to land it on 0" idiom work — e.g. zsh
    // redirecting a background job's stdin: `zclose(0); open("/dev/null", O_RDWR)` expects fd 0.
    // For a normal task 0/1/2 stay open (stdin/stdout/stderr), so open still returns >= 3.
    int fd = -1;
    for(int i=0; i<1024; i++) {
        if (g_fdTable[i].type == FileType.FD_NONE) {
            fd = i;
            break;
        }
    }
    if (fd == -1) return negErrno(EMFILE);

    if (cstrEq(path, "/dev/null")) {
        g_fdTable[fd].type = FileType.FD_NULL;
        g_fdTable[fd].flags = flags;
        g_fdTable[fd].offset = 0;
        g_fdTable[fd].backend = null;
        g_fdTable[fd].fileSize = 0;
        deviceNoteOpen(path);
        return publishActiveFdReturn(fd);
    }

    if (cstrEq(path, "/dev/zero")) {
        g_fdTable[fd].type = FileType.FD_ZERO;
        g_fdTable[fd].flags = flags;
        g_fdTable[fd].offset = 0;
        g_fdTable[fd].backend = null;
        g_fdTable[fd].fileSize = 0;
        deviceNoteOpen(path);
        return publishActiveFdReturn(fd);
    }

    if (cstrEq(path, "/dev/urandom")) {
        g_fdTable[fd].type = FileType.FD_URANDOM;
        g_fdTable[fd].flags = flags;
        g_fdTable[fd].offset = 0;
        g_fdTable[fd].backend = null;
        g_fdTable[fd].fileSize = 0;
        deviceNoteOpen(path);
        return publishActiveFdReturn(fd);
    }

    // /dev/fb0 — read-only view of the composited framebuffer (for the Screenshot app).
    // read() streams the pixels row-by-row as width*height*4 XRGB8888 bytes (padding stripped);
    // FBIOGET_VSCREENINFO returns the geometry.  See fileObjRead FD_FB + linux_sys_ioctl.
    if (cstrEq(path, "/dev/fb0")) {
        import display.framebuffer : g_fb;
        g_fdTable[fd].type = FileType.FD_FB;
        g_fdTable[fd].flags = flags;
        g_fdTable[fd].offset = 0;
        g_fdTable[fd].backend = null;
        g_fdTable[fd].fileSize = cast(ulong)g_fb.width * g_fb.height * 4;
        deviceNoteOpen(path);
        return publishActiveFdReturn(fd);
    }

    if (cstrEq(path, "/dev/random")) {
        g_fdTable[fd].type = FileType.FD_RANDOM;
        g_fdTable[fd].flags = flags;
        g_fdTable[fd].offset = 0;
        g_fdTable[fd].backend = null;
        g_fdTable[fd].fileSize = 0;
        deviceNoteOpen(path);
        return publishActiveFdReturn(fd);
    }

    if (cstrEq(path, "/dev/tty") || cstrEq(path, "/dev/console") || cstrEq(path, "/dev/stdin") ||
        cstrEq(path, "/dev/stdout") || cstrEq(path, "/dev/stderr")) {
        g_fdTable[fd].type = FileType.FD_CONSOLE;
        g_fdTable[fd].flags = flags;
        g_fdTable[fd].offset = 0;
        g_fdTable[fd].backend = null;
        g_fdTable[fd].fileSize = 0;
        deviceNoteOpen(path);
        return publishActiveFdReturn(fd);
    }

    // DM8 §7: enforce the calling task's identity device policy on brokered device nodes
    // (input/gpu/camera/mic/audio/usb) — a domain that denies a class cannot open its node.
    { const int dg = deviceClassGate(path); if (dg < 0) return dg; }

    // /dev/dri/card0, /dev/dri/renderD128 → DRM/KMS device
    if (cstrEq(path, "/dev/dri/card0") || cstrEq(path, "/dev/dri/renderD128")) {
        g_fdTable[fd].type    = FileType.FD_DRM;
        g_fdTable[fd].flags   = flags;
        g_fdTable[fd].offset  = 0;
        // backend!=null marks the *render* node so stat() reports minor 128
        // (DRM_NODE_RENDER); card0 keeps backend=null -> minor 0 (DRM_NODE_PRIMARY).
        // Mesa's EGL gbm init only skips the "compatible render device" search when
        // drmGetNodeTypeFromFd(fd) == DRM_NODE_RENDER (i.e. minor>>6 == 2).
        g_fdTable[fd].backend = cstrEq(path, "/dev/dri/renderD128") ? cast(void*)1 : null;
        g_fdTable[fd].fileSize = 0;
        deviceNoteOpen(path);
        if (cstrEq(path, "/dev/dri/card0")) dispMark(g_dispLogCard0, "card0 opened\0".ptr);
        return publishActiveFdReturn(fd);
    }

    // /dev/ptmx → allocate a new pseudo-terminal, return the master (GUI G4)
    if (cstrEq(path, "/dev/ptmx")) {
        int idx = ptyAlloc();
        if (idx < 0) return negErrno(ENOMEM);
        g_fdTable[fd].type     = FileType.FD_PTY_MASTER;
        g_fdTable[fd].flags    = flags;
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = cast(void*)cast(size_t)idx;
        g_fdTable[fd].fileSize = 0;
        deviceNoteOpen(path);
        return publishActiveFdReturn(fd);
    }

    // /dev/pts/N → open the slave end of an already-allocated pseudo-terminal
    if (cstrEqPrefix(path, "/dev/pts/")) {
        const(char)* p = path + 9; // first digit after "/dev/pts/"
        if (*p < '0' || *p > '9') return negErrno(ENOENT);
        int idx = 0;
        while (*p >= '0' && *p <= '9') { idx = idx * 10 + (*p - '0'); p++; }
        if (idx < 0 || idx >= PTY_MAX || !g_ptys[idx].inUse) return negErrno(ENXIO);
        g_fdTable[fd].type     = FileType.FD_PTY_SLAVE;
        g_fdTable[fd].flags    = flags;
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = cast(void*)cast(size_t)idx;
        g_fdTable[fd].fileSize = 0;
        deviceNoteOpen(path);
        return publishActiveFdReturn(fd);
    }

    // /dev/input/event* → input event device; backend encodes device index (0=kbd,1=mouse)
    if (cstrEqPrefix(path, "/dev/input/event")) {
        const(char)* p = path + 16; // points to digit after "event"
        int devIdx = 0;
        while (*p >= '0' && *p <= '9') { devIdx = devIdx * 10 + (*p - '0'); p++; }
        g_fdTable[fd].type     = FileType.FD_INPUT_EVENT;
        g_fdTable[fd].flags    = flags;
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = cast(void*)cast(size_t)devIdx;
        g_fdTable[fd].fileSize = 0;
        deviceNoteOpen(path);
        return publishActiveFdReturn(fd);
    }

    // Existing rtfs assets take priority over the synthetic-directory and
    // virtual-file shims below: the unpacked xkb/fonts asset trees live under
    // /usr/share/X11/xkb, whose ancestor paths are also listed as synthetic dirs,
    // so without this a file open like .../rules/evdev would resolve to a 0-byte
    // synthetic directory (fstat size 0 → mmap(0) → EINVAL in libxkbcommon).
    {
        int rp; const(char)* rl; size_t rll;
        const int ri = rtResolve(path, rp, rl, rll);
        if (ri >= 0 && g_rt[ri].kind == RT_REG) {
            if ((flags & O_CREAT) && (flags & O_EXCL)) return negErrno(EEXIST);
            if (flags & O_TRUNC) g_rt[ri].size = 0;
            g_fdTable[fd].type     = FileType.FD_RTFILE;
            g_fdTable[fd].flags    = flags;
            g_fdTable[fd].offset   = (flags & O_APPEND) ? g_rt[ri].size : 0;
            g_fdTable[fd].backend  = cast(void*)cast(size_t)ri;
            g_fdTable[fd].fileSize = g_rt[ri].size;
            return publishActiveFdReturn(fd);
        } else if (ri >= 0 && g_rt[ri].kind == RT_DIR) {
            if ((flags & 3) != O_RDONLY) return negErrno(EISDIR);
            g_fdTable[fd].type     = FileType.FD_RTDIR;
            g_fdTable[fd].flags    = flags;
            g_fdTable[fd].offset   = 0;
            g_fdTable[fd].backend  = cast(void*)cast(size_t)ri;
            g_fdTable[fd].fileSize = 0;
            // M3: an rtfs RT_DIR shadows NMPLUGINDIR (something creates the dir) — tag it so getdents
            // still lists the wifi plugin (the SYNTHDIR_NMPLUGIN case runs before the empty rt-children loop).
            if (cstrEq(path, "/usr/lib/NetworkManager/1.44.2")) g_fdTable[fd].fileSize = SYNTHDIR_NMPLUGIN;
            return publishActiveFdReturn(fd);
        }
    }

    // An explicit virtual FILE (g_vfs) must win over the synthetic-DIRECTORY shim
    // below: isSyntheticDirectoryPath() also returns true for paths under certain
    // prefixes (isVirtualDirectoryPath), which would otherwise serve a real file
    // like /sys/class/drm/card0/uevent as an empty 0-byte directory — udev-zero
    // then reads no DEVNAME and Weston rejects "card0 is not a KMS device".
    // A4: dynamic /proc/<pid>/<file> (stat/status/cmdline/comm) for ps/top.  Must run
    // before the synthetic-directory shim so the file isn't mistaken for a directory.
    {
        const(char)* psub; size_t psubLen;
        const int ppid = procParsePid(path, psub, psubLen);
        if (ppid > 0 && psub !is null) {
            const size_t plen = procSynth(ppid, psub, psubLen);
            if (plen > 0) {
                g_fdTable[fd].type     = FileType.FD_FILE;
                g_fdTable[fd].flags    = flags & ~(O_WRONLY | O_RDWR);
                g_fdTable[fd].offset   = 0;
                g_fdTable[fd].backend  = cast(void*)g_procBuf.ptr;
                g_fdTable[fd].fileSize = plen;
                return publishActiveFdReturn(fd);
            }
        }
    }

    // F1/F5: /objects/<kind>/<obj>/<field> — render the object's meta / capabilities /
    // relationships (each object is a directory of these field files; F5).
    {
        const(char)* osub; size_t osubLen; int ofield;
        const int okind = objfsParseDeep(path, osub, osubLen, ofield);
        if (okind > 0 && osub !is null && ofield > 0) {
            const long olen = objfsField(okind, osub, osubLen, ofield, g_procBuf.ptr, g_procBuf.length - 1);
            if (olen > 0) {
                g_fdTable[fd].type     = FileType.FD_FILE;
                g_fdTable[fd].flags    = flags & ~(O_WRONLY | O_RDWR);
                g_fdTable[fd].offset   = 0;
                g_fdTable[fd].backend  = cast(void*)g_procBuf.ptr;
                g_fdTable[fd].fileSize = cast(ulong)olen;
                return publishActiveFdReturn(fd);
            }
            if (olen < 0) return negErrno(ENOENT);
        }
    }

    // F4: /objects/apps/<app>/<file> — read the persisted app blobs (manifest,
    // permissions, identity-binding, executable, storage/data) off the object store.
    {
        int appIdx;
        const int ak = appsfsParse(path, appIdx);
        if (ak >= 3 && ak != 7) {                 // a file (not the /storage dir)
            auto e = objstoreApp(appIdx);
            if (e is null) return negErrno(ENOENT);
            int n = 0;
            if      (ak == 3) n = objstoreReadBlob(e.manifestLba, e.manifestLen, cast(ubyte*)g_appsBuf.ptr, g_appsBuf.length - 1);
            else if (ak == 4) n = objstoreReadBlob(e.permsLba,    e.permsLen,    cast(ubyte*)g_appsBuf.ptr, g_appsBuf.length - 1);
            else if (ak == 5) n = appsRenderIdentity(e, cast(ubyte*)g_appsBuf.ptr, g_appsBuf.length - 1);
            else if (ak == 6) n = objstoreReadBlob(e.execLba,     e.execLen,     cast(ubyte*)g_appsBuf.ptr, g_appsBuf.length - 1);
            else if (ak == 8) n = objstoreReadBlob(e.storageLba,  e.storageLen,  cast(ubyte*)g_appsBuf.ptr, g_appsBuf.length - 1);
            g_fdTable[fd].type     = FileType.FD_FILE;
            g_fdTable[fd].flags    = flags & ~(O_WRONLY | O_RDWR);
            g_fdTable[fd].offset   = 0;
            g_fdTable[fd].backend  = cast(void*)g_appsBuf.ptr;
            g_fdTable[fd].fileSize = cast(ulong)(n > 0 ? n : 0);
            return publishActiveFdReturn(fd);
        }
    }

    // F4: /objects/store — the object-store info file (boots = persistence proof).
    if (cstrEq(path, "/objects/store")) {
        size_t pos = 0;
        void put(const(char)* s) { while (*s && pos < g_appsBuf.length - 1) g_appsBuf[pos++] = *s++; }
        void dec(ulong v) { char[24] t=void; int i=0; if(!v)t[i++]='0'; while(v){t[i++]=cast(char)('0'+v%10);v/=10;} while(i>0 && pos<g_appsBuf.length-1) g_appsBuf[pos++]=t[--i]; }
        if (objstoreMounted()) {
            put("store=HOSOBJFS\nmounted=true\napps=".ptr); dec(objstoreAppCount());
            put("\nboots=".ptr); dec(objstoreBootCount()); put("\n".ptr);
        } else {
            put("store=none\nmounted=false\n".ptr);
        }
        g_fdTable[fd].type = FileType.FD_FILE;
        g_fdTable[fd].flags = flags & ~(O_WRONLY | O_RDWR);
        g_fdTable[fd].offset = 0;
        g_fdTable[fd].backend = cast(void*)g_appsBuf.ptr;
        g_fdTable[fd].fileSize = cast(ulong)pos;
        return publishActiveFdReturn(fd);
    }

    // DM10.3: /config/domain.action — the domain CONTROL-WRITE file.  The Domain Manager (a
    // Linux-personality client) writes a "verb name [arg]" command here to invoke a domain
    // lifecycle/overlay op (start/stop/pause/resume/snapshot/commit/clone).  The write handler
    // (fileObjWrite, FD_DOMAIN_CTL) routes to domainControlWrite — itself deny-by-default.
    if (cstrEq(path, "/config/domain.action")) {
        if ((flags & 3) == O_RDONLY) return negErrno(EACCES);   // write-only control endpoint
        g_fdTable[fd].type     = FileType.FD_DOMAIN_CTL;
        g_fdTable[fd].flags    = flags;
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = null;
        g_fdTable[fd].fileSize = 0;
        return publishActiveFdReturn(fd);
    }

    // INSTALLER §D: /config/install.action — the installer CONTROL-WRITE file.  The "Install to
    // Disk" app writes "install [diskidx]" here to install the running OS to a target disk.
    if (cstrEq(path, "/config/install.action")) {
        if ((flags & 3) == O_RDONLY) return negErrno(EACCES);   // write-only control endpoint
        g_fdTable[fd].type     = FileType.FD_INSTALL_CTL;
        g_fdTable[fd].flags    = flags;
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = null;
        g_fdTable[fd].fileSize = 0;
        return publishActiveFdReturn(fd);
    }

    // INSTALLER §D: /config/install.progress — read-only; returns the install progress as a
    // 0..1000 permille decimal string so the installer GUI can draw a progress bar.
    if (cstrEq(path, "/config/install.progress")) {
        if ((flags & 3) != O_RDONLY) return negErrno(EACCES);   // read-only
        g_fdTable[fd].type     = FileType.FD_INSTALL_PROGRESS;
        g_fdTable[fd].flags    = flags;
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = null;
        g_fdTable[fd].fileSize = 0;
        return publishActiveFdReturn(fd);
    }

    // UPDATE U1: /config/update.action — the A/B update engine CONTROL-WRITE file (mirrors
    // install.action).  Writes are verbs: switch / rollback / boot-ok / status / init-state.
    if (cstrEq(path, "/config/update.action")) {
        if ((flags & 3) == O_RDONLY) return negErrno(EACCES);   // write-only control endpoint
        g_fdTable[fd].type     = FileType.FD_UPDATE_CTL;
        g_fdTable[fd].flags    = flags;
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = null;
        g_fdTable[fd].fileSize = 0;
        return publishActiveFdReturn(fd);
    }

    // UPDATE U1: /config/update.status — read-only; returns the update-engine state as JSON
    // (version, boot slot, A/B state, last verb outcome) for the Settings System Update page.
    if (cstrEq(path, "/config/update.status")) {
        if ((flags & 3) != O_RDONLY) return negErrno(EACCES);   // read-only
        g_fdTable[fd].type     = FileType.FD_UPDATE_STATUS;
        g_fdTable[fd].flags    = flags;
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = null;
        g_fdTable[fd].fileSize = 0;
        return publishActiveFdReturn(fd);
    }

    // DRIVERS: /config/hardware.detect — read-only; returns a comma-separated list of the Linux driver
    // codes for the PCI devices actually present (e.g. "iwlwifi,e1000e,snd_hda_intel"), so the installer
    // Drivers page auto-populates + pre-checks the hardware in THIS machine (like install.progress above).
    if (cstrEq(path, "/config/hardware.detect")) {
        if ((flags & 3) != O_RDONLY) return negErrno(EACCES);   // read-only
        g_fdTable[fd].type     = FileType.FD_HW_DETECT;
        g_fdTable[fd].flags    = flags;
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = null;
        g_fdTable[fd].fileSize = 0;
        return publishActiveFdReturn(fd);
    }

    // /run/klog (also /dev/klog) — read-only live view of the kernel log RAM ring (see fileObjRead
    // FD_KLOG).  The desktop "Logs" viewer opens this to show the FULL boot + driver log (kernel klog,
    // lkl-boot/iwlwifi, dbus/NM/wpa) without needing serial capture or a boot photo.  Not an rtfs node,
    // so this synthetic intercept (like install.progress above) is what serves it.
    if (cstrEq(path, "/run/klog") || cstrEq(path, "/dev/klog")) {
        if ((flags & 3) != O_RDONLY) return negErrno(EACCES);   // read-only
        import core.io : g_klogHead, KLOG_RING_SIZE;
        const ulong head = g_klogHead;
        g_fdTable[fd].type     = FileType.FD_KLOG;
        g_fdTable[fd].flags    = flags;
        g_fdTable[fd].offset   = (head > KLOG_RING_SIZE) ? head - KLOG_RING_SIZE : 0;  // oldest retained byte
        g_fdTable[fd].backend  = null;
        g_fdTable[fd].fileSize = head;                                                 // live size (refreshed in lseek/fstat)
        return publishActiveFdReturn(fd);
    }

    // F2: /config/<name>.json — render the live tables as declarative JSON.
    {
        const int cfgId = configfsParse(path);
        if (cfgId > 0) {
            if ((flags & 3) != O_RDONLY) return negErrno(EROFS);  // read-only for now (F2.2 = writable)
            const long clen = configfsRender(cfgId, g_configBuf.ptr, g_configBuf.length - 1);
            if (clen > 0) {
                g_fdTable[fd].type     = FileType.FD_FILE;
                g_fdTable[fd].flags    = flags & ~(O_WRONLY | O_RDWR);
                g_fdTable[fd].offset   = 0;
                g_fdTable[fd].backend  = cast(void*)g_configBuf.ptr;
                g_fdTable[fd].fileSize = cast(ulong)clen;
                return publishActiveFdReturn(fd);
            }
            if (clen < 0) return negErrno(ENOENT);
        }
    }

    // F3: /system immutable base — read-only views over the active generation +
    // base components.  Any write/create ANYWHERE under /system is denied (EROFS),
    // not just the recognised documents — the base is immutable.
    {
        if (cstrEq(path, "/system") || cstrEqPrefix(path, "/system/")) {
            if ((flags & O_CREAT) || (flags & 3) != O_RDONLY) return negErrno(EROFS);
        }
        const(char)* scomp; size_t scompLen;
        const int sk = sysfsParse(path, scomp, scompLen);
        if (sk != 0) {
            long slen = -1;
            if      (sk == 2) slen = sysGenList(g_sysBuf.ptr, g_sysBuf.length - 1);
            else if (sk == 4) slen = sysGenMeta(g_sysBuf.ptr, g_sysBuf.length - 1);
            else if (sk == 5) slen = sysComponentMeta(scomp, scompLen);
            else if (sk == 7) slen = sysStateInstalled(g_sysBuf.ptr, g_sysBuf.length - 1);
            if (slen > 0) {
                g_fdTable[fd].type     = FileType.FD_FILE;
                g_fdTable[fd].flags    = flags & ~(O_WRONLY | O_RDWR);
                g_fdTable[fd].offset   = 0;
                g_fdTable[fd].backend  = cast(void*)g_sysBuf.ptr;
                g_fdTable[fd].fileSize = cast(ulong)slen;
                return publishActiveFdReturn(fd);
            }
            if (sk == 5 && slen < 0) return negErrno(ENOENT);
            // sk == 1 or 3 (a directory) falls through to the synthetic-dir handling.
        }
    }

    if (isSyntheticDirectoryPath(path) && !pathIsExactVfsFile(path)) {
        if ((flags & 3) != O_RDONLY) {
            return negErrno(EISDIR);
        }
        initSyntheticFileFd(fd, flags, fileBackendDirectory);
        // Tag /sys/dev/char so getdents64 can enumerate the char-device entries
        // libudev-zero scans there to discover input (and DRM) devices.
        if (cstrEq(path, "/sys/dev/char")) g_fdTable[fd].fileSize = SYNTHDIR_DEVCHAR;
        // R3: tag the virtio-gpu .../device/drm dir so getdents lists card0+renderD128
        // (libdrm scandirs it to set available_nodes = PRIMARY|RENDER).
        if (cstrEq(path, "/sys/dev/char/226:0/device/drm") ||
            cstrEq(path, "/sys/dev/char/226:128/device/drm")) g_fdTable[fd].fileSize = SYNTHDIR_DRMDIR;
        // R3: tag /dev/dri so getdents lists card0+renderD128 — libdrm's
        // opendir("/dev/dri")+readdir loop (BOTH drmGetDevice2 and drmGetDevices2)
        // needs these entries to call process_device() and build the device list.
        if (cstrEq(path, "/dev/dri")) g_fdTable[fd].fileSize = SYNTHDIR_DEVDRI;
        // Tag /proc so getdents64 enumerates the live process pids (ps/top).
        if (cstrEq(path, "/proc")) g_fdTable[fd].fileSize = SYNTHDIR_PROC;
        // M3: tag /sys/class/net so getdents64 lists lo + wlan0 -> NM discovers the wifi device.
        if (cstrEq(path, "/sys/class/net")) g_fdTable[fd].fileSize = SYNTHDIR_NETCLASS;
        // M3: tag NMPLUGINDIR (dead now — wifi is an internal factory, load_factories_from_dir disabled —
        // but harmless; NM never reads this dir).
        if (cstrEq(path, "/usr/lib/NetworkManager/1.44.2")) g_fdTable[fd].fileSize = SYNTHDIR_NMPLUGIN;
        // F1: tag /objects/<kind> so getdents64 enumerates its live objects.
        // F5: tag /objects/<kind>/<obj> so getdents64 lists its field files.
        {
            const(char)* osub; size_t osubLen; int ofield;
            const int okind = objfsParseDeep(path, osub, osubLen, ofield);
            if (okind > 0 && osub is null)        g_fdTable[fd].fileSize = SYNTHDIR_OBJ_BASE + okind;
            else if (okind > 0 && ofield == 0)    g_fdTable[fd].fileSize = SYNTHDIR_OBJ_ENTRY + cast(ulong)okind; // DM2.4: encode kind
        }
        // F3: tag /system/current so getdents64 enumerates the base components.
        {
            const(char)* sc; size_t scl;
            if (sysfsParse(path, sc, scl) == 3) g_fdTable[fd].fileSize = SYNTHDIR_SYSCUR;
            if (sysfsParse(path, sc, scl) == 6) g_fdTable[fd].fileSize = SYNTHDIR_SYSSTATE;
        }
        // F4: tag the /objects/apps directory tree for getdents enumeration.
        {
            int ai;
            const int ak = appsfsParse(path, ai);
            if (ak == 1)      g_fdTable[fd].fileSize = SYNTHDIR_APPS;
            else if (ak == 2) g_fdTable[fd].fileSize = SYNTHDIR_APP_BASE + ai;
            else if (ak == 7) g_fdTable[fd].fileSize = SYNTHDIR_STOR_BASE + ai;
        }
        return publishActiveFdReturn(fd);
    }

    if (cstrEq(path, "/proc/self/exe")) {
        return sys_open("/init.elf\0".ptr, flags);
    }

    ulong modPhys = 0;
    ulong modSize = 0;
    if (findBootModule(path, modPhys, modSize) ||
        findBootModuleLib(path, modPhys, modSize)) {
        g_fdTable[fd].type = FileType.FD_BOOT_MODULE;
        g_fdTable[fd].flags = flags;
        g_fdTable[fd].offset = 0;
        g_fdTable[fd].backend = cast(void*)modPhys;
        g_fdTable[fd].fileSize = modSize;
        return publishActiveFdReturn(fd);
    }

    // Check Bundle
    BundleFile bf;
    if (findBundleFile(path, bf)) {
         g_fdTable[fd].type = FileType.FD_BUNDLE;
         g_fdTable[fd].flags = flags;
         g_fdTable[fd].offset = 0;
         g_fdTable[fd].backend = cast(void*)bf.offset;
         g_fdTable[fd].fileSize = bf.size;
         return publishActiveFdReturn(fd);
    }

    // ORG P9.3 / IR-P3: object-reference-graph exports require the typed
    // ADMIN_INSPECT cap; uid 0 is not consulted.
    if (cstrEq(path, "/proc/cmdline")) {
        const(char)[] content = displayCmdlineContent();
        g_fdTable[fd].type     = FileType.FD_FILE;
        g_fdTable[fd].flags    = flags & ~(O_WRONLY | O_RDWR);
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = (content.length > 0)
            ? cast(void*)content.ptr
            : cast(void*)cast(size_t)(fileBackendDirectory + 1);
        g_fdTable[fd].fileSize = content.length;
        return publishActiveFdReturn(fd);
    }

    if (cstrEq(path, "/proc/org/graph") || cstrEq(path, "/proc/org/stats")) {
        if (!adminRequire(CAP_RIGHT_ADMIN_INSPECT)) return negErrno(EACCES);
        const(char)[] content = cstrEq(path, "/proc/org/graph")
            ? orgDotContent() : orgStatsContent();
        g_fdTable[fd].type     = FileType.FD_FILE;
        g_fdTable[fd].flags    = flags & ~(O_WRONLY | O_RDWR);
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = (content.length > 0)
            ? cast(void*)content.ptr
            : cast(void*)cast(size_t)(fileBackendDirectory + 1);
        g_fdTable[fd].fileSize = content.length;
        return publishActiveFdReturn(fd);
    }

    if (cstrEq(path, "/proc/display-info")) {
        const(char)[] content = displayInfoContent();
        g_fdTable[fd].type     = FileType.FD_FILE;
        g_fdTable[fd].flags    = flags & ~(O_WRONLY | O_RDWR);
        g_fdTable[fd].offset   = 0;
        g_fdTable[fd].backend  = (content.length > 0)
            ? cast(void*)content.ptr
            : cast(void*)cast(size_t)(fileBackendDirectory + 1);
        g_fdTable[fd].fileSize = content.length;
        return publishActiveFdReturn(fd);
    }

    // Check virtual filesystem table (/proc/*, /sys/*, /etc/*, ...)
    {
        const(char)[] dyn = pxHostnameVirtualFile(path);
        if (dyn.length > 0) {
            g_fdTable[fd].type     = FileType.FD_FILE;
            g_fdTable[fd].flags    = flags & ~(O_WRONLY | O_RDWR);
            g_fdTable[fd].offset   = 0;
            g_fdTable[fd].backend  = cast(void*)dyn.ptr;
            g_fdTable[fd].fileSize = dyn.length;
            return publishActiveFdReturn(fd);
        }
    }
    foreach (ref vfe; g_vfs) {
        if (cstrEq(path, vfe.path)) {
            g_fdTable[fd].type     = FileType.FD_FILE;
            g_fdTable[fd].flags    = flags & ~(O_WRONLY | O_RDWR); // read-only
            g_fdTable[fd].offset   = 0;
            // backend > fileBackendDirectory signals virtual content;
            // for non-empty content use the data pointer, for empty use sentinel 3.
            g_fdTable[fd].backend  = (vfe.content.length > 0)
                ? cast(void*)vfe.content.ptr
                : cast(void*)cast(size_t)(fileBackendDirectory + 1);
            g_fdTable[fd].fileSize = vfe.content.length;
            return publishActiveFdReturn(fd);
        }
    }

    // Writable runtime overlay (rtfs): /run, /tmp, /var/tmp subtrees.
    {
        int rparent; const(char)* rleaf; size_t rleafLen;
        const int ridx = rtResolve(path, rparent, rleaf, rleafLen);
        if (ridx >= 0) {
            if (g_rt[ridx].kind == RT_DIR) {
                if ((flags & 3) != O_RDONLY) return negErrno(EISDIR);
                g_fdTable[fd].type     = FileType.FD_RTDIR;
                g_fdTable[fd].flags    = flags;
                g_fdTable[fd].offset   = 0;
                g_fdTable[fd].backend  = cast(void*)cast(size_t)ridx;
                g_fdTable[fd].fileSize = 0;
                return publishActiveFdReturn(fd);
            }
            // existing regular overlay file
            if ((flags & O_CREAT) && (flags & O_EXCL)) return negErrno(EEXIST);
            if (flags & O_TRUNC) { g_rt[ridx].size = 0; }
            g_fdTable[fd].type     = FileType.FD_RTFILE;
            g_fdTable[fd].flags    = flags;
            g_fdTable[fd].offset   = (flags & O_APPEND) ? g_rt[ridx].size : 0;
            g_fdTable[fd].backend  = cast(void*)cast(size_t)ridx;
            g_fdTable[fd].fileSize = g_rt[ridx].size;
            return publishActiveFdReturn(fd);
        }
        // create a new file when requested and the parent is a writable overlay dir
        if ((flags & O_CREAT) && rparent >= 0 && rleaf !is null &&
            g_rt[rparent].kind == RT_DIR) {
            const int created = rtCreate(rparent, rleaf, rleafLen, RT_REG,
                                         cast(ushort)0x1B6 /*0666*/,
                                         userCurrentUid(), userCurrentGid());
            if (created < 0) return negErrno(ENOSPC);
            g_fdTable[fd].type     = FileType.FD_RTFILE;
            g_fdTable[fd].flags    = flags;
            g_fdTable[fd].offset   = 0;
            g_fdTable[fd].backend  = cast(void*)cast(size_t)created;
            g_fdTable[fd].fileSize = 0;
            return publishActiveFdReturn(fd);
        }
    }

    if ((flags & O_CREAT) != 0) {
        initPlainFileFd(fd, flags);
        return publishActiveFdReturn(fd);
    }

    // DIAGNOSTIC (Hyprland reopenDRMNode hunt): log DRM-related sysfs paths that
    // aren't found, so we can see exactly what libdrm's drmGetDeviceNameFromFd2 /
    // drmGetDevice2 needs but the synthetic sysfs is missing.
    if (g_drmSysfsProbe && g_drmSysfsFailN < 48 &&
        (cstrEqPrefix(path, "/sys/dev/char/226") || cstrEqPrefix(path, "/sys/class/drm") ||
         cstrEqPrefix(path, "/sys/bus/pci") || cstrEqPrefix(path, "/sys/devices"))) {
        ++g_drmSysfsFailN;
        klog("[sysfail] "); klog(path); klog("\n");
    }
    return negErrno(ENOENT);
}
__gshared bool  g_drmSysfsProbe = false;   // Hyprland DRM sysfs diagnostic (flip true to re-hunt)
__gshared ulong g_drmSysfsFailN = 0;

private long fileObjClose(ObjHeader* oh) {
    File* f = fileFromObj(oh);
    if (f is null) return negErrno(EBADF);
    ++g_objOpsDispatch;
    uint oid = oh.id;

    if (f.type == FileType.FD_SOCKET) {
        closeLocalSocket(f);
    } else if (f.type == FileType.FD_EPOLL) {
        // Instance is shared across fork-copied tables and dups (see fdInstanceRef);
        // destroy only when the LAST reference closes — a forked child exiting must
        // not kill the parent's live event loop.
        int eid = cast(int)cast(size_t)f.backend;
        if (eid >= 0 && eid < EPOLL_MAX_INSTANCES && g_epollTable[eid].inUse) {
            if (g_epollTable[eid].refs > 1) --g_epollTable[eid].refs;
            else g_epollTable[eid].inUse = false;
        }
    } else if (f.type == FileType.FD_EVENTFD) {
        int eid = cast(int)cast(size_t)f.backend;
        if (eid >= 0 && eid < EVENTFD_MAX && g_eventfd_inUse[eid]) {
            if (g_eventfd_refs[eid] > 1) --g_eventfd_refs[eid];
            else g_eventfd_inUse[eid] = false;
        }
    } else if (f.type == FileType.FD_TIMERFD) {
        // Free the timer slot when the last fd copy closes (timerfds previously never
        // freed → 16-slot exhaustion during boot churn → the compositor's idle timerfd
        // create failed and the frame engine died after its first frame).
        int ttid = cast(int)cast(size_t)f.backend;
        if (ttid >= 0 && ttid < TIMERFD_MAX && g_timerfds[ttid].inUse) {
            if (g_timerfds[ttid].refs > 1) --g_timerfds[ttid].refs;
            else g_timerfds[ttid] = TimerFdRec.init;
        }
    } else if (f.type == FileType.FD_MEMFD) {
        // Reclaim PRIME-aliased records (borrowed GEM pages) so the swapchain's
        // buffer cycle doesn't exhaust the memfd table.  Owner memfds are left
        // as-is (their pages are bump-allocated and never freed anyway).
        // Refcounted like epoll above: only the last fd copy reclaims.
        int mid = cast(int)cast(size_t)f.backend;
        if (mid >= 0 && mid < MEMFD_MAX && g_memfds[mid].inUse && g_memfds[mid].refs > 1) {
            --g_memfds[mid].refs;
        } else if (mid >= 0 && mid < MEMFD_MAX && g_memfds[mid].inUse && g_memfds[mid].aliased) {
            if (g_memfds[mid].vmoObjId != 0 && objGet(g_memfds[mid].vmoObjId) !is null)
                objRelease(g_memfds[mid].vmoObjId);
            if (g_memfds[mid].vgemHandle != 0)   // release the export ref this alias held
                drmGemFreeHandle(g_memfds[mid].vgemHandle);
            g_memfds[mid].inUse      = false;
            g_memfds[mid].refs       = 0;
            g_memfds[mid].physBase   = 0;
            g_memfds[mid].size       = 0;
            g_memfds[mid].vmoObjId   = 0;
            g_memfds[mid].aliased    = false;
            g_memfds[mid].vgemHandle = 0;  // R3: clear the virgl-alias mark on reuse
        }
    }

    if (f.type == FileType.FD_PIPE_READ) {
        auto pipe_ = getPipe(cast(size_t)pipeIdFromFd(f));
        if (pipe_ !is null) {
            --pipe_.readers;
            if (pipe_.readers <= 0 && pipe_.writers <= 0)
                pipe_.inUse = false;
        }
    } else if (f.type == FileType.FD_PIPE_WRITE) {
        auto pipe_ = getPipe(cast(size_t)pipeIdFromFd(f));
        if (pipe_ !is null) {
            --pipe_.writers;
            if (pipe_.readers <= 0 && pipe_.writers <= 0)
                pipe_.inUse = false;
        }
    }

    f.backend = null;
    f.type = FileType.FD_NONE;
    f.flags = 0;
    f.offset = 0;
    f.fileSize = 0;
    f.objId = 0;
    objRelease(oid);
    return 0;
}

public int sys_close(int fd) {
    ObjHeader* oh = fdObjectByIndexWithRights(fd, CAP_RIGHT_CLOSE);
    if (oh is null) return negErrno(EBADF);
    auto cop = g_objOps[oh.type].close;
    if (cop is null) return negErrno(EBADF);
    int ret = cast(int)cop(oh);
    if (ret == 0) capClear(cast(uint)fd);
    return ret;
}

// Close EVERY fd in a task's fd table on exit (no cap check — the task is gone).
// Critical for sockets: closeLocalSocket marks the PEER's `peerClosed`, so a
// Wayland client's exit makes Weston's end readable → Weston reaps the dead
// client and repaints (otherwise the closed window lingers on screen).  It is
// refcount-aware, so closing a fork-shared copy only hangs up the peer when the
// last holder goes.  Caller must ensure no live thread still shares `fdTabId`.
public void taskCloseAllFds(int fdTabId) {
    if (fdTabId < 0 || fdTabId >= FDTAB_COUNT) return;
    fdtabSetActive(fdTabId);
    foreach (fd; 0 .. 1024) {
        if (g_fdTable[fd].type == FileType.FD_NONE) continue;
        ObjHeader* oh = fdObjectByIndex(cast(int)fd);
        if (oh !is null) {
            auto cop = g_objOps[oh.type].close;
            if (cop !is null) cop(oh);
        }
        g_fdTable[fd].type = FileType.FD_NONE;
    }
}

public long linux_sys_read(ulong fd, ulong buf, ulong count) {
    return cast(long)sys_read(cast(int)fd, cast(void*)buf, cast(size_t)count);
}

public long linux_sys_write(ulong fd, ulong buf, ulong count) {
    return cast(long)sys_write(cast(int)fd, cast(const(void)*)buf, cast(size_t)count);
}

public long linux_sys_open(ulong path, ulong flags, ulong _mode) {
    auto p = cast(const(char)*)path;

    klog("[open] ");
    if (p !is null)
        klog(p);
    else
        klog("(null)");
    klog("\n");

    return cast(long)sys_open(cast(const(char)*)path, cast(int)flags);
}

public long linux_sys_close(ulong fd) {
    return cast(long)sys_close(cast(int)fd);
}

private long fileObjStat(ObjHeader* oh, ulong _statBuf) {
    File* f = fileFromObj(oh);
    if (f is null) return cast(long)negErrno(EBADF);
    ++g_objOpsDispatch;
    if (_statBuf != 0) {
        if (f.type == FileType.FD_BUNDLE || f.type == FileType.FD_BOOT_MODULE) {
            writeLinuxStat(_statBuf, 0x8000 | 0x01ED, f.fileSize); // S_IFREG | 0755 (executable: busybox, libs)
            // A unique (st_dev, st_ino) per file is essential: the dynamic
            // linker dedups shared objects by (dev, ino), so without it every
            // .so collapses onto one and dlsym() fails.  The backend value
            // (module phys addr / bundle offset) is unique per file.
            *cast(ulong*)(_statBuf + 0) =
                (f.type == FileType.FD_BOOT_MODULE) ? 1 : 2;        // st_dev
            *cast(ulong*)(_statBuf + 8) = cast(ulong)f.backend + 1; // st_ino
        } else if (fileIsSyntheticDirectory(f)) {
            writeLinuxStat(_statBuf, 0x4000 | 0x01ED, 0); // S_IFDIR | 0755
        } else if (f.type == FileType.FD_RTDIR) {
            const int idx = cast(int)cast(size_t)f.backend;
            const uint uid = (idx >= 0 && idx < RT_MAX_NODES) ? g_rt[idx].uid : userCurrentUid();
            const uint gid = (idx >= 0 && idx < RT_MAX_NODES) ? g_rt[idx].gid : userCurrentGid();
            const uint dmode = (idx >= 0 && idx < RT_MAX_NODES) ? g_rt[idx].mode : 0x1ED;
            writeLinuxStatOwned(_statBuf, 0x4000 | dmode, 0, uid, gid); // S_IFDIR | mode
        } else if (fileIsDevNull(f) || f.type == FileType.FD_CONSOLE) {
            clearLinuxStat(_statBuf);
            *cast(uint*)(_statBuf + 24) = 0x2000 | 0x0190; // S_IFCHR | 0620
            *cast(uint*)(_statBuf + 28) = userCurrentUid();
            *cast(uint*)(_statBuf + 32) = userCurrentGid();
        } else if (f.type == FileType.FD_DRM) {
            // Report the DRM device as a character device with the DRM major (226).
            // card0 = minor 0 (a "primary" node); renderD128 = minor 128 (a "render"
            // node).  libdrm's drmGetNodeTypeFromFd checks S_ISCHR + the encoded rdev
            // (minor>>6: 0=primary, 2=render) — Aquamarine's dumb-buffer allocator
            // wants the primary node, and Mesa's EGL gbm init only uses a render node
            // directly (skipping the failing "compatible render device" search) when
            // it sees minor>=128 here.
            clearLinuxStat(_statBuf);
            *cast(uint*)(_statBuf + 24) = 0x2000 | 0x01B6;     // S_IFCHR | 0666
            *cast(uint*)(_statBuf + 28) = userCurrentUid();
            *cast(uint*)(_statBuf + 32) = userCurrentGid();
            *cast(ulong*)(_statBuf + 40) =
                (f.backend !is null) ? 0xE280 : 0xE200;        // makedev(226,128) : makedev(226,0)
        } else if (f.type == FileType.FD_INPUT_EVENT) {
            // Char device, input major 13, minor 64 (event0) / 65 (event1).
            // libinput's evdev_device_have_same_syspath fstat()s the fd and maps
            // st_rdev back through /sys/dev/char/<maj:min>; without the right rdev
            // it can't match the udev device and rejects "failed to create".
            const int devIdx = cast(int)cast(size_t)f.backend;
            clearLinuxStat(_statBuf);
            *cast(uint*)(_statBuf + 24) = 0x2000 | 0x01B6;     // S_IFCHR | 0666
            *cast(uint*)(_statBuf + 28) = userCurrentUid();
            *cast(uint*)(_statBuf + 32) = userCurrentGid();
            *cast(ulong*)(_statBuf + 40) = 0x0D40 + cast(ulong)(devIdx == 1 ? 1 : 0); // makedev(13, 64|65)
        } else if (f.type == FileType.FD_SOCKET) {
            clearLinuxStat(_statBuf);
            *cast(uint*)(_statBuf + 24) = 0xC000 | 0x01B6; // S_IFSOCK | 0666
            *cast(uint*)(_statBuf + 28) = userCurrentUid();
            *cast(uint*)(_statBuf + 32) = userCurrentGid();
        } else if (f.type == FileType.FD_RTFILE) {
            const int idx = cast(int)cast(size_t)f.backend;
            const uint sz = (idx >= 0 && idx < RT_MAX_NODES) ? g_rt[idx].size : 0;
            const uint uid = (idx >= 0 && idx < RT_MAX_NODES) ? g_rt[idx].uid : userCurrentUid();
            const uint gid = (idx >= 0 && idx < RT_MAX_NODES) ? g_rt[idx].gid : userCurrentGid();
            const uint fmode = (idx >= 0 && idx < RT_MAX_NODES) ? g_rt[idx].mode : 0x1B6;
            const uint ftype = (idx >= 0 && idx < RT_MAX_NODES && g_rt[idx].kind == RT_LNK)
                               ? 0xA000 : 0x8000;          // S_IFLNK : S_IFREG
            writeLinuxStatOwned(_statBuf, ftype | fmode, sz, uid, gid);
        } else if (f.type == FileType.FD_KLOG) {
            import core.io : g_klogHead;
            writeLinuxStat(_statBuf, 0x8000 | 0x0124, g_klogHead); // S_IFREG | 0444 (live-growing size)
        } else {
            writeLinuxStat(_statBuf, 0x8000 | 0x01a4, f.fileSize); // S_IFREG | 0644
        }
    }
    return 0;
}

public long linux_sys_fstat(ulong fd, ulong _statBuf) {
    ObjHeader* oh = fdObjectByIndexWithRights(cast(int)fd, CAP_RIGHT_STAT);
    if (oh is null) return cast(long)negErrno(EBADF);
    auto sop = g_objOps[oh.type].stat;
    if (sop is null) return cast(long)negErrno(EBADF);
    return sop(oh, _statBuf);
}

private bool bootModulePathEq(ref const(BootModuleRecord) rec, const(char)* path) {
    if (path is null) return false;

    size_t i = 0;
    while (i < rec.name.length && rec.name[i] != '\0' && path[i] != 0) {
        if (rec.name[i] != path[i]) return false;
        ++i;
    }

    const bool recDone = i >= rec.name.length || rec.name[i] == '\0';
    if (recDone && path[i] == 0) {
        return true;
    }

    immutable bootPrefix = "boot():";
    foreach (idx, ch; bootPrefix) {
        if (idx >= rec.name.length || rec.name[idx] != ch) {
            return false;
        }
    }

    i = 0;
    while ((i + bootPrefix.length) < rec.name.length &&
           rec.name[i + bootPrefix.length] != '\0' &&
           path[i] != 0) {
        if (rec.name[i + bootPrefix.length] != path[i]) return false;
        ++i;
    }

    const bool suffixDone = (i + bootPrefix.length) >= rec.name.length ||
                            rec.name[i + bootPrefix.length] == '\0';
    return suffixDone && path[i] == 0;
}

private bool findBootModule(const(char)* path, out ulong physStart, out ulong size) {
    physStart = 0;
    size = 0;
    if (path is null || g_mboot_modules is null || g_module_count <= 0) {
        return false;
    }

    auto records = cast(BootModuleRecord*)g_mboot_modules;
    foreach (i; 0 .. cast(size_t)g_module_count) {
        auto rec = &records[i];
        if (!bootModulePathEq(*rec, path)) {
            continue;
        }
        physStart = cast(ulong)rec.mod_start;
        size = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
        return true;
    }
    return false;
}

// Last path component of a C string (after the final '/'), bounded by maxLen.
private const(char)* cstrLastComponent(const(char)* s, size_t maxLen) {
    if (s is null) return s;
    const(char)* base = s;
    size_t i = 0;
    while (i < maxLen && s[i] != 0) {
        if (s[i] == '/') base = s + i + 1;
        ++i;
    }
    return base;
}

// True if the path names a shared object (contains ".so" — either a final
// ".so" or a versioned ".so.N").
private bool cstrLooksLikeSo(const(char)* p) {
    if (p is null) return false;
    for (size_t i = 0; p[i] != 0; ++i) {
        if (p[i] == '.' && p[i+1] == 's' && p[i+2] == 'o' &&
            (p[i+3] == 0 || p[i+3] == '.'))
            return true;
    }
    return false;
}

// Compare two NUL-terminated C strings for equality (lhs bounded by maxLen).
private bool cstrEqC(const(char)* a, const(char)* b, size_t maxLen) {
    if (a is null || b is null) return false;
    size_t i = 0;
    while (i < maxLen && a[i] != 0 && b[i] != 0) {
        if (a[i] != b[i]) return false;
        ++i;
    }
    return (i >= maxLen) ? (b[i] == 0) : (a[i] == 0 && b[i] == 0);
}

// Resolve a shared-library open() (e.g. ld.so's dlopen / DT_NEEDED lookups under
// /lib, /usr/lib, …) to a bundled boot module by basename.  Without this, a
// request like "/lib/libfoo.so" would not match a module named
// "boot():/libfoo.so".  Restricted to .so paths so ordinary files are unaffected.
private bool findBootModuleLib(const(char)* path, out ulong physStart, out ulong size) {
    physStart = 0;
    size = 0;
    if (path is null || g_mboot_modules is null || g_module_count <= 0) return false;
    if (!cstrLooksLikeSo(path)) return false;

    const(char)* wantBase = cstrLastComponent(path, 4096);
    auto records = cast(BootModuleRecord*)g_mboot_modules;
    foreach (i; 0 .. cast(size_t)g_module_count) {
        auto rec = &records[i];
        const(char)* modBase = cstrLastComponent(rec.name.ptr, rec.name.length);
        if (cstrEqC(wantBase, modBase, 128)) {
            physStart = cast(ulong)rec.mod_start;
            size = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
            return true;
        }
    }
    return false;
}

private long bootModuleRead(ulong physBase, ulong fileSize, ulong readOffset, void* buf, ulong count) {
    if (readOffset >= fileSize) return 0;

    ulong remaining = fileSize - readOffset;
    ulong toRead = count;
    if (toRead > remaining) toRead = remaining;

    ubyte* src = cast(ubyte*)phys_to_virt(physBase) + readOffset;
    ubyte* dst = cast(ubyte*)buf;
    for (ulong i = 0; i < toRead; ++i) {
        dst[i] = src[i];
    }
    return cast(long)toRead;
}

// File-backed mmap helper: copy `len` bytes of file `fd`'s content starting at
// absolute byte `off` into `dst` (a kernel HHDM pointer to a freshly-allocated
// page), zero-filling past EOF.  Returns 1 if `fd` is a mappable regular file
// (bundle / boot module / virtual file / rtfs file), else 0 so the mmap caller
// falls back to an anonymous (zero) page.  Used by the dynamic linker, which
// mmaps each shared-object segment from its fd.
public int mmapCopyFileRange(int fd, ulong off, ubyte* dst, ulong len) {
    initFdTable();
    if (fd < 0 || fd >= 1024) return 0;
    File* f = &g_fdTable[fd];

    switch (f.type) {
        case FileType.FD_BUNDLE: {
            ulong done = 0;
            while (done < len) {
                long n = bundleRead(cast(ulong)f.backend, f.fileSize,
                                    off + done, dst + done, len - done);
                if (n <= 0) break;
                done += cast(ulong)n;
            }
            for (ulong i = done; i < len; ++i) dst[i] = 0;
            return 1;
        }
        case FileType.FD_BOOT_MODULE: {
            ulong done = 0;
            while (done < len) {
                long n = bootModuleRead(cast(ulong)f.backend, f.fileSize,
                                        off + done, dst + done, len - done);
                if (n <= 0) break;
                done += cast(ulong)n;
            }
            for (ulong i = done; i < len; ++i) dst[i] = 0;
            return 1;
        }
        case FileType.FD_FILE: {
            // Virtual file: backend > fileBackendDirectory is a content pointer.
            if (cast(size_t)f.backend <= fileBackendDirectory) return 0;
            auto src = cast(const(ubyte)*)f.backend;
            ulong fsize = f.fileSize;
            for (ulong i = 0; i < len; ++i) {
                ulong idx = off + i;
                dst[i] = (idx < fsize) ? src[idx] : 0;
            }
            return 1;
        }
        case FileType.FD_RTFILE: {
            int idx = cast(int)cast(size_t)f.backend;
            if (idx < 0 || idx >= RT_MAX_NODES || g_rt[idx].kind != RT_REG) return 0;
            auto src = g_rt[idx].data;
            ulong fsize = g_rt[idx].size;
            for (ulong i = 0; i < len; ++i) {
                ulong fidx = off + i;
                dst[i] = (fidx < fsize && src !is null) ? src[fidx] : 0;
            }
            return 1;
        }
        default:
            return 0;
    }
}

private bool cstrEq(const(char)* lhs, string rhs) {
    if (lhs is null) return false;

    size_t i = 0;
    while (i < rhs.length && lhs[i] != 0) {
        if (lhs[i] != rhs[i]) return false;
        ++i;
    }
    return lhs[i] == 0 && i == rhs.length;
}

private void clearLinuxStat(ulong statBuf) {
    ubyte* buf = cast(ubyte*)statBuf;
    for (int i = 0; i < 144; ++i) {
        buf[i] = 0;
    }
}

private void writeLinuxStatOwned(ulong statBuf, uint mode, ulong size,
                                 uint uid, uint gid) {
    clearLinuxStat(statBuf);
    *cast(uint*)(statBuf + 24) = mode;
    *cast(uint*)(statBuf + 28) = uid;
    *cast(uint*)(statBuf + 32) = gid;
    *cast(long*)(statBuf + 48) = cast(long)size;
    *cast(long*)(statBuf + 56) = 4096;
    *cast(long*)(statBuf + 64) = cast(long)((size + 511) / 512);
}

private void writeLinuxStat(ulong statBuf, uint mode, ulong size) {
    writeLinuxStatOwned(statBuf, mode, size, userCurrentUid(), userCurrentGid());
}

// GUI G7 display diagnostics.  Keep this allocation-free because procfs reads
// can happen while userland is bringing the desktop stack up.
__gshared char[2048] g_displayInfoBuf;
__gshared char[512]  g_displayConfigBuf;
__gshared char[256]  g_displayCmdlineBuf;

private void displayAppendChar(ref uint p, uint max, char c) {
    if (p + 1 < max)
        g_displayInfoBuf[p++] = c;
}

private void displayAppendStr(ref uint p, uint max, const(char)[] s) {
    foreach (c; s)
        displayAppendChar(p, max, c);
}

private void displayAppendUint(ref uint p, uint max, ulong v) {
    char[32] tmp;
    uint n = 0;
    do {
        tmp[n++] = cast(char)('0' + (v % 10));
        v /= 10;
    } while (v != 0 && n < tmp.length);
    while (n > 0)
        displayAppendChar(p, max, tmp[--n]);
}

private void displayAppendHex(ref uint p, uint max, ulong v) {
    displayAppendStr(p, max, "0x");
    char[16] tmp;
    uint n = 0;
    do {
        const ubyte d = cast(ubyte)(v & 0xF);
        tmp[n++] = cast(char)(d < 10 ? ('0' + d) : ('a' + d - 10));
        v >>= 4;
    } while (v != 0 && n < tmp.length);
    while (n > 0)
        displayAppendChar(p, max, tmp[--n]);
}

private const(char)[] displayConfigContent() {
    ulong phys = 0;
    ulong size = 0;
    if (!findBootModule("/display.conf\0".ptr, phys, size))
        return null;

    ulong n = size;
    if (n >= g_displayConfigBuf.length)
        n = g_displayConfigBuf.length - 1;
    if (n > 0)
        bootModuleRead(phys, size, 0, g_displayConfigBuf.ptr, n);
    g_displayConfigBuf[cast(size_t)n] = '\0';
    return g_displayConfigBuf[0 .. cast(size_t)n];
}

private ulong displayConfigUint(const(char)[] cfg, string key, ulong fallback) {
    if (cfg.length == 0)
        return fallback;

    size_t lineStart = 0;
    while (lineStart < cfg.length) {
        size_t lineEnd = lineStart;
        while (lineEnd < cfg.length && cfg[lineEnd] != '\n' && cfg[lineEnd] != '\r')
            ++lineEnd;

        if (lineEnd > lineStart + key.length && cfg[lineStart + key.length] == '=') {
            bool match = true;
            foreach (i, c; key) {
                if (cfg[lineStart + i] != c) {
                    match = false;
                    break;
                }
            }
            if (match) {
                ulong value = 0;
                bool any = false;
                for (size_t i = lineStart + key.length + 1; i < lineEnd; ++i) {
                    const char c = cfg[i];
                    if (c < '0' || c > '9')
                        break;
                    value = value * 10 + cast(ulong)(c - '0');
                    any = true;
                }
                if (any)
                    return value;
            }
        }

        lineStart = lineEnd;
        while (lineStart < cfg.length && (cfg[lineStart] == '\n' || cfg[lineStart] == '\r'))
            ++lineStart;
    }

    return fallback;
}

private const(char)[] displayConfigValue(const(char)[] cfg, string key, const(char)[] fallback) {
    if (cfg.length == 0)
        return fallback;

    size_t lineStart = 0;
    while (lineStart < cfg.length) {
        size_t lineEnd = lineStart;
        while (lineEnd < cfg.length && cfg[lineEnd] != '\n' && cfg[lineEnd] != '\r')
            ++lineEnd;

        if (lineEnd > lineStart + key.length && cfg[lineStart + key.length] == '=') {
            bool match = true;
            foreach (i, c; key) {
                if (cfg[lineStart + i] != c) {
                    match = false;
                    break;
                }
            }
            if (match)
                return cfg[lineStart + key.length + 1 .. lineEnd];
        }

        lineStart = lineEnd;
        while (lineStart < cfg.length && (cfg[lineStart] == '\n' || cfg[lineStart] == '\r'))
            ++lineStart;
    }

    return fallback;
}

private bool displaySliceEq(const(char)[] value, string expected) {
    if (value.length != expected.length)
        return false;
    foreach (i, c; expected)
        if (value[i] != c)
            return false;
    return true;
}

public int guiAutostartMode() {
    const(char)[] value = displayConfigValue(displayConfigContent(), "gui.autostart", "cairo");
    if (displaySliceEq(value, "none")) return 0;
    if (displaySliceEq(value, "term") || displaySliceEq(value, "terminal") || displaySliceEq(value, "wl-term")) return 1;
    if (displaySliceEq(value, "cairo") || displaySliceEq(value, "wl-cairo-demo")) return 2;
    if (displaySliceEq(value, "both")) return 3;
    if (displaySliceEq(value, "files") || displaySliceEq(value, "wl-files")) return 4;
    return 2;
}

private void displayAppendFormat(ref uint p, uint max) {
    if (g_fb is null) {
        displayAppendStr(p, max, "unavailable");
    } else if (g_fb.bpp == 32 &&
               g_fb.red_mask_size == 8 && g_fb.red_mask_shift == 16 &&
               g_fb.green_mask_size == 8 && g_fb.green_mask_shift == 8 &&
               g_fb.blue_mask_size == 8 && g_fb.blue_mask_shift == 0) {
        displayAppendStr(p, max, "XRGB8888");
    } else if (g_fb.bpp == 32 &&
               g_fb.red_mask_size == 8 && g_fb.red_mask_shift == 0 &&
               g_fb.green_mask_size == 8 && g_fb.green_mask_shift == 8 &&
               g_fb.blue_mask_size == 8 && g_fb.blue_mask_shift == 16) {
        displayAppendStr(p, max, "XBGR8888");
    } else if (g_fb.bpp == 24) {
        displayAppendStr(p, max, "RGB888");
    } else if (g_fb.bpp == 16) {
        displayAppendStr(p, max, "RGB565");
    } else {
        displayAppendStr(p, max, "bpp");
        displayAppendUint(p, max, g_fb.bpp);
    }
}

private void displayAppendKeyUint(ref uint p, uint max, string key, ulong value) {
    displayAppendStr(p, max, key);
    displayAppendChar(p, max, '=');
    displayAppendUint(p, max, value);
    displayAppendChar(p, max, '\n');
}

private void cmdlineAppendChar(ref uint p, uint max, char c) {
    if (p + 1 < max)
        g_displayCmdlineBuf[p++] = c;
}

private void cmdlineAppendStr(ref uint p, uint max, const(char)[] s) {
    foreach (c; s)
        cmdlineAppendChar(p, max, c);
}

private void cmdlineAppendUint(ref uint p, uint max, ulong value) {
    char[32] tmp;
    uint n = 0;
    do {
        tmp[n++] = cast(char)('0' + (value % 10));
        value /= 10;
    } while (value != 0 && n < tmp.length);
    while (n > 0)
        cmdlineAppendChar(p, max, tmp[--n]);
}

private void cmdlineAppendKeyUint(ref uint p, uint max, string key, ulong value) {
    if (p > 0)
        cmdlineAppendChar(p, max, ' ');
    cmdlineAppendStr(p, max, key);
    cmdlineAppendChar(p, max, '=');
    cmdlineAppendUint(p, max, value);
}

private void cmdlineAppendKeyStr(ref uint p, uint max, string key, const(char)[] value) {
    if (p > 0)
        cmdlineAppendChar(p, max, ' ');
    cmdlineAppendStr(p, max, key);
    cmdlineAppendChar(p, max, '=');
    cmdlineAppendStr(p, max, value);
}

private const(char)[] displayCmdlineContent() {
    uint p = 0;
    const uint max = cast(uint)g_displayCmdlineBuf.length;
    const(char)[] cfg = displayConfigContent();
    const ulong fbW = (g_fb !is null) ? g_fb.width : 0;
    const ulong fbH = (g_fb !is null) ? g_fb.height : 0;
    // Report the REAL framebuffer unless display.force_mode=1 explicitly pins a size.
    // Both /display.conf (Makefile:393) and the limine cmdline (limine.conf:11) hardcode
    // display.width=1280/height=800, and those used to win over the actual mode -- so the
    // desktop stayed 1280x800 no matter what the display was, which is half of why it
    // "does not auto resize".  force_mode already exists as the "I really mean it" switch,
    // so honour the hardware by default and let force_mode override it.
    const ulong forceMode = displayConfigUint(cfg, "display.force_mode", 0);
    const ulong outW = (forceMode == 0 && fbW != 0)
                     ? fbW : displayConfigUint(cfg, "display.width",  fbW != 0 ? fbW : 1280);
    const ulong outH = (forceMode == 0 && fbH != 0)
                     ? fbH : displayConfigUint(cfg, "display.height", fbH != 0 ? fbH : 800);
    cmdlineAppendKeyUint(p, max, "display.width", outW);
    cmdlineAppendKeyUint(p, max, "display.height", outH);
    cmdlineAppendKeyUint(p, max, "display.scale", displayConfigUint(cfg, "display.scale", 1));
    cmdlineAppendKeyUint(p, max, "display.refresh", displayConfigUint(cfg, "display.refresh", 60));
    cmdlineAppendKeyUint(p, max, "display.force_mode", displayConfigUint(cfg, "display.force_mode", 0));
    cmdlineAppendKeyStr(p, max, "gui.autostart", displayConfigValue(cfg, "gui.autostart", "cairo"));
    cmdlineAppendChar(p, max, '\n');
    g_displayCmdlineBuf[p] = '\0';
    return g_displayCmdlineBuf[0 .. p];
}

private const(char)[] displayInfoContent() {
    uint p = 0;
    const uint max = cast(uint)g_displayInfoBuf.length;
    const(char)[] cfg = displayConfigContent();

    const ulong fbW = (g_fb !is null) ? g_fb.width : 0;
    const ulong fbH = (g_fb !is null) ? g_fb.height : 0;
    const ulong targetW = displayConfigUint(cfg, "display.width",  fbW != 0 ? fbW : 1280);
    const ulong targetH = displayConfigUint(cfg, "display.height", fbH != 0 ? fbH : 800);
    const ulong scale   = displayConfigUint(cfg, "display.scale", 1);
    const ulong refresh = displayConfigUint(cfg, "display.refresh", 60);
    const ulong force   = displayConfigUint(cfg, "display.force_mode", 0);

    displayAppendStr(p, max, "backend=limine-framebuffer+hyprland-headless\n");
    displayAppendStr(p, max, "config_source=");
    displayAppendStr(p, max, cfg.length ? "/display.conf" : "built-in-defaults");
    displayAppendChar(p, max, '\n');

    displayAppendStr(p, max, "target_resolution=");
    displayAppendUint(p, max, targetW);
    displayAppendChar(p, max, 'x');
    displayAppendUint(p, max, targetH);
    displayAppendChar(p, max, '\n');
    displayAppendKeyUint(p, max, "scale", scale);
    displayAppendKeyUint(p, max, "refresh", refresh);
    displayAppendKeyUint(p, max, "force_mode", force);

    if (g_fb is null) {
        displayAppendStr(p, max, "current_resolution=unavailable\n");
        displayAppendStr(p, max, "framebuffer_address=0x0\n");
        displayAppendStr(p, max, "pitch=0\nformat=unavailable\n");
    } else {
        displayAppendStr(p, max, "current_resolution=");
        displayAppendUint(p, max, g_fb.width);
        displayAppendChar(p, max, 'x');
        displayAppendUint(p, max, g_fb.height);
        displayAppendChar(p, max, '\n');

        displayAppendStr(p, max, "framebuffer_address=");
        displayAppendHex(p, max, cast(ulong)g_fb.address);
        displayAppendChar(p, max, '\n');
        displayAppendKeyUint(p, max, "pitch", g_fb.pitch);

        displayAppendStr(p, max, "format=");
        displayAppendFormat(p, max);
        displayAppendChar(p, max, '\n');
        displayAppendKeyUint(p, max, "bpp", g_fb.bpp);
        displayAppendKeyUint(p, max, "memory_model", g_fb.memory_model);

        displayAppendStr(p, max, "red_mask=");
        displayAppendUint(p, max, g_fb.red_mask_size);
        displayAppendChar(p, max, '@');
        displayAppendUint(p, max, g_fb.red_mask_shift);
        displayAppendChar(p, max, '\n');
        displayAppendStr(p, max, "green_mask=");
        displayAppendUint(p, max, g_fb.green_mask_size);
        displayAppendChar(p, max, '@');
        displayAppendUint(p, max, g_fb.green_mask_shift);
        displayAppendChar(p, max, '\n');
        displayAppendStr(p, max, "blue_mask=");
        displayAppendUint(p, max, g_fb.blue_mask_size);
        displayAppendChar(p, max, '@');
        displayAppendUint(p, max, g_fb.blue_mask_shift);
        displayAppendChar(p, max, '\n');

        displayAppendKeyUint(p, max, "edid_size", g_fb.edid_size);
        displayAppendKeyUint(p, max, "mode_count", g_fb.mode_count);

        if (g_fb.modes !is null && g_fb.mode_count > 0 && g_fb.modes[0] !is null) {
            auto preferred = g_fb.modes[0];
            displayAppendStr(p, max, "preferred_mode=");
            displayAppendUint(p, max, preferred.width);
            displayAppendChar(p, max, 'x');
            displayAppendUint(p, max, preferred.height);
            displayAppendChar(p, max, '@');
            displayAppendUint(p, max, refresh);
            displayAppendChar(p, max, '\n');

            ulong count = g_fb.mode_count;
            if (count > 8)
                count = 8;
            foreach (i; 0 .. cast(size_t)count) {
                auto mode = g_fb.modes[i];
                if (mode is null)
                    continue;
                displayAppendStr(p, max, "mode.");
                displayAppendUint(p, max, i);
                displayAppendChar(p, max, '=');
                displayAppendUint(p, max, mode.width);
                displayAppendChar(p, max, 'x');
                displayAppendUint(p, max, mode.height);
                displayAppendStr(p, max, " pitch=");
                displayAppendUint(p, max, mode.pitch);
                displayAppendStr(p, max, " bpp=");
                displayAppendUint(p, max, mode.bpp);
                displayAppendChar(p, max, '\n');
            }
        } else {
            displayAppendStr(p, max, "preferred_mode=unavailable\n");
        }
    }

    g_displayInfoBuf[p] = '\0';
    return g_displayInfoBuf[0 .. p];
}

// ─────────────────────────────────────────────────────────────────────────────
// Writable runtime overlay ("rtfs") — a minimal in-memory tmpfs layered on top
// of the read-only synthetic namespace.  It exists so programs that must create
// directories and files under writable roots (/run, /tmp, /var/tmp) work — most
// importantly XDG_RUNTIME_DIR=/run/user/1000, which Wayland compositors
// (Hyprland) need in order to create <runtime>/hypr/<instance>/ plus its lock
// and socket files.  Nodes live in a fixed table (matching the static-table
// idiom used for sockets/pipes elsewhere in this file); file payloads are
// page-backed and allocated lazily on first write.
// ─────────────────────────────────────────────────────────────────────────────
// Track A (SHELL_AND_COMMANDS_ROADMAP A2): node count raised from 1024 so a full
// FHS tree + ~380 /bin applet symlinks + user files fit; symlinks (RT_LNK) added;
// payload pages are now freed on grow/unlink (no more leak) with byte accounting.
private enum int    RT_MAX_NODES = 12288;   // Z8: +~1018 zsh function/completion nodes
private enum size_t RT_NAME_MAX  = 96;
private enum ulong  RT_MAX_BYTES = 64UL * 1024 * 1024;   // tmpfs soft cap (ENOSPC past it)

private enum ubyte RT_FREE = 0;
private enum ubyte RT_DIR  = 1;
private enum ubyte RT_REG  = 2;
private enum ubyte RT_LNK  = 3;              // symbolic link; target string held in `data`

private struct RtNode {
    ubyte  kind;                 // RT_FREE / RT_DIR / RT_REG / RT_LNK
    int    parent;               // parent node index; -1 only for root (index 0)
    ushort mode;                 // permission bits only (no S_IF type bits)
    uint   uid;
    uint   gid;
    ubyte  nameLen;
    char[RT_NAME_MAX] name;      // single path component
    ubyte* data;                 // file payload / link target (virtual ptr), null until written
    ulong  dataPhys;             // phys addr backing `data` (0 = none) — so we can free it
    uint   size;                 // current file length / link target length in bytes
    uint   cap;                  // allocated capacity (page multiple)
}

__gshared RtNode[RT_MAX_NODES] g_rt;
__gshared bool  g_rtInitialized = false;
__gshared ulong g_rtBytes = 0;               // total bytes backing RT payloads (for the cap + df)

// Z8: a rolling free-slot hint turns the boot-time bulk creates (busybox, xkb, the
// ~1018 zsh functions) from O(n^2) into ~O(n).  Scan forward from the hint, then wrap
// to catch slots freed below it.
__gshared int g_rtAllocHint = 1;
private int rtAllocNode() {
    for (int i = g_rtAllocHint; i < RT_MAX_NODES; ++i)   // index 0 reserved for root
        if (g_rt[i].kind == RT_FREE) { g_rtAllocHint = i + 1; return i; }
    for (int i = 1; i < g_rtAllocHint && i < RT_MAX_NODES; ++i)
        if (g_rt[i].kind == RT_FREE) { g_rtAllocHint = i + 1; return i; }
    return -1;
}

private bool rtNameEndsWith(ref const(RtNode) n, string suffix) {
    if (n.nameLen < suffix.length) return false;
    size_t off = n.nameLen - suffix.length;
    foreach (i; 0 .. suffix.length)
        if (n.name[off + i] != suffix[i]) return false;
    return true;
}

private bool rtNameEq(ref const(RtNode) n, const(char)* name, size_t len) {
    if (n.nameLen != len) return false;
    foreach (i; 0 .. len)
        if (n.name[i] != name[i]) return false;
    return true;
}

private int rtFindChild(int parent, const(char)* name, size_t len) {
    for (int i = 1; i < RT_MAX_NODES; ++i) {
        if (g_rt[i].kind == RT_FREE) continue;
        if (g_rt[i].parent != parent) continue;
        if (rtNameEq(g_rt[i], name, len)) return i;
    }
    return -1;
}

private int rtCreate(int parent, const(char)* name, size_t len, ubyte kind,
                     ushort mode, uint uid, uint gid) {
    if (len == 0 || len > RT_NAME_MAX) return -1;
    int idx = rtAllocNode();
    if (idx < 0) return -1;
    g_rt[idx].kind    = kind;
    g_rt[idx].parent  = parent;
    g_rt[idx].mode    = mode;
    g_rt[idx].uid     = uid;
    g_rt[idx].gid     = gid;
    g_rt[idx].nameLen = cast(ubyte)len;
    foreach (i; 0 .. len) g_rt[idx].name[i] = name[i];
    g_rt[idx].data     = null;
    g_rt[idx].dataPhys = 0;
    g_rt[idx].size     = 0;
    g_rt[idx].cap      = 0;
    // DOMAIN_MANAGER DM6.2 data plane: if the creating task is bound into a domain, copy the new
    // file up into the domain's writable overlay.  No-op for normal (non-domain) tasks.
    if (kind == RT_REG) domainRecordWrite(cast(int)g_current_task_id, name, len);
    return idx;
}

// OBJECT_FILESYSTEM_ROADMAP F0: resolve an intermediate directory symlink to the dir
// it points at, so paths traverse dir symlinks (e.g. /compat/linux/bin -> /bin). The
// link target may be absolute or relative to the link's parent; bounded recursion.
__gshared int g_rtLinkDepth = 0;
private int rtLinkTargetDir(int linkIdx) {
    int result = -1;
    if (g_rtLinkDepth <= 16 && linkIdx >= 0 && linkIdx < RT_MAX_NODES
        && g_rt[linkIdx].kind == RT_LNK && g_rt[linkIdx].size > 0) {
        ++g_rtLinkDepth;
        char[512] tb = void;
        size_t pos = 0;
        if (g_rt[linkIdx].data[0] == '/') {                 // absolute target
            foreach (i; 0 .. g_rt[linkIdx].size) if (pos + 1 < tb.length) tb[pos++] = cast(char)g_rt[linkIdx].data[i];
        } else {                                            // relative to the link's parent
            pos = rtBuildPath(g_rt[linkIdx].parent, tb.ptr, tb.length);
            if (pos + 1 < tb.length) tb[pos++] = '/';
            foreach (i; 0 .. g_rt[linkIdx].size) if (pos + 1 < tb.length) tb[pos++] = cast(char)g_rt[linkIdx].data[i];
        }
        tb[pos < tb.length ? pos : tb.length - 1] = 0;
        int p2; const(char)* l2; size_t ll2;
        const int target = rtResolve(tb.ptr, p2, l2, ll2);
        if (target >= 0 && g_rt[target].kind == RT_DIR) result = target;
        --g_rtLinkDepth;
    }
    return result;
}

// Resolve `path` within the overlay.  `outParent` receives the parent-dir index
// of the final component when that parent exists in the overlay (-1 if an
// intermediate component is missing or is not a directory); `leaf`/`leafLen`
// describe the final component.  Returns the node index of the full path if it
// exists, else -1 (with outParent set so callers can create the leaf).
private int rtResolve(const(char)* path, out int outParent,
                      out const(char)* leaf, out size_t leafLen) {
    outParent = -1;
    leaf = null;
    leafLen = 0;
    if (path is null || path[0] != '/') return -1;

    int cur = 0;                 // overlay root
    const(char)* p = path + 1;   // skip leading '/'
    while (true) {
        while (*p == '/') ++p;   // collapse redundant slashes
        if (*p == 0) return cur; // path ended at a directory boundary

        const(char)* comp = p;
        size_t clen = 0;
        while (p[clen] != 0 && p[clen] != '/') ++clen;
        p += clen;

        const(char)* q = p;      // look past trailing slashes to detect last comp
        while (*q == '/') ++q;
        const bool isLast = (*q == 0);

        if (clen == 1 && comp[0] == '.') {
            if (isLast) { outParent = g_rt[cur].parent; leaf = comp; leafLen = clen; return cur; }
            continue;
        }
        if (clen == 2 && comp[0] == '.' && comp[1] == '.') {
            if (cur != 0) cur = g_rt[cur].parent;
            if (isLast) return cur;
            continue;
        }

        if (isLast) {
            outParent = cur;
            leaf = comp;
            leafLen = clen;
            return rtFindChild(cur, comp, clen);   // -1 if absent
        }

        int child = rtFindChild(cur, comp, clen);
        // F0: follow an intermediate directory symlink (e.g. /compat/linux/bin -> /bin).
        if (child >= 0 && g_rt[child].kind == RT_LNK) child = rtLinkTargetDir(child);
        if (child < 0 || g_rt[child].kind != RT_DIR) { outParent = -1; return -1; }
        cur = child;
    }
}

// Grow a file node's page-backed payload to at least `need` bytes.  The old pages
// are now FREED after the copy (was a leak) and the global byte total is kept so the
// RT_MAX_BYTES cap and `df` reflect reality.
private bool rtEnsureCap(ref RtNode n, uint need) {
    if (need <= n.cap) return true;
    const size_t pages = (need + 4095) / 4096;
    const uint newCap = cast(uint)(pages * 4096);
    // Enforce the tmpfs soft cap on the *additional* bytes this grow would commit.
    if (g_rtBytes + (newCap - n.cap) > RT_MAX_BYTES) return false;
    const ulong phys = alloc_phys_pages(pages);
    if (phys == 0) return false;
    ubyte* nd = cast(ubyte*)phys_to_virt(phys);
    foreach (i; 0 .. n.size) nd[i] = n.data[i];          // copy existing bytes
    foreach (i; n.size .. newCap) nd[i] = 0;             // zero the remainder
    const ulong oldPhys = n.dataPhys;
    const uint  oldCap  = n.cap;
    n.data     = nd;
    n.dataPhys = phys;
    n.cap      = newCap;
    g_rtBytes += newCap;
    if (oldPhys != 0 && oldCap != 0) {                   // release the previous backing
        free_phys_pages(oldPhys, oldCap / 4096);
        g_rtBytes -= oldCap;
    }
    return true;
}

// Release a node's payload pages (on unlink / overwrite) and update the byte total.
private void rtFreeData(ref RtNode n) {
    if (n.dataPhys != 0 && n.cap != 0) {
        free_phys_pages(n.dataPhys, n.cap / 4096);
        g_rtBytes -= n.cap;
    }
    n.data = null; n.dataPhys = 0; n.size = 0; n.cap = 0;
}

// Build the absolute path of RT node `idx` ("/a/b/c") into `buf`; returns length.
private size_t rtBuildPath(int idx, char* buf, size_t bufLen) {
    int[64] chain = void;
    int depth = 0;
    int cur = idx;
    while (cur > 0 && depth < 64) { chain[depth++] = cur; cur = g_rt[cur].parent; }
    size_t pos = 0;
    if (depth == 0) { if (bufLen > 1) buf[pos++] = '/'; buf[pos] = 0; return pos; }
    for (int d = depth - 1; d >= 0; --d) {
        const int n = chain[d];
        if (pos + 1 < bufLen) buf[pos++] = '/';
        foreach (i; 0 .. g_rt[n].nameLen)
            if (pos + 1 < bufLen) buf[pos++] = g_rt[n].name[i];
    }
    buf[pos < bufLen ? pos : bufLen - 1] = 0;
    return pos;
}

// Follow a leading symlink chain so callers (open) resolve through RT_LNK nodes.
// Returns `path` unchanged when it does not end at a symlink; otherwise returns a
// pointer into one of the two scratch buffers holding the rewritten target path.
// Absolute targets restart from root; relative targets splice onto the link's parent.
// Bounded to RT_LNK_MAX hops to break loops.
private enum int RT_LNK_MAX = 16;
private const(char)* rtFollowSymlinks(const(char)* path, char* bufA, char* bufB, size_t bufLen) {
    const(char)* cur = path;
    char* dst = bufA;
    for (int hop = 0; hop < RT_LNK_MAX; ++hop) {
        int rp; const(char)* rl; size_t rll;
        const int ri = rtResolve(cur, rp, rl, rll);
        if (ri < 0 || g_rt[ri].kind != RT_LNK) return cur;   // not a symlink — done
        const uint tlen = g_rt[ri].size;
        size_t pos = 0;
        if (tlen > 0 && g_rt[ri].data[0] == '/') {           // absolute target
            foreach (i; 0 .. tlen) if (pos + 1 < bufLen) dst[pos++] = cast(char)g_rt[ri].data[i];
        } else {                                             // relative to link's parent
            pos = rtBuildPath(g_rt[ri].parent, dst, bufLen);
            if (pos + 1 < bufLen) dst[pos++] = '/';
            foreach (i; 0 .. tlen) if (pos + 1 < bufLen) dst[pos++] = cast(char)g_rt[ri].data[i];
        }
        dst[pos < bufLen ? pos : bufLen - 1] = 0;
        cur = dst;
        dst = (dst == bufA) ? bufB : bufA;                   // ping-pong for the next hop
    }
    return cur;
}

// Track A A4: resolve a leading RT-overlay symlink chain for an exec path (e.g.
// /bin/cat -> /busybox), so execveTask can match the boot module.  Returns true and
// fills `outbuf` when the path was rewritten; false (outbuf untouched) otherwise.
public bool posixCanonExecPath(const(char)* path, char* outbuf, size_t outlen) {
    char[512] a = void;
    char[512] b = void;
    const(char)* r = rtFollowSymlinks(path, a.ptr, b.ptr, 512);
    if (r is path) return false;
    size_t i = 0;
    while (r[i] != 0 && i + 1 < outlen) { outbuf[i] = r[i]; ++i; }
    outbuf[i] = 0;
    return true;
}

// Seed one skeleton directory (idempotent).
private void rtMkdirPath(const(char)* path, ushort mode, uint uid, uint gid) {
    int parent; const(char)* leaf; size_t leafLen;
    const int idx = rtResolve(path, parent, leaf, leafLen);
    if (idx >= 0) return;                                // already exists
    if (parent < 0 || leaf is null) return;
    rtCreate(parent, leaf, leafLen, RT_DIR, mode, uid, gid);
}

// Track A A3: the full busybox applet set (deps/busybox/busybox.config / `busybox
// --list`).  Each becomes /bin/<name> -> /busybox so `ls /bin`, `which`, and PATH
// resolution see the real command set; busybox dispatches on argv[0]'s basename.
private immutable string g_busyboxApplets =
    "[ [[ acpid addgroup add-shell adduser adjtimex arch arp arping ascii ash awk " ~
    "base32 base64 basename bash bc beep blkdiscard blkid blockdev bootchartd brctl " ~
    "bunzip2 bzcat bzip2 cal cat chat chattr chgrp chmod chown chpasswd chpst chroot " ~
    "chrt chvt cksum clear cmp comm conspy cp cpio crc32 crond crontab cryptpw cttyhack " ~
    "cut date dc dd deallocvt delgroup deluser devmem df dhcprelay diff dirname dmesg " ~
    "dnsd dnsdomainname dos2unix dpkg dpkg-deb du dumpkmap dumpleases echo ed egrep " ~
    "eject env envdir envuidgid ether-wake expand expr factor fakeidentd fallocate false " ~
    "fatattr fbset fbsplash fdflush fdformat fdisk fgconsole fgrep find findfs flock fold " ~
    "free freeramdisk fsck fsck.minix fsfreeze fstrim fsync ftpd ftpget ftpput fuser " ~
    "getopt getty grep groups gunzip gzip halt hd hdparm head hexdump hexedit hostid " ~
    "hostname httpd hwclock i2cdetect i2cdump i2cget i2cset i2ctransfer id ifconfig " ~
    "ifdown ifenslave ifplugd ifup inetd install ionice iostat ip ipaddr ipcalc ipcrm " ~
    "ipcs iplink ipneigh iproute iprule iptunnel kbd_mode kill killall killall5 klogd " ~
    "last less link linux32 linux64 ln loadfont loadkmap logger login logname logread " ~
    "losetup lpd lpq lpr ls lsattr lsof lspci lsscsi lsusb lzcat lzma lzop makedevs " ~
    "makemime man md5sum mesg microcom mim mkdir mkdosfs mke2fs mkfifo mkfs.ext2 " ~
    "mkfs.minix mkfs.vfat mknod mkpasswd mkswap mktemp more mount mountpoint mpstat mt " ~
    "mv nameif nbd-client nc netstat nice nl nmeter nohup nologin nproc nsenter nslookup " ~
    "ntpd od openvt partprobe passwd paste patch pgrep pidof ping ping6 pipe_progress " ~
    "pivot_root pkill pmap popmaildir poweroff powertop printenv printf ps pscan pstree " ~
    "pwd pwdx raidautorun rdate rdev readahead readlink readprofile realpath reboot " ~
    "reformime remove-shell renice reset resize resume rev rm rmdir route rpm rpm2cpio " ~
    "rtcwake runlevel run-parts runsv runsvdir rx script scriptreplay sed seedrng " ~
    "sendmail seq setarch setconsole setfattr setfont setkeycodes setlogcons setpriv " ~
    "setserial setsid setuidgid sh sha1sum sha256sum sha3sum sha512sum showkey shred " ~
    "shuf slattach sleep smemcap softlimit sort split ssl_client start-stop-daemon stat " ~
    "strings stty su sulogin sum sv svc svlogd svok swapoff swapon sync sysctl syslogd " ~
    "tac tail tar taskset tcpsvd tee telnet telnetd test tftp tftpd time timeout top " ~
    "touch tr traceroute traceroute6 tree true truncate ts tsort tty ttysize tunctl " ~
    "udhcpc udhcpc6 udhcpd udpsvd uevent umount uname unexpand uniq unix2dos unlink " ~
    "unlzma unshare unxz unzip uptime users usleep uudecode uuencode vconfig vi vlock " ~
    "volname w wall watch watchdog wc wget which who whoami whois xargs xxd xz xzcat " ~
    "yes zcat zcip";

// Create /bin/<applet> -> /busybox for every busybox applet (Track A A3).
private void rtSeedBinSymlinks() {
    char[160] linkbuf = void;
    size_t i = 0;
    while (i < g_busyboxApplets.length) {
        while (i < g_busyboxApplets.length && g_busyboxApplets[i] == ' ') ++i;
        const size_t start = i;
        while (i < g_busyboxApplets.length && g_busyboxApplets[i] != ' ') ++i;
        const size_t nlen = i - start;
        if (nlen == 0 || nlen > 120) continue;
        size_t p = 0;
        linkbuf[p++] = '/'; linkbuf[p++] = 'b'; linkbuf[p++] = 'i'; linkbuf[p++] = 'n'; linkbuf[p++] = '/';
        foreach (k; 0 .. nlen) linkbuf[p++] = g_busyboxApplets[start + k];
        linkbuf[p] = 0;
        rtSymlinkCreate("/busybox".ptr, linkbuf.ptr);   // absolute target, exec-followed
    }
}

// Boot-time runtime-filesystem skeleton (emulates what pam_systemd/logind would
// otherwise build: a 0700 per-user XDG_RUNTIME_DIR plus the usual writable tmp
// roots).  Safe to call repeatedly; only the first call has effect.
private void rtInit() {
    if (g_rtInitialized) return;
    g_rtInitialized = true;

    g_rt[0].kind   = RT_DIR;
    g_rt[0].parent = -1;
    g_rt[0].mode   = 0x1ED;      // 0755
    g_rt[0].uid    = 0;
    g_rt[0].gid    = 0;
    g_rt[0].nameLen = 0;

    enum ushort M0755 = 0x1ED;   // rwxr-xr-x
    enum ushort M0700 = 0x1C0;   // rwx------
    enum ushort M1777 = 0x3FF;   // sticky rwxrwxrwx

    rtMkdirPath("/run\0".ptr,           M0755, 0, 0);
    rtMkdirPath("/run/user\0".ptr,      M0755, 0, 0);
    rtMkdirPath("/run/user/0\0".ptr,    M0700, 0, 0);
    rtMkdirPath("/run/user/1000\0".ptr, M0700, 1000, 1000);
    rtMkdirPath("/tmp\0".ptr,           M1777, 0, 0);
    rtMkdirPath("/home\0".ptr,          M0755, 0, 0);
    rtMkdirPath("/home/user\0".ptr,     M0700, 1000, 1000);
    {
        auto uname = userDefaultNameContent();
        if (uname.length > 0) {
            bool isDefault = uname.length == 4 &&
                             uname[0] == 'u' && uname[1] == 's' &&
                             uname[2] == 'e' && uname[3] == 'r';
            if (!isDefault) {
                char[80] homePath;
                size_t pos = 0;
                foreach (c; "/home/") homePath[pos++] = c;
                foreach (i; 0 .. uname.length)
                    if (pos + 1 < homePath.length) homePath[pos++] = uname[i];
                homePath[pos] = 0;
                rtMkdirPath(homePath.ptr, M0700, 1000, 1000);
            }
        }
    }
    rtMkdirPath("/var\0".ptr,           M0755, 0, 0);
    rtMkdirPath("/var/cache\0".ptr,     M0755, 0, 0);
    rtMkdirPath("/var/cache/fontconfig\0".ptr, M0755, 0, 0);
    rtMkdirPath("/var/tmp\0".ptr,       M1777, 0, 0);
    rtMkdirPath("/var/run\0".ptr,       M0755, 0, 0);

    // Track A A3: a standard FHS tree so the shell sees a real root.  /etc, /proc,
    // /sys, /dev stay synthetic (served by g_vfs / device shims) and are intentionally
    // not created here so their by-path content keeps resolving.
    rtMkdirPath("/bin\0".ptr,           M0755, 0, 0);
    rtMkdirPath("/sbin\0".ptr,          M0755, 0, 0);
    rtMkdirPath("/usr\0".ptr,           M0755, 0, 0);
    rtMkdirPath("/usr/bin\0".ptr,       M0755, 0, 0);
    rtMkdirPath("/usr/sbin\0".ptr,      M0755, 0, 0);
    rtMkdirPath("/usr/local\0".ptr,     M0755, 0, 0);
    rtMkdirPath("/usr/local/bin\0".ptr, M0755, 0, 0);
    // M3: NM dlopens device plugins by readdir'ing NMPLUGINDIR=/usr/lib/NetworkManager/1.44.2.  Seed it
    // as a real rtfs (writable+LISTABLE) dir so hos-nm-launch can drop the wifi plugin there AND NM's
    // opendir/getdents finds it — /usr/lib was not previously in the rtfs skeleton, so opendir failed
    // and NM loaded no wifi factory.
    rtMkdirPath("/usr/lib\0".ptr,                       M0755, 0, 0);
    rtMkdirPath("/usr/lib/NetworkManager\0".ptr,        M0755, 0, 0);
    rtMkdirPath("/usr/lib/NetworkManager/1.44.2\0".ptr, M0755, 0, 0);
    rtMkdirPath("/lib\0".ptr,           M0755, 0, 0);
    rtMkdirPath("/lib64\0".ptr,         M0755, 0, 0);
    rtMkdirPath("/opt\0".ptr,           M0755, 0, 0);
    rtMkdirPath("/mnt\0".ptr,           M0755, 0, 0);
    rtMkdirPath("/root\0".ptr,          M0700, 0, 0);
    rtMkdirPath("/var/log\0".ptr,       M0755, 0, 0);
    rtSeedBinSymlinks();                 // /bin/<applet> -> /busybox for all applets
    // Z1 (ZSH_INTEGRATION_ROADMAP): real upstream zsh is a boot module `/zsh`; expose it
    // at /bin/zsh (so `exec /bin/zsh` + PATH find it) and at the canonical
    // /system/shell/zsh/zsh.  execveTask follows the leading symlink to the boot module.
    rtSymlinkCreate("/zsh\0".ptr, "/bin/zsh\0".ptr);
    rtMkdirPath("/system/shell\0".ptr,      M0755, 0, 0);
    rtMkdirPath("/system/shell/zsh\0".ptr,  M0755, 0, 0);
    rtSymlinkCreate("/zsh\0".ptr, "/system/shell/zsh/zsh\0".ptr);
    // Z4a.5: /hos-zsh launches the SAME zsh boot module but in the native personality
    // (execveTask marks native by this request-path basename) — zsh as the native shell.
    rtSymlinkCreate("/zsh\0".ptr, "/hos-zsh\0".ptr);

    // OBJECT_FILESYSTEM_ROADMAP F0: the native object-OS root, additive over the Linux
    // FHS (which stays put and keeps working). `ls /` now shows the object tree; the
    // Linux tree is also reachable under /compat/linux via dir symlinks, and the
    // writable runtime under /state.
    rtMkdirPath("/objects\0".ptr,       M0755, 0, 0);   // native object model (F1: live views)
    { int _p; const(char)* _l; size_t _ll; g_objectsDirIdx = rtResolve("/objects\0".ptr, _p, _l, _ll); }
    rtMkdirPath("/system\0".ptr,        M0755, 0, 0);   // immutable base (F3)
    { int _p; const(char)* _l; size_t _ll; g_systemDirIdx = rtResolve("/system\0".ptr, _p, _l, _ll); }
    rtMkdirPath("/state\0".ptr,         M0755, 0, 0);   // mutable runtime/state
    rtMkdirPath("/config\0".ptr,        M0755, 0, 0);   // declarative config (F2)
    { int _p; const(char)* _l; size_t _ll; g_configDirIdx = rtResolve("/config\0".ptr, _p, _l, _ll); }
    rtMkdirPath("/volumes\0".ptr,       M0755, 0, 0);   // mounted disks / containers
    rtMkdirPath("/compat\0".ptr,        M0755, 0, 0);   // compatibility overlays
    rtMkdirPath("/compat/linux\0".ptr,  M0755, 0, 0);
    // Linux tree reachable under /compat/linux (canonical /bin etc. stay in place).
    rtSymlinkCreate("/bin\0".ptr,   "/compat/linux/bin\0".ptr);
    rtSymlinkCreate("/sbin\0".ptr,  "/compat/linux/sbin\0".ptr);
    rtSymlinkCreate("/usr\0".ptr,   "/compat/linux/usr\0".ptr);
    rtSymlinkCreate("/lib\0".ptr,   "/compat/linux/lib\0".ptr);
    rtSymlinkCreate("/lib64\0".ptr, "/compat/linux/lib64\0".ptr);
    // /state/<x> views onto the writable runtime areas.
    rtSymlinkCreate("/var/log\0".ptr,   "/state/logs\0".ptr);
    rtSymlinkCreate("/var/cache\0".ptr, "/state/cache\0".ptr);
    rtSymlinkCreate("/run\0".ptr,       "/state/sessions\0".ptr);
    // F1: /objects/processes reuses the live /proc view (per-pid object dirs).
    rtSymlinkCreate("/proc\0".ptr,      "/objects/processes\0".ptr);

    // Unpack the bundled xkeyboard-config tree (rules/keycodes/symbols/...) into
    // the overlay so libxkbcommon can compile a real keymap.  Without this,
    // xkb_context_new() can't add its include path and returns NULL → Hyprland's
    // keyboard setup dereferences a NULL context and crashes.  Paired with
    // XKB_CONFIG_ROOT=/usr/share/X11/xkb (exports.d).
    rtUnpackXkb();

    // Unpack bundled guest data assets. G10 splits the old aggregate assets.blob
    // into category blobs so fonts/icons/cursors/wallpapers/themes can evolve as
    // first-class OS resources while keeping the flat rtfs archive ABI.
    rtUnpackAssets();

    // Seed the editable shell-customization files (writable rtfs) — the live
    // "customize your shell" surface today; the full zsh/Oh-My-Zsh path is roadmapped.
    rtSeedShellConfig();
}

// Editable shell customization, seeded into the writable rtfs so a user can change
// it: /etc/profile (sourced by the busybox/ash login shell — aliases + prompt) and
// /etc/shell.json (the declarative config the future zsh config system consumes).
// See roadmap/ZSH_INTEGRATION_ROADMAP.md.
private void rtSeedShellConfig() {
    static immutable string PROFILE =
`# /etc/profile — AnonymOS shell customization.  EDIT THIS to customize your shell:
# aliases, options, and (optionally) the prompt.  Sourced by the interactive shell
# at login.  The full Z-shell + Oh-My-Zsh / Powerlevel customization is described in
# roadmap/ZSH_INTEGRATION_ROADMAP.md; this is the live customization point today.

# --- aliases (add your own) ---
alias ll='ls -lah'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias grep='grep --color=auto'
# AnonymOS object-model shortcuts:
alias objects='cat /objects/store'
alias caps='cat /config/identities.json'
alias services='cat /config/services.json'
alias sysinfo='cat /config/system.json'
# git (work once git is installed):
alias gs='git status'
alias ga='git add'
alias gc='git commit'
alias gp='git push'

# --- prompt ---
# The terminal sets a 4-field prompt by default:  [domain] user [perms]:cwd$
# To override it, uncomment and edit one of these:
#PS1='\u@\h:\w\$ '
#PS1='\w \$ '

# --- local override hook (not overwritten on update) ---
[ -r /etc/profile.local ] && . /etc/profile.local
`;
    // Z1: zsh does NOT read /etc/profile — its global interactive config is /etc/zshrc.
    // This makes real zsh usable as the default Linux shell on the cooperative kernel.
    static immutable string ZSHRC =
`# /etc/zshrc — AnonymOS global zsh config (interactive shells).
# zsh ignores /etc/profile; THIS is the zsh customization point.  The full
# Oh-My-Zsh / Powerlevel plan is roadmap/ZSH_INTEGRATION_ROADMAP.md (Z5/Z6).

# Job control (MONITOR) needs process groups + tcsetpgrp the cooperative kernel does
# not fully model yet; with it on, zsh wedges after the first external command.  Turn
# it off so commands run sequentially.  (Ctrl-Z / bg / fg are a later kernel item.)
unsetopt MONITOR
# No reverse-video '%' partial-line marker, no beeping.
unsetopt PROMPT_SP PROMPT_CR
setopt NO_BEEP

# Make %n (username) resolve even if the passwd lookup raced shell startup.
[[ -z "$USERNAME" ]] && USERNAME=${USER:-user}

# --- aliases (zsh has no /etc/profile; mirror the busybox /etc/profile set) ---
alias ll='ls -lah'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias grep='grep --color=auto'
# AnonymOS object-model shortcuts:
alias objects='cat /objects/store'
alias caps='cat /config/identities.json'
alias services='cat /config/services.json'
alias sysinfo='cat /config/system.json'
# git (works once git is installed):
alias gs='git status'

# --- Z4c/L5: LFE inside zsh -- the native shell is ONE shell (zsh), not a separate -sh ---------
# The native-personality zsh IS the native shell, with LFE embedded inside it (the Linux shell,
# EPIN_SHELL != native, gets none of this and is confined to POSIX):
#   * obj/id/ns/svc/sys  -- IN-PROCESS native-ABI builtins from the zsh/anonymos module (Z4c.4),
#                           calling HOS_SYS_QUERY directly from the zsh process.
#   * lfe ...             -- the FULL LFE language (defun/let/case/lists/tuples/pattern matching +
#                           the object-ABI forms, L2-L4) -- the same evaluator as the obj/... builtins.
#   * everything else     -- ordinary POSIX zsh.
# So:  lfe (defun inc (n) (- n -1)) (inc 41)  => 42 ;  obj => the object table ;  ls => ls.
# ('id' shadows coreutils id on purpose -- use 'command id' for the POSIX one.)
if [[ "$EPIN_SHELL" == native ]]; then
  hos() { /hos-sh "$@" }
  lfe() { /hos-sh "$@" }   # evaluate full LFE forms in the native shell (the L2-L4 evaluator)
  # Z4c.4: prefer the IN-PROCESS zsh module — obj/id/ns/svc/sys become native-ABI builtins that
  # call HOS_SYS_QUERY directly from the zsh process (no /hos-sh subprocess per command).  zsh
  # holds the N0 gate here (native personality), so the in-process syscall is granted.  If the
  # module is absent, fall back to the Z4c.1 helper-spawning functions.
  if zmodload zsh/anonymos 2>/dev/null; then
    : # obj/id/ns/svc/sys now provided in-process by zsh/anonymos
  else
    obj() { /hos-sh obj "$@" }
    id()  { /hos-sh id  "$@" }
    ns()  { /hos-sh ns  "$@" }
    svc() { /hos-sh svc "$@" }
    sys() { /hos-sh sys "$@" }
  fi
  # Z6.1: a native prompt from the kernel identity — "user@namespace [<full rights ceiling>]"
  # (e.g. ...exec admin) via HOSQ_WHOAMI, so the native shell's prompt visibly differs from the
  # Linux flavor's EPIN_*-derived one.  zsh can't issue the native syscall, so /hos-sh prints it.
  # NB: routed through a temp file + the read builtin, NOT command substitution: $(...) that
  # captures a spawned child's pipe currently hangs in native zsh (tracked); writing to a file
  # and reading it with the read builtin avoids the capture pipe entirely.  Computed once (the
  # identity is fixed per session); %~ (path) and %# still update live.
  /hos-sh whoami > "$HOME/.hos_id" 2>/dev/null
  __hos_id=; read -r __hos_id < "$HOME/.hos_id" 2>/dev/null
  rm -f "$HOME/.hos_id"
  # Fallback prompt; the Z7 theme (loaded below) overrides PROMPT in its precmd.  __hos_id
  # (e.g. "user@System [fs:rw net:nat ipc exec admin]") is kept GLOBAL so the theme can surface
  # the native-only exec/admin rights the Linux flavor's EPIN_* env doesn't carry.
  [[ -n "$__hos_id" ]] && PROMPT="${__hos_id//\%/%%}:%~%# "
  typeset -g __hos_id
fi

# --- Z5: declarative shell.json -> zsh config --------------------------------
# AnonymOS keeps the user-facing shell config in a declarative /etc/shell.json (history,
# completion, aliases).  This translator reads it at startup and applies the known keys onto
# zsh, so editing the JSON changes the shell.  Pure zsh (no jq/sed) — it scans the file line
# by line and matches with zsh's =~ / glob, so it runs in both the Linux and native flavors.
__hos_apply_shell_json() {
  local f=$1 line inaliases=0
  [[ -r $f ]] || return 0
  while IFS= read -r line; do
    if [[ $line == *'"size"'* ]] && [[ $line =~ '"size"[^0-9]*([0-9]+)' ]]; then
      HISTSIZE=$match[1]; SAVEHIST=$match[1]
    fi
    [[ $line == *'"shared"'*true* ]]          && setopt SHARE_HISTORY
    [[ $line == *'"saveDuplicates"'*false* ]] && setopt HIST_IGNORE_DUPS
    [[ $line == *'"menu"'*true* ]]            && zstyle ':completion:*' menu select
    [[ $line == *'"caseInsensitive"'*true* ]] && zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}'
    if [[ $line == *'"aliases"'* ]]; then inaliases=1; continue; fi
    if (( inaliases )); then
      [[ $line == *'}'* ]] && { inaliases=0; continue; }
      [[ $line =~ '"([^"]+)"[[:space:]]*:[[:space:]]*"([^"]*)"' ]] && alias -- "$match[1]=$match[2]"
    fi
  done < $f
}
# Resolution: system JSON first, then per-user ~/.shell.json overrides it.  zsh sources
# ~/.zshrc after this file, so an explicit user rc still gets the final word.
__hos_apply_shell_json /etc/shell.json
[[ -r "$HOME/.shell.json" ]] && __hos_apply_shell_json "$HOME/.shell.json"

# --- Z10: history (per identity / namespace, disposable-ephemeral) ----------------------------
# Each security domain gets its OWN history file, so command history never leaks between
# identities/namespaces.  Disposable domains keep history in RAM only — it is never written and
# dies with the shell (the "automatic expiration" the policy calls for).  Sizes + the shared/dedup
# flags come from /etc/shell.json (Z5); this adds the file + the per-domain split + Ctrl-R/fc.
setopt EXTENDED_HISTORY          # timestamp + duration per entry
setopt INC_APPEND_HISTORY        # append each command as it runs (survives a crash / mid-session exit)
setopt SHARE_HISTORY             # live-share across concurrent terminals of the SAME domain
setopt HIST_IGNORE_DUPS HIST_IGNORE_SPACE HIST_REDUCE_BLANKS HIST_VERIFY
: ${HISTSIZE:=100000}; : ${SAVEHIST:=100000}
if [[ $EPIN_NET == disposable ]]; then
  unset HISTFILE; SAVEHIST=0     # ephemeral: nothing persisted, gone when the shell exits
else
  __hos_dom=${EPIN_DOMAIN:-linux}; __hos_dom=${__hos_dom//[^A-Za-z0-9_-]/_}
  HISTFILE=${HOME:-/root}/.zsh_history.${__hos_dom}
  unset __hos_dom
fi
# NB: today HISTFILE lives in the ramfs, so history is persistent + shared WITHIN a boot; surviving
# a reboot needs a disk-backed home (object-FS F4.3 writable storage), and the shell.json
# "encrypted" option needs a crypto syscall over core/secipc.d's ChaCha20-Poly1305 — both tracked.

# --- Z8: completion engine ---------------------------------------------------
# zsh's function/completion tree is staged at the compiled-in default $fpath
# (/system/shell/zsh/share/zsh/5.9/functions, unpacked at boot from zshfns.blob).  Bring up
# the completion system: compinit scans $fpath for #compdef-tagged functions and builds the
# completion map.  -C skips the per-file security audit (the tree is kernel-seeded + trusted)
# so startup stays fast; the dump is cached in ~/.zcompdump.
autoload -Uz compinit
compinit -C -d "${HOME:-/root}/.zcompdump" 2>/dev/null
# AnonymOS object-model completions (Z8.2): #compdef-tagged _hos/_obj/_ns/_svc/_sys are staged
# alongside the upstream functions and picked up by compinit automatically.
zstyle ':completion:*' completer _complete _approximate
zstyle ':completion:*' menu select
zstyle ':completion:*:descriptions' format '%F{8}-- %d --%f'
zstyle ':completion:*' group-name ''

# --- Z7: theme engine --------------------------------------------------------
# Oh-My-Zsh-style themes live in $ZSH_THEMES_DIR.  The default 'anonymos' theme paints a colored
# multi-line prompt (identity/namespace/capabilities/path/git + an exit-status-tinted prompt char)
# using the truecolor SGR wl-term understands (Z7.1); the namespace is drawn in the domain color
# (EPIN_DOMAIN_COLOR) — the same unspoofable color on the window border.  A user theme in
# ~/.zsh/themes/ overrides the system one; set ZSH_THEME=none to keep the plain prompt.
ZSH_THEMES_DIR=${ZSH_THEMES_DIR:-/etc/zsh/themes}
: ${ZSH_THEME:=anonymos}
if [[ $ZSH_THEME != none ]]; then
  for __td in "$HOME/.zsh/themes" "$ZSH_THEMES_DIR"; do
    if [[ -r "$__td/$ZSH_THEME.zsh-theme" ]]; then source "$__td/$ZSH_THEME.zsh-theme"; break; fi
  done
  unset __td
fi

# --- Z9: plugin system ------------------------------------------------------------------------
# Oh-My-Zsh-compatible loader.  Each plugin in $plugins is sourced from
# $ZSH_PLUGINS_DIR/<name>/<name>.plugin.zsh (unpacked at boot from zshplugins.blob).  Ships the
# native AnonymOS object-model plugin + zsh-autosuggestions + zsh-syntax-highlighting.  The
# highlighter wraps ZLE widgets, so it is ALWAYS sourced LAST, after every other plugin.
ZSH_PLUGINS_DIR=${ZSH_PLUGINS_DIR:-/system/shell/zsh/plugins}
typeset -ga plugins
(( ${#plugins} )) || plugins=(anonymos zsh-autosuggestions zsh-syntax-highlighting)
__hos_load_plugin() {
  local p=$1 f
  for f in "$ZSH_PLUGINS_DIR/$p/$p.plugin.zsh" "$ZSH_PLUGINS_DIR/$p/$p.zsh" "$ZSH_PLUGINS_DIR/$p.plugin.zsh"; do
    [[ -r $f ]] && { source "$f"; return 0; }
  done
  return 1
}
__hos_syn=0
for __p in $plugins; do
  [[ $__p == zsh-syntax-highlighting ]] && { __hos_syn=1; continue; }
  __hos_load_plugin "$__p"
done
(( __hos_syn )) && __hos_load_plugin zsh-syntax-highlighting
unset __p __hos_syn

# --- Z9b: Oh My Zsh + Powerlevel9k (opt-in via omz-setup) -------------------------------------
# The popular customization stack is vendored under /system/shell/zsh/omz/.  This default config
# keeps the lean AnonymOS theme (Z7); omz-setup installs the ready Oh My Zsh + Powerlevel9k
# profile to ~/.zshrc (the offline, capability-respecting analogue of the gist's install-zsh.sh),
# so "set up my shell like everyone's" is one command — fully vendored, no network.
omz-setup() {
  local src=/system/shell/zsh/omz/anonymos/zshrc.omz dst=${HOME:-/root}/.zshrc
  [[ -r $src ]] || { print -ru2 'omz-setup: Oh My Zsh profile not found (omz.blob missing?)'; return 1; }
  if [[ -e $dst ]] && ! grep -q 'Oh My Zsh + Powerlevel9k profile' "$dst" 2>/dev/null; then
    cp -- "$dst" "$dst.pre-omz" 2>/dev/null && print -r -- 'omz-setup: backed up your ~/.zshrc to ~/.zshrc.pre-omz'
  fi
  cp -- "$src" "$dst" && print -r -- 'omz-setup: Oh My Zsh + Powerlevel9k installed to ~/.zshrc — run  exec zsh  (or open a new terminal).'
}

# --- local override hook (not overwritten on update) ---
[[ -r /etc/zshrc.local ]] && source /etc/zshrc.local
`;
    static immutable string SHELL_JSON =
`{
  "shell": {
    "default": "zsh",
    "theme": "anonymos",
    "prompt": {
      "showUser": true,
      "showHost": true,
      "showNamespace": true,
      "showIdentity": true,
      "showWorkingDirectory": true,
      "showGit": true,
      "showCapabilities": true,
      "showTime": false
    },
    "history": { "size": 100000, "shared": true, "saveDuplicates": false },
    "completion": { "enabled": true, "menu": true, "caseInsensitive": true, "fuzzy": true },
    "autosuggestions": true,
    "syntaxHighlighting": true,
    "plugins": ["git","history","extract","fzf","capabilities","namespace","identity","objects"],
    "aliases": {
      "ll": "ls -lah",
      "la": "ls -A",
      "gs": "git status",
      "z5demo": "echo Z5-CONFIG-LIVE"
    }
  }
}
`;
    // Z7: the default 'anonymos' theme.  A self-contained zsh prompt theme: colored multi-line
    // layout (identity/namespace/capabilities/object-path/git + exit-status-tinted prompt char,
    // exec-time on the right).  Works in both flavors — native surfaces the kernel identity's
    // exec/admin rights via $__hos_id (Z6.1), Linux reads EPIN_*.  The namespace is painted in the
    // domain's 24-bit color (EPIN_DOMAIN_COLOR), matching wl-term's unspoofable window border.
    // A Nerd-Font glyph set is selected when EPIN_NERDFONT is advertised, ASCII otherwise (the
    // terminal grid is single-byte today, so ASCII is the live path; the branch is ready for
    // terminal UTF-8 + a Nerd font).  No command substitution in the hot path except git (which
    // only runs when git is actually installed), so the prompt stays fork-light.
    static immutable string THEME =
`# anonymos.zsh-theme — AnonymOS multi-line prompt (Z7 theme engine, Deliverable 8).
# Segments: [identity@namespace] capabilities  object-path  git ;  line 2 = exit-tinted char.
# RPROMPT = exec-time.  Override per-user by dropping ~/.zsh/themes/anonymos.zsh-theme.

# --- glyph set: Nerd-Font when advertised (EPIN_NERDFONT), ASCII fallback otherwise ----------
if [[ -n "$EPIN_NERDFONT" ]]; then
  __a_arrow=$'\u276f'; __a_at='@'; __a_glyph=$'\ue0a0 '
else
  __a_arrow='>'; __a_at='@'; __a_glyph='git:'
fi
__a_rst=$'\e[0m'

# --- namespace color: EPIN_DOMAIN_COLOR is 0xAARRGGBB (Domain Manager); convert to a 24-bit SGR
# --- (wl-term groks 38;2;R;G;B since Z7.1) so the prompt's domain matches the window border. ----
__a_dom_sgr() {
  local dc=${EPIN_DOMAIN_COLOR:-0xff3b82f6}
  dc=${dc#0x}; dc=${dc#0X}
  local rgb
  if (( ${#dc} >= 8 )); then rgb=${dc[3,8]}; else rgb=${dc[1,6]}; fi
  (( ${#rgb} == 6 )) || rgb=3b82f6
  local r g b
  r=$(( 16#${rgb[1,2]} )) g=$(( 16#${rgb[3,4]} )) b=$(( 16#${rgb[5,6]} ))
  __a_dom=$'\e[38;2;'"${r};${g};${b}"$'m'
}
__a_dom_sgr 2>/dev/null || __a_dom=$'\e[38;2;59;130;246m'

# --- exec-time timer (preexec stamps the start second; precmd reports the delta) -------------
typeset -gi __a_t0=-1
__anonymos_preexec() { __a_t0=$SECONDS }

# --- git segment: only when git is installed AND inside a work tree (silent otherwise) -------
__anonymos_git() {
  __a_git=''
  (( $+commands[git] )) || return
  local b; b=$(git rev-parse --abbrev-ref HEAD 2>/dev/null) || return
  [[ -n $b && $b != HEAD ]] || return
  local d=''; git diff --quiet --ignore-submodules 2>/dev/null || d='*'
  __a_git=" %F{yellow}${__a_glyph}${b}${d}%f"
}

# --- assemble PROMPT/RPROMPT for each new prompt (precmd) ------------------------------------
__anonymos_precmd() {
  local last=$?
  # capabilities from the domain policy env (both flavors); native adds exec/admin from the id
  local caps='' dsk=$EPIN_DISK net=$EPIN_NET
  [[ -n $dsk && $dsk != none ]] && caps+="fs:$dsk "
  [[ -n $net && $net != none ]] && caps+="net:$net "
  [[ $EPIN_SECURE_IPC == 1 ]]    && caps+="ipc "
  if [[ $EPIN_SHELL == native && -n $__hos_id ]]; then
    [[ $__hos_id == *exec*  ]] && caps+="exec "
    [[ $__hos_id == *admin* ]] && caps+="admin "
  fi
  caps=${caps%% }
  local capseg=''; [[ -n $caps ]] && capseg=" %F{8}${caps}%f"
  local dom=${EPIN_DOMAIN:-linux}
  # %n (USERNAME) is unreliable: setting USERNAME attempts a setuid so the zshrc fallback can't,
  # and getpwuid races shell startup — so read the literal user from the env wl-term passes.
  local usr=${EPIN_USER:-${USER:-user}}
  local ns="%{${__a_dom}%}${dom}%{${__a_rst}%}"
  __anonymos_git
  # line 1: identity + namespace(domain color) + caps + object-path + git
  local l1="%F{8}[%f%B%F{green}${usr}%f%b%F{8}${__a_at}%f%B${ns}%b%F{8}]%f${capseg} %F{cyan}%~%f${__a_git}"
  # line 2: prompt char, green if the last command succeeded, red if it failed
  local mark; (( last == 0 )) && mark="%F{green}${__a_arrow}%f" || mark="%F{red}${__a_arrow}%f"
  PROMPT=$'\n'"${l1}"$'\n'"${mark} "
  # right prompt: elapsed wall-clock of the last command once it crosses ~2s
  RPROMPT=''
  if (( __a_t0 >= 0 )); then
    local el=$(( SECONDS - __a_t0 )); __a_t0=-1
    (( el >= 2 )) && RPROMPT="%F{8}${el}s%f"
  fi
}

# Register the hooks via the precmd_functions/preexec_functions arrays directly — these are
# zsh builtins that need no autoloaded helper (add-zsh-hook's function file isn't on $fpath in
# the base image yet; that arrives with the Z8/Z9 zsh function tree).  Guard against a double
# add if the theme is re-sourced, then paint the first prompt immediately.
typeset -ga precmd_functions preexec_functions
(( ${precmd_functions[(I)__anonymos_precmd]} ))  || precmd_functions+=(__anonymos_precmd)
(( ${preexec_functions[(I)__anonymos_preexec]} )) || preexec_functions+=(__anonymos_preexec)
__anonymos_precmd
`;
    rtAddFile("etc/profile\0".ptr,    "etc/profile".length,    cast(const(ubyte)*)PROFILE.ptr,    cast(uint)PROFILE.length);
    rtAddFile("etc/zshrc\0".ptr,      "etc/zshrc".length,      cast(const(ubyte)*)ZSHRC.ptr,      cast(uint)ZSHRC.length);
    rtAddFile("etc/shell.json\0".ptr, "etc/shell.json".length, cast(const(ubyte)*)SHELL_JSON.ptr, cast(uint)SHELL_JSON.length);
    rtAddFile("etc/zsh/themes/anonymos.zsh-theme\0".ptr, "etc/zsh/themes/anonymos.zsh-theme".length,
              cast(const(ubyte)*)THEME.ptr, cast(uint)THEME.length);

    // Z8.2: AnonymOS object-model completion, dropped into zsh's default $fpath next to the
    // upstream functions so compinit picks it up automatically.  Completes the verbs the Z4c
    // `hos` dispatcher and its obj/id/ns/svc/sys shortcuts accept.
    static immutable string HOSCOMP =
`#compdef hos obj id ns svc sys
# AnonymOS object-model completion (Z8.2 / Deliverable 11).  The Z4c object commands query the
# kernel object model (objects / identities / namespaces / services / system) — natively via the
# object ABI, or on Linux via the /objects store + /config/*.json FS views.  This completes the
# verb after the hos dispatcher; the bare shortcuts (obj/id/ns/svc/sys) are themselves the verbs.
local -a verbs
verbs=(
  'obj:list objects by type (kernel object store)'
  'id:list identity domains'
  'ns:list namespaces'
  'svc:list services'
  'sys:system and kernel info'
  'whoami:print this shell identity and rights'
)
if [[ $service == hos ]]; then
  _describe -t hos-verbs 'hos verb' verbs
else
  _message -e args 'no further arguments'
fi
`;
    rtAddFile("system/shell/zsh/share/zsh/5.9/functions/_hos\0".ptr,
              "system/shell/zsh/share/zsh/5.9/functions/_hos".length,
              cast(const(ubyte)*)HOSCOMP.ptr, cast(uint)HOSCOMP.length);
}

// Track A A2/A3: one-shot boot self-test of the runtime filesystem — symlinks,
// symlink-follow on open, mode/owner persistence (chmod), getdents, the /bin applet
// tree, and payload-page accounting.  Prints `[rtfs] selftest PASS/FAIL` to serial.
__gshared bool g_rtfsTested = false;
private void rtfsSelfTest() {
    if (g_rtfsTested) return;
    g_rtfsTested = true;
    int pass = 0, fail = 0;
    void chk(bool c) { if (c) ++pass; else ++fail; }

    // 1. /bin is a real overlay directory and holds the applet symlinks.
    int bp; const(char)* bl; size_t bll;
    const int binIdx = rtResolve("/bin\0".ptr, bp, bl, bll);
    chk(binIdx > 0 && g_rt[binIdx].kind == RT_DIR);
    int appletCount = 0;
    for (int i = 1; i < RT_MAX_NODES; ++i)
        if (g_rt[i].kind == RT_LNK && g_rt[i].parent == binIdx) ++appletCount;
    chk(appletCount >= 300);

    // 2. /bin/ls is a symlink whose target reads back as /busybox.
    int lp; const(char)* ll; size_t lll;
    const int lsIdx = rtResolve("/bin/ls\0".ptr, lp, ll, lll);
    chk(lsIdx > 0 && g_rt[lsIdx].kind == RT_LNK);
    {
        char[32] tgt; const long rl = linux_sys_readlink(cast(ulong)"/bin/ls\0".ptr,
                                                         cast(ulong)tgt.ptr, 32);
        chk(rl == 8 && tgt[0] == '/' && tgt[1] == 'b' && tgt[7] == 'x'); // "/busybox"
    }

    // 3. open("/bin/ls") follows the symlink through to the busybox boot module.
    {
        const int fd = sys_open("/bin/ls\0".ptr, O_RDONLY);
        chk(fd >= 0 && g_fdTable[fd].type == FileType.FD_BOOT_MODULE && g_fdTable[fd].fileSize > 0);
        if (fd >= 0) sys_close(fd);
    }

    // 4. create + write + read-back + chmod + stat + unlink on a tmp file, and verify
    //    the byte accounting returns to its starting point (no page leak).
    {
        const ulong bytes0 = g_rtBytes;
        const int wf = sys_open("/tmp/.rtfs_test\0".ptr, O_RDWR | O_CREAT | O_TRUNC);
        chk(wf >= 0);
        if (wf >= 0) {
            immutable ubyte[5] payload = ['h','e','l','l','o'];
            chk(sys_write(wf, payload.ptr, 5) == 5);
            sys_close(wf);
            const int rf = sys_open("/tmp/.rtfs_test\0".ptr, O_RDONLY);
            char[8] rb;
            const long n = sys_read(rf, rb.ptr, 8);
            chk(n == 5 && rb[0] == 'h' && rb[4] == 'o');
            if (rf >= 0) sys_close(rf);
            // chmod 0600 then stat the path and confirm the mode persisted.
            linux_sys_chmod(cast(ulong)"/tmp/.rtfs_test\0".ptr, 0x180 /*0600*/);
            ubyte[144] st;
            chk(linux_sys_stat(cast(ulong)"/tmp/.rtfs_test\0".ptr, cast(ulong)st.ptr) == 0);
            chk((*cast(uint*)(st.ptr + 24) & 0xFFF) == 0x180);
            linux_sys_unlink(cast(ulong)"/tmp/.rtfs_test\0".ptr);
        }
        chk(g_rtBytes == bytes0);                       // unlink freed the page
    }

    klog("[rtfs] selftest ");
    klog(fail == 0 ? "PASS".ptr : "FAIL".ptr);
    klog(" (/bin applets="); klog_dec(cast(ulong)appletCount);
    klog(", checks "); klog_dec(cast(ulong)pass); klog("/"); klog_dec(cast(ulong)(pass + fail));
    klog(", rtBytes="); klog_dec(g_rtBytes); klog(")\n");
}

// Find-or-create a directory child `name`(len) under overlay dir `cur`.
private int rtMkdirChild(int cur, const(char)* name, size_t len) {
    int c = rtFindChild(cur, name, len);
    if (c >= 0) return (g_rt[c].kind == RT_DIR) ? c : -1;
    return rtCreate(cur, name, len, RT_DIR, 0x1ED /*0755*/, 0, 0);
}

// Walk a '/'-separated relative path (no leading '/'), creating intermediate
// directories, then create the final component as a regular file holding `data`.
private void rtAddFile(const(char)* rel, size_t relLen, const(ubyte)* data, uint dataLen) {
    int cur = 0;                      // overlay root
    size_t i = 0;
    while (i < relLen) {
        size_t cstart = i;
        while (i < relLen && rel[i] != '/') ++i;
        size_t clen = i - cstart;
        const bool isLast = (i >= relLen);
        if (clen == 0) { ++i; continue; }   // collapse '//'
        if (isLast) {
            int fidx = rtFindChild(cur, rel + cstart, clen);
            if (fidx < 0) fidx = rtCreate(cur, rel + cstart, clen, RT_REG,
                                          cast(ushort)0x1A4 /*0644*/, 0, 0);
            if (fidx < 0 || g_rt[fidx].kind != RT_REG) return;
            if (!rtEnsureCap(g_rt[fidx], dataLen)) { ++g_xkbAllocFails; return; }
            foreach (k; 0 .. dataLen) g_rt[fidx].data[k] = data[k];
            g_rt[fidx].size = dataLen;
            return;
        }
        cur = rtMkdirChild(cur, rel + cstart, clen);
        if (cur < 0) return;
        ++i;                          // skip '/'
    }
}

// Publish the WIRED link state where the desktop panel can read it.
//
// The panel's network indicator (deps/weston-14.0.0/clients/desktop-shell.c, epin_net_state)
// used to consult ONLY /run/wifi/networks.  Inside a VM there is no Wi-Fi adapter to pass
// through, so that file never appears and the indicator showed the slashed "disconnected"
// glyph forever -- even with a perfectly working Ethernet link.  Publishing the real wired
// state here is what lets the panel tell "no connection", "wired" and "Wi-Fi" apart.
//
// Format, one line: "<kind>\t<up>\t<a.b.c.d>\n"  e.g. "wired\t1\t10.0.2.15\n".
public void publishNetStatus(bool up, ubyte a, ubyte b, ubyte c, ubyte d) @nogc nothrow {
    char[64] buf;
    uint n = 0;
    void putc(char ch) { if (n < buf.length) buf[n++] = ch; }
    void putDec(ubyte v) {
        if (v >= 100) putc(cast(char)('0' + v / 100));
        if (v >= 10)  putc(cast(char)('0' + (v / 10) % 10));
        putc(cast(char)('0' + v % 10));
    }
    foreach (ch; "wired\t") putc(ch);
    putc(up ? '1' : '0');
    putc('\t');
    putDec(a); putc('.'); putDec(b); putc('.'); putDec(c); putc('.'); putDec(d);
    putc('\n');
    rtAddFile("run/net/status\0".ptr, "run/net/status".length,
              cast(const(ubyte)*)buf.ptr, n);
}

// ─── Host WiFi bridge over COM2 ──────────────────────────────────────────────
// QEMU has no scannable WiFi device, so real signals can't come from inside the
// guest.  When launched with WIFI=1, qemu-run.sh attaches a second serial port
// (COM2, 0x2F8) wired to a host process (src/util/wifi-host-bridge.py) that runs
// real `nmcli` on the host's WiFi card.  This kernel bridge:
//   • drains COM2 RX, and on each form-feed-terminated frame writes the received
//     bytes verbatim to /run/wifi/networks (the exact file the desktop Wi-Fi menu
//     already renders — real SSIDs + real signal strengths + the active row);
//   • forwards a pending /run/wifi/connect ("SSID\nPSK\n", written by the menu) to
//     the host as "CONNECT\tSSID\tPSK\n", which runs a real `nmcli … connect`.
// It is presence-gated on a 16550 scratch-register probe: no second serial port →
// no bridge → the userspace demo agent runs instead (see maybeSpawnWifiAgent).
private enum ushort WIFI_COM2 = 0x2F8;
__gshared bool  g_wifiBridgePresent = false;
__gshared bool  g_wifiBridgeChecked = false;
__gshared ubyte[16384] g_wifiRxBuf;
__gshared uint  g_wifiRxLen = 0;

public bool wifiBridgeDetect() @nogc nothrow {
    if (g_wifiBridgeChecked) return g_wifiBridgePresent;
    g_wifiBridgeChecked = true;
    // 16550 scratch register (base+7) round-trips only when a device is present;
    // an absent COM2 reads back 0xFF and ignores writes.
    outb(WIFI_COM2 + 7, 0x5A); const bool a = (inb(WIFI_COM2 + 7) == 0x5A);
    outb(WIFI_COM2 + 7, 0xA5); const bool b = (inb(WIFI_COM2 + 7) == 0xA5);
    g_wifiBridgePresent = a && b;
    if (g_wifiBridgePresent) {
        outb(WIFI_COM2 + 1, 0x00);   // no interrupts (we poll)
        outb(WIFI_COM2 + 3, 0x80);   // DLAB
        outb(WIFI_COM2 + 0, 0x01);   // divisor 1 → 115200
        outb(WIFI_COM2 + 1, 0x00);
        outb(WIFI_COM2 + 3, 0x03);   // 8N1
        outb(WIFI_COM2 + 2, 0xC7);   // FIFO enable + clear
        outb(WIFI_COM2 + 4, 0x0B);   // DTR/RTS/OUT2
    }
    return g_wifiBridgePresent;
}

private void wifiCom2Tx(ubyte c) @nogc nothrow {
    uint spins = 0;
    // Short bound: if the host isn't draining COM2 (bridge slow/dead) we DROP the byte
    // rather than stall the kernel loop (which holds the BKL — a long spin freezes the
    // whole desktop).  Normal draining sets THRE within a handful of reads.
    while ((inb(WIFI_COM2 + 5) & 0x20) == 0) { if (++spins > 2000) return; }
    outb(WIFI_COM2, c);
}
private void wifiCom2TxStr(const(char)* s) @nogc nothrow { while (*s) wifiCom2Tx(cast(ubyte)*s++); }

// Delete an overlay file by absolute path (used to consume /run/wifi/connect).
private void wifiRtDelete(const(char)* absPath) @nogc nothrow {
    int par; const(char)* lf; size_t lfl;
    const int idx = rtResolve(absPath, par, lf, lfl);
    if (idx > 0 && idx < RT_MAX_NODES && g_rt[idx].kind == RT_REG) {
        rtFreeData(g_rt[idx]);
        g_rt[idx].kind = RT_FREE;
        g_rt[idx].parent = -1;
    }
}

// Called every kernel-loop iteration when the bridge is present, but THROTTLED to
// ~10 Hz: the work below (a form-feed-framed RX drain + an rtResolve of
// /run/wifi/connect, which is a full ~12k-node overlay scan when the file is absent)
// is far too heavy to run on every scheduler pass — doing so starved the guest so
// badly that client poll(timeout) calls returned instantly and a client spun open()ing
// /run/wifi/networks, freezing the desktop.  10 Hz is ample for a WiFi menu (the host
// sends a scan frame every 3 s; connect latency ≤100 ms).
__gshared ulong g_wifiPollLastMs = 0;
public void wifiBridgePoll() @nogc nothrow {
    if (!g_wifiBridgePresent) return;
    const ulong nowMs = pitMs();
    if (nowMs - g_wifiPollLastMs < 100) return;   // ~10 Hz
    g_wifiPollLastMs = nowMs;

    // 1) drain COM2 RX; commit a frame on form-feed (0x0C).
    uint budget = 8192;
    while (budget-- > 0 && (inb(WIFI_COM2 + 5) & 0x01)) {
        const ubyte ch = inb(WIFI_COM2);
        if (ch == 0x0C) {                                    // frame complete
            rtAddFile("run/wifi/networks\0".ptr, 17, g_wifiRxBuf.ptr, g_wifiRxLen);
            g_wifiRxLen = 0;
        } else if (g_wifiRxLen < g_wifiRxBuf.length) {
            g_wifiRxBuf[g_wifiRxLen++] = ch;
        } else {
            g_wifiRxLen = 0;                                 // overflow → drop frame
        }
    }

    // 2) forward a pending connect request, then delete it.
    int cpar; const(char)* clf; size_t clfl;
    const int ci = rtResolve("/run/wifi/connect\0".ptr, cpar, clf, clfl);
    if (ci > 0 && ci < RT_MAX_NODES && g_rt[ci].kind == RT_REG && g_rt[ci].size > 0) {
        wifiCom2TxStr("CONNECT\t".ptr);
        foreach (k; 0 .. g_rt[ci].size) {
            const ubyte c = g_rt[ci].data[k];
            wifiCom2Tx(c == '\n' ? cast(ubyte)'\t' : c);     // SSID\nPSK → SSID\tPSK
        }
        wifiCom2Tx('\n');
        wifiRtDelete("/run/wifi/connect\0".ptr);
    }
}

// Parse the bundled `xkb.blob` boot module — a flat archive of
// [u32 pathLen][path][u32 dataLen][data] entries (paths relative to overlay
// root, e.g. "usr/share/X11/xkb/symbols/us") — into the overlay.
private void rtUnpackXkb() {
    ulong phys, size;
    if (!findBootModule("/xkb.blob\0".ptr, phys, size)) return;
    if (phys == 0 || size < 8) return;
    const(ubyte)* base = cast(const(ubyte)*)phys_to_virt(phys);
    ulong off = 0;
    while (off + 8 <= size) {
        uint pathLen = *cast(const(uint)*)(base + off); off += 4;
        if (pathLen == 0 || pathLen > 1024 || off + cast(ulong)pathLen + 4 > size) break;
        const(char)* p = cast(const(char)*)(base + off); off += pathLen;
        uint dataLen = *cast(const(uint)*)(base + off); off += 4;
        if (off + cast(ulong)dataLen > size) break;
        const(ubyte)* d = base + off; off += dataLen;
        rtAddFile(p, pathLen, d, dataLen);
        ++g_xkbFiles;
        g_xkbBytes += dataLen;
    }
    klog("[xkb] unpacked files="); klog_hex(g_xkbFiles);
    klog(" bytes="); klog_hex(g_xkbBytes);
    klog(" allocFails="); klog_hex(g_xkbAllocFails); klog("\n");
}

__gshared uint g_xkbFiles = 0;
__gshared uint g_xkbBytes = 0;
__gshared uint g_xkbAllocFails = 0;

__gshared uint g_assetFiles = 0;
__gshared uint g_assetBytes = 0;

// Parse one bundled GUI asset boot module — same flat archive format as xkb.blob
// ([u32 pathLen][path][u32 dataLen][data], paths relative to overlay root, e.g.
// "usr/share/hypr/wall0.png") — into the rtfs overlay. Optional: boots fine
// without it, though toolkit clients will fall back to synthetic defaults.
private uint rtUnpackAssetBlob(const(char)* modulePath) {
    ulong phys, size;
    if (!findBootModule(modulePath, phys, size)) return 0;
    if (phys == 0 || size < 8) return 0;
    const(ubyte)* base = cast(const(ubyte)*)phys_to_virt(phys);
    ulong off = 0;
    uint files = 0;
    uint bytes = 0;
    while (off + 8 <= size) {
        uint pathLen = *cast(const(uint)*)(base + off); off += 4;
        if (pathLen == 0 || pathLen > 1024 || off + cast(ulong)pathLen + 4 > size) break;
        const(char)* p = cast(const(char)*)(base + off); off += pathLen;
        uint dataLen = *cast(const(uint)*)(base + off); off += 4;
        if (off + cast(ulong)dataLen > size) break;
        const(ubyte)* d = base + off; off += dataLen;
        rtAddFile(p, pathLen, d, dataLen);
        ++files;
        bytes += dataLen;
        ++g_assetFiles;
        g_assetBytes += dataLen;
    }
    klog("[assets] "); klog(modulePath);
    klog(" unpacked files="); klog_hex(files);
    klog(" bytes="); klog_hex(bytes);
    klog(" total_files="); klog_hex(g_assetFiles);
    klog(" total_bytes="); klog_hex(g_assetBytes); klog("\n");
    return files;
}

private void rtUnpackAssets() {
    const uint before = g_assetFiles;
    rtUnpackAssetBlob("/fonts.blob\0".ptr);
    rtUnpackAssetBlob("/icons.blob\0".ptr);
    rtUnpackAssetBlob("/cursors.blob\0".ptr);
    rtUnpackAssetBlob("/wallpapers.blob\0".ptr);
    rtUnpackAssetBlob("/themes.blob\0".ptr);

    // Legacy fallback for older ISO layouts.
    if (g_assetFiles == before) {
        rtUnpackAssetBlob("/assets.blob\0".ptr);
    }

    // Z8: zsh's autoloadable function + completion tree (compinit, compaudit, _<cmd>
    // completions, add-zsh-hook, promptinit, vcs_info, zle widgets) flattened at zsh's
    // compiled-in default $fpath (/system/shell/zsh/share/zsh/5.9/functions) so
    // `autoload -Uz compinit && compinit` brings up the whole completion system.
    rtUnpackAssetBlob("/zshfns.blob\0".ptr);

    // Z9: zsh plugins (zsh-syntax-highlighting, zsh-autosuggestions, and the native anonymos
    // object-model plugin), under /system/shell/zsh/plugins/<name>/… with their directory
    // structure preserved (plugins source sibling files by relative path).  The Z9 loader in
    // /etc/zshrc sources them (syntax-highlighting last, as it wraps ZLE widgets).
    rtUnpackAssetBlob("/zshplugins.blob\0".ptr);

    // Z9b: the Oh My Zsh + Powerlevel9k stack under /system/shell/zsh/omz/ (framework + lib +
    // git plugin + the P9k theme + the Z9 plugins + the AnonymOS profile).  Opt-in via the
    // `omz-setup` function in /etc/zshrc, which installs the profile to ~/.zshrc.
    rtUnpackAssetBlob("/omz.blob\0".ptr);

    // ZKsync boot-integrity wallet and contract artifacts under
    // /system/web/zksync-wallet so the installed OS can deploy/update the
    // on-chain hash registry from the bundled wallet UI.
    rtUnpackAssetBlob("/zksync-wallet.blob\0".ptr);
}

private enum size_t fileBackendPlain = 0;
private enum size_t fileBackendDevNull = 1;
private enum size_t fileBackendDirectory = 2;
// backend values > 2 are pointers to immutable string content (virtual files)

private size_t fileBackendKind(File* f) {
    return (f is null) ? fileBackendPlain : cast(size_t)f.backend;
}

private bool fileIsDevNull(File* f) {
    return f !is null && f.type == FileType.FD_FILE && fileBackendKind(f) == fileBackendDevNull;
}

private bool fileIsSyntheticDirectory(File* f) {
    return f !is null && f.type == FileType.FD_FILE && fileBackendKind(f) == fileBackendDirectory;
}

private bool fileIsRtDirectory(File* f) {
    return f !is null && f.type == FileType.FD_RTDIR;
}

private bool fileIsVirtualContent(File* f) {
    return f !is null && f.type == FileType.FD_FILE && cast(size_t)f.backend > fileBackendDirectory;
}

// ── Virtual filesystem table ──────────────────────────────────────────────────
// Read-only files synthesised by the kernel; content lives in the data segment.
private struct VFEntry { const(char)[] path; const(char)[] content; }

private __gshared char[65]  g_hostname = "hanonymOS";
private __gshared char[65]  g_domainname = "(none)";
private __gshared char[96]  g_pxHostnameFile;
private __gshared uint      g_pxHostnameFileLen;
private __gshared char[192] g_pxHostsFile;
private __gshared uint      g_pxHostsFileLen;

private uint pxHostLen() {
    uint n = 0;
    while (n < 64 && g_hostname[n] != 0) ++n;
    return n;
}

private void pxAppend(ref uint pos, char[] dst, const(char)* s) {
    while (*s != 0 && pos < dst.length) dst[pos++] = *s++;
}

private void pxAppendHost(ref uint pos, char[] dst) {
    const uint n = pxHostLen();
    foreach (i; 0 .. n) if (pos < dst.length) dst[pos++] = g_hostname[i];
}

private void pxRebuildHostnameFiles() {
    uint pos = 0;
    pxAppendHost(pos, g_pxHostnameFile[]);
    if (pos < g_pxHostnameFile.length) g_pxHostnameFile[pos++] = '\n';
    g_pxHostnameFileLen = pos;

    pos = 0;
    pxAppend(pos, g_pxHostsFile[], "127.0.0.1 localhost ".ptr);
    pxAppendHost(pos, g_pxHostsFile[]);
    pxAppend(pos, g_pxHostsFile[], "\n::1 localhost\n".ptr);
    g_pxHostsFileLen = pos;
}

public void posixSetBootHostname(const(char)* name, size_t len) {
    if (name is null || len == 0) return;
    if (len > 64) len = 64;
    size_t outLen = 0;
    foreach (i; 0 .. len) {
        char c = name[i];
        if (c == 0) break;
        const bool ok = (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') ||
                        c == '-';
        if (!ok) return;
        g_hostname[outLen++] = c;
    }
    if (outLen == 0) return;
    g_hostname[outLen] = 0;
    foreach (i; outLen + 1 .. g_hostname.length) g_hostname[i] = 0;
    pxRebuildHostnameFiles();
}

private const(char)[] pxHostnameVirtualFile(const(char)* path) {
    if (g_pxHostnameFileLen == 0) pxRebuildHostnameFiles();
    if (cstrEq(path, "/etc/hostname") ||
        cstrEq(path, "/proc/sys/kernel/hostname") ||
        cstrEq(path, "/run/openrc/options/hostname"))
        return g_pxHostnameFile[0 .. g_pxHostnameFileLen];
    if (cstrEq(path, "/etc/hosts"))
        return g_pxHostsFile[0 .. g_pxHostsFileLen];
    return null;
}

// Raw PCI config space (first 64 bytes) for the virtio-gpu, served as
// /sys/class/drm/<node>/device/config.  libdrm's drmParsePciDeviceInfo (called by
// drmGetDevices2 → aquamarine's CDRMRenderer) open()s this and read()s 64 bytes for
// the PCI IDs; without it the dir-shim serves the path as a directory → read() gives
// EISDIR → the node is dropped → "drmGetDevice failed / no matching devices" → no
// renderer.  Layout: vendor@0=1af4, device@2=1050, revision@8=01, class@9..11,
// subvendor@0x2c=1af4, subdevice@0x2e=1100 (little-endian).
private enum string VIRTIO_GPU_PCI_CONFIG =
    "\xf4\x1a\x50\x10\x07\x00\x10\x00\x01\x00\x00\x03" ~   // 0x00: vendor=1af4, device=1050, cmd, status, rev=01, class
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ~ // 0x0c
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ~ // 0x1c
    "\xf4\x1a\x00\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ~ // 0x2c: subvendor=1af4@0x2c, subdevice=1100@0x2e
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";  // 0x3c

private immutable VFEntry[] g_vfs = [
    // /proc
    { "/proc/version",           "Linux version 6.0.0 (HanonymOS) #1 SMP x86_64 GNU/Linux\n"         },
    { "/proc/uptime",            "0.00 0.00\n"                                                         },
    { "/proc/cmdline",           "display.width=1280 display.height=800 display.scale=1 display.refresh=60 display.force_mode=0\n" },
    { "/proc/filesystems",       "nodev\tproc\nnodev\tsysfs\nnodev\ttmpfs\nnodev\tdevtmpfs\n"          },
    { "/proc/mounts",            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"               },
    { "/proc/swaps",             "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"                  },
    { "/proc/meminfo",           "MemTotal:        524288 kB\nMemFree:         262144 kB\n"            },
    { "/proc/cpuinfo",           "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu MHz\t\t: 2000.000\n" },
    { "/proc/loadavg",           "0.00 0.00 0.00 1/1 1\n"                                             },
    { "/proc/stat",              "cpu  0 0 0 0 0 0 0 0 0 0\n"                                         },
    { "/proc/devices",           "Character devices:\n  5 /dev/tty\n  1 mem\n"                         },
    { "/proc/self/status",       "Name:\tinit\nState:\tS\nTgid:\t1\nPid:\t1\nPPid:\t0\n" ~
                                 "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n" ~
                                 "VmRSS:\t4096 kB\nVmPeak:\t8192 kB\n"                                },
    { "/proc/self/maps",         ""                                                                    },
    { "/proc/self/mountinfo",    "1 0 0:1 / / rw - tmpfs none rw\n"                                   },
    { "/proc/self/cgroup",       "0::/\n"                                                              },
    { "/proc/self/comm",         "init\n"                                                              },
    { "/proc/self/environ",      ""                                                                    },
    { "/proc/self/oom_score_adj","0\n"                                                                 },
    { "/proc/self/wchan",        "0\n"                                                                 },
    { "/proc/self/loginuid",     "1000\n"                                                              },
    { "/proc/self/sessionid",    "1\n"                                                                 },
    { "/proc/self/smaps",        ""                                                                    },
    { "/proc/self/smaps_rollup", ""                                                                    },
    { "/proc/self/mem",          ""                                                                    },
    { "/proc/sys/kernel/pid_max",          "32768\n"                                                   },
    { "/proc/sys/kernel/overcommit_memory","0\n"                                                       },
    { "/proc/sys/kernel/panic",            "0\n"                                                       },
    { "/proc/sys/kernel/hostname",         "hanonymOS\n"                                               },
    { "/proc/sys/kernel/ostype",           "Linux\n"                                                   },
    { "/proc/sys/kernel/osrelease",        "6.0.0\n"                                                   },
    { "/proc/sys/kernel/ngroups_max",      "65536\n"                                                   },
    { "/proc/sys/kernel/threads-max",      "1024\n"                                                    },
    { "/proc/sys/kernel/kptr_restrict",    "0\n"                                                       },
    { "/proc/sys/kernel/dmesg_restrict",   "0\n"                                                       },
    { "/proc/sys/kernel/perf_event_paranoid", "3\n"                                                   },
    { "/proc/sys/vm/overcommit_memory",    "0\n"                                                       },
    { "/proc/sys/vm/max_map_count",        "65536\n"                                                   },
    { "/proc/sys/fs/inotify/max_user_watches",   "8192\n"                                             },
    { "/proc/sys/fs/inotify/max_queued_events",  "16384\n"                                            },
    { "/proc/sys/fs/inotify/max_user_instances", "128\n"                                              },
    { "/proc/sys/fs/nr_open",              "1048576\n"                                                 },
    { "/proc/sys/fs/pipe-max-size",        "1048576\n"                                                 },
    { "/proc/sys/net/core/somaxconn",      "128\n"                                                     },
    // /sys
    { "/sys/fs/cgroup/cgroup.controllers",       "cpu memory io\n"                                    },
    { "/sys/fs/cgroup/cgroup.subtree_control",   "cpu memory\n"                                       },
    { "/sys/fs/cgroup/cgroup.procs",             "1\n"                                                 },
    { "/sys/power/state",                        "freeze mem disk\n"                                   },
    { "/sys/power/wakeup_count",                 "0\n"                                                 },
    { "/sys/class/tty/tty0/active",              "tty1\n"                                              },
    { "/sys/class/tty/tty1/active",              "tty1\n"                                              },
    // /etc (read by OpenRC + elogind at startup)
    { "/etc/os-release",    "NAME=\"HanonymOS\"\nID=anonymos\nID_LIKE=gentoo\n" ~
                            "PRETTY_NAME=\"HanonymOS 0.1\"\nVERSION=\"0.1\"\n" ~
                            "VERSION_ID=\"0.1\"\nANSI_COLOR=\"1;36\"\n"                               },
    { "/etc/hostname",      "hanonymOS\n"                                                              },
    { "/etc/hosts",         "127.0.0.1 localhost hanonymOS\n::1 localhost\n"                           },
    { "/etc/machine-id",    "deadbeefcafe00001234567890abcdef\n"                                       },
    { "/etc/nsswitch.conf", "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n"          },
    // SSH-in DEBUG default credential: root's password hash inline (password "epinos") so dropbear
    // (--disable-shadow) can authenticate remote logins. This is the fallback served before the user
    // registry populates. See core.user.userRebuildPasswd for the derived-passwd equivalent.
    { "/etc/passwd",        "root:$6$epinos00$hsmBcuD.jeUa5U5JgNPZ5NXUWOGpuIAopa/fwC9uOcFyNXtF4OO/aIkJ1A1qZ6jCMmH5lYQ7G2UWz5TmCy5ES0:0:0:root:/root:/bin/zsh\nuser:x:1000:1000:user:/home/user:/bin/zsh\n" },
    { "/etc/shadow",        "root::::::::\n"                                                           },
    { "/etc/group",         "root:x:0:\n"                                                              },
    { "/etc/shells",        "/bin/zsh\n/bin/sh\n/bin/ash\n/busybox\n"                                  },
    { "/etc/resolv.conf",   "nameserver 8.8.8.8\nnameserver 1.1.1.1\n"                                },
    { "/etc/localtime",     ""                                                                         },
    { "/etc/timezone",      "UTC\n"                                                                    },
    { "/etc/rc.conf",
      "# HanonymOS OpenRC configuration\n" ~
      "rc_sys=\"PREFIX\"\n" ~
      "rc_tty_number=1\n" ~
      "unicode=\"YES\"\n" ~
      "rc_logger=\"YES\"\n" ~
      "rc_parallel=\"NO\"\n" ~
      "rc_nocolor=\"YES\"\n" ~
      "rc_shell=/busybox\n"
    },
    { "/etc/inittab",
      "# HanonymOS inittab\n" ~
      "::sysinit:/sbin/rc sysinit\n" ~
      "::wait:/sbin/rc boot\n" ~
      "::wait:/sbin/rc default\n" ~
      "tty1::respawn:/sbin/getty 9600 tty1\n" ~
      "::ctrlaltdel:/sbin/reboot\n" ~
      "::shutdown:/sbin/rc shutdown\n"
    },
    { "/etc/fstab",
      "# HanonymOS fstab\n" ~
      "none / none ro 0 0\n" ~
      "proc /proc proc defaults 0 0\n" ~
      "none /tmp tmpfs defaults 0 0\n"
    },
    { "/etc/openrc/rc.conf",
      "rc_sys=\"PREFIX\"\n" ~
      "rc_tty_number=1\n"
    },
    { "/etc/elogind/logind.conf",
      "[Login]\n" ~
      "NAutoVTs=1\n" ~
      "ReserveVT=1\n" ~
      "KillUserProcesses=no\n" ~
      "IdleAction=ignore\n" ~
      "HandlePowerKey=poweroff\n" ~
      "HandleRebootKey=reboot\n" ~
      "HandleSuspendKey=ignore\n" ~
      "HandleHibernateKey=ignore\n" ~
      "HandleLidSwitch=ignore\n"
    },
    { "/etc/gdm/custom.conf",
      "[daemon]\n" ~
      "WaylandEnable=true\n" ~
      "DefaultSession=gnome\n" ~
      "AutomaticLoginEnable=false\n" ~
      "\n" ~
      "[security]\n" ~
      "DisallowTCP=true\n"
    },
    { "/etc/hypr/hyprland.conf",
      "# EpinAnonymOS Hyprland bootstrap config\n" ~
      "monitor=,preferred,auto,1\n" ~
      "\n" ~
      "input {\n" ~
      "    kb_layout = us\n" ~
      "}\n" ~
      "\n" ~
      "general {\n" ~
      "    gaps_in = 0\n" ~
      "    gaps_out = 0\n" ~
      "    border_size = 1\n" ~
      "}\n" ~
      "\n" ~
      "misc {\n" ~
      "    disable_hyprland_logo = true\n" ~
      "    disable_splash_rendering = true\n" ~
      "}\n" ~
      "\n" ~
      "# HOS: our kernel DRM present is synchronous and aquamarine is event-paced; the render engine\n" ~
      "# quiesces once the initial damage burst is spent and later client damage (the top bar) doesn't\n" ~
      "# reliably restart it.  Force a free-running full render every frame (0 = no damage tracking) so\n" ~
      "# the self-completing flip loop keeps presenting and composites late clients.\n" ~
      "debug {\n" ~
      "    damage_tracking = 0\n" ~
      "}\n" ~
      "\n" ~
      "# GNOME-style top bar (wlr-layer-shell): Activities | clock | wifi/volume/battery.\n" ~
      "# (Spawned by the kernel autostart alongside the other boot clients — no exec-once\n" ~
      "# here, or the bar starts twice now that exec-once works.)\n" ~
      "\n" ~
      "# SUPER+B toggles the bar.  It (and the Settings config panel) hide/show the bar by\n" ~
      "# creating/removing /run/hos-bar.hidden, which the bar polls once a second.\n" ~
      "bind = SUPER, B, exec, sh -c \"[ -e /run/hos-bar.hidden ] && rm -f /run/hos-bar.hidden || : > /run/hos-bar.hidden\"\n"
    },
    { "/etc/NetworkManager/NetworkManager.conf",
      "[main]\n" ~
      "plugins=keyfile\n" ~
      "dns=default\n" ~
      "\n" ~
      "[ifupdown]\n" ~
      "managed=true\n" ~
      "\n" ~
      "[device]\n" ~
      "wifi.scan-rand-mac-address=no\n"
    },
    { "/etc/NetworkManager/conf.d/20-connectivity.conf",
      "[connectivity]\n" ~
      "enabled=false\n"
    },
    { "/etc/NetworkManager/system-connections/Wired connection 1.nmconnection",
      "[connection]\n" ~
      "id=Wired connection 1\n" ~
      "uuid=6d3f9d49-0ce0-4c38-9d94-8dcf4220b067\n" ~
      "type=ethernet\n" ~
      "interface-name=eth0\n" ~
      "autoconnect=true\n" ~
      "\n" ~
      "[ethernet]\n" ~
      "\n" ~
      "[ipv4]\n" ~
      "method=auto\n" ~
      "dns=8.8.8.8;1.1.1.1;\n" ~
      "\n" ~
      "[ipv6]\n" ~
      "method=ignore\n" ~
      "\n" ~
      "[proxy]\n"
    },
    { "/etc/dconf/profile/user",
      "user-db:user\n" ~
      "system-db:local\n"
    },
    { "/etc/dconf/db/local.d/00-hanonymos-desktop",
      "[org/gnome/desktop/interface]\n" ~
      "gtk-theme='Default'\n" ~
      "icon-theme='hicolor'\n" ~
      "clock-format='24h'\n" ~
      "color-scheme='prefer-light'\n" ~
      "\n" ~
      "[org/gnome/desktop/sound]\n" ~
      "theme-name='freedesktop'\n" ~
      "\n" ~
      "[org/gnome/settings-daemon/plugins/xsettings]\n" ~
      "antialiasing='rgba'\n" ~
      "hinting='slight'\n"
    },
    { "/etc/pipewire/pipewire.conf",
      "context.properties = {\n" ~
      "    core.name = pipewire-0\n" ~
      "    default.clock.rate = 48000\n" ~
      "}\n"
    },
    { "/etc/pipewire/pipewire-pulse.conf",
      "pulse.properties = {\n" ~
      "    server.address = [ \"unix:/run/user/1000/pulse/native\" ]\n" ~
      "}\n"
    },
    { "/etc/pipewire/client.conf",
      "context.properties = {\n" ~
      "    remote.name = pipewire-0\n" ~
      "}\n"
    },
    { "/etc/wireplumber/wireplumber.conf",
      "wireplumber.profiles = {\n" ~
      "    main = true\n" ~
      "}\n"
    },
    { "/etc/dbus-1/session.conf",
      "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n" ~
      " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n" ~
      "<busconfig>\n" ~
      "  <type>session</type>\n" ~
      "  <listen>unix:path=/run/user/1000/bus</listen>\n" ~
      "  <policy context=\"default\">\n" ~
      "    <allow send_destination=\"*\"/>\n" ~
      "    <allow eavesdrop=\"true\"/>\n" ~
      "    <allow own=\"*\"/>\n" ~
      "  </policy>\n" ~
      "</busconfig>\n"
    },
    // D-Bus system config (elogind and NetworkManager register on the system bus)
    { "/etc/dbus-1/system.conf",
      "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n" ~
      " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n" ~
      "<busconfig>\n" ~
      "  <type>system</type>\n" ~
      "  <keep_umask/>\n" ~
      "  <listen>unix:path=/run/dbus/system_bus_socket</listen>\n" ~
      "  <policy context=\"default\">\n" ~
      "    <allow send_destination=\"*\" eavesdrop=\"true\"/>\n" ~
      "    <allow eavesdrop=\"true\"/>\n" ~
      "    <allow own=\"*\"/>\n" ~
      "  </policy>\n" ~
      "</busconfig>\n"
    },
    { "/usr/share/dbus-1/system.conf",
      "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n" ~
      " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n" ~
      "<busconfig>\n" ~
      "  <type>system</type>\n" ~
      "  <listen>unix:path=/run/dbus/system_bus_socket</listen>\n" ~
      "  <policy context=\"default\">\n" ~
      "    <allow send_destination=\"*\"/>\n" ~
      "    <allow own=\"*\"/>\n" ~
      "  </policy>\n" ~
      "</busconfig>\n"
    },
    { "/usr/share/dbus-1/session.conf",
      "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n" ~
      " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n" ~
      "<busconfig>\n" ~
      "  <type>session</type>\n" ~
      "  <listen>unix:path=/run/user/1000/bus</listen>\n" ~
      "  <policy context=\"default\">\n" ~
      "    <allow send_destination=\"*\"/>\n" ~
      "    <allow own=\"*\"/>\n" ~
      "  </policy>\n" ~
      "</busconfig>\n"
    },
    { "/etc/dbus-1/system.d/org.freedesktop.login1.conf",
      "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n" ~
      " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n" ~
      "<busconfig>\n" ~
      "  <policy user=\"root\">\n" ~
      "    <allow own=\"org.freedesktop.login1\"/>\n" ~
      "    <allow send_destination=\"org.freedesktop.login1\"/>\n" ~
      "    <allow receive_sender=\"org.freedesktop.login1\"/>\n" ~
      "  </policy>\n" ~
      "  <policy context=\"default\">\n" ~
      "    <allow send_destination=\"org.freedesktop.login1\"/>\n" ~
      "    <allow receive_sender=\"org.freedesktop.login1\"/>\n" ~
      "  </policy>\n" ~
      "</busconfig>\n"
    },
    { "/etc/dbus-1/system.d/org.gnome.DisplayManager.conf",
      "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n" ~
      " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n" ~
      "<busconfig>\n" ~
      "  <policy user=\"root\">\n" ~
      "    <allow own=\"org.gnome.DisplayManager\"/>\n" ~
      "    <allow send_destination=\"org.gnome.DisplayManager\"/>\n" ~
      "  </policy>\n" ~
      "  <policy context=\"default\">\n" ~
      "    <allow send_destination=\"org.gnome.DisplayManager\"/>\n" ~
      "    <allow receive_sender=\"org.gnome.DisplayManager\"/>\n" ~
      "  </policy>\n" ~
      "</busconfig>\n"
    },
    { "/etc/dbus-1/system.d/org.freedesktop.NetworkManager.conf",
      "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n" ~
      " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n" ~
      "<busconfig>\n" ~
      "  <policy user=\"root\">\n" ~
      "    <allow own=\"org.freedesktop.NetworkManager\"/>\n" ~
      "    <allow send_destination=\"org.freedesktop.NetworkManager\"/>\n" ~
      "    <allow receive_sender=\"org.freedesktop.NetworkManager\"/>\n" ~
      "  </policy>\n" ~
      "  <policy context=\"default\">\n" ~
      "    <allow send_destination=\"org.freedesktop.NetworkManager\"/>\n" ~
      "    <allow receive_sender=\"org.freedesktop.NetworkManager\"/>\n" ~
      "  </policy>\n" ~
      "</busconfig>\n"
    },
    { "/run/openrc/softlevel", "default\n" },
    { "/run/openrc/ksoftlevel", "default\n" },
    { "/run/openrc/options/hostname", "hanonymOS\n" },
    { "/run/dbus/pid", "1\n" },
    { "/run/dbus/session.pid", "2\n" },
    { "/run/NetworkManager/NetworkManager.pid", "3\n" },
    { "/run/NetworkManager/resolv.conf",
      "nameserver 8.8.8.8\n" ~
      "nameserver 1.1.1.1\n"
    },
    { "/run/NetworkManager/no-stub-resolv.conf",
      "nameserver 8.8.8.8\n" ~
      "nameserver 1.1.1.1\n"
    },
    { "/run/NetworkManager/devices/eth0",
      "[device]\n" ~
      "interface=eth0\n" ~
      "ip-interface=eth0\n" ~
      "managed=true\n" ~
      "state=100\n"
    },
    { "/run/user/1000/dconf/user", "" },
    { "/run/user/1000/pipewire-0.lock", "" },
    { "/run/user/1000/pipewire-0.manager", "" },
    { "/run/systemd/seats/seat0",
      "SEAT_ID=seat0\n" ~
      "CAN_GRAPHICAL=yes\n"
    },
    { "/run/systemd/sessions/1",
      "ID=1\n" ~
      "UID=1000\n" ~
      "USER=user\n" ~
      "STATE=online\n" ~
      "SEAT=seat0\n" ~
      "TTY=tty1\n" ~
      "TYPE=wayland\n" ~
      "CLASS=user\n"
    },
    { "/run/systemd/users/1000",
      "UID=1000\n" ~
      "STATE=active\n" ~
      "SESSIONS=1\n"
    },
    { "/var/lib/NetworkManager/NetworkManager.state",
      "[main]\n" ~
      "NetworkingEnabled=true\n" ~
      "WirelessEnabled=true\n" ~
      "WWANEnabled=false\n"
    },
    { "/run/gdm/custom.conf",
      "[daemon]\n" ~
      "WaylandEnable=true\n" ~
      "DefaultSession=gnome\n"
    },

    // ── fontconfig ─────────────────────────────────────────────────────────
    { "/etc/fonts/fonts.conf",
      "<?xml version=\"1.0\"?>\n" ~
      "<!DOCTYPE fontconfig SYSTEM \"fonts.dtd\">\n" ~
      "<fontconfig>\n" ~
      "  <dir>/usr/share/fonts</dir>\n" ~
      "  <dir>/usr/local/share/fonts</dir>\n" ~
      "  <cachedir>/var/cache/fontconfig</cachedir>\n" ~
      "  <alias><family>sans-serif</family><prefer><family>Noto Sans</family><family>DejaVu Sans</family></prefer></alias>\n" ~
      "  <alias><family>monospace</family><prefer><family>Noto Sans Mono</family><family>DejaVu Sans Mono</family></prefer></alias>\n" ~
      "  <alias><family>serif</family><prefer><family>Noto Serif</family><family>DejaVu Serif</family></prefer></alias>\n" ~
      "  <match target=\"font\"><edit name=\"antialias\" mode=\"assign\"><bool>true</bool></edit></match>\n" ~
      "  <match target=\"font\"><edit name=\"hinting\" mode=\"assign\"><bool>true</bool></edit></match>\n" ~
      "  <match target=\"font\"><edit name=\"hintstyle\" mode=\"assign\"><const>hintslight</const></edit></match>\n" ~
      "  <match target=\"font\"><edit name=\"rgba\" mode=\"assign\"><const>none</const></edit></match>\n" ~
      "</fontconfig>\n"
    },

    // ── Weston (GW3) ───────────────────────────────────────────────────────
    // Loaded from XDG_CONFIG_HOME=/etc → /etc/weston.ini. backend/renderer/shell
    // are set explicitly so Weston doesn't auto-detect (the WAYLAND_DISPLAY in the
    // launch env would otherwise mislead it into the nested backend). The shell's
    // helper client + the terminal launcher use absolute boot-module paths; the
    // module .so names are remapped to boot modules via WESTON_MODULE_MAP (exports.d).
    { "/etc/weston.ini",
      "[core]\n" ~
      "backend=drm-backend.so\n" ~
      "renderer=pixman\n" ~   // safe default (no-GPU boots); the kernel passes --renderer=gl when g_gpuVirgl
      "shell=desktop-shell.so\n" ~
      "require-input=false\n" ~
      "idle-time=0\n" ~
      "\n" ~
      "[shell]\n" ~
      "client=/weston-desktop-shell\n" ~
      "background-color=0xff1e1e2e\n" ~
      "panel-position=top\n" ~
      "panel-color=0xff000000\n" ~   // GNOME-Shell opaque black top bar (default 0xaa is translucent)
      "locking=false\n" ~
      "animation=none\n" ~
      "startup-animation=none\n" ~
      "\n" ~
      // GNOME top bar: NO icon launchers on the left (Activities widget only, drawn by the shell client).
      // The desktop-shell client's default-terminal-launcher fallback is removed too so this stays empty.
      "[keyboard]\n" ~
      "keymap_layout=us\n"
    },

    // ── GTK3 ───────────────────────────────────────────────────────────────
    { "/etc/gtk-3.0/settings.ini",
      "[Settings]\n" ~
      "gtk-font-name=Noto Sans 10\n" ~
      "gtk-icon-theme-name=Epin\n" ~
      "gtk-theme-name=Epin\n" ~
      "gtk-cursor-theme-name=Epin\n" ~
      "gtk-xft-antialias=1\n" ~
      "gtk-xft-hinting=1\n" ~
      "gtk-xft-hintstyle=hintslight\n" ~
      "gtk-xft-rgba=none\n" ~
      "gtk-modules=\n"
    },

    // ── Pango ──────────────────────────────────────────────────────────────
    // Empty modules.cache → Pango falls back to built-in engine only.
    { "/usr/lib/pango/1.0/modules.cache", "" },

    // ── GLib schemas / GSettings compatibility surface ─────────────────────
    { "/usr/share/glib-2.0/schemas/org.gnome.desktop.interface.gschema.xml",
      "<schemalist>\n" ~
      "  <schema id=\"org.gnome.desktop.interface\" path=\"/org/gnome/desktop/interface/\">\n" ~
      "    <key name=\"gtk-theme\" type=\"s\"><default>'Epin'</default></key>\n" ~
      "    <key name=\"icon-theme\" type=\"s\"><default>'Epin'</default></key>\n" ~
      "    <key name=\"cursor-theme\" type=\"s\"><default>'Epin'</default></key>\n" ~
      "    <key name=\"font-name\" type=\"s\"><default>'Noto Sans 10'</default></key>\n" ~
      "    <key name=\"monospace-font-name\" type=\"s\"><default>'Noto Sans Mono 11'</default></key>\n" ~
      "    <key name=\"clock-format\" type=\"s\"><default>'24h'</default></key>\n" ~
      "    <key name=\"color-scheme\" type=\"s\"><default>'prefer-light'</default></key>\n" ~
      "  </schema>\n" ~
      "</schemalist>\n"
    },
    { "/usr/share/glib-2.0/schemas/org.gnome.desktop.sound.gschema.xml",
      "<schemalist>\n" ~
      "  <schema id=\"org.gnome.desktop.sound\" path=\"/org/gnome/desktop/sound/\">\n" ~
      "    <key name=\"theme-name\" type=\"s\"><default>'freedesktop'</default></key>\n" ~
      "  </schema>\n" ~
      "</schemalist>\n"
    },
    { "/usr/share/glib-2.0/schemas/org.gnome.settings-daemon.plugins.xsettings.gschema.xml",
      "<schemalist>\n" ~
      "  <schema id=\"org.gnome.settings-daemon.plugins.xsettings\" path=\"/org/gnome/settings-daemon/plugins/xsettings/\">\n" ~
      "    <key name=\"antialiasing\" type=\"s\"><default>'rgba'</default></key>\n" ~
      "    <key name=\"hinting\" type=\"s\"><default>'slight'</default></key>\n" ~
      "  </schema>\n" ~
      "</schemalist>\n"
    },
    { "/usr/share/glib-2.0/schemas/org.gnome.settings-daemon.plugins.media-keys.gschema.xml",
      "<schemalist>\n" ~
      "  <schema id=\"org.gnome.settings-daemon.plugins.media-keys\" path=\"/org/gnome/settings-daemon/plugins/media-keys/\">\n" ~
      "    <key name=\"volume-step\" type=\"i\"><default>6</default></key>\n" ~
      "  </schema>\n" ~
      "</schemalist>\n"
    },
    // Raw schema XML is present for GNOME tooling. The compiled cache remains
    // a compatibility placeholder because the guest does not run the host's
    // schema compiler.
    { "/usr/share/glib-2.0/schemas/gschemas.compiled", "" },

    // ── locale / i18n ──────────────────────────────────────────────────────
    { "/etc/locale.conf",
      "LANG=C\n" ~
      "LC_ALL=C\n"
    },
    { "/usr/share/locale/locale.alias",
      "# locale.alias\n" ~
      "C               C\n" ~
      "POSIX           POSIX\n" ~
      "en_US           en_US.ISO8859-1\n" ~
      "en_US.UTF-8     en_US.UTF-8\n"
    },
    { "/usr/share/wayland-sessions/gnome.desktop",
      "[Desktop Entry]\n" ~
      "Name=GNOME\n" ~
      "Comment=GNOME Shell on HanonymOS\n" ~
      "Exec=/sbin/gnome-shell --wayland --display-server\n" ~
      "Type=Application\n" ~
      "DesktopNames=GNOME\n"
    },
    { "/usr/share/xsessions/gnome.desktop",
      "[Desktop Entry]\n" ~
      "Name=GNOME on X11\n" ~
      "Comment=GNOME via GDM on HanonymOS\n" ~
      "Exec=/sbin/gdm\n" ~
      "Type=Application\n" ~
      "DesktopNames=GNOME\n"
    },
    { "/usr/share/applications/gnome-control-center.desktop",
      "[Desktop Entry]\n" ~
      "Name=Settings\n" ~
      "Comment=Configure GNOME session services on HanonymOS\n" ~
      "Exec=/sbin/gnome-control-center\n" ~
      "Type=Application\n" ~
      "Categories=GNOME;GTK;Settings;\n" ~
      "OnlyShowIn=GNOME;\n"
    },
    { "/usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy",
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ~
      "<policyconfig>\n" ~
      "  <action id=\"org.freedesktop.NetworkManager.enable-disable-network\">\n" ~
      "    <description>Manage networking</description>\n" ~
      "    <message>Authentication is required to manage networking</message>\n" ~
      "    <defaults>\n" ~
      "      <allow_any>yes</allow_any>\n" ~
      "      <allow_inactive>yes</allow_inactive>\n" ~
      "      <allow_active>yes</allow_active>\n" ~
      "    </defaults>\n" ~
      "  </action>\n" ~
      "</policyconfig>\n"
    },
    { "/usr/share/dbus-1/system-services/org.freedesktop.login1.service",
      "[D-BUS Service]\n" ~
      "Name=org.freedesktop.login1\n" ~
      "Exec=/sbin/logind\n" ~
      "User=root\n"
    },
    { "/usr/share/dbus-1/system-services/org.freedesktop.NetworkManager.service",
      "[D-BUS Service]\n" ~
      "Name=org.freedesktop.NetworkManager\n" ~
      "Exec=/sbin/NetworkManager --no-daemon\n" ~
      "User=root\n"
    },
    { "/usr/share/dbus-1/services/org.freedesktop.DBus.service",
      "[D-BUS Service]\n" ~
      "Name=org.freedesktop.DBus\n" ~
      "Exec=/sbin/dbus-daemon --session --address=unix:path=/run/user/1000/bus --nofork\n"
    },
    { "/usr/share/dbus-1/services/ca.desrt.dconf.service",
      "[D-BUS Service]\n" ~
      "Name=ca.desrt.dconf\n" ~
      "Exec=/sbin/dconf-service\n"
    },
    { "/usr/share/dbus-1/services/org.pipewire.Media1.service",
      "[D-BUS Service]\n" ~
      "Name=org.pipewire.Media1\n" ~
      "Exec=/sbin/pipewire -c /etc/pipewire/pipewire.conf\n"
    },
    { "/usr/share/dbus-1/services/org.pipewire.WirePlumber.service",
      "[D-BUS Service]\n" ~
      "Name=org.pipewire.WirePlumber\n" ~
      "Exec=/sbin/wireplumber -c /etc/wireplumber/wireplumber.conf\n"
    },
    { "/usr/share/dbus-1/services/org.gnome.DisplayManager.service",
      "[D-BUS Service]\n" ~
      "Name=org.gnome.DisplayManager\n" ~
      "Exec=/sbin/gdm\n"
    },
    { "/usr/share/dbus-1/services/org.gnome.SettingsDaemon.service",
      "[D-BUS Service]\n" ~
      "Name=org.gnome.SettingsDaemon\n" ~
      "Exec=/sbin/gnome-settings-daemon\n"
    },
    { "/usr/share/dbus-1/services/org.gnome.SettingsDaemon.XSettings.service",
      "[D-BUS Service]\n" ~
      "Name=org.gnome.SettingsDaemon.XSettings\n" ~
      "Exec=/sbin/gnome-settings-daemon\n"
    },
    { "/usr/share/dbus-1/services/org.gnome.ControlCenter.service",
      "[D-BUS Service]\n" ~
      "Name=org.gnome.ControlCenter\n" ~
      "Exec=/sbin/gnome-control-center\n"
    },
    { "/usr/share/dbus-1/system-services/org.gnome.DisplayManager.service",
      "[D-BUS Service]\n" ~
      "Name=org.gnome.DisplayManager\n" ~
      "Exec=/sbin/gdm\n" ~
      "User=root\n"
    },
    { "/usr/share/pipewire/pipewire.conf",
      "context.properties = {\n" ~
      "    core.name = pipewire-0\n" ~
      "}\n"
    },
    { "/usr/share/pipewire/pipewire-pulse.conf",
      "pulse.properties = {\n" ~
      "    server.address = [ \"unix:/run/user/1000/pulse/native\" ]\n" ~
      "}\n"
    },
    { "/usr/share/wireplumber/wireplumber.conf",
      "wireplumber.profiles = {\n" ~
      "    main = true\n" ~
      "}\n"
    },

    // ── MIME database (GIO; empty → falls back to sniffing only) ──────────
    { "/usr/share/mime/mime.cache", "" },

    // ── GLib/GIO proc environ (env-var source for g_getenv fallback) ──────
    { "/proc/self/environ",
      "HOME=/home/user\x00" ~
      "PATH=/usr/bin:/bin:/usr/local/bin:/sbin:/usr/sbin\x00" ~
      "WAYLAND_DISPLAY=wayland-0\x00" ~
      "HOS_DISPLAY_WIDTH=1280\x00" ~
      "HOS_DISPLAY_HEIGHT=800\x00" ~
      "HOS_DISPLAY_SCALE=1\x00" ~
      "HOS_DISPLAY_REFRESH=60\x00" ~
      "HOS_DISPLAY_FORCE_MODE=0\x00" ~
      "XDG_RUNTIME_DIR=/run/user/1000\x00" ~
      "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus\x00" ~
      "DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket\x00" ~
      "XDG_DATA_DIRS=/usr/share\x00" ~
      "XDG_CONFIG_DIRS=/etc\x00" ~
      "XDG_SESSION_TYPE=wayland\x00" ~
      "XDG_CURRENT_DESKTOP=GNOME\x00" ~
      "XDG_SESSION_DESKTOP=gnome\x00" ~
      "DESKTOP_SESSION=gnome\x00" ~
      "GDMSESSION=gnome\x00" ~
      "XDG_SEAT=seat0\x00" ~
      "XDG_VTNR=1\x00" ~
      "DCONF_PROFILE=user\x00" ~
      "GSETTINGS_BACKEND=dconf\x00" ~
      "GSETTINGS_SCHEMA_DIR=/usr/share/glib-2.0/schemas\x00" ~
      "PIPEWIRE_RUNTIME_DIR=/run/user/1000\x00" ~
      "PIPEWIRE_REMOTE=pipewire-0\x00" ~
      "PULSE_SERVER=unix:/run/user/1000/pulse/native\x00" ~
      "LANG=C\x00" ~
      "LC_ALL=C\x00" ~
      "TERM=linux\x00"
    },

    // ── procfs network status for compatibility probes ────────────────────
    { "/proc/net/dev",
      "Inter-|   Receive                                                |  Transmit\n" ~
      " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" ~
      "    lo: 4096      32    0    0    0     0          0         0     4096      32    0    0    0     0       0          0\n" ~
      "  eth0: 65536     512   0    0    0     0          0         0    32768     256   0    0    0     0       0          0\n"
    },
    { "/proc/net/route",
      "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" ~
      "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" ~
      "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
    },

    // ── GdkPixbuf loaders ──────────────────────────────────────────────────
    // Empty loaders.cache → GdkPixbuf skips dynamic loader registration.
    { "/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache", "" },

    // ── DRM / KMS virtual sysfs (libdrm / udev / libinput probing) ────────
    // GW3: libudev-zero builds the card0 udev_device from this uevent —
    // udev_device_new_from_syspath() reads it and DEVNAME yields the devnode
    // /dev/dri/card0 that Weston then opens via libseat. (Weston is launched
    // with --drm-device=card0 → open_specific_drm_device, see exports.d.)
    { "/sys/class/drm/card0/uevent",
      "DRIVER=virtio_gpu\n" ~
      "MAJOR=226\n" ~
      "MINOR=0\n" ~
      "DEVNAME=dri/card0\n" ~
      "DEVTYPE=drm_minor\n"
    },
    { "/sys/class/drm/card0/status",           "connected\n"  },
    { "/sys/class/drm/card0/enabled",          "enabled\n"    },
    { "/sys/class/drm/card0/dpms",             "On\n"         },
    { "/sys/class/drm/card0/modes",            ""             },
    // R3: PCI device info for the virtio-gpu (0000:00:04.0, 1af4:1050) under BOTH
    // its DRM nodes' .../device/ dirs, so libdrm's drmProcessPciDevice() reads a
    // valid drmDevice → drmGetDevice2 succeeds → a real EGL render device → Weston
    // advertises zwp_linux_dmabuf → GPU Wayland clients render on virgl. card0
    // (226:0) is what Weston probes; renderD128 (226:128) is for GL clients.
    { "/sys/dev/char/226:0/device/uevent",
      "DRIVER=virtio_gpu\nPCI_CLASS=30000\nPCI_ID=1AF4:1050\n" ~
      "PCI_SUBSYS_ID=1AF4:1100\nPCI_SLOT_NAME=0000:00:04.0\n" ~
      "MODALIAS=pci:v00001AF4d00001050sv00001AF4sd00001100bc03sc00i00\n" },
    { "/sys/dev/char/226:0/device/vendor",           "0x1af4\n" },
    { "/sys/dev/char/226:0/device/device",           "0x1050\n" },
    { "/sys/dev/char/226:0/device/subsystem_vendor", "0x1af4\n" },
    { "/sys/dev/char/226:0/device/subsystem_device", "0x1100\n" },
    { "/sys/dev/char/226:0/device/revision",         "0x01\n"   },
    // card0's OWN char-node uevent (mirrors renderD128's at 226:128): aquamarine /
    // libudev-zero opens this directly during DRM enumeration; without it the read
    // returns NULL and libudev-zero strlen()s it → NULL-deref crash right after
    // "Found 1 GPUs".  (Weston never hit this — it's handed the device directly.)
    { "/sys/dev/char/226:0/uevent",
      "MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\nDEVTYPE=drm_minor\n" },
    { "/sys/dev/char/226:128/device/uevent",
      "DRIVER=virtio_gpu\nPCI_CLASS=30000\nPCI_ID=1AF4:1050\n" ~
      "PCI_SUBSYS_ID=1AF4:1100\nPCI_SLOT_NAME=0000:00:04.0\n" ~
      "MODALIAS=pci:v00001AF4d00001050sv00001AF4sd00001100bc03sc00i00\n" },
    { "/sys/dev/char/226:128/device/vendor",           "0x1af4\n" },
    { "/sys/dev/char/226:128/device/device",           "0x1050\n" },
    { "/sys/dev/char/226:128/device/subsystem_vendor", "0x1af4\n" },
    { "/sys/dev/char/226:128/device/subsystem_device", "0x1100\n" },
    { "/sys/dev/char/226:128/device/revision",         "0x01\n"   },
    { "/sys/dev/char/226:128/uevent",
      "MAJOR=226\nMINOR=128\nDEVNAME=dri/renderD128\nDEVTYPE=drm_minor\n" },   // aquamarine matches render nodes by devnode(renderD*)+DEVTYPE=drm_minor, not a separate drm_render_minor type
    { "/sys/class/drm/renderD128/uevent",
      "MAJOR=226\nMINOR=128\nDEVNAME=dri/renderD128\nDEVTYPE=drm_minor\n" },   // aquamarine matches render nodes by devnode(renderD*)+DEVTYPE=drm_minor, not a separate drm_render_minor type
    // PCI info under the /sys/class/drm/<node>/device/ path.  libdrm's drmGetDevices2
    // (aquamarine's CDRMRenderer uses it) resolves /sys/dev/char/226:N (our readlink →
    // /sys/class/drm/<node>) then reads <node>/device/{uevent,vendor,...}; without these
    // an empty-dir shim returns blank content → drmGetDevice failed → "no renderer".
    { "/sys/class/drm/card0/device/uevent",
      "DRIVER=virtio_gpu\nPCI_CLASS=30000\nPCI_ID=1AF4:1050\n" ~
      "PCI_SUBSYS_ID=1AF4:1100\nPCI_SLOT_NAME=0000:00:04.0\n" ~
      "MODALIAS=pci:v00001AF4d00001050sv00001AF4sd00001100bc03sc00i00\n" },
    { "/sys/class/drm/card0/device/vendor",           "0x1af4\n" },
    { "/sys/class/drm/card0/device/device",           "0x1050\n" },
    { "/sys/class/drm/card0/device/subsystem_vendor", "0x1af4\n" },
    { "/sys/class/drm/card0/device/subsystem_device", "0x1100\n" },
    { "/sys/class/drm/card0/device/revision",         "0x01\n"   },
    { "/sys/class/drm/renderD128/device/uevent",
      "DRIVER=virtio_gpu\nPCI_CLASS=30000\nPCI_ID=1AF4:1050\n" ~
      "PCI_SUBSYS_ID=1AF4:1100\nPCI_SLOT_NAME=0000:00:04.0\n" ~
      "MODALIAS=pci:v00001AF4d00001050sv00001AF4sd00001100bc03sc00i00\n" },
    { "/sys/class/drm/renderD128/device/vendor",           "0x1af4\n" },
    { "/sys/class/drm/renderD128/device/device",           "0x1050\n" },
    { "/sys/class/drm/renderD128/device/subsystem_vendor", "0x1af4\n" },
    { "/sys/class/drm/renderD128/device/subsystem_device", "0x1100\n" },
    { "/sys/class/drm/renderD128/device/revision",         "0x01\n"   },
    // raw PCI config space — libdrm's drmParsePciDeviceInfo read()s 64B for the PCI IDs
    { "/sys/class/drm/card0/device/config",      VIRTIO_GPU_PCI_CONFIG },
    { "/sys/class/drm/renderD128/device/config", VIRTIO_GPU_PCI_CONFIG },
    { "/sys/dev/char/226:0/device/config",       VIRTIO_GPU_PCI_CONFIG },
    { "/sys/dev/char/226:128/device/config",     VIRTIO_GPU_PCI_CONFIG },
    { "/sys/class/drm/card0-HDMI-A-1/status",  "connected\n"  },
    { "/sys/class/drm/card0-HDMI-A-1/enabled", "enabled\n"    },
    { "/sys/class/net/lo/address",             "00:00:00:00:00:00\n" },
    { "/sys/class/net/lo/operstate",           "unknown\n"    },
    { "/sys/class/net/lo/mtu",                 "65536\n"      },
    { "/sys/class/net/lo/ifindex",             "1\n"          },
    { "/sys/class/net/lo/type",                "772\n"        },
    { "/sys/class/net/eth0/address",           "52:54:00:12:34:56\n" },
    { "/sys/class/net/eth0/operstate",         "up\n"         },
    { "/sys/class/net/eth0/carrier",           "1\n"          },
    { "/sys/class/net/eth0/mtu",               "1500\n"       },
    { "/sys/class/net/eth0/ifindex",           "2\n"          },
    { "/sys/class/net/eth0/type",              "1\n"          },
    // M3: synthesize the AX210 wlan0 device so NM's nm-linux-platform discovers + classifies it as WIFI.
    // The phy80211/ subdir + uevent DEVTYPE=wlan are the wifi signals NM/udev key off.  ★ NM cross-checks
    // /sys/class/net/wlan0/{ifindex,address} against the values it got from rtnetlink (via the shim→LKL);
    // if they DON'T match it treats the sysfs as stale and ignores the phy80211 marker → NMDeviceEthernet.
    // With mac80211_hwsim disabled the real AX210 is the sole wlan0: ifindex 4, MAC c4:ff:99:d1:66:6d
    // (the FW13's card — see the rtnetlink link in /run/klog).  These MUST equal the live LKL values.
    { "/sys/class/net/wlan0/uevent",           "DEVTYPE=wlan\nINTERFACE=wlan0\nIFINDEX=4\n" },
    { "/sys/class/net/wlan0/address",          "c4:ff:99:d1:66:6d\n" },
    { "/sys/class/net/wlan0/addr_len",         "6\n"          },
    { "/sys/class/net/wlan0/type",             "1\n"          },
    { "/sys/class/net/wlan0/ifindex",          "4\n"          },
    { "/sys/class/net/wlan0/flags",            "0x1003\n"     },
    { "/sys/class/net/wlan0/operstate",        "down\n"       },
    { "/sys/class/net/wlan0/carrier",          "0\n"          },
    { "/sys/class/net/wlan0/mtu",              "1500\n"       },
    { "/sys/class/net/wlan0/tx_queue_len",     "1000\n"       },
    { "/sys/class/net/wlan0/phy80211/index",   "0\n"          },
    { "/sys/class/net/wlan0/phy80211/name",    "phy0\n"       },
    { "/sys/class/net/eth0/speed",             "1000\n"       },

    // ── Input event devices (libinput / udev enumeration) ─────────────────
    { "/sys/class/input/event0/device/name",  "Virtual Keyboard\n" },
    { "/sys/class/input/event1/device/name",  "Virtual Mouse\n"    },
    { "/sys/class/input/event0/device/phys",  "isa0060/serio0\n"   },
    { "/sys/class/input/event1/device/phys",  "isa0060/serio1\n"   },
    // libudev-zero builds these from /sys/dev/char/<maj:min>/uevent (it scans
    // /sys/dev/char). DEVNAME gives the /dev node libinput opens; ID_INPUT* are
    // the classification hints udev rules would normally add. The matching
    // `subsystem` symlink (→ .../class/input) is synthesised in readlink.
    // The EV/KEY/REL lines are the capability bitmasks libudev-zero parses (like
    // udev's input_id builtin) to derive ID_INPUT_KEYBOARD/MOUSE — and libinput
    // (evdev_device_get_udev_tags) classifies the device from those tags. Format:
    // space-separated 64-bit hex words, low word rightmost. Keyboard: EV_SYN|EV_KEY
    // (EV=3) + KEY bits 1..127 (incl. KEY_ENTER=28). Mouse: EV_SYN|EV_KEY|EV_REL
    // (EV=7) + REL_X|REL_Y|REL_WHEEL (REL=103) + BTN_MOUSE/BTN_LEFT (bit 0x110 →
    // word 4 bit 16 = 0x10000).
    { "/sys/class/input/event0/uevent",
      "MAJOR=13\nMINOR=64\nDEVNAME=input/event0\n" ~
      "ID_INPUT=1\nID_INPUT_KEYBOARD=1\nID_SEAT=seat0\n" ~
      "EV=3\nKEY=ffffffffffffffff fffffffffffffffe\n" },
    // Absolute pointer (the QEMU usb-tablet model): EV_SYN|EV_KEY|EV_ABS (EV=b)
    // + ABS_X|ABS_Y (ABS=3) + BTN_LEFT (0x110 → word4 bit16 = 0x10000).  Feeding
    // Weston an absolute position makes its pointer track the kernel-drawn cursor
    // exactly (no acceleration drift), so clicks land where the cursor is shown.
    { "/sys/class/input/event1/uevent",
      "MAJOR=13\nMINOR=65\nDEVNAME=input/event1\n" ~
      "ID_INPUT=1\nID_INPUT_MOUSE=1\nID_SEAT=seat0\n" ~
      "EV=b\nKEY=10000 0 0 0 0\nABS=3\n" },

    // ── libseat / seatd (session/seat management) ─────────────────────────
    { "/run/seatd.sock", "" },
];

// Look up a path in the virtual filesystem table.
// Returns the content slice, or null if not found.
private const(char)[] findVirtualFile(const(char)* path) {
    if (path is null) return null;
    if (cstrEq(path, "/proc/cmdline")) {
        return displayCmdlineContent();
    }
    if (cstrEq(path, "/proc/display-info")) {
        return displayInfoContent();
    }
    {
        auto h = pxHostnameVirtualFile(path);
        if (h.length) return h;
    }
    // Phase 10: /etc/passwd and /etc/group are derived from the User registry
    // (falling back to the static entry below only if the registry is empty).
    if (cstrEq(path, "/etc/passwd")) {
        auto g = userPasswdContent();
        if (g.length) return g;
    } else if (cstrEq(path, "/etc/group")) {
        auto g = userGroupContent();
        if (g.length) return g;
    }
    foreach (ref e; g_vfs) {
        if (cstrEq(path, e.path)) return e.content;
    }
    return null;
}

// Check whether a path matches any virtual directory prefix
// (used by isSyntheticDirectoryPath for /proc/*, /sys/*, /etc/* sub-directories).
private bool isVirtualDirectoryPath(const(char)* path) {
    if (path is null) return false;
    // Accept known /proc/ sub-dirs
    if (cstrEqPrefix(path, "/proc/sys/") ||
        cstrEqPrefix(path, "/proc/net/") ||
        cstrEqPrefix(path, "/proc/self/") ||
        cstrEqPrefix(path, "/sys/fs/") ||
        cstrEqPrefix(path, "/sys/class/") ||
        cstrEqPrefix(path, "/sys/devices/") ||
        cstrEqPrefix(path, "/sys/power") ||
        cstrEqPrefix(path, "/run/NetworkManager") ||
        cstrEqPrefix(path, "/run/openrc") ||
        cstrEqPrefix(path, "/run/elogind") ||
        cstrEqPrefix(path, "/run/gdm") ||
        cstrEqPrefix(path, "/run/user/1000/dconf") ||
        cstrEqPrefix(path, "/run/user/1000/pulse") ||
        cstrEqPrefix(path, "/run/dbus") ||
        cstrEqPrefix(path, "/etc/NetworkManager") ||
        cstrEqPrefix(path, "/etc/dbus-1") ||
        cstrEqPrefix(path, "/etc/dconf") ||
        cstrEqPrefix(path, "/etc/init.d") ||
        cstrEqPrefix(path, "/etc/conf.d") ||
        cstrEqPrefix(path, "/etc/runlevels") ||
        cstrEqPrefix(path, "/etc/openrc") ||
        cstrEqPrefix(path, "/etc/elogind") ||
        cstrEqPrefix(path, "/etc/gdm") ||
        cstrEqPrefix(path, "/etc/hypr") ||
        cstrEqPrefix(path, "/etc/pipewire") ||
        cstrEqPrefix(path, "/etc/wireplumber") ||
        cstrEqPrefix(path, "/etc/fonts/") ||
        cstrEqPrefix(path, "/etc/gtk-3.0/") ||
        cstrEqPrefix(path, "/usr/share/dbus-1/") ||
        cstrEqPrefix(path, "/usr/share/pipewire/") ||
        cstrEqPrefix(path, "/usr/share/wireplumber/") ||
        cstrEqPrefix(path, "/usr/share/glib-2.0/") ||
        cstrEqPrefix(path, "/usr/share/fonts/") ||
        cstrEqPrefix(path, "/usr/share/locale/") ||
        cstrEqPrefix(path, "/usr/share/wayland-sessions/") ||
        cstrEqPrefix(path, "/usr/share/xsessions/") ||
        cstrEqPrefix(path, "/usr/share/applications/") ||
        cstrEqPrefix(path, "/usr/share/polkit-1/") ||
        cstrEqPrefix(path, "/usr/share/mime/") ||
        cstrEqPrefix(path, "/usr/share/icons/") ||
        cstrEqPrefix(path, "/usr/share/cursors/") ||
        cstrEqPrefix(path, "/usr/share/backgrounds/") ||
        cstrEqPrefix(path, "/usr/share/themes/") ||
        cstrEqPrefix(path, "/usr/share/hos/") ||
        cstrEqPrefix(path, "/usr/share/X11/") ||
        cstrEqPrefix(path, "/usr/lib/pango/") ||
        cstrEqPrefix(path, "/usr/lib/gdk-pixbuf-2.0/") ||
        cstrEqPrefix(path, "/usr/lib/girepository-1.0/") ||
        cstrEqPrefix(path, "/var/lib/NetworkManager") ||
        cstrEqPrefix(path, "/var/cache/fontconfig/") ||
        cstrEqPrefix(path, "/sys/class/drm/") ||
        cstrEqPrefix(path, "/sys/class/net/") ||
        cstrEqPrefix(path, "/sys/class/input/") ||
        cstrEqPrefix(path, "/dev/dri/") ||
        cstrEqPrefix(path, "/dev/input/"))
        return true;
    return false;
}

// Compare C-string to a D string prefix
private bool cstrEqPrefix(const(char)* s, string prefix) {
    if (s is null) return false;
    for (size_t i = 0; i < prefix.length; ++i) {
        if (s[i] == 0 || s[i] != prefix[i]) return false;
    }
    return true;
}

private void initPlainFileFd(int fd, int flags) {
    g_fdTable[fd].type = FileType.FD_FILE;
    g_fdTable[fd].flags = flags;
    g_fdTable[fd].offset = 0;
    g_fdTable[fd].backend = null;
    g_fdTable[fd].fileSize = 0;
}

private void initSyntheticFileFd(int fd, int flags, size_t kind) {
    g_fdTable[fd].type = FileType.FD_FILE;
    g_fdTable[fd].flags = flags;
    g_fdTable[fd].offset = 0;
    g_fdTable[fd].backend = cast(void*)kind;
    g_fdTable[fd].fileSize = 0;
}

private bool isSyntheticDirectoryPath(const(char)* path) {
    // A4: /proc/<pid> is a (live) process directory.
    {
        const(char)* psub; size_t psubLen;
        if (procParsePid(path, psub, psubLen) > 0 && psub is null) return true;
    }
    // F1: /objects/<kind> is a (live) object-collection directory.
    // F5: /objects/<kind>/<obj> is the object's field directory (meta/caps/rels).
    {
        const(char)* osub; size_t osubLen; int ofield;
        const int okind = objfsParseDeep(path, osub, osubLen, ofield);
        if (okind > 0 && osub is null) return true;                 // /objects/<kind>
        if (okind > 0 && osub !is null && ofield == 0) return true; // /objects/<kind>/<obj>
    }
    // F3: /system/current is the active-generation component directory.
    {
        const(char)* sc; size_t scl;
        const int sk = sysfsParse(path, sc, scl);
        if (sk == 3 || sk == 6) return true;
    }
    // F4: /objects/apps, /objects/apps/<app>, and .../storage are directories.
    {
        int ai;
        const int ak = appsfsParse(path, ai);
        if (ak == 1 || ak == 2 || ak == 7) return true;
    }
    return cstrEq(path, "/") ||
           cstrEq(path, "/bin") ||
           cstrEq(path, "/sbin") ||
           cstrEq(path, "/usr") ||
           cstrEq(path, "/usr/bin") ||
           cstrEq(path, "/usr/sbin") ||
           cstrEq(path, "/usr/local") ||
           cstrEq(path, "/usr/local/bin") ||
           cstrEq(path, "/lib") ||
           cstrEq(path, "/lib64") ||
           cstrEq(path, "/usr/lib") ||
           cstrEq(path, "/usr/lib/NetworkManager") ||          // M3: NM plugin dir ancestors
           cstrEq(path, "/usr/lib/NetworkManager/1.44.2") ||   // M3: NMPLUGINDIR (SYNTHDIR_NMPLUGIN)
           cstrEq(path, "/usr/lib64") ||
           cstrEq(path, "/dev") ||
           cstrEq(path, "/dev/pts") ||
           cstrEq(path, "/proc") ||
           cstrEq(path, "/proc/self") ||
           cstrEq(path, "/proc/self/fd") ||
           cstrEq(path, "/proc/net") ||
           cstrEq(path, "/proc/sys") ||
           cstrEq(path, "/proc/sys/kernel") ||
           cstrEq(path, "/proc/sys/vm") ||
           cstrEq(path, "/proc/sys/fs") ||
           cstrEq(path, "/proc/sys/net") ||
           cstrEq(path, "/proc/sys/net/core") ||
           cstrEq(path, "/proc/sys/fs/inotify") ||
           cstrEq(path, "/run") ||
           cstrEq(path, "/run/user") ||
           cstrEq(path, "/run/user/0") ||
           cstrEq(path, "/run/user/1000") ||
           cstrEq(path, "/run/user/1000/dconf") ||
           cstrEq(path, "/run/user/1000/pulse") ||
           cstrEq(path, "/run/NetworkManager") ||
           cstrEq(path, "/run/NetworkManager/devices") ||
           cstrEq(path, "/run/dbus") ||
           cstrEq(path, "/run/openrc") ||
           cstrEq(path, "/run/elogind") ||
           cstrEq(path, "/run/gdm") ||
           cstrEq(path, "/run/systemd") ||
           cstrEq(path, "/run/systemd/sessions") ||
           cstrEq(path, "/run/systemd/seats") ||
           cstrEq(path, "/run/systemd/users") ||
           cstrEq(path, "/tmp") ||
           cstrEq(path, "/etc") ||
           cstrEq(path, "/etc/NetworkManager") ||
           cstrEq(path, "/etc/NetworkManager/conf.d") ||
           cstrEq(path, "/etc/NetworkManager/system-connections") ||
           cstrEq(path, "/etc/NetworkManager/dispatcher.d") ||
           cstrEq(path, "/etc/dbus-1") ||
           cstrEq(path, "/etc/dbus-1/system.d") ||
           cstrEq(path, "/etc/dbus-1/services") ||
           cstrEq(path, "/etc/dconf") ||
           cstrEq(path, "/etc/dconf/profile") ||
           cstrEq(path, "/etc/dconf/db") ||
           cstrEq(path, "/etc/dconf/db/local.d") ||
           cstrEq(path, "/etc/init.d") ||
           cstrEq(path, "/etc/conf.d") ||
           cstrEq(path, "/etc/runlevels") ||
           cstrEq(path, "/etc/runlevels/sysinit") ||
           cstrEq(path, "/etc/runlevels/boot") ||
           cstrEq(path, "/etc/runlevels/default") ||
           cstrEq(path, "/etc/runlevels/shutdown") ||
           cstrEq(path, "/etc/openrc") ||
           cstrEq(path, "/etc/elogind") ||
           cstrEq(path, "/etc/gdm") ||
           cstrEq(path, "/etc/hypr") ||
           cstrEq(path, "/etc/pipewire") ||
           cstrEq(path, "/etc/pipewire/pipewire.conf.d") ||
           cstrEq(path, "/etc/wireplumber") ||
           cstrEq(path, "/etc/wireplumber/main.lua.d") ||
           cstrEq(path, "/etc/modules.d") ||
           cstrEq(path, "/home") ||
           cstrEq(path, "/home/user") ||
           cstrEq(path, "/root") ||
           cstrEq(path, "/var") ||
           cstrEq(path, "/var/run") ||
           cstrEq(path, "/var/log") ||
           cstrEq(path, "/var/lib") ||
           cstrEq(path, "/var/lib/NetworkManager") ||
           cstrEq(path, "/var/lib/openrc") ||
           cstrEq(path, "/var/lib/elogind") ||
           cstrEq(path, "/var/lib/gdm") ||
           cstrEq(path, "/var/cache") ||
           cstrEq(path, "/sys") ||
           cstrEq(path, "/sys/fs") ||
           cstrEq(path, "/sys/fs/cgroup") ||
           cstrEq(path, "/sys/class") ||
           cstrEq(path, "/sys/class/net") ||
           cstrEq(path, "/sys/class/net/lo") ||
           cstrEq(path, "/sys/class/net/eth0") ||
           cstrEq(path, "/sys/class/net/wlan0") ||           // M3: the (hwsim/AX210) wifi device dir
           cstrEq(path, "/sys/class/net/wlan0/phy80211") ||  // M3: the wifi marker subdir
           cstrEq(path, "/sys/class/net/wlan1") ||
           cstrEq(path, "/usr/lib/NetworkManager/1.44.2") ||   // M3: NMPLUGINDIR (wifi plugin dir)
           cstrEq(path, "/sys/class/tty") ||
           cstrEq(path, "/sys/devices") ||
           cstrEq(path, "/sys/devices/virtual") ||
           cstrEq(path, "/sys/devices/virtual/tty") ||
           cstrEq(path, "/sys/power") ||
           cstrEq(path, "/mnt") ||
           // fontconfig
           cstrEq(path, "/etc/fonts") ||
           cstrEq(path, "/etc/fonts/conf.d") ||
           cstrEq(path, "/var/cache/fontconfig") ||
           // GTK
           cstrEq(path, "/etc/gtk-3.0") ||
           // GLib / GIO / GdkPixbuf
           cstrEq(path, "/usr/share/glib-2.0") ||
           cstrEq(path, "/usr/share/glib-2.0/schemas") ||
           cstrEq(path, "/usr/lib/gdk-pixbuf-2.0") ||
           cstrEq(path, "/usr/lib/gdk-pixbuf-2.0/2.10.0") ||
           // Pango
           cstrEq(path, "/usr/lib/pango") ||
           cstrEq(path, "/usr/lib/pango/1.0") ||
           // fonts / icons / themes
           cstrEq(path, "/usr/share/fonts") ||
           cstrEq(path, "/usr/local/share/fonts") ||
           cstrEq(path, "/usr/share/icons") ||
           cstrEq(path, "/usr/share/icons/hicolor") ||
           cstrEq(path, "/usr/share/icons/default") ||
           cstrEq(path, "/usr/share/cursors") ||
           cstrEq(path, "/usr/share/backgrounds") ||
           cstrEq(path, "/usr/share/themes") ||
           cstrEq(path, "/usr/share/hos") ||
           cstrEq(path, "/usr/share/hos/assets") ||
           // MIME
           cstrEq(path, "/usr/share/mime") ||
           // locale
           cstrEq(path, "/usr/share/locale") ||
           cstrEq(path, "/usr/share/wayland-sessions") ||
           cstrEq(path, "/usr/share/xsessions") ||
           cstrEq(path, "/usr/share/applications") ||
           cstrEq(path, "/usr/share/polkit-1") ||
           cstrEq(path, "/usr/share/polkit-1/actions") ||
           cstrEq(path, "/usr/share/dbus-1") ||
           cstrEq(path, "/usr/share/dbus-1/services") ||
           cstrEq(path, "/usr/share/dbus-1/system-services") ||
           cstrEq(path, "/usr/share/pipewire") ||
           cstrEq(path, "/usr/share/wireplumber") ||
           // xkb (xkbcommon needs this tree even with Wayland keymap events)
           cstrEq(path, "/usr/share/X11") ||
           cstrEq(path, "/usr/share/X11/xkb") ||
           cstrEq(path, "/usr/share/X11/xkb/rules") ||
           cstrEq(path, "/usr/share/X11/xkb/keycodes") ||
           cstrEq(path, "/usr/share/X11/xkb/symbols") ||
           cstrEq(path, "/usr/share/X11/xkb/types") ||
           cstrEq(path, "/usr/share/X11/xkb/compat") ||
           // GLib typelib / introspection
           cstrEq(path, "/usr/lib/girepository-1.0") ||
           cstrEq(path, "/usr/share") ||
           // DRM / KMS
           cstrEq(path, "/dev/dri") ||
           cstrEq(path, "/dev/input") ||
           cstrEq(path, "/sys/class/drm") ||
           cstrEq(path, "/sys/class/drm/card0") ||   // GW3: Weston/libudev-zero DRM discovery
           cstrEq(path, "/sys/class/input") ||
           // libdrm drmNodeIsDRM() stat()s this tree to confirm fd 226:0 is a
           // DRM node (needed by Aquamarine's dumb-buffer allocator path).
           cstrEq(path, "/sys/dev") ||
           cstrEq(path, "/sys/dev/char") ||
           // libudev-zero's udev_enumerate_scan_devices scans /sys/dev/block
           // BEFORE /sys/dev/char and aborts the whole scan if the first dir is
           // missing — so /sys/dev/block must exist (empty) or no input/DRM
           // devices are ever enumerated.
           cstrEq(path, "/sys/dev/block") ||
           cstrEq(path, "/sys/dev/char/226:0") ||
           // The real device dirs the /sys/dev/char/<maj:min> symlinks resolve to;
           // realpath must land here so udev's sysname is "eventN" (libinput skips
           // any input device whose sysname doesn't start with "event").
           cstrEq(path, "/sys/class/input/event0") ||  // keyboard
           cstrEq(path, "/sys/class/input/event1") ||  // mouse
           cstrEq(path, "/sys/dev/char/226:0/device") ||
           cstrEq(path, "/sys/dev/char/226:0/device/drm") ||
           // R3: a PCI-flavoured sysfs subtree for the virtio-gpu so libdrm's
           // drmGetDevice2() succeeds → Mesa reports a real EGL render device →
           // Weston enables zwp_linux_dmabuf → GPU clients (gl-wl-test, a GLES2
           // terminal) get the virgl device instead of falling back to softpipe.
           // drmProcessPciDevice scans .../device/drm/ for card%d + renderD%d to set
           // available_nodes (both nodes belong to the one PCI function 0000:00:04.0).
           cstrEq(path, "/sys/dev/char/226:0/device/drm/card0") ||
           cstrEq(path, "/sys/dev/char/226:0/device/drm/renderD128") ||
           cstrEq(path, "/sys/dev/char/226:128") ||
           cstrEq(path, "/sys/dev/char/226:128/device") ||
           cstrEq(path, "/sys/dev/char/226:128/device/drm") ||
           cstrEq(path, "/sys/dev/char/226:128/device/drm/card0") ||
           cstrEq(path, "/sys/dev/char/226:128/device/drm/renderD128") ||
           cstrEq(path, "/sys/class/drm/renderD128") ||
           cstrEq(path, "/sys/bus/pci") ||
           // libseat / seatd
           cstrEq(path, "/run/seatd") ||
           isVirtualDirectoryPath(path);
}

private bool isSyntheticSocketPath(const(char)* path) {
    if (cstrEq(path, "/run/user/1000/wayland-0"))
        return unixSocketListenerReady(path);

    return cstrEq(path, "/run/user/1000/pipewire-0") ||
           cstrEq(path, "/run/user/1000/pulse/native") ||
           cstrEq(path, "/run/user/1000/bus") ||
           cstrEq(path, "/run/dbus/system_bus_socket");
}

private bool getSyntheticReadlinkTarget(const(char)* path, out string target) {
    if (cstrEq(path, "/proc/self/exe")) {
        // Until the kernel tracks each task's executable path, return a stable
        // boot image target instead of failing every procfs probe.
        target = "/init.elf";
        return true;
    }
    // /sys/dev/char/<maj:min> are symlinks to the real device dir (so the udev
    // sysname becomes "eventN"); the .../subsystem symlinks give SUBSYSTEM=input.
    if (cstrEq(path, "/sys/dev/char/13:64")) { target = "/sys/class/input/event0"; return true; }
    if (cstrEq(path, "/sys/dev/char/13:65")) { target = "/sys/class/input/event1"; return true; }
    if (cstrEq(path, "/sys/class/input/event0/subsystem") ||
        cstrEq(path, "/sys/class/input/event1/subsystem")) {
        target = "/sys/class/input";
        return true;
    }
    // Aquamarine (Hyprland's backend) ENUMERATES DRM via libudev-zero: it readdir's
    // /sys/dev/char, readlinks each <maj:min> to its canonical class device to derive
    // the sysname (card0/renderD128), then reads that dir's uevent + follows its
    // subsystem symlink.  Weston never needed these (it's handed --drm-device=card0
    // directly), so only the input nodes were wired — leaving aquamarine's scanGPUs
    // EMPTY ("No gpus in scanGPUs" → software-readback fallback → the Mesa swrast
    // heap overflow that crashes Hyprland).  Mirror the input pattern so card0 is
    // discoverable → the real DRM/KMS backend (which the kernel already drives for
    // Weston) starts → no readback path at all.
    if (cstrEq(path, "/sys/dev/char/226:0"))   { target = "/sys/class/drm/card0";      return true; }
    if (cstrEq(path, "/sys/dev/char/226:128")) { target = "/sys/class/drm/renderD128"; return true; }
    if (cstrEq(path, "/sys/class/drm/card0/subsystem") ||
        cstrEq(path, "/sys/class/drm/renderD128/subsystem")) {
        target = "/sys/class/drm";
        return true;
    }
    // R3: the virtio-gpu DRM nodes' .../device/subsystem must resolve to a path
    // whose basename is "pci" — libdrm's get_subsystem_type() reads it and takes
    // the (simpler) drmProcessPciDevice path. Without it drmGetDevice2() fails and
    // Mesa can't expose an EGL render device (→ no dmabuf, GPU clients go softpipe).
    if (cstrEq(path, "/sys/dev/char/226:0/device/subsystem") ||
        cstrEq(path, "/sys/dev/char/226:128/device/subsystem") ||
        cstrEq(path, "/sys/class/drm/card0/device/subsystem") ||
        cstrEq(path, "/sys/class/drm/renderD128/device/subsystem")) {
        target = "/sys/bus/pci";
        return true;
    }

    target = null;
    return false;
}

private long statSyntheticPath(const(char)* path, ulong statBuf) {
    string target;

    if (isSyntheticDirectoryPath(path)) {
        writeLinuxStat(statBuf, 0x4000 | 0x01ED, 0); // S_IFDIR | 0755
        return 0;
    }

    if (isSyntheticSocketPath(path)) {
        writeLinuxStat(statBuf, 0xC000 | 0x01B6, 0); // S_IFSOCK | 0666
        return 0;
    }

    if (getSyntheticReadlinkTarget(path, target)) {
        writeLinuxStat(statBuf, 0xA000 | 0x01FF, cast(ulong)target.length); // S_IFLNK | 0777
        return 0;
    }

    return cast(long)negErrno(ENOENT);
}

// Minimal evdev (EVIOC*) emulation for the two synthetic input devices so that
// libinput recognises event0 as a keyboard and event1 as a relative pointer (and
// therefore draws/uses a cursor). devIdx: 0 = keyboard, 1 = mouse. The ioctl cmd
// encodes _IOC(dir, type='E'(0x45), nr, size); we dispatch on nr = cmd & 0xFF and
// honour the caller's buffer length size = (cmd >> 16) & 0x3FFF.
private long handleInputEvioc(int devIdx, ulong cmd, ulong arg) {
    const uint nr   = cast(uint)(cmd & 0xFF);
    const size_t sz = cast(size_t)((cmd >> 16) & 0x3FFF);
    const bool isMouse = (devIdx == 1);

    // Zero `n` bytes of the user buffer (SMAP-guarded).
    void zeroOut(size_t n) {
        if (arg == 0) return;
        smapBegin();
        auto b = cast(ubyte*)arg;
        foreach (i; 0 .. n) b[i] = 0;
        smapEnd();
    }
    // Set bit `bit` in the user bitmask buffer (already zeroed), if in range.
    void setBit(uint bit) {
        const size_t byteIdx = bit >> 3;
        if (arg == 0 || byteIdx >= sz) return;
        smapBegin();
        auto b = cast(ubyte*)arg;
        b[byteIdx] |= cast(ubyte)(1u << (bit & 7));
        smapEnd();
    }
    long writeStr(const(char)* s) {
        if (arg == 0 || sz == 0) return 0;
        smapBegin();
        auto b = cast(char*)arg;
        size_t i = 0;
        while (i + 1 < sz && s[i] != 0) { b[i] = s[i]; ++i; }
        b[i] = 0;
        smapEnd();
        return cast(long)(i + 1);
    }

    // EVIOCGVERSION (nr 0x01): driver version = EV_VERSION (0x010001).
    if (nr == 0x01) { if (arg) userWrite!int(arg, 0x010001); return 0; }

    // EVIOCGID (nr 0x02): struct input_id { u16 bustype, vendor, product, version }.
    if (nr == 0x02) {
        if (arg) {
            userWrite!ushort(arg + 0, 0x0011);                 // BUS_I8042
            userWrite!ushort(arg + 2, 0x0001);                 // vendor
            userWrite!ushort(arg + 4, isMouse ? 0x0002 : 0x0001); // product
            userWrite!ushort(arg + 6, 0x0001);                 // version
        }
        return 0;
    }

    // EVIOCGNAME (nr 0x06) / EVIOCGPHYS (0x07) / EVIOCGUNIQ (0x08).
    if (nr == 0x06) return writeStr(isMouse ? "Virtual Mouse\0".ptr : "Virtual Keyboard\0".ptr);
    if (nr == 0x07) return writeStr(isMouse ? "isa0060/serio1/input0\0".ptr : "isa0060/serio0/input0\0".ptr);
    if (nr == 0x08) { zeroOut(sz); return 0; }

    // EVIOCGPROP (nr 0x09): mark the absolute mouse INPUT_PROP_POINTER (bit 0) so
    // libinput treats it as an indirect pointer (cursor follows) rather than a
    // direct-touch device; keyboard reports none.
    if (nr == 0x09) { zeroOut(sz); if (isMouse) setBit(0 /*INPUT_PROP_POINTER*/); return 0; }

    // EVIOCGKEY (0x18) / EVIOCGLED (0x19) / EVIOCGSW (0x1b): current state = all 0.
    if (nr == 0x18 || nr == 0x19 || nr == 0x1b) { zeroOut(sz); return 0; }

    // EVIOCGBIT(ev) (nr 0x20 + ev): supported-codes bitmask for event type `ev`.
    if (nr >= 0x20 && nr <= 0x3f) {
        zeroOut(sz);
        const uint ev = nr - 0x20;
        if (ev == 0) {
            // Supported event types.  The mouse is ABSOLUTE (EV_ABS), not EV_REL,
            // so Weston's pointer follows the kernel-fed position exactly.
            setBit(EV_SYN); setBit(EV_KEY);
            if (isMouse) setBit(EV_ABS);
            else { setBit(0x11 /*EV_LED*/); setBit(0x14 /*EV_REP*/); setBit(0x04 /*EV_MSC*/); }
        } else if (ev == EV_KEY) {
            if (isMouse) { setBit(BTN_LEFT); setBit(BTN_RIGHT); setBit(BTN_MIDDLE); }
            else { foreach (k; 1 .. 128) setBit(k); }   // KEY_ESC..KEY_COMPOSE → keyboard
        } else if (ev == EV_ABS && isMouse) {
            setBit(ABS_X); setBit(ABS_Y);
        }
        // EV_REL / EV_MSC / EV_LED / EV_REP / EV_SW → left all-zero.
        return 0;
    }

    // EVIOCGABS(abs) (nr 0x40 + abs): report the X/Y axis ranges (0 .. fb dim-1)
    // so libinput maps absolute coordinates straight to screen pixels.
    if (nr >= 0x40 && nr <= 0x7f) {
        zeroOut(sz);
        if (isMouse && arg != 0 && sz >= 24) {
            const uint abs = nr - 0x40;
            int maxv;
            if (abs == ABS_X)      maxv = (g_fb !is null) ? cast(int)g_fb.width  - 1 : 1279;
            else if (abs == ABS_Y) maxv = (g_fb !is null) ? cast(int)g_fb.height - 1 : 799;
            else return 0;
            // struct input_absinfo { s32 value, minimum, maximum, fuzz, flat, resolution }
            userWrite!int(arg + 0,  0);
            userWrite!int(arg + 4,  0);
            userWrite!int(arg + 8,  maxv);
            userWrite!int(arg + 12, 0);
            userWrite!int(arg + 16, 0);
            userWrite!int(arg + 20, 0);
        }
        return 0;
    }

    // EVIOCGRAB (0x90) / EVIOCREVOKE (0x91) / EVIOCSCLOCKID (0xa0) / EVIOCSREP /
    // EVIOCGMTSLOTS / masks / repeat: accept as no-ops.
    return 0;
}

private long fileObjIoctl(ObjHeader* oh, ulong cmd, ulong arg) {
    File* f = fileFromObj(oh);
    if (f is null) return negErrno(EBADF);
    ++g_objOpsDispatch;

    if (f.type == FileType.FD_PTY_MASTER || f.type == FileType.FD_PTY_SLAVE) {
        return ptyIoctl(cast(int)cast(size_t)f.backend, cmd, arg);
    }

    if (f.type == FileType.FD_DRM) {
        // NB: no per-ioctl logging — PAGE_FLIP/HOS_PRESENT fire every frame and a
        // serial write per call throttles the compositor under KVM (one VM-exit
        // per byte). See the note in handleDrmIoctl.
        return handleDrmIoctl(fdIndexForFile(f), cmd, arg);
    }

    // A DRM ioctl (magic byte 'd' = 0x64) on a NON-DRM fd MUST return an error, not a
    // success stub: libdrm's drmGetVersion() treats ioctl()==0 as "device answered", then
    // strdup()s version->name — but a stub leaves name_len=0 so name stays NULL → strdup(NULL)
    // → strlen(NULL) → NULL fault.  This crashed Hyprland's IHyprRenderer ctor, which probes
    // drmGetVersion() on every session-device fd.  ENOTTY makes drmGetVersion() return NULL and
    // the caller skip the device (correct: it isn't a DRM node).
    if (((cmd >> 8) & 0xFF) == 0x64)
        return negErrno(25); // ENOTTY — not a DRM device

    // Input event ioctls (EVIOCGVERSION, EVIOCGNAME, EVIOCGBIT, ...). libinput
    // classifies a device from its evdev capabilities, so these MUST report real
    // bits — event0 as a keyboard (EV_KEY with keyboard keys) and event1 as a
    // pointer (EV_REL X/Y + mouse buttons). Returning 0 for everything made
    // libinput see capability-less devices and ignore them ("no input devices").
    if (f.type == FileType.FD_INPUT_EVENT) {
        return handleInputEvioc(cast(int)cast(size_t)f.backend, cmd, arg);
    }

    // /dev/fb0 — report the framebuffer geometry so the Screenshot app knows how many
    // pixels to read.  Fill the leading fields of struct fb_var_screeninfo (160 bytes).
    if (f.type == FileType.FD_FB) {
        if (cmd == 0x4600 /*FBIOGET_VSCREENINFO*/) {
            import display.framebuffer : g_fb;
            if (arg == 0) return cast(long)negErrno(14); // EFAULT
            auto v = cast(uint*)arg;
            foreach (i; 0 .. 40) v[i] = 0;   // zero the struct
            v[0] = g_fb.width;               // xres
            v[1] = g_fb.height;              // yres
            v[2] = g_fb.width;               // xres_virtual
            v[3] = g_fb.height;              // yres_virtual
            v[6] = 32;                       // bits_per_pixel (byte offset 24)
            return 0;
        }
        return cast(long)negErrno(25); // ENOTTY for other fb ioctls
    }

    if (f.type != FileType.FD_CONSOLE) {
        return cast(long)negErrno(25); // ENOTTY
    }

    // Terminal attribute ioctls — all treated as a standard interactive tty.
    // TCGETS / TCGETA / TCGETS2
    if (cmd == 0x5401 || cmd == 0x5405 || cmd == 0x542a) {
        if (arg == 0) return cast(long)negErrno(14); // EFAULT
        // Fill a struct termios with sane interactive-terminal defaults.
        // Layout (x86-64 Linux ABI): c_iflag, c_oflag, c_cflag, c_lflag
        // followed by c_line (1 byte) and c_cc[19].
        auto t = cast(uint*)arg;
        t[0] = 0x0500;        // c_iflag: ICRNL|IXON
        t[1] = 0x0005;        // c_oflag: OPOST|ONLCR
        t[2] = 0x04bf;        // c_cflag: B38400|CS8|CREAD|HUPCL
        t[3] = 0x8a3b;        // c_lflag: ICANON|ECHO|ECHOE|ECHOK|ISIG|IEXTEN
        // c_line and c_cc start at byte offset 16
        auto cc = cast(ubyte*)(cast(ubyte*)arg + 16);
        cc[ 0] = 3;   // VINTR  = Ctrl-C
        cc[ 1] = 28;  // VQUIT  = Ctrl-\
        cc[ 2] = 127; // VERASE = DEL
        cc[ 3] = 21;  // VKILL  = Ctrl-U
        cc[ 4] = 4;   // VEOF   = Ctrl-D
        cc[ 5] = 0;   // VTIME
        cc[ 6] = 1;   // VMIN   = wait for at least 1 character
        cc[ 7] = 0;   cc[8] = 17;  cc[9] = 19;  // VSWTC VSTART VSTOP
        cc[10] = 26;  // VSUSP  = Ctrl-Z
        cc[11] = 255; // VEOL
        cc[12] = 18;  // VREPRINT = Ctrl-R
        cc[13] = 0;   // VDISCARD
        cc[14] = 23;  // VWERASE = Ctrl-W
        cc[15] = 22;  // VLNEXT = Ctrl-V
        cc[16] = 255; // VEOL2
        return 0;
    }

    // TCSETS / TCSETSW / TCSETSF / TCSETS2 — accept any termios, store nothing
    if (cmd == 0x5402 || cmd == 0x5403 || cmd == 0x5404 || cmd == 0x542b) {
        return 0;
    }

    // TIOCGPGRP — return foreground process group (pgrp = 1)
    if (cmd == 0x540f) {
        if (arg != 0) *cast(int*)arg = 1;
        return 0;
    }

    // TIOCSPGRP — set foreground process group (accept silently)
    if (cmd == 0x5410) {
        return 0;
    }

    // TIOCSCTTY — set controlling terminal
    if (cmd == 0x540e) {
        return 0;
    }

    // TIOCNOTTY — detach from controlling terminal
    if (cmd == 0x5422) {
        return 0;
    }

    // TIOCGWINSZ — return a plausible terminal size (80×24)
    if (cmd == 0x5413) {
        if (arg != 0) {
            auto ws = cast(ushort*)arg;
            ws[0] = 24;   // rows
            ws[1] = 80;   // cols
            ws[2] = 640;  // xpixel
            ws[3] = 384;  // ypixel
        }
        return 0;
    }

    // TIOCSWINSZ — accept window-size change
    if (cmd == 0x5414) {
        return 0;
    }

    // TIOCGPTN / TIOCSPTLCK / TIOCGPKT — pseudo-terminal stubs
    if (cmd == 0x80045430 || cmd == 0x40045431 || cmd == 0x80045438) {
        return cast(long)negErrno(25); // ENOTTY (no PTY support)
    }

    return cast(long)negErrno(25); // ENOTTY for everything else
}

// ── TEMP boot-hang trace (remove once the weston/libseat stall is diagnosed) ──
// Weston reads the input devices sysfs uevent files and then goes quiet without
// ever opening a device node, so the syscall it is parked in is invisible.  These
// entry traces name it: the LAST [trace] line before the log falls silent is the
// call that never returned.  poll and ppoll are capped so a polling loop cannot
// flood the serial line and bury the interesting tail.
__gshared uint g_hangTracePollCount = 0;
__gshared uint g_hangTraceFutexCount = 0;   // separate budget: the poll flood must not starve it
enum uint HANG_TRACE_POLL_MAX = 300;

// Which process is calling — without this the poll traces are unattributable and the
// two re-arming pollers (seatd child, sshd launcher) look identical to weston.
private void hangTraceWho() {
    const int tid = cast(int)g_current_task_id;
    klog(" who="); klog_dec(g_current_task_id); klog(":");
    const(char)* p = (tid >= 0 && tid < MAX_TASKS) ? g_taskExecName[tid] : null;
    klog(p !is null ? p : "?".ptr);
}

// Per-task poll trace state.  A parked poll is re-armed by the kernel on EVERY scheduler
// pass, so one idle process emits thousands of identical lines and buries the tail.
__gshared uint[MAX_TASKS]  g_hangTracePollSeen;      // lines spent by this task
__gshared ulong[MAX_TASKS] g_hangTracePollLastNfds;  // last shape seen from this task…
__gshared ulong[MAX_TASKS] g_hangTracePollLastTmo;   // …so a re-arm of it can be collapsed
enum uint HANG_TRACE_POLL_PER_TID = 32;

// Collapse by (task, shape) rather than by shape alone.  The previous version skipped
// nfds=2/infinite and nfds=1/1000ms outright to keep two idle pollers from eating the
// budget — but that filter is blind to WHO is polling, so it would equally have hidden
// weston had weston blocked in either shape, silently discarding the one line the trace
// exists to capture.  Here the first poll of a given shape from a given task always
// prints; only a re-arm of that same shape by that same task is dropped.  A per-task cap
// keeps any one process from starving the others, with the global budget as a backstop.
private void hangTracePoll(const(char)* name, ulong nfds, ulong timeout) {
    const int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return;

    if (g_hangTracePollSeen[tid] != 0 &&
        g_hangTracePollLastNfds[tid] == nfds &&
        g_hangTracePollLastTmo[tid]  == timeout) return;   // parked on a shape already logged

    g_hangTracePollLastNfds[tid] = nfds;
    g_hangTracePollLastTmo[tid]  = timeout;

    if (g_hangTracePollSeen[tid] >= HANG_TRACE_POLL_PER_TID) return;
    if (g_hangTracePollCount >= HANG_TRACE_POLL_MAX) return;
    ++g_hangTracePollSeen[tid];
    ++g_hangTracePollCount;
    hangTrace2(name, nfds, timeout);
}

private void hangTrace2(const(char)* name, ulong a, ulong b) {
    klog("[trace] "); klog(name);
    klog(" a="); klog_hex(a);
    klog(" b="); klog_hex(b);
    hangTraceWho();
    klog("\n");
}

public long linux_sys_ioctl(ulong fd, ulong cmd, ulong arg) {
    hangTrace2("ioctl fd,cmd", fd, cmd);
    ObjHeader* oh = fdObjectByIndexWithRights(cast(int)fd, CAP_RIGHT_IOCTL);
    if (oh is null) return negErrno(EBADF);
    auto iop = g_objOps[oh.type].ioctl;
    if (iop is null) return negErrno(EBADF);
    return iop(oh, cmd, arg);
}

public long linuxSyscallCapPrecheck(ulong n, ulong a, ulong b, ulong c,
                                    ulong d, ulong e, ulong f) {
    switch (n) {
        case 0:   if (!fdRequireCap(a, CAP_RIGHT_READ))  return negErrno(EBADF); break; // read
        case 1:   if (!fdRequireCap(a, CAP_RIGHT_WRITE)) return negErrno(EBADF); break; // write
        case 3:   if (!fdRequireCap(a, CAP_RIGHT_CLOSE)) return negErrno(EBADF); break; // close
        case 5:   if (!fdRequireCap(a, CAP_RIGHT_STAT))  return negErrno(EBADF); break; // fstat
        case 8:   if (!fdRequireCap(a, CAP_RIGHT_STAT))  return negErrno(EBADF); break; // lseek
        case 16:  if (!fdRequireCap(a, CAP_RIGHT_IOCTL)) return negErrno(EBADF); break; // ioctl
        case 17:
        case 19:
        case 45:
        case 47:
        case 78:
        case 217:
        case 295:
            if (!fdRequireCap(a, CAP_RIGHT_READ)) return negErrno(EBADF);
            break;
        case 18:
        case 20:
        case 42:
        case 44:
        case 46:
        case 49:
        case 50:
        case 77:
        case 286:
        case 296:
            if (!fdRequireCap(a, CAP_RIGHT_WRITE)) return negErrno(EBADF);
            break;
        case 32:
        case 33:
        case 292:
            if (!fdRequireCap(a, CAP_RIGHT_DUP)) return negErrno(EBADF);
            break;
        case 43:
        case 288:
            if (!fdRequireCap(a, CAP_RIGHT_READ | CAP_RIGHT_WRITE)) return negErrno(EBADF);
            break;
        case 54:
            if (!fdRequireCap(a, CAP_RIGHT_IOCTL)) return negErrno(EBADF);
            break;
        case 55:
        case 72:
        case 81:
        case 232:
        case 287:
            if (!fdRequireCap(a, CAP_RIGHT_STAT)) return negErrno(EBADF);
            break;
        case 233:
            if (!fdRequireCap(a, CAP_RIGHT_WRITE)) return negErrno(EBADF);
            if ((b == 1 || b == 3) && !fdRequireCap(c, CAP_RIGHT_STAT))
                return negErrno(EBADF);
            break;
        default:
            break;
    }
    return 0;
}

public long linux_sys_access(ulong _path, ulong _mode) {
    if (_path == 0) {
        return cast(long)negErrno(EFAULT);
    }

    auto path = cast(const(char)*)_path;
    if (path[0] == 0) {
        return cast(long)negErrno(ENOENT);
    }

    if (isSyntheticDirectoryPath(path) || isSyntheticSocketPath(path)) {
        return 0;
    }

    string target;
    if (getSyntheticReadlinkTarget(path, target)) {
        return 0;
    }

    const long fd = sys_open(path, O_RDONLY);
    if (fd < 0) {
        return publishActiveFdReturn(fd);
    }

    sys_close(cast(int)fd);
    return 0;
}

public long linux_sys_readlink(ulong _path, ulong _buf, ulong _bufsiz) {
    if (_path == 0 || _buf == 0) {
        return cast(long)negErrno(EFAULT);
    }
    if (_bufsiz == 0) {
        return cast(long)negErrno(EINVAL);
    }

    auto path = cast(const(char)*)_path;
    auto outBuf = cast(char*)_buf;

    // RT overlay symlink (Track A A2): return the stored target, never following it.
    {
        int rp; const(char)* rl; size_t rll;
        const int ri = rtResolve(path, rp, rl, rll);
        if (ri >= 0 && g_rt[ri].kind == RT_LNK) {
            size_t n = cast(size_t)_bufsiz;
            if (n > g_rt[ri].size) n = g_rt[ri].size;
            foreach (i; 0 .. n) outBuf[i] = cast(char)g_rt[ri].data[i];
            return cast(long)n;
        }
        if (ri >= 0) return cast(long)negErrno(EINVAL);   // exists but not a symlink
    }

    string target;
    if (!getSyntheticReadlinkTarget(path, target)) {
        if (isSyntheticDirectoryPath(path) || isSyntheticSocketPath(path)) {
            return cast(long)negErrno(EINVAL);
        }

        const long fd = sys_open(path, O_RDONLY);
        if (fd >= 0) {
            sys_close(cast(int)fd);
            return cast(long)negErrno(EINVAL);
        }
        return publishActiveFdReturn(fd);
    }

    size_t n = cast(size_t)_bufsiz;
    if (n > target.length) {
        n = target.length;
    }
    foreach (i; 0 .. n) {
        outBuf[i] = target[i];
    }
    return cast(long)n;
}

public long linux_sys_openat(ulong _dirfd, ulong path, ulong flags, ulong mode) {
    auto p = cast(const(char)*)path;
    // openat(dirfd, "rel") -> open(dirpath + "/" + "rel").  dirfd was previously IGNORED, which broke any
    // directory-relative openat — e.g. NM's nmp_utils_sysctl_open_netdir opens /sys/class/net/wlan0 then
    // openat(fd,"ifindex"/"uevent") to classify the wifi device.  Absolute paths + AT_FDCWD fall through.
    enum int AT_FDCWD = -100;
    int dfd = cast(int)_dirfd;
    if (p !is null && p[0] != '/' && p[0] != 0 && dfd != AT_FDCWD &&
        dfd >= 0 && dfd < 1024 && g_activeFdTabId >= 0 && g_activeFdTabId < FDTAB_COUNT &&
        g_fdPath[g_activeFdTabId][dfd][0] == '/') {
        char[512] full = void;
        const(char)* base = g_fdPath[g_activeFdTabId][dfd].ptr;
        int n = 0;
        while (n < 400 && base[n] != 0) { full[n] = base[n]; ++n; }
        if (n > 0 && full[n-1] != '/') full[n++] = '/';
        int j = 0; while (n < 510 && p[j] != 0) { full[n++] = p[j++]; }
        full[n] = 0;
        return linux_sys_open(cast(ulong)full.ptr, flags, mode);
    }
    return linux_sys_open(path, flags, mode);
}

public long linux_sys_newfstatat(ulong _dirfd, ulong path, ulong statbuf, ulong _flags) {
    enum AT_SYMLINK_NOFOLLOW = 0x100;
    enum AT_EMPTY_PATH = 0x1000;
    enum SUPPORTED_FLAGS = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

    if (path == 0 || statbuf == 0) {
        return cast(long)negErrno(EFAULT);
    }
    if ((_flags & ~SUPPORTED_FLAGS) != 0) {
        return cast(long)negErrno(EINVAL);
    }

    auto pathPtr = cast(const(char)*)path;
    // M3: same wifi-plugin rewrite as sys_open — NM's nm_utils_validate_plugin stat()s the plugin path.
    if (cstrEq(pathPtr, "/usr/lib/NetworkManager/1.44.2/libnm-device-plugin-wifi.so")) {
        pathPtr = "/libnm-device-plugin-wifi.so".ptr;
        path = cast(ulong)pathPtr;
    }
    if (pathPtr[0] == 0) {
        if ((_flags & AT_EMPTY_PATH) != 0) {
            return linux_sys_fstat(_dirfd, statbuf);
        }
        return cast(long)negErrno(ENOENT);
    }

    if ((_flags & AT_SYMLINK_NOFOLLOW) == 0 && cstrEq(pathPtr, "/proc/self/exe")) {
        const long targetFd = sys_open("/init.elf\0".ptr, O_RDONLY);
        if (targetFd >= 0) {
            const long targetStatRes = linux_sys_fstat(cast(ulong)targetFd, statbuf);
            sys_close(cast(int)targetFd);
            return targetStatRes;
        }
    }

    // Exact rtfs assets must win over broad synthetic-prefix directories such as
    // /usr/share/fonts/*, otherwise fontconfig sees real TTF files as dirs.
    {
        int rparent; const(char)* rleaf; size_t rleafLen;
        const int ridx = rtResolve(pathPtr, rparent, rleaf, rleafLen);
        if (ridx >= 0) {
            // lstat (AT_SYMLINK_NOFOLLOW) on an RT symlink: report the link itself
            // (S_IFLNK + target length) rather than following it.  ls -l needs this.
            if (g_rt[ridx].kind == RT_LNK && (_flags & AT_SYMLINK_NOFOLLOW) != 0) {
                writeLinuxStatOwned(statbuf, 0xA000 | 0x1FF, g_rt[ridx].size,
                                    g_rt[ridx].uid, g_rt[ridx].gid); // S_IFLNK | 0777
                return 0;
            }
            const long rtFd = sys_open(pathPtr, O_RDONLY);  // follows symlinks (stat semantics)
            if (rtFd >= 0) {
                const long rtStatRes = linux_sys_fstat(cast(ulong)rtFd, statbuf);
                sys_close(cast(int)rtFd);
                return rtStatRes;
            }
            return rtFd;
        }
    }

    if (isSyntheticDirectoryPath(pathPtr)) {
        const long dirFd = sys_open(pathPtr, O_RDONLY);
        if (dirFd >= 0) {
            const long dirStatRes = linux_sys_fstat(cast(ulong)dirFd, statbuf);
            sys_close(cast(int)dirFd);
            return dirStatRes;
        }
    }

    const long syntheticStat = statSyntheticPath(pathPtr, statbuf);
    if (syntheticStat == 0) {
        return 0;
    }

    const long fd = sys_open(pathPtr, O_RDONLY);
    if (fd < 0) {
        return publishActiveFdReturn(fd);
    }

    const long statRes = linux_sys_fstat(cast(ulong)fd, statbuf);
    sys_close(cast(int)fd);
    // M3: NM's nm_utils_validate_plugin requires the wifi plugin be owned by root (st_uid==0).  The plugin
    // is the /libnm-device-plugin-wifi.so boot module (a trusted system file) — force st_uid=0 (offset 28).
    if (statRes == 0 && cstrEq(pathPtr, "/libnm-device-plugin-wifi.so"))
        *cast(uint*)(cast(ubyte*)statbuf + 28) = 0;
    return statRes;
}

public long linux_sys_brk(ulong addr) {
    if (addr == 0) {
        return cast(long)g_linuxBrk;
    }

    if (addr < 0x500000UL || addr > 0x8000000UL) {
        return cast(long)g_linuxBrk;
    }

    g_linuxBrk = addr;
    return cast(long)g_linuxBrk;
}

import core.syscalls.mmap : sys_mprotect, sys_munmap;

public long linux_sys_mprotect(ulong addr, ulong len, ulong prot) {
    return sys_mprotect(addr, len, prot);
}

public long linux_sys_munmap(ulong addr, ulong len) {
    return sys_munmap(addr, len);
}

private bool syntheticExecutableAvailable(const(char)* path) {
    if (path is null || path[0] == 0) {
        return false;
    }

    const int fd = sys_open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }

    sys_close(fd);
    return true;
}

public bool spawnAndWait(const(char)* prog, char** argv, char** envp, out int exitCode) {
    if (!syntheticExecutableAvailable(prog)) {
        exitCode = 127;
        return false;
    }

    exitCode = 0;
    return true;
}

public pid_t spawnRegisteredProcess(const(char)* path, const(char*)* argv, const(char*)* envp) {
    if (!syntheticExecutableAvailable(path)) {
        return -1;
    }

    return g_nextSyntheticPid++;
}

public pid_t waitpid(pid_t pid, int* status, int options) {
    return -1;
}

public int schedYield() {
    return 0;
}

// Structs for new syscalls
struct timespec {
    long tv_sec;
    long tv_nsec;
}

// Imports for clock_gettime
import core.ticks : getTickCount, get_ticks, pitMs;
import core.bundle;
import core.globals : hhdm_offset;

public long sys_writev(int fd, const(iovec)* iov, int iovcnt) {
    if (iov == null && iovcnt > 0) return negErrno(14); // EFAULT
    
    long total = 0;
    for (int i = 0; i < iovcnt; i++) {
        long res = sys_write(fd, iov[i].iov_base, iov[i].iov_len);
        if (res < 0) {
            if (total > 0) return total; // Partial write
            return res;
        }
        total += res;
    }
    return total;
}

public long sys_getrandom(void* buf, size_t buflen, uint flags) {
    if (buf == null) return negErrno(14); // EFAULT
    
    // Simple pseudo-random using ticks
    ubyte* b = cast(ubyte*)buf;
    ulong s = getTickCount();
    for(size_t i=0; i<buflen; i++) {
        s = s * 6364136223846793005UL + 1442695040888963407UL;
        b[i] = cast(ubyte)(s >> 32);
    }
    return cast(long)buflen;
}

public int sys_clock_gettime(int clk_id, timespec* tp) {
    if (tp == null) return negErrno(14); // EFAULT
    
    // R2: real monotonic ms from the PIT (1000 Hz), NOT getTickCount which
    // increments on every read (a fake clock that runs at the call rate, breaking
    // Weston's frame pacing).  Must match the page-flip-complete timestamp clock.
    ulong ticks = pitMs();
    tp.tv_sec = cast(long)(ticks / 1000);
    tp.tv_nsec = cast(long)((ticks % 1000) * 1000000);

    return 0;
}

// Linux wrappers
public long linux_sys_writev(ulong fd, ulong iov, ulong iovcnt) {
    return sys_writev(cast(int)fd, cast(const(iovec)*)iov, cast(int)iovcnt);
}

//public long linux_sys_getrandom(ulong buf, ulong buflen, ulong flags) {
//    return sys_getrandom(cast(void*)buf, cast(size_t)buflen, cast(uint)flags);
//}

public long linux_sys_getrandom(ulong buf, ulong len, ulong flags)
{
    if (buf == 0 && len != 0)
        return negErrno(EFAULT);

    random_get_bytes(cast(void*)buf, len);
    return cast(long)len;
}

public long linux_sys_clock_gettime(ulong clk_id, ulong tp) {
    return cast(long)sys_clock_gettime(cast(int)clk_id, cast(timespec*)tp);
}

public int sys_socket(int domain, int type, int protocol) {
    initFdTable();

    const int baseType = type & 0x0F;

    // AF_NETLINK: libudev-zero's udev_monitor opens a NETLINK_KOBJECT_UEVENT
    // socket for device hotplug. We never emit uevents, so hand back a valid
    // socket that simply stays in the 'created' state — never readable, recvmsg
    // never fires. Without this, udev_monitor_new_from_netlink() returns NULL and
    // Weston's libinput setup aborts ("failed to create the udev monitor").
    if (domain == AF_NETLINK) {
        const int nid = allocLocalSocket(AF_NETLINK, baseType);
        if (nid < 0) return negErrno(EMFILE);
        const int nfd = allocSocketFd(nid, O_RDWR);
        if (nfd < 0) { releaseLocalSocket(nid); return negErrno(EMFILE); }
        return publishActiveFdReturn(nfd);
    }

    if (domain != AF_UNIX) return negErrno(EAFNOSUPPORT);
    if (baseType != SOCK_STREAM) return negErrno(EPROTONOSUPPORT);
    if (protocol != 0) return negErrno(EPROTONOSUPPORT);

    const int socketId = allocLocalSocket(domain, baseType);
    if (socketId < 0) return negErrno(EMFILE);

    const int fd = allocSocketFd(socketId, O_RDWR);
    if (fd < 0) {
        releaseLocalSocket(socketId);
        return negErrno(EMFILE);
    }
    return publishActiveFdReturn(fd);
}

public int sys_bind(int sockfd, sockaddr* addr, uint addrlen) {
    initFdTable();
    if (sockfd < 0 || sockfd >= 1024) return negErrno(EBADF);
    if (addr is null) return negErrno(EFAULT);

    File* f = &g_fdTable[sockfd];
    auto sock = fileSocket(f);
    if (sock is null) return negErrno(ENOTSOCK);
    // A netlink monitor socket binds to a sockaddr_nl; accept it as a no-op (we
    // deliver no uevents, so the bound socket just never becomes readable).
    if (sock.domain == AF_NETLINK) return 0;
    if (addr.sa_family != AF_UNIX) return negErrno(EAFNOSUPPORT);
    if (sock.state != LocalSocketState.created && sock.state != LocalSocketState.bound) return negErrno(EINVAL);

    auto un = cast(sockaddr_un*)addr;
    const size_t pathLen = unixPathLength(un, addrlen);
    if (pathLen == 0) return negErrno(EINVAL);
    if (pathLen >= sock.path.length) return negErrno(ENAMETOOLONG);
    if (unixPathInUse(un, pathLen)) return negErrno(EADDRINUSE);

    copyUnixPath(*sock, un, pathLen);
    sock.state = LocalSocketState.bound;
    return 0;
}

public int sys_listen(int sockfd, int backlog) {
    initFdTable();
    if (sockfd < 0 || sockfd >= 1024) return negErrno(EBADF);

    auto sock = fileSocket(&g_fdTable[sockfd]);
    if (sock is null) return negErrno(ENOTSOCK);
    if (sock.state != LocalSocketState.bound && sock.state != LocalSocketState.listener) return negErrno(EINVAL);

    size_t effectiveBacklog = backlog > 0 ? cast(size_t)backlog : 1;
    if (effectiveBacklog >= localSocketPendingCapacity) {
        effectiveBacklog = localSocketPendingCapacity - 1;
    }
    sock.backlog = effectiveBacklog;
    sock.state = LocalSocketState.listener;
    return 0;
}

// The cap-gated LKL network-provider socket (lkl-boot binds this).  Native WiFi/network
// clients (wpa_supplicant/NetworkManager) reach the LKL's wlan0 ONLY by connecting here, and
// ONLY if their domain/identity holds DEVCLASS_NET — deny-by-default, same mechanism as the
// /dev/input, camera and USB gates (deviceClassGate).  Keeps the hijack inside the cap model.
private static immutable char[] NET_PROVIDER_PATH = "/run/hos-net.sock\0";

private bool sockPathIsNetProvider(const(sockaddr_un)* un, size_t pathLen) {
    if (pathLen != NET_PROVIDER_PATH.length - 1) return false;   // exclude the NUL
    foreach (i; 0 .. pathLen)
        if (un.sun_path[i] != NET_PROVIDER_PATH[i]) return false;
    return true;
}

// DEVCLASS_NET gate for the provider socket, mirroring deviceClassGate() exactly.
private int netProviderConnectGate() {
    int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return 0;
    const uint dom = g_tasks[tid].domainObjId;
    if (dom != 0)                                 // domain-bound task → the domain's device mask
        return domainDeviceAllowed(dom, DEVCLASS_NET) ? 0 : negErrno(EACCES);
    const uint idObj = g_tasks[tid].identityObjId;
    if (idObj == 0) return 0;                     // no identity → unrestricted (kernel/desktop/lkl-boot)
    if (!identityDeviceAllowed(idObj, DEVCLASS_NET)) return negErrno(EACCES);
    return 0;
}

public int sys_connect(int sockfd, const(sockaddr)* addr, uint addrlen) {
    initFdTable();
    if (sockfd < 0 || sockfd >= 1024) return negErrno(EBADF);
    if (addr is null) return negErrno(EFAULT);
    if (addr.sa_family != AF_UNIX) return negErrno(EAFNOSUPPORT);

    File* f = &g_fdTable[sockfd];
    auto client = fileSocket(f);
    if (client is null) return negErrno(ENOTSOCK);
    if (client.state == LocalSocketState.connected) return negErrno(EISCONN);
    if (client.state == LocalSocketState.listener) return negErrno(EOPNOTSUPP);

    auto un = cast(const(sockaddr_un)*)addr;
    const size_t pathLen = unixPathLength(un, addrlen);
    if (pathLen == 0) return negErrno(EINVAL);

    // Cap-gate: connecting to the LKL network provider requires DEVCLASS_NET (deny-by-default).
    if (sockPathIsNetProvider(un, pathLen)) {
        const int g = netProviderConnectGate();
        if (g != 0) return g;
    }

    auto listener = findUnixListener(un, pathLen);
    if (listener is null) return negErrno(ECONNREFUSED);

    const int clientId = fileSocketId(f);
    const int acceptedId = allocLocalSocket(AF_UNIX, SOCK_STREAM);
    if (acceptedId < 0) return negErrno(EMFILE);

    auto accepted = localSocketById(acceptedId);
    if (accepted is null) {
        releaseLocalSocket(acceptedId);
        return negErrno(EMFILE);
    }

    accepted.state = LocalSocketState.connected;
    accepted.peerId = clientId;
    accepted.peerClosed = false;

    client.state = LocalSocketState.connected;
    client.peerId = acceptedId;
    client.peerClosed = false;

    if (!pendingQueuePush(*listener, acceptedId)) {
        releaseLocalSocket(acceptedId);
        client.state = LocalSocketState.created;
        client.peerId = -1;
        return negErrno(EAGAIN);
    }

    return 0;
}

public int sys_accept(int sockfd, sockaddr* addr, uint* addrlen) {
    initFdTable();
    if (sockfd < 0 || sockfd >= 1024) return negErrno(EBADF);

    auto listener = fileSocket(&g_fdTable[sockfd]);
    if (listener is null) return negErrno(ENOTSOCK);
    if (listener.state != LocalSocketState.listener) return negErrno(EINVAL);

    const int acceptedId = pendingQueuePop(*listener);
    if (acceptedId < 0) return negErrno(EAGAIN);

    const int fd = allocSocketFd(acceptedId, O_RDWR);
    if (fd < 0) {
        releaseLocalSocket(acceptedId);
        return negErrno(EMFILE);
    }

    if (addr !is null) {
        auto un = cast(sockaddr_un*)addr;
        un.sun_family = AF_UNIX;
        if (addrlen !is null) {
            *addrlen = cast(uint)sockaddr_un.sizeof;
        }
    }
    return publishActiveFdReturn(fd);
}

public ssize_t sys_sendmsg(int sockfd, msghdr* msg, int flags) {
    initFdTable();
    if (sockfd < 0 || sockfd >= 1024) return negErrno(EBADF);
    if (msg is null) return negErrno(EFAULT);

    File* f = &g_fdTable[sockfd];
    if (f.type != FileType.FD_SOCKET) return negErrno(ENOTSOCK);

    // SCM_RIGHTS: copy any passed File descriptors into the peer's queue so the
    // peer's recvmsg can materialise them as new fds in its own table.
    if (msg.msg_control !is null && msg.msg_controllen >= cmsghdr.sizeof) {
        auto cm = cast(cmsghdr*)msg.msg_control;
        if (cm.cmsg_len < cmsghdr.sizeof || cm.cmsg_len > msg.msg_controllen) {
            return negErrno(EINVAL);
        }
        if (cm.cmsg_level == SOL_SOCKET && cm.cmsg_type == SCM_RIGHTS) {
            auto sock = fileSocket(f);
            auto peer = (sock !is null && sock.peerId >= 0)
                        ? localSocketById(sock.peerId) : null;
            if (peer !is null) {
                size_t dataLen = cm.cmsg_len - cmsghdr.sizeof;
                size_t nfds    = dataLen / int.sizeof;
                auto fdArray   = cast(int*)(cast(ubyte*)cm + cmsghdr.sizeof);
                foreach (k; 0 .. nfds) {
                    int passFd = fdArray[k];
                    if (passFd < 0 || passFd >= 1024 ||
                        g_fdTable[passFd].type == FileType.FD_NONE) {
                        return negErrno(EBADF);
                    }
                    if (!fdRequireCap(cast(ulong)passFd, CAP_RIGHT_PASS))
                        return negErrno(EBADF);
                }
                size_t queued = (peer.passedHead + scmRightsCapacity - peer.passedTail) %
                                scmRightsCapacity;
                size_t freeSlots = (scmRightsCapacity - 1) - queued;
                if (nfds > freeSlots) return negErrno(EAGAIN);
                foreach (k; 0 .. nfds) {
                    int passFd = fdArray[k];
                    size_t nextHead = (peer.passedHead + 1) % scmRightsCapacity;
                    peer.passedFiles[peer.passedHead] = g_fdTable[passFd];
                    // Delegate the fd's authority by value through the IPC router
                    // (validates the object id, clamps rights); a raw pointer is
                    // never queued.
                    auto cap = capGet(cast(uint)passFd);
                    peer.passedCaps[peer.passedHead] =
                        (cap !is null && cap.objId != 0 && cap.revoked == 0)
                            ? ipcDelegateCap(cap.objId, cap.rights)
                            : IpcCapDesc.init;
                    // ORG P10 (E10): the receiver socket now holds an *in-flight*
                    // **StrongRef** to the passed fd's object — this is what keeps a
                    // passed fd alive after the sender closes its own copy, and what
                    // forms the unreachable SCM_RIGHTS cycle (collected by ORG GC,
                    // matching Linux's net/unix/garbage.c) when two sockets pass each
                    // other and both direct fds are then closed.
                    publishActiveFd(passFd);
                    if (peer.fdObjId != 0 && g_fdTable[passFd].objId != 0)
                        edgeAdd(peer.fdObjId, g_fdTable[passFd].objId,
                                EdgeKind.StrongRef, 0);
                    peer.passedHead = nextHead;
                }
            }
        }
    }

    ssize_t totalSent = 0;
    foreach (i; 0 .. msg.msg_iovlen) {
        auto iov = &msg.msg_iov[i];
        if (iov.iov_len == 0) continue;
        const ssize_t sent = localSocketWrite(f, iov.iov_base, iov.iov_len);
        if (sent < 0) {
            return totalSent > 0 ? totalSent : sent;
        }
        totalSent += sent;
        if (cast(size_t)sent < iov.iov_len) {
            break;
        }
    }
    return totalSent;
}

public ssize_t sys_recvmsg(int sockfd, msghdr* msg, int flags) {
    initFdTable();
    if (sockfd < 0 || sockfd >= 1024) return negErrno(EBADF);
    if (msg is null) return negErrno(EFAULT);

    File* f = &g_fdTable[sockfd];
    if (f.type != FileType.FD_SOCKET) return negErrno(ENOTSOCK);

    ssize_t totalRead = 0;
    foreach (i; 0 .. msg.msg_iovlen) {
        auto iov = &msg.msg_iov[i];
        if (iov.iov_len == 0) continue;
        const ssize_t read = localSocketRead(f, iov.iov_base, iov.iov_len);
        if (read < 0) {
            if (totalRead > 0) break;     // already have data: stop, report it
            return read;                  // first iov failed (e.g. EAGAIN)
        }
        if (read == 0) {
            break;
        }
        totalRead += read;
        if (cast(size_t)read < iov.iov_len) {
            break;
        }
    }

    // SCM_RIGHTS: materialise any queued passed File structs as new fds in this
    // process's table, writing their numbers into the caller's control buffer.
    if (msg.msg_control !is null && msg.msg_controllen >= cmsghdr.sizeof) {
        auto sock = fileSocket(f);
        size_t maxFds = (msg.msg_controllen - cmsghdr.sizeof) / int.sizeof;
        auto cm = cast(cmsghdr*)msg.msg_control;
        auto outFds = cast(int*)(cast(ubyte*)cm + cmsghdr.sizeof);
        size_t nOut = 0;
        if (sock !is null) {
            while (nOut < maxFds && sock.passedTail != sock.passedHead) {
                int newFd = allocFd();
                if (newFd < 0) break;
                g_fdTable[newFd] = sock.passedFiles[sock.passedTail];
                g_fdTable[newFd].objId = 0;
                auto oh = ensureFileObject(&g_fdTable[newFd]);
                if (oh !is null) {
                    uint rights = capRightsForFile(&g_fdTable[newFd]);
                    // Accept the delegated capability descriptor through the IPC
                    // router; the receiver materialises its own handle narrowed
                    // to the delegated rights.
                    auto queuedCap = &sock.passedCaps[sock.passedTail];
                    if (queuedCap.objId != 0)
                        rights &= ipcAcceptCap(*queuedCap);
                    capInstall(cast(uint)newFd, oh.id, rights, CAP_INVALID);
                }
                sock.passedCaps[sock.passedTail] = IpcCapDesc.init;
                sock.passedTail = (sock.passedTail + 1) % scmRightsCapacity;
                outFds[nOut++] = newFd;
            }
        }
        if (nOut > 0) {
            cm.cmsg_len   = cmsghdr.sizeof + nOut * int.sizeof;
            cm.cmsg_level = SOL_SOCKET;
            cm.cmsg_type  = SCM_RIGHTS;
            msg.msg_controllen = cm.cmsg_len;
        } else {
            msg.msg_controllen = 0;
        }
    } else if (msg.msg_control !is null) {
        msg.msg_controllen = 0;
    }

    return totalRead;
}

public ssize_t sys_sendto(int sockfd, const(void)* buf, size_t len, int flags, const(sockaddr)* dest_addr, uint addrlen) {
    if (dest_addr !is null) return negErrno(EOPNOTSUPP);

    iovec iov;
    iov.iov_base = cast(void*)buf;
    iov.iov_len = len;
    msghdr msg;
    msg.msg_name = null;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = null;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    return sys_sendmsg(sockfd, &msg, flags);
}

public ssize_t sys_recvfrom(int sockfd, void* buf, size_t len, int flags, sockaddr* src_addr, uint* addrlen) {
    iovec iov;
    iov.iov_base = buf;
    iov.iov_len = len;
    msghdr msg;
    msg.msg_name = src_addr;
    msg.msg_namelen = (addrlen !is null) ? *addrlen : 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = null;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    const ssize_t ret = sys_recvmsg(sockfd, &msg, flags);
    if (src_addr !is null && addrlen !is null && ret >= 0) {
        *addrlen = cast(uint)sockaddr_un.sizeof;
    }
    return ret;
}

public long linux_sys_socket(ulong domain, ulong type, ulong protocol) {
    return cast(long)sys_socket(cast(int)domain, cast(int)type, cast(int)protocol);
}

public long linux_sys_bind(ulong sockfd, ulong addr, ulong addrlen) {
    return cast(long)sys_bind(cast(int)sockfd, cast(sockaddr*)addr, cast(uint)addrlen);
}

public long linux_sys_listen(ulong sockfd, ulong backlog) {
    return cast(long)sys_listen(cast(int)sockfd, cast(int)backlog);
}

public long linux_sys_accept(ulong sockfd, ulong addr, ulong addrlen) {
    return cast(long)sys_accept(cast(int)sockfd, cast(sockaddr*)addr, cast(uint*)addrlen);
}

public long linux_sys_connect(ulong sockfd, ulong addr, ulong addrlen) {
    return cast(long)sys_connect(cast(int)sockfd, cast(const(sockaddr)*)addr, cast(uint)addrlen);
}

public long linux_sys_sendmsg(ulong sockfd, ulong msg, ulong flags) {
    hangTrace2("sendmsg fd,flags", sockfd, flags);
    return cast(long)sys_sendmsg(cast(int)sockfd, cast(msghdr*)msg, cast(int)flags);
}

public long linux_sys_recvmsg(ulong sockfd, ulong msg, ulong flags) {
    hangTrace2("recvmsg fd,flags", sockfd, flags);
    return cast(long)sys_recvmsg(cast(int)sockfd, cast(msghdr*)msg, cast(int)flags);
}

public long linux_sys_sendto(ulong sockfd, ulong buf, ulong len, ulong flags, ulong dest_addr, ulong addrlen) {
    return cast(long)sys_sendto(cast(int)sockfd, cast(const(void)*)buf, cast(size_t)len, cast(int)flags, cast(const(sockaddr)*)dest_addr, cast(uint)addrlen);
}

public long linux_sys_recvfrom(ulong sockfd, ulong buf, ulong len, ulong flags, ulong src_addr, ulong addrlen) {
    return cast(long)sys_recvfrom(cast(int)sockfd, cast(void*)buf, cast(size_t)len, cast(int)flags, cast(sockaddr*)src_addr, cast(uint*)addrlen);
}


// --- Stub Syscalls for Phase 3e ---

struct utsname {
    char[65] sysname;
    char[65] nodename;
    char[65] release;
    char[65] version_;
    char[65] machine;
    char[65] domainname;
}

public long linux_sys_uname(ulong buf) {
    if (buf == 0) return negErrno(14); // EFAULT
    utsname* u = cast(utsname*)buf;
    
    // Helper to copy string
    void strcpy(char[] dst, string src) {
        size_t len = src.length;
        if (len >= dst.length) len = dst.length - 1;
        for(size_t i=0; i<len; i++) dst[i] = src[i];
        dst[len] = 0;
    }
    void strcpyC(char[] dst, const(char)* src) {
        size_t len = 0;
        while (src[len] != 0 && len < dst.length - 1) {
            dst[len] = src[len];
            ++len;
        }
        dst[len] = 0;
    }

    strcpy(u.sysname, "Linux"); // Pretend to be Linux
    strcpyC(u.nodename, g_hostname.ptr);
    strcpy(u.release, "6.0.0"); // Pretend to be a modern kernel
    strcpy(u.version_, "#1 SMP HanonymOS");
    strcpy(u.machine, "x86_64");
    strcpyC(u.domainname, g_domainname.ptr);

    return 0;
}

public long linux_sys_getpid() {
    return cast(long)linuxPidForTask(cast(int)g_current_task_id);
}

public long linux_sys_rt_sigaction(ulong signum, ulong act, ulong oldact, ulong sigsetsize) {
    // Track A A4: record only whether each signal has a NON-default disposition
    // (SIG_IGN or a handler) for the current task, so the PTY ^C/^\ path knows which
    // foreground tasks to auto-terminate (default) vs leave alone (the shell, vi, …).
    // We don't yet invoke user handlers — a non-default disposition just suppresses the
    // default terminate, which is what keeps interactive apps alive on ^C.
    const int tid = cast(int)g_current_task_id;
    if (signum < 64 && tid >= 0 && tid < MAX_TASKS) {
        if (oldact != 0 && signum < 64) {
            // Report the previously-installed handler (zsh queries this).
            *cast(ulong*)oldact = g_sigHandler[tid][signum];
        }
        if (act != 0) {
            // x86-64 kernel sigaction layout: sa_handler(+0), sa_flags(+8), sa_restorer(+16).
            const ulong handler  = *cast(ulong*)(act + 0);
            const ulong flags    = *cast(ulong*)(act + 8);
            const ulong restorer = *cast(ulong*)(act + 16);
            // SIG_DFL = 0 → default; SIG_IGN = 1 or any handler → custom (suppress kill)
            if (handler == 0) g_taskSigCustom[tid] &= ~(1UL << signum);
            else              g_taskSigCustom[tid] |=  (1UL << signum);
            // Z1: store the real handler so the run loop can invoke it (SIGCHLD).  A real
            // function pointer (not SIG_DFL/SIG_IGN = 0/1) with SA_RESTORER's trampoline is
            // what we can build a frame for; otherwise clear it (default/ignore handling).
            enum ulong SA_RESTORER = 0x04000000;
            if (handler > 1 && (flags & SA_RESTORER) && restorer != 0) {
                g_sigHandler[tid][signum]  = handler;
                g_sigRestorer[tid][signum] = restorer;
            } else {
                g_sigHandler[tid][signum]  = 0;
                g_sigRestorer[tid][signum] = 0;
            }
        }
    }
    return 0;
}

public long linux_sys_futex(ulong uaddr, ulong op, ulong val, ulong timeout, ulong uaddr2, ulong val3) {
    // TEMP boot-hang trace: pthread_join parks in FUTEX_WAIT with no timeout, so the
    // last futex line before silence identifies the wait that never woke.  Bounded so a
    // busy lock cannot flood the UART.
    if (g_hangTraceFutexCount < HANG_TRACE_POLL_MAX) {
        ++g_hangTraceFutexCount;
        klog("[trace] futex op="); klog_hex(op);
        klog(" uaddr="); klog_hex(uaddr);
        klog(" val="); klog_hex(val); klog("\n");
    }
    enum FUTEX_WAIT = 0;
    enum FUTEX_WAKE = 1;
    enum FUTEX_PRIVATE_FLAG = 0x80;
    enum LINUX_EFAULT = -14;
    enum LINUX_EAGAIN = -11;
    enum LINUX_ENOSYS = -38;

    if (uaddr == 0) {
        return LINUX_EFAULT;
    }

    auto futexWord = cast(int*)uaddr;
    auto futexOp = op & ~FUTEX_PRIVATE_FLAG;

    switch (futexOp) {
        case FUTEX_WAIT:
            if (*futexWord != cast(int)val) {
                return LINUX_EAGAIN;
            }
            // Blocking wait queues are not implemented yet. Report that honestly
            // instead of claiming success and letting userspace believe it slept.
            return LINUX_ENOSYS;
        case FUTEX_WAKE:
            return 0;
        default:
            return LINUX_ENOSYS;
    }
}

public long linux_sys_set_tid_address(ulong tidptr) {
    return cast(long)linuxTidForTask(cast(int)g_current_task_id);
}

public long linux_sys_set_robust_list(ulong head, ulong len) {
    return 0;
}

private struct LinuxRlimit {
    ulong rlim_cur;
    ulong rlim_max;
}

public long linux_sys_prlimit64(ulong pid, ulong resource, ulong new_limit, ulong old_limit) {
    enum RLIMIT_STACK = 3;
    enum RLIMIT_NOFILE = 7;
    enum ulong RLIM_INFINITY = ~cast(ulong)0;

    LinuxRlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;

    if (resource == RLIMIT_STACK) {
        limit.rlim_cur = 8UL * 1024UL * 1024UL;
        limit.rlim_max = 8UL * 1024UL * 1024UL;
    } else if (resource == RLIMIT_NOFILE) {
        limit.rlim_cur = 1024;
        limit.rlim_max = 1024;
    }

    if (old_limit != 0) {
        auto outLimit = cast(LinuxRlimit*)old_limit;
        outLimit.rlim_cur = limit.rlim_cur;
        outLimit.rlim_max = limit.rlim_max;
    }

    // Setting new limits is ignored for now; we only expose stable values.
    return 0;
}

public long linux_sys_rseq(ulong rseq, ulong rseq_len, ulong flags, ulong sig) {
    // glibc already knows how to fall back when rseq is unavailable. Pretending
    // success without maintaining per-thread rseq state is more dangerous.
    return -38; // ENOSYS
}

// Physical info for a file descriptor (used by Haskell mmap for file-backed mappings)
struct FdPhysInfo {
    ulong physBase;  // Physical address of file data start
    ulong fileSize;  // Total file size in bytes
}

// Returns true and fills `out_` if `fd` is a valid bundle file descriptor.
// physBase is the physical address of the bundle file's data.
public bool c_get_fd_phys_info(int fd, FdPhysInfo* out_) {
    initFdTable();
    if (fd < 0 || fd >= 1024) return false;
    File* f = &g_fdTable[fd];
    if (f.type == FileType.FD_BUNDLE) {
        // f.backend stores bf.offset (byte offset from g_bundleBase to file data)
        // g_bundleBase is a HHDM virtual address; subtract hhdm_offset to get physical
        ulong physBase = cast(ulong)g_bundleBase - hhdm_offset + cast(ulong)f.backend;
        out_.physBase = physBase;
        out_.fileSize = f.fileSize;
        return true;
    }

    if (f.type == FileType.FD_BOOT_MODULE) {
        out_.physBase = cast(ulong)f.backend;
        out_.fileSize = f.fileSize;
        return true;
    }

    if (f.type == FileType.FD_DRM) {
        // physBase = 0; mmap file-offset = GEM buffer physical address
        // → physMappingBase = 0 + fileOffset = gem_phys_addr (direct framebuffer)
        out_.physBase = 0;
        out_.fileSize = ulong.max;
        return true;
    }

    return false;
}

public long linux_sys_lseek(ulong fd, long offset, ulong whence) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return negErrno(9); // EBADF
    File* f = &g_fdTable[ifd];
    if (f.type == FileType.FD_NONE) return negErrno(9);

    // /run/klog grows continuously; refresh its size so SEEK_END lands on the live tail
    // (lets the viewer read just the last N bytes instead of the whole retained ring).
    if (f.type == FileType.FD_KLOG) { import core.io : g_klogHead; f.fileSize = g_klogHead; }

    ulong newOff;
    if (whence == 0) { // SEEK_SET
        if (offset < 0) return negErrno(22); // EINVAL
        newOff = cast(ulong)offset;
    } else if (whence == 1) { // SEEK_CUR
        newOff = f.offset + cast(ulong)offset;
    } else if (whence == 2) { // SEEK_END
        newOff = f.fileSize + cast(ulong)offset;
    } else {
        return negErrno(22); // EINVAL
    }

    f.offset = newOff;
    return cast(long)newOff;
}

public long linux_sys_lseek_wrap(ulong fd, ulong offset, ulong whence) {
    return linux_sys_lseek(fd, cast(long)offset, whence);
}

// ================================================================
// Additional Linux syscall implementations for musl/busybox/glibc
// ================================================================

// --- Process exit ---
// Halts the CPU; proper task teardown requires Haskell kernel cooperation.
public long linux_sys_exit(ulong code) @nogc nothrow {
    asm @nogc nothrow { cli; }
    while (true) { asm @nogc nothrow { hlt; } }
}

public long linux_sys_exit_group(ulong code) @nogc nothrow {
    return linux_sys_exit(code);
}

// --- TLS setup: arch_prctl ---
public long linux_sys_arch_prctl(ulong code, ulong addr) {
    enum ARCH_SET_GS = 0x1001;
    enum ARCH_SET_FS = 0x1002;
    enum ARCH_GET_FS = 0x1003;
    enum ARCH_GET_GS = 0x1004;

    if (code == ARCH_SET_FS) {
        asm @nogc nothrow {
            mov RCX, 0xC0000100;
            mov RAX, addr;
            mov RDX, addr;
            shr RDX, 32;
            wrmsr;
        }
        d_store_task_fsbase(g_current_task_id, addr);
        return 0;
    }
    if (code == ARCH_SET_GS) {
        asm @nogc nothrow {
            mov RCX, 0xC0000101;
            mov RAX, addr;
            mov RDX, addr;
            shr RDX, 32;
            wrmsr;
        }
        return 0;
    }
    if (code == ARCH_GET_FS) {
        if (addr == 0) return negErrno(EFAULT);
        ulong val;
        asm @nogc nothrow {
            mov RCX, 0xC0000100;
            rdmsr;
            shl RDX, 32;
            or  RAX, RDX;
            mov val, RAX;
        }
        *cast(ulong*)addr = val;
        return 0;
    }
    if (code == ARCH_GET_GS) {
        if (addr == 0) return negErrno(EFAULT);
        ulong val;
        asm @nogc nothrow {
            mov RCX, 0xC0000101;
            rdmsr;
            shl RDX, 32;
            or  RAX, RDX;
            mov val, RAX;
        }
        *cast(ulong*)addr = val;
        return 0;
    }
    return negErrno(EINVAL);
}

// --- Identity / session / group ---
// Phase 10 / IR-P3: identity is read from the active task's User object. The
// default subject is non-root; privileged actions are gated by typed admin
// capabilities, not uid 0.
public long linux_sys_getuid()  { return cast(long)userCurrentUid(); }
public long linux_sys_geteuid() { return cast(long)userCurrentUid(); }
public long linux_sys_getgid()  { return cast(long)userCurrentGid(); }
public long linux_sys_getegid() { return cast(long)userCurrentGid(); }
public long linux_sys_getppid() {
    int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return 0;
    int parent = g_tasks[tid].parentId;
    if (parent < 0 || parent >= MAX_TASKS) return 0;
    return cast(long)linuxPidForTask(parent);
}
// Track A A4: setpgid records the task's process group for terminal ^C/^\ delivery.
// getpgid/getpgrp keep the historical constant (1): busybox ash's job-control init
// compares getpgrp() == tcgetpgrp(tty) to decide it owns the terminal, and both have
// long reported 1, so the shell reaches its interactive prompt.  Returning real,
// mismatched pgids here makes ash think it's a background shell and it never prompts.
public long linux_sys_getpgid(ulong pid) { return 1; }
public long linux_sys_setpgid(ulong pid, ulong pgid) {
    int t = (pid == 0) ? cast(int)g_current_task_id : taskIdFromLinuxPid(cast(int)pid);
    if (t < 0 || t >= MAX_TASKS) return 0;
    g_taskPgid[t] = (pgid == 0) ? linuxPidForTask(t) : cast(int)pgid;
    return 0;
}
public long linux_sys_getpgrp() { return 1; }
public long linux_sys_setsid()  { return 1; }
public long linux_sys_gettid()  {
    return cast(long)linuxTidForTask(cast(int)g_current_task_id);
}
public long linux_sys_getgroups(ulong size, ulong list) { return 0; }
public long linux_sys_setgroups(ulong size, ulong list) {
    if (size == 0) return 0;
    return adminRequire(CAP_RIGHT_ADMIN_USER) ? 0 : negErrno(EPERM);
}

private bool setCurrentTaskUserObj(uint objId) {
    int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return false;
    if (!userSetActiveSubject(objId)) return false;
    g_tasks[tid].userObjId = objId;
    return true;
}

private long switchCurrentUid(uint uid) {
    if (uid == userCurrentUid()) return 0;
    if (!adminRequire(CAP_RIGHT_ADMIN_USER)) return negErrno(EPERM);
    auto u = userByUid(uid);
    if (u is null) return negErrno(EINVAL);
    return setCurrentTaskUserObj(u.objId) ? 0 : negErrno(EINVAL);
}

private long switchCurrentGid(uint gid) {
    if (gid == userCurrentGid()) return 0;
    if (!adminRequire(CAP_RIGHT_ADMIN_USER)) return negErrno(EPERM);
    auto u = userByGid(gid);
    if (u is null) return negErrno(EINVAL);
    return setCurrentTaskUserObj(u.objId) ? 0 : negErrno(EINVAL);
}

private bool idArgSpecified(ulong v) {
    return v != ulong.max;
}

public long linux_sys_setuid(ulong uid) {
    if (uid > uint.max) return negErrno(EINVAL);
    return switchCurrentUid(cast(uint)uid);
}

public long linux_sys_setgid(ulong gid) {
    if (gid > uint.max) return negErrno(EINVAL);
    return switchCurrentGid(cast(uint)gid);
}

public long linux_sys_setresuid(ulong r, ulong e, ulong s) {
    if ((idArgSpecified(r) && r > uint.max) ||
        (idArgSpecified(e) && e > uint.max) ||
        (idArgSpecified(s) && s > uint.max))
        return negErrno(EINVAL);
    uint target = userCurrentUid();
    if (idArgSpecified(r)) target = cast(uint)r;
    if (idArgSpecified(e) && cast(uint)e != target) return negErrno(EINVAL);
    if (idArgSpecified(s) && cast(uint)s != target) return negErrno(EINVAL);
    return switchCurrentUid(target);
}

public long linux_sys_setresgid(ulong r, ulong e, ulong s) {
    if ((idArgSpecified(r) && r > uint.max) ||
        (idArgSpecified(e) && e > uint.max) ||
        (idArgSpecified(s) && s > uint.max))
        return negErrno(EINVAL);
    uint target = userCurrentGid();
    if (idArgSpecified(r)) target = cast(uint)r;
    if (idArgSpecified(e) && cast(uint)e != target) return negErrno(EINVAL);
    if (idArgSpecified(s) && cast(uint)s != target) return negErrno(EINVAL);
    return switchCurrentGid(target);
}
public long linux_sys_getresuid(ulong rp, ulong ep, ulong sp) {
    const uint uid = userCurrentUid();
    if (rp) *cast(uint*)rp = uid;
    if (ep) *cast(uint*)ep = uid;
    if (sp) *cast(uint*)sp = uid;
    return 0;
}
public long linux_sys_getresgid(ulong rp, ulong ep, ulong sp) {
    const uint gid = userCurrentGid();
    if (rp) *cast(uint*)rp = gid;
    if (ep) *cast(uint*)ep = gid;
    if (sp) *cast(uint*)sp = gid;
    return 0;
}

// --- Umask ---
public long linux_sys_umask(ulong mask) {
    uint old = g_umask;
    g_umask = cast(uint)(mask & 511); // Octal 777
    return cast(long)old;
}

// --- Signal mask / return (stubs sufficient for musl startup) ---
public long linux_sys_rt_sigprocmask(ulong how, ulong nset, ulong oldset, ulong sigsetsize) {
    if (oldset != 0) {
        auto p = cast(ulong*)oldset;
        for (ulong i = 0; i < (sigsetsize + 7) / 8; ++i)
            p[i] = 0;
    }
    return 0;
}
public long linux_sys_rt_sigreturn() { return 0; }
public long linux_sys_sigaltstack(ulong ss, ulong old_ss) { return 0; }

// --- Kill / tgkill ---
// POSIX kill(pid, 0) is an *existence probe* (no signal sent): it must return -ESRCH once the
// target process is gone.  The previous stub always returned 0, which broke zsh's command-
// substitution wait: zsh's waitforpid() loop is `while (kill(pid,0) >= 0 || errno != ESRCH)
// { signal_suspend(SIGCHLD,...); }` (jobs.c) — designed to exit when the reaped $() child makes
// kill(pid,0) report ESRCH.  With kill always 0 the loop never terminated, so after every
// FORKING command (a $() / external in a sub-context) zsh spun in waitforpid, never returned to
// its main loop, never re-engaged ZLE, and left the terminal in cooked mode with no next prompt
// — the "$() hang".  Report real liveness instead; delivery of an actual signal stays a
// best-effort no-op for a live target (the kernel models signal delivery elsewhere), but a dead
// target always yields ESRCH so probe loops can terminate.  A reaped task's slot is reset to
// Task.init by releaseTask() (active=false), so taskIdFromLinuxPid(pid) resolves it as not alive.
public long linux_sys_kill(ulong pid, ulong sig) {
    // POSIX kill(pid, sig): for liveness probes (sig==0) and real signals alike we
    // model existence by the task slot.  A reaped/dead pid MUST return -ESRCH — zsh's
    // waitforpid() loop `while (kill(pid,0) >= 0 || errno != ESRCH)` relies on it to
    // terminate after a $()/cmdsubst child is reaped (otherwise it spins forever in
    // signal_suspend()).  NOTE: this requires zsh to be built WITHOUT BROKEN_KILL_ESRCH
    // (see deps/zsh/Makefile zsh_cv_sys_killesrch=yes) so its ESRCH is the real 3, not
    // the EINVAL fallback that a stale "kill always returns 0" probe once hardcoded.
    const int target = taskIdFromLinuxPid(cast(int)cast(long)pid);
    const bool alive = (target > 0 && target < MAX_TASKS &&
                        g_tasks[target].active && !g_tasks[target].exited);
    if (!alive) return cast(long)(-3);  // -ESRCH: no such (live) process
    return 0;                           // alive: existence probe ok / signal no-op
}
public long linux_sys_tgkill(ulong tgid, ulong tid, ulong sig) {
    return linux_sys_kill(tid, sig);    // thread-group kill: same liveness semantics
}
public long linux_sys_tkill(ulong tid, ulong sig)           { return 0; }
public long linux_sys_membarrier(ulong cmd, ulong flags, ulong cpu) {
    enum int MEMBARRIER_CMD_QUERY = 0;
    enum int MEMBARRIER_CMD_PRIVATE_EXPEDITED = 1 << 3;
    enum int MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED = 1 << 4;

    if (flags != 0) return negErrno(EINVAL);
    if (cmd == MEMBARRIER_CMD_QUERY)
        return MEMBARRIER_CMD_PRIVATE_EXPEDITED | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED;
    if (cmd == MEMBARRIER_CMD_PRIVATE_EXPEDITED ||
        cmd == MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED)
        return 0;
    return negErrno(EINVAL);
}

// --- stat / lstat (delegate to newfstatat) ---
public long linux_sys_stat(ulong path, ulong statbuf) {
    return linux_sys_newfstatat(cast(ulong)-100, path, statbuf, 0);
}
public long linux_sys_lstat(ulong path, ulong statbuf) {
    return linux_sys_newfstatat(cast(ulong)-100, path, statbuf, 0x100 /*AT_SYMLINK_NOFOLLOW*/);
}

// --- dup / dup2 / dup3 ---
private void incPipeRef(int fd) {
    File* f = &g_fdTable[fd];
    if (f.type == FileType.FD_PIPE_READ) {
        auto p = getPipe(cast(size_t)pipeIdFromFd(f));
        if (p !is null) ++p.readers;
    } else if (f.type == FileType.FD_PIPE_WRITE) {
        auto p = getPipe(cast(size_t)pipeIdFromFd(f));
        if (p !is null) ++p.writers;
    } else if (f.type == FileType.FD_SOCKET) {
        // dup of a socket fd: another reference to the same LocalSocket, so the
        // socket (and its connection to the peer) must outlive the original fd.
        // libseat's embedded seatd dups its connection fd and closes the original.
        auto s = fileSocket(f);
        if (s !is null) ++s.refCount;
    } else {
        fdInstanceRef(f);   // epoll/eventfd/memfd: dup shares the same instance
    }
}

public long linux_sys_dup(ulong fd) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024 || g_fdTable[ifd].type == FileType.FD_NONE)
        return negErrno(EBADF);
    if (!fdRequireCap(fd, CAP_RIGHT_DUP)) return negErrno(EBADF);
    for (int nfd = 0; nfd < 1024; ++nfd) {
        if (g_fdTable[nfd].type == FileType.FD_NONE) {
            g_fdTable[nfd] = g_fdTable[ifd];
            incPipeRef(ifd);
            deriveActiveFd(nfd, ifd);
            return nfd;
        }
    }
    return negErrno(EMFILE);
}

public long linux_sys_dup2(ulong fd, ulong newfd_) {
    initFdTable();
    int ifd = cast(int)fd;
    int infd = cast(int)newfd_;
    if (ifd < 0 || ifd >= 1024 || g_fdTable[ifd].type == FileType.FD_NONE)
        return negErrno(EBADF);
    if (!fdRequireCap(fd, CAP_RIGHT_DUP)) return negErrno(EBADF);
    if (infd < 0 || infd >= 1024)
        return negErrno(EBADF);
    if (ifd == infd)
        return infd;
    if (g_fdTable[infd].type != FileType.FD_NONE)
        sys_close(infd);
    g_fdTable[infd] = g_fdTable[ifd];
    incPipeRef(ifd);
    deriveActiveFd(infd, ifd);
    return infd;
}

public long linux_sys_dup3(ulong fd, ulong newfd_, ulong flags) {
    if (fd == newfd_) return negErrno(EINVAL);
    return linux_sys_dup2(fd, newfd_);
}

// --- pipe / pipe2 ---
public long linux_sys_pipe2(ulong pipefd_ptr, ulong flags) {
    if (pipefd_ptr == 0) return negErrno(EFAULT);
    initFdTable();
    int pipeId = allocPipeId();
    if (pipeId < 0) return negErrno(EMFILE);

    int rfd = -1, wfd = -1;
    for (int i = 0; i < 1024 && rfd < 0; ++i)
        if (g_fdTable[i].type == FileType.FD_NONE) rfd = i;
    for (int i = 0; i < 1024 && wfd < 0; ++i)
        if (i != rfd && g_fdTable[i].type == FileType.FD_NONE) wfd = i;

    if (rfd < 0 || wfd < 0) { g_pipes[pipeId].inUse = false; return negErrno(EMFILE); }

    g_fdTable[rfd] = File(FileType.FD_PIPE_READ, 0, 0, cast(void*)(cast(size_t)pipeId + 1), 0);
    g_fdTable[wfd] = File(FileType.FD_PIPE_WRITE, 0, 0, cast(void*)(cast(size_t)pipeId + 1), 0);
    publishActiveFd(rfd);
    publishActiveFd(wfd);

    int* pfd = cast(int*)pipefd_ptr;
    pfd[0] = rfd;
    pfd[1] = wfd;
    return 0;
}
public long linux_sys_pipe(ulong pipefd_ptr) { return linux_sys_pipe2(pipefd_ptr, 0); }

// --- fcntl ---
public long linux_sys_fcntl(ulong fd, ulong cmd, ulong arg) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024 || g_fdTable[ifd].type == FileType.FD_NONE)
        return negErrno(EBADF);
    enum F_DUPFD = 0, F_GETFD = 1, F_SETFD = 2, F_GETFL = 3, F_SETFL = 4;
    enum F_DUPFD_CLOEXEC = 1030;
    switch (cmd) {
        case F_GETFD: return 0;
        case F_SETFD: return 0;
        case F_GETFL: return g_fdTable[ifd].flags;
        case F_SETFL:
            // F_SETFL changes fd *status* flags (O_NONBLOCK, O_APPEND, …); it is
            // not a data write, so it must succeed on read-only fds too. Requiring
            // CAP_RIGHT_WRITE wrongly returned EBADF for e.g. a pipe's READ end —
            // which broke libseat's embedded seatd poller_init (it calls
            // set_nonblock() on signal_fds[0], the read end), so Weston's DRM
            // backend could not open a seat. The FD_NONE check above already
            // confirms the fd is valid and owned by this task.
            g_fdTable[ifd].flags = cast(int)arg;
            return 0;
        case F_DUPFD: case F_DUPFD_CLOEXEC:
            if (!fdRequireCap(fd, CAP_RIGHT_DUP)) return negErrno(EBADF);
            for (int nfd = cast(int)arg; nfd < 1024; ++nfd) {
                if (g_fdTable[nfd].type == FileType.FD_NONE) {
                    g_fdTable[nfd] = g_fdTable[ifd];
                    incPipeRef(ifd);
                    deriveActiveFd(nfd, ifd);
                    return nfd;
                }
            }
            return negErrno(EMFILE);
        case F_ADD_SEALS:
            if (!fdRequireCap(fd, CAP_RIGHT_WRITE)) return negErrno(EBADF);
            if (g_fdTable[ifd].type != FileType.FD_MEMFD) return negErrno(EINVAL);
            if ((cast(int)arg & ~F_SEAL_VALID_MASK) != 0) return negErrno(EINVAL);
            {
                int mid = cast(int)cast(size_t)g_fdTable[ifd].backend;
                if (mid < 0 || mid >= MEMFD_MAX || !g_memfds[mid].inUse)
                    return negErrno(EBADF);
                if ((g_memfds[mid].seals & F_SEAL_SEAL) != 0)
                    return negErrno(EPERM);
                g_memfds[mid].seals |= cast(int)arg;
            }
            return 0;
        case F_GET_SEALS:
            if (g_fdTable[ifd].type != FileType.FD_MEMFD) return negErrno(EINVAL);
            {
                int mid = cast(int)cast(size_t)g_fdTable[ifd].backend;
                if (mid < 0 || mid >= MEMFD_MAX || !g_memfds[mid].inUse)
                    return negErrno(EBADF);
                return g_memfds[mid].seals;
            }
        default: return negErrno(EINVAL);
    }
}

// --- getcwd / chdir ---
public long linux_sys_getcwd(ulong buf, ulong size) {
    if (buf == 0)  return negErrno(EFAULT);
    if (size == 0) return negErrno(EINVAL);
    if (g_cwd_len + 1 > size) return negErrno(ERANGE);
    auto out_ = cast(char*)buf;
    for (size_t i = 0; i <= g_cwd_len; ++i) out_[i] = g_cwd_buf[i];
    return cast(long)(g_cwd_len + 1);
}

public long linux_sys_chdir(ulong path) {
    if (path == 0) return negErrno(EFAULT);
    auto p = cast(const(char)*)path;
    bool ok = isSyntheticDirectoryPath(p);
    if (!ok) {
        // Also accept any REAL directory in the rtfs overlay — chdir previously only honoured a
        // hardcoded whitelist + the synthetic FS views, so `cd` into a normal/blob-staged dir
        // (e.g. /system/shell/zsh/omz, /etc/zsh/themes) failed with ENOENT even though `open`
        // resolved files under it.  Resolve the path; if it lands on a directory node, allow it.
        int rparent; const(char)* rleaf; size_t rleafLen;
        const int ri = rtResolve(p, rparent, rleaf, rleafLen);
        if (ri >= 0 && ri < RT_MAX_NODES && g_rt[ri].kind == RT_DIR) ok = true;
    }
    if (!ok) return negErrno(ENOENT);
    size_t len = 0;
    while (len < g_cwd_buf.length - 1 && p[len] != 0) g_cwd_buf[len] = p[len++];
    g_cwd_buf[len] = 0;
    g_cwd_len = len;
    return 0;
}

public long linux_sys_fchdir(ulong fd) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024 || g_fdTable[ifd].type == FileType.FD_NONE) return negErrno(EBADF);
    if (!fileIsSyntheticDirectory(&g_fdTable[ifd])) return negErrno(ENOTDIR);
    return 0;
}

// --- getdents64 ---
private struct linux_dirent64 {
    ulong  d_ino;
    long   d_off;
    ushort d_reclen;
    ubyte  d_type;
    // char d_name[] follows immediately
}
private enum DT_CHR = 2;
private enum DT_DIR = 4;
private enum DT_REG = 8;
private enum DT_LNK = 10;

// Linux ABI: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) = 19 bytes, then
// d_name[] immediately at offset 19. The D struct above pads to 24 (8-byte
// alignment), so its `.sizeof` must NOT be used for the trailing name offset —
// doing so wrote d_name into the padding and musl read back empty names.
private enum size_t DIRENT64_NAME_OFF = 19;

private bool writeDirent64(ubyte* buf, size_t bufSz, size_t* off, ulong ino, long doff,
                            ubyte dtype, const(char)* name, size_t nlen) {
    size_t reclen = (DIRENT64_NAME_OFF + nlen + 1 + 7) & ~cast(size_t)7;
    if (*off + reclen > bufSz) return false;
    auto ent = cast(linux_dirent64*)(buf + *off);
    ent.d_ino    = ino;
    ent.d_off    = doff;
    ent.d_reclen = cast(ushort)reclen;
    ent.d_type   = dtype;
    auto nb = cast(char*)(buf + *off + DIRENT64_NAME_OFF);
    for (size_t i = 0; i < nlen; ++i) nb[i] = name[i];
    nb[nlen] = 0;
    *off += reclen;
    return true;
}

// Marker stashed in a synthetic-dir fd's (otherwise unused) fileSize so getdents64
// knows it is /sys/dev/char and should list the char-device nodes (maj:min) that
// libudev-zero scans to discover devices.
private enum ulong SYNTHDIR_DEVCHAR = 0x0DE7C400;

// The char-device entries we expose under /sys/dev/char (name + d_ino).
private static immutable string[4] g_devCharEntries = ["226:0", "226:128", "13:64", "13:65"];

// M3: tag /sys/class/net so getdents64 lists the interfaces NM's nm-linux-platform enumerates.
// Without this the dir readdir is empty -> NM sees NO device even though the LKL has wlan0.
private enum ulong SYNTHDIR_NETCLASS = 0x0E7C1A55;
private static immutable string[2] g_netClassEntries = ["lo", "wlan0"];
// M3: NM loads device plugins by readdir'ing NMPLUGINDIR=/usr/lib/NetworkManager/1.44.2.  That dir is a
// synthetic prefix whose getdents is empty, so NM finds no wifi plugin.  Synthesize the listing (the .so
// file itself is a real openable rtfs file copied there by hos-nm-launch).
private enum ulong SYNTHDIR_NMPLUGIN = 0x0E7C1B60;
private static immutable string[1] g_nmPluginEntries = ["libnm-device-plugin-wifi.so"];

public long linux_sys_getdents64(ulong fd, ulong dirp, ulong count) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024 || g_fdTable[ifd].type == FileType.FD_NONE) return negErrno(EBADF);
    File* f = &g_fdTable[ifd];
    if (!fileIsSyntheticDirectory(f) && !fileIsRtDirectory(f)) return negErrno(ENOTDIR);
    if (count == 0) return negErrno(EINVAL);

    auto buf = cast(ubyte*)dirp;
    size_t written = 0;
    if (f.offset == 0) {
        if (!writeDirent64(buf, count, &written, 1, 1, DT_DIR, ".".ptr, 1)) return cast(long)written;
        f.offset = 1;
    }
    if (f.offset == 1) {
        if (!writeDirent64(buf, count, &written, 1, 2, DT_DIR, "..".ptr, 2)) return cast(long)written;
        f.offset = 2;
    }

    // A4: /proc enumeration — one directory entry per live process (ps/top).
    if (f.fileSize == SYNTHDIR_PROC) {
        ulong logical = 2;
        for (int t = 0; t < MAX_TASKS; ++t) {
            if (!g_tasks[t].active || g_tasks[t].exited) continue;
            if (f.offset <= logical) {
                char[12] nb = void; size_t nl = 0;
                int pid = linuxPidForTask(t);
                { char[12] tmp = void; int ti = 0;
                  if (pid == 0) tmp[ti++] = '0';
                  while (pid > 0) { tmp[ti++] = cast(char)('0' + pid % 10); pid /= 10; }
                  while (ti > 0) nb[nl++] = tmp[--ti]; }
                if (!writeDirent64(buf, count, &written, cast(ulong)(t + 4096),
                                   cast(long)logical + 1, DT_DIR, nb.ptr, nl))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        return cast(long)written;
    }

    // F1: /objects/<kind> enumeration — one entry per live object of that kind.
    // F5: each object is now a DIRECTORY (of meta/capabilities/relationships).
    if (f.fileSize >= SYNTHDIR_OBJ_BASE && f.fileSize < SYNTHDIR_OBJ_BASE + 16) {
        const int kind = cast(int)(f.fileSize - SYNTHDIR_OBJ_BASE);
        ulong logical = 2;
        for (int li = 0; ; ++li) {
            char[64] nb = void;
            const int nl = objfsEnum(kind, li, nb.ptr, nb.length);
            if (nl < 0) break;
            if (f.offset <= logical) {
                if (!writeDirent64(buf, count, &written, cast(ulong)(li + 8192),
                                   cast(long)logical + 1, DT_DIR, nb.ptr, cast(size_t)nl))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        return cast(long)written;
    }
    // F5: /objects/<kind>/<obj> enumeration — the object's field files.
    // DM2.4: the tag now encodes the kind (SYNTHDIR_OBJ_ENTRY + kind) so domains (kind 5 =
    // OBJFS_DOMAINS) also list a "filesystem" field (the restricted-view RuntimeView).
    if (f.fileSize >= SYNTHDIR_OBJ_ENTRY && f.fileSize < SYNTHDIR_OBJ_ENTRY + 16) {
        const ulong okind = f.fileSize - SYNTHDIR_OBJ_ENTRY;
        static immutable string[3] baseFields = ["meta", "capabilities", "relationships"];
        ulong logical = 2;
        foreach (nm; baseFields) {
            if (f.offset <= logical) {
                if (!writeDirent64(buf, count, &written, logical + 61440,
                                   cast(long)logical + 1, DT_REG, nm.ptr, nm.length))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        if (okind == 5) {   // OBJFS_DOMAINS → add the RuntimeView field
            if (f.offset <= logical) {
                static immutable string fsName = "filesystem";
                if (!writeDirent64(buf, count, &written, logical + 61440,
                                   cast(long)logical + 1, DT_REG, fsName.ptr, fsName.length))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        return cast(long)written;
    }

    // F3: /system/current enumeration — the active generation's base components
    // (the boot modules) plus the `generation` metadata file.
    if (f.fileSize == SYNTHDIR_SYSCUR) {
        ulong logical = 2;
        // the generation metadata file first
        if (f.offset <= logical) {
            static immutable string gname = "generation";
            if (!writeDirent64(buf, count, &written, logical + 32768,
                               cast(long)logical + 1, DT_REG, gname.ptr, gname.length))
                return cast(long)written;
            f.offset = logical + 1;
        }
        ++logical;
        for (int li = 0; ; ++li) {
            char[128] nb = void;
            const int nl = sysComponentEnum(li, nb.ptr, nb.length);
            if (nl < 0) break;
            if (f.offset <= logical) {
                if (!writeDirent64(buf, count, &written, cast(ulong)(li + 40960),
                                   cast(long)logical + 1, DT_REG, nb.ptr, cast(size_t)nl))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        return cast(long)written;
    }

    // INSTALLER §D4.2: /system/state enumeration exposes the installed-state marker.
    if (f.fileSize == SYNTHDIR_SYSSTATE) {
        ulong logical = 2;
        static immutable string iname = "installed";
        if (f.offset <= logical) {
            if (!writeDirent64(buf, count, &written, logical + 33024,
                               cast(long)logical + 1, DT_REG, iname.ptr, iname.length))
                return cast(long)written;
            f.offset = logical + 1;
        }
        return cast(long)written;
    }

    // F4: /objects/apps enumeration — one entry per installed (persisted) app.
    if (f.fileSize == SYNTHDIR_APPS) {
        ulong logical = 2;
        for (int li = 0; ; ++li) {
            char[80] nb = void;
            const int nl = objstoreAppEnum(li, nb.ptr, nb.length);
            if (nl < 0) break;
            if (f.offset <= logical) {
                if (!writeDirent64(buf, count, &written, cast(ulong)(li + 49152),
                                   cast(long)logical + 1, DT_DIR, nb.ptr, cast(size_t)nl))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        return cast(long)written;
    }
    // F4: /objects/apps/<app> enumeration — the app object's files.
    if (f.fileSize >= SYNTHDIR_APP_BASE && f.fileSize < SYNTHDIR_APP_BASE + 4096) {
        static immutable string[5] files = ["manifest.json", "permissions.json",
                                            "identity-binding.json", "executable", "storage"];
        static immutable ubyte[5] types = [DT_REG, DT_REG, DT_REG, DT_REG, DT_DIR];
        ulong logical = 2;
        foreach (i, nm; files) {
            if (f.offset <= logical) {
                if (!writeDirent64(buf, count, &written, logical + 53248,
                                   cast(long)logical + 1, types[i], nm.ptr, nm.length))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        return cast(long)written;
    }
    // F4: /objects/apps/<app>/storage enumeration — the writable storage blob.
    if (f.fileSize >= SYNTHDIR_STOR_BASE && f.fileSize < SYNTHDIR_STOR_BASE + 4096) {
        ulong logical = 2;
        if (f.offset <= logical) {
            static immutable string dname = "data";
            if (!writeDirent64(buf, count, &written, logical + 57344,
                               cast(long)logical + 1, DT_REG, dname.ptr, dname.length))
                return cast(long)written;
            f.offset = logical + 1;
        }
        return cast(long)written;
    }

    // /sys/dev/char enumeration (input + DRM device discovery for libudev-zero).
    if (f.fileSize == SYNTHDIR_DEVCHAR) {
        ulong logical = 2;
        foreach (e; g_devCharEntries) {
            if (f.offset <= logical) {
                if (!writeDirent64(buf, count, &written, logical + 3, cast(long)logical + 1,
                                   DT_DIR, e.ptr, e.length))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        return cast(long)written;
    }

    // M3: /sys/class/net enumeration — one entry per interface so NM's nm-linux-platform (which readdirs
    // this dir) discovers wlan0 and classifies it as wifi (via wlan0/phy80211 + uevent DEVTYPE=wlan).
    if (f.fileSize == SYNTHDIR_NETCLASS) {
        ulong logical = 2;
        foreach (e; g_netClassEntries) {
            if (f.offset <= logical) {
                if (!writeDirent64(buf, count, &written, logical + 5, cast(long)logical + 1,
                                   DT_DIR, e.ptr, e.length))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        return cast(long)written;
    }

    // M3: NMPLUGINDIR enumeration — list the wifi plugin .so so NM's read_plugin_paths finds it (the file
    // is a real openable rtfs file; only the directory listing was missing).
    if (f.fileSize == SYNTHDIR_NMPLUGIN) {
        ulong logical = 2;
        foreach (e; g_nmPluginEntries) {
            if (f.offset <= logical) {
                if (!writeDirent64(buf, count, &written, logical + 7, cast(long)logical + 1,
                                   DT_REG, e.ptr, e.length))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        return cast(long)written;
    }

    // R3: /dev/dri enumeration — the DRM char nodes libdrm readdirs then stat()s
    // (drmGetDevice2 + drmGetDevices2 both opendir("/dev/dri")). Without this the
    // device list stays empty → no EGL render device → Weston disables dmabuf.
    if (f.fileSize == SYNTHDIR_DEVDRI) {
        static immutable string[2] driNodes = ["card0", "renderD128"];
        ulong logical = 2;
        foreach (nm; driNodes) {
            if (f.offset <= logical) {
                if (!writeDirent64(buf, count, &written, logical + 70000,
                                   cast(long)logical + 1, DT_CHR, nm.ptr, cast(size_t)nm.length))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        return cast(long)written;
    }

    // R3: /sys/dev/char/226:*/device/drm enumeration — the PCI device's DRM nodes;
    // libdrm scandirs this dir to set available_nodes (card0=PRIMARY, renderD128=RENDER).
    if (f.fileSize == SYNTHDIR_DRMDIR) {
        static immutable string[2] drmNodes = ["card0", "renderD128"];
        ulong logical = 2;
        foreach (nm; drmNodes) {
            if (f.offset <= logical) {
                if (!writeDirent64(buf, count, &written, logical + 61440,
                                   cast(long)logical + 1, DT_DIR, nm.ptr, cast(size_t)nm.length))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        return cast(long)written;
    }

    if (fileIsRtDirectory(f)) {
        const int dirIdx = cast(int)cast(size_t)f.backend;
        ulong logical = 2;
        for (int i = 1; i < RT_MAX_NODES; ++i) {
            if (g_rt[i].kind == RT_FREE || g_rt[i].parent != dirIdx) continue;
            if (f.offset <= logical) {
                const ubyte dtype = (g_rt[i].kind == RT_DIR) ? DT_DIR
                                  : (g_rt[i].kind == RT_LNK) ? DT_LNK : DT_REG;
                if (!writeDirent64(buf, count, &written, cast(ulong)i + 1,
                                   cast(long)logical + 1, dtype,
                                   g_rt[i].name.ptr, g_rt[i].nameLen))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        // F1: /objects also lists the synthetic object kinds alongside its RT children.
        // F4 adds the persisted "apps" collection (DT_DIR) + the "store" info file.
        if (dirIdx == g_objectsDirIdx) {
            static immutable string[6] kinds = ["identities", "services", "namespaces", "users", "domains", "apps"];
            foreach (k; kinds) {
                if (f.offset <= logical) {
                    if (!writeDirent64(buf, count, &written, logical + 16384,
                                       cast(long)logical + 1, DT_DIR, k.ptr, k.length))
                        return cast(long)written;
                    f.offset = logical + 1;
                }
                ++logical;
            }
            if (f.offset <= logical) {
                static immutable string sname = "store";
                if (!writeDirent64(buf, count, &written, logical + 16384,
                                   cast(long)logical + 1, DT_REG, sname.ptr, sname.length))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
        }
        // F2: /config lists the generated declarative JSON documents.
        if (dirIdx == g_configDirIdx) {
            for (int li = 0; ; ++li) {
                char[32] nb = void;
                const int nl = configfsEnum(li, nb.ptr, nb.length);
                if (nl < 0) break;
                if (f.offset <= logical) {
                    if (!writeDirent64(buf, count, &written, logical + 24576,
                                       cast(long)logical + 1, DT_REG, nb.ptr, cast(size_t)nl))
                        return cast(long)written;
                    f.offset = logical + 1;
                }
                ++logical;
            }
        }
        // F3: /system lists the active deployment + the generations document.
        if (dirIdx == g_systemDirIdx) {
            static immutable string[3] names = ["current", "generations", "state"];
            static immutable ubyte[3]  types = [DT_DIR, DT_REG, DT_DIR];
            foreach (i, nm; names) {
                if (f.offset <= logical) {
                    if (!writeDirent64(buf, count, &written, logical + 28672,
                                       cast(long)logical + 1, types[i], nm.ptr, nm.length))
                        return cast(long)written;
                    f.offset = logical + 1;
                }
                ++logical;
            }
        }
    }

    return cast(long)written;
}

// --- gettimeofday ---
private struct linux_timeval   { long tv_sec; long tv_usec; }
private struct linux_timezone  { int tz_minuteswest; int tz_dsttime; }

public long linux_sys_gettimeofday(ulong tv, ulong tz) {
    if (tv) { auto t = cast(linux_timeval*)tv;  t.tv_sec = 0; t.tv_usec = 0; }
    if (tz) { auto z = cast(linux_timezone*)tz; z.tz_minuteswest = 0; z.tz_dsttime = 0; }
    return 0;
}

// --- nanosleep / clock_nanosleep ---
private struct linux_timespec { long tv_sec; long tv_nsec; }

public long linux_sys_nanosleep(ulong req, ulong rem) {
    if (rem) { auto r = cast(linux_timespec*)rem; r.tv_sec = 0; r.tv_nsec = 0; }
    return 0;
}
public long linux_sys_clock_nanosleep(ulong clk, ulong fl, ulong req, ulong rem) {
    return linux_sys_nanosleep(req, rem);
}
public long linux_sys_clock_getres(ulong clk, ulong res) {
    if (res) { auto r = cast(linux_timespec*)res; r.tv_sec = 0; r.tv_nsec = 1000000; }
    return 0;
}

// L3a: the userspace LKL PCI backend reaches EpinAnonymOS's native PCI through this custom syscall
// (number EPIN_SYS_LKL_PCI = 0x4100, routed in the dispatcher). bdf = (bus<<16)|(slot<<8)|func.
//   op 0: config READ  (size 1/2/4 at `off`)        -> value
//   op 1: config WRITE (size 1/2/4 at `off`, `val`) -> 0
//   op 2: SCAN — return the bdf of the first non-host-bridge PCI device (so the backend's .add can
//         pick a device without the bdf being known up front), or -1 if none.
// ---- L4: per-device capability gating for the LKL hardware bridge -----------------
// Each PROCESS may hold a capability for one PCI device (the "one LKL per device" isolation
// model the user requires): the 0x4100 bridge below denies any scan/config/MMIO for a device
// the caller was not explicitly granted, so an LKL driver sees ONLY its own hardware and can
// never reach (or even enumerate) another device.  Keyed on the process leader so all of an
// LKL's threads (its timer + IRQ-poller pthreads) share the one grant.
struct DeviceCap {
    bool     valid;
    uint     bdf;            // (bus<<16)|(slot<<8)|func
    ulong[6] barBase;        // BAR physical base (0 = unused)
    ulong[6] barEnd;         // base + size - 1
}
// A process may be granted SEVERAL devices (a single LKL driving e.g. the AX210 WiFi + the xHCI USB
// controller, each on its own PCI bus).  The grant is still per-process-leader + deny-by-default: only
// the explicitly-granted bdfs are visible/usable through the 0x4100 bridge.
enum int MAX_TASK_DEVS = 4;
__gshared DeviceCap[MAX_TASK_DEVS][MAX_TASKS] g_taskDevCap;
__gshared ulong g_lklInjLog = 0;   // L5 input bridge: log the first few injected events (verification)

private int devCapLeader(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return -1;
    const int p = g_tasks[tid].processLeaderTid;
    return (p >= 0 && p < MAX_TASKS) ? p : tid;
}
// SMP_ROADMAP S8: a leaf lock for the per-task device-cap table — makes the device bridge
// SMP-safe (so a per-device LKL pinned to its own core can grant/check caps without racing
// the BSP).  Wrapper pattern (single acquire/release).  Leaf: never held while taking the BKL.
private __gshared uint g_devCapLock = 0;
private uint dcTryLock(uint* p) { uint old=void; asm @nogc nothrow { mov RDX,p; mov EAX,1; xchg [RDX],EAX; mov old,EAX; } return old; }
private void dcUnlock(uint* p) { asm @nogc nothrow { mov RDX,p; xor EAX,EAX; mov [RDX],EAX; } }
private void dcLockAcq() { while (dcTryLock(&g_devCapLock) != 0) {} }
private void dcLockRel() { dcUnlock(&g_devCapLock); }

public bool taskHasDevCap(int tid, uint bdf) {
    dcLockAcq();
    bool r = false;
    const int p = devCapLeader(tid);
    if (p >= 0)
        foreach (j; 0 .. MAX_TASK_DEVS)
            if (g_taskDevCap[p][j].valid && g_taskDevCap[p][j].bdf == bdf) { r = true; break; }
    dcLockRel();
    return r;
}
public bool taskHasMmioCap(int tid, ulong phys) {
    dcLockAcq();
    bool r = false;
    const int p = devCapLeader(tid);
    if (p >= 0)
        outer: foreach (j; 0 .. MAX_TASK_DEVS) {
            auto c = &g_taskDevCap[p][j];
            if (!c.valid) continue;
            foreach (i; 0 .. 6)
                if (c.barBase[i] != 0 && phys >= c.barBase[i] && phys <= c.barEnd[i]) { r = true; break outer; }
        }
    dcLockRel();
    return r;
}
// Enumerate a process's granted devices by index (for the LKL host to create one PCI bus per device).
// Returns the idx-th granted bdf, or -1 when there are no more.  Grants are packed from slot 0.
public long taskGrantedDevByIndex(int tid, int idx) {
    dcLockAcq();
    long r = -1;
    const int p = devCapLeader(tid);
    if (p >= 0 && idx >= 0 && idx < MAX_TASK_DEVS && g_taskDevCap[p][idx].valid)
        r = cast(long)g_taskDevCap[p][idx].bdf;
    dcLockRel();
    return r;
}
// Grant PROCESS-leader task `tid` a capability for device `bdf` (records bdf + sizes its MMIO BARs).
// Privileged: only the kernel / a device-manager calls this — it is NOT reachable through the 0x4100 ABI.
public void grantDeviceCap(int tid, uint bdf) { dcLockAcq(); grantDeviceCap_impl(tid, bdf); dcLockRel(); }
private void grantDeviceCap_impl(int tid, uint bdf) {
    import drivers.pci : pciConfigRead32, pciConfigWrite32;
    const int p = devCapLeader(tid);
    if (p < 0) return;
    // APPEND to the process's device list: reuse a slot already holding this bdf, else the first free
    // slot.  (Was a single overwrite; now a process can hold several devices — e.g. AX210 + xHCI.)
    int di = -1;
    foreach (j; 0 .. MAX_TASK_DEVS) {
        if (g_taskDevCap[p][j].valid && g_taskDevCap[p][j].bdf == bdf) { di = j; break; }
        if (di < 0 && !g_taskDevCap[p][j].valid) di = j;
    }
    if (di < 0) return;                 // device-cap table full for this process
    auto c = &g_taskDevCap[p][di];
    *c = DeviceCap.init;
    c.valid = true;
    c.bdf   = bdf;
    const ubyte bus  = cast(ubyte)((bdf >> 16) & 0xFF);
    const ubyte slot = cast(ubyte)((bdf >> 8)  & 0xFF);
    const ubyte func = cast(ubyte)( bdf        & 0xFF);
    int i = 0;
    while (i < 6) {
        const ubyte o = cast(ubyte)(0x10 + i*4);
        const uint orig = pciConfigRead32(bus, slot, func, o);
        if (orig == 0 || (orig & 0x1)) { i++; continue; }      // empty or I/O-space BAR (we gate MMIO only)
        const bool is64 = ((orig & 0x6) == 0x4);
        pciConfigWrite32(bus, slot, func, o, 0xFFFFFFFF);
        const uint maskLo = pciConfigRead32(bus, slot, func, o);
        pciConfigWrite32(bus, slot, func, o, orig);            // restore the firmware-assigned BAR
        ulong base = orig & 0xFFFFFFF0UL;
        ulong size;
        if (is64) {
            const ubyte oh = cast(ubyte)(o + 4);
            const uint origHi = pciConfigRead32(bus, slot, func, oh);
            pciConfigWrite32(bus, slot, func, oh, 0xFFFFFFFF);
            const uint maskHi = pciConfigRead32(bus, slot, func, oh);
            pciConfigWrite32(bus, slot, func, oh, origHi);      // restore
            base |= (cast(ulong)origHi << 32);
            const ulong mask = (cast(ulong)maskHi << 32) | (maskLo & 0xFFFFFFF0U);
            size = (~mask) + 1;
        } else {
            const uint mask = maskLo & 0xFFFFFFF0U;
            size = cast(ulong)(cast(uint)(~mask) + 1);
        }
        if (size != 0 && base != 0) { c.barBase[i] = base; c.barEnd[i] = base + size - 1; }
        i += is64 ? 2 : 1;
    }
}
// Find the first device matching class (base<<8|sub) — for the bootstrap grant. 0xFFFFFFFF = none.
public uint findDeviceByClass(uint cls) {
    import drivers.pci : pciConfigRead32, scanPCIDevices;
    auto devs = scanPCIDevices();
    foreach (ref d; devs) {
        const uint clsReg = pciConfigRead32(d.bus, d.slot, d.func, 8);
        if (((((clsReg >> 24) & 0xFF) << 8) | ((clsReg >> 16) & 0xFF)) == cls) {
            // The LKL must NEVER be handed EpinOS's own virtio devices — above all the virtio-gpu it
            // uses for the desktop (under GPU=1 the virtio-gpu-gl is class 0x0380, so without this it
            // gets granted to the LKL; the LKL touching it corrupts the host-visible blob region and
            // QEMU aborts: KVM_SET_USER_MEMORY_REGION failed).  Skip virtio (vendor 0x1AF4); the LKL's
            // real targets (bochs-display 0x1234, qemu-xhci, NVMe, bare-metal nouveau 0x10DE) are not.
            const uint ven = pciConfigRead32(d.bus, d.slot, d.func, 0) & 0xFFFF;
            if (ven == 0x1AF4) continue;
            return (cast(uint)d.bus << 16) | (cast(uint)d.slot << 8) | d.func;
        }
    }
    return 0xFFFFFFFF;
}

// L5 kernel-side INTx wake: the bdf the task's PROCESS was granted, or 0xFFFFFFFF if none.
public uint taskGrantedBdf(int tid) {
    dcLockAcq();
    const int p = devCapLeader(tid);
    const uint r = (p >= 0 && g_taskDevCap[p][0].valid) ? g_taskDevCap[p][0].bdf : 0xFFFFFFFFu;  // first device
    dcLockRel();
    return r;
}
// WiFi W1: MSI delivery.  The AX210 is MSI-X-native and does NOT raise a cause the legacy
// INTx path can see, so we program its MSI capability to fire IDT vector 0x30 on the BSP
// LAPIC; the asm handler bumps g_msiIrqCount.  op6 (the LKL IRQ wait) treats a count delta
// as "interrupt pending" and wakes the driver's ISR.
extern extern(C) __gshared ulong g_msiIrqCount;   // asm.S msiHandler bumps this per MSI
__gshared uint  g_msiDeviceBdf = 0xFFFFFFFF;      // WiFi BDF only, for iwlwifi CSR diagnostics
__gshared ulong g_msiLastSeen  = 0;               // op6's last-observed g_msiIrqCount
__gshared uint  g_msiAddrLo = 0, g_msiData = 0;   // the programmed MSI message (for the on-screen HUD)
__gshared bool  g_msiSetupDone = false;
private enum uint MSI_VECTOR = 0x30;
// Persistent on-screen MSI diagnostic (row 2, under the WiFi survey): shows the programmed
// message + the LIVE fire count, so we can tell if the AX210's MSI is actually reaching
// vector 0x30 (fires>0) or not (fires=0 → address/data/enable problem, not a downstream one).
public void msiHudRepaint() @nogc nothrow {
    import arch.x86_64.bootstrap : fb_draw_hud_row;
    if (!g_msiSetupDone) return;
    static immutable char[16] hx = "0123456789abcdef";
    char[80] b; int n = 0;
    void put(string s) @nogc nothrow { foreach (c; s) if (n < 79) b[n++] = c; }
    void hex(uint v) @nogc nothrow { for (int i = 7; i >= 0; --i) if (n < 79) b[n++] = hx[(v >> (i*4)) & 0xF]; }
    void dec(ulong v) @nogc nothrow { char[20] t; int m = 0; if (v == 0) t[m++] = '0'; while (v && m < 20) { t[m++] = cast(char)('0' + v % 10); v /= 10; } while (m && n < 79) b[n++] = t[--m]; }
    put("MSI addr=0x"); hex(g_msiAddrLo); put(" data=0x"); hex(g_msiData);
    put(" bsp="); hex(g_bspApicId); put(" FIRES="); dec(g_msiIrqCount);
    b[n] = 0;
    fb_draw_hud_row(32, b.ptr);
}
// The BSP's x2APIC ID, captured ONCE on the BSP at boot (kernel_main.d).  The MSI MUST target
// the BSP — vector 0x30 (msiHandler) lives only in the BSP IDT.  Reading MSR 0x802 inside op9
// is wrong: LKL is multi-threaded and the probe thread may run on an AP, giving that AP's ID
// (observed 0x20 → addr 0xFEE20000) so the MSI lands on a CPU with no 0x30 handler → FIRES=0.
__gshared uint g_bspApicId = 0;
public uint readApicId() @nogc nothrow {   // the CURRENT cpu's x2APIC ID
    uint id;
    asm @nogc nothrow { mov ECX, 0x802; rdmsr; mov id, EAX; }
    return id;
}
// True (once) when any MSI arrived since op6 last checked.  Every LKL-owned device programs the
// same native vector, and the LKL embedder deliberately raises every registered Linux IRQ so each
// driver's handler can inspect/ack its own cause.  This therefore must NOT be gated by one BDF:
// xHCI commonly configures MSI after the AX210, and the old BDF gate then dropped all WiFi events.
public bool lklMsiPending() @nogc nothrow {
    const ulong now = g_msiIrqCount;
    if (now != g_msiLastSeen) { g_msiLastSeen = now; return true; }
    return false;
}

// W1 POLLED-INTERRUPT FALLBACK.  Even with the MSI aimed at the BSP + unmasked, the raw MSI
// write may never reach the LAPIC (VT-d interrupt-remapping drops compat-format MSIs; or a
// residual mask).  So instead of RELYING on MSI delivery, POLL the device's interrupt-status
// register and wake the driver's ISR when a cause is pending — a software-synthesised interrupt.
// We force iwlwifi onto single-MSI + non-ICT (LKL patches), so the authoritative register is
// CSR_INT (BAR0+0x008): a status/ACK register the driver clears by writing back, so merely
// READING it here does NOT steal the cause.  ALIVE = bit 0 (CSR_INT_BIT_ALIVE).
__gshared uint g_wifiCsrInt  = 0;     // last-read CSR_INT (0x008) — for the HUD
__gshared uint g_wifiCsrIntSeen = 0;  // STICKY-OR of every raw CSR_INT bit ever polled (regardless of
                                      // mask). Latches brief fw-error transients (SW_ERR=1<<25 / HW_ERR=
                                      // 1<<29) the ~1Hz diag sample would miss → splits "fw crashed on the
                                      // PNVM handshake" from "fw fully silent". Filter "wifi-irq" → INT_SEEN.
__gshared uint g_wifiCsrFh   = 0;     // last-read CSR_FH_INT_STATUS (0x010)
__gshared uint g_wifiCsrMask = 0;     // last-read CSR_INT_MASK (0x00C, host interrupt enable)
__gshared uint g_wifiMsixFh  = 0;     // last-read CSR_MSIX_FH_INT_CAUSES_AD (0x2800) — MSI-X mode
__gshared uint g_wifiMsixHw  = 0;     // last-read CSR_MSIX_HW_INT_CAUSES_AD (0x2808) — MSI-X mode
// op6 rate-limit: the LKL irq thread fires lkl_trigger_irq on EVERY op6 return, so a CSR cause
// that stays pending would make op6 return instantly forever → lkl_trigger_irq spam → the LKL's
// own main/threaded handler starves (firmware-alive livelock, LKL clock frozen).  After a
// CSR-driven wake we PARK until this deadline (≈2ms), yielding the cpu so the driver can drain.
public __gshared ulong g_wifiCsrCooldownMs = 0;
public __gshared ulong g_wifiCsrWakeCount = 0;      // all CSR-driven synthetic wakes (diagnostic)
public __gshared ulong g_wifiCsrMask0WakeCount = 0; // bounded recovery wakes while the hard ISR has mask=0

// Read the wifi device's iwlwifi CSR register at BAR0+regOff through the HHDM.  BAR0 is a
// 64-bit memory BAR (cfg 0x10 low / 0x14 high); the CSR block lives in its first page and is
// reachable via the direct map exactly like op3's MMIO reads.
private uint wifiCsrRead(uint bdf, uint regOff) @nogc nothrow {
    import drivers.pci : pciConfigRead32;
    import core.globals : hhdm_offset;
    import ldc.llvmasm;
    const ubyte bus  = cast(ubyte)((bdf >> 16) & 0xFF);
    const ubyte slot = cast(ubyte)((bdf >> 8)  & 0xFF);
    const ubyte func = cast(ubyte)( bdf        & 0xFF);
    const uint b0 = pciConfigRead32(bus, slot, func, 0x10);
    ulong base = cast(ulong)(b0 & ~0xFu);
    if ((b0 & 0x6) == 0x4)                                   // 64-bit BAR → high dword at 0x14
        base |= cast(ulong)pciConfigRead32(bus, slot, func, 0x14) << 32;
    if (base == 0) return 0xFFFFFFFF;
    const ulong va = base + regOff + hhdm_offset;
    // ★★ Device MMIO MUST be read UNCACHED.  The HHDM maps this BAR page WRITE-BACK, but op8 now
    // hands the LKL iwlwifi driver a SEPARATE strong-UC mapping (0x7E.. VA) of the SAME physical BAR
    // page.  Two mappings with conflicting cacheability is architecturally undefined on x86: the WB
    // cache line THIS read hits is never refreshed by the driver's UC accesses, so a plain load
    // returns a STALE copy that MISSES the device's autonomous CSR_INT=ALIVE update.  That silently
    // broke op6's wake decision (wifiCsrPending) after direct-map landed → the ISR never runs → the
    // firmware ALIVE notification is never processed → "Failed to run INIT ucode: -110" (firmware ran
    // to LMAC PC 0xd05c1c then reset to 0xd0 after the 2s timeout).  Before direct-map, the driver AND
    // this poll shared the one WB HHDM mapping, so the line stayed fresh — which is why it regressed.
    // CLFLUSH the line (+ fence) so every CSR read fetches the device's LIVE value regardless of the
    // alias; the read-miss on a WB-mapped MMIO address goes straight to the device.  (No-op under QEMU,
    // which doesn't model caches, so this stays safe there.)
    __asm("clflush ($0)\n\tmfence", "r,~{memory}", va);
    return *cast(shared const uint*)va;
}

// Refresh the CSR HUD values (safe to call from the present path — pure MMIO reads, no clear).
public void wifiCsrRefresh() @nogc nothrow {
    if (g_msiDeviceBdf == 0xFFFFFFFF || !g_msiSetupDone) return;
    g_wifiCsrInt  = wifiCsrRead(g_msiDeviceBdf, 0x008);      // CSR_INT
    g_wifiCsrMask = wifiCsrRead(g_msiDeviceBdf, 0x00C);      // CSR_INT_MASK
    g_wifiCsrFh   = wifiCsrRead(g_msiDeviceBdf, 0x010);      // CSR_FH_INT_STATUS
}

// op6 wake source: is a CSR_INT cause pending on the wifi device?
// Normally mirror real hardware and wake only for an enabled cause.  There is one important LKL
// recovery case: iwl_pcie_isr masks CSR_INT before its threaded handler drains RX and restores the
// mask.  If that handoff is lost, gating forever on mask==0 deadlocks with an already-DMA'd RX
// completion sitting in host RAM (the AX210 PNVM_INIT_COMPLETE failure).  Permit a mask-zero kick
// at most once per 2 ms so the one active Linux IRQ can resume the threaded handler without turning
// a persistent cause into the old tight lkl_trigger_irq storm.
public bool wifiCsrPending() @nogc nothrow {
    const uint bdf = g_msiDeviceBdf;
    if (bdf == 0xFFFFFFFF || !g_msiSetupDone) return false;

    // MSI-X cause registers — DIAGNOSTIC READ ONLY (do NOT wake on them).  We run single-MSI (arch/lkl
    // pci.c refuses MSI-X): the fw signals via legacy CSR_INT below.  Waking op6 on the MSI-X causes
    // storm-hogged the CPU when MSI-X was briefly enabled (a persistent un-acked FH cause + FIRES=0),
    // and it didn't fix the cmd-fetch anyway.  Keep the read so [wifi-irq] still shows MSIX_FH/HW.
    g_wifiMsixFh = wifiCsrRead(bdf, 0x2800);                 // CSR_MSIX_FH_INT_CAUSES_AD
    g_wifiMsixHw = wifiCsrRead(bdf, 0x2808);                 // CSR_MSIX_HW_INT_CAUSES_AD

    // ── legacy single-MSI mode ─────────────────────────────────────────────────
    const uint ci = wifiCsrRead(bdf, 0x008);                 // CSR_INT (status)
    g_wifiCsrInt = ci;
    if (ci != 0xFFFFFFFF) g_wifiCsrIntSeen |= ci;            // sticky-latch raw causes (fw-error transients)
    if (ci == 0 || ci == 0xFFFFFFFF) return false;           // nothing pending / device not accessible
    const uint mask = wifiCsrRead(bdf, 0x00C);               // CSR_INT_MASK (host interrupt enable)
    g_wifiCsrMask = mask;
    if (mask == 0xFFFFFFFF) return false;                    // device not accessible
    if (mask == 0) {
        const ulong nowMs = pitMs();
        if (nowMs < g_wifiCsrCooldownMs) return false;
        g_wifiCsrCooldownMs = nowMs + 2;
        ++g_wifiCsrWakeCount;
        ++g_wifiCsrMask0WakeCount;
        return true;
    }
    const bool pending = (ci & mask) != 0;                    // only an ENABLED cause → run the ISR (no storm)
    if (pending) ++g_wifiCsrWakeCount;
    return pending;
}

// Persistent HUD (row 3): the live CSR_INT / FH status, so we can SEE whether the firmware ever
// raises ALIVE (CSR_INT bit0=1) even when the MSI count stays 0 → splits "not delivered" (poll
// fixes it) from "firmware never came alive" (a deeper firmware problem).
public void wifiCsrHudRepaint() @nogc nothrow {
    import arch.x86_64.bootstrap : fb_draw_hud_row;
    if (!g_msiSetupDone) return;
    wifiCsrRefresh();
    static immutable char[16] hx = "0123456789abcdef";
    char[80] b; int n = 0;
    void put(string s) @nogc nothrow { foreach (c; s) if (n < 79) b[n++] = c; }
    void hex(uint v) @nogc nothrow { for (int i = 7; i >= 0; --i) if (n < 79) b[n++] = hx[(v >> (i*4)) & 0xF]; }
    put("CSR_INT=0x"); hex(g_wifiCsrInt); put(" MASK=0x"); hex(g_wifiCsrMask);
    put(" ALIVE="); b[n++] = (g_wifiCsrInt & 1) ? '1' : '0';
    b[n] = 0;
    fb_draw_hud_row(48, b.ptr);
}

// WiFi W1 diagnostic → /run/klog.  The AX210's interrupt path is the open blocker: firmware loads but
// the fw-reset/ALIVE interrupt may never reach the driver (MSI dropped by VT-d, or a cause-register/mode
// issue).  Emit the DECISIVE numbers to the kernel log ring at ~1 Hz so they're readable in the desktop
// Logs viewer (filter "wifi-irq") on real hardware with no serial:
//   FIRES   = g_msiIrqCount — how many times the device's MSI actually reached vector 0x30 on the BSP.
//             0 => the MSI write never lands (VT-d remap / masking) — the CSR poll fallback is needed.
//   CSR_INT = the device's live interrupt-status register.  bit0=ALIVE.  Non-zero => firmware IS raising
//             causes (so re-enabling the mask-gated CSR poll would deliver them); 0 => nothing pending.
//   MASK    = CSR_INT_MASK (host interrupt enable).  INTx = legacy PCI interrupt-status bit.
__gshared ulong g_wifiIrqDiagLastMs = 0;
public void wifiIrqDiagKlog() @nogc nothrow {
    if (g_msiDeviceBdf == 0xFFFFFFFF || !g_msiSetupDone) return;
    const ulong nowMs = pitMs();
    if (nowMs - g_wifiIrqDiagLastMs < 1000) return;         // ~1 Hz (cheap: a few MMIO reads)
    g_wifiIrqDiagLastMs = nowMs;
    wifiCsrRefresh();                                        // refresh CSR_INT / MASK / FH (pure reads, no ACK)
    g_wifiMsixFh = wifiCsrRead(g_msiDeviceBdf, 0x2800);      // CSR_MSIX_FH_INT_CAUSES_AD
    g_wifiMsixHw = wifiCsrRead(g_msiDeviceBdf, 0x2808);      // CSR_MSIX_HW_INT_CAUSES_AD
    klog("[wifi-irq] FIRES="); klog_dec(g_msiIrqCount);
    klog(" INTx="); klog_dec(deviceIntxAsserted(g_msiDeviceBdf) ? 1 : 0);
    klog(" CSR_INT=0x"); klog_hex(g_wifiCsrInt);
    klog(" MASK=0x"); klog_hex(g_wifiCsrMask);
    klog(" MSIX_FH=0x"); klog_hex(g_wifiMsixFh);            // MSI-X mode: FH causes (RX/TX)
    klog(" MSIX_HW=0x"); klog_hex(g_wifiMsixHw);            // MSI-X mode: HW causes (ALIVE bit0)
    klog(" ALIVE="); klog_dec((g_wifiCsrInt & 1) ? 1 : 0);
    klog(" CSR_WAKES="); klog_dec(g_wifiCsrWakeCount);
    klog(" MASK0_WAKES="); klog_dec(g_wifiCsrMask0WakeCount);
    // Sticky raw-cause latch: did the fw EVER raise SW_ERR (uCode crash, bit25) or HW_ERR (bit29)?
    // If FWERR=1 the -110 is a firmware crash (e.g. on the -83 PNVM handshake), not a missed interrupt.
    klog(" INT_SEEN=0x"); klog_hex(g_wifiCsrIntSeen);
    klog(" FWERR="); klog_dec((g_wifiCsrIntSeen & 0x22000000) ? 1 : 0);   // SW_ERR(1<<25)|HW_ERR(1<<29)
    klog(" bdf=0x"); klog_hex(g_msiDeviceBdf); klog("\n");
}

// L5 kernel-side INTx wake: is the device's PCI Status "Interrupt Status" bit set (a level-triggered
// INTx is asserted while the device has an unacked interrupt)?  Status is the high half of cfg 0x04.
public bool deviceIntxAsserted(uint bdf) {
    import drivers.pci : pciConfigRead32;
    const ubyte bus  = cast(ubyte)((bdf >> 16) & 0xFF);
    const ubyte slot = cast(ubyte)((bdf >> 8)  & 0xFF);
    const ubyte func = cast(ubyte)( bdf        & 0xFF);
    const uint status = (pciConfigRead32(bus, slot, func, 0x04) >> 16) & 0xFFFF;
    return (status & 0x08) != 0;   // bit 3 = Interrupt Status
}

// L6.1: bump allocator for op8 device-BAR mappings — a dedicated high VA range, deliberately clear of
// the LKL process's stack (0x70..) and thread stacks (0x74..).  See op8 for why this can't be g_nextMmapAddr.
private __gshared ulong g_lklBarNextVA = 0x7E0000000000UL;

// ── DECOY_DISTRO US5: LKL DMA bounce for the no-IOMMU path ────────────────────────
// The LKL's "physical RAM" (a memfd) is backed by pages allocated ONE AT A TIME
// (mmap.d / dma.d), so a buffer that is contiguous in the LKL's view is backed by
// PHYSICALLY-SCATTERED host pages.  op5 (map_page) can only return ONE physical
// address; a device that DMAs `sz` bytes linearly from it therefore writes past the
// first page into UNRELATED physical memory once the buffer spans >1 page — the
// no-IOMMU bulk-DMA corruption that hard-freezes the FW13.  (Small usbhid DMA fits one
// page → fine; bulk usb-storage does not.  It "works" in QEMU only because a fresh
// boot's sequential allocations happen to be contiguous.)
//
// Fix: for a multi-page map whose pages are NOT physically contiguous, DMA through a
// truly-contiguous BOUNCE buffer (alloc_phys_pages — the real contiguous allocator).
// Copy-on-BOTH-ends makes it direction-agnostic (map_page/unmap_page don't carry the
// DMA direction): copy caller→bounce on map, bounce→caller on unmap.  Contiguous maps
// (all of QEMU, all small WiFi DMA) take the fast path unchanged → non-regressive.
enum uint LKL_DMA_MAXBYTES = 256 * 1024;      // usb-storage transfers are <= ~240 KB
enum uint LKL_DMA_SLOTS    = 24;               // 24 * 256 KB = 6 MB bounce pool (lazy)
struct LklBounce { ulong bouncePhys; ulong bounceVirt; ulong callerVirt; uint size; bool inUse; }
__gshared LklBounce[LKL_DMA_SLOTS] g_lklBounce;
__gshared bool g_lklBounceInit = false;
__gshared uint g_lklDmaLog = 0;                // rate-limit the diagnostic
__gshared bool g_lklForceBounce = false;       // US5: force every multi-page map to bounce (test hook; QEMU-proved the bounce path is correct)

private void lklBounceInit() {
    import memory.mm : alloc_phys_pages;
    import core.globals : hhdm_offset;
    foreach (ref b; g_lklBounce) {
        const ulong phys = alloc_phys_pages(LKL_DMA_MAXBYTES / 4096);
        if (phys == 0) { b.bouncePhys = 0; continue; }   // pool partially allocated is fine
        b.bouncePhys = phys; b.bounceVirt = phys + hhdm_offset; b.inUse = false;
    }
    g_lklBounceInit = true;
}

// Return true iff [va, va+sz) is backed by physically-contiguous pages.
private bool lklRangeContiguous(ulong va, ulong sz) {
    import core.addrspace : activeVirtToPhys;
    ulong p0 = activeVirtToPhys(va & ~0xFFFUL);
    if (p0 == 0) return false;
    const ulong last = (va + sz - 1) & ~0xFFFUL;
    ulong expect = p0;
    for (ulong pg = va & ~0xFFFUL; pg <= last; pg += 4096) {
        const ulong p = activeVirtToPhys(pg);
        if (p == 0 || (p & ~0xFFFUL) != (expect & ~0xFFFUL)) return false;
        expect += 4096;
    }
    return true;
}

// op5 map: translate a DMA buffer's virt→phys, bouncing if multi-page + non-contiguous.
private long lklDmaMap(ulong va, ulong sz) {
    import core.addrspace : activeVirtToPhys;
    import core.stdc.string : memcpy;
    import core.kernel_main : debugUsbBootPresent, wifiDmaBounceBootPresent;
    const ulong phys = activeVirtToPhys(va);
    // US5 / US5b: the bounce fixes non-contiguous multi-page DMA corruption. It is needed for
    // usb-storage's bulk DMA (/epin-usb.conf) AND — the reason it exists here — for the AX210 FIRMWARE
    // load: a large host->device DMA whose scattered backing pages make op5's single-address return
    // corrupt pages 2..N -> bad LMAC ucode -> "Failed to start RT ucode -110" (LMAC PC 0xd0),
    // intermittently.  Gated OFF on plain WiFi boots (it once broke streaming-RX scanning); enabled for
    // WiFi ONLY when /epin-wifi-dma-bounce.conf is staged (WIFI_DMA_BOUNCE=1) so the fix is A/B-testable.
    if (!debugUsbBootPresent() && !wifiDmaBounceBootPresent())
        return cast(long)phys;                          // no bounce requested: original single-address op5
    // US5 TEST: g_lklForceBounce forces EVERY multi-page map through the bounce (QEMU proof).
    if (sz <= 4096 || (!g_lklForceBounce && lklRangeContiguous(va, sz)))
        return cast(long)phys;                          // fast path: single page or contiguous
    // Non-contiguous multi-page buffer → the corruption case. Bounce it.
    if (g_lklDmaLog < 32) {
        klog("[lkl-dma] NON-CONTIGUOUS map va=0x"); klog_hex(va);
        klog(" sz=0x"); klog_hex(sz); klog(" -> BOUNCE\n"); ++g_lklDmaLog;
    }
    if (!g_lklBounceInit) lklBounceInit();
    if (sz > LKL_DMA_MAXBYTES) {
        klog("[lkl-dma] BUG: DMA sz=0x"); klog_hex(sz); klog(" > bounce max — corruption risk\n");
        return cast(long)phys;                          // degrade loudly (should not happen for usb-storage)
    }
    foreach (ref b; g_lklBounce) {
        if (b.bouncePhys == 0 || b.inUse) continue;
        b.inUse = true; b.callerVirt = va; b.size = cast(uint)sz;
        memcpy(cast(void*)b.bounceVirt, cast(void*)va, sz);   // caller→bounce (correct for device reads)
        return cast(long)b.bouncePhys;
    }
    klog("[lkl-dma] BUG: bounce pool exhausted — corruption risk\n");
    return cast(long)phys;                              // degrade loudly
}

// op12 unmap: if `h` is a bounce, copy bounce→caller and free the slot.
private void lklDmaUnmap(ulong h) {
    import core.stdc.string : memcpy;
    foreach (ref b; g_lklBounce) {
        if (b.inUse && b.bouncePhys == h) {
            memcpy(cast(void*)b.callerVirt, cast(void*)b.bounceVirt, b.size);  // bounce→caller (device writes)
            b.inUse = false;
            return;
        }
    }
}

public long linux_sys_epin_lkl_pci(ulong op, ulong bdf, ulong off, ulong size, ulong val) {
    import drivers.pci : pciConfigRead32, pciConfigWrite32, scanPCIDevices;
    import core.globals : hhdm_offset;
    import core.addrspace : activeVirtToPhys;
    const ubyte bus  = cast(ubyte)((bdf >> 16) & 0xFF);
    const ubyte slot = cast(ubyte)((bdf >> 8)  & 0xFF);
    const ubyte func = cast(ubyte)( bdf        & 0xFF);
    const int  tid   = cast(int)g_current_task_id;   // L4: the calling LKL's task (resolved to its process)
    switch (op) {
        case 0: {                                   // config read
            if (!taskHasDevCap(tid, cast(uint)bdf)) return negErrno(EPERM);   // L4: not your device
            const uint dw = pciConfigRead32(bus, slot, func, cast(ubyte)(off & 0xFC));
            const uint sh = cast(uint)((off & 3) * 8);
            const uint v  = dw >> sh;
            if (size == 1) return v & 0xFF;
            if (size == 2) return v & 0xFFFF;
            return cast(long)cast(uint)v;
        }
        case 1: {                                   // config write (read-modify-write for sub-dword)
            if (!taskHasDevCap(tid, cast(uint)bdf)) return negErrno(EPERM);   // L4
            const ubyte al = cast(ubyte)(off & 0xFC);
            uint dw = pciConfigRead32(bus, slot, func, al);
            const uint sh = cast(uint)((off & 3) * 8);
            if      (size == 4) dw = cast(uint)val;
            else if (size == 2) dw = (dw & ~(0xFFFFu << sh)) | ((cast(uint)val & 0xFFFF) << sh);
            else if (size == 1) dw = (dw & ~(0xFFu   << sh)) | ((cast(uint)val & 0xFF)   << sh);
            pciConfigWrite32(bus, slot, func, al, dw);
            return 0;
        }
        case 2: {                                   // scan: off = wanted class (base<<8|sub), 0 = any non-bridge
            auto devs = scanPCIDevices();
            foreach (ref d; devs) {
                const uint thisBdf = (cast(uint)d.bus << 16) | (cast(uint)d.slot << 8) | d.func;
                if (!taskHasDevCap(tid, thisBdf)) continue;     // L4: only granted devices are even visible
                const uint clsReg = pciConfigRead32(d.bus, d.slot, d.func, 8);
                const uint base   = (clsReg >> 24) & 0xFF;
                const uint sub    = (clsReg >> 16) & 0xFF;
                if (off != 0) {
                    if (((base << 8) | sub) == cast(uint)off) return cast(long)thisBdf;
                } else if (base != 0x06) {           // 0x06 = bridge
                    return cast(long)thisBdf;
                }
            }
            return -1;
        }
        case 3: {                                   // MMIO read at phys: bdf = phys addr, size = 1/2/4/8
            if (!taskHasMmioCap(tid, bdf)) return negErrno(EPERM);   // L4: phys not in your device's BARs
            const ulong va = bdf + hhdm_offset;     // device BARs are reachable through the HHDM
            if (size == 1) return *cast(shared const ubyte*)va;
            if (size == 2) return *cast(shared const ushort*)va;
            if (size == 8) return cast(long)*cast(shared const ulong*)va;
            return *cast(shared const uint*)va;
        }
        case 4: {                                   // MMIO write at phys: bdf = phys, size, val
            if (!taskHasMmioCap(tid, bdf)) return negErrno(EPERM);   // L4
            const ulong va = bdf + hhdm_offset;
            if      (size == 1) *cast(shared ubyte*)va  = cast(ubyte)val;
            else if (size == 2) *cast(shared ushort*)va = cast(ushort)val;
            else if (size == 8) *cast(shared ulong*)va  = val;
            else                *cast(shared uint*)va   = cast(uint)val;
            return 0;
        }
        case 5:                                     // virt->phys DMA map: bdf = virt addr, size = byte count
            // US5: bounce non-contiguous multi-page buffers (no-IOMMU corruption fix). `size` may be 0
            // for legacy single-page callers → treated as one page (fast path).
            return lklDmaMap(bdf, size == 0 ? 4096 : size);   // caller's OWN memory — no device cap needed
        case 12:                                    // US5 DMA unmap: bdf = the handle op5 returned; copy a
            lklDmaUnmap(bdf); return 0;             // bounce back to the caller + free it (no-op if direct)
        case 7:                                     // L5 input bridge: inject an evdev event into the OS
            // bdf=isKeyboard, off=type, size=code, val=value.  Only a granted LKL driver (e.g. the USB
            // LKL holding the xHCI cap) may inject input — a plain task cannot synthesise keystrokes.
            if (taskGrantedBdf(tid) == 0xFFFFFFFFu) return negErrno(EPERM);
            if (g_lklInjLog < 24) {
                klog("[lkl-input] inject "); klog(bdf != 0 ? "kbd".ptr : "mouse".ptr);
                klog(" type="); klog_dec(off); klog(" code="); klog_dec(size);
                klog(" val="); klog_dec(val); klog("\n"); ++g_lklInjLog;
            }
            input_enqueue(bdf != 0, cast(ushort)off, cast(ushort)size, cast(int)val);
            return 0;
        case 8: {                                   // L6.1: direct-map a granted BAR's phys into the calling
            // LKL process and return the host VA.  A GPU framebuffer BAR is too large for the routed iomem
            // path (register_iomem caps a region at 16MB-1) and far too hot (a syscall per pixel word via
            // op3/op4); mapping it straight in makes the driver's TTM blits plain memcpys.  bdf = BAR phys
            // base, size = BAR length.  Same cap gate as op3/op4 — the WHOLE range must be a granted BAR.
            import arch.x86_64.arch : map_page_hhdm, PTE_PRESENT, PTE_RW, PTE_USER, PTE_CD, PTE_WT;
            import core.syscalls.mmap : alloc_phys_page_wrapper;
            if (size == 0) return negErrno(EINVAL);
            const ulong barPhys = bdf & ~0xFFFUL;
            const ulong endPhys = (bdf + size - 1) | 0xFFFUL;
            const ulong barLen  = endPhys - barPhys + 1;
            if (barLen > (256UL << 20)) return negErrno(EINVAL);              // sanity: <= 256MB
            if (!taskHasMmioCap(tid, barPhys) || !taskHasMmioCap(tid, endPhys))
                return negErrno(EPERM);                                       // L4: not (entirely) your device
            // ★ Map BARs in a DEDICATED high VA range — NOT g_nextMmapAddr (0x700000000000), which is
            // where the LKL process's main-thread STACK lives (rsp ~0x7000000ff450).  A 16MB framebuffer
            // mapped there overwrote the boot thread's stack -> rip=0 crash after lkl_start_kernel.  This
            // range (0x7E..) is clear of the stack (0x70..), the LKL thread stacks (0x74..), and the
            // normal mmap bump, with room below the 0x800000000000 user-canonical ceiling.
            const ulong vbase = g_lklBarNextVA;
            g_lklBarNextVA += (barLen + 0x1FFFFFUL) & ~0x1FFFFFUL;            // 2MB-rounded bump (gap between BARs)
            // Caching mode carried in `off`: 0 = UC- (PCD only — PAT entry 2; an MTRR may downgrade it to
            // write-combining, which is fine, even desirable, for a GPU framebuffer aperture). 1 = strong UC
            // (PCD|PWT — PAT entry 3: uncacheable AND strongly ordered; an MTRR CANNOT override it to WC).
            // Device CSR registers (AX210 wifi) MUST be strong-UC: readl/writel need each access to reach the
            // chip in-order, un-combined, un-speculated — otherwise the RF-sequencer handshake mistimes.
            const ulong mapFlags = (off == 1)
                ? (PTE_PRESENT | PTE_RW | PTE_USER | PTE_CD | PTE_WT)         // strong UC: device registers
                : (PTE_PRESENT | PTE_RW | PTE_USER | PTE_CD);                 // UC-: large aperture / framebuffer
            for (ulong o = 0; o < barLen; o += 4096)                          // map runs in the caller's CR3
                map_page_hhdm(barPhys + o, vbase + o, mapFlags, &alloc_phys_page_wrapper);
            return cast(long)(vbase + (bdf - barPhys));                       // preserve any sub-page offset
        }
        case 9: {                                   // W1 MSI setup: return the msi_msg field `off` for the LKL
            // to program into the device's MSI capability.  off 0=address_lo, 1=address_hi, 2=data.
            if (!taskHasDevCap(tid, cast(uint)bdf)) return negErrno(EPERM);   // L4: your device only
            if (off == 0) {                          // address_lo (all LKL devices share the native MSI vector)
                import drivers.pci : pciConfigRead32;
                const uint apicId = g_bspApicId;     // ALWAYS the BSP (where vector 0x30 lives), not the caller's CPU
                const uint addrLo = cast(uint)(0xFEE00000UL | (cast(ulong)apicId << 12)); // physical dest, no RH/DM
                const uint ubdf = cast(uint)bdf;
                const ubyte pciBus = cast(ubyte)((ubdf >> 16) & 0xFF);
                const ubyte pciDev = cast(ubyte)((ubdf >> 8) & 0xFF);
                const ubyte pciFun = cast(ubyte)(ubdf & 0xFF);
                const uint classReg = pciConfigRead32(pciBus, pciDev, pciFun, 0x08);
                const uint classSub = (classReg >> 16) & 0xFFFF;
                if (classSub == 0x0280)              // network controller / wireless: CSR HUD target only
                    g_msiDeviceBdf = ubdf;
                if (!g_msiSetupDone)                 // do not discard another device's pending MSI
                    g_msiLastSeen = g_msiIrqCount;
                g_msiAddrLo    = addrLo;
                g_msiData      = MSI_VECTOR;
                g_msiSetupDone = true;
                klog("[lkl-msi] setup bdf="); klog_hex(bdf);
                klog(" bspApic="); klog_hex(apicId); klog(" vec="); klog_hex(MSI_VECTOR); klog("\n");
                return cast(long)addrLo;
            }
            if (off == 1) return 0;                  // address_hi (BSP apic id < 256)
            if (off == 2) return cast(long)MSI_VECTOR; // data: vector 0x30, fixed delivery, edge
            return negErrno(EINVAL);
        }
        case 10:                                     // enumerate MY granted devices: off = index; returns the
            return taskGrantedDevByIndex(tid, cast(int)off);   // idx-th granted bdf, or -1 past the last.
        case 11:                                     // report USB-log status -> on-screen indicator (op11):
            if (taskGrantedBdf(tid) == 0xFFFFFFFFu) return negErrno(EPERM);   // only an LKL (holds a dev cap)
            // NOTE: no klog here — it would busy-spin on COM1 (bounded ~50000/char) with NO serial reader
            // on the FW13.  The on-screen indicator IS the status; a serial write only wastes cycles.
            g_usblogState = cast(int)bdf;            // bdf=state(0..3), off=bytesWritten, size=devKB, val=sd idx
            g_usblogBytes = off;
            g_usblogKB    = size;
            g_usblogSd    = cast(int)val;
            return 0;
        default: return negErrno(EINVAL);
    }
}

// --- statfs / fstatfs ---
private struct linux_statfs {
    long f_type; long f_bsize;  long f_blocks; long f_bfree; long f_bavail;
    long f_files; long f_ffree; int[2] f_fsid; long f_namelen;
    long f_frsize; long f_flags; long[4] f_spare;
}

public long linux_sys_statfs(ulong path, ulong buf) {
    if (!buf) return negErrno(EFAULT);
    auto s = cast(linux_statfs*)buf; *s = linux_statfs.init;
    s.f_type = 0xEF53; s.f_bsize = 4096; s.f_namelen = 255;
    return 0;
}
public long linux_sys_fstatfs(ulong fd, ulong buf) { return linux_sys_statfs(0, buf); }

// --- poll / select (stub: no events ready) ---
// Scan a userspace pollfd array, filling each entry's revents from current fd
// readiness; returns the number of ready fds.  Shared by poll() and ppoll().
private long pollScanFds(ulong fds, ulong nfds) {
    if (fds == 0 || nfds == 0) return 0;
    // struct pollfd { int fd(4); short events(2); short revents(2); } = 8 bytes
    int ready = 0;
    for (ulong i = 0; i < nfds; i++) {
        auto base     = cast(ubyte*)(fds + i * 8);
        int    fd     = *cast(int*   )(base + 0);
        ushort events = *cast(ushort*)(base + 4);
        ushort rev    = 0;
        if (fd >= 0 && fd < 1024) {
            if ((events & 0x0001) && fdReadable(fd)) rev |= 0x0001; // POLLIN
            if ((events & 0x0004) && fdWritable(fd)) rev |= 0x0004; // POLLOUT
        }
        *cast(ushort*)(base + 6) = rev; // revents
        if (rev) ready++;
    }
    return cast(long)ready;
}

public long linux_sys_poll(ulong fds, ulong nfds, ulong timeout) {
    hangTracePoll("poll nfds,timeout", nfds, timeout);
    return pollScanFds(fds, nfds);
}
// ppoll(fds, nfds, timeout_ts, sigmask, sigsetsize): scan readiness like poll;
// the timeout/blocking is handled cooperatively by the syscall dispatcher.
public long linux_sys_ppoll(ulong fds, ulong nfds, ulong tmo, ulong sig, ulong sz) {
    hangTracePoll("ppoll nfds,tmo", nfds, tmo);
    return pollScanFds(fds, nfds);
}
// Scan select() fd_set bitmasks for readiness and rewrite each set IN PLACE to only the ready fds,
// returning the total ready count.  Previously select/pselect6 just `return 0` immediately (no scan,
// no park), so a caller like zsh's ZLE that select()s on its tty spun in USERSPACE (~73% cpu) re-running
// select->0 forever.  Now select is real (scan like poll) + the dispatcher parks it (kernel_main.d).
private long selectScanFds(ulong n, ulong inp, ulong outp, ulong exp) {
    long nfds = cast(long)n; if (nfds < 0) nfds = 0; if (nfds > 1024) nfds = 1024;
    int ready = 0;
    int words = cast(int)((nfds + 63) / 64);
    ulong* rd = cast(ulong*)inp, wr = cast(ulong*)outp, ex = cast(ulong*)exp;
    for (int w = 0; w < words; w++) {
        ulong rin = rd ? rd[w] : 0;
        ulong win = wr ? wr[w] : 0;
        ulong rout = 0, wout = 0;
        if (rin | win) {
            for (int b = 0; b < 64; b++) {
                long fd = cast(long)w * 64 + b;
                if (fd >= nfds) break;
                ulong bit = 1UL << b;
                if ((rin & bit) && fd >= 0 && fd < 1024 && fdReadable(cast(int)fd)) { rout |= bit; ready++; }
                if ((win & bit) && fd >= 0 && fd < 1024 && fdWritable(cast(int)fd)) { wout |= bit; ready++; }
            }
        }
        if (rd) rd[w] = rout;
        if (wr) wr[w] = wout;
        if (ex) ex[w] = 0;   // no exception conditions are ever ready here
    }
    return cast(long)ready;
}
public long linux_sys_select(ulong n, ulong i, ulong o, ulong e, ulong tv) { return selectScanFds(n, i, o, e); }
public long linux_sys_pselect6(ulong n, ulong i, ulong o, ulong e, ulong tv, ulong sig) { return selectScanFds(n, i, o, e); }

// --- getrusage / times / sysinfo ---
public long linux_sys_getrusage(ulong who, ulong usage) {
    if (!usage) return negErrno(EFAULT);
    auto p = cast(ubyte*)usage;
    for (int i = 0; i < 136; ++i) p[i] = 0;
    return 0;
}
public long linux_sys_times(ulong tbuf) {
    if (tbuf) { auto p = cast(long*)tbuf; p[0] = p[1] = p[2] = p[3] = 0; }
    return 0;
}
private struct linux_sysinfo {
    long uptime; ulong[3] loads; ulong totalram; ulong freeram;
    ulong sharedram; ulong bufferram; ulong totalswap; ulong freeswap;
    ushort procs; ulong totalhigh; ulong freehigh; uint mem_unit; char[20] _f;
}
public long linux_sys_sysinfo(ulong info) {
    if (!info) return negErrno(EFAULT);
    auto s = cast(linux_sysinfo*)info; *s = linux_sysinfo.init;
    s.totalram = 512UL * 1024 * 1024; s.freeram = 256UL * 1024 * 1024;
    s.mem_unit = 1; s.procs = 1;
    return 0;
}

public long linux_sys_sysinfo2(ulong info) { return linux_sys_sysinfo(info); }

// --- wait4 / waitid (no children since fork is not yet impl) ---
private enum int ECHILD = 10;
public long linux_sys_wait4(ulong pid, ulong wstatus, ulong options, ulong rusage) {
    return negErrno(ECHILD);
}
public long linux_sys_waitid(ulong idtype, ulong id, ulong infop, ulong options, ulong rusage) {
    return negErrno(ECHILD);
}

// --- fork / clone / execve (ENOSYS stubs – need Haskell task support) ---
public long linux_sys_fork()  { return negErrno(ENOSYS); }
public long linux_sys_vfork() { return negErrno(ENOSYS); }
public long linux_sys_clone(ulong flags, ulong stk, ulong ptid, ulong ctid, ulong tls)
    { return negErrno(ENOSYS); }
public long linux_sys_clone3(ulong args, ulong size) { return negErrno(ENOSYS); }
public long linux_sys_execve(ulong path, ulong argv, ulong envp) { return negErrno(ENOSYS); }
public long linux_sys_execveat(ulong dfd, ulong path, ulong argv, ulong envp, ulong flags)
    { return negErrno(ENOSYS); }

// --- Filesystem modification stubs (read-only image) ---
private enum int EROFS = 30;
// mkdir/mkdirat: create a directory in the writable runtime overlay (rtfs).
// dirfd is ignored — Hyprland and friends pass absolute XDG_RUNTIME_DIR paths.
private long rtMkdirSyscall(const(char)* path, ushort mode) {
    initFdTable();
    if (path is null) return negErrno(EFAULT);
    if (path[0] != '/') return negErrno(ENOENT);   // only absolute paths supported

    int parent; const(char)* leaf; size_t leafLen;
    const int idx = rtResolve(path, parent, leaf, leafLen);
    if (idx >= 0) return negErrno(EEXIST);          // already exists in overlay
    if (isSyntheticDirectoryPath(path)) return negErrno(EEXIST); // exists read-only
    if (parent < 0 || leaf is null) return negErrno(EROFS);      // parent not writable
    if (g_rt[parent].kind != RT_DIR) return negErrno(ENOTDIR);
    const int created = rtCreate(parent, leaf, leafLen, RT_DIR, mode,
                                 userCurrentUid(), userCurrentGid());
    if (created < 0) return negErrno(ENOSPC);
    return 0;
}

public long linux_sys_mkdir(ulong p, ulong m) {
    return rtMkdirSyscall(cast(const(char)*)p, cast(ushort)(m & 0xFFF));
}
public long linux_sys_mkdirat(ulong d, ulong p, ulong m) {
    return rtMkdirSyscall(cast(const(char)*)p, cast(ushort)(m & 0xFFF));
}

private long rtUnlinkSyscall(const(char)* path, bool dirOnly) {
    initFdTable();
    if (path is null) return negErrno(EFAULT);
    int parent; const(char)* leaf; size_t leafLen;
    const int idx = rtResolve(path, parent, leaf, leafLen);
    if (idx < 0) {
        if (isSyntheticDirectoryPath(path)) return negErrno(EROFS);
        return negErrno(ENOENT);
    }
    if (idx == 0) return negErrno(EBUSY);           // never remove the overlay root
    if (dirOnly) {
        if (g_rt[idx].kind != RT_DIR) return negErrno(ENOTDIR);
        for (int i = 1; i < RT_MAX_NODES; ++i)
            if (g_rt[i].kind != RT_FREE && g_rt[i].parent == idx)
                return negErrno(ENOTEMPTY);
    } else if (g_rt[idx].kind == RT_DIR) {
        return negErrno(EISDIR);
    }
    rtFreeData(g_rt[idx]);                           // release payload/link pages (no leak)
    g_rt[idx].kind   = RT_FREE;
    g_rt[idx].parent = -1;
    return 0;
}

public long linux_sys_rmdir(ulong p) { return rtUnlinkSyscall(cast(const(char)*)p, true); }
public long linux_sys_unlink(ulong p) { return rtUnlinkSyscall(cast(const(char)*)p, false); }
public long linux_sys_unlinkat(ulong d, ulong p, ulong f) {
    enum AT_REMOVEDIR = 0x200;
    return rtUnlinkSyscall(cast(const(char)*)p, (f & AT_REMOVEDIR) != 0);
}

private long rtRenameSyscall(const(char)* oldp, const(char)* newp) {
    initFdTable();
    if (oldp is null || newp is null) return negErrno(EFAULT);
    int op; const(char)* ol; size_t oll;
    const int oidx = rtResolve(oldp, op, ol, oll);
    if (oidx < 0)
        return isSyntheticDirectoryPath(oldp) ? negErrno(EROFS) : negErrno(ENOENT);
    if (oidx == 0) return negErrno(EBUSY);

    int np; const(char)* nl; size_t nll;
    const int nidx = rtResolve(newp, np, nl, nll);
    if (np < 0 || nl is null || g_rt[np].kind != RT_DIR) return negErrno(EROFS);
    if (nll == 0 || nll > RT_NAME_MAX) return negErrno(EINVAL);
    if (nidx == oidx) return 0;                      // same node, nothing to do
    if (nidx >= 0) {                                 // replace existing target
        if (g_rt[nidx].kind == RT_DIR && g_rt[oidx].kind != RT_DIR)
            return negErrno(EISDIR);
        rtFreeData(g_rt[nidx]);                       // release the overwritten node's pages
        g_rt[nidx].kind   = RT_FREE;
        g_rt[nidx].parent = -1;
    }
    g_rt[oidx].parent  = np;
    g_rt[oidx].nameLen = cast(ubyte)nll;
    foreach (i; 0 .. nll) g_rt[oidx].name[i] = nl[i];
    return 0;
}

public long linux_sys_rename(ulong o, ulong n_) {
    return rtRenameSyscall(cast(const(char)*)o, cast(const(char)*)n_);
}
public long linux_sys_renameat2(ulong od, ulong o, ulong nd, ulong n_, ulong f) {
    return rtRenameSyscall(cast(const(char)*)o, cast(const(char)*)n_);
}
public long linux_sys_link(ulong o, ulong n_)    { return negErrno(EROFS); }

// Create a symlink `linkPath` -> `target` in the RT overlay (Track A A2).
private long rtSymlinkCreate(const(char)* target, const(char)* linkPath) {
    initFdTable();
    if (target is null || linkPath is null) return negErrno(EFAULT);
    int parent; const(char)* leaf; size_t leafLen;
    const int existing = rtResolve(linkPath, parent, leaf, leafLen);
    if (existing >= 0) return negErrno(EEXIST);
    if (parent < 0 || leaf is null || g_rt[parent].kind != RT_DIR) return negErrno(ENOENT);
    if (leafLen == 0 || leafLen > RT_NAME_MAX) return negErrno(EINVAL);

    size_t tlen = 0;
    while (target[tlen] != 0) ++tlen;
    if (tlen == 0) return negErrno(EINVAL);

    const int idx = rtCreate(parent, leaf, leafLen, RT_LNK, 0x1FF, userCurrentUid(), userCurrentGid());
    if (idx < 0) return negErrno(ENOSPC);
    if (!rtEnsureCap(g_rt[idx], cast(uint)tlen)) {       // store the target string
        g_rt[idx].kind = RT_FREE; g_rt[idx].parent = -1;
        return negErrno(ENOSPC);
    }
    foreach (i; 0 .. tlen) g_rt[idx].data[i] = target[i];
    g_rt[idx].size = cast(uint)tlen;
    return 0;
}

public long linux_sys_symlink(ulong t, ulong l)  {
    return rtSymlinkCreate(cast(const(char)*)t, cast(const(char)*)l);
}
public long linux_sys_symlinkat(ulong t, ulong d, ulong l) {
    // AT_FDCWD / absolute link paths only (our shells always pass absolute paths).
    return rtSymlinkCreate(cast(const(char)*)t, cast(const(char)*)l);
}
public long linux_sys_mknod(ulong p, ulong m, ulong d)   { return negErrno(EROFS); }
public long linux_sys_mknodat(ulong d, ulong p, ulong m, ulong dv) { return negErrno(EROFS); }
public long linux_sys_truncate(ulong p, ulong l)  { return negErrno(EROFS); }
public long linux_sys_creat(ulong p, ulong m)     { return negErrno(EROFS); }

// ── memfd infrastructure ──────────────────────────────────────────────────────
// A memfd is an anonymous, page-aligned physical region created by memfd_create,
// sized by ftruncate, and mapped with mmap.  Because the fd can be passed to
// another process via SCM_RIGHTS, two processes can mmap the same physical pages
// and share a pixel buffer.
private enum int MEMFD_MAX = 32;
private struct MemFdRec {
    bool  inUse;
    ulong physBase;  // 0 until ftruncate allocates backing pages
    ulong size;      // page-aligned byte size
    int   seals;
    uint  vmoObjId;  // Phase 3: VMO identity for shared mmap backings
    bool  aliased;   // true: physBase is borrowed (e.g. a GEM dumb buffer exported
                     // via PRIME); do NOT treat as owner, and reclaim the record on
                     // close so the swapchain's buffer cycle doesn't leak slots.
    uint  vgemHandle; // R3: 0, or the originating virgl GEM handle (>=0x10000) when this
                      // memfd is a PRIME alias of a virtgpu resource — so PRIME_FD_TO_HANDLE
                      // can hand the importer back a g_drmGems handle (not a dumb one).
    uint  refs;       // fd-copy refcount (fork/dup); reclaim the record only at 0
}
__gshared MemFdRec[MEMFD_MAX] g_memfds;

private uint ensureMemfdVmo(int mid) {
    if (mid < 0 || mid >= MEMFD_MAX || !g_memfds[mid].inUse) return 0;
    auto rec = &g_memfds[mid];
    auto h = objGet(rec.vmoObjId);
    if (h is null || h.type != ObjType.Vmo || h.impl !is cast(void*)rec) {
        if (h !is null && h.impl is cast(void*)rec && h.type == ObjType.Vmo)
            objRelease(rec.vmoObjId);
        rec.vmoObjId = objAlloc(ObjType.Vmo, cast(void*)rec);
    }
    return rec.vmoObjId;
}

public uint memfdVmoObj(ulong fd) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return 0;
    File* f = &g_fdTable[ifd];
    if (f.type != FileType.FD_MEMFD) return 0;
    int mid = cast(int)cast(size_t)f.backend;
    if (mid < 0 || mid >= MEMFD_MAX || !g_memfds[mid].inUse) return 0;
    if (g_memfds[mid].vmoObjId != 0 && objGet(g_memfds[mid].vmoObjId) !is null)
        return g_memfds[mid].vmoObjId;
    return ensureMemfdVmo(mid);
}

public long linux_sys_ftruncate(ulong fd, ulong length) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return negErrno(EBADF);
    File* f = &g_fdTable[ifd];
    if (f.type != FileType.FD_MEMFD) return negErrno(EINVAL);
    int mid = cast(int)cast(size_t)f.backend;
    if (mid < 0 || mid >= MEMFD_MAX || !g_memfds[mid].inUse) return negErrno(EBADF);

    ulong aligned = (length + 0xFFF) & ~0xFFFUL;
    if (aligned > g_memfds[mid].size && (g_memfds[mid].seals & F_SEAL_GROW))
        return negErrno(EPERM);
    if (aligned < g_memfds[mid].size && (g_memfds[mid].seals & F_SEAL_SHRINK))
        return negErrno(EPERM);
    if (g_memfds[mid].physBase != 0) {
        // A resize within the current contiguous allocation is free — the wl_shm
        // / toytoolkit cursor allocator grows its pool in steps and re-ftruncates.
        if (aligned <= g_memfds[mid].size) { f.fileSize = length; return 0; }
        // Grow.  A borrowed (PRIME/GEM-aliased) backing must not be moved.
        if (g_memfds[mid].aliased) return negErrno(EINVAL);
        // Allocate a larger contiguous region with geometric headroom (so a pool
        // that resizes repeatedly doesn't reallocate every step), copy the live
        // bytes, and repoint.  Callers growing a live wl_shm pool re-map both ends
        // afterward — the client via munmap+mmap, the compositor via mremap — so
        // moving the backing is safe; the old pages are leaked by the bump pool.
        ulong newSize = aligned;
        ulong dbl = g_memfds[mid].size * 2;
        if (dbl > newSize) newSize = dbl;
        size_t newPages = cast(size_t)(newSize >> 12);
        ulong newPhys = alloc_phys_pages(newPages);
        if (newPhys == 0) return negErrno(ENOMEM);
        auto gsrc = cast(ubyte*)phys_to_virt(g_memfds[mid].physBase);
        auto gdst = cast(ubyte*)phys_to_virt(newPhys);
        foreach (i; 0 .. cast(size_t)g_memfds[mid].size) gdst[i] = gsrc[i];
        foreach (i; cast(size_t)g_memfds[mid].size .. cast(size_t)newSize) gdst[i] = 0;
        uint growVmo = ensureMemfdVmo(mid);
        g_memfds[mid].physBase = newPhys;
        g_memfds[mid].size     = newSize;
        physPagesSetOwner(newPhys, newPages, 0, growVmo);
        f.fileSize             = length;
        return 0;
    }
    if (aligned == 0) { f.fileSize = 0; return 0; }
    size_t pages = cast(size_t)(aligned >> 12);
    ulong phys = alloc_phys_pages(pages);
    if (phys == 0) return negErrno(ENOMEM);
    uint vmoObjId = ensureMemfdVmo(mid);
    g_memfds[mid].physBase = phys;
    g_memfds[mid].size     = aligned;
    physPagesSetOwner(phys, pages, 0, vmoObjId);
    f.fileSize             = length;
    return 0;
}

// fallocate(fd, mode, offset, len). Weston's wl_shm allocator (toytoolkit /
// os_create_anonymous_file) does memfd_create → F_SEAL_SHRINK → posix_fallocate,
// which issues fallocate(fd, 0, 0, size). Without this the clients can't size
// their shared buffers ("creating a buffer file … failed: Function not
// implemented") and nothing draws. For our memfd-backed buffers, "allocate
// space up to offset+len" is exactly ftruncate-grow (which allocates the
// physical pages). Hole-punch / other FALLOC_FL_* modes are accepted as no-ops.
public long linux_sys_fallocate(ulong fd, ulong mode, ulong offset, ulong len) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return negErrno(EBADF);
    if (mode != 0) return 0;                       // FALLOC_FL_* → no-op success
    File* f = &g_fdTable[ifd];
    const ulong end = offset + len;
    if (f.type == FileType.FD_MEMFD) {
        if (end > f.fileSize) return linux_sys_ftruncate(fd, end);  // grow only
        return 0;
    }
    return 0;   // other fd types (rtfs temp files, …): accept as a no-op
}

// Resolve a memfd's CURRENT physical backing from the VMO object id recorded on
// an address-space region.  Used by mremap (kernel_main.d) to re-point a live
// wl_shm pool mapping after the memfd's ftruncate-grow moved its pages.  Returns
// 0 when no live memfd owns this VMO.
public ulong memfdPhysByVmo(uint vmoObjId, ulong* sizeOut) {
    initFdTable();
    if (vmoObjId == 0) return 0;
    for (int i = 0; i < MEMFD_MAX; ++i) {
        if (g_memfds[i].inUse && g_memfds[i].vmoObjId == vmoObjId) {
            if (sizeOut !is null) *sizeOut = g_memfds[i].size;
            return g_memfds[i].physBase;
        }
    }
    return 0;
}

// Resolve a FD_MEMFD fd to its physical base (size via out-pointer).  Returns 0
// if fd is not a sized memfd.  Used by the mmap dispatcher in kernel_main.d.
public ulong memfdResolve(ulong fd, ulong* sizeOut) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return 0;
    File* f = &g_fdTable[ifd];
    if (f.type != FileType.FD_MEMFD) return 0;
    int mid = cast(int)cast(size_t)f.backend;
    if (mid < 0 || mid >= MEMFD_MAX || !g_memfds[mid].inUse) return 0;
    if (sizeOut !is null) *sizeOut = g_memfds[mid].size;
    return g_memfds[mid].physBase;
}

private long fileObjMmap(ObjHeader* oh, ulong offset, ulong* physOut,
                         ulong* sizeOut, uint* vmoOut, bool* sharedOut) {
    File* f = fileFromObj(oh);
    if (f is null) return negErrno(EBADF);
    ++g_objOpsDispatch;
    if (physOut !is null)   *physOut = 0;
    if (sizeOut !is null)   *sizeOut = 0;
    if (vmoOut !is null)    *vmoOut = 0;
    if (sharedOut !is null) *sharedOut = false;

    if (f.type == FileType.FD_DRM && offset != 0) {
        if (physOut !is null)   *physOut = offset;
        if (vmoOut !is null)    *vmoOut = drmVmoForPhys(offset);
        if (sharedOut !is null) *sharedOut = true;
        return 1;
    }

    if (f.type == FileType.FD_MEMFD) {
        int mid = cast(int)cast(size_t)f.backend;
        if (mid < 0 || mid >= MEMFD_MAX || !g_memfds[mid].inUse) return 0;
        if (g_memfds[mid].physBase == 0) return 0;
        if (physOut !is null)   *physOut = g_memfds[mid].physBase + offset;
        if (sizeOut !is null)   *sizeOut = g_memfds[mid].size;
        if (vmoOut !is null)    *vmoOut = ensureMemfdVmo(mid);
        if (sharedOut !is null) *sharedOut = true;
        return 1;
    }

    return 0;
}

public long fdMmapBacking(ulong fd, ulong offset, ulong* physOut,
                          ulong* sizeOut, uint* vmoOut, bool* sharedOut) {
    ObjHeader* oh = fdObjectByIndexWithRights(cast(int)fd, CAP_RIGHT_MMAP);
    if (oh is null) return negErrno(EBADF);
    auto mop = g_objOps[oh.type].mmap;
    if (mop is null) return 0;
    return mop(oh, offset, physOut, sizeOut, vmoOut, sharedOut);
}

// --- Permission / ownership ---
// Persist mode/owner on RT-overlay nodes (Track A A2) so chmod/chown/stat round-trip;
// non-RT paths (synthetic /proc,/sys,/etc) keep the historical no-op so the OpenRC /
// elogind startup that chmods pseudo-paths doesn't fail.
private long rtChmodPath(const(char)* p, ushort mode) {
    if (p is null) return negErrno(EFAULT);
    int rp; const(char)* rl; size_t rll;
    const int ri = rtResolve(p, rp, rl, rll);
    if (ri >= 0) { g_rt[ri].mode = mode & 0xFFF; return 0; }
    return 0;                                  // non-RT path: accept silently (compat)
}

public long linux_sys_chmod(ulong p, ulong m)  { return rtChmodPath(cast(const(char)*)p, cast(ushort)m); }
public long linux_sys_fchmod(ulong fd, ulong m) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd >= 0 && ifd < 1024 && g_fdTable[ifd].type != FileType.FD_NONE) {
        File* f = &g_fdTable[ifd];
        if (f.type == FileType.FD_RTFILE || f.type == FileType.FD_RTDIR) {
            const int idx = cast(int)cast(size_t)f.backend;
            if (idx >= 0 && idx < RT_MAX_NODES) g_rt[idx].mode = cast(ushort)(m & 0xFFF);
        }
    }
    return 0;
}
public long linux_sys_fchmodat(ulong d, ulong p, ulong m, ulong f) {
    return rtChmodPath(cast(const(char)*)p, cast(ushort)m);
}

private bool chownIsNoop(ulong u, ulong g) {
    bool uidOk = (u == ulong.max) || (u == userCurrentUid());
    bool gidOk = (g == ulong.max) || (g == userCurrentGid());
    return uidOk && gidOk;
}

private long rtChownPath(const(char)* p, ulong u, ulong g) {
    if (p !is null) {
        int rp; const(char)* rl; size_t rll;
        const int ri = rtResolve(p, rp, rl, rll);
        if (ri >= 0) {                          // RT node: persist the requested owner
            if (u != ulong.max) g_rt[ri].uid = cast(uint)u;
            if (g != ulong.max) g_rt[ri].gid = cast(uint)g;
            return 0;
        }
    }
    if (chownIsNoop(u, g)) return 0;            // non-RT path: historical stub behaviour
    return adminRequire(CAP_RIGHT_ADMIN_USER) ? 0 : negErrno(EPERM);
}

public long linux_sys_chown(ulong p, ulong u, ulong g) { return rtChownPath(cast(const(char)*)p, u, g); }
public long linux_sys_lchown(ulong p, ulong u, ulong g){ return rtChownPath(cast(const(char)*)p, u, g); }
public long linux_sys_fchown(ulong fd, ulong u, ulong g){
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd >= 0 && ifd < 1024 && g_fdTable[ifd].type != FileType.FD_NONE) {
        File* f = &g_fdTable[ifd];
        if (f.type == FileType.FD_RTFILE || f.type == FileType.FD_RTDIR) {
            const int idx = cast(int)cast(size_t)f.backend;
            if (idx >= 0 && idx < RT_MAX_NODES) {
                if (u != ulong.max) g_rt[idx].uid = cast(uint)u;
                if (g != ulong.max) g_rt[idx].gid = cast(uint)g;
            }
            return 0;
        }
    }
    if (chownIsNoop(u, g)) return 0;
    return adminRequire(CAP_RIGHT_ADMIN_USER) ? 0 : negErrno(EPERM);
}
public long linux_sys_fchownat(ulong d, ulong p, ulong u, ulong g, ulong f) {
    return rtChownPath(cast(const(char)*)p, u, g);
}
public long linux_sys_utimensat(ulong d, ulong p, ulong t, ulong f) { return 0; }
public long linux_sys_utimes(ulong p, ulong t)         { return 0; }

// --- Positioned read (pread64) ---
public long linux_sys_pread64(ulong fd, ulong buf, ulong count, ulong offset) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024 || g_fdTable[ifd].type == FileType.FD_NONE) return negErrno(EBADF);
    ulong saved = g_fdTable[ifd].offset;
    g_fdTable[ifd].offset = offset;
    long ret = sys_read(ifd, cast(void*)buf, cast(size_t)count);
    g_fdTable[ifd].offset = saved;
    return ret;
}
public long linux_sys_pwrite64(ulong fd, ulong buf, ulong count, ulong offset) { return negErrno(EROFS); }
public long linux_sys_sendfile(ulong out_, ulong in_, ulong off, ulong cnt) { return negErrno(ENOSYS); }

// --- readv ---
public long linux_sys_readv(ulong fd, ulong iov_ptr, ulong iovcnt) {
    struct iovec { void* iov_base; size_t iov_len; }
    auto iovs = cast(iovec*)iov_ptr;
    long total = 0;
    for (ulong i = 0; i < iovcnt; ++i) {
        if (!iovs[i].iov_len) continue;
        long r = linux_sys_read(fd, cast(ulong)iovs[i].iov_base, iovs[i].iov_len);
        if (r < 0) return total > 0 ? total : r;
        total += r;
        if (cast(size_t)r < iovs[i].iov_len) break;
    }
    return total;
}

// --- Socket syscalls (already implemented above; expose with syscall-number naming) ---
public long linux_sys_socket_nr(ulong dom, ulong type, ulong proto) { return linux_sys_socket(dom, type, proto); }
public long linux_sys_bind_nr(ulong fd, ulong addr, ulong len)       { return linux_sys_bind(fd, addr, len); }
public long linux_sys_listen_nr(ulong fd, ulong bl)                  { return linux_sys_listen(fd, bl); }
public long linux_sys_accept_nr(ulong fd, ulong addr, ulong len)     { return linux_sys_accept(fd, addr, len); }
public long linux_sys_connect_nr(ulong fd, ulong addr, ulong len)    { return linux_sys_connect(fd, addr, len); }
public long linux_sys_sendmsg_nr(ulong fd, ulong msg, ulong fl)      { return linux_sys_sendmsg(fd, msg, fl); }
public long linux_sys_recvmsg_nr(ulong fd, ulong msg, ulong fl)      { return linux_sys_recvmsg(fd, msg, fl); }
public long linux_sys_sendto_nr(ulong fd, ulong buf, ulong len, ulong fl, ulong da, ulong dl)
    { return linux_sys_sendto(fd, buf, len, fl, da, dl); }
public long linux_sys_recvfrom_nr(ulong fd, ulong buf, ulong len, ulong fl, ulong sa, ulong sl)
    { return linux_sys_recvfrom(fd, buf, len, fl, sa, sl); }
public long linux_sys_accept4(ulong fd, ulong addr, ulong len, ulong fl)
    { return linux_sys_accept(fd, addr, len); }
public long linux_sys_shutdown(ulong fd, ulong how) { return sys_close(cast(int)fd); }
public long linux_sys_getsockopt(ulong fd, ulong lvl, ulong opt, ulong val, ulong len) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return negErrno(EBADF);
    auto f = &g_fdTable[ifd];
    // SO_PEERCRED on the seat connection fd: libseat's embedded seatd server calls
    // this to identify its peer, but our socketpair/connection fd isn't always a
    // recognised FD_SOCKET, so a strict ENOTSOCK makes the builtin backend fail to
    // open the seat ("Not a socket") and aquamarine never activates the session.
    // Return the active task's User object credentials for any open fd.
    if (lvl == SOL_SOCKET && cast(int)opt == SO_PEERCRED) {
        auto anySock = fileSocket(f);
        return copySockoptUcred(val, len, anySock);
    }

    auto sock = fileSocket(f);
    if (sock is null) return negErrno(ENOTSOCK);
    if (lvl != SOL_SOCKET) return negErrno(ENOPROTOOPT);

    switch (cast(int)opt) {
        case SO_PEERCRED:
            return copySockoptUcred(val, len, sock);
        case SO_TYPE:
            return copySockoptInt(val, len, sock.type);
        case SO_ERROR:
            return copySockoptInt(val, len, 0);
        case SO_ACCEPTCONN:
            return copySockoptInt(val, len, sock.state == LocalSocketState.listener ? 1 : 0);
        case SO_PROTOCOL:
            return copySockoptInt(val, len, 0);
        case SO_DOMAIN:
            return copySockoptInt(val, len, sock.domain);
        default:
            return negErrno(ENOPROTOOPT);
    }
}
public long linux_sys_setsockopt(ulong fd, ulong lvl, ulong opt, ulong val, ulong len) { return 0; }
public long linux_sys_getsockname(ulong fd, ulong addr, ulong len)  { return negErrno(ENOSYS); }
public long linux_sys_getpeername(ulong fd, ulong addr, ulong len)  { return negErrno(ENOTCONN); }
// --- socketpair: two connected AF_UNIX endpoints ---
public long linux_sys_socketpair(ulong dom, ulong t, ulong p, ulong sv) {
    if (!sv) return negErrno(EFAULT);
    initFdTable();

    const int baseType = cast(int)t & 0x0F;
    if (cast(int)dom != AF_UNIX) return negErrno(EAFNOSUPPORT);
    if (baseType != SOCK_STREAM && baseType != SOCK_SEQPACKET) return negErrno(EPROTONOSUPPORT);
    if (cast(int)p != 0) return negErrno(EPROTONOSUPPORT);

    int a = allocLocalSocket(AF_UNIX, baseType);
    if (a < 0) return negErrno(EMFILE);
    int b = allocLocalSocket(AF_UNIX, baseType);
    if (b < 0) {
        releaseLocalSocket(a);
        return negErrno(EMFILE);
    }

    auto sa = localSocketById(a);
    auto sb = localSocketById(b);
    sa.state = LocalSocketState.connected;
    sa.peerId = b;
    sb.state = LocalSocketState.connected;
    sb.peerId = a;

    int fda = allocSocketFd(a, O_RDWR);
    int fdb = allocSocketFd(b, O_RDWR);
    if (fda < 0 || fdb < 0) {
        if (fda >= 0) {
            g_fdTable[fda] = File.init;
            capClear(cast(uint)fda);
        }
        releaseLocalSocket(a);
        releaseLocalSocket(b);
        return negErrno(EMFILE);
    }

    (cast(int*)sv)[0] = fda;
    (cast(int*)sv)[1] = fdb;

    // ORG P10 (E9): the two endpoints peer each other with a **Weak** edge — a
    // mutual reference that must never pin (closing one must free it).  Resolve and
    // record each socket's backing object, then link them both ways.
    publishActiveFd(fda);
    publishActiveFd(fdb);
    if (sa.fdObjId != 0 && sb.fdObjId != 0) {
        edgeAdd(sa.fdObjId, sb.fdObjId, EdgeKind.Weak, 0);
        edgeAdd(sb.fdObjId, sa.fdObjId, EdgeKind.Weak, 0);
    }
    return 0;
}

// Bounds recursion when an epoll fd watches another epoll fd (libinput nests an
// epoll inside the one Weston polls); a self/cyclic watch can't loop forever.
private __gshared int g_fdReadableDepth = 0;

// --- Helper: test if FD has data available for reading ---
// PERF: count fdReadable()==true by FileType — under a busy-spin, the dominant
// type is the fd that keeps reporting "ready" without real data (the spin source).
__gshared ulong[24] g_fdrdTrue;

private bool fdReadable(int fd) @nogc nothrow {
    const bool r = fdReadableImpl(fd);
    if (r && fd >= 0 && fd < 1024) {
        const uint t = cast(uint)g_fdTable[fd].type;
        if (t < 24) ++g_fdrdTrue[t];
    }
    return r;
}

private bool fdReadableImpl(int fd) @nogc nothrow {
    if (fd < 0 || fd >= 1024) return false;
    if (!fdRequireCap(cast(ulong)fd, CAP_RIGHT_READ)) return false;
    auto f = &g_fdTable[fd];
    if (f.type == FileType.FD_CONSOLE)  return true;
    if (f.type == FileType.FD_EPOLL) {
        // An epoll fd is readable when any fd it watches is ready.  This makes a
        // *nested* epoll work: libinput hands Weston an epoll fd that itself
        // watches the evdev devices, so without this Weston's outer epoll never
        // wakes for pointer/keyboard input and the cursor never moves.
        if (g_fdReadableDepth >= 8) return false;
        int eid = cast(int)cast(size_t)f.backend;
        if (eid < 0 || eid >= EPOLL_MAX_INSTANCES) return false;
        auto inst = &g_epollTable[eid];
        ++g_fdReadableDepth;
        bool any = false;
        for (int i = 0; i < EPOLL_MAX_WATCHES; i++) {
            if (!inst.watches[i].active) continue;
            int wfd = inst.watches[i].watchFd;
            if ((inst.watches[i].events & EPOLLIN_F)  && fdReadable(wfd)) { any = true; break; }
            if ((inst.watches[i].events & EPOLLOUT_F) && fdWritable(wfd)) { any = true; break; }
        }
        --g_fdReadableDepth;
        return any;
    }
    if (f.type == FileType.FD_SOCKET) {
        // Readable only when data is actually queued or the peer has hung up.
        // Returning true unconditionally made poll() always report ready, so a
        // task poll()ing an empty socket never yielded — starving the peer task
        // that would supply the data (e.g. the forked embedded seatd server).
        auto sock = fileSocket(f);
        if (sock is null) return false;
        if (sock.state == LocalSocketState.listener)
            return sock.pendingHead != sock.pendingTail;   // a pending accept()
        return socketBufferReadable(sock.rx) > 0 || sock.peerClosed
            || sock.state == LocalSocketState.closed;
    }
    if (f.type == FileType.FD_FILE && cast(size_t)f.backend > 2)
        return f.offset < f.fileSize;
    if (f.type == FileType.FD_BUNDLE || f.type == FileType.FD_BOOT_MODULE)
        return f.offset < f.fileSize;
    if (f.type == FileType.FD_PIPE_READ) {
        int pid = pipeIdFromFd(f);
        auto pp = getPipe(cast(size_t)pid);
        return pp !is null && pp.head != pp.tail;
    }
    if (f.type == FileType.FD_EVENTFD) {
        int eid = cast(int)cast(size_t)f.backend;
        return eid >= 0 && eid < EVENTFD_MAX && g_eventfd_inUse[eid]
            && g_eventfd_counters[eid] > 0;
    }
    if (f.type == FileType.FD_INPUT_EVENT) {
        int devIdx = cast(int)cast(size_t)f.backend;
        auto ring = (devIdx == 1) ? &g_mouse_ring : &g_kbd_ring;
        return ring.head != ring.tail;
    }
    if (f.type == FileType.FD_DRM) {
        // Readable when a page-flip completion event is queued for this fd.
        return drmEventPending(fd);
    }
    if (f.type == FileType.FD_PTY_MASTER || f.type == FileType.FD_PTY_SLAVE) {
        int idx = cast(int)cast(size_t)f.backend;
        if (idx < 0 || idx >= PTY_MAX || !g_ptys[idx].inUse) return false;
        auto ring = (f.type == FileType.FD_PTY_MASTER) ? &g_ptys[idx].toMaster
                                                       : &g_ptys[idx].toSlave;
        return ring.head != ring.tail;
    }
    if (f.type == FileType.FD_TIMERFD) {
        int tid = cast(int)cast(size_t)f.backend;
        if (tid < 0 || tid >= TIMERFD_MAX || !g_timerfds[tid].inUse) return false;
        timerfdRefresh(g_timerfds[tid]);
        if (g_timerfds[tid].pending > 0) { g_tfdReady++; return true; }
        return false;
    }
    return false;
}

private const(char)* fdTypeName(uint t) @nogc nothrow {
    switch (cast(FileType)t) {
        case FileType.FD_CONSOLE:    return "console";
        case FileType.FD_FILE:       return "file";
        case FileType.FD_SOCKET:     return "socket";
        case FileType.FD_PIPE_READ:  return "pipe";
        case FileType.FD_EPOLL:      return "epoll";
        case FileType.FD_EVENTFD:    return "eventfd";
        case FileType.FD_DRM:        return "drm";
        case FileType.FD_INPUT_EVENT:return "input";
        case FileType.FD_TIMERFD:    return "timerfd";
        case FileType.FD_PTY_MASTER: return "ptym";
        case FileType.FD_PTY_SLAVE:  return "ptys";
        case FileType.FD_RTFILE:     return "rtfile";
        default:                     return "other";
    }
}

// DIAG: dump every live epoll instance's watch list (fd numbers + IN/OUT), plus every
// listening unix socket's pending-accept count.  Called from the periodic task census to
// answer "is the compositor's wayland listener actually watched by any epoll?".
public void epollDumpAll() @nogc nothrow {
    foreach (eid; 0 .. EPOLL_MAX_INSTANCES) {
        if (!g_epollTable[eid].inUse) continue;
        klog("  ep#"); klog_dec(cast(ulong)eid);
        klog("");
        klog(":");
        foreach (i; 0 .. EPOLL_MAX_WATCHES) {
            if (!g_epollTable[eid].watches[i].active) continue;
            klog(" "); klog_dec(cast(ulong)g_epollTable[eid].watches[i].watchFd);
            if (g_epollTable[eid].watches[i].events & EPOLLIN_F)  klog("i");
            if (g_epollTable[eid].watches[i].events & EPOLLOUT_F) klog("o");
        }
        klog("\n");
    }
    foreach (fd; 0 .. 1024) {
        auto f = &g_fdTable[fd];
        if (f.type != FileType.FD_SOCKET) continue;
        auto sock = fileSocket(f);
        if (sock is null || sock.state != LocalSocketState.listener) continue;
        size_t pend = (sock.pendingTail + localSocketPendingCapacity - sock.pendingHead) % localSocketPendingCapacity;
        if (pend == 0) continue;
        klog("  listener fd="); klog_dec(cast(ulong)fd);
        klog(" pendingAccepts="); klog_dec(pend); klog("\n");
    }
}

// PERF: dump fdReadable()==true counts by type (the busy-spin source) and reset.
public void fdReadableStats() @nogc nothrow {
    klog("[fdrd]");
    bool any = false;
    foreach (i; 0 .. 24) {
        if (g_fdrdTrue[i] == 0) continue;
        any = true;
        klog(" "); klog(fdTypeName(cast(uint)i)); klog("="); klog_dec(g_fdrdTrue[i]);
        g_fdrdTrue[i] = 0;
    }
    if (!any) klog(" (none)");
    klog("\n");
}

// --- Helper: test if FD can accept writes ---
private bool fdWritable(int fd) @nogc nothrow {
    if (fd < 0 || fd >= 1024) return false;
    if (!fdRequireCap(cast(ulong)fd, CAP_RIGHT_WRITE)) return false;
    auto f = &g_fdTable[fd];
    if (f.type == FileType.FD_CONSOLE)   return true;
    if (f.type == FileType.FD_PTY_MASTER || f.type == FileType.FD_PTY_SLAVE) return true;
    if (f.type == FileType.FD_SOCKET)    return true;
    if (f.type == FileType.FD_PIPE_WRITE) {
        int pid = pipeIdFromFd(f);
        auto pp = getPipe(cast(size_t)pid);
        return pp !is null && (pp.head - pp.tail) < PIPE_CAPACITY;
    }
    if (f.type == FileType.FD_EVENTFD)   return true;
    return false;
}

// --- epoll ---
public long linux_sys_epoll_create1(ulong flags) {
    initFdTable();
    int eid = -1;
    for (int i = 0; i < EPOLL_MAX_INSTANCES; i++)
        if (!g_epollTable[i].inUse) { eid = i; break; }
    if (eid < 0) return negErrno(EMFILE);
    int fd = allocFd();
    if (fd < 0) return negErrno(EMFILE);
    g_epollTable[eid] = EpollInst.init;
    g_epollTable[eid].inUse = true;
    g_epollTable[eid].refs  = 1;
    g_epollTable[eid].nestDepth = 1; // ORG 3.3: a fresh epoll is a depth-1 leaf
    g_fdTable[fd].type    = FileType.FD_EPOLL;
    g_fdTable[fd].flags   = cast(int)flags;
    g_fdTable[fd].offset  = 0;
    g_fdTable[fd].backend = cast(void*)cast(size_t)eid;
    g_fdTable[fd].fileSize = 0;
    return publishActiveFdReturn(fd);
}

public long linux_sys_epoll_ctl(ulong epfd, ulong op, ulong fd, ulong ev_ptr) {
    initFdTable();
    int efd = cast(int)epfd;
    if (efd < 0 || efd >= 1024 || g_fdTable[efd].type != FileType.FD_EPOLL)
        return negErrno(EBADF);
    int eid = cast(int)cast(size_t)g_fdTable[efd].backend;
    if (eid < 0 || eid >= EPOLL_MAX_INSTANCES) return negErrno(EBADF);
    auto inst = &g_epollTable[eid];
    int wfd = cast(int)fd;

    if (op == EPOLL_CTL_DEL) {
        for (int i = 0; i < EPOLL_MAX_WATCHES; i++)
            if (inst.watches[i].active && inst.watches[i].watchFd == wfd) {
                inst.watches[i].active = false; return 0;
            }
        return negErrno(ENOENT);
    }
    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
        if (!ev_ptr) return negErrno(EFAULT);
        // ORG 3.3 / threat T3: bound epoll-watching-epoll nesting depth (Linux caps
        // at 5).  Adding a child epoll lifts this instance to child.depth+1; refuse
        // if that would exceed the bound, so a watch-bomb can't build unbounded
        // nesting.  O(1) per add — no expensive graph walk on the hot path.
        if (op == EPOLL_CTL_ADD && wfd >= 0 && wfd < 1024 &&
            g_fdTable[wfd].type == FileType.FD_EPOLL) {
            int childEid = cast(int)cast(size_t)g_fdTable[wfd].backend;
            int childDepth = (childEid >= 0 && childEid < EPOLL_MAX_INSTANCES)
                             ? g_epollTable[childEid].nestDepth : 1;
            if (childDepth < 1) childDepth = 1;
            int parentDepth = childDepth + 1;
            if (parentDepth > EPOLL_MAX_NEST) return negErrno(ELOOP);
            if (parentDepth > inst.nestDepth) inst.nestDepth = cast(ubyte)parentDepth;
        }
        auto ev = cast(EpollEvent*)ev_ptr;
        int slot = -1;
        for (int i = 0; i < EPOLL_MAX_WATCHES; i++) {
            if (inst.watches[i].active && inst.watches[i].watchFd == wfd) {
                if (op == EPOLL_CTL_ADD) return negErrno(EEXIST);
                slot = i; break;
            }
            if (!inst.watches[i].active && slot < 0) slot = i;
        }
        if (slot < 0) return negErrno(ENOSPC);
        inst.watches[slot].active  = true;
        inst.watches[slot].watchFd = wfd;
        inst.watches[slot].events  = ev.events;
        inst.watches[slot].data    = ev.data;
        return 0;
    }
    return negErrno(EINVAL);
}

public long linux_sys_epoll_pwait(ulong epfd, ulong evs, ulong maxev, ulong timeout_ms, ulong sigmask, ulong ss) {
    initFdTable();
    if (!evs || maxev == 0) return negErrno(EFAULT);
    int efd = cast(int)epfd;
    if (efd < 0 || efd >= 1024 || g_fdTable[efd].type != FileType.FD_EPOLL)
        return negErrno(EBADF);
    int eid = cast(int)cast(size_t)g_fdTable[efd].backend;
    if (eid < 0 || eid >= EPOLL_MAX_INSTANCES) return negErrno(EBADF);
    auto inst = &g_epollTable[eid];
    auto outev = cast(EpollEvent*)evs;
    int nfound = 0;
    for (int i = 0; i < EPOLL_MAX_WATCHES && nfound < cast(int)maxev; i++) {
        if (!inst.watches[i].active) continue;
        uint ready = 0;
        int wfd = inst.watches[i].watchFd;
        if ((inst.watches[i].events & EPOLLIN_F)  && fdReadable(wfd))  ready |= EPOLLIN_F;
        if ((inst.watches[i].events & EPOLLOUT_F) && fdWritable(wfd))  ready |= EPOLLOUT_F;
        if (ready) {
            outev[nfound].events = ready;
            outev[nfound].data   = inst.watches[i].data;
            nfound++;
        }
    }
    return nfound; // 0 = timeout (no events ready)
}


// --- eventfd ---
public long linux_sys_eventfd2(ulong initval, ulong flags) {
    initFdTable();
    int eid = -1;
    for (int i = 0; i < EVENTFD_MAX; i++)
        if (!g_eventfd_inUse[i]) { eid = i; break; }
    if (eid < 0) return negErrno(EMFILE);
    int fd = allocFd();
    if (fd < 0) return negErrno(EMFILE);
    g_eventfd_inUse[eid]    = true;
    g_eventfd_refs[eid]     = 1;
    g_eventfd_counters[eid] = initval;
    g_eventfd_flags[eid]    = cast(int)flags;
    g_fdTable[fd].type    = FileType.FD_EVENTFD;
    g_fdTable[fd].flags   = cast(int)flags;
    g_fdTable[fd].offset  = 0;
    g_fdTable[fd].backend = cast(void*)cast(size_t)eid;
    g_fdTable[fd].fileSize = 0;
    return publishActiveFdReturn(fd);
}
// ── timerfd infrastructure ────────────────────────────────────────────────────
// Time base: ticks advance at ~1000 Hz from the PIT IRQ0 handler, so 1 tick ≈
// 1 ms.  timerfd expiries and intervals are tracked in ticks.
private enum int TIMERFD_MAX = 16;
private struct TimerFdRec {
    bool  inUse;
    uint  refs;           // fd-copy refcount (fork/dup); free the slot at 0.  Timerfds
                          // previously had NO close-path free at all, so every short-lived
                          // process leaked its instances and the 16-slot table exhausted
                          // during boot churn — after which the compositor's idle timerfd
                          // creation failed and the frame engine died after one frame.
    ulong intervalTicks;  // 0 => one-shot
    ulong nextExpiry;     // absolute tick of next expiry; 0 => disarmed
    ulong pending;        // expirations accumulated but not yet read
}
__gshared TimerFdRec[TIMERFD_MAX] g_timerfds;

// Bring a timer's pending-expiry count up to date relative to the tick clock.
private void timerfdRefresh(ref TimerFdRec t) {
    if (!t.inUse || t.nextExpiry == 0) return;
    ulong now = get_ticks();
    if (now < t.nextExpiry) return;
    if (t.intervalTicks == 0) {
        t.pending  += 1;
        t.nextExpiry = 0;            // one-shot consumed
    } else {
        ulong elapsed = now - t.nextExpiry;
        t.pending  += 1 + elapsed / t.intervalTicks;
        t.nextExpiry = now + t.intervalTicks - (elapsed % t.intervalTicks);
    }
}

public long linux_sys_timerfd_create(ulong clockid, ulong flags) {
    initFdTable();
    int tid = -1;
    for (int i = 0; i < TIMERFD_MAX; i++)
        if (!g_timerfds[i].inUse) { tid = i; break; }
    if (tid < 0) return negErrno(EMFILE);
    int fd = allocFd();
    if (fd < 0) return negErrno(EMFILE);
    g_timerfds[tid] = TimerFdRec.init;
    g_timerfds[tid].inUse = true;
    g_timerfds[tid].refs  = 1;
    g_fdTable[fd].type    = FileType.FD_TIMERFD;
    g_fdTable[fd].backend = cast(void*)cast(size_t)tid;
    return publishActiveFdReturn(fd);
}

// itimerspec { timespec it_interval; timespec it_value; }; timespec { long sec; long nsec; }
public long linux_sys_timerfd_settime(ulong fd, ulong flags, ulong newVal, ulong oldVal) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return negErrno(EBADF);
    File* f = &g_fdTable[ifd];
    if (f.type != FileType.FD_TIMERFD) return negErrno(EINVAL);
    int tid = cast(int)cast(size_t)f.backend;
    if (tid < 0 || tid >= TIMERFD_MAX || !g_timerfds[tid].inUse) return negErrno(EBADF);
    if (newVal == 0) return negErrno(EFAULT);

    auto specs = cast(long*)newVal;
    ulong intervalMs = cast(ulong)(specs[0] * 1000 + specs[1] / 1_000_000);
    ulong valueMs    = cast(ulong)(specs[2] * 1000 + specs[3] / 1_000_000);

    if (oldVal != 0) {
        auto o = cast(long*)oldVal;
        o[0] = 0; o[1] = 0; o[2] = 0; o[3] = 0;
    }

    if (valueMs == 0) {
        // Disarm
        g_timerfds[tid].nextExpiry    = 0;
        g_timerfds[tid].intervalTicks = 0;
        g_timerfds[tid].pending       = 0;
        return 0;
    }
    g_timerfds[tid].intervalTicks = intervalMs;
    // TFD_TIMER_ABSTIME (1): it_value is an ABSOLUTE CLOCK_MONOTONIC deadline, not a
    // relative delay.  libwayland's event-loop timer heap (wayland 1.23 set_timer())
    // arms the loop timerfd this way.  get_ticks() and clock_gettime(MONOTONIC) are
    // both the g_pitMs millisecond domain, so an absolute deadline is already in
    // nextExpiry's units — store it directly.  Treating it as relative
    // (get_ticks()+valueMs) made every repaint timer fire ~uptime seconds late and
    // growing — the erratic multi-second desktop latency (R2).
    if (flags & 1) {
        g_timerfds[tid].nextExpiry = valueMs;            // absolute deadline (ms)
    } else {
        g_timerfds[tid].nextExpiry = get_ticks() + valueMs;  // relative delay
    }
    g_timerfds[tid].pending       = 0;
    g_tfdArm++;
    return 0;
}

public long linux_sys_timerfd_gettime(ulong fd, ulong curVal) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024) return negErrno(EBADF);
    File* f = &g_fdTable[ifd];
    if (f.type != FileType.FD_TIMERFD) return negErrno(EINVAL);
    int tid = cast(int)cast(size_t)f.backend;
    if (tid < 0 || tid >= TIMERFD_MAX || !g_timerfds[tid].inUse) return negErrno(EBADF);
    if (curVal == 0) return negErrno(EFAULT);

    auto o = cast(long*)curVal;
    ulong now = get_ticks();
    ulong remainMs = (g_timerfds[tid].nextExpiry > now)
                   ? (g_timerfds[tid].nextExpiry - now) : 0;
    ulong ivMs = g_timerfds[tid].intervalTicks;
    o[0] = cast(long)(ivMs / 1000);
    o[1] = cast(long)((ivMs % 1000) * 1_000_000);
    o[2] = cast(long)(remainMs / 1000);
    o[3] = cast(long)((remainMs % 1000) * 1_000_000);
    return 0;
}
// signalfd / signalfd4(fd, sigset, sizemask, flags). We don't deliver async
// signals to userspace, so a signalfd never reports a pending signal — but it
// must EXIST and be pollable: libwayland's wl_event_loop_add_signal() calls
// signalfd() and returns NULL on failure, which makes Weston abort at startup
// (it registers SIGTERM/SIGUSR2/SIGCHLD handlers and exits if any is NULL).
// Back it with an always-empty eventfd: a valid, poll-able fd that stays
// not-readable (so the event loop never spuriously wakes or misreads it).
// SFD_NONBLOCK (0x800) / SFD_CLOEXEC (0x80000) share their bit values with the
// EFD_* flags, so `flags` passes straight through. fd >= 0 means "update an
// existing signalfd's mask" — a no-op for us, return it unchanged.
public long linux_sys_signalfd4(ulong fd, ulong m, ulong sz, ulong f) {
    if (cast(long)fd >= 0) return cast(long)fd;
    return linux_sys_eventfd2(0, f);
}
public long linux_sys_inotify_init1(ulong f) { return negErrno(ENOSYS); }

// --- prctl / scheduling ---
public long linux_sys_prctl(ulong opt, ulong a2, ulong a3, ulong a4, ulong a5) { return 0; }
public long linux_sys_sched_yield() { return 0; }
public long linux_sys_sched_getaffinity(ulong pid, ulong sz, ulong mask) {
    if (!mask) return negErrno(EFAULT);
    auto m = cast(ubyte*)mask;
    for (ulong i = 0; i < sz; ++i) m[i] = 0;
    m[0] = 1; // CPU 0 only
    return 0;
}
public long linux_sys_sched_setaffinity(ulong pid, ulong sz, ulong mask) { return 0; }

// --- Memory locking / advice stubs ---
public long linux_sys_mlock(ulong a, ulong l)   { return 0; }
public long linux_sys_munlock(ulong a, ulong l) { return 0; }
public long linux_sys_madvise(ulong a, ulong l, ulong adv) { return 0; }
public long linux_sys_msync(ulong a, ulong l, ulong f)     { return 0; }
public long linux_sys_mincore(ulong a, ulong l, ulong v)   { return negErrno(ENOSYS); }

// --- Misc stubs ---
public long linux_sys_sync()               { return 0; }
public long linux_sys_fsync(ulong fd)      { return 0; }
public long linux_sys_fdatasync(ulong fd)  { return 0; }
public long linux_sys_fadvise64(ulong fd, ulong off, ulong len, ulong adv) { return 0; }
public long linux_sys_getpriority(ulong w, ulong who) { return 0; }
public long linux_sys_setpriority(ulong w, ulong who, ulong p) { return 0; }
public long linux_sys_capget(ulong hdr, ulong dat)  { return 0; }
public long linux_sys_capset(ulong hdr, ulong dat)  { return 0; }
public long linux_sys_personality(ulong p)          { return 0; }
public long linux_sys_chroot(ulong path) {
    return adminRequire(CAP_RIGHT_ADMIN_MOUNT) ? 0 : negErrno(EPERM);
}
public long linux_sys_alarm(ulong sec)              { return 0; }
public long linux_sys_pause()                       { return negErrno(EINTR); }
public long linux_sys_setitimer(ulong w, ulong nv, ulong ov) { return 0; }
public long linux_sys_getitimer(ulong w, ulong cv)  { return 0; }
public long linux_sys_memfd_create(ulong name, ulong flags) {
    initFdTable();
    if ((flags & ~MFD_SUPPORTED_MASK) != 0) return negErrno(EINVAL);
    int mid = -1;
    for (int i = 0; i < MEMFD_MAX; i++)
        if (!g_memfds[i].inUse) { mid = i; break; }
    if (mid < 0) return negErrno(EMFILE);
    int fd = allocFd();
    if (fd < 0) return negErrno(EMFILE);
    g_memfds[mid].inUse    = true;
    g_memfds[mid].refs     = 1;
    g_memfds[mid].physBase = 0;
    g_memfds[mid].size     = 0;
    g_memfds[mid].seals    = (flags & MFD_ALLOW_SEALING) != 0 ? 0 : F_SEAL_SEAL;
    g_memfds[mid].vmoObjId = 0;
    g_fdTable[fd].type     = FileType.FD_MEMFD;
    g_fdTable[fd].backend  = cast(void*)cast(size_t)mid;
    g_fdTable[fd].fileSize = 0;
    g_fdTable[fd].offset   = 0;
    ensureMemfdVmo(mid);
    return publishActiveFdReturn(fd);
}
public long linux_sys_seccomp(ulong op, ulong f, ulong a) { return negErrno(EINVAL); }
public long linux_sys_bpf(ulong cmd, ulong attr, ulong sz)  { return negErrno(ENOSYS); }
public long linux_sys_io_uring_setup(ulong e, ulong p) { return negErrno(ENOSYS); }
public long linux_sys_io_uring_enter(ulong fd, ulong ts, ulong mc, ulong f, ulong s, ulong ss) { return negErrno(ENOSYS); }
public long linux_sys_io_uring_register(ulong fd, ulong op, ulong a, ulong n) { return negErrno(ENOSYS); }
public long linux_sys_flock(ulong fd, ulong op) { return 0; }
public long linux_sys_iopl(ulong level) {
    return adminRequire(CAP_RIGHT_ADMIN_DEVICE) ? 0 : negErrno(EPERM);
}
public long linux_sys_ioperm(ulong from, ulong num, ulong on) {
    return adminRequire(CAP_RIGHT_ADMIN_DEVICE) ? 0 : negErrno(EPERM);
}
public long linux_sys_ptrace(ulong req, ulong pid, ulong addr, ulong data) { return negErrno(ENOSYS); }
public long linux_sys_statx(ulong dfd, ulong path, ulong fl, ulong mask, ulong buf) {
    // glibc/libstdc++ std::filesystem::exists()/is_regular_file() use statx; it
    // was stubbed ENOSYS, so every exists() returned false — Hyprland's
    // resolveAssetPath never found /usr/share/hypr/wallN.png (or any rtfs file),
    // and getBackground() then dereferenced a null cairo surface.  Implement it by
    // resolving the path through sys_open (which consults the rtfs overlay,
    // synthetic dirs and boot modules) + fstat, then converting to statx layout.
    enum AT_EMPTY_PATH = 0x1000;
    if (buf == 0) return cast(long)negErrno(EFAULT);

    long fd;
    bool opened = false;
    auto p = cast(const(char)*)path;
    if ((fl & AT_EMPTY_PATH) != 0 && (path == 0 || p[0] == 0)) {
        fd = cast(long)cast(int)dfd;            // stat the dir fd itself
    } else {
        if (path == 0) return cast(long)negErrno(EFAULT);
        fd = sys_open(p, O_RDONLY);
        if (fd < 0) return fd;                  // ENOENT → exists() == false
        opened = true;
    }

    ubyte[144] st;
    foreach (i; 0 .. 144) st[i] = 0;
    long r = linux_sys_fstat(cast(ulong)fd, cast(ulong)st.ptr);
    if (opened) sys_close(cast(int)fd);
    if (r < 0) return r;

    uint  stMode = *cast(uint*) (st.ptr + 24);
    uint  stUid  = *cast(uint*) (st.ptr + 28);
    uint  stGid  = *cast(uint*) (st.ptr + 32);
    ulong stIno  = *cast(ulong*)(st.ptr + 8);
    ulong stSize = *cast(ulong*)(st.ptr + 48);

    // Fill struct statx (256 bytes).  Only the basic-stats fields std::filesystem
    // consults are populated; the rest stay zero.
    auto b = cast(ubyte*)buf;
    foreach (i; 0 .. 256) b[i] = 0;
    enum uint STATX_BASIC_STATS = 0x000007ff;
    *cast(uint*)  (b + 0)  = STATX_BASIC_STATS;        // stx_mask
    *cast(uint*)  (b + 4)  = 4096;                     // stx_blksize
    *cast(uint*)  (b + 16) = 1;                        // stx_nlink
    *cast(uint*)  (b + 20) = stUid;                    // stx_uid
    *cast(uint*)  (b + 24) = stGid;                    // stx_gid
    *cast(ushort*)(b + 28) = cast(ushort)stMode;       // stx_mode
    *cast(ulong*) (b + 32) = stIno;                    // stx_ino
    *cast(ulong*) (b + 40) = stSize;                   // stx_size
    *cast(ulong*) (b + 48) = (stSize + 511) / 512;     // stx_blocks
    // stx_rdev_major/minor — without these a device fd's rdev is lost through the
    // statx path that musl's fstat() uses, and libinput's evdev_device_have_
    // same_syspath (fstat → new_from_devnum) can't match the input node, so it
    // rejects the keyboard/mouse and there is no cursor.
    ulong stRdev = *cast(ulong*)(st.ptr + 40);
    *cast(uint*)(b + 128) = cast(uint)((stRdev >> 8) & 0xfff);  // stx_rdev_major
    *cast(uint*)(b + 132) = cast(uint)(stRdev & 0xff) |
                            cast(uint)((stRdev >> 12) & 0xffff_ff00); // stx_rdev_minor
    return 0;
}

// ============================================================
// OpenRC / elogind / init system syscalls
// ============================================================

// --- mount / umount2 (pretend success – no real VFS) ---
public long linux_sys_mount(ulong src, ulong tgt, ulong fstype, ulong fl, ulong data) {
    if (!adminRequire(CAP_RIGHT_ADMIN_MOUNT)) return negErrno(EPERM);
    return 0;
}
public long linux_sys_umount2(ulong tgt, ulong fl) {
    return adminRequire(CAP_RIGHT_ADMIN_MOUNT) ? 0 : negErrno(EPERM);
}

// --- swapon / swapoff ---
public long linux_sys_swapon(ulong path, ulong swapfl)  { return negErrno(ENODEV); }
public long linux_sys_swapoff(ulong path)               { return negErrno(EINVAL); }

// --- reboot ---
// QEMU ACPI shutdown: outw(0x604, 0x2000)
// Keyboard controller reset fallback: outb(0x64, 0xfe)
private enum uint LINUX_REBOOT_MAGIC1     = 0xfee1dead;
private enum uint LINUX_REBOOT_CMD_POWER_OFF = 0x4321fedc;
private enum uint LINUX_REBOOT_CMD_HALT      = 0xcdef0123;
private enum uint LINUX_REBOOT_CMD_RESTART   = 0x01234567;
private enum uint LINUX_REBOOT_CMD_RESTART2  = 0xa1b2c3d4;
private enum uint LINUX_REBOOT_CMD_CAD_ON    = 0x89abcdef;
private enum uint LINUX_REBOOT_CMD_CAD_OFF   = 0x00000000;

public long linux_sys_reboot(ulong magic1, ulong magic2, ulong cmd, ulong arg) {
    if (!adminRequire(CAP_RIGHT_ADMIN_REBOOT)) return negErrno(EPERM);
    if (cast(uint)magic1 != LINUX_REBOOT_MAGIC1) return negErrno(EINVAL);
    if (cmd == LINUX_REBOOT_CMD_POWER_OFF || cmd == LINUX_REBOOT_CMD_HALT) {
        // QEMU ACPI power-off: outw(0x2000, 0x604)
        asm @nogc nothrow {
            mov AX, 0x2000;
            mov DX, 0x604;
            out DX, AX;
        }
    } else if (cmd == LINUX_REBOOT_CMD_RESTART || cmd == LINUX_REBOOT_CMD_RESTART2) {
        // Keyboard controller reset: outb(0xfe, 0x64)
        asm @nogc nothrow {
            mov AL, 0xfe;
            mov DX, 0x64;
            out DX, AL;
        }
    }
    // Spin if port write didn't halt the machine
    while (true) asm @nogc nothrow { hlt; }
    return 0;
}

// --- settimeofday / adjtimex ---
public long linux_sys_settimeofday(ulong tv, ulong tz) { return 0; }

private struct linux_timex {
    uint modes; uint[3] _pad1;
    long offset; long freq; long maxerror; long esterror;
    int status; int[3] _pad2;
    long constant_; long precision; long tolerance;
    linux_timeval time_val; long tick;
    long ppsfreq; long jitter; int shift; int[3] _pad3;
    long stabil; long jitcnt; long calcnt; long errcnt; long stbcnt;
    int tai; int[11] _pad4;
}
public long linux_sys_adjtimex(ulong buf) {
    if (buf) {
        auto t = cast(linux_timex*)buf; *t = linux_timex.init;
        t.status = 0; t.constant_ = 10; t.precision = 1; t.tolerance = 32768000;
    }
    return 0; // TIME_OK
}

public long linux_sys_sethostname(ulong name, ulong len) {
    if (len > 64) return negErrno(EINVAL);
    posixSetBootHostname(cast(const(char)*)name, cast(size_t)len);
    return 0;
}
public long linux_sys_setdomainname(ulong name, ulong len) {
    if (len > 64) return negErrno(EINVAL);
    auto src = cast(const(char)*)name;
    for (ulong i = 0; i < len; ++i) g_domainname[i] = src[i];
    g_domainname[len] = '\0';
    return 0;
}

// --- pivot_root (not supported – OpenRC uses it in container mode only) ---
public long linux_sys_pivot_root(ulong newroot, ulong putold) { return negErrno(EINVAL); }

// --- acct (process accounting – not supported) ---
public long linux_sys_acct(ulong filename) { return negErrno(ENOSYS); }

// --- setrlimit (no enforcement; prlimit64 already handles getrlimit) ---
public long linux_sys_setrlimit(ulong res, ulong rlim) { return 0; }

// --- getdents (32-bit dirent; forward to getdents64) ---
public long linux_sys_getdents(ulong fd, ulong dirp, ulong count) {
    return linux_sys_getdents64(fd, dirp, count);
}

// --- signal misc ---
public long linux_sys_rt_sigpending(ulong set, ulong sz) {
    if (set) { auto p = cast(ubyte*)set; for (ulong i = 0; i < sz; ++i) p[i] = 0; }
    return 0;
}
public long linux_sys_rt_sigsuspend(ulong mask, ulong sz)              { return negErrno(EINTR); }
public long linux_sys_rt_sigtimedwait(ulong s, ulong i, ulong t, ulong sz) { return negErrno(EAGAIN); }
public long linux_sys_rt_sigqueueinfo(ulong pid, ulong sig, ulong si)  { return 0; }

// --- misc init/OpenRC needs ---
public long linux_sys_syslog(ulong t, ulong buf, ulong len)       { return negErrno(EPERM); }
public long linux_sys_mlockall(ulong fl)                           { return 0; }
public long linux_sys_munlockall()                                 { return 0; }
public long linux_sys_vhangup()                                    { return 0; }
public long linux_sys_sync_file_range(ulong fd, ulong off, ulong nb, ulong fl) { return 0; }
public long linux_sys_splice(ulong fi, ulong off_i, ulong fo, ulong off_o, ulong len, ulong fl)
    { return negErrno(ENOSYS); }
public long linux_sys_tee(ulong fdi, ulong fdo, ulong len, ulong fl) { return negErrno(ENOSYS); }

// ============================================================
// GTK / GLib / GIO support stubs
// ============================================================

// --- xattr (extended attributes) -- not supported; return ENOTSUP ---
public long linux_sys_getxattr(ulong path, ulong name, ulong val, ulong sz)  { return negErrno(ENOTSUP); }
public long linux_sys_lgetxattr(ulong path, ulong name, ulong val, ulong sz) { return negErrno(ENOTSUP); }
public long linux_sys_fgetxattr(ulong fd, ulong name, ulong val, ulong sz)   { return negErrno(ENOTSUP); }
public long linux_sys_setxattr(ulong path, ulong name, ulong val, ulong sz, ulong fl)  { return negErrno(ENOTSUP); }
public long linux_sys_lsetxattr(ulong path, ulong name, ulong val, ulong sz, ulong fl) { return negErrno(ENOTSUP); }
public long linux_sys_fsetxattr(ulong fd, ulong name, ulong val, ulong sz, ulong fl)   { return negErrno(ENOTSUP); }
public long linux_sys_listxattr(ulong path, ulong list, ulong sz)  { return 0; }  // empty list
public long linux_sys_llistxattr(ulong path, ulong list, ulong sz) { return 0; }
public long linux_sys_flistxattr(ulong fd, ulong list, ulong sz)   { return 0; }
public long linux_sys_removexattr(ulong path, ulong name)  { return negErrno(ENOTSUP); }
public long linux_sys_lremovexattr(ulong path, ulong name) { return negErrno(ENOTSUP); }
public long linux_sys_fremovexattr(ulong fd, ulong name)   { return negErrno(ENOTSUP); }

// --- readlinkat (AT_FDCWD = -100; defer to readlink for abs paths) ---
public long linux_sys_readlinkat(ulong dfd, ulong _path, ulong _buf, ulong bufsz) {
    // For absolute paths (or AT_FDCWD) delegate straight to readlink.
    auto p = cast(const(char)*)_path;
    if (p is null) return negErrno(EFAULT);
    if (p[0] == '/') return linux_sys_readlink(_path, _buf, bufsz);
    // Relative paths not supported in our stub kernel.
    return negErrno(ENOENT);
}

// --- mremap (GLib falls back to malloc/free if ENOSYS) ---
public long linux_sys_mremap(ulong old_addr, ulong old_sz, ulong new_sz, ulong fl, ulong new_addr) {
    return negErrno(ENOSYS);
}

// --- sendmmsg / recvmmsg (GIO/GSocket; return ENOSYS so callers use sendmsg) ---
public long linux_sys_sendmmsg(ulong sockfd, ulong msgvec, ulong vlen, ulong fl) { return negErrno(ENOSYS); }
public long linux_sys_recvmmsg(ulong sockfd, ulong msgvec, ulong vlen, ulong fl, ulong timeout) { return negErrno(ENOSYS); }

// --- copy_file_range (GIO optimistic path; fall back to read+write) ---
public long linux_sys_copy_file_range(ulong fd_in, ulong off_in, ulong fd_out, ulong off_out, ulong len, ulong fl) {
    return negErrno(ENOSYS);
}

// --- faccessat2 (glibc/musl access(); treat same as access()) ---
public long linux_sys_faccessat2(ulong dfd, ulong path, ulong mode, ulong fl) {
    return linux_sys_access(path, mode);
}

// --- name_to_handle_at / open_by_handle_at (GIO; not supported) ---
public long linux_sys_name_to_handle_at(ulong dfd, ulong path, ulong handle, ulong mnt, ulong fl) {
    return negErrno(ENOSYS);
}
public long linux_sys_open_by_handle_at(ulong mfd, ulong handle, ulong fl) {
    return negErrno(ENOSYS);
}

// ============================================================================
// DRM / KMS ioctl handler
// ============================================================================

import memory.mm : alloc_phys_pages, free_phys_pages, physPagesSetOwner;

// DRM ioctl command number byte (request & 0xFF)
private enum uint DRM_NR_VERSION            = 0x00;
private enum uint DRM_NR_WAIT_VBLANK        = 0x06;
private enum uint DRM_NR_GEM_CLOSE          = 0x09;
private enum uint DRM_NR_AUTH_MAGIC         = 0x11;
private enum uint DRM_NR_SET_MASTER         = 0x1e;
private enum uint DRM_NR_DROP_MASTER        = 0x1f;
private enum uint DRM_NR_GET_CAP            = 0x0c;
private enum uint DRM_NR_SET_CLIENT_CAP     = 0x0d;
private enum uint DRM_NR_PRIME_HANDLE_TO_FD = 0x2d;
private enum uint DRM_NR_PRIME_FD_TO_HANDLE = 0x2e;
// NB: these NR bytes are the real Linux DRM UAPI numbers (from libdrm's drm.h),
// because Weston issues ioctls through libdrm. Earlier values for ADDFB2/PAGE_FLIP
// were wrong (0xb0/0xb1) and only happened to be harmless because Hyprland used
// the custom HOS_PRESENT path instead of real KMS — corrected here for Weston.
private enum uint DRM_NR_MODE_GETRESOURCES       = 0xa0;
private enum uint DRM_NR_MODE_GETCRTC            = 0xa1;
private enum uint DRM_NR_MODE_SETCRTC            = 0xa2;
private enum uint DRM_NR_MODE_CURSOR             = 0xa3;
private enum uint DRM_NR_MODE_GETENCODER         = 0xa6;
private enum uint DRM_NR_MODE_GETCONNECTOR       = 0xa7;
private enum uint DRM_NR_MODE_GETPROPERTY        = 0xaa;
private enum uint DRM_NR_MODE_GETPROPBLOB        = 0xac;
private enum uint DRM_NR_MODE_ADDFB              = 0xae;
private enum uint DRM_NR_MODE_RMFB               = 0xaf;
private enum uint DRM_NR_MODE_PAGE_FLIP          = 0xb0;
private enum uint DRM_NR_MODE_DIRTYFB            = 0xb1;
private enum uint DRM_NR_MODE_CREATE_DUMB        = 0xb2;
private enum uint DRM_NR_MODE_MAP_DUMB           = 0xb3;
private enum uint DRM_NR_MODE_DESTROY_DUMB       = 0xb4;
private enum uint DRM_NR_MODE_GETPLANERESOURCES  = 0xb5;
private enum uint DRM_NR_MODE_GETPLANE           = 0xb6;
private enum uint DRM_NR_MODE_SETPLANE           = 0xb7;
private enum uint DRM_NR_MODE_ADDFB2             = 0xb8;
private enum uint DRM_NR_MODE_OBJ_GETPROPERTIES  = 0xb9;
private enum uint DRM_NR_MODE_CURSOR2            = 0xbb;
private enum uint DRM_NR_MODE_ATOMIC            = 0xbc;
private enum uint DRM_NR_HOS_PRESENT            = 0xf0;
private enum uint DRM_NR_HOS_WINDOWS            = 0xf1; // GUI roadmap G5: window rects for identity borders

// DRM object types (struct drm_mode_obj_get_properties.obj_type).
private enum uint DRM_MODE_OBJECT_CRTC      = 0xcccccccc;
private enum uint DRM_MODE_OBJECT_CONNECTOR = 0xc0c0c0c0;
private enum uint DRM_MODE_OBJECT_ENCODER   = 0xe0e0e0e0;
private enum uint DRM_MODE_OBJECT_PLANE     = 0xeeeeeeee;

// Property flag + the synthetic plane "type" property we expose to Weston.
private enum uint DRM_MODE_PROP_ENUM     = (1 << 3);
private enum uint DRM_PLANE_PROP_ID_TYPE = 100;   // synthetic prop id
private enum uint DRM_PLANE_TYPE_PRIMARY = 1;     // raw enum value for "Primary"
private enum uint DRM_PLANE_ID           = 1;     // our single primary plane

// FourCC pixel formats advertised by the primary plane / dumb buffers.
private enum uint DRM_FORMAT_XRGB8888 = 0x34325258; // 'XR24'
private enum uint DRM_FORMAT_ARGB8888 = 0x34325241; // 'AR24'

// DRM capability IDs
private enum ulong DRM_CAP_DUMB_BUFFER          = 0x1;
private enum ulong DRM_CAP_DUMB_PREFERRED_DEPTH = 0x3;
private enum ulong DRM_CAP_PRIME                = 0x5;   // R3: dma-buf import/export capability
private enum ulong DRM_CAP_TIMESTAMP_MONOTONIC  = 0x6;
private enum ulong DRM_CAP_CURSOR_WIDTH         = 0x8;
private enum ulong DRM_CAP_CURSOR_HEIGHT        = 0x9;
private enum ulong DRM_CAP_CRTC_IN_VBLANK_EVENT = 0x12;  // aquamarine (Hyprland) checkFeatures needs this = 1, else "DRM Backend failed"

// DRM client capabilities (DRM_IOCTL_SET_CLIENT_CAP).
private enum ulong DRM_CLIENT_CAP_STEREO_3D        = 1;
private enum ulong DRM_CLIENT_CAP_UNIVERSAL_PLANES = 2;
private enum ulong DRM_CLIENT_CAP_ATOMIC           = 3;

// Page-flip ioctl flags (struct drm_mode_crtc_page_flip.flags).
private enum uint DRM_MODE_PAGE_FLIP_EVENT = 0x01;
private enum uint DRM_MODE_PAGE_FLIP_ASYNC = 0x02;

// DRM event types delivered by read() on the card fd (struct drm_event.type).
private enum uint DRM_EVENT_VBLANK        = 0x01;
private enum uint DRM_EVENT_FLIP_COMPLETE = 0x02;

// GW2: framebuffer-object (fb_id) tracking for Weston's stock DRM backend.
// ADDFB/ADDFB2 bind a GEM dumb buffer to a unique fb_id; SETCRTC/PAGE_FLIP then
// present that fb_id by blitting its pixels (reached through the HHDM at
// physAddr + hhdm_offset) to the hardware framebuffer g_fb.
private struct DrmFb {
    bool   inUse;
    uint   fbId;
    uint   width;
    uint   height;
    uint   pitch;
    uint   format;     // bpp (legacy ADDFB) or fourcc (ADDFB2) — informational
    ulong  physAddr;   // physical base of the backing GEM buffer
    ulong  size;
    uint   resId;      // 0 = CPU dumb buffer; non-zero = virtgpu resource (Weston GL
                       // renderer) whose pixels live on the host GPU → transfer-from-host
                       // into the guest backing before scanout.
}
private enum DRMFB_MAX = 16;
__gshared DrmFb[DRMFB_MAX] g_drmFbs;
__gshared uint g_nextFbId = 1;

// Display-claim trace (real-hardware bring-up, e.g. Framework 13): the compositor
// must walk card0-open → GETRESOURCES → GETCONNECTOR → CREATE_DUMB → SETCRTC/PAGE_FLIP
// before it owns the panel (g_fbConsoleEnabled=false). On a machine with no working
// desktop the on-screen kernel log shows exactly which of these milestones it
// reached. Each fires once (one-shot) so it never spams the per-frame present path.
__gshared bool g_dispLogCard0;
__gshared bool g_dispLogRes;
__gshared bool g_dispLogConn;
__gshared bool g_dispLogDumb;
__gshared bool g_dispLogPresent;
// When true, re-stamp the WiFi/LKL real-hardware debug HUDs over the compositor every present
// (survey line + MSI/CSR rows + LKL console).  DISABLED (2026-07-17, user request): these green
// overlays clutter the desktop / obscure the Logs viewer.  All the same data is still in the klog
// (Logs app: [wifi-irq] / iwlwifi / DIAG lines), so nothing diagnostic is lost by turning the HUDs off.
__gshared bool g_wifiDebugHud = false;
// IMPORTANT: write display-claim markers DIRECTLY to the framebuffer, NOT via klog.
// On a serial-less laptop the kernel disables the gated fb console early ("framebuffer
// log off for fast boot", kernel_main.d) so klog goes to serial only = invisible on the
// panel. console_framebuffer_write is ungated, so these always show on-screen (and the
// desktop's own present overwrites them once it claims the display).
private void dispFbDec(ulong v) @nogc nothrow {
    char[20] b; int i = 20;
    if (v == 0) { console_framebuffer_write("0"); return; }
    while (v != 0 && i > 0) { b[--i] = cast(char)('0' + cast(uint)(v % 10)); v /= 10; }
    char[21] t; int n = 0;
    for (int j = i; j < 20; ++j) t[n++] = b[j];
    t[n] = 0;
    console_framebuffer_write(t.ptr);
}
private void dispMark(ref bool once, const(char)* msg) @nogc nothrow {
    if (once) return;
    once = true;
    console_framebuffer_write("\n[disp] "); console_framebuffer_write(msg);
}
// Bounded direct-fb trace of the modeset ioctls Weston issues AFTER create_dumb, to
// locate the stall between buffer-creation and the first present (which never fires).
// Not one-shot (we want the SEQUENCE: addfb→setcrtc→pageflip), just capped so it can't
// flood if a path repeats.
__gshared uint g_dispOpLogN;
private void dispOp(const(char)* label, ulong num) @nogc nothrow {
    if (g_dispOpLogN >= 24) return;
    ++g_dispOpLogN;
    console_framebuffer_write("\n[disp] "); console_framebuffer_write(label);
    dispFbDec(num);
}

private DrmFb* findDrmFb(uint fbId) @nogc nothrow {
    if (fbId == 0) return null;
    foreach (ref fb; g_drmFbs)
        if (fb.inUse && fb.fbId == fbId) return &fb;
    return null;
}

// Bind a GEM buffer (by handle) to a fresh fb_id. Returns the new id, or 0.
private uint drmAddFb(uint handle, uint width, uint height, uint pitch, uint format) @nogc nothrow {
    ulong phys; uint gw, gh, gpitch; ulong gsize; uint resId = 0;
    GemBuf* gem = findGem(handle);
    if (gem !is null) {
        phys = gem.physAddr; gw = gem.width; gh = gem.height; gpitch = gem.pitch; gsize = gem.size;
    } else {
        // Weston's GL renderer: the scanout buffer is a virtgpu resource (GPU-rendered),
        // not a CPU dumb GEM. Bind its backing + remember the resId so present() can
        // transfer the host-rendered pixels into that backing.
        auto vg = drmGemGet(handle);
        if (vg is null) return 0;
        phys = vg.phys; gw = width; gh = height; gpitch = vg.stride ? vg.stride : pitch;
        gsize = vg.size; resId = vg.resId;
    }
    int slot = -1;
    foreach (i, ref fb; g_drmFbs) { if (!fb.inUse) { slot = cast(int)i; break; } }
    if (slot < 0) return 0;
    uint id = g_nextFbId++;
    g_drmFbs[slot].inUse    = true;
    g_drmFbs[slot].fbId     = id;
    g_drmFbs[slot].width    = width  ? width  : gw;
    g_drmFbs[slot].height   = height ? height : gh;
    g_drmFbs[slot].pitch    = pitch  ? pitch  : gpitch;
    g_drmFbs[slot].format   = format;
    g_drmFbs[slot].physAddr = phys;
    g_drmFbs[slot].size     = gsize;
    g_drmFbs[slot].resId    = resId;
    return id;
}

// ── Kernel overlay cursor ────────────────────────────────────────────────────
// An 11×17 left_ptr arrow (hotspot = tip at the top-left) stamped directly onto
// g_fb at the kernel-tracked mouse position.  It is drawn on every mouse IRQ and
// re-stamped after every Weston present, so the pointer tracks at interrupt rate
// no matter how slowly Weston re-composites the scene in software.  handleMouseIRQ
// also feeds Weston the matching ABSOLUTE position, keeping Weston's own pointer
// exactly aligned with this sprite (so clicks land where the cursor is shown).
private enum int CUR_W = 11;
private enum int CUR_H = 17;
private static immutable string g_curArrow =
    "X.........." ~ "XX........." ~ "X#X........" ~ "X##X......." ~
    "X###X......" ~ "X####X....." ~ "X#####X...." ~ "X######X..." ~
    "X#######X.." ~ "X########X." ~ "X#####XXXXX" ~ "X##X##X...." ~
    "X#X.X##X..." ~ "XX..X##X..." ~ "X....X##X.." ~ ".....X##X.." ~
    "......XXX..";
__gshared int  g_curX = -1, g_curY = -1;   // -1 → not positioned yet
__gshared bool g_curSaveValid = false;
__gshared int  g_curSaveX = 0, g_curSaveY = 0;
__gshared uint[CUR_W * CUR_H] g_curSaveUnder;

// Restore the framebuffer pixels the cursor last covered (erase the sprite).
private void cursorErase() @nogc nothrow {
    if (!g_curSaveValid || g_fb is null || g_fb.address is null || g_fb.bpp != 32) return;
    auto px = cast(uint*)g_fb.address;
    const int fbw = cast(int)g_fb.width, fbh = cast(int)g_fb.height;
    const int stride = cast(int)(g_fb.pitch / 4);
    foreach (ry; 0 .. CUR_H) {
        const int sy = g_curSaveY + ry;
        if (sy < 0 || sy >= fbh) continue;
        foreach (rx; 0 .. CUR_W) {
            const int sx = g_curSaveX + rx;
            if (sx < 0 || sx >= fbw) continue;
            px[sy * stride + sx] = g_curSaveUnder[ry * CUR_W + rx];
        }
    }
    g_curSaveValid = false;
}

// Save the framebuffer under the cursor, then stamp the arrow over it.
private void cursorPaint() @nogc nothrow {
    if (g_curX < 0 || g_fb is null || g_fb.address is null || g_fb.bpp != 32) return;
    auto px = cast(uint*)g_fb.address;
    const int fbw = cast(int)g_fb.width, fbh = cast(int)g_fb.height;
    const int stride = cast(int)(g_fb.pitch / 4);
    g_curSaveX = g_curX; g_curSaveY = g_curY;
    foreach (ry; 0 .. CUR_H) {
        const int sy = g_curY + ry;
        foreach (rx; 0 .. CUR_W) {
            const int sx = g_curX + rx;
            uint bg = 0;
            if (sx >= 0 && sx < fbw && sy >= 0 && sy < fbh)
                bg = px[sy * stride + sx];
            g_curSaveUnder[ry * CUR_W + rx] = bg;
        }
    }
    g_curSaveValid = true;
    foreach (ry; 0 .. CUR_H) {
        const int sy = g_curY + ry;
        if (sy < 0 || sy >= fbh) continue;
        foreach (rx; 0 .. CUR_W) {
            const int sx = g_curX + rx;
            if (sx < 0 || sx >= fbw) continue;
            const char c = g_curArrow[ry * CUR_W + rx];
            if (c == 'X')      px[sy * stride + sx] = 0xff000000;
            else if (c == '#') px[sy * stride + sx] = 0xffffffff;
        }
    }
}

// Effective cursor position (defaults to screen centre before the first move).
public int cursorGetX() @nogc nothrow {
    if (g_curX >= 0) return g_curX;
    return (g_fb !is null) ? cast(int)g_fb.width / 2 : 0;
}
public int cursorGetY() @nogc nothrow {
    if (g_curY >= 0) return g_curY;
    return (g_fb !is null) ? cast(int)g_fb.height / 2 : 0;
}

// Move the cursor to (x,y), clamped on-screen.  Called from the mouse IRQ, where
// interrupts are already disabled, so erase+repaint is atomic vs. other code.
public void cursorSetPos(int x, int y) @nogc nothrow {
    if (g_fb is null) return;
    const int fbw = cast(int)g_fb.width, fbh = cast(int)g_fb.height;
    if (x < 0) x = 0; if (x >= fbw) x = fbw - 1;
    if (y < 0) y = 0; if (y >= fbh) y = fbh - 1;
    cursorErase();
    g_curX = x; g_curY = y;
    cursorPaint();
    // Freeze probe: this mouse-IRQ path is the ONE code path proven alive during a hard freeze
    // (the cursor still moves).  Draw the who/what overlay here — pure fb writes, no serial, no
    // cli/sti; self-gated to only appear when the desktop has stopped presenting (>1.5 s).
    freezeProbeRepaint();
}

// Re-stamp the cursor after Weston overwrote the framebuffer with a fresh frame.
// Runs in syscall context, where interrupts are already masked, so it can't race
// the mouse IRQ's cursorSetPos — no cli/sti needed (and a stray sti here would
// wrongly unmask interrupts mid-syscall and deadlock the compositor's present).
private void cursorRepaintAfterPresent() @nogc nothrow {
    if (g_fb is null) return;
    if (g_curX < 0) { g_curX = cast(int)g_fb.width / 2; g_curY = cast(int)g_fb.height / 2; }
    g_curSaveValid = false;            // Weston redrew the bg; the old save is stale
    cursorPaint();
}

// ── Present-path profiling (low-overhead frame instrumentation) ───────────────
// Cycle-accurate timing of the present path to find where a frame's time goes.
// Interval counters are reset each stats dump; totals persist.  Two rdtsc reads
// per present (~tens of cycles) — negligible vs the present itself.
__gshared ulong g_presTotal;        // cumulative presents
__gshared ulong g_presN;            // presents this interval
__gshared ulong g_presCostCyc;      // sum of full present cycles (blit+borders+cursor)
__gshared ulong g_presCostMax;      // max full present cycles this interval
__gshared ulong g_presGapCyc;       // sum of inter-present gaps (cycles) this interval
__gshared ulong g_presGapMax;       // max inter-present gap this interval
__gshared ulong g_presLastTsc;      // tsc at end of last present
__gshared ulong g_presCalibTsc0;    // calibration anchors (cycles<->ms)
__gshared ulong g_presCalibPit0;
__gshared ulong g_presBlitPx;       // sum of blitted pixels this interval (damage size)
__gshared ulong g_presFullN;        // # presents that fell back to a full-frame blit

// ── Freeze probe (on-screen, survives a compositor freeze) ────────────────────
// When Weston is starved the desktop stops presenting, so the normal HUDs (drawn from
// drmPresentFb) also stop — useless for diagnosing WHAT starved it.  This probe is
// driven from framebufferMoveCursor instead (the cursor still moves during a freeze),
// so it keeps updating: it detects a present-stall (>1.5 s since the last frame) and
// draws WHICH task is hogging the core (recent scheduler histogram) onto the frozen
// frame.  Nothing is drawn while the desktop presents normally (~60 fps).
__gshared ulong g_lastPresentMs = 0;                 // pitMs of the last present (set in presentAccount)
public __gshared int g_presenterTid = -1;            // the task that last PRESENTED = the compositor (name-agnostic: weston/Hyprland/…)
// Compositor death record (freeze-probe verified the FW13 scan-freeze = the compositor EXITED).
// The klog ring dies with a hard reset, so the cause of death must live in globals the on-screen
// overlay can show: exit code (128+sig = killed by signal; small = own exit; else fault) + when,
// plus the last signal ANY task sent (sender/target/signo) to catch a stray-kill culprit.
public __gshared int   g_cmpExitCode = -1;           // exit code of the dead presenter (-1 = alive)
public __gshared ulong g_cmpExitMs   = 0;            // pitMs when it died
public __gshared ulong g_cmpExitRip  = 0;            // its last user RIP (the crash site for code 11)
// Last CLIENT crash (a non-presenter task that exited nonzero) — this is the panel
// (weston-desktop-shell) segfaulting.  Recorded in exitTask; shown on the overlay so its crash
// site can be symbolized without /run/klog (lost on the hard reset).
public __gshared int   g_lastCrashTid  = -1;
public __gshared int   g_lastCrashCode = 0;
public __gshared ulong g_lastCrashRip  = 0;
public __gshared ulong g_lastCrashMs   = 0;
public __gshared char[24] g_lastCrashName;
// Compositor's last COMPLETE stderr line — Weston prints WHY it exits right before quitting.
// Low-overhead: one 160-byte copy per newline (not per char), only for the presenter's writes.
__gshared char[160] g_cmpLast; __gshared char[160] g_cmpCur; __gshared int g_cmpCurN = 0;
void cmpLogTap(char c) @nogc nothrow {
    if (c == '\n' || g_cmpCurN >= 159) {
        if (g_cmpCurN > 0) { g_cmpCur[g_cmpCurN] = 0; for (int i = 0; i <= g_cmpCurN; i++) g_cmpLast[i] = g_cmpCur[i]; }
        g_cmpCurN = 0;
    } else if (c >= 32 && c < 127) {
        g_cmpCur[g_cmpCurN++] = c;
    }
}
public __gshared int   g_lastSigSig  = 0;            // last signal delivered: signo…
public __gshared int   g_lastSigFrom = -1;           // …sender tid…
public __gshared int   g_lastSigTo   = -1;           // …target tid…
public __gshared ulong g_lastSigMs   = 0;            // …at pitMs
__gshared uint[MAX_TASKS] g_freezeSchedHist;         // per-task times-scheduled, recent-weighted
__gshared ulong g_freezeSchedSamples = 0;
// Last syscall ENTERED (recorded in dispatchSyscall).  During a hard freeze the kernel loop is
// typically stuck INSIDE one syscall handler: entries stop, so this snapshot names the culprit —
// the overlay shows the syscall nr + which task issued it + how long ago it entered.
public __gshared ulong g_freezeSysNr = 0;
public __gshared int   g_freezeSysTid = -1;
public __gshared ulong g_freezeSysStartMs = 0;
public void freezeSchedSample(int tid) @nogc nothrow {
    if (tid < 0 || tid >= MAX_TASKS) return;
    ++g_freezeSchedHist[tid];
    if ((++g_freezeSchedSamples & 0x3FFF) == 0)      // decay every 16384 → recent-weighted
        for (int i = 0; i < MAX_TASKS; i++) g_freezeSchedHist[i] >>= 1;
}
public void freezeProbeRepaint() @nogc nothrow {
    import core.console : g_desktopClaimedFb;
    import arch.x86_64.bootstrap : fb_draw_hud_row, g_fb;
    if (!g_desktopClaimedFb || g_fb is null || g_lastPresentMs == 0) return;
    const ulong now = pitMs();
    if (now < g_lastPresentMs || (now - g_lastPresentMs) < 1500) return;   // presenting fine → don't draw
    int[3] top; top[0] = -1; top[1] = -1; top[2] = -1;
    for (int i = 0; i < MAX_TASKS; i++) {
        const uint c = g_freezeSchedHist[i];
        if (c == 0) continue;
        if (top[0] < 0 || c > g_freezeSchedHist[top[0]]) { top[2]=top[1]; top[1]=top[0]; top[0]=i; }
        else if (top[1] < 0 || c > g_freezeSchedHist[top[1]]) { top[2]=top[1]; top[1]=i; }
        else if (top[2] < 0 || c > g_freezeSchedHist[top[2]]) { top[2]=i; }
    }
    char[96] b; int n = 0;
    void put(string s) @nogc nothrow { foreach (ch; s) if (n < 95) b[n++] = ch; }
    void dec(ulong v) @nogc nothrow { char[20] t; int m=0; if(v==0)t[m++]='0'; while(v&&m<20){t[m++]=cast(char)('0'+v%10);v/=10;} while(m&&n<95)b[n++]=t[--m]; }
    void nm(int tid) @nogc nothrow {
        const(char)* p = (tid>=0 && tid<MAX_TASKS) ? g_taskExecName[tid] : null;
        if (p is null) { put("?"); return; }
        int k=0; while (p[k] && k<15 && n<95) b[n++]=p[k++];
    }
    void hx(ulong v) @nogc nothrow { static immutable char[16] hd="0123456789abcdef"; bool s=false;
        for (int i=15;i>=0;--i){ const ubyte d=cast(ubyte)((v>>(i*4))&0xF); if(d||s||i==0){ if(n<95)b[n++]=hd[d]; s=true; } } }
    put("FREEZE "); dec((now-g_lastPresentMs)/1000); put("s  cur="); dec(g_current_task_id); put(":"); nm(cast(int)g_current_task_id);
    b[n]=0; fb_draw_hud_row(0, b.ptr);
    // The smoking gun during a hard freeze: the syscall the kernel entered last and never left.
    n=0; put("SYS 0x"); hx(g_freezeSysNr); put(" tid="); dec(cast(ulong)(g_freezeSysTid<0?0:g_freezeSysTid)); put(":"); nm(g_freezeSysTid);
    put(" in-flight "); dec((now>=g_freezeSysStartMs)?(now-g_freezeSysStartMs)/1000:0); put("s");
    b[n]=0; fb_draw_hud_row(16, b.ptr);
    n=0; put("HOG:");
    for (int r=0;r<3;r++){ if(top[r]<0)break; put(" "); dec(top[r]); put(":"); nm(top[r]); put("="); dec(g_freezeSchedHist[top[r]]); }
    b[n]=0; fb_draw_hud_row(32, b.ptr);
    // THE COMPOSITOR's state — identified as the task that last PRESENTED a frame (g_presenterTid),
    // so this works for ANY compositor (Hyprland, Weston, …) with no name-matching.  The freeze is
    // that task not presenting, and these flags show exactly why:
    //   x1 = it EXITED/crashed;  w1 p1 = poll-parked (dl=deadline ms, 0=forever);  w1 f1 = futex-parked;
    //   w0 = runnable but never scheduled (scheduler bug).  now= is current pitMs to compare deadlines.
    {
        import core.kernel_main : g_pollBlocked, g_pollDeadline, g_futexWaitActive, g_futexWaitDeadline;
        import core.task : g_tasks;
        n=0; put("CMP:");
        const int c = g_presenterTid;
        if (c < 0 || c >= MAX_TASKS) put(" (no present recorded yet)");
        else {
            auto t = &g_tasks[c];
            put(" "); dec(c); put(":"); nm(c);
            put(" a"); b[n++] = t.active ? '1':'0';
            put("x");  b[n++] = t.exited ? '1':'0';
            put("w");  b[n++] = t.waiting ? '1':'0';
            put("p");  b[n++] = g_pollBlocked[c] ? '1':'0';
            if (g_pollBlocked[c]) { put("(dl="); dec(g_pollDeadline[c]); put(")"); }
            put("f");  b[n++] = g_futexWaitActive[c] ? '1':'0';
            if (g_futexWaitActive[c]) { put("(dl="); dec(g_futexWaitDeadline[c]); put(")"); }
            put(" now="); dec(now);
        }
        b[n]=0; fb_draw_hud_row(48, b.ptr);
        // If the compositor died: WHY.  code 128+N = killed by signal N; small = its own exit(code);
        // 0xff00-style / large = fault path.  lastsig names the most recent kill() sender→target.
        if (g_cmpExitCode >= 0) {
            n=0; put("DIED: code="); dec(cast(ulong)g_cmpExitCode);
            put(" rip=0x"); hx(g_cmpExitRip);
            put(" at="); dec(g_cmpExitMs); put("ms");
            if (g_lastSigSig != 0) {
                put("  lastsig="); dec(cast(ulong)g_lastSigSig);
                put(" "); dec(cast(ulong)(g_lastSigFrom<0?0:g_lastSigFrom)); put(":"); nm(g_lastSigFrom);
                put("->"); dec(cast(ulong)(g_lastSigTo<0?0:g_lastSigTo));
                put(" at="); dec(g_lastSigMs); put("ms");
            }
            b[n]=0; fb_draw_hud_row(64, b.ptr);
            // Weston's last stderr line — its literal exit reason.
            n=0; put("WHY: ");
            { const(char)* q = g_cmpLast.ptr; int k=0; while (q[k] && k<110 && n<119) b[n++]=q[k++]; }
            b[n]=0; fb_draw_hud_row(80, b.ptr);
        }
    }
    // Last CLIENT crash (the panel/weston-desktop-shell segfaulting is the real bug — the compositor
    // then either quits or sits idle on a blank screen).  code 11 = SIGSEGV/CPU-exception; rip = the
    // crash site to symbolize against weston-desktop-shell.  Shown even when the compositor is alive.
    if (g_lastCrashTid >= 0) {
        n=0; put("CRASH: "); dec(cast(ulong)g_lastCrashTid); put(":");
        { const(char)* q = g_lastCrashName.ptr; int k=0; while (q[k] && k<20 && n<119) b[n++]=q[k++]; }
        put(" code="); dec(cast(ulong)g_lastCrashCode);
        put(" rip=0x"); hx(g_lastCrashRip);
        put(" at="); dec(g_lastCrashMs); put("ms");
        b[n]=0; fb_draw_hud_row(96, b.ptr);
    }
}

// Freeze probe → /run/klog.  Called from kernelLoop (which keeps running during a compositor
// freeze).  When the desktop has stopped presenting (>1.5 s) it logs, ~1 Hz, WHICH task is hogging
// the core (recent scheduler histogram) + when the stall clears — so after the desktop recovers you
// filter /run/klog for "freeze" and see the culprit, without needing the (dead) keyboard mid-freeze.
__gshared ulong g_freezeKlogLastMs = 0;
__gshared bool  g_freezeWasStalled = false;
public void freezeProbeKlog() @nogc nothrow {
    import core.console : g_desktopClaimedFb;
    if (!g_desktopClaimedFb || g_lastPresentMs == 0) return;
    const ulong now = pitMs();
    const bool stalled = (now >= g_lastPresentMs) && (now - g_lastPresentMs >= 1500);
    if (!stalled) {
        if (g_freezeWasStalled) {
            g_freezeWasStalled = false;
            klog("[freeze] CLEARED — desktop presenting again\n");
            for (int i = 0; i < MAX_TASKS; i++) g_freezeSchedHist[i] = 0;  // fresh histogram for the next episode
        }
        return;
    }
    if (g_freezeKlogLastMs != 0 && now - g_freezeKlogLastMs < 1000) return;   // ~1 Hz while stalled
    g_freezeKlogLastMs = now;
    g_freezeWasStalled = true;
    int[3] top; top[0]=-1; top[1]=-1; top[2]=-1;
    for (int i=0;i<MAX_TASKS;i++){ const uint c=g_freezeSchedHist[i]; if(c==0)continue;
        if(top[0]<0||c>g_freezeSchedHist[top[0]]){top[2]=top[1];top[1]=top[0];top[0]=i;}
        else if(top[1]<0||c>g_freezeSchedHist[top[1]]){top[2]=top[1];top[1]=i;}
        else if(top[2]<0||c>g_freezeSchedHist[top[2]]){top[2]=i;} }
    klog("[freeze] stalled "); klog_dec((now-g_lastPresentMs)/1000);
    klog("s cur="); klog_dec(g_current_task_id); klog(":");
    { const(char)* p=g_taskExecName[cast(int)g_current_task_id]; klog(p !is null ? p : "?".ptr); }
    klog(" HOG:");
    for(int r=0;r<3;r++){ if(top[r]<0)break; klog(" "); klog_dec(top[r]); klog(":");
        const(char)* p=g_taskExecName[top[r]]; klog(p !is null ? p : "?".ptr); klog("="); klog_dec(g_freezeSchedHist[top[r]]); }
    klog("\n");
}

// Shared accounting for both present paths (drmPresentFb = KMS PAGE_FLIP,
// drmPresentToFramebuffer = HOS_PRESENT).  t0/t1 bracket the present; blitPx is the
// pixels copied; full marks a full-frame blit.
private void presentAccount(ulong t0, ulong t1, ulong blitPx, bool full) @nogc nothrow {
    g_lastPresentMs = pitMs();                       // freeze probe: mark the desktop alive
    g_presenterTid  = cast(int)g_current_task_id;    // freeze probe: remember WHO presents (the compositor)
    if (g_presLastTsc != 0) {
        const ulong gap = t0 - g_presLastTsc;
        g_presGapCyc += gap;
        if (gap > g_presGapMax) g_presGapMax = gap;
    } else {
        g_presCalibTsc0 = t1;
        g_presCalibPit0 = pitMs();
    }
    const ulong cost = t1 - t0;
    g_presCostCyc += cost;
    if (cost > g_presCostMax) g_presCostMax = cost;
    g_presBlitPx += blitPx;
    if (full) ++g_presFullN;
    ++g_presN;
    ++g_presTotal;
    g_presLastTsc = t1;
}

// Present a bound framebuffer: blit its pixels to the hardware framebuffer.
// Source and destination are both kernel HHDM mappings, so no SMAP gate is
// needed (unlike drmPresentToFramebuffer, which reads a userspace pointer).
__gshared ulong g_primeDbgN = 0;

private long drmPresentFb(uint fbId) @nogc nothrow {
    const ulong _t0 = rdtsc();
    if (!g_fb || g_fb.address is null || g_fb.pitch == 0 || g_fb.bpp != 32)
        return negErrno(ENODEV);
    DrmFb* fb = findDrmFb(fbId);
    if (fb is null || fb.physAddr == 0 || fb.pitch == 0) return negErrno(EINVAL);

    // Weston GL renderer: the frame was rendered on the host GPU (virgl); pull it into
    // the guest backing before the scanout copy (our present is a guest-side memcpy, so
    // the GPU result must be transferred host->guest first).
    if (fb.resId != 0)
        gpuDrmTransferFromHost(fb.resId, 0, 0, 0, fb.width, fb.height, 1,
                               0, 0, fb.pitch, fb.pitch * fb.height);

    const uint copyW = fb.width  < g_fb.width  ? fb.width  : cast(uint)g_fb.width;
    const uint copyH = fb.height < g_fb.height ? fb.height : cast(uint)g_fb.height;
    const size_t rowBytes = cast(size_t)copyW * 4;
    if (rowBytes > g_fb.pitch || rowBytes > fb.pitch) return negErrno(EINVAL);


    auto src = cast(const(ubyte)*)(fb.physAddr + hhdm_offset);
    auto dst = cast(ubyte*)g_fb.address;
    foreach (row; 0 .. copyH) {
        memcpy(dst + cast(size_t)row * cast(size_t)g_fb.pitch,
               src + cast(size_t)row * cast(size_t)fb.pitch,
               rowBytes);
    }

    // Real-hardware bring-up: announce the first present (display claimed) while the
    // fb console is still live, so the confirmation lands on the panel right before
    // we stop drawing the kernel log over the compositor's output.
    if (!g_dispLogPresent) {
        console_framebuffer_write("\n[disp] FIRST PRESENT fb=");
        dispFbDec(copyW); console_framebuffer_write("x"); dispFbDec(copyH);
        console_framebuffer_write(" -> display CLAIMED\n");
        g_dispLogPresent = true;
    }
    // GUI roadmap G5: overlay trusted identity borders for each client window.
    hosDrawIdentityBorders();
    g_fbConsoleEnabled = false;
    g_desktopClaimedFb = true;   // the compositor now presents — no more kernel fb drawing
    // Weston just overwrote the whole framebuffer; re-stamp the overlay cursor.
    cursorRepaintAfterPresent();
    // Log-egress status — ALWAYS on (ungated): the user needs to SEE whether the debug log reached
    // its destination.  scp uploads (LOG UPLOAD row) and the USB-stick fallback (USB LOG row) are
    // re-stamped every present so they persist over the desktop.
    logupStatusRepaint();
    usblogStatusRepaint();
    // WiFi/LKL real-hardware debug HUDs (survey line, MSI/CSR rows, LKL console) are re-stamped
    // ON TOP of the compositor every present.  They are gated so a future release can restore a
    // clean desktop, but remain enabled during real-hardware WiFi bring-up.
    if (g_wifiDebugHud) {
        { import drivers.pci : wifiSurveyRepaint; wifiSurveyRepaint(); }  // persist the WiFi survey on-screen
        // ...and the live network state right below it.  This is the ONLY place the LAN
        // status is visible when the pointer does not work and no terminal is reachable.
        { import drivers.network.network : netHudRepaint; netHudRepaint(); }
        msiHudRepaint();   // persist the MSI diagnostic (addr/data/fire-count) on row 2
        wifiCsrHudRepaint();  // persist the polled CSR_INT / ALIVE state on row 3
        lklLogRepaint();   // persist the LKL/iwlwifi console at the bottom of the desktop
    }
    presentAccount(_t0, rdtsc(), cast(ulong)copyW * copyH, true);
    if (g_pendingInputMs != 0) {   // R2: full input→screen latency (one line per burst)
        klog("[lat] input->present_ms="); klog_dec(pitMs() - g_pendingInputMs); klog("\n");
        g_pendingInputMs = 0;
    }
    return 0;
}

// Dump present-path profile (called from the stats block).  Reports the frame
// rate and how much of each frame is the KERNEL present (blit+borders+cursor) vs
// everything else (Weston compositing + cooperative scheduling = the inter-present
// gap).  Resets interval counters; keeps the cumulative total.
public void presentProfStats() @nogc nothrow {
    klog("[present] total="); klog_dec(g_presTotal);
    klog(" flipQ="); klog_dec(g_flipQueued);
    klog(" flipRd="); klog_dec(g_flipRead);
    klog(" tfdArm="); klog_dec(g_tfdArm);
    klog(" tfdReady="); klog_dec(g_tfdReady);
    klog(" tfdRead="); klog_dec(g_tfdRead);
    if (g_presN == 0) { klog(" (idle: no frames this interval)\n"); return; }

    // cycles<->ms calibration over the whole run (clean PIT ms).
    const ulong dPit = pitMs() - g_presCalibPit0;
    const ulong dTsc = rdtsc() - g_presCalibTsc0;
    const ulong cpms = (dPit > 0) ? (dTsc / dPit) : 0;     // cycles per ms

    const ulong avgCost = g_presCostCyc / g_presN;
    const ulong avgGap  = (g_presN > 1) ? g_presGapCyc / (g_presN - 1) : 0; // gaps = frames-1
    const ulong avgPx   = g_presBlitPx / g_presN;

    klog(" frames="); klog_dec(g_presN);
    if (cpms > 0 && avgGap > 0) {
        const ulong frameUs = (avgGap * 1000) / cpms;
        const ulong fps     = (frameUs > 0) ? (1000000UL / frameUs) : 0;
        klog(" fps="); klog_dec(fps);
        klog(" frame_us="); klog_dec(frameUs);
        klog(" present_share_permil="); klog_dec((avgCost * 1000) / avgGap);
    }
    if (cpms > 0) {
        klog(" present_us="); klog_dec((avgCost * 1000) / cpms);
        klog(" maxpresent_us="); klog_dec((g_presCostMax * 1000) / cpms);
    }
    klog(" avg_blit_px="); klog_dec(avgPx);
    klog(" fullframe="); klog_dec(g_presFullN);
    klog(" cpms="); klog_dec(cpms);
    klog("\n");

    g_presN = 0; g_presCostCyc = 0; g_presCostMax = 0;
    g_presGapCyc = 0; g_presGapMax = 0; g_presBlitPx = 0; g_presFullN = 0;
}

// GW2: DRM page-flip completion events. After a PAGE_FLIP we present immediately
// and queue a DRM_EVENT_FLIP_COMPLETE that the compositor reads back from the card
// fd (it blocks on this to pace rendering). The queue is GLOBAL, not keyed by fd:
// there is a single card0, and a client commonly does its ioctls on one fd while
// it poll()s/read()s a DUP of that fd in its event loop (Weston does exactly this
// — PAGE_FLIP on fd 12 but epoll on fd 17). Keying events to the flipping fd meant
// the watching fd never saw them, so the compositor stalled after the first flip.
private struct DrmEvent {
    ulong userData;
    uint  seq;
    uint  crtcId;
}
private enum DRM_EVENT_QUEUE_MAX = 64;
__gshared DrmEvent[DRM_EVENT_QUEUE_MAX] g_drmEvents;
__gshared uint g_drmEvHead;     // write index
__gshared uint g_drmEvTail;     // read index
__gshared uint g_drmFlipSeq;

__gshared ulong g_flipQueued, g_flipRead;   // R2: flip-complete events queued vs read
__gshared ulong g_tfdArm, g_tfdReady, g_tfdRead;  // R2: timerfd armed / became-ready / read

private void drmQueueFlipEvent(int fd, ulong userData) @nogc nothrow {
    uint next = (g_drmEvHead + 1) % DRM_EVENT_QUEUE_MAX;
    if (next == g_drmEvTail) return;   // queue full → drop (compositor will recover)
    g_drmEvents[g_drmEvHead].userData = userData;
    g_drmEvents[g_drmEvHead].seq      = ++g_drmFlipSeq;
    g_drmEvents[g_drmEvHead].crtcId   = 1;
    g_drmEvHead = next;
    ++g_flipQueued;
}

// fd is accepted for call-site symmetry but ignored — any card0 fd drains events.
private bool drmEventPending(int fd) @nogc nothrow {
    return g_drmEvTail != g_drmEvHead;
}

// Find a GEM buffer by handle
private GemBuf* findGem(uint handle) {
    foreach (ref g; g_gemBufs)
        if (g.inUse && g.handle == handle) return &g;
    return null;
}

private GemBuf* findGemByPhys(ulong phys) {
    foreach (ref g; g_gemBufs)
        if (g.inUse && phys >= g.physAddr && phys < g.physAddr + g.size) return &g;
    return null;
}

private uint ensureGemVmo(GemBuf* gem) {
    if (gem is null) return 0;
    auto h = objGet(gem.vmoObjId);
    if (h is null || h.type != ObjType.Vmo || h.impl !is cast(void*)gem) {
        if (h !is null && h.impl is cast(void*)gem && h.type == ObjType.Vmo)
            objRelease(gem.vmoObjId);
        gem.vmoObjId = objAlloc(ObjType.Vmo, cast(void*)gem);
    }
    return gem.vmoObjId;
}

public uint drmVmoForPhys(ulong phys) {
    return ensureGemVmo(findGemByPhys(phys));
}

// Fill a drm_mode_modeinfo struct (68 bytes) at ptr using g_fb dimensions.
//
// Layout (all little-endian):
//   offset  0: clock       u32  (pixel clock kHz)
//   offset  4: hdisplay    u16
//   offset  6: hsync_start u16
//   offset  8: hsync_end   u16
//   offset 10: htotal      u16
//   offset 12: hskew       u16
//   offset 14: vdisplay    u16
//   offset 16: vsync_start u16
//   offset 18: vsync_end   u16
//   offset 20: vtotal      u16
//   offset 22: vscan       u16
//   offset 24: vrefresh    u32
//   offset 28: flags       u32
//   offset 32: type        u32
//   offset 36: name        char[32]
private void fillModeInfo(ubyte* ptr) {
    if (!ptr || !g_fb) return;
    uint w = cast(uint)g_fb.width;
    uint h = cast(uint)g_fb.height;
    uint htot = w + 280;
    uint vtot = h + 45;
    uint clk  = htot * vtot * 60 / 1000;  // pixel clock in kHz
    *cast(uint* )(ptr +  0) = clk;
    *cast(ushort*)(ptr +  4) = cast(ushort)w;
    *cast(ushort*)(ptr +  6) = cast(ushort)(w + 88);
    *cast(ushort*)(ptr +  8) = cast(ushort)(w + 132);
    *cast(ushort*)(ptr + 10) = cast(ushort)htot;
    *cast(ushort*)(ptr + 12) = 0;
    *cast(ushort*)(ptr + 14) = cast(ushort)h;
    *cast(ushort*)(ptr + 16) = cast(ushort)(h + 4);
    *cast(ushort*)(ptr + 18) = cast(ushort)(h + 9);
    *cast(ushort*)(ptr + 20) = cast(ushort)vtot;
    *cast(ushort*)(ptr + 22) = 0;
    *cast(uint* )(ptr + 24) = 60;          // vrefresh Hz
    *cast(uint* )(ptr + 28) = 5;           // flags: PHSYNC | PVSYNC
    *cast(uint* )(ptr + 32) = 0x48;        // type: DRIVER | PREFERRED
    // name: "HanonymOS\0"
    immutable char[10] nm = "HanonymOS\0";
    foreach (i; 0 .. 10) ptr[36 + i] = cast(ubyte)nm[i];
}

// Main DRM ioctl dispatcher — called when fd type is FD_DRM and magic=0x64.
//
// Struct offsets are taken directly from the Linux DRM UAPI headers.
/*
private long handleDrmIoctl(int ifd, ulong request, ulong arg) {
    uint nr = request & 0xFF;
    ubyte* p = cast(ubyte*)arg;

    klog("[drm] nr="); klog_hex(nr); klog(" arg="); klog_hex(arg); klog("\n");

    switch (nr) {

    // ── DRM_IOCTL_VERSION (0x00) ─────────────────────────────────────────
    // drm_version: int(4)+int(4)+int(4)+pad(4)+
    //              name_len(8)+name*(8)+date_len(8)+date*(8)+desc_len(8)+desc*(8)
    case DRM_NR_VERSION: {
        if (!p) return negErrno(EFAULT);
        *cast(int*)(p +  0) = 1;   // version_major
        *cast(int*)(p +  4) = 0;   // version_minor
        *cast(int*)(p +  8) = 0;   // version_patchlevel
        // p+12 = pad
        ulong* name_len = cast(ulong*)(p + 16);
        char** name_ptr = cast(char**)(p + 24);
        immutable char[11] drvnm = "virtio_gpu\0";
        if (*name_len > 0 && *name_ptr) {
            size_t n = (*name_len < 10) ? cast(size_t)*name_len : 10;
            foreach (i; 0 .. n) (*name_ptr)[i] = drvnm[i];
        }
        *name_len = 10;
        // date + desc MUST be non-empty: libdrm's drmGetVersion → drmCopyVersion does
        // strdup(version->date)/strdup(version->desc), and when *_len==0 libdrm never
        // allocates them (they stay NULL) → strdup(NULL) → strlen(NULL) → NULL fault
        // (crashes Hyprland's CHyprOpenGL/IHyprRenderer ctor via drmGetVersion).  Return
        // real short strings, filling the caller's buffer on the second (buffered) ioctl.
        ulong* date_len = cast(ulong*)(p + 32);
        char** date_ptr = cast(char**)(p + 40);
        immutable char[9] drvdt = "20240101\0";
        if (*date_len > 0 && *date_ptr) {
            size_t n = (*date_len < 8) ? cast(size_t)*date_len : 8;
            foreach (i; 0 .. n) (*date_ptr)[i] = drvdt[i];
        }
        *date_len = 8;
        ulong* desc_len = cast(ulong*)(p + 48);
        char** desc_ptr = cast(char**)(p + 56);
        immutable char[7] drvds = "swrast\0";
        if (*desc_len > 0 && *desc_ptr) {
            size_t n = (*desc_len < 6) ? cast(size_t)*desc_len : 6;
            foreach (i; 0 .. n) (*desc_ptr)[i] = drvds[i];
        }
        *desc_len = 6;
        return 0;
    }

    // ── DRM_IOCTL_GET_CAP (0x0c) ─────────────────────────────────────────
    // drm_get_cap: capability(8), value(8)
    case DRM_NR_GET_CAP: {
        if (!p) return negErrno(EFAULT);
        ulong cap = *cast(ulong*)(p + 0);
        ulong val = 0;
        switch (cap) {
        case DRM_CAP_DUMB_BUFFER:          val = 1;  break;
        case DRM_CAP_DUMB_PREFERRED_DEPTH: val = 32; break;
        case DRM_CAP_TIMESTAMP_MONOTONIC:  val = 1;  break;
        case DRM_CAP_CURSOR_WIDTH:         val = 64; break;
        case DRM_CAP_CURSOR_HEIGHT:        val = 64; break;
        default: break;
        }
        *cast(ulong*)(p + 8) = val;
        return 0;
    }

    // ── DRM_IOCTL_SET_CLIENT_CAP (0x0d) ──────────────────────────────────
    case DRM_NR_SET_CLIENT_CAP:
        return 0;  // accept any client capability flag

    // ── DRM_IOCTL_GEM_CLOSE (0x09) ───────────────────────────────────────
    // drm_gem_close: handle(4), pad(4)
    case DRM_NR_GEM_CLOSE: {
        if (!p) return negErrno(EFAULT);
        uint handle = *cast(uint*)(p + 0);
        GemBuf* g = findGem(handle);
        if (g) g.inUse = false;
        return 0;
    }

    // ── Misc: wait_vblank, auth_magic, set/drop_master ───────────────────
    case DRM_NR_WAIT_VBLANK:
    case DRM_NR_AUTH_MAGIC:
    case DRM_NR_SET_MASTER:
    case DRM_NR_DROP_MASTER:
        return 0;

    // ── PRIME (not supported; fall back to non-PRIME path) ───────────────
    case DRM_NR_PRIME_HANDLE_TO_FD:
    case DRM_NR_PRIME_FD_TO_HANDLE:
        return negErrno(ENOSYS);

    // ── DRM_IOCTL_MODE_GETRESOURCES (0xa0) ───────────────────────────────
    // drm_mode_card_res offsets:
    //   0:fb_id_ptr(8) 8:crtc_id_ptr(8) 16:conn_id_ptr(8) 24:enc_id_ptr(8)
    //   32:cnt_fbs(4) 36:cnt_crtcs(4) 40:cnt_conns(4) 44:cnt_encs(4)
    //   48:min_w(4) 52:max_w(4) 56:min_h(4) 60:max_h(4)
    case DRM_NR_MODE_GETRESOURCES: {
        if (!p) return negErrno(EFAULT);
        uint cnt_crtcs = *cast(uint*)(p + 36);
        uint cnt_conns = *cast(uint*)(p + 40);
        uint cnt_encs  = *cast(uint*)(p + 44);
        ulong crtc_ptr = *cast(ulong*)(p +  8);
        ulong conn_ptr = *cast(ulong*)(p + 16);
        ulong enc_ptr  = *cast(ulong*)(p + 24);
        // Fill arrays if the caller provided them with sufficient count
        if (cnt_crtcs >= 1 && crtc_ptr) *cast(uint*)crtc_ptr = 1;
        if (cnt_conns >= 1 && conn_ptr) *cast(uint*)conn_ptr = 1;
        if (cnt_encs  >= 1 && enc_ptr)  *cast(uint*)enc_ptr  = 1;
        *cast(uint*)(p + 32) = 0;  // count_fbs
        *cast(uint*)(p + 36) = 1;  // count_crtcs
        *cast(uint*)(p + 40) = 1;  // count_connectors
        *cast(uint*)(p + 44) = 1;  // count_encoders
        uint maxW = g_fb ? cast(uint)g_fb.width  : 1920;
        uint maxH = g_fb ? cast(uint)g_fb.height : 1080;
        *cast(uint*)(p + 48) = 0;
        *cast(uint*)(p + 52) = maxW;
        *cast(uint*)(p + 56) = 0;
        *cast(uint*)(p + 60) = maxH;
        return 0;
    }

    // ── DRM_IOCTL_MODE_GETCRTC (0xa1) ────────────────────────────────────
    // drm_mode_crtc offsets:
    //   0:set_conns_ptr(8) 8:cnt_conns(4) 12:crtc_id(4) 16:fb_id(4)
    //   20:x(4) 24:y(4) 28:gamma_size(4) 32:mode_valid(4) 36:mode(68)
    case DRM_NR_MODE_GETCRTC: {
        if (!p) return negErrno(EFAULT);
        *cast(uint*)(p + 12) = 1;   // crtc_id
        *cast(uint*)(p + 16) = 0;   // fb_id (none set yet)
        *cast(uint*)(p + 20) = 0;   // x
        *cast(uint*)(p + 24) = 0;   // y
        *cast(uint*)(p + 28) = 256; // gamma_size
        *cast(uint*)(p + 32) = 1;   // mode_valid
        fillModeInfo(p + 36);
        return 0;
    }

    // ── DRM_IOCTL_MODE_SETCRTC (0xa2) ────────────────────────────────────
    case DRM_NR_MODE_SETCRTC:
        return 0;  // mode set always succeeds (direct framebuffer)

    // ── DRM_IOCTL_MODE_GETENCODER (0xa6) ─────────────────────────────────
    // drm_mode_get_encoder: encoder_id(4) encoder_type(4) crtc_id(4)
    //                       possible_crtcs(4) possible_clones(4)
    case DRM_NR_MODE_GETENCODER: {
        if (!p) return negErrno(EFAULT);
        *cast(uint*)(p +  0) = 1;   // encoder_id
        *cast(uint*)(p +  4) = 2;   // encoder_type: TMDS (HDMI/DVI)
        *cast(uint*)(p +  8) = 1;   // crtc_id
        *cast(uint*)(p + 12) = 1;   // possible_crtcs (bit 0 → crtc 0)
        *cast(uint*)(p + 16) = 0;   // possible_clones
        return 0;
    }

    // ── DRM_IOCTL_MODE_GETCONNECTOR (0xa7) ───────────────────────────────
    // drm_mode_get_connector offsets:
    //   0:encoders_ptr(8) 8:modes_ptr(8) 16:props_ptr(8) 24:prop_vals_ptr(8)
    //   32:cnt_modes(4) 36:cnt_props(4) 40:cnt_encs(4) 44:encoder_id(4)
    //   48:connector_id(4) 52:conn_type(4) 56:conn_type_id(4) 60:connection(4)
    //   64:mm_width(4) 68:mm_height(4) 72:subpixel(4) 76:pad(4)
    case DRM_NR_MODE_GETCONNECTOR: {
        if (!p) return negErrno(EFAULT);
        uint req_modes = *cast(uint*)(p + 32);
        uint req_encs  = *cast(uint*)(p + 40);
        ulong modes_ptr = *cast(ulong*)(p +  8);
        ulong enc_ptr   = *cast(ulong*)(p +  0);
        if (req_modes >= 1 && modes_ptr)
            fillModeInfo(cast(ubyte*)modes_ptr);
        if (req_encs  >= 1 && enc_ptr)
            *cast(uint*)enc_ptr = 1;   // encoder id=1
        *cast(uint*)(p + 32) = 1;   // count_modes
        *cast(uint*)(p + 36) = 0;   // count_props
        *cast(uint*)(p + 40) = 1;   // count_encoders
        *cast(uint*)(p + 44) = 1;   // encoder_id (active)
        *cast(uint*)(p + 48) = 1;   // connector_id
        *cast(uint*)(p + 52) = 11;  // connector_type: DRM_MODE_CONNECTOR_HDMIA
        *cast(uint*)(p + 56) = 1;   // connector_type_id
        *cast(uint*)(p + 60) = 1;   // connection: DRM_MODE_CONNECTED
        uint mmW = g_fb ? cast(uint)(g_fb.width  * 27 / 96) : 530;
        uint mmH = g_fb ? cast(uint)(g_fb.height * 27 / 96) : 300;
        *cast(uint*)(p + 64) = mmW;
        *cast(uint*)(p + 68) = mmH;
        *cast(uint*)(p + 72) = 0;   // subpixel: DRM_MODE_SUBPIXEL_UNKNOWN
        *cast(uint*)(p + 76) = 0;
        return 0;
    }

    // ── DRM_IOCTL_MODE_ADDFB (0xae) / MODE_ADDFB2 (0xb0) ────────────────
    // Both return a new fb_id as the first u32 of their struct.
    case DRM_NR_MODE_ADDFB:
    case DRM_NR_MODE_ADDFB2: {
        if (!p) return negErrno(EFAULT);
        *cast(uint*)(p + 0) = 1;   // fb_id = 1
        return 0;
    }

    // ── DRM_IOCTL_MODE_RMFB (0xaf) ───────────────────────────────────────
    case DRM_NR_MODE_RMFB:
        return 0;

    // ── DRM_IOCTL_MODE_PAGE_FLIP (0xb1) ──────────────────────────────────
    case DRM_NR_MODE_PAGE_FLIP:
        // Already visible: compositor writes to GEM buffer = framebuffer
        return 0;

    // ── DRM_IOCTL_MODE_ATOMIC (0xbc): force legacy modesetting path ───────
    case DRM_NR_MODE_ATOMIC:
        return negErrno(EINVAL);

    // ── DRM_IOCTL_MODE_CREATE_DUMB (0xb2) ────────────────────────────────
    // drm_mode_create_dumb: height(4) width(4) bpp(4) flags(4)
    //                       handle(4) pitch(4) size(8)
    case DRM_NR_MODE_CREATE_DUMB: {
        if (!p) return negErrno(EFAULT);
        uint h   = *cast(uint*)(p + 0);
        uint w   = *cast(uint*)(p + 4);
        uint bpp = *cast(uint*)(p + 8);
        if (bpp == 0) bpp = 32;
        // Align pitch to 64 bytes
        uint pitch = (w * bpp / 8 + 63) & ~63u;
        ulong sz   = cast(ulong)pitch * h;
        // Map full-screen buffers directly to the Limine framebuffer physical
        // address so that compositor writes land immediately on-screen.
        ulong physAddr;
        if (g_fb && w == g_fb.width && h == g_fb.height) {
            physAddr = cast(ulong)g_fb.address - hhdm_offset;
            pitch    = cast(uint)g_fb.pitch;
            sz       = g_fb.pitch * g_fb.height;
        } else {
            size_t pages = cast(size_t)((sz + 4095) >> 12);
            physAddr = alloc_phys_pages(pages);
            if (!physAddr) return negErrno(ENOSPC);
        }
        // Allocate a GEM slot
        int slot = -1;
        foreach (i, ref gb; g_gemBufs)
            if (!gb.inUse) { slot = cast(int)i; break; }
        if (slot < 0) return negErrno(ENOSPC);
        uint handle = g_nextGemHandle++;
        g_gemBufs[slot].inUse    = true;
        g_gemBufs[slot].handle   = handle;
        g_gemBufs[slot].physAddr = physAddr;
        g_gemBufs[slot].width    = w;
        g_gemBufs[slot].height   = h;
        g_gemBufs[slot].pitch    = pitch;
        g_gemBufs[slot].bpp      = bpp;
        g_gemBufs[slot].size     = sz;
        *cast(uint* )(p + 16) = handle;
        *cast(uint* )(p + 20) = pitch;
        *cast(ulong*)(p + 24) = sz;
        return 0;
    }

    // ── DRM_IOCTL_MODE_MAP_DUMB (0xb3) ───────────────────────────────────
    // drm_mode_map_dumb: handle(4) pad(4) offset(8)
    // Returns offset = GEM physical address; mmap caller uses it as fileOffset.
    case DRM_NR_MODE_MAP_DUMB: {
        if (!p) return negErrno(EFAULT);
        uint handle = *cast(uint*)(p + 0);
        GemBuf* gem = findGem(handle);
        if (!gem) return negErrno(EINVAL);
        *cast(ulong*)(p + 8) = gem.physAddr;
        return 0;
    }

    // ── DRM_IOCTL_MODE_DESTROY_DUMB (0xb4) ───────────────────────────────
    case DRM_NR_MODE_DESTROY_DUMB: {
        if (!p) return negErrno(EFAULT);
        uint handle = *cast(uint*)(p + 0);
        GemBuf* gem = findGem(handle);
        if (gem) gem.inUse = false;
        return 0;
    }

    default:
        return 0;  // unknown DRM ioctls → success (non-fatal)
    }
}
*/

private void smapBegin() @nogc nothrow {

}

private void smapEnd() @nogc nothrow {

}

private T userRead(T)(ulong addr) @nogc nothrow {
    T v = *cast(T*)addr;
    return v;
}

private void userWrite(T)(ulong addr, T v) @nogc nothrow {
    *cast(T*)addr = v;
}

private void userCopyString(ulong dst, const(char)* src, size_t n) @nogc nothrow {
    auto d = cast(char*)dst;
    foreach (i; 0 .. n) d[i] = src[i];
}

// ── GUI roadmap G5: trusted identity-colored window borders ──────────────────
// Hyprland's CPU-readback present path clears the frame instead of compositing
// the scene, so the kernel — the trusted layer that owns the final blit to g_fb
// — draws each client window's border itself, in a colour derived from the
// owning process (its pid; a stand-in identity until per-client IdentityRec
// colours are wired).  Apps cannot influence this: the border is painted after
// the present blit, over whatever Hyprland produced.
private struct HosWinRect { int x, y, w, h; uint pid; }
private enum size_t HOS_WIN_MAX = 16;
private enum int    HOS_BORDER_PX = 4;
__gshared HosWinRect[HOS_WIN_MAX] g_hosWins;
__gshared uint g_hosWinCount = 0;
__gshared bool g_hosBorderLogged = false;

// A small palette of distinct, unmistakable identity colours (ARGB).  Indexed by
// the owning process so each client gets a stable border colour.
private immutable uint[8] HOS_ID_PALETTE = [
    0xFF4CC2A8, // teal
    0xFFE0B341, // amber
    0xFF6FA8DC, // blue
    0xFFCC6699, // magenta
    0xFF8FBF5F, // green
    0xFFE08A4C, // orange
    0xFFB18FE0, // violet
    0xFFD05757, // red
];

private uint hosIdentityColor(uint pid) @nogc nothrow {
    return HOS_ID_PALETTE[pid % HOS_ID_PALETTE.length];
}

private void fbFillRow(int x, int y, int w, uint color) @nogc nothrow {
    if (y < 0 || y >= cast(int)g_fb.height) return;
    int x0 = x < 0 ? 0 : x;
    int x1 = x + w; if (x1 > cast(int)g_fb.width) x1 = cast(int)g_fb.width;
    auto row = cast(uint*)(cast(ubyte*)g_fb.address + cast(size_t)y * g_fb.pitch);
    foreach (px; x0 .. x1) row[px] = color;
}

private enum int HOS_BORDER_RADIUS = 10; // GUI roadmap G16: rounded identity border

private void fbPutPixel(int x, int y, uint color) @nogc nothrow {
    if (x < 0 || y < 0 || x >= cast(int)g_fb.width || y >= cast(int)g_fb.height) return;
    auto row = cast(uint*)(cast(ubyte*)g_fb.address + cast(size_t)y * g_fb.pitch);
    row[x] = color;
}

private void fbDrawBorderSquare(int x, int y, int w, int h, uint color) @nogc nothrow {
    foreach (i; 0 .. HOS_BORDER_PX) {
        fbFillRow(x, y + i, w, color);             // top
        fbFillRow(x, y + h - 1 - i, w, color);     // bottom
    }
    foreach (yy; y .. y + h) {
        if (yy < 0 || yy >= cast(int)g_fb.height) continue;
        auto row = cast(uint*)(cast(ubyte*)g_fb.address + cast(size_t)yy * g_fb.pitch);
        foreach (i; 0 .. HOS_BORDER_PX) {
            int lx = x + i, rx = x + w - 1 - i;
            if (lx >= 0 && lx < cast(int)g_fb.width) row[lx] = color;
            if (rx >= 0 && rx < cast(int)g_fb.width) row[rx] = color;
        }
    }
}

// GUI roadmap G16: a rounded 4px identity ring, matching the compositor's
// rounded window decorations. Still kernel-owned and unspoofable.
private void fbDrawBorder(int x, int y, int w, int h, uint color) @nogc nothrow {
    if (w <= 0 || h <= 0) return;
    immutable int r = HOS_BORDER_RADIUS;
    if (w < 2 * r + 2 || h < 2 * r + 2) {
        fbDrawBorderSquare(x, y, w, h, color);
        return;
    }
    // straight edges between the corner arcs
    foreach (i; 0 .. HOS_BORDER_PX) {
        fbFillRow(x + r, y + i, w - 2 * r, color);
        fbFillRow(x + r, y + h - 1 - i, w - 2 * r, color);
    }
    foreach (yy; (y + r) .. (y + h - r)) {
        if (yy < 0 || yy >= cast(int)g_fb.height) continue;
        auto row = cast(uint*)(cast(ubyte*)g_fb.address + cast(size_t)yy * g_fb.pitch);
        foreach (i; 0 .. HOS_BORDER_PX) {
            int lx = x + i, rx = x + w - 1 - i;
            if (lx >= 0 && lx < cast(int)g_fb.width) row[lx] = color;
            if (rx >= 0 && rx < cast(int)g_fb.width) row[rx] = color;
        }
    }
    // four quarter-circle corner arcs, thickness HOS_BORDER_PX
    immutable int rOut2 = r * r;
    immutable int rIn   = r - HOS_BORDER_PX;
    immutable int rIn2  = rIn * rIn;
    immutable int tlx = x + r,         tly = y + r;
    immutable int trx = x + w - 1 - r, tryy = y + r;
    immutable int blx = x + r,         bly = y + h - 1 - r;
    immutable int brx = x + w - 1 - r, bryy = y + h - 1 - r;
    foreach (dy; 0 .. r + 1) {
        foreach (dx; 0 .. r + 1) {
            immutable int d2 = dx * dx + dy * dy;
            if (d2 > rOut2 || d2 < rIn2) continue;
            fbPutPixel(tlx - dx, tly - dy, color);
            fbPutPixel(trx + dx, tryy - dy, color);
            fbPutPixel(blx - dx, bly + dy, color);
            fbPutPixel(brx + dx, bryy + dy, color);
        }
    }
}

private void hosDrawIdentityBorders() @nogc nothrow {
    if (g_hosWinCount == 0) return;
    smapBegin();
    foreach (i; 0 .. g_hosWinCount) {
        auto wn = g_hosWins[i];
        fbDrawBorder(wn.x, wn.y, wn.w, wn.h, hosIdentityColor(wn.pid));
    }
    smapEnd();
    if (!g_hosBorderLogged) {
        klog("[g5] drew identity borders for "); klog_hex(g_hosWinCount);
        klog(" window(s); first rect x="); klog_hex(cast(ulong)cast(uint)g_hosWins[0].x);
        klog(" y="); klog_hex(cast(ulong)cast(uint)g_hosWins[0].y);
        klog(" w="); klog_hex(cast(ulong)cast(uint)g_hosWins[0].w);
        klog(" h="); klog_hex(cast(ulong)cast(uint)g_hosWins[0].h);
        klog(" color="); klog_hex(hosIdentityColor(g_hosWins[0].pid));
        klog(" -- G5 BORDER\n");
        g_hosBorderLogged = true;
    }
}

private long drmSetHosWindows(ulong arg) @nogc nothrow {
    // arg layout: u32 count, u32 pad, then count × { i32 x,y,w,h; u32 pid }.
    uint count = userRead!uint(arg + 0);
    if (count > HOS_WIN_MAX) count = HOS_WIN_MAX;
    ulong p = arg + 8;
    foreach (i; 0 .. count) {
        g_hosWins[i].x   = userRead!int(p + 0);
        g_hosWins[i].y   = userRead!int(p + 4);
        g_hosWins[i].w   = userRead!int(p + 8);
        g_hosWins[i].h   = userRead!int(p + 12);
        g_hosWins[i].pid = userRead!uint(p + 16);
        p += 20;
    }
    g_hosWinCount = count;
    // Logged only a few times at startup — drmSetHosWindows runs every frame, so a
    // per-call klog would flood the serial UART and stall the compositor under KVM.
    static uint g_hosWinLogN = 0;
    if (g_hosWinLogN < 3) {
        klog("[g5] set windows count="); klog_hex(count); klog("\n");
        g_hosWinLogN++;
    }
    // Paint the borders now as well as on present: Hyprland's frame/present cadence
    // is sparse after a window maps, but it still reports windows each render, so
    // drawing here guarantees the border appears even without a fresh present blit.
    hosDrawIdentityBorders();
    return 0;
}

private long drmPresentToFramebuffer(ulong arg) @nogc nothrow {
    const ulong _t0 = rdtsc();
    if (!g_fb || g_fb.address == null || g_fb.pitch == 0 || g_fb.bpp != 32)
        return negErrno(ENODEV);

    ulong srcPtr  = userRead!ulong(arg + 0);
    uint srcW     = userRead!uint(arg + 8);
    uint srcH     = userRead!uint(arg + 12);
    uint srcPitch = userRead!uint(arg + 16);
    uint format   = userRead!uint(arg + 20);
    ulong srcSize = userRead!ulong(arg + 24);

    if (srcPtr == 0 || srcW == 0 || srcH == 0 || srcPitch == 0 || format == 0)
        return negErrno(EINVAL);

    const size_t bytesPerPixel = 4;
    const size_t minRowBytes = cast(size_t)srcW * bytesPerPixel;
    if (srcPitch < minRowBytes)
        return negErrno(EINVAL);
    if (srcSize != 0 && srcSize < cast(ulong)srcPitch * srcH)
        return negErrno(EINVAL);

    const uint copyW = srcW < g_fb.width ? srcW : cast(uint)g_fb.width;
    const uint copyH = srcH < g_fb.height ? srcH : cast(uint)g_fb.height;

    // EpinAnonymOS: blit only the damaged sub-rectangle (the persistent framebuffer
    // retains the rest), so a cursor move copies ~1 KB instead of 4 MB. The
    // compositor passes the damage bounding box at offsets 32..44; (0,0,0,0) — or a
    // box that lands outside the frame — falls back to a full-frame blit.
    uint dmgX = userRead!uint(arg + 32);
    uint dmgY = userRead!uint(arg + 36);
    uint dmgW = userRead!uint(arg + 40);
    uint dmgH = userRead!uint(arg + 44);

    uint x0, y0, blitW, blitH;
    if (dmgW == 0 || dmgH == 0 || dmgX >= copyW || dmgY >= copyH) {
        x0 = 0; y0 = 0; blitW = copyW; blitH = copyH;
    } else {
        x0 = dmgX; y0 = dmgY;
        blitW = (dmgX + dmgW <= copyW) ? dmgW : (copyW - dmgX);
        blitH = (dmgY + dmgH <= copyH) ? dmgH : (copyH - dmgY);
    }

    const size_t rowBytes = cast(size_t)blitW * bytesPerPixel;
    if (rowBytes > g_fb.pitch || rowBytes > srcPitch)
        return negErrno(EINVAL);
    const size_t xByteOff = cast(size_t)x0 * bytesPerPixel;

    auto src = cast(const(ubyte)*)srcPtr;
    auto dst = cast(ubyte*)g_fb.address;

    smapBegin();
    foreach (row; y0 .. y0 + blitH) {
        memcpy(dst + cast(size_t)row * cast(size_t)g_fb.pitch + xByteOff,
               src + cast(size_t)row * cast(size_t)srcPitch + xByteOff,
               rowBytes);
    }
    smapEnd();

    // GUI roadmap G5: overlay trusted identity borders for each client window.
    hosDrawIdentityBorders();

    g_fbConsoleEnabled = false;

    presentAccount(_t0, rdtsc(), cast(ulong)blitW * blitH,
                   (blitW >= copyW && blitH >= copyH));
    return 0;
}

// ── R2.4 — virtio-gpu / virgl render-node ioctls (DRM_VIRTGPU_*, nr 0x41..0x4b) ──
// A small GEM table maps per-open bo handles to host virgl resources; MAP returns
// the backing's physical address (FD_DRM mmap maps offset==phys into user VA).
// Backed by the modern virgl transport primitives in drivers/graphics/virtio_gpu.d
// (the same path the R2.3b self-test proved).  Single GPU consumer for now.
private struct DrmGem { bool used; uint resId; ulong phys; uint size; uint stride; uint blobMem; ulong shmemOffset; uint refs; }  // +B6: blobMem(0=classic,2=HOST3D), shmemOffset into the host-visible window; refs: PRIME alias/import refcount so GEM_CLOSE of one handle doesn't free a buffer another node still scans out
private __gshared DrmGem[64] g_drmGems;
// virtgpu GEM handles are based at 0x10000 so they never collide with the small KMS dumb-buffer
// handles that share the DRM_IOCTL_GEM_CLOSE namespace.
private enum uint DRM_VGEM_BASE = 0x10000;

private uint drmGemAlloc(uint resId, ulong phys, uint size, uint stride) @nogc nothrow {
    foreach (i; 0 .. g_drmGems.length) {
        if (!g_drmGems[i].used) {
            g_drmGems[i] = DrmGem(true, resId, phys, size, stride);
            g_drmGems[i].refs = 1;
            return DRM_VGEM_BASE + cast(uint)i;
        }
    }
    return 0;
}
private DrmGem* drmGemGet(uint handle) @nogc nothrow {
    if (handle < DRM_VGEM_BASE) return null;
    uint slot = handle - DRM_VGEM_BASE;
    if (slot >= g_drmGems.length || !g_drmGems[slot].used) return null;
    return &g_drmGems[slot];
}
// Free a virtgpu GEM: unref the host resource (detaches backing) then reclaim the guest backing page.
private void drmGemFreeHandle(uint handle) @nogc nothrow {
    auto g = drmGemGet(handle);
    if (g is null) return;
    // Refcount: a PRIME export (memfd alias) or cross-node import holds extra refs. Closing one
    // handle must not free a buffer that another DRM node (e.g. card0 scanout) still references.
    if (g.refs > 1) { --g.refs; return; }
    if (g.blobMem != 0) {
        // B8: a host-visible blob — its phys is the BAR window (NOT allocator RAM), so unmap it from
        // the window and unref; do NOT free_phys_pages (would corrupt the physical allocator).
        // (The window offset is not yet reclaimed — bump allocator only; fine for the 256MiB window.)
        gpuUnmapBlob(g.resId);
        gpuDrmResourceUnref(g.resId);
    } else {
        gpuDrmResourceUnref(g.resId);
        if (g.phys != 0) {
            uint pages = (g.size + 4095) / 4096; if (pages == 0) pages = 1;
            free_phys_pages(g.phys, pages);
        }
    }
    *g = DrmGem.init;   // used = false
}

extern(C) bool gpuDrm3dReady() @nogc nothrow;
extern(C) uint gpuDrmCreateResource3D(uint, uint, uint, uint, uint, uint, uint) @nogc nothrow;
extern(C) int  gpuDrmAttachBacking(uint, ulong, uint) @nogc nothrow;
extern(C) int  gpuDrmCtxAttach(uint) @nogc nothrow;
extern(C) int  gpuDrmSubmit3D(const(ubyte)*, uint) @nogc nothrow;
extern(C) int  gpuDrmTransferFromHost(uint, uint, uint, uint, uint, uint, uint, uint, uint, uint, uint) @nogc nothrow;
extern(C) int  gpuDrmTransferToHost(uint, uint, uint, uint, uint, uint, uint, uint, uint, uint, uint) @nogc nothrow;
extern(C) uint gpuDrmGetCapset(uint, uint, ubyte*, uint) @nogc nothrow;
extern(C) int  gpuDrmResourceUnref(uint) @nogc nothrow;
extern(C) bool  gpuBlobEnabled() @nogc nothrow;                                          // B5
extern(C) ulong gpuBlobWindowPhys() @nogc nothrow;                                       // B6
extern(C) uint  gpuBlobCreateMapped(ulong, ulong, const(ubyte)*, uint, ulong*, uint*) @nogc nothrow;  // B6
extern(C) int   gpuUnmapBlob(uint) @nogc nothrow;                                        // B8
private __gshared ubyte[2048] g_drmCapsScratch;

private long handleVirtgpuIoctl(uint nr, ulong arg) {
    import core.globals : hhdm_offset;
    switch (nr) {
    case 0x43: { // DRM_VIRTGPU_GETPARAM { u64 param; u64 value }
        // NB: `value` is a USERSPACE POINTER where the result is written (Linux virtio_gpu copies the
        // result to *value via copy_to_user) — NOT a field to write the result into. Mesa's virgl
        // winsys sets value=&local and reads back *value; writing the value field instead leaves it
        // reading garbage for 3D_FEATURES -> the screen-create gate fails -> softpipe fallback.
        ulong param    = userRead!ulong(arg + 0);
        ulong valuePtr = userRead!ulong(arg + 8);
        ulong val = 0;
        if (param == 1)      val = gpuDrm3dReady() ? 1 : 0;  // VIRTGPU_PARAM_3D_FEATURES
        else if (param == 2) val = 1;                        // VIRTGPU_PARAM_CAPSET_QUERY_FIX
        else if (param == 3) val = gpuBlobEnabled() ? 1 : 0; // B5: VIRTGPU_PARAM_RESOURCE_BLOB
        else if (param == 4) val = gpuBlobEnabled() ? 1 : 0; // B5: VIRTGPU_PARAM_HOST_VISIBLE (flips Mesa supports_coherent)
        // NB: do NOT advertise PARAM_CONTEXT_INIT(6) — it makes Mesa take the capset context-init path
        // that our no-op CONTEXT_INIT doesn't fully set up, and the virgl screen falls back to softpipe.
        if (valuePtr != 0) userWrite!ulong(valuePtr, val);
        return 0;
    }
    case 0x49: { // DRM_VIRTGPU_GET_CAPS { cap_set_id; cap_set_ver; u64 addr; size; pad }
        uint  capId  = userRead!uint(arg + 0);
        uint  capVer = userRead!uint(arg + 4);
        ulong addr   = userRead!ulong(arg + 8);
        uint  size   = userRead!uint(arg + 16);
        if (addr == 0 || size == 0) return 0;
        uint want = (size > g_drmCapsScratch.length) ? cast(uint)g_drmCapsScratch.length : size;
        uint got  = gpuDrmGetCapset(capId, capVer, g_drmCapsScratch.ptr, want);  // forward the host capset
        foreach (i; 0 .. size) userWrite!ubyte(addr + i, (i < got) ? g_drmCapsScratch[i] : 0);
        return 0;
    }
    case 0x4b: // DRM_VIRTGPU_CONTEXT_INIT — virgl context 1 already exists; accept
        return 0;
    case 0x44: { // DRM_VIRTGPU_RESOURCE_CREATE
        uint target = userRead!uint(arg + 0);
        uint format = userRead!uint(arg + 4);
        uint bind   = userRead!uint(arg + 8);
        uint width  = userRead!uint(arg + 12);
        uint height = userRead!uint(arg + 16);
        uint depth  = userRead!uint(arg + 20);
        uint arrsz  = userRead!uint(arg + 24);
        uint rid = gpuDrmCreateResource3D(target, format, bind, width, height, depth, arrsz);
        if (rid == 0) return negErrno(EINVAL);
        uint stride = width * 4;                          // BGRA / 4 bytes per texel
        uint size   = stride * (height ? height : 1);
        uint pages  = (size + 4095) / 4096; if (pages == 0) pages = 1;
        ulong phys  = alloc_phys_pages(pages);
        if (phys == 0) return negErrno(ENOMEM);
        auto bp = cast(uint*)(phys + hhdm_offset);        // zero the backing
        foreach (i; 0 .. (pages * 4096) / 4) bp[i] = 0;
        gpuDrmAttachBacking(rid, phys, pages * 4096);
        gpuDrmCtxAttach(rid);
        uint handle = drmGemAlloc(rid, phys, size, stride);
        if (handle == 0) return negErrno(ENOMEM);
        userWrite!uint(arg + 40, handle);   // bo_handle (returned)
        userWrite!uint(arg + 44, rid);      // res_handle (returned)
        userWrite!uint(arg + 48, size);     // size (returned)
        userWrite!uint(arg + 52, stride);   // stride (returned)
        return 0;
    }
    case 0x4a: { // DRM_VIRTGPU_RESOURCE_CREATE_BLOB (B6): a host-visible blob the client renders into and
                 // shares cross-process with the compositor.  blob_mem@0, size@16(u64), cmd_size@28,
                 // cmd@32(ptr), blob_id@40(u64); bo_handle@8 + res_handle@12 returned.
        uint  blobMem = userRead!uint(arg + 0);
        ulong size    = userRead!ulong(arg + 16);
        uint  cmdSize = userRead!uint(arg + 28);
        ulong cmdPtr  = userRead!ulong(arg + 32);
        ulong blobId  = userRead!ulong(arg + 40);
        if (blobMem != 0x2 || size == 0 || !gpuBlobEnabled()) return negErrno(EINVAL);  // HOST3D only
        if (cmdSize == 0 || cmdSize > 256) return negErrno(EINVAL);
        ubyte[256] cmdBuf;
        foreach (i; 0 .. cmdSize) cmdBuf[i] = userRead!ubyte(cmdPtr + i);
        ulong shmemOff; uint mapInfo;
        uint resId = gpuBlobCreateMapped(blobId, size, cmdBuf.ptr, cmdSize, &shmemOff, &mapInfo);
        if (resId == 0) return negErrno(EINVAL);
        // The GEM's mmap offset is the blob's guest-phys in the host-visible window (FD_DRM maps phys).
        uint bh = drmGemAlloc(resId, gpuBlobWindowPhys() + shmemOff, cast(uint)size, 0);
        if (bh == 0) return negErrno(ENOMEM);
        auto gb = drmGemGet(bh);
        if (gb !is null) { gb.blobMem = blobMem; gb.shmemOffset = shmemOff; }
        userWrite!uint(arg + 8,  bh);       // bo_handle (out)
        userWrite!uint(arg + 12, resId);    // res_handle (out)
        return 0;
    }
    case 0x45: { // DRM_VIRTGPU_RESOURCE_INFO { bo_handle; res_handle(out); size(out); blob_mem(out) }
        auto g = drmGemGet(userRead!uint(arg + 0));
        if (g is null) return negErrno(EINVAL);
        userWrite!uint(arg + 4, g.resId);
        userWrite!uint(arg + 8, g.size);
        userWrite!uint(arg + 12, g.blobMem);   // B6: !=0 -> the importer takes the blob (mappable) path
        return 0;
    }
    case 0x41: { // DRM_VIRTGPU_MAP { u64 offset(out); u32 handle; u32 pad }
        auto g = drmGemGet(userRead!uint(arg + 8));
        if (g is null) return negErrno(EINVAL);
        userWrite!ulong(arg + 0, g.phys);   // FD_DRM mmap maps offset==phys
        return 0;
    }
    case 0x42: { // DRM_VIRTGPU_EXECBUFFER { flags; size; u64 command; u64 bo_handles; num_bo_handles; ... }
        uint  size      = userRead!uint(arg + 4);
        ulong cmd       = userRead!ulong(arg + 8);
        ulong boHandles = userRead!ulong(arg + 16);
        uint  numBo     = userRead!uint(arg + 24);
        if (cmd == 0 || size == 0) return negErrno(EINVAL);
        // Residency: ctx-attach every referenced bo's resource before the submit so the virgl
        // command stream can resolve them (idempotent host-side; RESOURCE_CREATE already attaches).
        if (boHandles != 0 && numBo > 0 && numBo <= 256) {
            foreach (i; 0 .. numBo) {
                auto g = drmGemGet(userRead!uint(boHandles + i * 4));
                if (g !is null) gpuDrmCtxAttach(g.resId);
            }
        }
        return (gpuDrmSubmit3D(cast(const(ubyte)*)cmd, size) == 0) ? 0 : negErrno(EINVAL);
    }
    case 0x46:    // DRM_VIRTGPU_TRANSFER_FROM_HOST
    case 0x47: {  // DRM_VIRTGPU_TRANSFER_TO_HOST  (same struct layout)
        auto g = drmGemGet(userRead!uint(arg + 0));
        if (g is null) return negErrno(EINVAL);
        uint bx = userRead!uint(arg + 4),  by = userRead!uint(arg + 8),  bz = userRead!uint(arg + 12);
        uint bw = userRead!uint(arg + 16), bh = userRead!uint(arg + 20), bd = userRead!uint(arg + 24);
        uint level  = userRead!uint(arg + 28), offset  = userRead!uint(arg + 32);
        uint stride = userRead!uint(arg + 36), lstride = userRead!uint(arg + 40);
        if (stride == 0) stride = g.stride;
        int r = (nr == 0x46)
            ? gpuDrmTransferFromHost(g.resId, bx, by, bz, bw, bh, bd, level, offset, stride, lstride)
            : gpuDrmTransferToHost  (g.resId, bx, by, bz, bw, bh, bd, level, offset, stride, lstride);
        return (r == 0) ? 0 : negErrno(EINVAL);
    }
    case 0x48: // DRM_VIRTGPU_WAIT — synchronous transport, already complete
        return 0;
    default:
        return negErrno(EINVAL);
    }
}

private long handleDrmIoctl(int ifd, ulong request, ulong arg) {
    // NB: do NOT log per ioctl here — DRM_NR_HOS_PRESENT (0xf0) fires on every
    // frame, so a klog/console write per call floods the slow serial UART and,
    // under KVM, throttles the whole compositor (one VM-exit per byte).
    uint nr = request & 0xFF;
    // DRM_IOCTL_SET_MASTER (0x1e) and DROP_MASTER (0x1f) are DRM_IO() ioctls: they carry
    // NO argument, so seatd calls ioctl(fd, DRM_IOCTL_SET_MASTER, 0) (seatd-0.9.1
    // common/drm.c:17).  The blanket arg==0 guard below answered those with EFAULT and
    // made the `case DRM_NR_SET_MASTER: return 0;` further down unreachable dead code —
    // which is where the boot log's "Could not make device fd drm master: Bad address"
    // comes from.  Exempt exactly those two; every other DRM ioctl dereferences arg.
    if (arg == 0 && nr != DRM_NR_SET_MASTER && nr != DRM_NR_DROP_MASTER)
        return negErrno(EFAULT);

    // R2.4: virtio-gpu / virgl render ioctls (DRM_COMMAND_BASE 0x40 + DRM_VIRTGPU_* 0x01..0x0b).
    if (nr >= 0x41 && nr <= 0x4b) return handleVirtgpuIoctl(nr, arg);

    switch (nr) {
    case DRM_NR_VERSION: {
        userWrite!int(arg + 0, 0);   // version_major MUST be 0 — Mesa's virgl winsys rejects major != 0
                                     // (virgl_drm_get_version -> -EINVAL -> screen-create NULL -> softpipe)
        userWrite!int(arg + 4, 0);   // version_minor 0 = legacy busy-poll fences (our uABI has no fence-fd export)
        userWrite!int(arg + 8, 0);

        ulong nameLen = userRead!ulong(arg + 16);
        ulong namePtr = userRead!ulong(arg + 24);
        immutable char[11] drvnm = "virtio_gpu\0";

        if (nameLen > 0 && namePtr != 0) {
            size_t n = nameLen < 10 ? cast(size_t)nameLen : 10;
            userCopyString(namePtr, drvnm.ptr, n);
        }
        userWrite!ulong(arg + 16, 10);

        // Return non-empty date/desc.  libdrm's drmGetVersion / callers wrap
        // these in std::string(version->date) etc.; if the kernel reports length
        // 0 the pointer stays NULL and strlen(NULL) faults.
        immutable char[9]  drvdate = "20200101\0";
        ulong dateLen = userRead!ulong(arg + 32);
        ulong datePtr = userRead!ulong(arg + 40);
        if (dateLen > 0 && datePtr != 0) {
            size_t n = dateLen < 8 ? cast(size_t)dateLen : 8;
            userCopyString(datePtr, drvdate.ptr, n);
        }
        userWrite!ulong(arg + 32, 8);

        immutable char[11] drvdesc = "Virtio GPU\0";
        ulong descLen = userRead!ulong(arg + 48);
        ulong descPtr = userRead!ulong(arg + 56);
        if (descLen > 0 && descPtr != 0) {
            size_t n = descLen < 10 ? cast(size_t)descLen : 10;
            userCopyString(descPtr, drvdesc.ptr, n);
        }
        userWrite!ulong(arg + 48, 10);

        return 0;
    }

    case DRM_NR_GET_CAP: {
        ulong cap = userRead!ulong(arg + 0);
        ulong val = 0;

        switch (cap) {
        case DRM_CAP_DUMB_BUFFER:          val = 1;  break;
        case DRM_CAP_DUMB_PREFERRED_DEPTH: val = 32; break;
        // R3: advertise dma-buf import|export. Mesa's virgl reads this as
        // PIPE_CAP_DMABUF → wires createImageFromDmaBufs → the EGL display
        // advertises EGL_EXT_image_dma_buf_import → Weston enables dmabuf → GPU
        // Wayland clients (gl-term/gl-wl-test) render on virgl, not softpipe.
        case DRM_CAP_PRIME:                val = 0x3; break;  // IMPORT(1)|EXPORT(2)
        case DRM_CAP_TIMESTAMP_MONOTONIC:  val = 1;  break;
        case DRM_CAP_CURSOR_WIDTH:         val = 64; break;
        case DRM_CAP_CURSOR_HEIGHT:        val = 64; break;
        case DRM_CAP_CRTC_IN_VBLANK_EVENT: val = 1;  break;  // aquamarine checkFeatures: fatal if 0
        default: break;
        }

        userWrite!ulong(arg + 8, val);
        return 0;
    }

    // struct drm_set_client_cap { u64 capability; u64 value; }
    // We implement legacy KMS only (SETCRTC + PAGE_FLIP), not atomic commit, so
    // refuse DRM_CLIENT_CAP_ATOMIC — that makes Weston's DRM backend fall back to
    // the legacy modeset path (MODE_ATOMIC would otherwise be attempted and fail).
    case DRM_NR_SET_CLIENT_CAP: {
        ulong capId = userRead!ulong(arg + 0);
        if (capId == DRM_CLIENT_CAP_ATOMIC) return negErrno(EOPNOTSUPP);
        return 0;
    }

    case DRM_NR_GEM_CLOSE: {
        uint handle = userRead!uint(arg + 0);
        if (handle >= DRM_VGEM_BASE) { drmGemFreeHandle(handle); return 0; }  // virtgpu GEM
        GemBuf* g = findGem(handle);
        if (g) {
            if (g.vmoObjId != 0 && objGet(g.vmoObjId) !is null)
                objRelease(g.vmoObjId);
            g.vmoObjId = 0;
            g.inUse = false;
        }
        return 0;
    }

    case DRM_NR_WAIT_VBLANK:
    case DRM_NR_AUTH_MAGIC:
    case DRM_NR_SET_MASTER:
    case DRM_NR_DROP_MASTER:
        return 0;

    // DRM_IOCTL_MODE_CREATE_LEASE (0xc6): we don't implement leases.  The default
    // case below would STUB-succeed (return 0) WITHOUT setting the output lease fd,
    // so aquamarine's reopenDRMNode() takes that garbage fd and CGBMAllocator::create
    // then fails drmGetCap(badfd, DRM_CAP_PRIME) → "PRIME export is not supported by
    // the gpu" → no GBM allocator → software readback → crash.  Returning EOPNOTSUPP
    // makes reopenDRMNode fall through to drmGetDeviceNameFromFd2 + open() the real
    // node (whose GET_CAP correctly reports PRIME import|export = 0x3).
    case 0xC6:
        return negErrno(EOPNOTSUPP);

    // struct drm_prime_handle { u32 handle; u32 flags; s32 fd; }
    // Export a dumb GEM buffer as a dma-buf fd.  Aquamarine's headless allocator
    // requires this to succeed (else attrs.success stays false and the swapchain
    // can't acquire a buffer).  We hand back an fd that aliases the GEM's physical
    // pages via the memfd machinery, so mmap'ing the prime fd yields the same
    // pixels as the dumb buffer.
    case DRM_NR_PRIME_HANDLE_TO_FD: {
        uint handle = userRead!uint(arg + 0);

        // R3: a virgl GEM (handle >= 0x10000) lives in g_drmGems, not the dumb GemBuf
        // table.  Export it as an FD_MEMFD aliasing the virtgpu resource's backing pages
        // and tag it with vgemHandle so the importer (Weston) recovers the *same*
        // g_drmGems handle → RESOURCE_INFO → the device-global virgl resource it samples.
        if (handle >= DRM_VGEM_BASE) {
            DrmGem* g = drmGemGet(handle);
            if (!g) return negErrno(EINVAL);

            int vslot = -1;
            foreach (i, ref m; g_memfds) { if (!m.inUse) { vslot = cast(int)i; break; } }
            if (vslot < 0) return negErrno(ENOSPC);
            int vnfd = -1;
            for (int i = 3; i < 1024; ++i)
                if (g_fdTable[i].type == FileType.FD_NONE) { vnfd = i; break; }
            if (vnfd < 0) return negErrno(EMFILE);

            g_memfds[vslot].inUse      = true;
            g_memfds[vslot].refs       = 1;
            g_memfds[vslot].physBase   = g.phys;
            g_memfds[vslot].size       = g.size;
            g_memfds[vslot].seals      = 0;
            g_memfds[vslot].vmoObjId   = 0;       // virgl GEMs carry no VMO identity
            g_memfds[vslot].aliased    = true;    // borrowed pages → reclaim on close
            g_memfds[vslot].vgemHandle = handle;  // mark as a virgl PRIME alias
            ++g.refs;                             // the memfd alias holds a reference to the resource

            g_fdTable[vnfd].type     = FileType.FD_MEMFD;
            g_fdTable[vnfd].flags    = 0;
            g_fdTable[vnfd].offset   = 0;
            g_fdTable[vnfd].backend  = cast(void*)cast(size_t)vslot;
            g_fdTable[vnfd].fileSize = g.size;

            userWrite!int(arg + 8, vnfd);
            return 0;
        }

        GemBuf* gem = findGem(handle);
        if (!gem) return negErrno(EINVAL);

        int slot = -1;
        foreach (i, ref m; g_memfds) { if (!m.inUse) { slot = cast(int)i; break; } }
        if (slot < 0) return negErrno(ENOSPC);

        int nfd = -1;
        for (int i = 3; i < 1024; ++i)
            if (g_fdTable[i].type == FileType.FD_NONE) { nfd = i; break; }
        if (nfd < 0) return negErrno(EMFILE);

        g_memfds[slot].inUse      = true;
        g_memfds[slot].refs       = 1;
        g_memfds[slot].physBase   = gem.physAddr;
        g_memfds[slot].size       = gem.size;
        g_memfds[slot].seals      = 0;
        g_memfds[slot].vmoObjId   = ensureGemVmo(gem);
        if (g_memfds[slot].vmoObjId != 0)
            objRetain(g_memfds[slot].vmoObjId);
        g_memfds[slot].aliased    = true;
        g_memfds[slot].vgemHandle = 0;   // dumb-buffer alias, not virgl

        g_fdTable[nfd].type     = FileType.FD_MEMFD;
        g_fdTable[nfd].flags    = 0;
        g_fdTable[nfd].offset   = 0;
        g_fdTable[nfd].backend  = cast(void*)cast(size_t)slot;
        g_fdTable[nfd].fileSize = gem.size;

        userWrite!int(arg + 8, nfd);     // drm_prime_handle.fd (output)
        return 0;
    }

    // struct drm_prime_handle { u32 handle(out); u32 flags; s32 fd(in); }
    // Inverse of PRIME_HANDLE_TO_FD.  Mesa's kms_swrast winsys imports a dma-buf
    // by calling this to recover the GEM handle, then MODE_MAP_DUMB(handle) +
    // mmap to render into it.  Our prime fd is an FD_MEMFD aliasing the GEM's
    // physical pages, so map fd → memfd physBase → the GEM with that physAddr.
    // (Without this the import returns NULL, the output render target is invalid,
    // and Hyprland's frame never lands in the buffer — the screen stays at the
    // dumb buffer's initial 0xFF memset.)
    case DRM_NR_PRIME_FD_TO_HANDLE: {
        int infd = userRead!int(arg + 8);
        if (infd < 0 || infd >= 1024) return negErrno(EINVAL);
        File* pf = &g_fdTable[infd];
        if (pf.type != FileType.FD_MEMFD) {
            if (g_primeDbgN < 16) { ++g_primeDbgN; klog("[prime] fd="); klog_hex(infd); klog(" FAIL not-memfd type="); klog_hex(cast(uint)pf.type); klog("\n"); }
            return negErrno(EINVAL);
        }
        int mid = cast(int)cast(size_t)pf.backend;
        if (mid < 0 || mid >= MEMFD_MAX || !g_memfds[mid].inUse) {
            if (g_primeDbgN < 16) { ++g_primeDbgN; klog("[prime] fd="); klog_hex(infd); klog(" FAIL memfd-not-inuse mid="); klog_hex(cast(uint)mid); klog("\n"); }
            return negErrno(EINVAL);
        }

        // R3: a virgl PRIME alias — hand back the originating g_drmGems handle so the
        // importer's RESOURCE_INFO resolves to the same device-global virgl resource
        // (the dumb-buffer physBase reverse-map below is only for KMS dumb buffers).
        if (g_memfds[mid].vgemHandle != 0) {
            // Cross-node import: the returned handle is a fresh reference on the same
            // device-global resource. Bump refs so a later GEM_CLOSE of the exporter's
            // handle doesn't free the buffer while this node still scans it out.
            DrmGem* ig = drmGemGet(g_memfds[mid].vgemHandle);
            if (ig !is null) ++ig.refs;
            userWrite!uint(arg + 0, g_memfds[mid].vgemHandle);
            return 0;
        }

        ulong phys = g_memfds[mid].physBase;
        uint handle = 0;
        foreach (ref gb; g_gemBufs) {
            if (gb.inUse && gb.physAddr == phys) { handle = gb.handle; break; }
        }
        // Reverse-map fallback: the memfd may alias a virgl resource whose vgemHandle
        // field was never stamped at export (aquamarine PRIME-exports a GBM scanout bo
        // by phys). Scan g_drmGems by phys and hand back a fresh reference so the
        // importer's ADDFB2 resolves — same buffer, +1 ref so a later GEM_CLOSE of the
        // exporter's handle doesn't free it out from under this node's scanout.
        if (handle == 0) {
            foreach (i; 0 .. g_drmGems.length) {
                if (g_drmGems[i].used && g_drmGems[i].phys == phys) {
                    ++g_drmGems[i].refs;
                    handle = DRM_VGEM_BASE + cast(uint)i;
                    break;
                }
            }
        }
        // CPU-scanout alias: a plain (memfd_create-backed) buffer used as a KMS scanout
        // target — the DATAPTR / CPU-readback present path where Hyprland glReadPixels
        // its rendered frame straight into the memfd's guest pages, then commits the memfd
        // for scanout. It is not a GEM in either table, so register a dumb GEM ALIAS over
        // the memfd's contiguous backing: drmAddFb then resolves it with resId=0, so
        // drmPresentFb blits the guest pages directly (no host transfer — the pixels are
        // already CPU-side). The alias does NOT own the pages (the memfd frees them);
        // GEM_CLOSE only clears the slot, so there is no double free.
        if (handle == 0 && phys != 0) {
            int gslot = -1;
            foreach (i, ref gb; g_gemBufs)
                if (!gb.inUse) { gslot = cast(int)i; break; }
            if (gslot >= 0) {
                uint nh = g_nextGemHandle++;
                g_gemBufs[gslot].inUse    = true;
                g_gemBufs[gslot].handle   = nh;
                g_gemBufs[gslot].physAddr = phys;
                g_gemBufs[gslot].width    = 0;
                g_gemBufs[gslot].height   = 0;
                g_gemBufs[gslot].pitch    = 0;
                g_gemBufs[gslot].bpp      = 32;
                g_gemBufs[gslot].size     = g_memfds[mid].size;
                g_gemBufs[gslot].vmoObjId = 0;
                handle = nh;
                if (g_primeDbgN < 16) { ++g_primeDbgN; klog("[prime] fd="); klog_hex(infd); klog(" CPU-alias handle="); klog_hex(nh); klog(" phys="); klog_hex(phys); klog("\n"); }
            }
        }
        if (handle == 0) {
            if (g_primeDbgN < 16) { ++g_primeDbgN; klog("[prime] fd="); klog_hex(infd); klog(" FAIL no-revmap phys="); klog_hex(phys); klog("\n"); }
            return negErrno(EINVAL);
        }
        userWrite!uint(arg + 0, handle);
        return 0;
    }

    case DRM_NR_MODE_GETRESOURCES: {
        dispMark(g_dispLogRes, "drm getresources\0".ptr);
        uint cnt_crtcs = userRead!uint(arg + 36);
        uint cnt_conns = userRead!uint(arg + 40);
        uint cnt_encs  = userRead!uint(arg + 44);

        ulong crtcPtr = userRead!ulong(arg + 8);
        ulong connPtr = userRead!ulong(arg + 16);
        ulong encPtr  = userRead!ulong(arg + 24);

        if (cnt_crtcs >= 1 && crtcPtr != 0) userWrite!uint(crtcPtr, 1);
        if (cnt_conns >= 1 && connPtr != 0) userWrite!uint(connPtr, 1);
        if (cnt_encs  >= 1 && encPtr  != 0) userWrite!uint(encPtr, 1);

        userWrite!uint(arg + 32, 0);
        userWrite!uint(arg + 36, 1);
        userWrite!uint(arg + 40, 1);
        userWrite!uint(arg + 44, 1);

        uint maxW = g_fb ? cast(uint)g_fb.width  : 1920;
        uint maxH = g_fb ? cast(uint)g_fb.height : 1080;

        userWrite!uint(arg + 48, 0);
        userWrite!uint(arg + 52, maxW);
        userWrite!uint(arg + 56, 0);
        userWrite!uint(arg + 60, maxH);
        return 0;
    }

    case DRM_NR_MODE_GETCRTC: {
        userWrite!uint(arg + 12, 1);
        userWrite!uint(arg + 16, 0);
        userWrite!uint(arg + 20, 0);
        userWrite!uint(arg + 24, 0);
        userWrite!uint(arg + 28, 256);
        userWrite!uint(arg + 32, 1);

        smapBegin();
        fillModeInfo(cast(ubyte*)(arg + 36));
        smapEnd();

        return 0;
    }

    // struct drm_mode_crtc { u64 set_connectors_ptr; u32 count_connectors;
    //   u32 crtc_id; u32 fb_id; u32 x; u32 y; u32 gamma_size; u32 mode_valid;
    //   struct drm_mode_modeinfo mode; }
    // The initial (legacy) modeset binds a framebuffer to the CRTC and scans it
    // out; present it immediately. fb_id == 0 means "disable the CRTC" (blank).
    case DRM_NR_MODE_SETCRTC: {
        uint fbId = userRead!uint(arg + 16);
        dispOp("setcrtc fb=", fbId);
        if (fbId == 0) return 0;
        return drmPresentFb(fbId);
    }

    case DRM_NR_MODE_GETENCODER: {
        userWrite!uint(arg + 0, 1);
        userWrite!uint(arg + 4, 2);
        userWrite!uint(arg + 8, 1);
        userWrite!uint(arg + 12, 1);
        userWrite!uint(arg + 16, 0);
        return 0;
    }

    case DRM_NR_MODE_GETCONNECTOR: {
        if (!g_dispLogConn) {
            console_framebuffer_write("\n[disp] drm getconnector mode=");
            dispFbDec(g_fb ? cast(ulong)g_fb.width  : 0); console_framebuffer_write("x");
            dispFbDec(g_fb ? cast(ulong)g_fb.height : 0);
            console_framebuffer_write(" bpp="); dispFbDec(g_fb ? cast(ulong)g_fb.bpp : 0);
            g_dispLogConn = true;
        }
        uint reqModes = userRead!uint(arg + 32);
        uint reqEncs  = userRead!uint(arg + 40);

        ulong modesPtr = userRead!ulong(arg + 8);
        ulong encPtr   = userRead!ulong(arg + 0);

        if (reqModes >= 1 && modesPtr != 0) {
            smapBegin();
            fillModeInfo(cast(ubyte*)modesPtr);
            smapEnd();
        }

        if (reqEncs >= 1 && encPtr != 0) {
            userWrite!uint(encPtr, 1);
        }

        userWrite!uint(arg + 32, 1);
        userWrite!uint(arg + 36, 0);
        userWrite!uint(arg + 40, 1);
        userWrite!uint(arg + 44, 1);
        userWrite!uint(arg + 48, 1);
        userWrite!uint(arg + 52, 11);
        userWrite!uint(arg + 56, 1);
        userWrite!uint(arg + 60, 1);

        uint mmW = g_fb ? cast(uint)(g_fb.width  * 27 / 96) : 530;
        uint mmH = g_fb ? cast(uint)(g_fb.height * 27 / 96) : 300;

        userWrite!uint(arg + 64, mmW);
        userWrite!uint(arg + 68, mmH);
        userWrite!uint(arg + 72, 0);
        userWrite!uint(arg + 76, 0);
        return 0;
    }

    // struct drm_mode_fb_cmd { u32 fb_id(out); u32 width; u32 height;
    //                          u32 pitch; u32 bpp; u32 depth; u32 handle; }
    case DRM_NR_MODE_ADDFB: {
        uint width  = userRead!uint(arg + 4);
        uint height = userRead!uint(arg + 8);
        uint pitch  = userRead!uint(arg + 12);
        uint bpp    = userRead!uint(arg + 16);
        uint handle = userRead!uint(arg + 24);
        uint id = drmAddFb(handle, width, height, pitch, bpp);
        dispOp("addfb id=", id);
        if (id == 0) return negErrno(EINVAL);
        userWrite!uint(arg + 0, id);
        return 0;
    }

    // struct drm_mode_fb_cmd2 { u32 fb_id(out); u32 width; u32 height;
    //   u32 pixel_format; u32 flags; u32 handles[4]; u32 pitches[4];
    //   u32 offsets[4]; u64 modifier[4]; }
    case DRM_NR_MODE_ADDFB2: {
        uint width   = userRead!uint(arg + 4);
        uint height  = userRead!uint(arg + 8);
        uint fourcc  = userRead!uint(arg + 12);
        uint handle  = userRead!uint(arg + 20);   // handles[0]
        uint pitch   = userRead!uint(arg + 36);   // pitches[0]
        uint id = drmAddFb(handle, width, height, pitch, fourcc);
        dispOp("addfb2 id=", id);
        if (id == 0) return negErrno(EINVAL);
        userWrite!uint(arg + 0, id);
        return 0;
    }

    case DRM_NR_MODE_RMFB: {
        uint id = userRead!uint(arg + 0);          // arg points at the fb_id
        DrmFb* fb = findDrmFb(id);
        if (fb) fb.inUse = false;
        return 0;
    }

    // struct drm_mode_crtc_page_flip { u32 crtc_id; u32 fb_id; u32 flags;
    //                                  u32 reserved; u64 user_data; }
    // Present the target framebuffer now and, if the caller asked for a flip
    // event, queue a completion the compositor reads back from the card fd.
    case DRM_NR_MODE_PAGE_FLIP: {
        uint fbId     = userRead!uint(arg + 4);
        uint flags    = userRead!uint(arg + 8);
        ulong userData = userRead!ulong(arg + 16);
        dispOp("pageflip fb=", fbId);
        long pr = drmPresentFb(fbId);
        if (pr < 0) return pr;
        if (flags & DRM_MODE_PAGE_FLIP_EVENT)
            drmQueueFlipEvent(ifd, userData);
        return 0;
    }

    // FB damage hint — we always present the whole framebuffer, so this is a
    // no-op success. (Weston's Pixman+DRM path may call drmModeDirtyFB.)
    case DRM_NR_MODE_DIRTYFB:
        return 0;

    // ── Universal-planes enumeration (Weston requires a PRIMARY plane) ───────
    // Weston's DRM backend mandates DRM_CLIENT_CAP_UNIVERSAL_PLANES, then refuses
    // to start unless it finds a primary plane bound to the CRTC. We expose a
    // single primary plane (id DRM_PLANE_ID) whose "type" property reports
    // "Primary", which lets the legacy modeset path scan out our framebuffer.

    // struct drm_mode_get_plane_res { u64 plane_id_ptr; u32 count_planes; }
    case DRM_NR_MODE_GETPLANERESOURCES: {
        ulong planePtr = userRead!ulong(arg + 0);
        uint  inCount  = userRead!uint(arg + 8);
        if (inCount >= 1 && planePtr != 0)
            userWrite!uint(planePtr, DRM_PLANE_ID);
        userWrite!uint(arg + 8, 1);
        return 0;
    }

    // struct drm_mode_get_plane { u32 plane_id; u32 crtc_id; u32 fb_id;
    //   u32 possible_crtcs; u32 gamma_size; u32 count_format_types;
    //   u64 format_type_ptr; }
    case DRM_NR_MODE_GETPLANE: {
        userWrite!uint(arg + 4, 0);   // crtc_id (unbound)
        userWrite!uint(arg + 8, 0);   // fb_id
        userWrite!uint(arg + 12, 1);  // possible_crtcs = bit 0 (our only CRTC, pipe 0)
        userWrite!uint(arg + 16, 0);  // gamma_size

        uint  inCount = userRead!uint(arg + 20);
        ulong fmtPtr  = userRead!ulong(arg + 24);
        if (fmtPtr != 0 && inCount >= 1) {
            userWrite!uint(fmtPtr + 0, DRM_FORMAT_XRGB8888);
            if (inCount >= 2) userWrite!uint(fmtPtr + 4, DRM_FORMAT_ARGB8888);
        }
        userWrite!uint(arg + 20, 2);  // count_format_types
        return 0;
    }

    case DRM_NR_MODE_SETPLANE:
        return 0;

    // struct drm_mode_obj_get_properties { u64 props_ptr; u64 prop_values_ptr;
    //   u32 count_props; u32 obj_id; u32 obj_type; }
    // Only the primary plane carries a property ("type"); all other objects
    // report zero properties (fine for the legacy, non-atomic path).
    case DRM_NR_MODE_OBJ_GETPROPERTIES: {
        uint objType = userRead!uint(arg + 24);
        uint objId   = userRead!uint(arg + 20);
        // aquamarine's getDRMProp queries with DRM_MODE_OBJECT_ANY (0) + the plane id
        // (not OBJECT_PLANE like Weston), so match on the object ID too — otherwise it
        // reads 0 props, can't resolve the "type" value, and aqPlane->init fails →
        // "Failed initializing resources" → DRM Backend failed.
        if (objType == DRM_MODE_OBJECT_PLANE || objId == DRM_PLANE_ID) {
            ulong propsPtr  = userRead!ulong(arg + 0);
            ulong valuesPtr = userRead!ulong(arg + 8);
            uint  inCount   = userRead!uint(arg + 16);
            if (inCount >= 1 && propsPtr != 0 && valuesPtr != 0) {
                userWrite!uint(propsPtr,  DRM_PLANE_PROP_ID_TYPE);
                userWrite!ulong(valuesPtr, DRM_PLANE_TYPE_PRIMARY);
            }
            userWrite!uint(arg + 16, 1);
        } else {
            userWrite!uint(arg + 16, 0);
        }
        return 0;
    }

    // struct drm_mode_get_property { u64 values_ptr; u64 enum_blob_ptr;
    //   u32 prop_id; u32 flags; char name[32]; u32 count_values;
    //   u32 count_enum_blobs; }   (name at +24, counts at +56/+60)
    // We expose exactly one property: the plane "type" enum, with a single
    // entry { value=1, name="Primary" } which Weston matches by name.
    case DRM_NR_MODE_GETPROPERTY: {
        uint propId = userRead!uint(arg + 16);
        if (propId != DRM_PLANE_PROP_ID_TYPE) return negErrno(EINVAL);

        userWrite!uint(arg + 20, DRM_MODE_PROP_ENUM);   // flags
        // name[32] = "type"
        immutable char[5] nm = "type\0";
        smapBegin();
        auto np = cast(ubyte*)(arg + 24);
        foreach (i; 0 .. 32) np[i] = (i < 5) ? cast(ubyte)nm[i] : 0;
        smapEnd();

        ulong valuesPtr = userRead!ulong(arg + 0);
        ulong enumPtr   = userRead!ulong(arg + 8);
        uint  inValues  = userRead!uint(arg + 56);
        uint  inEnums   = userRead!uint(arg + 60);

        if (valuesPtr != 0 && inValues >= 1)
            userWrite!ulong(valuesPtr, DRM_PLANE_TYPE_PRIMARY);
        if (enumPtr != 0 && inEnums >= 1) {
            // struct drm_mode_property_enum { u64 value; char name[32]; }
            userWrite!ulong(enumPtr + 0, DRM_PLANE_TYPE_PRIMARY);
            immutable char[8] pn = "Primary\0";
            smapBegin();
            auto ep = cast(ubyte*)(enumPtr + 8);
            foreach (i; 0 .. 32) ep[i] = (i < 8) ? cast(ubyte)pn[i] : 0;
            smapEnd();
        }
        userWrite!uint(arg + 56, 1);   // count_values
        userWrite!uint(arg + 60, 1);   // count_enum_blobs
        return 0;
    }

    // Hardware cursor — our KMS present path only scans out the primary plane,
    // so a legacy hardware cursor (drmModeSetCursor) would never appear.  Fail
    // these so Weston marks the cursor "broken" and composites it through the
    // Pixman renderer into the primary framebuffer instead (which we do present),
    // making the pointer actually visible.
    case DRM_NR_MODE_CURSOR:
    case DRM_NR_MODE_CURSOR2:
        return negErrno(EINVAL);

    case DRM_NR_MODE_ATOMIC:
        dispOp("atomic->EINVAL (legacy fallback expected) ", 0);
        return negErrno(EINVAL);

    case DRM_NR_HOS_PRESENT:
        return drmPresentToFramebuffer(arg);

    case DRM_NR_HOS_WINDOWS:
        return drmSetHosWindows(arg);

    case DRM_NR_MODE_CREATE_DUMB: {
        uint h   = userRead!uint(arg + 0);
        uint w   = userRead!uint(arg + 4);
        uint bpp = userRead!uint(arg + 8);

        if (bpp == 0) bpp = 32;
        if (!g_dispLogDumb) {
            console_framebuffer_write("\n[disp] create_dumb "); dispFbDec(w);
            console_framebuffer_write("x"); dispFbDec(h);
            console_framebuffer_write(" (panel "); dispFbDec(g_fb ? cast(ulong)g_fb.width : 0);
            console_framebuffer_write("x"); dispFbDec(g_fb ? cast(ulong)g_fb.height : 0);
            console_framebuffer_write(")");
            g_dispLogDumb = true;
        }

        uint pitch = (w * bpp / 8 + 63) & ~63u;
        ulong sz = cast(ulong)pitch * h;

        size_t pages = cast(size_t)((sz + 4095) >> 12);
        ulong physAddr = alloc_phys_pages(pages);
        if (!physAddr) { dispOp("create_dumb ENOSPC pages=", pages); return negErrno(ENOSPC); }

        if (g_fb && w == g_fb.width && h == g_fb.height) {
            // Userspace (Hyprland) is taking over the display.  Keep dumb buffers
            // distinct, but stop drawing the kernel text console over GUI output.
            g_fbConsoleEnabled = false;
            g_desktopClaimedFb = true;   // permanently silence ALL kernel fb drawing (incl. fault log + diagnostics)
        }

        int slot = -1;
        foreach (i, ref gb; g_gemBufs) {
            if (!gb.inUse) {
                slot = cast(int)i;
                break;
            }
        }

        if (slot < 0) return negErrno(ENOSPC);

        uint handle = g_nextGemHandle++;

        g_gemBufs[slot].inUse    = true;
        g_gemBufs[slot].handle   = handle;
        g_gemBufs[slot].physAddr = physAddr;
        g_gemBufs[slot].width    = w;
        g_gemBufs[slot].height   = h;
        g_gemBufs[slot].pitch    = pitch;
        g_gemBufs[slot].bpp      = bpp;
        g_gemBufs[slot].size     = sz;
        g_gemBufs[slot].vmoObjId = 0;
        uint vmoObjId = ensureGemVmo(&g_gemBufs[slot]);
        physPagesSetOwner(physAddr, pages, 0, vmoObjId);

        userWrite!uint(arg + 16, handle);
        userWrite!uint(arg + 20, pitch);
        userWrite!ulong(arg + 24, sz);
        return 0;
    }

    case DRM_NR_MODE_MAP_DUMB: {
        uint handle = userRead!uint(arg + 0);
        GemBuf* gem = findGem(handle);
        if (!gem) return negErrno(EINVAL);

        userWrite!ulong(arg + 8, gem.physAddr);
        return 0;
    }

    case DRM_NR_MODE_DESTROY_DUMB: {
        uint handle = userRead!uint(arg + 0);
        GemBuf* gem = findGem(handle);
        if (gem) {
            if (gem.vmoObjId != 0 && objGet(gem.vmoObjId) !is null)
                objRelease(gem.vmoObjId);
            gem.vmoObjId = 0;
            gem.inUse = false;
        }
        return 0;
    }

    default:
        return 0;
    }
}

// ── Stubs for syscalls referenced by kernel_main.d dispatch table ─────────────

public long linux_sys_epoll_create(ulong size) {
    return linux_sys_epoll_create1(0);
}

public long linux_sys_epoll_pwait2(ulong epfd, ulong events, ulong maxevents,
                                   ulong timeout, ulong sigmask) {
    return negErrno(ENOSYS);
}

public long linux_sys_faccessat(ulong dirfd, ulong path, ulong mode, ulong flags) {
    return linux_sys_access(path, mode);
}

public long linux_sys_getrlimit(ulong resource, ulong rlim) {
    return linux_sys_prlimit64(0, resource, 0, rlim);
}

public long linux_sys_getsid(ulong pid) { return 1; }

public long linux_sys_inotify_init() { return linux_sys_inotify_init1(0); }

public long linux_sys_linkat(ulong olddir, ulong oldpath,
                              ulong newdir, ulong newpath, ulong flags) {
    return negErrno(ENOSYS);
}

public long linux_sys_renameat(ulong olddir, ulong oldpath,
                               ulong newdir, ulong newpath) {
    return linux_sys_renameat2(olddir, oldpath, newdir, newpath, 0);
}

public long linux_sys_sched_setparam(ulong pid, ulong param) { return 0; }
public long linux_sys_sched_getparam(ulong pid, ulong param) { return 0; }

public long linux_sys_setreuid(ulong ruid, ulong euid) {
    return linux_sys_setresuid(ruid, euid, ulong.max);
}

public long linux_sys_userfaultfd(ulong flags) { return negErrno(ENOSYS); }
