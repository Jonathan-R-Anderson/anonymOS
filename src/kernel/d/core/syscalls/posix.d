module core.syscalls.posix;

import core.io : inb;
import core.console : console_putchar, console_backspace, g_fbConsoleEnabled;
import core.syscalls.socket : sockaddr, sockaddr_un, msghdr, iovec, cmsghdr,
                              AF_UNIX, AF_INET, AF_NETLINK, SOCK_STREAM, SOCK_DGRAM,
                              SOL_SOCKET, SCM_RIGHTS;
import core.exports : g_module_count, g_mboot_modules, phys_to_virt,
                      g_current_task_id, d_store_task_fsbase;
import core.random;
import core.io;
import core.stdc.string : memcpy;
import core.task : g_tasks, MAX_TASKS, linuxPidForTask, linuxTidForTask,
                   objEnsureNamespace;
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
import core.namespace : nsResolveWithRights; // Phase 9/IR-P2: namespace object caps
import core.user : userCurrentUid, userCurrentGid, userPasswdContent,
                   userGroupContent, userByUid, userByGid,
                   userSetActiveSubject; // Phase 10 / IR-P3 User objects
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
    FD_RANDOM,
    FD_URANDOM,
    FD_RTFILE,           // writable runtime-overlay (rtfs) regular file
    FD_RTDIR,            // runtime-overlay directory, enumerable with getdents64
    FD_PTY_MASTER,       // pseudo-terminal master (/dev/ptmx)
    FD_PTY_SLAVE,        // pseudo-terminal slave  (/dev/pts/N)
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
    uint mod_start;
    uint mod_end;
    char[120] name;
}

static assert(BootModuleRecord.sizeof == 128);

// Per-process file-descriptor tables.  fork() must give the child an INDEPENDENT
// copy (POSIX semantics): e.g. libseat's embedded seatd forks a server and each
// side close()s only its own copy of the socketpair — with a single shared table
// those closes would tear down the connection (the seat "Could not flush" bug).
// Threads (CLONE_VM) share their process's table.  `g_fdTable` points at the
// active process's table; the syscall dispatcher selects it per task each call
// via fdtabSetActive().  FDTAB_COUNT must be >= MAX_TASKS (task.d).
enum int FDTAB_COUNT = 64;
__gshared File[1024][FDTAB_COUNT] g_fdTabs;
// Active table pointer; set by fdtabSetActive() before each syscall is serviced
// (and defensively to process 0's table on first use).  &g_fdTabs[0][0] is not a
// compile-time constant, so it can't be used as a static initializer.
__gshared File* g_fdTable;

// Point g_fdTable at process `fdTabId`'s table.  Called from the syscall
// dispatcher with the current task's fdTabId before each syscall is serviced.
public void fdtabSetActive(int fdTabId) {
    if (fdTabId < 0 || fdTabId >= FDTAB_COUNT) fdTabId = 0;
    g_fdTable = &g_fdTabs[fdTabId][0];
}

// fork(): copy the parent process's fd table to the child's, bumping the
// refcounts of shared kernel objects (sockets/pipes) so the child holds its own
// reference and the parent closing its copy doesn't destroy them.
public void fdtabForkCopy(int srcTabId, int dstTabId) {
    if (srcTabId < 0 || srcTabId >= FDTAB_COUNT) return;
    if (dstTabId < 0 || dstTabId >= FDTAB_COUNT || dstTabId == srcTabId) return;
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
private struct EpollInst  { bool inUse; ubyte nestDepth; EpollWatch[EPOLL_MAX_WATCHES] watches; }

__gshared EpollInst[EPOLL_MAX_INSTANCES] g_epollTable;

// --- Eventfd infrastructure ---
private enum int EVENTFD_MAX   = 32;
private enum int EFD_SEMAPHORE = 1;
private enum int EFD_NONBLOCK  = 0x800;
private enum int EFD_CLOEXEC   = 0x80000;

__gshared ulong[EVENTFD_MAX] g_eventfd_counters;
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
private enum uint TIO_ICANON = 0x2, TIO_ECHO = 0x8;

struct Pty {
    bool      inUse;
    uint      iflag, oflag, cflag, lflag;
    ubyte[19] cc;
    ushort    rows, cols, xpix, ypix;
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

// one byte of terminal input (master write) through the input discipline
private void ptyInputByte(ref Pty p, ubyte b) @nogc nothrow {
    if (b == '\r') {
        if (p.iflag & TIO_IGNCR) return;
        if (p.iflag & TIO_ICRNL) b = '\n';
    } else if (b == '\n' && (p.iflag & TIO_INLCR)) {
        b = '\r';
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
            if (arg != 0) *cast(int*)arg = 1;
            return 0;
        case 0x5410: case 0x540e: case 0x5422: // TIOCSPGRP / TIOCSCTTY / TIOCNOTTY
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

private long copySockoptUcred(ulong val, ulong len)
{
    if (val == 0 || len == 0) return negErrno(EFAULT);
    auto optLen = cast(uint*)len;
    if (*optLen < LinuxUcred.sizeof) return negErrno(EINVAL);
    auto cred = cast(LinuxUcred*)val;
    cred.pid = 1;
    cred.uid = userCurrentUid(); // IR-P3: from the active task's User object
    cred.gid = userCurrentGid();
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

    rtInit();   // build the writable runtime-filesystem skeleton (/run, /tmp, …)

    g_fdTableInitialized = true;
    publishActiveFd(0);
    publishActiveFd(1);
    publishActiveFd(2);
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
        foreach (i; 0 .. count) {
            console_putchar(chars[i]);
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
        // redirects to once it disables stdout logging) onto the console so the
        // serial log stays a complete record for debugging.
        if (rtNameEndsWith(g_rt[idx], ".log"))
            for (size_t i = 0; i < count; ++i) console_putchar(cast(char)src[i]);
        f.offset += count;
        if (cast(uint)f.offset > g_rt[idx].size) g_rt[idx].size = cast(uint)f.offset;
        f.fileSize = g_rt[idx].size;
        return cast(ssize_t)count;
    }

    // Simulate success for others (e.g. /dev/null)
    return cast(ssize_t)count;
}

public ssize_t sys_write(int fd, const(void)* buf, size_t count) {
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
    uint target = nsResolveWithRights(g_tasks[tid].namespaceObjId, path, rest, rights);
    if (target == 0) return negErrno(ENOENT);
    uint need = openRightsForFlags(flags);
    if ((rights & need) != need) return negErrno(EACCES);
    return 0;
}

// True if `path` exactly names an entry in the virtual-file table (g_vfs).
private bool pathIsExactVfsFile(const(char)* path) @nogc nothrow {
    foreach (ref vfe; g_vfs)
        if (cstrEq(path, vfe.path)) return true;
    return false;
}

public int sys_open(const(char)* path, int flags) {
    initFdTable();
    if (path is null) {
        return negErrno(EFAULT);
    }

    int nsOpen = namespaceCheckOpen(path, flags);
    if (nsOpen < 0) return nsOpen;

    // Find free FD
    int fd = -1;
    for(int i=3; i<1024; i++) {
        if (g_fdTable[i].type == FileType.FD_NONE) {
            fd = i;
            break;
        }
    }
    if (fd == -1) return negErrno(EMFILE);

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

    // /dev/dri/card0, /dev/dri/renderD128 → DRM/KMS device
    if (cstrEq(path, "/dev/dri/card0") || cstrEq(path, "/dev/dri/renderD128")) {
        g_fdTable[fd].type    = FileType.FD_DRM;
        g_fdTable[fd].flags   = flags;
        g_fdTable[fd].offset  = 0;
        g_fdTable[fd].backend = null;
        g_fdTable[fd].fileSize = 0;
        deviceNoteOpen(path);
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
            return publishActiveFdReturn(fd);
        }
    }

    // An explicit virtual FILE (g_vfs) must win over the synthetic-DIRECTORY shim
    // below: isSyntheticDirectoryPath() also returns true for paths under certain
    // prefixes (isVirtualDirectoryPath), which would otherwise serve a real file
    // like /sys/class/drm/card0/uevent as an empty 0-byte directory — udev-zero
    // then reads no DEVNAME and Weston rejects "card0 is not a KMS device".
    if (isSyntheticDirectoryPath(path) && !pathIsExactVfsFile(path)) {
        if ((flags & 3) != O_RDONLY) {
            return negErrno(EISDIR);
        }
        initSyntheticFileFd(fd, flags, fileBackendDirectory);
        // Tag /sys/dev/char so getdents64 can enumerate the char-device entries
        // libudev-zero scans there to discover input (and DRM) devices.
        if (cstrEq(path, "/sys/dev/char")) g_fdTable[fd].fileSize = SYNTHDIR_DEVCHAR;
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

    return negErrno(ENOENT);
}

private long fileObjClose(ObjHeader* oh) {
    File* f = fileFromObj(oh);
    if (f is null) return negErrno(EBADF);
    ++g_objOpsDispatch;
    uint oid = oh.id;

    if (f.type == FileType.FD_SOCKET) {
        closeLocalSocket(f);
    } else if (f.type == FileType.FD_EPOLL) {
        int eid = cast(int)cast(size_t)f.backend;
        if (eid >= 0 && eid < EPOLL_MAX_INSTANCES) g_epollTable[eid].inUse = false;
    } else if (f.type == FileType.FD_EVENTFD) {
        int eid = cast(int)cast(size_t)f.backend;
        if (eid >= 0 && eid < EVENTFD_MAX) g_eventfd_inUse[eid] = false;
    } else if (f.type == FileType.FD_MEMFD) {
        // Reclaim PRIME-aliased records (borrowed GEM pages) so the swapchain's
        // buffer cycle doesn't exhaust the memfd table.  Owner memfds are left
        // as-is (their pages are bump-allocated and never freed anyway).
        int mid = cast(int)cast(size_t)f.backend;
        if (mid >= 0 && mid < MEMFD_MAX && g_memfds[mid].inUse && g_memfds[mid].aliased) {
            if (g_memfds[mid].vmoObjId != 0 && objGet(g_memfds[mid].vmoObjId) !is null)
                objRelease(g_memfds[mid].vmoObjId);
            g_memfds[mid].inUse    = false;
            g_memfds[mid].physBase = 0;
            g_memfds[mid].size     = 0;
            g_memfds[mid].vmoObjId = 0;
            g_memfds[mid].aliased  = false;
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
            writeLinuxStat(_statBuf, 0x8000 | 0x01a4, f.fileSize); // S_IFREG | 0644
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
            writeLinuxStatOwned(_statBuf, 0x4000 | 0x01ED, 0, uid, gid); // S_IFDIR | 0755
        } else if (fileIsDevNull(f) || f.type == FileType.FD_CONSOLE) {
            clearLinuxStat(_statBuf);
            *cast(uint*)(_statBuf + 24) = 0x2000 | 0x0190; // S_IFCHR | 0620
            *cast(uint*)(_statBuf + 28) = userCurrentUid();
            *cast(uint*)(_statBuf + 32) = userCurrentGid();
        } else if (f.type == FileType.FD_DRM) {
            // Report the DRM device as a character device with the DRM major
            // (226) and minor 0 (= card0, a "primary" node).  libdrm's
            // drmGetNodeTypeFromFd checks S_ISCHR + the encoded rdev, which
            // Aquamarine's dumb-buffer allocator requires.
            clearLinuxStat(_statBuf);
            *cast(uint*)(_statBuf + 24) = 0x2000 | 0x01B6;     // S_IFCHR | 0666
            *cast(uint*)(_statBuf + 28) = userCurrentUid();
            *cast(uint*)(_statBuf + 32) = userCurrentGid();
            *cast(ulong*)(_statBuf + 40) = 0xE200;             // st_rdev = makedev(226, 0)
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
            writeLinuxStatOwned(_statBuf, 0x8000 | 0x01B6, sz, uid, gid); // S_IFREG | 0666
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
    cmdlineAppendKeyUint(p, max, "display.width", displayConfigUint(cfg, "display.width", fbW != 0 ? fbW : 1280));
    cmdlineAppendKeyUint(p, max, "display.height", displayConfigUint(cfg, "display.height", fbH != 0 ? fbH : 800));
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
private enum int    RT_MAX_NODES = 1024;
private enum size_t RT_NAME_MAX  = 96;

private enum ubyte RT_FREE = 0;
private enum ubyte RT_DIR  = 1;
private enum ubyte RT_REG  = 2;

private struct RtNode {
    ubyte  kind;                 // RT_FREE / RT_DIR / RT_REG
    int    parent;               // parent node index; -1 only for root (index 0)
    ushort mode;                 // permission bits only (no S_IF type bits)
    uint   uid;
    uint   gid;
    ubyte  nameLen;
    char[RT_NAME_MAX] name;      // single path component
    ubyte* data;                 // file payload (virtual ptr), null until written
    uint   size;                 // current file length in bytes
    uint   cap;                  // allocated capacity (page multiple)
}

__gshared RtNode[RT_MAX_NODES] g_rt;
__gshared bool g_rtInitialized = false;

private int rtAllocNode() {
    for (int i = 1; i < RT_MAX_NODES; ++i)        // index 0 reserved for root
        if (g_rt[i].kind == RT_FREE) return i;
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
    g_rt[idx].data = null;
    g_rt[idx].size = 0;
    g_rt[idx].cap  = 0;
    return idx;
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

        const int child = rtFindChild(cur, comp, clen);
        if (child < 0 || g_rt[child].kind != RT_DIR) { outParent = -1; return -1; }
        cur = child;
    }
}

// Grow a file node's page-backed payload to at least `need` bytes.
private bool rtEnsureCap(ref RtNode n, uint need) {
    if (need <= n.cap) return true;
    const size_t pages = (need + 4095) / 4096;
    const ulong phys = alloc_phys_pages(pages);
    if (phys == 0) return false;
    ubyte* nd = cast(ubyte*)phys_to_virt(phys);
    const uint newCap = cast(uint)(pages * 4096);
    foreach (i; 0 .. n.size) nd[i] = n.data[i];          // copy existing bytes
    foreach (i; n.size .. newCap) nd[i] = 0;             // zero the remainder
    n.data = nd;                                         // old pages leak (minimal tmpfs)
    n.cap  = newCap;
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
    rtMkdirPath("/var\0".ptr,           M0755, 0, 0);
    rtMkdirPath("/var/cache\0".ptr,     M0755, 0, 0);
    rtMkdirPath("/var/cache/fontconfig\0".ptr, M0755, 0, 0);
    rtMkdirPath("/var/tmp\0".ptr,       M1777, 0, 0);
    rtMkdirPath("/var/run\0".ptr,       M0755, 0, 0);

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
    { "/etc/passwd",        "root:x:0:0:root:/root:/bin/sh\n"                                         },
    { "/etc/shadow",        "root::::::::\n"                                                           },
    { "/etc/group",         "root:x:0:\n"                                                              },
    { "/etc/shells",        "/bin/sh\n/bin/ash\n/busybox\n"                                            },
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
      "}\n"
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
      "renderer=pixman\n" ~
      "shell=desktop-shell.so\n" ~
      "require-input=false\n" ~
      "idle-time=0\n" ~
      "\n" ~
      "[shell]\n" ~
      "client=/weston-desktop-shell\n" ~
      "background-color=0xff1e1e2e\n" ~
      "panel-position=top\n" ~
      "locking=false\n" ~
      "animation=none\n" ~
      "startup-animation=none\n" ~
      "\n" ~
      "[launcher]\n" ~
      "icon=/usr/share/icons/Epin/apps/64/utilities-terminal.png\n" ~
      "path=/weston-terminal\n" ~
      "\n" ~
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

    // DRM ioctl: magic byte = 'd' (0x64)
    if (f.type == FileType.FD_DRM) {
        if (((cmd >> 8) & 0xFF) == 0x64)
            return handleDrmIoctl(fdIndexForFile(f), cmd, arg);
        return 0; // other ioctls on DRM fd → success
    }

    // Input event ioctls (EVIOCGVERSION, EVIOCGNAME, EVIOCGBIT, ...). libinput
    // classifies a device from its evdev capabilities, so these MUST report real
    // bits — event0 as a keyboard (EV_KEY with keyboard keys) and event1 as a
    // pointer (EV_REL X/Y + mouse buttons). Returning 0 for everything made
    // libinput see capability-less devices and ignore them ("no input devices").
    if (f.type == FileType.FD_INPUT_EVENT) {
        return handleInputEvioc(cast(int)cast(size_t)f.backend, cmd, arg);
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

public long linux_sys_ioctl(ulong fd, ulong cmd, ulong arg) {
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

    klog("[openat] ");
    if (p !is null)
        klog(p);
    else
        klog("(null)");
    klog("\n");

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
            const long rtFd = sys_open(pathPtr, O_RDONLY);
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
    return cast(long)sys_sendmsg(cast(int)sockfd, cast(msghdr*)msg, cast(int)flags);
}

public long linux_sys_recvmsg(ulong sockfd, ulong msg, ulong flags) {
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

    strcpy(u.sysname, "Linux"); // Pretend to be Linux
    strcpy(u.nodename, "HanonymOS");
    strcpy(u.release, "6.0.0"); // Pretend to be a modern kernel
    strcpy(u.version_, "#1 SMP HanonymOS");
    strcpy(u.machine, "x86_64");
    strcpy(u.domainname, "(none)");

    return 0;
}

public long linux_sys_getpid() {
    return cast(long)linuxPidForTask(cast(int)g_current_task_id);
}

public long linux_sys_rt_sigaction(ulong signum, ulong act, ulong oldact, ulong sigsetsize) {
    // Return success but do nothing.
    return 0;
}

public long linux_sys_futex(ulong uaddr, ulong op, ulong val, ulong timeout, ulong uaddr2, ulong val3) {
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
public long linux_sys_getpgid(ulong pid) { return 1; }
public long linux_sys_setpgid(ulong pid, ulong pgid) { return 0; }
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

// --- Kill / tgkill (stubs) ---
public long linux_sys_kill(ulong pid, ulong sig)            { return 0; }
public long linux_sys_tgkill(ulong tgid, ulong tid, ulong sig) { return 0; }
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
    if (!isSyntheticDirectoryPath(p)) return negErrno(ENOENT);
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
private enum DT_DIR = 4;
private enum DT_REG = 8;

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
private static immutable string[3] g_devCharEntries = ["226:0", "13:64", "13:65"];

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

    if (fileIsRtDirectory(f)) {
        const int dirIdx = cast(int)cast(size_t)f.backend;
        ulong logical = 2;
        for (int i = 1; i < RT_MAX_NODES; ++i) {
            if (g_rt[i].kind == RT_FREE || g_rt[i].parent != dirIdx) continue;
            if (f.offset <= logical) {
                const ubyte dtype = (g_rt[i].kind == RT_DIR) ? DT_DIR : DT_REG;
                if (!writeDirent64(buf, count, &written, cast(ulong)i + 1,
                                   cast(long)logical + 1, dtype,
                                   g_rt[i].name.ptr, g_rt[i].nameLen))
                    return cast(long)written;
                f.offset = logical + 1;
            }
            ++logical;
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
    return pollScanFds(fds, nfds);
}
// ppoll(fds, nfds, timeout_ts, sigmask, sigsetsize): scan readiness like poll;
// the timeout/blocking is handled cooperatively by the syscall dispatcher.
public long linux_sys_ppoll(ulong fds, ulong nfds, ulong tmo, ulong sig, ulong sz) {
    return pollScanFds(fds, nfds);
}
public long linux_sys_select(ulong n, ulong i, ulong o, ulong e, ulong tv) { return 0; }
public long linux_sys_pselect6(ulong n, ulong i, ulong o, ulong e, ulong tv, ulong sig) { return 0; }

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
    g_rt[idx].kind   = RT_FREE;
    g_rt[idx].parent = -1;
    g_rt[idx].size   = 0;                            // payload pages leak (minimal tmpfs)
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
public long linux_sys_symlink(ulong t, ulong l)  { return negErrno(EROFS); }
public long linux_sys_symlinkat(ulong t, ulong d, ulong l) { return negErrno(EROFS); }
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

// --- Permission / ownership stubs ---
public long linux_sys_chmod(ulong p, ulong m)         { return 0; }
public long linux_sys_fchmod(ulong fd, ulong m)        { return 0; }
public long linux_sys_fchmodat(ulong d, ulong p, ulong m, ulong f) { return 0; }

private bool chownIsNoop(ulong u, ulong g) {
    bool uidOk = (u == ulong.max) || (u == userCurrentUid());
    bool gidOk = (g == ulong.max) || (g == userCurrentGid());
    return uidOk && gidOk;
}

private long chownStub(ulong u, ulong g) {
    if (chownIsNoop(u, g)) return 0;
    return adminRequire(CAP_RIGHT_ADMIN_USER) ? 0 : negErrno(EPERM);
}

public long linux_sys_chown(ulong p, ulong u, ulong g) { return chownStub(u, g); }
public long linux_sys_lchown(ulong p, ulong u, ulong g){ return chownStub(u, g); }
public long linux_sys_fchown(ulong fd, ulong u, ulong g){ return chownStub(u, g); }
public long linux_sys_fchownat(ulong d, ulong p, ulong u, ulong g, ulong f) { return chownStub(u, g); }
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
    if (lvl == SOL_SOCKET && cast(int)opt == SO_PEERCRED)
        return copySockoptUcred(val, len);

    auto sock = fileSocket(f);
    if (sock is null) return negErrno(ENOTSOCK);
    if (lvl != SOL_SOCKET) return negErrno(ENOPROTOOPT);

    switch (cast(int)opt) {
        case SO_PEERCRED:
            return copySockoptUcred(val, len);
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
        return g_timerfds[tid].pending > 0;
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
    g_timerfds[tid].nextExpiry    = get_ticks() + valueMs;
    g_timerfds[tid].pending       = 0;
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

// --- sethostname / setdomainname ---
private __gshared char[65] g_hostname   = "localhost";
private __gshared char[65] g_domainname = "(none)";

public long linux_sys_sethostname(ulong name, ulong len) {
    if (len > 64) return negErrno(EINVAL);
    auto src = cast(const(char)*)name;
    for (ulong i = 0; i < len; ++i) g_hostname[i] = src[i];
    g_hostname[len] = '\0';
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

import memory.mm : alloc_phys_pages, physPagesSetOwner;

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
private enum ulong DRM_CAP_TIMESTAMP_MONOTONIC  = 0x6;
private enum ulong DRM_CAP_CURSOR_WIDTH         = 0x8;
private enum ulong DRM_CAP_CURSOR_HEIGHT        = 0x9;

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
}
private enum DRMFB_MAX = 16;
__gshared DrmFb[DRMFB_MAX] g_drmFbs;
__gshared uint g_nextFbId = 1;

private DrmFb* findDrmFb(uint fbId) @nogc nothrow {
    if (fbId == 0) return null;
    foreach (ref fb; g_drmFbs)
        if (fb.inUse && fb.fbId == fbId) return &fb;
    return null;
}

// Bind a GEM buffer (by handle) to a fresh fb_id. Returns the new id, or 0.
private uint drmAddFb(uint handle, uint width, uint height, uint pitch, uint format) @nogc nothrow {
    GemBuf* gem = findGem(handle);
    if (gem is null) return 0;
    int slot = -1;
    foreach (i, ref fb; g_drmFbs) { if (!fb.inUse) { slot = cast(int)i; break; } }
    if (slot < 0) return 0;
    uint id = g_nextFbId++;
    g_drmFbs[slot].inUse    = true;
    g_drmFbs[slot].fbId     = id;
    g_drmFbs[slot].width    = width  ? width  : gem.width;
    g_drmFbs[slot].height   = height ? height : gem.height;
    g_drmFbs[slot].pitch    = pitch  ? pitch  : gem.pitch;
    g_drmFbs[slot].format   = format;
    g_drmFbs[slot].physAddr = gem.physAddr;
    g_drmFbs[slot].size     = gem.size;
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

// Shared accounting for both present paths (drmPresentFb = KMS PAGE_FLIP,
// drmPresentToFramebuffer = HOS_PRESENT).  t0/t1 bracket the present; blitPx is the
// pixels copied; full marks a full-frame blit.
private void presentAccount(ulong t0, ulong t1, ulong blitPx, bool full) @nogc nothrow {
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
private long drmPresentFb(uint fbId) @nogc nothrow {
    const ulong _t0 = rdtsc();
    if (!g_fb || g_fb.address is null || g_fb.pitch == 0 || g_fb.bpp != 32)
        return negErrno(ENODEV);
    DrmFb* fb = findDrmFb(fbId);
    if (fb is null || fb.physAddr == 0 || fb.pitch == 0) return negErrno(EINVAL);

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

    // GUI roadmap G5: overlay trusted identity borders for each client window.
    hosDrawIdentityBorders();
    g_fbConsoleEnabled = false;
    // Weston just overwrote the whole framebuffer; re-stamp the overlay cursor.
    cursorRepaintAfterPresent();
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
        ulong* date_len = cast(ulong*)(p + 32);
        char** date_ptr = cast(char**)(p + 40);
        if (*date_len > 0 && *date_ptr) (*date_ptr)[0] = 0;
        *date_len = 0;
        ulong* desc_len = cast(ulong*)(p + 48);
        char** desc_ptr = cast(char**)(p + 56);
        if (*desc_len > 0 && *desc_ptr) (*desc_ptr)[0] = 0;
        *desc_len = 0;
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

private long handleDrmIoctl(int ifd, ulong request, ulong arg) {
    // NB: do NOT log per ioctl here — DRM_NR_HOS_PRESENT (0xf0) fires on every
    // frame, so a klog/console write per call floods the slow serial UART and,
    // under KVM, throttles the whole compositor (one VM-exit per byte).
    uint nr = request & 0xFF;
    if (arg == 0) return negErrno(EFAULT);

    switch (nr) {
    case DRM_NR_VERSION: {
        userWrite!int(arg + 0, 1);
        userWrite!int(arg + 4, 0);
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
        case DRM_CAP_TIMESTAMP_MONOTONIC:  val = 1;  break;
        case DRM_CAP_CURSOR_WIDTH:         val = 64; break;
        case DRM_CAP_CURSOR_HEIGHT:        val = 64; break;
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

    // struct drm_prime_handle { u32 handle; u32 flags; s32 fd; }
    // Export a dumb GEM buffer as a dma-buf fd.  Aquamarine's headless allocator
    // requires this to succeed (else attrs.success stays false and the swapchain
    // can't acquire a buffer).  We hand back an fd that aliases the GEM's physical
    // pages via the memfd machinery, so mmap'ing the prime fd yields the same
    // pixels as the dumb buffer.
    case DRM_NR_PRIME_HANDLE_TO_FD: {
        uint handle = userRead!uint(arg + 0);
        GemBuf* gem = findGem(handle);
        if (!gem) return negErrno(EINVAL);

        int slot = -1;
        foreach (i, ref m; g_memfds) { if (!m.inUse) { slot = cast(int)i; break; } }
        if (slot < 0) return negErrno(ENOSPC);

        int nfd = -1;
        for (int i = 3; i < 1024; ++i)
            if (g_fdTable[i].type == FileType.FD_NONE) { nfd = i; break; }
        if (nfd < 0) return negErrno(EMFILE);

        g_memfds[slot].inUse    = true;
        g_memfds[slot].physBase = gem.physAddr;
        g_memfds[slot].size     = gem.size;
        g_memfds[slot].seals    = 0;
        g_memfds[slot].vmoObjId = ensureGemVmo(gem);
        if (g_memfds[slot].vmoObjId != 0)
            objRetain(g_memfds[slot].vmoObjId);
        g_memfds[slot].aliased  = true;

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
        if (pf.type != FileType.FD_MEMFD) return negErrno(EINVAL);
        int mid = cast(int)cast(size_t)pf.backend;
        if (mid < 0 || mid >= MEMFD_MAX || !g_memfds[mid].inUse) return negErrno(EINVAL);
        ulong phys = g_memfds[mid].physBase;
        uint handle = 0;
        foreach (ref gb; g_gemBufs) {
            if (gb.inUse && gb.physAddr == phys) { handle = gb.handle; break; }
        }
        if (handle == 0) return negErrno(EINVAL);
        userWrite!uint(arg + 0, handle);
        return 0;
    }

    case DRM_NR_MODE_GETRESOURCES: {
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
        if (objType == DRM_MODE_OBJECT_PLANE) {
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

        uint pitch = (w * bpp / 8 + 63) & ~63u;
        ulong sz = cast(ulong)pitch * h;

        size_t pages = cast(size_t)((sz + 4095) >> 12);
        ulong physAddr = alloc_phys_pages(pages);
        if (!physAddr) return negErrno(ENOSPC);

        if (g_fb && w == g_fb.width && h == g_fb.height) {
            // Userspace (Hyprland) is taking over the display.  Keep dumb buffers
            // distinct, but stop drawing the kernel text console over GUI output.
            g_fbConsoleEnabled = false;
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
