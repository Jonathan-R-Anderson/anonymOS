module core.syscalls.posix;

import core.io : inb;
import core.console : console_putchar, console_backspace;
import core.syscalls.socket : sockaddr, sockaddr_un, msghdr, iovec, cmsghdr,
                              AF_UNIX, AF_INET, SOCK_STREAM, SOCK_DGRAM,
                              SOL_SOCKET, SCM_RIGHTS;
import core.exports : g_module_count, g_mboot_modules, phys_to_virt,
                      g_current_task_id, d_store_task_fsbase;
import core.random;
import core.io;
extern(C) @nogc nothrow:

// Minimal stubs if any underlying C code still references these.
// Based on previous grep, nothing outside of posix.d referenced PosixKernelShim.
// We might need to keep some symbols if they were exported and used elsewhere, 
// but the grep search for 'PosixKernelShim' was empty.

// If the linker complains about missing symbols later, we will add them here.

alias pid_t = int;
alias ssize_t = long;

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
}

struct File {
    FileType type;
    int flags;
    ulong offset;
    void* backend; // Generic pointer for driver-specific data
    ulong fileSize; // Size for bundle files or others
}

private struct BootModuleRecord {
    uint mod_start;
    uint mod_end;
    char[120] name;
}

static assert(BootModuleRecord.sizeof == 128);

__gshared File[1024] g_fdTable;
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
private enum int EPOLL_MAX_WATCHES   = 64;
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

private struct EpollEvent { uint events; ulong data; }
private struct EpollWatch { bool active; int watchFd; uint events; ulong data; }
private struct EpollInst  { bool inUse; EpollWatch[EPOLL_MAX_WATCHES] watches; }

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

// Event types (from linux/input-event-codes.h)
enum ushort EV_SYN = 0;
enum ushort EV_KEY = 1;
enum ushort EV_REL = 2;
enum ushort SYN_REPORT = 0;
enum ushort REL_X = 0;
enum ushort REL_Y = 1;
enum ushort BTN_LEFT   = 0x110;
enum ushort BTN_RIGHT  = 0x111;
enum ushort BTN_MIDDLE = 0x112;

public void input_enqueue(bool isKeyboard, ushort type, ushort code, int value) @nogc nothrow {
    auto ring = isKeyboard ? &g_kbd_ring : &g_mouse_ring;
    uint next = (ring.head + 1) % INPUT_RING_SIZE;
    if (next == ring.tail) return; // full — drop event
    ring.events[ring.head].tv_sec  = 0;
    ring.events[ring.head].tv_usec = 0;
    ring.events[ring.head].type    = type;
    ring.events[ring.head].code    = code;
    ring.events[ring.head].value   = value;
    ring.head = next;
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
private enum int EBADF  = 9;
private enum int ENOMEM = 12;
private enum int EEXIST = 17;
private enum int EAGAIN = 11;
private enum int EFAULT = 14;
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
    // its own fd).  Queued on the *receiver* socket's rx side.
    File[scmRightsCapacity] passedFiles;
    size_t passedHead;
    size_t passedTail;
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

private LocalSocket* findUnixListener(const(sockaddr_un)* addr, size_t len)
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
    cred.uid = 0;
    cred.gid = 0;
    *optLen = cast(uint)LinuxUcred.sizeof;
    return 0;
}

void initFdTable() {

    if (g_fdTableInitialized) return;
    g_fdTable[0].type = FileType.FD_CONSOLE;
    g_fdTable[0].flags = O_RDONLY;
    
    g_fdTable[1].type = FileType.FD_CONSOLE;
    g_fdTable[1].flags = O_WRONLY;
    
    g_fdTable[2].type = FileType.FD_CONSOLE;
    g_fdTable[2].flags = O_WRONLY;

    rtInit();   // build the writable runtime-filesystem skeleton (/run, /tmp, …)

    g_fdTableInitialized = true;
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


public ssize_t sys_read(int fd, void* _buf, size_t _count) {
    initFdTable();
    if (fd < 0 || fd >= 1024) return negErrno(EBADF);
    
    File* f = &g_fdTable[fd];
    if (f.type == FileType.FD_NONE) return negErrno(EBADF);
    if (f.type == FileType.FD_ZERO) {
        auto buffer = cast(ubyte*)_buf;

        foreach (i; 0 .. _count)
        {
            buffer[i] = 0;
        }
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
        return cast(ssize_t)(n * evtSz);
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

public ssize_t sys_write(int fd, const(void)* buf, size_t count) {
    initFdTable();
    if (buf is null && count != 0) return cast(ssize_t)negErrno(EFAULT);
    if (fd < 0 || fd >= 1024) return cast(ssize_t)negErrno(EBADF);

    File* f = &g_fdTable[fd];
    if (f.type == FileType.FD_NONE) return cast(ssize_t)negErrno(EBADF);

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

public int sys_open(const(char)* path, int flags) {
    initFdTable();
    if (path is null) {
        return negErrno(EFAULT);
    }

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
        return fd;
    }

    if (cstrEq(path, "/dev/urandom")) {
        g_fdTable[fd].type = FileType.FD_URANDOM;
        g_fdTable[fd].flags = flags;
        g_fdTable[fd].offset = 0;
        g_fdTable[fd].backend = null;
        g_fdTable[fd].fileSize = 0;
        return fd;
    }

    if (cstrEq(path, "/dev/random")) {
        g_fdTable[fd].type = FileType.FD_RANDOM;
        g_fdTable[fd].flags = flags;
        g_fdTable[fd].offset = 0;
        g_fdTable[fd].backend = null;
        g_fdTable[fd].fileSize = 0;
        return fd;
    }

    if (cstrEq(path, "/dev/tty") || cstrEq(path, "/dev/console") || cstrEq(path, "/dev/stdin") ||
        cstrEq(path, "/dev/stdout") || cstrEq(path, "/dev/stderr")) {
        g_fdTable[fd].type = FileType.FD_CONSOLE;
        g_fdTable[fd].flags = flags;
        g_fdTable[fd].offset = 0;
        g_fdTable[fd].backend = null;
        g_fdTable[fd].fileSize = 0;
        return fd;
    }

    // /dev/dri/card0, /dev/dri/renderD128 → DRM/KMS device
    if (cstrEq(path, "/dev/dri/card0") || cstrEq(path, "/dev/dri/renderD128")) {
        g_fdTable[fd].type    = FileType.FD_DRM;
        g_fdTable[fd].flags   = flags;
        g_fdTable[fd].offset  = 0;
        g_fdTable[fd].backend = null;
        g_fdTable[fd].fileSize = 0;
        return fd;
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
        return fd;
    }

    if (isSyntheticDirectoryPath(path)) {
        if ((flags & 3) != O_RDONLY) {
            return negErrno(EISDIR);
        }
        initSyntheticFileFd(fd, flags, fileBackendDirectory);
        return fd;
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
        return fd;
    }

    // Check Bundle
    BundleFile bf;
    if (findBundleFile(path, bf)) {
         g_fdTable[fd].type = FileType.FD_BUNDLE;
         g_fdTable[fd].flags = flags;
         g_fdTable[fd].offset = 0;
         g_fdTable[fd].backend = cast(void*)bf.offset;
         g_fdTable[fd].fileSize = bf.size;
         return fd;
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
            return fd;
        }
    }

    // Writable runtime overlay (rtfs): /run, /tmp, /var/tmp subtrees.
    {
        int rparent; const(char)* rleaf; size_t rleafLen;
        const int ridx = rtResolve(path, rparent, rleaf, rleafLen);
        if (ridx >= 0) {
            if (g_rt[ridx].kind == RT_DIR) {
                if ((flags & 3) != O_RDONLY) return negErrno(EISDIR);
                initSyntheticFileFd(fd, flags, fileBackendDirectory);
                return fd;
            }
            // existing regular overlay file
            if ((flags & O_CREAT) && (flags & O_EXCL)) return negErrno(EEXIST);
            if (flags & O_TRUNC) { g_rt[ridx].size = 0; }
            g_fdTable[fd].type     = FileType.FD_RTFILE;
            g_fdTable[fd].flags    = flags;
            g_fdTable[fd].offset   = (flags & O_APPEND) ? g_rt[ridx].size : 0;
            g_fdTable[fd].backend  = cast(void*)cast(size_t)ridx;
            g_fdTable[fd].fileSize = g_rt[ridx].size;
            return fd;
        }
        // create a new file when requested and the parent is a writable overlay dir
        if ((flags & O_CREAT) && rparent >= 0 && rleaf !is null &&
            g_rt[rparent].kind == RT_DIR) {
            const int created = rtCreate(rparent, rleaf, rleafLen, RT_REG,
                                         cast(ushort)0x1B6 /*0666*/, 0, 0);
            if (created < 0) return negErrno(ENOSPC);
            g_fdTable[fd].type     = FileType.FD_RTFILE;
            g_fdTable[fd].flags    = flags;
            g_fdTable[fd].offset   = 0;
            g_fdTable[fd].backend  = cast(void*)cast(size_t)created;
            g_fdTable[fd].fileSize = 0;
            return fd;
        }
    }

    if ((flags & O_CREAT) != 0) {
        initPlainFileFd(fd, flags);
        return fd;
    }

    return negErrno(ENOENT);
}

public int sys_close(int fd) {
    initFdTable();
    if (fd < 0 || fd >= 1024) return negErrno(EBADF);
    
    File* f = &g_fdTable[fd];
    if (f.type == FileType.FD_NONE) return negErrno(EBADF);

    if (f.type == FileType.FD_SOCKET) {
        closeLocalSocket(f);
    } else if (f.type == FileType.FD_EPOLL) {
        int eid = cast(int)cast(size_t)f.backend;
        if (eid >= 0 && eid < EPOLL_MAX_INSTANCES) g_epollTable[eid].inUse = false;
    } else if (f.type == FileType.FD_EVENTFD) {
        int eid = cast(int)cast(size_t)f.backend;
        if (eid >= 0 && eid < EVENTFD_MAX) g_eventfd_inUse[eid] = false;
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
    return 0;
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

public long linux_sys_fstat(ulong fd, ulong _statBuf) {
    initFdTable();
    int ifd = cast(int)fd;

    if (ifd >= 0 && ifd < 1024 && g_fdTable[ifd].type != FileType.FD_NONE) {
        if (_statBuf != 0) {
            File* f = &g_fdTable[ifd];
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
            } else if (fileIsDevNull(f) || f.type == FileType.FD_CONSOLE) {
                clearLinuxStat(_statBuf);
                *cast(uint*)(_statBuf + 24) = 0x2000 | 0x0190; // S_IFCHR | 0620
            } else if (f.type == FileType.FD_DRM) {
                // Report the DRM device as a character device with the DRM major
                // (226) and minor 0 (= card0, a "primary" node).  libdrm's
                // drmGetNodeTypeFromFd checks S_ISCHR + the encoded rdev, which
                // Aquamarine's dumb-buffer allocator requires.
                clearLinuxStat(_statBuf);
                *cast(uint*)(_statBuf + 24) = 0x2000 | 0x01B6;     // S_IFCHR | 0666
                *cast(ulong*)(_statBuf + 40) = 0xE200;             // st_rdev = makedev(226, 0)
            } else if (f.type == FileType.FD_SOCKET) {
                clearLinuxStat(_statBuf);
                *cast(uint*)(_statBuf + 24) = 0xC000 | 0x01B6; // S_IFSOCK | 0666
            } else if (f.type == FileType.FD_RTFILE) {
                const int idx = cast(int)cast(size_t)f.backend;
                const uint sz = (idx >= 0 && idx < RT_MAX_NODES) ? g_rt[idx].size : 0;
                writeLinuxStat(_statBuf, 0x8000 | 0x01B6, sz); // S_IFREG | 0666
            } else {
                writeLinuxStat(_statBuf, 0x8000 | 0x01a4, f.fileSize); // S_IFREG | 0644
            }
        }
        return 0;
    }
    return cast(long)negErrno(EBADF);
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

private void writeLinuxStat(ulong statBuf, uint mode, ulong size) {
    clearLinuxStat(statBuf);
    *cast(uint*)(statBuf + 24) = mode;
    *cast(long*)(statBuf + 48) = cast(long)size;
    *cast(long*)(statBuf + 56) = 4096;
    *cast(long*)(statBuf + 64) = cast(long)((size + 511) / 512);
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
private enum int    RT_MAX_NODES = 512;
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
    rtMkdirPath("/var\0".ptr,           M0755, 0, 0);
    rtMkdirPath("/var/tmp\0".ptr,       M1777, 0, 0);
    rtMkdirPath("/var/run\0".ptr,       M0755, 0, 0);
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
    { "/proc/cmdline",           "root=/dev/ram0 quiet\n"                                              },
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
    { "/proc/self/loginuid",     "0\n"                                                                 },
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
      "UID=0\n" ~
      "USER=root\n" ~
      "STATE=online\n" ~
      "SEAT=seat0\n" ~
      "TTY=tty1\n" ~
      "TYPE=wayland\n" ~
      "CLASS=user\n"
    },
    { "/run/systemd/users/0",
      "UID=0\n" ~
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
      "  <config><blank/></config>\n" ~
      "  <match target=\"font\"><edit name=\"antialias\" mode=\"assign\"><bool>false</bool></edit></match>\n" ~
      "  <match target=\"font\"><edit name=\"hinting\"   mode=\"assign\"><bool>false</bool></edit></match>\n" ~
      "</fontconfig>\n"
    },

    // ── GTK3 ───────────────────────────────────────────────────────────────
    { "/etc/gtk-3.0/settings.ini",
      "[Settings]\n" ~
      "gtk-font-name=Sans 10\n" ~
      "gtk-icon-theme-name=hicolor\n" ~
      "gtk-theme-name=Default\n" ~
      "gtk-cursor-theme-name=default\n" ~
      "gtk-xft-antialias=0\n" ~
      "gtk-xft-hinting=0\n" ~
      "gtk-modules=\n"
    },

    // ── Pango ──────────────────────────────────────────────────────────────
    // Empty modules.cache → Pango falls back to built-in engine only.
    { "/usr/lib/pango/1.0/modules.cache", "" },

    // ── GLib schemas / GSettings compatibility surface ─────────────────────
    { "/usr/share/glib-2.0/schemas/org.gnome.desktop.interface.gschema.xml",
      "<schemalist>\n" ~
      "  <schema id=\"org.gnome.desktop.interface\" path=\"/org/gnome/desktop/interface/\">\n" ~
      "    <key name=\"gtk-theme\" type=\"s\"><default>'Default'</default></key>\n" ~
      "    <key name=\"icon-theme\" type=\"s\"><default>'hicolor'</default></key>\n" ~
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
      "HOME=/root\x00" ~
      "PATH=/usr/bin:/bin:/usr/local/bin:/sbin:/usr/sbin\x00" ~
      "WAYLAND_DISPLAY=wayland-0\x00" ~
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

    // ── libseat / seatd (session/seat management) ─────────────────────────
    { "/run/seatd.sock", "" },
];

// Look up a path in the virtual filesystem table.
// Returns the content slice, or null if not found.
private const(char)[] findVirtualFile(const(char)* path) {
    if (path is null) return null;
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
        cstrEqPrefix(path, "/usr/share/themes/") ||
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
           cstrEq(path, "/usr/share/themes") ||
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
           cstrEq(path, "/sys/class/input") ||
           // libdrm drmNodeIsDRM() stat()s this tree to confirm fd 226:0 is a
           // DRM node (needed by Aquamarine's dumb-buffer allocator path).
           cstrEq(path, "/sys/dev") ||
           cstrEq(path, "/sys/dev/char") ||
           cstrEq(path, "/sys/dev/char/226:0") ||
           cstrEq(path, "/sys/dev/char/226:0/device") ||
           cstrEq(path, "/sys/dev/char/226:0/device/drm") ||
           // libseat / seatd
           cstrEq(path, "/run/seatd") ||
           isVirtualDirectoryPath(path);
}

private bool isSyntheticSocketPath(const(char)* path) {
    return cstrEq(path, "/run/user/1000/wayland-0") ||
           cstrEq(path, "/run/user/1000/pipewire-0") ||
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

public long linux_sys_ioctl(ulong fd, ulong cmd, ulong arg) {
    console_putchar('I');
    initFdTable();

    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024 || g_fdTable[ifd].type == FileType.FD_NONE)
        return negErrno(EBADF);

    if (g_fdTable[ifd].type == FileType.FD_DRM) {
        console_putchar('D');
        return handleDrmIoctl(ifd, cmd, arg);
    }

    // DRM ioctl: magic byte = 'd' (0x64)
    if (g_fdTable[ifd].type == FileType.FD_DRM) {
        if (((cmd >> 8) & 0xFF) == 0x64)
            return handleDrmIoctl(ifd, cmd, arg);
        return 0; // other ioctls on DRM fd → success
    }

    // Input event ioctls (EVIOCGVERSION, EVIOCGNAME, EVIOCGBIT, ...)
    if (g_fdTable[ifd].type == FileType.FD_INPUT_EVENT) {
        return 0; // accept all input device ioctls silently
    }

    if (g_fdTable[ifd].type != FileType.FD_CONSOLE) {
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
        return fd;
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
        return fd;
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

    const long syntheticStat = statSyntheticPath(pathPtr, statbuf);
    if (syntheticStat == 0) {
        return 0;
    }

    const long fd = sys_open(pathPtr, O_RDONLY);
    if (fd < 0) {
        return fd;
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
import core.ticks : getTickCount, get_ticks;
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
    
    // Ignore clk_id for now, always return monotonic/realtime (same in our kernel)
    ulong ticks = getTickCount();
    // Assuming 1000 Hz (1ms per tick)
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
    return fd;
}

public int sys_bind(int sockfd, sockaddr* addr, uint addrlen) {
    initFdTable();
    if (sockfd < 0 || sockfd >= 1024) return negErrno(EBADF);
    if (addr is null) return negErrno(EFAULT);

    File* f = &g_fdTable[sockfd];
    auto sock = fileSocket(f);
    if (sock is null) return negErrno(ENOTSOCK);
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
    return fd;
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
                }
                size_t queued = (peer.passedHead + scmRightsCapacity - peer.passedTail) %
                                scmRightsCapacity;
                size_t freeSlots = (scmRightsCapacity - 1) - queued;
                if (nfds > freeSlots) return negErrno(EAGAIN);
                foreach (k; 0 .. nfds) {
                    int passFd = fdArray[k];
                    size_t nextHead = (peer.passedHead + 1) % scmRightsCapacity;
                    peer.passedFiles[peer.passedHead] = g_fdTable[passFd];
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
    return 1; // Always return PID 1 for now (init)
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
    // Returns the caller's TID (which is PID for single-threaded).
    return 1; 
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
public long linux_sys_getuid()  { return 0; }
public long linux_sys_geteuid() { return 0; }
public long linux_sys_getgid()  { return 0; }
public long linux_sys_getegid() { return 0; }
public long linux_sys_getppid() { return 0; }
public long linux_sys_getpgid(ulong pid) { return 1; }
public long linux_sys_setpgid(ulong pid, ulong pgid) { return 0; }
public long linux_sys_getpgrp() { return 1; }
public long linux_sys_setsid()  { return 1; }
public long linux_sys_gettid()  {
    // Per-thread id.  Task 0 is the main thread (tid == pid == 1); other tasks
    // (pthreads created via clone) report their own task slot as the tid.
    return cast(long)(g_current_task_id == 0 ? 1 : g_current_task_id);
}
public long linux_sys_getgroups(ulong size, ulong list) { return 0; }
public long linux_sys_setgroups(ulong size, ulong list) { return 0; }
public long linux_sys_setuid(ulong uid)  { return 0; }
public long linux_sys_setgid(ulong gid)  { return 0; }
public long linux_sys_setresuid(ulong r, ulong e, ulong s) { return 0; }
public long linux_sys_setresgid(ulong r, ulong e, ulong s) { return 0; }
public long linux_sys_getresuid(ulong rp, ulong ep, ulong sp) {
    if (rp) *cast(uint*)rp = 0;
    if (ep) *cast(uint*)ep = 0;
    if (sp) *cast(uint*)sp = 0;
    return 0;
}
public long linux_sys_getresgid(ulong rp, ulong ep, ulong sp) {
    if (rp) *cast(uint*)rp = 0;
    if (ep) *cast(uint*)ep = 0;
    if (sp) *cast(uint*)sp = 0;
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
    }
}

public long linux_sys_dup(ulong fd) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024 || g_fdTable[ifd].type == FileType.FD_NONE)
        return negErrno(EBADF);
    for (int nfd = 0; nfd < 1024; ++nfd) {
        if (g_fdTable[nfd].type == FileType.FD_NONE) {
            g_fdTable[nfd] = g_fdTable[ifd];
            incPipeRef(ifd);
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
    if (infd < 0 || infd >= 1024)
        return negErrno(EBADF);
    if (ifd == infd)
        return infd;
    if (g_fdTable[infd].type != FileType.FD_NONE)
        sys_close(infd);
    g_fdTable[infd] = g_fdTable[ifd];
    incPipeRef(ifd);
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
        case F_SETFL: g_fdTable[ifd].flags = cast(int)arg; return 0;
        case F_DUPFD: case F_DUPFD_CLOEXEC:
            for (int nfd = cast(int)arg; nfd < 1024; ++nfd) {
                if (g_fdTable[nfd].type == FileType.FD_NONE) {
                    g_fdTable[nfd] = g_fdTable[ifd];
                    incPipeRef(ifd);
                    return nfd;
                }
            }
            return negErrno(EMFILE);
        case F_ADD_SEALS:
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

private bool writeDirent64(ubyte* buf, size_t bufSz, size_t* off, ulong ino, long doff,
                            ubyte dtype, const(char)* name, size_t nlen) {
    size_t reclen = (linux_dirent64.sizeof + nlen + 1 + 7) & ~cast(size_t)7;
    if (*off + reclen > bufSz) return false;
    auto ent = cast(linux_dirent64*)(buf + *off);
    ent.d_ino    = ino;
    ent.d_off    = doff;
    ent.d_reclen = cast(ushort)reclen;
    ent.d_type   = dtype;
    auto nb = cast(char*)(buf + *off + linux_dirent64.sizeof);
    for (size_t i = 0; i < nlen; ++i) nb[i] = name[i];
    nb[nlen] = 0;
    *off += reclen;
    return true;
}

public long linux_sys_getdents64(ulong fd, ulong dirp, ulong count) {
    initFdTable();
    int ifd = cast(int)fd;
    if (ifd < 0 || ifd >= 1024 || g_fdTable[ifd].type == FileType.FD_NONE) return negErrno(EBADF);
    File* f = &g_fdTable[ifd];
    if (!fileIsSyntheticDirectory(f)) return negErrno(ENOTDIR);
    if (count == 0) return negErrno(EINVAL);

    auto buf = cast(ubyte*)dirp;
    size_t written = 0;
    long pos = cast(long)f.offset;

    if (pos == 0 && writeDirent64(buf, count, &written, 1, 1, DT_DIR, ".".ptr,  1)) ++f.offset;
    if (f.offset >= 1 && pos <= 1 && writeDirent64(buf, count, &written, 1, 2, DT_DIR, "..".ptr, 2)) ++f.offset;

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
    const int created = rtCreate(parent, leaf, leafLen, RT_DIR, mode, 0, 0);
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
}
__gshared MemFdRec[MEMFD_MAX] g_memfds;

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
        // Already backed: allow resize only within the existing allocation.
        if (aligned <= g_memfds[mid].size) { f.fileSize = length; return 0; }
        return negErrno(EINVAL);
    }
    if (aligned == 0) { f.fileSize = 0; return 0; }
    size_t pages = cast(size_t)(aligned >> 12);
    ulong phys = alloc_phys_pages(pages);
    if (phys == 0) return negErrno(ENOMEM);
    g_memfds[mid].physBase = phys;
    g_memfds[mid].size     = aligned;
    f.fileSize             = length;
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

// --- Permission / ownership stubs ---
public long linux_sys_chmod(ulong p, ulong m)         { return 0; }
public long linux_sys_fchmod(ulong fd, ulong m)        { return 0; }
public long linux_sys_fchmodat(ulong d, ulong p, ulong m, ulong f) { return 0; }
public long linux_sys_chown(ulong p, ulong u, ulong g) { return 0; }
public long linux_sys_lchown(ulong p, ulong u, ulong g){ return 0; }
public long linux_sys_fchown(ulong fd, ulong u, ulong g){ return 0; }
public long linux_sys_fchownat(ulong d, ulong p, ulong u, ulong g, ulong f) { return 0; }
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
        if (fda >= 0) g_fdTable[fda] = File.init;
        releaseLocalSocket(a);
        releaseLocalSocket(b);
        return negErrno(EMFILE);
    }

    (cast(int*)sv)[0] = fda;
    (cast(int*)sv)[1] = fdb;
    return 0;
}

// --- Helper: test if FD has data available for reading ---
private bool fdReadable(int fd) @nogc nothrow {
    if (fd < 0 || fd >= 1024) return false;
    auto f = &g_fdTable[fd];
    if (f.type == FileType.FD_CONSOLE)  return true;
    if (f.type == FileType.FD_SOCKET)   return true; // socket may have data
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
    if (f.type == FileType.FD_TIMERFD) {
        int tid = cast(int)cast(size_t)f.backend;
        if (tid < 0 || tid >= TIMERFD_MAX || !g_timerfds[tid].inUse) return false;
        timerfdRefresh(g_timerfds[tid]);
        return g_timerfds[tid].pending > 0;
    }
    return false;
}

// --- Helper: test if FD can accept writes ---
private bool fdWritable(int fd) @nogc nothrow {
    if (fd < 0 || fd >= 1024) return false;
    auto f = &g_fdTable[fd];
    if (f.type == FileType.FD_CONSOLE)   return true;
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
    g_fdTable[fd].type    = FileType.FD_EPOLL;
    g_fdTable[fd].flags   = cast(int)flags;
    g_fdTable[fd].offset  = 0;
    g_fdTable[fd].backend = cast(void*)cast(size_t)eid;
    g_fdTable[fd].fileSize = 0;
    return fd;
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
    return fd;
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
    return fd;
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
public long linux_sys_signalfd4(ulong fd, ulong m, ulong sz, ulong f) { return negErrno(ENOSYS); }
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
public long linux_sys_chroot(ulong path)            { return 0; }
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
    g_fdTable[fd].type     = FileType.FD_MEMFD;
    g_fdTable[fd].backend  = cast(void*)cast(size_t)mid;
    g_fdTable[fd].fileSize = 0;
    g_fdTable[fd].offset   = 0;
    return fd;
}
public long linux_sys_seccomp(ulong op, ulong f, ulong a) { return negErrno(EINVAL); }
public long linux_sys_bpf(ulong cmd, ulong attr, ulong sz)  { return negErrno(ENOSYS); }
public long linux_sys_io_uring_setup(ulong e, ulong p) { return negErrno(ENOSYS); }
public long linux_sys_io_uring_enter(ulong fd, ulong ts, ulong mc, ulong f, ulong s, ulong ss) { return negErrno(ENOSYS); }
public long linux_sys_io_uring_register(ulong fd, ulong op, ulong a, ulong n) { return negErrno(ENOSYS); }
public long linux_sys_flock(ulong fd, ulong op) { return 0; }
public long linux_sys_iopl(ulong level)         { return 0; }
public long linux_sys_ioperm(ulong from, ulong num, ulong on) { return 0; }
public long linux_sys_ptrace(ulong req, ulong pid, ulong addr, ulong data) { return negErrno(ENOSYS); }
public long linux_sys_statx(ulong dfd, ulong path, ulong fl, ulong mask, ulong buf) { return negErrno(ENOSYS); }

// ============================================================
// OpenRC / elogind / init system syscalls
// ============================================================

// --- mount / umount2 (pretend success – no real VFS) ---
public long linux_sys_mount(ulong src, ulong tgt, ulong fstype, ulong fl, ulong data) {
    return 0;
}
public long linux_sys_umount2(ulong tgt, ulong fl) { return 0; }

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

import arch.x86_64.limine : limine_framebuffer;
extern __gshared limine_framebuffer* g_fb;
import memory.mm : alloc_phys_pages;

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
private enum uint DRM_NR_MODE_GETRESOURCES  = 0xa0;
private enum uint DRM_NR_MODE_GETCRTC       = 0xa1;
private enum uint DRM_NR_MODE_SETCRTC       = 0xa2;
private enum uint DRM_NR_MODE_GETENCODER    = 0xa6;
private enum uint DRM_NR_MODE_GETCONNECTOR  = 0xa7;
private enum uint DRM_NR_MODE_ADDFB         = 0xae;
private enum uint DRM_NR_MODE_RMFB          = 0xaf;
private enum uint DRM_NR_MODE_ADDFB2        = 0xb0;
private enum uint DRM_NR_MODE_PAGE_FLIP     = 0xb1;
private enum uint DRM_NR_MODE_CREATE_DUMB   = 0xb2;
private enum uint DRM_NR_MODE_MAP_DUMB      = 0xb3;
private enum uint DRM_NR_MODE_DESTROY_DUMB  = 0xb4;
private enum uint DRM_NR_MODE_ATOMIC        = 0xbc;

// DRM capability IDs
private enum ulong DRM_CAP_DUMB_BUFFER          = 0x1;
private enum ulong DRM_CAP_DUMB_PREFERRED_DEPTH = 0x3;
private enum ulong DRM_CAP_TIMESTAMP_MONOTONIC  = 0x6;
private enum ulong DRM_CAP_CURSOR_WIDTH         = 0x8;
private enum ulong DRM_CAP_CURSOR_HEIGHT        = 0x9;

// Find a GEM buffer by handle
private GemBuf* findGem(uint handle) {
    foreach (ref g; g_gemBufs)
        if (g.inUse && g.handle == handle) return &g;
    return null;
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

private long handleDrmIoctl(int ifd, ulong request, ulong arg) {
    console_putchar('H');
    uint nr = request & 0xFF;
    klog("[drm] nr="); klog_hex(nr); klog(" arg="); klog_hex(arg); klog("\n");
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

    case DRM_NR_SET_CLIENT_CAP:
        return 0;

    case DRM_NR_GEM_CLOSE: {
        uint handle = userRead!uint(arg + 0);
        GemBuf* g = findGem(handle);
        if (g) g.inUse = false;
        return 0;
    }

    case DRM_NR_WAIT_VBLANK:
    case DRM_NR_AUTH_MAGIC:
    case DRM_NR_SET_MASTER:
    case DRM_NR_DROP_MASTER:
        return 0;

    case DRM_NR_PRIME_HANDLE_TO_FD:
    case DRM_NR_PRIME_FD_TO_HANDLE:
        return negErrno(ENOSYS);

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

    case DRM_NR_MODE_SETCRTC:
        return 0;

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

    case DRM_NR_MODE_ADDFB:
    case DRM_NR_MODE_ADDFB2:
        userWrite!uint(arg + 0, 1);
        return 0;

    case DRM_NR_MODE_RMFB:
        return 0;

    case DRM_NR_MODE_PAGE_FLIP:
        return 0;

    case DRM_NR_MODE_ATOMIC:
        return negErrno(EINVAL);

    case DRM_NR_MODE_CREATE_DUMB: {
        uint h   = userRead!uint(arg + 0);
        uint w   = userRead!uint(arg + 4);
        uint bpp = userRead!uint(arg + 8);

        if (bpp == 0) bpp = 32;

        uint pitch = (w * bpp / 8 + 63) & ~63u;
        ulong sz = cast(ulong)pitch * h;

        ulong physAddr;
        if (g_fb && w == g_fb.width && h == g_fb.height) {
            physAddr = cast(ulong)g_fb.address - hhdm_offset;
            pitch = cast(uint)g_fb.pitch;
            sz = g_fb.pitch * g_fb.height;
        } else {
            size_t pages = cast(size_t)((sz + 4095) >> 12);
            physAddr = alloc_phys_pages(pages);
            if (!physAddr) return negErrno(ENOSPC);
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
        if (gem) gem.inUse = false;
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

public long linux_sys_setreuid(ulong ruid, ulong euid) { return 0; }

public long linux_sys_userfaultfd(ulong flags) { return negErrno(ENOSYS); }
