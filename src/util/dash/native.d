// dash's native runtime: every C function the interpreter calls, made of native object ABI calls
// (HOS_SYS_QUERY, src/kernel/d/core/hoscall.d) and nothing else.  dash makes no Linux syscall of its
// own -- the kernel runs it native-only and logs any that slips through, and the build refuses a
// `syscall` instruction anywhere but hos_call below.  musl is linked only for pure routines (string,
// number formatting, maths); this module replaces everything of musl's that reaches the kernel or the
// thread pointer (process start, files, directories, glob, fnmatch, the heap, the environment,
// signals, termios, strerror).  The Linux personality is one command away (`linux`), as a separate
// process -- never dash itself.
module dash.native;

import ldc.llvmasm : __asm;

@nogc nothrow:

// ── the one way into the kernel ─────────────────────────────────────────────────────────────────
enum long HOS_SYS_QUERY = 0x4000;
enum : long {
    Q_WHOAMI = 6, Q_OPEN = 7, Q_READ = 8, Q_WRITE = 9, Q_CLOSE = 10, Q_LSEEK = 11, Q_FSTAT = 12,
    Q_SPAWN = 15, Q_WAIT = 16, Q_FORK = 29, Q_HMOVE = 30, Q_CHAN = 31, Q_DIRLIST = 32, Q_STAT = 33,
    Q_MKDIR = 34, Q_REMOVE = 35, Q_RENAME = 36, Q_CHDIR = 37, Q_GETCWD = 38, Q_KILL = 39,
    Q_TIME = 40, Q_SLEEP = 41, Q_VMALLOC = 42, Q_VMFREE = 43, Q_EXIT = 44, Q_TERM = 45,
    Q_EVENTS = 46, Q_GETPID = 47,
}
enum ulong CAP_READ = 1, CAP_WRITE = 2;
enum : ulong { HOPEN_CREATE = 1UL << 32, HOPEN_TRUNC = 1UL << 33, HOPEN_APPEND = 1UL << 34,
               HOPEN_EXCL = 1UL << 35, HOPEN_DIR = 1UL << 36, HOPEN_CLOEXEC = 1UL << 37 }
enum uint NEV_INT = 1, NEV_CHLD = 2, NEV_TSTP = 4, NEV_WINCH = 8, NEV_QUIT = 16, NEV_PIPE = 32;
struct NStat { ulong size; ulong mtime; ulong ino; uint mode; uint uid; uint gid; uint nlink; }
struct NDirEnt { ushort reclen; ushort namelen; uint pad; NStat st; }

// rdi = op, rsi, rdx, r10 = the op's arguments (see hoscall.d).  Never inlined: this is the one
// place in the binary a `syscall` instruction may appear (scripts/check-native-dash.sh).
pragma(inline, false)
extern (C) long hos_call(long op, long a, long b, long c) {
    return __asm!long("syscall", "={rax},{rax},{rdi},{rsi},{rdx},{r10},~{rcx},~{r11},~{memory}",
                      HOS_SYS_QUERY, op, a, b, c);
}

// musl's FILE and internal locks (futexes) -- dash is single-threaded and formats only into
// string buffers, so they are no-ops here and musl's futex versions are never linked.
extern (C) int __lockfile(void* f) { return 0; }
extern (C) void __unlockfile(void* f) { }
extern (C) void __lock(void* l) { }
extern (C) void __unlock(void* l) { }

// ── errno ───────────────────────────────────────────────────────────────────────────────────────
__gshared int g_errno;
extern (C) int* __errno_location() { return &g_errno; }
extern (C) int* ___errno_location() { return &g_errno; }   // musl's internal name for the same
private long chk(long r) { if (r < 0 && r > -4096) { g_errno = cast(int)-r; return -1; } return r; }

// ── process start ───────────────────────────────────────────────────────────────────────────────
extern (C) int main(int argc, char** argv);
__gshared void function() @nogc nothrow g_beforeExit;   // dash flushes its output buffer here

extern (C) void _start() {
    asm @nogc nothrow {
        naked;
        xor RBP, RBP;
        mov RDI, RSP;          // -> argc, argv[], NULL, envp[], NULL, auxv
        and RSP, -16;
        call dashNativeStart;
        hlt;
    }
}
extern (C) void dashNativeStart(size_t* sp) {
    const int argc = cast(int)sp[0];
    auto argv = cast(char**)(sp + 1);
    envInit(argv + argc + 1);
    exit(main(argc, argv));
}
extern (C) void _exit(int code) { for (;;) hos_call(Q_EXIT, code, 0, 0); }
extern (C) void exit(int code) { if (g_beforeExit) g_beforeExit(); _exit(code); }
extern (C) void abort() { _exit(134); }

// ── processes ───────────────────────────────────────────────────────────────────────────────────
extern (C) int fork() { return cast(int)chk(hos_call(Q_FORK, 0, 0, 0)); }
extern (C) int execve(const(char)* path, const(char*)* argv, const(char*)* envp) {
    return cast(int)chk(hos_call(Q_SPAWN, cast(long)path, cast(long)argv, cast(long)envp));
}
extern (C) int waitpid(int pid, int* status, int options) {
    for (;;) {
        const long r = hos_call(Q_WAIT, pid, cast(long)status, options);
        if (r == -4) { pollEvents(); continue; }      // a native event, not the child: keep waiting
        return cast(int)chk(r);
    }
}
extern (C) int kill(int pid, int sig) { return cast(int)chk(hos_call(Q_KILL, pid, sig, 0)); }
extern (C) int getpid() { return cast(int)hos_call(Q_GETPID, 0, 0, 0); }

// ── handles (files, the terminal, channels) ─────────────────────────────────────────────────────
enum O_ACCMODE = 3, O_WRONLY_ = 1, O_RDWR_ = 2, O_CREAT_ = 0x40, O_EXCL_ = 0x80, O_TRUNC_ = 0x200,
     O_APPEND_ = 0x400, O_DIRECTORY_ = 0x10000, O_CLOEXEC_ = 0x80000;
extern (C) int open(const(char)* path, int flags, ...) {
    const acc = flags & O_ACCMODE;
    ulong r = acc == O_WRONLY_ ? CAP_WRITE : acc == O_RDWR_ ? (CAP_READ | CAP_WRITE) : CAP_READ;
    if (flags & O_CREAT_)     r |= HOPEN_CREATE;
    if (flags & O_TRUNC_)     r |= HOPEN_TRUNC;
    if (flags & O_APPEND_)    r |= HOPEN_APPEND;
    if (flags & O_EXCL_)      r |= HOPEN_EXCL;
    if (flags & O_DIRECTORY_) r |= HOPEN_DIR;
    if (flags & O_CLOEXEC_)   r |= HOPEN_CLOEXEC;
    return cast(int)chk(hos_call(Q_OPEN, cast(long)r, cast(long)path, 0));
}
extern (C) long read(int h, void* buf, size_t n) {
    const long r = hos_call(Q_READ, h, cast(long)buf, cast(long)n);
    if (r == -4) pollEvents();                         // ^C while reading: the handler runs now
    return chk(r);
}
extern (C) long write(int h, const(void)* buf, size_t n) {
    return chk(hos_call(Q_WRITE, h, cast(long)buf, cast(long)n));
}
extern (C) int close(int h) { return cast(int)chk(hos_call(Q_CLOSE, h, 0, 0)); }
extern (C) int dup(int h) { return cast(int)chk(hos_call(Q_HMOVE, h, -1, 0)); }
extern (C) int dup2(int from, int to) { return cast(int)chk(hos_call(Q_HMOVE, from, to, 0)); }
extern (C) int pipe(int* fds) { return cast(int)chk(hos_call(Q_CHAN, 0, cast(long)fds, 0)); }

// fcntl: dash marks its own handles close-on-spawn; nothing else is needed.
extern (C) int fcntl(int h, int cmd, ...) { return 0; }

// ── the filesystem ──────────────────────────────────────────────────────────────────────────────
extern (C) int chdir(const(char)* p) { return cast(int)chk(hos_call(Q_CHDIR, 0, cast(long)p, 0)); }
extern (C) char* getcwd(char* buf, size_t n) {
    const long r = hos_call(Q_GETCWD, 0, cast(long)buf, cast(long)n);
    if (r < 0) { g_errno = cast(int)-r; return null; }
    return buf;
}
extern (C) int unlink(const(char)* p) { return cast(int)chk(hos_call(Q_REMOVE, 0, cast(long)p, 0)); }
extern (C) int rmdir(const(char)* p) { return cast(int)chk(hos_call(Q_REMOVE, 1, cast(long)p, 0)); }
extern (C) int mkdir(const(char)* p, uint mode) { return cast(int)chk(hos_call(Q_MKDIR, mode, cast(long)p, 0)); }
extern (C) int rename(const(char)* a, const(char)* b) {
    return cast(int)chk(hos_call(Q_RENAME, cast(long)a, cast(long)b, 0));
}
int nstat(const(char)* path, ref NStat st, bool nofollow = false) {
    return cast(int)chk(hos_call(Q_STAT, cast(long)path, cast(long)&st, nofollow ? 1 : 0));
}
// struct stat (x86-64 layout, as dash.rt.Stat): the fields dash reads
extern (C) int stat(const(char)* path, void* out_) {
    NStat st;
    if (nstat(path, st) < 0) return -1;
    auto b = cast(ubyte*)out_;
    foreach (i; 0 .. 144) b[i] = 0;
    *cast(ulong*)(b + 8)  = st.ino;
    *cast(ulong*)(b + 16) = st.nlink;
    *cast(uint*)(b + 24)  = st.mode;
    *cast(uint*)(b + 28)  = st.uid;
    *cast(uint*)(b + 32)  = st.gid;
    *cast(long*)(b + 48)  = cast(long)st.size;
    *cast(long*)(b + 88)  = cast(long)st.mtime;
    return 0;
}
extern (C) int access(const(char)* path, int mode) {
    NStat st;
    if (nstat(path, st) < 0) return -1;
    if ((mode & 1) && (st.mode & 0x49) == 0 && (st.mode & 0xF000) != 0x4000) { g_errno = 13; return -1; }
    return 0;
}

// Directories: the native listing (Q_DIRLIST) read whole, walked like readdir.
struct Dirent { ulong d_ino; long d_off; ushort d_reclen; ubyte d_type; char[256] d_name; }
private struct Dir { ubyte* buf; size_t len, pos, cap; Dirent cur; }
ubyte dtypeOf(uint mode) {
    switch (mode & 0xF000) {
        case 0x4000: return 4;   case 0x8000: return 8;   case 0xA000: return 10;
        case 0x2000: return 2;   case 0x6000: return 6;   case 0x1000: return 1;  case 0xC000: return 12;
        default: return 0;
    }
}
// The raw records of directory `path` (malloc'd; *len bytes); null on error (errno set).
ubyte* dirList(const(char)* path, out size_t len) {
    size_t cap = 16384;
    for (;;) {
        auto b = cast(ubyte*)malloc(cap);
        if (b is null) { g_errno = 12; return null; }
        const long r = hos_call(Q_DIRLIST, cast(long)path, cast(long)b, cast(long)cap);
        if (r == -34 && cap < (64UL << 20)) { free(b); cap *= 4; continue; }   // ERANGE: larger
        if (r < 0) { free(b); g_errno = cast(int)-r; return null; }
        len = cast(size_t)r;
        return b;
    }
}
extern (C) void* opendir(const(char)* path) {
    size_t len;
    auto b = dirList(path, len);
    if (b is null) return null;
    auto d = cast(Dir*)calloc(1, Dir.sizeof);
    d.buf = b; d.len = len;
    return d;
}
extern (C) void* readdir(void* dp) {
    auto d = cast(Dir*)dp;
    if (d is null || d.pos + NDirEnt.sizeof > d.len) return null;
    auto e = cast(NDirEnt*)(d.buf + d.pos);
    auto name = cast(char*)(d.buf + d.pos + NDirEnt.sizeof);
    d.cur.d_ino = e.st.ino; d.cur.d_off = cast(long)d.pos; d.cur.d_reclen = e.reclen;
    d.cur.d_type = dtypeOf(e.st.mode);
    size_t n = e.namelen < 255 ? e.namelen : 255;
    foreach (k; 0 .. n) d.cur.d_name[k] = name[k];
    d.cur.d_name[n] = 0;
    d.pos += e.reclen;
    return &d.cur;
}
extern (C) int closedir(void* dp) {
    auto d = cast(Dir*)dp;
    if (d) { free(d.buf); free(d); }
    return 0;
}

// fnmatch: * ? [set] [!set] [a-z] and \ escapes; a leading '.' is matched only by a literal '.'
// (FNM_PERIOD), and '/' only by a literal '/' (FNM_PATHNAME) -- what the shell's globbing needs.
enum FNM_NOMATCH = 1;
private bool fnm(const(char)* p, const(char)* s, bool start) {
    for (;;) {
        const char c = *p;
        if (c == 0) return *s == 0;
        if (c == '*') {
            while (*p == '*') ++p;
            if (start && *s == '.') return false;
            for (const(char)* t = s; ; ++t) {
                if (fnm(p, t, false)) return true;
                if (*t == 0 || *t == '/') return false;
            }
        }
        if (*s == 0) return false;
        if (c == '?') { if (*s == '/' || (start && *s == '.')) return false; ++p; ++s; start = false; continue; }
        if (c == '[') {
            const(char)* q = p + 1;
            bool neg = false;
            if (*q == '!' || *q == '^') { neg = true; ++q; }
            bool hit = false, first = true;
            while (*q && (first || *q != ']')) {
                first = false;
                char lo = *q;
                if (lo == '\\' && q[1]) lo = *++q;
                if (q[1] == '-' && q[2] && q[2] != ']') {
                    char hi = q[2];
                    if (*s >= lo && *s <= hi) hit = true;
                    q += 3;
                } else { if (*s == lo) hit = true; ++q; }
            }
            if (*q != ']') { if (*s != '[') return false; ++p; ++s; start = false; continue; }   // literal '['
            if (hit == neg || *s == '/' || (start && *s == '.')) return false;
            p = q + 1; ++s; start = false; continue;
        }
        if (c == '\\' && p[1]) ++p;
        if (*p != *s) return false;
        ++p; ++s; start = false;
    }
}
extern (C) int fnmatch(const(char)* pattern, const(char)* str, int flags) {
    return fnm(pattern, str, true) ? 0 : FNM_NOMATCH;
}

// glob: expand each path component that has a wildcard against the native directory listing.
struct GlobT { size_t gl_pathc; char** gl_pathv; size_t gl_offs; int d1; void*[5] d2; }
enum GLOB_NOCHECK = 0x10, GLOB_NOSORT = 0x20, GLOB_NOMATCH = 3;
private bool hasWild(const(char)[] s) { foreach (c; s) if (c == '*' || c == '?' || c == '[') return true; return false; }
private struct StrVec { char** p; size_t n, cap;
    @nogc nothrow void push(char* s) {
        if (n == cap) { cap = cap ? cap * 2 : 16; p = cast(char**)realloc(p, cap * (char*).sizeof); }
        p[n++] = s;
    }
}
private char* dupn(const(char)[] s) {
    auto r = cast(char*)malloc(s.length + 1);
    foreach (k, c; s) r[k] = c;
    r[s.length] = 0;
    return r;
}
// `prefix` (a path so far, possibly "") + the rest of the pattern's components from `rest`.
private void globWalk(const(char)[] prefix, const(char)[] rest, ref StrVec out_) {
    while (rest.length && rest[0] == '/') rest = rest[1 .. $];
    if (rest.length == 0) { out_.push(dupn(prefix)); return; }
    size_t e = 0; while (e < rest.length && rest[e] != '/') ++e;
    const comp = rest[0 .. e];
    const tail = rest[e .. $];
    if (!hasWild(comp)) {
        char[1024] nb = void; size_t n = 0;
        foreach (c; prefix) if (n < 1000) nb[n++] = c;
        if (n && nb[n - 1] != '/') nb[n++] = '/';
        foreach (c; comp) if (n < 1020) nb[n++] = c;
        nb[n] = 0;
        NStat st;
        if (tail.length == 0) { if (nstat(nb.ptr, st, true) == 0) out_.push(dupn(nb[0 .. n])); }
        else if (nstat(nb.ptr, st) == 0 && (st.mode & 0xF000) == 0x4000) globWalk(nb[0 .. n], tail, out_);
        return;
    }
    char[1024] dir = void; size_t dl = 0;
    foreach (c; prefix) if (dl < 1000) dir[dl++] = c;
    if (dl == 0) dir[dl++] = '.';
    dir[dl] = 0;
    size_t len;
    auto b = dirList(dir.ptr, len);
    if (b is null) return;
    char[256] pat = void; size_t pl = comp.length < 255 ? comp.length : 255;
    foreach (k; 0 .. pl) pat[k] = comp[k];
    pat[pl] = 0;
    for (size_t pos = 0; pos + NDirEnt.sizeof <= len; ) {
        auto ent = cast(NDirEnt*)(b + pos);
        auto name = cast(char*)(b + pos + NDirEnt.sizeof);
        pos += ent.reclen;
        if (fnmatch(pat.ptr, name, 0) != 0) continue;
        if (tail.length && (ent.st.mode & 0xF000) != 0x4000 && (ent.st.mode & 0xF000) != 0xA000) continue;
        char[1024] nb = void; size_t n = 0;
        foreach (c; prefix) if (n < 1000) nb[n++] = c;
        if (n && nb[n - 1] != '/') nb[n++] = '/';
        for (size_t k = 0; name[k] && n < 1020; ++k) nb[n++] = name[k];
        nb[n] = 0;
        globWalk(nb[0 .. n], tail, out_);
    }
    free(b);
}
private int cstrcmp(const(char)* a, const(char)* b) {
    while (*a && *a == *b) { ++a; ++b; }
    return cast(int)cast(ubyte)*a - cast(int)cast(ubyte)*b;
}
extern (C) int glob(const(char)* pattern, int flags, void* errfunc, void* gp) {
    auto g = cast(GlobT*)gp;
    *g = GlobT.init;
    size_t pl = 0; while (pattern[pl]) ++pl;
    const pat = pattern[0 .. pl];
    StrVec v;
    if (pat.length && pat[0] == '/') globWalk("/", pat, v);
    else globWalk("", pat, v);
    if (v.n == 0) {
        if (!(flags & GLOB_NOCHECK)) return GLOB_NOMATCH;
        v.push(dupn(pat));
    }
    if (!(flags & GLOB_NOSORT))                       // insertion sort: globs are short lists
        foreach (i; 1 .. v.n) {
            auto x = v.p[i]; size_t j = i;
            while (j > 0 && cstrcmp(v.p[j - 1], x) > 0) { v.p[j] = v.p[j - 1]; --j; }
            v.p[j] = x;
        }
    v.push(null); --v.n;
    g.gl_pathc = v.n; g.gl_pathv = v.p;
    return 0;
}
extern (C) void globfree(void* gp) {
    auto g = cast(GlobT*)gp;
    if (g.gl_pathv) { foreach (i; 0 .. g.gl_pathc) free(g.gl_pathv[i]); free(g.gl_pathv); }
    *g = GlobT.init;
}

// ── the terminal ────────────────────────────────────────────────────────────────────────────────
extern (C) int isatty(int h) { return hos_call(Q_TERM, h, 0, 0) == 1 ? 1 : 0; }
// termios as dash's line editor uses it: tcgetattr reports a cooked terminal; tcsetattr with
// ICANON cleared asks for raw input, otherwise the cooked state is restored.
extern (C) int tcgetattr(int h, void* t) {
    if (!isatty(h)) { g_errno = 25; return -1; }
    auto b = cast(uint*)t;
    foreach (i; 0 .. 4) b[i] = 0;
    b[3] = 0x2 | 0x8 | 0x1 | 0x8000;                    // c_lflag: ICANON | ECHO | ISIG | IEXTEN
    b[0] = 0x400 | 0x100;                               // c_iflag: IXON | ICRNL
    return 0;
}
extern (C) int tcsetattr(int h, int act, const(void)* t) {
    const uint lflag = (cast(const(uint)*)t)[3];
    return cast(int)chk(hos_call(Q_TERM, h, (lflag & 0x2) ? 2 : 1, 0));
}
extern (C) int ioctl(int h, ulong req, ...) {
    import core.stdc.stdarg : va_list, va_start, va_arg, va_end;
    if (req == 0x5413) {                               // TIOCGWINSZ
        va_list ap; va_start(ap, req); auto ws = va_arg!(ushort*)(ap); va_end(ap);
        const long r = hos_call(Q_TERM, h, 3, 0);
        if (r < 0) { g_errno = cast(int)-r; return -1; }
        ws[0] = cast(ushort)(r >> 16); ws[1] = cast(ushort)(r & 0xFFFF); ws[2] = 0; ws[3] = 0;
        return 0;
    }
    g_errno = 25;                                      // ENOTTY: nothing else is asked for
    return -1;
}

// ── signals = native events ─────────────────────────────────────────────────────────────────────
alias sighandler_t = void function(int);
private __gshared sighandler_t[64] g_handlers;
extern (C) sighandler_t signal(int sig, sighandler_t h) {
    if (sig <= 0 || sig >= 64) return null;
    auto old = g_handlers[sig];
    g_handlers[sig] = h;
    return old;
}
// Read the pending native events and run the handler dash installed for each one's signal.
void pollEvents() {
    const long ev = hos_call(Q_EVENTS, 0, 0, 0);
    if (ev <= 0) return;
    static immutable int[6] sigOf = [2, 17, 20, 28, 3, 13];   // NEV_INT .. NEV_PIPE, bit order
    foreach (i, s; sigOf) {
        if (!(ev & (1L << i))) continue;
        auto h = g_handlers[s];
        if (h !is null && cast(size_t)h > 1) h(s);
    }
}

// ── time ────────────────────────────────────────────────────────────────────────────────────────
extern (C) long time(long* t) {
    const long ns = hos_call(Q_TIME, 0, 0, 0);
    const long s = ns > 0 ? ns / 1_000_000_000 : 0;
    if (t) *t = s;
    return s;
}
long monotonicNs() { return hos_call(Q_TIME, 1, 0, 0); }
extern (C) uint sleep(uint s) { hos_call(Q_SLEEP, cast(long)s * 1000, 0, 0); return 0; }
extern (C) int usleep(uint us) { hos_call(Q_SLEEP, us / 1000, 0, 0); return 0; }

// ── the environment ─────────────────────────────────────────────────────────────────────────────
extern (C) __gshared char** environ = null;
private __gshared size_t g_envN, g_envCap;
private size_t cslen(const(char)* s) { size_t n = 0; while (s[n]) ++n; return n; }
private void envInit(char** envp) {
    size_t n = 0; while (envp[n]) ++n;
    g_envCap = n + 16;
    environ = cast(char**)malloc(g_envCap * (char*).sizeof);
    foreach (i; 0 .. n) environ[i] = dupn(envp[i][0 .. cslen(envp[i])]);
    g_envN = n;
    environ[n] = null;
}
private long envFind(const(char)* name) {
    const nl = cslen(name);
    foreach (i; 0 .. g_envN) {
        auto e = environ[i];
        size_t k = 0;
        while (k < nl && e[k] == name[k]) ++k;
        if (k == nl && e[k] == '=') return cast(long)i;
    }
    return -1;
}
extern (C) char* getenv(const(char)* name) {
    if (environ is null) return null;
    const i = envFind(name);
    return i < 0 ? null : environ[i] + cslen(name) + 1;
}
extern (C) int setenv(const(char)* name, const(char)* val, int overwrite) {
    const i = envFind(name);
    if (i >= 0 && !overwrite) return 0;
    const nl = cslen(name), vl = cslen(val);
    auto e = cast(char*)malloc(nl + vl + 2);
    foreach (k; 0 .. nl) e[k] = name[k];
    e[nl] = '=';
    foreach (k; 0 .. vl) e[nl + 1 + k] = val[k];
    e[nl + 1 + vl] = 0;
    if (i >= 0) { free(environ[i]); environ[i] = e; return 0; }
    if (g_envN + 1 >= g_envCap) {
        g_envCap = g_envCap * 2 + 16;
        environ = cast(char**)realloc(environ, g_envCap * (char*).sizeof);
    }
    environ[g_envN++] = e;
    environ[g_envN] = null;
    return 0;
}
extern (C) int unsetenv(const(char)* name) {
    const i = envFind(name);
    if (i < 0) return 0;
    free(environ[i]);
    foreach (k; cast(size_t)i .. g_envN - 1) environ[k] = environ[k + 1];
    --g_envN;
    environ[g_envN] = null;
    return 0;
}

// ── the heap: size classes carved from native memory, large blocks straight from vm_alloc ──────
private enum size_t CHUNK = 1 << 20, HDR = 16, NCLASS = 8;   // classes 32 .. 4096 bytes (with header)
private struct FreeBlk { FreeBlk* next; }
private __gshared FreeBlk*[NCLASS] g_free;
private __gshared ubyte* g_chunk;
private __gshared size_t g_chunkLeft;
private enum ulong LARGE = 1UL << 63;
private void* vmAlloc(size_t n) {
    const long r = hos_call(Q_VMALLOC, cast(long)n, 0, 0);
    return (r < 0 && r > -4096) ? null : cast(void*)r;
}
extern (C) void* malloc(size_t n) {
    if (n == 0) n = 1;
    const size_t total = n + HDR;
    if (total > (32UL << (NCLASS - 1))) {
        const size_t sz = (total + 0xFFF) & ~cast(size_t)0xFFF;
        auto p = cast(ulong*)vmAlloc(sz);
        if (p is null) { g_errno = 12; return null; }
        p[0] = sz | LARGE;
        return cast(ubyte*)p + HDR;
    }
    size_t cls = 0; while ((32UL << cls) < total) ++cls;
    if (g_free[cls]) {
        auto b = g_free[cls]; g_free[cls] = b.next;
        auto p = cast(ulong*)b; p[0] = cls;
        return cast(ubyte*)p + HDR;
    }
    const size_t sz = 32UL << cls;
    if (g_chunkLeft < sz) {
        g_chunk = cast(ubyte*)vmAlloc(CHUNK);
        if (g_chunk is null) { g_chunkLeft = 0; g_errno = 12; return null; }
        g_chunkLeft = CHUNK;
    }
    auto p = cast(ulong*)g_chunk;
    g_chunk += sz; g_chunkLeft -= sz;
    p[0] = cls;
    return cast(ubyte*)p + HDR;
}
private size_t usable(void* q) {
    const ulong h = *cast(ulong*)(cast(ubyte*)q - HDR);
    return (h & LARGE) ? cast(size_t)(h & ~LARGE) - HDR : (32UL << h) - HDR;
}
extern (C) void free(void* q) {
    if (q is null) return;
    auto p = cast(ulong*)(cast(ubyte*)q - HDR);
    if (p[0] & LARGE) { hos_call(Q_VMFREE, cast(long)p, cast(long)(p[0] & ~LARGE), 0); return; }
    const size_t cls = cast(size_t)p[0];
    auto b = cast(FreeBlk*)p; b.next = g_free[cls]; g_free[cls] = b;
}
extern (C) void* calloc(size_t a, size_t b) {
    const size_t n = a * b;
    auto p = cast(ubyte*)malloc(n);
    if (p) foreach (i; 0 .. n) p[i] = 0;
    return p;
}
extern (C) void* realloc(void* q, size_t n) {
    if (q is null) return malloc(n);
    if (n == 0) { free(q); return null; }
    const have = usable(q);
    if (n <= have) return q;
    auto p = cast(ubyte*)malloc(n);
    if (p is null) return null;
    auto s = cast(ubyte*)q;
    foreach (i; 0 .. have) p[i] = s[i];
    free(q);
    return p;
}

// ── strerror (musl's reads the locale through the thread pointer) ───────────────────────────────
extern (C) char* strerror(int e) {
    switch (e) {
        case 1:  return cast(char*)"Operation not permitted".ptr;
        case 2:  return cast(char*)"No such file or directory".ptr;
        case 3:  return cast(char*)"No such process".ptr;
        case 4:  return cast(char*)"Interrupted".ptr;
        case 5:  return cast(char*)"I/O error".ptr;
        case 8:  return cast(char*)"Exec format error".ptr;
        case 9:  return cast(char*)"Bad handle".ptr;
        case 10: return cast(char*)"No child processes".ptr;
        case 11: return cast(char*)"Resource temporarily unavailable".ptr;
        case 12: return cast(char*)"Out of memory".ptr;
        case 13: return cast(char*)"Permission denied".ptr;
        case 17: return cast(char*)"File exists".ptr;
        case 20: return cast(char*)"Not a directory".ptr;
        case 21: return cast(char*)"Is a directory".ptr;
        case 22: return cast(char*)"Invalid argument".ptr;
        case 25: return cast(char*)"Not a terminal".ptr;
        case 28: return cast(char*)"No space left on device".ptr;
        case 30: return cast(char*)"Read-only file system".ptr;
        case 32: return cast(char*)"Broken pipe".ptr;
        case 36: return cast(char*)"File name too long".ptr;
        case 38: return cast(char*)"Not implemented".ptr;
        case 39: return cast(char*)"Directory not empty".ptr;
        default: return cast(char*)"Error".ptr;
    }
}

// ── the generic syscall(): only the native multiplexer exists here ──────────────────────────────
extern (C) long syscall(long n, long a, long b, long c, long d) {
    if (n != HOS_SYS_QUERY) { g_errno = 38; return -1; }
    return chk(hos_call(a, b, c, d));
}
