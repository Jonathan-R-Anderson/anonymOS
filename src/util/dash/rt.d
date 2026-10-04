// dash runtime: the C library surface, a mark-and-sweep heap, symbols, and growable buffers.
//
// dash is built -betterC (no druntime, no GC).  The process, file, directory, terminal, heap and
// environment functions declared below are dash.native's -- native object ABI calls, no Linux
// syscalls; musl supplies only the pure string / formatting / maths routines.  Everything the interpreter
// allocates while evaluating comes from gcAlloc; the REPL collects BETWEEN top-level statements,
// when the only live values are the ones reachable from the global environment -- so the collector
// never has to find roots on the machine stack.
module dash.rt;

extern (C) @nogc nothrow {
    // memory / strings
    void*  malloc(size_t);
    void*  calloc(size_t, size_t);
    void*  realloc(void*, size_t);
    void   free(void*);
    void*  memcpy(void*, const(void)*, size_t);
    void*  memmove(void*, const(void)*, size_t);
    void*  memset(void*, int, size_t);
    int    memcmp(const(void)*, const(void)*, size_t);
    size_t strlen(const(char)*);
    int    strcmp(const(char)*, const(char)*);
    int    strncmp(const(char)*, const(char)*, size_t);
    char*  strchr(const(char)*, int);
    char*  strerror(int);
    double strtod(const(char)*, char**);
    long   strtoll(const(char)*, char**, int);
    int    snprintf(char*, size_t, const(char)*, ...);
    // processes / files
    int    fork();
    int    execve(const(char)*, const(char*)*, const(char*)*);
    int    waitpid(int, int*, int);
    int    pipe(int*);
    int    dup(int);
    int    dup2(int, int);
    int    close(int);
    int    open(const(char)*, int, ...);
    long   read(int, void*, size_t);
    long   write(int, const(void)*, size_t);
    int    chdir(const(char)*);
    char*  getcwd(char*, size_t);
    char*  getenv(const(char)*);
    int    setenv(const(char)*, const(char)*, int);
    int    unsetenv(const(char)*);
    extern __gshared char** environ;
    int    access(const(char)*, int);
    int    isatty(int);
    int    getpid();
    int    kill(int, int);
    void   _exit(int);
    void   exit(int);
    long   syscall(long, long, long, long, long);
    long   time(long*);
    uint   sleep(uint);
    int    usleep(uint);
    int    unlink(const(char)*);
    int    mkdir(const(char)*, uint);
    int    ioctl(int, ulong, ...);
    alias sighandler_t = void function(int);
    sighandler_t signal(int, sighandler_t);
    // directories
    void*  opendir(const(char)*);
    void*  readdir(void*);
    int    closedir(void*);
    // glob
    int    glob(const(char)*, int, void*, void*);
    void   globfree(void*);
    int    fnmatch(const(char)*, const(char)*, int);
}

enum O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2, O_CREAT = 0x40, O_TRUNC = 0x200, O_APPEND = 0x400;
enum SIGINT = 2, SIGQUIT = 3, SIGKILL = 9, SIGTERM = 15, SIGPIPE = 13, SIGTSTP = 20;
enum sighandler_t SIG_DFL = cast(sighandler_t)0, SIG_IGN = cast(sighandler_t)1;
enum X_OK = 1, F_OK = 0, R_OK = 4, W_OK = 2;

// musl's struct dirent: d_ino, d_off, d_reclen, d_type, d_name[256]
struct Dirent { ulong d_ino; long d_off; ushort d_reclen; ubyte d_type; char[256] d_name; }
// musl's glob_t (x86_64): gl_pathc, gl_pathv, gl_offs, __dummy1, __dummy2[5]
struct GlobT { size_t gl_pathc; char** gl_pathv; size_t gl_offs; int d1; void*[5] d2; }
enum GLOB_NOCHECK = 0x10, GLOB_NOSORT = 0x20;
// stat (x86_64 kernel layout, identical in musl)
struct Stat {
    ulong st_dev, st_ino, st_nlink; uint st_mode, st_uid, st_gid, pad0; ulong st_rdev;
    long st_size, st_blksize, st_blocks; long[2] atim, mtim, ctim; long[3] unused;
}
extern (C) @nogc nothrow int stat(const(char)*, Stat*);

@nogc nothrow:

// ── output (buffered; flushed before anything else writes to the terminal) ─────────────────────
private __gshared char[8192] g_ob = 0;
private __gshared size_t g_obn;
void oflush() { if (g_obn) { size_t o = 0; while (o < g_obn) { long w = write(1, g_ob.ptr + o, g_obn - o); if (w <= 0) break; o += cast(size_t)w; } g_obn = 0; } }
void out_(const(char)[] s) {
    foreach (c; s) { if (g_obn == g_ob.length) oflush(); g_ob[g_obn++] = c; }
}
void outc(char c) { if (g_obn == g_ob.length) oflush(); g_ob[g_obn++] = c; }
void outz(const(char)* s) { if (s) out_(s[0 .. strlen(s)]); }
void outi(long v) { char[24] b; const n = snprintf(b.ptr, b.length, "%ld", v); out_(b[0 .. n]); }
void errOut(const(char)[] s) { oflush(); long w = write(2, s.ptr, s.length); cast(void)w; }

// ── errors: no exceptions in betterC; a failing evaluation returns null and leaves g_err set ──
__gshared char[512] g_errBuf = 0;
__gshared bool g_errSet;
__gshared bool g_interrupted;       // ^C while evaluating
void setErr(const(char)[] a, const(char)[] b = null, const(char)[] c = null, const(char)[] d = null,
            const(char)[] e = null, const(char)[] f = null) {
    if (g_errSet) return;           // keep the first (innermost) error
    size_t n = 0;
    const(char)[][6] parts = [a, b, c, d, e, f];
    foreach (s; parts) foreach (ch; s) if (n + 1 < g_errBuf.length) g_errBuf[n++] = ch;
    g_errBuf[n] = 0;
    g_errSet = true;
}
const(char)[] errText() { return g_errBuf[0 .. strlen(g_errBuf.ptr)]; }
void clearErr() { g_errSet = false; g_errBuf[0] = 0; }

// ── the heap ────────────────────────────────────────────────────────────────────────────────────
// Every block has a header; the trace kind says how the collector finds pointers inside it.
enum Kind : ubyte { Raw, Ptrs, Value, Env }
struct Hdr { Hdr* next; size_t size; Kind kind; bool mark; }
__gshared Hdr* g_heap;
__gshared size_t g_heapBytes, g_heapSinceGc;

private __gshared uint g_allocTick;
void* gcAlloc(size_t size, Kind kind) {
    // ^C during a long computation: native events are polled here (there are no signal handlers).
    if ((++g_allocTick & 0xFFF) == 0) { import dash.native : pollEvents; pollEvents(); }
    auto h = cast(Hdr*)calloc(1, Hdr.sizeof + size);
    if (h is null) { errOut("dash: out of memory\n"); _exit(111); }
    h.size = size; h.kind = kind; h.next = g_heap; g_heap = h;
    g_heapBytes += size; g_heapSinceGc += size;
    return cast(void*)(h + 1);
}
Hdr* hdrOf(void* p) { return (cast(Hdr*)p) - 1; }

// Tracers for the typed kinds are supplied by value.d / eval.d (they know the layouts).
alias TraceFn = void function(void* p) @nogc nothrow;
__gshared TraceFn g_traceValue, g_traceEnv;

void gcMark(void* p) {
    if (p is null) return;
    auto h = hdrOf(p);
    if (h.mark) return;
    h.mark = true;
    final switch (h.kind) {
        case Kind.Raw: break;
        case Kind.Ptrs: { auto a = cast(void**)p; foreach (i; 0 .. h.size / (void*).sizeof) gcMark(a[i]); break; }
        case Kind.Value: if (g_traceValue) g_traceValue(p); break;
        case Kind.Env: if (g_traceEnv) g_traceEnv(p); break;
    }
}
// After the roots have been marked: free everything unmarked, clear the marks.
void gcSweep() {
    Hdr** link = &g_heap;
    while (*link) {
        Hdr* h = *link;
        if (h.mark) { h.mark = false; link = &h.next; }
        else { *link = h.next; g_heapBytes -= h.size; free(h); }
    }
    g_heapSinceGc = 0;
}

// Growable array (malloc-backed: for parser/editor scratch, never holds heap values across a GC).
struct Vec(T) {
    @nogc nothrow:
    T* p; size_t n, cap;
    void push(T v) {
        if (n == cap) { cap = cap ? cap * 2 : 8; p = cast(T*)realloc(p, cap * T.sizeof); }
        p[n++] = v;
    }
    ref T opIndex(size_t i) { return p[i]; }
    T[] opSlice() { return p[0 .. n]; }
    size_t length() const { return n; }
    void clear() { n = 0; }
    void dispose() { free(p); p = null; n = cap = 0; }
    T pop() { return p[--n]; }
    ref T back() { return p[n - 1]; }
}

// Byte buffer.
struct Buf {
    @nogc nothrow:
    char* p; size_t n, cap;
    void put(char c) { if (n + 1 >= cap) grow(n + 2); p[n++] = c; p[n] = 0; }
    void put(const(char)[] s) { if (n + s.length + 1 >= cap) grow(n + s.length + 1); memcpy(p + n, s.ptr, s.length); n += s.length; p[n] = 0; }
    void putz(const(char)* s) { if (s) put(s[0 .. strlen(s)]); }
    void puti(long v) { char[24] b; const k = snprintf(b.ptr, b.length, "%ld", v); put(b[0 .. k]); }
    void grow(size_t want) { size_t c = cap ? cap : 64; while (c < want) c *= 2; p = cast(char*)realloc(p, c); cap = c; }
    const(char)[] str() { return p ? p[0 .. n] : ""; }
    char* cstr() { if (!p) grow(1); p[n] = 0; return p; }
    void clear() { n = 0; if (p) p[0] = 0; }
    void dispose() { free(p); p = null; n = cap = 0; }
}

// Permanent copy of a string (names, AST text): never collected.
const(char)[] permDup(const(char)[] s) {
    auto p = cast(char*)malloc(s.length + 1);
    memcpy(p, s.ptr, s.length); p[s.length] = 0;
    return p[0 .. s.length];
}
char* cz(const(char)[] s) {        // temporary NUL-terminated copy (malloc; caller frees)
    auto p = cast(char*)malloc(s.length + 1);
    memcpy(p, s.ptr, s.length); p[s.length] = 0;
    return p;
}

// ── symbols: interned names, small integer ids ──────────────────────────────────────────────────
alias Sym = uint;
private __gshared const(char)[][] g_symNames;   // id -> name (malloc-grown)
private __gshared size_t g_symCount, g_symCap;
private __gshared uint* g_symHash; private __gshared size_t g_symHashCap;

private uint hashStr(const(char)[] s) { uint h = 2166136261u; foreach (c; s) { h ^= cast(ubyte)c; h *= 16777619u; } return h; }

Sym intern(const(char)[] s) {
    if (g_symHashCap == 0 || g_symCount * 2 >= g_symHashCap) rehashSyms();
    size_t i = hashStr(s) & (g_symHashCap - 1);
    while (g_symHash[i] != 0) {
        const id = g_symHash[i] - 1;
        if (g_symNames[id] == s) return id;
        i = (i + 1) & (g_symHashCap - 1);
    }
    if (g_symCount == g_symCap) {
        g_symCap = g_symCap ? g_symCap * 2 : 256;
        g_symNames = (cast(const(char)[]*)realloc(g_symNames.ptr, g_symCap * (const(char)[]).sizeof))[0 .. g_symCap];
    }
    const id = cast(Sym)g_symCount++;
    g_symNames[id] = permDup(s);
    g_symHash[i] = id + 1;
    return id;
}
private void rehashSyms() {
    const nc = g_symHashCap ? g_symHashCap * 2 : 512;
    auto nh = cast(uint*)calloc(nc, uint.sizeof);
    foreach (id; 0 .. g_symCount) {
        size_t i = hashStr(g_symNames[id]) & (nc - 1);
        while (nh[i] != 0) i = (i + 1) & (nc - 1);
        nh[i] = cast(uint)id + 1;
    }
    free(g_symHash); g_symHash = nh; g_symHashCap = nc;
}
const(char)[] symName(Sym s) { return s < g_symCount ? g_symNames[s] : "?"; }
size_t symCount() { return g_symCount; }

bool isUpper(char c) { return c >= 'A' && c <= 'Z'; }
bool isLower(char c) { return (c >= 'a' && c <= 'z') || c == '_'; }
bool isDigit(char c) { return c >= '0' && c <= '9'; }
bool isAlpha(char c) { return isUpper(c) || isLower(c); }
bool isIdentChar(char c) { return isAlpha(c) || isDigit(c) || c == '\''; }
bool isSpace(char c) { return c == ' ' || c == '\t' || c == '\r'; }
bool eq(const(char)[] a, const(char)[] b) { return a == b; }
bool startsWith(const(char)[] s, const(char)[] p) { return s.length >= p.length && s[0 .. p.length] == p; }
bool endsWith(const(char)[] s, const(char)[] p) { return s.length >= p.length && s[$ - p.length .. $] == p; }

// ldc's -betterC checks (array bounds, switch) call glibc's __assert; musl names it differently.
extern (C) void __assert(const(char)* msg, const(char)* file, int line) {
    oflush();
    char[512] b;
    const n = snprintf(b.ptr, b.length, "dash: internal check failed: %s (%s:%d)\n", msg, file, line);
    write(2, b.ptr, n > 0 ? cast(size_t)n : 0);
    _exit(70);
}
