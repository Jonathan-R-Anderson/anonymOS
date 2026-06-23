// store-app.c — F4.2 launchable app image for the persisted object store.
//
// The kernel copies these bytes into the `hello` app object's executable blob on
// first boot (and into a `rogue` app declaring rights beyond the System ceiling).
// Launching /objects/apps/<app>/executable is cap-gated on the app's declared
// rights ⊆ the caller's identity ceiling; on grant this runs, proving it ran by
// printing a line, then exits cleanly so the launching shell returns.
//
// Freestanding/static like the other src/util clients (-nostdlib -e _start).

typedef unsigned long size_t;

static inline long sc3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}
// 4-arg syscall (arg4 in r10) — needed for the native object ABI multiplexer.
static inline long sc4(long n, long a, long b, long c, long d) {
    register long r10 asm("r10") = d;
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return r;
}

#define SYS_write      1
#define SYS_exit_group 231
#define HOS_SYS_QUERY  0x4000   /* the native object ABI multiplexer */
#define HOSQ_SYS       5

static size_t slen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
static void put(const char *s) { sc3(SYS_write, 1, (long)s, (long)slen(s)); }

void _start(void) {
    put("store-app: launched from the persisted object store with my declared capabilities\n");

    // NATIVE_OBJECT_ABI §3: a launched app runs under the LINUX personality, so the
    // native object ABI must be unreachable from here — proving the gate.  A native
    // shell (/hos-sh) calling the same op gets the system summary instead.
    static char buf[256];
    long r = sc4(HOS_SYS_QUERY, HOSQ_SYS, 0, (long)buf, (long)sizeof(buf));
    if (r == -38)
        put("store-app: native object ABI is DENIED (ENOSYS) -- Linux personality, as designed\n");
    else if (r > 0)
        put("store-app: native object ABI was GRANTED (UNEXPECTED for a Linux app!)\n");
    else
        put("store-app: native object ABI returned an unexpected error\n");

    sc3(SYS_exit_group, 0, 0, 0);
    for (;;) {}
}
