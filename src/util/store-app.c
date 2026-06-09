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

#define SYS_write      1
#define SYS_exit_group 231

static size_t slen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

void _start(void) {
    static const char msg[] =
        "store-app: launched from the persisted object store with my declared capabilities\n";
    sc3(SYS_write, 1, (long)msg, (long)slen(msg));
    sc3(SYS_exit_group, 0, 0, 0);
    for (;;) {}
}
