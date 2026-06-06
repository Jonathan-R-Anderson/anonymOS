// display-info.c - GUI roadmap G7 display diagnostics.
//
// Freestanding utility that prints the kernel's synthetic /proc/display-info.
// Built like wl-probe/test-drm so it remains usable before libc startup is a
// fully trusted dependency.

typedef unsigned long size_t;
typedef long ssize_t;

static inline long sc1(long n, long a) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx", "r11", "memory");
    return r;
}

static inline long sc3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

#define SYS_read        0
#define SYS_write       1
#define SYS_open        2
#define SYS_close       3
#define SYS_exit_group  231

#define O_RDONLY 0

static ssize_t sys_read(int fd, void *buf, size_t n) { return sc3(SYS_read, fd, (long)buf, (long)n); }
static ssize_t sys_write(int fd, const void *buf, size_t n) { return sc3(SYS_write, fd, (long)buf, (long)n); }
static int sys_open(const char *path, int flags, int mode) { return (int)sc3(SYS_open, (long)path, flags, mode); }
static int sys_close(int fd) { return (int)sc1(SYS_close, fd); }
static void sys_exit(int code) { sc1(SYS_exit_group, code); for (;;) {} }

static size_t slen(const char *s) {
    size_t n = 0;
    while (s[n])
        ++n;
    return n;
}

static void print(const char *s) {
    sys_write(1, s, slen(s));
}

void _start(void) {
    char buf[512];
    int fd = sys_open("/proc/display-info", O_RDONLY, 0);
    if (fd < 0) {
        print("display-info: unable to open /proc/display-info\n");
        sys_exit(1);
    }

    for (;;) {
        ssize_t n = sys_read(fd, buf, sizeof(buf));
        if (n > 0) {
            sys_write(1, buf, (size_t)n);
            continue;
        }
        break;
    }

    sys_close(fd);
    sys_exit(0);
}
