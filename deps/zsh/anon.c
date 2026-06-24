/* platform/anonymos/ — Z4a.3: zsh's native-personality host hooks.
 *
 * The true native-ABI port routes zsh's host I/O through the EpinAnonymOS native object
 * ABI (HOS_SYS_QUERY) when the process runs in the native personality, and through the
 * ordinary Linux syscalls otherwise.  zsh's parser/expander are untouched — only the
 * low-level open/read/write/close/lseek are interposed, via the linker's --wrap so no
 * call site changes.  For a Linux-personality zsh (the default shell) every hook falls
 * straight through to __real_*, so this is completely transparent there.
 *
 * A native file handle is returned to zsh as a normal-looking int fd in a high range
 * (>= ANON_BASE); the read/write/close/lseek hooks recognise it and route to the native
 * verbs.  (Operations zsh may also do on a handle — fstat/fcntl/dup — are not yet routed;
 * those native verbs land in later Z4a steps, at which point more of zsh's FS goes native.)
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>

/* native ABI (mirrors core/hoscall.d) */
#define HOS_SYS_QUERY   0x4000L
#define HOSQ_SYS        5L
#define HOSQ_OPEN       7L
#define HOSQ_READ       8L
#define HOSQ_WRITE      9L
#define HOSQ_CLOSE      10L
#define HOSQ_LSEEK      11L
#define CAP_RIGHT_READ  1L
#define CAP_RIGHT_WRITE 2L

/* native handles are surfaced to zsh as fds at/above this base */
#define ANON_BASE       0x40000000L

extern int     __real_open(const char *path, int flags, ...);
extern ssize_t __real_read(int fd, void *buf, size_t n);
extern ssize_t __real_write(int fd, const void *buf, size_t n);
extern int     __real_close(int fd);
extern off_t   __real_lseek(int fd, off_t off, int whence);

static long hosq(long op, long a, long b, long c) {
    return syscall(HOS_SYS_QUERY, op, a, b, c);
}

/* Am I a native-personality process?  Probe HOSQ_SYS once: a native task gets a byte
 * count (>= 0); a Linux task is denied (-ENOSYS).  Cached for the process lifetime. */
static int anon_native_cached = -1;
static int anon_native(void) {
    if (anon_native_cached < 0) {
        char b[8];
        long r = hosq(HOSQ_SYS, 0, (long)b, (long)sizeof b);
        anon_native_cached = (r >= 0) ? 1 : 0;
    }
    return anon_native_cached;
}

/* Only simple read-only opens go native in this first cut (the rights model maps cleanly);
 * anything with create/append/trunc/write semantics falls through until those land. */
int __wrap_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    if (anon_native() && (flags & O_ACCMODE) == O_RDONLY &&
        !(flags & (O_CREAT | O_TRUNC | O_APPEND))) {
        long h = hosq(HOSQ_OPEN, CAP_RIGHT_READ, (long)path, 0);
        if (h >= 0) return (int)(ANON_BASE + h);
        /* fall through to the Linux path on native-open failure */
    }
    return __real_open(path, flags, mode);
}

ssize_t __wrap_read(int fd, void *buf, size_t n) {
    if (fd >= (int)ANON_BASE) return hosq(HOSQ_READ, fd - ANON_BASE, (long)buf, (long)n);
    return __real_read(fd, buf, n);
}
ssize_t __wrap_write(int fd, const void *buf, size_t n) {
    if (fd >= (int)ANON_BASE) return hosq(HOSQ_WRITE, fd - ANON_BASE, (long)buf, (long)n);
    return __real_write(fd, buf, n);
}
int __wrap_close(int fd) {
    if (fd >= (int)ANON_BASE) return (int)hosq(HOSQ_CLOSE, fd - ANON_BASE, 0, 0);
    return __real_close(fd);
}
off_t __wrap_lseek(int fd, off_t off, int whence) {
    if (fd >= (int)ANON_BASE) return hosq(HOSQ_LSEEK, fd - ANON_BASE, (long)off, (long)whence);
    return __real_lseek(fd, off, whence);
}
