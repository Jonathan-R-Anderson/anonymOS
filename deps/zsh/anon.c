/* platform/anonymos/ — Z4a: zsh's native-personality host hooks.
 *
 * The true native-ABI port routes zsh's host I/O through the EpinAnonymOS native object
 * ABI (HOS_SYS_QUERY) when the process runs in the native personality.  zsh's parser/
 * expander are untouched — only the low-level open/read/write are interposed, via the
 * linker's --wrap so no call site changes.  For a Linux-personality zsh (the default
 * shell) every hook falls straight through to the real libc call, so this is completely
 * transparent there.
 *
 *  - Filesystem (Z4a.4): object_open resolves the path through the object filesystem
 *    (namespace-gated) and returns the real backing fd as the handle, so every other fd op
 *    (read/write/close/dup/fcntl/fstat/mmap) keeps working through the normal path.
 *  - Terminal (Z4a.6): the controlling terminal is a §12 Device object; native zsh's tty
 *    reads/writes go through device_read/device_write.  A tty is detected with isatty and
 *    cached per fd; non-tty fds (files, pipes) stay on the Linux path.
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/resource.h>

/* native ABI (mirrors core/hoscall.d) */
#define HOS_SYS_QUERY   0x4000L
#define HOSQ_SYS        5L
#define HOSQ_OPEN       7L
#define HOSQ_DEV_READ   13L
#define HOSQ_DEV_WRITE  14L
#define HOSQ_SPAWN      15L
#define HOSQ_WAIT       16L
#define CAP_RIGHT_READ  1L

extern int     __real_open(const char *path, int flags, ...);
extern ssize_t __real_read(int fd, void *buf, size_t n);
extern ssize_t __real_write(int fd, const void *buf, size_t n);
extern int     __real_execve(const char *path, char *const argv[], char *const envp[]);
extern pid_t   __real_wait3(int *status, int options, struct rusage *rusage);
extern pid_t   __real_waitpid(pid_t pid, int *status, int options);

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

/* Native zsh opens files through the object FS.  Only simple read-only opens go native in
 * this first cut (the rights model maps cleanly); create/append/trunc/write fall through. */
int __wrap_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    if (anon_native() && (flags & O_ACCMODE) == O_RDONLY &&
        !(flags & (O_CREAT | O_TRUNC | O_APPEND))) {
        long fd = hosq(HOSQ_OPEN, CAP_RIGHT_READ, (long)path, 0);
        if (fd >= 0) return (int)fd;
        /* fall through to the Linux path on native-open failure */
    }
    return __real_open(path, flags, mode);
}

/* Z4a.6: a native shell's I/O — the terminal (a §12 Device object) above all, but also the
 * files and pipes it reads/writes — goes through the native Device verbs instead of the
 * Linux read/write syscalls.  device_read/write reuse the VFS/PTY behind the fd, and the
 * kernel gives device_read the same cooperative blocking (+ ^C EINTR) a Linux terminal read
 * gets.  (Detecting *only* the tty would need isatty, which the kernel mishandles on a
 * dup'd PTY fd — zsh moves its terminal to a high fd; so we route all native I/O for now.) */
ssize_t __wrap_read(int fd, void *buf, size_t n) {
    if (anon_native()) return hosq(HOSQ_DEV_READ, fd, (long)buf, (long)n);
    return __real_read(fd, buf, n);
}
ssize_t __wrap_write(int fd, const void *buf, size_t n) {
    if (anon_native()) return hosq(HOSQ_DEV_WRITE, fd, (long)buf, (long)n);
    return __real_write(fd, buf, n);
}

/* Z4a.7: an external command's exec.  zsh forks, the child sets up its fds, then execve()s
 * the command; when native, route that through spawn_process — the kernel loads the image
 * into the (forked) caller via its process-creation machinery (Process object, cap-gate,
 * identity binding).  On success the call does not return (the task becomes the new image);
 * on failure (or non-native) fall through to the Linux exec. */
int __wrap_execve(const char *path, char *const argv[], char *const envp[]) {
    if (anon_native()) hosq(HOSQ_SPAWN, (long)path, (long)argv, (long)envp);
    return __real_execve(path, argv, envp);
}

/* Z4b.2: zsh reaps its jobs with wait3 (any child) and waitpid (a specific one); when native,
 * route both through object_wait — the §6 process-exit event verb.  The kernel blocks a
 * foreground wait the same way the Linux wait4 does (yield-and-re-run until the child exits),
 * and honours WNOHANG for the non-blocking reaps zsh's SIGCHLD handler does, so job control is
 * unchanged.  (rusage is dropped — wait4Task already ignores it on the Linux path too.)
 * hosq()'s syscall() does the -errno->-1/errno translation, matching wait3/waitpid. */
pid_t __wrap_wait3(int *status, int options, struct rusage *rusage) {
    if (anon_native()) return (pid_t)hosq(HOSQ_WAIT, -1, (long)status, (long)options);
    return __real_wait3(status, options, rusage);
}
pid_t __wrap_waitpid(pid_t pid, int *status, int options) {
    if (anon_native()) return (pid_t)hosq(HOSQ_WAIT, (long)pid, (long)status, (long)options);
    return __real_waitpid(pid, status, options);
}
