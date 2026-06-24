/* platform/anonymos/ — Z4a: zsh's native-personality host hooks.
 *
 * The true native-ABI port routes zsh's host I/O through the EpinAnonymOS native object
 * ABI (HOS_SYS_QUERY) when the process runs in the native personality.  zsh's parser/
 * expander are untouched — only the low-level open is interposed, via the linker's --wrap
 * so no call site changes.  For a Linux-personality zsh (the default shell) the hook falls
 * straight through to __real_open, so this is completely transparent there.
 *
 * object_open resolves the path through the object filesystem (namespace-gated) and, for a
 * VFS-backed file, returns the real backing fd as the handle — so every other fd operation
 * zsh does (read/write/close/dup/fcntl/fstat/mmap) keeps working through the normal path.
 * That is what makes a native shell actually run; a separate high handle space made zsh
 * grow its fd-indexed tables to ~1e9 entries and OOM.  (A future pure-object filesystem,
 * whose files are not VFS-backed, would hand back an opaque handle and also wrap the data
 * ops to route through object_read/write.)
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdarg.h>

/* native ABI (mirrors core/hoscall.d) */
#define HOS_SYS_QUERY   0x4000L
#define HOSQ_SYS        5L
#define HOSQ_OPEN       7L
#define CAP_RIGHT_READ  1L

extern int __real_open(const char *path, int flags, ...);

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
 * this first cut (the rights model maps cleanly); create/append/trunc/write fall through
 * until those land.  The returned native handle is a real fd, so read/write/close/… need no
 * wrapping. */
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
