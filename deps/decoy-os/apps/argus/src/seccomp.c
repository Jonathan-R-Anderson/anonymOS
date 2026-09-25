#include "seccomp.h"

#ifdef __linux__
#include <stddef.h>          /* offsetof */
#include <errno.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/sched.h>     /* CLONE_THREAD */

#ifndef CLONE_THREAD
#define CLONE_THREAD 0x10000
#endif

/*
 * Build a BPF seccomp filter dynamically so we can use #ifdef guards around
 * arch-specific syscall numbers (e.g. __NR_fork doesn't exist on aarch64
 * where fork is done via clone).
 */

#define FILTER_MAX 64   /* ample headroom for the denylist entries */

/* Append: load syscall number into accumulator */
#define LOAD_NR(f, n) \
    (f)[(n)++] = (struct sock_filter) \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                 (unsigned int)offsetof(struct seccomp_data, nr))

/* Append: deny syscall `nr` with EPERM */
#define DENY(f, n, nr) do { \
    (f)[(n)++] = (struct sock_filter) \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)(nr), 0, 1); \
    (f)[(n)++] = (struct sock_filter) \
        BPF_STMT(BPF_RET | BPF_K, \
                 SECCOMP_RET_ERRNO | ((unsigned int)(EPERM) & SECCOMP_RET_DATA)); \
} while (0)

/* Append: allow everything else */
#define ALLOW_REST(f, n) \
    (f)[(n)++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

void seccomp_apply(void)
{
    struct sock_filter filter[FILTER_MAX];
    int n = 0;

    /* Load syscall number once — all DENY jumps are relative from here */
    LOAD_NR(filter, n);

    DENY(filter, n, __NR_execve);
#ifdef __NR_execveat
    DENY(filter, n, __NR_execveat);
#endif
#ifdef __NR_fork
    DENY(filter, n, __NR_fork);
#endif
#ifdef __NR_vfork
    DENY(filter, n, __NR_vfork);
#endif
    DENY(filter, n, __NR_ptrace);
    DENY(filter, n, __NR_setuid);
    DENY(filter, n, __NR_setgid);
#ifdef __NR_setresuid
    DENY(filter, n, __NR_setresuid);
#endif
#ifdef __NR_setresgid
    DENY(filter, n, __NR_setresgid);
#endif
#ifdef __NR_setreuid
    DENY(filter, n, __NR_setreuid);
#endif
#ifdef __NR_setregid
    DENY(filter, n, __NR_setregid);
#endif
    DENY(filter, n, __NR_mount);
    DENY(filter, n, __NR_init_module);
#ifdef __NR_finit_module
    DENY(filter, n, __NR_finit_module);
#endif
#ifdef __NR_delete_module
    DENY(filter, n, __NR_delete_module);
#endif
#ifdef __NR_kexec_load
    DENY(filter, n, __NR_kexec_load);
#endif
#ifdef __NR_kexec_file_load
    DENY(filter, n, __NR_kexec_file_load);
#endif

    /*
     * Block process-creating clone() calls.
     * Thread-creating clone (CLONE_THREAD flag set in args[0]) is allowed
     * so that any pthread usage is not broken.
     *
     * Instruction sequence (re-loads NR since accumulator may be stale):
     *   1. Load syscall NR
     *   2. If NR != __NR_clone → jump to ALLOW_REST (skip 4 instructions)
     *   3. Load args[0] (clone flags)
     *   4. If CLONE_THREAD bit is set → jump to ALLOW_REST (skip 1)
     *   5. Return EPERM (process fork via clone — denied)
     */
#ifdef __NR_clone
    /* Re-load NR */
    filter[n++] = (struct sock_filter)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int)offsetof(struct seccomp_data, nr));
    /* If not clone, skip next 3 (jump to allow) */
    filter[n++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)__NR_clone, 0, 3);
    /* Load clone flags (args[0]) */
    filter[n++] = (struct sock_filter)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int)(offsetof(struct seccomp_data, args[0])));
    /* If CLONE_THREAD bit set, allow (skip 1 = the deny) */
    filter[n++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 1, 0);
    /* Not a thread clone — deny with EPERM */
    filter[n++] = (struct sock_filter)
        BPF_STMT(BPF_RET | BPF_K,
                 SECCOMP_RET_ERRNO | ((unsigned int)(EPERM) & SECCOMP_RET_DATA));
#endif

    ALLOW_REST(filter, n);

    struct sock_fprog prog = {
        .len    = (unsigned short)n,
        .filter = filter,
    };

    /*
     * PR_SET_NO_NEW_PRIVS is required before installing a seccomp filter
     * without CAP_SYS_ADMIN.  It is a one-way ratchet — once set, child
     * processes also cannot gain new privileges via suid/sgid executables.
     */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return;   /* kernel too old or unsupported — skip silently */

    /* Install the filter.  Ignore errors so a missing feature never
     * crashes argus; the privilege drop already provides the main protection. */
    syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

#else  /* !__linux__ */

void seccomp_apply(void) { /* no-op on non-Linux */ }

#endif
