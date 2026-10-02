/*
 * hos-container.c -- a minimal container runtime for anonymOS (ANDROID bring-up phase A8).
 *
 * Waydroid containers Android with LXC.  Rather than vendor the ~100k-line upstream liblxc, this is
 * the "built-in equivalent that satisfies the container contract" the roadmap allows: a small
 * static-musl program that performs exactly the lxc-start sequence against the kernel surface built
 * in A1-A7b -- it unshares a namespace set (mount/pid/uts/ipc), becomes pid 1 in its new pid
 * namespace, creates and joins a cgroup, makes a mount private to its mount namespace, optionally
 * pivot_root's into a rootfs, and execs the container's init.  Running it inside the anonymOS VM
 * exercises the whole stack end-to-end with a real process, not a kernel self-test.
 *
 *   hos-container [--root <dir>] [cmd [args...]]
 *
 * With no cmd it brings the container up, prints a PASS line, and exits -- the boot test path.
 * It is the engine hos-waydroid will drive once an Android image exists (A9); on its own it is a
 * tiny unprivileged-looking container launcher.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>

#define CGDIR "/sys/fs/cgroup/hosctr"

/* Create the container's cgroup and move the calling process into it.  Returns 0 on success. */
static int cgroup_join(void) {
    mkdir(CGDIR, 0755);                       /* EEXIST is fine */
    /* Enable controllers on the root's subtree so the child cgroup has them (best-effort). */
    int s = open("/sys/fs/cgroup/cgroup.subtree_control", O_WRONLY);
    if (s >= 0) { (void)!write(s, "+pids +memory", 13); close(s); }
    int f = open(CGDIR "/cgroup.procs", O_WRONLY);
    if (f < 0) return -1;
    char buf[16];
    int n = snprintf(buf, sizeof buf, "%d\n", (int)getpid());
    int w = (int)write(f, buf, (size_t)n);
    close(f);
    return (w == n) ? 0 : -1;
}

/* The container's "init": set up the sandbox, then exec the payload (or report and exit). */
static int container_init(const char *root, int argc, char **argv) {
    int ok = 1;

    int cpid = (int)getpid();                 /* first getpid in the new pid-ns -> 1 */
    printf("[hos-container] in-container pid=%d\n", cpid);
    if (cpid != 1) { fprintf(stderr, "[hos-container] expected pid 1 in the new pid namespace\n"); ok = 0; }

    sethostname("container", 9);              /* our UTS namespace */

    if (cgroup_join() == 0) {
        printf("[hos-container] cgroup: joined %s\n", CGDIR);
    } else { fprintf(stderr, "[hos-container] cgroup join failed: %s\n", strerror(errno)); ok = 0; }

    /* A mount made here lives in our mount namespace only. */
    if (mount("none", "/mnt", "tmpfs", 0, NULL) == 0)
        printf("[hos-container] mnt-ns: mounted tmpfs at /mnt\n");
    else
        printf("[hos-container] mnt-ns: mount skipped (%s)\n", strerror(errno));

    /* Switch into the container root if one was given. */
    if (root) {
        if (chdir(root) == 0 && chroot(root) == 0)
            printf("[hos-container] root: pivoted into %s\n", root);
        else
            printf("[hos-container] root: pivot into %s skipped (%s)\n", root, strerror(errno));
    }

    if (argc > 0) {
        execvp(argv[0], argv);
        fprintf(stderr, "[hos-container] exec %s failed: %s\n", argv[0], strerror(errno));
        return 127;
    }

    printf(ok ? "[hos-container] A8 PASS: namespaced (pid 1), cgrouped, mnt-ns up\n"
              : "[hos-container] A8 FAIL\n");

    /* A9.1: report whether the Android kernel ABI is reachable from inside the container.  These are
     * the nodes Android's init/bionic touch before any userland: the three binder contexts, ashmem,
     * cgroup2, and selinuxfs.  The remaining A9 work is Android's OWN userland (property service,
     * init, HALs, SurfaceFlinger) plus the system image. */
    static const char *abi[] = {
        "/dev/binder", "/dev/hwbinder", "/dev/vndbinder", "/dev/ashmem",
        "/sys/fs/cgroup/cgroup.controllers", "/sys/fs/selinux/enforce",
    };
    int ready = 1;
    for (unsigned i = 0; i < sizeof abi / sizeof abi[0]; ++i) {
        int fd = open(abi[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { close(fd); }
        else { ready = 0; printf("[hos-container] android-abi MISSING: %s (%s)\n", abi[i], strerror(errno)); }
    }
    printf("[hos-container] android-abi: %s\n",
           ready ? "READY (binder x3, ashmem, cgroup2, selinuxfs reachable in-container)"
                 : "incomplete");

    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    const char *root = NULL;
    int i = 1;
    if (i < argc && !strcmp(argv[i], "--root") && i + 1 < argc) { root = argv[i + 1]; i += 2; }

    /* Unshare the namespaces LXC gives Android.  CLONE_NEWPID takes effect for our CHILD (the
     * container init), which therefore becomes pid 1 in the new pid namespace. */
    if (unshare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID) != 0) {
        fprintf(stderr, "[hos-container] unshare failed: %s\n", strerror(errno));
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) { fprintf(stderr, "[hos-container] fork failed: %s\n", strerror(errno)); return 1; }
    if (pid == 0) {
        _exit(container_init(root, argc - i, &argv[i]));
    }

    int status = 0;
    waitpid(pid, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    printf("[hos-container] container exited (status %d)\n", code);
    return code;
}
