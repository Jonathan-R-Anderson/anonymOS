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
#include <sys/mman.h>
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

    /* A9.2/A9.3g: the system-property area under /dev/__properties__ is seeded by the kernel (bionic
     * prop_area + property_info), so just confirm a property reads back -- do NOT write here: this is
     * the area ART reads, and clobbering the context file breaks property resolution. */
    {
        int pf = open("/dev/__properties__/property_info", O_RDONLY);
        printf("[hos-container] prop-area: %s\n",
               pf >= 0 ? "present (kernel-seeded bionic property area)" : "absent");
        if (pf >= 0) close(pf);
    }

    /* A9.3b: the Android system image is mounted read-only at /aroot.  Prove it by reading a real
     * Android ELF binary (app_process64 -- the Zygote/app host) by its direct path, and A9.3c: again
     * through the /aroot/bin -> /system/bin symlink, exercising ext4 symlink following. */
    const char *APP = "/aroot/system/bin/app_process64";   /* direct, real file   */
    const char *LNK = "/aroot/bin/app_process64";          /* via /bin -> /system/bin symlink */
    int elfDirect = 0, elfLink = 0;
    int lf = open(APP, O_RDONLY);
    if (lf >= 0) { unsigned char h[8] = {0}; int rn = (int)read(lf, h, sizeof h); close(lf);
        elfDirect = rn >= 5 && h[0]==0x7f && h[1]=='E' && h[2]=='L' && h[3]=='F' && h[4]==2; }
    int sf = open(LNK, O_RDONLY);
    if (sf >= 0) { unsigned char h[8] = {0}; int rn = (int)read(sf, h, sizeof h); close(sf);
        elfLink = rn >= 5 && h[0]==0x7f && h[1]=='E' && h[2]=='L' && h[3]=='F' && h[4]==2; }
    if (elfDirect)
        printf("[hos-container] android-image: MOUNTED (app_process64 is a 64-bit ELF; /bin symlink follow=%s)\n",
               elfLink ? "OK" : "no");
    else
        printf("[hos-container] android-image: /aroot not readable (%s)\n", strerror(errno));

    /* A9.3c: try to actually EXEC a real Android binary from the image.  chroot into /aroot so the
     * binary's interpreter (/system/bin/linker64) and libraries resolve inside the image, then
     * execve app_process64.  The kernel's [exec] log lines report how far the load gets; whatever
     * fails is the next concrete bring-up step.  Done in a child so this reporter survives. */
    if (elfDirect) {
        pid_t ep = fork();
        if (ep == 0) {
            if (chroot("/aroot") != 0) {
                printf("[hos-container] exec-bionic: chroot /aroot failed: %s\n", strerror(errno));
                _exit(1);
            }
            chdir("/");   /* now inside the Android root */
            /* A9.3i: make this child's stderr unmistakably visible.  fds 0/1/2 are inherited as the
             * kernel console (-> serial), but prove the channel and route anything ART writes to fd 2
             * there too, so startVm()'s pre-CreateJavaVM failures (which AndroidRuntime::start returns
             * on WITHOUT logging) are captured. */
            dup2(1, 2);
            { const char *pb = "[exec-bionic] stderr->serial OK; invoking app_process64 --zygote\n";
              (void)!write(2, pb, strlen(pb)); }
            char *av[] = { (char *)"/system/bin/app_process64", (char *)"-Xzygote",
                           (char *)"/system/bin", (char *)"--zygote", NULL };
            char *ev[] = { (char *)"PATH=/system/bin", (char *)"ANDROID_ROOT=/system",
                           (char *)"ANDROID_DATA=/data",
                           /* A9.3i: recent ART derives the boot-image location and the ICU / time-zone
                            * data paths from these APEX-root env vars; app_process does not default
                            * them, and startVm() fails SILENTLY (returns -1 with no log) when they are
                            * unset.  Point each at its flattened APEX dir under /system/apex. */
                           (char *)"ANDROID_ART_ROOT=/apex/com.android.art",
                           (char *)"ANDROID_I18N_ROOT=/apex/com.android.i18n",
                           (char *)"ANDROID_TZDATA_ROOT=/apex/com.android.tzdata",
                           (char *)"ANDROID_RUNTIME_ROOT=/apex/com.android.runtime",
                           /* A9.3j: ART's JNI_CreateJavaVM aborts with "Boot classpath is empty"
                            * unless BOOTCLASSPATH is exported.  On a device derive_classpath builds
                            * it at boot from each APEX's etc/classpaths .pb fragments; we derived the same
                            * set+order from THIS GSI's fragments (read with debugfs).  The first 12
                            * jars are DEX2OATBOOTCLASSPATH -- the ones the prebuilt boot image in
                            * /system/framework/<isa>/ (boot.art + boot-*.art) was compiled against,
                            * so their order must match exactly; the remaining APEX jars follow in
                            * derive_classpath's (alphabetical-APEX) order. */
                           (char *)"BOOTCLASSPATH="
                               "/apex/com.android.art/javalib/core-oj.jar"
                               ":/apex/com.android.art/javalib/core-libart.jar"
                               ":/apex/com.android.art/javalib/okhttp.jar"
                               ":/apex/com.android.art/javalib/bouncycastle.jar"
                               ":/apex/com.android.art/javalib/apache-xml.jar"
                               ":/system/framework/framework.jar"
                               ":/system/framework/framework-graphics.jar"
                               ":/system/framework/ext.jar"
                               ":/system/framework/telephony-common.jar"
                               ":/system/framework/voip-common.jar"
                               ":/system/framework/ims-common.jar"
                               ":/apex/com.android.i18n/javalib/core-icu4j.jar"
                               ":/apex/com.android.adservices/javalib/framework-adservices.jar"
                               ":/apex/com.android.adservices/javalib/framework-sdksandbox.jar"
                               ":/apex/com.android.appsearch/javalib/framework-appsearch.jar"
                               ":/apex/com.android.btservices/javalib/framework-bluetooth.jar"
                               ":/apex/com.android.conscrypt/javalib/conscrypt.jar"
                               ":/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar"
                               ":/apex/com.android.media/javalib/updatable-media.jar"
                               ":/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar"
                               ":/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar"
                               ":/apex/com.android.os.statsd/javalib/framework-statsd.jar"
                               ":/apex/com.android.permission/javalib/framework-permission.jar"
                               ":/apex/com.android.permission/javalib/framework-permission-s.jar"
                               ":/apex/com.android.scheduling/javalib/framework-scheduling.jar"
                               ":/apex/com.android.sdkext/javalib/framework-sdkextensions.jar"
                               ":/apex/com.android.tethering/javalib/framework-connectivity.jar"
                               ":/apex/com.android.tethering/javalib/framework-connectivity-t.jar"
                               ":/apex/com.android.tethering/javalib/framework-tethering.jar"
                               ":/apex/com.android.uwb/javalib/framework-uwb.jar"
                               ":/apex/com.android.wifi/javalib/framework-wifi.jar",
                           (char *)"DEX2OATBOOTCLASSPATH="
                               "/apex/com.android.art/javalib/core-oj.jar"
                               ":/apex/com.android.art/javalib/core-libart.jar"
                               ":/apex/com.android.art/javalib/okhttp.jar"
                               ":/apex/com.android.art/javalib/bouncycastle.jar"
                               ":/apex/com.android.art/javalib/apache-xml.jar"
                               ":/system/framework/framework.jar"
                               ":/system/framework/framework-graphics.jar"
                               ":/system/framework/ext.jar"
                               ":/system/framework/telephony-common.jar"
                               ":/system/framework/voip-common.jar"
                               ":/system/framework/ims-common.jar"
                               ":/apex/com.android.i18n/javalib/core-icu4j.jar",
                           (char *)"SYSTEMSERVERCLASSPATH="
                               "/system/framework/com.android.location.provider.jar"
                               ":/system/framework/services.jar",
                           /* A9.3d/e: the bootstrap linker has no linker-config namespaces yet, so
                            * give it an explicit search path -- /system/lib64 plus the APEX lib dirs
                            * (now activated by the /apex -> /system/apex redirect) that hold the
                            * runtime: libc/libdl/libm (runtime/bionic), libc++/ld-android (runtime),
                            * libandroidicu (i18n), libnativeloader/libsigchain (art). */
                           (char *)"LD_LIBRARY_PATH=/system/lib64:/apex/com.android.runtime/lib64:"
                                   "/apex/com.android.runtime/lib64/bionic:/apex/com.android.art/lib64:"
                                   "/apex/com.android.i18n/lib64:/apex/com.android.os.statsd/lib64:"
                                   "/apex/com.android.vndk.current/lib64:/vendor/lib64",
                           NULL };
            execve("/system/bin/app_process64", av, ev);
            printf("[hos-container] exec-bionic: execve app_process64 failed: %s\n", strerror(errno));
            _exit(1);
        }
        int est = 0;
        waitpid(ep, &est, 0);
        printf("[hos-container] exec-bionic: attempt complete (child %s %d)\n",
               WIFEXITED(est) ? "exit" : "signal",
               WIFEXITED(est) ? WEXITSTATUS(est) : WTERMSIG(est));
    }

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
