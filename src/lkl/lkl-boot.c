/* L2: minimal LKL embedder — boot the Linux kernel as a library, print version, halt. */
#include <lkl.h>
#include <lkl_host.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    long ret;
    if ((ret = lkl_init(&lkl_host_ops)) < 0) {
        fprintf(stderr, "lkl_init failed: %ld\n", ret);
        return 1;
    }
    ret = lkl_start_kernel("mem=32M loglevel=8");
    if (ret < 0) {
        fprintf(stderr, "lkl_start_kernel failed: %ld\n", ret);
        return 1;
    }
    fprintf(stderr, ">>> LKL up inside the embedder. getpid()=%ld\n", lkl_sys_getpid());
    /* prove the LKL VFS works (the call-in path EpinAnonymOS will bridge) */
    long fd = lkl_sys_openat(LKL_AT_FDCWD, "/lkl-l2", LKL_O_CREAT|LKL_O_WRONLY, 0644);
    fprintf(stderr, ">>> lkl_sys_openat(/lkl-l2)=%ld\n", fd);
    if (fd >= 0) { lkl_sys_write(fd, "hello-from-L2\n", 14); lkl_sys_close(fd); }
    lkl_sys_halt();
    lkl_cleanup();
    fprintf(stderr, ">>> LKL halted cleanly.\n");
    return 0;
}
