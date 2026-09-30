/* ginsmod FILE.ko... -- load kernel modules in the order given (finit_module), for the guest
 * initramfs: its static busybox has no insmod/modprobe.  A module already loaded is fine. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY | O_CLOEXEC);
        if (fd < 0) { fprintf(stderr, "ginsmod: %s: %s\n", argv[i], strerror(errno)); rc = 1; continue; }
        if (syscall(SYS_finit_module, fd, "", 0) != 0 && errno != EEXIST) {
            fprintf(stderr, "ginsmod: %s: %s\n", argv[i], strerror(errno));
            rc = 1;
        }
        close(fd);
    }
    return rc;
}
