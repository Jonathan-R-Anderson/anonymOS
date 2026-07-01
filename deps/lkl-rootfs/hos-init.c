/*
 * hos-init — PID 1 inside the embedded LKL (NetworkManager-GUI feature, Stage 0).
 *
 * The LKL runs the real iwlwifi driver + wlan0; to host NetworkManager's daemon stack we need a
 * real userspace + rootfs inside the LKL.  This is the init we exec (via lkl_syscall execve from
 * src/lkl/lkl-boot.c) off an ext4 disk image (deps/lkl-rootfs.ext4), mounted by lkl_mount_dev.
 *
 * Stage 0: mount the basic filesystems, print sentinels proving exec+rootfs+process-model work,
 * then park.  Stage 1 replaces the park with exec'ing dbus-daemon -> wpa_supplicant -> NetworkManager.
 *
 * Built static-musl (no libc loader in this rootfs yet).  Everything goes to stderr, which lkl-boot
 * mirrors to the EpinAnonymOS klog (serial->framebuffer), so the sentinels show on the boot screen.
 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>

static void try_mount(const char *src, const char *tgt, const char *fs, unsigned long flags)
{
	mkdir(tgt, 0755);
	if (mount(src, tgt, fs, flags, "") == 0)
		fprintf(stderr, ">>> lkl init: mounted %s on %s\n", fs, tgt);
	else
		fprintf(stderr, ">>> lkl init: mount %s on %s FAILED errno=%d\n", fs, tgt, errno);
}

static void show_file(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) { fprintf(stderr, ">>> lkl: open %s -> errno %d\n", path, errno); return; }
	char b[128];
	int n = read(fd, b, sizeof(b) - 1);
	close(fd);
	if (n < 0) { fprintf(stderr, ">>> lkl: read %s -> errno %d\n", path, errno); return; }
	if (n > 0 && b[n - 1] == '\n') n--;
	b[n > 0 ? n : 0] = 0;
	fprintf(stderr, ">>> lkl: %s = %s\n", path, b);
}

int main(int argc, char **argv)
{
	fprintf(stderr, ">>> lkl init: hello from PID %d (hos-init stage0)\n", getpid());

	try_mount("devtmpfs", "/dev",  "devtmpfs", 0);
	try_mount("proc",     "/proc", "proc",     0);
	try_mount("tmpfs",    "/run",  "tmpfs",    0);
	try_mount("tmpfs",    "/tmp",  "tmpfs",    0);
	try_mount("sysfs",    "/sys",  "sysfs",    0);

	/* prove /proc works + that we are the process the kernel exec'd */
	show_file("/proc/1/comm");
	show_file("/proc/version");

	/* Drop a marker in the (shared-mount-ns) tmpfs so lkl-boot can CONFIRM we actually ran,
	 * independent of stdio/printk routing: our fd 0/1/2 aren't wired to the console and the
	 * kernel-printk filter would eat stderr, but a file in /run is visible to lkl-boot. */
	int mfd = open("/run/hos-init-ok", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (mfd >= 0) {
		char msg[96];
		int mn = snprintf(msg, sizeof(msg),
				  "hos-init stage0 OK: exec+rootfs+process-model work, pid=%d\n",
				  getpid());
		if (write(mfd, msg, mn) < 0) { /* nothing we can do */ }
		close(mfd);
	}

	fprintf(stderr, ">>> lkl init: stage0 OK, parking as PID %d (daemons come in stage1)\n", getpid());
	for (;;)
		pause();
	return 0;
}
