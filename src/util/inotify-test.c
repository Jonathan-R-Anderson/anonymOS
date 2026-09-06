// inotify-test.c — ROADMAP 2.2 verification.
//
// Exercises the four syscalls end to end from USERSPACE, over the real syscall path, and prints a
// PASS/FAIL line per check.  Kernel-spawned on purpose: a process Hyprland forks inherits no
// console, so its output would be invisible -- the property that cost several rounds in 3.0b.
//
// Watches a directory in the writable overlay, then creates, writes to and deletes a file in it,
// reading the queue after each step.  Directory-watch-plus-name is what GIO actually does, so this
// tests the shape real callers use rather than the shape easiest to implement.
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/inotify.h>

#define DIR  "/home/user/.inotify-test"
#define FILE DIR "/probe.txt"

static int pass = 0, fail = 0;
static void check(int ok, const char *what)
{
	printf("[inotify] %s %s\n", ok ? "PASS" : "FAIL", what);
	fflush(stdout);
	if (ok) pass++; else fail++;
}

/* Drain the queue and report whether `want` was seen (optionally for `name`). */
static int drain_for(int ifd, unsigned want, const char *name)
{
	char buf[4096];
	ssize_t n = read(ifd, buf, sizeof buf);
	if (n <= 0) return 0;
	for (char *p = buf; p < buf + n; ) {
		struct inotify_event *e = (struct inotify_event *)p;
		if ((e->mask & want) && (!name || (e->len && !strcmp(e->name, name))))
			return 1;
		p += sizeof(struct inotify_event) + e->len;
	}
	return 0;
}

int main(void)
{
	printf("[inotify] ROADMAP 2.2: exercising inotify over the runtime overlay\n");
	fflush(stdout);

	mkdir(DIR, 0755);

	int ifd = inotify_init1(0);
	check(ifd >= 0, "inotify_init1 returns a descriptor");
	if (ifd < 0) { printf("[inotify] RESULT %d passed %d failed\n", pass, fail); return 1; }

	int wd = inotify_add_watch(ifd, DIR, IN_CREATE | IN_MODIFY | IN_DELETE);
	check(wd > 0, "inotify_add_watch on a directory returns a watch descriptor");

	int fd = open(FILE, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	check(fd >= 0, "created a file in the watched directory");
	check(drain_for(ifd, IN_CREATE, "probe.txt"), "IN_CREATE delivered, with the child's name");

	if (fd >= 0) {
		(void)!write(fd, "hello inotify\n", 14);
		close(fd);
	}
	check(drain_for(ifd, IN_MODIFY, NULL), "IN_MODIFY delivered after a write");

	unlink(FILE);
	check(drain_for(ifd, IN_DELETE, "probe.txt"), "IN_DELETE delivered, with the child's name");

	check(inotify_rm_watch(ifd, wd) == 0, "inotify_rm_watch accepts the descriptor");
	check(inotify_rm_watch(ifd, 4242) < 0, "inotify_rm_watch rejects an unknown descriptor");
	close(ifd);

	printf("[inotify] RESULT %d passed, %d failed\n", pass, fail);
	fflush(stdout);
	return fail ? 1 : 0;
}
