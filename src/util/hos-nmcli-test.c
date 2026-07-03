/*
 * hos-nmcli-test.c -- "boot-doctor": diagnose the dbus/provider/NetworkManager launch chain and write
 * the verdict to /run/boot-status.txt (static-musl).  Runs UNGATED at boot (not gated on NM having
 * launched), because the open question is exactly whether NM launched at all.  ps / /proc/comm /
 * /proc/cmdline / dmesg are all unimplemented on this kernel and ls can't see AF_UNIX sockets, so this
 * probes by connect()ing directly:
 *   - /run/dbus/system_bus_socket   (is the system bus up?)
 *   - /run/hos-net.sock             (did lkl-boot's provider come up? = the gate NM waits on)
 *   - org.freedesktop.NetworkManager Version via dbus-send (did NM register?)
 * The verdict file is overwritten each iteration; `cat /run/boot-status.txt` in a terminal shows it.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "hos-net-proto.h"

static void napms(long ms){ struct timespec t = { ms/1000, (ms%1000)*1000000L }; nanosleep(&t, 0); }

/* connect to an AF_UNIX path; return 0 on success else the positive errno. */
static int probe_connect(const char *path){
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return errno;
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX; strncpy(sa.sun_path, path, sizeof(sa.sun_path)-1);
    int r = connect(s, (struct sockaddr*)&sa, sizeof sa);
    int e = errno; close(s);
    return r == 0 ? 0 : e;
}
/* ENOENT(2) = socket absent (listener down); EACCES/EPERM = present but cap-gated; ECONNREFUSED = stale. */
static const char *present(int e){ return (e == 0 || e == EACCES || e == EPERM || e == ECONNREFUSED) ? "PRESENT" : "absent"; }

static int nm_registered(void){
    pid_t p = fork();
    if (p == 0) {
        int nul = open("/dev/null", O_WRONLY); if (nul >= 0){ dup2(nul,1); dup2(nul,2); }
        char *argv[] = { "/dbus-send", "--system", "--print-reply",
                         "--dest=org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager",
                         "org.freedesktop.DBus.Properties.Get",
                         "string:org.freedesktop.NetworkManager", "string:Version", 0 };
        char *envp[] = { "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };
        execve("/dbus-send", argv, envp); _exit(127);
    }
    if (p < 0) return 0;
    int st = 0; waitpid(p, &st, 0);
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 1 : 0;
}

static void write_one(const char *path, const char *s){
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) { (void)!write(fd, s, strlen(s)); close(fd); }
}
static int read_full(int fd, void *buf, int n){
    int got = 0, r;
    while (got < n && (r = read(fd, (char*)buf + got, n - got)) > 0) got += r;
    return got == n;
}
/* Fetch the shim's netlink trace from the net-provider (NSP_GETTRACE) and write it where the sandboxed
 * terminal can read it.  The shim ships its trace lines to the provider over the (safe) socket; the
 * provider accumulates them in memory.  We — a separate, file-safe process — pull them and write the file,
 * so nothing in NM's fault-prone LD_PRELOAD context ever touches the filesystem.  Retry the connect: the
 * provider's tiny accept backlog often refuses the first attempt. */
static void fetch_trace(const char *dst){
    static char buf[NSP_MAXBUF];
    int s = -1;
    for (int i = 0; i < 200; i++) {
        s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s < 0) { napms(20); continue; }
        struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
        sa.sun_family = AF_UNIX; strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path)-1);
        if (connect(s, (struct sockaddr*)&sa, sizeof sa) == 0) break;
        close(s); s = -1; napms(20);
    }
    if (s < 0) { write_one(dst, "(could not connect to net-provider for NSP_GETTRACE)\n"); return; }

    nsp_req rq; memset(&rq, 0, sizeof rq); rq.op = NSP_GETTRACE;
    nsp_resp rs;
    if (write(s, &rq, sizeof rq) != (long)sizeof rq || !read_full(s, &rs, sizeof rs)) {
        close(s); write_one(dst, "(NSP_GETTRACE request/reply failed)\n"); return;
    }
    unsigned n = rs.buflen; if (n > sizeof buf) n = sizeof buf;
    if (n && !read_full(s, buf, n)) { close(s); write_one(dst, "(NSP_GETTRACE truncated reply)\n"); return; }
    close(s);
    if (!n) { write_one(dst, "(net-provider has no shim trace yet -- NM never sent an OVER-CAP/STUCK line)\n"); return; }
    int out = open(dst, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (out >= 0) { (void)!write(out, buf, n); close(out); }
}
static void write_status(const char *s){
    write_one("/run/boot-status.txt", s);
    write_one("/tmp/boot-status.txt", s);   /* /tmp is a plain ramfs; /run might not persist here */
    (void)!write(1, s, strlen(s));           /* stdout + stderr, in case one is redirected */
    (void)!write(2, s, strlen(s));
}

int main(void)
{
    (void)!write(1, "boot-doctor: starting checks...\n", 31);
    (void)!write(2, "boot-doctor: starting checks...\n", 31);
    /* Check the two sockets ONCE (each connect spawns a provider handler thread; don't churn them).
     * Their state doesn't change once up.  Then poll NM (dbus-send forks are reaped via wait4). */
    int db = probe_connect("/run/dbus/system_bus_socket");
    int pv = probe_connect("/run/hos-net.sock");
    const int prov_absent = (strcmp(present(pv), "absent") == 0);
    int ok = 0;
    for (int i = 1; i <= 20; i++) {
        int nm = nm_registered();
        const char *verdict =
            nm ? "NM IS UP + registered -- the full stack works on real hardware (M2b OK)."
          : (strcmp(present(pv), "absent") == 0)
               ? "PROVIDER SOCKET ABSENT -> lkl-boot's net-provider never came up -> NM's launch gate never fires. Chase LKL/provider."
          : (strcmp(present(db), "absent") == 0)
               ? "dbus socket absent -> the system bus did not start."
               : "provider+dbus PRESENT but NM not registered -> NM launched but is stuck/crashed before D-Bus.";
        char buf[640];
        snprintf(buf, sizeof buf,
            "=== EpinAnonymOS boot-doctor (iter %d/20) ===\n"
            "dbus   /run/dbus/system_bus_socket : %s (errno %d)\n"
            "prov   /run/hos-net.sock           : %s (errno %d)\n"
            "NM     registered on the bus       : %s\n"
            "VERDICT: %s\n",
            i, present(db), db, present(pv), pv, nm ? "YES" : "no", verdict);
        write_status(buf);
        if (nm) { ok = 1; break; }
        if (prov_absent) break;      /* NM can't launch without the provider — verdict won't change */
        napms(3000);
    }
    /* Pull the shim's netlink trace from the provider and write it where a terminal can read it. */
    fetch_trace("/run/shim-nm-dump.txt");
    fetch_trace("/tmp/shim-nm-dump.txt");
    return ok ? 0 : 1;
}
