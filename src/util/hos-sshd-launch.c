// hos-sshd-launch.c — SSH-in launcher for EpinAnonymOS remote access.
//
// Architecture (see roadmap): the working network on real hardware is the LKL (WiFi), so
// inbound SSH can't bind AF_INET on the native kernel. Instead `lkl-boot` runs a bridge
// thread that listens on the LKL's TCP :22, and relays each connection to THIS launcher
// over a native AF_UNIX socket (/run/sshd.sock). This launcher accepts that stream and, per
// connection, forks `dropbear -i` (inetd mode) with stdin/stdout = the connection — so
// dropbear speaks the SSH protocol over the bridged TCP byte stream, does auth against
// /etc/passwd, allocates a PTY, and spawns the login shell. No nshim needed (dropbear -i
// never calls socket(); it only reads/writes fd 0/1).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#define SSHD_SOCK  "/run/sshd.sock"
#define DROPBEAR   "/dropbear"                       // staged as a boot module at /
#define HOSTKEY    "/run/dropbear_host_key"          // generated at boot by the launcher
#define SSHD_LOG   "/run/sshd.log"                   // dedicated SSH log (Logs app: SUPER+L, Tab)

#include <stdarg.h>
#include <fcntl.h>
#include <time.h>

// Append a line to /run/sshd.log (mirrored into /run/klog by the kernel's *.log tap, so it
// shows in the Logs app both as a dedicated source and in the merged view).
static int g_log_fd = -2;
static void slog(const char *fmt, ...)
{
    char line[512];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof line - 2) n = (int)sizeof line - 2;
    line[n++] = '\n'; line[n] = 0;
    if (g_log_fd == -2) g_log_fd = open(SSHD_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_log_fd >= 0) { ssize_t w = write(g_log_fd, line, (size_t)n); (void)w; }
    else { fputs(line, stderr); fflush(stderr); }
}

static void reap(int sig) { (void)sig; while (waitpid(-1, NULL, WNOHANG) > 0) {} }

int main(void)
{
    signal(SIGCHLD, reap);
    signal(SIGPIPE, SIG_IGN);

    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0) { fprintf(stderr, "[sshd] socket: %d\n", errno); return 1; }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, SSHD_SOCK, sizeof(sa.sun_path) - 1);
    unlink(SSHD_SOCK);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) < 0) { slog("[sshd] bind %s: errno %d", SSHD_SOCK, errno); return 1; }
    if (listen(ls, 8) < 0) { slog("[sshd] listen: errno %d", errno); return 1; }
    slog("[sshd] launcher up: listening on %s -> forks dropbear -i per connection (log: %s)", SSHD_SOCK, SSHD_LOG);

    for (;;) {
        int cs = accept(ls, NULL, NULL);
        if (cs < 0) {
            if (errno == EINTR) continue;
            usleep(20000);
            continue;
        }
        slog("[sshd] SSH connection accepted -> spawning dropbear -i (its log follows)");
        pid_t pid = fork();
        if (pid == 0) {
            // Child: wire the connection to dropbear's stdin/stdout, redirect dropbear's stderr
            // (-E) to /run/sshd.log so its auth/PTY/shell diagnostics land in the dedicated log.
            close(ls);
            if (cs != 0) dup2(cs, 0);
            if (cs != 1) dup2(cs, 1);
            int lf = open(SSHD_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (lf >= 0) { dup2(lf, 2); if (lf > 2) close(lf); }   // dropbear -E -> /run/sshd.log
            if (cs > 2) close(cs);
            // -i inetd (single conn on fd0/1); -E log to stderr (now /run/sshd.log); -R auto-gen
            // host key if missing; password auth stays enabled for debug login.
            execl(DROPBEAR, "dropbear", "-i", "-E", "-R", "-r", HOSTKEY, (char *)NULL);
            slog("[sshd] execl(%s) failed: errno %d", DROPBEAR, errno);
            _exit(127);
        } else if (pid > 0) {
            close(cs);   // parent keeps only the listener
        } else {
            fprintf(stderr, "[sshd] fork: %d\n", errno);
            close(cs);
        }
    }
    return 0;
}
