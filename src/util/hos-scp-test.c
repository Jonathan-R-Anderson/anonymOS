/*
 * hos-scp-test.c -- one-command log-upload self-test with per-step tracing.  Run it by typing: /scp-test
 *
 * TRANSPORT = HTTP POST (not scp/SSH).  The FW13's SSH-over-LKL-shim handshake resets during the banner
 * exchange (sshd logs `kex_exchange_identification: read: Connection reset by peer`), but plain TCP works
 * fine -- so we upload /run/klog with `busybox-dyn wget --post-file` (a dynamic applet: LD_PRELOAD routes
 * its socket/connect/send through the LKL/wlan0, and HTTP has no SSH handshake to fail on) to a tiny
 * user-space receiver on the target (local/epin-log-receiver.py) that writes the body to
 * ~/epinanonymos-debug.log.  Target host+port come from /epin-debug-net.conf (log_target_ip/log_http_port).
 *
 * The kernel execs boot modules as ELF only (no `#!`), so this is a single static-musl ELF that walks
 * three logged steps -- target, DHCP lease, HTTP POST -- so a failure pins to the exact layer.
 */
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>

static void sleep_s(int s) { struct timespec t = { s, 0 }; nanosleep(&t, NULL); }
static int  have_lease(void) { return access("/run/wifi/dhcp-ok", F_OK) == 0; }

static char *const g_net_envp[] =
    { "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };
static char *const g_udhcpc_argv[] =
    { "/busybox-dyn", "udhcpc", "-i", "wlan0", "-f", "-s", "/udhcpc-script", 0 };

/* Pull key=value out of /epin-debug-net.conf (same file/keys hos-log-upload reads). */
static int cfg_get(const char *key, char *out, size_t outsz)
{
    int fd = open("/epin-debug-net.conf", O_RDONLY);
    if (fd < 0) return 0;
    char buf[1024];
    int n = (int)read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    size_t klen = strlen(key);
    for (char *line = buf; line && *line; ) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (!strncmp(line, key, klen) && line[klen] == '=') {
            snprintf(out, outsz, "%s", line + klen + 1);
            return out[0] ? 1 : 0;
        }
        line = nl ? nl + 1 : 0;
    }
    return 0;
}

static void read_file(const char *path, char *out, size_t outsz)
{
    out[0] = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    int n = (int)read(fd, out, (int)outsz - 1);
    if (n > 0) out[n] = 0;
    close(fd);
    for (char *q = out; *q; q++) if (*q == '\n' || *q == '\r') *q = ' ';
}

/* Run argv under the shim (stdin=/dev/null), capturing stdout+stderr into out; return exit code. */
static int run_capture(char *const argv[], char *out, size_t outsz)
{
    const char *tmp = "/run/upload-step.log";
    int lf = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    pid_t p = fork();
    if (p == 0) {
        int dn = open("/dev/null", O_RDONLY);
        if (dn >= 0) { dup2(dn, 0); if (dn > 2) close(dn); }
        if (lf >= 0) { dup2(lf, 1); dup2(lf, 2); if (lf > 2) close(lf); }
        execve(argv[0], argv, g_net_envp);
        _exit(127);
    }
    if (lf >= 0) close(lf);
    int st = 0;
    waitpid(p, &st, 0);
    if (out && outsz) read_file(tmp, out, outsz);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int main(void)
{
    char tip[64], tport[16], url[160];
    if (!cfg_get("log_target_ip", tip, sizeof tip)) snprintf(tip, sizeof tip, "10.224.238.237");
    if (!cfg_get("log_http_port", tport, sizeof tport)) snprintf(tport, sizeof tport, "8088");
    snprintf(url, sizeof url, "http://%s:%s/upload", tip, tport);

    /* ── STEP 1: target ─────────────────────────────────────────────────────── */
    fprintf(stderr, "[upload] STEP 1/3  target = %s  (HTTP POST /run/klog)\n", url);

    /* ── STEP 2: DHCP lease ─────────────────────────────────────────────────── */
    fprintf(stderr, "[upload] STEP 2/3  DHCP lease...\n");
    if (!have_lease()) {
        fprintf(stderr, "[upload]   no /run/wifi/dhcp-ok yet -- starting udhcpc, waiting up to 60s...\n");
        pid_t u = fork();
        if (u == 0) { execve("/busybox-dyn", g_udhcpc_argv, g_net_envp); _exit(127); }
        for (int i = 0; i < 60 && !have_lease(); i++) sleep_s(1);
    }
    if (!have_lease()) {
        fprintf(stderr, "[upload]   FAIL: no lease (wlan0 not associated/leased). Fix Wi-Fi first, then re-run.\n");
        return 1;
    }
    { char lease[64]; read_file("/run/wifi/dhcp-ok", lease, sizeof lease);
      fprintf(stderr, "[upload]   OK: leased IP = %s\n", lease[0] ? lease : "(present)"); }

    /* ── STEP 3: HTTP POST via busybox-dyn wget (plain TCP, no SSH) ──────────── */
    fprintf(stderr, "[upload] STEP 3/3  POST /run/klog -> %s (busybox-dyn wget via LKL)...\n", url);
    char out[600];
    char *const wget_argv[] = { "/busybox-dyn", "wget", "-q", "-T", "15",
                                "--post-file=/run/klog", "-O", "/dev/null", url, 0 };
    int rc = run_capture(wget_argv, out, sizeof out);
    if (out[0]) fprintf(stderr, "[upload]   wget said: %s\n", out);

    if (rc == 0) {
        fprintf(stderr, "[upload] RESULT: SUCCESS -- /run/klog POSTed to %s\n", url);
        fprintf(stderr, "[upload]         it is saved as ~/epinanonymos-debug.log on the target.\n");
        return 0;
    }
    fprintf(stderr, "[upload] RESULT: FAILED (wget rc=%d).\n", rc);
    if (strstr(out, "refused") || strstr(out, "onnection"))
        fprintf(stderr, "[upload]   -> TCP refused/reset: the receiver isn't listening, or a firewall on the target dropped it (`sudo ufw allow %s/tcp`).\n", tport);
    else
        fprintf(stderr, "[upload]   -> no reply / timeout: firewall DROP on the target port, receiver down, or wrong IP. On the target: start local/epin-log-receiver.py and `sudo ufw allow %s/tcp`.\n", tport);
    return 1;
}
