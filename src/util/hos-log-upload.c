/*
 * hos-log-upload.c -- debug log snapshot + scp launcher.
 *
 * This is intentionally small: it does not implement SSH. It waits for the Wi-Fi
 * path to look active, writes one combined /tmp/epin-debug-logs.txt snapshot, and
 * execs /scp using /ssh as the transport. The staged default is Dropbear
 * scp/dbclient; the child runs with LD_PRELOAD=/libnshim.so so AF_INET traffic
 * is routed through lkl-boot's cap-gated network provider.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CFG_PATH      "/epin-debug-net.conf"
#define SNAPSHOT_PATH "/tmp/epin-debug-logs.txt"
#define KEY_COPY_PATH "/tmp/epin-debug-ssh-key"

static void nap_ms(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, 0);
}

static void logf_stderr(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n >= (int)sizeof buf) n = (int)sizeof buf - 1;
    (void)!write(2, "[log-upload] ", 13);
    (void)!write(2, buf, (size_t)n);
    (void)!write(2, "\n", 1);
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) *--e = 0;
    return s;
}

static int config_value(const char *key, char *out, size_t outsz)
{
    out[0] = 0;
    int fd = open(CFG_PATH, O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096];
    long n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;

    for (char *line = buf; line && *line; ) {
        char *next = strchr(line, '\n');
        if (next) *next++ = 0;
        char *p = trim(line);
        if (*p && *p != '#') {
            char *eq = strchr(p, '=');
            if (eq) {
                *eq = 0;
                char *k = trim(p);
                char *v = trim(eq + 1);
                if (strcmp(k, key) == 0) {
                    strncpy(out, v, outsz - 1);
                    out[outsz - 1] = 0;
                    return out[0] != 0;
                }
            }
        }
        line = next;
    }
    return 0;
}

static int file_exists(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static void write_all(int fd, const void *buf, size_t n)
{
    const char *p = (const char *)buf;
    while (n) {
        long w = write(fd, p, n);
        if (w <= 0) return;
        p += w;
        n -= (size_t)w;
    }
}

static void write_str(int fd, const char *s)
{
    write_all(fd, s, strlen(s));
}

static void append_file(int out, const char *path)
{
    char header[256];
    int hn = snprintf(header, sizeof header, "\n===== %s =====\n", path);
    if (hn > 0) write_all(out, header, (size_t)hn);

    int in = open(path, O_RDONLY);
    if (in < 0) {
        write_str(out, "(unavailable)\n");
        return;
    }
    char buf[8192];
    for (;;) {
        long n = read(in, buf, sizeof buf);
        if (n <= 0) break;
        write_all(out, buf, (size_t)n);
    }
    close(in);
    write_str(out, "\n");
}

static void write_snapshot(void)
{
    mkdir("/tmp", 0777);
    int out = open(SNAPSHOT_PATH, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (out < 0) {
        logf_stderr("cannot create %s: errno=%d", SNAPSHOT_PATH, errno);
        return;
    }
    write_str(out, "EpinAnonymOS debug log snapshot\n");
    append_file(out, "/run/klog");
    append_file(out, "/run/boot-status.txt");
    append_file(out, "/run/nm.log");
    append_file(out, "/run/wpa.log");
    append_file(out, "/run/wifi/networks");
    append_file(out, "/run/shim-nm.log");
    close(out);
}

static int copy_file_mode(const char *src, const char *dst, mode_t mode)
{
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (out < 0) {
        close(in);
        return -1;
    }
    char buf[4096];
    for (;;) {
        long n = read(in, buf, sizeof buf);
        if (n <= 0) break;
        write_all(out, buf, (size_t)n);
    }
    close(in);
    close(out);
    chmod(dst, mode);
    return 0;
}

static int wifi_activated(void)
{
    int fd = open("/run/wifi/networks", O_RDONLY);
    if (fd < 0) return 0;
    char buf[1024];
    long n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    char *first = buf;
    char *nl = strchr(first, '\n');
    if (nl) *nl = 0;
    if (strncmp(first, "#dev\t", 5) != 0) return 0;
    char *last = strrchr(first, '\t');
    if (!last) return 0;
    return atoi(last + 1) >= 100;
}

static int run_scp(const char *target_user, const char *target_ip, const char *target_path, const char *key_path)
{
    char remote[512];
    int rn = snprintf(remote, sizeof remote, "%s@%s:%s", target_user, target_ip, target_path);
    if (rn <= 0 || rn >= (int)sizeof remote) {
        logf_stderr("remote target too long");
        return 2;
    }

    char *argv[32];
    int a = 0;
    argv[a++] = "/scp";
    argv[a++] = "-S";
    argv[a++] = "/ssh";
    argv[a++] = "-o";
    argv[a++] = "BatchMode=yes";
    argv[a++] = "-o";
    argv[a++] = "StrictHostKeyChecking=no";
    argv[a++] = "-o";
    argv[a++] = "PasswordAuthentication=no";
    if (key_path && key_path[0]) {
        argv[a++] = "-i";
        argv[a++] = (char *)key_path;
    }
    argv[a++] = SNAPSHOT_PATH;
    argv[a++] = remote;
    argv[a++] = 0;

    char *envp[] = {
        "LD_PRELOAD=/libnshim.so",
        "LD_LIBRARY_PATH=/",
        "PATH=/",
        "HOME=/",
        0
    };

    pid_t pid = fork();
    if (pid < 0) {
        logf_stderr("fork failed: errno=%d", errno);
        return 3;
    }
    if (pid == 0) {
        execve("/scp", argv, envp);
        _exit(127);
    }
    int st = 0;
    time_t start = time(0);
    for (;;) {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid) break;
        if (w < 0) {
            logf_stderr("waitpid failed: errno=%d", errno);
            return 4;
        }
        if (time(0) - start >= 60) {
            logf_stderr("scp timed out; terminating child");
            kill(pid, SIGTERM);
            nap_ms(1000);
            if (waitpid(pid, &st, WNOHANG) == 0) kill(pid, SIGKILL);
            (void)waitpid(pid, &st, 0);
            return 124;
        }
        nap_ms(250);
    }
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    return 5;
}

int main(void)
{
    logf_stderr("starting");

    char target_ip[64], target_user[64], target_path[160], key_src[160];
    if (!config_value("log_target_ip", target_ip, sizeof target_ip)) {
        logf_stderr("%s missing log_target_ip; upload disabled", CFG_PATH);
        return 1;
    }
    if (!config_value("log_target_user", target_user, sizeof target_user)) {
        strcpy(target_user, "root");
    }
    if (!config_value("log_target_path", target_path, sizeof target_path)) {
        strcpy(target_path, "epinanonymos-debug.log");
    }
    int have_key = config_value("log_ssh_key", key_src, sizeof key_src);
    const char *key_for_scp = 0;
    if (have_key) {
        if (copy_file_mode(key_src, KEY_COPY_PATH, 0600) == 0) key_for_scp = KEY_COPY_PATH;
        else logf_stderr("configured log_ssh_key is unavailable: %s", key_src);
    }

    if (!file_exists("/scp") || !file_exists("/ssh")) {
        logf_stderr("missing /scp or /ssh boot module; cannot use scp yet");
        write_snapshot();
        return 2;
    }

    for (int attempt = 1; attempt <= 20; attempt++) {
        write_snapshot();
        if (!wifi_activated() && attempt <= 6) {
            logf_stderr("waiting for Wi-Fi activation before scp attempt %d", attempt);
            nap_ms(10000);
            continue;
        }
        logf_stderr("scp attempt %d -> %s@%s:%s", attempt, target_user, target_ip, target_path);
        int rc = run_scp(target_user, target_ip, target_path, key_for_scp);
        if (rc == 0) {
            /* The kernel mirrors this line to the on-screen LOG UPLOAD row and freezes on
             * "upload complete" — keep that phrase, and say exactly where the file landed. */
            struct stat st;
            long kb = (stat(SNAPSHOT_PATH, &st) == 0) ? (long)(st.st_size / 1024) : 0;
            logf_stderr("upload complete -> %s@%s:%s (%ld KB)",
                        target_user, target_ip, target_path, kb);
            return 0;
        }
        logf_stderr("scp exited rc=%d", rc);
        nap_ms(30000);
    }
    logf_stderr("giving up after repeated scp failures");
    return 1;
}
