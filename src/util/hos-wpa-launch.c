/*
 * hos-wpa-launch.c -- bring up wpa_supplicant (static-musl), DIRECT mode (no NetworkManager, no D-Bus).
 *
 * The Wi-Fi menu is driven by hos-wpa-agent, which manages the runtime config /run/wpa-net.conf and
 * SIGHUPs wpa to associate.  So wpa is launched in `-c` mode against that shared config with a pidfile
 * (`-P /run/wpa.pid`) the agent reads to signal it.  This removes NetworkManager (the daemon that hung
 * at `platform-linux: create`, never registered its D-Bus name, and churned dbus/nmcli -> Weston
 * starvation) from the path entirely: wpa associates on its own in a few seconds, the kernel-supervised
 * udhcpc leases, and the menu reads scan results from the LKL provider (NSP_SCAN) via hos-wpa-agent.
 *
 * Initial config is always bare so nl80211 and its provider sockets initialize before any expensive
 * credential processing.  Credentials from /epin-debug-net.conf (or a config recovered after an
 * unexpected wpa exit) are queued for the agent, which applies them after wpa marks itself ready.
 * ctrl_interface is intentionally omitted:
 * it is an AF_UNIX SOCK_DGRAM socket and this kernel implements AF_UNIX SOCK_STREAM only, so requesting
 * it makes wpa fail "Failed to add interface wlan0" and tear the radio down.  Boot modules land at "/",
 * so LD_LIBRARY_PATH=/ resolves libnl-tiny.so etc.  Logs -> /run/wpa.log.
 */
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define WPA_CONF "/run/wpa-net.conf"
#define WPA_READY "/run/wpa-ready"
#define CONNECT_F "/run/wifi/connect"
#define CONNECT_TMP "/run/wifi/connect.tmp"

static void logline(const char *s){ (void)!write(2, s, strlen(s)); (void)!write(2, "\n", 1); }

/* pull wifi_ssid / wifi_psk out of /epin-debug-net.conf (key=value, one per line) */
static int read_cred(const char *key, char *out, size_t outsz)
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
            return 1;
        }
        line = nl ? nl + 1 : 0;
    }
    return 0;
}

/* Recover credentials written by hos-wpa-agent before an unexpected supplicant restart.  The agent
 * emits a deliberately small format, so no general wpa configuration parser is needed here. */
static int read_saved_cred(char *ssid, size_t ssz, char *psk, size_t psz)
{
    int fd = open(WPA_CONF, O_RDONLY);
    if (fd < 0) return 0;
    char b[1024]; int n = (int)read(fd, b, sizeof b - 1); close(fd);
    if (n <= 0) return 0;
    b[n] = 0;
    char *s = strstr(b, "ssid=\"");
    if (!s) return 0;
    s += 6; char *se = strchr(s, '"');
    if (!se || se == s || (size_t)(se - s) >= ssz) return 0;
    memcpy(ssid, s, (size_t)(se - s)); ssid[se - s] = 0;

    char *p = strstr(b, "psk=\"");
    if (p) {
        p += 5; char *pe = strchr(p, '"');
        if (!pe || (size_t)(pe - p) >= psz) return 0;
        memcpy(psk, p, (size_t)(pe - p)); psk[pe - p] = 0;
    } else if ((p = strstr(b, "psk=")) != NULL) {
        p += 4; char *pe = strchr(p, '\n'); if (!pe) pe = p + strlen(p);
        if ((size_t)(pe - p) >= psz) return 0;
        memcpy(psk, p, (size_t)(pe - p)); psk[pe - p] = 0;
    }
    return 1;
}

static int queue_connect(const char *ssid, const char *psk)
{
    char req[300];
    int n = snprintf(req, sizeof req, "%s\n%s\n", ssid, psk);
    if (n <= 0 || n >= (int)sizeof req) return 0;
    int fd = open(CONNECT_TMP, O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (fd < 0) return 0;
    int wrote = (int)write(fd, req, (size_t)n); close(fd);
    if (wrote != n || rename(CONNECT_TMP, CONNECT_F) != 0) {
        unlink(CONNECT_TMP);
        return 0;
    }
    return 1;
}

int main(void)
{
    mkdir("/run", 0755);
    mkdir("/run/wpa_supplicant", 0755);
    mkdir("/run/wifi", 0755);
    unlink(WPA_READY); /* a stale marker must never permit SIGHUP before this instance is ready */

    /* Keep shim diagnostics on: these travel through the provider's NSP_LOG channel and expose the
     * exact routed socket/ioctl where nl80211 initialization stops.  Resolve the interposer eagerly;
     * lazy binding on the first socket call can re-enter musl's loader while the shim is resolving
     * RTLD_NEXT symbols on this minimal pthread/futex implementation. */
    char *const envp[] = { "LD_PRELOAD=/libnshim.so", "LD_BIND_NOW=1", "HOS_SHIM_LOG=1",
                           "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };

    /* wpa's verbose debug -> /run/wpa.log (matches the boot-doctor / Logs-app expectation). */
    { int lf = open("/run/wpa.log", O_CREAT|O_WRONLY|O_TRUNC, 0644);
      if (lf >= 0) { dup2(lf,1); dup2(lf,2); if (lf > 2) close(lf); } }

    /* Always initialize nl80211 with a BARE config.  Parsing a passphrase runs PBKDF2 before driver
     * setup; on this cooperative kernel that ordering can leave the first provider socket starved.
     * Preserve an agent-written config across a supervised relaunch, otherwise use debug boot creds,
     * but queue either for the agent to apply only after wpa publishes WPA_READY. */
    char ssid[128] = {0}, psk[128] = {0};
    int have = read_saved_cred(ssid, sizeof ssid, psk, sizeof psk);
    if (!have) {
        have = (read_cred("wifi_ssid", ssid, sizeof ssid) && ssid[0]);
        if (have) read_cred("wifi_psk", psk, sizeof psk);
    }
    int cf = open(WPA_CONF, O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (cf >= 0) {
        static const char bare[] = "update_config=0\nap_scan=1\n";
        (void)!write(cf, bare, sizeof bare - 1);
        close(cf);
    }
    if (have) {
        size_t slen = strlen(ssid), plen = strlen(psk);
        int valid = slen >= 1 && slen <= 32 &&
                    (plen == 0 || (plen >= 8 && plen <= 63) || plen == 64);
        if (valid && queue_connect(ssid, psk))
            logline("[wpa-launch] credentials queued until nl80211 is ready");
        else
            logline("[wpa-launch] ignored invalid or unqueueable boot credentials");
    }

    /* wpa runs in the FOREGROUND (no -B: -B forks, and this kernel kills fork children), and a
     * foreground wpa never writes a -P pidfile.  So WE write it: execve() preserves our pid, so
     * getpid() here IS the pid wpa will run under — which hos-wpa-agent reads to SIGHUP wpa (reload
     * config -> associate) on a menu connect.  Without this the connect path is a silent no-op. */
    { char pb[24]; int m = snprintf(pb, sizeof pb, "%d\n", (int)getpid());
      int pf = open("/run/wpa.pid", O_CREAT|O_WRONLY|O_TRUNC, 0644);
      if (pf >= 0) { if (m > 0) (void)!write(pf, pb, (size_t)m); close(pf); } }
    logline("[wpa-launch] exec /wpa_supplicant -c " WPA_CONF " -i wlan0 -D nl80211 (direct, NM-less; pid -> /run/wpa.pid)");
    char *argv[] = { "/wpa_supplicant", "-i", "wlan0", "-c", WPA_CONF, "-D", "nl80211", "-dd", 0 };
    execve("/wpa_supplicant", argv, envp);
    logline("[wpa-launch] execve(/wpa_supplicant) FAILED (missing binary/interp/lib?)");
    return 1;
}
