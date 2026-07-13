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
 * Initial config: if /epin-debug-net.conf carries wifi_ssid (+wifi_psk) we pre-seed that network so the
 * box auto-associates at boot; otherwise a bare config (no network) — wpa idles until the user picks a
 * network in the menu (agent rewrites the config + SIGHUP).  ctrl_interface is intentionally omitted:
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

int main(void)
{
    mkdir("/run", 0755);
    mkdir("/run/wpa_supplicant", 0755);

    char *const envp[] = { "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };

    /* wpa's verbose debug -> /run/wpa.log (matches the boot-doctor / Logs-app expectation). */
    { int lf = open("/run/wpa.log", O_CREAT|O_WRONLY|O_TRUNC, 0644);
      if (lf >= 0) { dup2(lf,1); dup2(lf,2); if (lf > 2) close(lf); } }

    /* Seed the runtime config ONCE if the agent hasn't already written one (survives a relaunch). */
    if (access(WPA_CONF, F_OK) != 0) {
        char ssid[128] = {0}, psk[128] = {0};
        int have = (read_cred("wifi_ssid", ssid, sizeof ssid) && ssid[0]);
        if (have) read_cred("wifi_psk", psk, sizeof psk);
        int cf = open(WPA_CONF, O_CREAT|O_WRONLY|O_TRUNC, 0600);
        if (cf >= 0) {
            /* wpa_config_read() TERMINATES the whole wpa_supplicant process on ANY config it rejects,
             * and maybeSpawnWpa is one-shot — so a malformed seeded ssid/psk would kill Wi-Fi for the
             * session.  Guard exactly what wpa enforces: SSID 1..32 bytes; a WPA passphrase 8..63
             * chars (written QUOTED).  A 64-char raw PMK would need to be UNQUOTED, which we don't
             * emit here, so we do NOT accept plen==64 (quoting it => "too long passphrase" => reject).
             * Anything outside these bounds falls back to a bare no-network config (user picks in the
             * menu) rather than a config wpa would reject. */
            size_t slen = strlen(ssid), plen = strlen(psk);
            int ssid_ok = (slen >= 1 && slen <= 32);
            int psk_ok  = (plen >= 8 && plen <= 63);
            char cfg[512]; int m;
            if (have && ssid_ok && psk[0] && psk_ok)
                m = snprintf(cfg, sizeof cfg,
                    "update_config=0\nap_scan=1\nnetwork={\n\tssid=\"%s\"\n\tpsk=\"%s\"\n\tkey_mgmt=WPA-PSK\n\tscan_ssid=1\n}\n",
                    ssid, psk);
            else if (have && ssid_ok && !psk[0])
                m = snprintf(cfg, sizeof cfg,
                    "update_config=0\nap_scan=1\nnetwork={\n\tssid=\"%s\"\n\tkey_mgmt=NONE\n\tscan_ssid=1\n}\n",
                    ssid);   /* open network */
            else
                m = snprintf(cfg, sizeof cfg, "update_config=0\nap_scan=1\n");   /* bare: user picks in the menu */
            if (m > 0) (void)!write(cf, cfg, (size_t)m);
            close(cf);
        }
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
