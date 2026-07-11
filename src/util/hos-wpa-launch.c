/*
 * hos-wpa-launch.c -- bring up wpa_supplicant (static-musl).
 *
 * HEADLESS DEBUG BOOTS (/epin-debug-fast-net.conf present): drive wpa_supplicant DIRECTLY from a generated config
 * (`-c /wpa-direct.conf` with a network={ssid,psk} block) instead of `-u` (D-Bus/NetworkManager) mode.
 * This is the single biggest speed win for "boot -> associated -> lease -> scp": it removes the whole
 * daemon ladder (NetworkManager taking ~11s just to own its bus name, then wpa idling until NM calls
 * SelectNetwork over D-Bus) from the critical path.  wpa associates on its own in ~3-8s, so an UNSTABLE
 * box that crashes fast still gets onto WiFi and scp's its log in time.  Because wpa in -c mode does NOT
 * expose the fi.w1.wpa_supplicant1 D-Bus name, NetworkManager simply can't manage wifi and leaves wlan0
 * to us -- no conflict.  NORMAL boots (no debug-net.conf): keep -u (D-Bus) mode for the interactive menu.
 *
 * Boot modules land at "/", so LD_LIBRARY_PATH=/ resolves libnl-tiny.so etc.  Logs -> /run/wpa.log.
 */
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

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

    char *const envp[] = { "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/",
                           "DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket", 0 };

    /* wpa's verbose debug -> /run/wpa.log (matches the boot-doctor's expectation). */
    { int lf = open("/run/wpa.log", O_CREAT|O_WRONLY|O_TRUNC, 0644);
      if (lf >= 0) { dup2(lf,1); dup2(lf,2); if (lf > 2) close(lf); } }

    char ssid[128] = {0}, psk[128] = {0};
    if (access("/epin-debug-fast-net.conf", F_OK) == 0 &&
        read_cred("wifi_ssid", ssid, sizeof ssid) && read_cred("wifi_psk", psk, sizeof psk) && ssid[0]) {
        /* DEBUG FAST PATH: write a direct config and drive the radio without NM. */
        int cf = open("/wpa-direct.conf", O_CREAT|O_WRONLY|O_TRUNC, 0644);
        if (cf >= 0) {
            /* NO ctrl_interface: it is an AF_UNIX SOCK_DGRAM socket, and this kernel's AF_UNIX
             * implements only SOCK_STREAM -> socket(PF_UNIX,SOCK_DGRAM) returns EPROTONOSUPPORT,
             * which makes wpa fail "Failed to add interface wlan0" and tear the radio back down.
             * The debug fast-path drives the radio purely from this config (no wpa_cli consumer:
             * udhcpc + log-upload are independent), so wpa associates headlessly without it. */
            char cfg[512];
            int m = snprintf(cfg, sizeof cfg,
                "update_config=0\nap_scan=1\n"
                "network={\n\tssid=\"%s\"\n\tpsk=\"%s\"\n\tkey_mgmt=WPA-PSK\n\tscan_ssid=1\n}\n",
                ssid, psk);
            if (m > 0) (void)!write(cf, cfg, (size_t)m);
            close(cf);
            logline("[wpa-launch] DEBUG fast path: exec /wpa_supplicant -c /wpa-direct.conf -i wlan0 (NM-less direct associate)");
            char *argv[] = { "/wpa_supplicant", "-i", "wlan0", "-c", "/wpa-direct.conf", "-D", "nl80211", "-dd", 0 };
            execve("/wpa_supplicant", argv, envp);
            logline("[wpa-launch] execve(/wpa_supplicant -c) FAILED (missing binary/interp/lib?)");
            return 1;
        }
    }

    /* NORMAL boot: D-Bus mode for NetworkManager (interactive menu). */
    logline("[wpa-launch] exec /wpa_supplicant -u (D-Bus mode) under LD_PRELOAD=/libnshim.so");
    char *argv[] = { "/wpa_supplicant", "-u", "-dd", 0 };
    execve("/wpa_supplicant", argv, envp);
    logline("[wpa-launch] execve(/wpa_supplicant) FAILED (missing binary/interp/lib?)");
    return 1;
}
