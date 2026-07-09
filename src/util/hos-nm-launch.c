/*
 * hos-nm-launch.c -- M2b: bring up the REAL NetworkManager daemon (static-musl launcher).
 *
 * Kernel-spawned after (a) the system dbus-daemon is listening and (b) the LKL cap-gated net-provider
 * socket is up.  Writes NM's config + runtime dirs, then execve()s /NetworkManager under
 * LD_PRELOAD=/libnshim.so so NM's rtnetlink / nl80211 / packet sockets are transparently routed to the
 * LKL (which owns the real Wi-Fi device via the L4 device-cap).  NM owns org.freedesktop.NetworkManager
 * on the system bus; nmcli / the GUI drive it from there.
 *
 * Boot modules land at "/", so LD_LIBRARY_PATH=/ resolves libnm/libndp.  Logs -> fd 2 -> serial.log.
 */
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>

static void logline(const char *s){ (void)!write(2, s, strlen(s)); (void)!write(2, "\n", 1); }
static void writefile(const char *path, const char *data){
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) { (void)!write(fd, data, strlen(data)); close(fd); }
}
static void writefile_mode(const char *path, const char *data, mode_t mode){
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd >= 0) { (void)!write(fd, data, strlen(data)); close(fd); chmod(path, mode); }
}
static char *trim(char *s){
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) *--e = 0;
    return s;
}
static int config_value(const char *key, char *out, size_t outsz){
    out[0] = 0;
    int fd = open("/epin-debug-net.conf", O_RDONLY);
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
static void install_debug_wifi_profile(void){
    char ssid[128], psk[128];
    if (!config_value("wifi_ssid", ssid, sizeof ssid)) return;
    if (!config_value("wifi_psk", psk, sizeof psk)) return;

    char profile[1024];
    int n = snprintf(profile, sizeof profile,
        "[connection]\n"
        "id=%s\n"
        "uuid=7ef2cf3d-0f22-4db8-9c6a-2e18a30f5c40\n"
        "type=wifi\n"
        "autoconnect=true\n"
        "autoconnect-retries=0\n"
        "\n"
        "[wifi]\n"
        "mode=infrastructure\n"
        "ssid=%s\n"
        "\n"
        "[wifi-security]\n"
        "key-mgmt=wpa-psk\n"
        "psk=%s\n"
        "\n"
        "[ipv4]\n"
        "method=auto\n"
        "\n"
        "[ipv6]\n"
        "method=ignore\n"
        "\n"
        "[proxy]\n",
        ssid, ssid, psk);
    if (n <= 0 || n >= (int)sizeof profile) {
        logline("[nm-launch] debug wifi profile skipped: config too long");
        return;
    }
    /* IMPORTANT: /etc on EpinAnonymOS is a SYNTHETIC filesystem — NM can read a file there by path,
     * but its keyfile plugin's opendir()/getdents() enumerates nothing, so a profile dropped in
     * /etc/NetworkManager/system-connections is never LOADED (the device just scans forever and never
     * autoconnects).  /var/run is a writable+LISTABLE rtfs overlay, and NM's keyfile plugin ALSO reads
     * NM_KEYFILE_PATH_NAME_RUN (= NMRUNDIR "/system-connections" = /var/run/NetworkManager/
     * system-connections) at startup — so write the autoconnect profile THERE, where NM enumerates it.
     * NM then auto-activates it with its INTERNAL (root) subject, which sidesteps the D-Bus caller-UID
     * authorization ("Unable to determine UID of the request") that blocks an external
     * AddAndActivateConnection from the wifi-agent here. */
    mkdir("/var", 0755);
    mkdir("/var/run", 0755);
    mkdir("/var/run/NetworkManager", 0755);
    mkdir("/var/run/NetworkManager/system-connections", 0700);
    writefile_mode("/var/run/NetworkManager/system-connections/debug-wifi.nmconnection", profile, 0600);
    /* Also drop it in /etc — harmless, and it loads too if /etc ever becomes enumerable. */
    writefile_mode("/etc/NetworkManager/system-connections/debug-wifi.nmconnection", profile, 0600);
    logline("[nm-launch] installed debug Wi-Fi autoconnect profile (/var/run + /etc) from /epin-debug-net.conf");
}
/* Copy src -> dst (for placing the wifi device plugin at NMPLUGINDIR). */
static int copyfile(const char *src, const char *dst){
    int in = open(src, O_RDONLY); if (in < 0) return -1;
    int out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0755); if (out < 0){ close(in); return -1; }
    static char buf[65536]; long r; int ok = 0;
    while ((r = read(in, buf, sizeof buf)) > 0) { if (write(out, buf, r) != r){ ok = -1; break; } }
    close(in); close(out); return ok;
}

int main(void)
{
    mkdir("/etc", 0755);            mkdir("/etc/NetworkManager", 0755);
    mkdir("/etc/NetworkManager/system-connections", 0700);
    mkdir("/etc/NetworkManager/conf.d", 0755);
    mkdir("/var", 0755);           mkdir("/var/lib", 0755);
    mkdir("/var/lib/NetworkManager", 0755);
    mkdir("/run", 0755);           mkdir("/run/NetworkManager", 0755);
    install_debug_wifi_profile();

    /* NM dlopens its device plugins (incl. wifi!) from NMPLUGINDIR=/usr/lib/NetworkManager/1.44.2.
     * We do NOT copy the plugin there (copying creates a shadowing rtfs node): the KERNEL synthesizes
     * that dir's getdents to list the wifi plugin and rewrites its .so path to the boot module
     * /libnm-device-plugin-wifi.so.  Just verify the listing works. */
    { DIR *d = opendir("/usr/lib/NetworkManager/1.44.2");
      if (!d) logline("[nm-launch] NMPLUGINDIR-readdir: opendir FAILED");
      else { struct dirent *e; int n = 0;
             while ((e = readdir(d))) { if (e->d_name[0]=='.') continue;
                 logline("[nm-launch] NMPLUGINDIR entry:"); logline(e->d_name); n++; }
             if (!n) logline("[nm-launch] NMPLUGINDIR-readdir: EMPTY (kernel synth not working)");
             closedir(d); } }

    /* keyfile settings plugin (persist connections under system-connections), internal DHCP,
     * wpa_supplicant Wi-Fi backend.  no-auto-default keeps NM from auto-connecting wired at boot. */
    const char *conf =
        "[main]\n"
        "plugins=keyfile\n"
        "dhcp=internal\n"
        "no-auto-default=*\n"
        "[device]\n"
        "wifi.backend=wpa_supplicant\n"
        "[logging]\n"
        "level=DEBUG\n"
        "domains=ALL\n";
    writefile("/etc/NetworkManager/NetworkManager.conf", conf);

    logline("[nm-launch] M2b: exec /NetworkManager --no-daemon under LD_PRELOAD=/libnshim.so");
    /* M3 diag: focus the log on device discovery/classification (why wlan0 is/ isn't managed as wifi) and
     * REDIRECT NM's stdout+stderr to /run/nm.log so the boot-doctor can echo it to the serial (NM's own
     * stderr does not reach the console here). */
    /* --debug sets debug_stderr (nm-logging.c:1015) so NM ALSO writes its log to STDERR — which we
     * redirect to /run/nm.log below.  Without it NM logs only to syslog (/dev/log, absent) = discarded. */
    /* Include SETTINGS+AGENTS so nm.log shows keyfile profile loading (did debug-wifi.nmconnection
     * get read?) and the autoconnect/secrets decision — the CORE list alone hides all of that. */
    char *argv[] = { "/NetworkManager", "--no-daemon", "--debug", "--log-level=DEBUG",
                     "--log-domains=CORE,PLATFORM,DEVICE,WIFI,WIFI_SCAN,SUPPLICANT,SETTINGS,AGENTS", 0 };
    { int lf = open("/run/nm.log", O_CREAT|O_WRONLY|O_TRUNC, 0644);
      if (lf >= 0) { dup2(lf,1); dup2(lf,2); if (lf > 2) close(lf); } }
    /* NM's gio GDBus connects to its compiled-in default system-bus path (often /var/run/dbus/...);
     * our dbus-daemon listens on /run/dbus/system_bus_socket, so point NM there explicitly or it
     * never connects -> never owns org.freedesktop.NetworkManager. */
    /* HOS_SHIM_LOG intentionally OFF: shim_log() opens a fresh provider connection per call, and the
     * provider spawns a per-connection thread that leaks its task slot on exit (no thread reaper) — under
     * NM's sustained real-HW netlink activity that churns provider threads over time.  With the netlink
     * hang fixed we no longer need the trace; keep the shim silent so it adds no provider load. */
    /* LD_BIND_NOW=1: resolve the wifi plugin's symbols EAGERLY at g_module_open so an unresolved symbol
     * fails the load LOUDLY (NM logs "failed to load plugin: <symbol>") instead of lazily/ silently. */
    char *envp[] = { "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", "LD_BIND_NOW=1",
                     "DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket", 0 };
    execve("/NetworkManager", argv, envp);
    logline("[nm-launch] execve(/NetworkManager) FAILED (missing binary/interp/lib?)");
    return 1;
}
