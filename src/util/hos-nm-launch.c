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
    char *argv[] = { "/NetworkManager", "--no-daemon", "--debug", "--log-level=DEBUG",
                     "--log-domains=CORE,PLATFORM,DEVICE,WIFI,SUPPLICANT", 0 };
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
