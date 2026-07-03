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
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void logline(const char *s){ (void)!write(2, s, strlen(s)); (void)!write(2, "\n", 1); }
static void writefile(const char *path, const char *data){
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) { (void)!write(fd, data, strlen(data)); close(fd); }
}

int main(void)
{
    mkdir("/etc", 0755);            mkdir("/etc/NetworkManager", 0755);
    mkdir("/etc/NetworkManager/system-connections", 0700);
    mkdir("/etc/NetworkManager/conf.d", 0755);
    mkdir("/var", 0755);           mkdir("/var/lib", 0755);
    mkdir("/var/lib/NetworkManager", 0755);
    mkdir("/run", 0755);           mkdir("/run/NetworkManager", 0755);

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
    char *argv[] = { "/NetworkManager", "--no-daemon", "--log-level=DEBUG", "--log-domains=ALL", 0 };
    /* NM's gio GDBus connects to its compiled-in default system-bus path (often /var/run/dbus/...);
     * our dbus-daemon listens on /run/dbus/system_bus_socket, so point NM there explicitly or it
     * never connects -> never owns org.freedesktop.NetworkManager. */
    char *envp[] = { "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/",
                     "DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket",
                     "HOS_SHIM_LOG=1", 0 };
    execve("/NetworkManager", argv, envp);
    logline("[nm-launch] execve(/NetworkManager) FAILED (missing binary/interp/lib?)");
    return 1;
}
