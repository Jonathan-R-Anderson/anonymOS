/*
 * hos-wpa-launch.c -- M5: bring up wpa_supplicant in D-Bus mode for NetworkManager (static-musl).
 *
 * NM's wifi.backend=wpa_supplicant drives the radio through wpa_supplicant's D-Bus interface
 * (fi.w1.wpa_supplicant1).  NM does not spawn wpa itself — it expects the name to be owned on the
 * system bus (either already running or D-Bus-activatable).  D-Bus activation is awkward here (the
 * activated process must inherit LD_PRELOAD=/libnshim.so so its nl80211 sockets reach the LKL), so
 * we just launch `wpa_supplicant -u` at boot under the shim.  When NM manages wlan0 it calls
 * CreateInterface over D-Bus and wpa opens nl80211 for wlan0 through the cap-gated provider.
 *
 * Boot modules land at "/", so LD_LIBRARY_PATH=/ resolves libnl-tiny.so + libdbus-1.so.3.  Logs go
 * to /run/wpa.log (dup2) so the boot-doctor can echo them, matching hos-nm-launch.
 */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void logline(const char *s){ (void)!write(2, s, strlen(s)); (void)!write(2, "\n", 1); }

int main(void)
{
    mkdir("/run", 0755);
    mkdir("/run/wpa_supplicant", 0755);

    logline("[wpa-launch] M5: exec /wpa_supplicant -u (D-Bus mode) under LD_PRELOAD=/libnshim.so");

    /* -u = D-Bus control interface (fi.w1.wpa_supplicant1); NM adds wlan0 via CreateInterface.
     * -dd = verbose debug to stderr (redirected to /run/wpa.log below).  No -i/-c: interfaces and
     * connection params arrive over D-Bus from NM. */
    char *argv[] = { "/wpa_supplicant", "-u", "-dd", 0 };
    { int lf = open("/run/wpa.log", O_CREAT|O_WRONLY|O_TRUNC, 0644);
      if (lf >= 0) { dup2(lf,1); dup2(lf,2); if (lf > 2) close(lf); } }
    /* Same system-bus address override as NM: wpa's libdbus must reach OUR dbus-daemon socket. */
    char *envp[] = { "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/",
                     "DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket", 0 };
    execve("/wpa_supplicant", argv, envp);
    logline("[wpa-launch] execve(/wpa_supplicant) FAILED (missing binary/interp/lib?)");
    return 1;
}
