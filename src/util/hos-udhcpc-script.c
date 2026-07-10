/*
 * hos-udhcpc-script.c -- udhcpc lease-event handler for EpinAnonymOS (static-musl ELF).
 *
 * busybox udhcpc runs `-s <script> <action>` with the lease in the environment ($interface/$ip/
 * $subnet/$router).  A shell script can't be used: this kernel's execve resolves boot modules and
 * loads them as ELF only (no `#!` shebang support), so the "script" MUST be an ELF.  On a bound/renew
 * we fork the DYNAMIC busybox (busybox-dyn) to apply the address + default route — busybox does the
 * real ioctl/rtnetlink, and because it is dynamic it inherits LD_PRELOAD=/libnshim.so, so every op is
 * routed to the LKL that owns wlan0 (this whole external-DHCP path exists because NM's in-process
 * n-dhcp4 stalls before ever sending a DISCOVER).  Finally we touch /run/wifi/dhcp-ok, which the
 * wifi-agent turns into device state=100 so the log-uploader + menu see the link as up.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* busybox-dyn is dynamic → LD_PRELOAD makes its sockets/ioctls reach the LKL-owned wlan0. */
static char *const g_envp[] = {
    "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", (char *)0
};

static void run(char *const argv[])
{
    pid_t p = fork();
    if (p == 0) { execve(argv[0], argv, g_envp); _exit(127); }
    if (p > 0) { int st; waitpid(p, &st, 0); }
}

int main(int argc, char **argv)
{
    const char *action = (argc > 1) ? argv[1] : "";
    if (strcmp(action, "bound") != 0 && strcmp(action, "renew") != 0)
        return 0;  /* deconfig/leasefail: leave the link alone (NM/wpa own association) */

    char *ip = getenv("ip");
    if (!ip || !ip[0]) return 0;
    char *ifn = getenv("interface");  if (!ifn || !ifn[0]) ifn = "wlan0";
    char *subnet = getenv("subnet");  if (!subnet || !subnet[0]) subnet = "255.255.255.0";
    char *router = getenv("router");

    { char *a[] = { "/busybox-dyn", "ifconfig", ifn, ip, "netmask", subnet, "up", 0 }; run(a); }

    if (router && router[0]) {
        char first[64];  /* $router may be a space-separated list; use the first */
        size_t i = 0;
        for (; router[i] && router[i] != ' ' && i < sizeof first - 1; i++) first[i] = router[i];
        first[i] = 0;
        /* NB: NO "dev <ifn>" — busybox route puts the device NAME in rtentry.rt_dev as a POINTER, which
         * doesn't survive the shim's ioctl RPC (the LKL derefs a client-side pointer → SIOCADDRT ENODEV
         * "No such device").  Without it, the LKL picks the interface from the gateway's subnet. */
        { char *a[] = { "/busybox-dyn", "route", "add", "default", "gw", first, 0 }; run(a); }
    }

    /* Ensure /run/wifi exists: on debug-net boots the wifi-agent (which normally creates it) is
     * gated off, so without this the marker open() fails ENOENT -> /scp-test + the log-uploader
     * both think there is no lease even though the link is fully up. */
    mkdir("/run", 0755);
    mkdir("/run/wifi", 0755);
    int f = open("/run/wifi/dhcp-ok", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (f >= 0) { (void)!write(f, ip, strlen(ip)); (void)!write(f, "\n", 1); close(f); }
    fprintf(stderr, "[udhcpc-script] %s: applied %s/%s gw '%s' on %s\n",
            action, ip, subnet, router ? router : "", ifn);
    return 0;
}
