/*
 * hos-udhcpc-launch.c -- kernel-spawned launcher for the external DHCP client (static-musl).
 *
 * NM's in-process n-dhcp4 stalls before ever sending a DISCOVER (its nested epoll+timerfd never fires
 * here), so EpinAnonymOS gets its lease from a standalone busybox udhcpc — proven working: it
 * completes DISCOVER→OFFER→REQUEST→ACK through the LKL/AX210 and obtains a real lease.
 *
 * The wifi-agent used to fork()+execve this, but fork() from the agent produced a dead child here.  So
 * the kernel spawns THIS launcher instead (like hos-wpa-launch).  We run the DYNAMIC busybox under
 * LD_PRELOAD=/libnshim.so so udhcpc's AF_PACKET/rtnetlink are routed to the LKL that owns wlan0.
 *
 * Do not fork here.  On this kernel fork() can return a child PID while the child never progresses,
 * leaving the parent parked in waitpid forever and NM stuck in ip-config.  Wait for wlan0 to exist,
 * then directly exec foreground udhcpc; without -n, udhcpc retries DISCOVER until association and
 * subsequently remains alive to renew the lease.
 */
#include <unistd.h>
#include <string.h>
#include <poll.h>

static void logline(const char *s) { (void)!write(2, s, strlen(s)); (void)!write(2, "\n", 1); }
/* Kernel-spawned services can lose a nanosleep wakeup on this OS.  That left
 * this launcher asleep before its first exec while WPA completed and NM sat in
 * ip-config forever.  poll() timeout wakeups are proven by the Wi-Fi agent and
 * Wayland clients. */
static void sleep_s(int s) {
    int ms = s * 1000;
    while (ms > 0) {
        int chunk = ms > 60000 ? 60000 : ms;
        int rc = poll(NULL, 0, chunk);
        if (rc == 0) ms -= chunk;
        else if (rc < 0) continue;
        else break;
    }
}

static char *const g_argv[] = { "/busybox-dyn", "udhcpc", "-i", "wlan0", "-f", "-s", "/udhcpc-script", 0 };
static char *const g_envp[] = { "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };

int main(void)
{
    while (access("/sys/class/net/wlan0", F_OK) != 0) sleep_s(1);
    logline("[udhcpc-launch] wlan0 exists; exec /busybox-dyn udhcpc -i wlan0 -f -s /udhcpc-script");
    execve("/busybox-dyn", g_argv, g_envp);
    logline("[udhcpc-launch] execve(/busybox-dyn) FAILED (missing module/interp?)");
    return 1;
}
