/*
 * hos-udhcpc-launch.c -- kernel-spawned launcher for the external DHCP client (static-musl).
 *
 * NM's in-process n-dhcp4 stalls before ever sending a DISCOVER (its nested epoll+timerfd never fires
 * here), so EpinAnonymOS gets its lease from a standalone busybox udhcpc — proven working: it
 * completes DISCOVER→OFFER→REQUEST→ACK through the LKL/AX210 and obtains a real lease.
 *
 * The wifi-agent used to fork()+execve this, but fork() from the agent produced a dead child here.  So
 * the kernel spawns THIS launcher instead (like hos-wpa-launch), and it execve()s udhcpc directly — no
 * fork.  We exec the DYNAMIC busybox under LD_PRELOAD=/libnshim.so so udhcpc's AF_PACKET/rtnetlink are
 * routed to the LKL that owns wlan0.  udhcpc -f retries DISCOVER indefinitely, so it can start as soon
 * as wlan0 EXISTS (a short settle covers LKL bringing it up) and simply leases once wpa associates.
 */
#include <unistd.h>
#include <string.h>
#include <time.h>

static void logline(const char *s) { (void)!write(2, s, strlen(s)); (void)!write(2, "\n", 1); }

int main(void)
{
    /* Let the LKL create wlan0 (udhcpc's SIOCGIFINDEX needs it to exist; it need not be associated yet,
     * udhcpc will retry the DISCOVER until wpa brings the link up). */
    struct timespec ts = { 8, 0 };
    nanosleep(&ts, NULL);

    logline("[udhcpc-launch] exec /busybox-dyn udhcpc -i wlan0 -f -s /udhcpc-script (LD_PRELOAD=/libnshim.so)");
    char *argv[] = { "/busybox-dyn", "udhcpc", "-i", "wlan0", "-f", "-s", "/udhcpc-script", 0 };
    char *envp[] = { "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };
    execve("/busybox-dyn", argv, envp);
    logline("[udhcpc-launch] execve(/busybox-dyn) FAILED (missing module/interp?)");
    return 1;
}
