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
 * Robustness: udhcpc -f normally runs forever (holds the lease + renews), so the parent just parks in
 * waitpid().  But it CAN exit early — e.g. wlan0 not yet created when it starts (SIOCGIFINDEX fails), or
 * it loses a race with another udhcpc for the DHCP socket.  So we RESTART it on exit rather than
 * one-shot exec: udhcpc -f retries DISCOVER on its own until wpa associates, and this outer loop covers
 * the cases where the process itself dies.  If fork() is unavailable we fall back to a direct exec
 * (single-shot) so we're never worse off than the plain launcher.
 */
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

static void logline(const char *s) { (void)!write(2, s, strlen(s)); (void)!write(2, "\n", 1); }
static void sleep_s(int s) { struct timespec ts = { s, 0 }; nanosleep(&ts, NULL); }

static char *const g_argv[] = { "/busybox-dyn", "udhcpc", "-i", "wlan0", "-f", "-s", "/udhcpc-script", 0 };
static char *const g_envp[] = { "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };

int main(void)
{
    /* Let the LKL create wlan0 before the first attempt (udhcpc's SIOCGIFINDEX needs it to exist; it
     * need not be associated yet — udhcpc retries the DISCOVER until wpa brings the link up). */
    sleep_s(8);

    for (;;) {
        logline("[udhcpc-launch] exec /busybox-dyn udhcpc -i wlan0 -f -s /udhcpc-script (LD_PRELOAD=/libnshim.so)");
        pid_t p = fork();
        if (p == 0) {                         /* child: become udhcpc */
            execve("/busybox-dyn", g_argv, g_envp);
            _exit(127);
        }
        if (p > 0) {                          /* parent: wait for udhcpc, restart if it dies */
            int st;
            waitpid(p, &st, 0);
            logline("[udhcpc-launch] udhcpc exited — retrying in 5s (wlan0 not up yet, or socket race)");
            sleep_s(5);
            continue;
        }
        /* fork() failed — fall back to a direct one-shot exec so we still try once. */
        logline("[udhcpc-launch] fork failed; exec'ing udhcpc directly (single-shot)");
        execve("/busybox-dyn", g_argv, g_envp);
        logline("[udhcpc-launch] execve(/busybox-dyn) FAILED (missing module/interp?)");
        return 1;
    }
}
