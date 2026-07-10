/*
 * hos-scp-test.c -- one-command scp/upload self-test (static-musl ELF).  Run it by typing:  /scp-test
 *
 * Typing the long `LD_PRELOAD=/libnshim.so … /ssh …` lines by hand is slow and wedges the terminal, so
 * this bundles the whole end-to-end check into a single boot-module ELF (the kernel execs modules as
 * ELF only — a `#!` shell script can't be used).  It:
 *   1. makes sure wlan0 has a DHCP lease — normally the boot launcher (hos-udhcpc-launch) already holds
 *      one (so /run/wifi/dhcp-ok exists and we skip straight to the upload); if not, it starts a udhcpc
 *      and waits for the lease.
 *   2. drives dbclient (/ssh) EXACTLY like hos-log-upload — pipes a marker line to
 *      `cat > epin-scp-test.log` on bruns@192.168.1.181 under LD_PRELOAD=/libnshim.so.
 *   3. prints SUCCESS or FAILED (dbclient's own error text prints just above the verdict).
 */
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>

static void sleep_s(int s) { struct timespec t = { s, 0 }; nanosleep(&t, NULL); }
static int  have_lease(void) { return access("/run/wifi/dhcp-ok", F_OK) == 0; }

static char *const g_udhcpc_argv[] =
    { "/busybox-dyn", "udhcpc", "-i", "wlan0", "-f", "-s", "/udhcpc-script", 0 };
static char *const g_net_envp[] =
    { "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };

int main(void)
{
    fprintf(stderr, "[scp-test] checking Wi-Fi DHCP lease...\n");
    if (!have_lease()) {
        fprintf(stderr, "[scp-test] no lease yet -- starting udhcpc (also runs automatically at boot)...\n");
        pid_t u = fork();
        if (u == 0) { execve("/busybox-dyn", g_udhcpc_argv, g_net_envp); _exit(127); }
        for (int i = 0; i < 60 && !have_lease(); i++) sleep_s(1);
    }
    if (!have_lease()) {
        fprintf(stderr, "[scp-test] FAILED: Wi-Fi has no lease yet (still associating?). "
                        "Wait for the Wi-Fi indicator to show connected, then re-run /scp-test.\n");
        return 1;
    }
    fprintf(stderr, "[scp-test] lease is up. Uploading a test line to bruns@192.168.1.181 (dbclient)...\n");

    int pfd[2];
    if (pipe(pfd) != 0) { fprintf(stderr, "[scp-test] pipe() failed\n"); return 1; }

    pid_t p = fork();
    if (p == 0) {
        dup2(pfd[0], 0);
        close(pfd[0]); close(pfd[1]);
        char *const argv[] = { "/ssh", "-y", "-y", "-i", "/epin-debug-ssh-key",
                               "bruns@192.168.1.181", "cat > epin-scp-test.log", 0 };
        char *const envp[] = { "LD_PRELOAD=/libnshim.so", "LD_LIBRARY_PATH=/", "PATH=/", "HOME=/", 0 };
        execve("/ssh", argv, envp);
        _exit(127);
    }
    close(pfd[0]);
    const char *payload = "scp works from EpinAnonymOS\n";
    (void)!write(pfd[1], payload, strlen(payload));
    close(pfd[1]);                       /* EOF -> remote `cat` finishes and dbclient exits */

    int st = 0;
    waitpid(p, &st, 0);
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    if (rc == 0) {
        fprintf(stderr, "[scp-test] SUCCESS -- wrote epin-scp-test.log to bruns@192.168.1.181\n");
        fprintf(stderr, "[scp-test]   verify on that machine:  cat ~/epin-scp-test.log\n");
        return 0;
    }
    fprintf(stderr, "[scp-test] FAILED (dbclient rc=%d) -- see the /ssh error line just above.\n", rc);
    fprintf(stderr, "[scp-test]   if it mentions auth/permission, authorize the key on 192.168.1.181:\n");
    fprintf(stderr, "[scp-test]   append the bruns@Nostromo ed25519 pubkey to ~/.ssh/authorized_keys.\n");
    return 1;
}
