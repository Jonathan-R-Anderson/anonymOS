#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <syslog.h>
#include <arpa/inet.h>
#include "isolate.h"

#define ISOLATE_MAX_IPS  64

/* iptables moved from /sbin to /usr/sbin on modern distros; probe both */
static const char *iptables_path(void)
{
    static const char *candidates[] = {
        "/usr/sbin/iptables", "/sbin/iptables", NULL
    };
    for (int i = 0; candidates[i]; i++)
        if (access(candidates[i], X_OK) == 0)
            return candidates[i];
    return "/usr/sbin/iptables"; /* fallback; execv will fail with ENOENT */
}

static const char *ip6tables_path(void)
{
    static const char *candidates[] = {
        "/usr/sbin/ip6tables", "/sbin/ip6tables", NULL
    };
    for (int i = 0; candidates[i]; i++)
        if (access(candidates[i], X_OK) == 0)
            return candidates[i];
    return "/usr/sbin/ip6tables";
}

static int  g_dry_run = 0;
static char g_blocked[ISOLATE_MAX_IPS][64];
static int  g_blocked_count = 0;

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

/* Return 1 if the address string contains ':' (IPv6), 0 for IPv4. */
static int is_ipv6(const char *ip)
{
    return strchr(ip, ':') != NULL;
}

/*
 * Fork + execv the given argv[] and wait for the child.
 * argv[0] must be the full path to the binary.
 * Returns the child exit status, or -1 on fork/exec failure.
 */
static int run_iptables(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("isolate: fork");
        return -1;
    }
    if (pid == 0) {
        /* Child: redirect stdout/stderr to /dev/null to suppress iptables chatter */
        int devnull = open("/dev/null", 0 /* O_RDONLY */);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("isolate: waitpid");
        return -1;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

/*
 * Apply (add or remove) INPUT and OUTPUT rules for ip.
 * op is "-I" (insert) or "-D" (delete).
 * Returns 0 if both rules succeed, -1 on any failure.
 */
static int apply_rules(const char *op, const char *ip)
{
    const char *ipt = is_ipv6(ip) ? ip6tables_path() : iptables_path();
    int rc = 0;

    /* OUTPUT rule: block packets to the address */
    char *out_argv[] = {
        (char *)ipt,
        (char *)op,   "OUTPUT",
        "-d", (char *)ip,
        "-j", "DROP",
        NULL
    };
    if (run_iptables(out_argv) != 0)
        rc = -1;

    /* INPUT rule: block packets from the address */
    char *in_argv[] = {
        (char *)ipt,
        (char *)op,   "INPUT",
        "-s", (char *)ip,
        "-j", "DROP",
        NULL
    };
    if (run_iptables(in_argv) != 0)
        rc = -1;

    return rc;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

void isolate_init(int dry_run)
{
    g_dry_run      = dry_run;
    g_blocked_count = 0;
    memset(g_blocked, 0, sizeof(g_blocked));
}

int isolate_block_ip(const char *ip)
{
    if (!ip || !ip[0])
        return -1;

    /* Validate the address is well-formed */
    struct in6_addr addr6;
    struct in_addr  addr4;
    int ipv6 = is_ipv6(ip);
    if (ipv6) {
        if (inet_pton(AF_INET6, ip, &addr6) != 1) {
            fprintf(stderr, "[ISOLATE] invalid IPv6 address: %s\n", ip);
            return -1;
        }
    } else {
        if (inet_pton(AF_INET, ip, &addr4) != 1) {
            fprintf(stderr, "[ISOLATE] invalid IPv4 address: %s\n", ip);
            return -1;
        }
    }

    /* Already tracked? */
    if (isolate_is_blocked(ip))
        return 0;

    if (g_blocked_count >= ISOLATE_MAX_IPS) {
        fprintf(stderr, "[ISOLATE] block table full, cannot block ip=%s\n", ip);
        return -1;
    }

    if (g_dry_run) {
        fprintf(stderr, "[ISOLATE-DRY] would block ip=%s\n", ip);
        /* Still track it so is_blocked() works in dry-run tests */
        strncpy(g_blocked[g_blocked_count], ip, 63);
        g_blocked[g_blocked_count][63] = '\0';
        g_blocked_count++;
        return 0;
    }

    int rc = apply_rules("-I", ip);
    if (rc != 0) {
        fprintf(stderr, "[ISOLATE] failed to block ip=%s (iptables returned error)\n", ip);
        return -1;
    }

    strncpy(g_blocked[g_blocked_count], ip, 63);
    g_blocked[g_blocked_count][63] = '\0';
    g_blocked_count++;

    fprintf(stderr, "[ISOLATE] blocked ip=%s\n", ip);
    syslog(LOG_WARNING, "ISOLATE blocked ip=%s", ip);
    return 0;
}

int isolate_unblock_ip(const char *ip)
{
    if (!ip || !ip[0])
        return -1;

    /* Find the entry */
    int found = -1;
    for (int i = 0; i < g_blocked_count; i++) {
        if (strcmp(g_blocked[i], ip) == 0) {
            found = i;
            break;
        }
    }
    if (found < 0)
        return -1;   /* not tracked by us */

    if (g_dry_run) {
        fprintf(stderr, "[ISOLATE-DRY] would unblock ip=%s\n", ip);
    } else {
        int rc = apply_rules("-D", ip);
        if (rc != 0) {
            fprintf(stderr, "[ISOLATE] failed to unblock ip=%s\n", ip);
            /* Still remove from tracking to avoid repeated failed attempts */
        }
        fprintf(stderr, "[ISOLATE] unblocked ip=%s\n", ip);
    }

    /* Remove from tracking array (swap with last entry) */
    if (found < g_blocked_count - 1) {
        strncpy(g_blocked[found], g_blocked[g_blocked_count - 1], 63);
        g_blocked[found][63] = '\0';
    }
    memset(g_blocked[g_blocked_count - 1], 0, 64);
    g_blocked_count--;
    return 0;
}

void isolate_unblock_all(void)
{
    /* Iterate backwards so removal does not skip entries */
    for (int i = g_blocked_count - 1; i >= 0; i--) {
        if (g_dry_run) {
            fprintf(stderr, "[ISOLATE-DRY] would unblock ip=%s\n", g_blocked[i]);
        } else {
            apply_rules("-D", g_blocked[i]);
            fprintf(stderr, "[ISOLATE] unblocked ip=%s\n", g_blocked[i]);
        }
        memset(g_blocked[i], 0, 64);
    }
    g_blocked_count = 0;
}

int isolate_is_blocked(const char *ip)
{
    if (!ip || !ip[0])
        return 0;
    for (int i = 0; i < g_blocked_count; i++) {
        if (strcmp(g_blocked[i], ip) == 0)
            return 1;
    }
    return 0;
}
