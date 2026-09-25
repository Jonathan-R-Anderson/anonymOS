#ifndef __ISOLATE_H
#define __ISOLATE_H

/*
 * Network isolation via iptables/ip6tables.
 *
 * Adds and removes DROP rules in the INPUT and OUTPUT chains to block
 * communication with a given IP address.  All rules added during a session
 * are tracked so they can be atomically removed on exit.
 *
 * When dry_run is enabled no iptables commands are executed; actions are
 * only logged to stderr.
 */

/* 1 = log-only mode (no iptables commands executed), 0 = enforce */
void isolate_init(int dry_run);

/* Add INPUT+OUTPUT DROP rules for ip.  Returns 0 on success, -1 on error. */
int  isolate_block_ip(const char *ip);

/* Remove INPUT+OUTPUT DROP rules for ip.  Returns 0 on success, -1 on error. */
int  isolate_unblock_ip(const char *ip);

/* Remove all rules that were added during this session.  Safe to call on exit. */
void isolate_unblock_all(void);

/* Returns 1 if ip is currently blocked by this session, 0 otherwise. */
int  isolate_is_blocked(const char *ip);

#endif /* __ISOLATE_H */
