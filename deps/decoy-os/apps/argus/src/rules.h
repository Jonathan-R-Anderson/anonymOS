#ifndef __RULES_H
#define __RULES_H

#include "argus.h"

/*
 * Alert rule engine.
 *
 * Rules are loaded from a JSON file (--rules / "rules" config key).
 * Each rule specifies match criteria; matching events emit alert lines
 * in the active output format (text → stderr, JSON → event stream, syslog).
 *
 * Rule JSON format (array of rule objects):
 *
 *   [
 *     {
 *       "name":          "World-writable chmod",   // required
 *       "severity":      "high",                   // info|low|medium|high|critical
 *       "type":          "CHMOD",                  // event type; omit = match all
 *       "comm":          "",                        // exact comm; "" = any
 *       "uid":           -1,                        // exact uid; -1 = any
 *       "path_contains": "",                        // substring of filename; "" = any
 *       "mode_mask":     2,                         // CHMOD: flag if (mode & mask) != 0
 *       "message":       "{comm} chmod {filename} to 0{mode}"
 *     }
 *   ]
 *
 * Message template variables (replaced at alert time):
 *   {comm} {pid} {ppid} {uid} {gid} {cgroup}
 *   {filename} {args} {new_path} {mode}
 *   {target_pid} {ptrace_req}
 *   {daddr} {dport} {laddr} {lport}
 */

/* Load rules from a JSON file; returns number of rules loaded, or < 0 on error */
int  rules_load(const char *path);

/*
 * Check event against all loaded rules; emit alerts for each match.
 * Output format (text/JSON/syslog) is read from output_get_fmt().
 * Safe to call with zero rules loaded.
 */
void rules_check(const event_t *e);

/* Returns the number of currently loaded rules */
int  rules_count(void);

/* Unload all rules */
void rules_free(void);

/*
 * Pass the file descriptor of the kill_list BPF hash map.
 * When a rule with action="kill" matches, the event's PID is written into
 * this map so the BPF program can send SIGKILL on the next syscall.
 * Call after BPF attach. fd=-1 disables the feature (default).
 */
void rules_set_kill_fd(int fd);

#endif /* __RULES_H */
