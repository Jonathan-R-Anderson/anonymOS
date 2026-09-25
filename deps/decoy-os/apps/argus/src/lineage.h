#ifndef __LINEAGE_H
#define __LINEAGE_H

#include <stdint.h>

/*
 * Userspace process ancestry cache.
 *
 * Maintains a pid→{ppid,comm} hash table updated on every EXEC/EXIT event.
 * lineage_str() walks the parent chain and returns a human-readable string
 * like "systemd→sshd→bash" representing the ancestry of a process.
 *
 * The cache is best-effort: processes that were already running when argus
 * started won't be in the table until they exec again. lineage_str() emits
 * as much of the chain as it can and stops when a parent isn't found.
 */

/*
 * Walk /proc at startup and pre-populate the cache with every running process.
 * Fixes the cold-start problem where all lineage shows "?" until processes
 * re-exec. Safe to call before the BPF programs attach.
 */
void lineage_scan_proc(void);

/* Register a new process (call on EVENT_EXEC, before printing the event) */
void lineage_update(uint32_t pid, uint32_t ppid, const char *comm);

/* Remove a process from the cache (call on EVENT_EXIT, after printing) */
void lineage_remove(uint32_t pid);

/*
 * Build the ancestry string for a process whose parent is 'ppid'.
 * Writes "ancestor→...→parent" into buf (NUL-terminated, never overflows).
 * Returns buf so it can be used inline in printf calls.
 */
char *lineage_str(uint32_t ppid, char *buf, size_t len);

/* Returns the comm of the immediate parent of ppid, or empty string if not found */
void lineage_parent_comm(uint32_t ppid, char *out, size_t outsz);

/* Returns 1 if any ancestor in the ppid chain has comm matching target_comm */
int lineage_has_ancestor(uint32_t ppid, const char *target_comm);

#endif /* __LINEAGE_H */
