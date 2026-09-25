#ifndef __CANARY_H
#define __CANARY_H

#include "argus.h"

#define CANARY_MAX_PATHS 32

/*
 * Canary / honeypot file detection.
 *
 * Any process accessing a canary path (open, exec, write-close) triggers
 * an immediate high-severity alert regardless of other filters.  Useful
 * for placing fake credential files, decoy configs, or trap databases.
 */

void canary_init(void);

/* Register a canary path (exact match or prefix if ends with '/') */
void canary_add_path(const char *path);

/*
 * Check whether an event touches a canary path.
 * Emits a [CANARY] alert to stderr and syslog if matched.
 * Returns 1 if the event matched a canary, 0 otherwise.
 */
int canary_check(const event_t *ev);

/* Return number of registered canary paths */
int canary_count(void);

#endif /* __CANARY_H */
