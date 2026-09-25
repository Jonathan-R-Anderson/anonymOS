#ifndef __MEMFORENSICS_H
#define __MEMFORENSICS_H

#include "argus.h"

/*
 * Memory forensics on anonymous executable mappings.
 *
 * On each EVENT_MEMEXEC event the module walks /proc/<pid>/maps looking for
 * anonymous executable pages, reads their content from /proc/<pid>/mem,
 * computes Shannon entropy, and optionally scans with YARA.
 *
 * High-entropy anonymous executable regions are a strong indicator of
 * shellcode, packed payloads, or reflective injection.
 */

/* Initialise the module.  Must be called once before memforensics_check(). */
void memforensics_init(void);

/*
 * Inspect anonymous executable mappings for the process described by ev.
 * Should be called whenever ev->type == EVENT_MEMEXEC.
 * Emits [MEMFORENSICS] lines to stderr and syslog on suspicious findings.
 */
void memforensics_check(const event_t *ev);

#endif /* __MEMFORENSICS_H */
