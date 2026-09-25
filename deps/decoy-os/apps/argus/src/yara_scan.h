#ifndef __YARA_SCAN_H
#define __YARA_SCAN_H

#include "argus.h"

/*
 * YARA rule scanning — compiled in only when HAVE_YARA is defined.
 *
 * Scans file content against a directory of .yar rule files on:
 *   - EVENT_EXEC       → scan /proc/<pid>/exe
 *   - EVENT_WRITE_CLOSE → scan the written file
 *   - EVENT_KMOD_LOAD  → scan the module file
 *
 * Emits a [YARA] alert to stderr and syslog on any match.
 *
 * When built without libyara (no HAVE_YARA) all functions are no-ops.
 */

/*
 * Load all .yar files from rules_dir.
 * Returns 0 on success, -1 on error.
 * No-op when HAVE_YARA is not defined.
 */
int yara_scan_init(const char *rules_dir);

/*
 * Scan the file relevant to ev.
 * Returns number of YARA rules that matched (0 = clean), -1 = scan error.
 * No-op (returns 0) when HAVE_YARA is not defined.
 */
int yara_scan_event(const event_t *ev);

/* Free compiler and rules; safe to call even if init was never called. */
void yara_scan_fini(void);

/* Returns 1 if libyara support was compiled in, 0 otherwise. */
int yara_scan_available(void);

#endif /* __YARA_SCAN_H */
