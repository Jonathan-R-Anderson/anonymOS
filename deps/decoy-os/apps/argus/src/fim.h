#ifndef __FIM_H
#define __FIM_H

#include "argus.h"

/*
 * File Integrity Monitoring (FIM).
 *
 * fim_init() hashes a set of watched paths at startup.
 * fim_check() is called for each EVENT_WRITE_CLOSE event; if the event's
 * filename matches a watched path the file is re-hashed and an alert is
 * emitted to stderr if the hash changed.
 */

/* Initialise FIM with 'count' watched paths.  paths is a 2-D array of 256-byte
 * strings (same layout as argus_cfg_t.fim_paths). */
void fim_init(const char (*paths)[256], int count);

/* Check one event; on EVENT_WRITE_CLOSE re-hashes matched paths. */
void fim_check(const event_t *e);

/* Release all FIM resources. */
void fim_free(void);

#endif /* __FIM_H */
