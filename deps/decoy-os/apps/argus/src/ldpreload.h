#ifndef __LDPRELOAD_H
#define __LDPRELOAD_H

#include "argus.h"

/*
 * LD_PRELOAD / suspicious environment variable detector.
 *
 * On EVENT_EXEC, ldpreload_check() opens /proc/<pid>/environ, scans for
 * LD_PRELOAD, LD_LIBRARY_PATH, and PYTHONPATH, and emits an alert to stderr
 * for each one found.
 */
void ldpreload_check(const event_t *e);

#endif /* __LDPRELOAD_H */
