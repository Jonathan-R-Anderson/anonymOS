#ifndef __HOLLOW_H
#define __HOLLOW_H

#include "argus.h"

/*
 * Process hollowing detection.
 *
 * On every EVENT_EXEC, compares the /proc/<pid>/exe symlink (the real
 * binary on disk) against the first executable mapping in /proc/<pid>/maps.
 * A mismatch indicates the process image was replaced after exec — a
 * hallmark of process hollowing / RunPE style injection.
 *
 * Also detects memfd-backed execution: when /proc/<pid>/exe resolves to
 * a "memfd:" or "(deleted)" path the real binary never existed on disk.
 */

/*
 * Check a freshly-executed event for hollowing indicators.
 * Emits a [HOLLOW] alert to stderr if suspicious.
 * Returns 1 if hollowing detected, 0 otherwise.
 */
int hollow_check(const event_t *ev);

#endif /* __HOLLOW_H */
