#ifndef __BASELINE_H
#define __BASELINE_H

#include "argus.h"

/*
 * Baseline / anomaly detection module.
 *
 * Two modes:
 *
 *   Learning  — call baseline_learn_init(out_path, secs) at startup, then
 *               feed every event through baseline_learn(e).  When the
 *               learning window expires, baseline_flush() writes a JSON
 *               profile to out_path.  baseline_learning() returns 1 while
 *               the window is open.
 *
 *   Detection — call baseline_load(path) at startup, then feed every event
 *               through baseline_check(e).  Anomalous events cause an alert
 *               to be emitted via the current output channel and return 1.
 *
 * Profile JSON schema (one object per comm):
 *   {
 *     "version": 1,
 *     "comms": {
 *       "<comm>": {
 *         "exec_targets":   ["<filename>", ...],
 *         "connect_dests":  ["<addr>:<port>", ...],
 *         "open_paths":     ["<filename>", ...]
 *       }
 *     }
 *   }
 */

/*
 * Initialise learning mode.  Events should be fed via baseline_learn() for
 * at most 'secs' seconds; then baseline_flush() writes the profile to
 * 'out_path' and the module enters an idle state.
 * Returns 0 on success, -1 on error.
 */
int  baseline_learn_init(const char *out_path, int secs);

/* Feed one event into the learnt profile (learning mode only). */
void baseline_learn(const event_t *e);

/* Returns 1 if currently in the active learning window, 0 otherwise. */
int  baseline_learning(void);

/*
 * Close the learning window early and write the profile to the path supplied
 * to baseline_learn_init().  No-op if not in learning mode.
 */
void baseline_flush(void);

/*
 * Load a profile from 'path' and enter detection mode.
 * Returns the number of per-comm profiles loaded (>= 0), or -1 on error.
 */
int  baseline_load(const char *path);

/*
 * Check one event against the loaded profile.
 * Emits an alert and returns 1 if the event is anomalous.
 * Returns 0 when the event is within the learnt baseline or detection mode
 * is not active.
 */
int  baseline_check(const event_t *e);

/* Free all baseline resources (learning data and loaded profile). */
void baseline_free(void);

/*
 * Enable rolling merge: after an anomalous value is seen N times it is
 * automatically added to the profile without emitting an anomaly alert.
 * Call before baseline_load().  n=0 disables (default).
 */
void baseline_set_merge_after(int n);

/*
 * Enable cgroup-aware profiling: the profile key becomes "cgroup/comm"
 * instead of just "comm", so containers with the same process name are
 * profiled independently.  Call before baseline_load() / baseline_learn_init().
 * v=1 enables, v=0 disables (default).
 */
void baseline_set_cgroup_aware(int v);

#endif /* __BASELINE_H */
