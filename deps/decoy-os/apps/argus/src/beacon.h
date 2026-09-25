#ifndef __BEACON_H
#define __BEACON_H

#include "argus.h"

/*
 * C2 beaconing detection.
 *
 * Tracks outbound CONNECT events per (PID, dest-IP, dest-port) tuple.
 * When at least BEACON_MIN_SAMPLES connections to the same destination
 * have been observed, computes the coefficient of variation (CV) of the
 * inter-arrival intervals.  A low CV means the connections are highly
 * regular — a hallmark of malware beaconing.
 *
 * Alert threshold:  CV < beacon_cv_threshold  (default 0.15)
 * Minimum samples:  BEACON_MIN_SAMPLES        (5)
 * Observation window: BEACON_WINDOW_SECS      (300 s)
 */

#define BEACON_MIN_SAMPLES   5
#define BEACON_WINDOW_SECS   300   /* discard connections older than 5 min */
#define BEACON_MAX_ENTRIES   1024  /* max tracked (pid, dest) pairs          */

/* Initialise the beacon detector.
 * cv_threshold: coefficient-of-variation threshold below which an alert
 *   fires (0.0 = very strict, 1.0 = very permissive).  0 disables. */
void beacon_init(double cv_threshold);

/*
 * Record a CONNECT event and check for beaconing.
 * Emits a [BEACON] alert to stderr if suspicious.
 * Returns 1 if beaconing detected, 0 otherwise.
 */
int beacon_check(const event_t *ev);

#endif /* __BEACON_H */
