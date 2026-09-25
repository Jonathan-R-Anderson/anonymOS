#ifndef __METRICS_H
#define __METRICS_H

#include <stdint.h>
#include "argus.h"

/*
 * Prometheus metrics endpoint.
 *
 * Starts a background HTTP server on the configured port (default 9090).
 * Exposes argus counters in Prometheus text format at GET /metrics.
 *
 * Thread safety: all counters use __atomic builtins so they are safe to
 * increment from the main thread while the server reads them.
 *
 * Typical usage:
 *   metrics_init(9090);            // start HTTP listener
 *   ...
 *   metrics_event(e);              // in handle_event callback
 *   metrics_drop(delta);           // after each poll tick
 *   metrics_rule_hit();            // in rules_check when a rule fires
 *   metrics_anomaly();             // in baseline_check when anomaly fires
 *   metrics_fini();                // at exit
 */

/*
 * Start the metrics HTTP listener on the given TCP port.
 * Spawns one background pthread.  Returns 0 on success, -1 on error.
 * Pass port==0 to disable metrics entirely (metrics_event becomes a no-op).
 */
int  metrics_init(int port);

/* Record one event (increments per-type counter and total). */
void metrics_event(const event_t *e);

/* Add delta to the drop counter. */
void metrics_drop(uint64_t delta);

/* Increment the alert-rules-hit counter. */
void metrics_rule_hit(void);

/* Increment the baseline-anomaly counter. */
void metrics_anomaly(void);

/* Increment the forward-connection counter. */
void metrics_fwd_connect(void);

/* Shut down the listener thread (called at exit). */
void metrics_fini(void);

#endif /* __METRICS_H */
