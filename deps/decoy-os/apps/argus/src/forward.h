#ifndef __FORWARD_H
#define __FORWARD_H

#include <stdint.h>
#include "argus.h"

/*
 * TCP event forwarding — multi-target with optional TLS.
 *
 * Up to FORWARD_MAX_TARGETS destinations can be active simultaneously.
 * Each target maintains its own connection state and reconnect backoff.
 *
 * Reliability:
 *   - Connections are non-blocking; unreachable remotes defer with
 *     exponential backoff (1 s → 2 s → … → 30 s).
 *   - MSG_DONTWAIT sends; full send buffer counts as a drop.
 *   - Accumulated drops are reported as {"type":"DROP","count":N} on
 *     reconnect.
 *   - TLS is transparent to callers; enable per-target via FORWARD_FLAG_TLS.
 *
 * Typical usage:
 *   forward_add("siem.corp", 9000, 0);                   // plain TCP
 *   forward_add("backup.corp", 9000, FORWARD_FLAG_TLS);  // TLS + verify
 *   ...
 *   forward_event(e);        // in handle_event callback
 *   forward_drops(delta);    // after each poll tick
 *   forward_tick();          // once per poll tick (~100 ms)
 *   forward_clear();         // at exit
 */

/* Maximum simultaneous forwarding targets */
#define FORWARD_MAX_TARGETS 8

/* Per-target connection flags */
#define FORWARD_FLAG_TLS          0x1   /* encrypt with TLS                         */
#define FORWARD_FLAG_TLS_NOVERIFY 0x3   /* TLS without certificate verification     */
                                        /* (implies FORWARD_FLAG_TLS: bit 0x1 set)  */

/*
 * Parse "host:port" or "[ipv6addr]:port" into separate host/port.
 * Returns 0 on success, -1 on malformed input.
 */
int forward_parse_addr(const char *s, char *host_out, size_t hostsz,
                       int *port_out);

/*
 * Add a forwarding target.  Can be called up to FORWARD_MAX_TARGETS times.
 * flags: 0                       = plain TCP
 *        FORWARD_FLAG_TLS        = TLS with system-CA certificate verification
 *        FORWARD_FLAG_TLS_NOVERIFY = TLS without cert verification
 * Returns 0 if arguments are valid, -1 otherwise.
 */
int  forward_add(const char *host, int port, int flags);

/*
 * Convenience wrapper: clear all targets then add one plain-TCP target.
 * Equivalent to forward_clear() + forward_add(host, port, 0).
 */
int  forward_init(const char *host, int port);

/*
 * Format event as JSON and send to all active forward targets.
 * Non-blocking — drops silently when any connection is down or buffer full.
 */
void forward_event(const event_t *e);

/* Send {"type":"DROP","count":N} to all connected targets. */
void forward_drops(uint64_t count);

/*
 * Call once per poll loop tick (~100 ms).
 * Drives reconnect attempts for any disconnected targets.
 */
void forward_tick(void);

/* Returns 1 if at least one target is currently connected, 0 otherwise. */
int  forward_connected(void);

/* Flush pending drop reports, close all sockets, free TLS resources. */
void forward_fini(void);

/* Remove all targets (calls forward_fini internally). */
void forward_clear(void);

#endif /* __FORWARD_H */
