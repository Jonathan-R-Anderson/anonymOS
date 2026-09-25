#ifndef __WEBHOOK_H
#define __WEBHOOK_H

/*
 * SOAR / webhook HTTP POST dispatcher.
 *
 * Parses a plain HTTP URL (http://host:port/path) once at startup, then
 * accepts JSON bodies from any thread via webhook_fire().  A single
 * background pthread drains a circular queue and sends each payload as an
 * HTTP/1.1 POST with Connection: close.
 *
 * Design constraints:
 *  - webhook_fire() is always non-blocking; if the queue is full the
 *    payload is silently dropped.
 *  - Each queued entry holds up to WEBHOOK_BODY_MAX bytes of JSON.
 *  - No keepalive — each POST opens a fresh TCP socket and closes it.
 *  - Only plain HTTP (no TLS) is supported.
 *
 * Typical usage:
 *   webhook_init("http://siem.corp:8080/argus/events");
 *   ...
 *   webhook_fire(json_string);   // from event handler
 *   ...
 *   webhook_destroy();           // at exit — flushes queue, joins thread
 */

/* Maximum JSON body size per queued entry (bytes). */
#define WEBHOOK_BODY_MAX   4096

/* Capacity of the internal circular queue (entries). */
#define WEBHOOK_QUEUE_SIZE 64

/*
 * Parse url and start the background dispatch thread.
 * url must be of the form http://host[:port]/path.
 * If port is omitted it defaults to 80.
 * Must be called once before webhook_fire().
 */
void webhook_init(const char *url);

/*
 * Enqueue json_body for async HTTP POST.  Non-blocking.
 * If the queue is full the payload is dropped silently.
 * json_body is copied internally; the caller may free it immediately.
 */
void webhook_fire(const char *json_body);

/*
 * Flush remaining queue entries, signal the worker thread to stop, and
 * join it.  Blocks until the thread exits.  Safe to call even if
 * webhook_init() was never called or failed.
 */
void webhook_destroy(void);

/*
 * Read current statistics (all pointers may be NULL to skip that value).
 * Thread-safe; non-blocking.
 */
void webhook_stats(uint64_t *posts, uint64_t *drops, int *queue_depth);

#endif /* __WEBHOOK_H */
