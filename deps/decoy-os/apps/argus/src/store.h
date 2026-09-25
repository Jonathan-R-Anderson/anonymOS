#ifndef __STORE_H
#define __STORE_H

#include "argus.h"

/*
 * store — Persistent SQLite event store + HTTP query API
 *
 * When HAVE_SQLITE3 is defined at compile time:
 *   store_init()    opens (or creates) a SQLite database at db_path and
 *                   optionally starts a background HTTP query server thread
 *                   on query_port (pass 0 to disable).
 *   store_event()   enqueues an event for async insertion; never blocks the
 *                   caller.
 *   store_destroy() flushes the write queue, closes the database, and joins
 *                   all background threads.
 *
 * Without HAVE_SQLITE3 all three functions compile to no-ops so the rest of
 * the codebase can call them unconditionally.
 *
 * HTTP query API (query_port > 0):
 *   GET /events?type=X&comm=Y&since=N&limit=N
 *       Returns matching events as NDJSON (one JSON object per line).
 *       Max 10 000 rows; default limit 1 000.
 *   GET /stats
 *       Returns a single JSON object:
 *       {"total_events":N,"db_size_bytes":N,"uptime_secs":N}
 *   Anything else → 404.
 */

#include <stdint.h>

#ifdef HAVE_SQLITE3

void store_init(const char *db_path, int query_port);
void store_event(const event_t *ev);
void store_destroy(void);
void store_stats(uint64_t *inserts, uint64_t *errors);

#else /* !HAVE_SQLITE3 */

static inline void store_init(const char *db_path, int query_port)
{
    (void)db_path; (void)query_port;
}
static inline void store_event(const event_t *ev)    { (void)ev; }
static inline void store_destroy(void)               {}
static inline void store_stats(uint64_t *i, uint64_t *e)
    { (void)i; (void)e; }

#endif /* HAVE_SQLITE3 */

#endif /* __STORE_H */
