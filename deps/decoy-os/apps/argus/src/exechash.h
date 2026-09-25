#ifndef __EXECHASH_H
#define __EXECHASH_H

#include <stddef.h>
#include "argus.h"

/*
 * SHA-256 file hash enrichment for EXEC events.
 *
 * On each EVENT_EXEC, exechash_check() resolves the executable path via
 * /proc/<pid>/exe, computes a SHA-256 digest, and caches the result in a
 * 256-slot LRU cache keyed by (inode, mtime) to avoid re-hashing the same
 * binary repeatedly.  The hash is printed to stderr and optionally submitted
 * to the VirusTotal Files API for reputation lookup.
 *
 * Build requirements:
 *   - SHA-256 and VT HTTPS require OpenSSL.  Compile with -DHAVE_OPENSSL and
 *     link with -lssl -lcrypto.  Without HAVE_OPENSSL the module is a no-op
 *     beyond a one-time warning printed by exechash_init().
 *
 * Thread safety:
 *   - exechash_check() is safe to call from one thread at a time (the argus
 *     main event loop); the VT worker thread operates on a separate queue
 *     protected by its own mutex.
 *
 * Typical usage:
 *   exechash_init(NULL);               // no VT lookup
 *   exechash_init(getenv("VT_KEY"));   // with VT
 *   ...
 *   exechash_check(ev);                // in handle_event for EVENT_EXEC
 *   const char *h = exechash_get_cached(ev->pid);
 */

/*
 * Initialise the module.  vt_api_key may be NULL to disable VirusTotal
 * lookups.  Safe to call multiple times; only the first call has effect.
 */
void exechash_init(const char *vt_api_key);

/*
 * Compute the SHA-256 digest of the file at path.
 * On success writes a 64-character lower-case hex string + NUL to hex_out
 * (caller must supply a buffer of at least 65 bytes) and returns 0.
 * Returns -1 on any error (file not found, OpenSSL unavailable, etc.).
 */
int exechash_file(const char *path, char hex_out[65]);

/*
 * Hash-enrich an EXEC event.
 * Resolves /proc/<pid>/exe, looks up the (inode, mtime) in the LRU cache,
 * computes the hash on miss, prints a [HASH] line to stderr, and
 * optionally enqueues an async VT lookup if a key was provided.
 * Does nothing for non-EXEC events or if the module was not initialised.
 */
void exechash_check(const event_t *ev);

/*
 * Return the cached SHA-256 hex string for the most recent EXEC by pid,
 * or NULL if the pid is not in the cache.
 */
const char *exechash_get_cached(int pid);

#endif /* __EXECHASH_H */
