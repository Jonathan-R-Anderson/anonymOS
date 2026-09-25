#ifndef __DNS_H
#define __DNS_H

#include <stdint.h>
#include <stddef.h>

/*
 * Reverse-resolve a network address to a hostname.
 *
 *   addr   — 4 bytes (AF_INET) or 16 bytes (AF_INET6) in network byte order
 *   family — AF_INET (2) or AF_INET6 (10)
 *   out    — caller-supplied buffer to receive the NUL-terminated result
 *   outsz  — size of out in bytes
 *
 * On success the buffer is filled with the resolved hostname (or the
 * dotted-decimal / colon-hex address when resolution fails) and 0 is
 * returned.  Returns -1 for invalid arguments.
 *
 * Results are cached in a 512-entry table for DNS_TTL_SECS (300) seconds so
 * getnameinfo() is only called once per unique address per TTL window.
 */
int  dns_lookup(const uint8_t *addr, int family, char *out, size_t outsz);

/* Flush and free all cache entries (call at shutdown). */
void dns_free(void);

#endif /* __DNS_H */
