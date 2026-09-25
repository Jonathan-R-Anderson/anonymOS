#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "dns.h"

#define DNS_CACHE_SIZE  512
#define DNS_TTL_SECS    300

typedef struct {
    uint8_t  addr[16];    /* address in network byte order                  */
    int      family;      /* AF_INET or AF_INET6; 0 = slot unused           */
    char     name[256];   /* resolved hostname (or dotted-decimal fallback) */
    time_t   expires;     /* unix timestamp after which the entry is stale  */
} dns_entry_t;

static dns_entry_t g_cache[DNS_CACHE_SIZE];

static int addr_bytes(int family)
{
    return (family == AF_INET) ? 4 : 16;
}

/* Simple hash: mix address bytes with the family constant. */
static unsigned int hash_addr(const uint8_t *addr, int family)
{
    unsigned int h = (unsigned int)family * 2654435761u;
    int len = addr_bytes(family);
    for (int i = 0; i < len; i++)
        h = h * 31u + addr[i];
    return h % DNS_CACHE_SIZE;
}

int dns_lookup(const uint8_t *addr, int family, char *out, size_t outsz)
{
    if (!addr || !out || outsz == 0)
        return -1;
    if (family != AF_INET && family != AF_INET6)
        return -1;

    unsigned int slot = hash_addr(addr, family);
    int          len  = addr_bytes(family);
    time_t       now  = time(NULL);

    /* Cache hit? */
    if (g_cache[slot].family == family &&
        memcmp(g_cache[slot].addr, addr, (size_t)len) == 0 &&
        g_cache[slot].expires > now) {
        snprintf(out, outsz, "%s", g_cache[slot].name);
        return 0;
    }

    /* Resolve via getnameinfo() — may block briefly for uncached addresses */
    char resolved[256] = {};
    struct sockaddr_storage ss;
    socklen_t sslen;

    memset(&ss, 0, sizeof(ss));
    if (family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr, addr, 4);
        sslen = sizeof(*sin);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        memcpy(&sin6->sin6_addr, addr, 16);
        sslen = sizeof(*sin6);
    }

    if (getnameinfo((struct sockaddr *)&ss, sslen,
                    resolved, sizeof(resolved),
                    NULL, 0, NI_NAMEREQD) != 0) {
        /* Fall back to presentation form */
        inet_ntop(family, addr, resolved, sizeof(resolved));
    }

    /* Store in cache */
    g_cache[slot].family  = family;
    memcpy(g_cache[slot].addr, addr, (size_t)len);
    snprintf(g_cache[slot].name, sizeof(g_cache[slot].name), "%s", resolved);
    g_cache[slot].expires = now + DNS_TTL_SECS;

    snprintf(out, outsz, "%s", resolved);
    return 0;
}

void dns_free(void)
{
    memset(g_cache, 0, sizeof(g_cache));
}
