#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#ifdef __linux__
#include <bpf/bpf.h>
#endif
#include "threatintel.h"

/* ── BPF LPM key structures (must mirror argus.bpf.c definitions) ────── */

struct lpm_v4_key {
    uint32_t prefixlen;
    uint8_t  data[4];
};

struct lpm_v6_key {
    uint32_t prefixlen;
    uint8_t  data[16];
};

/* ── Userspace blocklist for offline testing ────────────────────────────── */

#define TIBL_MAX 65536

typedef struct {
    uint32_t network;   /* host byte order */
    uint32_t mask;      /* host byte order */
} tibl_v4_t;

static tibl_v4_t g_v4[TIBL_MAX];
static int       g_v4_count = 0;

/* ── helpers ─────────────────────────────────────────────────────────────── */

/* Parse "a.b.c.d/prefix" into network (NBO) + mask (NBO).
 * Returns 1 on success, 0 on failure. */
static int parse_cidr_v4(const char *s, uint32_t *net_nbo, uint32_t *mask_nbo,
                          int *prefix)
{
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (!slash)
        return 0;
    *slash = '\0';
    int plen = atoi(slash + 1);
    if (plen < 0 || plen > 32)
        return 0;

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1)
        return 0;

    *net_nbo  = addr.s_addr;   /* network byte order */
    *mask_nbo = (plen == 0) ? 0 : htonl(~((1u << (32 - plen)) - 1));
    *prefix   = plen;
    return 1;
}

/* Parse "IPv6/prefix" — we only need the raw bytes and prefix length. */
static int parse_cidr_v6(const char *s, uint8_t out_data[16], int *prefix)
{
    char buf[128];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (!slash)
        return 0;
    *slash = '\0';
    int plen = atoi(slash + 1);
    if (plen < 0 || plen > 128)
        return 0;

    struct in6_addr addr6;
    if (inet_pton(AF_INET6, buf, &addr6) != 1)
        return 0;

    memcpy(out_data, addr6.s6_addr, 16);
    *prefix = plen;
    return 1;
}

/* ── public API ──────────────────────────────────────────────────────────── */

int threatintel_load(const char *path, int map_fd_v4, int map_fd_v6)
{
    if (!path || !path[0])
        return -1;

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[256];
    int  loaded = 0;
#ifdef __linux__
    uint8_t val = 1;
#endif

    while (fgets(line, sizeof(line), f)) {
        /* Strip trailing newline / CR */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        /* Skip blank lines and comments */
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#')
            continue;

        /* Determine address family by checking for ':' (IPv6) or '.' (IPv4) */
        if (strchr(p, ':')) {
            /* IPv6 CIDR */
            uint8_t data[16];
            int     plen;
            if (!parse_cidr_v6(p, data, &plen))
                continue;

#ifdef __linux__
            if (map_fd_v6 >= 0) {
                struct lpm_v6_key k = {};
                k.prefixlen = (uint32_t)plen;
                memcpy(k.data, data, 16);
                bpf_map_update_elem(map_fd_v6, &k, &val, BPF_ANY);
            }
#else
            (void)map_fd_v6;
#endif
            loaded++;
        } else if (strchr(p, '.')) {
            /* IPv4 CIDR */
            uint32_t net_nbo, mask_nbo;
            int      plen;
            if (!parse_cidr_v4(p, &net_nbo, &mask_nbo, &plen))
                continue;

#ifdef __linux__
            if (map_fd_v4 >= 0) {
                struct lpm_v4_key k = {};
                k.prefixlen = (uint32_t)plen;
                memcpy(k.data, &net_nbo, 4);
                bpf_map_update_elem(map_fd_v4, &k, &val, BPF_ANY);
            }
#else
            (void)map_fd_v4;
#endif

            /* Store in userspace array for threatintel_check_ipv4() */
            if (g_v4_count < TIBL_MAX) {
                g_v4[g_v4_count].network = ntohl(net_nbo);
                g_v4[g_v4_count].mask    = ntohl(mask_nbo);
                g_v4_count++;
            }
            loaded++;
        }
    }

    fclose(f);
    return loaded;
}

int threatintel_check_ipv4(uint32_t addr)
{
    /* addr is expected in host byte order */
    for (int i = 0; i < g_v4_count; i++) {
        if ((addr & g_v4[i].mask) == (g_v4[i].network & g_v4[i].mask))
            return 1;
    }
    return 0;
}

void threatintel_free(void)
{
    memset(g_v4, 0, sizeof(tibl_v4_t) * (size_t)g_v4_count);
    g_v4_count = 0;
}
