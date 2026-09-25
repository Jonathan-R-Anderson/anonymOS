#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "framework.h"
#include "../src/threatintel.h"

/*
 * test_netcorr.c — unit tests for DNS correlation cache, entropy function,
 * and threatintel CIDR matching.
 *
 * The dns_cache and dns_entropy helpers are static in argus.c and not
 * separately exported.  We reproduce minimal inline versions here to
 * allow unit-testing without linking argus.c (which depends on libbpf).
 */

/* ── Inline DNS cache (mirrors argus.c implementation) ──────────────────── */

#define DNS_CACHE_SIZE 512

struct dns_cache_entry {
    uint32_t pid;
    uint8_t  ip[16];
    int      family;
    char     name[128];
    uint64_t ts;
};

static struct dns_cache_entry g_dns_cache[DNS_CACHE_SIZE];
static int                    g_dns_cache_pos = 0;

static void dns_cache_insert(uint32_t pid, const uint8_t *ip, int family,
                              const char *name)
{
    struct dns_cache_entry *ent = &g_dns_cache[g_dns_cache_pos % DNS_CACHE_SIZE];
    ent->pid    = pid;
    ent->family = family;
    memcpy(ent->ip, ip, 16);
    strncpy(ent->name, name ? name : "", sizeof(ent->name) - 1);
    ent->name[sizeof(ent->name) - 1] = '\0';
    ent->ts     = (uint64_t)time(NULL);
    g_dns_cache_pos++;
}

static const char *dns_cache_lookup(const uint8_t *ip, int family)
{
    uint64_t now = (uint64_t)time(NULL);
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        struct dns_cache_entry *ent = &g_dns_cache[i];
        if (!ent->name[0])
            continue;
        if (ent->family != family)
            continue;
        if (now - ent->ts > 60)
            continue;
        int addrlen = (family == 2) ? 4 : 16;
        if (memcmp(ent->ip, ip, addrlen) == 0)
            return ent->name;
    }
    return NULL;
}

/* ── Inline entropy function (mirrors argus.c implementation) ───────────── */

static double dns_entropy(const char *s)
{
    if (!s || !s[0])
        return 0.0;

    int freq[256] = {};
    int len = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        freq[(int)*p]++;
        len++;
    }
    if (len == 0)
        return 0.0;

    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0)
            continue;
        double p = (double)freq[i] / (double)len;
        double lp = __builtin_log(1.0 / p) / 0.693147180559945;
        h += p * lp;
    }
    return h;
}

/* ── tests ──────────────────────────────────────────────────────────────── */

/* test_dns_cache_hit: insert DNS entry, connect to same IP → lookup hits */
static void test_dns_cache_hit(void)
{
    uint8_t ip[16] = { 93, 184, 216, 34 };   /* example.com */
    dns_cache_insert(1234, ip, 2 /* AF_INET */, "example.com");

    const char *result = dns_cache_lookup(ip, 2);
    ASSERT_TRUE(result != NULL);
    if (result)
        ASSERT_STR_EQ(result, "example.com");
}

/* test_dns_cache_miss: IP not in cache → lookup returns NULL */
static void test_dns_cache_miss(void)
{
    uint8_t ip[16] = { 8, 8, 8, 8 };   /* not inserted */
    const char *result = dns_cache_lookup(ip, 2);
    ASSERT_NULL(result);
}

/* test_entropy_high: high-entropy label returns > 3.5 */
static void test_entropy_high(void)
{
    /* "xn--a9q3c7fjkp2" is a Punycode IDN with high character diversity */
    double h = dns_entropy("xn--a9q3c7fjkp2");
    ASSERT_TRUE(h > 3.5);
}

/* test_entropy_low: "google" is low-entropy */
static void test_entropy_low(void)
{
    double h = dns_entropy("google");
    ASSERT_TRUE(h < 3.5);
}

/* test_entropy_empty: empty string returns 0 */
static void test_entropy_empty(void)
{
    double h = dns_entropy("");
    ASSERT_EQ((int)(h * 1000), 0);
}

/* test_threatintel_check: verify userspace CIDR check works */
static void test_threatintel_check(void)
{
    /* Write a temporary blocklist file */
    const char *tmpfile = "/tmp/argus_ti_test.txt";
    FILE *f = fopen(tmpfile, "w");
    if (!f) { fprintf(stderr, "SKIP: cannot write tmpfile\n"); return; }
    fputs("# test blocklist\n", f);
    fputs("1.2.3.0/24\n", f);
    fputs("10.0.0.0/8\n", f);
    fclose(f);

    int n = threatintel_load(tmpfile, -1, -1);
    ASSERT_TRUE(n >= 2);

    /* 1.2.3.100 is in 1.2.3.0/24 (host byte order) */
    uint32_t in_range = (1u << 24) | (2u << 16) | (3u << 8) | 100u;
    ASSERT_EQ(threatintel_check_ipv4(in_range), 1);

    /* 1.2.4.1 is NOT in 1.2.3.0/24 */
    uint32_t out_range = (1u << 24) | (2u << 16) | (4u << 8) | 1u;
    ASSERT_EQ(threatintel_check_ipv4(out_range), 0);

    /* 10.20.30.40 is in 10.0.0.0/8 */
    uint32_t in_class_a = (10u << 24) | (20u << 16) | (30u << 8) | 40u;
    ASSERT_EQ(threatintel_check_ipv4(in_class_a), 1);

    threatintel_free();
    remove(tmpfile);
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void)
{
    test_dns_cache_hit();
    test_dns_cache_miss();
    test_entropy_high();
    test_entropy_low();
    test_entropy_empty();
    test_threatintel_check();

    TEST_SUMMARY();
}
