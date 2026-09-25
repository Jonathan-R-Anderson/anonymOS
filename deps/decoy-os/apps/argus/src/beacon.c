#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <syslog.h>
#include <arpa/inet.h>
#include "beacon.h"
#include "argus.h"

/* Circular buffer of up to BEACON_MIN_SAMPLES*4 timestamps per entry */
#define BEACON_TS_MAX 20

typedef struct {
    int      pid;
    uint8_t  daddr[16];
    uint8_t  family;
    uint16_t dport;
    char     comm[16];
    time_t   ts[BEACON_TS_MAX];  /* ring buffer of connection times */
    int      ts_count;
    int      ts_head;
    int      alerted;            /* 1 = already fired for this entry */
    time_t   last_used;
} beacon_entry_t;

static beacon_entry_t g_entries[BEACON_MAX_ENTRIES];
static double         g_cv_threshold = 0.0;

void beacon_init(double cv_threshold)
{
    g_cv_threshold = cv_threshold;
    memset(g_entries, 0, sizeof(g_entries));
}

static beacon_entry_t *find_or_alloc(const event_t *ev)
{
    time_t now = time(NULL);
    int    oldest_idx = 0;
    time_t oldest_ts  = now;
    int    addrlen    = (ev->family == 2) ? 4 : 16;

    for (int i = 0; i < BEACON_MAX_ENTRIES; i++) {
        beacon_entry_t *e = &g_entries[i];
        if (!e->pid) {
            e->pid = ev->pid;
            memcpy(e->daddr, ev->daddr, 16);
            e->family    = ev->family;
            e->dport     = ev->dport;
            e->ts_count  = 0;
            e->ts_head   = 0;
            e->alerted   = 0;
            e->last_used = now;
            strncpy(e->comm, ev->comm, sizeof(e->comm) - 1);
            return e;
        }
        if (e->pid == ev->pid &&
            e->dport == ev->dport &&
            e->family == ev->family &&
            memcmp(e->daddr, ev->daddr, addrlen) == 0)
            return e;

        if (e->last_used < oldest_ts) {
            oldest_ts  = e->last_used;
            oldest_idx = i;
        }
    }

    /* Evict least-recently-used */
    beacon_entry_t *e = &g_entries[oldest_idx];
    memset(e, 0, sizeof(*e));
    e->pid = ev->pid;
    memcpy(e->daddr, ev->daddr, 16);
    e->family    = ev->family;
    e->dport     = ev->dport;
    e->last_used = now;
    strncpy(e->comm, ev->comm, sizeof(e->comm) - 1);
    return e;
}

/* Compute mean and coefficient of variation of inter-arrival times.
 * Returns 1 if enough samples and CV < threshold. */
static int is_beaconing(beacon_entry_t *e)
{
    /* Collect valid timestamps within the observation window */
    time_t now = time(NULL);
    time_t valid[BEACON_TS_MAX];
    int    n = 0;

    for (int i = 0; i < e->ts_count && i < BEACON_TS_MAX; i++) {
        int idx = (e->ts_head - e->ts_count + i + BEACON_TS_MAX) % BEACON_TS_MAX;
        if (now - e->ts[idx] <= BEACON_WINDOW_SECS)
            valid[n++] = e->ts[idx];
    }

    if (n < BEACON_MIN_SAMPLES)
        return 0;

    /* Sort timestamps for interval computation */
    for (int i = 0; i < n - 1; i++)
        for (int j = i + 1; j < n; j++)
            if (valid[j] < valid[i]) {
                time_t tmp = valid[i]; valid[i] = valid[j]; valid[j] = tmp;
            }

    /* Compute inter-arrival intervals */
    double intervals[BEACON_TS_MAX];
    int    m = n - 1;
    double sum = 0.0;
    for (int i = 0; i < m; i++) {
        intervals[i] = (double)(valid[i + 1] - valid[i]);
        sum += intervals[i];
    }
    if (m < 1 || sum < 1.0)
        return 0;

    double mean = sum / m;
    if (mean < 1.0)
        return 0;

    double var = 0.0;
    for (int i = 0; i < m; i++) {
        double d = intervals[i] - mean;
        var += d * d;
    }
    double stddev = sqrt(var / m);
    double cv     = stddev / mean;

    return cv < g_cv_threshold ? 1 : 0;
}

int beacon_check(const event_t *ev)
{
    if (g_cv_threshold <= 0.0)
        return 0;
    if (ev->type != EVENT_CONNECT)
        return 0;

    beacon_entry_t *e = find_or_alloc(ev);
    if (!e)
        return 0;

    /* Record timestamp */
    e->ts[e->ts_head] = time(NULL);
    e->ts_head        = (e->ts_head + 1) % BEACON_TS_MAX;
    if (e->ts_count < BEACON_TS_MAX)
        e->ts_count++;
    e->last_used = time(NULL);

    if (e->alerted)
        return 0;   /* only alert once per (pid, dest) pair */

    if (!is_beaconing(e))
        return 0;

    e->alerted = 1;

    char ip_str[INET6_ADDRSTRLEN] = {};
    if (ev->family == 2)
        inet_ntop(AF_INET,  ev->daddr,      ip_str, sizeof(ip_str));
    else
        inet_ntop(AF_INET6, ev->daddr,      ip_str, sizeof(ip_str));

    fprintf(stderr,
        "[BEACON] pid=%-6d comm=%-16s periodic connections to %s:%u "
        "(>=%d conns, CV<%.2f)\n",
        ev->pid, ev->comm, ip_str, ev->dport,
        BEACON_MIN_SAMPLES, g_cv_threshold);
    syslog(LOG_WARNING,
        "BEACON pid=%d comm=%s periodic connections to %s:%u",
        ev->pid, ev->comm, ip_str, ev->dport);
    return 1;
}
