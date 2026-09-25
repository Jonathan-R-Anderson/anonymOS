#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "metrics.h"
#include "argus.h"
#include "webhook.h"
#include "iocenrich.h"
#include "store.h"

/* ── atomic counters ─────────────────────────────────────────────────────── */

static _Atomic uint64_t g_events_total;
static _Atomic uint64_t g_events_by_type[EVENT_TYPE_MAX];
static _Atomic uint64_t g_drops;
static _Atomic uint64_t g_rule_hits;
static _Atomic uint64_t g_anomalies;
static _Atomic uint64_t g_fwd_connects;

/* ── server state ────────────────────────────────────────────────────────── */

static int        g_port       = 0;
static int        g_listen_fd  = -1;
static pthread_t  g_thread;
static volatile int g_running  = 0;

/* ── counter increment helpers ───────────────────────────────────────────── */

void metrics_event(const event_t *e)
{
    if (!g_port) return;
    atomic_fetch_add(&g_events_total, 1);
    if (e && e->type < EVENT_TYPE_MAX)
        atomic_fetch_add(&g_events_by_type[e->type], 1);
}

void metrics_drop(uint64_t delta)
{
    if (!g_port || !delta) return;
    atomic_fetch_add(&g_drops, delta);
}

void metrics_rule_hit(void)
{
    if (!g_port) return;
    atomic_fetch_add(&g_rule_hits, 1);
}

void metrics_anomaly(void)
{
    if (!g_port) return;
    atomic_fetch_add(&g_anomalies, 1);
}

void metrics_fwd_connect(void)
{
    if (!g_port) return;
    atomic_fetch_add(&g_fwd_connects, 1);
}

/* ── HTTP response helpers ───────────────────────────────────────────────── */

static const char *type_label[] = {
    [EVENT_EXEC]        = "exec",
    [EVENT_OPEN]        = "open",
    [EVENT_EXIT]        = "exit",
    [EVENT_CONNECT]     = "connect",
    [EVENT_UNLINK]      = "unlink",
    [EVENT_RENAME]      = "rename",
    [EVENT_CHMOD]       = "chmod",
    [EVENT_BIND]        = "bind",
    [EVENT_PTRACE]      = "ptrace",
    [EVENT_DNS]         = "dns",
    [EVENT_SEND]        = "send",
    [EVENT_WRITE_CLOSE] = "write_close",
};

/*
 * Write Prometheus text format to the connected client socket.
 * We use a temporary FILE* backed by the socket fd for fprintf convenience.
 */
static void write_metrics(int cfd)
{
    FILE *f = fdopen(dup(cfd), "w");
    if (!f) return;

    /* HTTP/1.0 minimal response */
    fputs("HTTP/1.0 200 OK\r\n"
          "Content-Type: text/plain; version=0.0.4\r\n"
          "Connection: close\r\n"
          "\r\n", f);

    /* Total events */
    fprintf(f, "# HELP argus_events_total Total events observed by argus\n"
               "# TYPE argus_events_total counter\n"
               "argus_events_total %llu\n",
            (unsigned long long)atomic_load(&g_events_total));

    /* Per-type events */
    fprintf(f, "# HELP argus_events_by_type Events observed per type\n"
               "# TYPE argus_events_by_type counter\n");
    for (int i = 0; i < EVENT_TYPE_MAX; i++) {
        uint64_t v = atomic_load(&g_events_by_type[i]);
        if (i < (int)(sizeof(type_label)/sizeof(type_label[0])) && type_label[i])
            fprintf(f, "argus_events_by_type{type=\"%s\"} %llu\n",
                    type_label[i], (unsigned long long)v);
    }

    /* Drops */
    fprintf(f, "# HELP argus_drops_total Ring-buffer events dropped\n"
               "# TYPE argus_drops_total counter\n"
               "argus_drops_total %llu\n",
            (unsigned long long)atomic_load(&g_drops));

    /* Alert rule hits */
    fprintf(f, "# HELP argus_rule_hits_total Alert rules matched\n"
               "# TYPE argus_rule_hits_total counter\n"
               "argus_rule_hits_total %llu\n",
            (unsigned long long)atomic_load(&g_rule_hits));

    /* Baseline anomalies */
    fprintf(f, "# HELP argus_anomalies_total Baseline anomalies detected\n"
               "# TYPE argus_anomalies_total counter\n"
               "argus_anomalies_total %llu\n",
            (unsigned long long)atomic_load(&g_anomalies));

    /* Forward connections */
    fprintf(f, "# HELP argus_forward_connections_total Successful TCP forward connections\n"
               "# TYPE argus_forward_connections_total counter\n"
               "argus_forward_connections_total %llu\n",
            (unsigned long long)atomic_load(&g_fwd_connects));

    /* ── Enterprise module metrics ──────────────────────────────────────── */

    /* Webhook dispatcher */
    {
        uint64_t posts = 0, drops = 0;
        int      depth = 0;
        webhook_stats(&posts, &drops, &depth);
        fprintf(f,
            "# HELP argus_webhook_posts_total Webhook HTTP POSTs sent successfully\n"
            "# TYPE argus_webhook_posts_total counter\n"
            "argus_webhook_posts_total %llu\n"
            "# HELP argus_webhook_drops_total Webhook payloads dropped (queue full)\n"
            "# TYPE argus_webhook_drops_total counter\n"
            "argus_webhook_drops_total %llu\n"
            "# HELP argus_webhook_queue_depth Current webhook dispatch queue depth\n"
            "# TYPE argus_webhook_queue_depth gauge\n"
            "argus_webhook_queue_depth %d\n",
            (unsigned long long)posts,
            (unsigned long long)drops,
            depth);
    }

    /* IOC enrichment cache */
    {
        uint64_t lookups = 0, hits = 0, misses = 0;
        iocenrich_stats(&lookups, &hits, &misses);
        fprintf(f,
            "# HELP argus_ioc_lookups_total Total IOC enrichment lookups\n"
            "# TYPE argus_ioc_lookups_total counter\n"
            "argus_ioc_lookups_total %llu\n"
            "# HELP argus_ioc_cache_hits_total IOC lookups served from cache\n"
            "# TYPE argus_ioc_cache_hits_total counter\n"
            "argus_ioc_cache_hits_total %llu\n"
            "# HELP argus_ioc_cache_misses_total IOC lookups that required API calls\n"
            "# TYPE argus_ioc_cache_misses_total counter\n"
            "argus_ioc_cache_misses_total %llu\n",
            (unsigned long long)lookups,
            (unsigned long long)hits,
            (unsigned long long)misses);
    }

    /* SQLite event store */
    {
        uint64_t inserts = 0, errors = 0;
        store_stats(&inserts, &errors);
        fprintf(f,
            "# HELP argus_store_inserts_total Events successfully inserted into SQLite store\n"
            "# TYPE argus_store_inserts_total counter\n"
            "argus_store_inserts_total %llu\n"
            "# HELP argus_store_errors_total SQLite insert errors\n"
            "# TYPE argus_store_errors_total counter\n"
            "argus_store_errors_total %llu\n",
            (unsigned long long)inserts,
            (unsigned long long)errors);
    }

    fflush(f);
    fclose(f);
}

/* ── background HTTP listener thread ────────────────────────────────────── */

static void *metrics_thread(void *arg)
{
    (void)arg;

    while (g_running) {
        /* accept with 1-second timeout so we notice g_running==0 */
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_listen_fd, &rfds);

        int rc = select(g_listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) continue;

        struct sockaddr_in client = {};
        socklen_t slen = sizeof(client);
        int cfd = accept(g_listen_fd, (struct sockaddr *)&client, &slen);
        if (cfd < 0) continue;

        /* Read and discard the HTTP request (we serve any GET path) */
        char buf[512];
        ssize_t n = recv(cfd, buf, sizeof(buf) - 1, 0);
        (void)n;

        write_metrics(cfd);
        close(cfd);
    }
    return NULL;
}

/* ── public API ──────────────────────────────────────────────────────────── */

int metrics_init(int port)
{
    if (port <= 0) {
        g_port = 0;
        return 0;
    }

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) return -1;

    int one = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(g_listen_fd, 8) < 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        return -1;
    }

    g_port    = port;
    g_running = 1;

    /* Reset counters on (re)init */
    atomic_store(&g_events_total, 0);
    atomic_store(&g_drops,        0);
    atomic_store(&g_rule_hits,    0);
    atomic_store(&g_anomalies,    0);
    atomic_store(&g_fwd_connects, 0);
    for (int i = 0; i < EVENT_TYPE_MAX; i++)
        atomic_store(&g_events_by_type[i], 0);

    if (pthread_create(&g_thread, NULL, metrics_thread, NULL) != 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        g_running   = 0;
        g_port      = 0;
        return -1;
    }

    return 0;
}

void metrics_fini(void)
{
    if (!g_port) return;
    g_running = 0;
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    pthread_join(g_thread, NULL);
    g_port = 0;
}
