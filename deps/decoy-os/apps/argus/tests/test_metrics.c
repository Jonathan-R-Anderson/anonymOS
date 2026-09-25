/*
 * test_metrics.c — unit tests for the Prometheus metrics endpoint.
 *
 * Tests cover:
 *   - Counter increments (metrics_event, metrics_drop, metrics_rule_hit,
 *     metrics_anomaly, metrics_fwd_connect)
 *   - HTTP endpoint returns 200 with Prometheus text body
 *   - All expected metric names are present in the response
 *   - Per-type event counters are correctly labeled
 *   - metrics_init with port 0 is a no-op (safe)
 *   - metrics_fini is idempotent
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "argus.h"
#include "metrics.h"

/* ── minimal test harness ────────────────────────────────────────────────── */

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do {                                   \
    if (cond) { g_pass++; }                                     \
    else {                                                      \
        g_fail++;                                               \
        fprintf(stderr, "FAIL [%s:%d] %s\n",                   \
                __FILE__, __LINE__, msg);                       \
    }                                                           \
} while (0)

/* ── helper: fetch http://127.0.0.1:<port>/metrics ───────────────────────── */

static int fetch_metrics(int port, char *buf, size_t bufsz)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* Retry a few times to let the listener thread start */
    for (int i = 0; i < 20; i++) {
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) break;
        if (i == 19) { close(fd); return -1; }
        usleep(10000);   /* 10 ms */
    }

    const char *req = "GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n";
    if (send(fd, req, strlen(req), 0) < 0) { close(fd); return -1; }

    size_t total = 0;
    ssize_t n;
    while (total + 1 < bufsz &&
           (n = recv(fd, buf + total, bufsz - total - 1, 0)) > 0)
        total += (size_t)n;
    buf[total] = '\0';
    close(fd);
    return (int)total;
}

/* ── test functions ──────────────────────────────────────────────────────── */

static void test_port_zero_noop(void)
{
    /* metrics_init(0) should succeed and be a no-op */
    int rc = metrics_init(0);
    CHECK(rc == 0, "metrics_init(0) returns 0");
    /* Calling increment helpers should not crash */
    event_t e = {};
    e.type = EVENT_EXEC;
    metrics_event(&e);
    metrics_drop(5);
    metrics_rule_hit();
    metrics_anomaly();
    metrics_fwd_connect();
    metrics_fini();   /* no-op */
    metrics_fini();   /* idempotent */
    g_pass++;         /* survived */
}

static void test_http_endpoint(void)
{
    /* Use an ephemeral high port */
    int port = 19090;

    int rc = metrics_init(port);
    CHECK(rc == 0, "metrics_init starts successfully");
    if (rc != 0) return;

    /* Increment some counters */
    event_t e = {};
    e.type = EVENT_EXEC;    metrics_event(&e);
    e.type = EVENT_CONNECT; metrics_event(&e);
    e.type = EVENT_DNS;     metrics_event(&e);
    metrics_drop(3);
    metrics_rule_hit();
    metrics_rule_hit();
    metrics_anomaly();
    metrics_fwd_connect();

    char buf[8192] = {};
    int n = fetch_metrics(port, buf, sizeof(buf));
    CHECK(n > 0, "fetch_metrics returns data");

    /* HTTP status line */
    CHECK(strstr(buf, "200 OK") != NULL, "HTTP 200 OK");

    /* Prometheus metric names */
    CHECK(strstr(buf, "argus_events_total")       != NULL, "argus_events_total present");
    CHECK(strstr(buf, "argus_events_by_type")     != NULL, "argus_events_by_type present");
    CHECK(strstr(buf, "argus_drops_total")        != NULL, "argus_drops_total present");
    CHECK(strstr(buf, "argus_rule_hits_total")    != NULL, "argus_rule_hits_total present");
    CHECK(strstr(buf, "argus_anomalies_total")    != NULL, "argus_anomalies_total present");
    CHECK(strstr(buf, "argus_forward_connections_total") != NULL,
          "argus_forward_connections_total present");

    /* Per-type labels */
    CHECK(strstr(buf, "type=\"exec\"")    != NULL, "exec type label");
    CHECK(strstr(buf, "type=\"connect\"") != NULL, "connect type label");
    CHECK(strstr(buf, "type=\"dns\"")     != NULL, "dns type label");

    /* Total events should be 3 (exec + connect + dns) */
    CHECK(strstr(buf, "argus_events_total 3") != NULL, "events_total == 3");

    /* Drops */
    CHECK(strstr(buf, "argus_drops_total 3") != NULL, "drops_total == 3");

    /* Rule hits */
    CHECK(strstr(buf, "argus_rule_hits_total 2") != NULL, "rule_hits == 2");

    /* Anomalies */
    CHECK(strstr(buf, "argus_anomalies_total 1") != NULL, "anomalies == 1");

    /* Forward connections */
    CHECK(strstr(buf, "argus_forward_connections_total 1") != NULL,
          "fwd_connects == 1");

    metrics_fini();
}

static void test_second_fetch_accumulates(void)
{
    int port = 19091;
    int rc = metrics_init(port);
    CHECK(rc == 0, "second metrics_init");
    if (rc != 0) return;

    event_t e = {};
    e.type = EVENT_OPEN;
    metrics_event(&e);

    char buf[4096] = {};
    fetch_metrics(port, buf, sizeof(buf));
    CHECK(strstr(buf, "argus_events_total 1") != NULL, "first fetch: 1 event");

    /* Add another event — counter should increment */
    e.type = EVENT_EXIT;
    metrics_event(&e);

    char buf2[4096] = {};
    fetch_metrics(port, buf2, sizeof(buf2));
    CHECK(strstr(buf2, "argus_events_total 2") != NULL, "second fetch: 2 events");

    metrics_fini();
}

static void test_fini_idempotent(void)
{
    int port = 19092;
    metrics_init(port);
    metrics_fini();
    metrics_fini();   /* second call must not crash */
    metrics_fini();
    g_pass++;
}

static void test_null_event_safe(void)
{
    /* metrics_event(NULL) should be a no-op */
    metrics_init(0);
    metrics_event(NULL);   /* must not segfault */
    metrics_fini();
    g_pass++;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    test_port_zero_noop();
    test_http_endpoint();
    test_second_fetch_accumulates();
    test_fini_idempotent();
    test_null_event_safe();

    printf("metrics: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
