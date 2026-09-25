/*
 * argus-bench — synthetic event throughput benchmark.
 *
 * Pumps BENCH_N events through the output pipeline for each format
 * (text, json, cef) with output redirected to /dev/null, then reports
 * events/second.  Also prints process RSS so you can see the memory
 * footprint of the full argus userspace at rest.
 *
 * Build (from repo root):
 *   make bench
 *
 * Run:
 *   ./argus-bench [N]
 *   N defaults to 500000 events per format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/output.h"
#include "../src/argus.h"

#define DEFAULT_N 500000

/* Read process RSS in kB from /proc/self/status (Linux only). */
static long rss_kb(void)
{
#ifdef __linux__
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[128];
    long kb = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, " %ld", &kb);
            break;
        }
    }
    fclose(f);
    return kb;
#else
    return -1;
#endif
}

/* Build a varied event matching the requested index for realistic serialisation. */
static event_t make_event(int i)
{
    event_t e = {0};
    int t = i % 6;

    switch (t) {
    case 0:
        e.type = EVENT_EXEC;
        snprintf(e.filename, sizeof(e.filename), "/usr/bin/prog%d", i % 64);
        snprintf(e.args,     sizeof(e.args),     "--flag=%d", i);
        break;
    case 1:
        e.type       = EVENT_OPEN;
        e.open_flags = 0;
        e.success    = 1;
        snprintf(e.filename, sizeof(e.filename), "/etc/config%d.conf", i % 32);
        break;
    case 2: {
        e.type   = EVENT_CONNECT;
        e.family = 2;   /* AF_INET */
        e.dport  = (uint16_t)(443 + (i % 3) * 80);
        e.success = 1;
        /* 192.168.x.y */
        e.daddr[0] = 192; e.daddr[1] = 168;
        e.daddr[2] = (uint8_t)(i >> 8);
        e.daddr[3] = (uint8_t)(i & 0xff);
        break;
    }
    case 3:
        e.type    = EVENT_DNS;
        e.family  = 2;
        e.dport   = 53;
        e.success = 1;
        snprintf(e.filename, sizeof(e.filename), "host%d.example.com", i % 128);
        e.daddr[0] = 8; e.daddr[1] = 8; e.daddr[2] = 8; e.daddr[3] = 8;
        break;
    case 4:
        e.type     = EVENT_TLS_DATA;
        e.tls_payload_len = 128;
        memset(e.tls_payload, 'A' + (i % 26), 128);
        break;
    case 5:
        e.type = EVENT_HEARTBEAT;
        break;
    }

    e.pid  = 1000 + (i % 1000);
    e.ppid = 1;
    e.uid  = (uint32_t)(i % 100);
    snprintf(e.comm, sizeof(e.comm), "proc%d", i % 16);
    return e;
}

/* Run one benchmark pass. */
static void bench_fmt(const char *label, output_fmt_t fmt, FILE *sink, int n)
{
    filter_t f = {0};
    f.event_mask = TRACE_ALL | (1 << EVENT_TLS_DATA);
    output_init(fmt, &f);
    output_set_file(sink);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < n; i++) {
        event_t e = make_event(i);
        print_event(&e);
    }
    fflush(sink);

    clock_gettime(CLOCK_MONOTONIC, &t1);

    double elapsed = (double)(t1.tv_sec  - t0.tv_sec) +
                     (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    double eps = (double)n / elapsed;

    printf("  %-8s  %8.0f events/sec   (%.3fs for %d events)\n",
           label, eps, elapsed, n);

    output_fini();
}

int main(int argc, char **argv)
{
    int n = DEFAULT_N;
    if (argc > 1) {
        n = atoi(argv[1]);
        if (n <= 0) { fprintf(stderr, "usage: argus-bench [N]\n"); return 1; }
    }

    FILE *sink = fopen("/dev/null", "w");
    if (!sink) { perror("fopen /dev/null"); return 1; }

    printf("argus-bench v%s — output pipeline throughput\n", ARGUS_VERSION);
    printf("  events per run : %d\n", n);
    printf("  event mix      : EXEC, OPEN, CONNECT, DNS, TLS_DATA, HEARTBEAT\n\n");

    bench_fmt("text", OUTPUT_TEXT, sink, n);
    bench_fmt("json", OUTPUT_JSON, sink, n);
    bench_fmt("cef",  OUTPUT_CEF,  sink, n);

    fclose(sink);

    long rss = rss_kb();
    if (rss >= 0)
        printf("\n  RSS: %ld kB  (%.1f MB)\n", rss, (double)rss / 1024.0);

    return 0;
}
