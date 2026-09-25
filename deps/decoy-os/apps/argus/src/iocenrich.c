#include "iocenrich.h"

#ifdef HAVE_OPENSSL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "argus.h"

/* ── compile-time tunables ─────────────────────────────────────────────── */

#define IOC_QUEUE_CAP    128    /* request queue depth                       */
#define LRU_CAP          512    /* result cache entries                      */
#define LRU_TTL          3600   /* seconds before a cached result expires    */
#define VT_RATE_LIMIT    4      /* max VT requests per minute                */
#define OTX_RATE_LIMIT   10     /* max OTX requests per minute               */
#define HTTPS_TIMEOUT_S  5      /* connect / read timeout                    */
#define HTTPS_RESP_MAX   (64 * 1024)  /* max HTTPS response bytes to read   */

/* ── IOC types ─────────────────────────────────────────────────────────── */

typedef enum {
    IOC_IP     = 0,
    IOC_DOMAIN = 1,
    IOC_HASH   = 2,
} ioc_type_t;

/* ── request queue entry ───────────────────────────────────────────────── */

typedef struct {
    ioc_type_t type;
    char       value[256];
    int        pid;
    char       comm[16];
} ioc_req_t;

static ioc_req_t    g_queue[IOC_QUEUE_CAP];
static int          g_q_head    = 0;
static int          g_q_tail    = 0;
static pthread_mutex_t g_q_lock  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_q_cond  = PTHREAD_COND_INITIALIZER;
static volatile int    g_q_stop  = 0;
static pthread_t       g_worker;

/* ── statistics ─────────────────────────────────────────────────────────── */
static _Atomic uint64_t g_stat_lookups     = 0;
static _Atomic uint64_t g_stat_cache_hits  = 0;
static _Atomic uint64_t g_stat_cache_miss  = 0;

/* ── API keys ──────────────────────────────────────────────────────────── */

static char g_vt_key[256]  = {};
static char g_otx_key[256] = {};

/* ── LRU cache ─────────────────────────────────────────────────────────── */

typedef struct {
    char   key[256];   /* IOC value */
    int    vt_malicious;
    int    vt_total;
    int    otx_pulses;
    time_t expires;
    int    used;
} cache_entry_t;

static cache_entry_t g_cache[LRU_CAP];
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static cache_entry_t *cache_lookup(const char *key)
{
    time_t now = time(NULL);
    for (int i = 0; i < LRU_CAP; i++) {
        if (g_cache[i].used &&
            strcmp(g_cache[i].key, key) == 0 &&
            g_cache[i].expires > now)
            return &g_cache[i];
    }
    return NULL;
}

/* Returns a slot to write into (evicts oldest expired, then oldest overall) */
static cache_entry_t *cache_alloc(const char *key)
{
    time_t now = time(NULL);
    int best = 0;
    time_t best_exp = g_cache[0].expires;

    for (int i = 0; i < LRU_CAP; i++) {
        if (!g_cache[i].used) { best = i; break; }
        if (g_cache[i].expires <= now) { best = i; break; }
        if (g_cache[i].expires < best_exp) {
            best_exp = g_cache[i].expires;
            best     = i;
        }
    }

    memset(&g_cache[best], 0, sizeof(g_cache[best]));
    strncpy(g_cache[best].key, key, sizeof(g_cache[best].key) - 1);
    g_cache[best].expires = now + LRU_TTL;
    g_cache[best].used    = 1;
    return &g_cache[best];
}

/* ── rate limiter ──────────────────────────────────────────────────────── */

typedef struct {
    time_t window_start;
    int    count;
    int    limit;
} rate_limiter_t;

static rate_limiter_t g_vt_rl  = { .limit = VT_RATE_LIMIT  };
static rate_limiter_t g_otx_rl = { .limit = OTX_RATE_LIMIT };

/* Returns 1 if the request can proceed; 0 if rate limit hit (caller should
 * sleep to the next window). */
static void rate_wait(rate_limiter_t *rl)
{
    time_t now = time(NULL);
    if (now - rl->window_start >= 60) {
        rl->window_start = now;
        rl->count        = 0;
    }
    if (rl->count >= rl->limit) {
        /* Sleep until the current 60-second window expires */
        time_t sleep_secs = 60 - (now - rl->window_start);
        if (sleep_secs > 0)
            sleep((unsigned int)sleep_secs);
        rl->window_start = time(NULL);
        rl->count        = 0;
    }
    rl->count++;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Minimal HTTPS client
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * Perform a single HTTPS GET request.
 * host     — e.g. "www.virustotal.com"
 * path     — e.g. "/api/v3/ip_addresses/1.2.3.4"
 * headers  — extra HTTP headers, each terminated with \r\n (may be NULL)
 * resp_out — caller-allocated buffer of size resp_cap
 * Returns number of body bytes written to resp_out, or -1 on error.
 */
static int https_get(const char *host, const char *path,
                     const char *headers,
                     char *resp_out, size_t resp_cap)
{
    /* Resolve host */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, "443", &hints, &res) != 0 || !res)
        return -1;

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    /* Apply connect / I/O timeouts */
    struct timeval tv = { .tv_sec = HTTPS_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) != 0) {
        close(sockfd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    /* SSL handshake */
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(sockfd); return -1; }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(sockfd); return -1; }

    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(sockfd);
        return -1;
    }

    /* Build and send request */
    char req[2048];
    int rlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: argus/" ARGUS_VERSION "\r\n"
        "%s"
        "Connection: close\r\n"
        "\r\n",
        path, host, headers ? headers : "");

    if (SSL_write(ssl, req, rlen) <= 0) {
        SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); close(sockfd);
        return -1;
    }

    /* Read response */
    char raw[HTTPS_RESP_MAX];
    int  total = 0, n;
    while ((n = SSL_read(ssl, raw + total,
                         (int)(sizeof(raw) - (size_t)total - 1))) > 0) {
        total += n;
        if (total >= HTTPS_RESP_MAX - 1) break;
    }
    raw[total] = '\0';

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);

    if (total <= 0) return -1;

    /* Skip HTTP headers — find double CRLF */
    char *body = strstr(raw, "\r\n\r\n");
    if (!body) return -1;
    body += 4;

    size_t bodylen = (size_t)(raw + total - body);
    if (bodylen >= resp_cap) bodylen = resp_cap - 1;
    memcpy(resp_out, body, bodylen);
    resp_out[bodylen] = '\0';
    return (int)bodylen;
}

/* ── JSON field extraction helpers ──────────────────────────────────────── */

/*
 * Find "\"key\":" in src and parse the integer value that follows.
 * Returns the value or -1 if not found / not an integer.
 */
static long long extract_int(const char *src, const char *key)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(src, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '-' || (*p >= '0' && *p <= '9'))
        return strtoll(p, NULL, 10);
    return -1;
}

/* ══════════════════════════════════════════════════════════════════════════
 * VirusTotal queries
 * ══════════════════════════════════════════════════════════════════════════ */

static void vt_query(const ioc_req_t *req,
                     int *out_malicious, int *out_total)
{
    *out_malicious = -1;
    *out_total     = -1;

    if (!g_vt_key[0]) return;

    char path[512];
    switch (req->type) {
    case IOC_IP:
        snprintf(path, sizeof(path),
            "/api/v3/ip_addresses/%s", req->value);
        break;
    case IOC_DOMAIN:
        snprintf(path, sizeof(path),
            "/api/v3/domains/%s", req->value);
        break;
    case IOC_HASH:
        snprintf(path, sizeof(path),
            "/api/v3/files/%s", req->value);
        break;
    default:
        return;
    }

    char auth_hdr[320];
    snprintf(auth_hdr, sizeof(auth_hdr), "x-apikey: %s\r\n", g_vt_key);

    char resp[HTTPS_RESP_MAX];
    rate_wait(&g_vt_rl);
    int n = https_get("www.virustotal.com", path, auth_hdr,
                      resp, sizeof(resp));
    if (n <= 0) return;

    long long malicious = extract_int(resp, "malicious");
    if (malicious < 0) return;
    *out_malicious = (int)malicious;

    /* Sum all counts from last_analysis_stats to get total */
    const char *stats = strstr(resp, "last_analysis_stats");
    if (stats) {
        const char *fields[] = {
            "malicious", "suspicious", "undetected", "harmless", "timeout",
            "confirmed-timeout", "failure", "type-unsupported", NULL
        };
        int total = 0;
        for (int i = 0; fields[i]; i++) {
            long long v = extract_int(stats, fields[i]);
            if (v > 0) total += (int)v;
        }
        *out_total = total;
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * AlienVault OTX queries
 * ══════════════════════════════════════════════════════════════════════════ */

static int otx_query(const ioc_req_t *req)
{
    if (!g_otx_key[0]) return -1;

    char path[512];
    switch (req->type) {
    case IOC_IP:
        snprintf(path, sizeof(path),
            "/api/v1/indicators/IPv4/%s/general", req->value);
        break;
    case IOC_DOMAIN:
        snprintf(path, sizeof(path),
            "/api/v1/indicators/domain/%s/general", req->value);
        break;
    default:
        return -1;   /* OTX hash endpoint not requested */
    }

    char auth_hdr[320];
    snprintf(auth_hdr, sizeof(auth_hdr), "X-OTX-API-KEY: %s\r\n", g_otx_key);

    char resp[HTTPS_RESP_MAX];
    rate_wait(&g_otx_rl);
    int n = https_get("otx.alienvault.com", path, auth_hdr,
                      resp, sizeof(resp));
    if (n <= 0) return -1;

    long long pulses = extract_int(resp, "pulse_count");
    return (pulses >= 0) ? (int)pulses : -1;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Worker thread
 * ══════════════════════════════════════════════════════════════════════════ */

static void process_request(const ioc_req_t *req)
{
    /* Check cache first */
    atomic_fetch_add(&g_stat_lookups, 1);

    pthread_mutex_lock(&g_cache_lock);
    cache_entry_t *hit = cache_lookup(req->value);
    if (hit) {
        /* Already cached — re-emit alert if it was a positive result */
        int vm = hit->vt_malicious, vt = hit->vt_total, op = hit->otx_pulses;
        pthread_mutex_unlock(&g_cache_lock);
        atomic_fetch_add(&g_stat_cache_hits, 1);

        if (vm > 0) {
            fprintf(stderr,
                "[VT_HIT] pid=%d comm=%s ioc=%s malicious=%d/total=%d"
                " (cached)\n",
                req->pid, req->comm, req->value, vm, vt);
        }
        if (op > 0) {
            fprintf(stderr,
                "[OTX_HIT] pid=%d comm=%s ioc=%s pulses=%d (cached)\n",
                req->pid, req->comm, req->value, op);
        }
        return;
    }
    pthread_mutex_unlock(&g_cache_lock);
    atomic_fetch_add(&g_stat_cache_miss, 1);

    /* Query VirusTotal */
    int vt_malicious = -1, vt_total = 0;
    vt_query(req, &vt_malicious, &vt_total);

    /* Query OTX (only for IP / domain) */
    int otx_pulses = -1;
    if (req->type == IOC_IP || req->type == IOC_DOMAIN)
        otx_pulses = otx_query(req);

    /* Store in cache */
    pthread_mutex_lock(&g_cache_lock);
    cache_entry_t *slot = cache_alloc(req->value);
    slot->vt_malicious = vt_malicious;
    slot->vt_total     = vt_total;
    slot->otx_pulses   = otx_pulses;
    pthread_mutex_unlock(&g_cache_lock);

    /* Alert on positive results */
    if (vt_malicious > 0) {
        fprintf(stderr,
            "[VT_HIT] pid=%d comm=%s ioc=%s malicious=%d/total=%d\n",
            req->pid, req->comm, req->value, vt_malicious, vt_total);
        syslog(LOG_WARNING,
            "VT_HIT pid=%d comm=%s ioc=%s malicious=%d/total=%d",
            req->pid, req->comm, req->value, vt_malicious, vt_total);
    }
    if (otx_pulses > 0) {
        fprintf(stderr,
            "[OTX_HIT] pid=%d comm=%s ioc=%s pulses=%d\n",
            req->pid, req->comm, req->value, otx_pulses);
        syslog(LOG_WARNING,
            "OTX_HIT pid=%d comm=%s ioc=%s pulses=%d",
            req->pid, req->comm, req->value, otx_pulses);
    }
}

static void *worker_thread(void *arg)
{
    (void)arg;

    /* Initialise OpenSSL once on this thread's behalf */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    while (1) {
        ioc_req_t req;
        int got = 0;

        pthread_mutex_lock(&g_q_lock);
        while (!g_q_stop && g_q_head == g_q_tail) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec++;
            pthread_cond_timedwait(&g_q_cond, &g_q_lock, &ts);
        }
        if (g_q_tail != g_q_head) {
            req     = g_queue[g_q_tail];
            g_q_tail = (g_q_tail + 1) % IOC_QUEUE_CAP;
            got     = 1;
        }
        int should_stop = g_q_stop && (g_q_tail == g_q_head);
        pthread_mutex_unlock(&g_q_lock);

        if (got)
            process_request(&req);

        if (should_stop)
            break;
    }

    EVP_cleanup();
    ERR_free_strings();
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Public API
 * ══════════════════════════════════════════════════════════════════════════ */

void iocenrich_init(const char *vt_api_key, const char *otx_api_key)
{
    if (vt_api_key  && vt_api_key[0])
        strncpy(g_vt_key,  vt_api_key,  sizeof(g_vt_key)  - 1);
    if (otx_api_key && otx_api_key[0])
        strncpy(g_otx_key, otx_api_key, sizeof(g_otx_key) - 1);

    g_q_stop = 0;
    if (pthread_create(&g_worker, NULL, worker_thread, NULL) != 0)
        fprintf(stderr, "[iocenrich] failed to start worker thread\n");
}

void iocenrich_check(const event_t *ev)
{
    if (!ev) return;
    if (!g_vt_key[0] && !g_otx_key[0]) return;

    ioc_req_t req = {};
    req.pid = ev->pid;
    strncpy(req.comm, ev->comm, sizeof(req.comm) - 1);

    switch (ev->type) {
    case EVENT_CONNECT: {
        /* Build IP string from event address */
        char ip[INET6_ADDRSTRLEN] = {};
        if (ev->family == 2)
            inet_ntop(AF_INET,  ev->daddr, ip, sizeof(ip));
        else
            inet_ntop(AF_INET6, ev->daddr, ip, sizeof(ip));
        if (!ip[0]) return;
        strncpy(req.value, ip, sizeof(req.value) - 1);
        req.type = IOC_IP;
        break;
    }
    case EVENT_DNS:
        if (!ev->dns_name[0]) return;
        strncpy(req.value, ev->dns_name, sizeof(req.value) - 1);
        req.type = IOC_DOMAIN;
        break;
    case EVENT_EXEC:
        /* hash lookup: filename used as the IOC value (SHA-256 would be set
         * by exechash integration in req.value externally; here we fall back
         * to filename path as the lookup key). */
        if (!ev->filename[0]) return;
        strncpy(req.value, ev->filename, sizeof(req.value) - 1);
        req.type = IOC_HASH;
        break;
    default:
        return;
    }

    /* Enqueue (non-blocking) */
    pthread_mutex_lock(&g_q_lock);
    int next = (g_q_head + 1) % IOC_QUEUE_CAP;
    if (next != g_q_tail) {
        g_queue[g_q_head] = req;
        g_q_head = next;
        pthread_cond_signal(&g_q_cond);
    }
    /* else queue full — silently drop to stay non-blocking */
    pthread_mutex_unlock(&g_q_lock);
}

void iocenrich_stats(uint64_t *lookups, uint64_t *hits, uint64_t *misses)
{
    if (lookups) *lookups = atomic_load(&g_stat_lookups);
    if (hits)    *hits    = atomic_load(&g_stat_cache_hits);
    if (misses)  *misses  = atomic_load(&g_stat_cache_miss);
}

void iocenrich_update_keys(const char *vt_key, const char *otx_key)
{
    if (vt_key) {
        strncpy(g_vt_key, vt_key, sizeof(g_vt_key) - 1);
        g_vt_key[sizeof(g_vt_key) - 1] = '\0';
    }
    if (otx_key) {
        strncpy(g_otx_key, otx_key, sizeof(g_otx_key) - 1);
        g_otx_key[sizeof(g_otx_key) - 1] = '\0';
    }
}

void iocenrich_destroy(void)
{
    pthread_mutex_lock(&g_q_lock);
    g_q_stop = 1;
    pthread_cond_signal(&g_q_cond);
    pthread_mutex_unlock(&g_q_lock);
    pthread_join(g_worker, NULL);

    memset(g_vt_key,  0, sizeof(g_vt_key));
    memset(g_otx_key, 0, sizeof(g_otx_key));
    memset(g_cache,   0, sizeof(g_cache));
}

#endif /* HAVE_OPENSSL */
