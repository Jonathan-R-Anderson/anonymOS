#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "webhook.h"

#define WEBHOOK_CONNECT_TIMEOUT_S 5

/* ── internal types ──────────────────────────────────────────────────── */

typedef struct {
    char body[WEBHOOK_BODY_MAX];
} webhook_entry_t;

/* ── module state ────────────────────────────────────────────────────── */

static int              g_initialized = 0;

/* ── statistics (atomic, readable without lock) ──────────────────────── */
static _Atomic uint64_t g_stat_posts = 0;   /* successful POSTs sent     */
static _Atomic uint64_t g_stat_drops = 0;   /* entries dropped (q full)  */

/* parsed URL components */
static char             g_host[256];
static int              g_port;
static char             g_path[512];

/* circular queue */
static webhook_entry_t  g_queue[WEBHOOK_QUEUE_SIZE];
static int              g_head = 0;  /* next slot to write */
static int              g_tail = 0;  /* next slot to read  */
static int              g_count = 0;

static pthread_mutex_t  g_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   g_cond   = PTHREAD_COND_INITIALIZER;
static pthread_t        g_thread;
static int              g_stop = 0;

/* ── helpers ─────────────────────────────────────────────────────────── */

/*
 * Open a TCP connection to g_host:g_port.
 * Returns a connected fd >= 0, or -1 on failure.
 */
static int connect_to_host(void)
{
    struct addrinfo hints, *res, *rp;
    int fd = -1;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", g_port);
    if (getaddrinfo(g_host, port_str, &hints, &res) != 0)
        return -1;

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;

        /* Apply send/receive timeouts so a slow/dead endpoint can't block
         * the worker thread indefinitely. */
        struct timeval tv = { .tv_sec = WEBHOOK_CONNECT_TIMEOUT_S, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

/*
 * Send one JSON body via a fresh HTTP/1.1 POST connection.
 */
static void send_post(const char *body)
{
    int fd = connect_to_host();
    if (fd < 0)
        return;

    size_t body_len = strlen(body);
    char   header[1024];
    int    hdr_len;

    hdr_len = snprintf(header, sizeof(header),
                       "POST %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "Content-Type: application/json\r\n"
                       "Content-Length: %zu\r\n"
                       "Connection: close\r\n"
                       "\r\n",
                       g_path, g_host, body_len);

    if (hdr_len <= 0 || (size_t)hdr_len >= sizeof(header)) {
        close(fd);
        return;
    }

    /* Best-effort sends; ignore partial write errors */
    (void)write(fd, header, (size_t)hdr_len);
    (void)write(fd, body,   body_len);

    close(fd);
}

/* ── worker thread ───────────────────────────────────────────────────── */

static void *worker_thread(void *arg)
{
    (void)arg;

    for (;;) {
        char local_body[WEBHOOK_BODY_MAX];

        pthread_mutex_lock(&g_mutex);
        while (g_count == 0 && !g_stop)
            pthread_cond_wait(&g_cond, &g_mutex);

        if (g_count == 0 && g_stop) {
            pthread_mutex_unlock(&g_mutex);
            break;
        }

        /* dequeue one entry */
        memcpy(local_body, g_queue[g_tail].body, WEBHOOK_BODY_MAX);
        g_tail  = (g_tail + 1) % WEBHOOK_QUEUE_SIZE;
        g_count--;
        pthread_mutex_unlock(&g_mutex);

        send_post(local_body);
        atomic_fetch_add(&g_stat_posts, 1);
    }

    return NULL;
}

/* ── public API ──────────────────────────────────────────────────────── */

void webhook_init(const char *url)
{
    if (!url || !url[0])
        return;

    /* Expect: http://host[:port]/path */
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0)
        p += 7;

    /* host (up to ':' or '/') */
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    /* If colon comes before slash (or there is no slash), there is a port */
    if (colon && (!slash || colon < slash)) {
        size_t host_len = (size_t)(colon - p);
        if (host_len >= sizeof(g_host))
            host_len = sizeof(g_host) - 1;
        memcpy(g_host, p, host_len);
        g_host[host_len] = '\0';
        g_port = atoi(colon + 1);
        if (g_port <= 0 || g_port > 65535)
            g_port = 80;
    } else {
        size_t host_len = slash ? (size_t)(slash - p) : strlen(p);
        if (host_len >= sizeof(g_host))
            host_len = sizeof(g_host) - 1;
        memcpy(g_host, p, host_len);
        g_host[host_len] = '\0';
        g_port = 80;
    }

    /* path */
    if (slash) {
        strncpy(g_path, slash, sizeof(g_path) - 1);
        g_path[sizeof(g_path) - 1] = '\0';
    } else {
        g_path[0] = '/';
        g_path[1] = '\0';
    }

    if (g_host[0] == '\0')
        return;

    g_head  = 0;
    g_tail  = 0;
    g_count = 0;
    g_stop  = 0;

    if (pthread_create(&g_thread, NULL, worker_thread, NULL) != 0)
        return;

    g_initialized = 1;
}

void webhook_fire(const char *json_body)
{
    if (!g_initialized || !json_body || !json_body[0])
        return;

    pthread_mutex_lock(&g_mutex);
    if (g_count >= WEBHOOK_QUEUE_SIZE) {
        /* queue full — count the drop */
        atomic_fetch_add(&g_stat_drops, 1);
        pthread_mutex_unlock(&g_mutex);
        return;
    }

    strncpy(g_queue[g_head].body, json_body, WEBHOOK_BODY_MAX - 1);
    g_queue[g_head].body[WEBHOOK_BODY_MAX - 1] = '\0';
    g_head  = (g_head + 1) % WEBHOOK_QUEUE_SIZE;
    g_count++;
    pthread_cond_signal(&g_cond);
    pthread_mutex_unlock(&g_mutex);
}

void webhook_stats(uint64_t *posts, uint64_t *drops, int *queue_depth)
{
    if (posts)       *posts       = atomic_load(&g_stat_posts);
    if (drops)       *drops       = atomic_load(&g_stat_drops);
    if (queue_depth) {
        pthread_mutex_lock(&g_mutex);
        *queue_depth = g_count;
        pthread_mutex_unlock(&g_mutex);
    }
}

void webhook_destroy(void)
{
    if (!g_initialized)
        return;

    pthread_mutex_lock(&g_mutex);
    g_stop = 1;
    pthread_cond_signal(&g_cond);
    pthread_mutex_unlock(&g_mutex);

    pthread_join(g_thread, NULL);
    g_initialized = 0;
}
