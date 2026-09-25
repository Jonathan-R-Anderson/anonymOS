#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>
#include "exechash.h"

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/* ── constants ───────────────────────────────────────────────────────── */

#define CACHE_SIZE      256
#define VT_QUEUE_SIZE   32
#define VT_HOST         "www.virustotal.com"
#define VT_PORT_STR     "443"
#define VT_RATE_PER_MIN 4       /* max VT requests per 60 seconds */
#define READ_BUF_SIZE   4096

/* ── module state (always present) ──────────────────────────────────── */

static int  g_initialized = 0;

/* ── all OpenSSL-dependent state ─────────────────────────────────────── */

#ifdef HAVE_OPENSSL

/* LRU cache */
typedef struct {
    ino_t    inode;
    time_t   mtime;
    int      pid;           /* last pid that loaded this inode */
    char     hex[65];       /* SHA-256 hex string              */
    uint64_t last_used;     /* monotonic counter for LRU       */
    int      valid;
} cache_entry_t;

static cache_entry_t g_cache[CACHE_SIZE];
static uint64_t      g_cache_clock = 0;

/* VT async queue */
typedef struct {
    char hex[65];
} vt_entry_t;

static vt_entry_t      g_vt_queue[VT_QUEUE_SIZE];
static int             g_vt_head  = 0;
static int             g_vt_tail  = 0;
static int             g_vt_count = 0;
static pthread_mutex_t g_vt_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_vt_cond  = PTHREAD_COND_INITIALIZER;
static pthread_t       g_vt_thread;
static int             g_vt_stop  = 0;
static char            g_vt_key[128]; /* empty = no VT */

/* ── SHA-256 via OpenSSL EVP ─────────────────────────────────────────── */

int exechash_file(const char *path, char hex_out[65])
{
    FILE          *fp;
    EVP_MD_CTX    *ctx;
    unsigned char  buf[READ_BUF_SIZE];
    unsigned char  digest[EVP_MAX_MD_SIZE];
    unsigned int   digest_len = 0;
    size_t         n;
    int            i;

    if (!path || !hex_out)
        return -1;

    fp = fopen(path, "rb");
    if (!fp)
        return -1;

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(fp);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(fp);
            return -1;
        }
    }

    if (ferror(fp)) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    for (i = 0; i < (int)digest_len; i++)
        snprintf(hex_out + i * 2, 3, "%02x", digest[i]);
    hex_out[64] = '\0';

    return 0;
}

/* ── LRU cache helpers ───────────────────────────────────────────────── */

static cache_entry_t *cache_find(ino_t inode, time_t mtime)
{
    int i;
    for (i = 0; i < CACHE_SIZE; i++) {
        if (g_cache[i].valid &&
            g_cache[i].inode == inode &&
            g_cache[i].mtime == mtime)
            return &g_cache[i];
    }
    return NULL;
}

/* Return the least-recently-used slot (or an empty one). */
static cache_entry_t *cache_evict(void)
{
    int            i;
    int            lru_idx = 0;
    uint64_t       lru_val = g_cache[0].last_used;

    for (i = 1; i < CACHE_SIZE; i++) {
        if (!g_cache[i].valid)
            return &g_cache[i];
        if (g_cache[i].last_used < lru_val) {
            lru_val = g_cache[i].last_used;
            lru_idx = i;
        }
    }
    return &g_cache[lru_idx];
}

static cache_entry_t *cache_insert(ino_t inode, time_t mtime,
                                   int pid, const char *hex)
{
    cache_entry_t *e = cache_evict();
    e->inode     = inode;
    e->mtime     = mtime;
    e->pid       = pid;
    e->last_used = ++g_cache_clock;
    e->valid     = 1;
    strncpy(e->hex, hex, 64);
    e->hex[64] = '\0';
    return e;
}

/* ── VirusTotal minimal HTTPS client ─────────────────────────────────── */

static void vt_check_hash(const char *hex)
{
    struct addrinfo  hints, *res, *rp;
    int              fd = -1;
    SSL_CTX         *ctx = NULL;
    SSL             *ssl = NULL;
    char             request[512];
    char             response[4096];
    int              n, req_len;

    req_len = snprintf(request, sizeof(request),
                       "GET /api/v3/files/%s HTTP/1.1\r\n"
                       "Host: " VT_HOST "\r\n"
                       "x-apikey: %s\r\n"
                       "Accept: application/json\r\n"
                       "Connection: close\r\n"
                       "\r\n",
                       hex, g_vt_key);
    if (req_len <= 0 || (size_t)req_len >= sizeof(request))
        return;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(VT_HOST, VT_PORT_STR, &hints, &res) != 0)
        return;

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        return;

    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return; }
    ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return; }

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, VT_HOST);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return;
    }

    if (SSL_write(ssl, request, req_len) <= 0) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return;
    }

    memset(response, 0, sizeof(response));
    n = SSL_read(ssl, response, (int)(sizeof(response) - 1));

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);

    if (n <= 0)
        return;
    response[n] = '\0';

    /* Rudimentary check: "malicious": followed by a non-zero digit */
    {
        const char *tag = strstr(response, "\"malicious\":");
        if (tag) {
            const char *val = tag + 12;
            while (*val == ' ' || *val == '\t') val++;
            if (*val >= '1' && *val <= '9') {
                fprintf(stderr,
                        "[VT_HIT] sha256=%s  malicious detections reported\n",
                        hex);
            }
        }
    }
}

/* ── VT background worker thread ────────────────────────────────────── */

static void *vt_worker(void *arg)
{
    int    req_this_minute = 0;
    time_t window_start    = time(NULL);

    (void)arg;

    for (;;) {
        char local_hex[65];

        pthread_mutex_lock(&g_vt_mutex);
        while (g_vt_count == 0 && !g_vt_stop)
            pthread_cond_wait(&g_vt_cond, &g_vt_mutex);

        if (g_vt_count == 0 && g_vt_stop) {
            pthread_mutex_unlock(&g_vt_mutex);
            break;
        }

        memcpy(local_hex, g_vt_queue[g_vt_tail].hex, 65);
        g_vt_tail  = (g_vt_tail + 1) % VT_QUEUE_SIZE;
        g_vt_count--;
        pthread_mutex_unlock(&g_vt_mutex);

        /* Rate limiting: max VT_RATE_PER_MIN requests per 60-second window */
        {
            time_t now = time(NULL);
            if (now - window_start >= 60) {
                window_start    = now;
                req_this_minute = 0;
            }
            if (req_this_minute >= VT_RATE_PER_MIN) {
                time_t sleep_secs = 60 - (now - window_start);
                if (sleep_secs > 0)
                    sleep((unsigned int)sleep_secs);
                window_start    = time(NULL);
                req_this_minute = 0;
            }
        }

        vt_check_hash(local_hex);
        req_this_minute++;
    }

    return NULL;
}

#else /* !HAVE_OPENSSL */

int exechash_file(const char *path, char hex_out[65])
{
    (void)path;
    (void)hex_out;
    return -1;
}

#endif /* HAVE_OPENSSL */

/* ── public API ──────────────────────────────────────────────────────── */

void exechash_init(const char *vt_api_key)
{
    if (g_initialized)
        return;

#ifndef HAVE_OPENSSL
    (void)vt_api_key;
    fprintf(stderr,
            "[HASH] warning: compiled without HAVE_OPENSSL — "
            "exechash is a no-op\n");
    g_initialized = 1;
    return;
#else
    memset(g_cache, 0, sizeof(g_cache));
    g_cache_clock = 0;
    g_vt_head  = 0;
    g_vt_tail  = 0;
    g_vt_count = 0;
    g_vt_stop  = 0;

    if (vt_api_key && vt_api_key[0]) {
        strncpy(g_vt_key, vt_api_key, sizeof(g_vt_key) - 1);
        g_vt_key[sizeof(g_vt_key) - 1] = '\0';
        if (pthread_create(&g_vt_thread, NULL, vt_worker, NULL) != 0)
            g_vt_key[0] = '\0'; /* disable VT if thread spawn fails */
    } else {
        g_vt_key[0] = '\0';
    }

    g_initialized = 1;
#endif /* HAVE_OPENSSL */
}

void exechash_check(const event_t *ev)
{
    if (!g_initialized || !ev)
        return;
    if (ev->type != EVENT_EXEC)
        return;

#ifdef HAVE_OPENSSL
    {
        char        exe_path[512];
        char        proc_link[64];
        struct stat st;
        ssize_t     link_len;
        char        hex[65];

        snprintf(proc_link, sizeof(proc_link), "/proc/%d/exe", ev->pid);
        link_len = readlink(proc_link, exe_path, sizeof(exe_path) - 1);
        if (link_len <= 0)
            return;
        exe_path[link_len] = '\0';

        if (stat(exe_path, &st) != 0)
            return;

        /* Check LRU cache first */
        {
            cache_entry_t *ce = cache_find(st.st_ino, st.st_mtime);
            if (ce) {
                ce->pid       = ev->pid;
                ce->last_used = ++g_cache_clock;
                fprintf(stderr,
                        "[HASH] pid=%-6d comm=%-16s sha256=%s  (cached)\n",
                        ev->pid, ev->comm, ce->hex);
                return;
            }
        }

        /* Cache miss — compute hash */
        if (exechash_file(exe_path, hex) != 0)
            return;

        cache_insert(st.st_ino, st.st_mtime, ev->pid, hex);

        fprintf(stderr,
                "[HASH] pid=%-6d comm=%-16s sha256=%s\n",
                ev->pid, ev->comm, hex);

        /* Enqueue async VT lookup if a key was configured */
        if (g_vt_key[0]) {
            pthread_mutex_lock(&g_vt_mutex);
            if (g_vt_count < VT_QUEUE_SIZE) {
                strncpy(g_vt_queue[g_vt_head].hex, hex, 64);
                g_vt_queue[g_vt_head].hex[64] = '\0';
                g_vt_head  = (g_vt_head + 1) % VT_QUEUE_SIZE;
                g_vt_count++;
                pthread_cond_signal(&g_vt_cond);
            }
            pthread_mutex_unlock(&g_vt_mutex);
        }
    }
#endif /* HAVE_OPENSSL */
}

const char *exechash_get_cached(int pid)
{
#ifndef HAVE_OPENSSL
    (void)pid;
    return NULL;
#else
    int i;
    if (!g_initialized)
        return NULL;
    for (i = 0; i < CACHE_SIZE; i++) {
        if (g_cache[i].valid && g_cache[i].pid == pid)
            return g_cache[i].hex;
    }
    return NULL;
#endif
}
