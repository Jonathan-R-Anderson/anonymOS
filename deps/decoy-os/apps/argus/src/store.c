#include "store.h"

#ifdef HAVE_SQLITE3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include "argus.h"

/* ── compile-time tunables ─────────────────────────────────────────────── */

#define QUEUE_CAP        1024   /* circular write-queue depth               */
#define BATCH_MAX        64     /* inserts per SQLite transaction            */
#define HTTP_MAX_ROWS    10000  /* hard cap on /events result set           */
#define HTTP_DEF_LIMIT   1000   /* default row limit for /events            */
#define HTTP_REQ_BUF     4096  /* bytes for incoming HTTP request          */
#define HTTP_RESP_BUF    (256 * 1024) /* initial response buffer           */

/* ── event type label table (mirrors output.c) ────────────────────────── */

static const char * const g_type_label[EVENT_TYPE_MAX] = {
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
    [EVENT_PRIVESC]     = "privesc",
    [EVENT_MEMEXEC]     = "memexec",
    [EVENT_KMOD_LOAD]   = "kmod_load",
    [EVENT_NET_CORR]    = "net_corr",
    [EVENT_RATE_LIMIT]  = "rate_limit",
    [EVENT_THREAT_INTEL]= "threat_intel",
    [EVENT_TLS_SNI]     = "tls_sni",
    [EVENT_PROC_SCRAPE] = "proc_scrape",
    [EVENT_NS_ESCAPE]   = "ns_escape",
};

static const char *type_name(event_type_t t)
{
    if ((int)t >= 0 && t < EVENT_TYPE_MAX && g_type_label[t])
        return g_type_label[t];
    return "unknown";
}

/* ── async write queue ─────────────────────────────────────────────────── */

typedef struct {
    event_t ev;
    int     used;
} queue_slot_t;

static queue_slot_t  g_queue[QUEUE_CAP];
static int           g_q_head = 0;   /* writer advances head */
static int           g_q_tail = 0;   /* reader advances tail */
static pthread_mutex_t g_q_lock  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_q_cond  = PTHREAD_COND_INITIALIZER;
static volatile int    g_q_stop  = 0;

/* ── statistics ─────────────────────────────────────────────────────────── */

static _Atomic uint64_t g_stat_inserts = 0;
static _Atomic uint64_t g_stat_errors  = 0;

/* ── SQLite state ──────────────────────────────────────────────────────── */

static sqlite3        *g_db       = NULL;
static sqlite3_stmt   *g_ins_stmt = NULL;  /* prepared INSERT */

/* ── HTTP server state ─────────────────────────────────────────────────── */

static int          g_query_port    = 0;
static int          g_listen_fd     = -1;
static volatile int g_http_running  = 0;
static time_t       g_start_time;

/* ── background threads ────────────────────────────────────────────────── */

static pthread_t g_writer_thread;
static pthread_t g_http_thread;

/* ══════════════════════════════════════════════════════════════════════════
 * detail JSON builder
 * ══════════════════════════════════════════════════════════════════════════ */

static void build_detail(const event_t *ev, char *buf, size_t bufsz)
{
    buf[0] = '\0';
    switch (ev->type) {
    case EVENT_EXEC:
        snprintf(buf, bufsz,
            "{\"filename\":\"%s\",\"args\":\"%s\"}",
            ev->filename, ev->args);
        break;
    case EVENT_OPEN:
        snprintf(buf, bufsz,
            "{\"filename\":\"%s\",\"flags\":%u}",
            ev->filename, ev->open_flags);
        break;
    case EVENT_EXIT:
        snprintf(buf, bufsz, "{\"exit_code\":%d}", ev->exit_code);
        break;
    case EVENT_CONNECT:
    case EVENT_BIND:
    case EVENT_THREAT_INTEL: {
        char ip[INET6_ADDRSTRLEN] = {};
        if (ev->family == 2)
            inet_ntop(AF_INET,  ev->daddr, ip, sizeof(ip));
        else
            inet_ntop(AF_INET6, ev->daddr, ip, sizeof(ip));
        snprintf(buf, bufsz,
            "{\"daddr\":\"%s\",\"dport\":%u,\"family\":%u}",
            ip, ev->dport, ev->family);
        break;
    }
    case EVENT_UNLINK:
    case EVENT_WRITE_CLOSE:
    case EVENT_KMOD_LOAD:
        snprintf(buf, bufsz, "{\"filename\":\"%s\"}", ev->filename);
        break;
    case EVENT_RENAME:
        snprintf(buf, bufsz,
            "{\"filename\":\"%s\"}", ev->filename);
        break;
    case EVENT_CHMOD:
        snprintf(buf, bufsz,
            "{\"filename\":\"%s\",\"mode\":%u}",
            ev->filename, ev->mode);
        break;
    case EVENT_PTRACE:
        snprintf(buf, bufsz,
            "{\"ptrace_req\":%d,\"target_pid\":%d}",
            ev->ptrace_req, ev->target_pid);
        break;
    case EVENT_DNS:
    case EVENT_NET_CORR:
    case EVENT_TLS_SNI:
        snprintf(buf, bufsz, "{\"dns_name\":\"%s\"}", ev->dns_name);
        break;
    case EVENT_PRIVESC:
        snprintf(buf, bufsz,
            "{\"uid_before\":%u,\"uid_after\":%u,\"cap_data\":%llu}",
            ev->uid_before, ev->uid_after,
            (unsigned long long)ev->cap_data);
        break;
    case EVENT_MEMEXEC:
        snprintf(buf, bufsz, "{\"prot\":%u}", ev->mode);
        break;
    case EVENT_NS_ESCAPE:
        snprintf(buf, bufsz, "{\"clone_flags\":%u}", ev->mode);
        break;
    case EVENT_PROC_SCRAPE:
        snprintf(buf, bufsz, "{\"target_pid\":%d}", ev->target_pid);
        break;
    case EVENT_SEND:
        snprintf(buf, bufsz, "{\"payload_len\":%u}", ev->mode);
        break;
    default:
        break;
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * SQLite schema + prepared statement
 * ══════════════════════════════════════════════════════════════════════════ */

static const char *g_schema =
    "CREATE TABLE IF NOT EXISTS events ("
    "  id       INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts       INTEGER NOT NULL,"
    "  type     TEXT    NOT NULL,"
    "  pid      INTEGER,"
    "  ppid     INTEGER,"
    "  uid      INTEGER,"
    "  gid      INTEGER,"
    "  comm     TEXT,"
    "  cgroup   TEXT,"
    "  filename TEXT,"
    "  detail   TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts);"
    "CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);"
    "CREATE INDEX IF NOT EXISTS idx_events_comm ON events(comm);";

static const char *g_ins_sql =
    "INSERT INTO events(ts,type,pid,ppid,uid,gid,comm,cgroup,filename,detail)"
    " VALUES (?,?,?,?,?,?,?,?,?,?);";

static int db_open(const char *path)
{
    if (sqlite3_open(path, &g_db) != SQLITE_OK) {
        fprintf(stderr, "[store] sqlite3_open(%s): %s\n",
                path, sqlite3_errmsg(g_db));
        return -1;
    }
    /* WAL mode for better concurrent read/write performance */
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    char *errmsg = NULL;
    if (sqlite3_exec(g_db, g_schema, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "[store] schema error: %s\n", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    if (sqlite3_prepare_v2(g_db, g_ins_sql, -1, &g_ins_stmt, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "[store] prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Background writer thread
 * ══════════════════════════════════════════════════════════════════════════ */

static void insert_event(const event_t *ev)
{
    char detail[512];
    build_detail(ev, detail, sizeof(detail));

    sqlite3_reset(g_ins_stmt);
    sqlite3_bind_int64(g_ins_stmt, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_text (g_ins_stmt, 2, type_name(ev->type), -1, SQLITE_STATIC);
    sqlite3_bind_int  (g_ins_stmt, 3, ev->pid);
    sqlite3_bind_int  (g_ins_stmt, 4, ev->ppid);
    sqlite3_bind_int  (g_ins_stmt, 5, (int)ev->uid);
    sqlite3_bind_int  (g_ins_stmt, 6, (int)ev->gid);
    sqlite3_bind_text (g_ins_stmt, 7, ev->comm,   -1, SQLITE_STATIC);
    sqlite3_bind_text (g_ins_stmt, 8, ev->cgroup, -1, SQLITE_STATIC);
    sqlite3_bind_text (g_ins_stmt, 9, ev->filename[0] ? ev->filename : NULL,
                       -1, SQLITE_STATIC);
    sqlite3_bind_text (g_ins_stmt, 10, detail[0] ? detail : NULL,
                       -1, SQLITE_STATIC);
    if (sqlite3_step(g_ins_stmt) == SQLITE_DONE)
        atomic_fetch_add(&g_stat_inserts, 1);
    else
        atomic_fetch_add(&g_stat_errors, 1);
}

static void *writer_thread(void *arg)
{
    (void)arg;

    while (1) {
        /* Collect up to BATCH_MAX events from the queue */
        event_t batch[BATCH_MAX];
        int     n = 0;

        pthread_mutex_lock(&g_q_lock);
        while (!g_q_stop && g_q_head == g_q_tail) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec++;
            pthread_cond_timedwait(&g_q_cond, &g_q_lock, &ts);
        }

        while (n < BATCH_MAX && g_q_tail != g_q_head) {
            batch[n++] = g_queue[g_q_tail].ev;
            g_queue[g_q_tail].used = 0;
            g_q_tail = (g_q_tail + 1) % QUEUE_CAP;
        }
        int should_stop = g_q_stop && (g_q_tail == g_q_head);
        pthread_mutex_unlock(&g_q_lock);

        if (n > 0) {
            sqlite3_exec(g_db, "BEGIN;", NULL, NULL, NULL);
            for (int i = 0; i < n; i++)
                insert_event(&batch[i]);
            sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL);
        }

        if (should_stop)
            break;
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Minimal HTTP helpers
 * ══════════════════════════════════════════════════════════════════════════ */

/* Extract query param value from a URL query string.
 * ?key=value&... — copies value into dst (up to dstsz-1 bytes). */
static int get_param(const char *qs, const char *key,
                     char *dst, size_t dstsz)
{
    if (!qs || !*qs) return 0;
    size_t klen = strlen(key);
    const char *p = qs;
    while (*p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            p += klen + 1;
            size_t i = 0;
            while (*p && *p != '&' && i < dstsz - 1)
                dst[i++] = *p++;
            dst[i] = '\0';
            return 1;
        }
        /* advance to next param */
        while (*p && *p != '&') p++;
        if (*p == '&') p++;
    }
    return 0;
}

/* Write an exact number of bytes to a socket fd */
static void send_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n <= 0) break;
        buf += n;
        len -= (size_t)n;
    }
}

/* ── /stats handler ──────────────────────────────────────────────────────── */

static void handle_stats(int cfd)
{
    /* total row count */
    sqlite3_stmt *st = NULL;
    long long total = 0;
    if (sqlite3_prepare_v2(g_db, "SELECT COUNT(*) FROM events;",
                           -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)
            total = (long long)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }

    /* DB file size */
    long long db_sz = 0;
    sqlite3_stmt *ps = NULL;
    if (sqlite3_prepare_v2(g_db, "PRAGMA page_count;",
                           -1, &ps, NULL) == SQLITE_OK) {
        long long pcount = 0, psize = 0;
        if (sqlite3_step(ps) == SQLITE_ROW)
            pcount = (long long)sqlite3_column_int64(ps, 0);
        sqlite3_finalize(ps);

        sqlite3_stmt *ps2 = NULL;
        if (sqlite3_prepare_v2(g_db, "PRAGMA page_size;",
                               -1, &ps2, NULL) == SQLITE_OK) {
            if (sqlite3_step(ps2) == SQLITE_ROW)
                psize = (long long)sqlite3_column_int64(ps2, 0);
            sqlite3_finalize(ps2);
        }
        db_sz = pcount * psize;
    }

    long long uptime = (long long)(time(NULL) - g_start_time);

    char body[256];
    int blen = snprintf(body, sizeof(body),
        "{\"total_events\":%lld,\"db_size_bytes\":%lld,\"uptime_secs\":%lld}\n",
        total, db_sz, uptime);

    char hdr[256];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n", blen);

    send_all(cfd, hdr, (size_t)hlen);
    send_all(cfd, body, (size_t)blen);
}

/* ── /events handler ─────────────────────────────────────────────────────── */

static void handle_events(int cfd, const char *qs)
{
    char p_type[64]  = {};
    char p_comm[64]  = {};
    char p_since[32] = {};
    char p_limit[32] = {};

    get_param(qs, "type",  p_type,  sizeof(p_type));
    get_param(qs, "comm",  p_comm,  sizeof(p_comm));
    get_param(qs, "since", p_since, sizeof(p_since));
    get_param(qs, "limit", p_limit, sizeof(p_limit));

    int limit = p_limit[0] ? atoi(p_limit) : HTTP_DEF_LIMIT;
    if (limit <= 0 || limit > HTTP_MAX_ROWS)
        limit = HTTP_DEF_LIMIT;

    /* Build query */
    char sql[1024];
    int  off = 0;
    off += snprintf(sql + off, sizeof(sql) - (size_t)off,
        "SELECT ts,type,pid,ppid,uid,gid,comm,cgroup,filename,detail"
        " FROM events WHERE 1=1");

    if (p_type[0])
        off += snprintf(sql + off, sizeof(sql) - (size_t)off,
            " AND type='%s'", p_type);          /* safe: bounded, no user SQL */
    if (p_comm[0])
        off += snprintf(sql + off, sizeof(sql) - (size_t)off,
            " AND comm='%s'", p_comm);
    if (p_since[0])
        off += snprintf(sql + off, sizeof(sql) - (size_t)off,
            " AND ts>=%s", p_since);

    snprintf(sql + off, sizeof(sql) - (size_t)off,
        " ORDER BY ts DESC LIMIT %d;", limit);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) {
        const char *err =
            "HTTP/1.0 500 Internal Server Error\r\n"
            "Content-Length: 0\r\nConnection: close\r\n\r\n";
        send_all(cfd, err, strlen(err));
        return;
    }

    const char *hdr =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/x-ndjson\r\n"
        "Connection: close\r\n"
        "\r\n";
    send_all(cfd, hdr, strlen(hdr));

    char row[1024];
    while (sqlite3_step(st) == SQLITE_ROW) {
        long long ts  = sqlite3_column_int64(st, 0);
        const char *tp  = (const char *)sqlite3_column_text(st, 1);
        int pid  = sqlite3_column_int(st, 2);
        int ppid = sqlite3_column_int(st, 3);
        int uid  = sqlite3_column_int(st, 4);
        int gid  = sqlite3_column_int(st, 5);
        const char *comm  = (const char *)sqlite3_column_text(st, 6);
        const char *cgrp  = (const char *)sqlite3_column_text(st, 7);
        const char *fname = (const char *)sqlite3_column_text(st, 8);
        const char *det   = (const char *)sqlite3_column_text(st, 9);

        int n = snprintf(row, sizeof(row),
            "{\"ts\":%lld,\"type\":\"%s\",\"pid\":%d,\"ppid\":%d,"
            "\"uid\":%d,\"gid\":%d,\"comm\":\"%s\",\"cgroup\":\"%s\","
            "\"filename\":\"%s\",\"detail\":%s}\n",
            ts,
            tp    ? tp    : "",
            pid, ppid, uid, gid,
            comm  ? comm  : "",
            cgrp  ? cgrp  : "",
            fname ? fname : "",
            det   ? det   : "null");
        if (n > 0)
            send_all(cfd, row, (size_t)n);
    }
    sqlite3_finalize(st);
}

/* ── 404 handler ─────────────────────────────────────────────────────────── */

static void handle_404(int cfd)
{
    const char *resp =
        "HTTP/1.0 404 Not Found\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n";
    send_all(cfd, resp, strlen(resp));
}

/* ── HTTP request dispatcher ─────────────────────────────────────────────── */

static void dispatch(int cfd)
{
    char buf[HTTP_REQ_BUF];
    ssize_t n = recv(cfd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return;
    buf[n] = '\0';

    /* Only handle GET */
    if (strncmp(buf, "GET ", 4) != 0) {
        handle_404(cfd);
        return;
    }

    /* Extract path (and optional query string) from first request line */
    char *path_start = buf + 4;
    char *path_end   = strchr(path_start, ' ');
    if (!path_end) { handle_404(cfd); return; }
    *path_end = '\0';

    char *qs = strchr(path_start, '?');
    if (qs) *qs++ = '\0';

    if (strcmp(path_start, "/events") == 0)
        handle_events(cfd, qs ? qs : "");
    else if (strcmp(path_start, "/stats") == 0)
        handle_stats(cfd);
    else
        handle_404(cfd);
}

/* ── HTTP listener thread ────────────────────────────────────────────────── */

static void *http_thread(void *arg)
{
    (void)arg;

    while (g_http_running) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_listen_fd, &rfds);

        int rc = select(g_listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) continue;

        struct sockaddr_in cli = {};
        socklen_t slen = sizeof(cli);
        int cfd = accept(g_listen_fd, (struct sockaddr *)&cli, &slen);
        if (cfd < 0) continue;

        dispatch(cfd);
        close(cfd);
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Public API
 * ══════════════════════════════════════════════════════════════════════════ */

void store_init(const char *db_path, int query_port)
{
    if (!db_path || !db_path[0]) return;

    g_start_time = time(NULL);

    if (db_open(db_path) != 0) {
        fprintf(stderr, "[store] failed to open database %s\n", db_path);
        return;
    }

    /* Start background writer */
    g_q_stop = 0;
    if (pthread_create(&g_writer_thread, NULL, writer_thread, NULL) != 0) {
        fprintf(stderr, "[store] failed to create writer thread\n");
        return;
    }

    /* Optionally start HTTP query server */
    if (query_port > 0) {
        g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (g_listen_fd < 0) {
            fprintf(stderr, "[store] socket: %s\n", strerror(errno));
            goto http_done;
        }

        int one = 1;
        setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        struct sockaddr_in addr = {};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons((uint16_t)query_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(g_listen_fd,
                 (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
            listen(g_listen_fd, 8) < 0) {
            fprintf(stderr, "[store] bind/listen on port %d: %s\n",
                    query_port, strerror(errno));
            close(g_listen_fd);
            g_listen_fd = -1;
            goto http_done;
        }

        g_query_port   = query_port;
        g_http_running = 1;

        if (pthread_create(&g_http_thread, NULL, http_thread, NULL) != 0) {
            fprintf(stderr, "[store] failed to create HTTP thread\n");
            close(g_listen_fd);
            g_listen_fd    = -1;
            g_http_running = 0;
        }
    }
http_done:;
}

void store_event(const event_t *ev)
{
    if (!g_db || !ev) return;

    pthread_mutex_lock(&g_q_lock);
    int next = (g_q_head + 1) % QUEUE_CAP;
    if (next == g_q_tail) {
        /* Queue full — drop event silently to stay non-blocking */
        pthread_mutex_unlock(&g_q_lock);
        return;
    }
    g_queue[g_q_head].ev   = *ev;
    g_queue[g_q_head].used = 1;
    g_q_head = next;
    pthread_cond_signal(&g_q_cond);
    pthread_mutex_unlock(&g_q_lock);
}

void store_stats(uint64_t *inserts, uint64_t *errors)
{
    if (inserts) *inserts = atomic_load(&g_stat_inserts);
    if (errors)  *errors  = atomic_load(&g_stat_errors);
}

void store_destroy(void)
{
    /* Stop HTTP server */
    if (g_http_running) {
        g_http_running = 0;
        if (g_listen_fd >= 0) {
            close(g_listen_fd);
            g_listen_fd = -1;
        }
        pthread_join(g_http_thread, NULL);
    }

    /* Signal writer to drain and exit */
    pthread_mutex_lock(&g_q_lock);
    g_q_stop = 1;
    pthread_cond_signal(&g_q_cond);
    pthread_mutex_unlock(&g_q_lock);
    pthread_join(g_writer_thread, NULL);

    /* Close DB */
    if (g_ins_stmt) { sqlite3_finalize(g_ins_stmt); g_ins_stmt = NULL; }
    if (g_db)       { sqlite3_close(g_db);          g_db       = NULL; }

    g_query_port = 0;
}

#endif /* HAVE_SQLITE3 */
