/*
 * argus-server — fleet aggregator for multiple argus agents.
 *
 * Accepts NDJSON event streams from argus instances (--forward host:port),
 * merges them in real-time, adds a "host" field from the remote IP, and
 * re-emits the combined stream on stdout or to a file.
 *
 * Usage:
 *   argus-server [--port <N>] [--output <path>] [--stats-interval <secs>]
 *                [--correlate-window <secs>] [--correlate-threshold <N>]
 *
 * Each connected argus client sends {"type":"...","pid":...,...}\n lines.
 * argus-server injects "host":"<remote-ip>" into every object and writes
 * the result to the output sink.
 *
 * Fleet correlation engine:
 *   Tracks IOCs (IP+port for CONNECT/THREAT_INTEL, filename for EXEC/OPEN/
 *   WRITE_CLOSE/UNLINK, comm for PRIVESC/KMOD_LOAD) across all connected
 *   sensors.  When the same IOC is seen from >= correlate_threshold distinct
 *   hosts within correlate_window seconds a [FLEET] alert is emitted to
 *   stderr and injected into the output stream.
 *
 * Supports up to 64 simultaneous agent connections using select().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define DEFAULT_PORT     9000
#define MAX_CLIENTS      64
#define LINE_BUF_SZ      4096
#define HB_TIMEOUT_S     300   /* close clients silent for this many seconds  */

/* forward declaration — defined in globals section below */
static FILE *g_out;

/* ── fleet correlation engine ────────────────────────────────────────────── */

#define CORR_SLOTS      2048   /* hash table size for IOC tracking            */
#define CORR_MAX_HOSTS  16     /* max unique hosts tracked per IOC slot       */
#define CORR_KEY_SZ     192    /* max IOC key string length                   */

typedef struct {
    char   key[CORR_KEY_SZ];          /* "TYPE:value" e.g. "CONNECT:1.2.3.4:443" */
    char   hosts[CORR_MAX_HOSTS][INET6_ADDRSTRLEN];
    time_t times[CORR_MAX_HOSTS];
    int    n_hosts;
    int    alerted;
} corr_entry_t;

static corr_entry_t g_corr[CORR_SLOTS];
static int          g_corr_window    = 60;   /* seconds */
static int          g_corr_threshold = 3;    /* distinct hosts to fire alert */

static unsigned int corr_hash(const char *key)
{
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*key++))
        h = ((h << 5) + h) + (unsigned long)c;
    return (unsigned int)(h % CORR_SLOTS);
}

/* Extract a JSON string value for a given key; returns 1 on success */
static int json_str(const char *json, const char *field,
                    char *out, size_t outsz)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", field);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ') p++;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < outsz - 1) out[i++] = *p++;
    out[i] = '\0';
    return i > 0 ? 1 : 0;
}

/* Build a canonical IOC key from a JSON event line; returns 1 on success */
static int corr_make_key(const char *line, char *key, size_t keysz)
{
    char type[32]     = {};
    char filename[192]= {};
    char daddr[64]    = {};
    char dport[16]    = {};
    char comm[32]     = {};

    if (!json_str(line, "type", type, sizeof(type)))
        return 0;

    /* CONNECT / THREAT_INTEL → key on dest IP + port */
    if (strcmp(type, "CONNECT") == 0 || strcmp(type, "THREAT_INTEL") == 0) {
        json_str(line, "daddr", daddr, sizeof(daddr));
        json_str(line, "dport", dport, sizeof(dport));
        if (!daddr[0]) return 0;
        snprintf(key, keysz, "%s:%s:%s", type, daddr, dport);
        return 1;
    }

    /* EXEC / OPEN / WRITE_CLOSE / UNLINK / KMOD_LOAD → key on filename */
    if (strcmp(type, "EXEC") == 0      || strcmp(type, "OPEN") == 0 ||
        strcmp(type, "WRITE_CLOSE") == 0|| strcmp(type, "UNLINK") == 0 ||
        strcmp(type, "KMOD_LOAD") == 0) {
        json_str(line, "filename", filename, sizeof(filename));
        if (!filename[0]) return 0;
        snprintf(key, keysz, "%s:%s", type, filename);
        return 1;
    }

    /* PRIVESC / NS_ESCAPE / PTRACE → key on comm */
    if (strcmp(type, "PRIVESC") == 0 || strcmp(type, "NS_ESCAPE") == 0 ||
        strcmp(type, "PTRACE") == 0) {
        json_str(line, "comm", comm, sizeof(comm));
        if (!comm[0]) return 0;
        snprintf(key, keysz, "%s:%s", type, comm);
        return 1;
    }

    return 0;   /* event type not tracked */
}

/* Record an IOC sighting from host; returns 1 if alert threshold reached. */
static int corr_record(const char *key, const char *host)
{
    if (!g_corr_threshold || !g_corr_window)
        return 0;

    time_t now = time(NULL);
    unsigned int slot = corr_hash(key);

    /* Linear probe */
    for (unsigned int i = 0; i < CORR_SLOTS; i++) {
        unsigned int idx = (slot + i) % CORR_SLOTS;
        corr_entry_t *e  = &g_corr[idx];

        if (!e->key[0]) {
            /* Empty slot — insert */
            strncpy(e->key, key, CORR_KEY_SZ - 1);
            strncpy(e->hosts[0], host, INET6_ADDRSTRLEN - 1);
            e->times[0]  = now;
            e->n_hosts   = 1;
            e->alerted   = 0;
            return 0;
        }

        if (strncmp(e->key, key, CORR_KEY_SZ) != 0)
            continue;

        if (e->alerted)
            return 0;   /* already fired, don't re-alert */

        /* Expire old sightings outside the window */
        int fresh = 0;
        for (int j = 0; j < e->n_hosts; j++) {
            if (now - e->times[j] <= (time_t)g_corr_window) {
                if (j != fresh) {
                    memcpy(e->hosts[fresh], e->hosts[j], INET6_ADDRSTRLEN);
                    e->times[fresh] = e->times[j];
                }
                fresh++;
            }
        }
        e->n_hosts = fresh;

        /* Check if this host is already recorded */
        for (int j = 0; j < e->n_hosts; j++)
            if (strcmp(e->hosts[j], host) == 0) {
                e->times[j] = now;   /* refresh */
                goto check_threshold;
            }

        /* Add new host */
        if (e->n_hosts < CORR_MAX_HOSTS) {
            strncpy(e->hosts[e->n_hosts], host, INET6_ADDRSTRLEN - 1);
            e->times[e->n_hosts] = now;
            e->n_hosts++;
        }

    check_threshold:
        if (e->n_hosts >= g_corr_threshold) {
            e->alerted = 1;
            return 1;
        }
        return 0;
    }
    return 0;
}

/* Emit a fleet correlation alert */
static void corr_alert(const char *key, const char *line, const char *host)
{
    FILE *out = g_out ? g_out : stdout;

    fprintf(stderr,
        "[FLEET] IOC seen on %d+ hosts: %s  (latest from %s)\n",
        g_corr_threshold, key, host);

    /* Also inject a synthetic alert event into the output stream */
    fprintf(out,
        "{\"host\":\"fleet\",\"type\":\"FLEET_CORR\","
        "\"ioc\":\"%s\","
        "\"threshold\":%d,"
        "\"window\":%d,"
        "\"trigger_host\":\"%s\"}\n",
        key, g_corr_threshold, g_corr_window, host);
    fflush(out);
    (void)line;
}

/* ── per-client state ────────────────────────────────────────────────────── */

typedef struct {
    int    fd;
    char   remote_ip[INET6_ADDRSTRLEN];
    char   buf[LINE_BUF_SZ];
    int    buf_len;
    uint64_t lines;        /* lines received from this client */
    time_t   connected_at; /* unix timestamp of connect       */
    time_t   last_hb;      /* unix timestamp of last HEARTBEAT */
    char     version[32];  /* agent version from HEARTBEAT    */
    uint64_t agent_uptime; /* agent uptime_secs from HEARTBEAT */
    char     agent_id[128];/* stable agent hostname/ID from HEARTBEAT; used
                            * to detect reconnects from same sensor         */
} client_t;

/* ── globals ─────────────────────────────────────────────────────────────── */

static volatile int g_running = 1;
static FILE        *g_out     = NULL;    /* NULL = stdout */
static client_t     g_clients[MAX_CLIENTS];
static int          g_nclients = 0;
static uint64_t     g_total_lines = 0;

static void sig_handler(int s) { (void)s; g_running = 0; }

/* ── JSON line injection: insert "host":"<ip>" after opening '{' ──────────── */

static void emit_with_host(const char *line, const char *host)
{
    FILE *out = g_out ? g_out : stdout;

    /*
     * Input:  {"type":"EXEC",...}
     * Output: {"host":"1.2.3.4","type":"EXEC",...}
     */
    if (line[0] != '{') {
        fputs(line, out);
        fputc('\n', out);
        return;
    }

    fputc('{', out);
    fprintf(out, "\"host\":\"");
    /* JSON-escape the IP (safe — only contains [0-9a-fA-F:.]) */
    for (const char *p = host; *p; p++) fputc(*p, out);
    fputc('"', out);

    /* Append the rest of the line after '{' */
    const char *rest = line + 1;
    if (*rest == '}')
        fputc('}', out);
    else {
        fputc(',', out);
        fputs(rest, out);
    }
    fputc('\n', out);
    fflush(out);
}

/* ── accept new client ───────────────────────────────────────────────────── */

static void accept_client(int listen_fd)
{
    if (g_nclients >= MAX_CLIENTS) {
        /* Too many connections — accept and immediately close */
        int fd = accept(listen_fd, NULL, NULL);
        if (fd >= 0) close(fd);
        return;
    }

    struct sockaddr_in6 addr = {};
    socklen_t slen = sizeof(addr);
    int fd = accept(listen_fd, (struct sockaddr *)&addr, &slen);
    if (fd < 0) return;

    client_t *c = NULL;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].fd < 0) { c = &g_clients[i]; break; }
    }
    if (!c) { close(fd); return; }

    c->fd      = fd;
    c->buf_len = 0;
    c->lines   = 0;
    memset(c->buf, 0, sizeof(c->buf));

    /* Extract remote IP */
    if (addr.sin6_family == AF_INET6) {
        /* May be IPv4-mapped */
        const uint8_t *a = (const uint8_t *)&addr.sin6_addr;
        if (a[10] == 0xff && a[11] == 0xff) {
            /* IPv4-mapped ::ffff:a.b.c.d */
            struct in_addr v4;
            memcpy(&v4, a + 12, 4);
            inet_ntop(AF_INET, &v4, c->remote_ip, sizeof(c->remote_ip));
        } else {
            inet_ntop(AF_INET6, &addr.sin6_addr, c->remote_ip, sizeof(c->remote_ip));
        }
    } else {
        inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr,
                  c->remote_ip, sizeof(c->remote_ip));
    }

    c->connected_at = time(NULL);
    c->last_hb      = 0;
    c->version[0]   = '\0';
    c->agent_id[0]  = '\0';
    c->agent_uptime = 0;
    g_nclients++;
    fprintf(stderr, "info: client connected from %s (fd=%d, total=%d)\n",
            c->remote_ip, fd, g_nclients);
}

/* ── read data from client, process complete lines ───────────────────────── */

static void read_client(client_t *c)
{
    ssize_t n = recv(c->fd, c->buf + c->buf_len,
                     (size_t)(LINE_BUF_SZ - c->buf_len - 1), 0);
    if (n <= 0) {
        /* Connection closed or error */
        fprintf(stderr, "info: client %s disconnected (%llu lines received)\n",
                c->remote_ip, (unsigned long long)c->lines);
        close(c->fd);
        c->fd = -1;
        g_nclients--;
        return;
    }
    c->buf_len += (int)n;
    c->buf[c->buf_len] = '\0';

    /* Process all complete lines in the buffer */
    char *start = c->buf;
    char *nl;
    while ((nl = memchr(start, '\n', (size_t)(c->buf + c->buf_len - start))) != NULL) {
        *nl = '\0';
        /* Skip empty lines */
        if (start[0] != '\0') {
            emit_with_host(start, c->remote_ip);
            c->lines++;
            g_total_lines++;

            /* Heartbeat tracking — parse HEARTBEAT events to update agent state */
            if (strstr(start, "\"type\":\"HEARTBEAT\"")) {
                c->last_hb = time(NULL);

                /* Parse version string */
                const char *vp = strstr(start, "\"version\":\"");
                if (vp) {
                    vp += 11;
                    const char *ve = strchr(vp, '"');
                    if (ve) {
                        size_t vl = (size_t)(ve - vp);
                        if (vl >= sizeof(c->version)) vl = sizeof(c->version) - 1;
                        memcpy(c->version, vp, vl);
                        c->version[vl] = '\0';
                    }
                }

                /* Parse uptime */
                const char *up = strstr(start, "\"uptime_secs\":");
                if (up) c->agent_uptime = (uint64_t)strtoull(up + 14, NULL, 10);

                /* Parse agent_id (hostname) for reconnect deduplication */
                const char *hp = strstr(start, "\"hostname\":\"");
                if (hp) {
                    hp += 12;
                    const char *he = strchr(hp, '"');
                    if (he) {
                        size_t hl = (size_t)(he - hp);
                        if (hl >= sizeof(c->agent_id)) hl = sizeof(c->agent_id) - 1;
                        memcpy(c->agent_id, hp, hl);
                        c->agent_id[hl] = '\0';

                        /* Dedup: close any stale connection from the same agent.
                         * This handles the case where a sensor crashes and
                         * reconnects before the server detects the old TCP drop. */
                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            client_t *o = &g_clients[j];
                            if (o == c || o->fd < 0 || !o->agent_id[0]) continue;
                            if (strcmp(o->agent_id, c->agent_id) == 0) {
                                fprintf(stderr,
                                    "info: evicting stale connection fd=%d ip=%s "
                                    "(agent '%s' reconnected from %s)\n",
                                    o->fd, o->remote_ip, c->agent_id, c->remote_ip);
                                close(o->fd);
                                o->fd = -1;
                                g_nclients--;
                            }
                        }
                    }
                }
            }

            /* Fleet correlation */
            char corr_key[CORR_KEY_SZ];
            if (corr_make_key(start, corr_key, sizeof(corr_key))) {
                if (corr_record(corr_key, c->remote_ip))
                    corr_alert(corr_key, start, c->remote_ip);
            }
        }
        start = nl + 1;
    }

    /* Shift remaining partial line to the front */
    int remaining = (int)(c->buf + c->buf_len - start);
    if (remaining > 0 && start != c->buf)
        memmove(c->buf, start, (size_t)remaining);
    else if (remaining == 0)
        start = c->buf;   /* reset */
    c->buf_len = remaining;

    /* Safety: if buffer is full with no newline, discard */
    if (c->buf_len >= LINE_BUF_SZ - 1) {
        c->buf_len = 0;
    }
}

/* ── usage ───────────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "argus-server — fleet aggregator: accepts NDJSON streams from argus\n"
        "agents, re-emits them with a \"host\" field, and correlates IOCs\n"
        "across multiple sensors.\n"
        "\n"
        "Options:\n"
        "  --port                <N>     Listen port (default: %d)\n"
        "  --output              <path>  Write merged stream to file (default: stdout)\n"
        "  --stats-interval      <secs>  Print connection stats every N seconds (0=off)\n"
        "  --correlate-window    <secs>  Fleet correlation time window (default: 60)\n"
        "  --correlate-threshold <N>     Distinct hosts to trigger fleet alert (default: 3)\n"
        "  --mgmt-port           <N>     Management HTTP API port on 127.0.0.1 (0=off)\n"
        "                                  GET /agents — connected sensor health\n"
        "                                  GET /stats  — server statistics\n"
        "  --hb-timeout          <secs>  Close agents silent for this long (default: %d)\n"
        "                                  0 disables the timeout\n"
        "  --help                        Show this message\n",
        prog, DEFAULT_PORT, HB_TIMEOUT_S);
}

/* ── management HTTP server (/agents endpoint) ───────────────────────────── */

static int g_mgmt_port   = 0;
static int g_hb_timeout  = HB_TIMEOUT_S;   /* CLI-overridable */
static time_t g_start_time = 0;

static void *mgmt_server_thread(void *arg)
{
    (void)arg;
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return NULL;
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = {};
    a.sin_family      = AF_INET;
    a.sin_port        = htons((uint16_t)g_mgmt_port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(srv, (struct sockaddr *)&a, sizeof(a)) < 0 ||
        listen(srv, 4) < 0) { close(srv); return NULL; }

    fprintf(stderr, "info: management API on 127.0.0.1:%d\n", g_mgmt_port);

    while (g_running) {
        struct timeval tv = {1, 0};
        fd_set rs; FD_ZERO(&rs); FD_SET(srv, &rs);
        if (select(srv + 1, &rs, NULL, NULL, &tv) <= 0) continue;
        int cl = accept(srv, NULL, NULL);
        if (cl < 0) continue;

        /* Read request line (just need to know if /agents or /stats) */
        char req[512] = {};
        recv(cl, req, sizeof(req) - 1, 0);

        char body[8192] = {};
        time_t now = time(NULL);

        if (strstr(req, "GET /agents")) {
            /* JSON array of connected agent summaries */
            size_t pos = 0;
            pos += (size_t)snprintf(body + pos, sizeof(body) - pos, "[");
            int first = 1;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (g_clients[i].fd < 0) continue;
                client_t *c = &g_clients[i];
                long secs_since_hb = c->last_hb ? (long)(now - c->last_hb) : -1;
                const char *status = (secs_since_hb < 0)   ? "new"
                                   : (secs_since_hb < 90)  ? "healthy"
                                   : (secs_since_hb < 300) ? "stale"
                                                            : "missing";
                pos += (size_t)snprintf(body + pos, sizeof(body) - pos,
                    "%s{\"ip\":\"%s\",\"version\":\"%s\","
                    "\"uptime_secs\":%llu,\"connected_secs\":%ld,"
                    "\"lines\":%llu,\"last_heartbeat_secs\":%ld,"
                    "\"status\":\"%s\"}",
                    first ? "" : ",",
                    c->remote_ip,
                    c->version[0] ? c->version : "unknown",
                    (unsigned long long)c->agent_uptime,
                    (long)(now - c->connected_at),
                    (unsigned long long)c->lines,
                    secs_since_hb,
                    status);
                first = 0;
            }
            snprintf(body + pos, sizeof(body) - pos, "]");
        } else if (strstr(req, "GET /stats")) {
            snprintf(body, sizeof(body),
                "{\"agents\":%d,\"total_lines\":%llu,"
                "\"uptime_secs\":%ld,\"corr_window\":%d,"
                "\"corr_threshold\":%d}",
                g_nclients,
                (unsigned long long)g_total_lines,
                (long)(now - g_start_time),
                g_corr_window, g_corr_threshold);
        } else {
            const char *r404 = "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            send(cl, r404, strlen(r404), 0);
            close(cl);
            continue;
        }

        char hdr[256];
        snprintf(hdr, sizeof(hdr),
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
            "Content-Length: %zu\r\nConnection: close\r\n\r\n", strlen(body));
        send(cl, hdr,  strlen(hdr),  0);
        send(cl, body, strlen(body), 0);
        close(cl);
    }
    close(srv);
    return NULL;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    int  port           = DEFAULT_PORT;
    char output_path[256] = {};
    int  stats_interval = 60;

    static const struct option long_opts[] = {
        {"port",                required_argument, 0, 'p'},
        {"output",              required_argument, 0, 'o'},
        {"stats-interval",      required_argument, 0, 's'},
        {"correlate-window",    required_argument, 0, 'w'},
        {"correlate-threshold", required_argument, 0, 'c'},
        {"mgmt-port",           required_argument, 0, 'm'},
        {"hb-timeout",          required_argument, 0, 't'},
        {"help",                no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:o:s:w:c:m:t:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': port = atoi(optarg); break;
        case 'o': strncpy(output_path, optarg, sizeof(output_path) - 1); break;
        case 's': stats_interval = atoi(optarg); break;
        case 'w': g_corr_window    = atoi(optarg); break;
        case 'c': g_corr_threshold = atoi(optarg); break;
        case 'm': g_mgmt_port      = atoi(optarg); break;
        case 't': g_hb_timeout     = atoi(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (output_path[0]) {
        g_out = fopen(output_path, "a");
        if (!g_out) { perror("error: could not open output file"); return 1; }
    }

    /* Initialise client slots */
    for (int i = 0; i < MAX_CLIENTS; i++) g_clients[i].fd = -1;

    /* Create listen socket (IPv6 with IPV6_V6ONLY=0 → accepts IPv4-mapped too) */
    int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        /* Fall back to IPv4 if IPv6 is unavailable */
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) { perror("socket"); return 1; }
        int one = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in a4 = {};
        a4.sin_family      = AF_INET;
        a4.sin_port        = htons((uint16_t)port);
        a4.sin_addr.s_addr = INADDR_ANY;
        if (bind(listen_fd, (struct sockaddr *)&a4, sizeof(a4)) < 0 ||
            listen(listen_fd, 16) < 0) {
            perror("bind/listen"); return 1;
        }
    } else {
        int one = 1, zero = 0;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
        struct sockaddr_in6 a6 = {};
        a6.sin6_family = AF_INET6;
        a6.sin6_port   = htons((uint16_t)port);
        a6.sin6_addr   = in6addr_any;
        if (bind(listen_fd, (struct sockaddr *)&a6, sizeof(a6)) < 0 ||
            listen(listen_fd, 16) < 0) {
            perror("bind/listen"); return 1;
        }
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    g_start_time = time(NULL);
    if (g_mgmt_port > 0) {
        pthread_t mt;
        pthread_create(&mt, NULL, mgmt_server_thread, NULL);
        pthread_detach(mt);
    }

    fprintf(stderr, "info: argus-server listening on port %d\n", port);

    time_t last_stats = time(NULL);

    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        int max_fd = listen_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (g_clients[i].fd >= 0) {
                FD_SET(g_clients[i].fd, &rfds);
                if (g_clients[i].fd > max_fd) max_fd = g_clients[i].fd;
            }
        }

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int rc = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0 && errno == EINTR) break;
        if (rc < 0) { perror("select"); break; }

        if (FD_ISSET(listen_fd, &rfds))
            accept_client(listen_fd);

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (g_clients[i].fd >= 0 && FD_ISSET(g_clients[i].fd, &rfds))
                read_client(&g_clients[i]);
        }

        /* Periodic stats + stale-client sweep */
        {
            time_t now = time(NULL);

            /* Sweep for agents that stopped sending heartbeats */
            for (int i = 0; i < MAX_CLIENTS; i++) {
                client_t *sc = &g_clients[i];
                if (sc->fd < 0) continue;
                /* Only enforce timeout once we have received at least one hb */
                if (sc->last_hb > 0 &&
                    (now - sc->last_hb) > g_hb_timeout) {
                    fprintf(stderr,
                        "info: closing %s (fd=%d) — no heartbeat for %lds\n",
                        sc->remote_ip, sc->fd, (long)(now - sc->last_hb));
                    close(sc->fd);
                    sc->fd = -1;
                    g_nclients--;
                }
            }

            if (stats_interval > 0 && now - last_stats >= stats_interval) {
                last_stats = now;
                fprintf(stderr, "stats: clients=%d total_lines=%llu\n",
                        g_nclients, (unsigned long long)g_total_lines);
            }
        }
    }

    /* Cleanup */
    close(listen_fd);
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (g_clients[i].fd >= 0) close(g_clients[i].fd);
    if (g_out) fclose(g_out);

    fprintf(stderr, "info: argus-server stopped (total lines: %llu)\n",
            (unsigned long long)g_total_lines);
    return 0;
}
