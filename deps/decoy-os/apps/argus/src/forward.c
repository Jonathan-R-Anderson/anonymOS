#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif
#include "forward.h"
#include "output.h"
#include "argus.h"

#define RECONNECT_MIN_S   1
#define RECONNECT_MAX_S  30

/* ── per-target state ─────────────────────────────────────────────────────── */

typedef struct {
    char     host[256];
    int      port;
    int      flags;              /* FORWARD_FLAG_* */
    int      sock;               /* -1 = not connected */
    time_t   retry_at;
    int      backoff;
    uint64_t dropped;            /* drops not yet reported to remote */
#ifdef HAVE_OPENSSL
    SSL_CTX *ssl_ctx;
    SSL     *ssl;
#endif
} fwd_t;

static fwd_t g_fwd[FORWARD_MAX_TARGETS];
static int   g_fwd_n = 0;

/* ── helpers ─────────────────────────────────────────────────────────────── */

static int set_nonblocking(int fd)
{
    int f = fcntl(fd, F_GETFL, 0);
    if (f < 0) return -1;
    return fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

static void fwd_close(fwd_t *f)
{
#ifdef HAVE_OPENSSL
    if (f->ssl) {
        SSL_shutdown(f->ssl);
        SSL_free(f->ssl);
        f->ssl = NULL;
    }
#endif
    if (f->sock >= 0) {
        shutdown(f->sock, SHUT_RDWR);
        close(f->sock);
        f->sock = -1;
    }
    f->retry_at = time(NULL) + f->backoff;
    f->backoff   = f->backoff < RECONNECT_MAX_S
                 ? f->backoff * 2 : RECONNECT_MAX_S;
}

static void fwd_connect(fwd_t *f)
{
    struct addrinfo hints = {}, *res = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", f->port);

    if (getaddrinfo(f->host, port_str, &hints, &res) != 0 || !res) {
        f->retry_at = time(NULL) + f->backoff;
        f->backoff   = f->backoff < RECONNECT_MAX_S
                     ? f->backoff * 2 : RECONNECT_MAX_S;
        return;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return; }

    int one = 1;
    setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE, &one, sizeof(one));
#ifdef TCP_KEEPIDLE
    int idle = 10;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &idle, sizeof(idle));
#endif
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

#ifdef HAVE_OPENSSL
    int need_tls = (f->flags & FORWARD_FLAG_TLS) != 0;
    if (!need_tls)
        set_nonblocking(fd);
    /* TLS uses blocking I/O with a send timeout to avoid indefinite stalls */
    if (need_tls) {
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
#else
    set_nonblocking(fd);
#endif

    int r = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (r < 0 && errno != EINPROGRESS) {
        close(fd);
        f->retry_at = time(NULL) + f->backoff;
        f->backoff   = f->backoff < RECONNECT_MAX_S
                     ? f->backoff * 2 : RECONNECT_MAX_S;
        return;
    }

#ifdef HAVE_OPENSSL
    if (need_tls && f->ssl_ctx) {
        /* For non-blocking connect (EINPROGRESS), wait for writability */
        if (r < 0 && errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
            if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) {
                close(fd);
                f->retry_at = time(NULL) + f->backoff;
                f->backoff   = f->backoff < RECONNECT_MAX_S
                             ? f->backoff * 2 : RECONNECT_MAX_S;
                return;
            }
            int err = 0; socklen_t len = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err) { close(fd); return; }
        }

        SSL *ssl = SSL_new(f->ssl_ctx);
        if (!ssl) { close(fd); return; }
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, f->host);   /* SNI */

        int sr = SSL_connect(ssl);
        if (sr <= 0) {
            fprintf(stderr,
                    "warning: forward: TLS handshake to %s:%d failed (err %d), "
                    "reconnecting in %ds\n",
                    f->host, f->port, SSL_get_error(ssl, sr), f->backoff);
            SSL_free(ssl);
            close(fd);
            f->retry_at = time(NULL) + f->backoff;
            f->backoff   = f->backoff < RECONNECT_MAX_S
                         ? f->backoff * 2 : RECONNECT_MAX_S;
            return;
        }

        /* Switch to non-blocking now that TLS handshake is complete */
        set_nonblocking(fd);
        f->ssl  = ssl;
        f->sock = fd;
        f->backoff  = RECONNECT_MIN_S;
        fprintf(stderr, "info: forward: TLS connected to %s:%d (cipher: %s)\n",
                f->host, f->port, SSL_get_cipher(ssl));
        return;
    }
#endif

    f->sock    = fd;
    f->backoff = RECONNECT_MIN_S;
    fprintf(stderr, "info: forward: connected to %s:%d\n", f->host, f->port);
}

/* Returns 1 on success, 0 on full-buffer drop, -1 on hard error */
static int fwd_send(fwd_t *f, const char *buf, size_t len)
{
    if (f->sock < 0 || len == 0) return -1;

    ssize_t n;
#ifdef HAVE_OPENSSL
    if (f->ssl) {
        n = SSL_write(f->ssl, buf, (int)len);
        if (n <= 0) {
            int e = SSL_get_error(f->ssl, (int)n);
            if (e == SSL_ERROR_WANT_WRITE) {
                f->dropped++;
                return 0;
            }
            fprintf(stderr,
                    "warning: forward: TLS write to %s:%d failed, "
                    "reconnecting in %ds\n",
                    f->host, f->port, f->backoff);
            fwd_close(f);
            f->dropped++;
            return -1;
        }
        return 1;
    }
#endif
    n = send(f->sock, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            f->dropped++;
            return 0;
        }
        fprintf(stderr,
                "warning: forward: lost connection to %s:%d (%s), "
                "reconnecting in %ds\n",
                f->host, f->port, strerror(errno), f->backoff);
        fwd_close(f);
        f->dropped++;
        return -1;
    }
    return 1;
}

/* ── public API ───────────────────────────────────────────────────────────── */

int forward_parse_addr(const char *s, char *host_out, size_t hostsz,
                       int *port_out)
{
    if (!s || !host_out || !port_out) return -1;

    if (s[0] == '[') {
        /* IPv6 bracketed form: [::1]:9000 */
        const char *end_bracket = strchr(s, ']');
        if (!end_bracket || end_bracket[1] != ':') return -1;
        size_t len = (size_t)(end_bracket - s - 1);
        if (len == 0 || len >= hostsz) return -1;
        memcpy(host_out, s + 1, len);
        host_out[len] = '\0';
        *port_out = atoi(end_bracket + 2);
    } else {
        /* host:port — split at last ':' */
        const char *colon = strrchr(s, ':');
        if (!colon) return -1;
        size_t len = (size_t)(colon - s);
        if (len == 0 || len >= hostsz) return -1;
        memcpy(host_out, s, len);
        host_out[len] = '\0';
        *port_out = atoi(colon + 1);
    }

    if (*port_out <= 0 || *port_out > 65535) return -1;
    return 0;
}

int forward_add(const char *host, int port, int flags)
{
    if (!host || !*host || port <= 0 || port > 65535) return -1;
    if (g_fwd_n >= FORWARD_MAX_TARGETS) return -1;

    fwd_t *f = &g_fwd[g_fwd_n];
    memset(f, 0, sizeof(*f));
    strncpy(f->host, host, sizeof(f->host) - 1);
    f->port    = port;
    f->flags   = flags;
    f->sock    = -1;
    f->backoff = RECONNECT_MIN_S;

#ifdef HAVE_OPENSSL
    if (flags & FORWARD_FLAG_TLS) {
        f->ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!f->ssl_ctx) {
            fprintf(stderr, "warning: forward: failed to create SSL context\n");
            return -1;
        }
        if (flags & 0x2) {
            /* NOVERIFY: encrypt but don't authenticate the server */
            SSL_CTX_set_verify(f->ssl_ctx, SSL_VERIFY_NONE, NULL);
        } else {
            SSL_CTX_set_verify(f->ssl_ctx, SSL_VERIFY_PEER, NULL);
            SSL_CTX_set_default_verify_paths(f->ssl_ctx);
        }
    }
#else
    if (flags & FORWARD_FLAG_TLS) {
        fprintf(stderr,
                "warning: forward: TLS requested but argus built without "
                "OpenSSL — connecting plain TCP\n");
    }
#endif

    g_fwd_n++;

    fwd_connect(f);
    if (f->sock < 0) {
        fprintf(stderr,
                "warning: forward: cannot connect to %s:%d, "
                "will retry (backoff %ds)\n",
                f->host, f->port, f->backoff);
    }
    return 0;
}

int forward_init(const char *host, int port)
{
    forward_clear();
    return forward_add(host, port, 0);
}

void forward_event(const event_t *e)
{
    char buf[2048];
    size_t len = event_to_json(e, buf, sizeof(buf) - 2);
    if (len == 0) return;
    buf[len]     = '\n';
    buf[len + 1] = '\0';

    for (int i = 0; i < g_fwd_n; i++) {
        if (g_fwd[i].sock < 0) {
            g_fwd[i].dropped++;
            continue;
        }
        fwd_send(&g_fwd[i], buf, len + 1);
    }
}

void forward_drops(uint64_t count)
{
    if (count == 0) return;
    char buf[64];
    int n = snprintf(buf, sizeof(buf),
                     "{\"type\":\"DROP\",\"count\":%llu}\n",
                     (unsigned long long)count);
    if (n <= 0) return;

    for (int i = 0; i < g_fwd_n; i++) {
        if (g_fwd[i].sock >= 0)
            fwd_send(&g_fwd[i], buf, (size_t)n);
    }
}

void forward_tick(void)
{
    time_t now = time(NULL);
    for (int i = 0; i < g_fwd_n; i++) {
        fwd_t *f = &g_fwd[i];
        if (f->sock >= 0) continue;         /* already connected */
        if (now < f->retry_at) continue;    /* still in backoff  */

        fwd_connect(f);
        if (f->sock >= 0 && f->dropped > 0) {
            forward_drops(f->dropped);      /* report accumulated drops */
            f->dropped = 0;
        }
    }
}

int forward_connected(void)
{
    for (int i = 0; i < g_fwd_n; i++)
        if (g_fwd[i].sock >= 0) return 1;
    return 0;
}

void forward_fini(void)
{
    for (int i = 0; i < g_fwd_n; i++) {
        fwd_t *f = &g_fwd[i];
        if (f->sock >= 0 && f->dropped > 0)
            forward_drops(f->dropped);
        if (f->sock >= 0) {
            shutdown(f->sock, SHUT_RDWR);
            close(f->sock);
            f->sock = -1;
        }
#ifdef HAVE_OPENSSL
        if (f->ssl)     { SSL_free(f->ssl);     f->ssl     = NULL; }
        if (f->ssl_ctx) { SSL_CTX_free(f->ssl_ctx); f->ssl_ctx = NULL; }
#endif
    }
}

void forward_clear(void)
{
    forward_fini();
    memset(g_fwd, 0, sizeof(g_fwd));
    g_fwd_n = 0;
}
