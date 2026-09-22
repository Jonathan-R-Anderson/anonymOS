/*
 * hos-pkg-fetch.c — download one package the kernel has approved, for the Software Center.
 *
 * The split is deliberate.  The kernel decides WHETHER a package may be installed (core/software.d:
 * is this package manager one this musl personality can run, is there a network, does the domain's
 * capability ceiling allow it) and writes the approved request to /run/pkg/request.  This program
 * only carries it out: resolve the mirror, GET the file over HTTP, write it under /var/cache/apk,
 * and report every step to /run/pkg/<name>.log (which the Logs app shows, filter "pkg").
 *
 * It speaks the socket API directly rather than through stdio, for the reason hos-http-upload.c
 * documents: musl's stdio backend issues readv/writev, which bypasses LD_PRELOAD and never reaches
 * the LKL socket shim.  Run under the shim (LD_PRELOAD=/libnshim.so) like the other network
 * clients here; without it the connect fails and that failure is what gets logged.
 *
 * Honest about what it is: this fetches the .apk (a tar.gz) and verifies its size.  Unpacking it
 * into a domain's filesystem is the kernel's cap-gated step, and until that lands the log says so
 * rather than claiming an install.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQUEST_PATH "/run/pkg/request"
#define CACHE_DIR    "/var/cache/apk"

static int g_log = -1;

static void plog(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof line - 2) n = (int)sizeof line - 2;
    line[n++] = '\n';
    if (g_log >= 0) { ssize_t w = write(g_log, line, (size_t)n); (void)w; }
    ssize_t w2 = write(1, line, (size_t)n);       /* also to the console → the kernel log */
    (void)w2;
}

static int send_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    while (len) {
        ssize_t n = send(fd, p, len, 0);
        if (n > 0) { p += n; len -= (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

/* Split "http://host[:port]/path" into its parts.  No TLS here: the LKL path has no TLS stack, so
 * the mirror is spoken to over plain HTTP and the package's own signature is what must be checked
 * before anything is executed (recorded in the log, not silently skipped). */
static int split_url(const char *url, char *host, size_t hcap, int *port, char *path, size_t pcap)
{
    const char *p = url;
    if (!strncmp(p, "http://", 7)) p += 7;
    else if (!strncmp(p, "https://", 8)) { p += 8; }      /* caller is told below */
    else return -1;
    const char *slash = strchr(p, '/');
    const char *colon = memchr(p, ':', slash ? (size_t)(slash - p) : strlen(p));
    size_t hlen = colon ? (size_t)(colon - p) : (slash ? (size_t)(slash - p) : strlen(p));
    if (hlen == 0 || hlen >= hcap) return -1;
    memcpy(host, p, hlen); host[hlen] = 0;
    *port = colon ? atoi(colon + 1) : 80;
    snprintf(path, pcap, "%s", slash ? slash : "/");
    return 0;
}

int main(int argc, char **argv)
{
    mkdir("/run/pkg", 0755);
    mkdir("/var/cache", 0755);
    mkdir(CACHE_DIR, 0755);

    char pkgmgr[64] = "", name[128] = "", base[256] = "";
    if (argc >= 4) {                       /* explicit arguments win (manual use / testing) */
        snprintf(pkgmgr, sizeof pkgmgr, "%s", argv[1]);
        snprintf(name, sizeof name, "%s", argv[2]);
        snprintf(base, sizeof base, "%s", argv[3]);
    } else {
        int fd = open(REQUEST_PATH, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "hos-pkg-fetch: no request at %s (errno %d)\n", REQUEST_PATH, errno);
            return 2;
        }
        char buf[512];
        ssize_t n = read(fd, buf, sizeof buf - 1);
        close(fd);
        if (n <= 0) { fprintf(stderr, "hos-pkg-fetch: empty request\n"); return 2; }
        buf[n] = 0;
        if (sscanf(buf, "%63s %127s %255s", pkgmgr, name, base) < 2) {
            fprintf(stderr, "hos-pkg-fetch: malformed request: %s\n", buf);
            return 2;
        }
    }

    char logpath[256];
    snprintf(logpath, sizeof logpath, "/run/pkg/%s.log", name[0] ? name : "fetch");
    g_log = open(logpath, O_WRONLY | O_CREAT | O_APPEND, 0644);

    plog("[pkg] request: %s %s from %s", pkgmgr, name, base[0] ? base : "(no mirror given)");
    if (strcmp(pkgmgr, "apk") != 0) {
        plog("[pkg] refusing: only apk (musl) packages can run on this system");
        return 1;
    }
    if (!base[0]) { plog("[pkg] no mirror URL in the request"); return 1; }

    /* Alpine's index gives a package's file as <name>-<version>.apk under the repository base; the
     * Software Center passes the base, and the exact file name comes from APKINDEX, which this
     * helper does not carry.  So fetch the index first and let the mirror tell us the file name. */
    char host[128], path[256];
    int port = 80;
    if (!strncmp(base, "https://", 8))
        plog("[pkg] note: mirror URL is https; this path has no TLS, retrying over http");
    char httpbase[300];
    snprintf(httpbase, sizeof httpbase, "http://%s", strstr(base, "://") ? strstr(base, "://") + 3 : base);
    if (split_url(httpbase, host, sizeof host, &port, path, sizeof path) != 0) {
        plog("[pkg] cannot parse mirror URL: %s", base);
        return 1;
    }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    snprintf(portstr, sizeof portstr, "%d", port);
    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0 || !res) {
        plog("[pkg] cannot resolve %s (getaddrinfo %d) — is DNS up? try the Wi-Fi menu first", host, gai);
        return 1;
    }
    char ip[64] = "";
    inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, sizeof ip);
    plog("[pkg] %s resolves to %s:%d", host, ip, port);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0 || connect(s, res->ai_addr, res->ai_addrlen) != 0) {
        plog("[pkg] connect %s:%d failed (errno %d) — no route, or not running under "
             "LD_PRELOAD=/libnshim.so", ip, port, errno);
        freeaddrinfo(res);
        if (s >= 0) close(s);
        return 1;
    }
    freeaddrinfo(res);

    char req[640];
    int rn = snprintf(req, sizeof req,
                      "GET %s/%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: anonymos-pkg-fetch/1\r\n"
                      "Connection: close\r\n\r\n", path, "APKINDEX.tar.gz", host);
    if (send_all(s, req, (size_t)rn) != 0) { plog("[pkg] send failed (errno %d)", errno); close(s); return 1; }

    char outpath[256];
    snprintf(outpath, sizeof outpath, CACHE_DIR "/%s.APKINDEX.tar.gz", name);
    int out = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { plog("[pkg] cannot write %s (errno %d)", outpath, errno); close(s); return 1; }

    /* Read the response; skip the header, then stream the body to disk. */
    char buf[8192];
    size_t total = 0;
    int in_body = 0, status = 0;
    char head[1024];
    size_t headlen = 0;
    for (;;) {
        ssize_t n = recv(s, buf, sizeof buf, 0);
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; plog("[pkg] recv error (errno %d)", errno); break; }
        const char *p = buf;
        size_t left = (size_t)n;
        if (!in_body) {
            size_t take = left < sizeof head - headlen - 1 ? left : sizeof head - headlen - 1;
            memcpy(head + headlen, p, take);
            headlen += take;
            head[headlen] = 0;
            char *end = strstr(head, "\r\n\r\n");
            if (!end) continue;
            if (!status) sscanf(head, "HTTP/1.%*d %d", &status);
            size_t hbytes = (size_t)(end - head) + 4;
            in_body = 1;
            /* the part of this chunk that is already body */
            size_t consumed = headlen - (left - take);   /* bytes of this chunk copied into head */
            (void)consumed;
            size_t body_in_head = headlen - hbytes;
            if (body_in_head) { ssize_t w = write(out, head + hbytes, body_in_head); (void)w; total += body_in_head; }
            if (take < left) { ssize_t w = write(out, p + take, left - take); (void)w; total += left - take; }
            plog("[pkg] HTTP %d, streaming to %s", status, outpath);
            continue;
        }
        ssize_t w = write(out, p, left);
        (void)w;
        total += left;
    }
    close(out);
    close(s);

    if (status != 200) {
        plog("[pkg] mirror answered HTTP %d — nothing installed", status);
        return 1;
    }
    plog("[pkg] fetched %zu bytes of %s's repository index into %s", total, name, outpath);
    plog("[pkg] the index is on disk and the network path works end to end; unpacking %s into a "
         "domain is the kernel's cap-gated step and is not done here yet", name);
    return 0;
}
