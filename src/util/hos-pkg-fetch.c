/*
 * hos-pkg-fetch.c — download AND unpack one package the kernel has approved, for the Software Center.
 *
 * The split is deliberate.  The kernel decides WHETHER a package may be installed (core/software.d:
 * is this package manager one this musl personality can run, is there a network, does the domain's
 * capability ceiling allow it) and writes the approved request to /run/pkg/request.  This program
 * carries it out in userspace, where it is allowed to speak HTTP and to decompress: resolve the
 * mirror, fetch APKINDEX, resolve the package's exact version, GET the .apk, and UNPACK its data
 * members into a staging tree under /var/cache/apk.  It then writes /run/pkg/<name>.done so the
 * kernel can do the one step userspace cannot — the cap-gated placement of those files into the
 * (shared) Linux rootfs (rtAddFile), which is EROFS to userspace.  Every step is logged to
 * /run/pkg/<name>.log (the Logs app shows it, filter "pkg").
 *
 * It speaks the socket API directly rather than through stdio, for the reason hos-http-upload.c
 * documents: musl's stdio backend issues readv/writev, which bypasses LD_PRELOAD and never reaches
 * the LKL socket shim.  Run under the shim (LD_PRELOAD=/libnshim.so) like the other network
 * clients here; without it the connect fails and that failure is what gets logged.  (File I/O uses
 * the plain read/write syscalls too, for the same reason and to keep behaviour predictable.)
 *
 * Decompression is zlib (musl-static, from the gtk-stack sysroot).  No TLS: the LKL path has no TLS
 * stack, so the mirror is spoken to over plain HTTP -- which is why nothing it sends is trusted.  The
 * package is PINNED by the image's own catalog (the kernel puts the version and Alpine's control
 * checksum, APKINDEX "C:", in the request): the downloaded .apk's control segment must SHA-1 to that
 * checksum and its data segment must SHA-256 to the "datahash" the control segment carries, and only
 * that verified data segment is unpacked.  A tampered or substituted package installs nothing.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

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

/* Record a failed install so the kernel's poll stops waiting and reports "failed" rather than
 * leaving the status stuck at "busy".  Returns 1 so callers can `return fail_exit(name);`. */
static int fail_exit(const char *name)
{
    char fp[256];
    snprintf(fp, sizeof fp, "/run/pkg/%s.fail", name);
    int f = open(fp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (f >= 0) { ssize_t w = write(f, "failed\n", 7); (void)w; close(f); }
    return 1;
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

/* read exactly `len` bytes into buf unless EOF; returns bytes read (== len, or < len at EOF). */
static ssize_t read_full(int fd, void *buf, size_t len)
{
    unsigned char *p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        got += (size_t)n;
    }
    return (ssize_t)got;
}

/* mkdir -p for every parent directory of a file path (the file itself is not created). */
static void mkdir_parents(const char *path)
{
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = 0; mkdir(tmp, 0755); *p = '/'; }
    }
}

/* Fetch http://host:port<urlpath> into outpath.  Returns the HTTP status (200 on success),
 * 0 if the response had no parseable status, or -1 on a transport error (DNS/connect/send).
 * *out_bytes, if non-NULL, receives the number of body bytes written.  No TLS. */
static int http_get(const char *host, int port, const char *urlpath, const char *outpath,
                    size_t *out_bytes)
{
    if (out_bytes) *out_bytes = 0;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    snprintf(portstr, sizeof portstr, "%d", port);
    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0 || !res) {
        plog("[pkg] cannot resolve %s (getaddrinfo %d) — is DNS up? try the Wi-Fi menu first", host, gai);
        return -1;
    }
    char ip[64] = "";
    inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, sizeof ip);
    plog("[pkg] GET %s from %s:%d (%s)", urlpath, host, port, ip);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0 || connect(s, res->ai_addr, res->ai_addrlen) != 0) {
        plog("[pkg] connect %s:%d failed (errno %d) — no route, or not running under "
             "LD_PRELOAD=/libnshim.so", ip, port, errno);
        freeaddrinfo(res);
        if (s >= 0) close(s);
        return -1;
    }
    freeaddrinfo(res);

    char req[768];
    int rn = snprintf(req, sizeof req,
                      "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: anonymos-pkg-fetch/1\r\n"
                      "Connection: close\r\n\r\n", urlpath, host);
    if (send_all(s, req, (size_t)rn) != 0) { plog("[pkg] send failed (errno %d)", errno); close(s); return -1; }

    int out = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { plog("[pkg] cannot write %s (errno %d)", outpath, errno); close(s); return -1; }

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
    if (out_bytes) *out_bytes = total;
    return status;
}

/* Split "http://host[:port]/path" into its parts (no TLS; https is retried over http upstream). */
static int split_url(const char *url, char *host, size_t hcap, int *port, char *path, size_t pcap)
{
    const char *p = url;
    if (!strncmp(p, "http://", 7)) p += 7;
    else if (!strncmp(p, "https://", 8)) { p += 8; }
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

/* octal field parse (tar headers store sizes/modes as NUL/space-terminated octal ASCII). */
static unsigned long oct(const unsigned char *f, size_t n)
{
    unsigned long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (f[i] < '0' || f[i] > '7') break;
        v = (v << 3) + (unsigned long)(f[i] - '0');
    }
    return v;
}

/* Walk a decompressed ustar stream at tarpath.  For every regular-file entry whose path does NOT
 * begin with a dot (i.e. a DATA file, not the apk control members .PKGINFO, .SIGN.RSA, .pre-install
 * and friends), write it under stagedir mirroring its relative path and append that relative path
 * to manifest_fd; a symlink is recorded as "@<path>\t<target>".  Directory and control entries are
 * skipped (their data is consumed).
 * Returns the number of files written, or -1 on a read error. */
static int ustar_extract_data(const char *tarpath, const char *stagedir, int manifest_fd)
{
    int in = open(tarpath, O_RDONLY);
    if (in < 0) { plog("[pkg] untar: cannot open %s (errno %d)", tarpath, errno); return -1; }

    unsigned char hdr[512];
    int count = 0;
    for (;;) {
        ssize_t r = read_full(in, hdr, 512);
        if (r <= 0) break;
        if (r < 512) break;                             /* truncated */
        int allzero = 1;
        for (int i = 0; i < 512; i++) if (hdr[i]) { allzero = 0; break; }
        if (allzero) break;                             /* end-of-archive marker */

        char name[101];   memcpy(name,   hdr,       100); name[100] = 0;
        char prefix[156]; memcpy(prefix, hdr + 345, 155); prefix[155] = 0;
        char typeflag = (char)hdr[156];
        unsigned long size = oct(hdr + 124, 12);
        unsigned long padded = (size + 511) & ~511UL;

        char full[280];
        if (prefix[0]) snprintf(full, sizeof full, "%s/%s", prefix, name);
        else           snprintf(full, sizeof full, "%s", name);
        char *rel = full;
        if (rel[0] == '.' && rel[1] == '/') rel += 2;   /* strip leading "./" */

        int is_regular = (typeflag == '0' || typeflag == 0);
        int is_data    = (rel[0] != '.' && rel[0] != 0 && rel[0] != '/');

        if (is_regular && is_data) {
            char dst[1200];
            snprintf(dst, sizeof dst, "%s/%s", stagedir, rel);
            mkdir_parents(dst);
            int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
            unsigned long remaining = size;
            unsigned char blk[16384];
            int werr = (out < 0);
            while (remaining > 0) {
                size_t want = remaining < sizeof blk ? (size_t)remaining : sizeof blk;
                ssize_t got = read_full(in, blk, want);
                if (got <= 0) { werr = 1; break; }
                if (out >= 0) { ssize_t w = write(out, blk, (size_t)got); (void)w; }
                remaining -= (size_t)got;
            }
            if (out >= 0) close(out);
            /* consume the padding to the next 512 boundary */
            unsigned long pad = padded - size;
            while (pad > 0) { unsigned char t[512]; ssize_t g = read_full(in, t, pad < 512 ? pad : 512); if (g <= 0) break; pad -= (size_t)g; }
            if (!werr) {
                char line[300];
                int ln = snprintf(line, sizeof line, "%s\n", rel);
                ssize_t w = write(manifest_fd, line, (size_t)ln); (void)w;
                count++;
            } else {
                plog("[pkg] untar: failed writing %s", dst);
            }
        } else if (typeflag == '2' && is_data) {
            /* A symlink -- how every shared library publishes its soname (libstdc++.so.6 ->
             * libstdc++.so.6.0.32).  Dropping these left programs unable to load their libraries
             * ("Error loading shared library libstdc++.so.6").  Recorded in the manifest as
             * "@<path>\t<target>"; the kernel creates it (placement rules apply to the path). */
            char target[101]; memcpy(target, hdr + 157, 100); target[100] = 0;
            if (target[0] && !strchr(target, '\n') && !strchr(target, '\t')) {
                char line[420];
                int ln = snprintf(line, sizeof line, "@%s\t%s\n", rel, target);
                if (ln > 0 && ln < (int)sizeof line) { ssize_t w = write(manifest_fd, line, (size_t)ln); (void)w; count++; }
            }
            unsigned long skip = padded;
            while (skip > 0) { unsigned char t[512]; ssize_t g = read_full(in, t, skip < 512 ? skip : 512); if (g <= 0) break; skip -= (size_t)g; }
        } else {
            /* directory / hard link / control member: consume its data + padding */
            unsigned long skip = padded;
            while (skip > 0) { unsigned char t[512]; ssize_t g = read_full(in, t, skip < 512 ? skip : 512); if (g <= 0) break; skip -= (size_t)g; }
        }
    }
    close(in);
    return count;
}

/* ── integrity: SHA-1, SHA-256, base64 ────────────────────────────────────────────────────── *
 * Small, dependency-free implementations (FIPS 180-4).  They hash the COMPRESSED bytes of each gzip
 * stream of the .apk, which is what Alpine's index and .PKGINFO commit to. */
typedef struct { uint32_t h[5]; uint64_t len; unsigned char buf[64]; size_t n; } sha1_ctx;
typedef struct { uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t n; } sha256_ctx;
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha1_block(sha1_ctx *c, const unsigned char *p)
{
    uint32_t w[80], a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4];
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 80; i++) w[i] = ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & cc) | (~b & d);            k = 0x5A827999; }
        else if (i < 40) { f = b ^ cc ^ d;                     k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d);  k = 0x8F1BBCDC; }
        else             { f = b ^ cc ^ d;                     k = 0xCA62C1D6; }
        uint32_t t = ROL(a, 5) + f + e + k + w[i];
        e = d; d = cc; cc = ROL(b, 30); b = a; a = t;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}
static void sha1_init(sha1_ctx *c)
{
    static const uint32_t iv[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    memcpy(c->h, iv, sizeof iv); c->len = 0; c->n = 0;
}
static void sha1_update(sha1_ctx *c, const unsigned char *p, size_t n)
{
    c->len += n;
    while (n) { size_t k = 64 - c->n; if (k > n) k = n; memcpy(c->buf + c->n, p, k); c->n += k; p += k; n -= k;
                if (c->n == 64) { sha1_block(c, c->buf); c->n = 0; } }
}
static void sha1_final(sha1_ctx *c, unsigned char out[20])
{
    uint64_t bits = c->len * 8; unsigned char pad = 0x80; sha1_update(c, &pad, 1);
    unsigned char z = 0; while (c->n != 56) sha1_update(c, &z, 1);
    unsigned char lb[8]; for (int i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (56 - 8*i));
    sha1_update(c, lb, 8);
    for (int i = 0; i < 5; i++) { out[4*i] = c->h[i] >> 24; out[4*i+1] = c->h[i] >> 16; out[4*i+2] = c->h[i] >> 8; out[4*i+3] = c->h[i]; }
}
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
static void sha256_block(sha256_ctx *c, const unsigned char *p)
{
    uint32_t w[64], s[8];
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    memcpy(s, c->h, sizeof s);
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR(s[4], 6) ^ ROR(s[4], 11) ^ ROR(s[4], 25);
        uint32_t ch = (s[4] & s[5]) ^ (~s[4] & s[6]);
        uint32_t t1 = s[7] + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROR(s[0], 2) ^ ROR(s[0], 13) ^ ROR(s[0], 22);
        uint32_t mj = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]);
        uint32_t t2 = S0 + mj;
        s[7] = s[6]; s[6] = s[5]; s[5] = s[4]; s[4] = s[3] + t1; s[3] = s[2]; s[2] = s[1]; s[1] = s[0]; s[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++) c->h[i] += s[i];
}
static void sha256_init(sha256_ctx *c)
{
    static const uint32_t iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    memcpy(c->h, iv, sizeof iv); c->len = 0; c->n = 0;
}
static void sha256_update(sha256_ctx *c, const unsigned char *p, size_t n)
{
    c->len += n;
    while (n) { size_t k = 64 - c->n; if (k > n) k = n; memcpy(c->buf + c->n, p, k); c->n += k; p += k; n -= k;
                if (c->n == 64) { sha256_block(c, c->buf); c->n = 0; } }
}
static void sha256_final(sha256_ctx *c, unsigned char out[32])
{
    uint64_t bits = c->len * 8; unsigned char pad = 0x80; sha256_update(c, &pad, 1);
    unsigned char z = 0; while (c->n != 56) sha256_update(c, &z, 1);
    unsigned char lb[8]; for (int i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (56 - 8*i));
    sha256_update(c, lb, 8);
    for (int i = 0; i < 8; i++) { out[4*i] = c->h[i] >> 24; out[4*i+1] = c->h[i] >> 16; out[4*i+2] = c->h[i] >> 8; out[4*i+3] = c->h[i]; }
}
static void b64_encode(const unsigned char *in, size_t n, char *out)
{
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i+1] << 8 : 0) | (i + 2 < n ? in[i+2] : 0);
        out[o++] = T[v >> 18 & 63]; out[o++] = T[v >> 12 & 63];
        out[o++] = i + 1 < n ? T[v >> 6 & 63] : '=';
        out[o++] = i + 2 < n ? T[v & 63] : '=';
    }
    out[o] = 0;
}

/* One gzip stream of the .apk: where it lies in the file, its hashes, and (for small streams, i.e.
 * the control segment) its decompressed tar, so .PKGINFO can be read without a second pass. */
#define APK_MAX_MEMBERS 8
#define APK_KEEP_MAX    (256 * 1024)
struct apk_member {
    long start, end;
    unsigned char sha1[20], sha256[32];
    unsigned char *tar; size_t tarlen; int overflow;
};

/* Walk every gzip stream of the .apk at path, hashing each stream's compressed bytes.  zlib
 * reports how far into the input each stream ended (avail_in on Z_STREAM_END), which is what
 * makes the per-stream byte ranges exact. */
static int apk_scan(const char *path, struct apk_member *m, int *nm)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    z_stream zs; memset(&zs, 0, sizeof zs);
    if (inflateInit2(&zs, 15 + 16) != Z_OK) { close(fd); return -1; }
    unsigned char in[16384], out[16384];
    sha1_ctx s1; sha256_ctx s2;
    int cur = 0, rc = 0; long off = 0;
    *nm = 0;
    memset(&m[0], 0, sizeof m[0]); m[0].start = 0; sha1_init(&s1); sha256_init(&s2);
    for (;;) {
        ssize_t n = read(fd, in, sizeof in);
        if (n < 0) { if (errno == EINTR) continue; rc = -1; break; }
        if (n == 0) break;
        size_t pos = 0;
        while (pos < (size_t)n) {
            zs.next_in = in + pos; zs.avail_in = (uInt)((size_t)n - pos);
            zs.next_out = out; zs.avail_out = sizeof out;
            int r = inflate(&zs, Z_NO_FLUSH);
            size_t used = ((size_t)n - pos) - zs.avail_in;
            sha1_update(&s1, in + pos, used); sha256_update(&s2, in + pos, used);
            size_t have = sizeof out - zs.avail_out;
            struct apk_member *mm = &m[cur];
            if (have && !mm->overflow) {
                if (mm->tarlen + have > APK_KEEP_MAX) { free(mm->tar); mm->tar = NULL; mm->tarlen = 0; mm->overflow = 1; }
                else { unsigned char *nb = realloc(mm->tar, mm->tarlen + have);
                       if (!nb) { rc = -1; break; }
                       mm->tar = nb; memcpy(mm->tar + mm->tarlen, out, have); mm->tarlen += have; }
            }
            pos += used;
            if (r == Z_STREAM_END) {
                mm->end = off + (long)pos;
                sha1_final(&s1, mm->sha1); sha256_final(&s2, mm->sha256);
                if (++cur >= APK_MAX_MEMBERS) { rc = -1; break; }
                memset(&m[cur], 0, sizeof m[cur]); m[cur].start = mm->end;
                sha1_init(&s1); sha256_init(&s2);
                inflateReset(&zs);
                continue;
            }
            if (r != Z_OK && r != Z_BUF_ERROR) { rc = -1; break; }
            if (used == 0 && have == 0) break;            /* needs more input */
        }
        if (rc) break;
        off += n;
    }
    inflateEnd(&zs);
    close(fd);
    if (rc == 0 && m[cur].start != off) rc = -1;           /* trailing bytes that are not a whole stream */
    *nm = cur;
    return rc;
}

/* The value of "key = value" in .PKGINFO inside a decompressed control tar. */
static int pkginfo_field(const unsigned char *tar, size_t len, const char *key, char *out, size_t cap)
{
    size_t p = 0;
    while (p + 512 <= len) {
        const unsigned char *h = tar + p;
        if (h[0] == 0) break;
        unsigned long sz = oct(h + 124, 12);
        size_t body = p + 512;
        if (!strncmp((const char *)h, ".PKGINFO", 100) && body + sz <= len) {
            const char *t = (const char *)tar + body, *e = t + sz;
            size_t kl = strlen(key);
            while (t < e) {
                const char *nl = memchr(t, '\n', (size_t)(e - t)); if (!nl) nl = e;
                if ((size_t)(nl - t) > kl + 3 && !strncmp(t, key, kl) && !strncmp(t + kl, " = ", 3)) {
                    size_t vl = (size_t)(nl - (t + kl + 3)); if (vl >= cap) vl = cap - 1;
                    memcpy(out, t + kl + 3, vl); out[vl] = 0;
                    return 0;
                }
                t = nl + 1;
            }
            return -1;
        }
        p = body + ((sz + 511) / 512) * 512;
    }
    return -1;
}

/* Verify the downloaded .apk against the catalog's control checksum ("Q1<base64 SHA-1>"): exactly
 * one gzip stream must hash to it (the control segment); its .PKGINFO "datahash" must equal the
 * SHA-256 of the NEXT stream (the data segment), which must be the last one.  On success returns
 * the data segment's byte range -- the only bytes that will be unpacked. */
static int apk_verify(const char *path, const char *q1sum, long *dstart, long *dend)
{
    struct apk_member m[APK_MAX_MEMBERS];
    int nm = 0;
    memset(m, 0, sizeof m);
    int rc = -1;
    if (apk_scan(path, m, &nm) != 0 || nm < 2) { plog("[pkg] VERIFY FAILED: not a well-formed .apk (%d streams)", nm); goto out; }
    int ctrl = -1;
    for (int i = 0; i < nm; i++) {
        char b64[40], q1[48];
        b64_encode(m[i].sha1, 20, b64);
        snprintf(q1, sizeof q1, "Q1%s", b64);
        if (!strcmp(q1, q1sum)) { if (ctrl >= 0) { ctrl = -2; break; } ctrl = i; }
    }
    if (ctrl < 0) { plog("[pkg] VERIFY FAILED: no control segment matches the catalog checksum %s", q1sum); goto out; }
    if (ctrl + 1 != nm - 1) { plog("[pkg] VERIFY FAILED: the data segment is not the last stream"); goto out; }
    char dh[80];
    if (m[ctrl].overflow || !m[ctrl].tar || pkginfo_field(m[ctrl].tar, m[ctrl].tarlen, "datahash", dh, sizeof dh) != 0) {
        plog("[pkg] VERIFY FAILED: the control segment has no .PKGINFO datahash"); goto out; }
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + 2*i, 3, "%02x", m[ctrl + 1].sha256[i]);
    if (strcmp(hex, dh) != 0) { plog("[pkg] VERIFY FAILED: data segment SHA-256 %s != datahash %s", hex, dh); goto out; }
    *dstart = m[ctrl + 1].start; *dend = m[ctrl + 1].end;
    plog("[pkg] verified: control segment matches the catalog (%s); data segment SHA-256 matches .PKGINFO", q1sum);
    rc = 0;
out:
    for (int i = 0; i < APK_MAX_MEMBERS; i++) free(m[i].tar);
    return rc;
}

/* Inflate ONLY bytes [start, end) of inpath (one verified gzip stream) to outpath. */
static int gunzip_range_to_file(const char *inpath, long start, long end, const char *outpath)
{
    int in = open(inpath, O_RDONLY);
    if (in < 0) return -1;
    int out = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); return -1; }
    if (lseek(in, start, SEEK_SET) != start) { close(in); close(out); return -1; }
    z_stream zs; memset(&zs, 0, sizeof zs);
    if (inflateInit2(&zs, 15 + 16) != Z_OK) { close(in); close(out); return -1; }
    unsigned char inbuf[16384], outbuf[16384];
    long left = end - start; int rc = -1;
    while (left > 0) {
        ssize_t n = read(in, inbuf, left < (long)sizeof inbuf ? (size_t)left : sizeof inbuf);
        if (n <= 0) break;
        left -= n;
        zs.next_in = inbuf; zs.avail_in = (uInt)n;
        int r = Z_OK;
        while (zs.avail_in > 0 && r == Z_OK) {
            zs.next_out = outbuf; zs.avail_out = sizeof outbuf;
            r = inflate(&zs, Z_NO_FLUSH);
            size_t have = sizeof outbuf - zs.avail_out;
            if (have) { ssize_t w = write(out, outbuf, have); (void)w; }
        }
        if (r == Z_STREAM_END) { rc = 0; break; }
        if (r != Z_OK && r != Z_BUF_ERROR) break;
    }
    inflateEnd(&zs);
    close(in); close(out);
    return rc;
}

int main(int argc, char **argv)
{
    mkdir("/run/pkg", 0755);
    mkdir("/var/cache", 0755);
    mkdir(CACHE_DIR, 0755);

    char pkgmgr[64] = "", name[128] = "", base[256] = "", ver[64] = "", sum[64] = "";
    if (argc >= 6) {                       /* explicit arguments win (manual use / testing) */
        snprintf(pkgmgr, sizeof pkgmgr, "%s", argv[1]);
        snprintf(name, sizeof name, "%s", argv[2]);
        snprintf(base, sizeof base, "%s", argv[3]);
        snprintf(ver, sizeof ver, "%s", argv[4]);
        snprintf(sum, sizeof sum, "%s", argv[5]);
    } else {
        int fd = open(REQUEST_PATH, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "hos-pkg-fetch: no request at %s (errno %d)\n", REQUEST_PATH, errno);
            return 2;
        }
        char rbuf[512];
        ssize_t n = read(fd, rbuf, sizeof rbuf - 1);
        close(fd);
        if (n <= 0) { fprintf(stderr, "hos-pkg-fetch: empty request\n"); return 2; }
        rbuf[n] = 0;
        if (sscanf(rbuf, "%63s %127s %255s %63s %63s", pkgmgr, name, base, ver, sum) < 2) {
            fprintf(stderr, "hos-pkg-fetch: malformed request: %s\n", rbuf);
            return 2;
        }
    }

    char logpath[256];
    snprintf(logpath, sizeof logpath, "/run/pkg/%s.log", name[0] ? name : "fetch");
    g_log = open(logpath, O_WRONLY | O_CREAT | O_APPEND, 0644);

    plog("[pkg] request: %s %s from %s", pkgmgr, name, base[0] ? base : "(no mirror given)");
    if (strcmp(pkgmgr, "apk") != 0) {
        plog("[pkg] refusing: only apk (musl) packages can run on this system");
        return fail_exit(name);
    }
    if (!base[0]) { plog("[pkg] no mirror URL in the request"); return fail_exit(name); }

    char host[128], path[256];
    int port = 80;
    if (!strncmp(base, "https://", 8))
        plog("[pkg] note: mirror URL is https; this path has no TLS, retrying over http");
    char httpbase[300];
    snprintf(httpbase, sizeof httpbase, "http://%s", strstr(base, "://") ? strstr(base, "://") + 3 : base);
    if (split_url(httpbase, host, sizeof host, &port, path, sizeof path) != 0) {
        plog("[pkg] cannot parse mirror URL: %s", base);
        return fail_exit(name);
    }

    /* 1. The kernel pinned the package to the image's catalog: the exact version and the checksum
     *    its control segment must hash to.  The mirror's own index is NOT consulted -- it arrives
     *    over plain HTTP and could name any version with any contents. */
    if (!ver[0] || strncmp(sum, "Q1", 2) != 0) {
        plog("[pkg] refusing: the request carries no catalog pin (version + checksum), so the download could not be verified");
        return fail_exit(name);
    }
    plog("[pkg] pinned by the catalog: %s %s, control checksum %s", name, ver, sum);

    /* 2. Fetch the package's .apk (named <name>-<version>.apk under the repo base). */
    char apkurl[400], apkpath[300];
    snprintf(apkurl, sizeof apkurl, "%s/%s-%s.apk", path, name, ver);
    snprintf(apkpath, sizeof apkpath, CACHE_DIR "/%s-%s.apk", name, ver);
    size_t napk = 0;
    int status = http_get(host, port, apkurl, apkpath, &napk);
    if (status < 0) return fail_exit(name);
    if (status != 200) { plog("[pkg] mirror answered HTTP %d for %s-%s.apk — nothing installed", status, name, ver); return fail_exit(name); }
    plog("[pkg] fetched %zu bytes of %s-%s.apk", napk, name, ver);

    /* 2b. Verify before anything is unpacked: the control segment against the catalog checksum, the
     *     data segment against the SHA-256 the (now trusted) control segment commits to. */
    long dstart = 0, dend = 0;
    if (apk_verify(apkpath, sum, &dstart, &dend) != 0) {
        plog("[pkg] %s-%s.apk does not match this image's catalog -- tampered or corrupt; nothing installed", name, ver);
        unlink(apkpath);
        return fail_exit(name);
    }

    /* 3. Decompress + unpack ONLY the verified data segment into a staging tree, recording a manifest. */
    char apktar[300], stagedir[256], manifestpath[256];
    snprintf(apktar,       sizeof apktar,       CACHE_DIR "/%s.pkg.tar", name);
    snprintf(stagedir,     sizeof stagedir,     CACHE_DIR "/%s.files", name);
    snprintf(manifestpath, sizeof manifestpath, CACHE_DIR "/%s.manifest", name);
    if (gunzip_range_to_file(apkpath, dstart, dend, apktar) != 0) { plog("[pkg] could not decompress %s-%s.apk", name, ver); return fail_exit(name); }
    mkdir(stagedir, 0755);
    int manifest = open(manifestpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (manifest < 0) { plog("[pkg] cannot write manifest %s (errno %d)", manifestpath, errno); return fail_exit(name); }
    int nfiles = ustar_extract_data(apktar, stagedir, manifest);
    close(manifest);
    if (nfiles <= 0) { plog("[pkg] %s contained no installable data files", name); return fail_exit(name); }
    plog("[pkg] unpacked %d files of %s into %s", nfiles, name, stagedir);

    /* 4. Hand off to the kernel: it does the cap-gated placement into the (shared) Linux rootfs,
     *    which is read-only to userspace.  The .done marker names the staging dir + manifest so the
     *    kernel can rtAddFile each file and report the real install verdict on /config/software.status. */
    char donepath[256];
    snprintf(donepath, sizeof donepath, "/run/pkg/%s.done", name);
    int done = open(donepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (done >= 0) {
        char line[700];
        int ln = snprintf(line, sizeof line, "apk %s %s %s %s %d\n", name, ver, stagedir, manifestpath, nfiles);
        ssize_t w = write(done, line, (size_t)ln); (void)w;
        close(done);
    }
    plog("[pkg] staged %d files for %s-%s; kernel will place them (cap-gated) — see /run/pkg/%s.done",
         nfiles, name, ver, name);
    return 0;
}
