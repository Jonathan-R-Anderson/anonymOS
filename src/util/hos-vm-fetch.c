/*
 * hos-vm-fetch -- download the OPNsense firewall image inside anonymOS, verify it, and write it
 * into the VM store: the firewall the user chose in the installer arrives AFTER install, from
 * the official OPNsense mirrors (https://opnsense.org/download/ lists them), never on the media.
 *
 *   hos-vm-fetch [--target PATH] [--status PATH] [--mirror URL]...
 *
 * What it fetches: OPNsense 26.7's "serial" image (amd64, UEFI, serial console -- the one that runs
 * headless under Cloud Hypervisor), OPNsense-26.7-serial-amd64.img.bz2, plus the release's signed
 * checksum file and the image's own signature.
 *
 * Trust: the OPNsense 26.7 release key is PINNED below (its modulus; exponent 65537).  The
 * transport is plain HTTP -- this system has no TLS -- so integrity comes from the signatures:
 *   1. the checksum file must carry a valid RSA-4096 / SHA-256 signature by the pinned key;
 *   2. the downloaded .bz2 must match the SHA-256 that file lists;
 *   3. the decompressed image must carry a valid signature by the same key.
 * Anything else and the image is not committed.
 *
 * Writing: the .bz2 is decompressed as it streams in and written straight into the target (the
 * kernel's VM store, /vmstore/opnsense.img.part: the installer's 3 GiB partition, disk-backed) at
 * its offset -- the 2.5 GB image is never held in memory.  Sector 1 (the image's GPT header) is
 * held back and written LAST, after all three checks pass, then fsync()ed: that fsync is where the
 * kernel checks the header and publishes the image as /vmstore/opnsense.img, so an interrupted or
 * failed download is never mistaken for a disk.
 *
 * Progress goes to the status file ("state=... done=... total=... msg=...") the Virtual Machines
 * app shows.  Mirrors are tried in order; any failure is retried from the next mirror.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bzlib.h>
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
#include <time.h>
#include <unistd.h>

#define VERSION   "26.7"
#define IMAGE     "OPNsense-" VERSION "-serial-amd64.img"
#define SUMS      "OPNsense-" VERSION "-checksums-amd64.sha256"

/* The OPNsense 26.7 release public key (RSA-4096), pinned: the key file's SHA-256 is
 * 9f3b76ffef38fb6405595038b324b61043c9a2c375ae5c151d628508e9a845ce, identical on every mirror. */
static const char *const KEY_MODULUS_HEX =
    "CE248D2AECEB2F67302F1E4B5E62E77164B92E4FA2F42CD13173BFE3141805009A4A777C18183F1C0FE0E1A3E84D46BA"
    "A2F008D001DF5BC290250C81905CE7A62E8C2D927DB44685727D02895FAD49325DD515786C1F23B692A5E684E4805ACF"
    "B32681EE20651B909DE3D5425B5F610F10A5436E25916915A187EC7C2404B780033462F281608FC9FE1BC460FFB7AFED"
    "896F52B0EB36FA07CE67D0BF1B677F101849168044A33E65BD42D5C5375F6393D2718AC70FFC1A667937AC673603EF69"
    "23F48CD890302AAB2067A31215B5CE0CDA1C4A3A8551491DAA1B72F9071CD0E27E84C6CA29513E7F74090502304F76B2"
    "CACF102B49B9082A3DD7F7FE0E3A0D9E88FEB7960DF71F06444905D30ADD222EE17AF930ACBDBF48941BAB56CBD412C1"
    "FA63125D847AD759604FC61F623C99EED9A93550B73B93E3EE5DB4B279B5955512A92D0FB0506F87A1D0B414704031A9"
    "A5A208847D4DB7DC886AD99288666DD98ACC54D0736D0AC9CD25FEBD6700BA591A3C8B78B7E5F19A93B9203359FB8B8C"
    "67B5F226AD6502121EC97C7E15A95FBFB4BE669256155373D3F379CFA9416C00C3F39E62FA0158E81E76D3DC46CA177A"
    "17068F3A32128102A4801C05D40896303B93B8FF65921FD4E601816481539DB7443203802F83FE1ECC3D368CDABFEDD0"
    "229894DCFBFD176F5AD5EAC292AD3DAE9432360958EC9AA67BF462A736D889AF";

/* Official OPNsense mirrors that serve plain HTTP (from the download page's list). */
static const char *const DEFAULT_MIRRORS[] = {
    "http://mirrors.dotsrc.org/opnsense/releases/mirror",
    "http://mirror.init7.net/opnsense/releases/mirror",
    "http://mirror.ams1.nl.leaseweb.net/opnsense/releases/mirror",
    "http://mirrors.ocf.berkeley.edu/opnsense/releases/mirror",
};

static const char *g_status_path = "/vmstore/opnsense.status";
static const char *g_target = "/vmstore/opnsense.img.part";
static int g_target_given;               /* --target: a plain file (host tests) may be created */

static void status(const char *state, uint64_t done, uint64_t total, const char *fmt, ...)
{
    char msg[256] = "";
    if (fmt) { va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap); }
    char tmp[300];
    snprintf(tmp, sizeof tmp, "%s.new", g_status_path);
    FILE *f = fopen(tmp, "w");
    if (f) {
        fprintf(f, "image=OPNsense %s\nstate=%s\ndone=%llu\ntotal=%llu\nmsg=%s\n", VERSION, state,
                (unsigned long long)done, (unsigned long long)total, msg);
        fclose(f);
        rename(tmp, g_status_path);
    }
    printf("[vm-fetch] %s %llu/%llu %s\n", state, (unsigned long long)done, (unsigned long long)total, msg);
    fflush(stdout);
}

/* ── SHA-256 ──────────────────────────────────────────────────────────────────────────────── */
typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t n; } sha256_t;
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha_block(sha256_t *s, const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}
static void sha_init(sha256_t *s)
{
    static const uint32_t iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    memcpy(s->h, iv, sizeof iv); s->len = 0; s->n = 0;
}
static void sha_update(sha256_t *s, const void *data, size_t len)
{
    const uint8_t *p = data;
    s->len += len;
    while (len) {
        size_t take = 64 - s->n < len ? 64 - s->n : len;
        memcpy(s->buf + s->n, p, take);
        s->n += take; p += take; len -= take;
        if (s->n == 64) { sha_block(s, s->buf); s->n = 0; }
    }
}
static void sha_final(sha256_t *s, uint8_t out[32])
{
    uint64_t bits = s->len * 8;
    uint8_t pad = 0x80;
    sha_update(s, &pad, 1);
    uint8_t z = 0;
    while (s->n != 56) sha_update(s, &z, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_update(s, lb, 8);
    for (int i = 0; i < 8; i++) { out[4*i] = s->h[i] >> 24; out[4*i+1] = s->h[i] >> 16; out[4*i+2] = s->h[i] >> 8; out[4*i+3] = s->h[i]; }
}
static void hexstr(const uint8_t *d, size_t n, char *out) { for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", d[i]); }

/* ── RSA-4096 PKCS#1 v1.5 signature verification (public exponent 65537) ──────────────────── */
#define LIMBS 128                         /* 4096 bits in 32-bit limbs, little-endian limb order */
typedef struct { uint32_t v[LIMBS]; } big_t;

static void big_from_bytes(big_t *b, const uint8_t *p, size_t n)   /* big-endian bytes */
{
    memset(b, 0, sizeof *b);
    for (size_t i = 0; i < n && i < LIMBS * 4; i++) {
        size_t bit = (n - 1 - i);                                   /* byte index from the right */
        b->v[bit / 4] |= (uint32_t)p[i] << (8 * (bit % 4));
    }
}
static void big_to_bytes(const big_t *b, uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) { size_t bit = n - 1 - i; p[i] = (uint8_t)(b->v[bit / 4] >> (8 * (bit % 4))); }
}
static int big_cmp(const uint32_t *a, const uint32_t *b, int n)
{
    for (int i = n - 1; i >= 0; i--) if (a[i] != b[i]) return a[i] > b[i] ? 1 : -1;
    return 0;
}
/* r = (a * b) mod m, schoolbook multiply then bitwise shift-subtract reduction (17 of these per
 * verification; speed is not the point here, obvious correctness is). */
static void big_mulmod(big_t *r, const big_t *a, const big_t *b, const big_t *m)
{
    static uint32_t prod[2 * LIMBS];
    memset(prod, 0, sizeof prod);
    for (int i = 0; i < LIMBS; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < LIMBS; j++) {
            uint64_t t = (uint64_t)a->v[i] * b->v[j] + prod[i + j] + carry;
            prod[i + j] = (uint32_t)t; carry = t >> 32;
        }
        prod[i + LIMBS] = (uint32_t)carry;
    }
    uint32_t rem[LIMBS + 1];
    memset(rem, 0, sizeof rem);
    for (int bit = 2 * LIMBS * 32 - 1; bit >= 0; bit--) {
        uint32_t c = 0;                                              /* rem = rem << 1 | bit */
        for (int k = 0; k <= LIMBS; k++) { uint32_t nc = rem[k] >> 31; rem[k] = (rem[k] << 1) | c; c = nc; }
        rem[0] |= (prod[bit / 32] >> (bit % 32)) & 1;
        uint32_t mx[LIMBS + 1];
        memcpy(mx, m->v, sizeof m->v); mx[LIMBS] = 0;
        if (big_cmp(rem, mx, LIMBS + 1) >= 0) {                      /* rem -= m */
            uint64_t borrow = 0;
            for (int k = 0; k <= LIMBS; k++) {
                uint64_t t = (uint64_t)rem[k] - mx[k] - borrow;
                rem[k] = (uint32_t)t; borrow = (t >> 63) & 1;
            }
        }
    }
    memcpy(r->v, rem, sizeof r->v);
}
static int hexval(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

/* Does `sig` (512 bytes) sign SHA-256 digest `h` under the pinned key? */
static int rsa_verify_sha256(const uint8_t sig[512], const uint8_t h[32])
{
    uint8_t nbytes[512];
    for (int i = 0; i < 512; i++) nbytes[i] = (uint8_t)(hexval(KEY_MODULUS_HEX[2*i]) << 4 | hexval(KEY_MODULUS_HEX[2*i+1]));
    big_t n, s, x;
    big_from_bytes(&n, nbytes, 512);
    big_from_bytes(&s, sig, 512);
    if (big_cmp(s.v, n.v, LIMBS) >= 0) return 0;
    x = s;                                               /* s^65537 = s^(2^16) * s */
    for (int i = 0; i < 16; i++) big_mulmod(&x, &x, &x, &n);
    big_mulmod(&x, &x, &s, &n);
    uint8_t em[512];
    big_to_bytes(&x, em, 512);
    static const uint8_t DI[19] = { 0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20 };
    const size_t tlen = sizeof DI + 32;                  /* EM = 00 01 FF..FF 00 || DigestInfo || H */
    if (em[0] != 0x00 || em[1] != 0x01) return 0;
    size_t ps = 512 - tlen - 3;
    for (size_t i = 0; i < ps; i++) if (em[2 + i] != 0xff) return 0;
    if (em[2 + ps] != 0x00) return 0;
    if (memcmp(em + 3 + ps, DI, sizeof DI)) return 0;
    return memcmp(em + 3 + ps + sizeof DI, h, 32) == 0;
}

/* base64 (the .sig files are `openssl base64` of the raw signature) */
static int b64dec(const char *in, uint8_t *out, int cap)
{
    int n = 0; uint32_t acc = 0; int bits = 0;
    for (; *in; in++) {
        int v;
        char c = *in;
        if (c >= 'A' && c <= 'Z') v = c - 'A'; else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52; else if (c == '+') v = 62; else if (c == '/') v = 63;
        else continue;
        acc = acc << 6 | (uint32_t)v; bits += 6;
        if (bits >= 8) { bits -= 8; if (n < cap) out[n++] = (uint8_t)(acc >> bits); }
    }
    return n;
}

/* ── HTTP (plain; integrity from the signatures) ─────────────────────────────────────────── */
typedef int (*sink_fn)(void *ctx, const uint8_t *data, size_t len);   /* nonzero: abort */

static int split_url(const char *url, char *host, size_t hcap, int *port, char *path, size_t pcap)
{
    if (strncmp(url, "http://", 7)) return -1;
    const char *p = url + 7;
    const char *slash = strchr(p, '/');
    const char *colon = memchr(p, ':', slash ? (size_t)(slash - p) : strlen(p));
    size_t hlen = colon ? (size_t)(colon - p) : (slash ? (size_t)(slash - p) : strlen(p));
    if (hlen == 0 || hlen >= hcap) return -1;
    memcpy(host, p, hlen); host[hlen] = 0;
    *port = colon ? atoi(colon + 1) : 80;
    snprintf(path, pcap, "%s", slash ? slash : "/");
    return 0;
}

/* GET url, streaming the body to `sink`.  Returns the HTTP status, -1 on transport failure. */
static int http_get(const char *url, sink_fn sink, void *ctx, uint64_t *content_length)
{
    char host[256], path[512];
    int port;
    if (split_url(url, host, sizeof host, &port, path, sizeof path)) return -1;
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res = NULL;
    char ps[8]; snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(host, ps, &hints, &res) || !res) return -1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0 || connect(s, res->ai_addr, res->ai_addrlen)) { freeaddrinfo(res); if (s >= 0) close(s); return -1; }
    freeaddrinfo(res);
    char req[900];
    /* Exactly what curl 8 sends for `curl -O URL`: nothing here names this system. */
    int rn = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n",
                      path, host);
    for (int off = 0; off < rn; ) { ssize_t w = send(s, req + off, (size_t)(rn - off), 0); if (w <= 0) { close(s); return -1; } off += (int)w; }
    static uint8_t buf[65536];
    char head[4096]; size_t hl = 0;
    int status = -1, in_body = 0, aborted = 0;
    long long clen = -1, got = 0;       /* the connection stays open (keep-alive): stop at clen */
    if (content_length) *content_length = 0;
    for (;;) {
        if (in_body && clen >= 0 && got >= clen) break;
        ssize_t n = recv(s, buf, sizeof buf, 0);
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; status = -1; break; }
        const uint8_t *p = buf; size_t left = (size_t)n;
        if (!in_body) {
            size_t take = left < sizeof head - hl - 1 ? left : sizeof head - hl - 1;
            memcpy(head + hl, p, take); hl += take; head[hl] = 0;
            char *end = strstr(head, "\r\n\r\n");
            if (!end) { if (hl >= sizeof head - 1) { status = -1; break; } continue; }
            sscanf(head, "HTTP/1.%*d %d", &status);
            char *cl = strcasestr(head, "\r\nContent-Length:");
            if (cl && cl < end) clen = strtoll(cl + 17, NULL, 10);
            if (clen >= 0 && content_length) *content_length = (uint64_t)clen;
            size_t hb = (size_t)(end - head) + 4;
            in_body = 1;
            if (status != 200) break;
            if (hl > hb) { got += (long long)(hl - hb); if (sink(ctx, (const uint8_t *)head + hb, hl - hb)) { aborted = 1; break; } }
            if (take < left) { got += (long long)(left - take); if (sink(ctx, p + take, left - take)) { aborted = 1; break; } }
            continue;
        }
        got += (long long)left;
        if (sink(ctx, p, left)) { aborted = 1; break; }
    }
    close(s);
    return aborted ? -2 : status;
}

/* small files into memory */
struct membuf { char *p; size_t n, cap; };
static int mem_sink(void *ctx, const uint8_t *d, size_t len)
{
    struct membuf *m = ctx;
    if (m->n + len + 1 > m->cap) return 1;
    memcpy(m->p + m->n, d, len); m->n += len; m->p[m->n] = 0;
    return 0;
}

/* the image stream: hash the .bz2, decompress, hash + write the image, hold back sector 1 */
struct img {
    int fd;
    sha256_t sha_bz2, sha_img;
    bz_stream bz;
    int bz_end;
    uint64_t out_off, in_bytes, total;
    uint8_t hdr[512];                    /* the image's sector 1 (GPT header), written at commit */
    time_t last_status;
    int err;
};
static int img_write(struct img *im, const uint8_t *d, size_t len)
{
    sha_update(&im->sha_img, d, len);
    while (len) {
        size_t take = len;
        if (im->out_off < 1024 && im->out_off + take > 512) {       /* sector 1: keep, write zeros */
            if (im->out_off < 512) { take = 512 - (size_t)im->out_off; }
            else {
                take = 1024 - (size_t)im->out_off < len ? 1024 - (size_t)im->out_off : len;
                memcpy(im->hdr + (im->out_off - 512), d, take);
                static const uint8_t zeros[512];
                if (pwrite(im->fd, zeros, take, (off_t)im->out_off) != (ssize_t)take) { im->err = errno ? errno : EIO; return 1; }
                im->out_off += take; d += take; len -= take;
                continue;
            }
        }
        ssize_t w = pwrite(im->fd, d, take, (off_t)im->out_off);
        if (w != (ssize_t)take) { im->err = errno ? errno : EIO; return 1; }
        im->out_off += take; d += take; len -= take;
    }
    return 0;
}
static int img_sink(void *ctx, const uint8_t *d, size_t len)
{
    struct img *im = ctx;
    sha_update(&im->sha_bz2, d, len);
    im->in_bytes += len;
    static char out[1 << 17];
    im->bz.next_in = (char *)d;
    im->bz.avail_in = (unsigned)len;
    while (im->bz.avail_in > 0 && !im->bz_end) {
        im->bz.next_out = out;
        im->bz.avail_out = sizeof out;
        int r = BZ2_bzDecompress(&im->bz);
        if (r != BZ_OK && r != BZ_STREAM_END) { im->err = EILSEQ; return 1; }
        size_t produced = sizeof out - im->bz.avail_out;
        if (produced && img_write(im, (const uint8_t *)out, produced)) return 1;
        if (r == BZ_STREAM_END) im->bz_end = 1;
    }
    time_t now = time(NULL);
    if (now != im->last_status) {
        im->last_status = now;
        status("downloading", im->in_bytes, im->total, "%llu MB of the image written",
               (unsigned long long)(im->out_off >> 20));
    }
    return 0;
}

static int try_mirror(const char *mirror)
{
    char url[512];
    static char sums[8192], sumsig[2048], imgsig[2048];
    struct membuf mb;

    status("verifying", 0, 0, "checksums from %s", mirror);
    snprintf(url, sizeof url, "%s/%s", mirror, SUMS);
    mb = (struct membuf){ sums, 0, sizeof sums };
    if (http_get(url, mem_sink, &mb, NULL) != 200) { status("retrying", 0, 0, "no checksum file at %s", mirror); return -1; }
    snprintf(url, sizeof url, "%s/%s.sig", mirror, SUMS);
    mb = (struct membuf){ sumsig, 0, sizeof sumsig };
    if (http_get(url, mem_sink, &mb, NULL) != 200) { status("retrying", 0, 0, "no checksum signature at %s", mirror); return -1; }
    snprintf(url, sizeof url, "%s/%s.sig", mirror, IMAGE);
    mb = (struct membuf){ imgsig, 0, sizeof imgsig };
    if (http_get(url, mem_sink, &mb, NULL) != 200) { status("retrying", 0, 0, "no image signature at %s", mirror); return -1; }

    uint8_t sig[512], h[32];
    sha256_t s;
    if (b64dec(sumsig, sig, sizeof sig) != 512) { status("error", 0, 0, "malformed checksum signature"); return -1; }
    sha_init(&s); sha_update(&s, sums, strlen(sums)); sha_final(&s, h);
    if (!rsa_verify_sha256(sig, h)) { status("error", 0, 0, "the checksum file is NOT signed by the OPNsense " VERSION " key"); return -1; }
    const char *line = strstr(sums, "SHA256 (" IMAGE ".bz2) = ");
    if (!line) { status("error", 0, 0, "the image is not in the signed checksum file"); return -1; }
    char want[65];
    sscanf(line + strlen("SHA256 (" IMAGE ".bz2) = "), "%64[0-9a-f]", want);
    printf("[vm-fetch] checksum file signed by the OPNsense %s key; image SHA-256 %s\n", VERSION, want);

    int fd = open(g_target, O_WRONLY | (g_target_given ? O_CREAT : 0), 0600);
    if (fd < 0) { status("error", 0, 0, "cannot open the VM store %s: %s", g_target, strerror(errno)); return -2; }
    static struct img im;
    memset(&im, 0, sizeof im);
    im.fd = fd;
    sha_init(&im.sha_bz2); sha_init(&im.sha_img);
    if (BZ2_bzDecompressInit(&im.bz, 0, 0) != BZ_OK) { close(fd); return -1; }
    {   /* sector 1 zeroed first: a previous committed image stops being a valid disk right away */
        static const uint8_t zeros[512];
        if (pwrite(fd, zeros, 512, 512) != 512) { status("error", 0, 0, "cannot write the VM store: %s", strerror(errno)); close(fd); return -2; }
    }
    snprintf(url, sizeof url, "%s/%s.bz2", mirror, IMAGE);
    status("downloading", 0, 0, "%s", url);
    int st = http_get(url, img_sink, &im, &im.total);   /* total is set from the header, before the body */
    BZ2_bzDecompressEnd(&im.bz);
    if (st != 200 || !im.bz_end || im.err) {
        status("retrying", im.in_bytes, im.total, "download from %s failed (HTTP %d%s%s)", mirror, st,
               im.err ? ", " : "", im.err ? strerror(im.err) : "");
        close(fd);
        return -1;
    }
    uint8_t hb[32], hi[32];
    char got[65];
    sha_final(&im.sha_bz2, hb); hexstr(hb, 32, got);
    if (strcmp(got, want)) { status("retrying", im.in_bytes, 0, "SHA-256 mismatch from %s", mirror); close(fd); return -1; }
    sha_final(&im.sha_img, hi);
    if (b64dec(imgsig, sig, sizeof sig) != 512 || !rsa_verify_sha256(sig, hi)) {
        status("retrying", im.in_bytes, 0, "the image signature does not verify"); close(fd); return -1;
    }
    /* All three checks passed: commit -- the GPT header, the sector the kernel recognises. */
    if (pwrite(fd, im.hdr, 512, 512) != 512 || fsync(fd) != 0) {
        status("error", im.in_bytes, 0, "committing the image failed: %s", strerror(errno)); close(fd); return -2;
    }
    close(fd);
    status("done", im.in_bytes, im.in_bytes, "OPNsense %s verified and installed (%llu MB)", VERSION,
           (unsigned long long)(im.out_off >> 20));
    return 0;
}

int main(int argc, char **argv)
{
    const char *mirrors[16];
    int nm = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--target") && i + 1 < argc) { g_target = argv[++i]; g_target_given = 1; }
        else if (!strcmp(argv[i], "--status") && i + 1 < argc) g_status_path = argv[++i];
        else if (!strcmp(argv[i], "--mirror") && i + 1 < argc && nm < 16) mirrors[nm++] = argv[++i];
        else if (!strcmp(argv[i], "--selftest-rsa")) {
            /* the pinned key must verify a known-good signature: argv[i+1] = file, argv[i+2] = .sig */
            if (i + 2 >= argc) return 2;
            FILE *f = fopen(argv[i + 1], "rb"); if (!f) return 2;
            sha256_t s; sha_init(&s);
            static uint8_t b[1 << 16]; size_t n;
            while ((n = fread(b, 1, sizeof b, f)) > 0) sha_update(&s, b, n);
            fclose(f);
            uint8_t h[32]; sha_final(&s, h);
            FILE *g = fopen(argv[i + 2], "rb"); if (!g) return 2;
            static char txt[2048]; size_t tn = fread(txt, 1, sizeof txt - 1, g); txt[tn] = 0; fclose(g);
            uint8_t sig[512];
            int ok = b64dec(txt, sig, sizeof sig) == 512 && rsa_verify_sha256(sig, h);
            printf("rsa selftest: %s\n", ok ? "VALID" : "INVALID");
            return ok ? 0 : 1;
        }
    }
    if (nm == 0) for (size_t i = 0; i < sizeof DEFAULT_MIRRORS / sizeof DEFAULT_MIRRORS[0]; i++) mirrors[nm++] = DEFAULT_MIRRORS[i];
    for (int attempt = 0; attempt < 2; attempt++)
        for (int i = 0; i < nm; i++) {
            int r = try_mirror(mirrors[i]);
            if (r == 0) return 0;
            if (r == -2) return 1;                         /* the store itself failed: no point retrying */
        }
    status("error", 0, 0, "every mirror failed; the download is retried at the next boot");
    return 1;
}
