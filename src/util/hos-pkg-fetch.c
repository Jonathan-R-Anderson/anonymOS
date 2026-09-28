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
 * stack, so the mirror is spoken to over plain HTTP.  Alpine's index/packages are signed; verifying
 * that signature before execution is future work and is called out in the log rather than skipped
 * silently.
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

/* Inflate a gzip file (possibly several concatenated gzip members, as an .apk is) to outpath.
 * Returns 0 on success, -1 on error.  zlib's 15+32 window auto-detects the gzip header; on
 * Z_STREAM_END we reset and keep going so all concatenated members decompress into one stream. */
static int gunzip_to_file(const char *inpath, const char *outpath)
{
    int in = open(inpath, O_RDONLY);
    if (in < 0) { plog("[pkg] gunzip: cannot open %s (errno %d)", inpath, errno); return -1; }
    int out = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { plog("[pkg] gunzip: cannot write %s (errno %d)", outpath, errno); close(in); return -1; }

    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (inflateInit2(&zs, 15 + 32) != Z_OK) { close(in); close(out); return -1; }

    unsigned char inbuf[16384], outbuf[16384];
    int rc = 0;
    for (;;) {
        ssize_t n = read(in, inbuf, sizeof inbuf);
        if (n < 0) { if (errno == EINTR) continue; rc = -1; break; }
        if (n == 0) break;                             /* EOF */
        zs.next_in = inbuf;
        zs.avail_in = (uInt)n;
        while (zs.avail_in > 0) {
            zs.next_out = outbuf;
            zs.avail_out = sizeof outbuf;
            int r = inflate(&zs, Z_NO_FLUSH);
            size_t have = sizeof outbuf - zs.avail_out;
            if (have) { ssize_t w = write(out, outbuf, have); (void)w; }
            if (r == Z_STREAM_END) { inflateReset(&zs); continue; } /* next concatenated member */
            if (r != Z_OK) { plog("[pkg] gunzip: inflate error %d", r); rc = -1; break; }
        }
        if (rc) break;
    }
    inflateEnd(&zs);
    close(in);
    close(out);
    return rc;
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
 * to manifest_fd.  Directory, symlink, and control entries are skipped (their data is consumed).
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
        } else {
            /* directory / symlink / control member: consume its data + padding */
            unsigned long skip = padded;
            while (skip > 0) { unsigned char t[512]; ssize_t g = read_full(in, t, skip < 512 ? skip : 512); if (g <= 0) break; skip -= (size_t)g; }
        }
    }
    close(in);
    return count;
}

/* Find the version of package `name` in a decompressed APKINDEX at indexpath.  APKINDEX is a set of
 * blank-line-separated records; within a record `P:` is the name and `V:` the version.  Copies the
 * version of the matching record into ver (NUL-terminated).  Returns 0 on success, -1 if not found. */
static int apk_find_version(const char *indexpath, const char *name, char *ver, size_t vercap)
{
    int fd = open(indexpath, O_RDONLY);
    if (fd < 0) return -1;
    /* Read the whole index into memory (APKINDEX for one repo is a few MB). */
    size_t cap = 1 << 20, len = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return -1; }
    for (;;) {
        if (len + 65536 > cap) { cap *= 2; char *nb = realloc(buf, cap); if (!nb) { free(buf); close(fd); return -1; } buf = nb; }
        ssize_t n = read(fd, buf + len, 65536);
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; free(buf); close(fd); return -1; }
        len += (size_t)n;
    }
    close(fd);

    int found = -1;
    size_t namelen = strlen(name);
    char curver[64] = "";
    int match = 0;
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && buf[j] != '\n') j++;
        size_t linelen = j - i;
        const char *line = buf + i;
        if (linelen == 0) {                              /* record boundary */
            if (match && curver[0]) { snprintf(ver, vercap, "%s", curver); found = 0; break; }
            match = 0; curver[0] = 0;
        } else if (linelen >= 2 && line[0] == 'P' && line[1] == ':') {
            match = (linelen - 2 == namelen && !memcmp(line + 2, name, namelen));
        } else if (linelen >= 2 && line[0] == 'V' && line[1] == ':') {
            size_t vl = linelen - 2; if (vl >= sizeof curver) vl = sizeof curver - 1;
            memcpy(curver, line + 2, vl); curver[vl] = 0;
        }
        i = j + 1;
    }
    if (found != 0 && match && curver[0]) { snprintf(ver, vercap, "%s", curver); found = 0; }
    free(buf);
    return found;
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
        char rbuf[512];
        ssize_t n = read(fd, rbuf, sizeof rbuf - 1);
        close(fd);
        if (n <= 0) { fprintf(stderr, "hos-pkg-fetch: empty request\n"); return 2; }
        rbuf[n] = 0;
        if (sscanf(rbuf, "%63s %127s %255s", pkgmgr, name, base) < 2) {
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

    /* 1. Fetch the repository index, decompress it, and resolve the package's exact version. */
    char idxurl[300], idxgz[256], idxtar[256];
    snprintf(idxurl, sizeof idxurl, "%s/APKINDEX.tar.gz", path);
    snprintf(idxgz,  sizeof idxgz,  CACHE_DIR "/%s.APKINDEX.tar.gz", name);
    snprintf(idxtar, sizeof idxtar, CACHE_DIR "/%s.APKINDEX.tar", name);
    size_t nidx = 0;
    int status = http_get(host, port, idxurl, idxgz, &nidx);
    if (status < 0) return fail_exit(name);
    if (status != 200) { plog("[pkg] mirror answered HTTP %d for the index — nothing installed", status); return fail_exit(name); }
    plog("[pkg] fetched %zu bytes of index; decompressing", nidx);
    if (gunzip_to_file(idxgz, idxtar) != 0) { plog("[pkg] could not decompress the index"); return fail_exit(name); }

    /* The APKINDEX file inside the tar is what carries P:/V:.  Extract the data members of the
     * index tarball into a temp dir; the "APKINDEX" file lands there. */
    char idxdir[256], idxfile[300];
    snprintf(idxdir, sizeof idxdir, CACHE_DIR "/%s.idx", name);
    mkdir(idxdir, 0755);
    { int mf = open("/dev/null", O_WRONLY); if (mf < 0) mf = g_log;
      ustar_extract_data(idxtar, idxdir, mf); if (mf != g_log && mf >= 0) close(mf); }
    snprintf(idxfile, sizeof idxfile, "%s/APKINDEX", idxdir);

    char ver[64] = "";
    if (apk_find_version(idxfile, name, ver, sizeof ver) != 0 || !ver[0]) {
        plog("[pkg] %s not found in the repository index (%s) — nothing installed", name, host);
        return fail_exit(name);
    }
    plog("[pkg] resolved %s to version %s", name, ver);

    /* 2. Fetch the package's .apk (named <name>-<version>.apk under the repo base). */
    char apkurl[400], apkpath[300];
    snprintf(apkurl, sizeof apkurl, "%s/%s-%s.apk", path, name, ver);
    snprintf(apkpath, sizeof apkpath, CACHE_DIR "/%s-%s.apk", name, ver);
    size_t napk = 0;
    status = http_get(host, port, apkurl, apkpath, &napk);
    if (status < 0) return fail_exit(name);
    if (status != 200) { plog("[pkg] mirror answered HTTP %d for %s-%s.apk — nothing installed", status, name, ver); return fail_exit(name); }
    plog("[pkg] fetched %zu bytes of %s-%s.apk", napk, name, ver);

    /* 3. Decompress + unpack the .apk's data members into a staging tree, recording a manifest. */
    char apktar[300], stagedir[256], manifestpath[256];
    snprintf(apktar,       sizeof apktar,       CACHE_DIR "/%s.pkg.tar", name);
    snprintf(stagedir,     sizeof stagedir,     CACHE_DIR "/%s.files", name);
    snprintf(manifestpath, sizeof manifestpath, CACHE_DIR "/%s.manifest", name);
    if (gunzip_to_file(apkpath, apktar) != 0) { plog("[pkg] could not decompress %s-%s.apk", name, ver); return fail_exit(name); }
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
    plog("[pkg] NOTE: signature verification of the .apk is not yet performed (future work)");
    return 0;
}
