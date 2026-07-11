/* Minimal HTTP/1.1 uploader for the LKL socket shim.
 *
 * Do not replace this with stdio on the network fd: musl's hidden stdio backend issues
 * SYS_readv/SYS_writev directly, bypassing LD_PRELOAD and hitting libnshim's AF_UNIX placeholder.
 * This client deliberately uses the public socket/send/recv API, which libnshim can route.
 */
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: hos-http-upload IP PORT FILE\n");
        return 2;
    }
    char *end = NULL;
    long port = strtol(argv[2], &end, 10);
    if (!end || *end || port < 1 || port > 65535) {
        fprintf(stderr, "invalid port: %s\n", argv[2]);
        return 2;
    }
    int in = open(argv[3], O_RDONLY);
    struct stat st;
    if (in < 0 || fstat(in, &st) != 0 || st.st_size < 0) {
        fprintf(stderr, "cannot open/stat %s: errno=%d\n", argv[3], errno);
        if (in >= 0) close(in);
        return 2;
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (s < 0 || inet_pton(AF_INET, argv[1], &sa.sin_addr) != 1 ||
        connect(s, (struct sockaddr *)&sa, sizeof sa) != 0) {
        fprintf(stderr, "connect %s:%ld failed: errno=%d\n", argv[1], port, errno);
        if (s >= 0) close(s);
        close(in);
        return 3;
    }

    char hdr[512];
    int hn = snprintf(hdr, sizeof hdr,
        "POST /upload HTTP/1.1\r\nHost: %s:%ld\r\n"
        "Content-Type: application/octet-stream\r\nContent-Length: %lld\r\n"
        "Connection: close\r\n\r\n", argv[1], port, (long long)st.st_size);
    if (hn <= 0 || hn >= (int)sizeof hdr || send_all(s, hdr, (size_t)hn) != 0) goto ioerr;

    unsigned char buf[16384];
    for (;;) {
        ssize_t n = read(in, buf, sizeof buf);
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; goto ioerr; }
        if (send_all(s, buf, (size_t)n) != 0) goto ioerr;
    }
    close(in); in = -1;

    char response[512];
    ssize_t rn;
    do rn = recv(s, response, sizeof response - 1, 0); while (rn < 0 && errno == EINTR);
    if (rn <= 0) goto ioerr;
    response[rn] = 0;
    close(s);
    if (strncmp(response, "HTTP/1.0 200", 12) && strncmp(response, "HTTP/1.1 200", 12)) {
        char *eol = strstr(response, "\r\n"); if (eol) *eol = 0;
        fprintf(stderr, "server returned: %s\n", response);
        return 5;
    }
    return 0;

ioerr:
    fprintf(stderr, "HTTP transfer failed: errno=%d\n", errno);
    if (in >= 0) close(in);
    close(s);
    return 4;
}
