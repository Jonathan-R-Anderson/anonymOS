/*
 * Minimal functional libuuid for the HanonymOS sysroot.
 * Implements the subset of util-linux libuuid that Hyprland uses, generating
 * RFC 4122 version-4 (random) UUIDs from getrandom(2).
 */
#include "uuid.h"

#include <string.h>
#include <stdio.h>
#include <stddef.h>

#if defined(__has_include)
#  if __has_include(<sys/random.h>)
#    include <sys/random.h>
#    define HOS_HAVE_GETRANDOM 1
#  endif
#endif

#ifndef HOS_HAVE_GETRANDOM
#include <fcntl.h>
#include <unistd.h>
#endif

static void hos_fill_random(unsigned char *buf, size_t n) {
    size_t off = 0;
#ifdef HOS_HAVE_GETRANDOM
    while (off < n) {
        ssize_t r = getrandom(buf + off, n - off, 0);
        if (r <= 0)
            break;
        off += (size_t)r;
    }
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        while (off < n) {
            ssize_t r = read(fd, buf + off, n - off);
            if (r <= 0)
                break;
            off += (size_t)r;
        }
        close(fd);
    }
#endif
    /* Deterministic fallback so we never emit an all-zero UUID. */
    for (; off < n; off++)
        buf[off] = (unsigned char)(0x55u ^ (unsigned)off);
}

void uuid_generate_random(uuid_t out) {
    hos_fill_random(out, 16);
    out[6] = (unsigned char)((out[6] & 0x0F) | 0x40); /* version 4 */
    out[8] = (unsigned char)((out[8] & 0x3F) | 0x80); /* variant 1 */
}

void uuid_generate(uuid_t out) {
    uuid_generate_random(out);
}

void uuid_generate_time(uuid_t out) {
    uuid_generate_random(out);
}

int uuid_generate_time_safe(uuid_t out) {
    uuid_generate_random(out);
    return -1; /* time-safe path unavailable; mirrors libuuid's failure return */
}

void uuid_clear(uuid_t uu) {
    memset(uu, 0, 16);
}

void uuid_copy(uuid_t dst, const uuid_t src) {
    memcpy(dst, src, 16);
}

int uuid_compare(const uuid_t uu1, const uuid_t uu2) {
    return memcmp(uu1, uu2, 16);
}

int uuid_is_null(const uuid_t uu) {
    for (int i = 0; i < 16; i++)
        if (uu[i])
            return 0;
    return 1;
}

static void hos_unparse(const uuid_t uu, char *out, const char *fmt) {
    char *p = out;
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            *p++ = '-';
        p += sprintf(p, fmt, uu[i]);
    }
    *p = '\0';
}

void uuid_unparse_lower(const uuid_t uu, char *out) {
    hos_unparse(uu, out, "%02x");
}

void uuid_unparse_upper(const uuid_t uu, char *out) {
    hos_unparse(uu, out, "%02X");
}

void uuid_unparse(const uuid_t uu, char *out) {
    uuid_unparse_lower(uu, out);
}

int uuid_parse(const char *in, uuid_t uu) {
    if (!in)
        return -1;
    if (strlen(in) != 36)
        return -1;
    int j = 0;
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (in[i] != '-')
                return -1;
            continue;
        }
        unsigned int hi, lo;
        char c = in[i], d = in[i + 1];
        i++;
        #define HEXVAL(ch, v) do { \
            if ((ch) >= '0' && (ch) <= '9') (v) = (unsigned)((ch) - '0'); \
            else if ((ch) >= 'a' && (ch) <= 'f') (v) = (unsigned)((ch) - 'a' + 10); \
            else if ((ch) >= 'A' && (ch) <= 'F') (v) = (unsigned)((ch) - 'A' + 10); \
            else return -1; \
        } while (0)
        HEXVAL(c, hi);
        HEXVAL(d, lo);
        #undef HEXVAL
        uu[j++] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}
