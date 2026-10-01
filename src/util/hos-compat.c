/*
 * hos-compat.c -- run software built for another platform from inside a domain.
 *
 * anonymOS runs programs built for its own musl Linux personality.  Software for Windows, macOS
 * and Android runs through a COMPATIBILITY RUNTIME installed in the domain -- Wine for Windows,
 * Darling for macOS, Waydroid for Android.  This one small launcher is the shim between the two:
 * the Domain Manager delegates it to a domain as an ordinary application (appreg.d: hos-wine /
 * hos-darling / hos-waydroid are APP, delegable), and once the matching runtime is installed there
 * the foreign program runs as if it were native to that domain -- isolated, badged and routed like
 * everything else in it.
 *
 * It is ONE binary, staged under three names; argv[0]'s basename picks the runtime.  Invoked as the
 * generic `hos-compat <file>` it reads the file's first bytes and picks the runtime from them (PE
 * "MZ" -> Wine, Mach-O / universal -> Darling, an Android .apk (a Zip "PK") -> Waydroid).
 *
 * It installs nothing and needs no privilege of its own: it finds the runtime the domain already
 * has (the Software Center installs Wine into a domain; Darling and Waydroid are built by
 * scripts/build-{darling,waydroid}.sh -- see docs/COMPAT.md), and execs it.  When the runtime is
 * absent it says exactly which package or build step provides it and exits, rather than failing
 * obscurely.  It never falls back to running a foreign binary as a native one.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

enum rt { RT_NONE, RT_WINE, RT_DARLING, RT_WAYDROID };

/* Where each runtime's entry binary is looked for, and what provides it when missing. */
struct runtime {
    const char *name;        /* human name                                   */
    const char *const *bins; /* candidate entry binaries, in preference order */
    const char *verb;        /* a subcommand to insert before the file, or NULL */
    const char *provides;    /* the one line shown when it is not installed   */
};

static const char *wine_bins[]     = { "wine64", "wine", NULL };
static const char *darling_bins[]  = { "darling", NULL };
static const char *waydroid_bins[] = { "waydroid", NULL };

static const struct runtime RUNTIMES[] = {
    [RT_WINE] = { "Wine (Windows)", wine_bins, NULL,
        "Wine is not installed in this domain. Install it from the Software Center "
        "(package: wine), then run Windows programs here." },
    [RT_DARLING] = { "Darling (macOS)", darling_bins, "shell",
        "Darling is not installed in this domain. Build it with scripts/build-darling.sh and "
        "install it into this domain, then run macOS programs here (see docs/COMPAT.md)." },
    [RT_WAYDROID] = { "Waydroid (Android)", waydroid_bins, "app",
        "Waydroid is not installed in this domain. Build it with scripts/build-waydroid.sh and "
        "install it into this domain, then run Android apps here (see docs/COMPAT.md)." },
};

static const char *basename_of(const char *p) {
    const char *b = p;
    for (const char *s = p; *s; ++s)
        if (*s == '/') b = s + 1;
    return b;
}

static enum rt runtime_from_argv0(const char *argv0) {
    const char *b = basename_of(argv0);
    if (!strcmp(b, "hos-wine"))     return RT_WINE;
    if (!strcmp(b, "hos-darling"))  return RT_DARLING;
    if (!strcmp(b, "hos-waydroid")) return RT_WAYDROID;
    return RT_NONE;
}

/* Sniff a file's leading bytes to choose a runtime, for the generic `hos-compat <file>`. */
static enum rt runtime_from_file(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return RT_NONE;
    unsigned char h[4] = {0};
    ssize_t n = read(fd, h, sizeof h);
    close(fd);
    if (n < 2) return RT_NONE;
    if (h[0] == 'M' && h[1] == 'Z') return RT_WINE;                      /* PE/COFF (.exe/.dll) */
    if (h[0] == 'P' && h[1] == 'K') return RT_WAYDROID;                  /* Zip -> Android .apk */
    if (n >= 4) {
        unsigned be = (unsigned)h[0] << 24 | h[1] << 16 | h[2] << 8 | h[3];
        if (be == 0xFEEDFACEu || be == 0xFEEDFACFu ||                    /* Mach-O 32/64        */
            be == 0xCAFEBABEu || be == 0xCFFAEDFEu || be == 0xCEFAEDFEu) /* universal / LE      */
            return RT_DARLING;
    }
    return RT_NONE;
}

/* Is `bin` runnable on PATH or at a couple of well-known prefixes? */
static int have_binary(const char *bin) {
    if (strchr(bin, '/')) return access(bin, X_OK) == 0;
    const char *paths = getenv("PATH");
    char buf[512];
    const char *fallback = "/usr/local/bin:/usr/bin:/bin";
    if (!paths || !*paths) paths = fallback;
    const char *p = paths;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t len = colon ? (size_t)(colon - p) : strlen(p);
        if (len && len + 1 + strlen(bin) + 1 < sizeof buf) {
            memcpy(buf, p, len);
            buf[len] = '/';
            strcpy(buf + len + 1, bin);
            if (access(buf, X_OK) == 0) return 1;
        }
        if (!colon) break;
        p = colon + 1;
    }
    return 0;
}

static const char *find_binary(const struct runtime *rt) {
    for (const char *const *b = rt->bins; *b; ++b)
        if (have_binary(*b)) return *b;
    return NULL;
}

int main(int argc, char **argv) {
    enum rt which = runtime_from_argv0(argv[0]);
    int firstarg = 1;

    if (which == RT_NONE) {
        /* Generic entry: `hos-compat <file> [args]` -- choose by the file's header. */
        if (argc < 2) {
            fputs("hos-compat: run a Windows (.exe), macOS or Android (.apk) program in this domain.\n"
                  "usage: hos-compat <program> [args]   (or run as hos-wine / hos-darling / hos-waydroid)\n",
                  stderr);
            return 2;
        }
        which = runtime_from_file(argv[1]);
        if (which == RT_NONE) {
            fprintf(stderr, "hos-compat: %s is not a recognised Windows, macOS or Android program.\n", argv[1]);
            return 2;
        }
    }

    const struct runtime *rt = &RUNTIMES[which];

    if (argc < firstarg + 1 && which != RT_WAYDROID) {
        /* Launched with no program (e.g. straight from the app grid): say what this is for. */
        fprintf(stderr, "%s: give a program to run in this domain, e.g. %s <program>.\n",
                basename_of(argv[0]), basename_of(argv[0]));
        return 2;
    }

    const char *bin = find_binary(rt);
    if (!bin) {
        fprintf(stderr, "%s\n", rt->provides);
        return 127;
    }

    /* Build: <bin> [verb] <passed args...> */
    char *av[argc + 3];
    int n = 0;
    av[n++] = (char *)bin;
    if (rt->verb) av[n++] = (char *)rt->verb;
    for (int i = firstarg; i < argc; ++i) av[n++] = argv[i];
    av[n] = NULL;

    execvp(bin, av);
    fprintf(stderr, "%s: could not start %s: %s\n", basename_of(argv[0]), bin, strerror(errno));
    return 127;
}
