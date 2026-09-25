#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <syslog.h>
#include "memforensics.h"
#include "argus.h"

#ifdef HAVE_YARA
extern int yara_scan_buf(const unsigned char *buf, size_t size, const event_t *ev);
#endif

/* Maximum bytes read from a single mapping (16 MB) */
#define MEMF_MAX_READ   (16u * 1024u * 1024u)
/* Skip mappings larger than this (64 MB) */
#define MEMF_MAX_MAP    (64u * 1024u * 1024u)

/* --------------------------------------------------------------------------
 * Entropy calculation
 * -------------------------------------------------------------------------- */

/*
 * Compute Shannon entropy (bits per byte, range 0.0–8.0) of buf[0..size-1].
 * Returns 0.0 for an empty buffer.
 */
static double compute_entropy(const unsigned char *buf, size_t size)
{
    if (!buf || size == 0)
        return 0.0;

    unsigned long counts[256];
    memset(counts, 0, sizeof(counts));

    for (size_t i = 0; i < size; i++)
        counts[buf[i]]++;

    double entropy = 0.0;
    double n = (double)size;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0)
            continue;
        double p = (double)counts[i] / n;
        entropy -= p * log2(p);
    }
    return entropy;
}

/* --------------------------------------------------------------------------
 * /proc/<pid>/maps parser
 * -------------------------------------------------------------------------- */

/*
 * Scan one line from /proc/<pid>/maps.
 * Returns 1 and fills start/end if the line describes an anonymous
 * executable mapping (rwxp or r-xp with no trailing path), 0 otherwise.
 *
 * Example maps line:
 *   7f1234560000-7f1234580000 rwxp 00000000 00:00 0
 * (no filename after the inode field → anonymous)
 */
static int parse_anon_exec_line(const char *line,
                                unsigned long *start,
                                unsigned long *end)
{
    unsigned long lo = 0, hi = 0;
    char perms[8];
    unsigned long offset = 0;
    unsigned int dev_major = 0, dev_minor = 0;
    unsigned long inode = 0;
    char rest[512];

    rest[0] = '\0';
    int n = sscanf(line, "%lx-%lx %7s %lx %x:%x %lu%511[^\n]",
                   &lo, &hi, perms, &offset,
                   &dev_major, &dev_minor, &inode, rest);

    if (n < 7)
        return 0;

    /* Must have exec bit */
    if (perms[2] != 'x')
        return 0;

    /* Anonymous mapping: inode must be 0 and rest must be empty or whitespace only */
    if (inode != 0)
        return 0;

    /* Check rest contains nothing but whitespace (no filename) */
    const char *p = rest;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '\0' && *p != '\n')
        return 0;   /* has a filename → not anonymous */

    /* Sanity: size must be non-zero and below our skip threshold */
    if (hi <= lo)
        return 0;

    *start = lo;
    *end   = hi;
    return 1;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

void memforensics_init(void)
{
    /* Nothing to initialise currently.
     * When HAVE_YARA is defined the YARA runtime is managed by yara_scan.c;
     * we rely on yara_scan_buf() being callable after yara_scan_init(). */
}

void memforensics_check(const event_t *ev)
{
    if (!ev)
        return;
    if (ev->type != EVENT_MEMEXEC)
        return;
    if (ev->pid <= 0)
        return;

    /* ------------------------------------------------------------------ */
    /* Open /proc/<pid>/maps                                               */
    /* ------------------------------------------------------------------ */
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", ev->pid);

    FILE *maps_fp = fopen(maps_path, "r");
    if (!maps_fp)
        return;   /* process may have already exited */

    /* ------------------------------------------------------------------ */
    /* Open /proc/<pid>/mem                                                */
    /* ------------------------------------------------------------------ */
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", ev->pid);

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        fclose(maps_fp);
        return;
    }

    /* ------------------------------------------------------------------ */
    /* Walk maps lines                                                     */
    /* ------------------------------------------------------------------ */
    char line[512];
    while (fgets(line, sizeof(line), maps_fp)) {
        unsigned long map_start = 0, map_end = 0;

        if (!parse_anon_exec_line(line, &map_start, &map_end))
            continue;

        size_t map_size = (size_t)(map_end - map_start);

        if (map_size > MEMF_MAX_MAP) {
            fprintf(stderr,
                "[MEMFORENSICS] pid=%-6d comm=%-16s skipping huge anon_exec_mapping "
                "addr=0x%lx-0x%lx size=%zu\n",
                ev->pid, ev->comm, map_start, map_end, map_size);
            continue;
        }

        size_t read_size = map_size;
        if (read_size > MEMF_MAX_READ)
            read_size = MEMF_MAX_READ;

        unsigned char *buf = (unsigned char *)malloc(read_size);
        if (!buf)
            continue;

        /* Seek to the start of the mapping in /proc/<pid>/mem */
        if (lseek(mem_fd, (off_t)map_start, SEEK_SET) == (off_t)-1) {
            free(buf);
            continue;
        }

        ssize_t nread = read(mem_fd, buf, read_size);
        if (nread <= 0) {
            free(buf);
            continue;
        }

        size_t actual = (size_t)nread;
        double entropy = compute_entropy(buf, actual);

        fprintf(stderr,
            "[MEMFORENSICS] pid=%-6d comm=%-16s anon_exec_mapping "
            "addr=0x%lx-0x%lx size=%zu entropy=%.2f\n",
            ev->pid, ev->comm, map_start, map_end, actual, entropy);

        int suspicious = (entropy > 7.5);

#ifdef HAVE_YARA
        int yara_hits = yara_scan_buf(buf, actual, ev);
        if (yara_hits > 0)
            suspicious = 1;
#endif

        if (suspicious) {
            syslog(LOG_WARNING,
                "MEMFORENSICS pid=%d comm=%s anon_exec_mapping "
                "addr=0x%lx-0x%lx size=%zu entropy=%.2f",
                ev->pid, ev->comm, map_start, map_end, actual, entropy);
        }

        free(buf);
    }

    close(mem_fd);
    fclose(maps_fp);
}
