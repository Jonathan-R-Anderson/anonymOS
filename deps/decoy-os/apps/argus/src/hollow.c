#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "hollow.h"
#include "argus.h"

/*
 * Read the first executable mapping from /proc/<pid>/maps.
 * Writes the mapped file path into 'out' (up to outlen bytes).
 * Returns 0 on success, -1 on failure.
 */
static int first_exec_map(int pid, char *out, size_t outlen)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f)
        return -1;

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Format: addr-addr perms offset dev inode [path] */
        /* We want lines with 'x' in perms and a non-empty path */
        char perms[8] = {};
        char path[256] = {};
        unsigned long long start, end, offset;
        unsigned int dev_maj, dev_min;
        unsigned long long inode;

        int n = sscanf(line, "%llx-%llx %7s %llx %x:%x %llu %255[^\n]",
                       &start, &end, perms, &offset,
                       &dev_maj, &dev_min, &inode, path);
        if (n < 3)
            continue;
        if (perms[2] != 'x')   /* not executable */
            continue;
        if (!path[0] || path[0] == '[')  /* anonymous or vdso */
            continue;
        /* Strip leading spaces that sscanf may have left */
        char *p = path;
        while (*p == ' ') p++;
        strncpy(out, p, outlen - 1);
        out[outlen - 1] = '\0';
        found = 1;
        break;
    }
    fclose(f);
    return found ? 0 : -1;
}

int hollow_check(const event_t *ev)
{
    if (ev->type != EVENT_EXEC)
        return 0;

    /* Memfd / anonymous execution: binary was never on disk */
    if (ev->filename[0] == '\0' ||
        strncmp(ev->filename, "memfd:", 6) == 0 ||
        strstr(ev->filename, "(deleted)") != NULL) {
        fprintf(stderr,
            "[HOLLOW] pid=%-6d comm=%-16s fileless execution detected: %s\n",
            ev->pid, ev->comm,
            ev->filename[0] ? ev->filename : "(empty)");
        syslog(LOG_CRIT,
            "HOLLOW pid=%d comm=%s fileless execution: %s",
            ev->pid, ev->comm,
            ev->filename[0] ? ev->filename : "(empty)");
        return 1;
    }

    /* Read the actual first executable mapping */
    char mapped[256] = {};
    if (first_exec_map(ev->pid, mapped, sizeof(mapped)) != 0)
        return 0;   /* can't read maps — process may have exited already */

    /* Strip " (deleted)" suffix if present */
    char *del = strstr(mapped, " (deleted)");
    if (del) *del = '\0';

    /* Compare exe symlink vs first mapped executable */
    if (mapped[0] && strcmp(ev->filename, mapped) != 0) {
        /* Allow interpreter mismatches: scripts run via bash/python/etc. */
        const char *known_interps[] = {
            "/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/python",
            "/usr/bin/python3", "/usr/bin/perl", "/usr/bin/ruby", NULL
        };
        for (int i = 0; known_interps[i]; i++) {
            if (strncmp(mapped, known_interps[i],
                        strlen(known_interps[i])) == 0)
                return 0;
        }

        fprintf(stderr,
            "[HOLLOW] pid=%-6d comm=%-16s exe=%s maps_exec=%s\n",
            ev->pid, ev->comm, ev->filename, mapped);
        syslog(LOG_CRIT,
            "HOLLOW pid=%d comm=%s exe=%s maps_exec=%s",
            ev->pid, ev->comm, ev->filename, mapped);
        return 1;
    }

    return 0;
}
