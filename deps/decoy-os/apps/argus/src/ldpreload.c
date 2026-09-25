#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ldpreload.h"

/* Suspicious env var prefixes to scan for */
static const char * const SUSPICIOUS[] = {
    "LD_PRELOAD=",
    "LD_LIBRARY_PATH=",
    "PYTHONPATH=",
    NULL
};

void ldpreload_check(const event_t *e)
{
    if (!e || e->type != EVENT_EXEC)
        return;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/environ", e->pid);

    FILE *f = fopen(path, "rb");
    if (!f)
        return;   /* process may have already exited — that's fine */

    /* Read up to 8192 bytes of the environ blob (NUL-separated entries) */
    char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0)
        return;
    buf[n] = '\0';

    /* Walk NUL-separated entries */
    size_t i = 0;
    while (i < n) {
        const char *entry = buf + i;
        size_t elen = strlen(entry);

        for (int k = 0; SUSPICIOUS[k]; k++) {
            const char *pfx = SUSPICIOUS[k];
            size_t plen = strlen(pfx);
            if (elen >= plen && memcmp(entry, pfx, plen) == 0) {
                /* Found — extract just the var name (without '=') */
                char varname[32] = {};
                size_t vlen = plen - 1;   /* exclude trailing '=' */
                if (vlen >= sizeof(varname)) vlen = sizeof(varname) - 1;
                memcpy(varname, pfx, vlen);
                const char *value = entry + plen;
                fprintf(stderr,
                        "[LD_PRELOAD] pid=%d comm=%s %s=%s\n",
                        e->pid, e->comm, varname, value);
            }
        }

        /* Advance past this entry (past its NUL terminator) */
        i += elen + 1;
    }
}
