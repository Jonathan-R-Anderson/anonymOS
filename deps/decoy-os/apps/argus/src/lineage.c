#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <dirent.h>
#include "lineage.h"

/* ── process table ──────────────────────────────────────────────────────── */

#define TABLE_SIZE 8192           /* must be power of 2                      */
#define TABLE_MASK (TABLE_SIZE-1)
#define PID_EMPTY  0              /* slot is free                            */
#define PID_DEAD   UINT32_MAX     /* tombstone after lineage_remove()        */

typedef struct {
    uint32_t pid;
    uint32_t ppid;
    char     comm[16];
} slot_t;

static slot_t g_table[TABLE_SIZE];

static slot_t *lookup(uint32_t pid)
{
    uint32_t h = (pid * 2654435761u) & TABLE_MASK; /* Knuth multiplicative */
    for (int i = 0; i < TABLE_SIZE; i++) {
        slot_t *s = &g_table[(h + i) & TABLE_MASK];
        if (s->pid == PID_EMPTY)
            return NULL;               /* not found, clean stop  */
        if (s->pid == pid)
            return s;                  /* found                  */
        /* PID_DEAD or collision: keep probing */
    }
    return NULL;
}

static slot_t *find_insert_slot(uint32_t pid)
{
    uint32_t h = (pid * 2654435761u) & TABLE_MASK;
    slot_t *tombstone = NULL;
    for (int i = 0; i < TABLE_SIZE; i++) {
        slot_t *s = &g_table[(h + i) & TABLE_MASK];
        if (s->pid == pid)
            return s;                  /* update existing entry  */
        if (s->pid == PID_EMPTY)
            return tombstone ? tombstone : s;  /* insert here    */
        if (s->pid == PID_DEAD && !tombstone)
            tombstone = s;             /* reuse first tombstone  */
    }
    return tombstone;                  /* table full, reuse tombstone */
}

void lineage_update(uint32_t pid, uint32_t ppid, const char *comm)
{
    if (pid == PID_EMPTY || pid == PID_DEAD)
        return;
    slot_t *s = find_insert_slot(pid);
    if (!s)
        return;
    s->pid  = pid;
    s->ppid = ppid;
    strncpy(s->comm, comm, sizeof(s->comm) - 1);
    s->comm[sizeof(s->comm) - 1] = '\0';
}

void lineage_remove(uint32_t pid)
{
    slot_t *s = lookup(pid);
    if (s)
        s->pid = PID_DEAD;
}

/* ── lineage_scan_proc ──────────────────────────────────────────────────── */

void lineage_scan_proc(void)
{
    DIR *d = opendir("/proc");
    if (!d)
        return;

    struct dirent *ent;
    while ((ent = readdir(d))) {
        /* only numeric entries are PIDs */
        const char *np = ent->d_name;
        while (*np >= '0' && *np <= '9') np++;
        if (*np || np == ent->d_name)
            continue;

        char path[280];   /* "/proc/" + NAME_MAX(255) + "/status" + NUL */
        snprintf(path, sizeof(path), "/proc/%s/status", ent->d_name);
        FILE *f = fopen(path, "r");
        if (!f)
            continue;

        uint32_t pid  = (uint32_t)atoi(ent->d_name);
        uint32_t ppid = 0;
        char     comm[16] = {};
        char     line[256];

        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Name:\t", 6) == 0) {
                strncpy(comm, line + 6, sizeof(comm) - 1);
                char *nl = strchr(comm, '\n');
                if (nl) *nl = '\0';
            } else if (strncmp(line, "PPid:\t", 6) == 0) {
                ppid = (uint32_t)atoi(line + 6);
            }
        }
        fclose(f);

        if (pid && comm[0])
            lineage_update(pid, ppid, comm);
    }

    closedir(d);
}

/* ── lineage_str ────────────────────────────────────────────────────────── */

#define MAX_DEPTH   16
#define ARROW       "\xe2\x86\x92"   /* UTF-8 → */

char *lineage_str(uint32_t ppid, char *buf, size_t len)
{
    if (!buf || len == 0)
        return buf;
    buf[0] = '\0';

    /* Walk the parent chain, collecting comms onto a small stack */
    const char *stack[MAX_DEPTH];
    int depth = 0;

    uint32_t cur = ppid;
    for (int i = 0; i < MAX_DEPTH && cur > 1; i++) {
        slot_t *s = lookup(cur);
        if (!s)
            break;
        stack[depth++] = s->comm;
        cur = s->ppid;
    }

    if (depth == 0) {
        strncpy(buf, "?", len - 1);
        buf[len - 1] = '\0';
        return buf;
    }

    /* Reverse stack so output reads root→...→parent */
    size_t off = 0;
    for (int i = depth - 1; i >= 0 && off < len - 1; i--) {
        if (i < depth - 1) {
            /* append arrow separator */
            size_t alen = sizeof(ARROW) - 1;
            if (off + alen >= len - 1)
                break;
            memcpy(buf + off, ARROW, alen);
            off += alen;
        }
        size_t clen = strnlen(stack[i], 16);
        if (off + clen >= len - 1)
            clen = len - 1 - off;
        memcpy(buf + off, stack[i], clen);
        off += clen;
    }
    buf[off] = '\0';
    return buf;
}

/* ── lineage_parent_comm ────────────────────────────────────────────────── */

void lineage_parent_comm(uint32_t ppid, char *out, size_t outsz)
{
    if (!out || outsz == 0)
        return;
    out[0] = '\0';
    if (ppid == 0)
        return;
    slot_t *s = lookup(ppid);
    if (!s)
        return;
    strncpy(out, s->comm, outsz - 1);
    out[outsz - 1] = '\0';
}

/* ── lineage_has_ancestor ───────────────────────────────────────────────── */

int lineage_has_ancestor(uint32_t ppid, const char *target_comm)
{
    if (!target_comm || !target_comm[0])
        return 0;

    uint32_t cur = ppid;
    for (int i = 0; i < MAX_DEPTH && cur > 1; i++) {
        slot_t *s = lookup(cur);
        if (!s)
            break;
        if (strncmp(s->comm, target_comm, 15) == 0)
            return 1;
        cur = s->ppid;
    }
    return 0;
}
