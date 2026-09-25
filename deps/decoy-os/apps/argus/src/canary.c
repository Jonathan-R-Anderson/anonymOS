#include <stdio.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include "canary.h"
#include "argus.h"

static char g_paths[CANARY_MAX_PATHS][256];
static int  g_count = 0;

void canary_init(void)
{
    g_count = 0;
    memset(g_paths, 0, sizeof(g_paths));
}

void canary_add_path(const char *path)
{
    if (!path || !path[0] || g_count >= CANARY_MAX_PATHS)
        return;
    strncpy(g_paths[g_count], path, 255);
    g_count++;
}

int canary_count(void) { return g_count; }

static int path_matches(const char *canary, const char *event_path)
{
    if (!event_path || !event_path[0])
        return 0;
    size_t clen = strlen(canary);
    if (clen == 0)
        return 0;
    /* Prefix match when canary ends with '/' */
    if (canary[clen - 1] == '/')
        return strncmp(event_path, canary, clen) == 0;
    /* Exact match */
    return strcmp(event_path, canary) == 0;
}

int canary_check(const event_t *ev)
{
    if (g_count == 0)
        return 0;

    /* Only check events that involve a file path */
    if (ev->type != EVENT_OPEN &&
        ev->type != EVENT_EXEC &&
        ev->type != EVENT_WRITE_CLOSE &&
        ev->type != EVENT_UNLINK &&
        ev->type != EVENT_RENAME)
        return 0;

    const char *path = ev->filename;
    if (!path || !path[0])
        return 0;

    for (int i = 0; i < g_count; i++) {
        if (!path_matches(g_paths[i], path))
            continue;

        /* Also check args (rename new path) */
        const char *action =
            ev->type == EVENT_OPEN       ? "opened"      :
            ev->type == EVENT_EXEC       ? "executed"    :
            ev->type == EVENT_WRITE_CLOSE? "written"     :
            ev->type == EVENT_UNLINK     ? "deleted"     :
            ev->type == EVENT_RENAME     ? "renamed"     : "accessed";

        fprintf(stderr,
            "[CANARY] pid=%-6d comm=%-16s uid=%-5u %s canary file: %s\n",
            ev->pid, ev->comm, ev->uid, action, path);
        syslog(LOG_ALERT,
            "CANARY pid=%d comm=%s uid=%u %s canary: %s",
            ev->pid, ev->comm, ev->uid, action, path);
        return 1;
    }

    /* Also check rename destination */
    if (ev->type == EVENT_RENAME && ev->args[0]) {
        for (int i = 0; i < g_count; i++) {
            if (!path_matches(g_paths[i], ev->args))
                continue;
            fprintf(stderr,
                "[CANARY] pid=%-6d comm=%-16s uid=%-5u renamed into canary path: %s\n",
                ev->pid, ev->comm, ev->uid, ev->args);
            syslog(LOG_ALERT,
                "CANARY pid=%d comm=%s uid=%u renamed into canary: %s",
                ev->pid, ev->comm, ev->uid, ev->args);
            return 1;
        }
    }

    return 0;
}
