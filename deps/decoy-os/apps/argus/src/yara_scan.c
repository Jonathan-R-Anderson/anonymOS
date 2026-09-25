#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <dirent.h>
#include <sys/stat.h>
#include "yara_scan.h"
#include "argus.h"

#ifdef HAVE_YARA
#include <yara.h>

static YR_RULES    *g_rules    = NULL;
static YR_COMPILER *g_compiler = NULL;
static int          g_initialized = 0;

/* YARA callback: called once per matching rule */
static int yara_callback(YR_SCAN_CONTEXT *ctx, int message,
                          void *message_data, void *user_data)
{
    (void)ctx;
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE *rule = (YR_RULE *)message_data;
        yara_match_ctx_t *mc = (yara_match_ctx_t *)user_data;
        fprintf(stderr,
            "[YARA] pid=%-6d comm=%-16s file=%s rule=%s/%s\n",
            mc->pid, mc->comm, mc->filepath,
            rule->ns->name, rule->identifier);
        syslog(LOG_WARNING,
            "YARA pid=%d comm=%s file=%s rule=%s/%s",
            mc->pid, mc->comm, mc->filepath,
            rule->ns->name, rule->identifier);
        mc->matches++;
    }
    return CALLBACK_CONTINUE;
}

typedef struct {
    int  pid;
    char comm[16];
    char filepath[256];
    int  matches;
} yara_match_ctx_t;

int yara_scan_init(const char *rules_dir)
{
    if (!rules_dir || !rules_dir[0])
        return -1;

    yr_initialize();

    if (yr_compiler_create(&g_compiler) != ERROR_SUCCESS) {
        fprintf(stderr, "yara: failed to create compiler\n");
        return -1;
    }

    DIR *d = opendir(rules_dir);
    if (!d) {
        fprintf(stderr, "yara: cannot open rules dir: %s\n", rules_dir);
        yr_compiler_destroy(g_compiler);
        g_compiler = NULL;
        return -1;
    }

    struct dirent *ent;
    int n_loaded = 0;
    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen < 5 || strcmp(ent->d_name + nlen - 4, ".yar") != 0)
            continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", rules_dir, ent->d_name);

        FILE *f = fopen(path, "r");
        if (!f) continue;

        int err = yr_compiler_add_file(g_compiler, f, NULL, ent->d_name);
        fclose(f);
        if (err > 0) {
            fprintf(stderr, "yara: %d warning(s) loading %s\n", err, path);
        }
        n_loaded++;
    }
    closedir(d);

    if (n_loaded == 0) {
        fprintf(stderr, "yara: no .yar files found in %s\n", rules_dir);
        yr_compiler_destroy(g_compiler);
        g_compiler = NULL;
        return -1;
    }

    if (yr_compiler_get_rules(g_compiler, &g_rules) != ERROR_SUCCESS) {
        fprintf(stderr, "yara: failed to compile rules\n");
        yr_compiler_destroy(g_compiler);
        g_compiler = NULL;
        return -1;
    }

    yr_compiler_destroy(g_compiler);
    g_compiler    = NULL;
    g_initialized = 1;

    fprintf(stderr, "yara: loaded %d rule file(s) from %s\n",
            n_loaded, rules_dir);
    return 0;
}

int yara_scan_event(const event_t *ev)
{
    if (!g_initialized || !g_rules)
        return 0;

    char filepath[256] = {};

    if (ev->type == EVENT_EXEC) {
        /* Scan the process image via /proc/pid/exe */
        snprintf(filepath, sizeof(filepath), "/proc/%d/exe", ev->pid);
    } else if (ev->type == EVENT_WRITE_CLOSE || ev->type == EVENT_KMOD_LOAD) {
        if (!ev->filename[0])
            return 0;
        strncpy(filepath, ev->filename, sizeof(filepath) - 1);
    } else {
        return 0;
    }

    /* Skip special paths */
    if (strncmp(filepath, "/proc/", 6) == 0 && ev->type != EVENT_EXEC)
        return 0;
    if (strncmp(filepath, "/sys/",  5) == 0)
        return 0;

    /* Check file exists and is a regular file */
    struct stat st;
    if (stat(filepath, &st) != 0)
        return 0;
    if (!S_ISREG(st.st_mode))
        return 0;
    /* Skip very large files (> 64 MB) */
    if (st.st_size > 64 * 1024 * 1024)
        return 0;

    yara_match_ctx_t ctx = {
        .pid     = ev->pid,
        .matches = 0,
    };
    strncpy(ctx.comm,     ev->comm, sizeof(ctx.comm) - 1);
    strncpy(ctx.filepath, filepath, sizeof(ctx.filepath) - 1);

    yr_rules_scan_file(g_rules, filepath, 0,
                       (YR_CALLBACK_FUNC)yara_callback, &ctx, 10 /* timeout s */);
    return ctx.matches;
}

void yara_scan_fini(void)
{
    if (g_rules)    { yr_rules_destroy(g_rules);      g_rules    = NULL; }
    if (g_compiler) { yr_compiler_destroy(g_compiler); g_compiler = NULL; }
    if (g_initialized) { yr_finalize(); g_initialized = 0; }
}

int yara_scan_available(void) { return 1; }

#else /* !HAVE_YARA */

int  yara_scan_init(const char *rules_dir) { (void)rules_dir; return -1; }
int  yara_scan_event(const event_t *ev)    { (void)ev; return 0; }
void yara_scan_fini(void)                  {}
int  yara_scan_available(void)             { return 0; }

#endif /* HAVE_YARA */
