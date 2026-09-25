#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <arpa/inet.h>
#ifdef __linux__
#include <bpf/bpf.h>
#endif
#include "rules.h"
#include "output.h"
#include "argus.h"
#include "metrics.h"
#include "lineage.h"

#define RULES_MAX 64

typedef enum {
    SEV_INFO     = 0,
    SEV_LOW      = 1,
    SEV_MEDIUM   = 2,
    SEV_HIGH     = 3,
    SEV_CRITICAL = 4,
} severity_t;

static const char *sev_names[] = {
    [SEV_INFO]     = "info",
    [SEV_LOW]      = "low",
    [SEV_MEDIUM]   = "medium",
    [SEV_HIGH]     = "high",
    [SEV_CRITICAL] = "critical",
};

/* syslog priorities indexed by severity_t */
static const int sev_priority[] = {
    LOG_INFO, LOG_NOTICE, LOG_WARNING, LOG_WARNING, LOG_CRIT,
};

typedef struct {
    char       name[64];
    char       message[256];
    severity_t severity;
    int        event_type;           /* -1 = any; otherwise EVENT_* value */
    char       comm[16];             /* "" = any */
    int        uid;                  /* -1 = any */
    char       path_contains[128];   /* "" = any */
    uint32_t   mode_mask;            /* 0 = skip; flag if (mode & mask) != 0 */

    /* ── Suppression / threshold ────────────────────────────────────────── */
    int        threshold_count;      /* min hits before alert fires (0/1=always) */
    int        threshold_window_secs;/* rolling window for hit counting (0=any)  */
    int        suppress_after_secs;  /* suppress for N secs after threshold met   */

    /* ── Lineage matching ───────────────────────────────────────────────── */
    char       parent_comm[16];      /* "" = any; match immediate parent comm    */
    char       ancestor_comm[16];    /* "" = any; match any ancestor comm        */

    /* ── Active response ────────────────────────────────────────────────── */
    char       action[16];           /* "" = alert only; "kill" = send SIGKILL  */
} rule_t;

/* Per-rule runtime state — parallel to g_rules[] */
#define RULE_HIT_HISTORY 64

typedef struct {
    time_t hit_times[RULE_HIT_HISTORY]; /* circular buffer of match timestamps */
    int    hit_pos;                     /* next write position                   */
    int    hit_total;                   /* lifetime hits                         */
    time_t suppressed_until;            /* 0 = not suppressed                    */
} rule_state_t;

static rule_t       g_rules[RULES_MAX];
static rule_state_t g_state[RULES_MAX];
static int          g_rule_count = 0;
static int          g_kill_fd    = -1;   /* fd of kill_list BPF map; -1 = not set */

void rules_set_kill_fd(int fd) { g_kill_fd = fd; }

int rules_count(void) { return g_rule_count; }

void rules_free(void)
{
    g_rule_count = 0;
    memset(g_rules, 0, sizeof(g_rules));
    memset(g_state, 0, sizeof(g_state));
}

/* ── minimal JSON parser ─────────────────────────────────────────────────── */

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static const char *parse_str(const char *p, char *out, size_t max)
{
    p = skip_ws(p);
    if (*p != '"') return p;
    p++;
    size_t i = 0;
    while (*p && *p != '"') {
        if (*p == '\\') { p++; if (!*p) break; }
        if (i < max - 1) out[i++] = *p;
        p++;
    }
    out[i] = '\0';
    return *p == '"' ? p + 1 : p;
}

static const char *parse_int(const char *p, int *out)
{
    p = skip_ws(p);
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    if (*p < '0' || *p > '9') return p;
    *out = 0;
    while (*p >= '0' && *p <= '9') { *out = *out * 10 + (*p - '0'); p++; }
    if (neg) *out = -*out;
    return p;
}

static const char *past_colon(const char *p)
{
    p = skip_ws(p);
    if (*p == ':') p++;
    return skip_ws(p);
}

static severity_t parse_severity(const char *s)
{
    if (strcmp(s, "low")      == 0) return SEV_LOW;
    if (strcmp(s, "medium")   == 0) return SEV_MEDIUM;
    if (strcmp(s, "high")     == 0) return SEV_HIGH;
    if (strcmp(s, "critical") == 0) return SEV_CRITICAL;
    return SEV_INFO;
}

static int parse_event_type_str(const char *s)
{
    if (strcmp(s, "EXEC")        == 0) return EVENT_EXEC;
    if (strcmp(s, "OPEN")        == 0) return EVENT_OPEN;
    if (strcmp(s, "EXIT")        == 0) return EVENT_EXIT;
    if (strcmp(s, "CONNECT")     == 0) return EVENT_CONNECT;
    if (strcmp(s, "UNLINK")      == 0) return EVENT_UNLINK;
    if (strcmp(s, "RENAME")      == 0) return EVENT_RENAME;
    if (strcmp(s, "CHMOD")       == 0) return EVENT_CHMOD;
    if (strcmp(s, "BIND")        == 0) return EVENT_BIND;
    if (strcmp(s, "PTRACE")      == 0) return EVENT_PTRACE;
    if (strcmp(s, "DNS")         == 0) return EVENT_DNS;
    if (strcmp(s, "SEND")        == 0) return EVENT_SEND;
    if (strcmp(s, "WRITE_CLOSE")  == 0) return EVENT_WRITE_CLOSE;
    if (strcmp(s, "PRIVESC")      == 0) return EVENT_PRIVESC;
    if (strcmp(s, "MEMEXEC")      == 0) return EVENT_MEMEXEC;
    if (strcmp(s, "KMOD_LOAD")    == 0) return EVENT_KMOD_LOAD;
    if (strcmp(s, "NET_CORR")     == 0) return EVENT_NET_CORR;
    if (strcmp(s, "RATE_LIMIT")   == 0) return EVENT_RATE_LIMIT;
    if (strcmp(s, "THREAT_INTEL") == 0) return EVENT_THREAT_INTEL;
    if (strcmp(s, "TLS_SNI")      == 0) return EVENT_TLS_SNI;
    if (strcmp(s, "PROC_SCRAPE")  == 0) return EVENT_PROC_SCRAPE;
    if (strcmp(s, "NS_ESCAPE")    == 0) return EVENT_NS_ESCAPE;
    return -1;
}

/* ── rules_load ──────────────────────────────────────────────────────────── */

int rules_load(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "warning: rules file not found: %s\n", path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 1048576) { fclose(f); return -2; }

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return -2; }
    if (fread(buf, 1, sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -2;
    }
    buf[sz] = '\0';
    fclose(f);

    const char *p = skip_ws(buf);
    if (*p != '[') { free(buf); return -2; }
    p++;

    while (*p && *p != ']' && g_rule_count < RULES_MAX) {
        p = skip_ws(p);
        if (*p != '{') { p++; continue; }
        p++;

        rule_t *r = &g_rules[g_rule_count];
        r->event_type = -1;
        r->uid        = -1;

        while (*p && *p != '}') {
            p = skip_ws(p);
            if (*p != '"') { p++; continue; }

            char key[64] = {};
            p = parse_str(p, key, sizeof(key));
            p = past_colon(p);

            if (strcmp(key, "name") == 0)
                p = parse_str(p, r->name, sizeof(r->name));
            else if (strcmp(key, "message") == 0)
                p = parse_str(p, r->message, sizeof(r->message));
            else if (strcmp(key, "severity") == 0) {
                char sv[16] = {};
                p = parse_str(p, sv, sizeof(sv));
                r->severity = parse_severity(sv);
            }
            else if (strcmp(key, "type") == 0) {
                char tv[16] = {};
                p = parse_str(p, tv, sizeof(tv));
                r->event_type = parse_event_type_str(tv);
            }
            else if (strcmp(key, "comm") == 0)
                p = parse_str(p, r->comm, sizeof(r->comm));
            else if (strcmp(key, "path_contains") == 0)
                p = parse_str(p, r->path_contains, sizeof(r->path_contains));
            else if (strcmp(key, "uid") == 0)
                p = parse_int(p, &r->uid);
            else if (strcmp(key, "mode_mask") == 0) {
                int v = 0;
                p = parse_int(p, &v);
                r->mode_mask = (uint32_t)v;
            }
            else if (strcmp(key, "threshold_count") == 0)
                p = parse_int(p, &r->threshold_count);
            else if (strcmp(key, "threshold_window_secs") == 0)
                p = parse_int(p, &r->threshold_window_secs);
            else if (strcmp(key, "suppress_after_secs") == 0)
                p = parse_int(p, &r->suppress_after_secs);
            else if (strcmp(key, "parent_comm") == 0)
                p = parse_str(p, r->parent_comm, sizeof(r->parent_comm));
            else if (strcmp(key, "ancestor_comm") == 0)
                p = parse_str(p, r->ancestor_comm, sizeof(r->ancestor_comm));
            else if (strcmp(key, "action") == 0)
                p = parse_str(p, r->action, sizeof(r->action));

            p = skip_ws(p);
            if (*p == ',') p++;
        }
        if (*p == '}') p++;

        if (r->name[0])
            g_rule_count++;

        p = skip_ws(p);
        if (*p == ',') p++;
    }

    free(buf);
    return g_rule_count;
}

/* ── message template expansion ─────────────────────────────────────────── */

static void expand_message(const rule_t *r, const event_t *e,
                           char *out, size_t outsize)
{
    const char *src = r->message;
    size_t pos = 0;

    while (*src && pos + 1 < outsize) {
        if (*src != '{') {
            out[pos++] = *src++;
            continue;
        }
        const char *end = src + 1;
        while (*end && *end != '}') end++;
        if (!*end) { out[pos++] = *src++; continue; }

        size_t varlen = (size_t)(end - src - 1);
        char var[32] = {};
        if (varlen < sizeof(var))
            memcpy(var, src + 1, varlen);

        char val[256] = {};
        if      (strcmp(var, "comm")       == 0) snprintf(val, sizeof(val), "%s",  e->comm);
        else if (strcmp(var, "pid")        == 0) snprintf(val, sizeof(val), "%d",  e->pid);
        else if (strcmp(var, "ppid")       == 0) snprintf(val, sizeof(val), "%d",  e->ppid);
        else if (strcmp(var, "uid")        == 0) snprintf(val, sizeof(val), "%u",  e->uid);
        else if (strcmp(var, "gid")        == 0) snprintf(val, sizeof(val), "%u",  e->gid);
        else if (strcmp(var, "cgroup")     == 0) snprintf(val, sizeof(val), "%s",  e->cgroup[0] ? e->cgroup : "-");
        else if (strcmp(var, "filename")   == 0) snprintf(val, sizeof(val), "%s",  e->filename);
        else if (strcmp(var, "args")       == 0) snprintf(val, sizeof(val), "%s",  e->args);
        else if (strcmp(var, "new_path")   == 0) snprintf(val, sizeof(val), "%s",  e->args);
        else if (strcmp(var, "mode")       == 0) snprintf(val, sizeof(val), "%o",  e->mode);
        else if (strcmp(var, "target_pid") == 0) snprintf(val, sizeof(val), "%d",  e->target_pid);
        else if (strcmp(var, "ptrace_req") == 0) snprintf(val, sizeof(val), "%d",  e->ptrace_req);
        else if (strcmp(var, "dport")      == 0) snprintf(val, sizeof(val), "%u",  e->dport);
        else if (strcmp(var, "lport")      == 0) snprintf(val, sizeof(val), "%u",  e->dport);
        else if (strcmp(var, "daddr") == 0 || strcmp(var, "laddr") == 0)
            inet_ntop(e->family == 2 ? AF_INET : AF_INET6, e->daddr, val, sizeof(val));
        else if (strcmp(var, "uid_before") == 0) snprintf(val, sizeof(val), "%u", e->uid_before);
        else if (strcmp(var, "uid_after")  == 0) snprintf(val, sizeof(val), "%u", e->uid_after);
        else if (strcmp(var, "dns_name")   == 0) snprintf(val, sizeof(val), "%s", e->dns_name);
        else
            snprintf(val, sizeof(val), "{%s}", var);  /* unknown: keep literal */

        size_t vl = strlen(val);
        if (pos + vl >= outsize) vl = outsize - pos - 1;
        memcpy(out + pos, val, vl);
        pos += vl;
        src = end + 1;
    }
    out[pos] = '\0';
}

/* ── rule matching ───────────────────────────────────────────────────────── */

static int rule_matches(const rule_t *r, const event_t *e)
{
    if (r->event_type >= 0 && (int)e->type != r->event_type)
        return 0;
    if (r->comm[0] && strncmp(e->comm, r->comm, sizeof(r->comm)) != 0)
        return 0;
    if (r->uid >= 0 && (int)e->uid != r->uid)
        return 0;
    if (r->path_contains[0] && strstr(e->filename, r->path_contains) == NULL)
        return 0;
    if (r->mode_mask && e->type == EVENT_CHMOD &&
        (e->mode & r->mode_mask) == 0)
        return 0;

    /* ── Lineage checks ─────────────────────────────────────────────────── */
    if (r->parent_comm[0]) {
        char pcomm[16] = {};
        lineage_parent_comm((uint32_t)e->ppid, pcomm, sizeof(pcomm));
        if (strncmp(pcomm, r->parent_comm, sizeof(r->parent_comm)) != 0)
            return 0;
    }
    if (r->ancestor_comm[0]) {
        if (!lineage_has_ancestor((uint32_t)e->ppid, r->ancestor_comm))
            return 0;
    }

    return 1;
}

/* ── JSON string escape (writes to FILE) ─────────────────────────────────── */

static void write_json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  fprintf(f, "\\\""); break;
        case '\\': fprintf(f, "\\\\"); break;
        case '\n': fprintf(f, "\\n");  break;
        case '\r': fprintf(f, "\\r");  break;
        case '\t': fprintf(f, "\\t");  break;
        default:
            if (*p < 0x20) fprintf(f, "\\u%04x", *p);
            else fputc(*p, f);
            break;
        }
    }
    fputc('"', f);
}

/* ── alert emission ──────────────────────────────────────────────────────── */

static void emit_alert(const rule_t *r, const event_t *e)
{
    char msg[512];
    expand_message(r, e, msg, sizeof(msg));
    const char *sev = sev_names[r->severity];
    output_fmt_t fmt = output_get_fmt();

    if (fmt == OUTPUT_JSON) {
        FILE *out = output_stream();
        fprintf(out, "{\"type\":\"ALERT\",\"severity\":");
        write_json_str(out, sev);
        fprintf(out, ",\"rule\":");
        write_json_str(out, r->name);
        fprintf(out, ",\"pid\":%d,\"ppid\":%d,\"uid\":%u,\"comm\":",
                e->pid, e->ppid, e->uid);
        write_json_str(out, e->comm);
        fprintf(out, ",\"message\":");
        write_json_str(out, msg);
        fputs("}\n", out);
    } else if (fmt == OUTPUT_SYSLOG) {
        syslog(sev_priority[r->severity],
               "ALERT:%s rule=%s pid=%d comm=%s %s",
               sev, r->name, e->pid, e->comm, msg);
    } else {
        fprintf(stderr, "[ALERT:%s] %s: %s\n", sev, r->name, msg);
    }
}

/* ── suppression / threshold logic ──────────────────────────────────────── */

/*
 * Record a hit and decide whether to fire the alert.
 * Returns 1 if alert should fire, 0 if suppressed or threshold not met.
 */
static int should_fire(rule_t *r, rule_state_t *st)
{
    time_t now = time(NULL);

    /* Currently suppressed? */
    if (st->suppressed_until && now < st->suppressed_until)
        return 0;
    if (st->suppressed_until && now >= st->suppressed_until)
        st->suppressed_until = 0;   /* lift suppression */

    /* Record this hit in the circular buffer */
    st->hit_times[st->hit_pos % RULE_HIT_HISTORY] = now;
    st->hit_pos++;
    st->hit_total++;

    /* Check threshold (if configured) */
    int thr = r->threshold_count;
    if (thr <= 1) thr = 1;   /* default: fire on first hit */

    if (r->threshold_window_secs > 0) {
        /* Count hits within the window */
        int window_hits = 0;
        for (int k = 0; k < RULE_HIT_HISTORY; k++) {
            if (st->hit_times[k] &&
                now - st->hit_times[k] <= r->threshold_window_secs)
                window_hits++;
        }
        if (window_hits < thr)
            return 0;
    } else {
        if (st->hit_total < thr)
            return 0;
    }

    /* Threshold met — fire.  Now apply suppress_after if configured. */
    if (r->suppress_after_secs > 0) {
        /* Count hits in the window again to decide when to start suppression */
        int window_hits = r->threshold_window_secs > 0 ? thr : st->hit_total;
        if (window_hits >= thr)
            st->suppressed_until = now + r->suppress_after_secs;
    }

    return 1;
}

/* ── public API ──────────────────────────────────────────────────────────── */

void rules_check(const event_t *e)
{
    for (int i = 0; i < g_rule_count; i++) {
        if (!rule_matches(&g_rules[i], e))
            continue;
        if (!should_fire(&g_rules[i], &g_state[i]))
            continue;
        emit_alert(&g_rules[i], e);
        metrics_rule_hit();

        /* Active response: kill the offending process via BPF kill_list map */
        if (g_kill_fd >= 0 && g_rules[i].action[0] &&
            strcmp(g_rules[i].action, "kill") == 0) {
#ifdef __linux__
            uint32_t pid = (uint32_t)e->pid;
            uint8_t  val = 1;
            bpf_map_update_elem(g_kill_fd, &pid, &val, BPF_ANY);
#endif
        }
    }
}
