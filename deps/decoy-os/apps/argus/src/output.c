#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <syslog.h>
#include "output.h"
#include "lineage.h"
#include "argus.h"
#include "dns.h"

#define LINEAGE_BUF 256

static output_fmt_t g_fmt    = OUTPUT_TEXT;
static filter_t     g_filter = {0};
static FILE        *g_out    = NULL;   /* NULL = use stdout */

#define OUT (g_out ? g_out : stdout)

/* ── uid → username enrichment ──────────────────────────────────────────── */
/*
 * Lazily loads /etc/passwd on first call.  Uses a 512-slot hash table;
 * first entry per slot wins (collisions are silently ignored — enrichment
 * is best-effort, not authoritative).
 */

#define UID_CACHE_SZ 512

typedef struct { uint32_t uid; char name[32]; int used; } uid_entry_t;

static uid_entry_t g_uid_cache[UID_CACHE_SZ];
static int         g_uid_loaded = 0;

static void load_uid_cache(void)
{
    g_uid_loaded = 1;
    FILE *f = fopen("/etc/passwd", "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        /* name : x : uid : gid : ... */
        char *name = line;
        char *p = strchr(line, ':'); if (!p) continue; *p++ = '\0';
        p = strchr(p, ':');          if (!p) continue; p++;   /* skip 'x' */
        char *uid_s = p;
        p = strchr(p, ':');          if (!p) continue; *p = '\0';
        uint32_t uid = (uint32_t)atoi(uid_s);
        unsigned slot = uid % UID_CACHE_SZ;
        if (!g_uid_cache[slot].used) {
            g_uid_cache[slot].uid  = uid;
            g_uid_cache[slot].used = 1;
            strncpy(g_uid_cache[slot].name, name,
                    sizeof(g_uid_cache[slot].name) - 1);
        }
    }
    fclose(f);
}

static const char *uid_name(uint32_t uid)
{
    if (!g_uid_loaded) load_uid_cache();
    unsigned slot = uid % UID_CACHE_SZ;
    if (g_uid_cache[slot].used && g_uid_cache[slot].uid == uid)
        return g_uid_cache[slot].name;
    return NULL;
}

void output_init(output_fmt_t fmt, const filter_t *filter)
{
    g_fmt = fmt;
    if (filter)
        g_filter = *filter;
    if (fmt == OUTPUT_SYSLOG)
        openlog("argus", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

void output_update_filter(const filter_t *filter)
{
    if (filter)
        g_filter = *filter;
}

void output_set_file(FILE *f)
{
    g_out = f;
}

FILE *output_stream(void)
{
    return g_out ? g_out : stdout;
}

output_fmt_t output_get_fmt(void)
{
    return g_fmt;
}

void output_fini(void)
{
    if (g_fmt == OUTPUT_SYSLOG)
        closelog();
}

/* ── filtering ──────────────────────────────────────────────────────────── */

int event_matches(const event_t *e)
{
    /* event type mask (0 == TRACE_ALL) */
    if (g_filter.event_mask) {
        int bit = 1 << (int)e->type;
        if (!(g_filter.event_mask & bit))
            return 0;
    }

    if (g_filter.pid != 0 && e->pid != g_filter.pid)
        return 0;

    if (g_filter.comm[0] != '\0' &&
        strncmp(e->comm, g_filter.comm, sizeof(g_filter.comm)) != 0)
        return 0;

    if (g_filter.path[0] != '\0' &&
        strstr(e->filename, g_filter.path) == NULL)
        return 0;

    /* exclude paths — applied to all file events */
    if ((e->type == EVENT_OPEN        || e->type == EVENT_UNLINK  ||
         e->type == EVENT_RENAME      || e->type == EVENT_CHMOD   ||
         e->type == EVENT_WRITE_CLOSE) &&
        g_filter.exclude_count > 0) {
        for (int i = 0; i < g_filter.exclude_count; i++) {
            if (g_filter.excludes[i][0] &&
                strncmp(e->filename, g_filter.excludes[i],
                        strlen(g_filter.excludes[i])) == 0)
                return 0;
        }
    }

    return 1;
}

/* ── text output ────────────────────────────────────────────────────────── */

void print_header(const char *backend)
{
    if (g_fmt != OUTPUT_TEXT)
        return;

    static const struct { int bit; const char *name; } type_map[] = {
        { TRACE_EXEC,    "EXEC"    }, { TRACE_OPEN,   "OPEN"   },
        { TRACE_EXIT,    "EXIT"    }, { TRACE_CONNECT,"CONNECT"},
        { TRACE_UNLINK,  "UNLINK"  }, { TRACE_RENAME, "RENAME" },
        { TRACE_CHMOD,   "CHMOD"   }, { TRACE_BIND,   "BIND"   },
        { TRACE_PTRACE,  "PTRACE"  },
    };
    int mask = g_filter.event_mask ? g_filter.event_mask : TRACE_ALL;
    fprintf(OUT, "Tracing via %s (", backend);
    int first = 1;
    for (int i = 0; i < 9; i++) {
        if (mask & type_map[i].bit) {
            fprintf(OUT, "%s%s", first ? "" : ",", type_map[i].name);
            first = 0;
        }
    }
    fprintf(OUT, ")... Ctrl-C to stop.\n");

    if (g_filter.pid)
        fprintf(OUT, "  filter: pid=%d\n", g_filter.pid);
    if (g_filter.comm[0])
        fprintf(OUT, "  filter: comm=%s\n", g_filter.comm);
    if (g_filter.path[0])
        fprintf(OUT, "  filter: path=%s\n", g_filter.path);
    for (int i = 0; i < g_filter.exclude_count; i++)
        fprintf(OUT, "  exclude: %s\n", g_filter.excludes[i]);

    if (g_filter.pid || g_filter.comm[0] || g_filter.path[0] ||
        g_filter.exclude_count)
        fputc('\n', OUT);

    fprintf(OUT, "\n%-5s  %-6s  %-6s  %-10s  %-4s  %-16s  %-24s  %-32s  %s\n",
           "TYPE", "PID", "PPID", "USER", "GID", "COMM",
           "CGROUP", "LINEAGE", "DETAIL");
    fprintf(OUT, "%-5s  %-6s  %-6s  %-10s  %-4s  %-16s  %-24s  %-32s  %s\n",
           "-----", "------", "------", "----------", "----",
           "----------------", "------------------------",
           "--------------------------------", "------");
}

static void text_event(const event_t *e)
{
    char chain[LINEAGE_BUF];
    lineage_str(e->ppid, chain, sizeof(chain));

    static const char *type_names[] = {
        [EVENT_EXEC]        = "EXEC",  [EVENT_OPEN]        = "OPEN",
        [EVENT_EXIT]        = "EXIT",  [EVENT_CONNECT]     = "CONN",
        [EVENT_UNLINK]      = "UNLNK",[EVENT_RENAME]      = "RENM",
        [EVENT_CHMOD]       = "CMOD", [EVENT_BIND]        = "BIND",
        [EVENT_PTRACE]      = "PTRC", [EVENT_DNS]         = "DNS",
        [EVENT_SEND]        = "SEND", [EVENT_WRITE_CLOSE] = "WRCL",
        [EVENT_PRIVESC]     = "PRIV", [EVENT_MEMEXEC]     = "MXEC",
        [EVENT_KMOD_LOAD]   = "KMOD", [EVENT_NET_CORR]    = "CORR",
        [EVENT_RATE_LIMIT]  = "RATE", [EVENT_THREAT_INTEL]= "THRT",
        [EVENT_TLS_SNI]     = "SNI",  [EVENT_PROC_SCRAPE] = "SCRP",
        [EVENT_NS_ESCAPE]   = "NSES",
    };
    const char *tname = (e->type < EVENT_TYPE_MAX) ? type_names[e->type] : "?";

    /* Show username when available, fall back to raw UID */
    const char *uname = uid_name(e->uid);
    char uid_buf[20];
    if (uname) snprintf(uid_buf, sizeof(uid_buf), "%.10s", uname);
    else        snprintf(uid_buf, sizeof(uid_buf), "%u", e->uid);

    fprintf(OUT, "%-5s  %-6d  %-6d  %-10s  %-4u  %-16s  %-24s  %-32s  ",
           tname, e->pid, e->ppid, uid_buf, e->gid, e->comm,
           e->cgroup[0] ? e->cgroup : "-", chain);

    switch (e->type) {
    case EVENT_EXEC:
        fprintf(OUT, "%s %s", e->filename, e->args);
        break;
    case EVENT_OPEN:
        fprintf(OUT, "[%s] flags=0x%x %s",
                e->success ? "OK" : "FAIL", e->open_flags, e->filename);
        break;
    case EVENT_EXIT:
        fprintf(OUT, "exit_code=%d", e->exit_code);
        break;
    case EVENT_CONNECT: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        if (strcmp(host, ip) != 0)
            fprintf(OUT, "[%s] %s (%s):%u",
                    e->success ? "OK" : "FAIL", host, ip, e->dport);
        else
            fprintf(OUT, "[%s] %s:%u",
                    e->success ? "OK" : "FAIL", ip, e->dport);
        break;
    }
    case EVENT_UNLINK:
        fprintf(OUT, "[%s] %s", e->success ? "OK" : "FAIL", e->filename);
        break;
    case EVENT_RENAME:
        fprintf(OUT, "[%s] %s -> %s", e->success ? "OK" : "FAIL",
               e->filename, e->args);
        break;
    case EVENT_CHMOD:
        fprintf(OUT, "[%s] %s mode=0%o", e->success ? "OK" : "FAIL",
               e->filename, e->mode);
        break;
    case EVENT_BIND: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        if (strcmp(host, ip) != 0)
            fprintf(OUT, "[%s] %s (%s):%u",
                    e->success ? "OK" : "FAIL", host, ip, e->dport);
        else
            fprintf(OUT, "[%s] %s:%u",
                    e->success ? "OK" : "FAIL", ip, e->dport);
        break;
    }
    case EVENT_PTRACE:
        fprintf(OUT, "[%s] req=%d target_pid=%d",
               e->success ? "OK" : "FAIL", e->ptrace_req, e->target_pid);
        break;
    case EVENT_DNS: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, "[%s] query=%s dst=%s:%u",
                e->success ? "OK" : "FAIL", e->filename, ip, e->dport);
        break;
    }
    case EVENT_SEND: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, "[%s] dst=%s:%u len=%u",
                e->success ? "OK" : "FAIL", ip, e->dport, e->mode);
        break;
    }
    case EVENT_WRITE_CLOSE:
        fprintf(OUT, "%s", e->filename);
        break;
    case EVENT_PRIVESC:
        fprintf(OUT, "uid %u→%u caps=0x%llx",
                e->uid_before, e->uid_after, (unsigned long long)e->cap_data);
        break;
    case EVENT_MEMEXEC:
        fprintf(OUT, "prot=0x%x flags=0x%x", e->mode, e->open_flags);
        break;
    case EVENT_KMOD_LOAD:
        fprintf(OUT, "%s", e->filename[0] ? e->filename : "<anonymous>");
        break;
    case EVENT_NET_CORR: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, "dns=%s -> %s:%u", e->dns_name, ip, e->dport);
        break;
    }
    case EVENT_RATE_LIMIT:
        fprintf(OUT, "pid=%d rate-limited", e->pid);
        break;
    case EVENT_THREAT_INTEL: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, "[BLOCKED] %s:%u", ip, e->dport);
        break;
    }
    case EVENT_TLS_SNI:
        fprintf(OUT, "sni=%s", e->dns_name);
        break;
    case EVENT_PROC_SCRAPE:
        fprintf(OUT, "target_pid=%d path=%s",
                e->target_pid, e->filename);
        break;
    case EVENT_NS_ESCAPE:
        fprintf(OUT, "flags=0x%x", e->mode);
        break;
    case EVENT_TLS_DATA:
        fprintf(OUT, "tls_len=%u", e->tls_payload_len);
        break;
    case EVENT_HEARTBEAT:
        fprintf(OUT, "liveness");
        break;
    }
    fputc('\n', OUT);
}

/* ── JSON output ────────────────────────────────────────────────────────── */

static void json_str(const char *s)
{
    fputc('"', OUT);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  fprintf(OUT, "\\\""); break;
        case '\\': fprintf(OUT, "\\\\"); break;
        case '\n': fprintf(OUT, "\\n");  break;
        case '\r': fprintf(OUT, "\\r");  break;
        case '\t': fprintf(OUT, "\\t");  break;
        default:
            if (*p < 0x20)
                fprintf(OUT, "\\u%04x", *p);
            else
                fputc(*p, OUT);
            break;
        }
    }
    fputc('"', OUT);
}

static void json_event(const event_t *e)
{
    static const char *type_str[] = {
        [EVENT_EXEC]        = "EXEC",
        [EVENT_OPEN]        = "OPEN",
        [EVENT_EXIT]        = "EXIT",
        [EVENT_CONNECT]     = "CONNECT",
        [EVENT_UNLINK]      = "UNLINK",
        [EVENT_RENAME]      = "RENAME",
        [EVENT_CHMOD]       = "CHMOD",
        [EVENT_BIND]        = "BIND",
        [EVENT_PTRACE]      = "PTRACE",
        [EVENT_DNS]         = "DNS",
        [EVENT_SEND]        = "SEND",
        [EVENT_WRITE_CLOSE] = "WRITE_CLOSE",
        [EVENT_PRIVESC]     = "PRIVESC",
        [EVENT_MEMEXEC]     = "MEMEXEC",
        [EVENT_KMOD_LOAD]   = "KMOD_LOAD",
        [EVENT_NET_CORR]    = "NET_CORR",
        [EVENT_RATE_LIMIT]  = "RATE_LIMIT",
        [EVENT_THREAT_INTEL]= "THREAT_INTEL",
        [EVENT_TLS_SNI]     = "TLS_SNI",
        [EVENT_PROC_SCRAPE] = "PROC_SCRAPE",
        [EVENT_NS_ESCAPE]   = "NS_ESCAPE",
        [EVENT_TLS_DATA]    = "TLS_DATA",
        [EVENT_HEARTBEAT]   = "HEARTBEAT",
    };

    char chain[LINEAGE_BUF];
    lineage_str(e->ppid, chain, sizeof(chain));

    const char *ts = (e->type < EVENT_TYPE_MAX) ? type_str[e->type] : "UNKNOWN";
    fprintf(OUT, "{\"type\":\"%s\","
           "\"pid\":%d,\"ppid\":%d,"
           "\"uid\":%u,\"gid\":%u,",
           ts, e->pid, e->ppid, e->uid, e->gid);
    const char *uname = uid_name(e->uid);
    if (uname) { fprintf(OUT, "\"user\":"); json_str(uname); fprintf(OUT, ","); }
    fprintf(OUT, "\"comm\":");
    json_str(e->comm);
    fprintf(OUT, ",\"cgroup\":");
    json_str(e->cgroup);
    fprintf(OUT, ",\"lineage\":");
    json_str(chain);

    fprintf(OUT, ",\"duration_ns\":%llu,\"success\":%s",
           (unsigned long long)e->duration_ns,
           e->success ? "true" : "false");

    switch (e->type) {
    case EVENT_EXEC:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename);
        fprintf(OUT, ",\"args\":");     json_str(e->args);
        break;
    case EVENT_OPEN:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename);
        fprintf(OUT, ",\"open_flags\":%u", e->open_flags);
        break;
    case EVENT_EXIT:
        fprintf(OUT, ",\"exit_code\":%d", e->exit_code);
        break;
    case EVENT_CONNECT: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        fprintf(OUT, ",\"family\":%u,\"daddr\":\"%s\",\"hostname\":",
                e->family, ip);
        json_str(host);
        fprintf(OUT, ",\"dport\":%u", e->dport);
        break;
    }
    case EVENT_UNLINK:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename);
        break;
    case EVENT_RENAME:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename);
        fprintf(OUT, ",\"new_path\":"); json_str(e->args);
        break;
    case EVENT_CHMOD:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename);
        fprintf(OUT, ",\"mode\":%u", e->mode);
        break;
    case EVENT_BIND: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        fprintf(OUT, ",\"family\":%u,\"laddr\":\"%s\",\"hostname\":",
                e->family, ip);
        json_str(host);
        fprintf(OUT, ",\"lport\":%u", e->dport);
        break;
    }
    case EVENT_PTRACE:
        fprintf(OUT, ",\"ptrace_req\":%d,\"target_pid\":%d",
               e->ptrace_req, e->target_pid);
        break;
    case EVENT_DNS: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, ",\"query\":"); json_str(e->filename);
        fprintf(OUT, ",\"family\":%u,\"daddr\":\"%s\",\"dport\":%u",
                e->family, ip, e->dport);
        break;
    }
    case EVENT_SEND: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, ",\"family\":%u,\"daddr\":\"%s\",\"dport\":%u",
                e->family, ip, e->dport);
        fprintf(OUT, ",\"payload_len\":%u", e->mode);
        break;
    }
    case EVENT_WRITE_CLOSE:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename);
        break;
    case EVENT_PRIVESC:
        fprintf(OUT, ",\"uid_before\":%u,\"uid_after\":%u,\"cap_data\":%llu",
                e->uid_before, e->uid_after, (unsigned long long)e->cap_data);
        break;
    case EVENT_MEMEXEC:
        fprintf(OUT, ",\"prot\":\"0x%x\",\"mmap_flags\":\"0x%x\"",
                e->mode, e->open_flags);
        if (e->filename[0]) { fprintf(OUT, ",\"filename\":"); json_str(e->filename); }
        break;
    case EVENT_KMOD_LOAD:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename[0] ? e->filename : "");
        break;
    case EVENT_NET_CORR: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, ",\"dns_name\":"); json_str(e->dns_name);
        fprintf(OUT, ",\"daddr\":\"%s\",\"dport\":%u", ip, e->dport);
        break;
    }
    case EVENT_RATE_LIMIT:
        fprintf(OUT, ",\"limited_pid\":%d", e->pid);
        break;
    case EVENT_THREAT_INTEL: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, ",\"family\":%u,\"daddr\":\"%s\",\"dport\":%u",
                e->family, ip, e->dport);
        break;
    }
    case EVENT_TLS_SNI:
        fprintf(OUT, ",\"sni\":"); json_str(e->dns_name);
        break;
    case EVENT_PROC_SCRAPE:
        fprintf(OUT, ",\"target_pid\":%d,\"path\":", e->target_pid);
        json_str(e->filename);
        break;
    case EVENT_NS_ESCAPE:
        fprintf(OUT, ",\"ns_flags\":\"0x%x\"", e->mode);
        break;
    case EVENT_TLS_DATA:
        fprintf(OUT, ",\"tls_payload_len\":%u", e->tls_payload_len);
        break;
    case EVENT_HEARTBEAT:
        break;
    }
    fputs("}\n", OUT);
}

/* ── syslog output ──────────────────────────────────────────────────────── */

static void syslog_event(const event_t *e)
{
    static const char *type_str[] = {
        [EVENT_EXEC]        = "EXEC",        [EVENT_OPEN]        = "OPEN",
        [EVENT_EXIT]        = "EXIT",        [EVENT_CONNECT]     = "CONNECT",
        [EVENT_UNLINK]      = "UNLINK",      [EVENT_RENAME]      = "RENAME",
        [EVENT_CHMOD]       = "CHMOD",       [EVENT_BIND]        = "BIND",
        [EVENT_PTRACE]      = "PTRACE",      [EVENT_DNS]         = "DNS",
        [EVENT_SEND]        = "SEND",        [EVENT_WRITE_CLOSE] = "WRITE_CLOSE",
        [EVENT_PRIVESC]     = "PRIVESC",     [EVENT_MEMEXEC]     = "MEMEXEC",
        [EVENT_KMOD_LOAD]   = "KMOD_LOAD",   [EVENT_NET_CORR]    = "NET_CORR",
        [EVENT_RATE_LIMIT]  = "RATE_LIMIT",  [EVENT_THREAT_INTEL]= "THREAT_INTEL",
        [EVENT_TLS_SNI]     = "TLS_SNI",     [EVENT_PROC_SCRAPE] = "PROC_SCRAPE",
        [EVENT_NS_ESCAPE]   = "NS_ESCAPE",   [EVENT_TLS_DATA]    = "TLS_DATA",
        [EVENT_HEARTBEAT]   = "HEARTBEAT",
    };

    char chain[LINEAGE_BUF];
    lineage_str(e->ppid, chain, sizeof(chain));

    const char *ts = (e->type < EVENT_TYPE_MAX) ? type_str[e->type] : "UNKNOWN";
    char detail[512] = {};

    switch (e->type) {
    case EVENT_EXEC:
        snprintf(detail, sizeof(detail), "%s %s", e->filename, e->args);
        break;
    case EVENT_OPEN:
        snprintf(detail, sizeof(detail), "[%s] %s",
                 e->success ? "OK" : "FAIL", e->filename);
        break;
    case EVENT_EXIT:
        snprintf(detail, sizeof(detail), "exit_code=%d", e->exit_code);
        break;
    case EVENT_CONNECT: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        if (strcmp(host, ip) != 0)
            snprintf(detail, sizeof(detail), "[%s] %s (%s):%u",
                     e->success ? "OK" : "FAIL", host, ip, e->dport);
        else
            snprintf(detail, sizeof(detail), "[%s] %s:%u",
                     e->success ? "OK" : "FAIL", ip, e->dport);
        break;
    }
    case EVENT_UNLINK:
        snprintf(detail, sizeof(detail), "[%s] %s",
                 e->success ? "OK" : "FAIL", e->filename);
        break;
    case EVENT_RENAME:
        snprintf(detail, sizeof(detail), "[%s] %s -> %s",
                 e->success ? "OK" : "FAIL", e->filename, e->args);
        break;
    case EVENT_CHMOD:
        snprintf(detail, sizeof(detail), "[%s] %s mode=0%o",
                 e->success ? "OK" : "FAIL", e->filename, e->mode);
        break;
    case EVENT_BIND: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        if (strcmp(host, ip) != 0)
            snprintf(detail, sizeof(detail), "[%s] %s (%s):%u",
                     e->success ? "OK" : "FAIL", host, ip, e->dport);
        else
            snprintf(detail, sizeof(detail), "[%s] %s:%u",
                     e->success ? "OK" : "FAIL", ip, e->dport);
        break;
    }
    case EVENT_PTRACE:
        snprintf(detail, sizeof(detail), "[%s] req=%d target_pid=%d",
                 e->success ? "OK" : "FAIL", e->ptrace_req, e->target_pid);
        break;
    case EVENT_DNS: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        snprintf(detail, sizeof(detail), "[%s] query=%s dst=%s:%u",
                 e->success ? "OK" : "FAIL", e->filename, ip, e->dport);
        break;
    }
    case EVENT_SEND: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        snprintf(detail, sizeof(detail), "[%s] dst=%s:%u len=%u",
                 e->success ? "OK" : "FAIL", ip, e->dport, e->mode);
        break;
    }
    case EVENT_WRITE_CLOSE:
        snprintf(detail, sizeof(detail), "%s", e->filename);
        break;
    case EVENT_PRIVESC:
        snprintf(detail, sizeof(detail), "uid %u->%u caps=0x%llx",
                 e->uid_before, e->uid_after, (unsigned long long)e->cap_data);
        break;
    case EVENT_MEMEXEC:
        snprintf(detail, sizeof(detail), "prot=0x%x flags=0x%x %s",
                 e->mode, e->open_flags,
                 e->filename[0] ? e->filename : "<anon>");
        break;
    case EVENT_KMOD_LOAD:
        snprintf(detail, sizeof(detail), "%s",
                 e->filename[0] ? e->filename : "<anonymous>");
        break;
    case EVENT_NET_CORR: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        snprintf(detail, sizeof(detail), "dns=%s -> %s:%u",
                 e->dns_name, ip, e->dport);
        break;
    }
    case EVENT_RATE_LIMIT:
        snprintf(detail, sizeof(detail), "pid=%d rate-limited", e->pid);
        break;
    case EVENT_THREAT_INTEL: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        snprintf(detail, sizeof(detail), "[BLOCKED] %s:%u", ip, e->dport);
        break;
    }
    case EVENT_TLS_SNI:
        snprintf(detail, sizeof(detail), "sni=%s", e->dns_name);
        break;
    case EVENT_PROC_SCRAPE:
        snprintf(detail, sizeof(detail), "target_pid=%d path=%s",
                 e->target_pid, e->filename);
        break;
    case EVENT_NS_ESCAPE:
        snprintf(detail, sizeof(detail), "ns_flags=0x%x", e->mode);
        break;
    case EVENT_TLS_DATA:
        snprintf(detail, sizeof(detail), "tls_len=%u", e->tls_payload_len);
        break;
    case EVENT_HEARTBEAT:
        snprintf(detail, sizeof(detail), "liveness");
        break;
    }

    syslog(LOG_INFO,
           "type=%s pid=%d ppid=%d uid=%u comm=%s cgroup=%s lineage=%s %s",
           ts, e->pid, e->ppid, e->uid, e->comm,
           e->cgroup[0] ? e->cgroup : "-", chain, detail);
}

/* ── CEF output ─────────────────────────────────────────────────────────── */
/*
 * ArcSight Common Event Format v0.
 * Header: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
 * Extension: space-separated key=value pairs.
 *   Header field escaping : | → \|  \ → \\
 *   Extension value escaping: = → \=  \ → \\  \n → \\n
 */

static void cef_hdr_str(const char *s)
{
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '|' || *p == '\\') fputc('\\', OUT);
        fputc(*p, OUT);
    }
}

static void cef_ext_val(const char *s)
{
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '\\') { fprintf(OUT, "\\\\"); continue; }
        if (*p == '=')  { fprintf(OUT, "\\=");  continue; }
        if (*p == '\n') { fprintf(OUT, "\\n");  continue; }
        fputc(*p, OUT);
    }
}

static void cef_event(const event_t *e)
{
    static const struct { const char *id; const char *name; int sev; } meta[] = {
        [EVENT_EXEC]        = {"EXEC",         "Process Execution",        3},
        [EVENT_OPEN]        = {"OPEN",         "File Open",                3},
        [EVENT_EXIT]        = {"EXIT",         "Process Exit",             0},
        [EVENT_CONNECT]     = {"CONNECT",      "Network Connection",       3},
        [EVENT_UNLINK]      = {"UNLINK",       "File Deletion",            5},
        [EVENT_RENAME]      = {"RENAME",       "File Rename",              5},
        [EVENT_CHMOD]       = {"CHMOD",        "Permission Change",        5},
        [EVENT_BIND]        = {"BIND",         "Socket Bind",              3},
        [EVENT_PTRACE]      = {"PTRACE",       "Ptrace Call",              8},
        [EVENT_DNS]         = {"DNS",          "DNS Query",                3},
        [EVENT_SEND]        = {"SEND",         "Network Send",             3},
        [EVENT_WRITE_CLOSE] = {"WRITE_CLOSE",  "File Write-Close",         3},
        [EVENT_PRIVESC]     = {"PRIVESC",      "Privilege Escalation",     9},
        [EVENT_MEMEXEC]     = {"MEMEXEC",      "Memory Exec Mapping",      8},
        [EVENT_KMOD_LOAD]   = {"KMOD_LOAD",    "Kernel Module Load",       9},
        [EVENT_NET_CORR]    = {"NET_CORR",     "DNS-Connect Correlation",  5},
        [EVENT_RATE_LIMIT]  = {"RATE_LIMIT",   "Rate Limit Hit",           2},
        [EVENT_THREAT_INTEL]= {"THREAT_INTEL", "Threat Intel Match",       9},
        [EVENT_TLS_SNI]     = {"TLS_SNI",      "TLS SNI Observed",         3},
        [EVENT_PROC_SCRAPE] = {"PROC_SCRAPE",  "Proc Scraping Detected",   8},
        [EVENT_NS_ESCAPE]   = {"NS_ESCAPE",    "Namespace Escape",         9},
        [EVENT_TLS_DATA]    = {"TLS_DATA",     "Decrypted TLS Data",       3},
        [EVENT_HEARTBEAT]   = {"HEARTBEAT",    "Agent Liveness Ping",      0},
    };

    if (e->type >= EVENT_TYPE_MAX) return;
    const char *sig  = meta[e->type].id;
    const char *name = meta[e->type].name;
    int         sev  = meta[e->type].sev;

    /* Header */
    fprintf(OUT, "CEF:0|argus|argus|");
    cef_hdr_str(ARGUS_VERSION);
    fputc('|', OUT);
    cef_hdr_str(sig);
    fputc('|', OUT);
    cef_hdr_str(name);
    fprintf(OUT, "|%d|", sev);

    /* Extension: common fields */
    fprintf(OUT, "spid=%d suid=%u sgid=%u dproc=", e->pid, e->uid, e->gid);
    cef_ext_val(e->comm);

    const char *uname = uid_name(e->uid);
    if (uname) { fprintf(OUT, " suser="); cef_ext_val(uname); }

    char chain[LINEAGE_BUF];
    lineage_str(e->ppid, chain, sizeof(chain));
    fprintf(OUT, " flexString1Label=lineage flexString1=");
    cef_ext_val(chain);

    if (e->cgroup[0]) { fprintf(OUT, " cs1Label=cgroup cs1="); cef_ext_val(e->cgroup); }

    /* Extension: type-specific fields */
    switch (e->type) {
    case EVENT_EXEC:
        fprintf(OUT, " fname="); cef_ext_val(e->filename);
        fprintf(OUT, " cs2Label=args cs2="); cef_ext_val(e->args);
        break;
    case EVENT_OPEN:
        fprintf(OUT, " fname="); cef_ext_val(e->filename);
        fprintf(OUT, " outcome=%s", e->success ? "Success" : "Failure");
        break;
    case EVENT_EXIT:
        fprintf(OUT, " reason=exit_code=%d", e->exit_code);
        break;
    case EVENT_CONNECT: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        fprintf(OUT, " dst="); cef_ext_val(ip);
        fprintf(OUT, " dpt=%u", e->dport);
        if (strcmp(host, ip) != 0) { fprintf(OUT, " dhost="); cef_ext_val(host); }
        fprintf(OUT, " outcome=%s", e->success ? "Success" : "Failure");
        break;
    }
    case EVENT_BIND: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, " src="); cef_ext_val(ip);
        fprintf(OUT, " spt=%u", e->dport);
        fprintf(OUT, " outcome=%s", e->success ? "Success" : "Failure");
        break;
    }
    case EVENT_UNLINK:
        fprintf(OUT, " fname="); cef_ext_val(e->filename);
        fprintf(OUT, " outcome=%s", e->success ? "Success" : "Failure");
        break;
    case EVENT_RENAME:
        fprintf(OUT, " fname="); cef_ext_val(e->filename);
        fprintf(OUT, " cs2Label=new_path cs2="); cef_ext_val(e->args);
        fprintf(OUT, " outcome=%s", e->success ? "Success" : "Failure");
        break;
    case EVENT_CHMOD:
        fprintf(OUT, " fname="); cef_ext_val(e->filename);
        fprintf(OUT, " cs2Label=mode cs2=0%o", e->mode);
        fprintf(OUT, " outcome=%s", e->success ? "Success" : "Failure");
        break;
    case EVENT_PTRACE:
        fprintf(OUT, " cs2Label=ptrace_req cs2=%d cs3Label=target_pid cs3=%d",
                e->ptrace_req, e->target_pid);
        fprintf(OUT, " outcome=%s", e->success ? "Success" : "Failure");
        break;
    case EVENT_DNS: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, " dnsQuery="); cef_ext_val(e->filename);
        fprintf(OUT, " dst=%s dpt=%u", ip, e->dport);
        fprintf(OUT, " outcome=%s", e->success ? "Success" : "Failure");
        break;
    }
    case EVENT_SEND: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, " dst=%s dpt=%u cn1Label=payload_len cn1=%u",
                ip, e->dport, e->mode);
        fprintf(OUT, " outcome=%s", e->success ? "Success" : "Failure");
        break;
    }
    case EVENT_WRITE_CLOSE:
        fprintf(OUT, " fname="); cef_ext_val(e->filename);
        break;
    case EVENT_PRIVESC:
        fprintf(OUT, " cs2Label=uid_before cs2=%u cs3Label=uid_after cs3=%u"
                     " cn1Label=cap_data cn1=%llu",
                e->uid_before, e->uid_after, (unsigned long long)e->cap_data);
        break;
    case EVENT_MEMEXEC:
        fprintf(OUT, " cs2Label=prot cs2=0x%x cs3Label=mmap_flags cs3=0x%x",
                e->mode, e->open_flags);
        if (e->filename[0]) { fprintf(OUT, " fname="); cef_ext_val(e->filename); }
        break;
    case EVENT_KMOD_LOAD:
        fprintf(OUT, " fname=");
        cef_ext_val(e->filename[0] ? e->filename : "<anonymous>");
        break;
    case EVENT_NET_CORR: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, " cs2Label=dns_name cs2="); cef_ext_val(e->dns_name);
        fprintf(OUT, " dst=%s dpt=%u", ip, e->dport);
        break;
    }
    case EVENT_RATE_LIMIT:
        fprintf(OUT, " cs2Label=limited_pid cs2=%d", e->pid);
        break;
    case EVENT_THREAT_INTEL: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        fprintf(OUT, " dst=%s dpt=%u outcome=Blocked", ip, e->dport);
        break;
    }
    case EVENT_TLS_SNI:
        fprintf(OUT, " cs2Label=sni cs2="); cef_ext_val(e->dns_name);
        break;
    case EVENT_PROC_SCRAPE:
        fprintf(OUT, " cs2Label=target_pid cs2=%d fname=", e->target_pid);
        cef_ext_val(e->filename);
        break;
    case EVENT_NS_ESCAPE:
        fprintf(OUT, " cs2Label=ns_flags cs2=0x%x", e->mode);
        break;
    case EVENT_TLS_DATA:
        fprintf(OUT, " cn1Label=tls_len cn1=%u", e->tls_payload_len);
        break;
    case EVENT_HEARTBEAT:
        break;
    }
    fputc('\n', OUT);
}

/* ── summary mode ───────────────────────────────────────────────────────── */

#define SUMMARY_MAX_COMMS 64

typedef struct {
    char     comm[16];
    uint64_t counts[EVENT_TYPE_MAX];   /* indexed by event_type_t */
} comm_stat_t;

static int         g_summary_interval = 0;
static uint64_t    g_totals[EVENT_TYPE_MAX];
static uint64_t    g_summary_drops;
static comm_stat_t g_comm_stats[SUMMARY_MAX_COMMS];
static int         g_comm_count;
static time_t      g_last_flush;

void output_set_summary(int interval_secs)
{
    g_summary_interval = interval_secs;
    g_last_flush       = time(NULL);
    memset(g_totals,     0, sizeof(g_totals));
    memset(g_comm_stats, 0, sizeof(g_comm_stats));
    g_comm_count   = 0;
    g_summary_drops = 0;
}

static void summary_record(const event_t *e)
{
    if (e->type < EVENT_TYPE_MAX)
        g_totals[e->type]++;

    comm_stat_t *slot = NULL;
    for (int i = 0; i < g_comm_count; i++) {
        if (strncmp(g_comm_stats[i].comm, e->comm, 16) == 0) {
            slot = &g_comm_stats[i];
            break;
        }
    }
    if (!slot && g_comm_count < SUMMARY_MAX_COMMS) {
        slot = &g_comm_stats[g_comm_count++];
        strncpy(slot->comm, e->comm, 15);
        slot->comm[15] = '\0';
        memset(slot->counts, 0, sizeof(slot->counts));
    }
    if (slot && e->type < EVENT_TYPE_MAX)
        slot->counts[e->type]++;
}

static void print_top_comms(int type, int top)
{
    int order[SUMMARY_MAX_COMMS];
    for (int i = 0; i < g_comm_count; i++) order[i] = i;
    for (int i = 0; i < g_comm_count && i < top; i++) {
        int best = i;
        for (int j = i + 1; j < g_comm_count; j++)
            if (g_comm_stats[order[j]].counts[type] >
                g_comm_stats[order[best]].counts[type])
                best = j;
        int tmp = order[i]; order[i] = order[best]; order[best] = tmp;
    }
    for (int i = 0; i < g_comm_count && i < top; i++) {
        uint64_t c = g_comm_stats[order[i]].counts[type];
        if (c == 0) break;
        fprintf(OUT, "  %s(%llu)", g_comm_stats[order[i]].comm,
               (unsigned long long)c);
    }
}

static void summary_flush(void)
{
    static const char *line =
        "════════════════════════════════════════════════════════";
    fprintf(OUT, "\n%s\n", line);
    fprintf(OUT, " %lus summary\n", (unsigned long)g_summary_interval);
    static const struct { event_type_t t; const char *label; } rows[] = {
        { EVENT_EXEC,    "EXEC   " }, { EVENT_OPEN,   "OPEN   " },
        { EVENT_CONNECT, "CONNECT" }, { EVENT_EXIT,   "EXIT   " },
        { EVENT_UNLINK,  "UNLINK " }, { EVENT_RENAME, "RENAME " },
        { EVENT_CHMOD,   "CHMOD  " }, { EVENT_BIND,   "BIND   " },
        { EVENT_PTRACE,  "PTRACE " },
    };
    for (int r = 0; r < 9; r++) {
        uint64_t n = g_totals[rows[r].t];
        if (n == 0 && rows[r].t != EVENT_EXEC && rows[r].t != EVENT_OPEN)
            continue;
        fprintf(OUT, "  %s %6llu", rows[r].label, (unsigned long long)n);
        if (rows[r].t != EVENT_EXIT)
            print_top_comms(rows[r].t, 5);
        fputc('\n', OUT);
    }
    if (g_summary_drops)
        fprintf(OUT, "  DROPS   %6llu\n", (unsigned long long)g_summary_drops);
    fprintf(OUT, "%s\n\n", line);
    fflush(OUT);

    memset(g_totals,     0, sizeof(g_totals));
    memset(g_comm_stats, 0, sizeof(g_comm_stats));
    g_comm_count    = 0;
    g_summary_drops = 0;
    g_last_flush    = time(NULL);
}

void output_summary_tick(uint64_t drop_delta)
{
    if (!g_summary_interval)
        return;
    g_summary_drops += drop_delta;
    if (time(NULL) - g_last_flush >= g_summary_interval)
        summary_flush();
}

/* ── event_to_json ──────────────────────────────────────────────────────── */
/*
 * Serialise one event to a caller-supplied buffer as JSON (no newline).
 * Uses open_memstream so we can reuse the existing json_event formatter.
 * The g_out swap is safe because argus is single-threaded.
 */
size_t event_to_json(const event_t *e, char *buf, size_t bufsz)
{
    if (!buf || bufsz < 2) return 0;

    char  *ptr = NULL;
    size_t sz  = 0;
    FILE  *mem = open_memstream(&ptr, &sz);
    if (!mem) return 0;

    FILE *saved = g_out;
    g_out = mem;
    json_event(e);      /* writes JSON + '\n' into mem via OUT macro */
    g_out = saved;

    fclose(mem);        /* finalises ptr and sz */

    /* strip trailing newline written by json_event */
    size_t copy = sz;
    if (copy > 0 && ptr[copy - 1] == '\n') copy--;
    if (copy >= bufsz) copy = bufsz - 1;
    memcpy(buf, ptr, copy);
    buf[copy] = '\0';
    free(ptr);
    return copy;
}

/* ── dispatcher ─────────────────────────────────────────────────────────── */

void print_event(const event_t *e)
{
    if (g_summary_interval) {
        summary_record(e);
        return;
    }
    if (g_fmt == OUTPUT_JSON)
        json_event(e);
    else if (g_fmt == OUTPUT_SYSLOG)
        syslog_event(e);
    else if (g_fmt == OUTPUT_CEF)
        cef_event(e);
    else
        text_event(e);
}

void print_drops(uint64_t count)
{
    if (g_summary_interval) {
        g_summary_drops += count;
        return;
    }
    if (g_fmt == OUTPUT_JSON)
        fprintf(OUT, "{\"type\":\"DROP\",\"count\":%llu}\n",
               (unsigned long long)count);
    else if (g_fmt == OUTPUT_SYSLOG)
        syslog(LOG_WARNING, "dropped %llu event(s) — ring buffer full",
               (unsigned long long)count);
    else if (g_fmt == OUTPUT_CEF)
        fprintf(OUT, "CEF:0|argus|argus|%s|DROP|Ring Buffer Drop|5|cnt=%llu\n",
                ARGUS_VERSION, (unsigned long long)count);
    else
        fprintf(stderr, "[WARNING: %llu event(s) dropped — ring buffer full]\n",
                (unsigned long long)count);
}
