/*
 * compliance.c — Compliance framework mapping and HTML report generation.
 *
 * Maps Argus event types to controls from:
 *   CIS Linux Benchmark, PCI-DSS, NIST CSF, SOC2
 *
 * Generates a self-contained HTML report with summary and event log tables.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "compliance.h"
#include "argus.h"

/* ── compile-time limits ─────────────────────────────────────────────────── */

#define COMP_MAX_CONTROLS   32          /* max controls per framework          */
#define COMP_MAX_RECORDS    2048        /* circular event log capacity         */
#define COMP_DETAIL_LEN     128         /* bytes in each record's detail field */

/* ── control status ──────────────────────────────────────────────────────── */

typedef enum {
    STATUS_CLEAN     = 0,
    STATUS_TRIGGERED = 1,
    STATUS_ALERTED   = 2,
} control_status_t;

/* ── per-control runtime state ───────────────────────────────────────────── */

typedef struct {
    event_type_t     event_type;    /* which Argus event triggers this control */
    const char      *id;            /* e.g. "CIS 1.1.1"                        */
    const char      *name;          /* human-readable description               */
    uint64_t         event_count;   /* total events matched                     */
    uint64_t         alert_count;   /* alerts recorded via compliance_record_alert */
    time_t           first_seen;    /* epoch of first matching event            */
    time_t           last_seen;     /* epoch of most recent matching event      */
    control_status_t status;
} control_state_t;

/* ── per-event log record ────────────────────────────────────────────────── */

typedef struct {
    time_t       ts;
    event_type_t type;
    int          pid;
    char         comm[16];
    char         detail[COMP_DETAIL_LEN];
} event_record_t;

/* ── static control definition tables ───────────────────────────────────── */

/* Each table entry: { event_type, id, name } — status fields zeroed at init */

typedef struct {
    event_type_t  event_type;
    const char   *id;
    const char   *name;
} control_def_t;

static const control_def_t g_cis_defs[] = {
    { EVENT_EXEC,      "CIS 1.1.1", "Audit process execution" },
    { EVENT_PRIVESC,   "CIS 4.1.3", "Ensure privilege escalation is audited" },
    { EVENT_KMOD_LOAD, "CIS 1.2.1", "Ensure kernel module loading is restricted" },
    { EVENT_PTRACE,    "CIS 6.2.1", "Ensure ptrace is audited" },
    { EVENT_CHMOD,     "CIS 1.1.5", "Ensure permissions on sensitive files are audited" },
    { EVENT_NS_ESCAPE, "CIS 1.5.1", "Ensure namespace isolation is monitored" },
    { EVENT_MEMEXEC,   "CIS 6.1.1", "Ensure anonymous memory execution is audited" },
    { EVENT_UNLINK,    "CIS 6.3.1", "Ensure file deletion is audited" },
};

static const control_def_t g_pci_defs[] = {
    { EVENT_CONNECT,      "PCI-DSS 10.2.4", "Audit invalid access attempts" },
    { EVENT_PRIVESC,      "PCI-DSS 10.2.5", "Audit use of identification/authentication mechanisms" },
    { EVENT_EXEC,         "PCI-DSS 10.2.2", "Audit all actions taken by root or admin" },
    { EVENT_THREAT_INTEL, "PCI-DSS 6.3.3",  "All components protected from known vulnerabilities" },
    { EVENT_OPEN,         "PCI-DSS 10.2.1", "Audit all individual user access to cardholder data" },
    { EVENT_KMOD_LOAD,    "PCI-DSS 10.2.6", "Audit initialization, stopping of audit logs" },
};

static const control_def_t g_nist_defs[] = {
    { EVENT_EXEC,         "DE.CM-1",  "The network is monitored to detect potential cybersecurity events" },
    { EVENT_CONNECT,      "DE.CM-7",  "Monitoring for unauthorized personnel/connections/devices" },
    { EVENT_PRIVESC,      "PR.AC-4",  "Access permissions and authorizations are managed" },
    { EVENT_MEMEXEC,      "DE.CM-4",  "Malicious code is detected" },
    { EVENT_NS_ESCAPE,    "PR.PT-3",  "Communications and control networks are protected" },
    { EVENT_THREAT_INTEL, "RS.AN-1",  "Notifications from detection systems are investigated" },
    { EVENT_KMOD_LOAD,    "PR.IP-1",  "Baseline configuration of IT systems established" },
};

static const control_def_t g_soc2_defs[] = {
    { EVENT_PRIVESC,   "CC6.1", "Logical and physical access controls" },
    { EVENT_EXEC,      "CC7.2", "Monitor system components for anomalies" },
    { EVENT_CONNECT,   "CC6.6", "Logical access security measures" },
    { EVENT_MEMEXEC,   "CC7.1", "Detect and monitor for new vulnerabilities" },
    { EVENT_KMOD_LOAD, "CC8.1", "Change management controls" },
};

/* ── module state ────────────────────────────────────────────────────────── */

static compliance_framework_t  g_framework;
static char                    g_report_path[512];
static control_state_t         g_controls[COMP_MAX_CONTROLS];
static int                     g_ncontrols = 0;
static int                     g_initialized = 0;

/* Circular event log */
static event_record_t          g_records[COMP_MAX_RECORDS];
static int                     g_record_head = 0;   /* next write position   */
static int                     g_record_count = 0;  /* total records stored  */

/* ── helpers ─────────────────────────────────────────────────────────────── */

static const char *framework_name(compliance_framework_t fw)
{
    switch (fw) {
    case COMPLIANCE_CIS_LINUX: return "CIS Linux Benchmark";
    case COMPLIANCE_PCI_DSS:   return "PCI-DSS";
    case COMPLIANCE_NIST_CSF:  return "NIST CSF";
    case COMPLIANCE_SOC2:      return "SOC 2";
    }
    return "Unknown";
}

static const char *event_type_name(event_type_t t)
{
    switch (t) {
    case EVENT_EXEC:         return "EXEC";
    case EVENT_OPEN:         return "OPEN";
    case EVENT_EXIT:         return "EXIT";
    case EVENT_CONNECT:      return "CONNECT";
    case EVENT_UNLINK:       return "UNLINK";
    case EVENT_RENAME:       return "RENAME";
    case EVENT_CHMOD:        return "CHMOD";
    case EVENT_BIND:         return "BIND";
    case EVENT_PTRACE:       return "PTRACE";
    case EVENT_DNS:          return "DNS";
    case EVENT_SEND:         return "SEND";
    case EVENT_WRITE_CLOSE:  return "WRITE_CLOSE";
    case EVENT_PRIVESC:      return "PRIVESC";
    case EVENT_MEMEXEC:      return "MEMEXEC";
    case EVENT_KMOD_LOAD:    return "KMOD_LOAD";
    case EVENT_NET_CORR:     return "NET_CORR";
    case EVENT_RATE_LIMIT:   return "RATE_LIMIT";
    case EVENT_THREAT_INTEL: return "THREAT_INTEL";
    case EVENT_TLS_SNI:      return "TLS_SNI";
    case EVENT_PROC_SCRAPE:  return "PROC_SCRAPE";
    case EVENT_NS_ESCAPE:    return "NS_ESCAPE";
    case EVENT_TLS_DATA:     return "TLS_DATA";
    case EVENT_HEARTBEAT:    return "HEARTBEAT";
    }
    return "UNKNOWN";
}

/* Initialise the g_controls array from a definition table. */
static void load_controls(const control_def_t *defs, int n)
{
    g_ncontrols = 0;
    if (n > COMP_MAX_CONTROLS)
        n = COMP_MAX_CONTROLS;
    for (int i = 0; i < n; i++) {
        g_controls[i].event_type  = defs[i].event_type;
        g_controls[i].id          = defs[i].id;
        g_controls[i].name        = defs[i].name;
        g_controls[i].event_count = 0;
        g_controls[i].alert_count = 0;
        g_controls[i].first_seen  = 0;
        g_controls[i].last_seen   = 0;
        g_controls[i].status      = STATUS_CLEAN;
    }
    g_ncontrols = n;
}

/* Push one record into the circular log (drops oldest when full). */
static void push_record(const event_t *ev, const char *detail)
{
    event_record_t *r = &g_records[g_record_head];
    r->ts   = (time_t)(ev->duration_ns / 1000000000ULL); /* coarse ts from duration */
    if (r->ts == 0)
        r->ts = time(NULL);
    r->type = ev->type;
    r->pid  = ev->pid;
    strncpy(r->comm,   ev->comm, sizeof(r->comm) - 1);
    r->comm[sizeof(r->comm) - 1] = '\0';
    strncpy(r->detail, detail ? detail : "", sizeof(r->detail) - 1);
    r->detail[sizeof(r->detail) - 1] = '\0';

    g_record_head = (g_record_head + 1) % COMP_MAX_RECORDS;
    if (g_record_count < COMP_MAX_RECORDS)
        g_record_count++;
}

/* Build a brief detail string for an event. */
static void build_detail(const event_t *ev, char *buf, size_t sz)
{
    switch (ev->type) {
    case EVENT_EXEC:
        snprintf(buf, sz, "file=%s args=%s", ev->filename, ev->args);
        break;
    case EVENT_OPEN:
        snprintf(buf, sz, "file=%s flags=0x%x", ev->filename, ev->open_flags);
        break;
    case EVENT_CONNECT:
        snprintf(buf, sz, "dport=%u", ev->dport);
        break;
    case EVENT_PRIVESC:
        snprintf(buf, sz, "uid %u->%u cap=0x%llx",
                 ev->uid_before, ev->uid_after,
                 (unsigned long long)ev->cap_data);
        break;
    case EVENT_KMOD_LOAD:
        snprintf(buf, sz, "file=%s", ev->filename);
        break;
    case EVENT_CHMOD:
        snprintf(buf, sz, "file=%s mode=0%o", ev->filename, ev->mode);
        break;
    case EVENT_NS_ESCAPE:
        snprintf(buf, sz, "flags=0x%x", ev->mode);
        break;
    case EVENT_MEMEXEC:
        snprintf(buf, sz, "prot=0x%x", ev->mode);
        break;
    case EVENT_UNLINK:
        snprintf(buf, sz, "file=%s", ev->filename);
        break;
    case EVENT_PTRACE:
        snprintf(buf, sz, "req=%d target_pid=%d", ev->ptrace_req, ev->target_pid);
        break;
    case EVENT_THREAT_INTEL:
        snprintf(buf, sz, "dport=%u dns=%s", ev->dport, ev->dns_name);
        break;
    default:
        snprintf(buf, sz, "pid=%d", ev->pid);
        break;
    }
}

/* ── public API ──────────────────────────────────────────────────────────── */

void compliance_init(compliance_framework_t framework, const char *report_path)
{
    g_framework = framework;
    strncpy(g_report_path, report_path ? report_path : "compliance_report.html",
            sizeof(g_report_path) - 1);
    g_report_path[sizeof(g_report_path) - 1] = '\0';

    g_record_head  = 0;
    g_record_count = 0;

    switch (framework) {
    case COMPLIANCE_CIS_LINUX:
        load_controls(g_cis_defs,  (int)(sizeof(g_cis_defs)  / sizeof(g_cis_defs[0])));
        break;
    case COMPLIANCE_PCI_DSS:
        load_controls(g_pci_defs,  (int)(sizeof(g_pci_defs)  / sizeof(g_pci_defs[0])));
        break;
    case COMPLIANCE_NIST_CSF:
        load_controls(g_nist_defs, (int)(sizeof(g_nist_defs) / sizeof(g_nist_defs[0])));
        break;
    case COMPLIANCE_SOC2:
        load_controls(g_soc2_defs, (int)(sizeof(g_soc2_defs) / sizeof(g_soc2_defs[0])));
        break;
    }

    g_initialized = 1;
}

void compliance_record_event(const event_t *ev)
{
    if (!g_initialized)
        return;

    time_t now = time(NULL);
    char detail[COMP_DETAIL_LEN];
    build_detail(ev, detail, sizeof(detail));

    for (int i = 0; i < g_ncontrols; i++) {
        if (g_controls[i].event_type != ev->type)
            continue;

        g_controls[i].event_count++;
        if (g_controls[i].first_seen == 0)
            g_controls[i].first_seen = now;
        g_controls[i].last_seen = now;
        if (g_controls[i].status == STATUS_CLEAN)
            g_controls[i].status = STATUS_TRIGGERED;
    }

    push_record(ev, detail);
}

void compliance_record_alert(const event_t *ev, const char *rule_name,
                              const char *severity)
{
    if (!g_initialized)
        return;

    time_t now = time(NULL);
    char detail[COMP_DETAIL_LEN];
    snprintf(detail, sizeof(detail), "ALERT rule=%s severity=%s",
             rule_name ? rule_name : "", severity ? severity : "");

    for (int i = 0; i < g_ncontrols; i++) {
        if (g_controls[i].event_type != ev->type)
            continue;

        g_controls[i].alert_count++;
        g_controls[i].event_count++;
        if (g_controls[i].first_seen == 0)
            g_controls[i].first_seen = now;
        g_controls[i].last_seen = now;
        g_controls[i].status = STATUS_ALERTED;
    }

    push_record(ev, detail);
}

/* ── HTML report writer ──────────────────────────────────────────────────── */

static void html_escape(FILE *f, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
        case '&':  fputs("&amp;",  f); break;
        case '<':  fputs("&lt;",   f); break;
        case '>':  fputs("&gt;",   f); break;
        case '"':  fputs("&quot;", f); break;
        case '\'': fputs("&#39;",  f); break;
        default:   fputc(*s, f);       break;
        }
    }
}

static void fmt_time(char *buf, size_t sz, time_t t)
{
    if (t == 0) {
        strncpy(buf, "—", sz - 1);
        buf[sz - 1] = '\0';
        return;
    }
    struct tm *tm = localtime(&t);
    if (tm)
        strftime(buf, sz, "%Y-%m-%d %H:%M:%S", tm);
    else
        strncpy(buf, "?", sz - 1);
}

int compliance_write_report(void)
{
    if (!g_initialized)
        return -1;

    FILE *f = fopen(g_report_path, "w");
    if (!f) {
        perror("compliance: could not open report path");
        return -1;
    }

    char generated[64];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    if (tm)
        strftime(generated, sizeof(generated), "%Y-%m-%d %H:%M:%S", tm);
    else
        strncpy(generated, "unknown", sizeof(generated) - 1);

    /* ── HTML head ───────────────────────────────────────────────────────── */
    fprintf(f,
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "<title>Argus Compliance Report &mdash; %s</title>\n"
        "<style>\n"
        "  body { font-family: 'Segoe UI', Arial, sans-serif; margin: 2em;"
                " background: #f5f5f5; color: #222; }\n"
        "  h1   { color: #333; border-bottom: 2px solid #333; padding-bottom: .4em; }\n"
        "  h2   { color: #444; margin-top: 2em; }\n"
        "  p.subtitle { color: #666; margin-top: -.5em; }\n"
        "  table { border-collapse: collapse; width: 100%%; margin-top: 1em;"
                " background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,.15); }\n"
        "  th   { background: #333; color: #fff; padding: .6em 1em;"
                " text-align: left; font-size: .9em; }\n"
        "  td   { padding: .5em 1em; border-bottom: 1px solid #ddd;"
                " font-size: .85em; vertical-align: top; }\n"
        "  tr:last-child td { border-bottom: none; }\n"
        "  tr:hover td { background: #f0f4ff; }\n"
        "  .clean     { background: #e8f5e9; color: #1b5e20; font-weight: bold; }\n"
        "  .triggered { background: #fff8e1; color: #e65100; font-weight: bold; }\n"
        "  .alerted   { background: #ffebee; color: #b71c1c; font-weight: bold; }\n"
        "  .badge-clean     { display:inline-block; padding:.2em .7em;"
                            " border-radius:4px; background:#c8e6c9; color:#1b5e20; }\n"
        "  .badge-triggered { display:inline-block; padding:.2em .7em;"
                            " border-radius:4px; background:#ffe082; color:#e65100; }\n"
        "  .badge-alerted   { display:inline-block; padding:.2em .7em;"
                            " border-radius:4px; background:#ef9a9a; color:#b71c1c; }\n"
        "  footer { margin-top: 3em; color: #999; font-size: .8em;"
                  " border-top: 1px solid #ddd; padding-top: 1em; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n",
        framework_name(g_framework));

    /* ── page header ─────────────────────────────────────────────────────── */
    fprintf(f,
        "<h1>Argus Compliance Report &mdash; %s</h1>\n"
        "<p class=\"subtitle\">Generated: %s</p>\n",
        framework_name(g_framework), generated);

    /* ── summary table ───────────────────────────────────────────────────── */
    fprintf(f,
        "<h2>Control Summary</h2>\n"
        "<table>\n"
        "<thead><tr>\n"
        "  <th>Control ID</th>\n"
        "  <th>Control Name</th>\n"
        "  <th>Event Type</th>\n"
        "  <th>Event Count</th>\n"
        "  <th>Alert Count</th>\n"
        "  <th>First Seen</th>\n"
        "  <th>Last Seen</th>\n"
        "  <th>Status</th>\n"
        "</tr></thead>\n"
        "<tbody>\n");

    for (int i = 0; i < g_ncontrols; i++) {
        control_state_t *c = &g_controls[i];
        char first_buf[32], last_buf[32];
        fmt_time(first_buf, sizeof(first_buf), c->first_seen);
        fmt_time(last_buf,  sizeof(last_buf),  c->last_seen);

        const char *row_class  = "";
        const char *badge_class = "badge-clean";
        const char *status_str  = "CLEAN";
        switch (c->status) {
        case STATUS_TRIGGERED:
            row_class   = " class=\"triggered\"";
            badge_class = "badge-triggered";
            status_str  = "TRIGGERED";
            break;
        case STATUS_ALERTED:
            row_class   = " class=\"alerted\"";
            badge_class = "badge-alerted";
            status_str  = "ALERTED";
            break;
        default:
            row_class   = " class=\"clean\"";
            break;
        }

        fprintf(f, "<tr%s>\n", row_class);
        fprintf(f, "  <td>");   html_escape(f, c->id);   fprintf(f, "</td>\n");
        fprintf(f, "  <td>");   html_escape(f, c->name); fprintf(f, "</td>\n");
        fprintf(f, "  <td>%s</td>\n", event_type_name(c->event_type));
        fprintf(f, "  <td>%llu</td>\n", (unsigned long long)c->event_count);
        fprintf(f, "  <td>%llu</td>\n", (unsigned long long)c->alert_count);
        fprintf(f, "  <td>%s</td>\n", first_buf);
        fprintf(f, "  <td>%s</td>\n", last_buf);
        fprintf(f, "  <td><span class=\"%s\">%s</span></td>\n",
                badge_class, status_str);
        fprintf(f, "</tr>\n");
    }

    fprintf(f, "</tbody>\n</table>\n");

    /* ── event log table ─────────────────────────────────────────────────── */
    fprintf(f,
        "<h2>Event Log (%d record%s)</h2>\n"
        "<table>\n"
        "<thead><tr>\n"
        "  <th>Timestamp</th>\n"
        "  <th>Event Type</th>\n"
        "  <th>PID</th>\n"
        "  <th>Comm</th>\n"
        "  <th>Detail</th>\n"
        "</tr></thead>\n"
        "<tbody>\n",
        g_record_count, g_record_count == 1 ? "" : "s");

    /*
     * Walk the circular buffer in chronological order.
     * When the buffer is full, the oldest entry is at g_record_head.
     * When it is not full, the oldest entry is at index 0.
     */
    int start = (g_record_count == COMP_MAX_RECORDS) ? g_record_head : 0;
    for (int i = 0; i < g_record_count; i++) {
        int idx = (start + i) % COMP_MAX_RECORDS;
        event_record_t *r = &g_records[idx];
        char ts_buf[32];
        fmt_time(ts_buf, sizeof(ts_buf), r->ts);

        fprintf(f, "<tr>\n");
        fprintf(f, "  <td>%s</td>\n", ts_buf);
        fprintf(f, "  <td>%s</td>\n", event_type_name(r->type));
        fprintf(f, "  <td>%d</td>\n", r->pid);
        fprintf(f, "  <td>"); html_escape(f, r->comm);   fprintf(f, "</td>\n");
        fprintf(f, "  <td>"); html_escape(f, r->detail); fprintf(f, "</td>\n");
        fprintf(f, "</tr>\n");
    }

    fprintf(f, "</tbody>\n</table>\n");

    /* ── footer ──────────────────────────────────────────────────────────── */
    fprintf(f,
        "<footer>Generated by Argus v" ARGUS_VERSION "</footer>\n"
        "</body>\n"
        "</html>\n");

    fclose(f);
    return 0;
}

/* ── cleanup ─────────────────────────────────────────────────────────────── */

void compliance_destroy(void)
{
    g_initialized  = 0;
    g_ncontrols    = 0;
    g_record_head  = 0;
    g_record_count = 0;
    g_report_path[0] = '\0';
}
