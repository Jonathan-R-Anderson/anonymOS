#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "config.h"
#include "argus.h"

/* ── defaults ───────────────────────────────────────────────────────────── */

void cfg_defaults(argus_cfg_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->filter.event_mask  = TRACE_ALL;
    cfg->ring_buffer_kb     = 256;
    cfg->summary_interval   = 0;
    cfg->ldpreload_check    = 1;

    /*
     * Suppress high-frequency kernel pseudo-filesystem noise by default.
     * A config file with "exclude_paths": [] clears these.
     */
    strncpy(cfg->filter.excludes[0], "/proc", 127);
    strncpy(cfg->filter.excludes[1], "/sys",  127);
    strncpy(cfg->filter.excludes[2], "/dev",  127);
    cfg->filter.exclude_count = 3;
}

/* ── minimal JSON parser ────────────────────────────────────────────────── */
/*
 * Only handles the flat schema written by argus — no nesting beyond one-level
 * arrays. Ignores unknown keys. Errors leave the field at its current value.
 */

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* Parse a JSON string starting at the opening '"'. Returns ptr after '"'. */
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

/* Parse a JSON integer (no leading minus yet — all our ints are >= 0). */
static const char *parse_int(const char *p, int *out)
{
    p = skip_ws(p);
    if (*p < '0' || *p > '9') return p;
    *out = 0;
    while (*p >= '0' && *p <= '9') { *out = *out * 10 + (*p - '0'); p++; }
    return p;
}

/* Parse true/false into *out (1/0). */
static const char *parse_bool(const char *p, int *out)
{
    p = skip_ws(p);
    if (strncmp(p, "true",  4) == 0) { *out = 1; return p + 4; }
    if (strncmp(p, "false", 5) == 0) { *out = 0; return p + 5; }
    return p;
}

/* Advance past ':' and optional whitespace. */
static const char *past_colon(const char *p)
{
    p = skip_ws(p);
    if (*p == ':') p++;
    return skip_ws(p);
}

/* Parse a JSON double (digits with optional decimal point). */
static const char *parse_double(const char *p, double *out)
{
    p = skip_ws(p);
    if ((*p < '0' || *p > '9') && *p != '-')
        return p;
    double sign = 1.0;
    if (*p == '-') { sign = -1.0; p++; }
    double val = 0.0;
    while (*p >= '0' && *p <= '9') { val = val * 10.0 + (*p - '0'); p++; }
    if (*p == '.') {
        p++;
        double frac = 0.1;
        while (*p >= '0' && *p <= '9') { val += (*p - '0') * frac; frac *= 0.1; p++; }
    }
    *out = sign * val;
    return p;
}

/* ── event_types array parser ───────────────────────────────────────────── */

static int parse_event_types(const char *p, int *mask)
{
    *mask = 0;
    p = skip_ws(p);
    if (*p != '[') return 0;
    p++;
    while (*p && *p != ']') {
        char tok[16] = {};
        p = parse_str(p, tok, sizeof(tok));
        if      (strcmp(tok, "EXEC")    == 0) *mask |= TRACE_EXEC;
        else if (strcmp(tok, "OPEN")    == 0) *mask |= TRACE_OPEN;
        else if (strcmp(tok, "EXIT")    == 0) *mask |= TRACE_EXIT;
        else if (strcmp(tok, "CONNECT") == 0) *mask |= TRACE_CONNECT;
        else if (strcmp(tok, "UNLINK")  == 0) *mask |= TRACE_UNLINK;
        else if (strcmp(tok, "RENAME")  == 0) *mask |= TRACE_RENAME;
        else if (strcmp(tok, "CHMOD")   == 0) *mask |= TRACE_CHMOD;
        else if (strcmp(tok, "BIND")    == 0) *mask |= TRACE_BIND;
        else if (strcmp(tok, "PTRACE")  == 0) *mask |= TRACE_PTRACE;
        p = skip_ws(p);
        if (*p == ',') p++;
        p = skip_ws(p);
    }
    return 1;
}

/* ── exclude_paths array parser ─────────────────────────────────────────── */

static void parse_exclude_paths(const char *p, filter_t *f)
{
    p = skip_ws(p);
    if (*p != '[') return;
    p++;
    while (*p && *p != ']') {
        if (f->exclude_count >= 8) break;
        p = parse_str(p, f->excludes[f->exclude_count], 128);
        if (f->excludes[f->exclude_count][0])
            f->exclude_count++;
        p = skip_ws(p);
        if (*p == ',') p++;
        p = skip_ws(p);
    }
}

/* ── fim_paths array parser ─────────────────────────────────────────────── */

static void parse_fim_paths(const char *p, argus_cfg_t *cfg)
{
    p = skip_ws(p);
    if (*p != '[') return;
    p++;
    while (*p && *p != ']') {
        if (cfg->fim_path_count >= 16) break;
        p = parse_str(p, cfg->fim_paths[cfg->fim_path_count], 256);
        if (cfg->fim_paths[cfg->fim_path_count][0])
            cfg->fim_path_count++;
        p = skip_ws(p);
        if (*p == ',') p++;
        p = skip_ws(p);
    }
}

/* ── cfg_load ───────────────────────────────────────────────────────────── */

int cfg_load(const char *path, argus_cfg_t *cfg)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    /* Read entire file */
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 65536) { fclose(f); return -2; }

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return -2; }
    if (fread(buf, 1, sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -2;
    }
    buf[sz] = '\0';
    fclose(f);

    /* Scan for known keys */
    const char *p = buf;
    while (*p) {
        p = skip_ws(p);
        if (*p != '"') { p++; continue; }

        char key[64] = {};
        p = parse_str(p, key, sizeof(key));
        p = past_colon(p);

        if      (strcmp(key, "pid")  == 0)
            p = parse_int(p, &cfg->filter.pid);
        else if (strcmp(key, "comm") == 0)
            p = parse_str(p, cfg->filter.comm, sizeof(cfg->filter.comm));
        else if (strcmp(key, "path") == 0)
            p = parse_str(p, cfg->filter.path, sizeof(cfg->filter.path));
        else if (strcmp(key, "json") == 0) {
            int v = 0;
            p = parse_bool(p, &v);
            /* stored separately by caller — mark via ring_buffer_kb sentinel? */
            (void)v; /* caller reads this via the fmt field; skip for now */
        }
        else if (strcmp(key, "ring_buffer_kb") == 0)
            p = parse_int(p, &cfg->ring_buffer_kb);
        else if (strcmp(key, "summary_interval") == 0)
            p = parse_int(p, &cfg->summary_interval);
        else if (strcmp(key, "rate_limit_per_comm") == 0) {
            int v = 0;
            p = parse_int(p, &v);
            cfg->rate_limit_per_comm = (uint32_t)v;
        }
        else if (strcmp(key, "forward") == 0)
            p = parse_str(p, cfg->forward_addr, sizeof(cfg->forward_addr));
        else if (strcmp(key, "forward_tls") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->forward_tls = v;
        }
        else if (strcmp(key, "forward_tls_noverify") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->forward_tls_noverify = v;
        }
        else if (strcmp(key, "targets") == 0) {
            /* Array of {addr, tls, tls_noverify} forwarding targets */
            p = skip_ws(p);
            if (*p == '[') {
                p++;
                while (*p && *p != ']') {
                    p = skip_ws(p);
                    if (*p != '{') { p++; continue; }
                    p++;
                    if (cfg->forward_target_count >= CFG_MAX_TARGETS) {
                        /* Skip the rest of this object */
                        while (*p && *p != '}') p++;
                        if (*p == '}') p++;
                    } else {
                        cfg_target_t *t = &cfg->forward_targets[cfg->forward_target_count];
                        while (*p && *p != '}') {
                            p = skip_ws(p);
                            if (*p != '"') { p++; continue; }
                            char fkey[32] = {};
                            p = parse_str(p, fkey, sizeof(fkey));
                            p = past_colon(p);
                            if      (strcmp(fkey, "addr") == 0)
                                p = parse_str(p, t->addr, sizeof(t->addr));
                            else if (strcmp(fkey, "tls") == 0) {
                                int v = 0; p = parse_bool(p, &v); t->tls = v;
                            }
                            else if (strcmp(fkey, "tls_noverify") == 0) {
                                int v = 0; p = parse_bool(p, &v); t->tls_noverify = v;
                            }
                            p = skip_ws(p);
                            if (*p == ',') p++;
                        }
                        if (*p == '}') p++;
                        if (t->addr[0])
                            cfg->forward_target_count++;
                    }
                    p = skip_ws(p);
                    if (*p == ',') p++;
                }
            }
        }
        else if (strcmp(key, "syslog") == 0) {
            int v = 0;
            p = parse_bool(p, &v);
            cfg->use_syslog = v;
        }
        else if (strcmp(key, "output_path") == 0)
            p = parse_str(p, cfg->output_path, sizeof(cfg->output_path));
        else if (strcmp(key, "rules") == 0)
            p = parse_str(p, cfg->rules_path, sizeof(cfg->rules_path));
        else if (strcmp(key, "output_fmt") == 0) {
            char v[16] = {};
            p = parse_str(p, v, sizeof(v));
            if      (strcmp(v, "json")   == 0) cfg->output_fmt = OUTPUT_JSON;
            else if (strcmp(v, "syslog") == 0) cfg->output_fmt = OUTPUT_SYSLOG;
            else if (strcmp(v, "cef")    == 0) cfg->output_fmt = OUTPUT_CEF;
            else                               cfg->output_fmt = OUTPUT_TEXT;
        }
        else if (strcmp(key, "pid_file") == 0)
            p = parse_str(p, cfg->pid_file, sizeof(cfg->pid_file));
        else if (strcmp(key, "follow_pid") == 0)
            p = parse_int(p, &cfg->follow_pid);
        else if (strcmp(key, "baseline") == 0)
            p = parse_str(p, cfg->baseline_path, sizeof(cfg->baseline_path));
        else if (strcmp(key, "baseline_out") == 0)
            p = parse_str(p, cfg->baseline_out, sizeof(cfg->baseline_out));
        else if (strcmp(key, "baseline_learn_secs") == 0)
            p = parse_int(p, &cfg->baseline_learn_secs);
        else if (strcmp(key, "baseline_merge_after") == 0)
            p = parse_int(p, &cfg->baseline_merge_after);
        else if (strcmp(key, "metrics_port") == 0)
            p = parse_int(p, &cfg->metrics_port);
        else if (strcmp(key, "event_types") == 0)
            parse_event_types(p, &cfg->filter.event_mask);
        else if (strcmp(key, "exclude_paths") == 0) {
            /* Reset first so an empty array clears the defaults */
            cfg->filter.exclude_count = 0;
            parse_exclude_paths(p, &cfg->filter);
        }
        else if (strcmp(key, "threat_intel") == 0)
            p = parse_str(p, cfg->threat_intel_path, sizeof(cfg->threat_intel_path));
        else if (strcmp(key, "fim_paths") == 0)
            parse_fim_paths(p, cfg);
        else if (strcmp(key, "dga_entropy_threshold") == 0)
            p = parse_double(p, &cfg->dga_entropy_threshold);
        else if (strcmp(key, "ldpreload_check") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->ldpreload_check = v;
        }
        else if (strcmp(key, "yara_rules_dir") == 0)
            p = parse_str(p, cfg->yara_rules_dir, sizeof(cfg->yara_rules_dir));
        else if (strcmp(key, "syscall_profile_interval") == 0)
            p = parse_int(p, &cfg->syscall_profile_interval);
        else if (strcmp(key, "baseline_cgroup_aware") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->baseline_cgroup_aware = v;
        }
        else if (strcmp(key, "response_kill") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->response_kill = v;
        }
        else if (strcmp(key, "tls_sni_enable") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->tls_sni_enable = v;
        }
        else if (strcmp(key, "rate_limit_per_pid") == 0) {
            int v = 0; p = parse_int(p, &v); cfg->rate_limit_per_pid = (uint32_t)v;
        }
        else if (strcmp(key, "canary_paths") == 0) {
            /* array of strings */
            p = skip_ws(p);
            if (*p == '[') {
                p++;
                while (*p && *p != ']') {
                    p = skip_ws(p);
                    if (*p == '"' && cfg->canary_path_count < CANARY_MAX_PATHS) {
                        p = parse_str(p, cfg->canary_paths[cfg->canary_path_count],
                                      sizeof(cfg->canary_paths[0]));
                        cfg->canary_path_count++;
                    } else {
                        while (*p && *p != ',' && *p != ']') p++;
                    }
                    p = skip_ws(p);
                    if (*p == ',') p++;
                }
                if (*p == ']') p++;
            }
        }
        else if (strcmp(key, "alert_dedup_secs") == 0)
            p = parse_int(p, &cfg->alert_dedup_secs);
        else if (strcmp(key, "beacon_cv_threshold") == 0)
            p = parse_double(p, &cfg->beacon_cv_threshold);
        else if (strcmp(key, "lsm_deny") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->lsm_deny = v;
        }
        else if (strcmp(key, "mitre_tags") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->mitre_tags = v;
        }
        else if (strcmp(key, "webhook_url") == 0)
            p = parse_str(p, cfg->webhook_url, sizeof(cfg->webhook_url));
        else if (strcmp(key, "exec_hash") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->exec_hash = v;
        }
        else if (strcmp(key, "vt_api_key") == 0)
            p = parse_str(p, cfg->vt_api_key, sizeof(cfg->vt_api_key));
        else if (strcmp(key, "otx_api_key") == 0)
            p = parse_str(p, cfg->otx_api_key, sizeof(cfg->otx_api_key));
        else if (strcmp(key, "response_isolate") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->response_isolate = v;
        }
        else if (strcmp(key, "store_path") == 0)
            p = parse_str(p, cfg->store_path, sizeof(cfg->store_path));
        else if (strcmp(key, "store_query_port") == 0)
            p = parse_int(p, &cfg->store_query_port);
        else if (strcmp(key, "container_enrich") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->container_enrich = v;
        }
        else if (strcmp(key, "compliance_framework") == 0) {
            char fw[32] = {};
            p = parse_str(p, fw, sizeof(fw));
            if      (strcmp(fw, "cis")     == 0) cfg->compliance_framework = COMPLIANCE_CIS_LINUX;
            else if (strcmp(fw, "pci-dss") == 0) cfg->compliance_framework = COMPLIANCE_PCI_DSS;
            else if (strcmp(fw, "nist")    == 0) cfg->compliance_framework = COMPLIANCE_NIST_CSF;
            else if (strcmp(fw, "soc2")    == 0) cfg->compliance_framework = COMPLIANCE_SOC2;
        }
        else if (strcmp(key, "compliance_report") == 0)
            p = parse_str(p, cfg->compliance_report, sizeof(cfg->compliance_report));
        else if (strcmp(key, "syscall_anom_interval") == 0)
            p = parse_int(p, &cfg->syscall_anom_interval);
        else if (strcmp(key, "tls_data_enable") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->tls_data_enable = v;
        }
        else if (strcmp(key, "mem_forensics") == 0) {
            int v = 0; p = parse_bool(p, &v); cfg->mem_forensics = v;
        }
        else if (key[0] != '\0') {
            /* Unknown key — warn so users catch typos in config files */
            fprintf(stderr, "argus: config: unknown key \"%s\" (ignored)\n", key);
        }

        /* advance past current value to next key */
        while (*p && *p != ',' && *p != '}') p++;
        if (*p == ',') p++;
    }

    free(buf);
    return 0;
}
