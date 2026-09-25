#ifndef __CONFIG_H
#define __CONFIG_H

#include <stdint.h>
#include "output.h"
#include "canary.h"
#include "compliance.h"

/*
 * Full runtime configuration for argus.
 * Populated from the config file first, then overridden by CLI flags.
 * filter_t holds the event-matching rules; the rest are operational settings.
 */
/* One entry in the "targets" forwarding array */
#define CFG_MAX_TARGETS 8
typedef struct {
    char addr[256];         /* "host:port" or "[ipv6]:port"        */
    int  tls;               /* 1 = TLS with cert verification      */
    int  tls_noverify;      /* 1 = TLS without cert verification   */
} cfg_target_t;

typedef struct {
    filter_t     filter;
    int          ring_buffer_kb;        /* ring buffer size; default 256           */
    int          summary_interval;      /* 0 = per-event output, N = N-second roll */
    uint32_t     rate_limit_per_comm;   /* 0 = disabled; N = max events/sec/comm   */
    int          use_syslog;            /* 1 = emit to syslog(LOG_DAEMON)          */
    output_fmt_t output_fmt;            /* OUTPUT_TEXT/JSON/SYSLOG/CEF from config */
    int          follow_pid;            /* 0 = off; N = trace PID + descendants    */
    char         output_path[256];      /* "" = stdout; else write events to file  */
    char         pid_file[256];         /* "" = off; else write PID to this path   */
    char         rules_path[256];       /* "" = no rules; else load rules JSON     */
    char         forward_addr[256];     /* "" = off; else "host:port" to forward   */
    int          forward_tls;           /* 1 = TLS with cert verification           */
    int          forward_tls_noverify;  /* 1 = TLS without cert verification        */
    cfg_target_t forward_targets[CFG_MAX_TARGETS]; /* additional targets array     */
    int          forward_target_count;
    char         baseline_path[256];    /* "" = off; else load profile for anomaly */
    char         baseline_out[256];     /* "" = off; else write learnt profile     */
    int          baseline_learn_secs;   /* 0 = detect; >0 = learn for N seconds   */
    int          baseline_merge_after;  /* 0 = off; N = auto-merge after N sights  */
    int          metrics_port;          /* 0 = off; N = Prometheus HTTP on port N  */

    /* ── Threat intelligence ─────────────────────────────────────────────── */
    char         threat_intel_path[256]; /* CIDR blocklist file path              */

    /* ── File integrity monitoring ──────────────────────────────────────── */
    char         fim_paths[16][256];   /* watched file paths                      */
    int          fim_path_count;

    /* ── DGA/entropy detection ───────────────────────────────────────────── */
    double       dga_entropy_threshold; /* 0 = disabled, typical: 3.5            */

    /* ── LD_PRELOAD detection ────────────────────────────────────────────── */
    int          ldpreload_check;      /* 1 = enabled (default), 0 = disabled     */

    /* ── YARA scanning ───────────────────────────────────────────────────── */
    char         yara_rules_dir[256];  /* dir containing .yar files               */

    /* ── Syscall frequency profiling ────────────────────────────────────── */
    int          syscall_profile_interval; /* seconds between dumps, 0=off        */

    /* ── Container-aware baseline ────────────────────────────────────────── */
    int          baseline_cgroup_aware; /* 1 = key by cgroup+comm, 0 = comm only */

    /* ── Active response ─────────────────────────────────────────────────── */
    int          response_kill;        /* global kill action enable (safety switch) */

    /* ── TLS SNI uprobe ──────────────────────────────────────────────────── */
    int          tls_sni_enable;       /* 1 = attach uprobe on SSL_write          */

    /* ── Per-PID rate limiting ───────────────────────────────────────────── */
    uint32_t     rate_limit_per_pid;   /* userspace copy for config               */

    /* ── Canary / honeypot file detection ───────────────────────────────── */
    char         canary_paths[CANARY_MAX_PATHS][256];
    int          canary_path_count;

    /* ── Alert deduplication ─────────────────────────────────────────────── */
    int          alert_dedup_secs;     /* 0 = disabled; N = suppress window       */

    /* ── C2 beaconing detection ──────────────────────────────────────────── */
    double       beacon_cv_threshold;  /* 0 = disabled; typical 0.15              */

    /* ── LSM BPF enforcement ─────────────────────────────────────────────── */
    int          lsm_deny;            /* 1 = enforce kernel_rules via LSM hooks  */

    /* ── MITRE ATT&CK tagging ────────────────────────────────────────────── */
    int          mitre_tags;          /* 1 = add mitre_id/name/tactic to JSON    */

    /* ── Webhook / SOAR integration ─────────────────────────────────────── */
    char         webhook_url[512];    /* "" = off; else POST alerts here         */

    /* ── File hash enrichment ────────────────────────────────────────────── */
    int          exec_hash;           /* 1 = SHA-256 every EXEC binary           */
    char         vt_api_key[64];      /* VirusTotal API key (empty = off)        */
    char         otx_api_key[64];     /* AlienVault OTX API key (empty = off)    */

    /* ── Network isolation ───────────────────────────────────────────────── */
    int          response_isolate;    /* 1 = enable iptables isolation action    */

    /* ── Persistent event store ─────────────────────────────────────────── */
    char         store_path[256];     /* "" = off; else SQLite DB path           */
    int          store_query_port;    /* 0 = off; N = HTTP query API port        */

    /* ── Container enrichment ───────────────────────────────────────────── */
    int          container_enrich;    /* 1 = resolve cgroup to container info    */

    /* ── Compliance reporting ────────────────────────────────────────────── */
    compliance_framework_t compliance_framework;
    char         compliance_report[256]; /* "" = off; else write report to path */

    /* ── Syscall anomaly detection ───────────────────────────────────────── */
    int          syscall_anom_interval; /* 0 = off; N = check every N seconds   */

    /* ── TLS data capture ────────────────────────────────────────────────── */
    int          tls_data_enable;     /* 1 = attach uprobe on SSL_read           */

    /* ── Memory forensics ────────────────────────────────────────────────── */
    int          mem_forensics;       /* 1 = snapshot anon mappings on MEMEXEC   */
} argus_cfg_t;

/* Fill cfg with safe defaults (no filters, 256KB ring buffer, no summary) */
void cfg_defaults(argus_cfg_t *cfg);

/*
 * Load a JSON config file into cfg.
 * Config file values are merged in — only keys present in the file are set.
 * CLI flags should be applied after this call to override file values.
 *
 * Returns:
 *   0   success
 *  -1   file not found (not an error — just use defaults)
 *  -2   file read / parse error (logged to stderr)
 */
int cfg_load(const char *path, argus_cfg_t *cfg);

#endif /* __CONFIG_H */
