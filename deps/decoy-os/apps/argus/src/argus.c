#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "argus.skel.h"
#include "argus.h"
#include "output.h"
#include "lineage.h"
#include "config.h"
#include "rules.h"
#include "forward.h"
#include "baseline.h"
#include "dns.h"
#include "seccomp.h"
#include "metrics.h"
#include "fim.h"
#include "ldpreload.h"
#include "threatintel.h"
#include "canary.h"
#include "dedup.h"
#include "hollow.h"
#include "beacon.h"
#include "seqdetect.h"
#include "yara_scan.h"
#include "mitre.h"
#include "webhook.h"
#include "exechash.h"
#include "isolate.h"
#include "memforensics.h"
#include "store.h"
#include "iocenrich.h"
#include "container.h"
#include "compliance.h"
#include "syscallanom.h"

static volatile int running       = 1;
static volatile int reload_config = 0;
static uint64_t     last_drops      = 0;
static uint64_t     g_total_drops   = 0;   /* lifetime drop count for hint  */
static int          g_forwarding  = 0;   /* set after forward_init succeeds */

/* ── DNS correlation cache ──────────────────────────────────────────────── */

#define DNS_CACHE_SIZE 512

struct dns_cache_entry {
    uint32_t pid;
    uint8_t  ip[16];
    int      family;
    char     name[128];
    uint64_t ts;         /* populated time (seconds since epoch) */
};

static struct dns_cache_entry g_dns_cache[DNS_CACHE_SIZE];
static int                    g_dns_cache_pos = 0;   /* circular write cursor */

static void dns_cache_insert(uint32_t pid, const uint8_t *ip, int family,
                              const char *name)
{
    struct dns_cache_entry *ent = &g_dns_cache[g_dns_cache_pos % DNS_CACHE_SIZE];
    ent->pid    = pid;
    ent->family = family;
    memcpy(ent->ip, ip, 16);
    strncpy(ent->name, name ? name : "", sizeof(ent->name) - 1);
    ent->name[sizeof(ent->name) - 1] = '\0';
    ent->ts     = (uint64_t)time(NULL);
    g_dns_cache_pos++;
}

/* Returns a cached name for the given IP, or NULL if not found.
 * Only considers entries less than 60 seconds old. */
static const char *dns_cache_lookup(const uint8_t *ip, int family)
{
    uint64_t now = (uint64_t)time(NULL);
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        struct dns_cache_entry *ent = &g_dns_cache[i];
        if (!ent->name[0])
            continue;
        if (ent->family != family)
            continue;
        if (now - ent->ts > 60)
            continue;
        int addrlen = (family == 2) ? 4 : 16;
        if (memcmp(ent->ip, ip, addrlen) == 0)
            return ent->name;
    }
    return NULL;
}

/* ── Shannon entropy (for DGA detection) ───────────────────────────────── */

static double dns_entropy(const char *s)
{
    if (!s || !s[0])
        return 0.0;

    /* Count frequency of each ASCII character */
    int freq[256] = {};
    int len = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        freq[(int)*p]++;
        len++;
    }
    if (len == 0)
        return 0.0;

    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0)
            continue;
        double p = (double)freq[i] / (double)len;
        /* H = -sum(p * log2(p)) = sum(p * log2(1/p)) */
        double lp = 0.0;
        /* Compute log2 via natural log */
        double v = p;
        /* ln(v) via simple series approximation for v in (0,1]:
         * use the identity ln(v) = -ln(1/v).  For accuracy use the
         * standard library log() which is always available in <math.h>.
         * We avoid <math.h> by using a compile-time log2 via the relation
         * log2(x) = log(x)/log(2).  Since we can't include math.h
         * without -lm, implement a fast integer-quality log2 sufficient
         * for entropy calculation.
         */
        /* Use __builtin_log which is available in GCC/Clang without -lm */
        lp = __builtin_log(1.0 / v) / 0.693147180559945; /* ln(2) */
        h += p * lp;
    }
    return h;
}

/*
 * Decode a DNS QNAME from the raw sendto payload stored in filename.
 * DNS wire format: 12-byte header, then labels.  Each label is a length byte
 * followed by that many characters.  Root label = 0x00.
 * Writes the decoded name into out[outsz].  Returns 0 on success, -1 on error.
 */
static int parse_dns_payload(const uint8_t *payload, uint32_t payload_len,
                              char *out, size_t outsz)
{
    if (payload_len < 13 || outsz < 2)
        return -1;

    const uint8_t *p   = payload + 12;   /* QNAME starts at offset 12 */
    const uint8_t *end = payload + payload_len;
    size_t oi = 0;

    while (p < end) {
        uint8_t label_len = *p++;
        if (label_len == 0)
            break;                        /* root label — end of name */
        if (label_len > 63 || p + label_len > end)
            return -1;                    /* compression ptr or malformed */
        if (oi > 0 && oi < outsz - 1)
            out[oi++] = '.';
        for (uint8_t j = 0; j < label_len && oi < outsz - 1; j++)
            out[oi++] = (char)*p++;
    }
    out[oi < outsz ? oi : outsz - 1] = '\0';
    return (oi > 0) ? 0 : -1;
}

static void dga_check(const event_t *e, const argus_cfg_t *cfg)
{
    if (!cfg || cfg->dga_entropy_threshold <= 0.0)
        return;
    /* Use just the hostname part (before first dot) */
    char host[128] = {};
    strncpy(host, e->filename, sizeof(host) - 1);
    char *dot = strchr(host, '.');
    if (dot) *dot = '\0';
    double h = dns_entropy(host);
    if (h > cfg->dga_entropy_threshold)
        fprintf(stderr,
                "[DGA] pid=%d comm=%s query=%s entropy=%.2f (threshold=%.2f)\n",
                e->pid, e->comm, e->filename, h, cfg->dga_entropy_threshold);
}

static void sig_handler(int sig)    { (void)sig; running = 0; }
static void sighup_handler(int sig) { (void)sig; reload_config = 1; }

/* Pointer to current config — set in main() before the event loop starts.
 * Used by handle_event() for DGA threshold and ldpreload checks. */
static const argus_cfg_t *g_cfg = NULL;

/* ── drop accounting ────────────────────────────────────────────────────── */

static uint64_t read_drop_delta(int map_fd)
{
    uint32_t key   = 0;
    uint64_t drops = 0;
    if (bpf_map_lookup_elem(map_fd, &key, &drops))
        return 0;
    uint64_t delta = drops > last_drops ? drops - last_drops : 0;
    if (delta)
        last_drops = drops;
    return delta;
}

/* ── privilege drop ─────────────────────────────────────────────────────── */
/*
 * Called after all BPF programs are attached and the ring buffer fd is open.
 * Drops from root to 'nobody' (uid 65534) so the event loop runs with
 * minimal privilege. All open file descriptors remain valid after setuid.
 */
static void drop_privileges(void)
{
    uid_t uid = 65534;
    gid_t gid = 65534;

    struct passwd *pw = getpwnam("nobody");
    if (pw) {
        uid = pw->pw_uid;
        gid = pw->pw_gid;
    }

    if (setgroups(0, NULL) < 0 ||
        setgid(gid)         < 0 ||
        setuid(uid)         < 0) {
        perror("warning: could not drop privileges");
        /* non-fatal — continue as root rather than abort */
    }
}

/* ── CLI helpers ────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  --config          <path>       Config file (default: ~/.config/argus/config.json)\n"
        "  --pid             <pid>        Only trace this PID (kernel-enforced)\n"
        "  --follow          <pid>        Trace PID and all descendant processes\n"
        "  --comm            <name>       Only trace this process name (kernel-enforced)\n"
        "  --path            <str>        Only show events whose path contains <str>\n"
        "  --exclude         <pfx>        Exclude file events whose path starts with <pfx>\n"
        "  --events          <list>       Comma-separated types: EXEC,OPEN,EXIT,CONNECT,\n"
        "                                   UNLINK,RENAME,CHMOD,BIND,PTRACE\n"
        "  --ringbuf         <kb>         Ring buffer size in KB (default: 256)\n"
        "  --summary         <secs>       Rolling summary every N seconds\n"
        "  --rate-limit      <n>          Drop events after N per second per comm (0=off)\n"
        "  --output          <path>       Write events to file instead of stdout\n"
        "  --syslog                       Emit events to syslog(LOG_DAEMON)\n"
        "  --rules           <path>       Load alert rules from JSON file\n"
        "  --forward         <host:port>  Stream JSON events to remote host over TCP\n"
        "  --forward-tls                  Enable TLS for --forward (verify server cert)\n"
        "  --forward-tls-noverify         Enable TLS for --forward (skip cert verify)\n"
        "  --output-fmt      <fmt>        Output format: text (default), json, syslog, cef\n"
        "  --pid-file        <path>       Write daemon PID to file (removed on exit)\n"
        "  --baseline        <path>       Detect anomalies using learnt profile\n"
        "  --baseline-learn  <secs>       Learn a baseline for N seconds\n"
        "  --baseline-out    <path>       Write learnt baseline profile to file\n"
        "  --baseline-merge-after <n>    Auto-merge anomaly into profile after N sightings\n"
        "  --metrics-port    <port>       Expose Prometheus metrics on HTTP port (default off)\n"
        "  --no-drop-privs               Stay root after attach (not recommended)\n"
        "  --json                         Newline-delimited JSON output\n"
        "  --config-check                 Validate config file(s) and print settings, then exit\n"
        "  --version                      Print version and exit\n"
        "  --help                         Show this message\n"
        "\n"
        "Enterprise / detection options:\n"
        "  --canary          <path>       Honeypot file to monitor (repeat for multiple)\n"
        "  --alert-dedup     <secs>       Suppress duplicate alerts within N seconds\n"
        "  --beacon-cv       <0.0-1.0>   C2 beaconing detection CV threshold (e.g. 0.15)\n"
        "  --lsm-deny                     Enforce kernel_rules via BPF LSM hooks\n"
        "  --yara-rules      <dir>        Directory of .yar rule files for in-process scanning\n"
        "  --mitre-tags                   Add MITRE ATT&CK technique IDs to JSON output\n"
        "  --webhook         <url>        POST JSON alerts to this URL (SOAR integration)\n"
        "  --exec-hash                    Compute SHA-256 of every executed binary\n"
        "  --vt-api-key      <key>        VirusTotal API key for hash/IP/domain enrichment\n"
        "  --otx-api-key     <key>        AlienVault OTX API key for IOC enrichment\n"
        "  --response-isolate             Block source IPs via iptables on rule match\n"
        "  --store-path      <path>       SQLite3 DB path for persistent event store\n"
        "  --store-query-port <port>      HTTP query API port for the event store\n"
        "  --container-enrich             Resolve cgroup to container/pod name (Docker/K8s)\n"
        "  --compliance      <framework>  Compliance framework: cis, pci-dss, nist, soc2\n"
        "  --compliance-report <path>     Write HTML compliance report to path on exit\n"
        "  --syscall-anom    <secs>       Check syscall frequency anomalies every N seconds\n"
        "  --tls-data                     Capture decrypted TLS data via SSL_read uprobe\n"
        "  --mem-forensics                Snapshot anonymous executable mappings on exec\n",
        prog);
}

static int parse_event_list(const char *s)
{
    int mask = 0;
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *tok = strtok(buf, ",");
    while (tok) {
        while (*tok == ' ') tok++;
        if      (strcmp(tok, "EXEC")    == 0) mask |= TRACE_EXEC;
        else if (strcmp(tok, "OPEN")    == 0) mask |= TRACE_OPEN;
        else if (strcmp(tok, "EXIT")    == 0) mask |= TRACE_EXIT;
        else if (strcmp(tok, "CONNECT") == 0) mask |= TRACE_CONNECT;
        else if (strcmp(tok, "UNLINK")  == 0) mask |= TRACE_UNLINK;
        else if (strcmp(tok, "RENAME")  == 0) mask |= TRACE_RENAME;
        else if (strcmp(tok, "CHMOD")   == 0) mask |= TRACE_CHMOD;
        else if (strcmp(tok, "BIND")    == 0) mask |= TRACE_BIND;
        else if (strcmp(tok, "PTRACE")  == 0) mask |= TRACE_PTRACE;
        tok = strtok(NULL, ",");
    }
    return mask;
}

/* ── BPF setup ──────────────────────────────────────────────────────────── */

static int bpf_lsm_supported(void);  /* forward declaration */

static void setup_bpf_filters(struct argus_bpf *skel, const filter_t *f,
                               uint32_t rate_limit_per_comm,
                               uint32_t rate_limit_per_pid,
                               int follow_pid, int lsm_deny)
{
    argus_config_t cfg = {};
    uint32_t zero = 0;

    if (f->pid != 0) {
        uint32_t pid = (uint32_t)f->pid;
        uint8_t  val = 1;
        bpf_map_update_elem(bpf_map__fd(skel->maps.filter_pids),
                            &pid, &val, BPF_ANY);
        cfg.filter_pid_active = 1;
    }
    if (f->comm[0] != '\0') {
        char key[16] = {};
        strncpy(key, f->comm, sizeof(key) - 1);
        uint8_t val = 1;
        bpf_map_update_elem(bpf_map__fd(skel->maps.filter_comms),
                            key, &val, BPF_ANY);
        cfg.filter_comm_active = 1;
    }
    if (follow_pid > 0) {
        uint32_t pid = (uint32_t)follow_pid;
        uint8_t  val = 1;
        bpf_map_update_elem(bpf_map__fd(skel->maps.follow_pids),
                            &pid, &val, BPF_ANY);
        cfg.filter_follow_active = 1;
    }
    cfg.rate_limit_per_comm = rate_limit_per_comm;
    cfg.rate_limit_per_pid  = rate_limit_per_pid;
    cfg.lsm_deny_active     = (uint8_t)(lsm_deny && bpf_lsm_supported() ? 1 : 0);
    bpf_map_update_elem(bpf_map__fd(skel->maps.config_map),
                        &zero, &cfg, BPF_ANY);
}

/* Returns 1 if the running kernel has BPF LSM support. */
static int bpf_lsm_supported(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) return 0;
    char buf[256] = {};
    fgets(buf, sizeof(buf), f);
    fclose(f);
    return strstr(buf, "bpf") != NULL;
}

static void configure_programs(struct argus_bpf *skel, int event_mask,
                               int follow_pid, int lsm_deny,
                               int tls_data_enable, int syscall_anom_interval)
{
    /* 0 means trace-all (same convention as print_header / event_matches) */
    if (!event_mask) event_mask = TRACE_ALL;

    /* Fork handler is only useful when --follow is active */
    if (!follow_pid)
        bpf_program__set_autoload(skel->progs.handle_process_fork, false);
    if (!(event_mask & TRACE_EXEC)) {
        bpf_program__set_autoload(skel->progs.handle_execve_enter,    false);
        bpf_program__set_autoload(skel->progs.handle_execve_exit,     false);
        bpf_program__set_autoload(skel->progs.handle_execveat_enter,  false);
        bpf_program__set_autoload(skel->progs.handle_execveat_exit,   false);
    }
    if (!(event_mask & TRACE_OPEN)) {
        bpf_program__set_autoload(skel->progs.handle_openat_enter,  false);
        bpf_program__set_autoload(skel->progs.handle_openat_exit,   false);
    }
    if (!(event_mask & TRACE_EXIT))
        bpf_program__set_autoload(skel->progs.handle_process_exit,  false);
    if (!(event_mask & TRACE_CONNECT)) {
        bpf_program__set_autoload(skel->progs.handle_connect_enter, false);
        bpf_program__set_autoload(skel->progs.handle_connect_exit,  false);
    }
    if (!(event_mask & TRACE_UNLINK)) {
        bpf_program__set_autoload(skel->progs.handle_unlinkat_enter, false);
        bpf_program__set_autoload(skel->progs.handle_unlinkat_exit,  false);
    }
    if (!(event_mask & TRACE_RENAME)) {
        bpf_program__set_autoload(skel->progs.handle_renameat2_enter, false);
        bpf_program__set_autoload(skel->progs.handle_renameat2_exit,  false);
    }
    if (!(event_mask & TRACE_CHMOD)) {
        bpf_program__set_autoload(skel->progs.handle_fchmodat_enter, false);
        bpf_program__set_autoload(skel->progs.handle_fchmodat_exit,  false);
    }
    if (!(event_mask & TRACE_BIND)) {
        bpf_program__set_autoload(skel->progs.handle_bind_enter, false);
        bpf_program__set_autoload(skel->progs.handle_bind_exit,  false);
    }
    if (!(event_mask & TRACE_PTRACE)) {
        bpf_program__set_autoload(skel->progs.handle_ptrace_enter, false);
        bpf_program__set_autoload(skel->progs.handle_ptrace_exit,  false);
    }
    if (!(event_mask & (TRACE_DNS | TRACE_SEND))) {
        bpf_program__set_autoload(skel->progs.handle_sendto_enter, false);
        bpf_program__set_autoload(skel->progs.handle_sendto_exit,  false);
    }
    if (!(event_mask & TRACE_WRITE_CLOSE))
        bpf_program__set_autoload(skel->progs.handle_close_enter, false);

    /* LSM enforcement programs — only load when explicitly requested AND
     * the kernel actually supports BPF LSM (5.7+, CONFIG_BPF_LSM=y). */
    if (!lsm_deny || !bpf_lsm_supported()) {
        bpf_program__set_autoload(skel->progs.lsm_file_open,      false);
        bpf_program__set_autoload(skel->progs.lsm_bprm_check,     false);
        bpf_program__set_autoload(skel->progs.lsm_socket_connect,  false);
    }

    /* TLS data capture (SSL_read uprobe) — only when --tls-data is set */
    if (!tls_data_enable) {
        bpf_program__set_autoload(skel->progs.uprobe_ssl_read_enter,   false);
        bpf_program__set_autoload(skel->progs.uretprobe_ssl_read_exit, false);
    }

    /* Syscall frequency histogram — only when --syscall-anom is set */
    if (!syscall_anom_interval)
        bpf_program__set_autoload(skel->progs.handle_sys_enter, false);
}

/* ── event handler ──────────────────────────────────────────────────────── */

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx; (void)data_sz;
    const event_t *e = data;

    /* Symbol resolution: if filename looks like memfd or is empty, read /proc */
    event_t resolved_event;
    const event_t *ev = e;
    if (e->type == EVENT_EXEC &&
        (e->filename[0] == '\0' || strncmp(e->filename, "memfd:", 6) == 0 ||
         strstr(e->filename, "(deleted)") != NULL)) {
        resolved_event = *e;
        char exe_path[64];
        char link_target[128] = {};
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", e->pid);
        ssize_t n = readlink(exe_path, link_target, sizeof(link_target) - 1);
        if (n > 0) {
            link_target[n] = '\0';
            strncpy(resolved_event.filename, link_target,
                    sizeof(resolved_event.filename) - 1);
            ev = &resolved_event;
        }
    }

    /* ── DNS: decode query name from raw payload (BPF sends raw bytes) ── */
    event_t dns_decoded;
    if (ev->type == EVENT_DNS && ev->filename[0] != '\0' &&
        (unsigned char)ev->filename[0] <= 63) {
        /* filename holds raw DNS payload bytes — decode the QNAME */
        dns_decoded = *ev;
        if (parse_dns_payload((const uint8_t *)ev->filename,
                              (uint32_t)ev->mode > 0 ? (uint32_t)ev->mode : 128,
                              dns_decoded.filename,
                              sizeof(dns_decoded.filename)) != 0) {
            /* Decoding failed — leave filename as-is (may be pre-decoded) */
        }
        ev = &dns_decoded;
    }

    /* ── DNS correlation cache update ────────────────────────────────── */
    if (ev->type == EVENT_DNS) {
        dns_cache_insert((uint32_t)ev->pid, ev->daddr, ev->family,
                         ev->filename);
        if (g_cfg)
            dga_check(ev, g_cfg);
    }

    /* ── DNS→connect correlation (synthetic NET_CORR event) ────────── */
    if (ev->type == EVENT_CONNECT) {
        const char *dname = dns_cache_lookup(ev->daddr, ev->family);
        if (dname && dname[0]) {
            event_t corr = *ev;
            corr.type = EVENT_NET_CORR;
            strncpy(corr.dns_name, dname, sizeof(corr.dns_name) - 1);
            corr.dns_name[sizeof(corr.dns_name) - 1] = '\0';
            /* Emit the correlation event through normal paths */
            if (event_matches(&corr)) {
                print_event(&corr);
                if (g_forwarding)
                    forward_event(&corr);
            }
            rules_check(&corr);
        }
    }

    /* ── LD_PRELOAD env check on exec ────────────────────────────────── */
    if (ev->type == EVENT_EXEC)
        ldpreload_check(ev);

    /* ── File hash enrichment on exec ────────────────────────────────── */
    if (ev->type == EVENT_EXEC && g_cfg && g_cfg->exec_hash)
        exechash_check(ev);

    /* ── Memory forensics on memfd exec / suspicious exec ───────────── */
    if (g_cfg && g_cfg->mem_forensics)
        memforensics_check(ev);

    /* ── IOC enrichment on CONNECT / DNS / EXEC ─────────────────────── */
    if (ev->type == EVENT_CONNECT || ev->type == EVENT_DNS ||
        ev->type == EVENT_EXEC)
        iocenrich_check(ev);

    /* ── FIM check on file close-after-write ──────────────────────────── */
    if (ev->type == EVENT_WRITE_CLOSE)
        fim_check(ev);

    /* ── Canary / honeypot file detection ────────────────────────────── */
    canary_check(ev);

    /* ── Process hollowing detection ─────────────────────────────────── */
    hollow_check(ev);

    /* ── C2 beaconing detection ──────────────────────────────────────── */
    beacon_check(ev);

    /* ── Syscall sequence / attack-chain detection ───────────────────── */
    seqdetect_check(ev);

    /* ── YARA scanning on exec and file writes ───────────────────────── */
    yara_scan_event(ev);

    /* ── KMOD_LOAD: resolve fd→filename via /proc ─────────────────────── */
    if (ev->type == EVENT_KMOD_LOAD && ev->target_pid > 0) {
        event_t *mut_ev = (event_t *)ev;  /* safe: resolved_event or e copy */
        if (ev == e) {
            /* make a mutable copy */
            resolved_event = *e;
            mut_ev = &resolved_event;
            ev = mut_ev;
        }
        char fdpath[64];
        snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/%d",
                 ev->pid, ev->target_pid);
        char link_target[256] = {};
        ssize_t n = readlink(fdpath, link_target, sizeof(link_target) - 1);
        if (n > 0) {
            link_target[n] = '\0';
            strncpy(mut_ev->filename, link_target,
                    sizeof(mut_ev->filename) - 1);
            /* Warn if module loaded from outside /lib/modules */
            if (strncmp(link_target, "/lib/modules", 12) != 0)
                fprintf(stderr,
                        "[KMOD] pid=%d comm=%s loaded module from unusual path: %s\n",
                        ev->pid, ev->comm, link_target);
        }
    }

    if (event_matches(ev)) {
        print_event(ev);
        if (g_forwarding)
            forward_event(ev);
    }

    metrics_event(ev);

    /* Run alert rules and baseline check regardless of output filter */
    rules_check(ev);
    if (baseline_learning())
        baseline_learn(ev);
    else
        baseline_check(ev);

    /* ── Persistent event store ──────────────────────────────────────── */
    store_event(ev);

    /* ── Compliance event recording ──────────────────────────────────── */
    compliance_record_event(ev);

    /* Update lineage regardless of filter so the tree stays consistent */
    if (ev->type == EVENT_EXEC)
        lineage_update(ev->pid, ev->ppid, ev->comm);
    else if (ev->type == EVENT_EXIT)
        lineage_remove(ev->pid);

    return 0;
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    argus_cfg_t  cfg;
    output_fmt_t fmt          = OUTPUT_TEXT;
    int          no_drop_privs  = 0;
    int          forwarding     = 0;
    FILE        *output_file    = NULL;

    cfg_defaults(&cfg);

    /* Load config files — CLI flags override below */
    if (cfg_load("/etc/argus/config.json", &cfg) == -2)
        fprintf(stderr, "warning: error reading /etc/argus/config.json\n");
    {
        const char *home = getenv("HOME");
        if (home) {
            char path[256];
            snprintf(path, sizeof(path), "%s/.config/argus/config.json", home);
            if (cfg_load(path, &cfg) == -2)
                fprintf(stderr, "warning: error reading %s\n", path);
        }
    }

    static const struct option long_opts[] = {
        {"config",          required_argument, 0, 'C'},
        {"pid",             required_argument, 0, 'p'},
        {"follow",          required_argument, 0, 'F'},
        {"comm",            required_argument, 0, 'c'},
        {"path",            required_argument, 0, 'P'},
        {"exclude",         required_argument, 0, 'x'},
        {"events",          required_argument, 0, 'e'},
        {"ringbuf",         required_argument, 0, 'r'},
        {"summary",         required_argument, 0, 's'},
        {"rate-limit",      required_argument, 0, 'R'},
        {"output",          required_argument, 0, 'o'},
        {"syslog",          no_argument,       0, 'S'},
        {"rules",           required_argument, 0, 'a'},
        {"forward",             required_argument, 0, 'f'},
        {"forward-tls",         no_argument,       0, 't'},
        {"forward-tls-noverify",no_argument,       0, 'T'},
        {"output-fmt",      required_argument, 0, 'O'},
        {"pid-file",        required_argument, 0, 'D'},
        {"baseline",              required_argument, 0, 'b'},
        {"baseline-learn",        required_argument, 0, 'L'},
        {"baseline-out",          required_argument, 0, 'B'},
        {"baseline-merge-after",  required_argument, 0, 'M'},
        {"metrics-port",          required_argument, 0, 'm'},
        {"no-drop-privs",         no_argument,       0, 'n'},
        {"json",            no_argument,       0, 'j'},
        {"config-check",    no_argument,       0, 'K'},
        {"version",         no_argument,       0, 'V'},
        {"help",            no_argument,       0, 'h'},
        /* ── new detection options ── */
        {"canary",          required_argument, 0, 1000},
        {"alert-dedup",     required_argument, 0, 1001},
        {"beacon-cv",       required_argument, 0, 1002},
        {"lsm-deny",        no_argument,       0, 1003},
        {"yara-rules",      required_argument, 0, 1004},
        /* ── enterprise feature options ── */
        {"mitre-tags",      no_argument,       0, 1010},
        {"webhook",         required_argument, 0, 1011},
        {"exec-hash",       no_argument,       0, 1012},
        {"vt-api-key",      required_argument, 0, 1013},
        {"otx-api-key",     required_argument, 0, 1014},
        {"response-isolate",no_argument,       0, 1015},
        {"store-path",      required_argument, 0, 1016},
        {"store-query-port",required_argument, 0, 1017},
        {"container-enrich",no_argument,       0, 1018},
        {"compliance",      required_argument, 0, 1019},
        {"compliance-report",required_argument,0, 1020},
        {"syscall-anom",    required_argument, 0, 1021},
        {"tls-data",        no_argument,       0, 1022},
        {"mem-forensics",   no_argument,       0, 1023},
        {0, 0, 0, 0}
    };

    int config_check = 0;
    int fmt_set      = 0;   /* 1 = --json / --syslog / --output-fmt given explicitly */
    int opt;
    while ((opt = getopt_long(argc, argv, "C:p:F:c:P:x:e:r:s:R:o:Sa:f:tTO:D:b:L:B:M:m:njKVh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'C':
            if (cfg_load(optarg, &cfg) != 0)
                fprintf(stderr, "warning: could not load %s\n", optarg);
            break;
        case 'p': cfg.filter.pid = atoi(optarg);                                        break;
        case 'F': cfg.follow_pid = atoi(optarg);                                        break;
        case 'c': strncpy(cfg.filter.comm, optarg, sizeof(cfg.filter.comm)-1);          break;
        case 'P': strncpy(cfg.filter.path, optarg, sizeof(cfg.filter.path)-1);          break;
        case 'x':
            if (cfg.filter.exclude_count < 8)
                strncpy(cfg.filter.excludes[cfg.filter.exclude_count++],
                        optarg, 127);
            else
                fprintf(stderr, "warning: --exclude limit (8) reached, "
                                "ignoring '%s'\n", optarg);
            break;
        case 'e': cfg.filter.event_mask = parse_event_list(optarg);                     break;
        case 'r': {
            int kb = atoi(optarg);
            if (kb < 4 || kb > 65536) {
                fprintf(stderr, "error: --ringbuf must be between 4 and 65536 KB\n");
                return 1;
            }
            cfg.ring_buffer_kb = kb;
            break;
        }
        case 's': cfg.summary_interval      = atoi(optarg);                             break;
        case 'R': cfg.rate_limit_per_comm   = (uint32_t)atoi(optarg);                  break;
        case 'o': strncpy(cfg.output_path,   optarg, sizeof(cfg.output_path)-1);        break;
        case 'S': cfg.use_syslog            = 1;                                         break;
        case 'a': strncpy(cfg.rules_path,    optarg, sizeof(cfg.rules_path)-1);         break;
        case 'f': strncpy(cfg.forward_addr,  optarg, sizeof(cfg.forward_addr)-1);       break;
        case 't': cfg.forward_tls          = 1;                                          break;
        case 'T': cfg.forward_tls_noverify = 1;                                          break;
        case 'O':
            if      (strcmp(optarg, "json")   == 0) { fmt = OUTPUT_JSON;   fmt_set = 1; }
            else if (strcmp(optarg, "syslog") == 0) { cfg.use_syslog = 1; fmt_set = 1; }
            else if (strcmp(optarg, "cef")    == 0) { fmt = OUTPUT_CEF;   fmt_set = 1; }
            else if (strcmp(optarg, "text")   == 0) { fmt = OUTPUT_TEXT;  fmt_set = 1; }
            else {
                fprintf(stderr, "error: unknown --output-fmt '%s' "
                                "(valid: text, json, syslog, cef)\n", optarg);
                return 1;
            }
            break;
        case 'D': strncpy(cfg.pid_file, optarg, sizeof(cfg.pid_file)-1);                break;
        case 'b': strncpy(cfg.baseline_path, optarg, sizeof(cfg.baseline_path)-1);      break;
        case 'L': cfg.baseline_learn_secs   = atoi(optarg);                             break;
        case 'B': strncpy(cfg.baseline_out,  optarg, sizeof(cfg.baseline_out)-1);        break;
        case 'M': cfg.baseline_merge_after  = atoi(optarg);                              break;
        case 'm': cfg.metrics_port          = atoi(optarg);                              break;
        case 'n': no_drop_privs             = 1;                                         break;
        case 'j': fmt = OUTPUT_JSON; fmt_set = 1;                                        break;
        case 'K': config_check              = 1;                                         break;
        case 'V': printf("argus %s\n", ARGUS_VERSION); return 0;
        case 'h': usage(argv[0]); return 0;
        case 1000: /* --canary */
            if (cfg.canary_path_count < CANARY_MAX_PATHS)
                strncpy(cfg.canary_paths[cfg.canary_path_count++],
                        optarg, 255);
            break;
        case 1001: /* --alert-dedup */
            cfg.alert_dedup_secs = atoi(optarg);
            break;
        case 1002: /* --beacon-cv */
            cfg.beacon_cv_threshold = atof(optarg);
            break;
        case 1003: /* --lsm-deny */
            cfg.lsm_deny = 1;
            break;
        case 1004: /* --yara-rules */
            strncpy(cfg.yara_rules_dir, optarg, sizeof(cfg.yara_rules_dir) - 1);
            break;
        case 1010: cfg.mitre_tags         = 1;                                                       break;
        case 1011: strncpy(cfg.webhook_url, optarg, sizeof(cfg.webhook_url) - 1);                   break;
        case 1012: cfg.exec_hash          = 1;                                                       break;
        case 1013: strncpy(cfg.vt_api_key,  optarg, sizeof(cfg.vt_api_key)  - 1);                  break;
        case 1014: strncpy(cfg.otx_api_key, optarg, sizeof(cfg.otx_api_key) - 1);                  break;
        case 1015: cfg.response_isolate   = 1;                                                       break;
        case 1016: strncpy(cfg.store_path, optarg, sizeof(cfg.store_path)   - 1);                   break;
        case 1017: cfg.store_query_port   = atoi(optarg);                                            break;
        case 1018: cfg.container_enrich   = 1;                                                       break;
        case 1019:
            if      (strcmp(optarg, "cis")     == 0) cfg.compliance_framework = COMPLIANCE_CIS_LINUX;
            else if (strcmp(optarg, "pci-dss") == 0) cfg.compliance_framework = COMPLIANCE_PCI_DSS;
            else if (strcmp(optarg, "nist")    == 0) cfg.compliance_framework = COMPLIANCE_NIST_CSF;
            else if (strcmp(optarg, "soc2")    == 0) cfg.compliance_framework = COMPLIANCE_SOC2;
            else { fprintf(stderr, "error: unknown --compliance framework '%s' (cis,pci-dss,nist,soc2)\n", optarg); return 1; }
            break;
        case 1020: strncpy(cfg.compliance_report, optarg, sizeof(cfg.compliance_report) - 1);       break;
        case 1021: cfg.syscall_anom_interval = atoi(optarg);                                         break;
        case 1022: cfg.tls_data_enable     = 1;                                                      break;
        case 1023: cfg.mem_forensics       = 1;                                                      break;
        default:  usage(argv[0]); return 1;
        }
    }

    /* Apply output_fmt from config file when no explicit CLI flag was given */
    if (!fmt_set && cfg.output_fmt != OUTPUT_TEXT) {
        fmt = cfg.output_fmt;
        if (fmt == OUTPUT_SYSLOG)
            cfg.use_syslog = 1;
    }

    /* --syslog overrides --json / --cef / --output */
    if (cfg.use_syslog)
        fmt = OUTPUT_SYSLOG;

    if (config_check) {
        static const char *type_names[] = {
            "EXEC","OPEN","EXIT","CONNECT",
            "UNLINK","RENAME","CHMOD","BIND","PTRACE"
        };
        printf("argus %s — active configuration\n\n", ARGUS_VERSION);
        printf("  ring_buffer_kb      : %d\n",  cfg.ring_buffer_kb);
        printf("  summary_interval    : %d\n",  cfg.summary_interval);
        printf("  rate_limit_per_comm : %u\n",  cfg.rate_limit_per_comm);
        printf("  output_path         : %s\n",  cfg.output_path[0]  ? cfg.output_path  : "(stdout)");
        printf("  syslog              : %s\n",  cfg.use_syslog      ? "yes"            : "no");
        printf("  rules               : %s\n",  cfg.rules_path[0]   ? cfg.rules_path   : "(none)");
        printf("  output_fmt          : %s\n",
               fmt == OUTPUT_JSON   ? "json"   :
               fmt == OUTPUT_SYSLOG ? "syslog" :
               fmt == OUTPUT_CEF    ? "cef"    : "text");
        printf("  pid_file            : %s\n",  cfg.pid_file[0] ? cfg.pid_file : "(none)");
        printf("  forward             : %s\n",  cfg.forward_addr[0] ? cfg.forward_addr : "(off)");
        if (cfg.forward_addr[0]) {
            const char *tls_mode = cfg.forward_tls_noverify ? "tls-noverify"
                                 : cfg.forward_tls          ? "tls"
                                 : "plain";
            printf("  forward_tls         : %s\n", tls_mode);
        }
        if (cfg.forward_target_count > 0) {
            printf("  targets             : %d additional target(s)\n",
                   cfg.forward_target_count);
            for (int i = 0; i < cfg.forward_target_count; i++) {
                const char *tm = cfg.forward_targets[i].tls_noverify ? "tls-noverify"
                               : cfg.forward_targets[i].tls          ? "tls" : "plain";
                printf("    [%d] %s (%s)\n", i, cfg.forward_targets[i].addr, tm);
            }
        }
        printf("  follow_pid          : %d\n",  cfg.follow_pid);
        printf("  baseline            : %s\n",  cfg.baseline_path[0]     ? cfg.baseline_path     : "(off)");
        printf("  baseline_learn_secs : %d\n",  cfg.baseline_learn_secs);
        printf("  baseline_out        : %s\n",  cfg.baseline_out[0]      ? cfg.baseline_out      : "(none)");
        printf("  filter.pid          : %d\n",  cfg.filter.pid);
        printf("  filter.comm         : %s\n",  cfg.filter.comm[0] ? cfg.filter.comm : "(none)");
        printf("  filter.path         : %s\n",  cfg.filter.path[0] ? cfg.filter.path : "(none)");
        printf("  filter.event_mask   : ");
        int any = 0;
        for (int i = 0; i < EVENT_TYPE_MAX; i++)
            if (cfg.filter.event_mask & (1 << i)) {
                printf("%s%s", any ? "," : "", type_names[i]);
                any = 1;
            }
        if (!any) printf("ALL");
        printf("\n");
        printf("  exclude_paths     :");
        if (cfg.filter.exclude_count == 0) printf(" (none)");
        for (int i = 0; i < cfg.filter.exclude_count; i++)
            printf(" %s", cfg.filter.excludes[i]);
        printf("\n");
        return 0;
    }

    if (cfg.filter.event_mask == 0)
        cfg.filter.event_mask = TRACE_ALL;

    /* Open output file before dropping privileges */
    if (!cfg.use_syslog && cfg.output_path[0]) {
        output_file = fopen(cfg.output_path, "a");
        if (!output_file) {
            perror("error: could not open output file");
            return 1;
        }
    }

    /* Write PID file before privilege drop */
    if (cfg.pid_file[0]) {
        FILE *pf = fopen(cfg.pid_file, "w");
        if (pf) { fprintf(pf, "%d\n", (int)getpid()); fclose(pf); }
        else      perror("warning: could not write pid-file");
    }

    output_init(fmt, &cfg.filter);
    if (output_file)
        output_set_file(output_file);
    if (cfg.summary_interval > 0)
        output_set_summary(cfg.summary_interval);

    /* Initialise TCP forwarding (before privilege drop — needs getaddrinfo) */
    if (cfg.forward_addr[0]) {
        char fwd_host[256] = {};
        int  fwd_port = 0;
        if (forward_parse_addr(cfg.forward_addr, fwd_host, sizeof(fwd_host),
                               &fwd_port) != 0) {
            fprintf(stderr,
                    "error: --forward: invalid address '%s' "
                    "(expected host:port or [ipv6]:port)\n",
                    cfg.forward_addr);
            return 1;
        }
        int fwd_flags = 0;
        if (cfg.forward_tls_noverify)
            fwd_flags = FORWARD_FLAG_TLS_NOVERIFY;
        else if (cfg.forward_tls)
            fwd_flags = FORWARD_FLAG_TLS;
        if (forward_add(fwd_host, fwd_port, fwd_flags) == 0) {
            forwarding    = 1;
            g_forwarding  = 1;
        }
    }

    /* Additional targets from "targets" array in config file */
    for (int i = 0; i < cfg.forward_target_count; i++) {
        char fwd_host[256] = {};
        int  fwd_port = 0;
        if (forward_parse_addr(cfg.forward_targets[i].addr, fwd_host,
                               sizeof(fwd_host), &fwd_port) != 0) {
            fprintf(stderr, "warning: targets[%d]: invalid address '%s'\n",
                    i, cfg.forward_targets[i].addr);
            continue;
        }
        int fwd_flags = 0;
        if (cfg.forward_targets[i].tls_noverify)
            fwd_flags = FORWARD_FLAG_TLS_NOVERIFY;
        else if (cfg.forward_targets[i].tls)
            fwd_flags = FORWARD_FLAG_TLS;
        if (forward_add(fwd_host, fwd_port, fwd_flags) == 0) {
            forwarding   = 1;
            g_forwarding = 1;
        }
    }

    /* Load alert rules */
    if (cfg.rules_path[0]) {
        int n = rules_load(cfg.rules_path);
        if (n > 0)
            fprintf(stderr, "info: loaded %d alert rule(s) from %s\n",
                    n, cfg.rules_path);
    }

    /* Initialise baseline (learning or detection mode) */
    if (cfg.baseline_merge_after > 0)
        baseline_set_merge_after(cfg.baseline_merge_after);

    if (cfg.baseline_learn_secs > 0) {
        const char *out = cfg.baseline_out[0] ? cfg.baseline_out : "baseline.json";
        if (baseline_learn_init(out, cfg.baseline_learn_secs) == 0)
            fprintf(stderr,
                    "info: baseline learning for %d seconds → %s\n",
                    cfg.baseline_learn_secs, out);
    } else if (cfg.baseline_path[0]) {
        int n = baseline_load(cfg.baseline_path);
        if (n >= 0)
            fprintf(stderr, "info: loaded baseline profile (%d comm(s)) from %s\n",
                    n, cfg.baseline_path);
        else
            fprintf(stderr, "warning: could not load baseline profile %s\n",
                    cfg.baseline_path);
    }

    /* Start Prometheus metrics endpoint (before privilege drop — needs bind) */
    if (cfg.metrics_port > 0) {
        if (metrics_init(cfg.metrics_port) == 0)
            fprintf(stderr, "info: metrics endpoint on http://0.0.0.0:%d/metrics\n",
                    cfg.metrics_port);
        else
            fprintf(stderr, "warning: could not start metrics endpoint on port %d\n",
                    cfg.metrics_port);
    }

    /* Ignore SIGPIPE so piped consumers (jq, etc.) can exit without crashing us */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP,  sighup_handler);
    libbpf_set_print(NULL);

    /* Pre-populate lineage cache from /proc before attaching BPF programs */
    lineage_scan_proc();

    struct argus_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    skel = argus_bpf__open();
    if (!skel) {
        fprintf(stderr, "error: failed to open BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    bpf_map__set_max_entries(skel->maps.rb,
                             (uint32_t)cfg.ring_buffer_kb * 1024);
    configure_programs(skel, cfg.filter.event_mask, cfg.follow_pid, cfg.lsm_deny,
                       cfg.tls_data_enable, cfg.syscall_anom_interval);

    err = argus_bpf__load(skel);
    if (err) {
        fprintf(stderr, "error: failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    setup_bpf_filters(skel, &cfg.filter, cfg.rate_limit_per_comm,
                      cfg.rate_limit_per_pid, cfg.follow_pid, cfg.lsm_deny);

    err = argus_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "error: failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    /* Pass kill_list map fd to rules engine for active-response support */
    rules_set_kill_fd(bpf_map__fd(skel->maps.kill_list));

    /* Load threat intelligence CIDR blocklist into BPF LPM trie maps */
    if (cfg.threat_intel_path[0]) {
        int ti_fd_v4 = bpf_map__fd(skel->maps.threat_intel_v4);
        int ti_fd_v6 = bpf_map__fd(skel->maps.threat_intel_v6);
        int n = threatintel_load(cfg.threat_intel_path, ti_fd_v4, ti_fd_v6);
        if (n >= 0)
            fprintf(stderr, "info: loaded %d threat intel CIDR(s) from %s\n",
                    n, cfg.threat_intel_path);
        else
            fprintf(stderr, "warning: could not load threat intel from %s\n",
                    cfg.threat_intel_path);
    }

    /* Initialise file integrity monitoring */
    if (cfg.fim_path_count > 0)
        fim_init(
            (const char (*)[256])cfg.fim_paths,
            cfg.fim_path_count);

    /* Initialise canary / honeypot file detection */
    canary_init();
    for (int i = 0; i < cfg.canary_path_count; i++)
        canary_add_path(cfg.canary_paths[i]);
    if (cfg.canary_path_count > 0)
        fprintf(stderr, "info: monitoring %d canary path(s)\n",
                cfg.canary_path_count);

    /* Initialise alert deduplication */
    if (cfg.alert_dedup_secs > 0) {
        dedup_init(cfg.alert_dedup_secs);
        fprintf(stderr, "info: alert dedup window: %d seconds\n",
                cfg.alert_dedup_secs);
    }

    /* Initialise C2 beaconing detector */
    if (cfg.beacon_cv_threshold > 0.0) {
        beacon_init(cfg.beacon_cv_threshold);
        fprintf(stderr, "info: beacon detection CV threshold: %.2f\n",
                cfg.beacon_cv_threshold);
    }

    /* Initialise syscall sequence detector */
    seqdetect_init();

    /* Initialise YARA scanner */
    if (cfg.yara_rules_dir[0]) {
        if (yara_scan_init(cfg.yara_rules_dir) == 0)
            fprintf(stderr, "info: YARA rules loaded from %s\n",
                    cfg.yara_rules_dir);
        else if (!yara_scan_available())
            fprintf(stderr, "warning: --yara-rules specified but argus "
                            "was built without libyara support\n");
    }

    /* Initialise MITRE ATT&CK tagging (no-op init — just records config) */
    (void)cfg.mitre_tags;   /* used in handle_event via g_cfg */

    /* Initialise webhook/SOAR integration */
    if (cfg.webhook_url[0])
        webhook_init(cfg.webhook_url);

    /* Initialise exec file-hash enrichment */
    if (cfg.exec_hash)
        exechash_init(cfg.vt_api_key[0] ? cfg.vt_api_key : NULL);

    /* Initialise network isolation response */
    isolate_init(0 /* not dry-run */);

    /* Initialise memory forensics */
    if (cfg.mem_forensics)
        memforensics_init();

    /* Initialise persistent event store */
    if (cfg.store_path[0])
        store_init(cfg.store_path, cfg.store_query_port);

    /* Initialise IOC enrichment */
    if (cfg.vt_api_key[0] || cfg.otx_api_key[0])
        iocenrich_init(cfg.vt_api_key[0]  ? cfg.vt_api_key  : NULL,
                       cfg.otx_api_key[0] ? cfg.otx_api_key : NULL);

    /* Initialise container enrichment */
    if (cfg.container_enrich)
        container_init();

    /* Initialise compliance reporting */
    if (cfg.compliance_report[0])
        compliance_init(cfg.compliance_framework, cfg.compliance_report);

    /* Initialise syscall frequency anomaly detection */
    if (cfg.syscall_anom_interval > 0)
        syscallanom_init(cfg.syscall_anom_interval);

    /* LSM enforcement status */
    if (cfg.lsm_deny) {
        if (bpf_lsm_supported())
            fprintf(stderr, "info: LSM enforcement mode active "
                            "(kernel_rules enforced in-kernel)\n");
        else
            fprintf(stderr, "warning: --lsm-deny requested but kernel "
                            "does not support BPF LSM — enforcement disabled\n");
    }

    /* Configure cgroup-aware baseline */
    if (cfg.baseline_cgroup_aware)
        baseline_set_cgroup_aware(1);

    /* Expose config to handle_event() for DGA/ldpreload checks */
    g_cfg = &cfg;

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "error: failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    /* Drop root privileges — all BPF fds are already open */
    if (!no_drop_privs)
        drop_privileges();

    /* Install seccomp denylist (prevents exec/fork/ptrace/setuid from event loop) */
    seccomp_apply();

    print_header("eBPF");

    int drop_fd = bpf_map__fd(skel->maps.dropped);

    /* Save config file paths for SIGHUP reload */
    char cfg_home_path[256] = {};
    {
        const char *home = getenv("HOME");
        if (home)
            snprintf(cfg_home_path, sizeof(cfg_home_path),
                     "%s/.config/argus/config.json", home);
    }

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "error: ring buffer poll failed: %d\n", err);
            break;
        }

        /* ── SIGHUP: reload config files and update BPF filter maps ── */
        if (reload_config) {
            reload_config = 0;
            argus_cfg_t new_cfg;
            cfg_defaults(&new_cfg);
            cfg_load("/etc/argus/config.json", &new_cfg);
            if (cfg_home_path[0])
                cfg_load(cfg_home_path, &new_cfg);
            /* Preserve follow_pid — it's a startup-time CLI option */
            setup_bpf_filters(skel, &new_cfg.filter, new_cfg.rate_limit_per_comm,
                              new_cfg.rate_limit_per_pid, cfg.follow_pid, new_cfg.lsm_deny);
            output_update_filter(&new_cfg.filter);
            cfg.filter              = new_cfg.filter;
            cfg.rate_limit_per_comm = new_cfg.rate_limit_per_comm;
            /* Reload rules if path is configured */
            if (cfg.rules_path[0]) {
                rules_free();
                int n = rules_load(cfg.rules_path);
                if (n > 0)
                    fprintf(stderr, "info: reloaded %d alert rule(s)\n", n);
            }
            /* ── Enterprise module hot-reload ── */
            /* Webhook: restart if URL changed */
            if (strcmp(new_cfg.webhook_url, cfg.webhook_url) != 0) {
                webhook_destroy();
                if (new_cfg.webhook_url[0])
                    webhook_init(new_cfg.webhook_url);
            }
            /* IOC enrichment: update API keys in-place (no restart needed) */
            if (strcmp(new_cfg.vt_api_key,  cfg.vt_api_key)  != 0 ||
                strcmp(new_cfg.otx_api_key, cfg.otx_api_key) != 0) {
                iocenrich_update_keys(
                    new_cfg.vt_api_key[0]  ? new_cfg.vt_api_key  : NULL,
                    new_cfg.otx_api_key[0] ? new_cfg.otx_api_key : NULL);
            }
            /* Copy remaining enterprise fields */
            cfg.webhook_url[0] = '\0';
            strncpy(cfg.webhook_url,  new_cfg.webhook_url,  sizeof(cfg.webhook_url)  - 1);
            strncpy(cfg.vt_api_key,   new_cfg.vt_api_key,   sizeof(cfg.vt_api_key)   - 1);
            strncpy(cfg.otx_api_key,  new_cfg.otx_api_key,  sizeof(cfg.otx_api_key)  - 1);
            cfg.mitre_tags      = new_cfg.mitre_tags;
            cfg.exec_hash       = new_cfg.exec_hash;
            cfg.container_enrich = new_cfg.container_enrich;
            cfg.mem_forensics   = new_cfg.mem_forensics;
            fprintf(stderr, "info: configuration reloaded (SIGHUP)\n");
        }

        uint64_t delta = read_drop_delta(drop_fd);
        output_summary_tick(delta);
        if (delta) {
            if (!cfg.summary_interval)
                print_drops(delta);
            g_total_drops += delta;
            metrics_drop(delta);
            /* Ring-buffer sizing hint: suggest doubling if >1000 cumulative drops */
            if (g_total_drops >= 1000 && cfg.ring_buffer_kb < 65536) {
                int suggested = cfg.ring_buffer_kb * 2;
                if (suggested > 65536) suggested = 65536;
                fprintf(stderr,
                        "hint: %llu ring-buffer drops so far — "
                        "consider --ringbuf %d\n",
                        (unsigned long long)g_total_drops, suggested);
                g_total_drops = 0;   /* reset so hint fires at next 1000 drops */
            }
        }
        if (forwarding) {
            if (delta) forward_drops(delta);
            forward_tick();
        }

        /* ── Periodic syscall anomaly check ────────────────────────── */
        if (cfg.syscall_anom_interval > 0)
            syscallanom_check(skel);
    }

    /* Final drop check before exit */
    uint64_t delta = read_drop_delta(drop_fd);
    if (delta)
        print_drops(delta);

    /* Flush learning data if still in window at shutdown */
    baseline_flush();

    ring_buffer__free(rb);
cleanup:
    if (skel)
        argus_bpf__destroy(skel);
    output_fini();
    rules_free();
    baseline_free();
    dns_free();
    metrics_fini();
    fim_free();
    threatintel_free();
    if (forwarding)
        forward_fini();
    if (cfg.webhook_url[0])
        webhook_destroy();
    iocenrich_destroy();
    store_destroy();
    if (cfg.compliance_report[0]) {
        compliance_write_report();
        compliance_destroy();
    }
    isolate_unblock_all();
    if (output_file)
        fclose(output_file);
    if (cfg.pid_file[0])
        unlink(cfg.pid_file);
    return err < 0 ? -err : err;
}
