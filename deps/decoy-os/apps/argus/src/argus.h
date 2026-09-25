#ifndef __ARGUS_H
#define __ARGUS_H

#define ARGUS_VERSION "0.4.0"

/* vmlinux.h (BPF context) already provides these types */
#ifndef __VMLINUX_H__
#include <stdint.h>
#include <stdbool.h>
#endif

typedef enum {
    EVENT_EXEC          = 0,
    EVENT_OPEN          = 1,
    EVENT_EXIT          = 2,
    EVENT_CONNECT       = 3,
    EVENT_UNLINK        = 4,
    EVENT_RENAME        = 5,
    EVENT_CHMOD         = 6,
    EVENT_BIND          = 7,
    EVENT_PTRACE        = 8,
    EVENT_DNS           = 9,   /* outbound DNS query (sendto port 53)            */
    EVENT_SEND          = 10,  /* first 128 bytes of any sendto payload          */
    EVENT_WRITE_CLOSE   = 11,  /* close() on a write-mode fd (file was written)  */
    EVENT_PRIVESC       = 12,  /* setuid/setresuid/capset uid→0 or dangerous cap */
    EVENT_MEMEXEC       = 13,  /* mmap/mprotect PROT_EXEC on anon mapping        */
    EVENT_KMOD_LOAD     = 14,  /* init_module / finit_module                     */
    EVENT_NET_CORR      = 15,  /* DNS→connect correlation (synthetic, userspace) */
    EVENT_RATE_LIMIT    = 16,  /* per-PID rate limit exceeded                    */
    EVENT_THREAT_INTEL  = 17,  /* connect dest matched threat-intel blocklist     */
    EVENT_TLS_SNI       = 18,  /* TLS ClientHello SNI hostname (uprobe SSL_write) */
    EVENT_PROC_SCRAPE   = 19,  /* /proc/<pid>/mem|maps|fd read by foreign proc   */
    EVENT_NS_ESCAPE     = 20,  /* setns/unshare/clone with CLONE_NEW* flags      */
    EVENT_TLS_DATA      = 21,  /* decrypted TLS payload (uprobe SSL_read)         */
    EVENT_HEARTBEAT     = 22,  /* agent liveness ping (userspace-generated)       */
} event_type_t;

#define EVENT_TYPE_MAX 23   /* highest event_type_t value + 1 */

/* Bitmask values for filter_t.event_mask / argus_cfg_t event selection */
#define TRACE_EXEC          (1 << EVENT_EXEC)
#define TRACE_OPEN          (1 << EVENT_OPEN)
#define TRACE_EXIT          (1 << EVENT_EXIT)
#define TRACE_CONNECT       (1 << EVENT_CONNECT)
#define TRACE_UNLINK        (1 << EVENT_UNLINK)
#define TRACE_RENAME        (1 << EVENT_RENAME)
#define TRACE_CHMOD         (1 << EVENT_CHMOD)
#define TRACE_BIND          (1 << EVENT_BIND)
#define TRACE_PTRACE        (1 << EVENT_PTRACE)
#define TRACE_DNS           (1 << EVENT_DNS)
#define TRACE_SEND          (1 << EVENT_SEND)
#define TRACE_WRITE_CLOSE   (1 << EVENT_WRITE_CLOSE)
#define TRACE_PRIVESC       (1 << EVENT_PRIVESC)
#define TRACE_MEMEXEC       (1 << EVENT_MEMEXEC)
#define TRACE_KMOD_LOAD     (1 << EVENT_KMOD_LOAD)
#define TRACE_NET_CORR      (1 << EVENT_NET_CORR)
#define TRACE_RATE_LIMIT    (1 << EVENT_RATE_LIMIT)
#define TRACE_THREAT_INTEL  (1 << EVENT_THREAT_INTEL)
#define TRACE_TLS_SNI       (1 << EVENT_TLS_SNI)
#define TRACE_PROC_SCRAPE   (1 << EVENT_PROC_SCRAPE)
#define TRACE_NS_ESCAPE     (1 << EVENT_NS_ESCAPE)
#define TRACE_TLS_DATA      (1 << EVENT_TLS_DATA)
/* EVENT_HEARTBEAT is internal only — no TRACE_ bit */

#define TRACE_ALL  (TRACE_EXEC | TRACE_OPEN | TRACE_EXIT | TRACE_CONNECT | \
                    TRACE_UNLINK | TRACE_RENAME | TRACE_CHMOD | \
                    TRACE_BIND | TRACE_PTRACE | TRACE_DNS | \
                    TRACE_SEND | TRACE_WRITE_CLOSE | TRACE_PRIVESC | \
                    TRACE_MEMEXEC | TRACE_KMOD_LOAD | \
                    TRACE_THREAT_INTEL | TRACE_PROC_SCRAPE | TRACE_NS_ESCAPE)
/* NOTE: TRACE_NET_CORR, TRACE_RATE_LIMIT, TRACE_TLS_SNI are synthetic/opt-in
 * and not included in TRACE_ALL to avoid double-counting */

typedef struct event {
    /* ── common fields ─────────────────────────────────── */
    uint64_t     duration_ns;
    event_type_t type;
    int          pid;
    int          ppid;
    uint32_t     uid;
    uint32_t     gid;
    bool         success;
    char         comm[16];

    /* ── EVENT_EXEC / EVENT_OPEN / EVENT_WRITE_CLOSE / EVENT_KMOD_LOAD ── */
    char         filename[128];

    /* ── EVENT_EXEC only ────────────────────────────────── */
    char         args[256];   /* space-separated argv[1..N] */

    /* ── EVENT_EXIT only ────────────────────────────────── */
    int          exit_code;   /* raw kernel exit_code >> 8  */

    /* ── EVENT_CONNECT / EVENT_BIND / EVENT_THREAT_INTEL ──────────────── */
    uint8_t      family;      /* AF_INET (2) or AF_INET6 (10)              */
    uint16_t     dport;       /* dest port (CONNECT) or local port (BIND)  */
    uint8_t      daddr[16];   /* dest/local addr; IPv4 in first 4 bytes    */

    /* ── EVENT_CHMOD / EVENT_SEND / EVENT_MEMEXEC / EVENT_NS_ESCAPE ────── */
    uint32_t     mode;        /* CHMOD: new permission bits                 */
                              /* SEND:  captured payload length (≤128)      */
                              /* MEMEXEC: mmap prot flags                   */
                              /* NS_ESCAPE: clone/unshare/setns flags        */

    /* ── EVENT_OPEN ─────────────────────────────────────────── */
    uint32_t     open_flags;  /* openat flags (O_RDONLY/O_WRONLY/O_RDWR …) */

    /* ── EVENT_PTRACE / EVENT_PROC_SCRAPE ───────────────────── */
    int          ptrace_req;  /* ptrace request number                      */
    int          target_pid;  /* PTRACE: PID being traced                   */
                              /* PROC_SCRAPE: target PID whose /proc was read*/
                              /* KMOD_LOAD: fd arg of finit_module           */

    /* ── EVENT_PRIVESC ───────────────────────────────────────── */
    uint32_t     uid_before;  /* uid before setuid/setresuid                */
    uint32_t     uid_after;   /* uid after (0 = root)                       */
    uint64_t     cap_data;    /* capset: dangerous capability bitmask        */

    /* ── EVENT_NET_CORR / EVENT_TLS_SNI ──────────────────────── */
    char         dns_name[128]; /* correlated DNS name or TLS SNI hostname  */

    /* ── container / cgroup ─────────────────────────────────── */
    char         cgroup[64];  /* leaf cgroup name; empty string on host     */

    /* ── enrichment (userspace-filled, not from BPF) ────────── */
    char         sha256[65];  /* SHA-256 hex of executed binary (EXEC only) */

    /* ── EVENT_TLS_DATA ──────────────────────────────────────── */
    char         tls_payload[256]; /* first 256 bytes of decrypted TLS data */
    uint32_t     tls_payload_len;  /* actual captured length                */
} event_t;

/*
 * In-kernel drop rule — stored in kernel_rules BPF array map.
 * Matching events are silently dropped before the ring buffer.
 * Shared between BPF (vmlinux.h context) and userspace.
 */
#define KERNEL_RULES_MAX 16

typedef struct {
    int      active;       /* 0 = slot unused                         */
    int      event_type;   /* -1 = any; otherwise EVENT_* value       */
    uint32_t uid;          /* 0xFFFFFFFF = any                        */
    char     comm[16];     /* all-zero = any                          */
} kernel_rule_t;

/*
 * BPF filter configuration — written by userspace into config_map[0],
 * read by every BPF handler via should_drop().
 */
typedef struct argus_config {
    uint8_t  filter_pid_active;    /* 1 = only pass PIDs in filter_pids      */
    uint8_t  filter_comm_active;   /* 1 = only pass comms in filter_comms    */
    uint8_t  filter_follow_active; /* 1 = pass PIDs in follow_pids tree      */
    uint8_t  lsm_deny_active;      /* 1 = LSM hooks enforce kernel_rules     */
    uint32_t rate_limit_per_comm;  /* 0 = disabled; N = max events/sec/comm  */
    uint32_t rate_limit_per_pid;   /* 0 = disabled; N = max events/sec/pid   */
} argus_config_t;

#endif /* __ARGUS_H */
