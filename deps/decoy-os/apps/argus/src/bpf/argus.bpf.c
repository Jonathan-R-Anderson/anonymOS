#include "vmlinux.h"
/* __user is a sparse annotation — not always defined by older vmlinux.h */
#ifndef __user
#define __user
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "argus.h"

/* ── Ring buffer: kernel → userspace ───────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ── Drop counter ───────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint64_t);
} dropped SEC(".maps");

static __always_inline void note_drop(void)
{
    uint32_t zero = 0;
    uint64_t *cnt = bpf_map_lookup_elem(&dropped, &zero);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

/* ── Kernel-side filter maps ────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, argus_config_t);
} config_map SEC(".maps");

/*
 * kernel_rules — in-kernel drop rules written by userspace.
 * Events matching an active rule are discarded before the ring buffer.
 * Uses a fixed ARRAY of KERNEL_RULES_MAX entries; inactive slots have
 * active==0 and are skipped.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, KERNEL_RULES_MAX);
    __type(key, uint32_t);
    __type(value, kernel_rule_t);
} kernel_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, uint32_t);
    __type(value, uint8_t);
} filter_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, uint8_t);
} filter_comms SEC(".maps");

/*
 * follow_pids — set of PIDs being tracked by --follow.
 * Seed PID is inserted by userspace; child PIDs are added by
 * handle_process_fork when their parent is present in the set.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, uint8_t);
} follow_pids SEC(".maps");

/* ── Per-comm rate limiting ─────────────────────────────────────────────── */

struct rate_slot {
    uint64_t window_ns;   /* ktime_ns when current window started */
    uint32_t count;       /* events emitted in this window        */
    uint32_t pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, struct rate_slot);
} rate_limit_map SEC(".maps");

/* ── Per-PID rate limiting ──────────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, uint32_t);
    __type(value, struct rate_slot);
} pid_rate_map SEC(".maps");

/* ── Active response kill list ──────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, uint32_t);
    __type(value, uint8_t);
} kill_list SEC(".maps");

/* ── Threat intel LPM trie (IPv4) ───────────────────────────────────────── */
struct lpm_v4_key {
    uint32_t prefixlen;
    uint8_t  data[4];
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v4_key);
    __type(value, uint8_t);
} threat_intel_v4 SEC(".maps");

/* ── Threat intel LPM trie (IPv6) ───────────────────────────────────────── */
struct lpm_v6_key {
    uint32_t prefixlen;
    uint8_t  data[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v6_key);
    __type(value, uint8_t);
} threat_intel_v6 SEC(".maps");

/* ── Scratch maps for new handlers ──────────────────────────────────────── */
struct privesc_start { uint64_t ts; uint32_t uid_before; uint32_t pad; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct privesc_start);
} privesc_scratch SEC(".maps");

struct mmap_start { uint64_t id; int prot; int flags; int fd; uint32_t pad; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uint64_t);
    __type(value, struct mmap_start);
} mmap_active SEC(".maps");

struct kmod_start { uint64_t ts; int fd; uint32_t pad; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct kmod_start);
} kmod_scratch SEC(".maps");

struct ns_start { uint64_t ts; uint32_t flags; uint32_t fd; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct ns_start);
} ns_scratch SEC(".maps");

/* ── Filter helpers ─────────────────────────────────────────────────────── */

static __always_inline int check_kill_list(uint32_t pid)
{
    uint8_t *v = bpf_map_lookup_elem(&kill_list, &pid);
    if (v) { bpf_send_signal(9); return 1; }
    return 0;
}

static __always_inline int should_drop_pid(uint32_t pid)
{
    uint32_t zero = 0;
    argus_config_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return 0;
    if (cfg->filter_pid_active && !bpf_map_lookup_elem(&filter_pids, &pid))
        return 1;
    return 0;
}

/*
 * should_filter_out — exit-handler gate combining pid/comm allowlist and
 * per-comm rate limiting into one config_map lookup.
 */
static __always_inline int should_filter_out(uint32_t pid, char comm[16])
{
    /* Kill-list check: send SIGKILL and drop if pid is listed */
    if (check_kill_list(pid))
        return 1;

    uint32_t zero = 0;
    argus_config_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return 0;

    if (cfg->filter_pid_active && !bpf_map_lookup_elem(&filter_pids, &pid))
        return 1;
    if (cfg->filter_comm_active && !bpf_map_lookup_elem(&filter_comms, comm))
        return 1;
    if (cfg->filter_follow_active && !bpf_map_lookup_elem(&follow_pids, &pid))
        return 1;

    if (cfg->rate_limit_per_comm > 0) {
        uint64_t now = bpf_ktime_get_ns();
        struct rate_slot *slot = bpf_map_lookup_elem(&rate_limit_map, comm);
        if (!slot) {
            struct rate_slot ns = { .window_ns = now, .count = 1, .pad = 0 };
            bpf_map_update_elem(&rate_limit_map, comm, &ns, BPF_ANY);
        } else if (now - slot->window_ns > 1000000000ULL) {
            slot->window_ns = now;
            slot->count = 1;
        } else if (slot->count >= cfg->rate_limit_per_comm) {
            return 1;
        } else {
            slot->count++;
        }
    }

    /* Per-PID rate limiting */
    argus_config_t *cfg_pid = bpf_map_lookup_elem(&config_map, &zero);
    if (cfg_pid && cfg_pid->rate_limit_per_pid > 0) {
        struct rate_slot *ps = bpf_map_lookup_elem(&pid_rate_map, &pid);
        uint64_t now_ns_pid = bpf_ktime_get_ns();
        if (ps) {
            if (now_ns_pid - ps->window_ns < 1000000000ULL) {
                if (ps->count >= cfg_pid->rate_limit_per_pid) {
                    note_drop();
                    return 1;
                }
                ps->count++;
            } else {
                ps->window_ns = now_ns_pid;
                ps->count = 1;
            }
        } else {
            struct rate_slot new_slot = { .window_ns = now_ns_pid, .count = 1 };
            bpf_map_update_elem(&pid_rate_map, &pid, &new_slot, BPF_ANY);
        }
    }

    return 0;
}

/*
 * kernel_rule_drop — check whether a (pid, comm, event_type, uid) tuple
 * matches any active kernel_rules entry.  Returns 1 to drop, 0 to pass.
 * Called from each BPF exit handler BEFORE reserving ring-buffer space.
 *
 * Implementation note: kernel 5.15's BPF verifier rejects ANY backwards
 * branch as a potential infinite loop — even inside bounded loops with a
 * `continue`.  The only portable fix is to emit the 16-slot check as
 * fully manual-unrolled code with zero backwards jumps.
 *
 * KR_COMM_NEQ: true if the rule comm and event comm differ.
 *   Uses chained `||` (all forward short-circuit branches).
 * KR_CHECK(n): check one slot.  All branches are forward-only:
 *   map lookup returns NULL → skip (forward),
 *   active==0 → skip (forward), type/uid/comm mismatch → skip (forward).
 */
#define KR_COMM_NEQ(r, c) \
    ((r)[0]!=(c)[0] || (r)[1]!=(c)[1] || (r)[2]!=(c)[2] || (r)[3]!=(c)[3] || \
     (r)[4]!=(c)[4] || (r)[5]!=(c)[5] || (r)[6]!=(c)[6] || (r)[7]!=(c)[7] || \
     (r)[8]!=(c)[8] || (r)[9]!=(c)[9] || (r)[10]!=(c)[10]|| (r)[11]!=(c)[11]|| \
     (r)[12]!=(c)[12]|| (r)[13]!=(c)[13]|| (r)[14]!=(c)[14]|| (r)[15]!=(c)[15])

#define KR_CHECK(n, etype_arg, uid_arg, comm_arg) do {          \
    uint32_t _ki = (n);                                          \
    kernel_rule_t *_r = bpf_map_lookup_elem(&kernel_rules, &_ki);\
    if (_r && _r->active &&                                      \
        (_r->event_type == -1 || _r->event_type == (etype_arg)) &&\
        (_r->uid == 0xFFFFFFFFU || _r->uid == (uid_arg))  &&    \
        (_r->comm[0] == '\0'  || !KR_COMM_NEQ(_r->comm, (comm_arg))))\
        return 1;                                                \
} while (0)

static __always_inline int kernel_rule_drop(
        uint32_t pid __attribute__((unused)),
        char comm[16], int etype, uint32_t uid)
{
    KR_CHECK( 0, etype, uid, comm); KR_CHECK( 1, etype, uid, comm);
    KR_CHECK( 2, etype, uid, comm); KR_CHECK( 3, etype, uid, comm);
    KR_CHECK( 4, etype, uid, comm); KR_CHECK( 5, etype, uid, comm);
    KR_CHECK( 6, etype, uid, comm); KR_CHECK( 7, etype, uid, comm);
    KR_CHECK( 8, etype, uid, comm); KR_CHECK( 9, etype, uid, comm);
    KR_CHECK(10, etype, uid, comm); KR_CHECK(11, etype, uid, comm);
    KR_CHECK(12, etype, uid, comm); KR_CHECK(13, etype, uid, comm);
    KR_CHECK(14, etype, uid, comm); KR_CHECK(15, etype, uid, comm);
    return 0;
}

/* ── Cgroup helper ──────────────────────────────────────────────────────── */

/*
 * Read the leaf cgroup name from the current task.
 * Uses BPF CO-RE: task_struct → css_set → cgroup → kernfs_node → name.
 * On host processes the name is typically "/" or the slice name.
 * On Docker/k8s containers it is the container ID or scope name.
 */
static __always_inline void fill_cgroup(event_t *e)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const char *name = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
    if (name)
        bpf_probe_read_kernel_str(e->cgroup, sizeof(e->cgroup), name);
}

/* ── Common event header fill ───────────────────────────────────────────── */

static __always_inline void fill_common(event_t *e, uint32_t pid,
                                        char comm[16])
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->pid  = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    uint64_t uid_gid = bpf_get_current_uid_gid();
    e->uid = (uint32_t)(uid_gid);
    e->gid = (uint32_t)(uid_gid >> 32);

    __builtin_memcpy(e->comm, comm, 16);
    fill_cgroup(e);
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_EXEC — tracepoint/syscalls/sys_{enter,exit}_execve
 * ══════════════════════════════════════════════════════════════════════════ */

struct exec_start {
    uint64_t ts;
    char     filename[128];
    char     args[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct exec_start);
} exec_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uint32_t);
    __type(value, struct exec_start);
} execs SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t zero = 0;
    struct exec_start *es = bpf_map_lookup_elem(&exec_scratch, &zero);
    if (!es)
        return 0;

    __builtin_memset(es, 0, sizeof(*es));
    es->ts = bpf_ktime_get_ns();

    bpf_probe_read_user_str(es->filename, sizeof(es->filename),
                            (const char *)ctx->args[0]);

    const char *const *argv = (const char *const *)ctx->args[1];

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        const char *argp = NULL;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i + 1]) || !argp)
            break;
        bpf_probe_read_user_str(es->args + i * 32, 31, argp);
        if (i < 7)
            es->args[i * 32 + 31] = ' ';
    }

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    if (should_drop_pid(pid))
        return 0;
    bpf_map_update_elem(&execs, &pid, es, BPF_ANY);
    return 0;
}

/* ── execveat enter/exit — same pattern, different arg offsets ── */

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t zero = 0;
    struct exec_start *es = bpf_map_lookup_elem(&exec_scratch, &zero);
    if (!es)
        return 0;

    __builtin_memset(es, 0, sizeof(*es));
    es->ts = bpf_ktime_get_ns();

    /* execveat: args[0]=dirfd, args[1]=pathname, args[2]=argv */
    bpf_probe_read_user_str(es->filename, sizeof(es->filename),
                            (const char *)ctx->args[1]);

    const char *const *argv = (const char *const *)ctx->args[2];

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        const char *argp = NULL;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i + 1]) || !argp)
            break;
        bpf_probe_read_user_str(es->args + i * 32, 31, argp);
        if (i < 7)
            es->args[i * 32 + 31] = ' ';
    }

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    if (should_drop_pid(pid))
        return 0;
    bpf_map_update_elem(&execs, &pid, es, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int handle_execveat_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* Identical to execve exit — shares the same execs scratch map */
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct exec_start *es = bpf_map_lookup_elem(&execs, &pid);
    if (!es)
        goto cleanup;

    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_EXEC;
    e->duration_ns = bpf_ktime_get_ns() - es->ts;
    e->success     = (ctx->ret == 0);
    fill_common(e, pid, comm);

    __builtin_memcpy(e->filename, es->filename, sizeof(e->filename));
    __builtin_memcpy(e->args,     es->args,     sizeof(e->args));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&execs, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int handle_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct exec_start *es = bpf_map_lookup_elem(&execs, &pid);
    if (!es)
        goto cleanup;

    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_EXEC;
    e->duration_ns = bpf_ktime_get_ns() - es->ts;
    e->success     = (ctx->ret == 0);
    fill_common(e, pid, comm);

    __builtin_memcpy(e->filename, es->filename, sizeof(e->filename));
    __builtin_memcpy(e->args,     es->args,     sizeof(e->args));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&execs, &pid);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_OPEN — tracepoint/syscalls/sys_{enter,exit}_openat
 * ══════════════════════════════════════════════════════════════════════════ */

struct open_start {
    uint64_t ts;
    uint32_t flags;          /* openat flags (args[2]) */
    uint32_t pad;
    char     filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uint64_t);
    __type(value, struct open_start);
} opens SEC(".maps");

/*
 * fd_track — maps (pid<<32|fd) → filename for write-mode opens.
 * Populated by handle_openat_exit when flags indicate write intent.
 * Consumed by handle_close_enter to emit EVENT_WRITE_CLOSE.
 */
struct fd_entry {
    char filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);        /* (uint64_t)pid << 32 | (uint32_t)fd */
    __type(value, struct fd_entry);
} fd_track SEC(".maps");

/*
 * fd_entry_scratch — per-CPU staging area for struct fd_entry so it does not
 * consume BPF stack space in handle_openat_exit (the 128-byte filename field
 * would push the combined inlined frame past the 512-byte limit).
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct fd_entry);
} fd_entry_scratch SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct open_start os = {};
    os.ts    = bpf_ktime_get_ns();
    os.flags = (uint32_t)ctx->args[2];   /* openat flags */
    bpf_probe_read_user_str(os.filename, sizeof(os.filename),
                            (const char *)ctx->args[1]);

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&opens, &id, &os, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct open_start *os = bpf_map_lookup_elem(&opens, &id);
    if (!os)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    uint64_t uid_gid = bpf_get_current_uid_gid();
    uint32_t uid = (uint32_t)uid_gid;

    if (kernel_rule_drop(pid, comm, EVENT_OPEN, uid))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_OPEN;
    e->duration_ns = bpf_ktime_get_ns() - os->ts;
    e->success     = (ctx->ret >= 0);
    e->open_flags  = os->flags;
    fill_common(e, pid, comm);

    __builtin_memcpy(e->filename, os->filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

    /*
     * Track write-mode opens so we can emit EVENT_WRITE_CLOSE on close().
     * O_WRONLY=1, O_RDWR=2; either means the file will be written.
     * Use fd_entry_scratch (PERCPU_ARRAY) to avoid 128-byte stack allocation.
     */
    if (ctx->ret >= 0 && (os->flags & 3) != 0) {
        uint32_t zero = 0;
        struct fd_entry *fe = bpf_map_lookup_elem(&fd_entry_scratch, &zero);
        if (fe) {
            __builtin_memcpy(fe->filename, os->filename, sizeof(fe->filename));
            uint64_t key = ((uint64_t)pid << 32) | (uint32_t)ctx->ret;
            bpf_map_update_elem(&fd_track, &key, fe, BPF_ANY);
        }
    }

cleanup:
    bpf_map_delete_elem(&opens, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_EXIT — tracepoint/sched/sched_process_exit
 * ══════════════════════════════════════════════════════════════════════════ */

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    if (should_filter_out(pid, comm))
        goto cleanup;

    {
        event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
        if (!e) {
            note_drop();
            goto cleanup;
        }

        e->type    = EVENT_EXIT;
        e->success = true;
        fill_common(e, pid, comm);

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

        bpf_ringbuf_submit(e, 0);
    }

cleanup:
    /* Remove exited PID from follow set so it doesn't linger */
    {
        uint32_t zero = 0;
        argus_config_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
        if (cfg && cfg->filter_follow_active)
            bpf_map_delete_elem(&follow_pids, &pid);
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_CONNECT — tracepoint/syscalls/sys_{enter,exit}_connect
 * ══════════════════════════════════════════════════════════════════════════ */

#define AF_INET  2
#define AF_INET6 10

struct connect_start {
    uint64_t ts;
    uint8_t  family;
    uint16_t dport;
    uint8_t  daddr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uint64_t);
    __type(value, struct connect_start);
} connects SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in  sin  = {};
    struct sockaddr_in6 sin6 = {};
    uint16_t family = 0;

    bpf_probe_read_user(&family, sizeof(family), (void *)ctx->args[1]);

    struct connect_start cs = {};
    cs.ts     = bpf_ktime_get_ns();
    cs.family = (uint8_t)family;

    if (family == AF_INET) {
        bpf_probe_read_user(&sin, sizeof(sin), (void *)ctx->args[1]);
        cs.dport = bpf_ntohs(sin.sin_port);
        __builtin_memcpy(cs.daddr, &sin.sin_addr.s_addr, 4);
    } else if (family == AF_INET6) {
        bpf_probe_read_user(&sin6, sizeof(sin6), (void *)ctx->args[1]);
        cs.dport = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(cs.daddr, &sin6.sin6_addr.in6_u.u6_addr8, 16);
    } else {
        return 0;
    }

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&connects, &id, &cs, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int handle_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct connect_start *cs = bpf_map_lookup_elem(&connects, &id);
    if (!cs)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_CONNECT;
    e->duration_ns = bpf_ktime_get_ns() - cs->ts;
    e->success     = (ctx->ret == 0 || ctx->ret == -115 /* EINPROGRESS */);
    e->family      = cs->family;
    e->dport       = cs->dport;
    __builtin_memcpy(e->daddr, cs->daddr, sizeof(e->daddr));
    fill_common(e, pid, comm);

    /* Threat intel check for IPv4 */
    if (e->family == 2) {
        struct lpm_v4_key tk = {};
        tk.prefixlen = 32;
        __builtin_memcpy(tk.data, e->daddr, 4);
        if (bpf_map_lookup_elem(&threat_intel_v4, &tk)) {
            e->type = EVENT_THREAT_INTEL;
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&connects, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_UNLINK — tracepoint/syscalls/sys_{enter,exit}_unlinkat
 * Covers both unlink() and unlinkat() — glibc routes unlink() through
 * unlinkat(AT_FDCWD, path, 0) on modern kernels.
 * ══════════════════════════════════════════════════════════════════════════ */

struct unlink_start {
    uint64_t ts;
    char     path[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, struct unlink_start);
} unlinks SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct unlink_start us = {};
    us.ts = bpf_ktime_get_ns();
    /* unlinkat: args[0]=dirfd, args[1]=pathname, args[2]=flags */
    bpf_probe_read_user_str(us.path, sizeof(us.path),
                            (const char *)ctx->args[1]);

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&unlinks, &id, &us, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int handle_unlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct unlink_start *us = bpf_map_lookup_elem(&unlinks, &id);
    if (!us)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_UNLINK;
    e->duration_ns = bpf_ktime_get_ns() - us->ts;
    e->success     = (ctx->ret == 0);
    fill_common(e, pid, comm);
    __builtin_memcpy(e->filename, us->path, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&unlinks, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_RENAME — tracepoint/syscalls/sys_{enter,exit}_renameat2
 * Covers rename(), renameat(), renameat2() — all route through renameat2
 * on kernels 3.15+. Old path stored in filename[], new path in args[].
 * ══════════════════════════════════════════════════════════════════════════ */

struct rename_start {
    uint64_t ts;
    char     old_path[128];
    char     new_path[128];
};

/*
 * rename_start is 264 bytes — exceeds safe BPF stack usage when combined
 * with other locals. Use a PERCPU_ARRAY scratch buffer instead.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct rename_start);
} rename_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, struct rename_start);
} renames SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t zero = 0;
    struct rename_start *rs = bpf_map_lookup_elem(&rename_scratch, &zero);
    if (!rs)
        return 0;

    __builtin_memset(rs, 0, sizeof(*rs));
    rs->ts = bpf_ktime_get_ns();

    /* renameat2: args[1]=oldpath, args[3]=newpath */
    bpf_probe_read_user_str(rs->old_path, sizeof(rs->old_path),
                            (const char *)ctx->args[1]);
    bpf_probe_read_user_str(rs->new_path, sizeof(rs->new_path),
                            (const char *)ctx->args[3]);

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&renames, &id, rs, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int handle_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct rename_start *rs = bpf_map_lookup_elem(&renames, &id);
    if (!rs)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_RENAME;
    e->duration_ns = bpf_ktime_get_ns() - rs->ts;
    e->success     = (ctx->ret == 0);
    fill_common(e, pid, comm);
    __builtin_memcpy(e->filename, rs->old_path, sizeof(e->filename));
    __builtin_memcpy(e->args,     rs->new_path, 128);   /* new path */

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&renames, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_CHMOD — tracepoint/syscalls/sys_{enter,exit}_fchmodat
 * Covers chmod() and fchmodat() — glibc routes chmod() through fchmodat().
 * ══════════════════════════════════════════════════════════════════════════ */

struct chmod_start {
    uint64_t ts;
    char     path[128];
    uint32_t mode;
    uint32_t pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, struct chmod_start);
} chmods SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_fchmodat_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct chmod_start cs = {};
    cs.ts   = bpf_ktime_get_ns();
    cs.mode = (uint32_t)ctx->args[2];
    /* fchmodat: args[0]=dirfd, args[1]=pathname, args[2]=mode */
    bpf_probe_read_user_str(cs.path, sizeof(cs.path),
                            (const char *)ctx->args[1]);

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&chmods, &id, &cs, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmodat")
int handle_fchmodat_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct chmod_start *cs = bpf_map_lookup_elem(&chmods, &id);
    if (!cs)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_CHMOD;
    e->duration_ns = bpf_ktime_get_ns() - cs->ts;
    e->success     = (ctx->ret == 0);
    e->mode        = cs->mode;
    fill_common(e, pid, comm);
    __builtin_memcpy(e->filename, cs->path, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&chmods, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_BIND — tracepoint/syscalls/sys_{enter,exit}_bind
 * Captures local address a process binds to (server-side network events).
 * IPv4 and IPv6 only; UNIX sockets are ignored.
 * ══════════════════════════════════════════════════════════════════════════ */

struct bind_start {
    uint64_t ts;
    uint8_t  family;
    uint16_t lport;
    uint8_t  laddr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, struct bind_start);
} binds SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_bind")
int handle_bind_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* bind: args[0]=sockfd, args[1]=sockaddr*, args[2]=addrlen */
    uint16_t family = 0;
    bpf_probe_read_user(&family, sizeof(family), (void *)ctx->args[1]);

    struct bind_start bs = {};
    bs.ts     = bpf_ktime_get_ns();
    bs.family = (uint8_t)family;

    struct sockaddr_in  sin  = {};
    struct sockaddr_in6 sin6 = {};

    if (family == AF_INET) {
        bpf_probe_read_user(&sin, sizeof(sin), (void *)ctx->args[1]);
        bs.lport = bpf_ntohs(sin.sin_port);
        __builtin_memcpy(bs.laddr, &sin.sin_addr.s_addr, 4);
    } else if (family == AF_INET6) {
        bpf_probe_read_user(&sin6, sizeof(sin6), (void *)ctx->args[1]);
        bs.lport = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(bs.laddr, &sin6.sin6_addr.in6_u.u6_addr8, 16);
    } else {
        return 0;
    }

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&binds, &id, &bs, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bind")
int handle_bind_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct bind_start *bs = bpf_map_lookup_elem(&binds, &id);
    if (!bs)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_BIND;
    e->duration_ns = bpf_ktime_get_ns() - bs->ts;
    e->success     = (ctx->ret == 0);
    e->family      = bs->family;
    e->dport       = bs->lport;    /* dport field reused for local port */
    __builtin_memcpy(e->daddr, bs->laddr, sizeof(e->daddr));
    fill_common(e, pid, comm);

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&binds, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_PTRACE — tracepoint/syscalls/sys_{enter,exit}_ptrace
 * Captures ptrace attach/traceme attempts. No user-memory reads needed —
 * request and target pid come directly from the syscall arg registers.
 * ══════════════════════════════════════════════════════════════════════════ */

struct ptrace_start {
    uint64_t ts;
    int      request;
    int      target_pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, struct ptrace_start);
} ptraces SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* ptrace: args[0]=request, args[1]=pid, args[2]=addr, args[3]=data */
    struct ptrace_start ps = {};
    ps.ts         = bpf_ktime_get_ns();
    ps.request    = (int)ctx->args[0];
    ps.target_pid = (int)ctx->args[1];

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&ptraces, &id, &ps, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ptrace")
int handle_ptrace_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct ptrace_start *ps = bpf_map_lookup_elem(&ptraces, &id);
    if (!ps)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_PTRACE;
    e->duration_ns = bpf_ktime_get_ns() - ps->ts;
    e->success     = (ctx->ret == 0);
    e->ptrace_req  = ps->request;
    e->target_pid  = ps->target_pid;
    fill_common(e, pid, comm);

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&ptraces, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_WRITE_CLOSE — tracepoint/syscalls/sys_enter_close
 * Emitted when a write-mode fd (tracked by handle_openat_exit) is closed.
 * ══════════════════════════════════════════════════════════════════════════ */

SEC("tracepoint/syscalls/sys_enter_close")
int handle_close_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t fd = (uint32_t)ctx->args[0];
    uint64_t id = bpf_get_current_pid_tgid();
    uint32_t pid = (uint32_t)(id >> 32);

    uint64_t key = ((uint64_t)pid << 32) | fd;
    struct fd_entry *fe = bpf_map_lookup_elem(&fd_track, &key);
    if (!fe)
        return 0;

    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    uint64_t uid_gid = bpf_get_current_uid_gid();
    if (kernel_rule_drop(pid, comm, EVENT_WRITE_CLOSE, (uint32_t)uid_gid))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type    = EVENT_WRITE_CLOSE;
    e->success = true;
    fill_common(e, pid, comm);
    __builtin_memcpy(e->filename, fe->filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&fd_track, &key);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_DNS / EVENT_SEND — tracepoint/syscalls/sys_{enter,exit}_sendto
 *
 * EVENT_DNS  — sendto to UDP port 53; filename holds parsed DNS query name.
 * EVENT_SEND — any sendto; filename holds first 128 bytes of payload;
 *              mode field holds actual captured length.
 *
 * Both reuse daddr/dport for the destination address.
 * ══════════════════════════════════════════════════════════════════════════ */

struct sendto_start {
    uint64_t ts;
    uint8_t  family;
    uint16_t dport;
    uint8_t  daddr[16];
    uint32_t payload_len;
    uint32_t pad;
    char     payload[128];   /* raw bytes for EVENT_SEND */
    int      is_dns;         /* 1 if dest port == 53; name decoded in userspace */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct sendto_start);
} sendto_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, struct sendto_start);
} sendtos SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sendto_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* sendto args: fd, buf, len, flags, dest_addr, addrlen */
    uint64_t id  = bpf_get_current_pid_tgid();
    uint32_t pid = (uint32_t)(id >> 32);
    if (should_drop_pid(pid))
        return 0;

    void *dest_addr = (void *)ctx->args[4];
    if (!dest_addr)
        return 0;   /* no destination — skip (UNIX domain or connected socket) */

    uint16_t family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), dest_addr))
        return 0;
    if (family != AF_INET && family != AF_INET6)
        return 0;

    uint32_t zero = 0;
    struct sendto_start *ss = bpf_map_lookup_elem(&sendto_scratch, &zero);
    if (!ss)
        return 0;
    __builtin_memset(ss, 0, sizeof(*ss));

    ss->ts     = bpf_ktime_get_ns();
    ss->family = (uint8_t)family;

    struct sockaddr_in  sin  = {};
    struct sockaddr_in6 sin6 = {};
    if (family == AF_INET) {
        bpf_probe_read_user(&sin, sizeof(sin), dest_addr);
        ss->dport = bpf_ntohs(sin.sin_port);
        __builtin_memcpy(ss->daddr, &sin.sin_addr.s_addr, 4);
    } else {
        bpf_probe_read_user(&sin6, sizeof(sin6), dest_addr);
        ss->dport = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(ss->daddr, &sin6.sin6_addr.in6_u.u6_addr8, 16);
    }

    /* Capture payload (up to 128 bytes) */
    const void *buf = (const void *)ctx->args[1];
    uint32_t    len = (uint32_t)ctx->args[2];
    if (len > 128) len = 128;
    ss->payload_len = len;
    if (buf && len > 0)
        bpf_probe_read_user(ss->payload, len & 127, buf);

    /* Mark as DNS if destination port is 53; name parsing done in userspace
     * from the raw payload to keep the BPF program within the 1M instruction
     * verifier limit on kernel 5.15.  dns_name is left empty here; argus.c
     * decodes it via parse_dns_payload() from ss->payload on the exit path. */
    if (ss->dport == 53 && ss->payload_len >= 13)
        ss->is_dns = 1;

    bpf_map_update_elem(&sendtos, &id, ss, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int handle_sendto_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct sendto_start *ss = bpf_map_lookup_elem(&sendtos, &id);
    if (!ss)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    uint64_t uid_gid = bpf_get_current_uid_gid();
    uint32_t uid     = (uint32_t)uid_gid;

    event_type_t etype = ss->is_dns ? EVENT_DNS : EVENT_SEND;
    if (kernel_rule_drop(pid, comm, etype, uid))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = etype;
    e->duration_ns = bpf_ktime_get_ns() - ss->ts;
    e->success     = (ctx->ret >= 0);
    e->family      = ss->family;
    e->dport       = ss->dport;
    e->mode        = ss->payload_len;   /* payload_len stored in mode field */
    __builtin_memcpy(e->daddr, ss->daddr, sizeof(e->daddr));
    fill_common(e, pid, comm);

    /* Always copy raw payload; for DNS, userspace decodes the name
     * from offset 12 of the payload (QNAME in the DNS wire format). */
    __builtin_memcpy(e->filename, ss->payload, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&sendtos, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Sched fork — tracepoint/sched/sched_process_fork
 * Propagates the follow_pids set to child processes when --follow is active.
 * Only runs when filter_follow_active == 1; disabled at load time otherwise.
 * ══════════════════════════════════════════════════════════════════════════ */

SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    uint32_t zero = 0;
    argus_config_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg || !cfg->filter_follow_active)
        return 0;

    uint32_t parent_pid = ctx->parent_pid;
    uint32_t child_pid  = ctx->child_pid;

    if (bpf_map_lookup_elem(&follow_pids, &parent_pid)) {
        uint8_t val = 1;
        bpf_map_update_elem(&follow_pids, &child_pid, &val, BPF_ANY);
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_PRIVESC — setuid / setresuid privilege escalation detection
 * ══════════════════════════════════════════════════════════════════════════ */

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t zero = 0;
    struct privesc_start *ps = bpf_map_lookup_elem(&privesc_scratch, &zero);
    if (!ps) return 0;
    ps->ts = bpf_ktime_get_ns();
    ps->uid_before = (uint32_t)(bpf_get_current_uid_gid() & 0xffffffff);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setuid")
int handle_setuid_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (ctx->ret != 0) return 0;
    uint32_t zero = 0;
    struct privesc_start *ps = bpf_map_lookup_elem(&privesc_scratch, &zero);
    if (!ps || !ps->ts) return 0;

    uint64_t id = bpf_get_current_pid_tgid();
    uint32_t pid = id >> 32;
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm)) return 0;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) { note_drop(); return 0; }
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, pid, comm);
    e->type       = EVENT_PRIVESC;
    e->uid_before = ps->uid_before;
    e->uid_after  = (uint32_t)(bpf_get_current_uid_gid() & 0xffffffff);
    e->success    = 1;
    ps->ts = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int handle_setresuid_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t zero = 0;
    struct privesc_start *ps = bpf_map_lookup_elem(&privesc_scratch, &zero);
    if (!ps) return 0;
    ps->ts = bpf_ktime_get_ns();
    ps->uid_before = (uint32_t)(bpf_get_current_uid_gid() & 0xffffffff);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setresuid")
int handle_setresuid_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (ctx->ret != 0) return 0;
    uint32_t zero = 0;
    struct privesc_start *ps = bpf_map_lookup_elem(&privesc_scratch, &zero);
    if (!ps || !ps->ts) return 0;

    uint64_t id = bpf_get_current_pid_tgid();
    uint32_t pid = id >> 32;
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm)) return 0;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) { note_drop(); return 0; }
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, pid, comm);
    e->type       = EVENT_PRIVESC;
    e->uid_before = ps->uid_before;
    e->uid_after  = (uint32_t)(bpf_get_current_uid_gid() & 0xffffffff);
    e->success    = 1;
    ps->ts = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_MEMEXEC — mmap/mprotect with PROT_EXEC on anonymous mappings
 * ══════════════════════════════════════════════════════════════════════════ */

#define PROT_EXEC_FLAG  0x4
#define MAP_ANONYMOUS   0x20

SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_mmap_enter(struct trace_event_raw_sys_enter *ctx)
{
    int prot  = (int)ctx->args[2];
    int flags = (int)ctx->args[3];
    if (!(prot & PROT_EXEC_FLAG)) return 0;
    if (!(flags & MAP_ANONYMOUS))  return 0;

    uint64_t id  = bpf_get_current_pid_tgid();
    struct mmap_start ms = { .id = id, .prot = prot, .flags = flags,
                             .fd = (int)ctx->args[4], .pad = 0 };
    bpf_map_update_elem(&mmap_active, &id, &ms, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int handle_mmap_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();
    struct mmap_start *ms = bpf_map_lookup_elem(&mmap_active, &id);
    if (!ms) return 0;
    bpf_map_delete_elem(&mmap_active, &id);
    if ((long)ctx->ret < 0) return 0;

    uint32_t pid = id >> 32;
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm)) return 0;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) { note_drop(); return 0; }
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, pid, comm);
    e->type       = EVENT_MEMEXEC;
    e->mode       = (uint32_t)ms->prot;
    e->open_flags = (uint32_t)ms->flags;
    e->success    = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int handle_mprotect_enter(struct trace_event_raw_sys_enter *ctx)
{
    int prot = (int)ctx->args[2];
    if (!(prot & PROT_EXEC_FLAG)) return 0;

    uint64_t id  = bpf_get_current_pid_tgid();
    struct mmap_start ms = { .id = id, .prot = prot, .flags = 0,
                             .fd = -1, .pad = 0 };
    bpf_map_update_elem(&mmap_active, &id, &ms, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mprotect")
int handle_mprotect_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();
    struct mmap_start *ms = bpf_map_lookup_elem(&mmap_active, &id);
    if (!ms) return 0;
    bpf_map_delete_elem(&mmap_active, &id);
    if (ctx->ret != 0) return 0;

    uint32_t pid = id >> 32;
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm)) return 0;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) { note_drop(); return 0; }
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, pid, comm);
    e->type       = EVENT_MEMEXEC;
    e->mode       = (uint32_t)ms->prot;
    e->open_flags = 1;   /* flag: this is mprotect, not mmap */
    e->success    = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_KMOD_LOAD — kernel module load via finit_module / init_module
 * ══════════════════════════════════════════════════════════════════════════ */

SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_finit_module_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t zero = 0;
    struct kmod_start *ks = bpf_map_lookup_elem(&kmod_scratch, &zero);
    if (!ks) return 0;
    ks->ts = bpf_ktime_get_ns();
    ks->fd = (int)ctx->args[0];
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_finit_module")
int handle_finit_module_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint32_t zero = 0;
    struct kmod_start *ks = bpf_map_lookup_elem(&kmod_scratch, &zero);
    if (!ks || !ks->ts) return 0;

    uint64_t id  = bpf_get_current_pid_tgid();
    uint32_t pid = id >> 32;
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm)) return 0;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) { note_drop(); return 0; }
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, pid, comm);
    e->type       = EVENT_KMOD_LOAD;
    e->target_pid = ks->fd;   /* repurpose target_pid to carry fd for userspace */
    e->success    = (ctx->ret == 0);
    ks->ts = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_init_module_enter(struct trace_event_raw_sys_enter *ctx)
{
    (void)ctx;
    uint32_t zero = 0;
    struct kmod_start *ks = bpf_map_lookup_elem(&kmod_scratch, &zero);
    if (!ks) return 0;
    ks->ts = bpf_ktime_get_ns();
    ks->fd = -1;   /* in-memory load, no fd */
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_init_module")
int handle_init_module_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint32_t zero = 0;
    struct kmod_start *ks = bpf_map_lookup_elem(&kmod_scratch, &zero);
    if (!ks || !ks->ts) return 0;

    uint64_t id  = bpf_get_current_pid_tgid();
    uint32_t pid = id >> 32;
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm)) return 0;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) { note_drop(); return 0; }
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, pid, comm);
    e->type    = EVENT_KMOD_LOAD;
    e->success = (ctx->ret == 0);
    ks->ts = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_NS_ESCAPE — namespace escape via unshare(2) or setns(2)
 * ══════════════════════════════════════════════════════════════════════════ */

#define CLONE_NEWNS   0x00020000
#define CLONE_NEWPID  0x20000000
#define CLONE_NEWNET  0x40000000
#define CLONE_NEWUSER 0x10000000
#define NS_FLAGS_MASK (CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUSER)

SEC("tracepoint/syscalls/sys_enter_unshare")
int handle_unshare_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t flags = (uint32_t)ctx->args[0];
    if (!(flags & NS_FLAGS_MASK)) return 0;

    uint32_t zero = 0;
    struct ns_start *ns = bpf_map_lookup_elem(&ns_scratch, &zero);
    if (!ns) return 0;
    ns->ts    = bpf_ktime_get_ns();
    ns->flags = flags;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unshare")
int handle_unshare_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint32_t zero = 0;
    struct ns_start *ns = bpf_map_lookup_elem(&ns_scratch, &zero);
    if (!ns || !ns->ts) return 0;
    ns->ts = 0;
    if (ctx->ret != 0) return 0;

    uint64_t id  = bpf_get_current_pid_tgid();
    uint32_t pid = id >> 32;
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm)) return 0;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) { note_drop(); return 0; }
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, pid, comm);
    e->type    = EVENT_NS_ESCAPE;
    e->mode    = ns->flags & NS_FLAGS_MASK;
    e->success = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int handle_setns_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t nstype = (uint32_t)ctx->args[1];
    if (nstype && !(nstype & NS_FLAGS_MASK)) return 0;

    uint32_t zero = 0;
    struct ns_start *ns = bpf_map_lookup_elem(&ns_scratch, &zero);
    if (!ns) return 0;
    ns->ts    = bpf_ktime_get_ns();
    ns->flags = nstype ? nstype : NS_FLAGS_MASK;   /* 0 means any ns */
    ns->fd    = (uint32_t)ctx->args[0];
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setns")
int handle_setns_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint32_t zero = 0;
    struct ns_start *ns = bpf_map_lookup_elem(&ns_scratch, &zero);
    if (!ns || !ns->ts) return 0;
    ns->ts = 0;
    if (ctx->ret != 0) return 0;

    uint64_t id  = bpf_get_current_pid_tgid();
    uint32_t pid = id >> 32;
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm)) return 0;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) { note_drop(); return 0; }
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, pid, comm);
    e->type    = EVENT_NS_ESCAPE;
    e->mode    = ns->flags;
    e->success = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * LSM enforcement — optional, kernel 5.7+ with CONFIG_BPF_LSM=y.
 *
 * These programs enforce kernel_rules in-kernel: if a matching rule exists
 * and lsm_deny_active == 1 in config_map, the operation is denied with
 * -EPERM before it even reaches the syscall handler.
 *
 * argus.c checks for BPF LSM support at runtime and calls
 * bpf_program__set_autoload(false) on these programs when unsupported,
 * so the skeleton loads cleanly on older kernels.
 * ══════════════════════════════════════════════════════════════════════════ */

static __always_inline int lsm_should_deny(char comm[16], int etype,
                                            uint32_t uid)
{
    uint32_t zero = 0;
    argus_config_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg || !cfg->lsm_deny_active)
        return 0;
    return kernel_rule_drop(0, comm, etype, uid);
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret)
{
    if (ret != 0) return ret;   /* already denied upstream */
    uint64_t uid_gid = bpf_get_current_uid_gid();
    uint32_t uid     = (uint32_t)uid_gid;
    char comm[16]    = {};
    bpf_get_current_comm(comm, sizeof(comm));
    return lsm_should_deny(comm, EVENT_OPEN, uid) ? -1 : 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm, int ret)
{
    if (ret != 0) return ret;
    uint64_t uid_gid = bpf_get_current_uid_gid();
    uint32_t uid     = (uint32_t)uid_gid;
    char comm[16]    = {};
    bpf_get_current_comm(comm, sizeof(comm));
    return lsm_should_deny(comm, EVENT_EXEC, uid) ? -1 : 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
    if (ret != 0) return ret;
    uint64_t uid_gid = bpf_get_current_uid_gid();
    uint32_t uid     = (uint32_t)uid_gid;
    char comm[16]    = {};
    bpf_get_current_comm(comm, sizeof(comm));
    return lsm_should_deny(comm, EVENT_CONNECT, uid) ? -1 : 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Syscall frequency histogram — per-(comm, syscall_nr) event counter.
 *
 * Userspace reads this map periodically via syscallanom_check() to detect
 * sudden shifts in a process's syscall distribution.
 * ══════════════════════════════════════════════════════════════════════════ */

struct syscall_key {
    char     comm[16];
    uint32_t nr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct syscall_key);
    __type(value, uint64_t);
} syscall_counts SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_key k = {};
    bpf_get_current_comm(k.comm, sizeof(k.comm));
    k.nr = (uint32_t)ctx->id;

    uint64_t one = 1;
    uint64_t *cnt = bpf_map_lookup_elem(&syscall_counts, &k);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
    else
        bpf_map_update_elem(&syscall_counts, &k, &one, BPF_ANY);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * TLS data capture — uprobe on SSL_read to capture decrypted payload.
 *
 * Attaches to SSL_read(ssl, buf, num) in libssl.so at runtime.
 * The exit probe reads `num` bytes from the userspace `buf` pointer.
 *
 * argus.c attaches this only when --tls-data is passed.
 * ══════════════════════════════════════════════════════════════════════════ */

struct ssl_read_args {
    uint64_t ssl;    /* SSL* (ignored) */
    uint64_t buf;    /* void* — userspace pointer to decrypted data */
    int      num;    /* max bytes to read */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint64_t);                  /* pid_tgid */
    __type(value, struct ssl_read_args);
} ssl_read_scratch SEC(".maps");

SEC("uprobe/SSL_read")
int uprobe_ssl_read_enter(struct pt_regs *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();
    struct ssl_read_args args = {};
    args.buf = PT_REGS_PARM2(ctx);
    args.num = (int)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&ssl_read_scratch, &id, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_ssl_read_exit(struct pt_regs *ctx)
{
    uint64_t id  = bpf_get_current_pid_tgid();
    uint32_t pid = id >> 32;
    int      ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_read_scratch, &id);
        return 0;
    }

    struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_scratch, &id);
    if (!args) return 0;

    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) { note_drop(); bpf_map_delete_elem(&ssl_read_scratch, &id); return 0; }
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, pid, comm);
    e->type = EVENT_TLS_DATA;

    uint32_t cap = (uint32_t)ret;
    if (cap > sizeof(e->tls_payload)) cap = sizeof(e->tls_payload);
    e->tls_payload_len = cap;
    bpf_probe_read_user(e->tls_payload, cap, (void *)(uintptr_t)args->buf);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&ssl_read_scratch, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
