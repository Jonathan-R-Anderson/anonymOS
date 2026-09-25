// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// prx-sd eBPF kernel-side event collection
//
// Phase 1 hooks:
//   1. sched_process_exec  — process execution
//   2. sys_enter_openat    — file open
//   3. sys_enter_connect   — network connect
//   4. sched_process_exit  — process exit (cleanup)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "prxsd.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ── Ring buffer map ─────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); /* 1 MB ring buffer */
} events SEC(".maps");

/* ── Per-CPU drop counter (tracks bpf_ringbuf_reserve failures) ───── */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_cnt SEC(".maps");

/* ── Helpers ─────────────────────────────────────────────────────────── */

static __always_inline void inc_drops(void)
{
    __u32 key = PRXSD_STATS_DROPS;
    __u64 *val = bpf_map_lookup_elem(&drop_cnt, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline void fill_header(struct prxsd_event *hdr, __u32 kind)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    hdr->ts_ns     = bpf_ktime_get_ns();
    hdr->pid       = pid_tgid >> 32;
    hdr->tid       = (__u32)pid_tgid;
    hdr->uid       = (__u32)uid_gid;
    hdr->gid       = uid_gid >> 32;
    hdr->kind      = kind;
    hdr->cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));

    /* Read ppid from current task's parent */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    hdr->ppid = BPF_CORE_READ(parent, tgid);

    /* Read namespace IDs */
    struct nsproxy *ns = BPF_CORE_READ(task, nsproxy);
    if (ns) {
        struct mnt_namespace *mnt_ns = BPF_CORE_READ(ns, mnt_ns);
        if (mnt_ns) {
            hdr->mnt_ns = BPF_CORE_READ(mnt_ns, ns.inum);
        }
        struct pid_namespace *pid_ns = BPF_CORE_READ(ns, pid_ns_for_children);
        if (pid_ns) {
            hdr->pid_ns = BPF_CORE_READ(pid_ns, ns.inum);
        }
    }
}

/* ── Hook 1: Process execution ───────────────────────────────────────── */

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct exec_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        inc_drops();
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, PRXSD_EVENT_EXEC);

    /* Read the filename from the tracepoint context.
     * The filename offset is stored in __data_loc_filename. */
    unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename),
                       (void *)ctx + fname_off);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Hook 2: File open (openat) ──────────────────────────────────────── */

struct sys_enter_openat_args {
    unsigned long long unused;
    long               syscall_nr;
    long               dfd;
    const char        *filename;
    long               flags;
    long               mode;
};

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct sys_enter_openat_args *ctx)
{
    struct file_open_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        inc_drops();
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, PRXSD_EVENT_FILE_OPEN);

    bpf_probe_read_user_str(&e->path, sizeof(e->path), ctx->filename);
    e->flags = (__s32)ctx->flags;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Hook 3: Network connect ─────────────────────────────────────────── */

struct sys_enter_connect_args {
    unsigned long long unused;
    long               syscall_nr;
    long               fd;
    struct sockaddr   *uservaddr;
    long               addrlen;
};

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct sys_enter_connect_args *ctx)
{
    struct connect_event *e;

    /* Read the address family first to decide if we care */
    unsigned short af = 0;
    bpf_probe_read_user(&af, sizeof(af), &ctx->uservaddr->sa_family);

    /* Only capture AF_INET (2) and AF_INET6 (10) */
    if (af != 2 && af != 10)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        inc_drops();
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, PRXSD_EVENT_CONNECT);
    e->af = af;

    if (af == 2) {
        /* struct sockaddr_in { sa_family(2), sin_port(2), sin_addr(4) } */
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), ctx->uservaddr);
        e->port = __builtin_bswap16(sin.sin_port);
        __builtin_memcpy(&e->addr4, &sin.sin_addr, 4);
    } else {
        /* struct sockaddr_in6 { sa_family(2), sin6_port(2), flowinfo(4), sin6_addr(16) } */
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), ctx->uservaddr);
        e->port = __builtin_bswap16(sin6.sin6_port);
        __builtin_memcpy(&e->addr6, &sin6.sin6_addr, 16);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Hook 4: Process exit ────────────────────────────────────────────── */

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct exit_event *e;

    /* Only emit for thread group leaders (main thread exit) */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    if (pid != tid)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        inc_drops();
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, PRXSD_EVENT_EXIT);

    /* Read exit code from task_struct */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->exit_code = BPF_CORE_READ(task, exit_code) >> 8;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
