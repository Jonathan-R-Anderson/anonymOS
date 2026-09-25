// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Orin eBPF Real-Time Streamer
 * Attaches to key syscalls to stream security events via ring buffer.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256

// Event types
enum event_type {
    EVENT_EXEC = 1,
    EVENT_CONNECT = 2,
    EVENT_FILE_OPEN = 3,
};

// Event structure pushed to user-space
struct event {
    __u32 pid;
    __u32 uid;
    __u32 type;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
    __u64 timestamp;
};

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Helper to submit event
static __always_inline void submit_event(struct pt_regs *ctx, enum event_type type, const char *filename) {
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->type = type;
    e->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (filename) {
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
    } else {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}

// Tracepoint: sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[0];
    submit_event(ctx, EVENT_EXEC, filename);
    return 0;
}

// Tracepoint: sys_enter_connect (simplified for IP extraction in userland or just flagging)
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    // args[1] is struct sockaddr *, complex to read fully in eBPF without helpers
    // For this MVP, we log the attempt and let userland resolve details if needed,
    // or just log the comm/pid.
    submit_event(ctx, EVENT_CONNECT, NULL);
    return 0;
}

// Tracepoint: sys_enter_openat
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[1];
    submit_event(ctx, EVENT_FILE_OPEN, filename);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";