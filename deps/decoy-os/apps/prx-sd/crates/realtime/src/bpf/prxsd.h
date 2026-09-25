/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* prx-sd eBPF shared event definitions */

#ifndef __PRXSD_H
#define __PRXSD_H

/* Maximum lengths for in-kernel buffers. Keep small to fit ring buffer. */
#define COMM_LEN   16
#define PATH_LEN  256
#define ARGV_LEN  128

/* Stats map key for kernel-side ring buffer drop counter */
#define PRXSD_STATS_DROPS  0

/* Event kind tags — must match Rust RuntimeEventKind */
enum prxsd_event_kind {
    PRXSD_EVENT_EXEC       = 1,
    PRXSD_EVENT_FILE_OPEN  = 2,
    PRXSD_EVENT_CONNECT    = 3,
    PRXSD_EVENT_EXIT       = 4,
};

/* Common event header — every event starts with this */
struct prxsd_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 kind;          /* enum prxsd_event_kind */
    __u64 cgroup_id;
    __u64 mnt_ns;
    __u64 pid_ns;
    char  comm[COMM_LEN];
};

/* Process execution event (sched_process_exec) */
struct exec_event {
    struct prxsd_event hdr;
    char filename[PATH_LEN];  /* path of the executed binary */
    char argv[ARGV_LEN];      /* first argument (truncated) */
};

/* File open event (sys_enter_openat/openat2) */
struct file_open_event {
    struct prxsd_event hdr;
    char path[PATH_LEN];
    __s32 flags;               /* open flags */
};

/* Network connect event (sys_enter_connect) */
struct connect_event {
    struct prxsd_event hdr;
    __u32 af;                  /* address family (AF_INET / AF_INET6) */
    __u16 port;                /* remote port (host byte order) */
    __u8  addr4[4];            /* IPv4 address */
    __u8  addr6[16];           /* IPv6 address */
};

/* Process exit event (sched_process_exit) */
struct exit_event {
    struct prxsd_event hdr;
    __s32 exit_code;
};

#endif /* __PRXSD_H */
