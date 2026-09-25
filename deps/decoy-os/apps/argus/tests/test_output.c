#include <string.h>
#include "../src/output.h"
#include "../src/argus.h"
#include "framework.h"

/* Build a minimal event_t for testing */
static event_t make_exec(int pid, int ppid, const char *comm, const char *file)
{
    event_t e = {0};
    e.type = EVENT_EXEC;
    e.pid  = pid;
    e.ppid = ppid;
    strncpy(e.comm,     comm, sizeof(e.comm) - 1);
    strncpy(e.filename, file, sizeof(e.filename) - 1);
    return e;
}

static event_t make_open(int pid, const char *file)
{
    event_t e = {0};
    e.type = EVENT_OPEN;
    e.pid  = pid;
    strncpy(e.filename, file, sizeof(e.filename) - 1);
    return e;
}

/* ── pid filter ─────────────────────────────────────────────────────────── */

static void test_pid_filter(void)
{
    filter_t f = {0}; f.pid = 1234; f.event_mask = TRACE_ALL;
    output_init(OUTPUT_TEXT, &f);

    event_t match    = make_exec(1234, 1, "bash", "/bin/bash");
    event_t no_match = make_exec(5678, 1, "bash", "/bin/bash");
    ASSERT_EQ(event_matches(&match),    1);
    ASSERT_EQ(event_matches(&no_match), 0);
}

/* ── comm filter ────────────────────────────────────────────────────────── */

static void test_comm_filter(void)
{
    filter_t f = {0};
    strncpy(f.comm, "curl", sizeof(f.comm) - 1);
    f.event_mask = TRACE_ALL;
    output_init(OUTPUT_TEXT, &f);

    event_t match    = make_exec(1, 0, "curl", "/usr/bin/curl");
    event_t no_match = make_exec(2, 0, "wget", "/usr/bin/wget");
    ASSERT_EQ(event_matches(&match),    1);
    ASSERT_EQ(event_matches(&no_match), 0);
}

/* ── path include filter ────────────────────────────────────────────────── */

static void test_path_filter(void)
{
    filter_t f = {0};
    strncpy(f.path, "/etc", sizeof(f.path) - 1);
    f.event_mask = TRACE_ALL;
    output_init(OUTPUT_TEXT, &f);

    event_t match    = make_open(1, "/etc/passwd");
    event_t no_match = make_open(1, "/tmp/foo");
    ASSERT_EQ(event_matches(&match),    1);
    ASSERT_EQ(event_matches(&no_match), 0);
}

/* ── exclude paths ──────────────────────────────────────────────────────── */

static void test_exclude_paths(void)
{
    filter_t f = {0};
    f.event_mask = TRACE_ALL;
    strncpy(f.excludes[0], "/proc", 127);
    strncpy(f.excludes[1], "/sys",  127);
    f.exclude_count = 2;
    output_init(OUTPUT_TEXT, &f);

    event_t proc_open = make_open(1, "/proc/1/status");
    event_t sys_open  = make_open(1, "/sys/kernel/btf/vmlinux");
    event_t etc_open  = make_open(1, "/etc/hosts");
    ASSERT_EQ(event_matches(&proc_open), 0);
    ASSERT_EQ(event_matches(&sys_open),  0);
    ASSERT_EQ(event_matches(&etc_open),  1);

    /* excludes only apply to OPEN — EXEC with same path should still pass */
    event_t proc_exec = make_exec(1, 0, "cat", "/proc/version");
    ASSERT_EQ(event_matches(&proc_exec), 1);
}

/* ── event_mask ─────────────────────────────────────────────────────────── */

static void test_event_mask(void)
{
    filter_t f = {0};
    f.event_mask = TRACE_EXEC;   /* only EXEC */
    output_init(OUTPUT_TEXT, &f);

    event_t exec_ev = make_exec(1, 0, "bash", "/bin/bash");
    event_t open_ev = make_open(1, "/tmp/foo");

    event_t exit_ev = {0}; exit_ev.type = EVENT_EXIT; exit_ev.pid = 1;
    event_t conn_ev = {0}; conn_ev.type = EVENT_CONNECT; conn_ev.pid = 1;

    ASSERT_EQ(event_matches(&exec_ev), 1);
    ASSERT_EQ(event_matches(&open_ev), 0);
    ASSERT_EQ(event_matches(&exit_ev), 0);
    ASSERT_EQ(event_matches(&conn_ev), 0);
}

/* ── combined filters ───────────────────────────────────────────────────── */

static void test_combined_filters(void)
{
    filter_t f = {0};
    f.pid = 42;
    strncpy(f.comm, "curl", sizeof(f.comm) - 1);
    f.event_mask = TRACE_ALL;
    output_init(OUTPUT_TEXT, &f);

    /* both pid and comm match */
    event_t both  = make_exec(42, 1, "curl", "/usr/bin/curl");
    /* pid matches but not comm */
    event_t pid_only  = make_exec(42, 1, "wget", "/usr/bin/wget");
    /* comm matches but not pid */
    event_t comm_only = make_exec(99, 1, "curl", "/usr/bin/curl");

    ASSERT_EQ(event_matches(&both),      1);
    ASSERT_EQ(event_matches(&pid_only),  0);
    ASSERT_EQ(event_matches(&comm_only), 0);
}

/* ── no filter (pass all) ───────────────────────────────────────────────── */

static void test_no_filter(void)
{
    filter_t f = {0};
    f.event_mask = TRACE_ALL;
    output_init(OUTPUT_TEXT, &f);

    event_t e1 = make_exec(1, 0, "init", "/sbin/init");
    event_t e2 = make_open(9999, "/var/log/syslog");
    ASSERT_EQ(event_matches(&e1), 1);
    ASSERT_EQ(event_matches(&e2), 1);
}

int main(void)
{
    test_pid_filter();
    test_comm_filter();
    test_path_filter();
    test_exclude_paths();
    test_event_mask();
    test_combined_filters();
    test_no_filter();
    TEST_SUMMARY();
}
