/*
 * test_baseline.c — unit tests for baseline.c
 *
 * Tests cover:
 *  - baseline_learn_init() argument validation
 *  - baseline_learn() accumulates EXEC / OPEN / CONNECT events
 *  - baseline_flush() writes a valid JSON profile
 *  - baseline_load() reads the profile back
 *  - baseline_check() distinguishes known vs. anomalous events
 *  - round-trip: learn → flush → load → check
 *  - baseline_free() resets all state
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../src/baseline.h"
#include "../src/output.h"
#include "../src/argus.h"
#include "framework.h"

/* ── helpers ─────────────────────────────────────────────────────────────── */

static event_t make_exec(const char *comm, const char *file)
{
    event_t e = {0};
    e.type    = EVENT_EXEC;
    e.pid     = 100; e.ppid = 1;
    e.success = 1;
    strncpy(e.comm,     comm, sizeof(e.comm) - 1);
    strncpy(e.filename, file, sizeof(e.filename) - 1);
    return e;
}

static event_t make_open(const char *comm, const char *path, int success)
{
    event_t e = {0};
    e.type    = EVENT_OPEN;
    e.pid     = 100; e.ppid = 1;
    e.success = success;
    strncpy(e.comm,     comm, sizeof(e.comm) - 1);
    strncpy(e.filename, path, sizeof(e.filename) - 1);
    return e;
}

static event_t make_connect(const char *comm, const char *ipv4, uint16_t port)
{
    event_t e = {0};
    e.type    = EVENT_CONNECT;
    e.pid     = 100; e.ppid = 1;
    e.success = 1;
    e.family  = 2;   /* AF_INET */
    e.dport   = port;
    strncpy(e.comm, comm, sizeof(e.comm) - 1);
    inet_pton(AF_INET, ipv4, e.daddr);
    return e;
}

/* Write to a temp file, return malloc'd path (caller frees) */
static char *tmp_path(void)
{
    char *p = strdup("/tmp/argus_bl_test_XXXXXX");
    int fd = mkstemp(p);
    if (fd >= 0) close(fd);
    return p;
}

/* ── baseline_learn_init error cases ─────────────────────────────────────── */

static void test_learn_init_null_path(void)
{
    ASSERT_EQ(baseline_learn_init(NULL, 60), -1);
}

static void test_learn_init_zero_secs(void)
{
    ASSERT_EQ(baseline_learn_init("/tmp/bl.json", 0), -1);
}

static void test_learn_init_negative_secs(void)
{
    ASSERT_EQ(baseline_learn_init("/tmp/bl.json", -1), -1);
}

static void test_learn_init_valid(void)
{
    ASSERT_EQ(baseline_learn_init("/tmp/bl.json", 60), 0);
    ASSERT_EQ(baseline_learning(), 1);
    baseline_free();
}

/* ── baseline_learning() ─────────────────────────────────────────────────── */

static void test_learning_false_before_init(void)
{
    baseline_free();
    ASSERT_EQ(baseline_learning(), 0);
}

static void test_learning_true_after_init(void)
{
    ASSERT_EQ(baseline_learn_init("/tmp/bl.json", 3600), 0);
    ASSERT_EQ(baseline_learning(), 1);
    baseline_free();
}

/* ── baseline_learn() accumulates events ─────────────────────────────────── */

static void test_learn_accumulates_exec(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);

    event_t e = make_exec("nginx", "/usr/sbin/nginx");
    baseline_learn(&e);

    /* Flush and reload — exec_targets must contain the filename */
    baseline_flush();
    int n = baseline_load(path);
    ASSERT_TRUE(n > 0);

    /* Known exec target → no anomaly */
    event_t chk = make_exec("nginx", "/usr/sbin/nginx");
    ASSERT_EQ(baseline_check(&chk), 0);

    /* Unknown exec target → anomaly */
    event_t unk = make_exec("nginx", "/tmp/malware");
    ASSERT_EQ(baseline_check(&unk), 1);

    baseline_free();
    unlink(path);
    free(path);
}

static void test_learn_accumulates_open(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);

    event_t e = make_open("sshd", "/etc/ssh/sshd_config", 1);
    baseline_learn(&e);

    /* Failed opens should NOT be learnt */
    event_t fail = make_open("sshd", "/etc/shadow", 0);
    baseline_learn(&fail);

    baseline_flush();
    int n = baseline_load(path);
    ASSERT_TRUE(n > 0);

    /* Known open path → no anomaly */
    event_t chk = make_open("sshd", "/etc/ssh/sshd_config", 1);
    ASSERT_EQ(baseline_check(&chk), 0);

    /* Failed-open path was not learnt — should not trigger anomaly */
    event_t chk2 = make_open("sshd", "/etc/shadow", 1);
    ASSERT_EQ(baseline_check(&chk2), 1);

    baseline_free();
    unlink(path);
    free(path);
}

static void test_learn_accumulates_connect(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);

    event_t e = make_connect("curl", "93.184.216.34", 443);
    baseline_learn(&e);

    baseline_flush();
    int n = baseline_load(path);
    ASSERT_TRUE(n > 0);

    /* Known destination → no anomaly */
    event_t chk = make_connect("curl", "93.184.216.34", 443);
    ASSERT_EQ(baseline_check(&chk), 0);

    /* Different port → anomaly */
    event_t unk = make_connect("curl", "93.184.216.34", 4444);
    ASSERT_EQ(baseline_check(&unk), 1);

    /* Different IP → anomaly */
    event_t unk2 = make_connect("curl", "198.51.100.1", 443);
    ASSERT_EQ(baseline_check(&unk2), 1);

    baseline_free();
    unlink(path);
    free(path);
}

/* ── baseline_flush() writes valid JSON ──────────────────────────────────── */

static void test_flush_writes_json(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);

    event_t e1 = make_exec("bash", "/bin/ls");
    event_t e2 = make_open("bash", "/etc/hosts", 1);
    baseline_learn(&e1);
    baseline_learn(&e2);
    baseline_flush();

    /* File must exist and start with {"version":1 */
    FILE *f = fopen(path, "r");
    ASSERT_TRUE(f != NULL);
    char buf[256] = {};
    fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    ASSERT_TRUE(strstr(buf, "\"version\":1") != NULL);
    ASSERT_TRUE(strstr(buf, "\"bash\"")      != NULL);
    ASSERT_TRUE(strstr(buf, "/bin/ls")       != NULL);
    ASSERT_TRUE(strstr(buf, "/etc/hosts")    != NULL);

    /* baseline_learning() must be 0 after flush */
    ASSERT_EQ(baseline_learning(), 0);

    baseline_free();
    unlink(path);
    free(path);
}

/* ── baseline_load() ─────────────────────────────────────────────────────── */

static void test_load_null_path(void)
{
    ASSERT_EQ(baseline_load(NULL), -1);
}

static void test_load_nonexistent(void)
{
    ASSERT_EQ(baseline_load("/tmp/argus_nonexistent_bl_987654.json"), -1);
}

static void test_load_returns_comm_count(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);

    /* Create 3 distinct comms */
    baseline_learn(&(event_t){ .type = EVENT_EXEC, .success = 1,
        .comm = "a", .filename = "/bin/a" });
    baseline_learn(&(event_t){ .type = EVENT_EXEC, .success = 1,
        .comm = "b", .filename = "/bin/b" });
    baseline_learn(&(event_t){ .type = EVENT_EXEC, .success = 1,
        .comm = "c", .filename = "/bin/c" });
    baseline_flush();

    int n = baseline_load(path);
    ASSERT_EQ(n, 3);

    baseline_free();
    unlink(path);
    free(path);
}

/* ── baseline_check() ────────────────────────────────────────────────────── */

static void test_check_not_detecting_returns_0(void)
{
    baseline_free();  /* ensure clean state */
    event_t e = make_exec("bash", "/tmp/malware");
    ASSERT_EQ(baseline_check(&e), 0);
}

static void test_check_unknown_comm_returns_0(void)
{
    /* A comm not in the profile → no opinion (return 0) */
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);
    baseline_learn(&(event_t){ .type = EVENT_EXEC, .success = 1,
        .comm = "known_comm", .filename = "/bin/x" });
    baseline_flush();
    baseline_load(path);

    event_t e = make_exec("unknown_comm", "/tmp/malware");
    ASSERT_EQ(baseline_check(&e), 0);

    baseline_free();
    unlink(path);
    free(path);
}

static void test_check_known_exec_returns_0(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);
    baseline_learn(&(event_t){ .type = EVENT_EXEC, .success = 1,
        .comm = "nginx", .filename = "/usr/sbin/nginx" });
    baseline_flush();
    baseline_load(path);

    event_t e = make_exec("nginx", "/usr/sbin/nginx");
    ASSERT_EQ(baseline_check(&e), 0);

    baseline_free();
    unlink(path);
    free(path);
}

static void test_check_anomalous_exec_returns_1(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);
    baseline_learn(&(event_t){ .type = EVENT_EXEC, .success = 1,
        .comm = "nginx", .filename = "/usr/sbin/nginx" });
    baseline_flush();
    baseline_load(path);

    event_t e = make_exec("nginx", "/tmp/backdoor");
    ASSERT_EQ(baseline_check(&e), 1);

    baseline_free();
    unlink(path);
    free(path);
}

/* ── baseline_free() resets state ────────────────────────────────────────── */

static void test_free_resets_state(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);
    ASSERT_EQ(baseline_learning(), 1);

    baseline_free();
    ASSERT_EQ(baseline_learning(), 0);

    /* After free, check returns 0 (not detecting) */
    event_t e = make_exec("nginx", "/tmp/backdoor");
    ASSERT_EQ(baseline_check(&e), 0);

    unlink(path);
    free(path);
}

/* ── full round-trip ─────────────────────────────────────────────────────── */

static void test_round_trip(void)
{
    char *path = tmp_path();

    /* 1. Learn */
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);

    event_t exec1  = make_exec("curl", "/usr/bin/curl");
    event_t open1  = make_open("curl", "/etc/ssl/certs/ca-certificates.crt", 1);
    event_t conn1  = make_connect("curl", "93.184.216.34", 443);
    baseline_learn(&exec1);
    baseline_learn(&open1);
    baseline_learn(&conn1);

    /* 2. Flush */
    baseline_flush();
    ASSERT_EQ(baseline_learning(), 0);

    /* 3. Load */
    int n = baseline_load(path);
    ASSERT_EQ(n, 1);  /* one comm: "curl" */

    /* 4. Check — known entries */
    ASSERT_EQ(baseline_check(&exec1), 0);
    ASSERT_EQ(baseline_check(&open1), 0);
    ASSERT_EQ(baseline_check(&conn1), 0);

    /* 5. Check — anomalies */
    event_t bad_exec = make_exec("curl", "/tmp/sh");
    ASSERT_EQ(baseline_check(&bad_exec), 1);

    event_t bad_open = make_open("curl", "/etc/shadow", 1);
    ASSERT_EQ(baseline_check(&bad_open), 1);

    event_t bad_conn = make_connect("curl", "198.51.100.5", 4444);
    ASSERT_EQ(baseline_check(&bad_conn), 1);

    baseline_free();
    unlink(path);
    free(path);
}

/* ── rolling merge tests ─────────────────────────────────────────────────── */

/*
 * Build a profile with one known exec, then call baseline_check() for an
 * anomalous exec N times and verify:
 *   - First N-1 calls return 1 (anomaly)
 *   - Nth call returns 0 (merged silently)
 *   - Subsequent calls return 0 (now in profile)
 */
static void test_merge_after_fires_then_merges(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);

    event_t known = make_exec("nginx", "/usr/sbin/nginx");
    baseline_learn(&known);
    baseline_flush();

    baseline_set_merge_after(3);
    int n = baseline_load(path);
    ASSERT_TRUE(n > 0);

    event_t anomaly = make_exec("nginx", "/tmp/injected");

    /* Redirect anomaly output so it doesn't clutter the test run */
    FILE *devnull = fopen("/dev/null", "w");
    output_set_file(devnull);

    /* Sightings 1 and 2 → still anomalous */
    ASSERT_EQ(baseline_check(&anomaly), 1);
    ASSERT_EQ(baseline_check(&anomaly), 1);

    /* Sighting 3 → merge threshold reached, no longer anomalous */
    ASSERT_EQ(baseline_check(&anomaly), 0);

    /* Further checks → in profile now */
    ASSERT_EQ(baseline_check(&anomaly), 0);
    ASSERT_EQ(baseline_check(&anomaly), 0);

    output_set_file(NULL);
    if (devnull) fclose(devnull);
    baseline_free();
    unlink(path);
    free(path);
}

/* merge_after=1: first sighting silently merges (never fires an anomaly) */
static void test_merge_after_one(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);
    baseline_learn(&(event_t){ .type = EVENT_EXEC, .success = 1,
        .comm = "sshd", .filename = "/usr/sbin/sshd" });
    baseline_flush();

    baseline_set_merge_after(1);
    baseline_load(path);

    event_t anomaly = make_exec("sshd", "/tmp/sshd_backdoor");

    FILE *devnull = fopen("/dev/null", "w");
    output_set_file(devnull);

    /* First sighting — merge_after=1 means merge immediately → returns 0 */
    ASSERT_EQ(baseline_check(&anomaly), 0);
    /* Already in profile */
    ASSERT_EQ(baseline_check(&anomaly), 0);

    output_set_file(NULL);
    if (devnull) fclose(devnull);
    baseline_free();
    unlink(path);
    free(path);
}

/* merge_after=0 (disabled): anomalies fire indefinitely */
static void test_merge_after_zero_disabled(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);
    baseline_learn(&(event_t){ .type = EVENT_EXEC, .success = 1,
        .comm = "bash", .filename = "/bin/bash" });
    baseline_flush();

    baseline_set_merge_after(0);   /* disabled */
    baseline_load(path);

    event_t anomaly = make_exec("bash", "/tmp/malicious");

    FILE *devnull = fopen("/dev/null", "w");
    output_set_file(devnull);

    /* Should always return 1, never merge */
    ASSERT_EQ(baseline_check(&anomaly), 1);
    ASSERT_EQ(baseline_check(&anomaly), 1);
    ASSERT_EQ(baseline_check(&anomaly), 1);
    ASSERT_EQ(baseline_check(&anomaly), 1);
    ASSERT_EQ(baseline_check(&anomaly), 1);

    output_set_file(NULL);
    if (devnull) fclose(devnull);
    baseline_free();
    unlink(path);
    free(path);
}

/* Different anomaly values accumulate separately */
static void test_merge_after_independent_values(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);
    baseline_learn(&(event_t){ .type = EVENT_EXEC, .success = 1,
        .comm = "curl", .filename = "/usr/bin/curl" });
    baseline_flush();

    baseline_set_merge_after(2);
    baseline_load(path);

    event_t a1 = make_exec("curl", "/tmp/evil1");
    event_t a2 = make_exec("curl", "/tmp/evil2");

    FILE *devnull = fopen("/dev/null", "w");
    output_set_file(devnull);

    /* a1 sighting 1 → anomaly */
    ASSERT_EQ(baseline_check(&a1), 1);
    /* a2 sighting 1 → anomaly (independent counter) */
    ASSERT_EQ(baseline_check(&a2), 1);
    /* a1 sighting 2 → merged */
    ASSERT_EQ(baseline_check(&a1), 0);
    /* a2 sighting 2 → merged */
    ASSERT_EQ(baseline_check(&a2), 0);
    /* both now in profile */
    ASSERT_EQ(baseline_check(&a1), 0);
    ASSERT_EQ(baseline_check(&a2), 0);

    output_set_file(NULL);
    if (devnull) fclose(devnull);
    baseline_free();
    unlink(path);
    free(path);
}

/* baseline_free() clears sighting counts — after reload merge starts fresh */
static void test_merge_sights_reset_on_free(void)
{
    char *path = tmp_path();
    ASSERT_EQ(baseline_learn_init(path, 3600), 0);
    baseline_learn(&(event_t){ .type = EVENT_EXEC, .success = 1,
        .comm = "wget", .filename = "/usr/bin/wget" });
    baseline_flush();

    baseline_set_merge_after(3);
    baseline_load(path);

    event_t anomaly = make_exec("wget", "/tmp/malware");

    FILE *devnull = fopen("/dev/null", "w");
    output_set_file(devnull);

    /* Two sightings — not yet merged */
    ASSERT_EQ(baseline_check(&anomaly), 1);
    ASSERT_EQ(baseline_check(&anomaly), 1);

    /* Free and reload — sighting count resets */
    baseline_free();
    baseline_set_merge_after(3);
    baseline_load(path);

    /* Must be anomalous again (count reset to 0) */
    ASSERT_EQ(baseline_check(&anomaly), 1);

    output_set_file(NULL);
    if (devnull) fclose(devnull);
    baseline_free();
    unlink(path);
    free(path);
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void)
{
    /* Use text output so emit_anomaly() goes to stderr and doesn't clutter */
    output_init(OUTPUT_TEXT, NULL);

    /* learn_init validation */
    test_learn_init_null_path();
    test_learn_init_zero_secs();
    test_learn_init_negative_secs();
    test_learn_init_valid();

    /* baseline_learning */
    test_learning_false_before_init();
    test_learning_true_after_init();

    /* learn accumulation */
    test_learn_accumulates_exec();
    test_learn_accumulates_open();
    test_learn_accumulates_connect();

    /* flush */
    test_flush_writes_json();

    /* load */
    test_load_null_path();
    test_load_nonexistent();
    test_load_returns_comm_count();

    /* check */
    test_check_not_detecting_returns_0();
    test_check_unknown_comm_returns_0();
    test_check_known_exec_returns_0();
    test_check_anomalous_exec_returns_1();

    /* free */
    test_free_resets_state();

    /* round-trip */
    test_round_trip();

    /* rolling merge */
    test_merge_after_fires_then_merges();
    test_merge_after_one();
    test_merge_after_zero_disabled();
    test_merge_after_independent_values();
    test_merge_sights_reset_on_free();

    TEST_SUMMARY();
}
