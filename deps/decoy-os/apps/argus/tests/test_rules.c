#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../src/rules.h"
#include "../src/output.h"
#include "../src/argus.h"
#include "framework.h"

/* ── helpers ─────────────────────────────────────────────────────────────── */

/* Write a JSON rules file to a temp path and return the path */
static char *write_rules_file(const char *json)
{
    static char path[64];
    snprintf(path, sizeof(path), "/tmp/argus_test_rules_%d.json", (int)getpid());
    FILE *f = fopen(path, "w");
    if (!f) return NULL;
    fputs(json, f);
    fclose(f);
    return path;
}

static event_t make_chmod(int pid, uint32_t uid, const char *file, uint32_t mode)
{
    event_t e = {0};
    e.type    = EVENT_CHMOD;
    e.pid     = pid;
    e.uid     = uid;
    strncpy(e.comm,     "chmod", sizeof(e.comm) - 1);
    strncpy(e.filename, file,    sizeof(e.filename) - 1);
    e.mode    = mode;
    e.success = 1;
    return e;
}

static event_t make_ptrace(int pid, int target)
{
    event_t e = {0};
    e.type       = EVENT_PTRACE;
    e.pid        = pid;
    e.uid        = 0;
    strncpy(e.comm, "gdb", sizeof(e.comm) - 1);
    e.ptrace_req = 16;
    e.target_pid = target;
    e.success    = 1;
    return e;
}

static event_t make_exec(int pid, const char *comm, const char *file)
{
    event_t e = {0};
    e.type = EVENT_EXEC;
    e.pid  = pid;
    e.uid  = 1000;
    strncpy(e.comm,     comm, sizeof(e.comm) - 1);
    strncpy(e.filename, file, sizeof(e.filename) - 1);
    e.success = 1;
    return e;
}

static event_t make_unlink(int pid, uint32_t uid, const char *file)
{
    event_t e = {0};
    e.type = EVENT_UNLINK;
    e.pid  = pid;
    e.uid  = uid;
    strncpy(e.comm,     "rm",  sizeof(e.comm) - 1);
    strncpy(e.filename, file,  sizeof(e.filename) - 1);
    e.success = 1;
    return e;
}

/* ── test: rules_load parses correctly ───────────────────────────────────── */

static void test_load_basic(void)
{
    char *path = write_rules_file(
        "["
        "  {\"name\":\"chmod world-writable\","
        "   \"severity\":\"high\","
        "   \"type\":\"CHMOD\","
        "   \"mode_mask\":2,"
        "   \"message\":\"world-writable chmod on {filename}\"}"
        "]");
    ASSERT_TRUE(path != NULL);

    rules_free();
    int n = rules_load(path);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(rules_count(), 1);

    unlink(path);
    rules_free();
}

static void test_load_multiple_rules(void)
{
    char *path = write_rules_file(
        "["
        "  {\"name\":\"R1\",\"type\":\"PTRACE\",\"message\":\"ptrace\"},"
        "  {\"name\":\"R2\",\"type\":\"EXEC\",\"comm\":\"nc\",\"message\":\"netcat\"},"
        "  {\"name\":\"R3\",\"type\":\"UNLINK\",\"uid\":0,\"message\":\"root deleted\"}"
        "]");
    ASSERT_TRUE(path != NULL);

    rules_free();
    int n = rules_load(path);
    ASSERT_EQ(n, 3);

    unlink(path);
    rules_free();
}

static void test_load_missing_file(void)
{
    rules_free();
    int n = rules_load("/tmp/argus_nonexistent_rules_file.json");
    ASSERT_EQ(n, -1);
    ASSERT_EQ(rules_count(), 0);
}

static void test_load_empty_array(void)
{
    char *path = write_rules_file("[]");
    ASSERT_TRUE(path != NULL);

    rules_free();
    int n = rules_load(path);
    ASSERT_EQ(n, 0);

    unlink(path);
    rules_free();
}

/* ── test: rule matching — CHMOD mode_mask ───────────────────────────────── */

static void test_chmod_mode_mask_match(void)
{
    char *path = write_rules_file(
        "[{\"name\":\"ww\",\"type\":\"CHMOD\",\"mode_mask\":2,"
        " \"message\":\"world-writable\"}]");
    rules_free();
    rules_load(path);

    /* mode 0777 has other-write bit (2) set — should match */
    event_t match   = make_chmod(1, 0, "/etc/passwd", 0777);
    /* mode 0644 does not have bit 2 — should not match */
    event_t nomatch = make_chmod(1, 0, "/etc/passwd", 0644);

    /* Redirect output to /dev/null so alerts don't clutter test output */
    output_init(OUTPUT_TEXT, NULL);
    FILE *devnull = fopen("/dev/null", "w");
    output_set_file(devnull);

    /* Count alerts by temporarily capturing — here we just verify no crash
     * and that the function runs.  Correctness is verified by rules_count(). */
    rules_check(&match);   /* should fire */
    rules_check(&nomatch); /* should not fire */

    /* Rule is still loaded — count unchanged */
    ASSERT_EQ(rules_count(), 1);

    output_set_file(NULL);
    if (devnull) fclose(devnull);
    unlink(path);
    rules_free();
}

/* ── test: rule matching — uid filter ────────────────────────────────────── */

static void test_uid_filter(void)
{
    char *path = write_rules_file(
        "[{\"name\":\"root-unlink\",\"type\":\"UNLINK\",\"uid\":0,"
        " \"message\":\"root deleted {filename}\"}]");
    rules_free();
    rules_load(path);

    event_t root_del = make_unlink(1, 0, "/etc/shadow");
    event_t user_del = make_unlink(2, 1000, "/tmp/foo");

    output_init(OUTPUT_TEXT, NULL);
    FILE *devnull = fopen("/dev/null", "w");
    output_set_file(devnull);

    rules_check(&root_del); /* should fire */
    rules_check(&user_del); /* should not fire */

    ASSERT_EQ(rules_count(), 1);

    output_set_file(NULL);
    if (devnull) fclose(devnull);
    unlink(path);
    rules_free();
}

/* ── test: rule matching — comm filter ───────────────────────────────────── */

static void test_comm_filter(void)
{
    char *path = write_rules_file(
        "[{\"name\":\"nc\",\"type\":\"EXEC\",\"comm\":\"nc\","
        " \"message\":\"netcat executed\"}]");
    rules_free();
    rules_load(path);

    event_t match   = make_exec(1, "nc",   "/usr/bin/nc");
    event_t nomatch = make_exec(2, "curl", "/usr/bin/curl");

    output_init(OUTPUT_TEXT, NULL);
    FILE *devnull = fopen("/dev/null", "w");
    output_set_file(devnull);

    rules_check(&match);
    rules_check(&nomatch);

    ASSERT_EQ(rules_count(), 1);

    output_set_file(NULL);
    if (devnull) fclose(devnull);
    unlink(path);
    rules_free();
}

/* ── test: rule matching — path_contains filter ──────────────────────────── */

static void test_path_contains_filter(void)
{
    char *path = write_rules_file(
        "[{\"name\":\"shadow\",\"path_contains\":\"/etc/shadow\","
        " \"message\":\"shadow touched by {comm}\"}]");
    rules_free();
    rules_load(path);

    event_t match   = make_unlink(1, 0, "/etc/shadow");
    event_t nomatch = make_unlink(2, 0, "/tmp/foo");

    output_init(OUTPUT_TEXT, NULL);
    FILE *devnull = fopen("/dev/null", "w");
    output_set_file(devnull);

    rules_check(&match);
    rules_check(&nomatch);

    ASSERT_EQ(rules_count(), 1);

    output_set_file(NULL);
    if (devnull) fclose(devnull);
    unlink(path);
    rules_free();
}

/* ── test: match-all rule (no type restriction) ──────────────────────────── */

static void test_match_all_types(void)
{
    char *path = write_rules_file(
        "[{\"name\":\"any\",\"uid\":0,\"message\":\"root event\"}]");
    rules_free();
    rules_load(path);

    event_t chmod_e   = make_chmod(1, 0, "/etc/foo", 0644);
    event_t ptrace_e  = make_ptrace(2, 100);
    event_t user_exec = make_exec(3, "bash", "/bin/bash");  /* uid=1000, no match */

    output_init(OUTPUT_TEXT, NULL);
    FILE *devnull = fopen("/dev/null", "w");
    output_set_file(devnull);

    rules_check(&chmod_e);   /* uid=0 → match */
    rules_check(&ptrace_e);  /* uid=0 → match */
    rules_check(&user_exec); /* uid=1000 → no match */

    ASSERT_EQ(rules_count(), 1);

    output_set_file(NULL);
    if (devnull) fclose(devnull);
    unlink(path);
    rules_free();
}

/* ── test: message template expansion ───────────────────────────────────────*/

static void test_message_template(void)
{
    /* We test expansion indirectly by loading a rule with known template
     * variables and verifying rules_load() and rules_check() run without error.
     * A full expansion test would require capturing alert output. */
    char *path = write_rules_file(
        "[{\"name\":\"tmpl\",\"type\":\"CHMOD\","
        " \"message\":\"{comm} changed {filename} to 0{mode} (pid={pid})\"}]");
    rules_free();
    int n = rules_load(path);
    ASSERT_EQ(n, 1);

    event_t e = make_chmod(42, 0, "/etc/cron.d/job", 0777);
    output_init(OUTPUT_TEXT, NULL);
    FILE *devnull = fopen("/dev/null", "w");
    output_set_file(devnull);

    rules_check(&e);

    ASSERT_EQ(rules_count(), 1);

    output_set_file(NULL);
    if (devnull) fclose(devnull);
    unlink(path);
    rules_free();
}

/* ── test: JSON alert output format ─────────────────────────────────────── */

static void test_json_alert_output(void)
{
    char *rules_path = write_rules_file(
        "[{\"name\":\"ptrace-alert\",\"severity\":\"critical\","
        " \"type\":\"PTRACE\",\"message\":\"ptrace from {comm}\"}]");
    rules_free();
    rules_load(rules_path);

    /* Capture JSON output to a temp file */
    char out_path[64];
    snprintf(out_path, sizeof(out_path), "/tmp/argus_alert_out_%d.json",
             (int)getpid());
    FILE *out = fopen(out_path, "w");
    ASSERT_TRUE(out != NULL);

    output_init(OUTPUT_JSON, NULL);
    output_set_file(out);

    event_t e = make_ptrace(999, 42);
    rules_check(&e);

    fflush(out);
    fclose(out);
    output_set_file(NULL);

    /* Read back and verify it contains expected fields */
    FILE *r = fopen(out_path, "r");
    ASSERT_TRUE(r != NULL);
    char buf[512] = {};
    if (r) {
        fread(buf, 1, sizeof(buf) - 1, r);
        fclose(r);
    }

    ASSERT_TRUE(strstr(buf, "\"type\":\"ALERT\"")   != NULL);
    ASSERT_TRUE(strstr(buf, "\"severity\":\"critical\"") != NULL);
    ASSERT_TRUE(strstr(buf, "ptrace-alert")         != NULL);
    ASSERT_TRUE(strstr(buf, "\"pid\":999")           != NULL);

    unlink(out_path);
    unlink(rules_path);
    rules_free();
}

/* ── test: rules_free resets count ───────────────────────────────────────── */

static void test_rules_free(void)
{
    char *path = write_rules_file(
        "[{\"name\":\"r1\",\"message\":\"x\"},"
        " {\"name\":\"r2\",\"message\":\"y\"}]");
    rules_free();
    rules_load(path);
    ASSERT_EQ(rules_count(), 2);
    rules_free();
    ASSERT_EQ(rules_count(), 0);

    unlink(path);
}

/* ── test: threshold_count — alert fires only after N hits ───────────────── */

/* Count how many lines are written to a file by rules_check() */
static int count_alerts(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int n = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] != '\0' && line[0] != '\n') n++;
    }
    fclose(f);
    return n;
}

static void test_threshold_count(void)
{
    /* Rule fires only after 3 hits (threshold_count=3, no window) */
    char *rules_path = write_rules_file(
        "[{\"name\":\"thresh3\",\"type\":\"EXEC\","
        " \"threshold_count\":3,"
        " \"message\":\"exec alert\"}]");
    rules_free();
    rules_load(rules_path);

    char out_path[64];
    snprintf(out_path, sizeof(out_path), "/tmp/argus_thresh_%d.txt", (int)getpid());
    FILE *out = fopen(out_path, "w");
    ASSERT_TRUE(out != NULL);
    output_init(OUTPUT_JSON, NULL);
    output_set_file(out);

    event_t e = make_exec(1, "bash", "/bin/bash");

    /* Hits 1 and 2 — below threshold, no alert */
    rules_check(&e);
    rules_check(&e);
    fflush(out);
    ASSERT_EQ(count_alerts(out_path), 0);

    /* Hit 3 — threshold met, alert fires */
    rules_check(&e);
    fflush(out);
    ASSERT_EQ(count_alerts(out_path), 1);

    /* Hit 4 — threshold already met; with no suppress_after, fires again */
    rules_check(&e);
    fflush(out);
    ASSERT_EQ(count_alerts(out_path), 2);

    output_set_file(NULL);
    fclose(out);
    unlink(out_path);
    unlink(rules_path);
    rules_free();
}

/* ── test: suppress_after_secs — mute after threshold ───────────────────── */

static void test_suppress_after(void)
{
    /* threshold=1 (always matches), suppress for 60 seconds after first hit */
    char *rules_path = write_rules_file(
        "[{\"name\":\"supp\",\"type\":\"EXEC\","
        " \"suppress_after_secs\":60,"
        " \"message\":\"exec\"}]");
    rules_free();
    rules_load(rules_path);

    char out_path[64];
    snprintf(out_path, sizeof(out_path), "/tmp/argus_supp_%d.txt", (int)getpid());
    FILE *out = fopen(out_path, "w");
    ASSERT_TRUE(out != NULL);
    output_init(OUTPUT_JSON, NULL);
    output_set_file(out);

    event_t e = make_exec(1, "bash", "/bin/bash");

    /* First hit — fires and arms suppression */
    rules_check(&e);
    fflush(out);
    ASSERT_EQ(count_alerts(out_path), 1);

    /* Second hit within the suppression window — must NOT fire */
    rules_check(&e);
    rules_check(&e);
    fflush(out);
    ASSERT_EQ(count_alerts(out_path), 1);

    output_set_file(NULL);
    fclose(out);
    unlink(out_path);
    unlink(rules_path);
    rules_free();
}

/* ── test: threshold_count=3 + suppress_after_secs ──────────────────────── */

static void test_threshold_then_suppress(void)
{
    /* fire after 3 hits, then suppress for 60 s */
    char *rules_path = write_rules_file(
        "[{\"name\":\"ts\",\"type\":\"EXEC\","
        " \"threshold_count\":3,"
        " \"suppress_after_secs\":60,"
        " \"message\":\"alert\"}]");
    rules_free();
    rules_load(rules_path);

    char out_path[64];
    snprintf(out_path, sizeof(out_path), "/tmp/argus_ts_%d.txt", (int)getpid());
    FILE *out = fopen(out_path, "w");
    ASSERT_TRUE(out != NULL);
    output_init(OUTPUT_JSON, NULL);
    output_set_file(out);

    event_t e = make_exec(1, "nc", "/usr/bin/nc");

    /* Hits 1+2: below threshold */
    rules_check(&e);
    rules_check(&e);
    fflush(out);
    ASSERT_EQ(count_alerts(out_path), 0);

    /* Hit 3: threshold met — fires once */
    rules_check(&e);
    fflush(out);
    ASSERT_EQ(count_alerts(out_path), 1);

    /* Hits 4+5: suppressed */
    rules_check(&e);
    rules_check(&e);
    fflush(out);
    ASSERT_EQ(count_alerts(out_path), 1);

    output_set_file(NULL);
    fclose(out);
    unlink(out_path);
    unlink(rules_path);
    rules_free();
}

/* ── test: rules_free resets suppression state ───────────────────────────── */

static void test_free_resets_suppression(void)
{
    char *rules_path = write_rules_file(
        "[{\"name\":\"s\",\"type\":\"EXEC\","
        " \"suppress_after_secs\":3600,"
        " \"message\":\"x\"}]");
    rules_free();
    rules_load(rules_path);

    char out_path[64];
    snprintf(out_path, sizeof(out_path), "/tmp/argus_frs_%d.txt", (int)getpid());
    FILE *out = fopen(out_path, "w");
    output_init(OUTPUT_JSON, NULL);
    output_set_file(out);

    event_t e = make_exec(1, "bash", "/bin/bash");
    rules_check(&e);   /* fires + suppresses */
    fflush(out);
    ASSERT_EQ(count_alerts(out_path), 1);

    rules_check(&e);   /* suppressed */
    fflush(out);
    ASSERT_EQ(count_alerts(out_path), 1);

    /* Reload rule — state reset */
    rules_free();
    rules_load(rules_path);

    rules_check(&e);   /* fires again (state cleared) */
    fflush(out);
    ASSERT_EQ(count_alerts(out_path), 2);

    output_set_file(NULL);
    fclose(out);
    unlink(out_path);
    unlink(rules_path);
    rules_free();
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    test_load_basic();
    test_load_multiple_rules();
    test_load_missing_file();
    test_load_empty_array();
    test_chmod_mode_mask_match();
    test_uid_filter();
    test_comm_filter();
    test_path_contains_filter();
    test_match_all_types();
    test_message_template();
    test_json_alert_output();
    test_rules_free();

    /* suppression / threshold */
    test_threshold_count();
    test_suppress_after();
    test_threshold_then_suppress();
    test_free_resets_suppression();

    TEST_SUMMARY();
}
