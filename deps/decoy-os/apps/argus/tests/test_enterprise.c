/*
 * test_enterprise.c — unit tests for enterprise modules and event types
 * added in v0.4.0.
 *
 * Tests that can run without root, BPF, or network access:
 *   1. Output formatting of EVENT_TLS_DATA and EVENT_HEARTBEAT (text/json/cef)
 *   2. event_to_json() for the same events
 *   3. compliance_init / compliance_record_event / compliance_write_report
 *      (writes a temp HTML file and verifies it is non-empty)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/output.h"
#include "../src/argus.h"
#include "../src/compliance.h"
#include "framework.h"

/* ── helpers ──────────────────────────────────────────────────────────────── */

static event_t make_tls_data(void)
{
    event_t e = {0};
    e.type = EVENT_TLS_DATA;
    e.pid  = 1234;
    e.ppid = 1;
    e.uid  = 1000;
    strncpy(e.comm, "curl", sizeof(e.comm) - 1);
    e.tls_payload_len = 32;
    memset(e.tls_payload, 'X', 32);
    return e;
}

static event_t make_heartbeat(void)
{
    event_t e = {0};
    e.type = EVENT_HEARTBEAT;
    e.pid  = 100;
    e.ppid = 1;
    e.uid  = 0;
    strncpy(e.comm, "argus", sizeof(e.comm) - 1);
    return e;
}

/* ── output format tests ─────────────────────────────────────────────────── */

/*
 * Redirect output to a temp buffer via a pipe, call print_event, then
 * verify the output contains the expected substring.
 */
static int captures_event(output_fmt_t fmt, event_t *e, const char *needle)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) return 0;

    FILE *wf = fdopen(pipefd[1], "w");
    if (!wf) { close(pipefd[0]); close(pipefd[1]); return 0; }

    filter_t f = {0};
    f.event_mask = ~0;   /* allow all events */
    output_init(fmt, &f);
    output_set_file(wf);
    print_event(e);
    fflush(wf);
    fclose(wf);   /* closes pipefd[1] */

    char buf[4096] = {};
    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    close(pipefd[0]);
    output_fini();

    if (n <= 0) return 0;
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

static void test_tls_data_text(void)
{
    event_t e = make_tls_data();
    ASSERT_TRUE(captures_event(OUTPUT_TEXT, &e, "tls_len=32"));
}

static void test_tls_data_json(void)
{
    event_t e = make_tls_data();
    ASSERT_TRUE(captures_event(OUTPUT_JSON, &e, "\"type\":\"TLS_DATA\""));
    ASSERT_TRUE(captures_event(OUTPUT_JSON, &e, "\"tls_payload_len\":32"));
}

static void test_tls_data_cef(void)
{
    event_t e = make_tls_data();
    ASSERT_TRUE(captures_event(OUTPUT_CEF, &e, "TLS_DATA"));
    ASSERT_TRUE(captures_event(OUTPUT_CEF, &e, "cn1Label=tls_len"));
}

static void test_heartbeat_text(void)
{
    event_t e = make_heartbeat();
    /* HEARTBEAT events must not crash; they emit only common fields */
    ASSERT_TRUE(captures_event(OUTPUT_TEXT, &e, "HEARTBEAT"));
}

static void test_heartbeat_json(void)
{
    event_t e = make_heartbeat();
    ASSERT_TRUE(captures_event(OUTPUT_JSON, &e, "\"type\":\"HEARTBEAT\""));
}

static void test_heartbeat_cef(void)
{
    event_t e = make_heartbeat();
    ASSERT_TRUE(captures_event(OUTPUT_CEF, &e, "HEARTBEAT"));
}

/* ── event_to_json() ─────────────────────────────────────────────────────── */

static void test_event_to_json_tls_data(void)
{
    event_t e = make_tls_data();
    char buf[2048];
    size_t n = event_to_json(&e, buf, sizeof(buf));
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(strstr(buf, "\"type\":\"TLS_DATA\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"tls_payload_len\":32") != NULL);
}

static void test_event_to_json_heartbeat(void)
{
    event_t e = make_heartbeat();
    char buf[2048];
    size_t n = event_to_json(&e, buf, sizeof(buf));
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(strstr(buf, "\"type\":\"HEARTBEAT\"") != NULL);
}

/* ── compliance module ───────────────────────────────────────────────────── */

static void test_compliance_pci_dss(void)
{
    char tmp[] = "/tmp/argus_compliance_XXXXXX.html";
    /* mkstemps generates a unique path */
    int fd = mkstemps(tmp, 5);
    if (fd < 0) { ASSERT_TRUE(0); return; }
    close(fd);

    compliance_init(COMPLIANCE_PCI_DSS, tmp);

    /* Record a mix of event types */
    event_t exec_e = {0};
    exec_e.type = EVENT_EXEC;
    exec_e.pid = 100;
    strncpy(exec_e.comm, "bash", sizeof(exec_e.comm) - 1);
    compliance_record_event(&exec_e);

    event_t priv_e = {0};
    priv_e.type = EVENT_PRIVESC;
    priv_e.pid  = 200;
    strncpy(priv_e.comm, "sudo", sizeof(priv_e.comm) - 1);
    compliance_record_event(&priv_e);
    compliance_record_alert(&priv_e, "priv_esc", "HIGH");

    int rc = compliance_write_report();
    ASSERT_EQ(rc, 0);
    compliance_destroy();

    /* Report file should be non-empty and contain "PCI" */
    FILE *f = fopen(tmp, "r");
    ASSERT_TRUE(f != NULL);
    if (f) {
        char buf[256];
        int found = 0;
        while (fgets(buf, sizeof(buf), f)) {
            if (strstr(buf, "PCI") || strstr(buf, "pci")) { found = 1; break; }
        }
        fclose(f);
        ASSERT_TRUE(found);
    }
    unlink(tmp);
}

static void test_compliance_nist_csf(void)
{
    char tmp[] = "/tmp/argus_nist_XXXXXX.html";
    int fd = mkstemps(tmp, 5);
    if (fd < 0) { ASSERT_TRUE(0); return; }
    close(fd);

    compliance_init(COMPLIANCE_NIST_CSF, tmp);

    event_t e = {0};
    e.type = EVENT_KMOD_LOAD;
    strncpy(e.comm,     "insmod",   sizeof(e.comm) - 1);
    strncpy(e.filename, "evil.ko",  sizeof(e.filename) - 1);
    compliance_record_event(&e);

    ASSERT_EQ(compliance_write_report(), 0);
    compliance_destroy();
    unlink(tmp);
}

static void test_compliance_cis(void)
{
    char tmp[] = "/tmp/argus_cis_XXXXXX.html";
    int fd = mkstemps(tmp, 5);
    if (fd < 0) { ASSERT_TRUE(0); return; }
    close(fd);

    compliance_init(COMPLIANCE_CIS_LINUX, tmp);

    event_t e = {0};
    e.type = EVENT_TLS_SNI;
    strncpy(e.comm,     "curl",    sizeof(e.comm) - 1);
    strncpy(e.dns_name, "bad.host", sizeof(e.dns_name) - 1);
    compliance_record_event(&e);

    ASSERT_EQ(compliance_write_report(), 0);
    compliance_destroy();
    unlink(tmp);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    /* Output formatting */
    test_tls_data_text();
    test_tls_data_json();
    test_tls_data_cef();
    test_heartbeat_text();
    test_heartbeat_json();
    test_heartbeat_cef();

    /* JSON serialiser */
    test_event_to_json_tls_data();
    test_event_to_json_heartbeat();

    /* Compliance */
    test_compliance_pci_dss();
    test_compliance_nist_csf();
    test_compliance_cis();

    TEST_SUMMARY();
}
