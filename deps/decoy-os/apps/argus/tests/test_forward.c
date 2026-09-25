#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../src/forward.h"
#include "../src/output.h"
#include "../src/argus.h"
#include "framework.h"

/* ── forward_parse_addr tests ─────────────────────────────────────────────── */

static void test_parse_host_port(void)
{
    char host[64]; int port;
    ASSERT_EQ(forward_parse_addr("192.168.1.1:9000", host, sizeof(host), &port), 0);
    ASSERT_STR_EQ(host, "192.168.1.1");
    ASSERT_EQ(port, 9000);
}

static void test_parse_hostname_port(void)
{
    char host[64]; int port;
    ASSERT_EQ(forward_parse_addr("logserver.example.com:514", host, sizeof(host), &port), 0);
    ASSERT_STR_EQ(host, "logserver.example.com");
    ASSERT_EQ(port, 514);
}

static void test_parse_ipv6(void)
{
    char host[64]; int port;
    ASSERT_EQ(forward_parse_addr("[::1]:9000", host, sizeof(host), &port), 0);
    ASSERT_STR_EQ(host, "::1");
    ASSERT_EQ(port, 9000);
}

static void test_parse_ipv6_full(void)
{
    char host[64]; int port;
    ASSERT_EQ(forward_parse_addr("[2001:db8::1]:8514", host, sizeof(host), &port), 0);
    ASSERT_STR_EQ(host, "2001:db8::1");
    ASSERT_EQ(port, 8514);
}

static void test_parse_no_port(void)
{
    char host[64]; int port = 0;
    ASSERT_EQ(forward_parse_addr("192.168.1.1", host, sizeof(host), &port), -1);
}

static void test_parse_bad_port_zero(void)
{
    char host[64]; int port = 0;
    ASSERT_EQ(forward_parse_addr("host:0", host, sizeof(host), &port), -1);
}

static void test_parse_bad_port_overflow(void)
{
    char host[64]; int port = 0;
    ASSERT_EQ(forward_parse_addr("host:99999", host, sizeof(host), &port), -1);
}

static void test_parse_ipv6_missing_bracket(void)
{
    char host[64]; int port = 0;
    /* Missing closing bracket */
    ASSERT_EQ(forward_parse_addr("[::1:9000", host, sizeof(host), &port), -1);
}

static void test_parse_null(void)
{
    char host[64]; int port = 0;
    ASSERT_EQ(forward_parse_addr(NULL, host, sizeof(host), &port), -1);
}

static void test_parse_empty_host(void)
{
    char host[64]; int port = 0;
    ASSERT_EQ(forward_parse_addr(":9000", host, sizeof(host), &port), -1);
}

/* ── forward_init with bad args ───────────────────────────────────────────── */

static void test_init_null_host(void)
{
    ASSERT_EQ(forward_init(NULL, 9000), -1);
}

static void test_init_bad_port(void)
{
    ASSERT_EQ(forward_init("localhost", 0),      -1);
    ASSERT_EQ(forward_init("localhost", 99999),  -1);
    ASSERT_EQ(forward_init("localhost", -1),     -1);
}

static void test_init_unreachable_host(void)
{
    /* Should not crash or return an error — non-blocking connect to an
     * unreachable address returns EINPROGRESS so g_sock is set (in-progress).
     * The actual failure shows up later when send() fails.  We just verify
     * forward_init returns 0 (valid args) and forward_fini cleans up. */
    int r = forward_init("192.0.2.1", 9999);  /* TEST-NET — never routable */
    ASSERT_EQ(r, 0);                            /* args valid → returns 0 */
    forward_fini();                             /* must not crash */
    ASSERT_EQ(forward_connected(), 0);          /* fini closed it */
}

/* ── TCP server helper for end-to-end tests ──────────────────────────────── */

typedef struct {
    int    port;
    int    listen_fd;
    char   received[65536];
    size_t received_len;
    int    done;
} tcp_server_t;

static void *server_thread(void *arg)
{
    tcp_server_t *srv = arg;

    int client = accept(srv->listen_fd, NULL, NULL);
    if (client < 0) { srv->done = 1; return NULL; }

    ssize_t n;
    while ((n = read(client, srv->received + srv->received_len,
                     sizeof(srv->received) - srv->received_len - 1)) > 0) {
        srv->received_len += (size_t)n;
    }
    srv->received[srv->received_len] = '\0';
    close(client);
    srv->done = 1;
    return NULL;
}

static int start_server(tcp_server_t *srv)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;   /* kernel picks a free port */

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    listen(fd, 1);

    socklen_t addrlen = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &addrlen);
    srv->port       = ntohs(addr.sin_port);
    srv->listen_fd  = fd;
    srv->received_len = 0;
    srv->done       = 0;

    pthread_t tid;
    pthread_create(&tid, NULL, server_thread, srv);
    pthread_detach(tid);
    return 0;
}

/* ── end-to-end: forward_event sends JSON to TCP server ──────────────────── */

static event_t make_exec_event(int pid, const char *comm, const char *file)
{
    event_t e = {0};
    e.type    = EVENT_EXEC;
    e.pid     = pid;
    e.ppid    = 1;
    e.uid     = 1000;
    e.gid     = 1000;
    e.success = 1;
    strncpy(e.comm,     comm, sizeof(e.comm) - 1);
    strncpy(e.filename, file, sizeof(e.filename) - 1);
    strncpy(e.args,     "arg1 arg2", sizeof(e.args) - 1);
    return e;
}

static void test_forward_sends_json(void)
{
    tcp_server_t srv = {};
    if (start_server(&srv) != 0) {
        /* Can't start server — skip gracefully */
        ASSERT_TRUE(1);
        return;
    }

    char addr[32];
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", srv.port);

    char host[64]; int port;
    forward_parse_addr(addr, host, sizeof(host), &port);
    int r = forward_init(host, port);
    ASSERT_EQ(r, 0);

    /* Give the non-blocking connect time to complete */
    usleep(50000);

    output_init(OUTPUT_JSON, NULL);

    event_t e1 = make_exec_event(1234, "curl", "/usr/bin/curl");
    event_t e2 = make_exec_event(5678, "wget", "/usr/bin/wget");
    forward_event(&e1);
    forward_event(&e2);

    /* Flush and close — this triggers shutdown so server's read() returns EOF */
    forward_fini();

    /* Wait for server thread to finish reading */
    int waited = 0;
    while (!srv.done && waited < 2000) { usleep(10000); waited += 10; }

    close(srv.listen_fd);

    /* Verify two JSON lines were received */
    ASSERT_TRUE(srv.received_len > 0);
    ASSERT_TRUE(strstr(srv.received, "\"type\":\"EXEC\"")   != NULL);
    ASSERT_TRUE(strstr(srv.received, "\"comm\":\"curl\"")   != NULL);
    ASSERT_TRUE(strstr(srv.received, "\"comm\":\"wget\"")   != NULL);
    ASSERT_TRUE(strstr(srv.received, "\"pid\":1234")        != NULL);
    ASSERT_TRUE(strstr(srv.received, "\"pid\":5678")        != NULL);

    /* Verify NDJSON framing: each line ends with '\n' */
    int newline_count = 0;
    for (size_t i = 0; i < srv.received_len; i++)
        if (srv.received[i] == '\n') newline_count++;
    ASSERT_EQ(newline_count, 2);
}

static void test_forward_drops_reported(void)
{
    tcp_server_t srv = {};
    if (start_server(&srv) != 0) { ASSERT_TRUE(1); return; }

    char host[64]; int port;
    char addr[32];
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", srv.port);
    forward_parse_addr(addr, host, sizeof(host), &port);
    forward_init(host, port);
    usleep(50000);

    forward_drops(42);
    forward_fini();

    int waited = 0;
    while (!srv.done && waited < 2000) { usleep(10000); waited += 10; }
    close(srv.listen_fd);

    ASSERT_TRUE(strstr(srv.received, "\"type\":\"DROP\"")   != NULL);
    ASSERT_TRUE(strstr(srv.received, "\"count\":42")        != NULL);
}

/* ── event_to_json correctness ───────────────────────────────────────────── */

static void test_event_to_json_exec(void)
{
    output_init(OUTPUT_JSON, NULL);
    event_t e = make_exec_event(99, "bash", "/bin/bash");
    char buf[1024];
    size_t n = event_to_json(&e, buf, sizeof(buf));
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(strstr(buf, "\"type\":\"EXEC\"")  != NULL);
    ASSERT_TRUE(strstr(buf, "\"pid\":99")         != NULL);
    ASSERT_TRUE(strstr(buf, "\"comm\":\"bash\"")  != NULL);
    ASSERT_TRUE(strstr(buf, "\"filename\":\"/bin/bash\"") != NULL);
    /* Must not end with newline — forward.c appends its own */
    ASSERT_TRUE(n == 0 || buf[n - 1] != '\n');
}

static void test_event_to_json_json_escape(void)
{
    output_init(OUTPUT_JSON, NULL);
    event_t e = {0};
    e.type = EVENT_EXEC;
    e.pid  = 1;
    /* filename with characters that need JSON escaping */
    strncpy(e.filename, "/tmp/te\"st\nfile", sizeof(e.filename) - 1);
    strncpy(e.comm, "test", sizeof(e.comm) - 1);

    char buf[1024];
    size_t n = event_to_json(&e, buf, sizeof(buf));
    ASSERT_TRUE(n > 0);
    /* Backslash-escaped quote and newline must appear */
    ASSERT_TRUE(strstr(buf, "\\\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\\n")  != NULL);
}

static void test_event_to_json_buf_too_small(void)
{
    output_init(OUTPUT_JSON, NULL);
    event_t e = make_exec_event(1, "x", "/x");

    /* bufsz == 1: below the < 2 guard → returns 0 */
    char one[1];
    ASSERT_EQ(event_to_json(&e, one, 1), 0);

    /* bufsz == 0: NULL/zero guard → returns 0 */
    char zero[1];
    ASSERT_EQ(event_to_json(&e, zero, 0), 0);

    /* bufsz too small to hold full JSON → truncates but NUL-terminates */
    char small[16];
    size_t n = event_to_json(&e, small, sizeof(small));
    ASSERT_TRUE(n < sizeof(small));
    ASSERT_EQ(small[n], '\0');
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    /* parse tests */
    test_parse_host_port();
    test_parse_hostname_port();
    test_parse_ipv6();
    test_parse_ipv6_full();
    test_parse_no_port();
    test_parse_bad_port_zero();
    test_parse_bad_port_overflow();
    test_parse_ipv6_missing_bracket();
    test_parse_null();
    test_parse_empty_host();

    /* init error handling */
    test_init_null_host();
    test_init_bad_port();
    test_init_unreachable_host();

    /* event_to_json */
    test_event_to_json_exec();
    test_event_to_json_json_escape();
    test_event_to_json_buf_too_small();

    /* end-to-end TCP */
    test_forward_sends_json();
    test_forward_drops_reported();

    TEST_SUMMARY();
}
