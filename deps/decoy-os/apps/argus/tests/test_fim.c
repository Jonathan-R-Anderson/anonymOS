#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "framework.h"
#include "../src/fim.h"
#include "../src/argus.h"

/* ── helpers ───────────────────────────────────────────────────────────── */

static const char *TMPFILE = "/tmp/argus_fim_test.txt";

static void write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror("fopen"); exit(1); }
    fputs(content, f);
    fclose(f);
}

/* Redirect stderr to /dev/null for the duration of the test to avoid
 * polluting test output; returns the saved stderr fd. */
static int suppress_stderr(void)
{
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    int devnull = open("/dev/null", 1 /* O_WRONLY */);
    dup2(devnull, STDERR_FILENO);
    close(devnull);
    return saved;
}

static void restore_stderr(int saved)
{
    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
}

/* ── test_fim_no_change ─────────────────────────────────────────────────── */

static void test_fim_no_change(void)
{
    write_file(TMPFILE, "hello world\n");

    static char paths[1][256];
    strncpy(paths[0], TMPFILE, 255);
    fim_init((const char (*)[256])paths, 1);

    event_t e = {};
    e.type = EVENT_WRITE_CLOSE;
    strncpy(e.filename, TMPFILE, sizeof(e.filename) - 1);

    /* Re-checking same content should NOT print anything.
     * We just verify fim_check doesn't crash. */
    int saved = suppress_stderr();
    fim_check(&e);
    restore_stderr(saved);

    _pass++;   /* if we got here without crash, it passes */

    fim_free();
    unlink(TMPFILE);
}

/* ── test_fim_change_detected ───────────────────────────────────────────── */

static void test_fim_change_detected(void)
{
    write_file(TMPFILE, "original content\n");

    static char paths[1][256];
    strncpy(paths[0], TMPFILE, 255);
    fim_init((const char (*)[256])paths, 1);

    /* Modify the file */
    write_file(TMPFILE, "modified content!\n");

    event_t e = {};
    e.type = EVENT_WRITE_CLOSE;
    strncpy(e.filename, TMPFILE, sizeof(e.filename) - 1);

    /* Capture stderr to detect "[FIM]" alert */
    char alert_buf[256] = {};
    int pipefd[2];
    pipe(pipefd);
    fflush(stderr);
    int saved_stderr = dup(STDERR_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);

    fim_check(&e);

    fflush(stderr);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);

    ssize_t n = read(pipefd[0], alert_buf, sizeof(alert_buf) - 1);
    close(pipefd[0]);
    if (n > 0) alert_buf[n] = '\0';

    ASSERT_TRUE(strstr(alert_buf, "[FIM]") != NULL);

    fim_free();
    unlink(TMPFILE);
}

/* ── test_fim_wrong_path ────────────────────────────────────────────────── */

static void test_fim_wrong_path(void)
{
    write_file(TMPFILE, "some content\n");

    static char paths[1][256];
    strncpy(paths[0], TMPFILE, 255);
    fim_init((const char (*)[256])paths, 1);

    event_t e = {};
    e.type = EVENT_WRITE_CLOSE;
    strncpy(e.filename, "/tmp/some_other_file.txt", sizeof(e.filename) - 1);

    /* Capture stderr — should be empty */
    char alert_buf[256] = {};
    int pipefd[2];
    pipe(pipefd);
    fflush(stderr);
    int saved_stderr = dup(STDERR_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);

    fim_check(&e);

    fflush(stderr);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);

    /* Set non-blocking to avoid hanging on empty pipe */
    ssize_t n = read(pipefd[0], alert_buf, sizeof(alert_buf) - 1);
    close(pipefd[0]);
    if (n > 0) alert_buf[n] = '\0';

    ASSERT_TRUE(strstr(alert_buf, "[FIM]") == NULL);

    fim_free();
    unlink(TMPFILE);
}

/* ── test_fim_event_type_guard ──────────────────────────────────────────── */

static void test_fim_event_type_guard(void)
{
    write_file(TMPFILE, "content\n");

    static char paths[1][256];
    strncpy(paths[0], TMPFILE, 255);
    fim_init((const char (*)[256])paths, 1);

    /* Calling with non-WRITE_CLOSE event should be a no-op */
    event_t e = {};
    e.type = EVENT_EXEC;   /* not WRITE_CLOSE */
    strncpy(e.filename, TMPFILE, sizeof(e.filename) - 1);

    int saved = suppress_stderr();
    fim_check(&e);   /* must not crash */
    restore_stderr(saved);

    _pass++;

    fim_free();
    unlink(TMPFILE);
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void)
{
    test_fim_no_change();
    test_fim_change_detected();
    test_fim_wrong_path();
    test_fim_event_type_guard();

    TEST_SUMMARY();
}
