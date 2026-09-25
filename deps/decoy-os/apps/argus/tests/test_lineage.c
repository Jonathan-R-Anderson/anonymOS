#include <string.h>
#include "../src/lineage.h"
#include "framework.h"

/* Reset the table between tests by removing all entries we added */
static void cleanup(uint32_t *pids, int n)
{
    for (int i = 0; i < n; i++) lineage_remove(pids[i]);
}

static void test_unknown_ppid(void)
{
    char buf[256];
    /* ppid 99999 was never inserted — should return "?" */
    lineage_str(99999, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "?");
}

static void test_single_parent(void)
{
    char buf[256];
    lineage_update(100, 1, "systemd");
    lineage_update(200, 100, "sshd");

    /* process with ppid=200 should show "systemd→sshd" */
    lineage_str(200, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "systemd\xe2\x86\x92sshd");

    uint32_t pids[] = {100, 200};
    cleanup(pids, 2);
}

static void test_chain(void)
{
    char buf[256];
    lineage_update(1,   0,   "systemd");
    lineage_update(100, 1,   "sshd");
    lineage_update(200, 100, "bash");

    lineage_str(200, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "sshd\xe2\x86\x92""bash");

    /* Stop at pid 1 — systemd is not walked (loop stops when cur <= 1) */
    uint32_t pids[] = {1, 100, 200};
    cleanup(pids, 3);
}

static void test_remove(void)
{
    char buf[256];
    lineage_update(500, 1, "parent");
    lineage_remove(500);
    /* After removal, 500 is a tombstone — lookup should return "?" */
    lineage_str(500, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "?");
}

static void test_update_overwrite(void)
{
    char buf[256];
    lineage_update(300, 1, "original");
    lineage_update(300, 1, "updated");  /* same pid, new comm */
    lineage_update(400, 300, "child");

    /* lineage_str takes the *parent's* pid — process 400 has ppid=300 */
    lineage_str(300, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "updated");

    uint32_t pids[] = {300, 400};
    cleanup(pids, 2);
}

static void test_buf_too_small(void)
{
    char buf[4];  /* way too small */
    lineage_update(600, 1, "longparent");
    lineage_str(600, buf, sizeof(buf));
    /* Should not overflow — result may be truncated but NUL-terminated */
    ASSERT_TRUE(buf[sizeof(buf)-1] == '\0');
    uint32_t pids[] = {600};
    cleanup(pids, 1);
}

int main(void)
{
    test_unknown_ppid();
    test_single_parent();
    test_chain();
    test_remove();
    test_update_overwrite();
    test_buf_too_small();
    TEST_SUMMARY();
}
