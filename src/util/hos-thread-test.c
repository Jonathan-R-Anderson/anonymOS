/*
 * hos-thread-test.c -- pinpoint the glib cross-thread wakeup deadlock (static-musl).
 *
 * NM hangs in glib's multithreaded main loop: a worker thread writes a GWakeup eventfd to wake the
 * main thread's g_poll (ppoll on musl).  This test isolates the two things that must work:
 *   (1) does a cloned worker thread actually get SCHEDULED and run? (it prints markers)
 *   (2) after the worker writes an eventfd / pipe, does the main thread SEE it readable?
 * The main thread never blocks in poll (musl poll->ppoll never times out here); it uses a bounded
 * nanosleep loop + non-blocking poll(timeout=0) readiness scans, so the test can't hang.  Logs -> fd 2.
 */
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <time.h>
#include <stdint.h>

static void L(const char *s){ (void)!write(2, s, strlen(s)); (void)!write(2, "\n", 1); }
static void napms(long ms){ struct timespec t = { ms/1000, (ms%1000)*1000000L }; nanosleep(&t, 0); }

static volatile int g_worker_ran = 0;
static int g_efd = -1;
static int g_pipe_w = -1;
static pthread_key_t g_tls_key;

static void *tls_worker(void *a){
    (void)a;
    void *before = pthread_getspecific(g_tls_key);
    pthread_setspecific(g_tls_key, (void*)0x5678);
    void *after = pthread_getspecific(g_tls_key);
    L(before == 0 ? "[thr-test] T4 TLS key worker start-NULL: PASS"
                  : "[thr-test] T4 TLS key worker start-NULL: FAIL (leaked main value)");
    L(after == (void*)0x5678 ? "[thr-test] T4 TLS key worker set/get: PASS"
                             : "[thr-test] T4 TLS key worker set/get: FAIL");
    return (void*)0;
}

static void *worker(void *a){
    (void)a;
    g_worker_ran = 1;
    L("[thr-test]   worker: RAN (thread scheduled)");
    napms(200);
    uint64_t v = 1;
    if (g_efd >= 0)    (void)!write(g_efd, &v, 8);
    if (g_pipe_w >= 0) (void)!write(g_pipe_w, "x", 1);
    L("[thr-test]   worker: wrote eventfd + pipe");
    return 0;
}

/* non-blocking readiness scan (timeout 0 -> the kernel does a single pollScanFds, no park) */
static int readable(int fd){
    struct pollfd p = { fd, POLLIN, 0 };
    return (poll(&p, 1, 0) > 0) && (p.revents & POLLIN);
}

int main(void)
{
    L("[thr-test] start");

    g_efd = eventfd(0, 0);
    if (g_efd < 0) { L("[thr-test] eventfd(): FAIL (ENOSYS)"); }

    int fds[2] = { -1, -1 };
    if (pipe(fds) == 0) g_pipe_w = fds[1];

    pthread_t t;
    int cr = pthread_create(&t, 0, worker, 0);
    L(cr == 0 ? "[thr-test] pthread_create: OK" : "[thr-test] pthread_create: FAIL");

    int saw_run = 0, saw_efd = 0, saw_pipe = 0;
    for (int i = 0; i < 50; i++) {         /* up to ~5s, bounded (cannot hang) */
        napms(100);
        if (!saw_run && g_worker_ran) { saw_run = 1; L("[thr-test] main: observed worker_ran flag (shared memory OK)"); }
        if (!saw_efd && g_efd >= 0 && readable(g_efd))   { saw_efd = 1;  L("[thr-test] main: eventfd READABLE after worker write: PASS"); }
        if (!saw_pipe && fds[0] >= 0 && readable(fds[0])){ saw_pipe = 1; L("[thr-test] main: pipe READABLE after worker write: PASS"); }
        if (saw_efd && saw_pipe) break;
    }
    if (!saw_run)  L("[thr-test] main: worker thread NEVER RAN (scheduler didn't run the clone) -- ROOT CAUSE");
    if (!saw_efd)  L("[thr-test] main: eventfd NEVER readable -- FAIL (eventfd wakeup broken)");
    if (!saw_pipe) L("[thr-test] main: pipe NEVER readable -- FAIL (pipe wakeup broken)");
    pthread_join(t, 0);
    L("[thr-test] join OK");

    /* T4: pthread TLS keys -- glib uses a pthread_key (GPrivate) to track g_thread_self(); if
     * getspecific/setspecific are broken, glib gets a NULL GRealThread -> pthread_join(NULL) crash. */
    {
        if (pthread_key_create(&g_tls_key, 0) != 0) { L("[thr-test] T4 pthread_key_create: FAIL"); }
        else {
            pthread_setspecific(g_tls_key, (void*)0x1234);
            void *got_main = pthread_getspecific(g_tls_key);
            L(got_main == (void*)0x1234 ? "[thr-test] T4 TLS key main-thread: PASS"
                                        : "[thr-test] T4 TLS key main-thread: FAIL (getspecific != set)");
            pthread_t t2;
            pthread_create(&t2, 0, tls_worker, 0);
            pthread_join(t2, 0);
            /* main's value must be unchanged by the worker */
            L(pthread_getspecific(g_tls_key) == (void*)0x1234 ? "[thr-test] T4 TLS key main-unchanged: PASS"
                                                              : "[thr-test] T4 TLS key main-unchanged: FAIL");
        }
    }
    L("[thr-test] done");
    return 0;
}
