/* L2: minimal LKL embedder — boot the Linux kernel as a library on EpinAnonymOS.
 *
 * It overrides LKL's TIMER host-op with a thread-based one. The default LKL posix-host
 * drives the kernel clock with a POSIX timer (timer_create) whose SIGEV_THREAD helper
 * waits on rt_sigtimedwait — neither of which this musl-tuned OS supports, so LKL spins
 * forever. Our timer is just a pthread that sleeps on a MONOTONIC-clock condvar (futex,
 * which the OS does support) and calls the kernel's clock callback when it expires.
 */
#include <lkl.h>
#include <lkl_host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

/* ---- thread-based timer host-op (no POSIX timers, no signals) ------------------- */
struct hosttimer {
    void (*fn)(void);          /* the LKL clock callback (raises the timer IRQ) */
    pthread_t       th;
    pthread_mutex_t m;
    pthread_cond_t  c;         /* condvar bound to CLOCK_MONOTONIC */
    long long       deadline;  /* absolute CLOCK_MONOTONIC ns when armed */
    int             armed, stop;
};

static long long mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void *timer_thread(void *arg)
{
    struct hosttimer *t = arg;
    for (;;) {
        pthread_mutex_lock(&t->m);
        while (!t->armed && !t->stop)
            pthread_cond_wait(&t->c, &t->m);          /* idle until armed (woken by re-arm signal) */
        if (t->stop) { pthread_mutex_unlock(&t->m); break; }
        long long now = mono_ns(), dl = t->deadline;
        pthread_mutex_unlock(&t->m);

        long long rem = dl - now;
        if (rem > 0) {
            struct timespec ts = { .tv_sec  = rem / 1000000000LL,
                                   .tv_nsec = rem % 1000000000LL };
            nanosleep(&ts, NULL);                     /* a REAL sleep — the kernel parks this thread */
        }
        pthread_mutex_lock(&t->m);
        if (mono_ns() >= t->deadline) {               /* due (a re-arm may have pushed it later) */
            t->armed = 0;
            pthread_mutex_unlock(&t->m);
            t->fn();                                  /* fire -> the LKL clock IRQ */
        } else {
            pthread_mutex_unlock(&t->m);              /* re-armed later: loop and sleep the remainder */
        }
    }
    return NULL;
}

static void *ht_timer_alloc(void (*fn)(void))
{
    struct hosttimer *t = calloc(1, sizeof(*t));
    if (!t)
        return NULL;
    t->fn = fn;
    pthread_mutex_init(&t->m, NULL);
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&t->c, &ca);
    pthread_create(&t->th, NULL, timer_thread, t);
    return t;
}

static int ht_timer_set_oneshot(void *_t, unsigned long ns)
{
    struct hosttimer *t = _t;
    pthread_mutex_lock(&t->m);
    t->deadline = mono_ns() + (long long)ns;
    t->armed = 1;
    pthread_cond_signal(&t->c);
    pthread_mutex_unlock(&t->m);
    return 0;
}

static void ht_timer_free(void *_t)
{
    struct hosttimer *t = _t;
    pthread_mutex_lock(&t->m);
    t->stop = 1;
    pthread_cond_signal(&t->c);
    pthread_mutex_unlock(&t->m);
    pthread_join(t->th, NULL);
    free(t);
}

/* lkl_init keeps the pointer, so the ops must outlive it -> file scope. */
static struct lkl_host_operations ops;

int main(int argc, char **argv)
{
    long ret;

    ops = lkl_host_ops;                       /* start from the default posix-host ops */
    ops.timer_alloc       = ht_timer_alloc;   /* ...and swap the clock for our thread timer */
    ops.timer_set_oneshot = ht_timer_set_oneshot;
    ops.timer_free        = ht_timer_free;

    if ((ret = lkl_init(&ops)) < 0) {
        fprintf(stderr, "lkl_init failed: %ld\n", ret);
        return 1;
    }
    ret = lkl_start_kernel("mem=32M loglevel=8");
    if (ret < 0) {
        fprintf(stderr, "lkl_start_kernel failed: %ld\n", ret);
        return 1;
    }
    fprintf(stderr, ">>> LKL up inside EpinAnonymOS. getpid()=%ld\n", lkl_sys_getpid());
    /* prove the LKL VFS works (the call-in path EpinAnonymOS will bridge in L4) */
    long fd = lkl_sys_openat(LKL_AT_FDCWD, "/lkl-l2", LKL_O_CREAT | LKL_O_WRONLY, 0644);
    fprintf(stderr, ">>> lkl_sys_openat(/lkl-l2)=%ld\n", fd);
    if (fd >= 0) {
        lkl_sys_write(fd, "hello-from-L2\n", 14);
        lkl_sys_close(fd);
    }
    lkl_sys_halt();
    lkl_cleanup();
    fprintf(stderr, ">>> LKL halted cleanly.\n");
    return 0;
}
