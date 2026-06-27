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
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

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

/* ---- L3a: custom LKL PCI backend over EpinAnonymOS's native PCI -----------------
 * No VFIO/IOMMU. PCI config r/w goes through the EPIN_SYS_LKL_PCI custom syscall; the
 * backend's .add scans for a device. BAR/DMA/IRQ are stubbed here (L3b/L3c).
 */
#define EPIN_SYS_LKL_PCI 0x4100
static inline long epin_pci_call(long op, long bdf, long off, long size, long val)
{
    return syscall(EPIN_SYS_LKL_PCI, op, bdf, off, size, val);
}

struct epin_pci_dev { long bdf; };
static struct epin_pci_dev g_epin_pci;

static struct lkl_pci_dev *epin_pci_add(const char *name, void *kernel_ram, unsigned long ram_size)
{
    (void)name; (void)kernel_ram; (void)ram_size;
    long bdf = epin_pci_call(2, 0, 0x0108, 0, 0); /* prefer NVMe (class 0x0108) — conflict-free */
    if (bdf < 0)
        bdf = epin_pci_call(2, 0, 0, 0, 0);      /* else first non-bridge device */
    if (bdf < 0) {
        fprintf(stderr, ">>> epin_pci: no PCI device found\n");
        return NULL;
    }
    g_epin_pci.bdf = bdf;
    fprintf(stderr, ">>> epin_pci: device %02lx:%02lx.%lx, vendor/device=0x%08lx\n",
            (bdf >> 16) & 0xff, (bdf >> 8) & 0xff, bdf & 0xff,
            epin_pci_call(0, bdf, 0, 4, 0));
    return (struct lkl_pci_dev *)&g_epin_pci;
}
static void epin_pci_remove(struct lkl_pci_dev *dev) { (void)dev; }
static int epin_pci_read(struct lkl_pci_dev *dev, int where, int size, void *val)
{
    struct epin_pci_dev *d = (struct epin_pci_dev *)dev;
    long v = epin_pci_call(0, d->bdf, where, size, 0);
    if (size == 1)      *(uint8_t  *)val = (uint8_t)v;
    else if (size == 2) *(uint16_t *)val = (uint16_t)v;
    else                *(uint32_t *)val = (uint32_t)v;
    return size;
}
static int epin_pci_write(struct lkl_pci_dev *dev, int where, int size, void *val)
{
    struct epin_pci_dev *d = (struct epin_pci_dev *)dev;
    uint32_t v = (size == 1) ? *(uint8_t *)val : (size == 2) ? *(uint16_t *)val : *(uint32_t *)val;
    epin_pci_call(1, d->bdf, where, size, v);
    return size;
}
/* ---- L3b: BAR MMIO + DMA through the 0x4100 syscall (no mmap, no IOMMU) ---------
 * register_iomem is an exported liblkl symbol but lives in the internal lib/iomem.h
 * (off our -I include/ path), so declare it + its ops struct here.
 */
struct lkl_iomem_ops {
    int (*read)(void *data, int offset, void *res, int size);
    int (*write)(void *data, int offset, void *value, int size);
};
extern void *register_iomem(void *data, int size, const struct lkl_iomem_ops *ops);
extern int lkl_trigger_irq(int irq);   /* exported liblkl symbol — raises a Linux IRQ inside LKL */

/* Every BAR MMIO routes here: data = the BAR's physical base, forward (phys+offset) to op3/op4. */
static int g_mmio_log, g_db, g_mp;  /* log the first handful so we can SEE the driver touch real registers */
static int epin_iomem_read(void *data, int offset, void *res, int size)
{
    long phys = (long)(uintptr_t)data + offset;
    long v = epin_pci_call(3, phys, 0, size, 0);            /* op3 = MMIO read at phys */
    if (size == 1)      *(uint8_t  *)res = (uint8_t)v;
    else if (size == 2) *(uint16_t *)res = (uint16_t)v;
    else if (size == 8) *(uint64_t *)res = (uint64_t)v;
    else                *(uint32_t *)res = (uint32_t)v;
    if (g_mmio_log < 20)
        fprintf(stderr, ">>> epin_mmio RD  off=0x%02x sz=%d -> 0x%lx\n", offset, size, v), g_mmio_log++;
    return 0;
}
static int epin_iomem_write(void *data, int offset, void *value, int size)
{
    long phys = (long)(uintptr_t)data + offset;
    uint64_t v = (size == 1) ? *(uint8_t *)value : (size == 2) ? *(uint16_t *)value :
                 (size == 8) ? *(uint64_t *)value : *(uint32_t *)value;
    epin_pci_call(4, phys, 0, size, (long)v);               /* op4 = MMIO write at phys */
    if (offset >= 0x1000) {                                  /* NVMe doorbells: 0x1000 admin SQ, 0x1004 admin
                                                             CQ, 0x1008 IO-SQ(qid1), 0x100c IO-CQ(qid1) */
        if (g_db < 60) { fprintf(stderr, ">>> epin_DB    off=0x%03x <- 0x%llx\n", offset,
                                 (unsigned long long)v); g_db++; }
    } else if (g_mmio_log < 20) {
        fprintf(stderr, ">>> epin_mmio WR  off=0x%02x sz=%d <- 0x%llx\n", offset, size,
                (unsigned long long)v); g_mmio_log++;
    }
    return 0;
}
static const struct lkl_iomem_ops epin_iomem_ops = {
    .read = epin_iomem_read, .write = epin_iomem_write,
};

/* .resource_alloc(idx): read BAR[idx] from config -> the firmware-assigned phys, then hand LKL an
 * iomem token over it.  LKL stores the token as the resource start; driver MMIO routes via the ops. */
static void *epin_pci_resource_alloc(struct lkl_pci_dev *dev, unsigned long sz, int idx)
{
    struct epin_pci_dev *d = (struct epin_pci_dev *)dev;
    const int off = 0x10 + idx * 4;
    uint32_t lo = (uint32_t)epin_pci_call(0, d->bdf, off, 4, 0);
    unsigned long long bar_phys;
    if ((lo & 0x1) == 0 && (lo & 0x6) == 0x4) {            /* 64-bit memory BAR */
        uint32_t hi = (uint32_t)epin_pci_call(0, d->bdf, off + 4, 4, 0);
        bar_phys = ((unsigned long long)hi << 32) | (lo & ~0xFUL);
    } else {                                               /* 32-bit memory BAR */
        bar_phys = (lo & ~0xFUL);
    }
    if (!bar_phys)
        return NULL;
    fprintf(stderr, ">>> epin_pci: BAR%d phys=0x%llx size=0x%lx\n", idx, bar_phys, sz);
    return register_iomem((void *)(uintptr_t)bar_phys, (int)sz, &epin_iomem_ops);
}

/* .map_page: translate an LKL buffer's virtual addr -> a phys IOVA the device can DMA to (op5). */
static unsigned long long epin_pci_map_page(struct lkl_pci_dev *dev, void *vaddr, unsigned long sz)
{
    (void)dev; (void)sz;
    long phys = epin_pci_call(5, (long)(uintptr_t)vaddr, 0, 0, 0);   /* op5 = virt->phys */
    if (phys <= 0) {
        fprintf(stderr, ">>> epin_pci: map_page(%p) FAILED (not mapped)\n", vaddr);
        return 0;
    }
    if (g_mp < 60)
        fprintf(stderr, ">>> epin_dma  map_page(%p) -> phys 0x%lx\n", vaddr, phys), g_mp++;
    return (unsigned long long)phys;
}
static void epin_pci_unmap_page(struct lkl_pci_dev *dev, unsigned long long h, unsigned long sz)
{ (void)dev; (void)h; (void)sz; }

/* ---- L3c: IRQ forward (polled INTx -> lkl_trigger_irq) -------------------------
 * LKL has no MSI/MSI-X, so the device uses a legacy INTx pin.  EpinAnonymOS has no
 * kernel-mode interrupt delivery (it polls), so we mirror the model in userspace: a
 * thread polls the device's PCI Status register (bit 3 = Interrupt Status, set while
 * INTx is asserted) and raises the matching Linux IRQ inside LKL.  A periodic safety
 * trigger guarantees forward progress even if the status read ever lies.
 */
static struct { long bdf; int irq; } g_irq;
static void *epin_irq_thread(void *arg)
{
    (void)arg;
    int idle = 0;
    for (;;) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 250000 };   /* 250us poll */
        nanosleep(&ts, NULL);
        int sts = (int)epin_pci_call(0, g_irq.bdf, 0x06, 2, 0);    /* PCI Status (cfg 0x06) */
        if ((sts & 0x08) || ++idle >= 16) {                        /* INTx asserted, or ~4ms net */
            lkl_trigger_irq(g_irq.irq);
            idle = 0;
        }
    }
    return NULL;
}
static int epin_pci_irq_init(struct lkl_pci_dev *dev, int irq)
{
    struct epin_pci_dev *d = (struct epin_pci_dev *)dev;
    g_irq.bdf = d->bdf;
    g_irq.irq = irq;
    pthread_t th;
    pthread_create(&th, NULL, epin_irq_thread, NULL);
    fprintf(stderr, ">>> epin_pci: irq_init irq=%d bdf=%lx (polled INTx -> lkl_trigger_irq)\n",
            irq, d->bdf);
    return 0;
}

static struct lkl_dev_pci_ops epin_pci_ops = {
    .add            = epin_pci_add,
    .remove         = epin_pci_remove,
    .irq_init       = epin_pci_irq_init,
    .read           = epin_pci_read,
    .write          = epin_pci_write,
    .resource_alloc = epin_pci_resource_alloc,
    .map_page       = epin_pci_map_page,
    .unmap_page     = epin_pci_unmap_page,
};

/* lkl_init keeps the pointer, so the ops must outlive it -> file scope. */
static struct lkl_host_operations ops;

int main(int argc, char **argv)
{
    long ret;

    /* L4 isolation demo: we were granted a cap for ONLY our device (NVMe). Prove the 0x4100 bridge is
     * default-deny -- a config read of a NON-granted device (the host bridge at bdf 0) must be rejected. */
    long denied = epin_pci_call(0, 0x000000, 0, 4, 0);
    fprintf(stderr, ">>> epin_pci: L4 isolation -- config-read non-granted bdf 0 -> %ld (%s)\n",
            denied, denied < 0 ? "DENIED (good -- cannot see other devices)" : "ALLOWED (BAD!)");

    ops = lkl_host_ops;                       /* start from the default posix-host ops */
    ops.timer_alloc       = ht_timer_alloc;   /* ...and swap the clock for our thread timer */
    ops.timer_set_oneshot = ht_timer_set_oneshot;
    ops.timer_free        = ht_timer_free;
    ops.pci_ops           = &epin_pci_ops;    /* L3a: our native-PCI backend */

    if ((ret = lkl_init(&ops)) < 0) {
        fprintf(stderr, "lkl_init failed: %ld\n", ret);
        return 1;
    }
    /* lkl_pci=epin -> the kernel calls epin_pci_ops.add("epin") + scans bus 0 via .read */
    ret = lkl_start_kernel("mem=32M loglevel=8 lkl_pci=epin");
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
