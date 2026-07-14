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
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include "hos-net-proto.h"
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
extern int memfd_create(const char *name, unsigned int flags);  /* musl: declared only under _GNU_SOURCE */

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
        /* Wait on the condition itself, using the CLOCK_MONOTONIC absolute deadline configured in
         * ht_timer_alloc().  The old nanosleep() could NOT be interrupted by ht_timer_set_oneshot's
         * condition signal: when LKL re-armed an earlier deadline, the timer kept sleeping until the
         * obsolete later one.  That produced 200ms+ late clock IRQs during iwlwifi firmware work and
         * delayed/prevented wlan0 registration.  A condition timed-wait wakes immediately on every
         * re-arm, then recomputes the deadline while still holding the timer-state mutex. */
        for (;;) {
            const long long dl = t->deadline;
            struct timespec abs = { .tv_sec  = dl / 1000000000LL,
                                    .tv_nsec = dl % 1000000000LL };
            if (mono_ns() >= dl)
                break;
            (void)pthread_cond_timedwait(&t->c, &t->m, &abs);
            if (t->stop || !t->armed)
                break;
            /* A re-arm changes t->deadline and signals t->c; loop to wait for the new deadline. */
        }
        if (t->stop) { pthread_mutex_unlock(&t->m); break; }
        if (!t->armed) { pthread_mutex_unlock(&t->m); continue; }
        t->armed = 0;
        pthread_mutex_unlock(&t->m);
        t->fn();                                      /* fire -> the LKL clock IRQ */
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

/* ---- USB log persistence -------------------------------------------------------
 * The FW13 desktop-freeze debugging needs the full /run/klog OFF the machine, but a hard reset
 * wipes the RAM ring.  The LKL drives USB mass storage (usb-storage -> /dev/sda), so mount a 2nd
 * FAT-formatted USB stick and continuously append the growing kernel log ring to hoslog.txt.
 * We READ /run/klog via plain libc (EpinAnonymOS's synthetic klog file) and WRITE via lkl_sys_*
 * (the LKL's mounted USB) — lkl-boot bridges both.  Survives the compositor freeze (lkl-boot stays
 * alive), so the log around the freeze is captured. */
#include <lkl/linux/kdev_t.h>
/* fwd decl: epin_pci_call is defined further down, but epin_usblog_thread reports status through it (op11). */
static inline long epin_pci_call(long op, long bdf, long off, long size, long val);
static void *epin_usblog_thread(void *arg)
{
    (void)arg;
    char mnt[80] = {0};
    /* SAFETY + VISIBILITY (real-HW): a mount is a BLOCKING LKL call sharing the single LKL "cpu" with
     * USB input, so we start LATE (12 s, after enumeration) and YIELD between attempts.  We DRIVE the
     * mount off /proc/partitions (what the LKL ACTUALLY enumerated) and LOG the whole device list + every
     * mount result.  Every fprintf(stderr) here lands in /run/klog -> the desktop "Logs" app (filter
     * "usblog"), so even a FAILED capture is diagnosable ON the machine.  We prefer the LARGEST device
     * (the 123 GB log stick dwarfs the boot ESP) and try every filesystem we built. */
    { struct timespec s = { 4, 0 }; nanosleep(&s, NULL); }   /* was 12s; the round loop below retries every 2s, so late USB enumeration is still caught — cut for faster first-write on a box that may crash early */
    /* Ensure /proc is mounted (we read /proc/partitions).  Idempotent: a 2nd mount just returns -EBUSY. */
    lkl_sys_mkdir("/proc", 0555);
    lkl_sys_mount("proc", "/proc", "proc", 0, 0);
    fprintf(stderr, ">>> usblog: probing for a log USB stick (via /proc/partitions)...\n");
    epin_pci_call(11, 0, 0, 0, 0);                     /* on-screen status: searching (op11: state=0) */
    static const char *const FSS[] = { "vfat", "exfat", "ntfs3", "ext4", 0 };
    struct blkcand { int maj, min; unsigned long kb; char name[32]; };
    char lastparts[3072] = {0};
    char path[128];
    int out = -1;                                      /* the open hoslog.txt fd == "we're capturing" */
    unsigned long mountedKB = 0; int mountedSd = 0;    /* the mounted device, for the on-screen status */
    for (int round = 0; round < 40 && out < 0; round++) {
        char parts[3072];
        int plen = 0;
        int pf = lkl_sys_open("/proc/partitions", 0 /*O_RDONLY*/, 0);
        if (pf >= 0) {
            long n = lkl_sys_read(pf, parts, sizeof parts - 1);
            plen = (n > 0) ? (int)n : 0;
            lkl_sys_close(pf);
        } else if (round == 0) {
            fprintf(stderr, ">>> usblog: cannot open /proc/partitions (%d) — /proc not mounted?\n", pf);
        }
        parts[plen] = 0;
        if (plen == (int)sizeof parts - 1) {           /* buffer full: drop the truncated trailing line */
            char *lastnl = strrchr(parts, '\n');
            if (lastnl) lastnl[1] = 0;
        }
        /* Log the device list only when it CHANGES (avoid per-round spam), but ALWAYS re-attempt mounts
         * below — a device present since boot whose first mount failed transiently must still be retried. */
        const int changed = (strcmp(parts, lastparts) != 0);
        if (changed) {
            /* Prefix EVERY line with "usblog:" so the whole list survives the desktop Logs "usblog"
             * filter (the raw /proc/partitions rows don't contain the word, so a %s blob would vanish). */
            fprintf(stderr, ">>> usblog: LKL block devices (/proc/partitions):\n");
            if (!plen) {
                fprintf(stderr, ">>> usblog:   (none enumerated yet)\n");
            } else {
                for (char *ln = parts; ln && *ln; ) {
                    char *nl = strchr(ln, '\n');
                    int len = nl ? (int)(nl - ln) : (int)strlen(ln);
                    if (len > 0) fprintf(stderr, ">>> usblog:   %.*s\n", len, ln);
                    ln = nl ? nl + 1 : 0;
                }
            }
            fprintf(stderr, ">>> usblog: ---\n");
            strncpy(lastparts, parts, sizeof lastparts - 1); lastparts[sizeof lastparts - 1] = 0;
        }
        /* Collect sd* candidates (skip the blank line after the header), sort by size DESC. */
        struct blkcand cand[24]; int nc = 0;
        for (char *line = parts; line && *line; ) {
            char *nl = strchr(line, '\n');
            if (*line != '\n' && *line != '\r') {          /* skip blank/header-gap lines */
                int maj = 0, min = 0; unsigned long kb = 0; char name[32] = {0};
                if (sscanf(line, "%d %d %lu %31s", &maj, &min, &kb, name) == 4 &&
                    name[0] == 's' && name[1] == 'd' && kb >= 2048 /*skip <2MB*/ && nc < 24) {
                    cand[nc].maj = maj; cand[nc].min = min; cand[nc].kb = kb;
                    strncpy(cand[nc].name, name, sizeof cand[nc].name - 1);
                    cand[nc].name[sizeof cand[nc].name - 1] = 0; nc++;
                }
            }
            line = nl ? nl + 1 : 0;
        }
        for (int i = 0; i < nc; i++)
            for (int j = i + 1; j < nc; j++)
                if (cand[j].kb > cand[i].kb) { struct blkcand t = cand[i]; cand[i] = cand[j]; cand[j] = t; }
        if (changed && nc == 0)
            fprintf(stderr, ">>> usblog: no sd* mass-storage device yet (usb-storage/uas not bound?)\n");
        /* on-screen status: found a candidate (state 1) or still searching (state 0) */
        if (nc > 0) epin_pci_call(11, 1, 0, (long)cand[0].kb, cand[0].name[2] - 'a');
        else        epin_pci_call(11, 0, 0, 0, 0);
        /* Mount + open the log file per candidate.  A read-only mount (write-protected FAT / dirty NTFS)
         * mounts OK but O_WRONLY fails -> umount and fall through to the next FS/device rather than dead-end. */
        for (int c = 0; c < nc && out < 0; c++) {
            for (int f = 0; FSS[f] && out < 0; f++) {
                long r = lkl_mount_blkdev(LKL_MKDEV(cand[c].maj, cand[c].min), FSS[f], 0, NULL, mnt, sizeof mnt);
                if (r < 0) {
                    if (r != -22 /*EINVAL: wrong FS, expected while probing*/) {
                        fprintf(stderr, ">>> usblog: /dev/%s as %s -> err %ld\n", cand[c].name, FSS[f], r);
                        struct timespec y = { 0, 200000000 }; nanosleep(&y, NULL);   /* yield only on real I/O err */
                    }
                    continue;
                }
                snprintf(path, sizeof path, "%s/hoslog.txt", mnt);
                out = lkl_sys_open(path, LKL_O_WRONLY | LKL_O_CREAT | LKL_O_TRUNC, 0644);
                if (out >= 0) {
                    mountedKB = cand[c].kb; mountedSd = cand[c].name[2] - 'a';
                    fprintf(stderr, ">>> usblog: MOUNTED /dev/%s (%lu KB) as %s at %s; capturing /run/klog -> %s\n",
                            cand[c].name, cand[c].kb, FSS[f], mnt, path);
                    epin_pci_call(11, 2, 0, (long)mountedKB, mountedSd);   /* on-screen: WRITING (0 bytes yet) */
                } else {
                    fprintf(stderr, ">>> usblog: /dev/%s mounted %s but %s unwritable (%d, read-only?) — next\n",
                            cand[c].name, FSS[f], path, out);
                    lkl_umount_timeout(mnt, 0, 2000);
                }
            }
        }
        if (out < 0) { struct timespec ts = { 2, 0 }; nanosleep(&ts, NULL); }
    }
    if (out < 0) {
        epin_pci_call(11, 3, 0, 0, 0);                 /* on-screen status: NO writable drive found */
        fprintf(stderr, ">>> usblog: gave up — no writable USB block device (see the block-device list "
                        "above; filter 'usblog' in the Logs app). Attach a writable FAT32/exFAT stick.\n");
        return NULL;
    }
    long long off = 0;
    static char buf[16384];
    for (;;) {
        int kf = open("/run/klog", 0 /*O_RDONLY*/);   /* EpinAnonymOS synthetic klog RAM ring */
        if (kf >= 0) {
            lseek(kf, (off_t)off, 0 /*SEEK_SET*/);     /* stream coordinate; kernel clamps if we lagged */
            int n;
            while ((n = (int)read(kf, buf, sizeof buf)) > 0) {
                long w = lkl_sys_write(out, buf, n);
                if (w <= 0) break;                     /* write error (e.g. ENOSPC) -> retry this region next pass */
                off += w;                              /* advance only by bytes actually written (short-write safe) */
                if (w < n) break;
            }
            close(kf);
            lkl_sys_fsync(out);                        /* flush to the stick so a hard reset keeps it */
        }
        epin_pci_call(11, 2, (long)off, (long)mountedKB, mountedSd);  /* on-screen: WRITING, bytes so far */
        struct timespec ts = { 3, 0 };                 /* ~3 s cadence (lighter USB contention) */
        nanosleep(&ts, NULL);
    }
    return NULL;
}

/* ---- L6.0: LKL MMU memory host-op (memfd, not shm_open) ------------------------
 * LKL's MMU backs "physical" memory with a host shm object that it mmaps at kernel
 * virtual addresses (so the kernel-virtual DMA buffers are real host pages -> the
 * bridge's op5 virt->phys still works).  The default posix-host uses shm_open (POSIX
 * /dev/shm), which EpinAnonymOS lacks -- so back it with a memfd, which it supports. */
static int g_lkl_memfd = -1;
static void epin_shmem_init(unsigned long size)
{
    g_lkl_memfd = memfd_create("lkl_phys_mem", 0);
    if (g_lkl_memfd < 0 || ftruncate(g_lkl_memfd, (off_t)size) != 0) {
        fprintf(stderr, ">>> epin_shmem_init FAILED (memfd=%d size=%lu)\n", g_lkl_memfd, size);
        abort();
    }
    fprintf(stderr, ">>> epin_shmem_init: LKL MMU phys-mem = memfd %d, %lu bytes\n", g_lkl_memfd, size);
}
static void *epin_shmem_mmap(void *addr, unsigned long pg_off, unsigned long size, enum lkl_prot prot)
{
    int p = 0;
    if (prot & LKL_PROT_READ)  p |= PROT_READ;
    if (prot & LKL_PROT_WRITE) p |= PROT_WRITE;
    if (prot & LKL_PROT_EXEC)  p |= PROT_EXEC;
    /* MAP_FIXED (overwrite), NOT MAP_FIXED_NOREPLACE: LKL remaps pages (the addr can already be
     * mapped) and EpinAnonymOS rejects NOREPLACE on a taken addr -> BUG_ON(res != va).  MAP_FIXED
     * handles both fresh maps and remaps. */
    void *ret = mmap(addr, size, p, MAP_SHARED | MAP_FIXED, g_lkl_memfd, (off_t)pg_off);
    if (ret != addr)
        fprintf(stderr, ">>> epin_shmem_mmap: req %p got %p sz %lu off %lu errno %d\n",
                addr, ret, size, pg_off, errno);
    return (ret == MAP_FAILED) ? NULL : ret;
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
/* The kernel may grant this ONE LKL SEVERAL devices (AX210 WiFi + xHCI USB).  The LKL calls .add()
 * once per PCI bus it creates; we hand back the next granted device each call (NULL when exhausted),
 * so each lands on its own bus.  op10(i) enumerates our granted bdfs. */
static struct epin_pci_dev g_epin_devs[8];
static int g_epin_ndev   = -1;   /* -1 until enumerated */
static int g_epin_addIdx = 0;    /* which device the next .add() hands out */

static struct lkl_pci_dev *epin_pci_add(const char *name, void *kernel_ram, unsigned long ram_size)
{
    (void)name; (void)kernel_ram; (void)ram_size;
    if (g_epin_ndev < 0) {                            /* first call: enumerate ALL our granted devices */
        g_epin_ndev = 0;
        for (int i = 0; i < 8; i++) {
            long bdf = epin_pci_call(10, 0, i, 0, 0); /* op10: our i-th granted device (-1 past the last) */
            if (bdf < 0) break;
            g_epin_devs[g_epin_ndev++].bdf = bdf;
            fprintf(stderr, ">>> epin_pci: granted device #%d bdf=%02lx:%02lx.%lx vendor/device=0x%08lx\n",
                    g_epin_ndev - 1, (bdf >> 16) & 0xff, (bdf >> 8) & 0xff, bdf & 0xff,
                    epin_pci_call(0, bdf, 0, 4, 0));
        }
        if (g_epin_ndev == 0) {                       /* fallback: class-scan (single device / older kernel) */
            long bdf = epin_pci_call(2, 0, 0x0280, 0, 0);
            if (bdf < 0) bdf = epin_pci_call(2, 0, 0x0380, 0, 0);
            if (bdf < 0) bdf = epin_pci_call(2, 0, 0x0c03, 0, 0);
            if (bdf < 0) bdf = epin_pci_call(2, 0, 0x0108, 0, 0);
            if (bdf < 0) bdf = epin_pci_call(2, 0, 0, 0, 0);
            if (bdf >= 0) {
                g_epin_devs[g_epin_ndev++].bdf = bdf;
                fprintf(stderr, ">>> epin_pci: (class-scan) device bdf=0x%lx vendor/device=0x%08lx\n",
                        bdf, epin_pci_call(0, bdf, 0, 4, 0));
            }
        }
        if (g_epin_ndev == 0) { fprintf(stderr, ">>> epin_pci: no granted PCI device\n"); return NULL; }
    }
    if (g_epin_addIdx >= g_epin_ndev) return NULL;    /* exhausted -> the LKL stops creating buses */
    return (struct lkl_pci_dev *)&g_epin_devs[g_epin_addIdx++];
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
extern void *register_iomem_direct(void *host_va, int size);  /* L6.1: a host-mapped (op8) BAR, direct */
extern int lkl_trigger_irq(int irq);   /* exported liblkl symbol — raises a Linux IRQ inside LKL */
extern long lkl_syscall(long no, long *params);   /* raw LKL syscall (for execve, no inline wrapper) */
/* Spawn a real userspace process INSIDE the LKL via the kernel's own run_init_process path
 * (kernel_thread -> kernel_execve).  Added to arch/lkl/kernel/setup.c.  A host-pthread execve
 * can't work (kernel-thread context, no userspace return path); this is the correct mechanism. */
extern int lkl_run_userspace(const char *path);
/* Embedded hos-init (deps/lkl-rootfs/hos-init.c), linked in via objcopy -I binary. */
extern const unsigned char _binary_hos_init_start[];
extern const unsigned char _binary_hos_init_end[];

/* Every BAR MMIO routes here: data = the BAR's physical base, forward (phys+offset) to op3/op4. */
static unsigned long g_vram_base = 0, g_vram_size = 0;  /* L6.2: host-visible GPU VRAM mapping (op8) */
static int epin_iomem_read(void *data, int offset, void *res, int size)
{
    long phys = (long)(uintptr_t)data + offset;
    long v = epin_pci_call(3, phys, 0, size, 0);            /* op3 = MMIO read at phys */
    if (size == 1)      *(uint8_t  *)res = (uint8_t)v;
    else if (size == 2) *(uint16_t *)res = (uint16_t)v;
    else if (size == 8) *(uint64_t *)res = (uint64_t)v;
    else                *(uint32_t *)res = (uint32_t)v;
    return 0;
}
static int epin_iomem_write(void *data, int offset, void *value, int size)
{
    long phys = (long)(uintptr_t)data + offset;
    uint64_t v = (size == 1) ? *(uint8_t *)value : (size == 2) ? *(uint16_t *)value :
                 (size == 8) ? *(uint64_t *)value : *(uint32_t *)value;
    epin_pci_call(4, phys, 0, size, (long)v);               /* op4 = MMIO write at phys */
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
    /* DIRECT-MAP (op8) instead of the routed op3/op4-syscall-per-access iomem path when:
     *  - the BAR is a large aperture (GPU framebuffer): register_iomem caps at 16MB-1 and a
     *    syscall per pixel word is unusable (TTM blits must be plain memcpy); OR
     *  - the device is NETWORK class (0x02 — the AX210 wifi): its CSR registers are accessed in
     *    TIGHT, TIMING-CRITICAL loops (the LTR-ROM-erratum keep-busy spin, the FSEQ/RF power-up),
     *    and a routed op3/op4 SYSCALL per iwl_read32/write32 is ~1000x too slow → the erratum
     *    workaround can't keep the chip busy at hardware speed → RF sequencer fails (LMAC=0xd0,
     *    -110).  op8 maps the BAR straight into this process so iwl_read32/write32 become direct
     *    uncached MMIO — real-hardware speed, exactly like a native kernel's ioremap.
     * Other small register BARs (GPU bochs dispi/VGA, USB xHCI) keep the proven routed path. */
    /* NOTE: direct-mapping the WiFi (small) register BAR via op8 REGRESSED it — iwl_read32(HW_REV)
     * returned 0xFFFFFFFF (device not responding) and the probe died at -EIO before firmware load.
     * The op8 direct-map path works for the large GPU framebuffer BAR but NOT for this small MMIO
     * register BAR (mapping/attr issue under investigation), so the AX210 stays on the proven ROUTED
     * op3/op4 path (which reaches firmware-load + the alive attempt). Only huge apertures direct-map. */
    if (sz > 0xFFFFFF) {
        long va = epin_pci_call(8, (long)bar_phys, 0, (long)sz, 0);   /* op8 = direct-map BAR phys */
        if (va > 0) {
            void *tok = register_iomem_direct((void *)(uintptr_t)va, (int)sz);
            fprintf(stderr, ">>> epin_pci: BAR%d DIRECT phys=0x%llx -> va=0x%lx tok=%p\n",
                    idx, bar_phys, va, tok);
            if (tok) {
                g_vram_base = (unsigned long)va;   /* L6.2: VRAM host-VA for direct pixel writes */
                g_vram_size = (unsigned long)sz;
                return tok;
            }
            fprintf(stderr, ">>> epin_pci: BAR%d register_iomem_direct full — routed fallback\n", idx);
        } else {
            fprintf(stderr, ">>> epin_pci: BAR%d op8 FAILED (%ld) — routed fallback\n", idx, va);
        }
    }
    return register_iomem((void *)(uintptr_t)bar_phys, (int)sz, &epin_iomem_ops);
}

/* .map_page: translate an LKL buffer's virtual addr -> a phys IOVA the device can DMA to (op5).
 * US5: pass the transfer SIZE so the kernel can bounce a multi-page buffer whose backing host
 * pages aren't physically contiguous (the no-IOMMU bulk-DMA corruption fix). */
static unsigned long long epin_pci_map_page(struct lkl_pci_dev *dev, void *vaddr, unsigned long sz)
{
    (void)dev;
    long phys = epin_pci_call(5, (long)(uintptr_t)vaddr, 0, (long)sz, 0);   /* op5 = virt->phys(+bounce) */
    if (phys <= 0) {
        fprintf(stderr, ">>> epin_pci: map_page(%p) FAILED (not mapped)\n", vaddr);
        return 0;
    }
    return (unsigned long long)phys;
}
/* US5: op12 copies a bounce buffer back to the caller (device writes) + frees it; a no-op for
 * the direct (contiguous) fast path. h is exactly what map_page returned. */
static void epin_pci_unmap_page(struct lkl_pci_dev *dev, unsigned long long h, unsigned long sz)
{ (void)dev; (void)sz; epin_pci_call(12, (long)h, 0, (long)sz, 0); }

/* ---- L3c: IRQ forward (polled INTx -> lkl_trigger_irq) -------------------------
 * LKL has no MSI/MSI-X, so the device uses a legacy INTx pin.  EpinAnonymOS has no
 * kernel-mode interrupt delivery (it polls), so we mirror the model in userspace: a
 * thread polls the device's PCI Status register (bit 3 = Interrupt Status, set while
 * INTx is asserted) and raises the matching Linux IRQ inside LKL.  A periodic safety
 * trigger guarantees forward progress even if the status read ever lies.
 */
/* MSI-X: the AX210 (gen2) requests SEVERAL vectors (up to num_cpus+2) — ALIVE/HW causes land on
 * the non-RX vector, RX on the others.  All our vectors share IDT 0x30 (op9 returns the same
 * message), so op6/g_msiIrqCount can't tell which fired.  Track EVERY registered irq for the
 * granted device and raise them all on each wake — each Linux handler reads its own MSI-X cause
 * register and ignores a spurious call, so the ALIVE handler is guaranteed to run. */
#define EPIN_MAX_IRQS 16
static struct { long bdf; int irqs[EPIN_MAX_IRQS]; int n; } g_irq;
static void *epin_irq_thread(void *arg)
{
    (void)arg;
    for (;;) {
        /* op6: BLOCK in the kernel until our granted device's interrupt is pending.  The
         * EpinAnonymOS kernel poll-loop (which always runs) does the detection and wakes us — so
         * this thread is PARKED between interrupts.  Returns 1 = real interrupt, 0 = 50ms safety. */
        epin_pci_call(6, 0, 0, 0, 0);
        int i, n = g_irq.n;
        for (i = 0; i < n; i++)
            lkl_trigger_irq(g_irq.irqs[i]);   /* raise every wifi IRQ; handlers ack their own causes */
    }
    return NULL;
}
static int g_irq_thread_started;
static int epin_pci_irq_init(struct lkl_pci_dev *dev, int irq)
{
    struct epin_pci_dev *d = (struct epin_pci_dev *)dev;
    int i, found = 0;
    g_irq.bdf = d->bdf;
    for (i = 0; i < g_irq.n; i++)                 /* dedup: irq_init may be re-called per vector */
        if (g_irq.irqs[i] == irq) { found = 1; break; }
    if (!found && g_irq.n < EPIN_MAX_IRQS)
        g_irq.irqs[g_irq.n++] = irq;              /* MSI-X: accumulate all vectors (INTx/MSI: just 1) */
    if (!g_irq_thread_started) {
        g_irq_thread_started = 1;
        pthread_t th;
        pthread_create(&th, NULL, epin_irq_thread, NULL);
    }
    fprintf(stderr, ">>> epin_pci: irq_init irq=%d bdf=%lx nvec=%d (op6 wake -> trigger all)\n",
            irq, d->bdf, g_irq.n);
    return 0;
}

/* WiFi W1: return the MSI message field the LKL programs into the device's MSI cap.
 * field 0=address_lo, 1=address_hi, 2=data.  Backed by the 0x4100 bridge op9. */
static long epin_pci_msi_setup(struct lkl_pci_dev *dev, int field)
{
    struct epin_pci_dev *d = (struct epin_pci_dev *)dev;
    return epin_pci_call(9, d->bdf, field, 0, 0);
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
    .msi_setup      = epin_pci_msi_setup,
};

/* lkl_init keeps the pointer, so the ops must outlive it -> file scope. */
static struct lkl_host_operations ops;

/* ---- L5 input bridge: LKL evdev (/dev/input/event*) -> EpinAnonymOS input rings ----
 * usbhid creates the LKL's input nodes after USB enumeration; we mknod them (no devtmpfs in
 * this LKL), wait for them to open, then read evdev input_event records and inject each into
 * the OS via op7 (-> input_enqueue).  event0 = keyboard (isKbd=1), event1 = mouse (isKbd=0).
 * input_event is the same 24-byte struct on both sides, so type/code/value pass straight through. */
#define EPIN_INPUT_INJECT 7
struct epin_in_ev { long sec, usec; unsigned short type, code; int value; }; /* 24B == kernel input_event */
struct epin_in_reader { const char *path; long dev; long isKbd; };
static void *epin_input_reader(void *arg)
{
    struct epin_in_reader *r = arg;
    lkl_sys_mknod(r->path, 020000 | 0666, r->dev);        /* S_IFCHR|rw — create the evdev node */
    long fd;
    while ((fd = lkl_sys_openat(LKL_AT_FDCWD, r->path, 0 /*O_RDONLY*/, 0)) < 0) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 200000000 };  /* 200ms: wait for usbhid to register */
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, ">>> epin_input: bridging %s -> %s ring\n", r->path, r->isKbd ? "kbd" : "mouse");
    struct epin_in_ev ev;
    for (;;) {
        long n = lkl_sys_read(fd, (char *)&ev, sizeof(ev));   /* blocks until an evdev event */
        /* L5 polish: forward EV_SYN(0)/EV_KEY(1)/EV_REL(2)/EV_ABS(3) only; drop EV_MSC(4) scancodes
         * (the compositor ignores them) so the 128-entry rings aren't pressured by redundant events. */
        if (n == (long)sizeof(ev) && ev.type != 4)
            epin_pci_call(EPIN_INPUT_INJECT, r->isKbd, ev.type, ev.code, ev.value);
        else if (n < 0) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 20000000 };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}
static struct epin_in_reader g_kbdReader = { "/dev/input/event0", (13 << 8) | 64, 1 };
static struct epin_in_reader g_mseReader = { "/dev/input/event1", (13 << 8) | 65, 0 };

/* ---- L6.2: in-LKL KMS client — draw a test pattern to /dev/dri/card0 (DRM dumb buffer + modeset),
 * so the LKL's bochs-drm scans it out to the bochs-display.  Proof that pixels from the LKL GPU reach
 * the screen.  DRM uapi structs are self-contained (the lkl include path lacks drm/drm_mode.h). */
struct drm_mode_card_res {
    uint64_t fb_id_ptr, crtc_id_ptr, connector_id_ptr, encoder_id_ptr;
    uint32_t count_fbs, count_crtcs, count_connectors, count_encoders;
    uint32_t min_width, max_width, min_height, max_height;
};
struct drm_mode_modeinfo {
    uint32_t clock;
    uint16_t hdisplay, hsync_start, hsync_end, htotal, hskew;
    uint16_t vdisplay, vsync_start, vsync_end, vtotal, vscan;
    uint32_t vrefresh, flags, type;
    char name[32];
};
struct drm_mode_get_connector {
    uint64_t encoders_ptr, modes_ptr, props_ptr, prop_values_ptr;
    uint32_t count_modes, count_props, count_encoders;
    uint32_t encoder_id, connector_id, connector_type, connector_type_id;
    uint32_t connection, mm_width, mm_height, subpixel;
    uint32_t pad;
};
struct drm_mode_create_dumb { uint32_t height, width, bpp, flags, handle, pitch; uint64_t size; };
struct drm_mode_fb_cmd { uint32_t fb_id, width, height, pitch, bpp, depth, handle; };
struct drm_mode_map_dumb { uint32_t handle, pad; uint64_t offset; };
struct drm_mode_crtc {
    uint64_t set_connectors_ptr;
    uint32_t count_connectors, crtc_id, fb_id, x, y, gamma_size, mode_valid;
    struct drm_mode_modeinfo mode;
};
#define DRM_IOCTL_SET_MASTER         0x641eUL
#define DRM_IOCTL_MODE_GETRESOURCES  0xc04064a0UL
#define DRM_IOCTL_MODE_GETCONNECTOR  0xc05064a7UL
#define DRM_IOCTL_MODE_CREATE_DUMB   0xc02064b2UL
#define DRM_IOCTL_MODE_ADDFB         0xc01c64aeUL
#define DRM_IOCTL_MODE_MAP_DUMB      0xc01064b3UL
#define DRM_IOCTL_MODE_SETCRTC       0xc06864a2UL


/* ALL LKL kernel printk flows through lkl_ops->print (the registered console's write).  The
 * default posix-host print dumps every message (loglevel gating isn't honoured here), which floods
 * the on-screen log with driver/subsystem registrations (iwlwifi/cfg80211/NET/btrfs/...).  Filter
 * it: pass through only lines that look like real problems (panic/oops/error), drop the routine
 * spam.  Our own ">>>" status lines use stderr — a separate write path NOT routed through here. */
static int epin_str_contains(const char *hay, int haylen, const char *needle)
{
    int nl = (int)strlen(needle);
    for (int i = 0; i + nl <= haylen; i++)
        if (memcmp(hay + i, needle, (size_t)nl) == 0) return 1;
    return 0;
}
static void provtrace_append(const char *s, unsigned n);   /* fwd decl (defined below) */
static void epin_lkl_print(const char *str, int len)
{
    /* WiFi AX210 debug: the driver's own printk shows WHERE the device fails (firmware load / ALIVE /
     * PCI / DMA).  It's normally dropped (below), so capture the wifi/firmware lines into the provtrace
     * ring — the boot-doctor pulls that (NSP_GETTRACE) into /run/boot-status.txt so it's readable even
     * with no terminal + no serial.  32K ring, drop-oldest, so the LAST (failure) lines survive. */
    static const char *const wifi[] = {
        "iwlwifi", "iwl_", "firmware", "ucode", "pnvm", "ALIVE", "alive", "cfg80211", "mac80211",
        "0xFFFFFFFF", "not respond", "timeout", "Timeout", "Failed", "failed", "error", "Error", "IRQ", 0
    };
    for (int i = 0; wifi[i]; i++)
        if (epin_str_contains(str, len, wifi[i])) { provtrace_append(str, (unsigned)len); break; }

    /* Forward the LKL kernel printk to fd 2 (stderr) -> FD_CONSOLE -> kchar -> the kernel klog RAM
     * ring -> /run/klog -> the "Logs" viewer, so the iwlwifi/cfg80211/mac80211 bring-up is readable
     * on-screen with no serial.  loglevel=7 (in lkl_start_kernel below) lets INFO/WARNING messages
     * reach this callback at all.
     *
     * FLOOD CONTROL: when the AX210 fails to come alive, iwlmvm auto-restarts the firmware in a tight
     * loop and re-logs the whole bring-up each time (~hundreds of lines/sec).  Unthrottled that (a)
     * starves the compositor and (b) evicts the FIRST (real) failure from the 4 MB drop-oldest ring
     * before it can be read.  So forward the first PRINT_FREE lines verbatim (the initial bring-up +
     * first failure — the part I actually need), then heavily sample (1-in-PRINT_SAMPLE) with a
     * periodic "[throttled]" marker, so the loop can't run away but the trace still trickles. */
    enum { PRINT_FREE = 3000, PRINT_SAMPLE = 32 };
    static unsigned long g_printN = 0, g_printDrop = 0;
    unsigned long n = g_printN++;
    if (n < PRINT_FREE || (n % PRINT_SAMPLE) == 0) {
        if (g_printDrop) {
            char m[64]; int ml = snprintf(m, sizeof m, "[lkl printk throttled: dropped %lu]\n", g_printDrop);
            if (ml > 0) (void)!write(2, m, ml);
            g_printDrop = 0;
        }
        (void)!write(2, str, len);
    } else {
        g_printDrop++;
    }
}

/* --- Wireless-Extensions bits (LKL ships no linux/wireless.h; these are stable uABI) --- */
#define WX_SIOCSIWSCAN  0x8B18
#define WX_SIOCGIWSCAN  0x8B19
#define WX_SIOCGIWAP    0x8B15   /* per-AP marker (BSSID) in scan results */
#define WX_SIOCGIWESSID 0x8B1B   /* SSID in scan results */
struct wx_iw_point { void *pointer; unsigned short length; unsigned short flags; };
struct wx_iwreq {
    char ifrn_name[16];
    union { char name[16]; struct wx_iw_point data; unsigned char pad[16]; } u;
};

/* Core WEXT scan: trigger on `ifname` via LKL socket `s`, format results as text into out[]
 * ("SSID: ...\n" lines + a "DONE N AP(s), M bytes\n" trailer).  Returns AP count, or -1 on error.
 * Shared by the H0 boot proof AND the cap-gated network provider (which relays out[] to a native
 * client).  This is the exact lkl_sys_* socket/ioctl path the provider forwards for wpa/NM. */
/* A wlan device runs ONE scan at a time; serialize all scans (boot proof + every provider
 * request) so concurrent SIOCSIWSCAN don't collide with -EBUSY(16). */
static pthread_mutex_t g_wifi_scan_lock = PTHREAD_MUTEX_INITIALIZER;

static int epin_wifi_scan_core(long s, const char *ifname, char *out, int outsz)
{
    int n = 0;
    int rc = -1;
#define WSC_OUT(...) do { if (n < outsz) { int _w = snprintf(out + n, outsz - n, __VA_ARGS__); \
                          if (_w > 0) n += _w; } } while (0)
    pthread_mutex_lock(&g_wifi_scan_lock);
    struct wx_iwreq wrq;
    memset(&wrq, 0, sizeof wrq);
    strncpy(wrq.ifrn_name, ifname, sizeof(wrq.ifrn_name) - 1);
    long r = lkl_sys_ioctl(s, WX_SIOCSIWSCAN, (long)&wrq);
    /* A scan already running (our own or the KERNEL's internal cfg80211 scan) rejects the trigger
     * with -EBUSY(16) or -EINVAL(22); that's not fatal - just poll GIWSCAN for that scan's results. */
    if (r < 0 && r != -16 && r != -22) { WSC_OUT("ERR scan trigger failed %ld\n", r); goto done; }

    static unsigned char buf[16384];
    for (int t = 0; t < 60; t++) {                 /* up to ~15s */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 250000000L };
        nanosleep(&ts, NULL);
        memset(&wrq, 0, sizeof wrq);
        strncpy(wrq.ifrn_name, ifname, sizeof(wrq.ifrn_name) - 1);
        wrq.u.data.pointer = buf;
        wrq.u.data.length  = sizeof buf;
        r = lkl_sys_ioctl(s, WX_SIOCGIWSCAN, (long)&wrq);
        if (r < 0) {
            if (r == -11) continue;                /* -EAGAIN: scan still in progress */
            WSC_OUT("ERR GIWSCAN failed %ld\n", r);
            goto done;
        }
        unsigned len = wrq.u.data.length;
        if (len > sizeof buf) len = sizeof buf;
        int aps = 0; unsigned o = 0;               /* walk the iw_event stream */
        while (o + 4 <= len) {
            unsigned short ev_len = *(unsigned short *)(buf + o);
            unsigned short ev_cmd = *(unsigned short *)(buf + o + 2);
            if (ev_len < 4 || (unsigned)(o + ev_len) > len) break;
            if (ev_cmd == WX_SIOCGIWAP) aps++;
            else if (ev_cmd == WX_SIOCGIWESSID && ev_len > 8) {
                unsigned sl = ev_len - 8; if (sl > 32) sl = 32;
                char ssid[33]; memcpy(ssid, buf + o + 8, sl); ssid[sl] = 0;
                WSC_OUT("SSID: %s\n", ssid[0] ? ssid : "(hidden)");
            }
            o += ev_len;
        }
        WSC_OUT("DONE %d AP(s), %u bytes\n", aps, len);
        rc = aps;
        goto done;
    }
    WSC_OUT("ERR scan timed out (RX may be dead)\n");
done:
    pthread_mutex_unlock(&g_wifi_scan_lock);
    return rc;
#undef WSC_OUT
}

/* H0 boot proof: scan once and print just the AP count (the SSID list is suppressed now to keep
 * the boot log compact — the H1b client lines below are what matter). */
static void epin_wifi_scan(long s, const char *ifname)
{
    static char out[4096];
    int aps = epin_wifi_scan_core(s, ifname, out, sizeof out);
    fprintf(stderr, ">>> wifi scan: DONE -- %d AP(s) heard on %s\n", aps, ifname);
}

/* Find wlanN (iwlwifi's async probe creates it) and bring it up.  Returns 1 + copies the ifname
 * to ifout on success (polls up to ~60s), else 0.  Real AX210 firmware initialization can exceed
 * 15 seconds on the single-core LKL path, especially immediately after boot.  Giving up at 15s let
 * the fallback USB logger begin blocking storage work just before wlan0 was ready.  Idempotent — safe to call from both the boot
 * proof and the provider's scan handler on separate LKL sockets. */
static int epin_wifi_bringup(long s, char *ifout, int outsz)
{
    static const char *const names[] = { "wlan0", "wlan1", "wlp0s0", 0 };
    for (int tries = 0; tries < 120; tries++) {
        for (int i = 0; names[i]; i++) {
            struct lkl_ifreq ifr;
            memset(&ifr, 0, sizeof ifr);
            strncpy(ifr.lkl_ifr_name, names[i], sizeof(ifr.lkl_ifr_name) - 1);
            if (lkl_sys_ioctl(s, LKL_SIOCGIFINDEX, (long)&ifr) != 0)
                continue;
            memset(&ifr, 0, sizeof ifr);
            strncpy(ifr.lkl_ifr_name, names[i], sizeof(ifr.lkl_ifr_name) - 1);
            lkl_sys_ioctl(s, LKL_SIOCGIFFLAGS, (long)&ifr);
            ifr.lkl_ifr_flags |= LKL_IFF_UP;
            lkl_sys_ioctl(s, LKL_SIOCSIFFLAGS, (long)&ifr);
            if (ifout && outsz > 0) { strncpy(ifout, names[i], outsz - 1); ifout[outsz - 1] = 0; }
            return 1;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 500000000L };  /* 500ms */
        nanosleep(&ts, NULL);
    }
    return 0;
}

/* QEMU log-egress: if a wired ethN appears (a virtio-net-pci granted to the LKL solely for the
 * scp-upload test), bring it up with the QEMU user-net (slirp) statics 10.0.2.15/24 gw 10.0.2.2
 * so the LKL TCP stack has a route to the host.  Silently exits when no ethN shows up within
 * ~15 s (FW13 / wifi-only boots have none). */
static void *epin_eth_thread(void *arg)
{
    (void)arg;
    long s = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_DGRAM, 0);
    if (s < 0) return NULL;
    static const char *const names[] = { "eth0", "eth1", 0 };
    for (int tries = 0; tries < 60; tries++) {
        for (int i = 0; names[i]; i++) {
            struct lkl_ifreq ifr;
            memset(&ifr, 0, sizeof ifr);
            strncpy(ifr.lkl_ifr_name, names[i], sizeof(ifr.lkl_ifr_name) - 1);
            if (lkl_sys_ioctl(s, LKL_SIOCGIFINDEX, (long)&ifr) != 0)
                continue;
            int ifindex = ifr.lkl_ifr_ifindex;
            /* NOTE: do NOT lkl_if_set_mac() here — that goes through virtio-net's control
             * virtqueue, whose completion IRQ misbehaves on the bridge ("irq: nobody cared"
             * → LKL host-thread crash).  The garbled config-space MAC (which made IFF_UP
             * fail -EADDRNOTAVAIL) is instead randomized at probe time by the virtio_net
             * patch in the LKL tree (is_valid_ether_addr check in virtnet_probe). */
            /* Bring the link UP the same way epin_wifi_bringup does (SIOCSIFFLAGS ioctl —
             * lkl_if_up's rtnetlink path returned -99 here), then retry the default route
             * until the kernel accepts it: right after IFF_UP the gateway add still returns
             * -ENETUNREACH until the address/link settle. */
            memset(&ifr, 0, sizeof ifr);
            strncpy(ifr.lkl_ifr_name, names[i], sizeof(ifr.lkl_ifr_name) - 1);
            lkl_sys_ioctl(s, LKL_SIOCGIFFLAGS, (long)&ifr);
            ifr.lkl_ifr_flags |= LKL_IFF_UP;
            long fu = lkl_sys_ioctl(s, LKL_SIOCSIFFLAGS, (long)&ifr);
            int r1 = lkl_if_set_ipv4(ifindex, inet_addr("10.0.2.15"), 24);
            int r2 = -1;
            for (int g = 0; g < 20; g++) {
                r2 = lkl_set_ipv4_gateway(inet_addr("10.0.2.2"));
                if (r2 == 0 || r2 == -LKL_EEXIST) { r2 = 0; break; }
                struct timespec gs = { .tv_sec = 0, .tv_nsec = 500000000L };
                nanosleep(&gs, NULL);
            }
            fprintf(stderr, ">>> eth: %s flags=%ld ip=%d gw=%d (slirp statics -> host route for scp egress)\n",
                    names[i], fu, r1, r2);
            lkl_sys_close(s);
            return NULL;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 500000000L };
        nanosleep(&ts, NULL);
    }
    lkl_sys_close(s);
    return NULL;
}

/* Bring wlan0 up + the H0 boot-proof scan (prints on-screen). */
static void epin_wifi_report(void)
{
    lkl_sys_mkdir("/proc", 0555);
    lkl_sys_mount("proc", "/proc", "proc", 0, 0);

    long s = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_DGRAM, 0);
    if (s < 0) { fprintf(stderr, ">>> wifi: socket failed %ld\n", s); return; }
    char ifname[32];
    if (epin_wifi_bringup(s, ifname, sizeof ifname)) {
        fprintf(stderr, ">>> wifi: %s up (boot scan skipped so wpa_supplicant owns the radio)\n", ifname);
        /* epin_wifi_scan(s, ifname);  // H0 boot scan disabled: it contended with wpa's own scan */
    } else {
        fprintf(stderr, ">>> wifi: no wlanN (firmware not alive)\n");
    }
    lkl_sys_close(s);
}

/* H1: the cap-gated NETWORK PROVIDER.  lkl-boot holds the wlan0 device cap (L4); it exposes a
 * NATIVE EpinAnonymOS AF_UNIX socket (NSP_PATH) that native clients (hos-wifi; later the
 * wpa_supplicant/NetworkManager syscall-shim) connect to.  The kernel gates connect() on
 * DEVCLASS_NET (deny-by-default), so only authorized domains reach wlan0 through here.
 *
 * H1b protocol: a general socket-remoting RPC (hos-net-proto.h) - the client issues SOCKET/BIND/
 * SENDTO/RECVFROM/SETSOCKOPT/CLOSE/POLL/etc and the provider runs each as the matching lkl syscall
 * against the LKL (so a native process's AF_NETLINK/AF_PACKET traffic reaches the real wlan0).
 * NOTE: the accept()/read()/write() here are NATIVE EpinAnonymOS syscalls; the lkl calls inside
 * the dispatch drive the LKL - two separate worlds bridged by this RPC. */
#define NET_PROVIDER_PATH NSP_PATH

/* read/write exactly n bytes over a stream fd; 1 = ok, 0 = eof/error.  EpinAnonymOS AF_UNIX
 * read/write are NON-blocking (return -EAGAIN when the rx buffer is empty / tx buffer full and
 * the peer is still open), so we retry on EAGAIN — waiting EVENT-DRIVEN in host poll() (the kernel
 * parks this thread and wakes it within a ~1ms tick of readiness) instead of the old flat 2ms
 * nanosleep.  That nap was a scheduling quantum under EVERY RPC (the serve loop sits in
 * nsp_read_full between requests), and across NM's thousands of boot-enumeration netlink
 * round-trips it summed to tens of seconds of WiFi bring-up; idle it was 500 wakeups/s per
 * connection of pure churn, now a parked poll.  Only a real 0 (peer closed / EOF) or a non-EAGAIN
 * error ends the loop; the poll timeout is just a safety re-check bound. */
static void nsp_wait(int fd, short ev){ struct pollfd p = { fd, ev, 0 }; poll(&p, 1, 1000); }
static int nsp_read_full(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        long r = read(fd, (char *)buf + got, n - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r < 0 && errno == EAGAIN) { nsp_wait(fd, POLLIN); continue; }
        return 0;   /* r == 0 (EOF) or a real error */
    }
    return 1;
}
static int nsp_write_full(int fd, const void *buf, size_t n)
{
    size_t put = 0;
    while (put < n) {
        long r = write(fd, (const char *)buf + put, n - put);
        if (r > 0) { put += (size_t)r; continue; }
        if (r < 0 && errno == EAGAIN) { nsp_wait(fd, POLLOUT); continue; }
        return 0;
    }
    return 1;
}

/* M4 diagnostics: the shim can't write files on the laptop (a file write from NM's LD_PRELOAD context
 * faults), so it ships trace lines here via NSP_LOG.  We accumulate them in this in-memory ring and hand
 * the whole thing back on NSP_GETTRACE, which the boot-doctor (a safe, separate process) writes to a
 * terminal-readable file.  Guarded by a mutex — many client threads call NSP_LOG concurrently. */
#define PROVTRACE_CAP 32768
static char            g_provtrace[PROVTRACE_CAP];
static unsigned        g_provtracelen;
static pthread_mutex_t g_provtracelock = PTHREAD_MUTEX_INITIALIZER;
static void provtrace_append(const char *s, unsigned n)
{
    /* NON-BLOCKING: this is called from epin_lkl_print() = the LKL console/printk callback, which runs on
     * the LKL CPU thread in emulated-atomic context.  Under a real-AX210 firmware error-storm the printk
     * rate can be high; a blocking lock here could serialize/stall the LKL's printk-heavy thread and stop
     * it pumping USB-HID input -> the kernel-drawn cursor freezes.  trylock-and-drop: if the ring is busy
     * (e.g. the NSP_GETTRACE consumer holds it), just drop this diagnostic line — never block the LKL. */
    if (pthread_mutex_trylock(&g_provtracelock) != 0) return;
    if (g_provtracelen + n + 1 >= PROVTRACE_CAP) {         /* full: drop oldest half */
        unsigned drop = PROVTRACE_CAP / 2;
        if (drop < g_provtracelen) { memmove(g_provtrace, g_provtrace + drop, g_provtracelen - drop); g_provtracelen -= drop; }
        else g_provtracelen = 0;
    }
    if (n + 1 < PROVTRACE_CAP) {
        memcpy(g_provtrace + g_provtracelen, s, n); g_provtracelen += n;
        g_provtrace[g_provtracelen++] = '\n';
    }
    pthread_mutex_unlock(&g_provtracelock);
}

/* Per-LKL-fd SO_TYPE cache.  NSP_RECVFROM needs the socket type to decide whether to OR in MSG_TRUNC,
 * but SO_TYPE is immutable per socket, so querying it via getsockopt on EVERY receive doubled the LKL
 * syscalls on NM's hottest path.  Cache it: populated at NSP_SOCKET (the type is the create arg),
 * cleared at NSP_CLOSE, and lazily filled on a recvfrom cache-miss (fds not born via NSP_SOCKET).
 * 0 = unknown.  A stale-0 read merely recomputes (still correct); the ONLY nonzero writer is create
 * with the true type, so a read can never see a WRONG nonzero value even under the pooled-connection
 * concurrency.  LKL fds are small ints; index is range-guarded.  SOCK_NONBLOCK/SOCK_CLOEXEC are
 * masked off the create arg so the base type (SOCK_STREAM=1/DGRAM=2/RAW=3) is stored. */
#define NSP_SOTYPE_MAX 4096
static int g_sotype[NSP_SOTYPE_MAX];

/* Serve one connected client: a loop of framed RPC requests, each executed against the LKL. */
static void epin_net_serve_conn(int cs)
{
    /* respbuf GROWS on demand (up to NSP_HARDCAP) so a large AX210 RX datagram is carried whole instead
     * of truncated.  reqbuf stays FIXED at NSP_MAXBUF: netlink TX requests are tiny, and keeping reqbuf
     * bounded by NSP_MAXBUF keeps every respbuf-sized copy (esp. NSP_IOCTL's memcpy(respbuf,reqbuf,buflen))
     * within respcap (>= NSP_MAXBUF always).  Small reads (the common case, all of QEMU) never realloc. */
    size_t respcap = NSP_MAXBUF;
    unsigned char *reqbuf  = malloc(NSP_MAXBUF);
    unsigned char *respbuf = malloc(respcap);
    unsigned char reqaddr[256], respaddr[256];
    if (!reqbuf || !respbuf) { free(reqbuf); free(respbuf); close(cs); return; }
    for (;;) {
        nsp_req rq;
        if (!nsp_read_full(cs, &rq, sizeof rq)) break;
        if (rq.buflen > NSP_MAXBUF || rq.addrlen > sizeof reqaddr) break;
        if (rq.buflen  && !nsp_read_full(cs, reqbuf,  rq.buflen))  break;
        if (rq.addrlen && !nsp_read_full(cs, reqaddr, rq.addrlen)) break;

        nsp_resp rs; memset(&rs, 0, sizeof rs);
        long p[6] = {0,0,0,0,0,0};
        switch (rq.op) {
        case NSP_SOCKET:
            rs.ret = lkl_sys_socket(rq.a0, rq.a1, rq.a2);
            if (rs.ret >= 0 && rs.ret < NSP_SOTYPE_MAX)     /* memoize base SO_TYPE for NSP_RECVFROM */
                g_sotype[rs.ret] = rq.a1 & ~(04000 /*SOCK_NONBLOCK*/ | 02000000 /*SOCK_CLOEXEC*/);
            break;
        case NSP_BIND:
            p[0]=rq.fd; p[1]=(long)reqaddr; p[2]=rq.addrlen;
            rs.ret = lkl_syscall(__lkl__NR_bind, p);
            break;
        case NSP_CONNECT:
            p[0]=rq.fd; p[1]=(long)reqaddr; p[2]=rq.addrlen;
            rs.ret = lkl_syscall(__lkl__NR_connect, p);
            break;
        case NSP_SENDTO:
            p[0]=rq.fd; p[1]=(long)reqbuf; p[2]=rq.buflen; p[3]=rq.a2;
            p[4]=rq.addrlen?(long)reqaddr:0; p[5]=rq.addrlen;
            rs.ret = lkl_syscall(__lkl__NR_sendto, p);
            break;
        case NSP_RECVFROM: {
            /* maxlen = the client's requested capacity; floor a bad/zero/negative a0 to NSP_MAXBUF and
             * ceil to NSP_HARDCAP so a garbage value can neither under-read nor trigger a huge alloc. */
            unsigned maxlen = ((int)rq.a0 <= 0) ? NSP_MAXBUF : (unsigned)rq.a0;
            if (maxlen > NSP_HARDCAP) maxlen = NSP_HARDCAP;
            if (maxlen > respcap) {   /* grow respbuf to hold the requested (large) datagram whole */
                unsigned char *nb = realloc(respbuf, maxlen);
                if (!nb) { rs.ret = -12 /*ENOMEM*/; break; }
                respbuf = nb; respcap = maxlen;
            }
            unsigned alen = sizeof respaddr;
            /* Wait up to 1s for readability first, so a missing/expected-empty reply can't block
             * this client's thread forever (e.g. a client that reads past a netlink dump's end).
             * On timeout we return -EAGAIN; for blocking fds the SHIM retries (libnshim.c recvfrom:
             * ~60s cap while a request is outstanding, with a lost-reply RE-REQUEST at ~5s; ~240s
             * for pure event waits).  This ppoll is fully event-driven: data arriving mid-wait
             * returns immediately, so the 1s costs nothing on the happy path. */
            struct { int fd; short events; short revents; } pfd = { rq.fd, 1 /*POLLIN*/, 0 };
            struct { long sec, nsec; } tmo = { 1, 0 };   /* 1s: the shim retries for blocking fds */
            long pp[6] = { (long)&pfd, 1, (long)&tmo, 0, 8, 0 };
            long pr = lkl_syscall(__lkl__NR_ppoll, pp);
            if (pr <= 0) { rs.ret = (pr == 0) ? -11 /*EAGAIN: timed out*/ : pr; break; }
            /* OR in MSG_TRUNC (0x20) only for datagram sockets: on netlink, if the datagram is larger than maxlen the
             * kernel copies maxlen bytes and DISCARDS the tail — but with MSG_TRUNC recvfrom returns the
             * TRUE datagram length.  Applying MSG_TRUNC to TCP is invalid stream emulation and can discard
             * bytes, so first query SO_TYPE and preserve the caller's flags for SOCK_STREAM. */
            /* SO_TYPE is immutable — use the per-fd cache (populated at NSP_SOCKET); only query LKL on
             * a miss, then memoize.  Removes one getsockopt syscall per receive on NM's hottest path. */
            int stype = (rq.fd >= 0 && rq.fd < NSP_SOTYPE_MAX) ? g_sotype[rq.fd] : 0;
            int sr = 0;
            if (stype == 0) {
                unsigned stypelen = sizeof stype;
                long sp[6] = { rq.fd, LKL_SOL_SOCKET, LKL_SO_TYPE, (long)&stype, (long)&stypelen, 0 };
                sr = (int)lkl_syscall(__lkl__NR_getsockopt, sp);
                if (sr == 0 && rq.fd >= 0 && rq.fd < NSP_SOTYPE_MAX) g_sotype[rq.fd] = stype;
            }
            int recvflags = rq.a2;
            if (sr == 0 && stype != LKL_SOCK_STREAM) recvflags |= 0x20 /*MSG_TRUNC*/;
            p[0]=rq.fd; p[1]=(long)respbuf; p[2]=maxlen; p[3]=recvflags;
            p[4]=(long)respaddr; p[5]=(long)&alen;
            rs.ret = lkl_syscall(__lkl__NR_recvfrom, p);
            /* rs.ret is the TRUE datagram length; respbuf holds only min(true,maxlen) bytes, so send just
             * that many (fixes an OOB where buflen=rs.ret could exceed respbuf/NSP_MAXBUF). */
            if (rs.ret > 0) rs.buflen = ((uint32_t)rs.ret < maxlen) ? (uint32_t)rs.ret : maxlen;
            if (alen <= sizeof respaddr) rs.addrlen = alen;
            break; }
        case NSP_SETSOCKOPT:
            p[0]=rq.fd; p[1]=rq.a0; p[2]=rq.a1; p[3]=(long)reqbuf; p[4]=rq.buflen;
            rs.ret = lkl_syscall(__lkl__NR_setsockopt, p);
            break;
        case NSP_GETSOCKOPT: {
            unsigned optlen = (unsigned)rq.a2; if (optlen > NSP_MAXBUF) optlen = NSP_MAXBUF;
            p[0]=rq.fd; p[1]=rq.a0; p[2]=rq.a1; p[3]=(long)respbuf; p[4]=(long)&optlen;
            rs.ret = lkl_syscall(__lkl__NR_getsockopt, p);
            if (rs.ret == 0) rs.buflen = optlen;
            break; }
        case NSP_GETSOCKNAME: {
            unsigned alen = sizeof respaddr;
            p[0]=rq.fd; p[1]=(long)respaddr; p[2]=(long)&alen;
            rs.ret = lkl_syscall(__lkl__NR_getsockname, p);
            if (rs.ret == 0 && alen <= sizeof respaddr) rs.addrlen = alen;
            break; }
        case NSP_GETPEERNAME: {
            unsigned alen = sizeof respaddr;
            p[0]=rq.fd; p[1]=(long)respaddr; p[2]=(long)&alen;
            rs.ret = lkl_syscall(__lkl__NR_getpeername, p);
            if (rs.ret == 0 && alen <= sizeof respaddr) rs.addrlen = alen;
            break; }
        case NSP_SHUTDOWN:
            p[0]=rq.fd; p[1]=rq.a0;
            rs.ret = lkl_syscall(__lkl__NR_shutdown, p);
            break;
        case NSP_CLOSE:
            if (rq.fd >= 0 && rq.fd < NSP_SOTYPE_MAX) g_sotype[rq.fd] = 0;  /* fd numbers get reused */
            rs.ret = lkl_sys_close(rq.fd);
            break;
        case NSP_IOCTL:
            /* arg struct (e.g. struct ifreq) is in reqbuf; the ioctl reads+writes it in place. */
            rs.ret = lkl_sys_ioctl(rq.fd, rq.a0, (long)reqbuf);
            if (rs.ret >= 0 && rq.buflen) { memcpy(respbuf, reqbuf, rq.buflen); rs.buflen = rq.buflen; }
            break;
        case NSP_POLL: {
            struct { int fd; short events; short revents; } pfd = { rq.fd, (short)rq.a0, 0 };
            struct { long sec, nsec; } tmo = { rq.a1/1000, (long)(rq.a1%1000)*1000000L };
            p[0]=(long)&pfd; p[1]=1; p[2]=(rq.a1<0)?0:(long)&tmo; p[3]=0; p[4]=8;
            rs.ret = lkl_syscall(__lkl__NR_ppoll, p);
            if (rs.ret > 0) rs.ret = pfd.revents;
            break; }
        case NSP_SCAN: {
            long ws = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_DGRAM, 0);
            int aps = -1;
            if (ws >= 0) {
                char ifn[32];
                if (epin_wifi_bringup(ws, ifn, sizeof ifn))
                    aps = epin_wifi_scan_core(ws, ifn, (char *)respbuf, NSP_MAXBUF);
                else { const char *m="ERR wlan not up yet\n"; memcpy(respbuf,m,strlen(m)); }
                lkl_sys_close(ws);
            } else { const char *m="ERR lkl socket\n"; memcpy(respbuf,m,strlen(m)); }
            rs.ret = aps;
            rs.buflen = (uint32_t)strlen((char *)respbuf);
            fprintf(stderr, ">>> net-provider: served SCAN (%d AP(s)) to a native client\n", aps);
            break; }
        case NSP_LOG:
            if (rq.buflen >= NSP_MAXBUF) rq.buflen = NSP_MAXBUF - 1;
            reqbuf[rq.buflen] = 0;
            fprintf(stderr, ">>> net-provider[client]: %s\n", (char *)reqbuf);
            provtrace_append((char *)reqbuf, rq.buflen);   /* keep for NSP_GETTRACE (boot-doctor -> file) */
            rs.ret = 0;
            break;
        case NSP_GETTRACE: {                               /* return the accumulated shim trace */
            pthread_mutex_lock(&g_provtracelock);
            unsigned n = g_provtracelen < NSP_MAXBUF ? g_provtracelen : NSP_MAXBUF;
            if (n) memcpy(respbuf, g_provtrace, n);
            pthread_mutex_unlock(&g_provtracelock);
            rs.ret = n; rs.buflen = n;
            break; }
        default:
            rs.ret = -38; /* -ENOSYS */
            break;
        }
        if (!nsp_write_full(cs, &rs, sizeof rs)) break;
        if (rs.buflen  && !nsp_write_full(cs, respbuf,  rs.buflen))  break;
        if (rs.addrlen && !nsp_write_full(cs, respaddr, rs.addrlen)) break;
    }
    free(reqbuf); free(respbuf);
    close(cs);
}

static void *epin_net_conn_thread(void *arg)
{
    epin_net_serve_conn((int)(intptr_t)arg);
    return NULL;
}

/* ---- SSH-in bridge: LKL TCP :22  <->  native AF_UNIX /run/sshd.sock ------------
 * The working network is the LKL's (WiFi on real HW), so inbound SSH must be accepted on
 * the LKL stack. This thread lkl_sys_listen()s on :22 and relays each accepted connection
 * to the native hos-sshd-launch daemon over /run/sshd.sock, which forks `dropbear -i` on it.
 * lkl-boot is uniquely able to bridge because it makes BOTH lkl_sys_* (LKL) and native
 * syscalls (AF_UNIX to EpinAnonymOS). No nshim/provider protocol change needed. */
#define SSHD_BRIDGE_SOCK "/run/sshd.sock"
#define SSHD_BRIDGE_LOG  "/run/sshd.log"
struct ssh_relay { long lkl_fd; int unix_fd; };

/* Log a bridge event to BOTH stderr (-> /run/klog) and the dedicated /run/sshd.log so it
 * shows in the Logs app under SUPER+L -> Tab to /run/sshd.log. Native open/write (lkl-boot
 * makes native EpinAnonymOS syscalls); the kernel's *.log tap also mirrors it into klog. */
static int g_sshlog_fd = -2;
static void ssh_log(const char *msg)
{
    fprintf(stderr, ">>> sshd-bridge: %s\n", msg);
    if (g_sshlog_fd == -2) g_sshlog_fd = open(SSHD_BRIDGE_LOG, 01 /*O_WRONLY*/ | 0100 /*O_CREAT*/ | 02000 /*O_APPEND*/, 0644);
    if (g_sshlog_fd >= 0) {
        char b[256]; int n = snprintf(b, sizeof b, "[bridge] %s\n", msg);
        if (n > 0) { ssize_t w = write(g_sshlog_fd, b, (size_t)n); (void)w; }
    }
}

/* Pump native unix_fd -> lkl_fd (client->server bytes). The sibling thread does the reverse. */
static void *epin_ssh_relay_up(void *arg)
{
    struct ssh_relay *r = (struct ssh_relay *)arg;
    char buf[8192];
    for (;;) {
        long n = read(r->unix_fd, buf, sizeof buf);          /* native AF_UNIX read */
        if (n <= 0) break;
        long off = 0;
        while (off < n) {
            long w = lkl_sys_write(r->lkl_fd, buf + off, (unsigned)(n - off));   /* LKL write */
            if (w <= 0) goto done;
            off += w;
        }
    }
done:
    lkl_sys_shutdown(r->lkl_fd, 2 /*SHUT_RDWR*/);
    shutdown(r->unix_fd, 2);
    return NULL;
}

static void *epin_ssh_bridge_thread(void *arg)
{
    (void)arg;
    /* SSH-in is OPT-IN: the kernel spawns hos-sshd-launch (which creates /run/sshd.sock) only when
     * /epin-ssh.conf is staged (SSH=1). If the launcher never comes up, do NOT bind LKL tcp/22 — a
     * blocking listener on the LKL stack must not run on a normal (WiFi) boot. Wait ~60s for the
     * launcher socket; if it never appears, exit the bridge quietly (no :22, no WiFi interference). */
    int launcher_up = 0;
    for (int i = 0; i < 120; i++) {
        if (access(SSHD_BRIDGE_SOCK, 0 /*F_OK*/) == 0) { launcher_up = 1; break; }
        struct timespec s = { 0, 500000000 }; nanosleep(&s, NULL);   /* 0.5s */
    }
    if (!launcher_up) return NULL;   /* SSH disabled (no launcher) — bridge stays dormant */
    ssh_log("launcher present; creating LKL tcp socket for :22");
    long ls = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_STREAM, 0);
    if (ls < 0) { char m[64]; snprintf(m, sizeof m, "lkl socket FAILED (%ld)", ls); ssh_log(m); return NULL; }
    int one = 1;
    lkl_sys_setsockopt(ls, LKL_SOL_SOCKET, 2 /*SO_REUSEADDR*/, &one, sizeof one);
    struct lkl_sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = LKL_AF_INET;
    sa.sin_port   = (unsigned short)((22 << 8) | (22 >> 8));   /* htons(22) on little-endian */
    sa.sin_addr.lkl_s_addr = 0;                                /* INADDR_ANY */
    long br;
    for (int i = 0; i < 60; i++) {                            /* retry: interface may still be coming up */
        br = lkl_sys_bind(ls, (struct lkl_sockaddr *)&sa, sizeof sa);
        if (br == 0) break;
        struct timespec s = { 1, 0 }; nanosleep(&s, NULL);
    }
    if (br != 0) { char m[64]; snprintf(m, sizeof m, "lkl bind :22 FAILED (%ld)", br); ssh_log(m); lkl_sys_close(ls); return NULL; }
    if (lkl_sys_listen(ls, 4) != 0) { ssh_log("lkl listen FAILED"); lkl_sys_close(ls); return NULL; }
    ssh_log("LISTENING on LKL tcp/22 -> relays to /run/sshd.sock (dropbear)");

    for (;;) {
        /* ppoll-with-timeout, NOT a raw blocking accept: a blocking lkl_sys_accept would hold the
         * LKL cpu and STARVE the WiFi scan path (which shares the single LKL). The event-driven
         * ppoll yields the cpu (same pattern the net-provider uses) so scanning keeps working. */
        struct { int fd; short events; short revents; } pfd = { (int)ls, 1 /*POLLIN*/, 0 };
        struct { long sec, nsec; } tmo = { 1, 0 };   /* 1s wait; returns immediately on a connection */
        long pp[6] = { (long)&pfd, 1, (long)&tmo, 0, 8, 0 };
        long pr = lkl_syscall(__lkl__NR_ppoll, pp);
        if (pr <= 0) continue;                        /* timeout/err: yield, retry (WiFi runs meanwhile) */
        long cs = lkl_sys_accept(ls, NULL, NULL);
        if (cs < 0) { struct timespec s = { 0, 20000000 }; nanosleep(&s, NULL); continue; }
        ssh_log("SSH connection accepted on tcp/22");
        /* Connect to the native dropbear launcher. */
        int us = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un ua; memset(&ua, 0, sizeof ua);
        ua.sun_family = AF_UNIX; strncpy(ua.sun_path, SSHD_BRIDGE_SOCK, sizeof(ua.sun_path) - 1);
        if (us < 0 || connect(us, (struct sockaddr *)&ua, sizeof ua) != 0) {
            char m[96]; snprintf(m, sizeof m, "launcher /run/sshd.sock NOT reachable (errno %d) — is hos-sshd-launch up? dropping", errno);
            ssh_log(m);
            if (us >= 0) close(us);
            lkl_sys_close(cs);
            continue;
        }
        ssh_log("relaying SSH session to dropbear via /run/sshd.sock");
        struct ssh_relay *r = malloc(sizeof *r);
        r->lkl_fd = cs; r->unix_fd = us;
        pthread_t up;
        pthread_create(&up, NULL, epin_ssh_relay_up, r);       /* unix -> lkl */
        pthread_detach(up);
        /* This thread does lkl -> unix inline, then cleans up when either side closes. */
        char buf[8192];
        for (;;) {
            long n = lkl_sys_read(cs, buf, sizeof buf);
            if (n <= 0) break;
            long off = 0;
            while (off < n) { long w = write(us, buf + off, (size_t)(n - off)); if (w <= 0) goto rdone; off += w; }
        }
    rdone:
        lkl_sys_shutdown(cs, 2); shutdown(us, 2);
        /* the up-relay exits on its own read returning 0; give it a moment then close fds */
        struct timespec s = { 0, 50000000 }; nanosleep(&s, NULL);
        lkl_sys_close(cs); close(us);
        ssh_log("SSH session closed");
    }
    return NULL;
}

static void *epin_net_provider_thread(void *arg)
{
    (void)arg;
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0) { fprintf(stderr, ">>> net-provider: socket failed (errno %d)\n", errno); return NULL; }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path) - 1);
    unlink(NSP_PATH);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) < 0) {
        fprintf(stderr, ">>> net-provider: bind %s failed (errno %d)\n", NSP_PATH, errno);
        return NULL;
    }
    if (listen(ls, 8) < 0) {
        fprintf(stderr, ">>> net-provider: listen failed (errno %d)\n", errno);
        return NULL;
    }
    fprintf(stderr, ">>> net-provider: listening on %s (cap-gated: DEVCLASS_NET, RPC)\n", NSP_PATH);

    static int connCount = 0;
    for (;;) {
        /* EpinAnonymOS accept() is non-blocking (-EAGAIN when no client is queued): park in poll()
         * until the listener is readable instead of the old flat 100ms nanosleep — a connecting
         * client (wpa/NM/udhcpc launch) is served within a tick rather than up to 100ms late, and
         * an idle provider makes no wakeups at all. */
        struct pollfd lp = { ls, POLLIN, 0 };
        poll(&lp, 1, 1000);
        int cs = accept(ls, NULL, NULL);
        if (cs < 0) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 20000000L };
            nanosleep(&ts, NULL);   /* real accept error (not just empty queue): don't hot-spin */
            continue;
        }
        fprintf(stderr, ">>> net-provider: client #%d connected (fd %d)\n", ++connCount, cs);
        /* thread-per-connection so a blocking netlink recv on one client can't stall others */
        pthread_t th;
        if (pthread_create(&th, NULL, epin_net_conn_thread, (void *)(intptr_t)cs) == 0)
            pthread_detach(th);
        else
            close(cs);
    }
    return NULL;
}

/* Self-test client (output visible via lkl-boot's own stderr): connect to OUR provider socket
 * and run a SCAN.  Proves the AF_UNIX provider + protocol + serve-via-LKL work in-environment,
 * independent of the external hos-wifi process (isolates provider bugs from client/spawn bugs). */
static void *epin_net_selftest_thread(void *arg)
{
    (void)arg;
    int s = -1;
    for (int i = 0; i < 600; i++) {                 /* retry ~60s (provider + wlan0 come up async) */
        s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s >= 0) {
            struct sockaddr_un sa;
            memset(&sa, 0, sizeof sa);
            sa.sun_family = AF_UNIX;
            strncpy(sa.sun_path, NET_PROVIDER_PATH, sizeof(sa.sun_path) - 1);
            if (connect(s, (struct sockaddr *)&sa, sizeof sa) == 0) break;
            close(s);
        }
        s = -1;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L };
        nanosleep(&ts, NULL);
    }
    if (s < 0) { fprintf(stderr, ">>> net-selftest: could not connect to provider\n"); return NULL; }
    /* speak the H1b binary RPC: one NSP_SCAN request */
    nsp_req rq; memset(&rq, 0, sizeof rq); rq.op = NSP_SCAN;
    nsp_resp rs; static char buf[4096];
    if (!nsp_write_full(s, &rq, sizeof rq) || !nsp_read_full(s, &rs, sizeof rs)) {
        fprintf(stderr, ">>> net-selftest: RPC framing error\n"); close(s); return NULL;
    }
    unsigned n = rs.buflen < sizeof(buf) - 1 ? rs.buflen : sizeof(buf) - 1;
    if (n && !nsp_read_full(s, buf, n)) n = 0;
    buf[n] = 0;
    close(s);
    fprintf(stderr, ">>> net-selftest: NSP_SCAN round-trip OK (ret=%ld AP(s))\n", (long)rs.ret);
    return NULL;
}

int main(int argc, char **argv)
{
    long ret;

    /* L4 isolation demo: we were granted a cap for ONLY our device (NVMe). Prove the 0x4100 bridge is
     * default-deny -- a config read of a NON-granted device (the host bridge at bdf 0) must be rejected. */
    long denied = epin_pci_call(0, 0x000000, 0, 4, 0);
    fprintf(stderr, ">>> epin_pci: L4 isolation -- config-read non-granted bdf 0 -> %ld (%s)\n",
            denied, denied < 0 ? "DENIED (good -- cannot see other devices)" : "ALLOWED (BAD!)");

    ops = lkl_host_ops;                       /* start from the default posix-host ops */
    ops.print             = epin_lkl_print;   /* filter the LKL kernel printk flood off-screen */
    ops.timer_alloc       = ht_timer_alloc;   /* ...and swap the clock for our thread timer */
    ops.timer_set_oneshot = ht_timer_set_oneshot;
    ops.timer_free        = ht_timer_free;
    ops.pci_ops           = &epin_pci_ops;    /* L3a: our native-PCI backend */
    ops.shmem_init        = epin_shmem_init;  /* L6.0: LKL MMU phys-mem via memfd (no shm_open) */
    ops.shmem_mmap        = epin_shmem_mmap;

    if ((ret = lkl_init(&ops)) < 0) {
        fprintf(stderr, "lkl_init failed: %ld\n", ret);
        return 1;
    }
    /* lkl_pci=epin -> the kernel calls epin_pci_ops.add("epin") + scans bus 0 via .read */
    /* W1: the WiFi build (cfg80211+mac80211+iwlwifi + all WLAN drivers + embedded AX210
     * firmware) needs FAR more than the old minimal 32M — 32M OOM-panics in early init
     * ("System is deadlocked on memory").  256M (memfd-backed; EpinAnonymOS's ftruncate
     * allocates it eagerly + CONTIGUOUS, so don't over-ask — 256M is ample for the stack). */
    /* loglevel=7 (console_loglevel: print everything up to KERN_DEBUG): the AX210/iwlwifi bring-up
     * trace we need to debug (firmware load, ALIVE, PCI/DMA, MSI-X registrations) is mostly KERN_INFO,
     * which loglevel=4 silently dropped before printk reached epin_lkl_print.  The flood is now cheap
     * and desirable: epin_lkl_print forwards it to fd 2 -> the kernel klog ring -> /run/klog -> the
     * on-desktop Logs viewer (not the slow framebuffer console).  Dropped `quiet` for the same reason. */
    /* mac80211_hwsim.radios=0: the wifi-lkl.config builds in mac80211_hwsim (a SIMULATED wifi radio,
     * handy for testing the stack with no hardware).  On the real FW13 it auto-creates 2 PHANTOM
     * radios (wlan0/wlan1, MACs 02:00:00:00:0x:00) that NetworkManager latches onto INSTEAD of the
     * real AX210 (wlan2, C4:FF:99:...) — NM constructs its NMDeviceWifi for the fake wlan0 and stalls
     * there, never managing the real card.  radios=0 creates ZERO fake radios so the AX210 is the sole
     * (and first-enumerated) Wi-Fi device NM manages. */
    /* loglevel=5 (KERN_WARNING and above): the AX210 bring-up trace is captured/understood, so drop the
     * verbose INFO printk flood — every char of it runs through kchar → the klog ring, which is sustained
     * single-core load that worsens the desktop contention.  Raise back to 7 only when debugging the driver. */
    /* ONE LKL now drives ALL our granted devices (AX210 WiFi + xHCI USB, each on its own PCI bus), so we
     * run every service in this single instance (WiFi + USB), sized for the WiFi stack (the big consumer;
     * usb-storage is light on top). */
    /* Keep INFO enabled while AX210 bring-up is unresolved.  iwlwifi reports firmware selection,
     * hardware revision and the exact probe stage at INFO; loglevel=5 hid all of that and left only
     * the later "waiting for wlan0" symptom.  epin_lkl_print already throttles the stream. */
    ret = lkl_start_kernel("mem=256M loglevel=7 lkl_pci=epin mac80211_hwsim.radios=0");
    if (ret < 0) {
        fprintf(stderr, "lkl_start_kernel failed: %ld\n", ret);
        return 1;
    }
    fprintf(stderr, ">>> LKL up inside EpinAnonymOS.\n");
    /* iwlwifi requests its embedded firmware asynchronously during the PCI probe.  LKL is a
     * single-CPU cooperative kernel: immediately starting provider/input threads and repeatedly
     * issuing SIOCGIFINDEX from epin_wifi_bringup made those host syscalls contend with the queued
     * firmware worker.  The hardware log proved it: regulatory/firmware work did not run until
     * ~82 seconds, after the polling phase.  Leave the freshly booted LKL alone briefly; its timer
     * IRQ thread continues entering the kernel and can schedule the firmware worker, but no service
     * client can take the CPU away from it. */
    fprintf(stderr, ">>> wifi: quiet firmware settle (10s before provider clients/polling)...\n");
    {
        struct timespec settle = { .tv_sec = 10, .tv_nsec = 0 };
        while (nanosleep(&settle, &settle) != 0 && errno == EINTR) {}
    }
    fprintf(stderr, ">>> wifi: firmware settle complete; starting services\n");
    /* L5: do NOT halt — the USB enumeration runs ASYNCHRONOUSLY in the kernel's hub work-thread.
     * Halting here rebooted the kernel mid-enumeration ("reboot: Restarting system" at ~t=3s),
     * before usbhid bound + /dev/input/event* appeared — THAT was the "stall".  Keep the LKL
     * resident so the keyboard/mouse fully enumerate; the input bridge (read /dev/input/event*
     * -> EpinAnonymOS input rings) lands here next. */
    /* ONE LKL, ALL services (it owns every granted device).  USB (input bridge + /run/klog capture) AND
     * WiFi (net provider + wlan0 bring-up) run together.  Each self-guards: the input readers/usblog just
     * wait if there's no USB device; wifi_report fails softly if there's no wlan0. */
    lkl_sys_mkdir("/dev", 0755);
    lkl_sys_mkdir("/dev/input", 0755);
    pthread_t tkbd, tmse, tusb, tnet;
    int start_usblog_after_wifi = 0;
    pthread_create(&tkbd, NULL, epin_input_reader, &g_kbdReader);   /* USB kbd/mouse -> input rings */
    pthread_create(&tmse, NULL, epin_input_reader, &g_mseReader);
    /* Log egress: when the scp uploader is configured (/epin-debug-net.conf present), the NETWORK path
     * owns log delivery — do NOT run the USB-stick hunt.  (USB capture was exhausted as unreliable on
     * this hardware, and its blocking mount attempts share the single LKL "cpu" with the net provider,
     * slowing association.)  USB remains only as the fallback for boots with no debug-net config. */
    {
        int cfd = open("/epin-debug-net.conf", 0 /*O_RDONLY*/);
        if (cfd >= 0) {
            close(cfd);
            fprintf(stderr, ">>> usblog: /epin-debug-net.conf present -> network scp owns log egress; USB capture disabled\n");
        } else {
            /* Do not start this yet.  USB partition enumeration/mount attempts are blocking LKL
             * storage operations on the same single cooperative LKL CPU used by iwlwifi's async
             * firmware loader.  Starting the probe here used to starve the AX210 probe before it
             * registered wlan0 (the last visible line was "usblog: probing..."). */
            start_usblog_after_wifi = 1;
        }
    }
    /* H1: start the WiFi provider EARLY (before the blocking boot scan) so its socket exists ASAP — a
     * native client reaches wlan0 only through this DEVCLASS_NET-gated AF_UNIX socket. */
    pthread_create(&tnet, NULL, epin_net_provider_thread, NULL);
    /* SSH-in: bridge LKL tcp/22 -> native dropbear launcher so the machine is remotely reachable. */
    { pthread_t tssh; pthread_create(&tssh, NULL, epin_ssh_bridge_thread, NULL); pthread_detach(tssh); }
    /* QEMU scp-egress: configure a granted virtio-net ethN with slirp statics (no-op if absent). */
    {
        pthread_t teth;
        if (pthread_create(&teth, NULL, epin_eth_thread, NULL) == 0)
            pthread_detach(teth);
    }
    /* bring wlan0 up once iwlwifi's async probe creates it + prove the scan/RX path (H0) */
    epin_wifi_report();
    /* Wi-Fi has now had its exclusive firmware/device-registration window.  Only after
     * that critical path completes (or reports a real failure) may the fallback USB logger perform
     * its blocking partition and mount probes. */
    if (start_usblog_after_wifi)
        pthread_create(&tusb, NULL, epin_usblog_thread, NULL);      /* /run/klog -> USB stick */

    /* NOTE: the old "run hos-init as an LKL userspace process" Stage 0 is REMOVED — proven
     * impossible: LKL has no cpu user-mode (arch/lkl start_thread() is an empty stub), so it
     * cannot execute a separate ELF's code.  NetworkManager will run NATIVE on EpinAnonymOS
     * with its network syscalls routed into this LKL via a cap-gated provider (hijack). */

    fprintf(stderr, ">>> LKL resident.\n");
    for (;;) {
        struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
        nanosleep(&ts, NULL);
    }
    return 0;   /* unreached */
}
