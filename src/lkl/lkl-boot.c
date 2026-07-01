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
#include <errno.h>
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
static struct epin_pci_dev g_epin_pci;

static struct lkl_pci_dev *epin_pci_add(const char *name, void *kernel_ram, unsigned long ram_size)
{
    (void)name; (void)kernel_ram; (void)ram_size;
    long bdf = epin_pci_call(2, 0, 0x0280, 0, 0); /* W1: prefer the WiFi card (network ctrl, class 0x0280 = Intel AX210) */
    if (bdf < 0)
        bdf = epin_pci_call(2, 0, 0x0380, 0, 0); /* L6.1: else a display controller (bochs GPU, 0x0380) */
    if (bdf < 0)
        bdf = epin_pci_call(2, 0, 0x0c03, 0, 0); /* else a USB controller (xHCI, class 0x0c03) — L5 */
    if (bdf < 0)
        bdf = epin_pci_call(2, 0, 0x0108, 0, 0); /* else NVMe (class 0x0108) — the L3/L4 vehicle */
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

/* .map_page: translate an LKL buffer's virtual addr -> a phys IOVA the device can DMA to (op5). */
static unsigned long long epin_pci_map_page(struct lkl_pci_dev *dev, void *vaddr, unsigned long sz)
{
    (void)dev; (void)sz;
    long phys = epin_pci_call(5, (long)(uintptr_t)vaddr, 0, 0, 0);   /* op5 = virt->phys */
    if (phys <= 0) {
        fprintf(stderr, ">>> epin_pci: map_page(%p) FAILED (not mapped)\n", vaddr);
        return 0;
    }
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
static void epin_lkl_print(const char *str, int len)
{
    static const char *const keep[] = {
        "panic", "Panic", "Oops", "oops", "BUG", "Call Trace", "RIP:", "Kernel panic",
        "segfault", "unable to handle", "deadlock", 0
    };
    for (int i = 0; keep[i]; i++)
        if (epin_str_contains(str, len, keep[i])) { (void)!write(2, str, len); return; }
    /* else: drop the routine kernel printk (it never reaches the screen) */
}

/* Bring wlan0 up once iwlwifi's async probe has created it (poll up to ~15s). */
static void epin_wifi_report(void)
{
    lkl_sys_mkdir("/proc", 0555);
    lkl_sys_mount("proc", "/proc", "proc", 0, 0);

    long s = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_DGRAM, 0);
    if (s < 0) { fprintf(stderr, ">>> wifi: socket failed %ld\n", s); return; }
    static const char *const names[] = { "wlan0", "wlan1", "wlp0s0", 0 };
    for (int tries = 0; tries < 30; tries++) {
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
            fprintf(stderr, ">>> wifi: %s up\n", names[i]);
            lkl_sys_close(s);
            return;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 500000000L };  /* 500ms */
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, ">>> wifi: no wlanN (firmware not alive)\n");
    lkl_sys_close(s);
}

/* NetworkManager feature, Stage 0: write the embedded hos-init into the LKL's (writable ramfs)
 * rootfs and execve it — proving the LKL can run a REAL userspace process, the foundation for
 * running dbus-daemon + wpa_supplicant + NetworkManager inside the LKL next to wlan0.  Runs on a
 * dedicated thread; execve replaces this task's image with hos-init (it should NOT return). */
static void *epin_lkl_init_thread(void *arg)
{
	(void)arg;
	const unsigned char *blob = _binary_hos_init_start;
	unsigned long len = (unsigned long)(_binary_hos_init_end - _binary_hos_init_start);
	lkl_sys_mkdir("/sbin", 0755);
	long fd = lkl_sys_openat(LKL_AT_FDCWD, "/sbin/hos-init",
				 LKL_O_CREAT | LKL_O_WRONLY | LKL_O_TRUNC, 0755);
	if (fd < 0) { fprintf(stderr, ">>> lkl: create /sbin/hos-init -> %ld\n", fd); return NULL; }
	unsigned long off = 0;
	while (off < len) {
		long n = lkl_sys_write(fd, (char *)blob + off, len - off);
		if (n <= 0) { fprintf(stderr, ">>> lkl: write init off=%lu -> %ld\n", off, n);
			      lkl_sys_close(fd); return NULL; }
		off += (unsigned long)n;
	}
	lkl_sys_close(fd);
	lkl_sys_chmod("/sbin/hos-init", 0755);
	fprintf(stderr, ">>> lkl: wrote /sbin/hos-init (%lu bytes); launching as LKL userspace PID...\n", len);
	/* Launch via the kernel's own run_init_process mechanism (a kernel_thread that kernel_execve's),
	 * NOT a host-pthread execve (which fails: kernel-thread context has no userspace return path). */
	int pid = lkl_run_userspace("/sbin/hos-init");
	if (pid <= 0) {
		fprintf(stderr, ">>> lkl: lkl_run_userspace failed: %d (launch FAILED)\n", pid);
		return NULL;
	}
	fprintf(stderr, ">>> lkl: hos-init launched as PID %d; waiting for its marker...\n", pid);
	/* CONFIRM it actually ran: poll the marker it drops in the (shared) tmpfs. Filter- and
	 * stdio-independent proof that a genuine userspace process exec'd + mounted its rootfs. */
	for (int i = 0; i < 50; i++) {
		long mfd = lkl_sys_openat(LKL_AT_FDCWD, "/run/hos-init-ok", LKL_O_RDONLY, 0);
		if (mfd >= 0) {
			char buf[128];
			long n = lkl_sys_read(mfd, buf, sizeof(buf) - 1);
			lkl_sys_close(mfd);
			if (n > 0) { buf[n] = 0; if (buf[n-1] == '\n') buf[n-1] = 0; }
			fprintf(stderr, ">>> lkl: USERSPACE CONFIRMED -- %s\n", n > 0 ? buf : "(marker present)");
			return NULL;
		}
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
		nanosleep(&ts, NULL);
	}
	fprintf(stderr, ">>> lkl: hos-init PID %d created but marker never appeared (ran? check)\n", pid);
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
    /* loglevel=4 (console_loglevel: only KERN_ERR(3) and above print): silence the LKL kernel's
     * verbose driver/subsystem printk (all the iwlwifi/cfg80211/NET info+warning registrations)
     * that floods the on-screen log.  Real errors still show; our own status lines come from
     * lkl-boot's stderr, which is a separate write path unaffected by the kernel log level. */
    ret = lkl_start_kernel("mem=256M loglevel=4 quiet lkl_pci=epin");
    if (ret < 0) {
        fprintf(stderr, "lkl_start_kernel failed: %ld\n", ret);
        return 1;
    }
    fprintf(stderr, ">>> LKL up inside EpinAnonymOS.\n");
    /* L5: do NOT halt — the USB enumeration runs ASYNCHRONOUSLY in the kernel's hub work-thread.
     * Halting here rebooted the kernel mid-enumeration ("reboot: Restarting system" at ~t=3s),
     * before usbhid bound + /dev/input/event* appeared — THAT was the "stall".  Keep the LKL
     * resident so the keyboard/mouse fully enumerate; the input bridge (read /dev/input/event*
     * -> EpinAnonymOS input rings) lands here next. */
    /* L5 input bridge: read the LKL's USB keyboard + mouse evdev nodes -> EpinAnonymOS input rings. */
    lkl_sys_mkdir("/dev", 0755);
    lkl_sys_mkdir("/dev/input", 0755);
    pthread_t tkbd, tmse;
    pthread_create(&tkbd, NULL, epin_input_reader, &g_kbdReader);
    pthread_create(&tmse, NULL, epin_input_reader, &g_mseReader);

    /* bring wlan0 up once iwlwifi's async probe creates it */
    epin_wifi_report();

    /* NetworkManager Stage 0: prove the LKL can exec a real userspace process (hos-init). */
    pthread_t tinit;
    pthread_create(&tinit, NULL, epin_lkl_init_thread, NULL);

    fprintf(stderr, ">>> LKL resident.\n");
    for (;;) {
        struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
        nanosleep(&ts, NULL);
    }
    return 0;   /* unreached */
}
