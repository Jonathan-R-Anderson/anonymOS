/*
 * kvm-smoke.c — KVM compatibility ABI smoke test for anonymOS.
 *
 * RUNS ON HARDWARE ONLY. This program needs a real /dev/kvm with a working
 * KVM implementation (anonymOS's Linux personality on VT-x/AMD-V hardware,
 * or stock Linux). It CANNOT run in this sandbox or any container/VM without
 * /dev/kvm; there it fails at step 1 (open). It must at least COMPILE here:
 *
 *     gcc -std=c99 -Wall -Wextra -o /tmp/kvm-smoke kvm-smoke.c
 *
 * No <linux/kvm.h> is used on purpose: every ioctl number, capability
 * number, exit reason, and struct layout is transcribed from
 * src/kernel/d/core/virt/kvmabi.d (the anonymOS KVM compat ABI reference),
 * so this test validates the ABI the kernel actually implements, not the
 * host's headers. If anonymOS's numbers ever drift from real KVM, this test
 * still passes on anonymOS and fails on stock Linux — that asymmetry is the
 * signal, so keep the numbers in sync with kvmabi.d by hand.
 *
 * Guest program (loaded at guest-physical 0x0):
 *     in  al, 0x10        ; 0xE4 0x10   -> exits with KVM_EXIT_IO
 *     hlt                 ; 0xF4        -> exits with KVM_EXIT_HLT
 *     jmp short $-4       ; 0xEB 0xFC   -> failsafe, never reached in the
 *                                         expected flow (see step 6 note)
 *
 * NOTE on step 6 direction: the task text says to expect "out", but the
 * prescribed guest bytes are `in al, 0x10` (opcode 0xE4), which KVM reports
 * as KVM_EXIT_IO_IN (0), not KVM_EXIT_IO_OUT (1). This test asserts what the
 * hardware/KVM actually produces for the given bytes: direction == IN.
 * If the intent was really an OUT exit, the guest bytes must change to
 * `out 0x10, al` (0xE6 0x10).
 *
 * Expected behavior per step, and what the interesting errnos mean:
 *
 *  1. open("/dev/kvm", O_RDWR)
 *       ENOENT  — /dev/kvm does not exist: KVM module not loaded, or this
 *                 machine has no hardware virtualization (or the anonymOS
 *                 Linux personality did not create the device node).
 *       EACCES  — /dev/kvm exists but is not readable/writable by you; add
 *                 yourself to the kvm group or fix the node permissions.
 *       ENODEV  — the node exists but no driver is attached.
 *
 *  2. KVM_GET_API_VERSION must return 12 (KVM_API_VERSION).
 *       Any other value = ABI mismatch between this test and the kernel;
 *       update the constants from kvmabi.d. ENOTTY = the fd is not a KVM
 *       system fd at all.
 *
 *  3. KVM_CHECK_EXTENSION
 *       KVM_CAP_USER_MEMORY -> 1, KVM_CAP_IRQCHIP -> 1 (documented probe
 *       shim: anonymOS reports the cap so probing VMMs proceed, while
 *       KVM_CREATE_IRQCHIP itself is rejected with ENOTTY — split-irqchip
 *       model), KVM_CAP_IRQFD -> 0 (not implemented).
 *       0/1 return, never -1 on a healthy KVM fd; ENOTTY = wrong fd.
 *
 *  4. KVM_CREATE_VM
 *       ENODEV — /dev/kvm opened but hardware virtualization is unavailable
 *       (disabled in BIOS/firmware, or nested virt blocked). EACCES — the
 *       process lacks permission to create VMs.
 *
 *  5. KVM_SET_USER_MEMORY_REGION (slot 0, 2 MiB at guest-phys 0x0)
 *       EINVAL — bad slot/flags/size/alignment; ENOMEM — host cannot back
 *       the region; EFAULT — bad userspace pointer.
 *
 *  6. KVM_CREATE_VCPU(0)
 *       EINVAL — vCPU id out of range (too many vCPUs); ENOMEM — out of
 *       memory; EBUSY — vCPU 0 already exists on this VM.
 *
 *  7. mmap the vCPU fd (MAP_SHARED) -> struct kvm_run at offset 0.
 *       ENODEV — fd does not support mmap (wrong fd type); EINVAL — bad
 *       length/offset. The mapping must be at least 2352 bytes.
 *
 *  8. Program real-mode entry state (KVM_SET_SREGS/KVM_SET_REGS): cs.base=0,
 *     rip=0 so execution starts at guest-phys 0x0. Without this the vCPU
 *     would start at the x86 reset vector (linear 0xFFFFFFF0), which is
 *     unmapped here, and KVM_RUN would exit with KVM_EXIT_SHUTDOWN instead
 *     of running the guest. This is standard real-KVM bring-up, not
 *     anonymOS-specific.
 *
 *  9. KVM_RUN #1 -> KVM_EXIT_IO, direction IN, port 0x10, size 1, count 1.
 *       EINTR from KVM_RUN just means a signal arrived: retry the ioctl.
 *       Any other exit reason here = the guest did not execute as loaded
 *       (check step 8 state and the guest bytes).
 *
 * 10. KVM_RUN #2 -> KVM_EXIT_HLT.
 *       (The trailing `jmp short $-4` is a halt-failsafe: it is never
 *       executed in the expected flow because the vCPU stays halted after
 *       the first HLT exit and this test never resumes it. Its displacement
 *       targets offset 1 — mid-instruction — so do not rely on it as a
 *       real loop; it is padding after HLT.)
 *
 * 11. Teardown: munmap, close vCPU fd, VM fd, /dev/kvm fd.
 *
 * Exit status: 0 if every step PASSed, 1 otherwise. Each step prints
 * "PASS: <name>" or "FAIL: <name> (<detail>)".
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* ioctl numbers — transcribed from src/kernel/d/core/virt/kvmabi.d     */
/* ------------------------------------------------------------------ */
#define KVM_GET_API_VERSION     0xae00UL
#define KVM_CREATE_VM           0xae01UL
#define KVM_CHECK_EXTENSION     0xae03UL
#define KVM_GET_VCPU_MMAP_SIZE  0xae04UL
#define KVM_CREATE_VCPU         0xae41UL
#define KVM_SET_USER_MEMORY_REGION 0x4020ae46UL
#define KVM_RUN                 0xae80UL
#define KVM_GET_REGS            0x8090ae81UL
#define KVM_SET_REGS            0x4090ae82UL
#define KVM_GET_SREGS           0x8138ae83UL
#define KVM_SET_SREGS           0x4138ae84UL

#define KVM_API_VERSION         12

/* KVM_CAP_* — from kvmabi.d */
#define KVM_CAP_IRQCHIP         0
#define KVM_CAP_HLT             1
#define KVM_CAP_USER_MEMORY     3
#define KVM_CAP_IRQFD           32

/* KVM_EXIT_* — from kvmabi.d */
#define KVM_EXIT_IO             2
#define KVM_EXIT_HLT            5
#define KVM_EXIT_IO_IN          0
#define KVM_EXIT_IO_OUT         1

/* ------------------------------------------------------------------ */
/* struct kvm_userspace_memory_region — 32 bytes (kvmabi.d static assert)*/
/* ------------------------------------------------------------------ */
struct kvm_userspace_memory_region {
    uint32_t slot;
    uint32_t flags;
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
};
typedef char assert_mem_region_size[
    sizeof(struct kvm_userspace_memory_region) == 32 ? 1 : -1];

/* ------------------------------------------------------------------ */
/* struct kvm_run — 2352 bytes (kvmabi.d static assert). Only the fields */
/* this test touches are modeled explicitly; the exit union is fixed at */
/* 256 bytes and the sync_regs tail at 2048 bytes per the UAPI layout.  */
/* ------------------------------------------------------------------ */
struct kvm_run_exit_io {
    uint8_t  direction;
    uint8_t  size;
    uint16_t port;
    uint32_t count;
    uint64_t data_offset;   /* relative to kvm_run start */
};                          /* 16 bytes */

struct kvm_run {
    /* in */
    uint8_t  request_interrupt_window;
    uint8_t  immediate_exit;
    uint8_t  padding1[6];
    /* out */
    uint32_t exit_reason;
    uint8_t  ready_for_interrupt_injection;
    uint8_t  if_flag;
    uint16_t flags;
    /* in (pre) / out (post) */
    uint64_t cr8;
    uint64_t apic_base;
    /* out */
    union {
        uint64_t hw_reason;
        struct kvm_run_exit_io io;
        uint8_t  raw[256];
    } u;                    /* 256 bytes */
    /* in */
    uint64_t kvm_valid_regs;
    uint64_t kvm_dirty_regs;
    uint8_t  sync_regs[2048];
};                          /* 2352 bytes */
typedef char assert_kvm_run_size[sizeof(struct kvm_run) == 2352 ? 1 : -1];
typedef char assert_kvm_run_io[sizeof(struct kvm_run_exit_io) == 16 ? 1 : -1];

/* ------------------------------------------------------------------ */
/* struct kvm_regs — 144 bytes; struct kvm_sregs — 312 bytes            */
/* (kvmabi.d static asserts). Minimal real-mode bring-up only.         */
/* ------------------------------------------------------------------ */
struct kvm_regs {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rsp, rbp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip, rflags;
};
typedef char assert_kvm_regs_size[sizeof(struct kvm_regs) == 144 ? 1 : -1];

struct kvm_segment {
    uint64_t base;
    uint32_t limit;
    uint16_t selector;
    uint8_t  type;
    uint8_t  present, dpl, db, s, l, g, avl;
    uint8_t  unusable;
    uint8_t  padding;
};                          /* 24 bytes */

struct kvm_dtable {
    uint64_t base;
    uint16_t limit;
    uint16_t padding[3];
};                          /* 16 bytes */

struct kvm_sregs {
    struct kvm_segment cs, ds, es, fs, gs, ss;   /* 6*24 = 144 */
    struct kvm_segment tr, ldt;                  /* 2*24 = 48  */
    struct kvm_dtable  gdt, idt;                 /* 2*16 = 32  */
    uint64_t cr0, cr2, cr3, cr4, cr8;            /* 5*8  = 40  */
    uint64_t efer;                               /* 8          */
    uint64_t apic_base;                          /* 8          */
    uint64_t interrupt_bitmap[4];                /* 4*8  = 32  */
};                                               /* 312 bytes */
typedef char assert_kvm_sregs_size[sizeof(struct kvm_sregs) == 312 ? 1 : -1];

/* ------------------------------------------------------------------ */

#define GUEST_MEM_SIZE   (2UL * 1024 * 1024)   /* 2 MiB */
#define GUEST_PHYS_BASE  0x0UL

/* in al, 0x10 ; hlt ; jmp short $-4 */
static const uint8_t guest_code[] = { 0xE4, 0x10, 0xF4, 0xEB, 0xFC };

static int failures = 0;

static void pass(const char *name)
{
    printf("PASS: %s\n", name);
    fflush(stdout);
}

static void fail(const char *name, const char *detail)
{
    printf("FAIL: %s (%s)\n", name, detail);
    fflush(stdout);
    failures++;
}

static void fail_errno(const char *name)
{
    char buf[128];
    snprintf(buf, sizeof buf, "errno=%d (%s)", errno, strerror(errno));
    fail(name, buf);
}

int main(void)
{
    int kvm_fd = -1, vm_fd = -1, vcpu_fd = -1;
    void *guest_mem = MAP_FAILED;
    struct kvm_run *run = NULL;
    size_t run_mmap_size = 0;
    long r;

    /* 1. open /dev/kvm */
    kvm_fd = open("/dev/kvm", O_RDWR);
    if (kvm_fd < 0) {
        fail_errno("open /dev/kvm");
        goto out;
    }
    pass("open /dev/kvm");

    /* 2. API version must be 12 */
    r = ioctl(kvm_fd, KVM_GET_API_VERSION, 0);
    if (r != KVM_API_VERSION) {
        char buf[64];
        snprintf(buf, sizeof buf, "got %ld, want %d", r, KVM_API_VERSION);
        fail("KVM_GET_API_VERSION == 12", buf);
        goto out;
    }
    pass("KVM_GET_API_VERSION == 12");

    /* 3. capability probes */
    r = ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
    if (r != 1) {
        char buf[64];
        snprintf(buf, sizeof buf, "KVM_CAP_USER_MEMORY -> %ld, want 1", r);
        fail("KVM_CHECK_EXTENSION KVM_CAP_USER_MEMORY == 1", buf);
        goto out;
    }
    pass("KVM_CHECK_EXTENSION KVM_CAP_USER_MEMORY == 1");

    r = ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_IRQCHIP);
    if (r != 1) {
        char buf[64];
        snprintf(buf, sizeof buf, "KVM_CAP_IRQCHIP -> %ld, want 1", r);
        fail("KVM_CHECK_EXTENSION KVM_CAP_IRQCHIP == 1 (probe shim)", buf);
        goto out;
    }
    pass("KVM_CHECK_EXTENSION KVM_CAP_IRQCHIP == 1 (probe shim)");

    r = ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_IRQFD);
    if (r != 0) {
        char buf[64];
        snprintf(buf, sizeof buf, "KVM_CAP_IRQFD -> %ld, want 0", r);
        fail("KVM_CHECK_EXTENSION KVM_CAP_IRQFD == 0", buf);
        goto out;
    }
    pass("KVM_CHECK_EXTENSION KVM_CAP_IRQFD == 0");

    /* 4. create the VM */
    vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
    if (vm_fd < 0) {
        fail_errno("KVM_CREATE_VM");
        goto out;
    }
    pass("KVM_CREATE_VM");

    /* 5. back 2 MiB of guest-physical 0x0 and register the memslot */
    guest_mem = mmap(NULL, GUEST_MEM_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guest_mem == MAP_FAILED) {
        fail_errno("mmap guest memory");
        goto out;
    }
    memcpy(guest_mem, guest_code, sizeof guest_code);
    {
        struct kvm_userspace_memory_region reg;
        memset(&reg, 0, sizeof reg);
        reg.slot = 0;
        reg.flags = 0;
        reg.guest_phys_addr = GUEST_PHYS_BASE;
        reg.memory_size = GUEST_MEM_SIZE;
        reg.userspace_addr = (uint64_t)(uintptr_t)guest_mem;
        if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &reg) != 0) {
            fail_errno("KVM_SET_USER_MEMORY_REGION");
            goto out;
        }
    }
    pass("KVM_SET_USER_MEMORY_REGION (slot 0, 2 MiB @ 0x0)");

    /* 6. create vCPU 0 */
    vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
    if (vcpu_fd < 0) {
        fail_errno("KVM_CREATE_VCPU(0)");
        goto out;
    }
    pass("KVM_CREATE_VCPU(0)");

    /* 7. mmap the vCPU fd -> struct kvm_run */
    r = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    run_mmap_size = (r > 0) ? (size_t)r : (size_t)sysconf(_SC_PAGESIZE);
    if (run_mmap_size < sizeof(struct kvm_run)) {
        char buf[64];
        snprintf(buf, sizeof buf, "mmap size %zu < %zu",
                 run_mmap_size, sizeof(struct kvm_run));
        fail("KVM_GET_VCPU_MMAP_SIZE", buf);
        goto out;
    }
    run = mmap(NULL, run_mmap_size, PROT_READ | PROT_WRITE,
               MAP_SHARED, vcpu_fd, 0);
    if (run == MAP_FAILED) {
        run = NULL;
        fail_errno("mmap vcpu fd (kvm_run)");
        goto out;
    }
    pass("mmap vcpu fd -> struct kvm_run");

    /* 8. real-mode entry state: cs.base = 0, rip = 0 -> fetch from 0x0 */
    {
        struct kvm_sregs sregs;
        struct kvm_regs regs;
        if (ioctl(vcpu_fd, KVM_GET_SREGS, &sregs) != 0) {
            fail_errno("KVM_GET_SREGS");
            goto out;
        }
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        if (ioctl(vcpu_fd, KVM_SET_SREGS, &sregs) != 0) {
            fail_errno("KVM_SET_SREGS");
            goto out;
        }
        memset(&regs, 0, sizeof regs);
        regs.rip = 0;
        regs.rflags = 0x2;   /* bit 1 is always 1 on x86 */
        if (ioctl(vcpu_fd, KVM_SET_REGS, &regs) != 0) {
            fail_errno("KVM_SET_REGS");
            goto out;
        }
    }
    pass("real-mode entry state (cs.base=0, rip=0)");

    /* 9. KVM_RUN #1 -> KVM_EXIT_IO, IN, port 0x10, size 1 */
    for (;;) {
        r = ioctl(vcpu_fd, KVM_RUN, 0);
        if (r == 0)
            break;
        if (errno == EINTR)
            continue;   /* signal: just retry */
        fail_errno("KVM_RUN #1");
        goto out;
    }
    {
        struct kvm_run_exit_io *io = &run->u.io;
        char buf[160];
        if (run->exit_reason != KVM_EXIT_IO ||
            io->direction != KVM_EXIT_IO_IN ||
            io->port != 0x10 || io->size != 1 || io->count != 1) {
            snprintf(buf, sizeof buf,
                     "exit_reason=%u dir=%u port=0x%x size=%u count=%u "
                     "(want reason=%d dir=%d port=0x10 size=1 count=1)",
                     run->exit_reason, io->direction, io->port,
                     io->size, io->count,
                     KVM_EXIT_IO, KVM_EXIT_IO_IN);
            fail("KVM_RUN #1 -> KVM_EXIT_IO (IN, port 0x10, size 1)", buf);
            goto out;
        }
        /* Supply a byte for the guest's IN: stored at data_offset. */
        if (io->data_offset + 1 <= run_mmap_size)
            *((uint8_t *)run + io->data_offset) = 0x42;
    }
    pass("KVM_RUN #1 -> KVM_EXIT_IO (IN, port 0x10, size 1)");

    /* 10. KVM_RUN #2 -> KVM_EXIT_HLT */
    for (;;) {
        r = ioctl(vcpu_fd, KVM_RUN, 0);
        if (r == 0)
            break;
        if (errno == EINTR)
            continue;
        fail_errno("KVM_RUN #2");
        goto out;
    }
    if (run->exit_reason != KVM_EXIT_HLT) {
        char buf[64];
        snprintf(buf, sizeof buf, "exit_reason=%u, want %d (HLT)",
                 run->exit_reason, KVM_EXIT_HLT);
        fail("KVM_RUN #2 -> KVM_EXIT_HLT", buf);
        goto out;
    }
    pass("KVM_RUN #2 -> KVM_EXIT_HLT");

out:
    /* 11. teardown */
    if (run)
        munmap(run, run_mmap_size);
    if (vcpu_fd >= 0)
        close(vcpu_fd);
    if (vm_fd >= 0)
        close(vm_fd);
    if (guest_mem != MAP_FAILED)
        munmap(guest_mem, GUEST_MEM_SIZE);
    if (kvm_fd >= 0)
        close(kvm_fd);

    if (failures == 0) {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    printf("%d TEST(S) FAILED\n", failures);
    return 1;
}
