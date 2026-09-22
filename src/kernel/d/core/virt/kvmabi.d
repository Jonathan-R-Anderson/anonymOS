// KVM compatibility ABI — constants and struct layouts for the Linux
// KVM ioctl interface (include/uapi/linux/kvm.h).
//
// This module is PURE DATA: ioctl numbers, capability numbers, exit
// reasons, and struct layouts with static asserts against the sizes
// measured from the authoritative UAPI headers.  It has no dependency
// on hardware, the object model, or the syscall layer, so the layout
// asserts can be validated by any D compiler.
//
// Verified against:
//   - torvalds/linux include/uapi/linux/kvm.h (ioctl nr/size/dir,
//     KVM_CAP_* numbers, KVM_EXIT_* reasons)
//   - /usr/include/linux/kvm.h + asm/kvm.h on the build host
//     (struct sizes via sizeof: kvm_run=2352, kvm_regs=144,
//     kvm_sregs=312, kvm_fpu=416, kvm_vcpu_events=64, ...)
//   - Cloud Hypervisor vmm/src/seccomp_filters.rs (the exact ioctl
//     numbers the pinned VMM will issue)
//
// Two corrections to KVM_API_TRACE.md found while verifying:
//   - KVM_GET_MSR_INDEX_LIST is 0xc004ae02 (_IOWR(0xAE,0x02), size 4),
//     NOT 0xc008ae05 — that number is KVM_GET_SUPPORTED_CPUID.
//   - KVM_CREATE_PIT2 is 0x4040ae77 (nr 0x77), not 0xa0.
//
// Constraints: -betterC, no imports, no functions (pure data).
module core.virt.kvmabi;

// ---------------------------------------------------------------------------
// ioctls for the /dev/kvm (system) fd
// ---------------------------------------------------------------------------
enum ulong KVM_GET_API_VERSION   = 0xae00;
enum ulong KVM_CREATE_VM         = 0xae01;
enum ulong KVM_GET_MSR_INDEX_LIST= 0xc004ae02; // _IOWR(AE,0x02,size=4)
enum ulong KVM_CHECK_EXTENSION  = 0xae03;
enum ulong KVM_GET_VCPU_MMAP_SIZE= 0xae04;
enum ulong KVM_GET_SUPPORTED_CPUID = 0xc008ae05; // _IOWR(AE,0x05,size=8)

// ---------------------------------------------------------------------------
// ioctls for the VM fd
// ---------------------------------------------------------------------------
enum ulong KVM_CREATE_VCPU          = 0xae41;
enum ulong KVM_GET_DIRTY_LOG         = 0x4010ae42; // _IOW(AE,0x42,size=16)
enum ulong KVM_SET_USER_MEMORY_REGION = 0x4020ae46; // _IOW(AE,0x46,size=32)
enum ulong KVM_SET_TSS_ADDR         = 0xae47;
enum ulong KVM_SET_IDENTITY_MAP_ADDR= 0x4008ae48;   // _IOW(AE,0x48,u64)
enum ulong KVM_CREATE_IRQCHIP       = 0xae60;        // rejected: ENOTTY
enum ulong KVM_IRQ_LINE             = 0x4008ae61;   // _IOW(AE,0x61,size=8)
enum ulong KVM_SET_GSI_ROUTING      = 0x4008ae6a;   // _IOW(AE,0x6a,size=8)
enum ulong KVM_IRQFD                = 0x4020ae76;   // _IOW(AE,0x76,size=32)
enum ulong KVM_CREATE_PIT2          = 0x4040ae77;   // rejected: ENOTTY
enum ulong KVM_IOEVENTFD            = 0x4040ae79;   // _IOW(AE,0x79,size=64)
enum ulong KVM_SET_CLOCK            = 0x4030ae7b;   // _IOW(AE,0x7b,size=48)
enum ulong KVM_GET_CLOCK            = 0x8030ae7c;   // _IOR(AE,0x7c,size=48)
enum ulong KVM_ENABLE_CAP           = 0x4068aea3;   // _IOW(AE,0xa3,size=104)

// ---------------------------------------------------------------------------
// ioctls for the vCPU fd
// ---------------------------------------------------------------------------
enum ulong KVM_RUN              = 0xae80;
enum ulong KVM_GET_REGS         = 0x8090ae81; // _IOR(AE,0x81,size=144)
enum ulong KVM_SET_REGS         = 0x4090ae82; // _IOW(AE,0x82,size=144)
enum ulong KVM_GET_SREGS        = 0x8138ae83; // _IOR(AE,0x83,size=312)
enum ulong KVM_SET_SREGS        = 0x4138ae84; // _IOW(AE,0x84,size=312)
enum ulong KVM_GET_MSRS         = 0xc008ae88; // _IOWR(AE,0x88,size=8)
enum ulong KVM_SET_MSRS         = 0x4008ae89; // _IOW(AE,0x89,size=8)
enum ulong KVM_SET_CPUID2       = 0x4008ae90; // _IOW(AE,0x90,size=8)
enum ulong KVM_GET_FPU          = 0x81a0ae8c; // _IOR(AE,0x8c,size=416)
enum ulong KVM_SET_FPU          = 0x41a0ae8d; // _IOW(AE,0x8d,size=416)
enum ulong KVM_GET_LAPIC        = 0x8400ae8e; // _IOR(AE,0x8e,size=1024)
enum ulong KVM_SET_LAPIC        = 0x4400ae8f; // _IOW(AE,0x8f,size=1024)
enum ulong KVM_GET_MP_STATE     = 0x8004ae98; // _IOR(AE,0x98,size=4)
enum ulong KVM_SET_MP_STATE     = 0x4004ae99; // _IOW(AE,0x99,size=4)
enum ulong KVM_NMI              = 0xae9a;
enum ulong KVM_GET_VCPU_EVENTS  = 0x8040ae9f; // _IOR(AE,0x9f,size=64)
enum ulong KVM_SET_VCPU_EVENTS  = 0x4040aea0; // _IOW(AE,0xa0,size=64)
enum ulong KVM_SET_TSC_KHZ      = 0xaea2;     // _IO(AE,0xa2)
enum ulong KVM_GET_TSC_KHZ      = 0xaea3;
enum ulong KVM_GET_DEBUGREGS    = 0x8080aea1; // _IOR(AE,0xa1,size=128)
enum ulong KVM_SET_DEBUGREGS    = 0x4080aea2; // _IOW(AE,0xa2,size=128)
enum ulong KVM_GET_XSAVE        = 0x9000aea4; // _IOR(AE,0xa4,size=4096)
enum ulong KVM_SET_XSAVE        = 0x5000aea5; // _IOW(AE,0xa5,size=4096)
enum ulong KVM_GET_XCRS         = 0x8188aea6; // _IOR(AE,0xa6,size=392)
enum ulong KVM_SET_XCRS         = 0x4188aea7; // _IOW(AE,0xa7,size=392)

enum uint KVM_API_VERSION = 12;

// ---------------------------------------------------------------------------
// KVM_CAP_* extension numbers (verified against /usr/include/linux/kvm.h;
// every value below was cross-checked 2026-09-21 — wrong numbers here make
// Cloud Hypervisor mis-detect the platform, so they are load-bearing).
// ---------------------------------------------------------------------------
enum uint KVM_CAP_IRQCHIP          = 0;
enum uint KVM_CAP_HLT              = 1;
enum uint KVM_CAP_USER_MEMORY      = 3;
enum uint KVM_CAP_SET_TSS_ADDR     = 4;
enum uint KVM_CAP_EXT_CPUID        = 7;
enum uint KVM_CAP_NR_VCPUS         = 9;   // returns recommended max vCPUs
enum uint KVM_CAP_NR_MEMSLOTS      = 10;  // returns max memslots
enum uint KVM_CAP_PIT              = 11;
enum uint KVM_CAP_NOP_IO_DELAY     = 12;
enum uint KVM_CAP_MP_STATE         = 14;
enum uint KVM_CAP_USER_NMI         = 22;
enum uint KVM_CAP_SET_GUEST_DEBUG  = 23;
enum uint KVM_CAP_IRQ_ROUTING      = 25;
enum uint KVM_CAP_IRQFD            = 32;
enum uint KVM_CAP_PIT2             = 33;
enum uint KVM_CAP_IOEVENTFD        = 36;
enum uint KVM_CAP_SET_IDENTITY_MAP_ADDR = 37;
enum uint KVM_CAP_ADJUST_CLOCK     = 39;
enum uint KVM_CAP_VCPU_EVENTS      = 41;
enum uint KVM_CAP_DEBUGREGS        = 50;
enum uint KVM_CAP_ENABLE_CAP       = 54;
enum uint KVM_CAP_XSAVE            = 55;
enum uint KVM_CAP_XCRS             = 56;
enum uint KVM_CAP_TSC_CONTROL      = 60;
enum uint KVM_CAP_GET_TSC_KHZ      = 61;
enum uint KVM_CAP_MAX_VCPUS        = 66;  // returns max vCPUs
enum uint KVM_CAP_SIGNAL_MSI       = 77;
enum uint KVM_CAP_READONLY_MEM     = 81;
enum uint KVM_CAP_TSC_DEADLINE_TIMER = 72;
enum uint KVM_CAP_DISABLE_QUIRKS   = 116;
enum uint KVM_CAP_MULTI_ADDRESS_SPACE = 118;
enum uint KVM_CAP_SPLIT_IRQCHIP    = 121; // returns #GSIs when supported
enum uint KVM_CAP_IMMEDIATE_EXIT   = 136;

// ---------------------------------------------------------------------------
// KVM_EXIT_* reasons
// ---------------------------------------------------------------------------
enum uint KVM_EXIT_UNKNOWN      = 0;
enum uint KVM_EXIT_EXCEPTION    = 1;
enum uint KVM_EXIT_IO           = 2;
enum uint KVM_EXIT_HYPERCALL    = 3;
enum uint KVM_EXIT_DEBUG        = 4;
enum uint KVM_EXIT_HLT          = 5;
enum uint KVM_EXIT_MMIO         = 6;
enum uint KVM_EXIT_IRQ_WINDOW_OPEN = 7;
enum uint KVM_EXIT_SHUTDOWN     = 8;
enum uint KVM_EXIT_FAIL_ENTRY   = 9;
enum uint KVM_EXIT_INTR         = 10;
enum uint KVM_EXIT_NMI          = 16;
enum uint KVM_EXIT_INTERNAL_ERROR = 17;
enum uint KVM_EXIT_IOAPIC_EOI   = 26;

enum uint KVM_EXIT_IO_IN  = 0;
enum uint KVM_EXIT_IO_OUT = 1;

// ---------------------------------------------------------------------------
// struct kvm_userspace_memory_region (32 bytes)
// ---------------------------------------------------------------------------
struct KvmUserspaceMemoryRegion {
    uint  slot;
    uint  flags;
    ulong guestPhysAddr;
    ulong memorySize;
    ulong userspaceAddr;
}
static assert(KvmUserspaceMemoryRegion.sizeof == 32);
enum uint KVM_MEM_LOG_DIRTY_PAGES = 1u << 0;
enum uint KVM_MEM_READONLY        = 1u << 1;

// ---------------------------------------------------------------------------
// struct kvm_run (2352 bytes).  Only the exit variants we produce are
// modeled explicitly; the union is fixed at 256 bytes per UAPI.
// ---------------------------------------------------------------------------
struct KvmExitIo {
    ubyte direction;
    ubyte size;
    ushort port;
    uint count;
    ulong dataOffset; // relative to kvm_run start
}
static assert(KvmExitIo.sizeof == 16);

struct KvmExitMmio {
    ulong physAddr;
    ubyte[8] data;
    uint len;
    ubyte isWrite;
}
static assert(KvmExitMmio.sizeof == 24);

struct KvmExitHypercall {
    ulong nr;
    ulong[6] args;
    ulong ret;
    uint longMode;
    uint pad;
}
static assert(KvmExitHypercall.sizeof == 72);

union KvmRunExit {
    ulong hwReason;      // KVM_EXIT_UNKNOWN
    KvmExitIo io;        // KVM_EXIT_IO
    KvmExitMmio mmio;    // KVM_EXIT_MMIO
    KvmExitHypercall hypercall; // KVM_EXIT_HYPERCALL
    ubyte vector;        // KVM_EXIT_IOAPIC_EOI (first byte)
    ubyte[256] raw;
}
static assert(KvmRunExit.sizeof == 256);

struct KvmRun {
    // in
    ubyte requestInterruptWindow;
    ubyte immediateExit;
    ubyte[6] padding1;
    // out
    uint exitReason;
    ubyte readyForInterruptInjection;
    ubyte ifFlag;
    ushort flags;
    // in (pre) / out (post)
    ulong cr8;
    ulong apicBase;
    // out
    KvmRunExit u;
    // in
    ulong kvmValidRegs;
    ulong kvmDirtyRegs;
    ubyte[2048] syncRegs; // KVM_CAP_SYNC_REGS not advertised; kept for size
}
static assert(KvmRun.sizeof == 2352);

// ---------------------------------------------------------------------------
// struct kvm_regs (144 bytes)
// ---------------------------------------------------------------------------
struct KvmRegs {
    ulong rax, rbx, rcx, rdx;
    ulong rsi, rdi, rsp, rbp;
    ulong r8, r9, r10, r11;
    ulong r12, r13, r14, r15;
    ulong rip, rflags;
}
static assert(KvmRegs.sizeof == 144);

// ---------------------------------------------------------------------------
// struct kvm_segment (24), kvm_dtable (16), kvm_sregs (312)
// ---------------------------------------------------------------------------
struct KvmSegment {
    ulong base;
    uint limit;
    ushort selector;
    ubyte type;
    ubyte present, dpl, db, s, l, g, avl;
    ubyte unusable;
    ubyte padding;
}
static assert(KvmSegment.sizeof == 24);

struct KvmDTable {
    ulong base;
    ushort limit;
    ushort[3] padding;
}
static assert(KvmDTable.sizeof == 16);

struct KvmSRegs {
    KvmSegment cs, ds, es, fs, gs, ss;
    KvmSegment tr, ldt;
    KvmDTable gdt, idt;
    ulong cr0, cr2, cr3, cr4, cr8;
    ulong efer;
    ulong apicBase;
    ulong[4] interruptBitmap; // KVM_NR_INTERRUPTS=256
}
static assert(KvmSRegs.sizeof == 312);

// ---------------------------------------------------------------------------
// struct kvm_fpu (416 bytes)
// ---------------------------------------------------------------------------
struct KvmFpu {
    ubyte[8][16] fpr;
    ushort fcw;
    ushort fsw;
    ubyte ftwx;
    ubyte pad1;
    ushort lastOpcode;
    ulong lastIp;
    ulong lastDp;
    ubyte[16][16] xmm;
    uint mxcsr;
    uint pad2;
}
static assert(KvmFpu.sizeof == 416);

// ---------------------------------------------------------------------------
// struct kvm_msrs (8) + struct kvm_msr_entry (16)
// ---------------------------------------------------------------------------
struct KvmMsrEntry {
    uint index;
    uint reserved;
    ulong data;
}
static assert(KvmMsrEntry.sizeof == 16);

struct KvmMsrs {
    uint nmsrs;
    uint pad;
    // KvmMsrEntry entries[] follows
}
static assert(KvmMsrs.sizeof == 8);

// Boot MSRs Cloud Hypervisor programs (from the trace): a fixed allow-list.
// Anything outside this list on KVM_SET_MSRS is rejected with EINVAL — the
// guest must never be able to reprogram host-reserved MSRs through us.
enum uint MSR_IA32_SYSENTER_CS  = 0x174;
enum uint MSR_IA32_SYSENTER_ESP = 0x175;
enum uint MSR_IA32_SYSENTER_EIP = 0x176;
enum uint MSR_IA32_TSC          = 0x10;
enum uint MSR_IA32_EFER         = 0xc0000080;
enum uint MSR_IA32_STAR         = 0xc0000081;
enum uint MSR_IA32_LSTAR        = 0xc0000082;
enum uint MSR_IA32_CSTAR        = 0xc0000083;
enum uint MSR_IA32_FMASK        = 0xc0000084;
enum uint MSR_IA32_KERNEL_GS_BASE = 0xc0000102;

// ---------------------------------------------------------------------------
// struct kvm_cpuid2 (8) + struct kvm_cpuid_entry2 (40)
// ---------------------------------------------------------------------------
struct KvmCpuidEntry2 {
    uint func;
    uint index;
    uint flags;
    uint eax, ebx, ecx, edx;
    uint[3] padding;
}
static assert(KvmCpuidEntry2.sizeof == 40);

struct KvmCpuid2 {
    uint nent;
    uint padding;
    // KvmCpuidEntry2 entries[] follows
}
static assert(KvmCpuid2.sizeof == 8);

// ---------------------------------------------------------------------------
// struct kvm_vcpu_events (64 bytes)
// ---------------------------------------------------------------------------
struct KvmVcpuEvents {
    struct Ex {
        ubyte injected, nr, hasErrorCode, pending;
        uint errorCode;
    }
    Ex exception_;
    struct Intr {
        ubyte injected, nr, soft, shadow;
    }
    Intr interrupt;
    struct Nmi {
        ubyte injected, pending, masked, pad;
    }
    Nmi nmi;
    uint sipiVector;
    uint flags;
    struct Smi {
        ubyte smm, pending, smmInsideNmi, latchedInit;
    }
    Smi smi;
    struct Tf { ubyte pending; }
    Tf tripleFault;
    ubyte[26] reserved;
    ubyte exceptionHasPayload;
    // exceptionPayload lands at offset 56 (already 8-aligned): no padding.
    ulong exceptionPayload;
}
static assert(KvmVcpuEvents.sizeof == 64);

// ---------------------------------------------------------------------------
// struct kvm_mp_state (4)
// ---------------------------------------------------------------------------
struct KvmMpState { uint mpState; }
static assert(KvmMpState.sizeof == 4);
enum uint KVM_MP_STATE_RUNNABLE        = 0;
enum uint KVM_MP_STATE_UNINITIALIZED   = 1;
enum uint KVM_MP_STATE_INIT_RECEIVED   = 2;
enum uint KVM_MP_STATE_HALTED          = 3;
enum uint KVM_MP_STATE_SIPI_RECEIVED   = 4;
enum uint KVM_MP_STATE_STOPPED         = 5;
enum uint KVM_MP_STATE_CHECK_STOP      = 6;
enum uint KVM_MP_STATE_OPERATING       = 7;
enum uint KVM_MP_STATE_LOAD            = 8;
enum uint KVM_MP_STATE_AP_RESET_HOLD   = 9;
enum uint KVM_MP_STATE_SUSPENDED       = 10;

// ---------------------------------------------------------------------------
// struct kvm_debugregs (128), struct kvm_xsave (4096), struct kvm_xcrs (392)
// ---------------------------------------------------------------------------
struct KvmDebugregs {
    ulong[4] db;
    ulong dr6;
    ulong dr7;
    ulong flags;
    ulong[9] reserved;
}
static assert(KvmDebugregs.sizeof == 128);

struct KvmXsave {
    uint[1024] region;
}
static assert(KvmXsave.sizeof == 4096);

struct KvmXcr {
    uint xcr;
    uint reserved;
    ulong value;
}
static assert(KvmXcr.sizeof == 16);

struct KvmXcrs {
    uint nrXcrs;
    uint flags;
    KvmXcr[16] xcrs;
    ulong[16] padding;
}
static assert(KvmXcrs.sizeof == 392);

// ---------------------------------------------------------------------------
// struct kvm_irqfd (32), struct kvm_ioeventfd (64), struct kvm_enable_cap (104)
// ---------------------------------------------------------------------------
struct KvmIrqfd {
    uint fd;
    uint gsi;
    uint flags;
    uint resamplefd;
    ubyte[16] pad;
}
static assert(KvmIrqfd.sizeof == 32);
enum uint KVM_IRQFD_FLAG_DEASSIGN = 1u << 0;
enum uint KVM_IRQFD_FLAG_RESAMPLE = 1u << 1; // not supported: EINVAL

struct KvmIoeventfd {
    ulong datamatch;
    ulong addr;
    uint len;
    int fd;
    uint flags;
    ubyte[36] pad;
}
static assert(KvmIoeventfd.sizeof == 64);
enum uint KVM_IOEVENTFD_FLAG_DATAMATCH = 1u << 0; // not supported: EINVAL
enum uint KVM_IOEVENTFD_FLAG_PIO       = 1u << 1; // not supported: EINVAL
enum uint KVM_IOEVENTFD_FLAG_DEASSIGN  = 1u << 2;

struct KvmEnableCap {
    uint cap;
    uint flags;
    ulong[4] args;
    ubyte[64] pad;
}
static assert(KvmEnableCap.sizeof == 104);

// ---------------------------------------------------------------------------
// struct kvm_clock_data (48)
// ---------------------------------------------------------------------------
struct KvmClockData {
    ulong clock_;
    uint flags;
    uint pad0;
    ulong realtime;
    ulong hostTsc;
    uint[4] pad;
}
static assert(KvmClockData.sizeof == 48);

// ---------------------------------------------------------------------------
// Per-vCPU KVM state-cache capacity.  The cache itself lives in
// core.virt.kvm as two lazily-allocated host pages (fixed regs + MSRs, and
// the CPUID2 list) so no single page-size assumption leaks into the ABI.
// ---------------------------------------------------------------------------
enum uint KVM_CACHE_MAX_MSRS  = 64;
enum uint KVM_CACHE_MAX_CPUID = 64;

// ---------------------------------------------------------------------------
// struct kvm_irq_routing (8) + struct kvm_irq_routing_entry (48)
// ---------------------------------------------------------------------------
struct KvmRoutingIrqchip { uint irqchip; uint pin; }
struct KvmRoutingMsi { uint addressLo; uint addressHi; uint data; uint pad2; }
struct KvmIrqRoutingEntry {
    uint gsi;
    uint type;
    uint flags;
    uint pad;
    union {
        KvmRoutingIrqchip irqchip;
        KvmRoutingMsi msi;
        uint[8] pad8;
    }
}
static assert(KvmIrqRoutingEntry.sizeof == 48);

struct KvmIrqRouting {
    uint nr;
    uint flags;
    // KvmIrqRoutingEntry entries[] follows
}
static assert(KvmIrqRouting.sizeof == 8);
enum uint KVM_IRQ_ROUTING_IRQCHIP = 1;
enum uint KVM_IRQ_ROUTING_MSI     = 2;

// ---------------------------------------------------------------------------
// struct kvm_msr_list (4) — variable tail of u32 indices
// ---------------------------------------------------------------------------
struct KvmMsrList {
    uint nmsrs;
    // uint indices[] follows
}
static assert(KvmMsrList.sizeof == 4);

// ---------------------------------------------------------------------------
// struct kvm_lapic_state (1024)
// ---------------------------------------------------------------------------
struct KvmLapicState {
    ubyte[1024] regs;
}
static assert(KvmLapicState.sizeof == 1024);
