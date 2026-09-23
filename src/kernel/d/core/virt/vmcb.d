// VIRT: exact AMD VMCB layout (Virtual Machine Control Block).
//
// Authoritative source: AMD64 APM Vol. 2 Rev. 3.43 ("VMCB Layout"),
// cross-checked against Linux arch/x86/include/asm/svm.h (struct
// vmcb_control_area / struct vmcb_save_area, with BUILD_BUG offset
// assertions) and VirtualBox include/VBox/vmm/hm_svm.h.
//
// The VMCB is ONE 4 KiB page, 4 KiB PHYSICALLY ALIGNED, mapped write-back.
//   control area : 0x000-0x3FF (static_assert sizeof == 0x400)
//   save area    : 0x400-0xFFF (save area starts at offset 0x400)
//
// Every offset below was verified against the research report
// (openspec/changes/add-amd-svm-npt-backend).  Do NOT "fix" these from
// memory: the proposed values in the original task brief were wrong for
// most control-area fields (off by +0x20 from IOPM onward, EXITCODE at
// 0x070 not 0x0C0, etc.).
//
// Constraints: -betterC, @nogc nothrow.  This module is dependency-free
// (pure layout); it must stay importable from vm.d without cycles.
module core.virt.vmcb;

extern (C) @nogc nothrow:

// --- page geometry --------------------------------------------------------------
enum uint VMCB_SIZE       = 0x1000;
enum uint VMCB_CTRL_SIZE  = 0x400;
enum uint VMCB_SAVE_BASE  = 0x400;

// --- control-area offsets ---------------------------------------------------------
enum uint VMCB_INTERCEPTS   = 0x000; // 6 x u32 intercept vectors
enum uint VMCB_IOPM_BASE    = 0x040; // u64, low 12 bits ignored (4K aligned)
enum uint VMCB_MSRPM_BASE   = 0x048; // u64, low 12 bits ignored
enum uint VMCB_TSC_OFFSET   = 0x050; // u64
enum uint VMCB_ASID         = 0x058; // u32 guest ASID (0 = host, never guest)
enum uint VMCB_TLB_CONTROL  = 0x05C; // u8
enum uint VMCB_INT_CTL      = 0x060; // u32
enum uint VMCB_INT_VECTOR   = 0x064; // u32
enum uint VMCB_INT_STATE    = 0x068; // u32
enum uint VMCB_EXITCODE     = 0x070; // u64 — read after #VMEXIT
enum uint VMCB_EXITINFO1    = 0x078; // u64
enum uint VMCB_EXITINFO2    = 0x080; // u64
enum uint VMCB_EXITINTINFO  = 0x088; // u32 (+ u32 err @ 0x08C)
enum uint VMCB_MISC_CTL     = 0x090; // u64: bit 0 = NP enable
enum uint VMCB_EVENTINJ     = 0x0A8; // u32 (+ u32 err @ 0x0AC)
enum uint VMCB_NCR3         = 0x0B0; // u64 nested-paging root (4K-aligned HPA)
enum uint VMCB_MISC_CTL2    = 0x0B8; // u64
enum uint VMCB_CLEAN        = 0x0C0; // u32 clean bits (+ u32 rsvd @ 0x0C4)
enum uint VMCB_NRIP         = 0x0C8; // u64 next RIP (needs CPUID EDX[3])

// --- save-area offsets (each segment = u16 sel, u16 attrib, u32 limit, u64 base) --
enum uint VMCB_ES           = 0x400;
enum uint VMCB_CS           = 0x410;
enum uint VMCB_SS           = 0x420;
enum uint VMCB_DS           = 0x430;
enum uint VMCB_FS           = 0x440;
enum uint VMCB_GS           = 0x450;
enum uint VMCB_GDTR         = 0x460;
enum uint VMCB_LDTR         = 0x470;
enum uint VMCB_IDTR         = 0x480;
enum uint VMCB_TR           = 0x490;
enum uint VMCB_VMPL         = 0x4CA; // u8
enum uint VMCB_CPL          = 0x4CB; // u8
enum uint VMCB_EFER         = 0x4D0; // u64
enum uint VMCB_CR4          = 0x548; // u64
enum uint VMCB_CR3          = 0x550; // u64
enum uint VMCB_CR0          = 0x558; // u64
enum uint VMCB_DR7          = 0x560; // u64
enum uint VMCB_DR6          = 0x568; // u64
enum uint VMCB_RFLAGS       = 0x570; // u64
enum uint VMCB_RIP          = 0x578; // u64
enum uint VMCB_RSP          = 0x5D8; // u64
enum uint VMCB_RAX          = 0x5F8; // u64
enum uint VMCB_STAR         = 0x600; // u64
enum uint VMCB_LSTAR        = 0x608; // u64
enum uint VMCB_CSTAR        = 0x610; // u64
enum uint VMCB_SFMASK       = 0x618; // u64
enum uint VMCB_KERNEL_GS    = 0x620; // u64 KernelGsBase
enum uint VMCB_SYSENTER_CS  = 0x628; // u64
enum uint VMCB_SYSENTER_ESP = 0x630; // u64
enum uint VMCB_SYSENTER_EIP = 0x638; // u64
enum uint VMCB_CR2          = 0x640; // u64
enum uint VMCB_GPAT         = 0x668; // u64 guest PAT (with NPT)

// --- segment attrib encoding ------------------------------------------------------
// type[3:0], S b4, DPL[6:5], P b7, AVL b12, L b13, DB b14, G b15.
enum ushort VMCB_SEG_TYPE_MASK = 0x000F;
enum ushort VMCB_SEG_S        = 1 << 4;
enum ushort VMCB_SEG_DPL_MASK = 0x0060;
enum ushort VMCB_SEG_P        = 1 << 7;
enum ushort VMCB_SEG_AVL      = 1 << 12;
enum ushort VMCB_SEG_L       = 1 << 13;
enum ushort VMCB_SEG_DB      = 1 << 14;
enum ushort VMCB_SEG_G       = 1 << 15;

// --- intercept bits (absolute bit number across the 6 words) -------------------------
enum uint SVM_INT_CPUID    = 114;
enum uint SVM_INT_HLT      = 120;
enum uint SVM_INT_IOIO     = 123;
enum uint SVM_INT_MSR      = 124;
enum uint SVM_INT_SHUTDOWN = 127;
enum uint SVM_INT_VMRUN    = 128;
enum uint SVM_INT_VMMCALL  = 129;
enum uint SVM_INT_VMLOAD   = 130;
enum uint SVM_INT_VMSAVE   = 131;

// --- TLB_CONTROL values (VMCB 0x05C) --------------------------------------------------
enum ubyte SVM_TLB_NONE      = 0;
enum ubyte SVM_TLB_FLUSH_ALL = 1; // entire TLB incl. all ASIDs
enum ubyte SVM_TLB_FLUSH_ASID = 3; // this ASID only
enum ubyte SVM_TLB_FLUSH_ASID_NONGLOBAL = 7;

// --- clean bits (VMCB 0x0C0) -------------------------------------------------------------
enum uint SVM_CLEAN_INTERCEPTS = 1u << 0;
enum uint SVM_CLEAN_PERM_MAP   = 1u << 1;
enum uint SVM_CLEAN_ASID       = 1u << 2;
enum uint SVM_CLEAN_INTR       = 1u << 3;
enum uint SVM_CLEAN_NPT        = 1u << 4;
enum uint SVM_CLEAN_CR         = 1u << 5;
enum uint SVM_CLEAN_DR         = 1u << 6;
enum uint SVM_CLEAN_DT         = 1u << 7;
enum uint SVM_CLEAN_SEG        = 1u << 8;
enum uint SVM_CLEAN_CR2        = 1u << 9;
enum uint SVM_CLEAN_LBR        = 1u << 10;
enum uint SVM_CLEAN_AVIC       = 1u << 11;
enum uint SVM_CLEAN_CET        = 1u << 12;

// --- IOPM / MSRPM geometry ---------------------------------------------------------------
enum uint SVM_IOPM_PAGES  = 3; // 12 KiB
enum uint SVM_MSRPM_PAGES = 2; // 8 KiB

// --- misc_ctl bits ----------------------------------------------------------------------------
enum ulong SVM_MISC_ENABLE_NP = 1UL << 0;

// --- CPUID.8000000A:EDX feature bits ---------------------------------------------------------------
enum uint SVM_FEAT_NPT           = 1u << 0;
enum uint SVM_FEAT_NRIP_SAVE     = 1u << 3;
enum uint SVM_FEAT_VMCB_CLEAN    = 1u << 5;
enum uint SVM_FEAT_FLUSH_BY_ASID = 1u << 6;
enum uint SVM_FEAT_DECODE_ASSISTS = 1u << 7;

// --- exact-layout structs -------------------------------------------------------------------------------
// Packed; every critical offset is static-asserted.  Reserved fields keep
// the arithmetic honest — the asserts, not the field names, are the spec.

align(1) struct VmcbSeg {
    ushort selector;
    ushort attrib;
    uint limit;
    ulong base;
}
static assert(VmcbSeg.sizeof == 16);

align(1) struct VmcbControl {
    uint[6] intercepts;          // 0x000
    uint[9] reserved0;           // 0x018
    ushort pauseFilterThreshold; // 0x03C
    ushort pauseFilterCount;     // 0x03E
    ulong iopmBasePa;            // 0x040
    ulong msrpmBasePa;           // 0x048
    ulong tscOffset;             // 0x050
    uint asid;                   // 0x058
    ubyte tlbControl;            // 0x05C
    ubyte erapControl;           // 0x05D
    ushort reserved1;            // 0x05E
    uint intCtl;                 // 0x060
    uint intVector;              // 0x064
    uint intState;               // 0x068
    uint reserved2;              // 0x06C
    ulong exitcode;              // 0x070
    ulong exitinfo1;             // 0x078
    ulong exitinfo2;             // 0x080
    uint exitintinfo;            // 0x088
    uint exitintinfoErr;         // 0x08C
    ulong miscCtl;               // 0x090
    ulong avicApicBar;           // 0x098
    ulong ghcbGpa;               // 0x0A0
    uint eventinj;               // 0x0A8
    uint eventinjErr;            // 0x0AC
    ulong ncr3;                  // 0x0B0
    ulong miscCtl2;              // 0x0B8
    uint cleanBits;              // 0x0C0
    uint reserved3;              // 0x0C4
    ulong nrip;                  // 0x0C8
    ubyte insnLen;               // 0x0D0
    ubyte[15] insnBytes;         // 0x0D1
    ulong avicBackingPage;       // 0x0E0
    ubyte[8] reserved4;          // 0x0E8
    ulong avicLogicalTable;      // 0x0F0
    ulong avicPhysicalTable;     // 0x0F8
    ubyte[0x38] reserved5;       // 0x100-0x137
    ulong allowedSevFeatures;    // 0x138
    ulong guestSevFeatures;      // 0x140
    ubyte[0x298] reserved6;      // 0x148-0x3DF
    ubyte[32] hypervisorUse;     // 0x3E0-0x3FF
}
static assert(VmcbControl.sizeof == 0x400);
static assert(VmcbControl.iopmBasePa.offsetof == 0x040);
static assert(VmcbControl.msrpmBasePa.offsetof == 0x048);
static assert(VmcbControl.tscOffset.offsetof == 0x050);
static assert(VmcbControl.asid.offsetof == 0x058);
static assert(VmcbControl.tlbControl.offsetof == 0x05C);
static assert(VmcbControl.exitcode.offsetof == 0x070);
static assert(VmcbControl.exitinfo1.offsetof == 0x078);
static assert(VmcbControl.exitinfo2.offsetof == 0x080);
static assert(VmcbControl.exitintinfo.offsetof == 0x088);
static assert(VmcbControl.miscCtl.offsetof == 0x090);
static assert(VmcbControl.eventinj.offsetof == 0x0A8);
static assert(VmcbControl.ncr3.offsetof == 0x0B0);
static assert(VmcbControl.miscCtl2.offsetof == 0x0B8);
static assert(VmcbControl.cleanBits.offsetof == 0x0C0);
static assert(VmcbControl.nrip.offsetof == 0x0C8);
static assert(VmcbControl.insnLen.offsetof == 0x0D0);

align(1) struct VmcbSave {
    VmcbSeg es;                  // 0x400
    VmcbSeg cs;                  // 0x410
    VmcbSeg ss;                  // 0x420
    VmcbSeg ds;                  // 0x430
    VmcbSeg fs;                  // 0x440
    VmcbSeg gs;                  // 0x450
    VmcbSeg gdtr;                // 0x460
    VmcbSeg ldtr;                // 0x470
    VmcbSeg idtr;                // 0x480
    VmcbSeg tr;                  // 0x490
    ubyte[0x2A] reserved0;       // 0x4A0-0x4C9
    ubyte vmpl;                  // 0x4CA
    ubyte cpl;                   // 0x4CB
    uint reserved1;              // 0x4CC
    ulong efer;                  // 0x4D0
    ubyte[0x70] reserved2;       // 0x4D8-0x547
    ulong cr4;                   // 0x548
    ulong cr3;                   // 0x550
    ulong cr0;                   // 0x558
    ulong dr7;                   // 0x560
    ulong dr6;                   // 0x568
    ulong rflags;                // 0x570
    ulong rip;                   // 0x578
    ubyte[0x58] reserved3;       // 0x580-0x5D7
    ulong rsp;                   // 0x5D8
    ulong sCet;                  // 0x5E0
    ulong ssp;                   // 0x5E8
    ulong isstAddr;              // 0x5F0
    ulong rax;                   // 0x5F8
    ulong star;                  // 0x600
    ulong lstar;                 // 0x608
    ulong cstar;                 // 0x610
    ulong sfmask;                // 0x618
    ulong kernelGsBase;          // 0x620
    ulong sysenterCs;            // 0x628
    ulong sysenterEsp;           // 0x630
    ulong sysenterEip;           // 0x638
    ulong cr2;                   // 0x640
    ubyte[0x20] reserved4;       // 0x648-0x667
    ulong gpat;                  // 0x668
    ulong dbgctl;                // 0x670
    ulong brFrom;                // 0x678
    ulong brTo;                  // 0x680
    ulong lastExcpFrom;          // 0x688
    ulong lastExcpTo;            // 0x690
    ubyte[0x48] reserved5;       // 0x698-0x6DF
    ulong specCtrl;              // 0x6E0
    ubyte[0x918] reserved6;      // 0x6E8-0xFFF
}
static assert(VmcbSave.sizeof == 0xC00);
static assert(VmcbSave.cpl.offsetof == 0xCB);
static assert(VmcbSave.efer.offsetof == 0xD0);
static assert(VmcbSave.cr4.offsetof == 0x148);
static assert(VmcbSave.cr3.offsetof == 0x150);
static assert(VmcbSave.cr0.offsetof == 0x158);
static assert(VmcbSave.rflags.offsetof == 0x170);
static assert(VmcbSave.rip.offsetof == 0x178);
static assert(VmcbSave.rsp.offsetof == 0x1D8);
static assert(VmcbSave.rax.offsetof == 0x1F8);
static assert(VmcbSave.cr2.offsetof == 0x240);
static assert(VmcbSave.gpat.offsetof == 0x268);

align(1) struct Vmcb {
    VmcbControl control;
    VmcbSave save;
}
static assert(Vmcb.sizeof == 0x1000);

// --- helpers ----------------------------------------------------------------------------------------

// Set one intercept bit in the 6-word vector.
void vmcbSetIntercept(VmcbControl* c, uint bit) {
    if (c is null || bit >= 192) return;
    c.intercepts[bit / 32] |= 1u << (bit % 32);
}

// Write one segment entry (u16 sel, u16 attrib, u32 limit, u64 base).
void vmcbWriteSeg(VmcbSeg* s, ushort sel, ushort attrib, uint limit, ulong base) {
    if (s is null) return;
    s.selector = sel;
    s.attrib = attrib;
    s.limit = limit;
    s.base = base;
}

// Translate a KVM segment (type/present/dpl/db/s/l/g/avl split fields) into
// the VMCB attrib encoding.  Unusable segments encode as all-zero.
ushort vmcbSegAttrib(ubyte type, ubyte s, ubyte dpl, ubyte present,
                     ubyte avl, ubyte l, ubyte db, ubyte g, ubyte unusable) {
    if (unusable) return 0;
    return cast(ushort)(
        (type & 0x0F) |
        ((s & 1) << 4) |
        ((dpl & 3) << 5) |
        ((present & 1) << 7) |
        ((avl & 1) << 12) |
        ((l & 1) << 13) |
        ((db & 1) << 14) |
        ((g & 1) << 15));
}
