module arch.x86_64.gdt;

import core.io;

extern (C):

@nogc nothrow:

struct gdt_entry {
    align(1):
    ushort limit_low;
    ushort base_low;
    ubyte  base_middle;
    ubyte  access;
    ubyte  granularity;
    ubyte  base_high;
}

struct tss_entry {
    align(1):
    ushort limit_low;
    ushort base_low;
    ubyte  base_middle;
    ubyte  access;
    ubyte  granularity;
    ubyte  base_high;
    uint   base_upper;
    uint   reserved;
}

struct gdt_ptr {
    align(1):
    ushort limit;
    ulong  base;
}

static assert(gdt_ptr.sizeof == 10);
static assert(gdt_entry.sizeof == 8);
static assert(tss_entry.sizeof == 16);

struct tss {
    align(1):
    uint   reserved0;
    ulong  rsp0;
    ulong  rsp1;
    ulong  rsp2;
    ulong  reserved1;
    ulong  ist1;
    ulong  ist2;
    ulong  ist3;
    ulong  ist4;
    ulong  ist5;
    ulong  ist6;
    ulong  ist7;
    ulong  reserved2;
    ushort reserved3;
    ushort iomap_base;
}

static assert(tss.sizeof == 104);

align(16) __gshared gdt_entry[7] gdt;
align(16) __gshared tss tssArea;
align(16) __gshared ubyte[0x4000] x64EmergencyKernelStack;

// Alias for assembly if needed (but we do it all in D/Inline Asm)
// extern char tssArea[]; 

__gshared gdt_ptr gdt_pointer;

void gdt_set_gate(int num, ulong base, ulong limit, ubyte access, ubyte gran) {
    gdt[num].base_low    = (base & 0xFFFF);
    gdt[num].base_middle = (base >> 16) & 0xFF;
    gdt[num].base_high   = (base >> 24) & 0xFF;

    gdt[num].limit_low   = (limit & 0xFFFF);
    gdt[num].granularity = (limit >> 16) & 0x0F;

    gdt[num].granularity |= gran & 0xF0;
    gdt[num].access      = access;
}

void tss_set_gate(int num, ulong base, ulong limit)
{
    auto tss_desc = cast(tss_entry*)&gdt[num];

    tss_desc.limit_low   = cast(ushort)(limit & 0xFFFF);
    tss_desc.base_low    = cast(ushort)(base & 0xFFFF);
    tss_desc.base_middle = cast(ubyte)((base >> 16) & 0xFF);

    tss_desc.access = 0x89;

    tss_desc.granularity = 0x00;

    tss_desc.base_high  = cast(ubyte)((base >> 24) & 0xFF);
    tss_desc.base_upper = cast(uint)((base >> 32) & 0xFFFFFFFF);

    tss_desc.reserved = 0;
}
extern (C) void loadGdt(gdt_ptr*);
extern (C) void loadTr(ushort);

void init_gdt() {
    klog("init_gdt: size of gdt_ptr="); klog_hex(gdt_ptr.sizeof); klog("\n");
    klog("init_gdt: GDT Addr="); klog_hex(cast(ulong)gdt.ptr); klog("\n");
    klog("init_gdt: TSS Addr="); klog_hex(cast(ulong)&tssArea); klog("\n");
    klog("init_gdt: clearing structures\n");
    
    ubyte* gdt_raw = cast(ubyte*)gdt.ptr;
    for (size_t i = 0; i < gdt.sizeof; i++) {
        gdt_raw[i] = 0;
        if (i % 8 == 0) klog(".");
    }
    klog(" GDT cleared\n");
    
    ubyte* tss_raw = cast(ubyte*)&tssArea;
    for (size_t i = 0; i < tss.sizeof; i++) {
        tss_raw[i] = 0;
        if (i % 8 == 0) klog(".");
    }
    klog(" TSS cleared\n");
    auto kstackTop =
        cast(ulong)&x64EmergencyKernelStack[0] + x64EmergencyKernelStack.length;

    tssArea.rsp0 = kstackTop;
    tssArea.ist1 = kstackTop;
    tssArea.iomap_base = cast(ushort)tssArea.sizeof;
    klog("init_gdt: TSS rsp0/ist1=");
    klog_hex(kstackTop);
    klog("\n");
    klog("init_gdt: setting gates\n");
    // NULL
    gdt_set_gate(0, 0, 0, 0, 0); 
    // Kernel Code (64-bit)
    gdt_set_gate(1, 0, 0xFFFFFFFF, 0x9A, 0xAF); 
    // Kernel Data
    gdt_set_gate(2, 0, 0xFFFFFFFF, 0x92, 0xCF); 
    // User Data (Index 3)
    gdt_set_gate(3, 0, 0xFFFFFFFF, 0xF2, 0xCF); 
    // User Code (Index 4)
    gdt_set_gate(4, 0, 0xFFFFFFFF, 0xFA, 0xAF); 

    // TSS (two slots 5 and 6)
    klog("init_gdt: setup TSS gate at index 5\n");
    tss_set_gate(5, cast(ulong)&tssArea, tss.sizeof - 1);

    gdt_pointer.limit = cast(ushort)(gdt.sizeof - 1);
    gdt_pointer.base = cast(ulong)gdt.ptr;

    klog("init_gdt: Loading GDT...\n");
    loadGdt(&gdt_pointer);
    klog("init_gdt: GDT loaded.\n");

    klog("init_gdt: Loading TSS (selector 0x28)...\n");
    loadTr(0x28); 
    klog("init_gdt: TR loaded.\n");
}


void x64_set_tss_stacks(ulong rsp0, ulong ist1) {
    tssArea.rsp0 = rsp0;
    tssArea.ist1 = ist1;
}

// ------------------------------------------------------------------
// SMP_ROADMAP S4.1: per-CPU GDT + TSS + IST/kernel stack for the APs.
//
// The kernel-entry path (context.S) uses ONE global TSS (`tssArea`) — its rsp0/ist1
// point at a single shared kernel stack.  For an AP to ever take a syscall/IRQ/fault it
// needs its OWN TSS (so the CPU loads the AP's own kernel stack on the ring3→ring0
// transition, not the BSP's), and a TSS needs its own GDT slot (ltr's busy bit forbids two
// CPUs sharing one TSS descriptor).  So each AP gets its own GDT (a copy of the BSP's known-
// good code/data descriptors + its own TSS descriptor) + its own TSS + its own IST stack.
//
// The BSP prepares all of this single-threaded BEFORE releasing the APs (so there is no
// allocator/data race); each AP then just loadGdt+loadTr its own copy.
// ------------------------------------------------------------------
enum uint MAX_SMP_CPUS = 256;       // per-CPU descriptor/stack pool ceiling (matches kmain MAX_CPUS)
align(16) __gshared gdt_entry[7][MAX_SMP_CPUS]  g_apGdt;
align(16) __gshared tss[MAX_SMP_CPUS]           g_apTss;
align(16) __gshared gdt_ptr[MAX_SMP_CPUS]       g_apGdtPtr;
align(16) __gshared ubyte[0x2000][MAX_SMP_CPUS] g_apIstStack;   // 8 KiB rsp0/ist1 kernel stack per AP

private void apGdtSetGate(uint idx, int num, ulong base, ulong limit, ubyte access, ubyte gran) {
    g_apGdt[idx][num].base_low    = cast(ushort)(base & 0xFFFF);
    g_apGdt[idx][num].base_middle = cast(ubyte)((base >> 16) & 0xFF);
    g_apGdt[idx][num].base_high   = cast(ubyte)((base >> 24) & 0xFF);
    g_apGdt[idx][num].limit_low   = cast(ushort)(limit & 0xFFFF);
    g_apGdt[idx][num].granularity = cast(ubyte)((limit >> 16) & 0x0F);
    g_apGdt[idx][num].granularity |= cast(ubyte)(gran & 0xF0);
    g_apGdt[idx][num].access      = access;
}

private void apTssSetGate(uint idx, int num, ulong base, ulong limit) {
    auto td = cast(tss_entry*)&g_apGdt[idx][num];
    td.limit_low   = cast(ushort)(limit & 0xFFFF);
    td.base_low    = cast(ushort)(base & 0xFFFF);
    td.base_middle = cast(ubyte)((base >> 16) & 0xFF);
    td.access      = 0x89;                       // present, 64-bit TSS (available)
    td.granularity = 0x00;
    td.base_high   = cast(ubyte)((base >> 24) & 0xFF);
    td.base_upper  = cast(uint)((base >> 32) & 0xFFFFFFFF);
    td.reserved    = 0;
}

// BSP-side: fully build AP `idx`'s GDT + TSS.  Call before releasing the AP.
void prepareApCpuState(uint idx) {
    if (idx >= MAX_SMP_CPUS) return;
    // Build the 5 standard descriptors from canonical VALUES (NOT by copying the BSP's gdt[],
    // which init_gdt has not populated yet at smpBringup time — _start runs smpBringup before
    // bootstrap_kernel→init_gdt, so a copy would hand the AP a null code segment → triple fault).
    // These are exactly init_gdt's gates.
    apGdtSetGate(idx, 0, 0, 0,           0x00, 0x00);   // NULL
    apGdtSetGate(idx, 1, 0, 0xFFFFFFFF,  0x9A, 0xAF);   // kernel code (64-bit)
    apGdtSetGate(idx, 2, 0, 0xFFFFFFFF,  0x92, 0xCF);   // kernel data
    apGdtSetGate(idx, 3, 0, 0xFFFFFFFF,  0xF2, 0xCF);   // user data
    apGdtSetGate(idx, 4, 0, 0xFFFFFFFF,  0xFA, 0xAF);   // user code
    // This AP's own kernel stack top → rsp0 (ring0 entry) + ist1 (the entry IST).
    ulong ktop = cast(ulong)&g_apIstStack[idx][0] + g_apIstStack[idx].length;
    ubyte* traw = cast(ubyte*)&g_apTss[idx];
    for (size_t i = 0; i < tss.sizeof; i++) traw[i] = 0;
    g_apTss[idx].rsp0       = ktop;
    g_apTss[idx].ist1       = ktop;
    g_apTss[idx].iomap_base = cast(ushort)tss.sizeof;
    // TSS descriptor at index 5 (selector 0x28) → this AP's TSS (16 bytes spanning slots 5,6).
    apTssSetGate(idx, 5, cast(ulong)&g_apTss[idx], tss.sizeof - 1);
    g_apGdtPtr[idx].limit = cast(ushort)(g_apGdt[idx].sizeof - 1);
    g_apGdtPtr[idx].base  = cast(ulong)g_apGdt[idx].ptr;
}

gdt_ptr* apGdtPtr(uint idx) { return (idx < MAX_SMP_CPUS) ? &g_apGdtPtr[idx] : null; }

extern(C) void x64_set_tss_stacks_default()
{
    ulong kstack = 0xffffffff81b4c2a0UL;
    x64_set_tss_stacks(kstack, kstack);
}