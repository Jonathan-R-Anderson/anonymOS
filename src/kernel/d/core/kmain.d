module core.kmain;

import arch.x86_64.limine;
import arch.x86_64.bootstrap;
import arch.x86_64.arch;
import core.globals;
import core.io;
import ldc.attributes;
import ldc.llvmasm;

extern (C):

// Start Marker
@(section(".limine_reqs"))
align(8) __gshared ulong[4] limine_requests_start = [0xf6b8f4b39de7d1ae, 0xfab91a6940fcb9cf, 0x785c6ed015d3e316, 0x181e920a7852b9d9];

// Base Revision
@(section(".limine_reqs"))
align(8) __gshared limine_base_revision base_revision = { 
    id0: 0xf9562b2d5c95a6c8, 
    id1: 0x6a7b384944536bdc, 
    revision: 1
};

// Requests
@(section(".limine_reqs"))
align(8) __gshared limine_memmap_request memmap_req = { id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x67cf3d9d378a806f, id3: 0xe304acdfc50c3c62, revision: 0, response: null };

@(section(".limine_reqs"))
align(8) __gshared limine_module_request module_req = { id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x3e7e279702be32af, id3: 0xca1c4f3bd1280cee, revision: 0, response: null, internal_module_count: 0, internal_modules: null };

@(section(".limine_reqs"))
align(8) __gshared limine_kernel_address_request kernel_addr_req = { id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x71ba76863cc55f63, id3: 0xb2644a48c516a487, revision: 0, response: null };

@(section(".limine_reqs"))
align(8) __gshared limine_hhdm_request hhdm_req = { id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x48dcf1cb8ad2b852, id3: 0x63984e959a98244b, revision: 0, response: null };

@(section(".limine_reqs"))
align(8) __gshared limine_paging_mode_request paging_req = { 
    id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x95c1a0edab0944cb, id3: 0xa4e5cb3842f7488a,
    revision: 0, 
    response: null,
    mode: LIMINE_PAGING_MODE_X86_64_4LVL,
    flags: 0
};

@(section(".limine_reqs"))
align(8) __gshared limine_stack_size_request stack_req = {
    id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x224ef0460a8e8926, id3: 0xe1cb0fc25f46ea3d,
    revision: 0,
    response: null,
    stack_size: 0x100000 // 1MB
};

@(section(".limine_reqs"))
align(8) __gshared limine_framebuffer_request framebuffer_req = {
    id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x9d5827dcd881dd75, id3: 0xa3148604f6fab11b,
    revision: 0,
    response: null
};

@(section(".limine_reqs"))
align(8) __gshared limine_terminal_request terminal_req = {
    id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0xc8ac59310c2b0844, id3: 0xa68d0c7265d38878,
    revision: 0,
    response: null,
    callback: null
};

// SMP / multiprocessor (SMP_ROADMAP S0/S1): ask limine to enumerate + park the APs.
@(section(".limine_reqs"))
align(8) __gshared limine_smp_request smp_req = {
    id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x95a67b819a1b857e, id3: 0xa0b61b723b6a73e0,
    revision: 0,
    response: null,
    flags: 0   // no x2APIC request for now
};

// End Marker
@(section(".limine_reqs"))
align(8) __gshared ulong[2] limine_requests_end = [0xadc0e0531bb10d03, 0x9572709f31764c62];

// SMP_ROADMAP: dynamic core count — discovered at runtime, NEVER hardcoded.  MAX_CPUS is a
// generous compile-time ceiling; the live count comes from limine.  S1 brings every AP online
// to a parked idle loop; S2 gives each a per-CPU area (S3+ a BKL + real work).
enum uint MAX_CPUS = 256;
public __gshared uint  g_smpCpuCount = 1;            // total CPUs (incl. BSP); 1 until discovered
public __gshared uint  g_bspCpuIndex = 0;            // which per-CPU slot is the BSP
public __gshared ubyte[MAX_CPUS] g_cpuOnline;        // [i] = 1 once AP i reports in (i = per-CPU index)
public __gshared ubyte[MAX_CPUS] g_cpuPercpuOk;      // [i] = 1 once AP i verified its GS-addressed area

extern(C) extern __gshared ulong g_current_task_id;  // the single global current task (exports.d)

// SMP_ROADMAP S2: per-CPU state.  One area per discovered CPU, sized to the runtime N (NEVER a fixed
// 8).  `selfPtr` sits at offset 0 so `%gs:0` reads it once the GS base points here — the production
// fast path (S3, behind swapgs).  Today the kernel scheduler still uses the global g_current_task_id;
// `currentTask` is the per-CPU mirror it migrates onto in S3.
struct PerCpu {
    PerCpu* selfPtr;        // offset 0: %gs:0 ⟹ &g_percpu[thisCpu]
    uint    cpuIndex;
    uint    lapicId;
    ulong   currentTask;    // per-CPU current task (shim today; authoritative in S3)
    ulong   idleTask;
    uint    schedCursor;    // per-CPU scheduler run cursor (S4)
    bool    alive;
}
public __gshared PerCpu[MAX_CPUS] g_percpu;

// IA32_GS_BASE (0xC0000101): same MSR arch_prctl(ARCH_SET_GS) writes — so it is UNSAFE to rely on in
// the live syscall path without swapgs (userspace can clobber it).  S2 sets+verifies it only on the
// parked APs (which never run userspace); the BSP addresses its area by index until S3 adds swapgs.
private void setGsBase(void* p) {
    const ulong base = cast(ulong)p;
    asm @nogc nothrow { mov RCX, 0xC0000101; mov RAX, base; mov RDX, base; shr RDX, 32; wrmsr; }
}
private void* readGsBase() {
    ulong val;
    asm @nogc nothrow { mov RCX, 0xC0000101; rdmsr; shl RDX, 32; or RAX, RDX; mov val, RAX; }
    return cast(void*)val;
}

// S2 accessors (the migration shim).  BSP-only until S3 makes the per-CPU field authoritative.
public PerCpu* thisCpu()    { return &g_percpu[g_bspCpuIndex]; }
public ulong   thisCpuTask(){ return g_percpu[g_bspCpuIndex].currentTask; }

// The AP entry point.  Limine parks each AP spinning on its goto_address; when the BSP writes this
// pointer the AP jumps here (its own limine_smp_info* in RDI).  S1: report online.  S2: point this
// AP's GS base at its per-CPU area and verify `%gs`-addressing round-trips, then park.
extern(C) void apEntry(limine_smp_info* info) {
    const uint idx = cast(uint)info.extra_argument;  // the per-CPU index the BSP stashed
    if (idx < MAX_CPUS) {
        setGsBase(&g_percpu[idx]);                   // S2: this CPU's per-CPU area, GS-addressed
        auto self = cast(PerCpu*)readGsBase();       // read it back (no swapgs needed — AP never runs user)
        if (self is &g_percpu[idx] && self.cpuIndex == idx && self.selfPtr is &g_percpu[idx])
            g_cpuPercpuOk[idx] = 1;                  // GS-addressed per-CPU area verified
        g_percpu[idx].alive = true;
        g_cpuOnline[idx] = 1;
    }
    __asm("cli", "");                                // park (no per-CPU IDT/scheduler yet — S3+)
    for (;;) __asm("hlt", "");
}

// Discover the live CPU count, lay out per-CPU state, and bring every AP online (S0 + S1 + S2).  Runs
// early, while limine's page tables are still active, so the APs share the BSP's address space.
void smpBringup() {
    auto resp = smp_req.response;
    if (resp is null) { klog("[smp] no SMP response — single-core boot\n"); return; }
    g_smpCpuCount = cast(uint)resp.cpu_count;
    klog("[smp] "); klog_hex(resp.cpu_count); klog(" CPUs discovered (bsp lapic=");
    klog_hex(resp.bsp_lapic_id); klog(")\n");

    // S2: lay out one per-CPU area per discovered CPU, BEFORE releasing the APs (they read it on entry).
    foreach (i; 0 .. resp.cpu_count) {
        if (i >= MAX_CPUS) break;
        g_percpu[i] = PerCpu.init;
        g_percpu[i].selfPtr  = &g_percpu[i];
        g_percpu[i].cpuIndex = cast(uint)i;
        g_percpu[i].lapicId  = resp.cpus[i].lapic_id;
        if (resp.cpus[i].lapic_id == resp.bsp_lapic_id) g_bspCpuIndex = cast(uint)i;
    }
    if (g_bspCpuIndex < MAX_CPUS) {
        g_percpu[g_bspCpuIndex].alive = true;
        g_percpu[g_bspCpuIndex].currentTask = g_current_task_id;   // shim: mirror the global (0 this early)
    }

    uint apCount = 0;
    foreach (i; 0 .. resp.cpu_count) {
        if (i >= MAX_CPUS) break;
        auto cpu = resp.cpus[i];
        if (cpu.lapic_id == resp.bsp_lapic_id) continue;   // the BSP is already running
        cpu.extra_argument = i;                            // stash the per-CPU index (read before goto)
        cpu.goto_address   = cast(void*)&apEntry;          // release the AP (it spins until non-null)
        ++apCount;
    }

    // Bounded wait for the APs to report in (they were already started by limine, just parked).
    uint online = 0;
    for (uint spin = 0; spin < 50_000_000u && online < apCount; ++spin) {
        online = 0;
        foreach (i; 0 .. resp.cpu_count) if (i < MAX_CPUS && g_cpuOnline[i]) ++online;
        __asm("pause", "");
    }
    uint pcok = 0;
    foreach (i; 0 .. resp.cpu_count) if (i < MAX_CPUS && g_cpuPercpuOk[i]) ++pcok;
    klog("[smp] "); klog_hex(online); klog(" of "); klog_hex(apCount); klog(" APs online; ");
    klog_hex(pcok); klog(" with GS-addressed per-CPU state verified; bsp idx="); klog_hex(g_bspCpuIndex); klog("\n");
    // BSP self-check (index-addressed; its GS stays free for userspace until S3 swapgs)
    if (g_bspCpuIndex < MAX_CPUS && thisCpu().cpuIndex == g_bspCpuIndex
        && thisCpuTask() == g_current_task_id)
        klog("[smp] BSP per-CPU area OK (currentTask shim seeded)\n");
}

extern __gshared ulong hhdm_offset;


void initializeKernelCore() {
    // D owns early platform bring-up (CPU, boot protocol and memory handoff).
    enable_sse();
    klog("AnonymOS Kernel Starting...\n");
    klog("Base Revision Addr: "); klog_hex(cast(ulong)&base_revision); klog("\n");
    klog("Base Rev Magic 0:  "); klog_hex(base_revision.id0); klog("\n");
    klog("Base Rev Magic 1:  "); klog_hex(base_revision.id1); klog("\n");
    klog("Base Revision Val: "); klog_hex(base_revision.revision); klog("\n");

    if (paging_req.response) {
        klog("Paging Mode: "); klog_hex(paging_req.response.mode); klog("\n");
        klog("Paging Flags: "); klog_hex(paging_req.response.flags); klog("\n");
    }

    if (hhdm_req.response) {
        hhdm_offset = hhdm_req.response.offset;
        klog("HHDM Offset: "); klog_hex(hhdm_offset); klog("\n");
    }

    smpBringup();   // SMP_ROADMAP S0/S1: discover the live core count + park every AP online
}

void _start() {
    initializeKernelCore();

    // Hand off from D core to runtime/bootstrap bridge used by Haskell kernel logic.
    bootstrap_kernel(memmap_req.response, kernel_addr_req.response, module_req.response, terminal_req.response, framebuffer_req.response);

    hcf();
}

void hcf() {
    __asm("cli", "");
    while(1) {
        __asm("hlt", "");
    }
}
