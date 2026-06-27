module core.kmain;

import arch.x86_64.limine;
import arch.x86_64.bootstrap;
import arch.x86_64.arch;
import arch.x86_64.gdt : loadGdt, loadTr, prepareApCpuState, apGdtPtr;  // SMP S4.1 per-CPU GDT/TSS
import arch.x86_64.interrupts : loadIdt, buildApIdt, g_apIdtPtr;        // SMP S4.2 per-CPU IDT
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
public __gshared ubyte[MAX_CPUS] g_apCpuStateOk;     // S4.1: [i] = 1 once AP i installed its own GDT/TSS
public __gshared ubyte[MAX_CPUS] g_apIdtOk;          // S4.2: [i] = 1 once AP i handled a #BP on its own IST
public __gshared ubyte[MAX_CPUS] g_apSyscallOk;      // S4.3: [i] = 1 once AP i routed `syscall` to its own stub

extern(C) void setupApSyscall();   // asm.S: set this CPU's syscall MSRs (LSTAR→apSyscallStub, STAR/FMASK/EFER.SCE)
extern(C) void apDoSyscall();      // asm.S: CPL0 `syscall` self-test round-trip through apSyscallStub

extern(C) extern __gshared ulong g_current_task_id;  // the single global current task (exports.d)

// SMP_ROADMAP S2: per-CPU state.  One area per discovered CPU, sized to the runtime N (NEVER a fixed
// 8).  `selfPtr` sits at offset 0 so `%gs:0` reads it once the GS base points here — the production
// fast path (S3, behind swapgs).  Today the kernel scheduler still uses the global g_current_task_id;
// `currentTask` is the per-CPU mirror it migrates onto in S3.
align(64) struct PerCpu {  // cache-line sized so per-CPU writes don't false-share between cores
    PerCpu* selfPtr;        // offset 0: %gs:0 ⟹ &g_percpu[thisCpu]
    ulong   currentTask;    // 8:  per-CPU current task (shim today; authoritative in S4)
    ulong   idleTask;       // 16
    ulong   heartbeat;      // 24: S4 foundation per-CPU work counter (the AP increments it, lock-free)
    uint    cpuIndex;       // 32
    uint    lapicId;        // 36
    uint    schedCursor;    // 40: per-CPU scheduler run cursor (S4)
    bool    alive;          // 44
    ubyte[3] _pad0;         // 45..47
    ulong   bpHandled;      // 48: S4.2 — the AP's #BP handler sets this via %gs:48 (see asm.S)
    ulong   syscallSeen;    // 56: S4.3 — the AP's syscall stub sets this via %gs:56 (see asm.S)
}
static assert(PerCpu.sizeof == 64);
static assert(PerCpu.bpHandled.offsetof == 48);    // apBpHandler   in asm.S hardcodes %gs:48
static assert(PerCpu.syscallSeen.offsetof == 56);  // apSyscallStub in asm.S hardcodes %gs:56
static assert(PerCpu.heartbeat.offsetof == 24);
static assert(PerCpu.cpuIndex.offsetof == 32);
align(64) public __gshared PerCpu[MAX_CPUS] g_percpu;
public __gshared ulong g_apWorkTotal = 0;   // shared total, incremented under the BKL by the AP workers

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
// S4.1: read back the Task Register selector (str) to confirm TR points at the loaded TSS.
private ushort readTr() {
    ushort sel = void;
    asm @nogc nothrow { str sel; }
    return sel;
}

// S2 accessors (the migration shim).  BSP-only until S3 makes the per-CPU field authoritative.
public PerCpu* thisCpu()    { return &g_percpu[g_bspCpuIndex]; }
public ulong   thisCpuTask(){ return g_percpu[g_bspCpuIndex].currentTask; }

// SMP_ROADMAP S3: the Big Kernel Lock.  A correct cross-core test-and-set spinlock (xchg with a
// memory operand is atomic on x86 — no LOCK prefix needed).  This is the primitive a serial-but-
// correct kernel takes at every entry; wiring it into the syscall/IRQ/fault prologue lands with S4
// (when APs actually run kernel code + contend) — doing it now, with APs parked, would add entry-
// path risk and serialize nothing.  Here it is implemented and PROVEN to serialize across the live
// cores.
public __gshared uint  g_bkl = 0;            // 0 = free, 1 = held
enum uint BKL_PROOF_ITERS = 100_000;
public __gshared ulong g_bklCounter = 0;     // mutated ONLY under the BKL (the mutual-exclusion proof)
public __gshared ubyte[MAX_CPUS] g_cpuBklDone;

private uint bklTryHold(uint* p) {           // returns the PREVIOUS value: 0 = we acquired
    uint old = void;
    asm @nogc nothrow { mov RDX, p; mov EAX, 1; xchg [RDX], EAX; mov old, EAX; }
    return old;
}
public void bklAcquire(uint* p) { while (bklTryHold(p) != 0) __asm("pause", ""); }
public void bklRelease(uint* p) { asm @nogc nothrow { mov RDX, p; xor EAX, EAX; mov [RDX], EAX; } }

// Each caller hammers a shared counter under the BKL; a correct lock yields exactly its share.
private void bklProofRun() {
    foreach (r; 0 .. BKL_PROOF_ITERS) { bklAcquire(&g_bkl); ++g_bklCounter; bklRelease(&g_bkl); }
}

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
        // S4.1: install THIS CPU's own GDT + TSS (its own IST/kernel stack), prepared by the BSP.
        // This is the prerequisite for an AP ever taking a syscall/IRQ/fault — the CPU loads rsp0/
        // ist1 from its OWN TSS on a ring3→ring0 transition, not the BSP's single global stack.
        // loadGdt reloads every segment selector (incl. %gs ← kdata, base 0), so re-establish the
        // per-CPU GS base immediately after, then re-verify it still round-trips.
        auto gp = apGdtPtr(idx);
        if (gp !is null) {
            loadGdt(gp);
            loadTr(0x28);                            // TR → this AP's own TSS (GDT index 5)
            setGsBase(&g_percpu[idx]);               // re-establish per-CPU GS after the segment reload
            auto self2 = cast(PerCpu*)readGsBase();
            if (self2 is &g_percpu[idx] && readTr() == 0x28)
                g_apCpuStateOk[idx] = 1;             // own GDT/TSS installed + GS survived the reload
        }
        // S4.2: load the AP IDT, then deliberately take a #BP (int3).  The CPU switches to THIS
        // AP's IST1 stack (from its S4.1 TSS) and runs apBpHandler, which sets bpHandled via %gs:48.
        // First FUNCTIONAL exercise of the per-CPU TSS/IST — a ring-0 trap handled end-to-end on the
        // AP's own stacks, isolated from the BSP's single global entry path.
        loadIdt(&g_apIdtPtr);
        g_percpu[idx].bpHandled = 0;
        __asm("int3", "");                           // → apBpHandler on IST1 → bpHandled=1 → iret
        if (g_percpu[idx].bpHandled == 1) g_apIdtOk[idx] = 1;
        // S4.3: set up THIS CPU's own syscall MSRs (LSTAR→apSyscallStub, STAR/FMASK/EFER.SCE — all
        // per-CPU MSRs, so the BSP's syscall path is untouched) and self-test that `syscall` routes
        // to its own stub (a CPL0 round-trip).  The third leg of per-CPU entry state, after GDT/TSS
        // (S4.1) + IDT (S4.2) — the syscall-entry plumbing an AP needs to run a real task.
        setupApSyscall();
        g_percpu[idx].syscallSeen = 0;
        apDoSyscall();                               // syscall → apSyscallStub → jmp *rcx returns here
        if (g_percpu[idx].syscallSeen == 1) g_apSyscallOk[idx] = 1;
        bklProofRun();                               // S3: contend on the BKL with the BSP + other APs
        g_cpuBklDone[idx] = 1;
        // S4 foundation: instead of parking, run SUSTAINED parallel kernel work via this CPU's
        // GS-addressed per-CPU area (S2), BKL-coordinated for the shared total — so N-1 cores do
        // continuous work while the BSP boots the desktop.  Real per-CPU *tasks* (a per-CPU
        // scheduler + swapgs + the entry-path BKL) are the full S4 — see SMP_ROADMAP.
        auto pc = cast(PerCpu*)readGsBase();         // this AP's per-CPU area (via GS)
        if (pc is &g_percpu[idx]) {
            for (;;) {
                ++pc.heartbeat;                                      // lock-free (own cache line)
                if ((pc.heartbeat & 0xFFFF) == 0) {                 // periodically touch shared state
                    bklAcquire(&g_bkl); ++g_apWorkTotal; bklRelease(&g_bkl);
                }
            }
        }
    }
    __asm("cli", "");                                // fallback park (idx out of range / GS mismatch)
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

    // S4.1: BSP builds each AP's own GDT + TSS + IST stack SINGLE-THREADED, before releasing them
    // (no allocator/data race).  The AP just loadGdt+loadTr its own copy on entry.
    foreach (i; 0 .. resp.cpu_count) {
        if (i >= MAX_CPUS) break;
        if (cast(uint)i == g_bspCpuIndex) continue;   // BSP keeps init_gdt's tssArea
        prepareApCpuState(cast(uint)i);
    }
    buildApIdt();   // S4.2: build the shared AP IDT once (vector 3 → apBpHandler on IST1)

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

    // S3: the BKL — the BSP contends concurrently with the (already-released) APs, then verifies the
    // shared counter == N × ITERS.  A correct lock loses no updates; a race or broken lock undercounts.
    bklProofRun();
    uint bklDone = 0;
    for (uint spin = 0; spin < 500_000_000u && bklDone < apCount; ++spin) {
        bklDone = 0;
        foreach (i; 0 .. resp.cpu_count) if (i < MAX_CPUS && g_cpuBklDone[i]) ++bklDone;
        __asm("pause", "");
    }
    const ulong bklExpect = cast(ulong)g_smpCpuCount * BKL_PROOF_ITERS;
    klog("[smp] BKL: counter="); klog_hex(g_bklCounter); klog(" expected="); klog_hex(bklExpect);
    klog((g_bklCounter == bklExpect) ? " PASS (cross-core mutual exclusion across all cores)\n"
                                     : " FAIL (lost updates → broken lock / race)\n");

    // S4.1: every AP loaded its OWN GDT+TSS (survived loadGdt's segment reload, TR→its own TSS, GS
    // re-established) — the per-CPU kernel-entry stacks an AP needs to take a syscall/IRQ are in place.
    uint cpuStateOk = 0;
    foreach (i; 0 .. resp.cpu_count) if (i < MAX_CPUS && g_apCpuStateOk[i]) ++cpuStateOk;
    klog("[smp] "); klog_hex(cpuStateOk); klog(" of "); klog_hex(apCount);
    klog((cpuStateOk == apCount)
         ? " APs installed their own per-CPU GDT/TSS (S4.1: ready for kernel entry)\n"
         : " APs installed per-CPU GDT/TSS — MISMATCH\n");

    // S4.2: every AP took a #BP and handled it on its OWN IST stack (per-CPU TSS/IST/IDT work
    // end-to-end for a ring-0 trap) — the first functional exercise of the S4.1 entry stacks.
    uint idtOk = 0;
    foreach (i; 0 .. resp.cpu_count) if (i < MAX_CPUS && g_apIdtOk[i]) ++idtOk;
    klog("[smp] "); klog_hex(idtOk); klog(" of "); klog_hex(apCount);
    klog((idtOk == apCount)
         ? " APs handled a #BP on their own IST stack (S4.2: per-CPU IDT + fault entry works)\n"
         : " APs handled #BP on own IST — MISMATCH\n");

    // S4.3: every AP set its own syscall MSRs and `syscall` routed to its own per-CPU stub (CPL0
    // round-trip) — the per-CPU syscall-entry plumbing an AP needs to run a real task.
    uint sysOk = 0;
    foreach (i; 0 .. resp.cpu_count) if (i < MAX_CPUS && g_apSyscallOk[i]) ++sysOk;
    klog("[smp] "); klog_hex(sysOk); klog(" of "); klog_hex(apCount);
    klog((sysOk == apCount)
         ? " APs routed `syscall` to their own per-CPU entry stub (S4.3: syscall entry ready)\n"
         : " APs syscall-entry — MISMATCH\n");
}

// SMP_ROADMAP S4 foundation report: read the AP work counters AFTER the desktop is up, proving the
// APs ran sustained kernel work IN PARALLEL with the BSP's whole boot (the desktop loaded meanwhile).
public void smpWorkReport() @nogc nothrow {
    if (g_smpCpuCount <= 1) { klog("[smp] single-core: no AP workers\n"); return; }
    klog("[smp] AP parallel work (ran while the BSP booted the desktop):");
    bool allWorked = true;
    foreach (i; 0 .. g_smpCpuCount) {
        if (i >= MAX_CPUS || i == g_bspCpuIndex) continue;
        klog(" cpu"); klog_hex(i); klog("="); klog_hex(g_percpu[i].heartbeat);
        if (g_percpu[i].heartbeat == 0) allWorked = false;
    }
    klog("; sharedWork="); klog_hex(g_apWorkTotal); klog("\n");
    klog(allWorked ? "[smp] S4 foundation PASS: every AP ran sustained parallel kernel work\n"
                   : "[smp] S4 foundation: an AP did no work\n");
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
