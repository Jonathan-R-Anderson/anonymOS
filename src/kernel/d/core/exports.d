module core.exports;

import memory.mm;
import arch.x86_64.arch;
import core.io;

extern (C) @nogc nothrow:
ulong x64GetUserRDX();
ulong x64ReadCR2();


import core.globals;
import core.utils;

void trap0();
void trap1();
void trap2();
void trap3();
void trap4();
void trap5();
void trap6();
void trap7();
void trap8();
void trap9();
void trap10();
void trap11();
void trap12();
void trap13();
void trap14();
void trap15();
void trap16();
void trap17();
void trap18();
void trap19();
void trap20();
void trap21();
void trap22();
void trap23();
void trap24();
void trap25();
void trap26();
void trap27();
void trap28();
void trap29();
void trap30();
void trap31();
void irq0();
void irq1();
void irq2();
void irq3();
void irq4();
void irq5();
void irq6();
void irq7();
void irq8();
void irq9();
void irq10();
void irq11();
void irq12();
void irq13();
void irq14();
void irq15();

ulong phys_to_virt(ulong phys) {
    return phys + hhdm_offset;
}

struct multiboot_module_t {
    uint mod_start;
    uint mod_end;
    uint string;
    uint reserved;
}

__gshared int g_module_count;
__gshared multiboot_module_t* g_mboot_modules;

extern(C) void c_assert(int condition);

void __assert(const char *msg, const char *file, int line) {
    klog("ASSERTION FAILED: ");
    klog(msg);
    klog("\nFile: "); klog(file);
    klog("\nLine: "); klog_hex(line);
    while(1) { asm @nogc nothrow { hlt; } }
}

void report_kernel_panic(const char* msg) {
    klog("KERNEL PANIC: ");
    klog(msg);
    while(1) { asm @nogc nothrow { hlt; } }
}

extern(C) void report_kernel_fault(ulong trap, ulong err, ulong rip, ulong rflags) {
    ulong cr2 = x64ReadCR2();
    klog("KERNEL FAULT trap=");
    klog_hex(trap);
    klog(" err=");
    klog_hex(err);
    klog(" rip=");
    klog_hex(rip);
    klog(" rflags=");
    klog_hex(rflags);
    klog(" cr2=");
    klog_hex(cr2);
    klog("\n");
    while(1) { asm @nogc nothrow { cli; hlt; } }
}

extern(C) void debug_isr_info(ulong oldIst1, ulong vecNum) {
    klog("[ISR oi=");
    klog_hex(oldIst1);
    klog(" v=");
    klog_hex(vecNum & 0xff);
    klog("]\n");
}

private bool cstrContainsExports(const(char)* haystack, const(char)* needle)
{
    if (haystack is null || needle is null)
        return false;

    ulong needleLen = 0;
    while (needle[needleLen] != 0)
        needleLen++;

    if (needleLen == 0)
        return true;

    for (ulong i = 0; haystack[i] != 0; i++) {
        ulong j = 0;

        while (needle[j] != 0 &&
               haystack[i + j] != 0 &&
               haystack[i + j] == needle[j])
        {
            j++;
        }

        if (j == needleLen)
            return true;
    }

    return false;
}

extern(C) void copy_phys_page(ulong srcPhys, ulong dstPhys)
{
    enum ulong HHDM_OFFSET = 0xffff800000000000UL;

    auto src = cast(ubyte*)(HHDM_OFFSET + srcPhys);
    auto dst = cast(ubyte*)(HHDM_OFFSET + dstPhys);

    for (ulong i = 0; i < 4096; i++)
    {
        dst[i] = src[i];
    }
}

void report_sse_panic() {
    klog("SSE PANIC!\n");
    while(1) { asm @nogc nothrow { hlt; } }
}

__gshared ulong x64FirstTrapSeen;
__gshared ulong x64FirstTrapHalt = 0;

extern(C) void x64_debug_first_trap(
    ulong vecRaw, ulong hasError, ulong* rawFrame,
    ulong oldIst1, ulong entryRsp)
{ /* debug output removed */ }

extern (C) int main(int argc, char** argv); // C ABI entry shim (unused)

// Pointer conversion functions
ulong ptrToWord(void* ptr) {
    return cast(ulong)ptr;
}

void* wordToPtr(ulong w) {
    return cast(void*)w;
}

ulong c_peek_u64(ulong addr) {
    return *(cast(ulong*)addr);
}

ushort c_peek_u16(ulong addr) {
    return *(cast(ushort*)addr);
}

uint c_peek_u32(ulong addr) {
    return *(cast(uint*)addr);
}

ulong interrupt_vector_addr(ulong vector) {
    switch (vector) {
        case 0: return cast(ulong)&trap0;
        case 1: return cast(ulong)&trap1;
        case 2: return cast(ulong)&trap2;
        case 3: return cast(ulong)&trap3;
        case 4: return cast(ulong)&trap4;
        case 5: return cast(ulong)&trap5;
        case 6: return cast(ulong)&trap6;
        case 7: return cast(ulong)&trap7;
        case 8: return cast(ulong)&trap8;
        case 9: return cast(ulong)&trap9;
        case 10: return cast(ulong)&trap10;
        case 11: return cast(ulong)&trap11;
        case 12: return cast(ulong)&trap12;
        case 13: return cast(ulong)&trap13;
        case 14: return cast(ulong)&trap14;
        case 15: return cast(ulong)&trap15;
        case 16: return cast(ulong)&trap16;
        case 17: return cast(ulong)&trap17;
        case 18: return cast(ulong)&trap18;
        case 19: return cast(ulong)&trap19;
        case 20: return cast(ulong)&trap20;
        case 21: return cast(ulong)&trap21;
        case 22: return cast(ulong)&trap22;
        case 23: return cast(ulong)&trap23;
        case 24: return cast(ulong)&trap24;
        case 25: return cast(ulong)&trap25;
        case 26: return cast(ulong)&trap26;
        case 27: return cast(ulong)&trap27;
        case 28: return cast(ulong)&trap28;
        case 29: return cast(ulong)&trap29;
        case 30: return cast(ulong)&trap30;
        case 31: return cast(ulong)&trap31;
        case 32: return cast(ulong)&irq0;
        case 33: return cast(ulong)&irq1;
        case 34: return cast(ulong)&irq2;
        case 35: return cast(ulong)&irq3;
        case 36: return cast(ulong)&irq4;
        case 37: return cast(ulong)&irq5;
        case 38: return cast(ulong)&irq6;
        case 39: return cast(ulong)&irq7;
        case 40: return cast(ulong)&irq8;
        case 41: return cast(ulong)&irq9;
        case 42: return cast(ulong)&irq10;
        case 43: return cast(ulong)&irq11;
        case 44: return cast(ulong)&irq12;
        case 45: return cast(ulong)&irq13;
        case 46: return cast(ulong)&irq14;
        case 47: return cast(ulong)&irq15;
        default:
            report_kernel_panic("invalid interrupt vector");
            return 0;
    }
}

struct hs_idt_entry {
    ushort offsetLo;
    ushort selector;
    ushort istAndType;
    ushort offsetMid;
    uint offsetHi;
    uint reserved;
}

void write_interrupt_vectors(void* idt_base) {
    auto entries = cast(hs_idt_entry*)idt_base;
    foreach (vector; 0 .. 48) {
        ulong offset = interrupt_vector_addr(vector);
        entries[vector].offsetLo = cast(ushort)(offset & 0xFFFF);
        entries[vector].selector = 0x08;
        entries[vector].istAndType = cast(ushort)((1 << 15) | (0xE << 8) | 1);
        entries[vector].offsetMid = cast(ushort)((offset >> 16) & 0xFFFF);
        entries[vector].offsetHi = cast(uint)((offset >> 32) & 0xFFFFFFFF);
        entries[vector].reserved = 0;
    }
}

// Kernel stack and TSS
// align(1) is required: lidt reads a 10-byte descriptor (2-byte limit at
// offset 0, 8-byte base at offset 2).  Without it D inserts 6 bytes of
// padding before the ulong base, so lidt reads zeros for the base and
// loads IDTR.base = 0, causing a triple fault on the first exception.
struct IDTDescriptor {
    align(1):
    ushort limit;
    ulong base;
}

// kernelTmpStack, kernelTmpStack_top, and setupSysCalls are defined in context.S
extern __gshared ubyte kernelTmpStack_top;
extern(C) void loadIdt(IDTDescriptor*);
extern(C) void setupSysCalls();

extern __gshared ubyte[104] tssArea;

// loadIdt is defined in asm.S

void* alloc_from_regions(ulong size) {
    // Return virtual address
    if (size > 4096) {
        ulong start = alloc_phys_page();
        ulong needed = (size + 4095) / 4096;
        for(int i=1; i<needed; i++) alloc_phys_page();
        return cast(void*)phys_to_virt(start);
    }
    return cast(void*)phys_to_virt(alloc_phys_page());
}

// General-purpose kernel heap allocator (bump, no free)
void* malloc(size_t size) {
    return alloc_from_regions(size);
}

void free(void* ptr) { /* bump allocator — no-op */ }

int fprintf(void* f, const char* fmt, ...) { return 0; }

void puts(char* s) {
    klog(s);
    klog("\n");
}

void arch_invalidate_page(ulong addr) {
    invlpg(addr);
}

void ext_halt() {
    while (true) { asm @nogc nothrow { cli; hlt; } }
}

void x64_ready_for_userspace() {
    setupSysCalls();

    auto tmpStackTop = cast(ulong)&kernelTmpStack_top;
    *cast(ulong*)(cast(ubyte*)&tssArea + 4) = tmpStackTop;
    *cast(ulong*)(cast(ubyte*)&tssArea + 0x24) = tmpStackTop;

    auto idtBase = alloc_from_regions(4096);
    memset(idtBase, 0, 4096);
    write_interrupt_vectors(idtBase);

    IDTDescriptor idt;
    idt.limit = cast(ushort)(48 * hs_idt_entry.sizeof - 1);
    idt.base = cast(ulong)idtBase;
    loadIdt(&idt);
}

// Install the real IDT (trap0-trap31 + irq0-irq15 → serviceISR) and
// initialize TSS IST1/RSP0 to kernelTmpStack_top.  Called from Haskell
// after x64SetupSysCalls; deliberately does NOT call setupSysCalls() to
// avoid double-programming the SYSCALL MSRs.
void x64_setup_full_idt() {
    kchar('l');  // entered x64_setup_full_idt

    kchar('1');

    auto tmpStackTop = cast(ulong)&kernelTmpStack_top;

    kchar('2');

    *cast(ulong*)(cast(ubyte*)&tssArea + 4) = tmpStackTop;

    kchar('3');

    *cast(ulong*)(cast(ubyte*)&tssArea + 0x24) = tmpStackTop;

    kchar('4');

    void* idtBase = alloc_from_regions(4096);

    kchar('5');

    memset(idtBase, 0, 4096);

    kchar('6');

    write_interrupt_vectors(idtBase);

    kchar('7');

    IDTDescriptor idt;

    kchar('8');

    idt.limit = cast(ushort)(48 * hs_idt_entry.sizeof - 1);

    kchar('9');

    idt.base = cast(ulong)idtBase;

    kchar('A');

    loadIdt(&idt);

    kchar('B');
}

// Missing symbols

void free_from_regions(void* ptr, ulong size) {
    // No-op
}

void write_serial(int c) {
    char[2] s;
    s[0] = cast(char)c;
    s[1] = 0;
    klog(s.ptr);
}

extern(C) void abort() {
    klog("ABORT CALLED\n");
    while(true) { asm @nogc nothrow { hlt; } }
}

void arch_unmap_init_task() {
    // No-op
}

ulong get_init_module_phys_base() {
    return init_module_phys_base;
}

// Map a page: convenience wrapper used by display/driver code
void map_page_for_kernel(ulong virt_addr, ulong phys_addr, ulong flags) {
    map_page_hhdm(phys_addr, virt_addr, flags, &alloc_phys_page);
}

// Math stubs
private double absd(double x) {
    return (x < 0.0) ? -x : x;
}

private float absf(float x) {
    return (x < 0.0f) ? -x : x;
}

double frexp(double x, int* exp) {
    if (x == 0.0) {
        *exp = 0;
        return 0.0;
    }
    bool neg = x < 0.0;
    double m = neg ? -x : x;
    int e = 0;
    while (m >= 1.0) {
        m *= 0.5;
        e++;
    }
    while (m < 0.5) {
        m *= 2.0;
        e--;
    }
    *exp = e;
    return neg ? -m : m;
}

float frexpf(float x, int* exp) {
    if (x == 0.0f) {
        *exp = 0;
        return 0.0f;
    }
    bool neg = x < 0.0f;
    float m = neg ? -x : x;
    int e = 0;
    while (m >= 1.0f) {
        m *= 0.5f;
        e++;
    }
    while (m < 0.5f) {
        m *= 2.0f;
        e--;
    }
    *exp = e;
    return neg ? -m : m;
}

double ldexp(double x, int exp) {
    if (exp > 0) {
        while (exp-- > 0) {
            x *= 2.0;
        }
    } else {
        while (exp++ < 0) {
            x *= 0.5;
        }
    }
    return x;
}

float ldexpf(float x, int exp) {
    if (exp > 0) {
        while (exp-- > 0) {
            x *= 2.0f;
        }
    } else {
        while (exp++ < 0) {
            x *= 0.5f;
        }
    }
    return x;
}

double fabs(double x) {
    return absd(x);
}

float fabsf(float x) {
    return absf(x);
}

double ceil(double x) {
    long i = cast(long)x;
    double base = cast(double)i;
    if (x > base) {
        return base + 1.0;
    }
    return base;
}

double log(double x) {
    if (x <= 0.0) {
        return 0.0 / 0.0;
    }

    int exp;
    double m = frexp(x, &exp);
    double y = (m - 1.0) / (m + 1.0);
    double y2 = y * y;
    double term = y;
    double sum = 0.0;

    foreach (k; 0 .. 12) {
        sum += term / cast(double)(2 * k + 1);
        term *= y2;
    }

    enum LN2 = 0.6931471805599453;
    return 2.0 * sum + cast(double)exp * LN2;
}

double sqrt(double x) {
    if (x < 0.0) {
        return 0.0 / 0.0;
    }
    if (x == 0.0) {
        return 0.0;
    }

    double guess = (x >= 1.0) ? x : 1.0;
    foreach (_; 0 .. 32) {
        guess = 0.5 * (guess + x / guess);
    }
    return guess;
}

float sqrtf(float x) {
    if (x < 0.0f) {
        return cast(float)(0.0 / 0.0);
    }
    if (x == 0.0f) {
        return 0.0f;
    }

    float guess = (x >= 1.0f) ? x : 1.0f;
    foreach (_; 0 .. 24) {
        guess = 0.5f * (guess + x / guess);
    }
    return guess;
}

double __isnan(double x) { return (x != x) ? 1.0 : 0.0; }
float __isnanf(float x) { return (x != x) ? 1.0f : 0.0f; }
double __isinf(double x) { return (x == (1.0 / 0.0) || x == -(1.0 / 0.0)) ? 1.0 : 0.0; }
float __isinff(float x) { return (x == cast(float)(1.0 / 0.0) || x == cast(float)(-(1.0 / 0.0))) ? 1.0f : 0.0f; }

// Interrupt handler stubs - these will be overridden by actual handlers
// Trap handlers are defined in context.S

// IRQ handlers are defined in context.S


// User space state (curUserSpaceState, kernelState, x64TrapErrorCode defined in context.S)
extern __gshared ubyte[0x298] curUserSpaceState;
extern __gshared ubyte[0x290] kernelState;
extern __gshared ulong x64LastSyscallRax;
extern __gshared ulong x64LastSyscallRdi;
extern __gshared ulong x64LastSyscallRsi;
extern __gshared ulong x64LastSyscallRdx;
extern __gshared ulong x64LastSyscallR10;
extern __gshared ulong x64LastSyscallR8;
extern __gshared ulong x64LastSyscallR9;
extern __gshared ulong x64LastSyscallRip;

// kernelState is defined in context.S
// x64TrapErrorCode is defined in context.S
extern __gshared ulong x64TrapErrorCode;

// x64SwitchToUserspace is defined in context.S

ulong x64_get_user_state_word(ulong index) {
    auto words = cast(ulong*)(cast(void*)&curUserSpaceState[0] + 8);
    return words[index];
}

enum ulong X64_USER_CS = 0x23;
enum ulong X64_USER_SS = 0x1b;

enum ulong X64_RAX_I    = 0;
enum ulong X64_RBX_I    = 1;
enum ulong X64_RCX_I    = 2;
enum ulong X64_RDX_I    = 3;
enum ulong X64_RSI_I    = 4;
enum ulong X64_RDI_I    = 5;
enum ulong X64_R8_I     = 6;
enum ulong X64_R9_I     = 7;
enum ulong X64_R10_I    = 8;
enum ulong X64_R11_I    = 9;
enum ulong X64_R12_I    = 10;
enum ulong X64_R13_I    = 11;
enum ulong X64_R14_I    = 12;
enum ulong X64_R15_I    = 13;
enum ulong X64_RIP_I    = 14;
enum ulong X64_RSP_I    = 15;
enum ulong X64_RBP_I    = 16;
enum ulong X64_RFLAGS_I = 17;

bool x64_is_canonical(ulong value) {
    ulong high = value >> 48;
    return high == 0 || high == 0xffff;
}

void x64_log_bool(bool value) {
    if (value) {
        klog("1");
    } else {
        klog("0");
    }
}

void x64_log_hex_field(const(char)* name, ulong value) {
    klog(name);
    klog_hex(value);
}

// Diagnostic: dumps CR2, RIP, error code bits, and CR3 to serial when a page fault
// cannot be resolved.
extern(C) void x64_pf_log(ulong vaddr) {
    auto words = cast(ulong*)(cast(void*)&curUserSpaceState[0] + 8);
    ulong rip  = words[X64_RIP_I];
    ulong cr2  = x64ReadCR2();
    ulong cr3  = x64ReadCR3();
    ulong err  = x64TrapErrorCode;

    klog("\nPF vaddr="); klog_hex(vaddr);
    klog(" cr2=");  klog_hex(cr2);
    klog(" rip=");  klog_hex(rip);
    klog(" err=");  klog_hex(err);
    klog(" P=");    klog_hex(err & 1);
    klog(" W=");    klog_hex((err >> 1) & 1);
    klog(" U=");    klog_hex((err >> 2) & 1);
    klog(" I=");    klog_hex((err >> 4) & 1);
    klog(" cr3=");  klog_hex(cr3);
    klog("\n");
}

void x64_debug_userspace_iret_frame(ulong* gp, ulong* frame, ulong cs, ulong ss) { /* debug output removed */ }

void x64_set_user_state_word(ulong index, ulong value) {
    auto words = cast(ulong*)(cast(void*)&curUserSpaceState[0] + 8);
    words[index] = value;
}

extern(C) ulong x64GetUserRDX()
{
    auto words = cast(ulong*)(cast(void*)&curUserSpaceState[0] + 8);
    return words[3];
}

void x64_clear_user_reason() {
    auto words = cast(ulong*)&curUserSpaceState[0];
    words[0] = 0;
}

extern(C) void x64_clear_user_syscall_state() {
    auto words = cast(ulong*)&curUserSpaceState[0];

    // clear reason
    words[0] = 0;

    // clear last syscall snapshot
    x64LastSyscallRax = 0;
    x64LastSyscallRdi = 0;
    x64LastSyscallRsi = 0;
    x64LastSyscallRdx = 0;
    x64LastSyscallR10 = 0;
    x64LastSyscallR8  = 0;
    x64LastSyscallR9  = 0;
    x64LastSyscallRip = 0;
}

ulong x64_get_kernel_state_word(ulong index) {
    auto words = cast(ulong*)(cast(void*)&kernelState[0]);
    return words[index];
}

ulong x64_get_last_syscall_word(ulong index) {
    switch (index) {
        case 0: return x64LastSyscallRax;
        case 1: return x64LastSyscallRdi;
        case 2: return x64LastSyscallRsi;
        case 3: return x64LastSyscallRdx;
        case 4: return x64LastSyscallR10;
        case 5: return x64LastSyscallR8;
        case 6: return x64LastSyscallR9;
        case 7: return x64LastSyscallRip;
        default:
            report_kernel_panic("invalid syscall snapshot index");
            return 0;
    }
}

void update_current_fs_base(ulong base) {
    asm @nogc nothrow {
        mov RCX, 0xC0000100;
        mov RAX, base;
        mov RDX, base;
        shr RDX, 32;
        wrmsr;
    }
}

__gshared ulong[1024] g_task_fsbase;
__gshared bool[1024]  g_task_fsbase_set;
__gshared ulong       g_current_task_id = 0;

void d_set_current_task_id(ulong taskId) {
    g_current_task_id = taskId;
}

void d_store_task_fsbase(ulong taskId, ulong base) {
    if (taskId < 1024) {
        g_task_fsbase[taskId] = base;
        g_task_fsbase_set[taskId] = true;
    }
}

void d_apply_task_fsbase(ulong taskId) {
    if (taskId < 1024 && g_task_fsbase_set[taskId]) {
        ulong base = g_task_fsbase[taskId];
        asm @nogc nothrow {
            mov RCX, 0xC0000100;
            mov RAX, base;
            mov RDX, base;
            shr RDX, 32;
            wrmsr;
        }
    }
}

__gshared ulong[1024] g_task_cleartid_phys;
__gshared bool[1024]  g_task_cleartid_set;

void d_store_task_cleartid_phys(ulong taskId, ulong physAddr) {
    if (taskId < 1024) {
        g_task_cleartid_phys[taskId] = physAddr;
        g_task_cleartid_set[taskId] = (physAddr != 0);
    }
}

void d_do_cleartid(ulong taskId) {
    if (taskId < 1024 && g_task_cleartid_set[taskId]) {
        ulong physAddr = g_task_cleartid_phys[taskId];
        g_task_cleartid_set[taskId] = false;
        if (physAddr != 0 && hhdm_offset != 0) {
            uint* p = cast(uint*)(physAddr + hhdm_offset);
            *p = 0;
        }
    }
}

// Seed the initial stack for a Linux-mode process with a complete auxiliary vector.
// Returns the RSP offset (from stackPhys virtual base) where the stack pointer should be set.
// stackPhys: physical address of the stack allocation
// stackSize: total size of stack allocation in bytes
// stackVirtBase: virtual address where the stack is mapped in userspace
// infoWords: [mainEntry, mainPhdr, mainPhent, mainPhnum, interpBase, execBase, execFn]
// pg: page size
private ulong _copyKernelStrToStack(ulong stackPhysVirt, ulong stackVirtBase, ref ulong strCursor, const(char)* src) {
    if (src is null || strCursor == 0) {
        return 0;
    }

    ulong len = 0;
    while (len < 2047 && src[len] != 0) {
        ++len;
    }

    const ulong bytes = len + 1;
    if (strCursor <= bytes) {
        return 0;
    }

    ulong next = (strCursor - bytes) & ~0xFUL;
    auto dst = cast(ubyte*)(stackPhysVirt + next);
    foreach (i; 0 .. len) {
        dst[i] = cast(ubyte)src[i];
    }
    dst[len] = 0;

    strCursor = next;
    return stackVirtBase + next;
}

ulong linux_seed_initial_stack(
    ulong stackPhys,
    ulong stackSize,
    ulong stackVirtBase,
    const(ulong)* infoWords,
    ulong pg)
{
    ulong stackPhysVirt = phys_to_virt(stackPhys);

    ulong mainEntry  = infoWords[0];
    ulong mainPhdr   = infoWords[1];
    ulong mainPhent  = infoWords[2];
    ulong mainPhnum  = infoWords[3];
    ulong interpBase = infoWords[4];
    // infoWords[5] = execBase (PIE load bias, informational)
    // infoWords[6] = kernel pointer to the exec filename string
    ulong execFnKptr = infoWords[6];

    // Use the caller-supplied exec filename when available.
    const char* execName = (execFnKptr != 0) ? cast(const(char)*)(execFnKptr) : "busybox";

    // --- AT_RANDOM ---
    ulong atRandomPhysOff = stackSize - 64;
    auto randPtr = cast(ubyte*)(stackPhysVirt + atRandomPhysOff);
    ulong seed = stackPhys ^ mainEntry ^ 0xDEADBEEF12345678;

    foreach (i; 0 .. 16) {
        seed = seed * 6364136223846793005 + 1442695040888963407;
        randPtr[i] = cast(ubyte)(seed >> 33);
    }

    ulong atRandomVirt = stackVirtBase + atRandomPhysOff;

    // --- AT_PLATFORM ---
    ulong platformPhysOff = stackSize - 80;
    auto platformPtr = cast(ubyte*)(stackPhysVirt + platformPhysOff);

    platformPtr[0] = 'x';
    platformPtr[1] = '8';
    platformPtr[2] = '6';
    platformPtr[3] = '_';
    platformPtr[4] = '6';
    platformPtr[5] = '4';
    platformPtr[6] = 0;

    ulong atPlatformVirt = stackVirtBase + platformPhysOff;

    // --- argv/env strings ---
    ulong strCursor = platformPhysOff;
    ulong execFnVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, execName);

    enum bootEnvCount = 21;
    ulong[bootEnvCount] envVirts;
    ulong envc = 0;

    ulong envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "HOME=/root\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "USER=root\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "LOGNAME=root\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "SHELL=/bin/sh\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "TERM=linux\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "PATH=/usr/bin:/bin:/usr/local/bin:/sbin:/usr/sbin\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "XDG_RUNTIME_DIR=/run/user/1000\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "XDG_CONFIG_HOME=/etc\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "XDG_CONFIG_DIRS=/etc\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "XDG_DATA_DIRS=/usr/share\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "XDG_SESSION_TYPE=wayland\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "XDG_CURRENT_DESKTOP=Hyprland\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "XDG_SESSION_DESKTOP=Hyprland\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "DESKTOP_SESSION=hyprland\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "WAYLAND_DISPLAY=wayland-0\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    // Seat: no seatd daemon here, so tell libseat to use its in-process builtin
    // backend instead of failing to reach /run/seatd.sock.
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "LIBSEAT_BACKEND=builtin\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    // Software rendering: no GPU, force Mesa's software gallium driver (llvmpipe,
    // self-contained in kms_swrast_dri.so) so EGL/GLES comes up on dumb buffers.
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "LIBGL_ALWAYS_SOFTWARE=1\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "GALLIUM_DRIVER=llvmpipe\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "MESA_LOADER_DRIVER_OVERRIDE=kms_swrast\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;
    // Verbose aquamarine logging to surface the first EGL/DRM backend failures.
    envVirt = _copyKernelStrToStack(stackPhysVirt, stackVirtBase, strCursor, "AQ_TRACE=1\0".ptr);
    if (envVirt != 0) envVirts[envc++] = envVirt;

    bool isHyprland =
    execName !is null &&
    (cstrContainsExports(execName, "Hyprland") ||
     cstrContainsExports(execName, "hyprland"));
    ulong frameWords;
    ulong stupidFlagVirt = 0;

    if (isHyprland) {
        stupidFlagVirt =
            _copyKernelStrToStack(
                stackPhysVirt,
                stackVirtBase,
                strCursor,
                "--i-am-really-stupid\0".ptr);

        frameWords = 1 + 2 + 1 + envc + 1 + 40;
    } else {
        frameWords = 1 + 1 + 1 + envc + 1 + 40;
    }

    ulong rspPhysOff = ((strCursor - 16 - frameWords * 8) & ~0xFUL);
    auto p = cast(ulong*)(stackPhysVirt + rspPhysOff);

    int idx = 0;

    if (isHyprland) {
        p[idx++] = 2;
        p[idx++] = execFnVirt;
        p[idx++] = stupidFlagVirt;
        p[idx++] = 0;
    } else {
        p[idx++] = 1;
        p[idx++] = execFnVirt;
        p[idx++] = 0;
    }

    // envp
    foreach (i; 0 .. envc) {
        p[idx++] = envVirts[i];
    }
    p[idx++] = 0;

    // --- AUXV ---
    p[idx++] = 33; p[idx++] = 0;                // AT_SYSINFO_EHDR
    p[idx++] = 16; p[idx++] = 0xbfebfbff;       // AT_HWCAP
    p[idx++] = 26; p[idx++] = 0;                // AT_HWCAP2
    p[idx++] = 6;  p[idx++] = pg;               // AT_PAGESZ
    p[idx++] = 17; p[idx++] = 100;              // AT_CLKTCK
    p[idx++] = 3;  p[idx++] = mainPhdr;         // AT_PHDR
    p[idx++] = 4;  p[idx++] = mainPhent;        // AT_PHENT
    p[idx++] = 5;  p[idx++] = mainPhnum;        // AT_PHNUM
    p[idx++] = 7;  p[idx++] = interpBase;       // AT_BASE
    p[idx++] = 8;  p[idx++] = 0;                // AT_FLAGS
    p[idx++] = 9;  p[idx++] = mainEntry;        // AT_ENTRY
    p[idx++] = 11; p[idx++] = 0;                // AT_UID
    p[idx++] = 12; p[idx++] = 0;                // AT_EUID
    p[idx++] = 13; p[idx++] = 0;                // AT_GID
    p[idx++] = 14; p[idx++] = 0;                // AT_EGID
    p[idx++] = 23; p[idx++] = 0;                // AT_SECURE
    p[idx++] = 25; p[idx++] = atRandomVirt;     // AT_RANDOM
    p[idx++] = 15; p[idx++] = atPlatformVirt;   // AT_PLATFORM
    p[idx++] = 31; p[idx++] = execFnVirt;       // AT_EXECFN

    // AT_NULL
    p[idx++] = 0;
    p[idx++] = 0;

    ulong rsp = stackVirtBase + rspPhysOff;
    klog("[linux-stack] rsp="); klog_hex(rsp);
    klog(" argc="); klog_hex(p[0]);
    klog(" argv0="); klog_hex(p[1]);
    klog(" envp0="); klog_hex(p[3]);
    klog(" aux0="); klog_hex(p[4]);
    klog(" phdr="); klog_hex(mainPhdr);
    klog(" phent="); klog_hex(mainPhent);
    klog(" phnum="); klog_hex(mainPhnum);
    klog(" entry="); klog_hex(mainEntry);
    klog(" base="); klog_hex(interpBase);
    klog(" execfn="); klog_hex(execFnVirt);
    klog(" random="); klog_hex(atRandomVirt);
    klog("\n");

    return rsp;
}

// Copy a NUL-terminated string from srcVirt into the stack area.
// strCursor is the current stack-write offset (from stackPhysVirt), decremented in place.
// Returns the virtual address of the copy, or 0 if srcVirt is 0 / out of space.
private ulong _copyStrToStack(ulong stackPhysVirt, ulong stackVirtBase, ref ulong strCursor, ulong srcVirt) {
    if (srcVirt == 0) return 0;
    auto src = cast(const(char)*)srcVirt;
    ulong len = 0;
    while (len < 4095 && src[len] != 0) ++len;
    if (strCursor < len + 1) return 0;
    strCursor -= (len + 1);
    auto dst = cast(char*)(stackPhysVirt + strCursor);
    foreach (i; 0 .. len) dst[i] = src[i];
    dst[len] = 0;
    return stackVirtBase + strCursor;
}

// Seed the Linux initial stack for execve with real argv and envp.
// argvUserVirt: user virtual address of char** argv (0 = use execfn as argv[0])
// envpUserVirt: user virtual address of char** envp (0 = empty envp)
// The old page table is still active when this is called, so user virtual addresses are readable.
ulong linux_seed_initial_stack_with_args(
    ulong stackPhys, ulong stackSize, ulong stackVirtBase,
    const(ulong)* infoWords, ulong pg,
    ulong argvUserVirt, ulong envpUserVirt)
{
    ulong stackPhysVirt = phys_to_virt(stackPhys);

    ulong mainEntry  = infoWords[0];
    ulong mainPhdr   = infoWords[1];
    ulong mainPhent  = infoWords[2];
    ulong mainPhnum  = infoWords[3];
    ulong interpBase = infoWords[4];
    ulong execFn     = infoWords[6];

    // AT_RANDOM: 16 pseudo-random bytes
    ulong atRandomPhysOff = stackSize - 64;
    {
        auto randPtr = cast(ubyte*)(stackPhysVirt + atRandomPhysOff);
        ulong seed = stackPhys ^ mainEntry ^ 0xDEADBEEF12345678;
        foreach (i; 0 .. 16) {
            seed = seed * 6364136223846793005 + 1442695040888963407;
            randPtr[i] = cast(ubyte)(seed >> 33);
        }
    }
    ulong atRandomVirt = stackVirtBase + atRandomPhysOff;

    // AT_PLATFORM: "x86_64\0"
    ulong platformPhysOff = stackSize - 80;
    {
        auto pp = cast(ubyte*)(stackPhysVirt + platformPhysOff);
        pp[0]='x'; pp[1]='8'; pp[2]='6'; pp[3]='_'; pp[4]='6'; pp[5]='4'; pp[6]=0;
    }
    ulong atPlatformVirt = stackVirtBase + platformPhysOff;

    // String area: fill downward from just below AT_PLATFORM
    ulong strCursor = platformPhysOff;

    // Copy execfn (kernel pointer from infoWords[6])
    ulong execFnVirt = _copyStrToStack(stackPhysVirt, stackVirtBase, strCursor, execFn);

    // Collect and copy envp strings (in reverse so they sit in forward order)
    enum MAXARGS = 128;
    enum MAXENVS = 256;
    ulong[MAXARGS] argvVirts;
    ulong[MAXENVS] envpVirts;
    ulong argc = 0;
    ulong envc = 0;

    if (envpUserVirt != 0) {
        auto envArr = cast(const(ulong)*)envpUserVirt;
        while (envc < MAXENVS && envArr[envc] != 0) ++envc;
        if (envc > 0) {
            for (long i = cast(long)(envc - 1); i >= 0; --i)
                envpVirts[i] = _copyStrToStack(stackPhysVirt, stackVirtBase, strCursor, envArr[i]);
        }
    }

    // Collect and copy argv strings (in reverse)
    if (argvUserVirt != 0) {
        auto argArr = cast(const(ulong)*)argvUserVirt;
        while (argc < MAXARGS && argArr[argc] != 0) ++argc;
        if (argc > 0) {
            for (long i = cast(long)(argc - 1); i >= 0; --i)
                argvVirts[i] = _copyStrToStack(stackPhysVirt, stackVirtBase, strCursor, argArr[i]);
        }
    }

    // Fall back to execfn as argv[0] when no argv provided
    if (argc == 0) {
        argvVirts[0] = (execFnVirt != 0) ? execFnVirt : stackVirtBase;
        argc = 1;
    }

    // Build the stack frame below the string area.
    // Words: 1(argc) + argc + 1(null) + envc + 1(null) + 20*2(auxv entries)
    ulong frameWords = 1 + argc + 1 + envc + 1 + 40;
    ulong rspPhysOff = ((strCursor - frameWords * 8 - 16) & ~0xFUL);
    auto p = cast(ulong*)(stackPhysVirt + rspPhysOff);
    int idx = 0;

    p[idx++] = argc;
    foreach (i; 0 .. argc) p[idx++] = argvVirts[i];
    p[idx++] = 0;  // argv terminator
    foreach (i; 0 .. envc) p[idx++] = envpVirts[i];
    p[idx++] = 0;  // envp terminator

    // Auxvec (20 entries × 2 words = 40 words)
    p[idx++] = 33; p[idx++] = 0;              // AT_SYSINFO_EHDR (no vDSO)
    p[idx++] = 16; p[idx++] = 0xbfebfbff;     // AT_HWCAP
    p[idx++] = 26; p[idx++] = 0;              // AT_HWCAP2
    p[idx++] = 6;  p[idx++] = pg;             // AT_PAGESZ
    p[idx++] = 17; p[idx++] = 100;            // AT_CLKTCK
    p[idx++] = 3;  p[idx++] = mainPhdr;       // AT_PHDR
    p[idx++] = 4;  p[idx++] = mainPhent;      // AT_PHENT
    p[idx++] = 5;  p[idx++] = mainPhnum;      // AT_PHNUM
    p[idx++] = 7;  p[idx++] = interpBase;     // AT_BASE
    p[idx++] = 8;  p[idx++] = 0;              // AT_FLAGS
    p[idx++] = 9;  p[idx++] = mainEntry;      // AT_ENTRY
    p[idx++] = 11; p[idx++] = 0;              // AT_UID
    p[idx++] = 12; p[idx++] = 0;              // AT_EUID
    p[idx++] = 13; p[idx++] = 0;              // AT_GID
    p[idx++] = 14; p[idx++] = 0;              // AT_EGID
    p[idx++] = 23; p[idx++] = 0;              // AT_SECURE
    p[idx++] = 25; p[idx++] = atRandomVirt;   // AT_RANDOM
    p[idx++] = 15; p[idx++] = atPlatformVirt; // AT_PLATFORM
    p[idx++] = 31; p[idx++] = execFnVirt;     // AT_EXECFN
    p[idx++] = 0;  p[idx++] = 0;              // AT_NULL

    return stackVirtBase + rspPhysOff;
}
