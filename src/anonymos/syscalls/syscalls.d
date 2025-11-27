module anonymos.syscalls.syscalls;

import anonymos.console : printLine, printHex, printUnsigned, print;
import anonymos.syscalls.posix; // Import the module to access package-visible sys_* functions
import anonymos.syscalls.linux;

// MSR constants
enum MSR_EFER = 0xC0000080;
enum MSR_STAR  = 0xC0000081;
enum MSR_LSTAR = 0xC0000082;
enum MSR_FMASK = 0xC0000084;
enum ulong EFER_SCE = 1;

// Segment selectors (must match GDT in boot.s)
enum ushort KERNEL_CS = 0x08;
enum ushort USER_CS   = 0x1B;
enum ushort USER_SS   = 0x23;
static assert((USER_CS & 0x3) == 0x3, "USER_CS must be ring3");
static assert(USER_SS == USER_CS + 0x08, "USER_SS must follow USER_CS");

// Syscall numbers (Linux x86_64)
enum SYS_READ    = 0;
enum SYS_WRITE   = 1;
enum SYS_OPEN    = 2;
enum SYS_CLOSE   = 3;
enum SYS_FSTAT   = 5;
enum SYS_MMAP    = 9;
enum SYS_MPROTECT= 10;
enum SYS_MUNMAP  = 11;
enum SYS_BRK     = 12;
enum SYS_ACCESS  = 21;
enum SYS_GETPID  = 39;
enum SYS_FORK    = 57;
enum SYS_EXECVE  = 59;
enum SYS_EXIT    = 60;
enum SYS_WAIT4   = 61;
enum SYS_KILL    = 62;
enum SYS_UNAME   = 63;
enum SYS_READLINK= 89;
enum SYS_ARCH_PRCTL = 158;
enum SYS_SET_TID_ADDRESS = 218;
enum SYS_SET_ROBUST_LIST = 273;
enum SYS_PRLIMIT64 = 302;
enum SYS_RSEQ    = 334;
enum SYS_CAP_INVOKE = 1000; // Custom syscall number for capability invocation
enum SYS_JIT_SEAL = 1001;   // Custom syscall to seal RW -> RX
enum SYS_BLOCK_READ = 1002;
enum SYS_BLOCK_WRITE = 1003;

import anonymos.drivers.ahci : readSector, writeSector, g_primaryPort;
import anonymos.kernel.physmem : allocFrame, freeFrame;
import core.stdc.string : memcpy;

extern(C) long sys_block_read(ulong lba, ulong count, void* buf)
{
    if (g_primaryPort is null) return -1;
    if (count == 0) return 0;
    if (count > 8) return -22; // EINVAL (limit to 4KB for now)

    // Allocate bounce buffer (1 page)
    size_t phys = allocFrame();
    if (phys == 0) return -12; // ENOMEM
    
    // Map to kernel virt
    // We assume linear map
    void* kbuf = cast(void*)(phys + 0xFFFF_8000_0000_0000);
    
    if (!readSector(g_primaryPort, lba, cast(ushort)count, kbuf))
    {
        freeFrame(phys);
        return -5; // EIO
    }
    
    // Copy to user
    memcpy(buf, kbuf, count * 512);
    
    freeFrame(phys);
    return 0;
}

extern(C) long sys_block_write(ulong lba, ulong count, void* buf)
{
    print("[syscall] sys_block_write lba=");
    printUnsigned(lba);
    printLine("");

    if (g_primaryPort is null) return -1;
    if (count == 0) return 0;
    if (count > 8) return -22;

    size_t phys = allocFrame();
    if (phys == 0) return -12;
    
    void* kbuf = cast(void*)(phys + 0xFFFF_8000_0000_0000);
    
    memcpy(kbuf, buf, count * 512);
    
    if (!writeSector(g_primaryPort, lba, cast(ushort)count, kbuf))
    {
        freeFrame(phys);
        return -5;
    }
    
    freeFrame(phys);
    return 0;
}

extern(C) long sys_cap_invoke(ulong capId, ulong method, ulong arg1, ulong arg2)
{
    // Placeholder for capability invocation logic
    // In a real system, we would look up the capability in the process's c-list,
    // verify rights, and dispatch to the object.
    
    import anonymos.console : printLine, printHex;
    // printLine("[syscall] sys_cap_invoke");
    // printHex(capId);
    
    return 0;
}

extern(C) void wrmsr(uint msr, ulong value)
{
    asm {
        mov ECX, msr;
        mov EAX, value; // Low 32
        mov RDX, value;
        shr RDX, 32;    // High 32
        wrmsr;
    }
}

extern(C) ulong rdmsr(uint msr)
{
    ulong low, high;
    asm {
        mov ECX, msr;
        rdmsr;
        mov low, RAX;
        mov high, RDX;
    }
    return (high << 32) | low;
}

// Assembly entry point for syscalls
extern(C) void syscallEntry();

// Initialize syscall mechanism
void initSyscalls()
{
    // Enable SYSCALL/SYSRET without disturbing NXE/LME bits set during boot.
    // For SYSRET to land in USER_CS/USER_SS, STAR encodes (user_cs - 0x10) in [63:48].
    const ulong starValue = (cast(ulong)(USER_CS - 0x10) << 48) | (cast(ulong)KERNEL_CS << 32);
    const ulong eferValue = rdmsr(MSR_EFER) | EFER_SCE;
    wrmsr(MSR_EFER, eferValue);

    // Set LSTAR to syscallEntry
    wrmsr(MSR_LSTAR, cast(ulong)&syscallEntry);

    // Set SFMASK (RFLAGS mask) - mask interrupts (IF=0x200)
    wrmsr(MSR_FMASK, 0x200); 

    // STAR encodes kernel/user selectors for syscall/sysret transitions.
    wrmsr(MSR_STAR, starValue);
}

extern(C) void handleSyscall(ulong rax, ulong rdi, ulong rsi, ulong rdx, ulong r10, ulong r8, ulong r9)
{
    // printLine("[syscall] Dispatching...");
    // printHex(rax);

    import anonymos.syscalls.posix : syscallAllowed;
    if (!syscallAllowed(rax))
    {
        asm { mov RAX, -1; }
        return;
    }

    long result = -38; // ENOSYS

    switch (rax)
    {
        case SYS_READ:
             result = sys_read(cast(int)rdi, cast(void*)rsi, cast(size_t)rdx);
             break;
        
        case SYS_WRITE:
             result = sys_write(cast(int)rdi, cast(void*)rsi, cast(size_t)rdx);
             break;

        case SYS_OPEN:
             result = sys_open(cast(const(char)*)rdi, cast(int)rsi, cast(int)rdx);
             break;

        case SYS_CLOSE:
             result = sys_close(cast(int)rdi);
             break;
             
        case SYS_FSTAT:
             result = sys_fstat(cast(int)rdi, cast(anonymos.syscalls.linux.stat_t*)rsi);
             break;

        case SYS_MMAP:
             result = sys_mmap(rdi, rsi, rdx, r10, r8, r9);
             break;

        case SYS_MPROTECT:
             result = sys_mprotect(rdi, rsi, rdx);
             break;

        case SYS_MUNMAP:
             result = sys_munmap(rdi, rsi);
             break;

        case SYS_BRK:
             result = sys_brk(rdi);
             break;

        case SYS_ACCESS:
             result = sys_access(cast(const(char)*)rdi, cast(int)rsi);
             break;

        case SYS_EXIT:
            sys__exit(cast(int)rdi);
            break;

        case SYS_EXECVE:
            result = sys_execve(cast(const(char)*)rdi, cast(const(char*)*)rsi, cast(const(char*)*)rdx);
            break;

        case SYS_FORK:
            result = sys_fork();
            break;

        case SYS_WAIT4:
            result = sys_waitpid(cast(int)rdi, cast(int*)rsi, cast(int)rdx);
            break;
        
        case SYS_GETPID:
            result = sys_getpid();
            break;

        case SYS_UNAME:
            result = sys_uname(cast(utsname*)rdi);
            break;
            
        case SYS_READLINK:
            result = sys_readlink(cast(const(char)*)rdi, cast(char*)rsi, cast(ulong)rdx);
            break;

        case SYS_ARCH_PRCTL:
            result = sys_arch_prctl(cast(int)rdi, rsi);
            break;

        case SYS_SET_TID_ADDRESS:
            result = sys_set_tid_address(cast(int*)rdi);
            break;

        case SYS_SET_ROBUST_LIST:
            result = sys_set_robust_list(cast(void*)rdi, rsi);
            break;
            
        case SYS_PRLIMIT64:
            result = sys_prlimit64(cast(int)rdi, cast(int)rsi, cast(void*)rdx, cast(void*)r10);
            break;

        case SYS_RSEQ:
            result = sys_rseq(cast(void*)rdi, cast(uint)rsi, cast(int)rdx, cast(uint)r10);
            break;

        case SYS_KILL:
            result = sys_kill(cast(int)rdi, cast(int)rsi);
            break;

        case SYS_CAP_INVOKE:
            result = sys_cap_invoke(cast(ulong)rdi, cast(ulong)rsi, cast(ulong)rdx, cast(ulong)r10);
            break;

        case SYS_JIT_SEAL:
            result = sys_jit_seal(rdi);
            break;

        case SYS_BLOCK_READ:
            result = sys_block_read(rdi, rsi, cast(void*)rdx);
            break;

        case SYS_BLOCK_WRITE:
            result = sys_block_write(rdi, rsi, cast(void*)rdx);
            break;

        default:
            print("[syscall] Unknown syscall: ");
            printUnsigned(cast(size_t)rax);
            printLine("");
            break;
    }

    // Return result in RAX
    asm {
        mov RAX, result;
    }
}

// Assembly stub
extern(C) void syscallEntry()
{
    asm {
        naked;
        // Save user return context and switch to the kernel stack.
        mov [scratch_rsp], RSP;
        mov RSP, [kernel_rsp];
        push R11;      // user RFLAGS for sysret
        push RCX;      // user RIP for sysret

        // Preserve the 6th argument (r9) before shuffling for the D ABI.
        push R9;

        // handleSyscall(rax, rdi, rsi, rdx, r10, r8, r9)
        mov R9, R8;    // sixth arg becomes r9
        mov R8, R10;   // fifth arg becomes r8
        mov RCX, RDX;  // fourth arg becomes rcx
        mov RDX, RSI;  // third arg becomes rdx
        mov RSI, RDI;  // second arg becomes rsi
        mov RDI, RAX;  // first arg becomes rdi (syscall number)

        call handleSyscall;

        add RSP, 8;    // drop saved arg6
        pop RCX;       // restore user RIP
        pop R11;       // restore user RFLAGS

        mov RSP, [scratch_rsp];

        sysretq;
    }
}

// Scratch space for stack switching (very primitive, single core only)
__gshared ulong scratch_rsp;
extern(C) __gshared ulong kernel_rsp;
