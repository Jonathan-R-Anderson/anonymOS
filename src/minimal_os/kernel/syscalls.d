module minimal_os.kernel.syscalls;

import minimal_os.console : printLine, printHex, printUnsigned, print;
import minimal_os.posix; // Import the module to access package-visible sys_* functions
import minimal_os.kernel.linux_syscalls;

// MSR constants
enum MSR_STAR  = 0xC0000081;
enum MSR_LSTAR = 0xC0000082;
enum MSR_FMASK = 0xC0000084;

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

extern(C) void wrmsr(uint msr, ulong value);
extern(C) ulong rdmsr(uint msr);

// Assembly entry point for syscalls
extern(C) void syscallEntry();

// Initialize syscall mechanism
void initSyscalls()
{
    // Set LSTAR to syscallEntry
    wrmsr(MSR_LSTAR, cast(ulong)&syscallEntry);

    // Set SFMASK (RFLAGS mask) - mask interrupts (IF=0x200)
    wrmsr(MSR_FMASK, 0x200); 

    // Set STAR (CS/SS selectors)
    // Kernel CS: 0x08, User CS: 0x18 (assuming standard GDT layout)
    // STAR[47:32] = Kernel CS
    // STAR[63:48] = User CS (actually User CS - 16, so if User CS is 0x23, we put 0x13? No, usually 0x18/0x20)
    // For now, assuming 0x08 is kernel code, 0x10 is kernel data.
    // 0x18 user code (32), 0x20 user data, 0x28 user code (64)
    // This depends on GDT setup in loader.
    // Let's assume a standard setup for now or leave it if loader sets it.
    // wrmsr(MSR_STAR, 0x0023000800000000); // Example
}

extern(C) void handleSyscall(ulong rax, ulong rdi, ulong rsi, ulong rdx, ulong r10, ulong r8, ulong r9)
{
    // printLine("[syscall] Dispatching...");
    // printHex(rax);

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
             result = sys_fstat(cast(int)rdi, cast(stat_t*)rsi);
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
extern(C) naked @nogc nothrow void syscallEntry()
{
    // Save user stack pointer and switch to kernel stack
    asm {
        // Save user rsp
        mov [scratch_rsp], rsp;
        // Load kernel rsp
        mov rsp, [kernel_rsp];

        // Save registers that will be used for argument shuffling
        // Push the 7th argument (original r9) onto the stack for the call
        push r9;

        // Shuffle registers to match D calling convention for handleSyscall
        // handleSyscall(rax, rdi, rsi, rdx, r10, r8, r9)
        // D expects: rdi, rsi, rdx, rcx, r8, r9 for first six args
        // Map as follows:
        //   rdi <- rax (syscall number)
        //   rsi <- rdi (original arg1)
        //   rdx <- rsi (original arg2)
        //   rcx <- rdx (original arg3)
        //   r8  <- r10 (original arg4)
        //   r9  <- r8  (original arg5)
        //   [stack] holds original r9 (arg6)
        mov r9, r8;   // sixth arg becomes r9
        mov r8, r10;  // fifth arg becomes r8
        mov rcx, rdx; // fourth arg becomes rcx
        mov rdx, rsi; // third arg becomes rdx
        mov rsi, rdi; // second arg becomes rsi
        mov rdi, rax; // first arg becomes rdi (syscall number)

        // Call the dispatcher
        call handleSyscall;

        // Clean up the stack (pop the pushed original r9)
        add rsp, 8;

        // Restore user stack pointer
        mov rsp, [scratch_rsp];

        // Return to user mode (RAX already contains the return value)
        sysretq;
    }
}

// Scratch space for stack switching (very primitive, single core only)
__gshared ulong scratch_rsp;
__gshared ulong kernel_rsp;

// We need to set kernel_rsp somewhere.
// For now, let's allocate a static stack.
__gshared ubyte[4096] static_kernel_stack;

shared static this()
{
    kernel_rsp = cast(ulong)static_kernel_stack.ptr + 4096;
}
