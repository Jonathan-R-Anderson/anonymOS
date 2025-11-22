module minimal_os.kernel.linux_syscalls;

import minimal_os.console : printLine, printHex, printUnsigned;
import minimal_os.posix : setErrno, Errno;

// Constants
enum PROT_READ  = 0x1;
enum PROT_WRITE = 0x2;
enum PROT_EXEC  = 0x4;

enum MAP_SHARED  = 0x01;
enum MAP_PRIVATE = 0x02;
enum MAP_FIXED   = 0x10;
enum MAP_ANONYMOUS = 0x20;

// Structs
struct timespec {
    long tv_sec;
    long tv_nsec;
}

struct stat_t {
    ulong st_dev;
    ulong st_ino;
    ulong st_nlink;
    uint  st_mode;
    uint  st_uid;
    uint  st_gid;
    uint  __pad0;
    ulong st_rdev;
    long  st_size;
    long  st_blksize;
    long  st_blocks;
    timespec st_atim;
    timespec st_mtim;
    timespec st_ctim;
    long[3] __unused;
}

struct utsname {
    char[65] sysname;
    char[65] nodename;
    char[65] release;
    char[65] version_;
    char[65] machine;
    char[65] domainname;
}

// Syscall Implementations

extern(C) @nogc nothrow void wrmsr(uint msr, ulong value);

extern(C) @nogc nothrow ulong sys_mmap(ulong addr, ulong len, ulong prot, ulong flags, ulong fd, ulong off)
{
    // printLine("[syscall] mmap stub");
    // For now, just allocate memory or return error.
    // If MAP_ANONYMOUS, we can just return a pointer to some heap.
    // If file backed, we need to read file.
    
    // Very primitive allocator for now:
    // We don't have a real VMM exposed here easily.
    // But we can assume identity mapping and just increment a pointer?
    // No, that's dangerous.
    
    // For now, fail.
    return cast(ulong)-12; // ENOMEM
}

extern(C) @nogc nothrow int sys_mprotect(ulong addr, ulong len, ulong prot)
{
    return 0; // Success (stub)
}

extern(C) @nogc nothrow int sys_munmap(ulong addr, ulong len)
{
    return 0; // Success (stub)
}

extern(C) @nogc nothrow ulong sys_brk(ulong addr)
{
    // printLine("[syscall] brk stub");
    // If addr is 0, return current break.
    // If addr > current break, allocate.
    
    static __gshared ulong current_brk = 0x10000000; // Start heap at 256MB
    
    if (addr == 0) return current_brk;
    
    // Align to page?
    current_brk = addr;
    return current_brk;
}

extern(C) @nogc nothrow int sys_fstat(int fd, stat_t* buf)
{
    if (buf is null) return -14; // EFAULT
    
    // Fill with dummy data
    buf.st_dev = 1;
    buf.st_ino = 1;
    buf.st_mode = 0x81FF; // File, 0777
    buf.st_nlink = 1;
    buf.st_uid = 0;
    buf.st_gid = 0;
    buf.st_size = 0; // Unknown size
    buf.st_blksize = 4096;
    buf.st_blocks = 0;
    
    return 0;
}

extern(C) @nogc nothrow int sys_uname(utsname* buf)
{
    if (buf is null) return -14;
    
    buf.sysname[0] = 'L'; buf.sysname[1] = 'i'; buf.sysname[2] = 'n'; buf.sysname[3] = 'u'; buf.sysname[4] = 'x'; buf.sysname[5] = 0;
    buf.release[0] = '5'; buf.release[1] = '.'; buf.release[2] = '0'; buf.release[3] = 0;
    buf.version_[0] = '#'; buf.version_[1] = '1'; buf.version_[2] = 0;
    buf.machine[0] = 'x'; buf.machine[1] = '8'; buf.machine[2] = '6'; buf.machine[3] = '_'; buf.machine[4] = '6'; buf.machine[5] = '4'; buf.machine[6] = 0;
    
    return 0;
}

extern(C) @nogc nothrow int sys_access(const(char)* path, int mode)
{
    // Always say yes for now
    return 0;
}

extern(C) @nogc int sys_arch_prctl(int code, ulong addr)
{
    // ARCH_SET_FS = 0x1002
    // ARCH_SET_GS = 0x1001
    
    if (code == 0x1002) // SET_FS
    {
        // wrmsr FS_BASE (0xC0000100)
        // We need to use a helper because inline asm in @nogc nothrow functions is tricky with LDC sometimes?
        // Actually, the error says "asm statement is assumed to use GC".
        // We can mark the asm block as trusted or just use the wrmsr helper we defined in syscalls.d?
        // But wrmsr is in syscalls.d, not here.
        // Let's declare it here.
        
        wrmsr(0xC0000100, addr);
        return 0;
    }
    
    return -22; // EINVAL
}

extern(C) @nogc nothrow int sys_set_tid_address(int* tidptr)
{
    return 1; // Return PID (1)
}

extern(C) @nogc nothrow int sys_set_robust_list(void* head, ulong len)
{
    return 0;
}

extern(C) @nogc nothrow int sys_rseq(void* rseq, uint len, int flags, uint sig)
{
    return 0; // Ignore
}

extern(C) @nogc nothrow int sys_prlimit64(int pid, int resource, void* new_limit, void* old_limit)
{
    return 0;
}

extern(C) @nogc nothrow ulong sys_readlink(const(char)* path, char* buf, ulong bufsiz)
{
    return -2; // ENOENT
}
