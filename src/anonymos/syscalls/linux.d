module anonymos.syscalls.linux;

import anonymos.console : printLine, printHex, printUnsigned;
import anonymos.syscalls.posix : setErrno, Errno, currentProcess, currentVmMap;
import anonymos.kernel.vm_map : Prot, VMMap;

// Constants
enum PROT_READ  = 0x1;
enum PROT_WRITE = 0x2;
enum PROT_EXEC  = 0x4;

enum MAP_SHARED  = 0x01;
enum MAP_PRIVATE = 0x02;
enum MAP_FIXED   = 0x10;
enum MAP_ANONYMOUS = 0x20;

enum SYS_JIT_SEAL = 1001; // custom: flip RW region to RX

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

extern(C) @nogc nothrow long sys_mmap(ulong addr, ulong len, ulong prot, ulong flags, ulong fd, ulong off)
{
    cast(void)fd; cast(void)off;
    auto proc = currentProcess();
    auto vm = currentVmMap();
    if (proc is null || vm is null) return setErrno(Errno.EINVAL);

    if ((prot & PROT_WRITE) != 0 && (prot & PROT_EXEC) != 0)
    {
        return setErrno(Errno.EINVAL);
    }

    if ((flags & MAP_ANONYMOUS) == 0)
    {
        return setErrno(Errno.ENOSYS); // file-backed not supported yet
    }
    if ((flags & MAP_PRIVATE) == 0)
    {
        return setErrno(Errno.EINVAL);
    }

    const ulong pageMask = 4096 - 1;
    if (len == 0) return setErrno(Errno.EINVAL);
    const ulong alignedLen = (len + pageMask) & ~pageMask;
    ulong base;
    if ((flags & MAP_FIXED) != 0)
    {
        base = addr & ~pageMask;
    }
    else
    {
        base = (addr != 0) ? (addr & ~pageMask) : proc.mmapCursor;
    }
    if (base == 0) base = proc.heapLimit ? proc.heapLimit : 0x0000000200000000;

    uint vmProt = Prot.user;
    if (prot & PROT_READ)  vmProt |= Prot.read;
    if (prot & PROT_WRITE) vmProt |= Prot.write;
    if (prot & PROT_EXEC)  vmProt |= Prot.exec;

    if (!vm.mapRegion(base, cast(size_t)alignedLen, vmProt))
    {
        return setErrno(Errno.ENOMEM);
    }

    const ulong next = base + alignedLen;
    if (next > proc.mmapCursor) proc.mmapCursor = next;
    return cast(long)base;
}

extern(C) @nogc nothrow int sys_mprotect(ulong addr, ulong len, ulong prot)
{
    auto vm = currentVmMap();
    if (vm is null) return setErrno(Errno.EINVAL);
    if (len == 0) return setErrno(Errno.EINVAL);
    if ((prot & PROT_WRITE) != 0 && (prot & PROT_EXEC) != 0)
    {
        return setErrno(Errno.EINVAL);
    }
    const ulong pageMask = 4096 - 1;
    const ulong alignedAddr = addr & ~pageMask;
    auto region = vm.findRegion(alignedAddr);
    if (region is null) return setErrno(Errno.EINVAL);
    if (len != region.length) return setErrno(Errno.EINVAL);

    uint vmProt = Prot.user;
    if (prot & PROT_READ)  vmProt |= Prot.read;
    if (prot & PROT_WRITE) vmProt |= Prot.write;
    if (prot & PROT_EXEC)  vmProt |= Prot.exec;

    return vm.protectRegion(alignedAddr, vmProt) ? 0 : setErrno(Errno.EINVAL);
}

extern(C) @nogc nothrow int sys_munmap(ulong addr, ulong len)
{
    auto vm = currentVmMap();
    if (vm is null) return setErrno(Errno.EINVAL);
    const ulong pageMask = 4096 - 1;
    const ulong alignedAddr = addr & ~pageMask;
    if (len == 0) return setErrno(Errno.EINVAL);
    auto region = vm.findRegion(alignedAddr);
    if (region is null) return setErrno(Errno.EINVAL);
    if (len != region.length) return setErrno(Errno.EINVAL);

    return vm.unmapRegion(alignedAddr) ? 0 : setErrno(Errno.EINVAL);
}

extern(C) @nogc nothrow ulong sys_brk(ulong addr)
{
    auto proc = currentProcess();
    if (proc is null) return 0;

    // Return current break
    if (addr == 0)
    {
        return proc.heapBrk ? proc.heapBrk : proc.heapBase;
    }

    if (proc.heapBase == 0 || proc.heapLimit == 0)
    {
        return proc.heapBrk;
    }

    if (addr < proc.heapBase || addr > proc.heapLimit)
    {
        return proc.heapBrk; // fail, return unchanged
    }

    proc.heapBrk = addr;
    return proc.heapBrk;
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

/// Custom syscall to flip a RW, non-exec region to RX (JIT seal).
extern(C) @nogc nothrow int sys_jit_seal(ulong addr)
{
    auto vm = currentVmMap();
    if (vm is null) return setErrno(Errno.EINVAL);

    const ulong pageMask = 4096 - 1;
    const ulong alignedAddr = addr & ~pageMask;
    auto region = vm.findRegion(alignedAddr);
    if (region is null) return setErrno(Errno.EINVAL);

    // Require it is RW, non-exec before sealing.
    const bool wasWritable = (region.prot & Prot.write) != 0;
    const bool wasExec = (region.prot & Prot.exec) != 0;
    if (!wasWritable || wasExec)
    {
        return setErrno(Errno.EINVAL);
    }

    return vm.flipRegionToRX(alignedAddr) ? 0 : setErrno(Errno.EINVAL);
}
