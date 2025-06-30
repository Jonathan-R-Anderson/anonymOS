module posix;

pragma(LDC_no_moduleinfo);

extern(C) @nogc nothrow:

import core.sys.posix.unistd :
    read,
    write,
    close,
    lseek = lseek64,
    fork,
    execve,
    pipe,
    chdir,
    getcwd,
    dup,
    dup2,
    unlink,
    rmdir,
    getpid,
    getppid,
    getuid,
    geteuid,
    getgid,
    getegid,
    chown,
    fchown,
    sleep,
    usleep,
    access,
    isatty,
    _exit,
    brk,
    sbrk,
    readlink;
import core.sys.posix.sys.types : useconds_t;
import core.sys.posix.stdio : rename;
import core.sys.posix.signal : kill, sigaction, sigaction_t;
import core.stdc.signal : signal, sigfn_t;
import core.sys.posix.sys.wait : waitpid;
import core.sys.posix.sys.ioctl : ioctl;
import core.sys.posix.sys.mman : mmap, munmap, mprotect, posix_madvise as c_posix_madvise;
import core.sys.posix.sys.time : gettimeofday, timeval;
import core.sys.posix.time : clock_gettime, timespec;
import core.stdc.config : c_ulong, ptrdiff_t;
public import core.sys.posix.fcntl : open, O_RDONLY, O_WRONLY, O_RDWR, O_CREAT,
    O_TRUNC, O_APPEND, fcntl, creat;
import core.sys.posix.sys.stat : stat, fstat, lstat, stat_t, mode_t, off_t, chmod, fchmod, mkdir, umask;
import core.stdc.stdlib : exit;

// Basic wrappers around common POSIX syscalls. The functions simply
// forward to the underlying C library so they can be used from D code
// compiled with the cross-compiler.

int posix_open(const(char)* path, int flags, mode_t mode)
{
    return open(path, flags, mode);
}

long posix_read(int fd, void* buf, ulong count)
{
    return read(fd, buf, count);
}

long posix_write(int fd, const(void)* buf, ulong count)
{
    return write(fd, buf, count);
}

int posix_close(int fd)
{
    return close(fd);
}

long posix_lseek(int fd, off_t offset, int whence)
{
    return lseek(fd, offset, whence);
}

int posix_pipe(int* fds)
{
    int[2] tmp;
    int rc = pipe(tmp);
    if(rc == 0)
    {
        fds[0] = tmp[0];
        fds[1] = tmp[1];
    }
    return rc;
}

int posix_dup(int fd)
{
    return dup(fd);
}

int posix_dup2(int oldfd, int newfd)
{
    return dup2(oldfd, newfd);
}

int posix_chdir(const(char)* path)
{
    return chdir(path);
}

char* posix_getcwd(char* buf, size_t size)
{
    return getcwd(buf, size);
}

int posix_unlink(const(char)* path)
{
    return unlink(path);
}

int posix_mkdir(const(char)* path, mode_t mode)
{
    return mkdir(path, mode);
}

int posix_rmdir(const(char)* path)
{
    return rmdir(path);
}

int posix_rename(const(char)* old, const(char)* newp)
{
    return rename(old, newp);
}

int posix_fork()
{
    return fork();
}

int posix_execve(const(char)* path, char** argv, char** envp)
{
    return execve(path, argv, envp);
}

int posix_waitpid(int pid, int* status, int options)
{
    return waitpid(pid, status, options);
}

void posix_exit(int status)
{
    exit(status);
}

int posix_kill(int pid, int sig)
{
    return kill(pid, sig);
}

int posix_stat(const(char)* path, stat_t* buf)
{
    return stat(path, buf);
}

int posix_fstat(int fd, stat_t* buf)
{
    return fstat(fd, buf);
}

int posix_lstat(const(char)* path, stat_t* buf)
{
    return lstat(path, buf);
}

int posix_chmod(const(char)* path, mode_t mode)
{
    return chmod(path, mode);
}

int posix_fchmod(int fd, mode_t mode)
{
    return fchmod(fd, mode);
}

int posix_chown(const(char)* path, int uid, int gid)
{
    return chown(path, uid, gid);
}

int posix_fchown(int fd, int uid, int gid)
{
    return fchown(fd, uid, gid);
}

uint posix_umask(uint mask)
{
    return umask(mask);
}

int posix_getpid()
{
    return getpid();
}

int posix_getppid()
{
    return getppid();
}

int posix_getuid()
{
    return getuid();
}

int posix_geteuid()
{
    return geteuid();
}

int posix_getgid()
{
    return getgid();
}

int posix_getegid()
{
    return getegid();
}

uint posix_sleep(uint seconds)
{
    return sleep(seconds);
}

int posix_usleep(useconds_t usec)
{
    return usleep(usec);
}

void posix__exit(int status)
{
    _exit(status);
}

int posix_isatty(int fd)
{
    return isatty(fd);
}

int posix_access(const(char)* path, int mode)
{
    return access(path, mode);
}

int posix_brk(void* addr)
{
    return brk(addr);
}

void* posix_sbrk(ptrdiff_t increment)
{
    return sbrk(increment);
}

void* posix_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    return mmap(addr, length, prot, flags, fd, offset);
}

int posix_munmap(void* addr, size_t length)
{
    return munmap(addr, length);
}

int posix_mprotect(void* addr, size_t length, int prot)
{
    return mprotect(addr, length, prot);
}

int posix_madvise(void* addr, size_t length, int advice)
{
    return c_posix_madvise(addr, length, advice);
}

int posix_gettimeofday(timeval* tv, void* tz)
{
    return gettimeofday(tv, tz);
}

int posix_clock_gettime(int clk_id, timespec* ts)
{
    return clock_gettime(clk_id, ts);
}

int posix_sigaction(int sig, const(sigaction_t)* act, sigaction_t* oact)
{
    return sigaction(sig, act, oact);
}

sigfn_t posix_signal(int sig, sigfn_t func)
{
    return signal(sig, func);
}

int posix_ioctl(int fd, c_ulong request, ...)
{
    return ioctl(fd, request);
}

long posix_readlink(const(char)* path, char* buf, size_t bufsiz)
{
    return readlink(path, buf, bufsiz);
}

