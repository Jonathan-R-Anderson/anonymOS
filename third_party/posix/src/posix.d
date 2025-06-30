module posix;

pragma(LDC_no_moduleinfo);

extern(C) @nogc nothrow:

import core.sys.posix.unistd : read, write, close, lseek = lseek64, fork, execve, pipe, chdir, getcwd, dup, dup2, unlink, rmdir, getpid, getppid, getuid, geteuid, getgid, getegid, chown, fchown, sleep, usleep;
import core.sys.posix.sys.types : useconds_t;
import core.sys.posix.stdio : rename;
import core.sys.posix.signal : kill;
import core.sys.posix.sys.wait : waitpid;
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

