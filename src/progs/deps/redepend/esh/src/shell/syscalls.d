module shell.syscalls;

/**
 * Raw syscall wrappers for AnonymOS
 * These bypass D's standard library and call the kernel directly
 */

// Syscall numbers
enum SYS_READ = 0;
enum SYS_WRITE = 1;
enum SYS_OPEN = 2;
enum SYS_CLOSE = 3;
enum SYS_STAT = 4;
enum SYS_FSTAT = 5;
enum SYS_NANOSLEEP = 35;
enum SYS_TIME = 201;
enum SYS_GETDENTS64 = 217;
enum SYS_CHDIR = 80;
enum SYS_MKDIR = 83;
enum SYS_RMDIR = 84;
enum SYS_UNLINK = 87;
enum SYS_RENAME = 82;
enum SYS_CHMOD = 90;
enum SYS_KILL = 62;
enum SYS_READLINK = 89;
enum SYS_IOCTL = 16;
enum SYS_SOCKET = 41;
enum SYS_GETUID = 102;
enum SYS_GETGID = 104;
enum SYS_LINK = 86;
enum SYS_SYMLINK = 88;
enum SYS_GETCWD = 79;
enum SYS_FORK = 57;
enum SYS_EXIT = 60;
enum SYS_WAIT4 = 61;

// Structures
struct linux_dirent64 {
    ulong d_ino;
    long d_off;
    ushort d_reclen;
    ubyte d_type;
    char[256] d_name;
}

struct stat_t {
    ulong st_dev;
    ulong st_ino;
    ulong st_nlink;
    uint st_mode;
    uint st_uid;
    uint st_gid;
    uint __pad0;
    ulong st_rdev;
    long st_size;
    long st_blksize;
    long st_blocks;
    long st_atime;
    long st_atime_nsec;
    long st_mtime;
    long st_mtime_nsec;
    long st_ctime;
    long st_ctime_nsec;
    long[3] __unused;
}

struct sockaddr {
    ushort sa_family;
    char[14] sa_data;
}

struct ifreq {
    char[16] ifr_name;
    sockaddr ifr_addr;
    // Union not easily representable in D struct without union keyword or careful layout.
    // For getting addr, this layout works (addr is usually the first member of union).
}

struct ifconf {
    int ifc_len;
    long ifc_buf; // Pointer to buffer
}

enum SIOCGIFCONF = 0x8912;
enum SIOCGIFADDR = 0x8915;
enum SIOCGIFFLAGS = 0x8913;
enum SIOCSIFFLAGS = 0x8914;
enum SIOCSIFADDR = 0x8916;
enum SIOCGIFNETMASK = 0x891b;
enum SIOCGIFHWADDR = 0x8927;

long syscall(long number, long arg1 = 0, long arg2 = 0, long arg3 = 0, long arg4 = 0) {
    long ret;
    asm {
        mov RAX, number;
        mov RDI, arg1;
        mov RSI, arg2;
        mov RDX, arg3;
        mov R10, arg4;
        syscall;
        mov ret, RAX;
    }
    return ret;
}

// File operations
long sys_open(const(char)* path, int flags, int mode = 0) {
    return syscall(SYS_OPEN, cast(long)path, flags, mode);
}

long sys_close(int fd) {
    return syscall(SYS_CLOSE, fd);
}

long sys_read(int fd, void* buf, ulong count) {
    return syscall(SYS_READ, fd, cast(long)buf, count);
}

long sys_write(int fd, const(void)* buf, ulong count) {
    return syscall(SYS_WRITE, fd, cast(long)buf, count);
}

long sys_getdents64(int fd, void* dirp, uint count) {
    return syscall(SYS_GETDENTS64, fd, cast(long)dirp, count);
}

long sys_fstat(int fd, stat_t* statbuf) {
    return syscall(SYS_FSTAT, fd, cast(long)statbuf);
}

long sys_stat(const(char)* path, stat_t* statbuf) {
    return syscall(SYS_STAT, cast(long)path, cast(long)statbuf);
}

long sys_chdir(const(char)* path) {
    return syscall(SYS_CHDIR, cast(long)path);
}

long sys_getcwd(char* buf, size_t size) {
    return syscall(SYS_GETCWD, cast(long)buf, size);
}

long sys_mkdir(const(char)* path, int mode) {
    return syscall(SYS_MKDIR, cast(long)path, mode);
}

long sys_rmdir(const(char)* path) {
    return syscall(SYS_RMDIR, cast(long)path);
}

long sys_unlink(const(char)* path) {
    return syscall(SYS_UNLINK, cast(long)path);
}

long sys_rename(const(char)* oldpath, const(char)* newpath) {
    return syscall(SYS_RENAME, cast(long)oldpath, cast(long)newpath);
}

long sys_chmod(const(char)* path, int mode) {
    return syscall(SYS_CHMOD, cast(long)path, mode);
}

long sys_kill(int pid, int sig) {
    return syscall(SYS_KILL, pid, sig);
}

long sys_readlink(const(char)* path, char* buf, size_t bufsiz) {
    return syscall(SYS_READLINK, cast(long)path, cast(long)buf, bufsiz);
}

long sys_symlink(const(char)* target, const(char)* linkpath) {
    return syscall(SYS_SYMLINK, cast(long)target, cast(long)linkpath);
}

long sys_link(const(char)* oldpath, const(char)* newpath) {
    return syscall(SYS_LINK, cast(long)oldpath, cast(long)newpath);
}


long sys_ioctl(int fd, ulong request, long arg) {
    return syscall(SYS_IOCTL, fd, request, arg);
}

long sys_socket(int domain, int type, int protocol) {
    return syscall(SYS_SOCKET, domain, type, protocol);
}

long sys_getuid() {
    return syscall(SYS_GETUID);
}

long sys_getgid() {
    return syscall(SYS_GETGID);
}

long sys_time(long* tloc) {
    return syscall(SYS_TIME, cast(long)tloc);
}

struct timespec {
    long tv_sec;
    long tv_nsec;
}

long sys_nanosleep(timespec* req, timespec* rem) {
    return syscall(SYS_NANOSLEEP, cast(long)req, cast(long)rem);
}

long sys_fork() {
    return syscall(SYS_FORK);
}

// fork() is provided by libc/core.sys.posix.unistd

void sys_exit(int code) {
    syscall(SYS_EXIT, code);
}

long sys_wait4(int pid, int* status, int options, void* rusage = null) {
    return syscall(SYS_WAIT4, pid, cast(long)status, options, cast(long)rusage);
}

// Standard C-style wrappers removed to avoid conflict with core.sys.posix.sys.wait
// libc's waitpid should work if it uses SYS_WAIT4 (61) which we handle.

// --- Userland Security Wrappers ---
// SYS_GETUID/GID already defined above
enum SYS_SETUID = 105;
enum SYS_UNSHARE = 272;

// sys_getuid, sys_getgid defined above

long sys_setuid(int uid) {
    return syscall(SYS_SETUID, uid);
}

long sys_unshare(int flags) {
    return syscall(SYS_UNSHARE, flags);
}

// Helper functions
import std.stdio;
import std.string;

void listDir(string path) {
    import std.conv : to;
    
    // Open directory
    auto fd = sys_open(path.toStringz, 0 /* O_RDONLY */);
    if (fd < 0) {
        std.stdio.writeln("ls: cannot access '", path, "': No such file or directory");
        return;
    }
    
    // Read directory entries
    ubyte[4096] buffer;
    long nread;
    
    while ((nread = sys_getdents64(cast(int)fd, buffer.ptr, buffer.length)) > 0) {
        size_t pos = 0;
        while (pos < nread) {
            auto d = cast(linux_dirent64*)(buffer.ptr + pos);
            
            // Skip . and ..
            string name = to!string(cast(char*)d.d_name.ptr);
            if (name != "." && name != "..") {
                std.stdio.writeln(name);
            }
            
            pos += d.d_reclen;
        }
    }
    
    sys_close(cast(int)fd);
}
