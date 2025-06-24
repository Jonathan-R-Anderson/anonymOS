module kernel.lib.stdc.stdio;

// Basic stdio implementation for -betterC builds.
// This file provides a very small subset of C stdio backed by the host
// operating system.  It is intentionally tiny but functional so the
// kernel can persist its in-memory filesystem to ``fs.img``.

import kernel.lib.stdc.stdint;    // for size_t
import kernel.lib.stdc.stdlib : malloc, free;

extern(C):

struct FILE
{
    int fd;          // underlying file descriptor
}

// ---------------------------------------------------------------------
//  Linux syscall wrappers
// ---------------------------------------------------------------------
version(linux)
{
    private enum SYS_READ  = 0;
    private enum SYS_WRITE = 1;
    private enum SYS_OPEN  = 2;
    private enum SYS_CLOSE = 3;
    private enum SYS_LSEEK = 8;

    private enum O_RDONLY = 0;
    private enum O_WRONLY = 1;
    private enum O_RDWR   = 2;
    private enum O_CREAT  = 0x40;
    private enum O_TRUNC  = 0x200;
    private enum O_APPEND = 0x400;

    private long linux_syscall(long num, long a1 = 0, long a2 = 0, long a3 = 0,
                               long a4 = 0, long a5 = 0, long a6 = 0)
    {
        long ret;
        asm
        {
            mov RAX, num;
            mov RDI, a1;
            mov RSI, a2;
            mov RDX, a3;
            mov R10, a4;
            mov R8,  a5;
            mov R9,  a6;
            syscall;
            mov ret, RAX;
        }
        return ret;
    }
}

// ---------------------------------------------------------------------
//  Plan 9 wrappers (using libc calls when available)
// ---------------------------------------------------------------------
version(Plan9)
{
    enum OREAD  = 0;
    enum OWRITE = 1;
    enum ORDWR  = 2;
    enum OTRUNC = 16;
    extern(C) int   open(const char*, int);
    extern(C) int   create(const char*, int, int);
    extern(C) long  seek(int, long, int);
    extern(C) long  read(int, void*, long);
    extern(C) long  write(int, const void*, long);
    extern(C) int   close(int);
}

// ---------------------------------------------------------------------
//  fopen
// ---------------------------------------------------------------------
FILE* fopen(const(char)* path, const(char)* mode)
{
    if(path is null || mode is null) return null;
    int flags = 0;
    bool createFile = false;

    // Parse access mode similar to standard C behaviour
    final switch(mode[0])
    {
        case 'r':
            version(linux)  flags = O_RDONLY;
            version(Plan9)  flags = OREAD;
            break;
        case 'w':
            version(linux)
            {
                flags = O_WRONLY | O_CREAT | O_TRUNC;
                createFile = true;
            }
            version(Plan9)
            {
                flags = OWRITE | OTRUNC;
                createFile = true;
            }
            break;
        case 'a':
            version(linux)
            {
                flags = O_WRONLY | O_CREAT | O_APPEND;
                createFile = true;
            }
            version(Plan9)
            {
                flags = OWRITE;
                createFile = true;
            }
            break;
        default:
            return null;
    }

    // handle '+' modifier for read/write
    if(mode[1] == '+')
    {
        version(linux)
            flags = (flags & ~3) | O_RDWR;
        version(Plan9)
            flags = ORDWR;
    }

    int fd;
    version(linux)
    {
        fd = cast(int)linux_syscall(SYS_OPEN, cast(long)path, flags, 0o666);
    }
    version(Plan9)
    {
        if(createFile)
            fd = create(path, flags, 0o666);
        else
            fd = open(path, flags);
    }

    if(fd < 0)
        return null;

    auto f = cast(FILE*)malloc(FILE.sizeof);
    if(f is null)
    {
        version(linux)  linux_syscall(SYS_CLOSE, fd);
        version(Plan9)  close(fd);
        return null;
    }
    f.fd = fd;
    return f;
}

// ---------------------------------------------------------------------
//  fclose
// ---------------------------------------------------------------------
int fclose(FILE* f)
{
    if(f is null) return 0;
    version(linux)  linux_syscall(SYS_CLOSE, f.fd);
    version(Plan9)  close(f.fd);
    free(f);
    return 0;
}

// ---------------------------------------------------------------------
//  fread and fwrite
// ---------------------------------------------------------------------
size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    if(stream is null || ptr is null || size == 0 || nmemb == 0) return 0;
    auto total = size * nmemb;
    long res;
    version(linux)  res = linux_syscall(SYS_READ, stream.fd, cast(long)ptr, total);
    version(Plan9)  res = read(stream.fd, ptr, cast(int)total);
    if(res <= 0) return 0;
    return cast(size_t)res / size;
}

size_t fwrite(const(void)* ptr, size_t size, size_t nmemb, FILE* stream)
{
    if(stream is null || ptr is null || size == 0 || nmemb == 0) return 0;
    auto total = size * nmemb;
    long res;
    version(linux)  res = linux_syscall(SYS_WRITE, stream.fd, cast(long)ptr, total);
    version(Plan9)  res = write(stream.fd, ptr, cast(int)total);
    if(res <= 0) return 0;
    return cast(size_t)res / size;
}

// ---------------------------------------------------------------------
//  fgets
// ---------------------------------------------------------------------
char* fgets(char* s, int size, FILE* stream)
{
    if(stream is null || s is null || size <= 1) return null;
    int i = 0;
    while(i < size - 1)
    {
        ubyte c;
        long r;
        version(linux)  r = linux_syscall(SYS_READ, stream.fd, cast(long)&c, 1);
        version(Plan9)  r = read(stream.fd, &c, 1);
        if(r <= 0) break;
        s[i++] = cast(char)c;
        if(c == '\n') break;
    }
    if(i == 0) return null;
    s[i] = 0;
    return s;
}
