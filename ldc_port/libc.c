#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

// Simple syscall wrapper for the Internet Computer OS
long ic_syscall(long number, long a1, long a2, long a3, long a4, long a5) {
    long ret;
    asm volatile ("syscall"
                  : "=a"(ret)
                  : "a"(number), "D"(a1), "S"(a2), "d"(a3), "r10"(a4), "r8"(a5)
                  : "rcx", "r11", "memory");
    return ret;
}

int open(const char *path, int flags, int mode) {
    return ic_syscall(2, (long)path, flags, mode, 0, 0);
}

long read(int fd, void *buf, long count) {
    return ic_syscall(4, fd, (long)buf, count, 0, 0);
}

long write(int fd, const void *buf, long count) {
    return ic_syscall(5, fd, (long)buf, count, 0, 0);
}

int close(int fd) {
    return ic_syscall(7, fd, 0, 0, 0, 0);
}

void _exit(int code) {
    ic_syscall(21, code, 0, 0, 0, 0);
    while (1) {}
}

void *sbrk(ptrdiff_t increment) {
    static char *heap_end;
    if (!heap_end) {
        // assume linker defined end symbol
        extern char _end;
        heap_end = &_end;
    }
    char *prev = heap_end;
    heap_end += increment;
    return prev;
}
