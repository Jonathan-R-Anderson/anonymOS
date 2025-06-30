module core.sys.posix.sys.mman;

extern(C):
void* mmap(void* addr, size_t length, int prot, int flags, int fd, long offset){ return cast(void*)-1; }
int munmap(void* addr, size_t length){ return -1; }
int mprotect(void* addr, size_t len, int prot){ return -1; }
int posix_madvise(void* addr, size_t len, int advice){ return 0; } 