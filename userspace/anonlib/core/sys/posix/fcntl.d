module core.sys.posix.fcntl;

extern(C):

enum O_RDONLY = 0;
enum O_WRONLY = 1;
enum O_RDWR   = 2;
enum O_CREAT  = 0x40;
enum O_TRUNC  = 0x200;
enum O_APPEND = 0x400;

int open(const char* path, int flags, int mode=0) { return -1; }

int fcntl(int fd, int cmd, ...) { return -1; } 