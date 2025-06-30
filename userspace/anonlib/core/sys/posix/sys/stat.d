module core.sys.posix.sys.stat;

extern(C):
alias mode_t = uint;
alias off_t = long;

struct stat { uint st_mode; ulong st_size; }

enum S_IFDIR = 0x4000;
enum S_IFREG = 0x8000;

int stat(const char* path, stat* buf) { return -1; }
int lstat(const char* path, stat* buf) { return -1; }
int fstat(int fd, stat* buf) { return -1; }

int mkdir(const char* path, mode_t mode) { return 0; }
int rmdir(const char* path) { return 0; } 