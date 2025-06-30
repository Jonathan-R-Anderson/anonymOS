module core.sys.posix.sys.stat;

extern(C):
alias mode_t = uint;
alias off_t = long;

struct stat { uint st_mode; ulong st_size; }

enum S_IFDIR = 0x4000;
enum S_IFREG = 0x8000;

// Provide public aliases with expected names
alias lstat = _lstat;
alias fstat = _fstat;

enum S_IFMT  = 0xF000; // mask
enum S_IFLNK = 0xA000;
enum S_IFCHR = 0x2000;
enum S_IFBLK = 0x6000;
enum S_IFIFO = 0x1000;
enum S_IFSOCK = 0xC000;

enum S_IRUSR = 0x100;
enum S_IWUSR = 0x80;
enum S_IXUSR = 0x40;
enum S_IRGRP = 0x20;
enum S_IWGRP = 0x10;

pragma(mangle, "stat")  int _stat(const char* path, stat* buf) { return -1; }
pragma(mangle, "lstat") int _lstat(const char* path, stat* buf) { return -1; }
pragma(mangle, "fstat") int _fstat(int fd, stat* buf) { return -1; }

int mkdir(const char* path, mode_t mode) { return 0; }
int rmdir(const char* path) { return 0; } 