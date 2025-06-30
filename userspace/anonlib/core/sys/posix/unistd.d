module core.sys.posix.unistd;

extern(C):
alias size_t = ulong;
alias ssize_t = long;

int chdir(const char* path);
char* getcwd(char* buf, size_t size);
int symlink(const char* target, const char* linkpath);
long readlink(const char* path, char* buf, size_t bufsiz);
int unlink(const char* path);
int link(const char* existing, const char* newpath);
int getpid();
int rename(const char* oldp, const char* newp);

extern(C):
ssize_t read(int fd, void* buf, size_t n) { return -1; }
ssize_t write(int fd, const(void)* buf, size_t n) { return -1; }
int close(int fd) { return 0; }
long lseek64(int fd, long off, int whence) { return -1; }
int fork() { return -1; }
int execve(const char* path, const char** argv, const char** envp) { return -1; }
int pipe(int[2] fds) { return -1; }
int dup(int fd) { return -1; }
int dup2(int oldfd, int newfd) { return -1; }
int getppid() { return 0; }
int getuid() { return 0; }
int geteuid() { return 0; }
int getgid() { return 0; }
int rmdir(const char* path) { return -1; }
int getegid() { return 0; }
int chown(const char* path, int uid, int gid) { return -1; }
int fchown(int fd, int uid, int gid) { return -1; }
ssize_t sleep(unsigned int seconds) { return 0; }
int usleep(useconds_t u) { return 0; }
int access(const char* path, int mode) { return -1; }
int isatty(int fd) { return 0; }
void _exit(int status) {}
void* brk(void* addr) { return null; }
void* sbrk(intptr_t inc) { return null; } 