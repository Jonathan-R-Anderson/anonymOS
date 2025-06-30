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

auto stubInt(...) { return -1; }

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