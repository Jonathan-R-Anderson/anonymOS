module core.sys.posix.unistd;

extern(C):
alias size_t = ulong;

int chdir(const char* path);
char* getcwd(char* buf, size_t size);
int symlink(const char* target, const char* linkpath);
long readlink(const char* path, char* buf, size_t bufsiz);
int unlink(const char* path);
int link(const char* existing, const char* newpath);
int getpid(); 