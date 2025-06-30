module core.sys.posix.dirent;

extern(C):

struct DIR {}
struct dirent { char[256] d_name; }

DIR* opendir(const char* path) { return null; }
dirent* readdir(DIR* d) { return null; }
int closedir(DIR* d) { return 0; } 