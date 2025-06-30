module core.sys.posix.dirent;

extern(C):

struct DIR {}
struct dirent { char d_name[256]; }

DIR* opendir(const char* path) { return null; }
struct dirent* readdir(DIR* d) { return null; }
int closedir(DIR* d) { return 0; } 