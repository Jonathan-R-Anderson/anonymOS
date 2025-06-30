module core.sys.posix.signal;

extern(C):

alias pid_t = int;

enum SIGKILL = 9;

int kill(pid_t pid, int sig); 