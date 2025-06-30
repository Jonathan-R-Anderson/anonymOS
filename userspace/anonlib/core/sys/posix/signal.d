module core.sys.posix.signal;

extern(C):

alias pid_t = int;

enum SIGKILL = 9;

int kill(pid_t pid, int sig);

struct sigaction_t { void* handler; }
pragma(mangle, "sigaction") int sigaction(int signum, const(sigaction_t)* act, sigaction_t* old){ return -1; } 