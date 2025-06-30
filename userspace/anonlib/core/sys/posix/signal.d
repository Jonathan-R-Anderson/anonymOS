module core.sys.posix.signal;

extern(C):

alias pid_t = int;

enum SIGKILL = 9;

int kill(pid_t pid, int sig);

struct sigaction { void* handler; }
alias sigaction_t = sigaction;
int sigaction(int signum, const(sigaction)* act, sigaction* old){ return -1; } 