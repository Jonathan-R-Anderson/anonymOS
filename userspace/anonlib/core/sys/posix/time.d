module core.sys.posix.time;

extern(C):
struct timespec { long tv_sec; long tv_nsec; }
int clock_gettime(int clk_id, timespec* ts) { if(ts){ ts.tv_sec = 0; ts.tv_nsec = 0;} return 0; } 