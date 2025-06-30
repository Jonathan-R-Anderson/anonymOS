module core.sys.posix.sys.time;

extern(C):
struct timeval { long tv_sec; long tv_usec; }
int gettimeofday(timeval* tv, void* tz)
{
    if(tv) { tv.tv_sec = 0; tv.tv_usec = 0; }
    return 0;
} 