module kernel.lib.posix_stubs;

import core.stdc.stddef : size_t;

extern(C):

alias time_t = long; // simple 64-bit Unix epoch seconds

struct tm
{
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
}

// Very naive clock – just counts calls.
static __gshared time_t _fakeClock;

extern(C) time_t time(time_t* now)
{
    ++_fakeClock;
    if(now !is null) *now = _fakeClock;
    return _fakeClock;
}

extern(C) tm* gmtime_r(const time_t* timer, tm* result)
{
    if(result is null) return null;
    // crude conversion: everything zero except h/m/s.
    time_t v = *timer;
    result.tm_sec   = cast(int)(v % 60);
    result.tm_min   = cast(int)((v / 60) % 60);
    result.tm_hour  = cast(int)((v / 3600) % 24);
    result.tm_mday  = 1;
    result.tm_mon   = 0;
    result.tm_year  = 70; // 1970
    result.tm_wday  = 0;
    result.tm_yday  = 0;
    result.tm_isdst = 0;
    return result;
}

// case-insensitive compares --------------------------------------------------
private int _lwr(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

extern(C) int strcasecmp(const char* a, const char* b)
{
    size_t i = 0;
    while(a[i] && b[i])
    {
        int d = _lwr(a[i]) - _lwr(b[i]);
        if(d) return d;
        ++i;
    }
    return _lwr(a[i]) - _lwr(b[i]);
}

extern(C) int strncasecmp(const char* a, const char* b, size_t n)
{
    for(size_t i = 0; i < n; ++i)
    {
        if(!a[i] || !b[i])
            return _lwr(a[i]) - _lwr(b[i]);
        int d = _lwr(a[i]) - _lwr(b[i]);
        if(d) return d;
    }
    return 0;
}

// filesystem dummies ---------------------------------------------------------
extern(C) int mkdir(const char* path, int mode) { return 0; }
extern(C) int rmdir(const char* path)         { return 0; }
extern(C) int unlink(const char* path)        { return 0; }

struct stat
{
    uint  st_mode;
    ulong st_size;
}

pragma(mangle, "stat")  extern(C) int _stat (const char* p, stat* s){ if(s){s.st_mode=0x8000; s.st_size=0;} return 0; }
pragma(mangle, "fstat") extern(C) int _fstat(int fd, stat* s){ if(s){s.st_mode=0x8000; s.st_size=0;} return 0; }
pragma(mangle, "lstat") extern(C) int _lstat(const char* p, stat* s){ return _stat(p,s); } 