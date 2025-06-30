module core.stdc.time;

public import core.stdc.config : time_t;

extern(C):

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

// Declarations only – the implementations live in kernel.lib.posix_stubs and
// are linked in separately.  Declaring them here satisfies the compiler.

pragma(mangle, "time")      time_t _time(time_t* t);
alias time = _time; // expose under expected name

pragma(mangle, "gmtime_r")  tm* _gmtime_r(const time_t* timer, tm* result);
alias gmtime_r = _gmtime_r; 