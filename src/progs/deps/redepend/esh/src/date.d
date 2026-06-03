module date;

import std.stdio;
import std.conv;
import std.string; // format if possible, otherwise manual
import shell.syscalls;

immutable string[] weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
immutable string[] months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", 
                              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

bool isLeapYear(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

int daysInMonth(int month, int year) {
    immutable int[12] days = [31,28,31,30,31,30,31,31,30,31,30,31];
    int d = days[month - 1];
    if(month == 2 && isLeapYear(year)) d = 29;
    return d;
}

void dateCommand(string[] tokens) {
    long t = sys_time(null);
    if(t < 0) {
        writeln("date: error getting time");
        return;
    }
    
    // Convert t (seconds since 1970) to date
    long days = t / 86400;
    long seconds = t % 86400;
    if(seconds < 0) {
        seconds += 86400;
        days--;
    }
    
    int hour = cast(int)(seconds / 3600);
    int minute = cast(int)((seconds % 3600) / 60);
    int second = cast(int)(seconds % 60);
    int wday = cast(int)((days + 4) % 7); // 1970-01-01 was Thursday (4)
    if(wday < 0) wday += 7;
    
    int year = 1970;
    while(true) {
        int diy = isLeapYear(year) ? 366 : 365;
        if(days < diy) break;
        days -= diy;
        year++;
    }
    
    int month = 1;
    while(true) {
        int dim = daysInMonth(month, year);
        if(days < dim) break;
        days -= dim;
        month++;
    }
    int day = cast(int)days + 1;
    
    // Format: Thu Jan 1 00:00:00 UTC 1970
    writef("%s %s %d %02d:%02d:%02d UTC %d\n", 
           weekdays[wday], months[month-1], day, hour, minute, second, year);
}
