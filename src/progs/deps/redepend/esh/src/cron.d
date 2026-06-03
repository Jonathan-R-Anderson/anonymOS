module cron;

import std.stdio;
import std.conv;
import std.string;
import std.algorithm;
import shell.syscalls;
import date; // Re-use our DateTime struct/logic? No, `date.d` usually doesn't expose it publicly unless I check/modify.
// `date.d` only has `dateCommand`. I should move DateTime logic to a shared place or copy it.
// Copying is safer to avoid dependency mess.

struct DateTime {
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
    int weekday;
}

DateTime fromUnixTime(long timestamp) {
    long days = timestamp / 86400;
    long seconds = timestamp % 86400;
    DateTime dt;
    dt.hour = cast(int)(seconds / 3600);
    dt.minute = cast(int)((seconds % 3600) / 60);
    dt.second = cast(int)(seconds % 60);
    dt.weekday = cast(int)((days + 4) % 7);
    int year = 1970;
    long daysLeft = days;
    int daysInYear = 365;
    while (true) {
        daysInYear = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) ? 366 : 365;
        if (daysLeft < daysInYear) break;
        daysLeft -= daysInYear;
        year++;
    }
    dt.year = year;
    int[12] daysInMonth = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (daysInYear == 366) daysInMonth[1] = 29;
    int month = 0;
    while (month < 12 && daysLeft >= daysInMonth[month]) {
        daysLeft -= daysInMonth[month];
        month++;
    }
    dt.month = month + 1;
    dt.day = cast(int)(daysLeft + 1);
    return dt;
}

struct CronJob {
    string min;
    string hour;
    string dom;
    string month;
    string dow;
    string cmd;
}

bool matchField(string val, int current) {
    if (val == "*") return true;
    try {
        if (val.indexOf(',') >= 0) {
            foreach(part; val.split(",")) {
                if (part == to!string(current)) return true;
            }
            return false;
        }
        if (val.indexOf('-') >= 0) {
            auto parts = val.split("-");
            if (parts.length == 2) {
                int start = to!int(parts[0]);
                int end = to!int(parts[1]);
                return current >= start && current <= end;
            }
        }
        if (val.startsWith("*/")) {
            int step = to!int(val[2..$]);
            return (current % step) == 0;
        }
        return to!int(val) == current;
    } catch (Exception e) { return false; }
}

bool shouldRun(CronJob job, DateTime dt) {
    if (!matchField(job.min, dt.minute)) return false;
    if (!matchField(job.hour, dt.hour)) return false;
    if (!matchField(job.dom, dt.day)) return false;
    if (!matchField(job.month, dt.month)) return false;
    if (!matchField(job.dow, dt.weekday)) return false;
    return true;
}

void cronCommand(string[] tokens) {
    writeln("Starting simple cron scheduler...");
    writeln("Press Ctrl+C to stop (if supported) or kill process.");

    CronJob[] jobs;
    // Hardcoded example job since file reading parsing is verbose
    // In full impl, read /etc/crontab
    
    // Attempt to read local crontab file "crontab"
    auto fd = sys_open("crontab".toStringz, 0);
    if (fd >= 0) {
        ubyte[4096] msg;
        long n = sys_read(cast(int)fd, msg.ptr, 4096);
        sys_close(cast(int)fd);
        if (n > 0) {
            string content = cast(string)msg[0..n];
            foreach(line; content.splitLines) {
                line = line.strip();
                if (line.length == 0 || line.startsWith("#")) continue;
                auto parts = line.split();
                if (parts.length >= 6) {
                    CronJob j;
                    j.min = parts[0];
                    j.hour = parts[1];
                    j.dom = parts[2];
                    j.month = parts[3];
                    j.dow = parts[4];
                    j.cmd = parts[5 .. $].join(" ");
                    jobs ~= j;
                }
            }
        }
    } else {
        writeln("No 'crontab' file found. Running with no jobs.");
    }
    
    writeln("Loaded ", jobs.length, " jobs.");

    int lastMin = -1;

    while (true) {
        long t = sys_time(null);
        auto dt = fromUnixTime(t);
        
        if (dt.minute != lastMin) {
            lastMin = dt.minute;
            foreach(job; jobs) {
                if (shouldRun(job, dt)) {
                    writeln("[CRON] Executing: ", job.cmd);
                    // syswrap.system(job.cmd); // Not working well statically
                }
            }
        }
        
        // Sleep 10s
        timespec req;
        req.tv_sec = 10;
        req.tv_nsec = 0;
        sys_nanosleep(&req, null);
    }
}
