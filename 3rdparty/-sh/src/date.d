module date;

import std.stdio;
import std.datetime : Clock, SysTime, DateTime;
import std.conv : to;
import std.string : split, startsWith;

SysTime parseDateString(string s) {
    try {
        auto parts = s.split(" ");
        auto date = parts[0].split("-");
        if(date.length < 3) return Clock.currTime();
        int year = to!int(date[0]);
        int month = to!int(date[1]);
        int day = to!int(date[2]);
        int hour = 0, minute = 0, second = 0;
        if(parts.length > 1) {
            auto time = parts[1].split(":");
            hour = to!int(time[0]);
            if(time.length > 1) minute = to!int(time[1]);
            if(time.length > 2) second = to!int(time[2]);
        }
        auto dt = DateTime(year, month, day, hour, minute, second);
        return SysTime(dt);
    } catch(Exception) {
        return Clock.currTime();
    }
}

string two(int n) {
    return n < 10 ? "0" ~ to!string(n) : to!string(n);
}

string four(int n) {
    if(n < 10) return "000" ~ to!string(n);
    if(n < 100) return "00" ~ to!string(n);
    if(n < 1000) return "0" ~ to!string(n);
    return to!string(n);
}

string formatDate(SysTime t, string fmt) {
    string result;
    for(size_t i=0; i<fmt.length; ++i) {
        if(fmt[i] == '%' && i + 1 < fmt.length) {
            auto c = fmt[i+1];
            switch(c) {
                case '%': result ~= "%"; break;
                case 'Y': result ~= four(t.year); break;
                case 'm': result ~= two(t.month); break;
                case 'd': result ~= two(t.day); break;
                case 'H': result ~= two(t.hour); break;
                case 'M': result ~= two(t.minute); break;
                case 'S': result ~= two(t.second); break;
                case 'F': result ~= four(t.year) ~ "-" ~ two(t.month) ~ "-" ~ two(t.day); break;
                case 'T': result ~= two(t.hour) ~ ":" ~ two(t.minute) ~ ":" ~ two(t.second); break;
                default: result ~= "%" ~ c; break;
            }
            i++;
        } else {
            result ~= fmt[i];
        }
    }
    return result;
}

void dateCommand(string[] tokens) {
    SysTime time = Clock.currTime();
    bool utc = false;
    string fmt = "%c";
    size_t idx = 1;
    while(idx < tokens.length) {
        auto t = tokens[idx];
        if(t == "-u" || t == "--utc" || t == "--universal") {
            utc = true;
        } else if(t.startsWith("--date=")) {
            time = parseDateString(t[7 .. $]);
        } else if(t == "-d" && idx + 1 < tokens.length) {
            time = parseDateString(tokens[idx+1]);
            idx++;
        } else if(t.length > 0 && t[0] == '+') {
            fmt = t[1 .. $];
        }
        idx++;
    }
    if(utc) time = time.toUTC();
    if(fmt == "%c")
        writeln(time.toISOExtString());
    else
        writeln(formatDate(time, fmt));
}

