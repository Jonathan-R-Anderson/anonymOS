module cal;

import std.stdio;
import std.conv;
import std.string;
import shell.syscalls; // for sys_time

bool isLeapYear(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

int daysInMonth(int month, int year) {
    immutable int[12] days = [31,28,31,30,31,30,31,31,30,31,30,31];
    int d = days[month - 1];
    if(month == 2 && isLeapYear(year))
        d = 29;
    return d;
}

// 0=Sun, 1=Mon...
int dayOfWeek(int year, int month, int day) {
    if(month < 3) {
        month += 12;
        year--;
    }
    int K = year % 100;
    int J = year / 100;
    int h = (day + (13*(month+1))/5 + K + K/4 + J/4 + 5*J) % 7;
    return (h + 6) % 7; 
}

string getMonthName(int m) {
    static immutable string[] months = [
        "", "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    ];
    if (m < 1 || m > 12) return "Invalid";
    return months[m];
}

void printMonth(int month, int year, bool mondayFirst=false) {
    // Basic implementation ignores mondayFirst for layout simplicity in minimal mode
    // but keeps signature for compatibility
    writeln("    ", getMonthName(month), " ", year);
    writeln("Su Mo Tu We Th Fr Sa");
    
    int startDay = dayOfWeek(year, month, 1); // 0=Sun
    // If mondayFirst were true, we'd shift. Ignoring for now.
    
    int days = daysInMonth(month, year);
    
    for(int i=0; i<startDay; i++) write("   ");
    
    for(int d=1; d<=days; d++) {
        writef("%2d ", d);
        if((startDay + d) % 7 == 0) writeln();
    }
    if((startDay + days) % 7 != 0) writeln();
}

void printYear(int year, bool mondayFirst=false) {
    for(int m=1; m<=12; m++) {
        printMonth(m, year, mondayFirst);
        writeln();
    }
}

void calCommand(string[] tokens) {
    int month = 0, year = 0;
    bool monday = false; // parse -m if needed
    
    // Simple parsing
    int idx = 1;
    if (tokens.length > idx && tokens[idx] == "-m") { monday = true; idx++; }
    
    if (tokens.length <= idx) {
        // Current date
        long t = sys_time(null);
        if (t > 0) {
            long dayCount = t / 86400;
            int y = 1970;
            while(true) {
                int diy = isLeapYear(y) ? 366 : 365;
                if (dayCount < diy) break;
                dayCount -= diy;
                y++;
            }
            year = y;
            int m = 1;
            while(true) {
                int dim = daysInMonth(m, year);
                if (dayCount < dim) break;
                dayCount -= dim;
                m++;
            }
            month = m;
        } else {
            month = 1; year = 1970;
        }
    } else if (tokens.length == idx + 1) {
        try {
            year = to!int(tokens[idx]);
            printYear(year, monday);
            return;
        } catch(Exception) { }
    } else {
        try {
            month = to!int(tokens[idx]);
            year = to!int(tokens[idx+1]);
        } catch(Exception) { }
    }
    
    if (month >= 1 && month <= 12) {
        printMonth(month, year, monday);
    }
}
