module cal;

import std.stdio;

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

// 0 = Sunday
int dayOfWeek(int year, int month, int day) {
    if(month < 3) {
        month += 12;
        year--;
    }
    int K = year % 100;
    int J = year / 100;
    int h = (day + (13*(month+1))/5 + K + K/4 + J/4 + 5*J) % 7;
    return (h + 6) % 7; // convert to 0=Sunday
}

void printMonth(int month, int year, bool mondayFirst=false) {
    static immutable string[] months = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    ];
    writefln("    %s %d", months[month-1], year);
    auto header = mondayFirst ? "Mo Tu We Th Fr Sa Su" : "Su Mo Tu We Th Fr Sa";
    writeln(header);

    int start = dayOfWeek(year, month, 1);
    if(mondayFirst)
        start = start == 0 ? 6 : start - 1;

    int days = daysInMonth(month, year);
    int w = 0;
    foreach(i; 0 .. start) { write("   "); w++; }
    foreach(d; 1 .. days + 1) {
        writef("%2d ", d);
        w++;
        if(w % 7 == 0)
            writeln();
    }
    if(w % 7 != 0)
        writeln();
}

void printYear(int year, bool mondayFirst=false) {
    foreach(m; 1 .. 13) {
        printMonth(m, year, mondayFirst);
        writeln();
    }
}
