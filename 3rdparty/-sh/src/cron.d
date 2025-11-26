module cron;

import std.stdio;
import std.file : readText, exists;
import std.datetime : Clock, SysTime;
import syswrap : system;
import std.conv : to;
import std.algorithm : splitter;
import std.string : split, indexOf, strip, startsWith, join, splitLines;
import core.thread : Thread;
import core.time : dur;

struct CronJob {
    bool[60] mins;
    bool[24] hours;
    bool[32] dom; // 1-31
    bool[13] months; //1-12
    bool[7] dow; //0-6
    string cmd;
}

CronJob[] jobs;

bool[] parseField(string field, int minVal, int maxVal) {
    bool[] mask;
    mask.length = maxVal + 1;
    foreach(part; splitter(field, ',')) {
        auto p = part.strip;
        if(p == "*") {
            foreach(i; minVal..maxVal+1) mask[i] = true;
            continue;
        }
        int step = 1;
        string range = p;
        auto slash = p.indexOf('/');
        if(slash >= 0) {
            range = p[0..slash];
            step = to!int(p[slash+1..$]);
        }
        int start = minVal;
        int end = maxVal;
        auto dash = range.indexOf('-');
        if(range != "*") {
            if(dash >= 0) {
                start = to!int(range[0..dash]);
                end = to!int(range[dash+1..$]);
            } else {
                start = to!int(range);
                end = start;
            }
        }
        for(int i = start; i <= end; i += step) {
            if(i >= minVal && i <= maxVal) mask[i] = true;
        }
    }
    return mask;
}

void loadCrontab(string path) {
    jobs.length = 0;
    if(!exists(path)) return;
    foreach(line; readText(path).splitLines) {
        auto t = line.strip;
        if(t.length == 0 || t.startsWith("#")) continue;
        auto parts = t.split();
        if(parts.length < 6) continue;
        CronJob job;
        job.mins = parseField(parts[0],0,59).dup[0..60];
        job.hours = parseField(parts[1],0,23).dup[0..24];
        job.dom = parseField(parts[2],1,31).dup[0..32];
        job.months = parseField(parts[3],1,12).dup[0..13];
        job.dow = parseField(parts[4],0,6).dup[0..7];
        job.cmd = parts[5..$].join(" ");
        jobs ~= job;
    }
}

void runCron(string path) {
    loadCrontab(path);
    int lastMin = -1;
    for(;;) {
        auto now = Clock.currTime();
        if(now.minute != lastMin) {
            lastMin = now.minute;
            foreach(job; jobs) {
                if(job.mins[now.minute] &&
                   job.hours[now.hour] &&
                   job.dom[now.day] &&
                   job.months[now.month] &&
                   job.dow[now.dayOfWeek]) {
                   system(job.cmd);
                }
            }
        }
        Thread.sleep(dur!"seconds"(1));
    }
}

void cronCommand(string[] args) {
    string path = "crontab";
    if(args.length > 1) path = args[1];
    runCron(path);
}

