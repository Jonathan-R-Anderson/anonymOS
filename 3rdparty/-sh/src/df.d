module df;

import std.stdio;
import std.file : readText;
import std.string : split, toStringz, splitLines, startsWith;
import std.algorithm : canFind;
import std.format : format;
import std.conv : to;
import core.sys.posix.sys.statvfs;

struct Mount {
    string device;
    string dir;
    string type;
}

Mount[] getMounts() {
    Mount[] mounts;
    try {
        auto data = readText("/proc/mounts");
        foreach(line; data.splitLines()) {
            auto parts = line.split();
            if(parts.length >= 3)
                mounts ~= Mount(parts[0], parts[1], parts[2]);
        }
    } catch(Exception) {}
    return mounts;
}

string humanSize(ulong bytes, bool si) {
    ulong base = si ? 1000UL : 1024UL;
    string[] units = ["B","K","M","G","T","P","E"];
    double value = cast(double)bytes;
    int idx = 0;
    while(value >= base && idx < units.length - 1) {
        value /= base;
        idx++;
    }
    return format("%.1f%s", value, units[idx]);
}

void printEntry(string fs, string dir, string type, bool human, bool si, bool showType, ulong blockSize) {
    statvfs_t buf;
    if(statvfs(dir.toStringz, &buf) != 0) {
        writeln("df: cannot access ", dir);
        return;
    }
    ulong bs = buf.f_frsize ? buf.f_frsize : buf.f_bsize;
    ulong totalBytes = buf.f_blocks * bs;
    ulong availBytes = buf.f_bavail * bs;
    ulong usedBytes = (buf.f_blocks - buf.f_bfree) * bs;
    string stotal, sused, savail;
    if(human) {
        stotal = humanSize(totalBytes, si);
        sused = humanSize(usedBytes, si);
        savail = humanSize(availBytes, si);
    } else {
        auto div = blockSize;
        stotal = to!string(totalBytes / div);
        sused = to!string(usedBytes / div);
        savail = to!string(availBytes / div);
    }
    auto pct = totalBytes == 0 ? 0 : cast(int)((usedBytes * 100) / totalBytes);
    if(showType)
        writefln("%-15s %10s %10s %10s %3s%% %-10s %s", fs, stotal, sused, savail, pct, dir, type);
    else
        writefln("%-15s %10s %10s %10s %3s%% %s", fs, stotal, sused, savail, pct, dir);
}

void dfCommand(string[] tokens) {
    bool human = false;
    bool si = false;
    bool showType = false;
    string[] onlyTypes;
    string[] excludeTypes;
    ulong blockSize = 1024;

    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-h" || t == "--human-readable") human = true, si = false;
        else if(t == "-H" || t == "--si") human = true, si = true;
        else if(t == "-k" || t == "--kilobytes") blockSize = 1024;
        else if(t == "-m" || t == "--megabytes") blockSize = 1024UL*1024UL;
        else if(t == "-T" || t == "--print-type") showType = true;
        else if(t.startsWith("-t")) {
            string v = t.length > 2 ? t[2..$] : (idx+1<tokens.length ? tokens[++idx] : "");
            if(v.length) onlyTypes ~= v;
        } else if(t.startsWith("--type=")) {
            onlyTypes ~= t[7..$];
        } else if(t.startsWith("-x")) {
            string v = t.length > 2 ? t[2..$] : (idx+1<tokens.length ? tokens[++idx] : "");
            if(v.length) excludeTypes ~= v;
        } else if(t.startsWith("--exclude-type=")) {
            excludeTypes ~= t[15..$];
        } else if(t == "--") { idx++; break; }
        else { idx++; continue; }
        idx++;
    }

    auto paths = tokens[idx .. $];
    auto mounts = getMounts();

    writefln("%-15s %10s %10s %10s %s %s", "Filesystem", human?"Size":"1K-blocks", "Used", "Available", "Use%", showType?"Mounted on Type":"Mounted on");

    if(paths.length == 0) {
        foreach(m; mounts) {
            if(onlyTypes.length && !onlyTypes.canFind(m.type)) continue;
            if(excludeTypes.length && excludeTypes.canFind(m.type)) continue;
            printEntry(m.device, m.dir, m.type, human, si, showType, blockSize);
        }
    } else {
        foreach(p; paths) {
            // find mount by path
            string dir = p;
            foreach(m; mounts) if(p.startsWith(m.dir)) dir = m.dir;
            string type = "";
            foreach(m; mounts) if(m.dir == dir) { type = m.type; break; }
            printEntry(dir, dir, type, human, si, showType, blockSize);
        }
    }
}

