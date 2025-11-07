module fdisk;

import std.stdio;
import std.file : readText, exists, dirEntries, SpanMode;
import std.string : split, strip, startsWith;
import std.conv : to;

void printUsage()
{
    writeln("Usage: fdisk [-u] device");
    writeln("       fdisk -l [-u] device ...");
    writeln("       fdisk -s partition ...");
    writeln("       fdisk -v");
}

void listDevice(string dev)
{
    string base = dev.startsWith("/dev/") ? dev[5..$] : dev;
    string sys = "/sys/block/" ~ base;
    if(!exists(sys)) {
        writeln("fdisk: cannot open " ~ dev);
        return;
    }
    long sectorSize = to!long(readText(sys ~ "/queue/hw_sector_size").strip);
    long diskSectors = to!long(readText(sys ~ "/size").strip);
    long diskMB = (diskSectors * sectorSize) / 1024 / 1024;
    writeln("Disk " ~ dev ~ ": " ~ to!string(diskMB) ~ " MB");
    foreach(entry; dirEntries(sys, SpanMode.shallow)) {
        auto name = entry.name.split("/")[$-1];
        if(!name.startsWith(base) || name == base) continue;
        auto sizePath = entry.name ~ "/size";
        if(!exists(sizePath)) continue;
        long sz;
        try { sz = to!long(readText(sizePath).strip); } catch(Exception) { continue; }
        long mb = (sz * sectorSize) / 1024 / 1024;
        writeln("  " ~ dev ~ name[base.length .. $] ~ " " ~ to!string(mb) ~ " MB");
    }
}

long partitionSize(string part)
{
    string base = part.startsWith("/dev/") ? part[5..$] : part;
    size_t i = base.length;
    while(i > 0 && base[i-1] >= '0' && base[i-1] <= '9') i--;
    string dev = base[0 .. i];
    string sys = "/sys/block/" ~ dev ~ "/" ~ base ~ "/size";
    if(!exists(sys)) return -1;
    long sectors = to!long(readText(sys).strip);
    long sectorSize = to!long(readText("/sys/block/" ~ dev ~ "/queue/hw_sector_size").strip);
    return (sectors * sectorSize) / 1024; // 1K blocks
}

void fdiskCommand(string[] tokens)
{
    bool optList = false;
    bool optVersion = false;
    bool optSize = false;
    string[] args;
    size_t idx = 1;
    while(idx < tokens.length) {
        auto t = tokens[idx];
        if(t == "-l") optList = true;
        else if(t == "-v") optVersion = true;
        else if(t == "-s") {
            optSize = true;
        } else if(t == "-u") {
            // ignored
        } else if(t.startsWith("-")) {
            writeln("fdisk: unknown option " ~ t);
            return;
        } else {
            args ~= t;
        }
        idx++;
    }

    if(optVersion) {
        writeln("fdisk (shell builtin) 0.1");
        return;
    }

    if(optSize) {
        if(args.length == 0) { writeln("fdisk: option requires a partition"); return; }
        foreach(p; args) {
            auto blocks = partitionSize(p);
            if(blocks < 0) writeln("fdisk: " ~ p ~ ": no such partition");
            else writeln(blocks);
        }
        return;
    }

    if(optList) {
        if(args.length == 0) {
            foreach(entry; dirEntries("/sys/block", SpanMode.shallow))
                args ~= "/dev/" ~ entry.name.split("/")[$-1];
        }
        foreach(dev; args)
            listDevice(dev);
        return;
    }

    if(args.length == 0) {
        printUsage();
        return;
    }

    listDevice(args[0]);
}

