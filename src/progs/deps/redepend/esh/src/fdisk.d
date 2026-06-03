module fdisk;

import std.stdio;
import std.string : splitLines, split, strip, toStringz;
import std.conv : to;
import shell.syscalls;

void listPartitions() {
    auto fd = sys_open("/proc/partitions".toStringz, 0);
    if (fd < 0) {
        writeln("fdisk: cannot open /proc/partitions");
        return;
    }
    ubyte[4096] buf;
    long n;
    string content;
    while ((n = sys_read(cast(int)fd, buf.ptr, 4096)) > 0) content ~= cast(string)buf[0..n];
    sys_close(cast(int)fd);
    
    writeln("Device       Blocks");
    foreach (line; content.splitLines) {
        line = line.strip();
        if (line.length == 0 || line.split().length < 4) continue;
        auto parts = line.split();
        // major minor #blocks name
        if (parts[0] == "major") continue; 
        if (parts.length >= 4) {
            writeln(parts[3], "\t", parts[2]);
        }
    }
}

void fdiskCommand(string[] tokens) {
    bool list = false;
    foreach(t; tokens) if(t == "-l") list = true;
    
    if (list) {
        listPartitions();
    } else {
        writeln("Usage: fdisk -l");
        writeln("       (interactive mode not supported in minimal)");
    }
}
