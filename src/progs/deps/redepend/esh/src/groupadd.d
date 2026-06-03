module groupadd;

import std.stdio;
import std.string;
import std.conv;
import std.algorithm;
import shell.syscalls;

void groupaddCommand(string[] tokens) {
    if(tokens.length < 2) {
        writeln("Usage: groupadd group");
        return;
    }
    string newGroup = tokens[1];
    
    int fd = cast(int)sys_open("/etc/group", 0); // Read
    string content;
    if(fd >= 0) {
        ubyte[4096] buf;
        long n;
        while((n = sys_read(fd, buf.ptr, 4096)) > 0)
            content ~= cast(string)buf[0..n];
        sys_close(fd);
    }
    
    long maxGid = 999;
    foreach(line; content.splitLines) {
        auto parts = line.split(":");
        if(parts.length >= 3) {
            if(parts[0] == newGroup) {
                writeln("groupadd: group '", newGroup, "' already exists");
                return;
            }
            try {
                long g = to!long(parts[2]);
                if(g > maxGid) maxGid = g;
            } catch(Exception) {}
        }
    }
    
    long newGid = maxGid + 1;
    string entry = newGroup ~ ":x:" ~ to!string(newGid) ~ ":\n";
    
    // Append using O_WRONLY | O_APPEND (0x400) | O_CREAT (0x40)
    int afd = cast(int)sys_open("/etc/group", 1 | 0x400 | 0x40, 420); // O_WRONLY=1, 0644=420
    if(afd < 0) {
        writeln("groupadd: cannot lock /etc/group"); // simplistic
        return;
    }
    // lseek end? O_APPEND handles it.
    sys_write(afd, entry.ptr, entry.length);
    sys_close(afd);
}
