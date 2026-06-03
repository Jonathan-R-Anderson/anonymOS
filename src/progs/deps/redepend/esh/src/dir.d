module dir;

import std.stdio;
import std.string;
import std.algorithm;
import std.conv;
import shell.syscalls;

void dirCommand(string[] tokens) {
    string path = (tokens.length > 1) ? tokens[1] : ".";
    
    int fd = cast(int)sys_open(path.toStringz, 0x10000 | 0);
    if(fd < 0) {
        writeln("dir: cannot access ", path);
        return;
    }
    
    string[] entries;
    ubyte[4096] buf;
    long n;
    while((n = sys_getdents64(fd, buf.ptr, 4096)) > 0) {
        size_t pos = 0;
        while(pos < n) {
            auto d = cast(linux_dirent64*)(buf.ptr + pos);
            string name = to!string(cast(char*)d.d_name.ptr);
            pos += d.d_reclen;
            if (name != "." && name != "..") entries ~= name;
        }
    }
    sys_close(fd);
    
    entries.sort;
    
    // Simple column output
    foreach(e; entries) {
        writef("%-16s ", e);
        // primitive wrapping?
    }
    if(entries.length > 0) writeln();
}
