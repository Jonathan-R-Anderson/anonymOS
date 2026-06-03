module lsof;

import std.stdio;
import std.conv;
import std.string : toStringz;
import shell.syscalls;

void lsofCommand(string[] tokens) {
    writeln("COMMAND    PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME");
    
    // Try to read /proc/self/fd directory
    auto fd = sys_open("/proc/self/fd".toStringz, 0);
    if (fd < 0) {
        writeln("lsof: cannot access /proc/self/fd");
        return;
    }
    
    ubyte[4096] buffer;
    long nread;
    
    while ((nread = sys_getdents64(cast(int)fd, buffer.ptr, buffer.length)) > 0) {
        size_t pos = 0;
        while (pos < nread) {
            auto d = cast(linux_dirent64*)(buffer.ptr + pos);
            string name = to!string(cast(char*)d.d_name.ptr);
            
            if (name != "." && name != "..") {
                try {
                    int fdNum = to!int(name);
                    writefln("esh      %5d root  %3d   CHR              0,0      0    0 /dev/pts/0",
                             1, fdNum);
                } catch (Exception e) {
                    // Skip non-numeric entries
                }
            }
            
            pos += d.d_reclen;
        }
    }
    
    sys_close(cast(int)fd);
}
