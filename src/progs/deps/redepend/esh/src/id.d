module id;

import std.stdio;
import shell.syscalls;

void idCommand(string[] tokens) {
    long uid = sys_getuid();
    long gid = sys_getgid();
    
    // In future: resolve names from /etc/passwd if available
    write("uid=", uid);
    write("(sysop) "); // Initial default
    write("gid=", gid);
    write("(sysop) ");
    writeln("");
}
