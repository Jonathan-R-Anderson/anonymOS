module linkcmd;

import std.stdio;
import std.string : toStringz;
import shell.syscalls;

void linkCommand(string[] tokens) {
    if(tokens.length != 3) {
        writeln("Usage: link FILE1 FILE2");
        return;
    }
    string f1 = tokens[1];
    string f2 = tokens[2];
    
    if(sys_link(f1.toStringz, f2.toStringz) < 0) {
        writeln("link: cannot create link ", f2, " to ", f1);
    }
}
