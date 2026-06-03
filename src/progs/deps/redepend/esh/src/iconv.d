module iconv;

import std.stdio;
import std.string;
import shell.syscalls;

void iconvCommand(string[] tokens) {
    // Minimal override: Just copy input to output (assuming UTF-8 or compatible)
    // Ignore -f -t flags
    
    int fdIn = 0;
    string inFile;
    
    foreach(t; tokens[1..$]) {
        if (!t.startsWith("-")) inFile = t;
    }
    
    if (inFile.length > 0) {
        fdIn = cast(int)sys_open(inFile.toStringz, 0);
        if (fdIn < 0) {
            writeln("iconv: cannot open ", inFile);
            return;
        }
    }
    
    ubyte[4096] buf;
    long n;
    while((n = sys_read(fdIn, buf.ptr, 4096)) > 0) {
        sys_write(1, buf.ptr, n);
    }
    
    if (fdIn != 0) sys_close(fdIn);
}
