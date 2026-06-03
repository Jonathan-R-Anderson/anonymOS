module look;

import std.stdio;
import std.string;
import std.algorithm;
import shell.syscalls;

void lookCommand(string[] tokens) {
    bool ignoreCase = false;
    string prefix;
    string file;
    
    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        if(tokens[idx] == "-f") ignoreCase = true;
        idx++;
    }
    
    if(idx < tokens.length) prefix = tokens[idx++];
    if(idx < tokens.length) file = tokens[idx++];
    
    if(prefix.length == 0) {
        writeln("usage: look [-f] string [file ...]");
        return;
    }
    
    if(file.length == 0) file = "/usr/share/dict/words";
    
    int fd = cast(int)sys_open(file.toStringz, 0);
    if(fd < 0) {
        writeln("look: ", file, ": Cannot open");
        return;
    }
    
    if(ignoreCase) prefix = prefix.toLower();
    
    ubyte[4096] buf;
    long n;
    string leftover;
    
    while((n = sys_read(fd, buf.ptr, 4096)) > 0) {
        string chunk = leftover ~ cast(string)buf[0..n];
        auto lines = chunk.splitLines;
        
        if(n == 4096 && chunk[$-1] != '\n') {
            leftover = lines[$-1];
            lines = lines[0..$-1];
        } else {
            leftover = "";
        }
        
        foreach(line; lines) {
            string cmp = ignoreCase ? line.toLower() : line;
            if(cmp.startsWith(prefix)) {
                writeln(line);
            }
        }
    }
    sys_close(fd);
}
