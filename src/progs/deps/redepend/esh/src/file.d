module file;

import std.stdio;
import std.string;
import std.conv;
import shell.syscalls;

void fileCommand(string[] tokens) {
    if(tokens.length < 2) {
        writeln("Usage: file FILE...");
        return;
    }
    
    foreach(fname; tokens[1..$]) {
        stat_t st;
        if(sys_stat(fname.toStringz, &st) < 0) {
            writeln(fname, ": cannot open (No such file or directory)");
            continue;
        }
        
        string type = "data";
        
        // Mode check
        if((st.st_mode & 0xF000) == 0x4000) {
            writeln(fname, ": directory");
            continue;
        } else if((st.st_mode & 0xF000) == 0xA000) { // S_IFLNK
             // stat follows link? sys_stat does.
             // If we want to detect link we need lstat.
             // But file usually repts on target unless -h.
             // We'll stick to target type for now.
        }
        
        // Read header
        int fd = cast(int)sys_open(fname.toStringz, 0);
        if(fd < 0) {
             writeln(fname, ": cannot reading header");
             continue; 
        }
        
        ubyte[512] buf;
        long n = sys_read(fd, buf.ptr, 512);
        sys_close(fd);
        
        if(n > 0) {
            if(n >= 4 && buf[0]==0x7f && buf[1]=='E' && buf[2]=='L' && buf[3]=='F') {
                type = "ELF 64-bit LSB executable"; // Simplified guess
            } else if(n >= 2 && buf[0]=='#' && buf[1]=='!') {
                type = "script text";
            } else {
                // Check if text (isPrintable or whitespace)
                bool text = true;
                foreach(b; buf[0..n]) {
                    if(b == 0 || (b < 32 && b != 9 && b != 10 && b != 13)) {
                        text = false; 
                        break; 
                    }
                }
                if(text) type = "ASCII text";
                else type = "data";
            }
        } else {
            type = "empty";
        }
        
        writeln(fname, ": ", type);
    }
}
