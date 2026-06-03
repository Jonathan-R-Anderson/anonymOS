module egrep;

import std.stdio;
import std.regex;
import std.string;
import std.conv;
import shell.syscalls;

string[] readLines(string fname) {
    if (fname == "-") {
        ubyte[4096] buf;
        long n;
        string content;
        while ((n = sys_read(0, buf.ptr, 4096)) > 0) content ~= cast(string)buf[0..n];
        return content.splitLines;
    }
    auto fd = sys_open(fname.toStringz, 0);
    if (fd < 0) return [];
    ubyte[4096] buf;
    long n;
    string content;
    while ((n = sys_read(cast(int)fd, buf.ptr, 4096)) > 0) content ~= cast(string)buf[0..n];
    sys_close(cast(int)fd);
    return content.splitLines;
}

void egrepCommand(string[] tokens) {
    bool countOnly = false;
    bool silent = false;
    bool invert = false;
    bool ignoreCase = false;
    bool listOnly = false;
    string pattern;
    
    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-c") countOnly = true;
        else if(t == "-s") silent = true;
        else if(t == "-v") invert = true;
        else if(t == "-i") ignoreCase = true;
        else if(t == "-l") listOnly = true;
        else if(t == "-e") {
            idx++;
            if(idx < tokens.length) pattern = tokens[idx];
        }
        else if(t == "--") { idx++; break; }
        else if(!t.startsWith("-")) break; // Should not happen with check
        idx++;
    }
    
    if(pattern.length == 0 && idx < tokens.length) {
        pattern = tokens[idx];
        idx++;
    }
    
    if(pattern.length == 0) {
        if(!silent) writeln("Usage: egrep [options] PATTERN [FILE...]");
        return;
    }
    
    Regex!char r;
    try {
        r = regex(pattern, ignoreCase ? "i" : "");
    } catch(Exception e) {
        if(!silent) writeln("egrep: invalid regex: ", e.msg);
        return;
    }
    
    auto files = tokens[idx .. $];
    if(files.length == 0) files = ["-"];
    
    foreach(f; files) {
        auto lines = readLines(f);
        if(lines.length == 0 && f != "-" && !silent) {
            // Check if file exists? readLines returns [] on error too.
             // We'll assume error already handled or silent
        }
        
        long count = 0;
        bool printedFile = false;
        
        foreach(line; lines) {
            auto m = matchFirst(line, r);
            bool match = !m.empty;
            if(invert) match = !match;
            
            if(match) {
                count++;
                if(listOnly) {
                    writeln(f);
                    printedFile = true;
                    break;
                }
                if(!countOnly && !silent) {
                    if(files.length > 1) write(f, ":");
                    writeln(line);
                }
            }
        }
        
        if(countOnly && !listOnly && !silent) {
            if(files.length > 1) write(f, ":");
            writeln(count);
        }
    }
}
