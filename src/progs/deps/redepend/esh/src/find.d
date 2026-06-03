module find;

import std.stdio;
import std.path : baseName;
import std.algorithm : startsWith, canFind;
import std.conv : to;
import std.string;
import shell.syscalls;

void search(string path, string pattern, bool usePattern, char ftype, int depth, int maxDepth) {
    auto fd = sys_open(path.toStringz, 0);
    if (fd < 0) return;
    
    ubyte[4096] buffer;
    long nread;
    
    while ((nread = sys_getdents64(cast(int)fd, buffer.ptr, buffer.length)) > 0) {
        size_t pos = 0;
        while (pos < nread) {
            auto d = cast(linux_dirent64*)(buffer.ptr + pos);
            string name = to!string(cast(char*)d.d_name.ptr);
            
            if (name == "." || name == "..") {
                pos += d.d_reclen;
                continue;
            }
            
            string fullPath = path ~ "/" ~ name;
            bool match = true;
            
            if (usePattern) {
                match = baseName(fullPath).canFind(pattern.strip("*"));
            }
            
            if (match && ftype) {
                if (ftype == 'f' && d.d_type != 8) match = false;  // DT_REG
                else if (ftype == 'd' && d.d_type != 4) match = false;  // DT_DIR
            }
            
            if (match) writeln(fullPath);
            
            if (d.d_type == 4 && (maxDepth < 0 || depth < maxDepth)) {
                search(fullPath, pattern, usePattern, ftype, depth+1, maxDepth);
            }
            
            pos += d.d_reclen;
        }
    }
    
    sys_close(cast(int)fd);
}

void findCommand(string[] tokens) {
    string start = ".";
    string pattern;
    bool usePattern = false;
    char ftype = '\0';
    int maxDepth = -1;
    
    size_t idx = 1;
    if (idx < tokens.length && !tokens[idx].startsWith("-")) {
        start = tokens[idx];
        idx++;
    }
    
    while (idx < tokens.length) {
        auto t = tokens[idx];
        if (t == "-name" && idx + 1 < tokens.length) {
            pattern = tokens[idx+1];
            usePattern = true;
            idx += 2;
        } else if (t == "-type" && idx + 1 < tokens.length) {
            ftype = tokens[idx+1][0];
            idx += 2;
        } else if (t == "-maxdepth" && idx + 1 < tokens.length) {
            maxDepth = to!int(tokens[idx+1]);
            idx += 2;
        } else {
            idx++;
        }
    }
    
    search(start, pattern, usePattern, ftype, 0, maxDepth);
}
