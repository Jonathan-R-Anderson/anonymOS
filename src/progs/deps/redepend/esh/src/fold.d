module fold;

import std.stdio;
import std.string : splitLines, lastIndexOf, stripRight, toStringz;
import std.conv : to;
import std.algorithm : startsWith;
import std.array : split;
import shell.syscalls;

void foldLine(string line, size_t width, bool breakSpaces) {
    while(line.length > width) {
        size_t cut = width;
        if(breakSpaces) {
            auto segment = line[0 .. width];
            auto sp = segment.lastIndexOf(' ');
            auto tab = segment.lastIndexOf('\t');
            size_t idx = sp;
            if(tab != size_t.max && tab > idx) idx = tab;
            if(idx != size_t.max) cut = idx + 1;
        }
        writeln(line[0 .. cut]);
        line = line[cut .. $];
    }
    writeln(line);
}

void foldCommand(string[] tokens) {
    bool spaces = false;
    size_t width = 80;

    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-s" || t == "--spaces") {
            spaces = true;
        } else if(t.startsWith("-w")) {
            string val = t.length > 2 ? t[2 .. $] : (idx + 1 < tokens.length ? tokens[++idx] : "");
            if(val.length) width = to!size_t(val);
        } else if(t.startsWith("--width=")) {
            width = to!size_t(t[8 .. $]);
        } else if(t == "--") { idx++; break; }
        else { break; }
        idx++;
    }

    auto files = tokens[idx .. $];
    if(files.length == 0) files = ["-"];

    foreach(f; files) {
        if(f == "-") {
            string line;
            while((line = readln()) !is null) {
                line = line.stripRight("\n");
                foldLine(line, width, spaces);
            }
        } else {
            auto fd = sys_open(f.toStringz, 0);
            if (fd < 0) {
                writeln("fold: cannot read ", f);
                continue;
            }
            
            ubyte[4096] buffer;
            string leftover;
            long nread;
            
            while ((nread = sys_read(cast(int)fd, buffer.ptr, buffer.length)) > 0) {
                string chunk = leftover ~ cast(string)buffer[0..nread];
                auto lines = chunk.split("\n");
                
                if (nread == buffer.length) {
                    leftover = lines[$-1];
                    lines = lines[0..$-1];
                } else {
                    leftover = "";
                }
                
                foreach (line; lines) {
                    foldLine(line, width, spaces);
                }
            }
            
            if (leftover.length > 0) {
                foldLine(leftover, width, spaces);
            }
            
            sys_close(cast(int)fd);
        }
    }
}
