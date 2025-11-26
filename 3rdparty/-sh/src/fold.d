module fold;

import std.stdio;
import std.file : readText;
import std.string : splitLines, lastIndexOf, stripRight;
import std.conv : to;
import std.algorithm : startsWith;

void foldLine(string line, size_t width, bool breakSpaces)
{
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

void foldCommand(string[] tokens)
{
    bool bytes = false;
    bool spaces = false;
    size_t width = 80;

    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-b" || t == "--bytes") {
            bytes = true; // currently unused
        } else if(t == "-s" || t == "--spaces") {
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
            string data;
            try {
                data = readText(f);
            } catch(Exception) {
                writeln("fold: cannot read ", f);
                continue;
            }
            foreach(line; data.splitLines)
                foldLine(line, width, spaces);
        }
    }
}

