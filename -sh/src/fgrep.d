module fgrep;

import std.stdio;
import std.file : readText;
import std.algorithm : canFind, startsWith;
import std.string : toLower, splitLines;
import std.conv : to;

void fgrepCommand(string[] tokens)
{
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
            else {
                if(!silent) writeln("fgrep: option requires an argument -- e");
                return;
            }
        } else {
            break;
        }
        idx++;
    }

    if(pattern.length == 0 && idx < tokens.length) {
        pattern = tokens[idx];
        idx++;
    }

    if(pattern.length == 0 || idx >= tokens.length) {
        if(!silent) writeln("Usage: fgrep [OPTIONS] pattern file...");
        return;
    }

    auto files = tokens[idx .. $];
    auto pat = ignoreCase ? pattern.toLower : pattern;
    foreach(f; files) {
        size_t count = 0;
        try {
            foreach(line; readText(f).splitLines) {
                auto l = ignoreCase ? line.toLower : line;
                bool matched = l.canFind(pat);
                if(invert) matched = !matched;
                if(matched) {
                    count++;
                    if(!countOnly && !silent && !listOnly) {
                        if(files.length > 1) write(f ~ ":");
                        writeln(line);
                    }
                }
            }
            if(listOnly && count > 0 && !silent)
                writeln(f);
            if(countOnly && !silent)
                if(files.length > 1)
                    writeln(f ~ ":" ~ to!string(count));
                else
                    writeln(to!string(count));
        } catch(Exception) {
            if(!silent) writeln("fgrep: cannot read ", f);
        }
    }
}

