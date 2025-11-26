module egrep;

import std.stdio;
import std.file : readText;
import std.regex : regex, matchFirst;
import std.string : toLower, startsWith, splitLines;
import std.conv : to;

void egrepCommand(string[] tokens)
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
                if(!silent) writeln("egrep: option requires an argument -- e");
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
        if(!silent) writeln("Usage: egrep [OPTIONS] pattern file...");
        return;
    }

    auto flags = ignoreCase ? "i" : "";
    auto re = regex(pattern, flags);
    auto files = tokens[idx .. $];
    foreach(f; files) {
        size_t count = 0;
        try {
            foreach(line; readText(f).splitLines) {
                auto m = matchFirst(ignoreCase ? line.toLower : line, re);
                bool matched = !m.empty;
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
            if(!silent) writeln("egrep: cannot read ", f);
        }
    }
}

