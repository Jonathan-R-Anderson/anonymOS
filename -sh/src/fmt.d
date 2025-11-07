module fmt;

import std.stdio;
import std.string : split, splitLines, strip, join, stripRight;
import std.file : readText;
import std.conv : to;
import std.ascii : isDigit;
import std.algorithm : startsWith, count;

string[] formatParagraph(string para, size_t width)
{
    auto words = para.split();
    string line;
    string[] result;
    foreach(w; words) {
        if(line.length == 0) {
            line = w;
        } else if(line.length + 1 + w.length <= width) {
            line ~= " " ~ w;
        } else {
            result ~= line;
            line = w;
        }
    }
    if(line.length)
          result ~= line;
    return result;
}

void processLines(string[] lines, size_t width, bool splitOnly, bool uniform)
{
    string para;
    foreach(line; lines) {
        auto trimmed = line.strip();
        if(splitOnly) {
            if(trimmed.length == 0) {
                writeln();
            } else {
                auto p = uniform ? trimmed.split().join(" ") : trimmed;
                foreach(l; formatParagraph(p, width))
                    writeln(l);
            }
            continue;
        }
        if(trimmed.length == 0) {
            if(para.length) {
                auto p = uniform ? para.split().join(" ") : para;
                foreach(l; formatParagraph(p, width))
                    writeln(l);
                para = "";
            }
            writeln();
        } else {
            if(para.length)
                para ~= " " ~ trimmed;
            else
                para = trimmed;
        }
    }
    if(para.length) {
        auto p = uniform ? para.split().join(" ") : para;
        foreach(l; formatParagraph(p, width))
            writeln(l);
    }
}

void fmtCommand(string[] tokens)
{
    size_t width = 75;
    bool splitOnly = false;
    bool uniform = false;

    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-s" || t == "--split-only") {
            splitOnly = true;
        } else if(t == "-u" || t == "--uniform-spacing") {
            uniform = true;
        } else if(t.startsWith("-w")) {
            string val = t.length > 2 ? t[2 .. $] : (idx + 1 < tokens.length ? tokens[idx+1] : "");
            if(val.length == 0) {
                writeln("fmt: option requires an argument -- w");
                return;
            }
            width = to!size_t(val);
            if(t.length == 2) idx++;
        } else if(t.startsWith("--width=")) {
            width = to!size_t(t[8 .. $]);
        } else if(t.length > 1 && t[1..$].count!(c => isDigit(c)) == t.length-1) {
            width = to!size_t(t[1 .. $]);
        } else if(t == "--") {
            idx++;
            break;
        } else {
            break;
        }
        idx++;
    }

    auto files = tokens[idx .. $];
    if(files.length == 0) files = ["-"];
    foreach(f; files) {
        string[] lines;
        if(f == "-") {
            string line;
            while((line = readln()) !is null) {
                line = line.stripRight("\n");
                lines ~= line;
            }
        } else {
            try {
                lines = readText(f).splitLines;
            } catch(Exception) {
                writeln("fmt: cannot read ", f);
                continue;
            }
        }
        processLines(lines, width, splitOnly, uniform);
    }
}

