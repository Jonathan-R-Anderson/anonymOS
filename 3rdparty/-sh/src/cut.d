module cut;

import std.stdio;
import std.string : split, splitLines, join, indexOf, startsWith, stripRight;
import std.file : readText;
import std.conv : to;

struct Range {
    size_t start;
    size_t end;
}

Range[] parseRanges(string spec) {
    Range[] ranges;
    foreach(part; spec.split(",")) {
        if(part.length == 0) continue;
        size_t start = 1;
        size_t end = size_t.max;
        auto dash = part.indexOf('-');
        if(dash >= 0) {
            auto left = part[0 .. dash];
            auto right = part[dash+1 .. $];
            if(dash == 0) { // -M
                if(right.length)
                    end = to!size_t(right);
            } else {
                start = to!size_t(left);
                if(right.length)
                    end = to!size_t(right);
            }
        } else {
            start = to!size_t(part);
            end = start;
        }
        ranges ~= Range(start, end);
    }
    return ranges;
}

bool inRanges(size_t idx, Range[] ranges) {
    foreach(r; ranges) {
        if(idx >= r.start && idx <= r.end)
            return true;
    }
    return false;
}

string cutBytes(string line, Range[] ranges) {
    string result;
    size_t i = 1;
    foreach(ch; line) {
        if(inRanges(i, ranges)) result ~= ch;
        i++;
    }
    return result;
}

string cutFields(string line, Range[] ranges, char delim, bool onlyDelim, string outDelim) {
    if(onlyDelim && line.indexOf(delim) < 0)
        return "";
    auto fields = line.split(delim);
    string[] outFields;
    foreach(i, f; fields) {
        if(inRanges(i+1, ranges)) outFields ~= f;
    }
    return outFields.join(outDelim);
}

void cutCommand(string[] tokens) {
    string byteSpec;
    string charSpec;
    string fieldSpec;
    bool useBytes = false;
    bool useChars = false;
    bool useFields = false;
    char delim = '\t';
    bool onlyDelim = false;
    string outDelim;

    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t.startsWith("-b")) {
            useBytes = true;
            if(t.length > 2)
                byteSpec = t[2 .. $];
            else if(idx + 1 < tokens.length) { byteSpec = tokens[idx+1]; idx++; }
        } else if(t.startsWith("--bytes=")) {
            useBytes = true; byteSpec = t[8 .. $];
        } else if(t.startsWith("-c")) {
            useChars = true;
            if(t.length > 2)
                charSpec = t[2 .. $];
            else if(idx + 1 < tokens.length) { charSpec = tokens[idx+1]; idx++; }
        } else if(t.startsWith("--characters=")) {
            useChars = true; charSpec = t[13 .. $];
        } else if(t.startsWith("-f")) {
            useFields = true;
            if(t.length > 2)
                fieldSpec = t[2 .. $];
            else if(idx + 1 < tokens.length) { fieldSpec = tokens[idx+1]; idx++; }
        } else if(t.startsWith("--fields=")) {
            useFields = true; fieldSpec = t[9 .. $];
        } else if(t == "-d") {
            idx++; if(idx < tokens.length) delim = tokens[idx][0];
        } else if(t.startsWith("-d")) {
            delim = t[2];
        } else if(t.startsWith("--delimiter=")) {
            auto s = t[12 .. $];
            if(s.length) delim = s[0];
        } else if(t == "-s" || t == "--only-delimited") {
            onlyDelim = true;
        } else if(t.startsWith("--output-delimiter=")) {
            outDelim = t[19 .. $];
        } else if(t == "--output-delimiter") {
            idx++; if(idx < tokens.length) outDelim = tokens[idx];
        } else if(t == "-n") {
            // no-op
        } else if(t == "--") {
            idx++; break;
        } else if(t == "--help") {
            writeln("Usage: cut [OPTION]... [FILE]...");
            return;
        } else {
            break;
        }
        idx++;
    }

    if(outDelim.length == 0) outDelim = to!string(delim);
    if(useChars && !useBytes && charSpec.length) byteSpec = charSpec, useBytes=true;
    if(useFields && fieldSpec.length == 0) return; // nothing to select
    Range[] ranges;
    if(useBytes)
        ranges = parseRanges(byteSpec);
    else if(useFields)
        ranges = parseRanges(fieldSpec);
    else
        return; // nothing to do

    auto files = tokens[idx .. $];
    if(files.length == 0) files = ["-"];

    auto processLine = (string line) {
        if(useFields)
            return cutFields(line, ranges, delim, onlyDelim, outDelim);
        else
            return cutBytes(line, ranges);
    };

    foreach(f; files) {
        if(f == "-") {
            string line;
            while((line = readln()) !is null) {
                auto l = line.stripRight("\n");
                auto resultLine = processLine(l);
                if(resultLine.length || !onlyDelim)
                    writeln(resultLine);
            }
        } else {
            try {
                foreach(line; readText(f).splitLines) {
                    auto resultLine = processLine(line);
                    if(resultLine.length || !onlyDelim)
                        writeln(resultLine);
                }
            } catch(Exception) {
                writeln("cut: cannot read ", f);
            }
        }
    }
}

