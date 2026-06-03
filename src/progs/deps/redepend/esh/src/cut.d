module cut;

import std.stdio;
import std.string : split, join, indexOf, startsWith, stripRight, toStringz;
import std.conv : to;
import shell.syscalls;

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
            if(dash == 0) {
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
    string fieldSpec;
    bool useBytes = false;
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
        } else if(t.startsWith("-f")) {
            useFields = true;
            if(t.length > 2)
                fieldSpec = t[2 .. $];
            else if(idx + 1 < tokens.length) { fieldSpec = tokens[idx+1]; idx++; }
        } else if(t == "-d") {
            idx++; if(idx < tokens.length) delim = tokens[idx][0];
        } else if(t.startsWith("-d")) {
            delim = t[2];
        } else if(t == "-s") {
            onlyDelim = true;
        }
        idx++;
    }

    if(outDelim.length == 0) outDelim = to!string(delim);
    if(useFields && fieldSpec.length == 0) return;
    
    Range[] ranges;
    if(useBytes)
        ranges = parseRanges(byteSpec);
    else if(useFields)
        ranges = parseRanges(fieldSpec);
    else
        return;

    auto files = tokens[idx .. $];
    if(files.length == 0) files = ["-"];

    auto processLine = (string line) {
        if(useFields)
            return cutFields(line, ranges, delim, onlyDelim, outDelim);
        else
            return cutBytes(line, ranges);
    };

    foreach(f; files) {
        int fd = 0; // stdin
        bool closeFd = false;
        if(f != "-") {
            fd = cast(int)sys_open(f.toStringz, 0);
            if (fd < 0) {
                writeln("cut: cannot read ", f);
                continue;
            }
            closeFd = true;
        }

        ubyte[4096] buffer;
        string leftover;
        long nread;
        
        while ((nread = sys_read(fd, buffer.ptr, buffer.length)) > 0) {
            string chunk = leftover ~ cast(string)buffer[0..nread];
            auto lines = chunk.split("\n");
            
            if (nread == buffer.length && chunk[$-1] != '\n') { // Simplified check logic
                // If last char is not newline, we might have partial line
                // Ideally check EOF. For now, assume split if big buffer.
                // Or just keep last part.
                leftover = lines[$-1];
                lines = lines[0..$-1];
            } else {
                leftover = "";
            }
            
            foreach (line; lines) {
                auto resultLine = processLine(line);
                if(resultLine.length || !onlyDelim)
                    writeln(resultLine);
            }
        }
        
        if (leftover.length) {
            auto resultLine = processLine(leftover);
             if(resultLine.length || !onlyDelim) writeln(resultLine);
        }

        if (closeFd) sys_close(fd);
    }
}
