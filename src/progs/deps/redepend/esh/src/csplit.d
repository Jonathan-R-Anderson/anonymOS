module csplit;

import std.stdio;
import std.string;
import std.regex;
import std.conv;
import std.format; 
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

void writeChunk(string fname, string[] lines, size_t start, size_t end, bool quiet) {
    auto fd = sys_open(fname.toStringz, 0x241, 420);
    if (fd < 0) return;
    long total = 0;
    for(size_t i=start; i<end; i++) {
        if (i >= lines.length) break;
        string l = lines[i] ~ "\n";
        sys_write(cast(int)fd, l.ptr, l.length);
        total += l.length;
    }
    sys_close(cast(int)fd);
    if(!quiet) writeln(total);
}

void csplitFile(string fname, string[] pats, string prefix, int digits, bool quiet, bool elide) {
    auto lines = readLines(fname);
    if (lines.length == 0) {
        if(!quiet) writeln("csplit: ", fname, ": Empty or cannot open");
        return;
    }

    int fileIdx = 0;
    size_t currentLine = 0;
    
    foreach (pattern; pats) {
        size_t splitAt = currentLine;
        bool isRegex = pattern.startsWith("/") || pattern.startsWith("%");
        bool isSkip = pattern.startsWith("%"); 
        
        string pStr = pattern;
        if (isRegex) pStr = pattern[1 .. $-1];

        if (!isRegex) {
            try {
                size_t ln = to!size_t(pattern);
                if (ln > 0) splitAt = ln - 1;
                else splitAt = 0;
            } catch(Exception) { }
        } else {
             auto r = regex(pStr);
             bool found = false;
             // csplit regex usually means "up to the line matching". 
             // Logic: search from current line (or next?)
             size_t searchStart = currentLine + (isSkip ? 0 : 0); // usually matches current line?
             // If pattern is /Reg/, copy up to match.
             for(size_t k = searchStart; k < lines.length; k++) {
                 // But don't match immediately if offset... simplified.
                 if (!matchFirst(lines[k], r).empty) {
                     splitAt = k;
                     found = true;
                     break;
                 }
             }
             if (!found) {
                 if (!quiet) writeln("csplit: '", pattern, "': match not found");
                 // Continue? Standard csplit fails. We'll continue with splitAt = end?
                 splitAt = lines.length;
             }
        }
        
        if (splitAt > lines.length) splitAt = lines.length;
        if (splitAt < currentLine) splitAt = currentLine;

        if (!isSkip) {
            if (elide && splitAt == currentLine) {
                 // skip empty
            } else {
                string fmt = "%s%0" ~ to!string(digits) ~ "d"; 
                string outName = format(fmt, prefix, fileIdx++);
                writeChunk(outName, lines, currentLine, splitAt, quiet);
            }
        }
        currentLine = splitAt;
    }
    
    if (currentLine < lines.length || (currentLine == lines.length && !elide)) {
        string fmt = "%s%0" ~ to!string(digits) ~ "d";
        string outName = format(fmt, prefix, fileIdx++);
        writeChunk(outName, lines, currentLine, lines.length, quiet);
    }
}

void csplitCommand(string[] tokens) {
    if (tokens.length < 3) {
        writeln("Usage: csplit FILE PATTERN...");
        return;
    }
    string fname = tokens[1];
    string[] pats = tokens[2..$];
    csplitFile(fname, pats, "xx", 2, false, false);
}
