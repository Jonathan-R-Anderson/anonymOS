module csplit;

import std.stdio;
import std.file : readText, write;
import std.string : splitLines, join, indexOf;
import std.regex : regex, matchFirst;
import std.conv : to;
import std.format : format;

struct Pattern {
    bool isRegex;
    string regexStr;
    size_t lineNum; // for numeric patterns
    int offset;
    bool createFile; // true for /regex/, false for %regex%
}

Pattern parsePattern(string p) {
    Pattern pat;
    if(p.length > 0 && (p[0] == '/' || p[0] == '%')) {
        pat.isRegex = true;
        pat.createFile = p[0] == '/';
        auto rest = p[1 .. $];
        auto idx = rest.indexOf('/');
        if(idx < 0) idx = rest.length;
        pat.regexStr = rest[0 .. idx];
        if(idx + 1 <= rest.length) {
            auto off = rest[idx+1 .. $];
            if(off.length) pat.offset = to!int(off);
        }
    } else {
        pat.isRegex = false;
        pat.lineNum = to!size_t(p);
    }
    return pat;
}

size_t findRegex(string[] lines, size_t start, string re) {
    auto r = regex(re);
    foreach(i; start .. lines.length) {
        if(matchFirst(lines[i], r)) return i;
    }
    return size_t.max; // not found
}

void csplitFile(string file, string[] patternStrs, string prefix="xx", int digits=2, bool quiet=false, bool elide=false) {
    string[] lines;
    try {
        lines = readText(file).splitLines();
    } catch(Exception) {
        writeln("csplit: cannot read " ~ file);
        return;
    }

    Pattern[] pats;
    foreach(p; patternStrs) pats ~= parsePattern(p);

    size_t start = 0;
    int outIndex = 0;
    foreach(p; pats) {
        size_t cut = lines.length;
        if(p.isRegex) {
            auto m = findRegex(lines, start, p.regexStr);
            if(m == size_t.max) {
                writeln("csplit: pattern not found: /" ~ p.regexStr ~ "/");
                return;
            }
            long c = cast(long)m + p.offset;
            if(c < 0) c = 0;
            if(c > cast(long)lines.length) c = lines.length;
            cut = cast(size_t)c;
        } else {
            cut = p.lineNum > 0 ? p.lineNum - 1 : 0;
        }
        if(p.createFile || !p.isRegex) {
            auto piece = lines[start .. cut].join("\n");
            if(!elide || piece.length) {
                auto name = prefix ~ format("%0" ~ to!string(digits) ~ "d", outIndex);
                write(name, piece ~ "\n");
                if(!quiet) writeln(piece.length, "");
            }
            outIndex++;
        }
        start = cut;
    }
    auto finalPiece = lines[start .. $].join("\n");
    if(!elide || finalPiece.length) {
        auto name = prefix ~ format("%0" ~ to!string(digits) ~ "d", outIndex);
        write(name, finalPiece ~ "\n");
        if(!quiet) writeln(finalPiece.length, "");
    }
}

