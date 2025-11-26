module cmp;

import std.stdio;
import std.file : read;
import std.conv : to;
import std.array : array;

private string formatChar(ubyte b)
{
    if(b < 32)
        return "^" ~ cast(char)(b + 64);
    else if(b == 127)
        return "^?";
    else if(b > 127) {
        auto code = b - 128;
        string s = "M-";
        if(code < 32)
            s ~= "^" ~ cast(char)(code + 64);
        else if(code == 127)
            s ~= "^?";
        else
            s ~= cast(char)code;
        return s;
    } else if(b >= 32 && b <= 126)
        return to!string(cast(char)b);
    else
        return "^?";
}

ubyte[] readAll(string name)
{
    if(name == "-") {
        ubyte[] data;
        foreach(chunk; stdin.byChunk(4096))
            data ~= cast(ubyte[])chunk;
        return data;
    } else {
        return cast(ubyte[])read(name);
    }
}

bool cmpFiles(string f1, string f2, size_t ignore=0, bool printChars=false, bool listDiffs=false, bool quiet=false)
{
    ubyte[] a, b;
    try { a = readAll(f1); } catch(Exception) { writeln("cmp: cannot read ", f1); return false; }
    try { b = readAll(f2); } catch(Exception) { writeln("cmp: cannot read ", f2); return false; }

    if(ignore) {
        a = ignore < a.length ? a[ignore .. $] : a[$ .. $];
        b = ignore < b.length ? b[ignore .. $] : b[$ .. $];
    }

    size_t minLen = a.length < b.length ? a.length : b.length;
    size_t line = 1;
    bool differ = false;

    for(size_t i = 0; i < minLen; i++) {
        if(a[i] == '\n') line++;
        if(a[i] != b[i]) {
            differ = true;
            if(!quiet) {
                size_t off = i + 1 + ignore;
                if(listDiffs) {
                    writefln("%d %o %o", off, a[i], b[i]);
                } else if(printChars) {
                    auto s1 = formatChar(a[i]);
                    auto s2 = formatChar(b[i]);
                    writefln("%d %s %s", off, s1, s2);
                } else {
                    writeln("cmp: ", f1, " ", f2, " differ: byte ", off, ", line ", line);
                    return false;
                }
            }
        }
    }

    if(a.length != b.length) {
        differ = true;
        if(!quiet && !listDiffs && !printChars) {
            line = 1;
            foreach(idx, bval; a[0 .. minLen]) if(bval == '\n') line++;
            size_t off = minLen + 1 + ignore;
            if(a.length < b.length)
                writeln("cmp: EOF on ", f1, " after byte ", off-1, ", line ", line);
            else
                writeln("cmp: EOF on ", f2, " after byte ", off-1, ", line ", line);
        }
    }

    return !differ;
}

