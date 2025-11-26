module du;

import std.stdio;
import std.file : dirEntries, DirEntry, SpanMode;
import std.conv : to;
import std.path : buildNormalizedPath;
import std.format : format;
import std.string : startsWith;

struct Options {
    bool human;
    bool si;
    bool all;
    bool summarize;
    bool showTotal;
    long maxDepth;
    ulong blockSize;
}

string humanSize(ulong bytes, bool si)
{
    ulong base = si ? 1000UL : 1024UL;
    string[] units = ["B","K","M","G","T","P","E"];
    double value = cast(double)bytes;
    int idx = 0;
    while(value >= base && idx < units.length - 1) {
        value /= base;
        idx++;
    }
    return format("%.1f%s", value, units[idx]);
}

void printEntry(ulong bytes, string path, ref Options opts)
{
    string result;
    if(opts.human)
        result = humanSize(bytes, opts.si);
    else
        result = to!string(bytes / opts.blockSize);
    writeln(result, "\t", path);
}

ulong walk(string path, int depth, ref Options opts)
{
    DirEntry de;
    try {
        de = DirEntry(path);
    } catch(Exception) {
        writeln("du: cannot access ", path);
        return 0;
    }
    ulong total = 0;
    if(de.isDir)
    {
        foreach(entry; dirEntries(path, SpanMode.shallow))
        {
            total += walk(entry.name, depth + 1, opts);
        }
        total += de.size;
        if(!opts.summarize && depth <= opts.maxDepth && (!de.isDir ? opts.all : true))
            printEntry(total, path, opts);
    }
    else
    {
        total = de.size;
        if(!opts.summarize && opts.all && depth <= opts.maxDepth)
            printEntry(total, path, opts);
    }
    return total;
}

void duCommand(string[] tokens)
{
    Options opts;
    opts.human = false;
    opts.si = false;
    opts.all = false;
    opts.summarize = false;
    opts.showTotal = false;
    opts.maxDepth = long.max; // unlimited
    opts.blockSize = 1024;

    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-h" || t == "--human-readable") { opts.human = true; opts.si = false; }
        else if(t == "-H" || t == "--si") { opts.human = true; opts.si = true; }
        else if(t == "-a" || t == "--all") { opts.all = true; }
        else if(t == "-s" || t == "--summarize") { opts.summarize = true; }
        else if(t == "-c" || t == "--total") { opts.showTotal = true; }
        else if(t.startsWith("--max-depth=")) { opts.maxDepth = to!long(t[12 .. $]); }
        else if(t == "--max-depth" && idx + 1 < tokens.length) { opts.maxDepth = to!long(tokens[++idx]); }
        else if(t == "-b" || t == "--bytes") { opts.blockSize = 1; opts.human = false; }
        else if(t == "-k" || t == "--kilobytes") { opts.blockSize = 1024; opts.human = false; }
        else if(t == "-m" || t == "--megabytes") { opts.blockSize = 1024UL*1024UL; opts.human = false; }
        else if(t == "--") { idx++; break; }
        else { idx++; continue; }
        idx++;
    }

    auto paths = tokens[idx .. $];
    if(paths.length == 0)
        paths = ["."];

    ulong grand = 0;
    foreach(p; paths) {
        auto abs = buildNormalizedPath(p);
        auto sz = walk(abs, 0, opts);
        if(opts.summarize)
            printEntry(sz, p, opts);
        grand += sz;
    }
    if(opts.showTotal && paths.length > 1)
        printEntry(grand, "total", opts);
}

