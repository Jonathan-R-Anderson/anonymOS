module ddrescue;

import std.stdio;
import std.file : exists, readText, append, write;
import std.conv : to;
import std.string : split, startsWith;

size_t parseSize(string s)
{
    size_t mult = 1;
    if(s.length && (s[$-1] == 'K' || s[$-1] == 'k')) {
        mult = 1024;
        s = s[0 .. $-1];
    } else if(s.length && s[$-1] == 'M') {
        mult = 1024UL * 1024UL;
        s = s[0 .. $-1];
    } else if(s.length && s[$-1] == 'G') {
        mult = 1024UL * 1024UL * 1024UL;
        s = s[0 .. $-1];
    }
    return to!size_t(s) * mult;
}

void logEntry(string logFile, string entry)
{
    if(logFile.length)
        append(logFile, entry ~ "\n");
}

void ddrescueCommand(string[] tokens)
{
    size_t block = 512;
    size_t ipos = 0;
    size_t opos = 0;
    size_t maxSize = size_t.max;
    size_t maxErrors = size_t.max;
    int maxRetries = 0;
    string logFile;
    string infile;
    string outfile;
    bool verbose = false;

    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t.startsWith("-b=")) block = parseSize(t[3 .. $]);
        else if(t.startsWith("--block-size=")) block = parseSize(t[13 .. $]);
        else if(t.startsWith("-i=")) ipos = parseSize(t[3 .. $]);
        else if(t.startsWith("--input-position=")) ipos = parseSize(t[17 .. $]);
        else if(t.startsWith("-o=")) opos = parseSize(t[3 .. $]);
        else if(t.startsWith("--output-position=")) opos = parseSize(t[18 .. $]);
        else if(t.startsWith("-s=")) maxSize = parseSize(t[3 .. $]);
        else if(t.startsWith("--max-size=")) maxSize = parseSize(t[11 .. $]);
        else if(t.startsWith("-e=")) maxErrors = to!size_t(t[3 .. $]);
        else if(t.startsWith("--max-errors=")) maxErrors = to!size_t(t[13 .. $]);
        else if(t.startsWith("-r=")) maxRetries = to!int(t[3 .. $]);
        else if(t.startsWith("--max-retries=")) maxRetries = to!int(t[14 .. $]);
        else if(t == "-v" || t == "--verbose") verbose = true;
        else if(t == "-q" || t == "--quiet") verbose = false;
        else break;
        idx++;
    }

    if(idx < tokens.length) { infile = tokens[idx]; idx++; }
    if(idx < tokens.length) { outfile = tokens[idx]; idx++; }
    if(idx < tokens.length) { logFile = tokens[idx]; idx++; }

    if(infile.length == 0 || outfile.length == 0) {
        writeln("Usage: ddrescue [options] infile outfile [logfile]");
        return;
    }

    File fin;
    File fout;
    try { fin = File(infile, "rb"); } catch(Exception) { writeln("ddrescue: cannot read " ~ infile); return; }
    try {
        if(exists(outfile))
            fout = File(outfile, "r+b");
        else
            fout = File(outfile, "w+b");
    } catch(Exception) { writeln("ddrescue: cannot write " ~ outfile); fin.close(); return; }

    fin.seek(cast(long)ipos);
    fout.seek(cast(long)opos);

    ubyte[] buf;
    buf.length = block;

    size_t copied = 0;
    size_t errors = 0;

    while(copied < maxSize) {
        size_t toRead = block;
        if(copied + toRead > maxSize) toRead = maxSize - copied;
        size_t n = 0;
        ubyte[] readData;
        bool readOk = false;
        foreach(i; 0 .. maxRetries + 1) {
            try {
                readData = fin.rawRead(buf[0 .. toRead]);
                n = readData.length;
                readOk = true;
                break;
            } catch(Exception e) {
                if(i == maxRetries) {
                    errors++;
                    logEntry(logFile, "error " ~ to!string(ipos) ~ " " ~ to!string(block));
                    break;
                }
            }
        }
        if(!readOk) {
            if(errors > maxErrors) break;
            ipos += block;
            opos += block;
            fin.seek(cast(long)ipos);
            fout.seek(cast(long)opos);
            copied += block;
            continue;
        }
        if(n == 0) break;
        fout.rawWrite(readData[0 .. n]);
        logEntry(logFile, "ok " ~ to!string(ipos) ~ " " ~ to!string(n));
        ipos += n;
        opos += n;
        copied += n;
        if(n < toRead) break;
    }

    fin.close();
    fout.close();

    if(verbose)
        writeln("ddrescue: copied " ~ to!string(copied) ~ " bytes");
}
