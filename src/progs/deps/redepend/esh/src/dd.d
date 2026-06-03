module dd;

import std.stdio;
import std.file : exists;
import std.conv : to;
import std.string : split, indexOf, endsWith;

size_t parseBytes(string s)
{
    size_t mult = 1;
    if(s.length >= 2 && (s.endsWith("KB") || s.endsWith("kB"))) {
        mult = 1000;
        s = s[0 .. $-2];
    } else if(s.length >= 2 && s.endsWith("MB")) {
        mult = 1000 * 1000;
        s = s[0 .. $-2];
    } else if(s.length >= 2 && s.endsWith("GB")) {
        mult = 1000UL * 1000UL * 1000UL;
        s = s[0 .. $-2];
    } else if(s.length && (s[$-1] == 'K' || s[$-1] == 'k')) {
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

void ddCommand(string[] tokens)
{
    string infile;
    string outfile;
    size_t bs = 512;
    size_t count = size_t.max;
    size_t skip = 0;
    size_t seek = 0;
    bool notrunc = false;

    foreach(t; tokens[1 .. $]) {
        auto idx = t.indexOf('=');
        if(idx < 0) continue;
        auto key = t[0 .. idx];
        auto val = t[idx+1 .. $];
        switch(key) {
            case "if": infile = val; break;
            case "of": outfile = val; break;
            case "bs":
            case "ibs":
            case "obs":
                bs = parseBytes(val); break;
            case "count": count = to!size_t(val); break;
            case "skip":
            case "iseek":
                skip = to!size_t(val); break;
            case "seek":
            case "oseek":
                seek = to!size_t(val); break;
            case "conv":
                foreach(c; val.split(','))
                    if(c == "notrunc") notrunc = true;
                break;
            default:
                break;
        }
    }

    File fin;
    bool closeIn = true;
    if(infile.length == 0 || infile == "-") {
        fin = stdin;
        closeIn = false;
    } else {
        try { fin = File(infile, "rb"); } catch(Exception) { writeln("dd: cannot read " ~ infile); return; }
    }

    File fout;
    bool closeOut = true;
    if(outfile.length == 0 || outfile == "-") {
        fout = stdout;
        closeOut = false;
    } else {
        try {
            if(notrunc) {
                if(exists(outfile))
                    fout = File(outfile, "r+b");
                else
                    fout = File(outfile, "w+b");
            } else {
                fout = File(outfile, "wb");
            }
        } catch(Exception) { writeln("dd: cannot write " ~ outfile); if(closeIn) fin.close(); return; }
    }

    if(skip > 0) {
        fin.seek(cast(long)(skip * bs));
    }
    if(seek > 0) {
        fout.seek(cast(long)(seek * bs));
    }

    size_t blocks = 0;
    foreach(chunk; fin.byChunk(bs)) {
        if(blocks >= count) break;
        fout.rawWrite(chunk);
        blocks++;
        if(chunk.length < bs) break;
    }

    if(closeIn) fin.close();
    if(closeOut) fout.close();
}

