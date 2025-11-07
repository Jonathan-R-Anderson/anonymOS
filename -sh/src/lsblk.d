module lsblk;

import std.stdio;
import std.file : dirEntries, readText, exists, SpanMode;
import std.string : strip, startsWith;
import std.algorithm : sort;
import std.conv : to;
import df : humanSize;

void lsblkCommand(string[] tokens)
{
    bool bytes = false;
    bool all = false;
    size_t idx = 1;
      while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-b" || t == "--bytes") bytes = true;
        else if(t == "-a" || t == "--all") all = true;
        else if(t == "--") { idx++; break; }
        idx++;
    }

    string[] devs;
    foreach(entry; dirEntries("/sys/block", SpanMode.shallow))
        devs ~= entry.name;
    devs.sort;

    writeln("NAME\tSIZE");
    foreach(dev; devs) {
        auto sizePath = "/sys/block/"~dev~"/size";
        ulong sectors = 0;
        if(exists(sizePath)) {
            try { sectors = to!ulong(strip(readText(sizePath))); } catch(Exception) {}
        }
        ulong bytesTotal = sectors * 512;
        if(bytesTotal == 0 && !all) continue;
        string size = bytes ? to!string(bytesTotal) : humanSize(bytesTotal, false);
        writefln("%s\t%s", dev, size);
        foreach(part; dirEntries("/sys/block/"~dev, SpanMode.shallow)) {
            if(part.isDir && part.name.startsWith(dev)) {
                auto psizePath = "/sys/block/"~dev~"/"~part.name~"/size";
                ulong psec = 0;
                if(exists(psizePath)) {
                    try { psec = to!ulong(strip(readText(psizePath))); } catch(Exception) {}
                }
                ulong pbytes = psec * 512;
                if(pbytes == 0 && !all) continue;
                string psize = bytes ? to!string(pbytes) : humanSize(pbytes, false);
                writefln("`- %s\t%s", part.name, psize);
            }
        }
    }
}

