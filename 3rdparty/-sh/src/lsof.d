module lsof;

import std.stdio;
import std.file : dirEntries, readLink, readText, SpanMode;
import std.string : strip, startsWith;
import std.algorithm : sort;

bool isNumeric(string s) {
    foreach(ch; s) if(ch < '0' || ch > '9') return false; 
    return s.length > 0;
}

void lsofCommand(string[] tokens)
{
    string pidFilter;
    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t.startsWith("-p")) {
            if(t.length > 2) pidFilter = t[2..$];
            else if(idx + 1 < tokens.length) pidFilter = tokens[++idx];
        } else if(t == "--") { idx++; break; }
        idx++;
    }

    writeln("COMMAND\tPID\tFD\tNAME");
    foreach(procDir; dirEntries("/proc", SpanMode.shallow)) {
        if(!procDir.isDir) continue;
        auto pid = procDir.name;
        if(!isNumeric(pid)) continue;
        if(pidFilter.length && pid != pidFilter) continue;
        string comm;
        try { comm = strip(readText("/proc/"~pid~"/comm")); } catch(Exception) { comm = pid; }
        foreach(fdEntry; dirEntries("/proc/"~pid~"/fd", SpanMode.shallow)) {
            string fd = fdEntry.name;
            string target;
            try { target = readLink("/proc/"~pid~"/fd/"~fd); } catch(Exception) { target = ""; }
            writefln("%s\t%s\t%s\t%s", comm, pid, fd, target);
        }
    }
}

