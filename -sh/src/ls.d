module ls;

import std.stdio;
import std.file : dirEntries, DirEntry, SpanMode;
import std.algorithm : sort;
import std.string : format, startsWith;
import std.datetime : unixTimeToStdTime, SysTime;
import core.sys.posix.sys.stat : S_IFMT, S_IFDIR, S_IFLNK, S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK,
    S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH;

string permString(uint mode)
{
    char type = '-';
    switch(mode & S_IFMT) {
        case S_IFDIR:  type = 'd'; break;
        case S_IFLNK:  type = 'l'; break;
        case S_IFCHR:  type = 'c'; break;
        case S_IFBLK:  type = 'b'; break;
        case S_IFIFO:  type = 'p'; break;
        case S_IFSOCK: type = 's'; break;
        default: break;
    }
    string result;
    result ~= type;
    uint[9] bits = [S_IRUSR,S_IWUSR,S_IXUSR,S_IRGRP,S_IWGRP,S_IXGRP,S_IROTH,S_IWOTH,S_IXOTH];
    foreach(i,b; bits) {
        if(mode & b) {
            final switch(i%3) {
                  case 0: result ~= 'r'; break;
                  case 1: result ~= 'w'; break;
                  case 2: result ~= 'x'; break;
            }
        } else result ~= '-';
    }
    return result;
}

void lsCommand(string[] tokens)
{
    bool all = false;
    bool longFmt = false;
    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-a" || t == "--all") all = true;
        else if(t == "-l") longFmt = true;
        else if(t == "--") { idx++; break; }
        idx++;
    }
    string path = idx < tokens.length ? tokens[idx] : ".";
    DirEntry[] entries;
    foreach(e; dirEntries(path, SpanMode.shallow)) entries ~= e;
    entries.sort!((a,b) => a.name < b.name);
    foreach(e; entries) {
        auto name = e.name;
        if(!all && name.startsWith(".")) continue;
        if(longFmt) {
            auto st = e.statBuf;
            auto perms = permString(st.st_mode);
            auto size = st.st_size;
            writefln("%s %8d %s", perms, size, name);
        } else {
            writeln(name);
        }
    }
}

