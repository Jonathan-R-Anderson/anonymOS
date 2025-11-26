module ln;

import std.stdio;
import std.file : remove, exists, isDir;
import core.sys.posix.unistd : link, symlink;
import std.path : baseName, buildPath;
import std.string : startsWith, toStringz;

/// Simplified ln implementation supporting -s, -f and -v.
void lnCommand(string[] tokens)
{
    bool symbolic = false;
    bool force = false;
    bool verbose = false;
    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
            if(t == "-s" || t == "--symbolic") symbolic = true;
            else if(t == "-f" || t == "--force") force = true;
            else if(t == "-v" || t == "--verbose") verbose = true;
            else if(t == "--") { idx++; break; }
            else break;
        idx++;
    }
    auto files = tokens[idx .. $];
    if(files.length < 2) {
        writeln("ln: missing file operand");
        return;
    }
    string dest = files[$-1];
    bool destIsDir = false;
    if(files.length > 2) destIsDir = true;
    else destIsDir = isDir(dest);
        foreach(src; files[0 .. $-1]) {
            string target = destIsDir ? buildPath(dest, baseName(src)) : dest;
            if(force && exists(target)) {
                try remove(target); catch(Exception) {}
            }
            try {
                if(symbolic)
                    symlink(toStringz(src), toStringz(target));
                else
                    link(toStringz(src), toStringz(target));
                if(verbose)
                    writeln(src, " -> ", target);
            } catch(Exception) {
                writeln("ln: failed to link ", src, " to ", target);
            }
        }
}

