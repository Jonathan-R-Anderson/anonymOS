module linkcmd;

import std.stdio;
import std.string : toStringz;
import core.sys.posix.unistd : link;

/// Create a hard link.
void linkCommand(string[] tokens)
{
    if(tokens.length != 3) {
        writeln("Usage: link FILE1 FILE2");
        return;
    }
    auto src = tokens[1];
    auto dest = tokens[2];
    try {
        link(toStringz(src), toStringz(dest));
    } catch(Exception) {
        writeln("link: cannot link ", src, " to ", dest);
    }
}

