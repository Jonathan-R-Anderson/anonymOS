module rm;

import std.stdio;
import shell.syscalls;
import std.string : toStringz;
import std.algorithm : startsWith;

void rmCommand(string[] tokens) {
    if (tokens.length < 2) {
        writeln("rm: missing operand");
        return;
    }

    bool recursive = false;
    bool force = false;
    size_t start = 1;

    foreach (i; 1 .. tokens.length) {
        if (tokens[i] == "-r" || tokens[i] == "-R") recursive = true;
        else if (tokens[i] == "-f") force = true;
        else if (tokens[i].startsWith("-")) { /* ignore other flags */ }
        else {
            start = i;
            break;
        }
    }

    foreach (i; start .. tokens.length) {
        string path = tokens[i];
        long res;
        if (recursive) {
            res = sys_rmdir(path.toStringz); // Simplified: try rmdir first
            if (res < 0) res = sys_unlink(path.toStringz);
        } else {
            res = sys_unlink(path.toStringz);
        }

        if (res < 0 && !force) {
            writeln("rm: cannot remove '", path, "': error ", -res);
        }
    }
}
