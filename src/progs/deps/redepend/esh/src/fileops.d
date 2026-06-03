module fileops;

import std.stdio;
import shell.syscalls;
import std.string : toStringz;

void rmdirCommand(string[] tokens) {
    if (tokens.length < 2) {
        writeln("rmdir: missing operand");
        return;
    }
    foreach (i; 1 .. tokens.length) {
        long res = sys_rmdir(tokens[i].toStringz);
        if (res < 0) writeln("rmdir: failed to remove '", tokens[i], "': error ", -res);
    }
}

void touchCommand(string[] tokens) {
    if (tokens.length < 2) {
        writeln("touch: missing file operand");
        return;
    }
    foreach (i; 1 .. tokens.length) {
        // O_WRONLY | O_CREAT = 1 | 64 = 65
        auto fd = sys_open(tokens[i].toStringz, 65, 420);
        if (fd >= 0) sys_close(cast(int)fd);
        else writeln("touch: cannot touch '", tokens[i], "': error ", -fd);
    }
}

void chmodCommand(string[] tokens) {
    if (tokens.length < 3) return;
    // Simplified: need octal parser for mode
    long res = sys_chmod(tokens[2].toStringz, 0 /* mode */);
}

void unlinkCommand(string[] tokens) {
    if (tokens.length < 2) return;
    sys_unlink(tokens[1].toStringz);
}
