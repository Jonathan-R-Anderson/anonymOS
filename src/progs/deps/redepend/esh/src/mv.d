module mv;

import std.stdio;
import shell.syscalls;
import std.string : toStringz;

void mvCommand(string[] tokens) {
    if (tokens.length < 3) {
        writeln("mv: missing destination file operand after '", tokens[$-1], "'");
        return;
    }

    string srcPath = tokens[1];
    string dstPath = tokens[2];

    long res = sys_rename(srcPath.toStringz, dstPath.toStringz);
    if (res < 0) {
        // If rename fails, try cp + rm
        // But for now just print error
        writeln("mv: cannot rename '", srcPath, "' to '", dstPath, "': error ", -res);
    }
}
