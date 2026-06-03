module cp;

import std.stdio;
import shell.syscalls;
import std.string : toStringz;

void cpCommand(string[] tokens) {
    if (tokens.length < 3) {
        writeln("cp: missing destination file operand after '", tokens[$-1], "'");
        return;
    }

    string srcPath = tokens[1];
    string dstPath = tokens[2];

    auto fdSrc = sys_open(srcPath.toStringz, 0 /* O_RDONLY */);
    if (fdSrc < 0) {
        writeln("cp: cannot open '", srcPath, "': error ", -fdSrc);
        return;
    }

    // O_WRONLY | O_CREAT | O_TRUNC = 1 | 64 | 512 = 577
    auto fdDst = sys_open(dstPath.toStringz, 577, 420);
    if (fdDst < 0) {
        writeln("cp: cannot create '", dstPath, "': error ", -fdDst);
        sys_close(cast(int)fdSrc);
        return;
    }

    ubyte[8192] buffer;
    long nread;
    while ((nread = sys_read(cast(int)fdSrc, buffer.ptr, buffer.length)) > 0) {
        sys_write(cast(int)fdDst, buffer.ptr, nread);
    }

    sys_close(cast(int)fdSrc);
    sys_close(cast(int)fdDst);
}
