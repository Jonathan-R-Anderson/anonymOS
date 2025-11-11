// unlink.d — D translation of the provided C source
//
// Usage: unlink FILE
//
// Returns 0 on success, non-zero on error.

import std.stdio  : stderr, writefln;
import std.string : toStringz; // not using fromStringz to avoid const→immutable hiccup
import core.sys.posix.unistd : unlink;
import core.stdc.errno  : errno;
import core.stdc.string : strerror, strlen;

private void usage(string prog)
{
    stderr.writefln("Usage: %s file", prog);
}

int main(string[] args)
{
    const prog = args.length ? args[0] : "unlink";

    // Expect exactly one argument: FILE
    if (args.length != 2) {
        usage(prog);
        return 1;
    }

    const path = args[1];

    // Call POSIX unlink(2)
    if (unlink(path.toStringz) < 0) {
        // Emulate perror(path)
        const(char)* cmsg = strerror(errno);

        string errStr;
        if (cmsg is null) {
            errStr = "unknown error";
        } else {
            // Convert C NUL-terminated string → D string (immutable)
            errStr = (cmsg[0 .. strlen(cmsg)]).idup;
        }

        stderr.writefln("%s: %s", path, errStr);
        return 1;
    }

    return 0;
}
