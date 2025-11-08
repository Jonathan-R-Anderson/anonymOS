// unlink.d — D translation of the provided C source
//
// Usage: unlink FILE
//
// Returns 0 on success, non-zero on error.

import std.stdio : writeln, stderr, writefln;
import std.string : toStringz;
import core.sys.posix.unistd : unlink;
import core.stdc.errno : errno;
import core.stdc.string : strerror;

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

    auto path = args[1];

    // Call POSIX unlink(2)
    if (unlink(path.toStringz) < 0) {
        // Emulate perror(path)
        auto msg = strerror(errno);
        if (msg is null) msg = "unknown error".ptr;
        // msg is a C string; writefln handles %s for char*
        stderr.writefln("%s: %s", path, msg);
        return 1;
    }

    return 0;
}
