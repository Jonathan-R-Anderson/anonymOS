// link.d — D translation of the C program
module link; // must match filename link.d

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio : writefln, stderr;
import std.string : fromStringz;
import std.conv : to;
import core.stdc.stdlib : EXIT_FAILURE, exit;
import core.stdc.string : strerror;
import core.stdc.errno : errno;
import core.sys.posix.unistd : link; // POSIX link(2)
alias c_link = link; // avoid confusion with module name

void usage(string prog) // no @safe/@nogc/nothrow here
{
    stderr.writefln(
        "Usage:\n" ~
        "  %s file1 file2\n\n" ~
        "Description:\n" ~
        "  Create a new hard link 'file2' to existing 'file1' (link(2)).\n" ~
        "Options:\n" ~
        "  -h, --help   Show this help and exit",
        prog
    );
    exit(1);
    assert(0); // hint to the compiler: doesn't return
}

extern(C) int main(int argc, char** argv)
{
    string[] args;
    args.length = argc;
    foreach (i; 0 .. argc)
        args[i] = (cast(const char*)argv[i]).to!string;

    if (args.length == 2 && (args[1] == "-h" || args[1] == "--help"))
        usage(args[0]);

    if (args.length != 3)
        usage(args[0]);

    const src = args[1];
    const dst = args[2];

    if (c_link(cast(const char*)src.ptr, cast(const char*)dst.ptr) < 0) {
        auto emsg = fromStringz(strerror(errno));
        stderr.writefln("link(%s, %s): %s", src, dst, emsg);
        return EXIT_FAILURE;
    }

    return 0;
}
