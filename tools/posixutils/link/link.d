// link.d — D translation of the provided C program
module link_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio : writeln, writefln, stderr;
import std.string : format;
import std.conv : to;
import core.stdc.stdlib : EXIT_FAILURE;
import core.stdc.string : strerror;
import core.stdc.errno : errno;
import core.sys.posix.unistd : link;

noreturn void usage(string prog)
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
    import core.stdc.stdlib : exit;
    exit(1);
}

extern(C) int main(int argc, char** argv)
{
    // Collect argv as D strings
    string[] args;
    args.length = argc;
    foreach (i; 0 .. argc) args[i] = argv[i].to!string;

    if (args.length == 2 && (args[1] == "-h" || args[1] == "--help"))
        usage(args[0]);

    if (args.length != 3) // prog + file1 + file2
        usage(args[0]);

    auto src = args[1];
    auto dst = args[2];

    // Call POSIX link(2)
    if (link(src.ptr, dst.ptr) < 0) {
        // Match the C program’s error style
        stderr.writefln("link(%s, %s): %s", src, dst, strerror(errno));
        return 1;
    }

    return 0;
}
