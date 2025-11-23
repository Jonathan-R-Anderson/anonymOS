// mkfifo.d — D translation of a simple POSIX mkfifo(1)
module mkfifo_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio                   : writeln, writefln, stderr;
import std.string                  : toStringz;
import std.getopt                  : getopt, defaultGetoptPrinter, GetoptResult;
import std.conv                    : to;
import core.stdc.stdio             : perror;
import core.sys.posix.sys.stat     : mkfifo;
import core.sys.posix.sys.types    : mode_t;

void usage(string prog)
{
    stderr.writefln("Usage: %s FILE...", prog);
    import core.stdc.stdlib : exit;
    exit(1);
}

extern(C) int main(int argc, char** argv)
{
    // Rebuild a D string[] from C argv
    string[] args;
    args.length = argc;
    foreach (i; 0 .. argc)
        args[i] = argv[i].to!string;

    bool showHelp = false;

    // getopt removes recognized options from `args` in-place.
    GetoptResult res = getopt(
        args,
        "h|help", &showHelp
    );

    if (showHelp)
    {
        defaultGetoptPrinter("mkfifo - make FIFOs (named pipes)", res.options);
        writeln("\nUsage:\n  ", args[0], " FILE...");
        return 0;
    }

    // After getopt, `args` contains the program name at [0] and remaining positionals at [1..$]
    if (args.length <= 1)
        usage(args[0]);

    auto files = args[1 .. $];

    // Mode 0666 (rw-rw-rw-) in decimal
    enum mode_t defaultMode = cast(mode_t)438; // 0666 octal == 438 decimal

    int exitStatus = 0;
    foreach (f; files)
    {
        if (mkfifo(f.toStringz, defaultMode) != 0)
        {
            perror(f.toStringz);
            exitStatus = 1;
        }
    }
    return exitStatus;
}
