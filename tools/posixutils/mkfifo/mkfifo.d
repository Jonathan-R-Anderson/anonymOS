// mkfifo.d — D translation of the provided C mkfifo
module mkfifo_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio          : writeln, writefln, stderr;
import std.string         : toStringz;
import std.getopt         : getopt, defaultGetoptPrinter, GetoptResult;
import std.conv           : to;
import core.stdc.stdio    : perror;
import core.sys.posix.sys.stat : mkfifo;
import core.sys.posix.sys.types : mode_t;

noreturn void usage(string prog) {
    stderr.writefln("Usage: %s FILE...", prog);
    import core.stdc.stdlib : exit; exit(1);
}

extern(C) int main(int argc, char** argv) {
    // Collect args
    string[] args; args.length = argc;
    foreach (i; 0 .. argc) args[i] = argv[i].to!string;

    bool showHelp = false;
    GetoptResult res = getopt(
        args,
        "h|help", &showHelp
    );

    if (showHelp) {
        defaultGetoptPrinter("mkfifo - make FIFOs (named pipes)", res.options);
        writeln("\nUsage:\n  ", args[0], " FILE...");
        return 0;
    }

    auto rest = res.args;
    if (rest.length < 2) usage(args[0]);        // need at least one FILE
    auto files = rest[1 .. $];                  // drop program name

    int exitStatus = 0;
    foreach (f; files) {
        // TODO: support -m MODE (chmod-like parser). For now, 0666 like the C code.
        if (mkfifo(f.toStringz, cast(mode_t)0o666) != 0) {
            perror(f.toStringz);
            exitStatus = 1;
        }
    }
    return exitStatus;
}
