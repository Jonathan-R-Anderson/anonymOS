// mkdir.d — D implementation of the provided C mkdir
module mkdir_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio        : writeln, writefln, stderr;
import std.string       : toStringz;
import std.path         : dirName;
import std.getopt       : getopt, defaultGetoptPrinter, GetoptResult;
import std.conv         : to;
import core.stdc.errno  : errno, ENOENT;
import core.stdc.stdio  : perror;

// Disambiguate: function stat -> statFn; struct type is stat_t on Linux druntime
import core.sys.posix.sys.stat : stat_t, mkdir, S_ISDIR, statFn = stat;
import core.sys.posix.sys.types : mode_t;

enum PFX = "mkdir: ";

struct Options { bool parents; }

void usage(string prog) {
    stderr.writefln("Usage: %s [-p|--parents] DIR...", prog);
    import core.stdc.stdlib : exit;
    exit(1);
}

bool isDotOrRoot(string p) {
    return p == "." || p == "/";
}

int ensureParent(Options opt, string path); // forward decl

int makeOne(Options opt, string path) {
    if (isDotOrRoot(path)) return 0;

    auto parent = dirName(path);
    if (parent.length == 0) parent = ".";

    // Ensure parent exists / is a directory
    stat_t st;
    if (statFn(parent.toStringz, &st) != 0) {
        if (!opt.parents || errno != ENOENT) {
            perror(parent.toStringz);
            return 1;
        }
        // Recursively create parent
        auto rc = ensureParent(opt, parent);
        if (rc != 0) return rc;
        // Re-stat after creating parent
        if (statFn(parent.toStringz, &st) != 0) {
            perror(parent.toStringz);
            return 1;
        }
    }
    // Confirm parent is a directory
    if (!S_ISDIR(st.st_mode)) {
        stderr.writefln("%sparent '%s' is not a directory", PFX, parent);
        return 1;
    }

    // Use 0x1FF (== 0777) for wide compiler compatibility.
    if (mkdir(path.toStringz, cast(mode_t)0x1FF) != 0) {
        perror(path.toStringz);
        return 1;
    }
    return 0;
}

// ensureParent mirrors makeOne but is used when we know we're operating on a parent
int ensureParent(Options opt, string path) {
    if (isDotOrRoot(path)) return 0;

    auto parent = dirName(path);
    if (parent.length == 0) parent = ".";

    stat_t st;
    if (statFn(parent.toStringz, &st) != 0) {
        if (!opt.parents || errno != ENOENT) {
            perror(parent.toStringz);
            return 1;
        }
        auto rc = ensureParent(opt, parent);
        if (rc != 0) return rc;
        if (statFn(parent.toStringz, &st) != 0) {
            perror(parent.toStringz);
            return 1;
        }
    }
    if (!S_ISDIR(st.st_mode)) {
        stderr.writefln("%sparent '%s' is not a directory", PFX, parent);
        return 1;
    }

    if (mkdir(path.toStringz, cast(mode_t)0x1FF) != 0) {
        perror(path.toStringz);
        return 1;
    }
    return 0;
}

extern(C) int main(int argc, char** argv) {
    // Collect args
    string[] args; args.length = argc;
    foreach (i; 0 .. argc) args[i] = argv[i].to!string;

    Options opt;
    bool showHelp = false;
    GetoptResult go = getopt(
        args,
        "p|parents", &opt.parents,
        "h|help",    &showHelp
    );
    if (showHelp) {
        defaultGetoptPrinter("mkdir - make directories", go.options);
        writeln("\nUsage:\n  ", args[0], " [-p|--parents] DIR...");
        return 0;
    }

    // After getopt, `args` has been compacted to remaining positional args
    // with the program name still at index 0.
    if (args.length < 2) {
        usage(args[0]); // prints and exits(1)
    }

    // Drop program name
    auto dirs = args[1 .. $];
    int exitStatus = 0;
    foreach (d; dirs)
        exitStatus |= makeOne(opt, d);

    return exitStatus ? 1 : 0;
}
