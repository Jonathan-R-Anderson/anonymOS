// mkdir.d — D implementation of the provided C mkdir
module mkdir_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio           : writeln, writefln, stderr;
import std.string          : toStringz;
import std.path            : dirName;
import std.getopt          : getopt, defaultGetoptPrinter, GetoptResult;
import std.conv            : to;
import core.stdc.errno     : errno, ENOENT;
import core.stdc.stdio     : perror;
import core.sys.posix.sys.stat : stat_t = stat, stat, mkdir, S_ISDIR;
import core.sys.posix.sys.types : mode_t;

enum PFX = "mkdir: ";

struct Options { bool parents; }

noreturn void usage(string prog) {
    stderr.writefln("Usage: %s [-p|--parents] DIR...", prog);
    import core.stdc.stdlib : exit; exit(1);
}

bool isDotOrRoot(string p) {
    return p == "." || p == "/";
}

int ensureParent(Options opt, string path); // fwd

int makeOne(Options opt, string path) {
    if (isDotOrRoot(path)) return 0;

    // Find parent directory component
    auto parent = dirName(path);
    if (parent.length == 0) parent = ".";

    // Ensure parent exists / is a directory
    stat_t st;
    if (stat(parent.toStringz, &st) != 0) {
        if (!opt.parents || errno != ENOENT) {
            perror(parent.toStringz);
            return 1;
        }
        // Recursively create parent
        auto rc = ensureParent(opt, parent);
        if (rc != 0) return rc;
        // Re-stat after creating parent
        if (stat(parent.toStringz, &st) != 0) {
            perror(parent.toStringz);
            return 1;
        }
    }
    // Confirm parent is a directory
    if (!S_ISDIR(st.st_mode)) {
        stderr.writefln("%sparent '%s' is not a directory", PFX, parent);
        return 1;
    }

    // NOTE: Matches your C behavior: even with -p, if the target already
    // exists, we report an error (no special-casing EEXIST).
    if (mkdir(path.toStringz, cast(mode_t)0o777) != 0) {
        perror(path.toStringz);
        return 1;
    }
    return 0;
}

// ensureParent mirrors makeOne but used when we know we are working on a parent
int ensureParent(Options opt, string path) {
    if (isDotOrRoot(path)) return 0;

    auto parent = dirName(path);
    if (parent.length == 0) parent = ".";

    stat_t st;
    if (stat(parent.toStringz, &st) != 0) {
        if (!opt.parents || errno != ENOENT) {
            perror(parent.toStringz);
            return 1;
        }
        auto rc = ensureParent(opt, parent);
        if (rc != 0) return rc;
        if (stat(parent.toStringz, &st) != 0) {
            perror(parent.toStringz);
            return 1;
        }
    }
    if (!S_ISDIR(st.st_mode)) {
        stderr.writefln("%sparent '%s' is not a directory", PFX, parent);
        return 1;
    }

    if (mkdir(path.toStringz, cast(mode_t)0o777) != 0) {
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

    auto rest = go.args;
    if (rest.length < 2) { // program + at least one DIR expected
        if (rest.length == 1) {
            // one DIR provided → ok
        } else usage(args[0]);
    }
    // drop program name
    auto dirs = rest[1 .. $];
    if (dirs.length == 0) usage(args[0]);

    int exitStatus = 0;
    foreach (d; dirs)
        exitStatus |= makeOne(opt, d);

    return exitStatus ? 1 : 0;
}
