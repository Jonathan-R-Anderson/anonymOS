/**
 * D port of:
 *   cmp - compare two files
 *
 * Options:
 *   -l, --verbose   Write the byte number (decimal) and the differing bytes (octal) for each difference.
 *   -s, --silent    Write nothing for differing files; return exit status only.
 *
 * Exit status:
 *   0  files are identical
 *   1  files differ (or EOF on one)
 *   2  trouble (usage, open error, etc.)
 */

module cmp_d;

import std.stdio : File, stderr, stdout, writefln, writeln;
import std.getopt : getopt, defaultGetoptPrinter, config;
import std.exception : errnoEnforce;
import std.string : toStringz;
import core.stdc.errno : errno;
import core.stdc.string : strerror;
import std.string : fromStringz;

struct Opts {
    bool verbose = false; // -l
    bool silent  = false; // -s
}

private int fgetc(ref File f)
{
    ubyte[1] b;
    auto n = f.rawRead(b[]).length;
    if (n == 0) return -1; // EOF
    return cast(int)b[0];
}

int main(string[] args)
{
    Opts opt;
    // Parse options
    auto help = getopt(
        args,
        config.bundling, // allow -ls style
        "l|verbose", "Write the byte number and differing bytes (octal) for each difference.", &opt.verbose,
        "s|silent",  "Write nothing; return status only.", &opt.silent
    );
    // Remaining args should be exactly two pathnames
    if (args.length - help.index != 3) {
        stderr.writeln("cmp: two pathnames required for comparison");
        return 2;
    }

    auto file1 = args[help.index + 1];
    auto file2 = args[help.index + 2];

    // Open files (text vs binary does not matter on POSIX; use "rb" for portability)
    File f1, f2;
    try {
        f1 = File(file1, "rb");
    } catch (Exception e) {
        stderr.writeln(file1, ": ", e.msg);
        return 2;
    }
    try {
        f2 = File(file2, "rb");
    } catch (Exception e) {
        stderr.writeln(file2, ": ", e.msg);
        return 2;
    }

    scope(exit) { f1.close(); f2.close(); }

    ulong lines = 1;         // line count (from file1), starts at 1
    ulong bytes = 0;         // byte position (1-based like original)
    bool diff  = false;      // first difference found?

    int rc = 0;

    while (true) {
        auto c1 = fgetc(f1);
        auto c2 = fgetc(f2);

        bytes++;

        if (c1 == '\n') {
            lines++;
        }

        if (c1 == -1 || c2 == -1) {
            if (c1 != c2) {
                // EOF on one file only
                stderr.writefln("cmp: EOF on %s", (c1 == -1) ? file1 : file2);
                rc = 1;
            }
            break;
        } else if (!diff && c1 == c2) {
            continue;
        }

        // Difference handling
        diff = true;

        if (opt.silent) { // -s: no output, just status
            rc = 1;
            break;
        }

        if (!opt.verbose) { // default (not -l): print one line and stop
            stdout.writefln("%s %s differ: char %s, line %s",
                            file1, file2, bytes, lines);
            rc = 1;
            break;
        }

        // -l: print byte (decimal) and differing bytes (octal), continue
        // D's %o prints octal; ensure values are in 0..255
        stdout.writefln("%s %o %o", bytes, c1 & 0xFF, c2 & 0xFF);
    }

    return rc;
}
