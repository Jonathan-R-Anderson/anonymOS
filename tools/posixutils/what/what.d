// what.d — D translation of the provided C source
//
// Usage:
//   what [-s|--short] [FILE...]
// If no FILEs are given, reads from stdin.
//
// Behavior:
//   - Finds "@(#)" tokens and prints the subsequent text up to a terminator:
//       one of: '"', '>', '\n', '\\', or end-of-string.
//   - For each match, prints:
//       <filename>:
//         <extracted text>
//   - With -s/--short, quits after the first match per file.

import std.stdio : File, stdin, stdout, stderr, write, writefln, writeln;
import std.getopt : getopt;
import std.string : indexOf, stripRight;
import std.file : exists, isFile;
import std.algorithm : min;

enum LINE_MAX = 4096; // used only to mirror spirit; D can read arbitrarily
enum PFX = "what: ";
enum SCCS = "@(#)";

struct Options {
    bool shortMode = false;   // -s / --short
    string[] files;           // empty => stdin
}

@safe pure nothrow @nogc
bool isTerminator(char ch) {
    // Matches C's is_terminator list
    return ch == '"' || ch == '>' || ch == '\n' || ch == '\\' || ch == '\0';
}

void scanLineAndPrint(string filename, ref string line, bool shortMode, ref bool stopThisFile)
{
    size_t pos = 0;
    while (true) {
        auto at = line.indexOf(SCCS, pos);
        if (at < 0) return; // no more in this line

        // start just after "@(#)"
        size_t start = cast(size_t)at + SCCS.length;
        size_t i = start;

        // advance until a terminator
        while (i < line.length && !isTerminator(line[i])) {
            ++i;
        }

        auto payload = line[start .. i];

        // Print result
        // <filename>:\n\t<payload>\n
        writefln("%s:", filename);
        writefln("\t%s", payload);

        if (shortMode) { stopThisFile = true; return; }

        // continue searching after what we consumed
        pos = i < line.length ? i + 1 : i;
    }
}

int processOne(string name, File f, bool shortMode)
{
    // setlinebuf equivalent isn't needed; std.stdio buffers reasonably.
    bool stopThisFile = false;

    // Keep newline because original code’s fgets retained it; our
    // terminator test treats '\n' as a hard stop anyway.
    foreach (line; f.byLine(KeepTerminator.yes)) {
        auto s = line.idup; // own a copy as string
        scanLineAndPrint(name, s, shortMode, stopThisFile);
        if (stopThisFile) break;
    }

    if (f.error) {
        stderr.writefln("%s%s: read error", PFX, name);
        return 1;
    }
    return 0;
}

Options parseArgs(string[] args)
{
    Options opt;
    getopt(args,
        "s|short", &opt.shortMode,
    );
    if (args.length > 1)
        opt.files = args[1 .. $];
    return opt;
}

int main(string[] args)
{
    auto opt = parseArgs(args);

    // If no files, read stdin once.
    if (opt.files.length == 0) {
        auto f = stdin;
        return processOne("(standard input)", f, opt.shortMode);
    }

    int rc = 0;
    foreach (path; opt.files) {
        File f;
        if (!f.open(path, "r")) {
            stderr.writefln("%s%s: cannot open", PFX, path);
            rc = 1;
            continue;
        }
        scope(exit) f.close();

        if (processOne(path, f, opt.shortMode) != 0) {
            rc = 1;
        }
    }

    return rc;
}
