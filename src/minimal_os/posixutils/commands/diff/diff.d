// diff.d — D translation of the provided C++ "diff" skeleton
module diff;

import std.stdio : writeln, writefln, stderr, File, write, readln;
import std.getopt : getopt, defaultGetoptPrinter;
import std.string : toStringz, fromStringz;
import std.conv : to;
import std.exception : enforce;
import std.array : array;
import std.typecons : Nullable;

// C stdio for fopen/fgets/fclose/ferror parity
import core.stdc.stdio : FILE, fopen, fclose, fgets, ferror, perror;
import core.stdc.errno : errno;
import core.stdc.string : strlen;
import core.stdc.stdlib : EXIT_FAILURE; // for EXIT_FAILURE/EXIT_SUCCESS if you use them


// -------------------- Constants & enums --------------------
enum N_DIFFS = 2;
enum HASH_START = 0x6750_2139;
enum LINE_MAX_LEN = 4096;

enum OptModeType {
    MODE_CONTEXT,
    MODE_ED,
    MODE_REVERSE_ED,
}

// -------------------- Options / globals --------------------
__gshared bool optRecurse = false;
__gshared bool optBlanksEquiv = false;
__gshared uint optCtxtLines = 3;
__gshared OptModeType optMode = OptModeType.MODE_CONTEXT;

// -------------------- Utilities --------------------
/* djb2-derived hash: hash * 33 ^ c */
@safe nothrow pure @nogc
ulong blobHash(ulong hash, const(ubyte)[] buf)
{
    foreach (c; buf)
        hash = ((hash << 5) + hash) ^ c;
    return hash;
}

// -------------------- AutoFile --------------------
final class AutoFile
{
    FILE* fp;

    this(string filename)
    {
        // read-only; mimic ro_file_open behavior by trying a simple fopen
        fp = fopen(filename.toStringz, "r");
    }

    ~this()
    {
        if (fp !is null) fclose(fp);
    }

    bool isOpen() const @safe @nogc { return fp !is null; }
    bool haveError() @nogc { return (fp is null) ? true : (ferror(fp) != 0); }
}

// -------------------- Diff structs --------------------
final class DiffLine
{
    string data;
    ulong  hash;

    this(string s)
    {
        data = s;
        hash = blobHash(HASH_START, cast(const(ubyte)[]) data);
    }
}

final class DiffFile
{
    string filename;
    DiffLine[] lines;
    bool[ulong] haveHash; // simple set<ulong>
}

__gshared DiffFile[N_DIFFS] dfiles;

// -------------------- File reading --------------------
int readFile(ref DiffFile dfile) @system
{
    auto af = new AutoFile(dfile.filename);
    if (!af.isOpen())
    {
        perror(dfile.filename.toStringz);
        return 1;
    }

    // fgets buffer (includes trailing newline when present)
    char[LINE_MAX_LEN + 1] buf;

    while (true)
    {
        auto linePtr = fgets(buf.ptr, cast(int)buf.length, af.fp);
        if (linePtr is null) break;

        buf[$-1] = '\0'; // ensure terminator
        // Convert to D string (C string up to '\0')
        auto s = fromStringz(linePtr).idup;

        auto dl = new DiffLine(s);
        dfile.lines ~= dl;
        dfile.haveHash[dl.hash] = true;
    }

    if (af.haveError())
        return 1;

    return 0;
}

// -------------------- Core diff (skeleton like original) --------------------
int doDiff()
{
    foreach (i; 0 .. N_DIFFS)
    {
        if (readFile(dfiles[i]) != 0)
            return 1;
    }

    // TODO: implement actual diff logic (context/ed/reverse-ed, recursive, blanks-equivalent)
    // For now, parity with the original skeleton: succeed after loading inputs.
    return 0;
}

// -------------------- Main / CLI --------------------
int main(string[] args)
{
    // Initialize DiffFile holders
    foreach (i; 0 .. N_DIFFS) dfiles[i] = new DiffFile();

    string[] positionals;

    try
    {
        getopt(
            args,
            "b", &optBlanksEquiv,
            "c", { optMode = OptModeType.MODE_CONTEXT; optCtxtLines = 3; },
            "C", (string n){ optMode = OptModeType.MODE_CONTEXT; optCtxtLines = n.to!uint; },
            "e", { optMode = OptModeType.MODE_ED; },
            "f", { optMode = OptModeType.MODE_REVERSE_ED; },
            "r", &optRecurse
        );
        // remaining positionals live in args[1..$]
        positionals = args[1 .. $];
    }
    catch (Exception e)
    {
        stderr.writeln(e.msg);
        return EXIT_FAILURE;
    }

    // Expect exactly two positional args: file1 file2
    if (positionals.length != 2)
    {
        stderr.writeln("Usage: diff [-b] [-c|-C N|-e|-f] [-r] file1 file2");
        return EXIT_FAILURE;
    }

    dfiles[0].filename = positionals[0];
    dfiles[1].filename = positionals[1];

    auto rc = doDiff();
    return rc;
}
