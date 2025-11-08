// sort.d — D translation of the provided POSIX utils "sort" skeleton
module sort_d;

import core.stdc.string : strcoll;
import core.stdc.stdio  : perror;
import std.stdio        : File, stdin, stdout, writeln, writef, writefln;
import std.string       : toStringz;
import std.algorithm    : sort, min;
import std.conv         : to;
import std.array        : Appender, array;
import std.exception    : enforce;
import std.typecons     : Tuple;
import std.meta;
import std.getopt;
import std.range        : byLine, empty;
import std.uni          : lineSep;

// ----------------------------- Data types -----------------------------

struct SortLine {
    string line;
    this(string s) { line = s; }
    const(char)* cstr() const { return line.toStringz; }
}

struct MergeFile {
    string   filename;
    File     f;          // lazily opened if not stdin
    bool     opened = false;
    string   line;
    bool     haveLine = false;

    this(string name) { filename = name; }

    bool ensureOpen()
    {
        if (opened) return true;
        if (filename == "-") {
            f = stdin;
            opened = true;
            return true;
        }
        try {
            f = File(filename, "r");
            opened = true;
            return true;
        } catch (Exception) {
            perror(filename.toStringz);
            return false;
        }
    }

    // read next line into buffer (preserve trailing '\n' like fgets)
    bool nextLine()
    {
        if (!ensureOpen()) return false;
        if (f.eof()) return false;

        // Read a full line; std.stdio byLine strips the newline, so re-add it.
        import std.algorithm : joiner;
        import std.array : appender;

        string s;
        // read a single line (without newline), then append '\n' if file had it
        // Simpler approach: readln will include '\n' if present
        try {
            s = f.readln(); // includes trailing '\n' when present
        } catch (Exception) {
            return false;
        }
        if (s.length == 0 && f.eof())
            return false;

        line = s;
        haveLine = true;
        return true;
    }

    void close()
    {
        if (opened && filename != "-") {
            f.close();
        }
        opened = false;
    }
}

// ----------------------------- Options -----------------------------

enum Mode { sortMode, mergeMode, checkMode }

__gshared Mode   optMode        = Mode.sortMode;
__gshared string optOutput      = "-";
__gshared bool   optUnique      = false;
__gshared bool   optAlphaNum    = false;
__gshared bool   optForceUpper  = false;
__gshared bool   optIgnoreNonPr = false;
__gshared bool   optNumeric     = false;
__gshared bool   optReverse     = false;
__gshared bool   optIgnoreLBl   = false;
__gshared int    optSeparator   = -1; // char code or -1
__gshared string[] optKeydefs;

// we keep all lines when sorting; in merge we stream
SortLine[] lines;
MergeFile[] mergeFiles;

// ----------------------------- Compare -----------------------------

// locale-aware compare via strcoll; mirror C: rc <= 0 => a "before/equal" b
int rawCompare(in string A, in string B)
{
    auto rc = strcoll(A.toStringz, B.toStringz);
    return optReverse ? -rc : rc;
}

// std.sort comparator expects "a should come before b"
bool lineLess(ref const SortLine a, ref const SortLine b)
{
    return rawCompare(a.line, b.line) < 0;
}

// used for merge winner selection (minimum)
size_t mergeNextIndex()
{
    enforce(mergeFiles.length > 0);
    size_t idx = 0;
    foreach (i; 1 .. mergeFiles.length)
    {
        // pick the smaller (according to comparator)
        if (rawCompare(mergeFiles[i].line, mergeFiles[idx].line) < 0)
            idx = i;
    }
    return idx;
}

// ----------------------------- Merge helpers -----------------------------

// pull a line into mf.haveLine if needed; return true if mf has a line to output
bool mergeEnsure(MergeFile ref mf)
{
    if (mf.haveLine) return true;
    return mf.nextLine();
}

// advance all files; drop those that are exhausted
bool mergeFillMore()
{
    import std.algorithm : remove;
    size_t i = 0;
    while (i < mergeFiles.length)
    {
        if (!mergeEnsure(mergeFiles[i]))
        {
            // EOF or error: close and remove
            mergeFiles[i].close();
            // remove by swapping back
            mergeFiles = mergeFiles[0 .. i] ~ mergeFiles[i+1 .. $];
            continue;
        }
        ++i;
    }
    return true;
}

void mergeEmit(MergeFile ref mf, ref File outF)
{
    enforce(mf.haveLine);
    outF.write(mf.line);
    mf.haveLine = false;
}

// ----------------------------- Check mode -----------------------------

struct Checker {
    bool   havePrev = false;
    string prev;
    bool push(string s)
    {
        if (!havePrev) { prev = s; havePrev = true; return true; }
        auto ok = (rawCompare(prev, s) <= 0);
        prev = s;
        return ok;
    }
}

// ----------------------------- I/O helpers -----------------------------

// open output stream (stdout if "-", else path)
File openOutput()
{
    if (optOutput == "-" || optOutput.length == 0) {
        return stdout;
    }
    return File(optOutput, "w");
}

// read all lines from given File into `lines` (append)
void readAllIntoLines(ref File f, bool checking, ref Checker chk, ref int exitStatus)
{
    string s;
    while (true) {
        try {
            s = f.readln(); // includes newline when present
        } catch (Exception) {
            break;
        }
        if (s.length == 0 && f.eof()) break;

        if (checking) {
            if (!chk.push(s)) {
                exitStatus = 1; // like original: non-zero when out-of-order
                // stop early to match original RC_STOP_WALK behavior
                // But still consume remaining input to keep IO simple? We'll break.
                break;
            }
        } else {
            lines ~= SortLine(s);
        }
    }
}

// ----------------------------- main -----------------------------

int main(string[] argv)
{
    // minimal usage text parity
    immutable usage = "sort - sort, merge, or sequence check text files\n"
                      ~ "usage: " ~ (argv.length ? argv[0] : "sort")
                      ~ " [-cmu df i n r b] [-t CHAR] [-k KEYDEF] [-o FILE] [FILE...]\n";

    // parse options (keep flags even if not fully implemented, to mirror interface)
    string fieldSepArg;
    string keyArg;
    bool wantCheck = false, wantMerge = false;

    auto help = getopt(argv,
        "c", &wantCheck,
        "m", &wantMerge,
        "o", &optOutput,
        "u", &optUnique,
        "d", &optAlphaNum,
        "f", &optForceUpper,
        "i", &optIgnoreNonPr,
        "n", &optNumeric,
        "r", &optReverse,
        "b", &optIgnoreLBl,
        "t", &fieldSepArg,
        "k", &keyArg
    );

    if (help == GetoptResult.helpWanted)
    {
        writeln(usage);
        return 0;
    }

    if (!help)
    {
        // getopt error prints its own message; show usage
        writeln(usage);
        return 2;
    }

    if (fieldSepArg.length)
    {
        if (fieldSepArg.length != 1) {
            writeln("sort: -t expects a single character");
            return 2;
        }
        optSeparator = fieldSepArg[0];
    }
    if (keyArg.length)
        optKeydefs ~= keyArg;

    optMode = wantCheck ? Mode.checkMode : (wantMerge ? Mode.mergeMode : Mode.sortMode);

    // Remaining argv are files; if none, use "-"
    string[] files = argv[help.index .. $];
    if (files.length == 0)
        files = ["-"];

    // Open output
    File outF;
    try outF = openOutput();
    catch (Exception e) {
        perror(optOutput.toStringz);
        return 2;
    }

    int exitStatus = 0;

    // Walk files
    if (optMode == Mode.mergeMode)
    {
        // Prepare merge files
        foreach (fn; files)
            mergeFiles ~= MergeFile(fn);

        // Merge drive
        while (true)
        {
            if (!mergeFillMore()) { exitStatus = 1; break; }
            if (mergeFiles.length == 0) break;

            if (mergeFiles.length == 1) {
                mergeEmit(mergeFiles[0], outF);
            } else {
                auto idx = mergeNextIndex();
                mergeEmit(mergeFiles[idx], outF);
            }
        }
        // close any remaining
        foreach (ref mf; mergeFiles) mf.close();
    }
    else
    {
        // SORT or CHECK
        Checker chk;
        foreach (fn; files)
        {
            File f;
            bool needClose = false;
            try {
                if (fn == "-") f = stdin;
                else { f = File(fn, "r"); needClose = true; }
            } catch (Exception) {
                perror(fn.toStringz);
                exitStatus = 2;
                continue;
            }

            readAllIntoLines(f, optMode == Mode.checkMode, chk, exitStatus);

            if (needClose) f.close();

            if (optMode == Mode.checkMode && exitStatus != 0) {
                // stop early like RC_STOP_WALK
                break;
            }
        }

        if (optMode == Mode.sortMode)
        {
            // Sort and output
            lines.sort!lineLess;

            if (optUnique) {
                // simple unique on full lines (adjacent after sort)
                SortLine[] uniqueLines;
                uniqueLines.reserve(lines.length);
                string last;
                bool have = false;
                foreach (ref sl; lines) {
                    if (!have || rawCompare(last, sl.line) != 0) {
                        uniqueLines ~= sl;
                        last = sl.line;
                        have = true;
                    }
                }
                lines = uniqueLines;
            }

            foreach (ref sl; lines)
                outF.write(sl.line);
        }
        // MODE_CHECK just sets exitStatus accordingly
    }

    // Flush output if it's a file
    try { outF.flush(); } catch (Exception) {}

    return exitStatus;
}
