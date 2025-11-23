// diff.d — D translation of the provided C++ "diff" skeleton
module diff;

import std.stdio : writeln, writefln, stderr, File, readln;
import std.getopt : getopt, defaultGetoptPrinter;
import std.string : toStringz, fromStringz, indexOf;
import std.conv : to;
import std.array : appender;
import std.format : format;
import std.algorithm : max, min, sort;
import std.path : baseName, buildPath;
import std.file : exists, isDir, dirEntries, SpanMode, mkdirRecurse, rmdirRecurse, tempDir, fileWrite = write;
import std.process : thisProcessID;

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

alias LineEmitter = void delegate(const(char)[]);

__gshared LineEmitter diffEmitter;

shared static this()
{
    diffEmitter = (const(char)[] line) { writeln(line); };
}

void emitLine(const(char)[] line)
{
    if (diffEmitter !is null)
        diffEmitter(line);
    else
        writeln(line);
}

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
    string normalizedCache;
    bool haveNormalized = false;

    this(string s)
    {
        data = s;
        hash = blobHash(HASH_START, cast(const(ubyte)[]) data);
    }

    string normalized() @trusted
    {
        if (!optBlanksEquiv)
            return data;
        if (!haveNormalized)
        {
            normalizedCache = collapseWhitespace(data);
            haveNormalized = true;
        }
        return normalizedCache;
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

// -------------------- Core diff helpers --------------------
enum DiffOpType { Equal, Add, Delete }

struct DiffOp
{
    DiffOpType type;
    size_t idx1;
    size_t idx2;
}

struct Chunk { size_t startOp; size_t endOp; }

struct Change
{
    size_t start1;
    size_t len1;
    size_t start2;
    size_t len2;
    string[] lines1;
    string[] lines2;
}

@safe string collapseWhitespace(const(string) s)
{
    auto builder = appender!string();
    bool inSpace = false;
    foreach (ch; s)
    {
        if (ch == ' ' || ch == '\t')
        {
            if (!inSpace)
            {
                builder.put(' ');
                inSpace = true;
            }
        }
        else
        {
            builder.put(ch);
            inSpace = false;
        }
    }
    return builder.data.idup;
}

bool filesExist(string left, string right)
{
    if (!exists(left))
    {
        stderr.writefln("diff: %s: No such file or directory", left);
        return false;
    }
    if (!exists(right))
    {
        stderr.writefln("diff: %s: No such file or directory", right);
        return false;
    }
    return true;
}

bool linesEqual(size_t i, size_t j)
{
    return dfiles[0].lines[i].normalized() == dfiles[1].lines[j].normalized();
}

DiffOp[] buildDiffOps()
{
    auto left = dfiles[0].lines;
    auto right = dfiles[1].lines;
    size_t n = left.length;
    size_t m = right.length;
    auto dp = new size_t[][](n + 1);
    foreach (idx; 0 .. n + 1)
        dp[idx] = new size_t[](m + 1);

    for (size_t i = n; i-- > 0;)
    {
        for (size_t j = m; j-- > 0;)
        {
            if (linesEqual(i, j))
                dp[i][j] = dp[i + 1][j + 1] + 1;
            else
                dp[i][j] = max(dp[i + 1][j], dp[i][j + 1]);
        }
    }

    DiffOp[] ops;
    size_t i = 0;
    size_t j = 0;
    while (i < n && j < m)
    {
        if (linesEqual(i, j))
        {
            ops ~= DiffOp(DiffOpType.Equal, i + 1, j + 1);
            ++i;
            ++j;
        }
        else if (dp[i + 1][j] >= dp[i][j + 1])
        {
            ops ~= DiffOp(DiffOpType.Delete, i + 1, j + 1);
            ++i;
        }
        else
        {
            ops ~= DiffOp(DiffOpType.Add, i, j + 1);
            ++j;
        }
    }

    while (i < n)
    {
        ops ~= DiffOp(DiffOpType.Delete, i + 1, j + 1);
        ++i;
    }
    while (j < m)
    {
        ops ~= DiffOp(DiffOpType.Add, i, j + 1);
        ++j;
    }

    return ops;
}

Chunk[] buildChunks(const DiffOp[] ops)
{
    Chunk[] chunks;
    size_t i = 0;
    while (i < ops.length)
    {
        if (ops[i].type == DiffOpType.Equal)
        {
            ++i;
            continue;
        }

        size_t start = i;
        size_t ctxBefore = optCtxtLines;
        while (start > 0 && ctxBefore > 0 && ops[start - 1].type == DiffOpType.Equal)
        {
            --start;
            --ctxBefore;
        }

        size_t end = i;
        size_t ctxAfter = optCtxtLines;
        size_t j = i + 1;
        while (j < ops.length)
        {
            if (ops[j].type == DiffOpType.Equal)
            {
                if (ctxAfter == 0)
                    break;
                end = j;
                --ctxAfter;
            }
            else
            {
                end = j;
                ctxAfter = optCtxtLines;
            }
            ++j;
        }

        chunks ~= Chunk(start, end);
        i = end + 1;
    }
    return chunks;
}

Change[] buildChanges(const DiffOp[] ops)
{
    Change[] changes;
    size_t i = 0;
    while (i < ops.length)
    {
        if (ops[i].type == DiffOpType.Equal)
        {
            ++i;
            continue;
        }

        Change ch;
        ch.start1 = ops[i].idx1;
        ch.start2 = ops[i].idx2;
        while (i < ops.length && ops[i].type != DiffOpType.Equal)
        {
            auto op = ops[i];
            final switch (op.type)
            {
                case DiffOpType.Delete:
                    if (ch.len1 == 0)
                        ch.start1 = op.idx1;
                    ++ch.len1;
                    ch.lines1 ~= dfiles[0].lines[op.idx1 - 1].data;
                    break;
                case DiffOpType.Add:
                    if (ch.len2 == 0)
                        ch.start2 = op.idx2;
                    ++ch.len2;
                    ch.lines2 ~= dfiles[1].lines[op.idx2 - 1].data;
                    break;
                case DiffOpType.Equal:
                    break;
            }
            ++i;
        }
        changes ~= ch;
    }
    return changes;
}

void emitChunkLines(const DiffOp[] ops, size_t start, size_t end)
{
    auto chunkOps = ops[start .. end + 1];
    size_t min1 = size_t.max, max1 = 0;
    size_t min2 = size_t.max, max2 = 0;

    foreach (op; chunkOps)
    {
        if (op.idx1 != 0 && op.type != DiffOpType.Add)
        {
            min1 = min(min1, op.idx1);
            max1 = max(max1, op.idx1);
        }
        if (op.idx2 != 0 && op.type != DiffOpType.Delete)
        {
            min2 = min(min2, op.idx2);
            max2 = max(max2, op.idx2);
        }
    }

    size_t start1 = (min1 == size_t.max) ? chunkOps[0].idx1 : min1;
    size_t start2 = (min2 == size_t.max) ? chunkOps[0].idx2 : min2;
    size_t count1 = (min1 == size_t.max || max1 < min1) ? 0 : (max1 - min1 + 1);
    size_t count2 = (min2 == size_t.max || max2 < min2) ? 0 : (max2 - min2 + 1);

    emitLine("***************");
    emitLine(format("*** %s,%s ****", start1, count1));
    foreach (op; chunkOps)
    {
        if (op.type == DiffOpType.Add)
            continue;
        string prefix = (op.type == DiffOpType.Equal) ? "  " : "- ";
        auto line = (op.idx1 > 0) ? dfiles[0].lines[op.idx1 - 1].data : "";
        emitLine(prefix ~ line);
    }

    emitLine(format("--- %s,%s ----", start2, count2));
    foreach (op; chunkOps)
    {
        if (op.type == DiffOpType.Delete)
            continue;
        string prefix = (op.type == DiffOpType.Equal) ? "  " : "+ ";
        auto line = (op.idx2 > 0) ? dfiles[1].lines[op.idx2 - 1].data : "";
        emitLine(prefix ~ line);
    }
}

void emitContext(const DiffOp[] ops)
{
    emitLine("*** " ~ dfiles[0].filename);
    emitLine("--- " ~ dfiles[1].filename);
    foreach (chunk; buildChunks(ops))
        emitChunkLines(ops, chunk.startOp, chunk.endOp);
}

string formatRange(size_t start, size_t len)
{
    if (len == 0)
        return to!string(start);
    if (len == 1)
        return to!string(start);
    return format("%s,%s", start, start + len - 1);
}

void emitEd(const Change[] changes, bool reverse)
{
    foreach (const ref ch; changes)
    {
        auto start = reverse ? ch.start2 : ch.start1;
        auto lenDel = reverse ? ch.len2 : ch.len1;
        auto lenAdd = reverse ? ch.len1 : ch.len2;
        auto addLines = reverse ? ch.lines1 : ch.lines2;

        if (lenDel > 0 && lenAdd > 0)
        {
            auto rangeStr = formatRange(start, lenDel);
            emitLine(rangeStr ~ "c");
            foreach (line; addLines)
                emitLine(line);
            emitLine(".");
        }
        else if (lenDel > 0)
        {
            auto rangeStr = formatRange(start, lenDel);
            emitLine(rangeStr ~ "d");
        }
        else if (lenAdd > 0)
        {
            emitLine(to!string(start) ~ "a");
            foreach (line; addLines)
                emitLine(line);
            emitLine(".");
        }
    }
}

bool hasDifferences(const DiffOp[] ops)
{
    foreach (op; ops)
        if (op.type != DiffOpType.Equal)
            return true;
    return false;
}

void resetDiffFile(DiffFile dfile)
{
    dfile.lines.length = 0;
    dfile.haveHash.clear();
}

int diffFiles(string left, string right)
{
    dfiles[0].filename = left;
    dfiles[1].filename = right;
    foreach (i; 0 .. N_DIFFS)
    {
        resetDiffFile(dfiles[i]);
        if (readFile(dfiles[i]) != 0)
            return 1;
    }

    auto ops = buildDiffOps();
    if (!hasDifferences(ops))
        return 0;

    final switch (optMode)
    {
        case OptModeType.MODE_CONTEXT:
            emitContext(ops);
            break;
        case OptModeType.MODE_ED:
            emitEd(buildChanges(ops), false);
            break;
        case OptModeType.MODE_REVERSE_ED:
            emitEd(buildChanges(ops), true);
            break;
    }
    return 0;
}

string[] directoryEntries(string path)
{
    string[] names;
    foreach (entry; dirEntries(path, SpanMode.shallow))
    {
        auto name = baseName(entry.name);
        if (name == "." || name == "..")
            continue;
        names ~= name;
    }
    sort(names);
    return names;
}

int diffDirectories(string left, string right)
{
    auto leftEntries = directoryEntries(left);
    auto rightEntries = directoryEntries(right);
    string[] allNames;
    bool[string] seen;
    foreach (name; leftEntries ~ rightEntries)
    {
        if (name in seen)
            continue;
        seen[name] = true;
        allNames ~= name;
    }
    sort(allNames);

    foreach (name; allNames)
    {
        auto leftPath = buildPath(left, name);
        auto rightPath = buildPath(right, name);
        bool leftExists = exists(leftPath);
        bool rightExists = exists(rightPath);

        if (!leftExists)
        {
            emitLine("Only in " ~ right ~ ": " ~ name);
            continue;
        }
        if (!rightExists)
        {
            emitLine("Only in " ~ left ~ ": " ~ name);
            continue;
        }

        bool leftDir = isDir(leftPath);
        bool rightDir = isDir(rightPath);

        if (leftDir != rightDir)
        {
            emitLine("File type mismatch for " ~ name);
            continue;
        }

        if (leftDir)
        {
            emitLine("diff " ~ leftPath ~ " " ~ rightPath);
            auto rc = diffDirectories(leftPath, rightPath);
            if (rc != 0)
                return rc;
        }
        else
        {
            emitLine("diff " ~ leftPath ~ " " ~ rightPath);
            auto rc = diffFiles(leftPath, rightPath);
            if (rc != 0)
                return rc;
        }
    }
    return 0;
}

int diffPaths(string left, string right)
{
    if (!filesExist(left, right))
        return 1;

    bool leftDir = isDir(left);
    bool rightDir = isDir(right);

    if (leftDir || rightDir)
    {
        if (!(leftDir && rightDir))
        {
            stderr.writefln("diff: file/directory mismatch between %s and %s", left, right);
            return 1;
        }
        if (!optRecurse)
        {
            stderr.writefln("diff: %s and %s are directories (use -r)", left, right);
            return 1;
        }
        emitLine("diff " ~ left ~ " " ~ right);
        return diffDirectories(left, right);
    }

    return diffFiles(left, right);
}

int doDiff()
{
    return diffPaths(dfiles[0].filename, dfiles[1].filename);
}

void resetDiffOptions()
{
    optMode = OptModeType.MODE_CONTEXT;
    optCtxtLines = 3;
    optBlanksEquiv = false;
    optRecurse = false;
}

string createTempDir(string label)
{
    static size_t counter;
    auto dir = buildPath(tempDir(), format("diff_unittest_%s_%s_%s", thisProcessID(), label, counter++));
    mkdirRecurse(dir);
    return dir;
}

string captureDiffOutput(int delegate() action)
{
    auto sink = appender!string();
    auto previous = diffEmitter;
    diffEmitter = (const(char)[] line)
    {
        sink.put(line);
        sink.put('\n');
    };
    scope(exit) diffEmitter = previous;
    auto rc = action();
    assert(rc == 0);
    return sink.data.idup;
}

unittest
{
    resetDiffOptions();
    optMode = OptModeType.MODE_CONTEXT;
    optCtxtLines = 1;
    auto dir = createTempDir("context");
    scope(exit) rmdirRecurse(dir);
    auto left = buildPath(dir, "left.txt");
    auto right = buildPath(dir, "right.txt");
    fileWrite(left, "alpha\nkeep\nbeta\n");
    fileWrite(right, "alpha\nkeep\nbeta updated\n");

    auto output = captureDiffOutput(() => diffFiles(left, right));
    auto expected = "*** " ~ left ~ "\n" ~
        "--- " ~ right ~ "\n" ~
        "***************\n" ~
        "*** 1,3 ****\n" ~
        "  alpha\n" ~
        "  keep\n" ~
        "- beta\n" ~
        "--- 1,3 ----\n" ~
        "  alpha\n" ~
        "  keep\n" ~
        "+ beta updated\n";
    assert(output == expected);
}

unittest
{
    resetDiffOptions();
    optMode = OptModeType.MODE_ED;
    auto dir = createTempDir("ed");
    scope(exit) rmdirRecurse(dir);
    auto left = buildPath(dir, "a.txt");
    auto right = buildPath(dir, "b.txt");
    fileWrite(left, "alpha\nbeta\ndelta\n");
    fileWrite(right, "alpha\nbeta\ngamma\ndelta\n");

    auto output = captureDiffOutput(() => diffFiles(left, right));
    auto expected = "2a\n" ~ "gamma\n" ~ ".\n";
    assert(output == expected);
}

unittest
{
    resetDiffOptions();
    optMode = OptModeType.MODE_REVERSE_ED;
    auto dir = createTempDir("reverse_ed");
    scope(exit) rmdirRecurse(dir);
    auto left = buildPath(dir, "a.txt");
    auto right = buildPath(dir, "b.txt");
    fileWrite(left, "alpha\nbeta\ndelta\n");
    fileWrite(right, "alpha\nbeta\ngamma\ndelta\n");

    auto output = captureDiffOutput(() => diffFiles(left, right));
    auto expected = "3d\n";
    assert(output == expected);
}

unittest
{
    resetDiffOptions();
    optMode = OptModeType.MODE_CONTEXT;
    optBlanksEquiv = true;
    auto dir = createTempDir("blanks");
    scope(exit) rmdirRecurse(dir);
    auto left = buildPath(dir, "a.txt");
    auto right = buildPath(dir, "b.txt");
    fileWrite(left, "value    with   spaces\n");
    fileWrite(right, "value with spaces\n");

    auto output = captureDiffOutput(() => diffFiles(left, right));
    assert(output.length == 0);
}

unittest
{
    resetDiffOptions();
    optMode = OptModeType.MODE_CONTEXT;
    optRecurse = true;
    optCtxtLines = 0;
    auto dir = createTempDir("recursive");
    scope(exit) rmdirRecurse(dir);
    auto leftDir = buildPath(dir, "left");
    auto rightDir = buildPath(dir, "right");
    mkdirRecurse(leftDir);
    mkdirRecurse(rightDir);

    fileWrite(buildPath(leftDir, "only_left.txt"), "left\n");
    fileWrite(buildPath(rightDir, "only_right.txt"), "right\n");
    fileWrite(buildPath(leftDir, "shared.txt"), "one\ntwo\n");
    fileWrite(buildPath(rightDir, "shared.txt"), "one\nchanged\n");

    auto output = captureDiffOutput(() => diffPaths(leftDir, rightDir));
    assert(output.indexOf("diff " ~ leftDir ~ " " ~ rightDir) >= 0);
    assert(output.indexOf("Only in " ~ leftDir ~ ": only_left.txt") >= 0);
    assert(output.indexOf("Only in " ~ rightDir ~ ": only_right.txt") >= 0);
    assert(output.indexOf("diff " ~ buildPath(leftDir, "shared.txt") ~ " " ~ buildPath(rightDir, "shared.txt")) >= 0);
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
