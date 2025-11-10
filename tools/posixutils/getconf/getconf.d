module getconf_d;

import std.stdio  : stderr, writeln, writefln;
import std.getopt : getopt;
import std.string : toStringz, fromStringz;

import core.sys.posix.unistd;

// ---------- POSIX interop ----------
extern (C) {
    long   sysconf(int name);
    long   pathconf(const(char)* path, int name);
    size_t confstr(int name, char* buf, size_t len);

    import core.stdc.errno  : errno;
    import core.stdc.stdio  : perror;
}

// ---------- Compile-time data ingestion ----------
private:

enum string pathVarData   = import("getconf-path.data");
enum string sysVarData    = import("getconf-system.data");
enum string confstrData   = import("getconf-confstr.data");

bool isWhitespace(char ch) pure nothrow @safe @nogc
{
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' || ch == '\v';
}

string stripLine(string line) pure nothrow @safe
{
    size_t start;
    while (start < line.length && isWhitespace(line[start]))
        ++start;
    size_t end = line.length;
    while (end > start && isWhitespace(line[end - 1]))
        --end;
    return line[start .. end];
}

int indexOfChar(string line, char ch) pure nothrow @safe
{
    foreach (idx, c; line)
    {
        if (c == ch)
            return cast(int) idx;
    }
    return -1;
}

string[] splitWhitespace(string line) pure nothrow @safe
{
    string[] tokens;
    size_t i;
    while (i < line.length)
    {
        while (i < line.length && isWhitespace(line[i]))
            ++i;
        if (i >= line.length)
            break;
        const start = i;
        while (i < line.length && !isWhitespace(line[i]))
            ++i;
        tokens ~= line[start .. i];
    }
    return tokens;
}

string generateMapLiteral(string data) pure @safe
{
    string[] entries;
    size_t pos;
    while (pos < data.length)
    {
        size_t lineEnd = pos;
        while (lineEnd < data.length && data[lineEnd] != '\n' && data[lineEnd] != '\r')
            ++lineEnd;
        auto line = data[pos .. lineEnd];

        size_t next = lineEnd;
        while (next < data.length && (data[next] == '\n' || data[next] == '\r'))
            ++next;
        pos = next;

        auto trimmed = stripLine(line);
        if (!trimmed.length || trimmed[0] == '#')
            continue;

        const hash = indexOfChar(trimmed, '#');
        if (hash >= 0)
        {
            trimmed = stripLine(trimmed[0 .. hash]);
            if (!trimmed.length)
                continue;
        }

        auto tokens = splitWhitespace(trimmed);
        if (tokens.length < 2)
            continue;

        auto name = tokens[0];
        auto value = tokens[1];

        entries ~= "\"" ~ name ~ "\": " ~ value;
    }

    string result = "[";
    foreach (idx, entry; entries)
    {
        if (idx) result ~= ", ";
        result ~= entry;
    }
    result ~= "]";
    return result;
}

enum string pathVarLiteral = generateMapLiteral(pathVarData);
enum string sysVarLiteral = generateMapLiteral(sysVarData);
enum string confstrLiteral = generateMapLiteral(confstrData);

immutable int[string] pathvar_map = mixin(pathVarLiteral);
immutable int[string] sysvar_map = mixin(sysVarLiteral);
immutable int[string] confstr_map = mixin(confstrLiteral);

int map_lookup(in int[string] map, string key) @safe pure nothrow
{
    const valuePtr = key in map;
    return valuePtr is null ? -1 : *valuePtr;
}

public:

extern (D):

// ---------- Globals / options ----------
string optVar;
string optPathname;
string optSpec; // -v (unused, just for parity)

// ---------- Helpers ----------
@system
int doVar(in int[string] map, bool pathvar)
{
    const val = map_lookup(map, optVar);
    if (val < 0)
    {
        if (pathvar) stderr.writefln("invalid path variable %s", optVar);
        else         stderr.writefln("invalid system variable %s", optVar);
        return 1;
    }

    errno = 0;
    long l;
    if (pathvar)
    {
        l = pathconf(optPathname.toStringz, val);
        if (l < 0) { perror("pathconf(3)"); return 1; }
    }
    else
    {
        l = sysconf(val);
        if (l < 0) { perror("sysconf(3)"); return 1; }
    }

    writeln(l);
    return 0;
}

@system
int doConfstr(int val)
{
    size_t n = confstr(val, null, 0);
    if (n == 0)
    {
        stderr.writefln("invalid confstr variable %s", optVar);
        return 1;
    }

    auto buf = new char[n + 1];
    // use &buf[0] in @safe contexts; we're @system anyway, but this is fine
    auto wrote = confstr(val, &buf[0], n + 1);
    writeln(fromStringz(&buf[0]));
    return (wrote == 0) ? 1 : 0; // optional: treat error as nonzero
}

// ---------- Main ----------
@system
int main(string[] args)
{
    // parse options; getopt mutates args (removes options)
    auto res = getopt(args, "v", &optSpec);

    // remaining positionals are in args[1..$]
    auto pos = args[1 .. $];
    if (pos.length < 1 || pos.length > 2)
    {
        stderr.writefln("Usage: %s [system_var | path_var pathname]", args[0]);
        return 1;
    }

    optVar = pos[0];
    if (pos.length == 2) optPathname = pos[1];

    if (optPathname.length)
        return doVar(pathvar_map, true);

    const csVal = map_lookup(confstr_map, optVar);
    if (csVal >= 0)
        return doConfstr(csVal);

    return doVar(sysvar_map, false);
}
