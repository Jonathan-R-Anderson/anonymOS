module getconf_d;

import std.stdio  : stderr, writeln, writefln;
import std.getopt : getopt;
import std.string : toStringz, fromStringz;

// ---------- POSIX interop ----------
extern (C) {
    long   sysconf(int name);
    long   pathconf(const(char)* path, int name);
    size_t confstr(int name, char* buf, size_t len);

    import core.stdc.errno  : errno;
    import core.stdc.stdio  : perror;

    struct strmap; // opaque C type
    int map_lookup(const strmap* map, const(char)* key);

    // Provided by your C objs/libs (pointers, not by-value)
    __gshared const(strmap)* pathvar_map;
    __gshared const(strmap)* sysvar_map;
    __gshared const(strmap)* confstr_map;
}

extern (D):

// ---------- Globals / options ----------
string optVar;
string optPathname;
string optSpec; // -v (unused, just for parity)

// ---------- Helpers ----------
@system
int doVar(const strmap* mapptr, bool pathvar)
{
    const val = map_lookup(mapptr, optVar.toStringz);
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

    const csVal = map_lookup(confstr_map, optVar.toStringz);
    if (csVal >= 0)
        return doConfstr(csVal);

    return doVar(sysvar_map, false);
}
