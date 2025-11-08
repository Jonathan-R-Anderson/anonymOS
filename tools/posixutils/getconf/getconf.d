// getconf.d — D translation of the provided C++ getconf tool
module getconf_d;

import std.stdio : stdout, stderr, writeln, writef, writefln;
import std.getopt : getopt;
import std.string : toStringz, fromStringz;
import std.conv   : to;

// ---------- POSIX interop ----------
extern (C):
    // sysconf(3), pathconf(3), confstr(3)
    long sysconf(int name);
    long pathconf(const(char)* path, int name);
    size_t confstr(int name, char* buf, size_t len);

    // errno / strerror / perror
    import core.stdc.errno  : errno;
    import core.stdc.string : strerror;
    import core.stdc.stdio  : perror;

    // Opaque map type and lookup helper (must be provided by your C objects)
    struct strmap;
    int map_lookup(const strmap* map, const(char)* key);

    // External maps produced from your headers:
    //   #define STRMAP pathvar_map   #include "getconf-path.h"
    //   #define STRMAP sysvar_map    #include "getconf-system.h"
    //   #define STRMAP confstr_map   #include "getconf-confstr.h"
    __gshared const strmap pathvar_map;
    __gshared const strmap sysvar_map;
    __gshared const strmap confstr_map;

// ---------- Globals / options ----------
@safe:
string optVar;
string optPathname;
string optSpec; // -v (not implemented)

// ---------- Helpers ----------
int doVar(const strmap* mapptr, bool pathvar)
{
    const val = map_lookup(mapptr, optVar.toStringz);
    if (val < 0)
    {
        if (pathvar)
            stderr.writefln("invalid path variable %s", optVar);
        else
            stderr.writefln("invalid system variable %s", optVar);
        return 1;
    }

    errno = 0;
    long l;
    if (pathvar)
    {
        l = pathconf(optPathname.toStringz, val);
        if (l < 0)
        {
            perror("pathconf(3)");
            return 1;
        }
    }
    else
    {
        l = sysconf(val);
        if (l < 0)
        {
            perror("sysconf(3)");
            return 1;
        }
    }

    writefln("%s", l);
    return 0;
}

int doConfstr(int val)
{
    // First call to get required size (includes terminating NUL)
    size_t n = confstr(val, null, 0);
    if (n == 0)
    {
        stderr.writefln("invalid confstr variable %s", optVar);
        return 1;
    }

    // Allocate n+1 for safety, then call again
    auto buf = new char[n + 1];
    auto wrote = confstr(val, buf.ptr, n + 1);
    // wrote may be 0 on error; we could check but mirror original behavior
    writeln(fromStringz(buf.ptr));
    return 0;
}

// ---------- Main ----------
int main(string[] args)
{
    try
    {
        auto help = getopt(
            args,
            "v", &optSpec  // (not implemented, parity with original)
        );

        // Positionals:
        //   [system_var | path_var pathname]
        auto pos = help.args;
        if (pos.length < 1 || pos.length > 2)
        {
            stderr.writefln("Usage: %s [system_var | path_var pathname]", args[0]);
            return 1;
        }

        optVar = pos[0];
        if (pos.length == 2)
            optPathname = pos[1];
    }
    catch (Exception e)
    {
        stderr.writeln(e.msg);
        return 2;
    }

    // If we have a pathname, treat var as a pathconf variable
    if (optPathname.length)
        return doVar(&pathvar_map, true);

    // If it's in confstr list, use confstr
    auto csVal = map_lookup(&confstr_map, optVar.toStringz);
    if (csVal >= 0)
        return doConfstr(csVal);

    // Otherwise, use sysconf
    return doVar(&sysvar_map, false);
}
