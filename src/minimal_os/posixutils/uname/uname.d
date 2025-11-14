// uname.d — D port of the POSIX `uname` utility with options
import std.stdio : writeln, stderr, writefln;
import std.getopt : getopt, defaultGetoptPrinter, GetoptResult;
import std.array : Appender, join;
import std.string : fromStringz;
import core.sys.posix.sys.utsname : utsname, uname; // correct module path
import core.stdc.errno : errno;

@trusted private string z(const(char)* p)
{
    if (p is null) return "";
    // On some toolchains fromStringz returns const(char)[];
    // .idup => immutable(char)[] which is `string`.
    return fromStringz(p).idup;
}

int main(string[] args)
{
    // Flags
    bool optAll = false;
    bool optM = false, optN = false, optR = false, optS = false, optV = false;

    GetoptResult res;
    try
    {
        res = getopt(args,
            "all|a",      &optAll,
            "machine|m",  &optM,
            "nodename|n", &optN,
            "kernel-release|r", &optR,
            "kernel-name|s",    &optS,
            "kernel-version|v", &optV
        );
    }
    catch (Exception)
    {
        defaultGetoptPrinter("uname - return system name", res.options);
        return 1;
    }

    // If -a was given, behave like -mnrsv
    if (optAll)
    {
        optM = optN = optR = optS = optV = true;
    }

    // If no specific flag was set, default to -s
    if (!(optM || optN || optR || optS || optV))
        optS = true;

    utsname u;
    if (uname(&u) != 0)
    {
        writefln("uname: failed (errno %s)", errno);
        return 1;
    }

    // Build output in POSIX-ish order: m n r s v (or just selected flags)
    auto parts = Appender!(string[])();
    parts.reserve(5);

    if (optM) parts.put(z(&u.machine[0]));
    if (optN) parts.put(z(&u.nodename[0]));
    if (optR) parts.put(z(&u.release[0]));
    if (optS) parts.put(z(&u.sysname[0]));

    // Handle the `version` field safely (D reserves `version`)
    static if (__traits(hasMember, utsname, "version_"))
    {
        if (optV) parts.put(z(&u.version_[0]));
    }
    else static if (__traits(hasMember, utsname, "version"))
    {
        // Access indirectly so the parser never sees `.version`
        auto p = &(__traits(getMember, u, "version"))[0];
        if (optV) parts.put(z(p));
    }

    writeln(parts.data.join(" "));
    return 0;
}
