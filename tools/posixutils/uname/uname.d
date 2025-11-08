// uname.d — D port of the POSIX `uname` utility with options
import std.stdio : writeln, stderr, writefln;
import std.getopt : getopt, defaultGetoptPrinter, GetoptResult;
import std.array : Appender, join;
import std.string : fromStringz;
import core.sys.posix.utsname : utsname, uname;
import core.stdc.errno : errno;

private string z(const(char)* p) { return p ? fromStringz(p) : ""; }

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
    catch (Exception e)
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

    // Build output in the POSIX order used by your C code: m n r s v
    auto parts = Appender!(string[])();
    if (optM) parts.put(z(&u.machine[0]));
    if (optN) parts.put(z(&u.nodename[0]));
    if (optR) parts.put(z(&u.release[0]));
    if (optS) parts.put(z(&u.sysname[0]));
    if (optV) parts.put(z(&u.version[0]));

    writeln(parts.data.join(" "));
    return 0;
}
