// df.d — D translation of the provided C/C++ "df" source
module df;

import std.stdio : stdout, stderr, write, writef, writefln, writeln;
import std.string : fromStringz, toStringz;
import std.getopt : getopt, defaultGetoptPrinter;
import std.conv : to;
import std.typecons : Nullable;
import std.algorithm : max;
import std.array : array;

// ---- C/POSIX interop ----
extern (C) @system:

version (linux)
{
    import core.sys.linux.mntent : setmntent, getmntent, endmntent, mntent;
    import core.sys.linux.sys.statfs : statfs, statfs as c_statfs; // alias name clash guard
    import core.sys.posix.sys.stat : stat, stat as c_stat, lstat as c_lstat;
    import core.sys.posix.sys.types : dev_t;
    import core.stdc.stdio : FILE, perror, fopen, fclose;
    enum char* MOUNT_PATH = "/proc/mounts".ptr;
}
else version (OSX)
{
    import core.sys.darwin.sys.mount : getmntinfo, statfs, MNT_WAIT;
    import core.sys.posix.sys.stat : stat, stat as c_stat, lstat as c_lstat;
    import core.sys.posix.sys.types : dev_t;
    import core.stdc.stdio : perror;
}

extern (C) @system nothrow:
version (linux)
{
    // statfs function
    int statfs(const(char)* path, statfs* buf);
}
else version (OSX)
{
    // statfs exists in darwin mount.h as well
    int statfs(const(char)* path, statfs* buf);
}

extern (C) @system:
int stat(const(char)* path, stat* buf);

// ---- D side ----
@safe:

final class FSListEnt
{
    string devname;
    string dir;
    dev_t  dev;
    bool   masked;
}

__gshared ulong   optBlockSize = 512;
__gshared bool    optPortable = false;
__gshared bool    optTotalAlloc = false; // parsed but (like original) not used in output
__gshared bool    fslistMasked = false;

__gshared FSListEnt[] fslist;

// ---- Helpers ----

private void pushMount(string devname, string dir)
@system
{
    // Determine device id to match paths: prefer stat(devname).st_rdev,
    // else stat(dir).st_dev, else -1
    stat st;
    dev_t dv = cast(dev_t) -1;

    if (c_stat(devname.toStringz, &st) == 0)
        dv = st.st_rdev;
    else if (c_stat(dir.toStringz, &st) == 0)
        dv = st.st_dev;

    auto ent = new FSListEnt;
    ent.devname = devname;
    ent.dir = dir;
    ent.dev = dv;
    ent.masked = false;
    fslist ~= ent;
}

version (linux)
private int readMountList()
@system
{
    auto f = setmntent(MOUNT_PATH, "r");
    if (f is null)
    {
        perror(MOUNT_PATH);
        return 1;
    }

    scope(exit) endmntent(f);

    mntent* me;
    while ((me = getmntent(f)) !is null)
    {
        auto dev = fromStringz(me.mnt_fsname);
        auto dir = fromStringz(me.mnt_dir);
        pushMount(dev, dir);
    }
    return 0;
}
else version (OSX)
private int readMountList()
@system
{
    statfs* mounts = null;
    auto n = getmntinfo(&mounts, MNT_WAIT);
    if (n < 0)
    {
        perror("getmntinfo");
        return 1;
    }
    foreach (i; 0 .. n)
    {
        auto dev = fromStringz(mounts[i].f_mntfromname);
        auto dir = fromStringz(mounts[i].f_mntonname);
        pushMount(dev, dir);
    }
    return 0;
}

private void maskAll()
@safe
{
    foreach (ref e; fslist) e.masked = true;
}

private int maskFromPath(string path)
@system
{
    // Mark filesystems whose st_dev matches stat(path).st_dev as masked=true
    stat st;
    if (c_stat(path.toStringz, &st) != 0)
    {
        perror(path.toStringz);
        return 1;
    }

    fslistMasked = true;
    foreach (ref e; fslist)
    {
        if (e.dev == st.st_dev)
            e.masked = true;
    }
    return 0;
}

version (linux)
private int outputOne(FSListEnt e)
@system
{
    statfs sf;
    if (statfs(e.dir.toStringz, &sf) < 0)
    {
        perror(e.dir.toStringz);
        return 1;
    }

    ulong blksz = cast(ulong) sf.f_bsize;

    // totals in chosen block size
    auto total = cast(ulong) sf.f_blocks * blksz / optBlockSize;
    auto avail = cast(ulong) sf.f_bavail * blksz / optBlockSize;
    auto free_ = cast(ulong) sf.f_bfree  * blksz / optBlockSize;

    if (total == 0) return 0;

    auto used = total - free_;
    auto pct  = ((total - avail) * 100) / total;

    if (optPortable)
        writefln("%-20s %9s %9s %9s %7s%% %s",
                 e.devname, total, used, avail, pct, e.dir);
    else
        writefln("%-20s %9s %9s %9s %3s%% %s",
                 e.devname, total, used, avail, pct, e.dir);
    return 0;
}
else version (OSX)
private int outputOne(FSListEnt e)
@system
{
    statfs sf;
    if (statfs(e.dir.toStringz, &sf) < 0)
    {
        perror(e.dir.toStringz);
        return 1;
    }

    ulong blksz = cast(ulong) sf.f_bsize;

    auto total = cast(ulong) sf.f_blocks * blksz / optBlockSize;
    auto avail = cast(ulong) sf.f_bavail * blksz / optBlockSize;
    auto free_ = cast(ulong) sf.f_bfree  * blksz / optBlockSize;

    if (total == 0) return 0;

    auto used = total - free_;
    auto pct  = ((total - avail) * 100) / total;

    if (optPortable)
        writefln("%-20s %9s %9s %9s %7s%% %s",
                 e.devname, total, used, avail, pct, e.dir);
    else
        writefln("%-20s %9s %9s %9s %3s%% %s",
                 e.devname, total, used, avail, pct, e.dir);
    return 0;
}

private int outputList()
@safe
{
    int rc = 0;

    if (optPortable)
        writefln("Filesystem         %4s-blocks      Used Available Capacity Mounted on", optBlockSize);
    else
        writefln("Filesystem         %4s-blocks      Used Available Use%% Mounted on", optBlockSize);

    foreach (e; fslist)
        if (e.masked)
            rc |= outputOne(e);

    return rc;
}

// ---- Main ----
int main(string[] args)
{
    // Flags: -k, -P, -t (parsing 't' for parity with original; output matches original behavior)
    bool kFlag = false, pFlag = false, tFlag = false;

    string[] paths; // positional args

    try
    {
        auto help = getopt(args,
            std.getopt.config.passThrough,
            "k", &kFlag,
            "P|portability", &pFlag,
            "t", &tFlag
        );

        // Gather remaining positionals
        paths = help.args.dup;
    }
    catch (Exception e)
    {
        stderr.writeln(e.msg);
        return 2;
    }

    if (kFlag) optBlockSize = 1024;
    optPortable = pFlag;
    optTotalAlloc = tFlag; // retained (not used), to mirror original CLI

    // Pre-walk: read mount list
    if (auto r = readMountList())
        return r;

    int rc = 0;

    if (paths.length == 0)
    {
        // No args: mask all (original df does this if no path matched)
        maskAll();
    }
    else
    {
        foreach (p; paths)
            rc |= maskFromPath(p);
        if (!fslistMasked)
            maskAll();
    }

    rc |= outputList();
    return rc;
}
