module df;

import std.stdio : writefln, writeln, stderr;
import std.string : split, strip, toStringz, replace, startsWith;
import std.getopt : getopt, config;
import std.file : readText;

version (linux) {} else
    static assert(0, "This df.d targets Linux only.");

// ---- Minimal Linux statvfs binding (no druntime dependency) ----
extern(C) @system nothrow {
    struct StatVFS {
        ulong  f_bsize;
        ulong  f_frsize;
        ulong  f_blocks;
        ulong  f_bfree;
        ulong  f_bavail;
        ulong  f_files;
        ulong  f_ffree;
        ulong  f_favail;
        ulong  f_fsid;
        ulong  f_flag;
        ulong  f_namemax;
        ulong[6] __f_spare; // padding
    }

    // Expose as c_statvfs in D, but link to libc's "statvfs".
    pragma(mangle, "statvfs")
    int c_statvfs(const char* path, StatVFS* buf);
}

// ---- State ----
final class FS {
    string devname;
    string dir;
    bool   selected;
}

__gshared ulong optBlockSize = 512;
__gshared bool  optPortable  = false;
__gshared bool  optTotalFlag = false;

__gshared FS[] mounts;

// /proc/self/mounts escapes spaces as \040 etc.
@system string decodeTok(string s) {
    // backtick literals avoid D escape processing
    return s.replace(`\040`, " ")
            .replace(`\011`, "\t")
            .replace(`\012`, "\n")
            .replace(`\134`, `\`);
}

@system int loadMounts() {
    string txt;
    try { txt = readText("/proc/self/mounts"); }
    catch (Exception e) {
        stderr.writeln("df: failed to read /proc/self/mounts: ", e.msg);
        return 1;
    }

    foreach (line; txt.split('\n')) {
        auto L = line.strip;
        if (!L.length) continue;
        auto cols = L.split(" ");
        if (cols.length < 2) continue;
        auto dev = decodeTok(cols[0]);
        auto dir = decodeTok(cols[1]);
        auto f = new FS;
        f.devname = dev;
        f.dir = dir;
        f.selected = false;
        mounts ~= f;
    }
    return 0;
}

@system bool statOne(string path, out ulong total, out ulong used, out ulong avail) {
    StatVFS s;
    if (c_statvfs(path.toStringz, &s) != 0) return false;

    // Prefer f_frsize if nonzero, else f_bsize
    ulong blksz = s.f_frsize != 0 ? s.f_frsize : s.f_bsize;

    // Convert blocks to requested units
    auto toUnits = (ulong blocks) => (blocks * blksz) / optBlockSize;

    total = toUnits(s.f_blocks);
    auto free_ = toUnits(s.f_bfree);
    avail = toUnits(s.f_bavail);
    used  = total >= free_ ? total - free_ : 0;
    return true;
}

@system void header() {
    if (optPortable)
        writefln("Filesystem         %4s-blocks      Used Available Capacity Mounted on", optBlockSize);
    else
        writefln("Filesystem         %4s-blocks      Used Available Use%% Mounted on", optBlockSize);
}

@system int printFS(const FS e) {
    ulong total, used, avail;
    if (!statOne(e.dir, total, used, avail)) {
        stderr.writeln("df: ", e.dir, ": statvfs failed");
        return 1;
    }
    if (total == 0) return 0;

    auto pct = ((total - avail) * 100) / total;

    if (optPortable)
        writefln("%-20s %9s %9s %9s %7s%% %s",
                 e.devname, total, used, avail, pct, e.dir);
    else
        writefln("%-20s %9s %9s %9s %3s%% %s",
                 e.devname, total, used, avail, pct, e.dir);
    return 0;
}

@system void selectAll() { foreach (ref m; mounts) m.selected = true; }

@system void selectByPaths(string[] paths) {
    foreach (ref m; mounts) m.selected = false;

    foreach (p; paths) {
        size_t best = size_t.max, bestLen = 0;
        foreach (i, m; mounts) {
            if (p.length >= m.dir.length && p.startsWith(m.dir)) {
                if (m.dir.length > bestLen) { best = i; bestLen = m.dir.length; }
            }
        }
        if (best != size_t.max) mounts[best].selected = true;
    }

    bool any = false; foreach (m; mounts) if (m.selected) { any = true; break; }
    if (!any) selectAll();
}

@system int main(string[] args) {
    bool kFlag = false, pFlag = false, tFlag = false;

    auto opt = getopt(args,
        config.passThrough,
        "k", &kFlag,
        "P|portability", &pFlag,
        "t", &tFlag
    );
    auto paths = args;


    if (kFlag) optBlockSize = 1024;
    optPortable  = pFlag;
    optTotalFlag = tFlag; // kept for CLI parity

    if (auto rc = loadMounts()) return rc;

    if (paths.length == 0) selectAll();
    else                   selectByPaths(paths);

    header();
    int rc = 0;
    foreach (m; mounts) if (m.selected) rc |= printFS(m);
    return rc;
}
