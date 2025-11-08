/**
 * D port of:
 *   chown - change file owner and group
 * Also behaves like chgrp when invoked as "chgrp".
 *
 * Usage:
 *   chown_d [-h] [-H|-L|-P] [-R] owner[:group] file...
 *   chgrp_d [-h] [-H|-L|-P] [-R] group file...
 *
 * Options:
 *   -h   change symlink itself (only for path arguments; not for found entries)
 *   -H   follow symlinked dirs on the command line
 *   -L   follow all symlinks to dirs (during traversal)
 *   -P   do not follow symlinks (default)
 *   -R   recurse into directories
 *
 * Notes:
 * - Owner/group may be names or numeric IDs.
 * - If invoked as "chgrp*", only the group is taken from the first operand.
 */

module chown_d;

import core.sys.posix.unistd : chown, lchown;
import core.sys.posix.sys.stat : stat, lstat, stat_t, S_ISDIR, S_ISLNK;
import core.sys.posix.dirent : DIR, dirent, opendir, readdir, closedir;
import core.sys.posix.pwd : passwd, getpwnam;
import core.sys.posix.grp : group, getgrnam;
import core.sys.posix.sys.types : uid_t, gid_t;
import core.stdc.errno : errno;
import core.stdc.string : strerror;

import std.stdio : writeln, stderr, writefln;
import std.file : exists;
import std.path : baseName, buildPath;
import std.string : fromStringz, indexOf;
import std.conv : to, ConvException;

enum FollowMode { H, L, P }

struct Opts {
    bool changeLinkSelfArg = false; // -h
    FollowMode follow = FollowMode.P;
    bool recurse = false;           // -R
    bool actAsChgrp = false;        // name begins with "chgrp"
    // Targets; -1 means "unspecified"
    long uid = -1;
    long gid = -1;
}

private void perr(string what, string path)
{
    auto msg = fromStringz(strerror(errno));
    stderr.writefln("%s: %s: %s", what, path, msg);
}

private bool parseUID(string s, out long uid)
{
    // Try name first
    auto pw = getpwnam(s.ptr);
    if (pw !is null) { uid = pw.pw_uid; return true; }
    // Then numeric
    try { uid = s.to!long; return true; } catch (ConvException) {}
    return false;
}

private bool parseGID(string s, out long gid)
{
    // Try name first
    auto gr = getgrnam(s.ptr);
    if (gr !is null) { gid = gr.gr_gid; return true; }
    // Then numeric
    try { gid = s.to!long; return true; } catch (ConvException) {}
    return false;
}

private bool setOwnerGroup(ref Opts o, string ownerGroup, bool chgrpMode)
{
    if (chgrpMode) {
        if (!parseGID(ownerGroup, o.gid)) {
            stderr.writefln("invalid group '%s'", ownerGroup);
            return false;
        }
        return true;
    }

    // owner[:group]
    auto c = ownerGroup.indexOf(':');
    if (c < 0) {
        if (!parseUID(ownerGroup, o.uid)) {
            stderr.writefln("invalid owner '%s'", ownerGroup);
            return false;
        }
        return true;
    } else {
        auto owner = ownerGroup[0 .. c];
        auto group = ownerGroup[c + 1 .. $];
        if (owner.length && !parseUID(owner, o.uid)) {
            stderr.writefln("invalid owner '%s'", owner);
            return false;
        }
        if (group.length && !parseGID(group, o.gid)) {
            stderr.writefln("invalid group '%s'", group);
            return false;
        }
        return true;
    }
}

private bool needChown(ref Opts o, ref stat_t st)
{
    if (o.uid != -1 && st.st_uid != o.uid) return true;
    if (o.gid != -1 && st.st_gid != o.gid) return true;
    return false;
}

private int doChown(string path, bool linkItself, ref Opts o)
{
    // Choose uid/gid parameters; POSIX sentinel is (uid_t)-1 / (gid_t)-1.
    uid_t uidParam = (o.uid == -1) ? cast(uid_t)-1 : cast(uid_t)o.uid;
    gid_t gidParam = (o.gid == -1) ? cast(gid_t)-1 : cast(gid_t)o.gid;

    int rc = linkItself ? lchown(path.ptr, uidParam, gidParam)
                        :  chown (path.ptr, uidParam, gidParam);
    if (rc < 0) { perr("chown", path); return 1; }
    return 0;
}

private bool lstatOK(string path, out stat_t st)
{
    if (lstat(path.ptr, &st) < 0) return false;
    return true;
}

private bool statOK(string path, out stat_t st)
{
    if (stat(path.ptr, &st) < 0) return false;
    return true;
}

private int processEntry(string path, ref Opts o, bool isCmdline);

private int recurseDir(string path, ref Opts o)
{
    auto d = opendir(path.ptr);
    if (d is null) { perr("opendir", path); return 1; }

    scope(exit) closedir(d);
    int status = 0;

    dirent* e;
    while ((e = readdir(d)) !is null)
    {
        auto name = fromStringz(e.d_name);
        if (name == "." || name == "..") continue;
        auto child = buildPath(path, name);
        status |= processEntry(child, o, false);
    }
    return status;
}

private int processSymlink(string path, ref Opts o, bool isCmdline)
{
    // -h applies to symlink itself only for path arguments
    int status = 0;
    if (isCmdline && o.changeLinkSelfArg)
        status |= doChown(path, /*link*/true, o);

    // Follow rules for recursion
    if (!o.recurse) return status;

    // Decide if we should follow the link into a directory
    stat_t st;
    const followThis =
        (o.follow == FollowMode.L) ||
        (o.follow == FollowMode.H && isCmdline);

    if (!followThis) return status;
    if (!statOK(path, st)) { perr("stat", path); return status | 1; }
    if (!S_ISDIR(st.st_mode)) return status;

    // When following the link, chown affects the target (not the link)
    // We don't change the link itself here unless -h was set above.
    status |= recurseDir(path, o);
    return status;
}

private int processNonLink(string path, ref Opts o, ref stat_t lst, bool /*isCmdline*/)
{
    int status = 0;

    // Change owner/group if needed
    if (needChown(o, lst))
        status |= doChown(path, /*link*/false, o);

    // Recurse if directory
    if (o.recurse && S_ISDIR(lst.st_mode))
        status |= recurseDir(path, o);

    return status;
}

private int processEntry(string path, ref Opts o, bool isCmdline)
{
    stat_t lst;
    if (!lstatOK(path, lst)) { perr("lstat", path); return 1; }

    if (S_ISLNK(lst.st_mode))
        return processSymlink(path, o, isCmdline);

    return processNonLink(path, o, lst, isCmdline);
}

int main(string[] argv)
{
    Opts o;
    auto prog = (argv.length ? baseName(argv[0]) : "chown_d");
    if (prog.length >= 5 && prog[0 .. 5] == "chgrp")
        o.actAsChgrp = true;

    // Parse options
    string ownerGroup;
    string[] files;
    bool endOpts = false;
    int status = 0;

    for (size_t i = 1; i < argv.length; ++i)
    {
        auto a = argv[i];
        if (!endOpts && a.length && a[0] == '-')
        {
            if (a == "--") { endOpts = true; continue; }
            if (a == "-")  { files ~= a; continue; } // treat "-" as filename (accepted)

            // short options cluster
            foreach (ch; a[1 .. $])
            {
                // Use a normal switch (not final), so we can have a default branch.
                switch (ch)
                {
                    case 'h': o.changeLinkSelfArg = true; break;
                    case 'H': o.follow = FollowMode.H; break;
                    case 'L': o.follow = FollowMode.L; break;
                    case 'P': o.follow = FollowMode.P; break;
                    case 'R': o.recurse = true; break;
                    default:
                        stderr.writefln("Usage: %s [-h] [-H|-L|-P] [-R] %s",
                            prog, o.actAsChgrp ? "group file..." : "owner[:group] file...");
                        return 1;
                }
            }
            continue;
        }
        if (ownerGroup.length == 0) ownerGroup = a;
        else files ~= a;
    }

    if (ownerGroup.length == 0 || files.length == 0)
    {
        stderr.writefln("Usage: %s [-h] [-H|-L|-P] [-R] %s",
            prog, o.actAsChgrp ? "group file..." : "owner[:group] file...");
        return 1;
    }

    if (!setOwnerGroup(o, ownerGroup, o.actAsChgrp))
        return 1;

    // If not recursive, -H/-L are irrelevant; we still honor -h on cmdline symlinks.
    foreach (f; files)
        status |= processEntry(f, o, /*isCmdline*/true);

    return status ? 1 : 0;
}
