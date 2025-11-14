module id_d;

import std.stdio : stdout, stderr, writeln, writef, writefln;
import std.getopt : getopt;
import std.string : toStringz, fromStringz;
import std.conv   : to;

import core.sys.posix.sys.types : uid_t, gid_t;
import core.sys.posix.unistd : getuid, geteuid, getgid, getegid;
import core.sys.posix.pwd : passwd, getpwnam, getpwuid;
import core.sys.posix.grp : group, getgrgid, getgrent, setgrent, endgrent;
import core.stdc.errno : errno;
import core.stdc.string : strcmp;
import core.stdc.stdio : perror;

enum OptMode { DEF, GRP_ALL, EGID, EUID }

__gshared bool optName    = false; // -n
__gshared bool optRealID  = false; // -r
__gshared OptMode optMode = OptMode.DEF;

__gshared string optUser;          // optional [user]

bool userInGroup(const group* gr)
{
    if (optUser.length == 0) return false;
    if (gr is null || gr.gr_mem is null) return false;

    size_t i = 0;
    while (gr.gr_mem[i] !is null)
    {
        if (strcmp(gr.gr_mem[i], optUser.toStringz) == 0)
            return true;
        ++i;
    }
    return false;
}

struct GrpEnt { gid_t gid; string name; }

bool matchGroups(gid_t gid, gid_t egid, ref GrpEnt[] outv)
{
    outv.length = 0;
    setgrent();
    scope(exit) endgrent();

    while (true)
    {
        errno = 0;
        auto gr = getgrent();
        if (gr is null)
        {
            if (errno != 0)
                perror("getgrent");
            break;
        }

        if (gr.gr_gid == gid || gr.gr_gid == egid || userInGroup(gr))
        {
            // CHANGE: .idup so it's an immutable string
            outv ~= GrpEnt(gr.gr_gid, fromStringz(gr.gr_name).idup);
        }
    }
    return true;
}

void prUID(uid_t uid, bool space, bool newline)
{
    if (optName)
    {
        errno = 0;
        auto pw = getpwuid(uid);
        if (pw is null && errno != 0)
            perror("warning(getpwuid)");
        if (pw !is null)
        {
            writef("%s%s%s", space ? " " : "", fromStringz(pw.pw_name), newline ? "\n" : "");
            return;
        }
    }
    writef("%s%llu%s", space ? " " : "", cast(ulong)uid, newline ? "\n" : "");
}

void prGID(gid_t gid, bool space, bool newline)
{
    if (optName)
    {
        errno = 0;
        auto gr = getgrgid(gid);
        if (gr is null && errno != 0)
            perror("warning(getgrgid)");
        if (gr !is null)
        {
            writef("%s%s%s", space ? " " : "", fromStringz(gr.gr_name), newline ? "\n" : "");
            return;
        }
    }
    writef("%s%llu%s", space ? " " : "", cast(ulong)gid, newline ? "\n" : "");
}

int idGrpAll(ref GrpEnt[] grp, gid_t gid, gid_t egid)
{
    foreach (i, g; grp)
    {
        auto s = optName ? g.name : (cast(ulong)g.gid).to!string;
        writef("%s%s%s", (i == 0) ? "" : " ", s, (i == grp.length - 1) ? "\n" : "");
    }
    if (grp.length == 0) writeln();
    return 0;
}

int idDef(uid_t uid, uid_t euid, gid_t gid, gid_t egid, ref GrpEnt[] grp)
{
    const haveOptUser = (optUser.length != 0);
    writef("uid=%llu%s%s%s",
           cast(ulong)uid,
           haveOptUser ? "(" : "",
           haveOptUser ? optUser : "",
           haveOptUser ? ")" : "");

    if (uid != euid)
    {
        auto pw = getpwuid(euid);
        writef(" euid=%llu%s%s%s",
               cast(ulong)euid,
               pw ? "(" : "",
               pw ? fromStringz(pw.pw_name) : "",
               pw ? ")" : "");
    }

    auto gr = getgrgid(gid);
    writef(" gid=%llu%s%s%s",
           cast(ulong)gid,
           gr ? "(" : "",
           gr ? fromStringz(gr.gr_name) : "",
           gr ? ")" : "");

    if (gid != egid)
    {
        auto gr2 = getgrgid(egid);
        writef(" egid=%llu%s%s%s",
               cast(ulong)egid,
               gr2 ? "(" : "",
               gr2 ? fromStringz(gr2.gr_name) : "",
               gr2 ? ")" : "");
    }

    if (grp.length)
    {
        writef(" groups=");
        foreach (i, g; grp)
        {
            writef("%s%llu(%s)",
                   (i == 0) ? "" : ",",
                   cast(ulong)g.gid,
                   g.name);
        }
    }

    writeln();
    return 0;
}

int doID()
{
    uid_t uid, euid;
    gid_t gid, egid;

    if (optUser.length != 0)
    {
        errno = 0;
        auto pw = getpwnam(optUser.toStringz);
        if (pw is null)
        {
            if (errno != 0)
                perror(optUser.toStringz);
            else
                stderr.writefln("user '%s' not found", optUser);
            return 1;
        }
        uid = pw.pw_uid;
        euid = pw.pw_uid;
        gid = pw.pw_gid;
        egid = pw.pw_gid;
    }
    else
    {
        uid = getuid();
        euid = geteuid();
        gid = getgid();
        egid = getegid();

        if (optRealID)
        {
            euid = uid;
            egid = gid;
        }

        if (optMode == OptMode.GRP_ALL || optMode == OptMode.DEF)
        {
            auto pw = getpwuid(uid);
            if (pw !is null)
                // CHANGE: .idup so optUser is an immutable string
                optUser = fromStringz(pw.pw_name).idup;
        }
    }

    // CHANGE: use plain switch (no 'final') so 'default' is allowed
    switch (optMode)
    {
        case OptMode.EUID: prUID(euid, false, true); return 0;
        case OptMode.EGID: prGID(egid, false, true); return 0;
        default:           break;
    }

    GrpEnt[] grp;
    if (!matchGroups(gid, egid, grp))
        return 1;

    // CHANGE: use plain switch (no 'final')
    switch (optMode)
    {
        case OptMode.GRP_ALL: return idGrpAll(grp, gid, egid);
        case OptMode.DEF:     return idDef(uid, euid, gid, egid, grp);
        default:              return 1;
    }
}

int main(string[] args)
{
    try
    {
        auto res = getopt(
            args,
            "n", &optName,
            "r", &optRealID,
            "g", { optMode = OptMode.EGID; },
            "G", { optMode = OptMode.GRP_ALL; },
            "u", { optMode = OptMode.EUID; }
        );

        auto pos = args[1 .. $];
        if (pos.length > 1)
        {
            stderr.writefln("Usage: %s [user]", args[0]);
            return 2;
        }
        if (pos.length == 1) optUser = pos[0];
    }
    catch (Exception e)
    {
        stderr.writeln(e.msg);
        return 2;
    }

    return doID();
}
