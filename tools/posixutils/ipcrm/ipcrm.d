// ipcrm.d — D port of the provided C/C++ ipcrm
module ipcrm_d;

import std.stdio   : stderr, writefln, writeln;
import std.getopt  : getopt;
import std.string  : toStringz, fromStringz;

// ---------------- C / POSIX bindings ----------------
extern (C)
{
    // errno / strerror
    import core.stdc.errno  : errno;
    import core.stdc.string : strerror;

    // Provide our own binding for strtoul that accepts const(char)* and char**.
    // This matches glibc's C signature and sidesteps druntime's inout qualifiers.
    pragma(mangle, "strtoul")
    ulong c_strtoul(const(char)* nptr, char** endptr, int base);

    // SysV IPC common pieces
    import core.sys.posix.sys.ipc : key_t, IPC_PRIVATE, IPC_RMID;
    import core.sys.posix.sys.msg : msgget, msgctl;
    import core.sys.posix.sys.shm : shmget, shmctl;

    // Some druntime packages don't ship a SysV sem header module.
    // Declare the two functions we need explicitly.
    int  semget(key_t key, int nsems, int semflg);
    int  semctl(int semid, int semnum, int cmd, ...);
}

// ---------------- Masks (same bit layout as the C version) ----------------
enum OPT_MSG = 1 << 0;
enum OPT_SHM = 1 << 1;
enum OPT_SEM = 1 << 2;
enum OPT_KEY = 1 << 3;

struct ArgEnt {
    int   mask;
    ulong arg; // id or key
}

// We collect all actions and then perform them
ArgEnt[] arglist;

// Exit status mirrors original behavior: success unless any failure occurs
int exitStatus = 0;

// ---------------- Helpers ----------------
string argName(int mask)
{
    if ((mask & OPT_MSG) != 0) return "msg";
    if ((mask & OPT_SHM) != 0) return "shm";
    if ((mask & OPT_SEM) != 0) return "sem";
    return "?";
}

void pushOpt(int mask, ulong val)
{
    arglist ~= ArgEnt(mask, val);
}

// Parse numeric argument
// For KEY options => base = 0 (auto: 0x.., 0.., dec).
// For ID options  => base = 10.
void pushArgOpt(int mask, string s)
{
    int baseVal = ((mask & OPT_KEY) != 0) ? 0 : 10;
    char* endptr = null;

    // use our const-correct binding
    auto val = c_strtoul(s.toStringz, &endptr, baseVal);

    bool fullyParsed = (endptr !is null) && (*endptr == '\0');
    bool isBadKey    = ((mask & OPT_KEY) != 0) && (val == IPC_PRIVATE);

    if (!fullyParsed || isBadKey)
    {
        stderr.writefln("%s%s '%s' invalid",
            argName(mask),
            ((mask & OPT_KEY) != 0) ? "key" : "id",
            s);
        exitStatus = 1;
        return;
    }

    pushOpt(mask, cast(ulong) val);
}

void pinterr(ulong l)
{
    // "key 0x%x lookup failed: %s"
    stderr.writefln("key 0x%x lookup failed: %s", l, fromStringz(strerror(errno)));
    exitStatus = 1;
}

void removeOne(const ArgEnt ae)
{
    int id;
    string errmsg; // use D string for formatter

    if ((ae.mask & OPT_KEY) != 0)
    {
        // lookup by key
        const key = cast(key_t) ae.arg;
        if      ((ae.mask & OPT_MSG) != 0) id = msgget(key, 0);
        else if ((ae.mask & OPT_SHM) != 0) id = shmget(key, 0, 0);
        else if ((ae.mask & OPT_SEM) != 0) id = semget(key, 0, 0);
        else { assert(0); }

        if (id < 0) {
            pinterr(ae.arg);
            return;
        }
    }
    else
    {
        // direct id path
        id = cast(int) ae.arg;
    }

    int rc;
    if      ((ae.mask & OPT_MSG) != 0) { rc = msgctl(id, IPC_RMID, null); errmsg = "msgctl(0x%x): %s\n"; }
    else if ((ae.mask & OPT_SHM) != 0) { rc = shmctl(id, IPC_RMID, null); errmsg = "shmctl(0x%x): %s\n"; }
    else if ((ae.mask & OPT_SEM) != 0)
    {
        // semctl is variadic; Linux allows passing 0 for the union.
        rc = semctl(id, 0, IPC_RMID, 0);
        errmsg = "semctl(0x%x): %s\n";
    }
    else { assert(0); }

    if (rc < 0) {
        stderr.writefln(errmsg, id, fromStringz(strerror(errno)));
        exitStatus = 1;
    }
}

// ---------------- Main ----------------
int main(string[] args)
{
    // Options:
    //  -q msgid   (remove message queue by id)
    //  -m shmid   (remove shared memory by id)
    //  -s semid   (remove semaphore by id)
    //  -Q msgkey  (remove message queue by key)
    //  -M shmkey  (remove shared memory by key)
    //  -S semkey  (remove semaphore by key)

    string qArg, mArg, sArg, QArg, MArg, SArg;

    try {
        auto help = getopt(
            args,
            "q", &qArg,
            "m", &mArg,
            "s", &sArg,
            "Q", &QArg,
            "M", &MArg,
            "S", &SArg
        );
        // no positionals expected
    } catch (Exception e) {
        stderr.writeln(e.msg);
        return 2;
    }

    if (qArg.length) pushArgOpt(OPT_MSG, qArg);
    if (mArg.length) pushArgOpt(OPT_SHM, mArg);
    if (sArg.length) pushArgOpt(OPT_SEM, sArg);

    if (QArg.length) pushArgOpt(OPT_MSG | OPT_KEY, QArg);
    if (MArg.length) pushArgOpt(OPT_SHM | OPT_KEY, MArg);
    if (SArg.length) pushArgOpt(OPT_SEM | OPT_KEY, SArg);

    // Perform removals
    foreach (ae; arglist)
        removeOne(ae);

    return exitStatus;
}
