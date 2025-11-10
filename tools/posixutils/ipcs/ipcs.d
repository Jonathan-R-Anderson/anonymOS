// ipcs.d — D port of the provided C ipcs
module ipcs_d;

import std.stdio : stdout, stderr, writefln, writeln, writef, writefln;
import std.getopt : getopt;
import std.string : toStringz, fromStringz;
import std.conv   : to, octal;

// uname
import core.sys.posix.sys.utsname : utsname, uname;
// time
import core.stdc.time : time_t, time, strftime, tm;
import core.sys.posix.time : localtime_r;
// errno/strerror
import core.stdc.errno : errno;
import core.stdc.string : strerror;

// SysV IPC
import core.sys.posix.sys.ipc : key_t;
import core.sys.posix.sys.msg : msqid_ds, msginfo, msgctl;
import core.stdc.config : c_ulong;
import ipcs.sem_compat : semid_ds, seminfo, semctl;

version (linux)
{
    import core.sys.linux.sys.shm : shmid_ds, shminfo, shmctl;
}
else version (OSX)
{
    import core.sys.darwin.sys.shm : shmid_ds, shminfo, shmctl;
}
else
{
    import core.sys.posix.sys.shm : shmid_ds, shmctl;

    // Fallback definition for platforms where shminfo is not exposed by druntime.
    struct shminfo
    {
        // These fields mirror the SysV IPC shminfo layout but are unused by the
        // implementation; they exist solely to satisfy the shmctl interface.
        c_ulong shmmax;
        c_ulong shmmin;
        c_ulong shmmni;
        c_ulong shmseg;
        c_ulong shmall;
    }
}

// --- GNU extensions (command constants) ---
enum int MSG_INFO = 12;
enum int MSG_STAT = 11;
enum int SHM_INFO = 14;
enum int SHM_STAT = 13;
enum int SEM_INFO = 19;
enum int SEM_STAT = 18;
enum int IPC_RMID = 0;

// X/Open requires us to define semun ourselves
union semun {
    int            val;
    semid_ds*      buf;
    ushort*        array;
    seminfo*       __buf;
}

// ---------------- CLI options ----------------
enum IOPT_MSG = 1 << 0;
enum IOPT_SHM = 1 << 1;
enum IOPT_SEM = 1 << 2;
enum IOPT_ALL = IOPT_MSG | IOPT_SHM | IOPT_SEM;

enum ROPT_SIZE    = 1 << 0;
enum ROPT_CREATOR = 1 << 1;
enum ROPT_OUTST   = 1 << 2;
enum ROPT_PROC    = 1 << 3;
enum ROPT_TIME    = 1 << 4;
enum ROPT_ALL     = ROPT_SIZE | ROPT_CREATOR | ROPT_OUTST | ROPT_PROC | ROPT_TIME;

__gshared uint optInfo  = 0;
__gshared uint optPrint = 0;

// ---------------- Small helpers for libc field name variations ----------------
private ulong ipcKey(T)(ref T perm) {
    static if (__traits(compiles, perm.__key)) return perm.__key;
    else static if (__traits(compiles, perm.key)) return perm.key;
    else return 0;
}

private ulong msgCbytes(ref msqid_ds ds) {
    static if (__traits(compiles, ds.__msg_cbytes)) return ds.__msg_cbytes;
    else static if (__traits(compiles, ds.msg_cbytes)) return ds.msg_cbytes;
    else return 0;
}

// ---------------- Header ----------------
int printHeader()
{
    utsname uts;
    if (uname(&uts) < 0) {
        stderr.writefln("uname: %s", strerror(errno));
        return 1;
    }

    time_t now = 0;
    now = time(null);
    if (now == cast(time_t) -1) {
        stderr.writefln("time: %s", strerror(errno));
        return 1;
    }

    tm tmb;
    if (localtime_r(&now, &tmb) is null) {
        stderr.writefln("localtime_r: %s", strerror(errno));
        return 1;
    }

    char[64] buf;
    auto n = strftime(buf.ptr, buf.length, "%a, %d %b %Y %H:%M:%S %Z", &tmb);
    if (n < 15) {
        stderr.writeln("strftime(3) failed");
        return 1;
    }

    writefln("IPC status from %s as of %s", fromStringz(uts.nodename.ptr), fromStringz(buf.ptr));
    return 0;
}

// ---------------- Message Queues ----------------
int printMsg()
{
    writeln("Message queues:");
    msginfo mi;
    // Per GNU ipcs: msgctl(0, MSG_INFO, (struct msqid_ds *)&mi) returns highest index
    auto maxq = msgctl(0, MSG_INFO, cast(msqid_ds*)&mi);
    if (maxq < 0) {
        stderr.writefln("msgctl: %s", strerror(errno));
        return 1;
    }

    for (int mq = 0; mq <= maxq; ++mq) {
        msqid_ds ds;
        auto rc = msgctl(mq, MSG_STAT, &ds);
        if (rc < 0) continue;

        // Columns: type, id, key, perms (as bits), uid, gid
        writef("m %d 0x%x --%c%c%c%c%c%c%c%c%c %d %d",
               mq,
               cast(uint) ipcKey(ds.msg_perm),
               (ds.msg_perm.mode & octal!"400") ? 'r' : '-', // user read
               (ds.msg_perm.mode & octal!"200") ? 'w' : '-', // user write
               (ds.msg_perm.mode & octal!"200") ? 'a' : '-', // user alter
               (ds.msg_perm.mode & octal!"40") ? 'r' : '-', // group read
               (ds.msg_perm.mode & octal!"20") ? 'w' : '-', // group write
               (ds.msg_perm.mode & octal!"20") ? 'a' : '-', // group alter
               (ds.msg_perm.mode & octal!"4") ? 'r' : '-', // other read
               (ds.msg_perm.mode & octal!"2") ? 'w' : '-', // other write
               (ds.msg_perm.mode & octal!"2") ? 'a' : '-', // other alter
               ds.msg_perm.uid,
               ds.msg_perm.gid);

        if ((optPrint & ROPT_CREATOR) != 0)
            writef(" %d %d", ds.msg_perm.cuid, ds.msg_perm.cgid);

        if ((optPrint & ROPT_OUTST) != 0)
            writef(" %lu %lu", msgCbytes(ds), ds.msg_qnum);

        if ((optPrint & ROPT_SIZE) != 0)
            writef(" %lu", ds.msg_qbytes);

        if ((optPrint & ROPT_PROC) != 0)
            writef(" %d %d", ds.msg_lspid, ds.msg_lrpid);

        if ((optPrint & ROPT_TIME) != 0)
            writef(" %lu %lu", ds.msg_stime, ds.msg_rtime);

        writefln(" %lu", ds.msg_ctime);
    }

    return 0;
}

// ---------------- Shared Memory ----------------
int printShm()
{
    writeln("Shared memory:");
    shminfo shi;
    auto maxshm = shmctl(0, SHM_INFO, cast(shmid_ds*)&shi);
    if (maxshm < 0) {
        stderr.writefln("shmctl: %s", strerror(errno));
        return 1;
    }

    for (int id = 0; id <= maxshm; ++id) {
        shmid_ds ds;
        auto rc = shmctl(id, SHM_STAT, &ds);
        if (rc < 0) continue;

        writef("m %d 0x%x --%c%c%c%c%c%c%c%c%c %d %d",
               id,
               cast(uint) ipcKey(ds.shm_perm),
               (ds.shm_perm.mode & octal!"400") ? 'r' : '-', // user read
               (ds.shm_perm.mode & octal!"200") ? 'w' : '-', // user write
               (ds.shm_perm.mode & octal!"200") ? 'a' : '-', // user alter
               (ds.shm_perm.mode & octal!"40") ? 'r' : '-', // group read
               (ds.shm_perm.mode & octal!"20") ? 'w' : '-', // group write
               (ds.shm_perm.mode & octal!"20") ? 'a' : '-', // group alter
               (ds.shm_perm.mode & octal!"4") ? 'r' : '-', // other read
               (ds.shm_perm.mode & octal!"2") ? 'w' : '-', // other write
               (ds.shm_perm.mode & octal!"2") ? 'a' : '-', // other alter
               ds.shm_perm.uid,
               ds.shm_perm.gid);

        if ((optPrint & ROPT_CREATOR) != 0)
            writef(" %d %d", ds.shm_perm.cuid, ds.shm_perm.cgid);

        if ((optPrint & ROPT_OUTST) != 0)
            writef(" %lu", ds.shm_nattch);

        if ((optPrint & ROPT_SIZE) != 0)
            writef(" %lu", ds.shm_segsz);

        if ((optPrint & ROPT_PROC) != 0)
            writef(" %d %d", ds.shm_cpid, ds.shm_lpid);

        if ((optPrint & ROPT_TIME) != 0)
            writef(" %lu %lu", ds.shm_atime, ds.shm_dtime);

        writefln(" %lu", ds.shm_ctime);
    }

    return 0;
}

// ---------------- Semaphores ----------------
int printSem()
{
    writeln("Semaphores:");

    seminfo sei;
    semun arg;
    // As in GNU ipcs: SEM_INFO returns max index
    arg.array = cast(ushort*) &sei; // matches their API quirk
    auto maxsem = semctl(0, 0, SEM_INFO, arg);
    if (maxsem < 0) {
        stderr.writefln("semctl: %s", strerror(errno));
        return 1;
    }

    for (int sid = 0; sid <= maxsem; ++sid) {
        semid_ds ds;
        arg.buf = &ds;
        auto rc = semctl(sid, 0, SEM_STAT, arg);
        if (rc < 0) continue;

        writef("m %d 0x%x --%c%c%c%c%c%c%c%c%c %d %d",
               sid,
               cast(uint) ipcKey(ds.sem_perm),
               (ds.sem_perm.mode & octal!"400") ? 'r' : '-', // user read
               (ds.sem_perm.mode & octal!"200") ? 'w' : '-', // user write
               (ds.sem_perm.mode & octal!"200") ? 'a' : '-', // user alter
               (ds.sem_perm.mode & octal!"40") ? 'r' : '-', // group read
               (ds.sem_perm.mode & octal!"20") ? 'w' : '-', // group write
               (ds.sem_perm.mode & octal!"20") ? 'a' : '-', // group alter
               (ds.sem_perm.mode & octal!"4") ? 'r' : '-', // other read
               (ds.sem_perm.mode & octal!"2") ? 'w' : '-', // other write
               (ds.sem_perm.mode & octal!"2") ? 'a' : '-', // other alter
               ds.sem_perm.uid,
               ds.sem_perm.gid);

        if ((optPrint & ROPT_CREATOR) != 0)
            writef(" %d %d", ds.sem_perm.cuid, ds.sem_perm.cgid);

        if ((optPrint & ROPT_SIZE) != 0)
            writef(" %lu", ds.sem_nsems);

        if ((optPrint & ROPT_TIME) != 0)
            writef(" %lu", ds.sem_otime);

        writefln(" %lu", ds.sem_ctime);
    }

    return 0;
}

// ---------------- Main ----------------
int main(string[] args)
{
    // Options:
    //  Facilities: -q (msg), -m (shm), -s (sem)
    //  Print: -a(all) = -b -c -o -p -t; -b(size), -c(creator), -o(outstanding),
    //         -p(process), -t(time)
    bool f_q, f_m, f_s, p_a, p_b, p_c, p_o, p_p, p_t;

    try {
        auto help = getopt(
            args,
            "q|msg", &f_q,
            "m|shm", &f_m,
            "s|sem", &f_s,

            "a|all",      &p_a,
            "b|max-size", &p_b,
            "c|creator",  &p_c,
            "o|outstanding", &p_o,
            "p|process",  &p_p,
            "t|time",     &p_t
        );
        // No positionals expected
    } catch (Exception e) {
        stderr.writeln(e.msg);
        return 2;
    }

    if (f_q) optInfo |= IOPT_MSG;
    if (f_m) optInfo |= IOPT_SHM;
    if (f_s) optInfo |= IOPT_SEM;

    if (p_a) optPrint |= ROPT_ALL;
    if (p_b) optPrint |= ROPT_SIZE;
    if (p_c) optPrint |= ROPT_CREATOR;
    if (p_o) optPrint |= ROPT_OUTST;
    if (p_p) optPrint |= ROPT_PROC;
    if (p_t) optPrint |= ROPT_TIME;

    // Defaults (match original)
    if (optInfo == 0)  optInfo  = IOPT_ALL;
    if (optPrint == 0) optPrint = ROPT_PROC;

    if (printHeader() != 0) return 1;

    if ((optInfo & IOPT_MSG) != 0 && printMsg() != 0) return 1;
    if ((optInfo & IOPT_SHM) != 0 && printShm() != 0) return 1;
    if ((optInfo & IOPT_SEM) != 0 && printSem() != 0) return 1;

    return 0;
}
