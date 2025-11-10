module ipcs.sem_compat;

static if (__traits(compiles, { import core.sys.posix.sys.sem; }))
{
    public import core.sys.posix.sys.sem : semid_ds, seminfo, semctl;
}
else
{
    import core.sys.posix.sys.ipc : ipc_perm;
    import core.stdc.config : c_ulong;
    import core.stdc.time : time_t;

    alias sys_ulong_t = c_ulong;

    extern (C):
    struct semid_ds
    {
        ipc_perm sem_perm;
        time_t sem_otime;
        sys_ulong_t __sem_otime_high;
        time_t sem_ctime;
        sys_ulong_t __sem_ctime_high;
        sys_ulong_t sem_nsems;
        sys_ulong_t __glibc_reserved3;
        sys_ulong_t __glibc_reserved4;
    }

    struct seminfo
    {
        int semmap;
        int semmni;
        int semmns;
        int semmnu;
        int semmsl;
        int semopm;
        int semume;
        int semusz;
        int semvmx;
        int semaem;
    }

    int semctl(int semid, int semnum, int cmd, ...);
}
