// touch.d — D port of posixutils "touch" (Jeff Garzik)
//
// Build (POSIX):
//   ldc2 -O2 -release touch.d
// or without Phobos/GC:
//   ldc2 -O2 -release -betterC touch.d
//
// Usage:
//   touch [-a] [-c] [-m] [-r FILE] [-t STAMP] FILE...

extern (C):
version (Posix) {} else static assert(0, "POSIX required.");

import core.stdc.config;
import core.stdc.stdlib : exit, EXIT_FAILURE, EXIT_SUCCESS;
import core.stdc.stdio  : fprintf, stderr, perror, printf, sscanf;
import core.stdc.string : strlen, strchr, memset, strcmp;
import core.stdc.errno  : errno, ENOENT;
import core.stdc.time   : time_t, time, tm, mktime, localtime; // use localtime (not localtime_r)
import core.sys.posix.sys.stat : stat_t, c_stat = stat,
                                 S_IRUSR, S_IWUSR, S_IRGRP, S_IWGRP, S_IROTH, S_IWOTH;
import core.sys.posix.utime    : utimbuf, utime;
import core.sys.posix.fcntl    : creat;
import core.sys.posix.unistd   : close; // for closing the creat() fd

// Some druntime builds don’t provide core.stdc.getopt.
// Declare the POSIX getopt symbols explicitly.
extern(C) nothrow @nogc {
    int getopt(int argc, char** argv, const char* optstring);
    extern __gshared char* optarg;
    extern __gshared int optind;
    extern __gshared int opterr;
}

enum PFX = "touch: ";

__gshared bool  optDefault = true;
__gshared bool  optAtime;
__gshared bool  optCreatOk = true;
__gshared bool  optMtime;
__gshared bool  optRefFile;
__gshared time_t touchAtime, touchMtime, touchTimeNow;
__gshared stat_t touchRefStat;

/// Parse STAMP like GNU/coreutils:
///   [[CC]YY]MMDDhhmm[.ss]
static void parseUserTime(char* ut) @nogc nothrow
{
    tm tminfo;
    memset(&tminfo, 0, tminfo.sizeof);

    char* suff = strchr(ut, '.');
    if (suff) { *suff = 0; ++suff; }

    touchTimeNow = time(null);

    if (strlen(ut) == 8)
    {
        auto curp = localtime(&touchTimeNow);
        if (curp) tminfo = *curp;

        int mon = 0, mday = 0, hour = 0, min = 0;
        const int rc = sscanf(ut, "%02d%02d%02d%02d", &mon, &mday, &hour, &min);
        if (rc != 4) { fprintf(stderr, "%sinvalid time spec\n", PFX.ptr); exit(EXIT_FAILURE); }
        tminfo.tm_mon  = mon - 1;
        tminfo.tm_mday = mday;
        tminfo.tm_hour = hour;
        tminfo.tm_min  = min;
    }
    else if (strlen(ut) == 10)
    {
        int yy = 0, mon = 0, mday = 0, hour = 0, min = 0;
        const int rc = sscanf(ut, "%02d%02d%02d%02d%02d", &yy, &mon, &mday, &hour, &min);
        if (rc != 5) { fprintf(stderr, "%sinvalid time spec\n", PFX.ptr); exit(EXIT_FAILURE); }
        int fullYear = (yy >= 69) ? (1900 + yy) : (2000 + yy);
        tminfo.tm_year = fullYear - 1900;
        tminfo.tm_mon  = mon - 1;
        tminfo.tm_mday = mday;
        tminfo.tm_hour = hour;
        tminfo.tm_min  = min;
        tminfo.tm_sec  = 0;
    }
    else if (strlen(ut) == 12)
    {
        int yyyy = 0, mon = 0, mday = 0, hour = 0, min = 0;
        const int rc = sscanf(ut, "%04d%02d%02d%02d%02d", &yyyy, &mon, &mday, &hour, &min);
        if (rc != 5) { fprintf(stderr, "%sinvalid time spec\n", PFX.ptr); exit(EXIT_FAILURE); }
        tminfo.tm_year = yyyy - 1900;
        tminfo.tm_mon  = mon - 1;
        tminfo.tm_mday = mday;
        tminfo.tm_hour = hour;
        tminfo.tm_min  = min;
        tminfo.tm_sec  = 0;
    }
    else
    {
        fprintf(stderr, "%sinvalid time spec\n", PFX.ptr);
        exit(EXIT_FAILURE);
    }

    if (suff)
    {
        int ss = 0;
        const int rc2 = sscanf(suff, "%02d", &ss);
        if (rc2 != 1) { fprintf(stderr, "%sinvalid time spec\n", PFX.ptr); exit(EXIT_FAILURE); }
        tminfo.tm_sec = ss;
    }

    touchTimeNow = mktime(&tminfo);
}

/// Apply utime on one file; create file unless -c
static int touchOne(const char* path) @nogc
{
    utimbuf ut;
    ut.actime  = touchAtime;
    ut.modtime = touchMtime;

    // If user didn't specify both times, try to preserve the other from the file.
    if (!optAtime || !optMtime)
    {
        stat_t st;
        if (c_stat(path, &st) == 0)
        {
            if (!optAtime)  ut.actime  = cast(time_t) st.st_atime;
            if (!optMtime)  ut.modtime = cast(time_t) st.st_mtime;
        }
        else if (errno != ENOENT)
        {
            perror(path);
            return 1;
        }
        // If ENOENT, we'll potentially create the file below and use the chosen times.
    }

    int triedCreate = 0;
    for (;;)
    {
        if (utime(path, &ut) == 0)
            return 0;

        if (errno != ENOENT)
        {
            perror(path);
            return 1;
        }

        if (!optCreatOk || triedCreate)
            return 1;

        // Create then retry utime (rw-rw-rw-)
        int fd = creat(path, S_IRUSR | S_IWUSR |
                              S_IRGRP | S_IWGRP |
                              S_IROTH | S_IWOTH);
        if (fd < 0)
        {
            perror(path);
            return 1;
        }
        // Close the descriptor and retry utime.
        close(fd);
        triedCreate = 1;
    }
}

int main(int argc, char** argv)
{
    opterr = 0;
    touchTimeNow = time(null);

    for (;;)
    {
        int c = getopt(argc, argv, "acmr:t:");
        if (c == -1) break;

        switch (c)
        {
        case 'a':
            optDefault = false; optAtime = true; break;
        case 'c':
            optCreatOk = false; break;
        case 'm':
            optDefault = false; optMtime = true; break;
        case 'r':
            if (c_stat(optarg, &touchRefStat) < 0) { perror(optarg); return EXIT_FAILURE; }
            optRefFile = true;
            break;
        case 't':
            optRefFile = false;
            parseUserTime(optarg);
            break;
        default:
            fprintf(stderr, "%sinvalid option\n", PFX.ptr);
            return EXIT_FAILURE;
        }
    }

    if (optDefault) { optAtime = true; optMtime = true; }

    if (optRefFile)
    {
        touchAtime = cast(time_t) touchRefStat.st_atime;
        touchMtime = cast(time_t) touchRefStat.st_mtime;
    }
    else
    {
        touchAtime = touchTimeNow;
        touchMtime = touchTimeNow;
    }

    if (optind >= argc)
    {
        fprintf(stderr, "%smissing file operand\n", PFX.ptr);
        return EXIT_FAILURE;
    }

    int rc = 0;
    for (int i = optind; i < argc; ++i)
        if (touchOne(argv[i]) != 0) rc = 1;

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
