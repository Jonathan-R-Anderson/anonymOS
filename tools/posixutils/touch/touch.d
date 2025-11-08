// touch.d — D port of posixutils "touch" (Jeff Garzik)
//
// Build (POSIX):
//   ldc2 -O -release touch.d
// or without Phobos/GC:
//   ldc2 -O -release -betterC touch.d
//
// Usage is identical to the original:
//   touch [-a] [-c] [-m] [-r FILE] [-t STAMP] FILE...

extern (C):
version (Posix) {} else static assert(0, "POSIX required.");

import core.stdc.config;
import core.stdc.stdlib : exit, EXIT_FAILURE, EXIT_SUCCESS;
import core.stdc.stdio  : fprintf, stderr, perror, printf;
import core.stdc.string : strlen, strchr, sscanf, memset, strcmp;
import core.stdc.errno  : errno, ENOENT;
import core.stdc.time   : time_t, time, tm, mktime, localtime_r;
import core.sys.posix.sys.stat : stat, stat_t, stat as c_stat;
import core.sys.posix.utime    : utimbuf, utime;
import core.sys.posix.fcntl    : creat;
import core.stdc.getopt        : getopt, optarg, optind, opterr;

enum PFX = "touch: ";

__gshared bool  optDefault = true;
__gshared bool  optAtime;
__gshared bool  optCreatOk = true;
__gshared bool  optMtime;
__gshared bool  optRefFile;
__gshared time_t touchAtime, touchMtime, touchTimeNow;
__gshared stat_t touchRefStat;

///
/// Parse STAMP like GNU/coreutils & your C version:
///   [[CC]YY]MMDDhhmm[.ss]
/// - 8  digits:          MMDDhhmm  (year from current local time)
/// - 10 digits:          YYMMDDhhmm  (1969–2068 rule)
/// - 12 digits:          YYYYMMDDhhmm
/// Optional ".ss" adds seconds.
///
static void parseUserTime(char* ut) @nogc nothrow
{
    tm tminfo;
    memset(&tminfo, 0, tminfo.sizeof);

    // Work on a mutable copy of the pointer for suffix split
    char* suff = strchr(ut, '.');
    if (suff)
    {
        *suff = 0;
        ++suff;
    }

    touchTimeNow = time(null);
    // seed with current local date for the 8-digit case
    if (strlen(ut) == 8)
    {
        tm cur;
        localtime_r(&touchTimeNow, &cur);
        tminfo = cur;

        int mon = 0, mday = 0, hour = 0, min = 0;
        const int rc = sscanf(ut, "%02d%02d%02d%02d",
                              &mon, &mday, &hour, &min);
        if (rc != 4)
        {
            fprintf(stderr, PFX ~ "invalid time spec\n");
            exit(EXIT_FAILURE);
        }
        tminfo.tm_mon  = mon - 1;  // struct tm expects 0..11
        tminfo.tm_mday = mday;
        tminfo.tm_hour = hour;
        tminfo.tm_min  = min;
        // seconds left as-is (from cur)
    }
    else if (strlen(ut) == 10)
    {
        int yy = 0, mon = 0, mday = 0, hour = 0, min = 0;
        const int rc = sscanf(ut, "%02d%02d%02d%02d%02d",
                              &yy, &mon, &mday, &hour, &min);
        if (rc != 5)
        {
            fprintf(stderr, PFX ~ "invalid time spec\n");
            exit(EXIT_FAILURE);
        }
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
        const int rc = sscanf(ut, "%04d%02d%02d%02d%02d",
                              &yyyy, &mon, &mday, &hour, &min);
        if (rc != 5)
        {
            fprintf(stderr, PFX ~ "invalid time spec\n");
            exit(EXIT_FAILURE);
        }
        tminfo.tm_year = yyyy - 1900;
        tminfo.tm_mon  = mon - 1;
        tminfo.tm_mday = mday;
        tminfo.tm_hour = hour;
        tminfo.tm_min  = min;
        tminfo.tm_sec  = 0;
    }
    else
    {
        fprintf(stderr, PFX ~ "invalid time spec\n");
        exit(EXIT_FAILURE);
    }

    if (suff)
    {
        int ss = 0;
        const int rc2 = sscanf(suff, "%02d", &ss);
        if (rc2 != 1)
        {
            fprintf(stderr, PFX ~ "invalid time spec\n");
            exit(EXIT_FAILURE);
        }
        tminfo.tm_sec = ss;
    }

    touchTimeNow = mktime(&tminfo);
}

///
/// Apply utime on one file, honoring -a/-m selection and -c/-r/-t semantics.
/// Creates the file if missing unless -c is set.
///
static int touchOne(const char* path) @nogc
{
    utimbuf ut;
    ut.actime  = touchAtime;
    ut.modtime = touchMtime;

    // If either atime/mtime not explicitly selected, preserve the other from the file
    if (!optAtime || !optMtime)
    {
        stat_t st;
        if (c_stat(path, &st) < 0)
            goto err_out; // matches original fallthrough

        if (!optAtime)  ut.actime  = cast(time_t) st.st_atime;
        if (!optMtime)  ut.modtime = cast(time_t) st.st_mtime;
    }

    int secondTime = 0;

again_butthead:
    if (utime(path, &ut) == 0)
        return 0;

    if (errno != ENOENT)
        goto err_out;

    if (!optCreatOk || secondTime)
        return 1;

    // Try to create then retry utime
    const int fd = creat(path, 0o666);
    if (fd < 0)
        goto err_out;

    // no need to keep fd open; creat()'s descriptor will be closed at process exit,
    // but we keep parity with the simple original (no close needed for correctness here).
    secondTime = 1;
    goto again_butthead;

err_out:
    perror(path);
    return 1;
}

int main(int argc, char** argv)
{
    // Equivalent options to the C version:
    //  -a             change access time
    //  -c             do not create
    //  -m             change modification time
    //  -r FILE        use FILE's times
    //  -t STAMP       use timestamp (overrides -r)
    opterr = 0; // we'll print our own messages if needed

    touchTimeNow = time(null);

    for (;;)
    {
        int c = getopt(argc, argv, "acmr:t:");
        if (c == -1) break;

        final switch (c)
        {
        case 'a':
            optDefault = false;
            optAtime = true;
            break;
        case 'c':
            optCreatOk = false;
            break;
        case 'm':
            optDefault = false;
            optMtime = true;
            break;
        case 'r':
            {
                if (c_stat(optarg, &touchRefStat) < 0)
                {
                    perror(optarg);
                    return EXIT_FAILURE;
                }
                optRefFile = true;
            }
            break;
        case 't':
            {
                optRefFile = false;
                parseUserTime(optarg);
            }
            break;
        default:
            fprintf(stderr, PFX ~ "invalid option\n");
            return EXIT_FAILURE;
        }
    }

    if (optDefault)
    {
        optAtime = true;
        optMtime = true;
    }

    if (optRefFile)
    {
        touchAtime = cast(time_t) touchRefStat.st_atime;
        touchMtime = cast(time_t) touchRefStat.st_mtime;
    }
    else
    {
        // either -t provided (parseUserTime set touchTimeNow), or default now()
        if (!optRefFile && !optarg) { /* nothing extra */ }
        touchAtime = touchTimeNow;
        touchMtime = touchTimeNow;
    }

    if (optind >= argc)
    {
        fprintf(stderr, PFX ~ "missing file operand\n");
        return EXIT_FAILURE;
    }

    int rc = 0;
    for (int i = optind; i < argc; ++i)
    {
        if (touchOne(argv[i]) != 0)
            rc = 1;
    }

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
