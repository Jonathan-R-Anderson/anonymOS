// date.d — D translation of the provided C/C++ source
module date;

// ------------------------------
// C / POSIX interop imports
// ------------------------------
import core.stdc.time   : time_t = time_t, time = time, tm = tm, localtime = localtime,
                          mktime = mktime, strftime = strftime;
import core.stdc.string : memcpy, strlen;
import core.stdc.stdlib : getenv;                // POSIX setenv is not here
version (Posix) import core.sys.posix.stdlib : setenv, unsetenv;

// Portable POSIX clock setting
import core.sys.posix.time : clock_settime, timespec, CLOCK_REALTIME;

// ------------------------------
// D imports
// ------------------------------
import std.stdio     : writeln, writefln, stderr;
import std.string    : fromStringz, toStringz;
import std.getopt    : getopt, defaultGetoptPrinter, config;
import std.typecons  : Nullable;
import std.algorithm : min;
import std.exception : enforce;
import std.ascii     : isDigit;

// ------------------------------
// Globals / options
// ------------------------------
__gshared int optUTC = 0;

// ------------------------------
// Helpers
// ------------------------------
private tm* fetchLocalTime()
{
    time_t t = time(null); // returns (time_t)-1 on error
    if (t == cast(time_t) -1)
        return null;

    auto l = localtime(&t);
    if (l is null)
        return null;

    return l;
}

private void prFormatted(const tm* ptm, const char* fmt)
{
    enum BUFSZ = 4096;
    char[BUFSZ] buf;
    // strftime returns number of bytes written (excluding NUL)
    size_t n = strftime(buf.ptr, buf.length, fmt, ptm);
    if (n >= buf.length) n = buf.length - 1;
    buf[n] = 0;
    writeln(fromStringz(buf.ptr));
}

// Set the system wall clock to the given seconds since epoch.
// Returns true on success, false on failure.
private bool setSystemTimeSeconds(long sec)
{
    timespec ts;
    ts.tv_sec  = cast(typeof(ts.tv_sec)) sec;
    ts.tv_nsec = 0;
    return clock_settime(CLOCK_REALTIME, &ts) == 0;
}

private int outputDefault()
{
    enum defaultFmt = "%a %b %e %H:%M:%S %Z %Y";
    auto l = fetchLocalTime();
    if (l is null) {
        stderr.writeln("time/localtime failed");
        return 1;
    }
    prFormatted(l, defaultFmt.ptr);
    return 0;
}

private int outputFormat(const(char)* argZ)
{
    auto l = fetchLocalTime();
    if (l is null) {
        stderr.writeln("time/localtime failed");
        return 1;
    }
    // Skip leading '+'
    if (argZ[0] == '+')
        ++argZ;
    prFormatted(l, argZ);
    return 0;
}

private int inputDate(const(char)* dateStrZ)
{
    // Parse: MM DD hh mm [YY] [YY]
    tm tmbuf;
    auto l = fetchLocalTime();
    if (l is null) {
        stderr.writeln("time/localtime failed");
        return 1;
    }
    // Copy whole tm so fields like tm_isdst carry over
    memcpy(&tmbuf, l, tm.sizeof);

    auto s = dateStrZ;
    int[6] parsed; // mon, mday, hour, min, y1, y2
    size_t need = 4; // minimum required groups
    size_t got = 0;

    int read2Digits(const(char)* p, ref size_t advance)
    {
        if (!(isDigit(p[0]) && isDigit(p[1]))) return -1;
        advance = 2;
        return (p[0] - '0') * 10 + (p[1] - '0');
    }

    size_t off = 0;
    for (; got < parsed.length; ++got)
    {
        size_t adv = 0;
        auto v = read2Digits(s + off, adv);
        if (v < 0) break;
        parsed[got] = v;
        off += adv;
        if (got + 1 == need) break; // ensure at least 4 groups (MMDDhhmm)
    }

    if (got + 1 < need) {
        stderr.writefln("invalid date format '%s'", fromStringz(dateStrZ));
        return 1;
    }

    // Try to read optional groups
    for (++got; got < parsed.length; ++got) {
        size_t adv = 0;
        int v = read2Digits(s + off, adv);
        if (v < 0) break;
        parsed[got] = v;
        off += adv;
    }

    // Assign (keep the original program’s off-by-one behavior for tm_mon)
    tmbuf.tm_mon  = parsed[0]; // NOTE: original code did not subtract 1
    tmbuf.tm_mday = parsed[1];
    tmbuf.tm_hour = parsed[2];
    tmbuf.tm_min  = parsed[3];

    if (got == 4) {
        // only MMDDhhmm => keep current year
    } else if (got == 5) {
        int y1 = parsed[4];
        if (y1 <= 68) y1 += 2000; else y1 += 1900;
        tmbuf.tm_year = y1 - 1900;
    } else if (got >= 6) {
        int y = parsed[4] * 100 + parsed[5];
        tmbuf.tm_year = y - 1900;
    }

    // Normalize
    auto tt = mktime(&tmbuf);
    if (tt == cast(time_t) -1) {
        stderr.writeln("mktime failed");
        return 1;
    }

    // Set system time
    if (!setSystemTimeSeconds(cast(long) tt)) {
        stderr.writeln("cannot set date (requires privileges)");
        // Like the original, still print the resulting default output
        auto rc1 = outputDefault();
        return 1 | rc1;
    }

    // Print new date
    return outputDefault();
}

// ------------------------------
// Main
// ------------------------------
extern(D)
int main(string[] args)
{
    // Options: --utc / -u
    // Positional: either none -> default output, or a single argument:
    //   +FORMAT  -> custom format
    //   DATESTR  -> set date
    string fmtOrDate;

    try {
        auto res = getopt(args,
            config.passThrough, // allow positionals to remain in args
            "utc|u", &optUTC
        );

        // Remaining positionals are in args[1 .. $] (program name is args[0])
        string[] positionals = (args.length > 1) ? args[1 .. $] : [];

        if (positionals.length >= 2) {
            defaultGetoptPrinter("Too many positional arguments.", res.options);
            return 2;
        }
        if (positionals.length == 1) {
            fmtOrDate = positionals[0];
        }
    } catch (Exception e) {
        stderr.writeln(e.msg);
        return 2;
    }

    // Handle TZ swap if --utc
    Nullable!string oldTZ;
    if (optUTC != 0) {
        auto tz = getenv("TZ");
        if (tz !is null)
            oldTZ = fromStringz(tz).idup; // immutable string for Nullable!string
        // setenv("TZ","UTC0",1)
        version (Posix) {
            if (setenv("TZ", "UTC0".ptr, 1) < 0) {
                stderr.writeln("setenv failed");
                return 1;
            }
        } else {
            stderr.writeln("--utc not supported on this platform");
            return 1;
        }
    }

    scope(exit) {
        // restore TZ if we changed it
        version (Posix) {
            if (!oldTZ.isNull) {
                setenv("TZ", oldTZ.get.toStringz, 1);
            }
        }
    }

    int rc = 0;
    if (fmtOrDate.length == 0) {
        rc = outputDefault();
    } else if (fmtOrDate[0] == '+') {
        rc = outputFormat(fmtOrDate.toStringz);
    } else {
        rc = inputDate(fmtOrDate.toStringz);
    }
    return rc;
}
