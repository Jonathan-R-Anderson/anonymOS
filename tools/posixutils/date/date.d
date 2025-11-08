// date.d — D translation of the provided C/C++ source
module date;

extern (C) nothrow @nogc:
    // C interop: time / tm / strftime / localtime / mktime / getenv / setenv
    import core.stdc.time : time_t = time_t, time = time, tm = tm, localtime = localtime,
                            mktime = mktime, strftime = strftime;
    import core.stdc.string : memcpy, strlen;
    import core.stdc.stdlib : getenv, setenv;

    // POSIX settimeofday
    import core.sys.posix.sys.time : timeval, settimeofday;

extern (C):
// (end of @nogc block for the C bits)

pure @safe:
import std.stdio : writeln, writefln, stderr;
import std.string : fromStringz, toStringz;
import std.exception : enforce;
import std.getopt : getopt, defaultGetoptPrinter;
import std.conv : to;
import std.typecons : Nullable;
import std.algorithm : min;

// ------------------------------
// Globals / options
// ------------------------------
__gshared int optUTC = 0;

// ------------------------------
// Helpers
// ------------------------------
@nogc nothrow
private tm* fetchLocalTime()
{
    time_t t;
    // time(&t) — time returns (time_t)-1 on error
    t = time(null);
    if (t == cast(time_t) -1)
        return null;

    auto l = localtime(&t);
    if (l is null)
        return null;

    return l;
}

@nogc nothrow
private void prFormatted(const tm* ptm, const char* fmt)
{
    // Match original: large buffer, print a single line
    enum BUFSZ = 4096;
    char[BUFSZ] buf;
    // strftime returns number of bytes placed in the array (not including the trailing '\0')
    size_t n = strftime(buf.ptr, buf.length, fmt, ptm);
    // Ensure NUL-termination (strftime already does if any output)
    if (n >= buf.length) n = buf.length - 1;
    buf[n] = 0;
    // Write line
    writeln(fromStringz(buf.ptr));
}

private int outputDefault()
{
    // "%a %b %e %H:%M:%S %Z %Y"
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
    // arg is like "+%Y-%m-%d ..."
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
    // Behavior mirrors the original:
    // parse MM DD hh mm [YY] [YY] (two optional year chunks; if only one YY: map <=68 -> 2000+, else 1900+)
    tm tmbuf;
    auto l = fetchLocalTime();
    if (l is null) {
        stderr.writeln("time/localtime failed");
        return 1;
    }
    // Copy the whole tm so fields like tm_isdst carry over
    memcpy(&tmbuf, l, tm.sizeof);

    // Manual sscanf-like parsing (fixed-width 2 digits each)
    // We accept strings containing at least 8 digits (MMDDhhmm) and optionally 2 or 4 more digits (YYYY).
    // Stop at first non-digit beyond what we consume (to behave close to the original).
    import std.ascii : isDigit;

    auto s = dateStrZ;
    int parsed[6]; // mon, mday, hour, min, y1, y2
    size_t need = 4; // minimum groups required
    size_t got = 0;

    int read2Digits(const(char)* p, ref size_t advance) @trusted {
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
        if (got + 1 == need) break; // ensure at least 4 groups
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

    // Assign: (keep the original program’s off-by-one behavior for tm_mon)
    tmbuf.tm_mon  = parsed[0]; // NOTE: original code did not subtract 1
    tmbuf.tm_mday = parsed[1];
    tmbuf.tm_hour = parsed[2];
    tmbuf.tm_min  = parsed[3];

    if (got == 4) {
        // only MMDDhhmm
        // keep tm_year from localtime()
    } else if (got == 5) {
        int y1 = parsed[4];
        if (y1 <= 68) y1 += 2000; else y1 += 1900;
        tmbuf.tm_year = y1 - 1900;
    } else if (got >= 6) {
        int y = parsed[4] * 100 + parsed[5];
        tmbuf.tm_year = y - 1900;
    }

    // mktime
    auto tt = mktime(&tmbuf);
    if (tt == cast(time_t) -1) {
        stderr.writeln("mktime failed");
        return 1;
    }

    // settimeofday
    timeval tv;
    tv.tv_sec  = tt;
    tv.tv_usec = 0;
    if (settimeofday(&tv, null) < 0) {
        // perror-like message; we can’t easily pull errno string portably w/o extra imports,
        // so keep it simple and clear:
        stderr.writeln("cannot set date (requires privileges)");
        // still print the resulting default output like the original
        auto rc1 = outputDefault();
        return 1 | rc1;
    }

    // Print new date
    return outputDefault();
}

// ------------------------------
// Main
// ------------------------------
int main(string[] args)
{
    // Options: --utc / -u
    // Positional: either none -> default output, or a single argument:
    //   +FORMAT  -> custom format
    //   DATESTR  -> set date
    string fmtOrDate;
    try {
        auto help = getopt(args,
            std.getopt.config.passThrough, // gather remaining as positional
            "utc|u", &optUTC
        );
        // Remaining positional (after options) live in help.args
        if (help.args.length >= 2) {
            defaultGetoptPrinter("Too many positional arguments.", help.options);
            return 2;
        }
        if (help.args.length == 1) {
            fmtOrDate = help.args[0];
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
            oldTZ = fromStringz(tz);
        // setenv("TZ","UTC0",1)
        if (setenv("TZ", "UTC0".ptr, 1) < 0) {
            stderr.writeln("setenv failed");
            return 1;
        }
    }

    int rc = 0;
    scope(exit) {
        if (!oldTZ.isNull) {
            setenv("TZ", oldTZ.get.toStringz, 1);
        }
    }

    if (fmtOrDate.length == 0) {
        rc = outputDefault();
    } else if (fmtOrDate[0] == '+') {
        rc = outputFormat(fmtOrDate.toStringz);
    } else {
        rc = inputDate(fmtOrDate.toStringz);
    }

    return rc;
}
