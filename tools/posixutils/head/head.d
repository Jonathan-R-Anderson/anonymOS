// head.d — D implementation of the provided C head tool
module head_d;

import std.stdio : File, stdin, stdout, stderr;
import std.getopt : getopt;
import std.string : toStringz;
import std.conv : to;
import std.algorithm.searching : countUntil;
import core.stdc.stdio : perror;

enum HEAD_BUF_SZ = 8192;

__gshared uint headLines = 10;
__gshared bool printHeader = false;

void doPrintHeader(string fn)
{
    if (printHeader)
        stdout.writefln("\n==> %s <==", fn);
}

int headFile(string fn, ref File f)
{
    ubyte[HEAD_BUF_SZ] buf;
    ulong lines = 0;

    doPrintHeader(fn);

    // Read raw chunks and search for newlines
    while (!f.eof())
    {
        size_t nread = 0;
        try {
            nread = f.rawRead(buf[]).length;
        } catch (Throwable) {
            // Mirror perror(fn) + return 1
            perror(fn.toStringz);
            return 1;
        }
        if (nread == 0) break;

        size_t off = 0;
        auto tmpLines = lines;

        // Scan this buffer for up to (headLines - lines) newlines
        while (tmpLines < headLines)
        {
            auto idx = countUntil(buf[off .. nread], cast(ubyte) '\n'); // -1 if not found
            if (idx < 0) break;
            off += cast(size_t) idx + 1; // include the newline
            ++tmpLines;
        }

        if (tmpLines >= headLines)
        {
            // Write bytes up to and including the Nth newline, then stop.
            stdout.rawWrite(buf[0 .. off]);
            return 0;
        }

        // Otherwise, write whole buffer and continue
        stdout.rawWrite(buf[0 .. nread]);
        lines = tmpLines;
    }

    return 0;
}

int main(string[] args)
{
    string nArg;
    string[] files;

    try {
        getopt(args,
            "n|lines", &nArg
        );
        // getopt removes handled options from `args`, leaving the program name
        // followed by the remaining positional parameters.
        if (args.length > 1)
            files = args[1 .. $].dup;
        else
            files = [];
    } catch (Exception e) {
        stderr.writeln(e.msg);
        return 2;
    }

    if (nArg.length)
    {
        int tmp = 0;
        try {
            tmp = nArg.to!int;
        } catch (Exception) {
            // match original: ARGP_ERR_UNKNOWN → nonzero exit
            return 2;
        }
        if (tmp <= 0) return 2;
        headLines = cast(uint) tmp;
    }

    // Header if more than one input (like walker.arglist.size() > 1)
    if (files.length > 1) printHeader = true;

    int rc = 0;

    if (files.length == 0)
    {
        // Read from stdin; no header when single input
        auto f = stdin;
        rc |= headFile("(standard input)", f);
    }
    else
    {
        foreach (path; files)
        {
            if (path == "-")
            {
                auto f = stdin;
                rc |= headFile("-", f);
                continue;
            }

            File f;
            try {
                f = File(path, "rb");
            } catch (Throwable) {
                perror(path.toStringz);
                rc |= 1;
                continue;
            }
            scope(exit) f.close();
            rc |= headFile(path, f);
        }
    }

    return rc;
}
