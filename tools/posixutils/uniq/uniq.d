// uniq.d - D translation of the provided C source
// Features: -c/--count, --skip=N, src [dest]

import std.stdio : File, stdin, stdout, stderr, writefln;
import std.string : cmp, stripRight, toStringz;
import std.getopt : getopt, defaultGetoptPrinter, GetoptResult;
import std.conv : to;
import std.exception : enforce;
import core.stdc.stdlib : exit;

struct Options {
    bool count = false;
    size_t skip = 0;
    string src;
    string dest; // optional
}

struct UniqState {
    string lastLine;       // stored *after* skip, to match the C code
    size_t lastLen = 0;    // length of lastLine
    ulong  dups = 0;
    bool   haveLast = false;
}

private int writeLastLine(ref UniqState st, File outf, bool countFlag) {
    // Match C: if -c prefix count and a space, else just the line
    // st.lastLine already contains the trailing newline (we keep it from input)
    // Return nonzero on error
    try {
        if (countFlag) {
            // print: <count><space><line>
            // Note: the C code uses "%lu %s" where %s includes the '\n' already.
            outf.writefln("%s %s", st.dups, st.lastLine.stripRight("\n"));
            // writefln adds its own newline; stripRight to avoid double newlines
        } else {
            outf.write(st.lastLine);
        }
        return 0;
    } catch (Throwable) {
        return 1;
    }
}

private int processLine(ref UniqState st, string line, size_t skip, File outf, bool countFlag) {
    // Emulate the C logic:
    // 1) If skip > line length, compare as empty string
    // 2) Compare (lineAfterSkip) to last stored post-skip line
    // 3) If different, flush last; then set last to current; dups=1
    // 4) If same, just increment dups
    string after;
    if (skip > line.length) {
        after = "";
    } else {
        after = line[skip .. $];
    }

    const bool match = (after.length == st.lastLen) && (cmp(after, st.lastLine) == 0);

    if (match) {
        st.dups++;
        return 0;
    }

    if (st.haveLast) {
        if (writeLastLine(st, outf, countFlag) != 0) return 1;
    }

    st.lastLine = after;
    st.lastLen  = after.length;
    st.dups     = 1;
    st.haveLast = true;
    return 0;
}

private int doUniq(string srcFn, string destFn, bool countFlag, size_t skip) {
    File inf;
    File outf;
    bool err = false;

    // open input
    try {
        inf = File(srcFn, "r");
    } catch (Throwable) {
        stderr.writefln("%s: failed to open", srcFn);
        return 1;
    }

    // open output (stdout if empty)
    const useStdout = destFn.length == 0;
    if (useStdout) {
        outf = stdout;
    } else {
        try {
            outf = File(destFn, "w");
        } catch (Throwable) {
            stderr.writefln("%s: failed to open", destFn);
            return 1;
        }
    }

    UniqState st;
    scope(exit) {
        // flush/close
        try { outf.flush(); } catch (Throwable) {}
        if (!useStdout) {
            try { outf.close(); } catch (Throwable) {}
        }
        try { inf.close(); } catch (Throwable) {}
    }

    // read line by line; keep newlines (like fgets)
    foreach (line; inf.byLineCopy(KeepTerminator.yes)) {
        if (processLine(st, line, skip, outf, countFlag) != 0) {
            err = true;
            break;
        }
    }

    if (st.haveLast && !err) {
        if (writeLastLine(st, outf, countFlag) != 0) err = true;
    }

    return err ? 1 : 0;
}

private Options parseArgs(string[] args) {
    Options opt;
    auto helpPrinter = (string msg, GetoptResult res) {
        defaultGetoptPrinter(msg, res);
    };

    auto res = getopt(args,
        "c|count",   &opt.count,
        "skip",      &opt.skip,
    , helpPrinter);

    // positional: src [dest]
    auto rest = res.args;
    enforce(rest.length >= 1, "uniq: missing source file\nUsage: uniq [-c|--count] [--skip=N] SRC [DEST]");

    opt.src = rest[0];
    if (rest.length >= 2) opt.dest = rest[1];
    return opt;
}

int main(string[] args) {
    try {
        auto opt = parseArgs(args);
        return doUniq(opt.src, opt.dest, opt.count, opt.skip);
    } catch (Exception e) {
        stderr.writefln("%s", e.msg);
        return 1;
    }
}
