// uniq.d - D translation of the provided C source
// Features: -c/--count, --skip=N, src [dest]

import std.stdio : File, stdin, stdout, stderr, writefln, KeepTerminator;
import std.string : cmp, stripRight;
import std.getopt : getopt;
import std.exception : enforce, collectException;
import core.stdc.stdlib : exit;

struct Options {
    bool   count = false;
    size_t skip = 0;
    string src;
    string dest; // optional
}

struct UniqState {
    string lastLine;       // stored *after* skip
    size_t lastLen = 0;
    ulong  dups = 0;
    bool   haveLast = false;
}

private int writeLastLine(ref UniqState st, File outf, bool countFlag) {
    try {
        if (countFlag) {
            outf.writefln("%s %s", st.dups, st.lastLine.stripRight("\n"));
        } else {
            outf.write(st.lastLine);
        }
        return 0;
    } catch (Throwable) {
        return 1;
    }
}

private int processLine(ref UniqState st, string line, size_t skip, File outf, bool countFlag) {
    string after = (skip > line.length) ? "" : line[skip .. $];
    const bool match = (after.length == st.lastLen) && (cmp(after, st.lastLine) == 0);

    if (match) {
        ++st.dups;
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

    // Open input
    try {
        inf = File(srcFn, "r");
    } catch (Throwable) {
        stderr.writefln("%s: failed to open", srcFn);
        return 1;
    }

    // Open output (stdout if empty)
    const bool useStdout = destFn.length == 0;
    if (useStdout) {
        outf = stdout;
    } else {
        try {
            outf = File(destFn, "w");
        } catch (Throwable) {
            collectException(inf.close());
            stderr.writefln("%s: failed to open", destFn);
            return 1;
        }
    }

    UniqState st;

    scope(exit) {
        collectException(outf.flush());
        if (!useStdout) collectException(outf.close());
        collectException(inf.close());
    }

    // Read line by line; keep terminators (like fgets)
    foreach (line; inf.byLineCopy(KeepTerminator.yes)) {
        if (processLine(st, line, skip, outf, countFlag) != 0) {
            return 1;
        }
    }

    if (st.haveLast) {
        if (writeLastLine(st, outf, countFlag) != 0) return 1;
    }

    return 0;
}

private Options parseArgs(string[] args) {
    Options opt;

    // Use ref-getopt pattern: argv is modified to contain only positionals
    auto argv = args.dup;
    auto res  = getopt(
        argv,                // <-- ref overload chosen
        "c|count", &opt.count,
        "skip",    &opt.skip
    );

    // Now argv == [SRC, DEST?]
    enforce(argv.length >= 1,
        "uniq: missing source file\nUsage: uniq [-c|--count] [--skip=N] SRC [DEST]");

    opt.src = argv[0];
    if (argv.length >= 2) opt.dest = argv[1];
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
