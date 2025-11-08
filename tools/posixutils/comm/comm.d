module comm_d;

import std.stdio : File, stdin, stdout, stderr, write, writeln, readln;
import std.getopt : getopt, config;
import std.string : toStringz;
import core.stdc.string : strcoll;
import core.stdc.locale : setlocale, LC_ALL;

enum OPT_FILE1 = 1 << 0;
enum OPT_FILE2 = 1 << 1;
enum OPT_DUP   = 1 << 2;

struct Options {
    int outmask = 0; // bitmask of suppressed columns
}

struct Inputs {
    File f1;
    File f2;
    bool close1 = false;
    bool close2 = false;
    string name1;
    string name2;
}

static string leadF2;  // prefix for column 2 lines
static string leadDup; // prefix for column 3 lines

private void lineOut(int ltype, const char[] line, ref Options opt)
{
    if (ltype & opt.outmask) return;

    // regular switch (not final) so having a default is fine
    switch (ltype) {
        case OPT_FILE1:
            write(line);
            break;
        case OPT_FILE2:
            write(leadF2, line);
            break;
        case OPT_DUP:
            write(leadDup, line);
            break;
        default:
            break;
    }
}

private bool readLine(ref File f, ref string outLine)
{
    try {
        auto s = f.readln();              // includes '\n' if present
        if (s.length == 0) return false;  // EOF
        outLine = s;
        return true;
    } catch (Exception e) {
        // Explicit rethrow keeps older toolchains happy
        throw e;
    }
}

private int openInputs(string a, string b, ref Inputs inps)
{
    inps.name1 = a;
    inps.name2 = b;

    const bool aStdin = (a == "-");
    const bool bStdin = (b == "-");

    if (aStdin && bStdin) {
        stderr.writeln("comm: both inputs cannot be '-' (stdin)");
        return 1;
    }

    if (aStdin) {
        inps.f1 = stdin;
    } else {
        try {
            inps.f1 = File(a, "r");
            inps.close1 = true;
        } catch (Exception e) {
            stderr.writeln(a, ": ", e.msg);
            return 1;
        }
    }

    if (bStdin) {
        inps.f2 = stdin;
    } else {
        try {
            inps.f2 = File(b, "r");
            inps.close2 = true;
        } catch (Exception e) {
            if (inps.close1) inps.f1.close();
            stderr.writeln(b, ": ", e.msg);
            return 1;
        }
    }

    return 0;
}

private int compareFiles(ref Inputs inps, ref Options opt)
{
    // prefixes depending on suppressed columns
    leadF2 = (opt.outmask & OPT_FILE1) ? "" : "\t";
    if ((opt.outmask & (OPT_FILE1 | OPT_FILE2)) == 0)                       leadDup = "\t\t";
    else if ((opt.outmask & (OPT_FILE1 | OPT_FILE2)) == (OPT_FILE1 | OPT_FILE2)) leadDup = "";
    else                                                                      leadDup = "\t";

    string l1, l2;
    bool have1 = false, have2 = false;
    bool want1 = true,  want2 = true;

    int rc = 0;

    while (want1 || want2) {
        if (want1 && !have1) {
            try {
                have1 = readLine(inps.f1, l1);
                if (!have1) want1 = false;
            } catch (Exception e) {
                stderr.writeln(inps.name1, ": ", e.msg);
                rc = 1; break;
            }
        }
        if (want2 && !have2) {
            try {
                have2 = readLine(inps.f2, l2);
                if (!have2) want2 = false;
            } catch (Exception e) {
                stderr.writeln(inps.name2, ": ", e.msg);
                rc = 1; break;
            }
        }

        if (!have1 && !have2) break;

        if (!have1) {
            lineOut(OPT_FILE2, l2, opt);
            have2 = false;
            continue;
        } else if (!have2) {
            lineOut(OPT_FILE1, l1, opt);
            have1 = false;
            continue;
        } else {
            // locale-aware compare (includes trailing '\n', matching POSIX comm)
            auto cmp = strcoll(l1.toStringz, l2.toStringz);
            if (cmp < 0) {
                lineOut(OPT_FILE1, l1, opt);
                have1 = false;
            } else if (cmp > 0) {
                lineOut(OPT_FILE2, l2, opt);
                have2 = false;
            } else {
                lineOut(OPT_DUP, l1, opt);
                have1 = have2 = false;
            }
        }
    }

    return rc;
}

int main(string[] args)
{
    setlocale(LC_ALL, "");

    Options opt;
    bool sup1 = false, sup2 = false, sup3 = false;

    // getopt mutates args in place; keep it simple
    getopt(args, config.bundling,
        "1", &sup1,
        "2", &sup2,
        "3", &sup3
    );

    if (sup1) opt.outmask |= OPT_FILE1;
    if (sup2) opt.outmask |= OPT_FILE2;
    if (sup3) opt.outmask |= OPT_DUP;

    // After getopt: args[1].. are positional
    if (args.length != 3) {
        stderr.writeln("Usage: comm_d [-1] [-2] [-3] file1 file2");
        return 1;
    }

    auto file1 = args[1];
    auto file2 = args[2];

    Inputs inps;
    auto orc = openInputs(file1, file2, inps);
    if (orc != 0) return 1;

    scope(exit) {
        if (inps.close1) inps.f1.close();
        if (inps.close2) inps.f2.close();
    }

    return compareFiles(inps, opt);
}
