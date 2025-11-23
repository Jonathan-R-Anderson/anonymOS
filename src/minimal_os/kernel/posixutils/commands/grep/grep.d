// grep.d — D translation of the provided C++ grep (std.regex version)
module grep_d;

version (OSX) {} // allow building on macOS

import std.stdio : File, stdin, stdout, stderr, writeln, write, writef, writefln, readln;
import std.getopt : getopt, config, defaultGetoptPrinter;
import std.string : indexOf, icmp, CaseSensitive, splitLines, strip, split, endsWith;
import std.conv : to;
import std.algorithm : min;
import std.array : array;
import std.regex : regex, Regex, matchFirst; // <-- use D regex


// --------- CLI state / enums (mirroring original) ------------
enum MatchType { BRE, ERE, STRING }  // BRE=default, ERE with -E, fixed strings with -F
enum OutputType { NONE, CONTENT, PATH, COUNT } // -q, (default), -l, -c

enum OutputOpts : uint {
    LINENO        = 1 << 0,  // -n
    SUPPRESS_ERRS = 1 << 1,  // -s
}

final class Pattern {
    // For BRE/ERE we’ll store a compiled std.regex
    Regex!char rx;
    bool hasRx = false;
    string  pat; // original pattern
    this(string s) { pat = s; }
}

__gshared MatchType   optMatch = MatchType.BRE;
__gshared OutputType  optOut   = OutputType.CONTENT;
__gshared uint        outOpts  = 0;
__gshared bool        optIgnoreCase = false;
__gshared bool        optInvert     = false;
__gshared bool        optWholeLine  = false;

__gshared Pattern[] patterns;

// per-file counters
__gshared ulong nMatches = 0;
__gshared ulong nTotalMatches = 0;
__gshared ulong nLines = 0;
__gshared size_t nFiles = 0;

// -------------- Helpers for patterns -------------------------
void addPattern(string s) {
    patterns ~= new Pattern(s);
}

void addPatternsFromList(string liststr) {
    foreach (line; liststr.splitLines())
        if (line.length != 0)
            addPattern(line);
}

void addPatternsFromFile(string path) {
    File f;
    try {
        f = File(path, "r");
    } catch (Throwable) {
        if ((outOpts & OutputOpts.SUPPRESS_ERRS) == 0)
            stderr.writefln("%s: %s", path, "cannot open");
        import core.stdc.stdlib : exit;
        exit(2);
    }
    scope(exit) f.close();

    foreach (line; f.byLine()) {
        auto s = line.idup;
        addPattern(s);
    }
}

void compilePatterns() {
    // Map GNU grep flags to std.regex:
    // -E (ERE): default-like behavior in std.regex (no basic vs extended split),
    // -x: anchor with ^...$,
    // -i: case-insensitive via flag string "i".
    auto rxFlags = optIgnoreCase ? "i" : "";

    foreach (p; patterns) {
        auto pat = p.pat;
        if (optWholeLine) {
            bool needPre = !(pat.length && pat[0] == '^');
            bool needSuf = !(pat.length && pat[$-1] == '$');
            if (needPre) pat = "^" ~ pat;
            if (needSuf) pat ~= "$";
        }
        // BRE vs ERE:
        // D's std.regex is closer to ERE. If user explicitly asked for BRE,
        // we still compile as-is; most common patterns work identically.
        try {
            p.rx = regex(pat, rxFlags);
            p.hasRx = true;
        } catch (Exception e) {
            stderr.writefln("invalid pattern '%s': %s", p.pat, e.msg);
            import core.stdc.stdlib : exit;
            exit(2);
        }
    }
}

// -------------- Matching ------------------------------
bool matchStringD(string line) {
    // -x: full line equality vs any pattern
    if (optWholeLine) {
        foreach (p; patterns) {
            if (optIgnoreCase) {
                if (icmp(line, p.pat) == 0) return true;
            } else {
                if (line == p.pat) return true;
            }
        }
        return false;
    }
    // substring search
    foreach (p; patterns) {
        if (optIgnoreCase) {
            if (indexOf(line, p.pat, CaseSensitive.no) != -1) return true;
        } else {
            if (indexOf(line, p.pat) != -1) return true;
        }
    }
    return false;
}

bool matchRegex(const(char)* lineZ) {
    // Use std.regex: convert C string to D slice
    import std.string : fromStringz;
    auto line = fromStringz(lineZ);
    foreach (p; patterns)
        if (p.hasRx && !line.matchFirst(p.rx).empty)
            return true;
    return false;
}

bool matchRegexD(string line) {
    foreach (p; patterns)
        if (p.hasRx && !line.matchFirst(p.rx).empty)
            return true;
    return false;
}

// -------------- Per-line processing --------------------
enum STOP_LOOP = 1 << 30;

int grepLine(string fn, string line) {
    bool matched = (optMatch == MatchType.STRING)
        ? matchStringD(line)
        : matchRegexD(line);

    if (optInvert) matched = !matched;

    nLines++;
    if (matched) nMatches++;

    final switch (optOut) {
        case OutputType.NONE:
            return matched ? STOP_LOOP : 0;

        case OutputType.PATH:
            if (matched) {
                writeln(fn);
                return STOP_LOOP;
            }
            return 0;

        case OutputType.COUNT:
            return 0;

        case OutputType.CONTENT:
            if (!matched) return 0;
            break;
    }

    if ((outOpts & OutputOpts.LINENO) != 0) {
        if (nFiles > 1) writef("%s:%s%u:%s\n", fn, "", cast(uint)nLines, line);
        else            writef("%u:%s\n", cast(uint)nLines, line);
    } else {
        if (nFiles > 1) writef("%s:%s\n", fn, line);
        else            writefln("%s", line);
    }
    return 0;
}

// -------------- File processing ------------------------
int grepFile(string prFn, ref File f, ref int exitStatus) {
    nLines = 0;
    nMatches = 0;

    foreach (line; f.byLine()) {
        auto s = line.idup;
        auto ret = grepLine(prFn, s);
        if ((ret & STOP_LOOP) != 0)
            break;
    }

    if (optOut == OutputType.COUNT) {
        if (nFiles > 1) writef("%s:%s%u\n", prFn, "", cast(uint)nMatches);
        else            writefln("%u", cast(uint)nMatches);
    }

    nTotalMatches += nMatches;
    return 0;
}

// -------------- CLI parsing & orchestration -------------
struct CLI {
    bool   setERE = false;
    bool   setFixed = false;
    bool   setCount = false;
    bool   setFilesWithMatches = false;
    bool   setLineNum = false;
    bool   setQuiet = false;
    bool   setNoMsgs = false;
    bool   setIgnoreCase = false;
    bool   setInvert = false;
    bool   setLineRegexp = false;

    string[] ePatterns; // from -e
    string[] fPatternFiles; // from -f

    string[] positionals; // pattern (if none via -e/-f), then files...
}

void inferAliasBehavior(string argv0) {
    import std.path : baseName;
    auto base = baseName(argv0);
    if (base == "egrep")      optMatch = MatchType.ERE;
    else if (base == "fgrep") optMatch = MatchType.STRING;
}

int main(string[] args)
{
    inferAliasBehavior(args.length ? args[0] : "grep");

    CLI cli;
    try {
        auto help = getopt(
            args,
            config.caseSensitive,

            "E|extended-regexp",      { cli.setERE = true; },
            "F|fixed-strings",        { cli.setFixed = true; },
            "c|count",                { cli.setCount = true; },
            "e|regexp", (string p){ cli.ePatterns ~= p; },
            "f|file",   (string p){ cli.fPatternFiles ~= p; },
            "i|ignore-case",          { cli.setIgnoreCase = true; },
            "l|files-with-matches",   { cli.setFilesWithMatches = true; },
            "n|line-number",          { cli.setLineNum = true; },
            "q|quiet|silent",         { cli.setQuiet = true; },
            "s|no-messages",          { cli.setNoMsgs = true; },
            "v|invert-match",         { cli.setInvert = true; },
            "x|line-regexp",          { cli.setLineRegexp = true; }
        );
        cli.positionals = args[1 .. $].dup;
    } catch (Exception e) {
        stderr.writeln(e.msg);
        return 2;
    }

    if (cli.setERE)   optMatch = MatchType.ERE;
    if (cli.setFixed) optMatch = MatchType.STRING;
    if (cli.setCount) optOut   = OutputType.COUNT;
    if (cli.setFilesWithMatches) optOut = OutputType.PATH;
    if (cli.setLineNum) outOpts |= OutputOpts.LINENO;
    if (cli.setQuiet)   optOut   = OutputType.NONE;
    if (cli.setNoMsgs)  outOpts |= OutputOpts.SUPPRESS_ERRS;
    if (cli.setIgnoreCase) optIgnoreCase = true;
    if (cli.setInvert)     optInvert     = true;
    if (cli.setLineRegexp) optWholeLine  = true;

    foreach (p; cli.ePatterns)
        addPatternsFromList(p);
    foreach (pf; cli.fPatternFiles)
        addPatternsFromFile(pf);

    string[] files;
    if (patterns.length == 0) {
        if (cli.positionals.length > 0) {
            addPattern(cli.positionals[0]);
            files = cli.positionals[1 .. $].dup;
        } else {
            stderr.writeln("no patterns specified");
            return 2;
        }
    } else {
        files = cli.positionals.dup;
    }

    if (optMatch != MatchType.STRING)
        compilePatterns();

    nFiles = files.length;
    if (nFiles == 0) nFiles = 1;

    int exitStatus = 0;

    if (files.length == 0) {
        auto prFn = "(standard input)";
        auto f = stdin;
        grepFile(prFn, f, exitStatus);
    } else {
        foreach (path; files) {
            if (path == "-") {
                auto f = stdin;
                auto prFn = nFiles > 1 ? "-" : "(standard input)";
                grepFile(prFn, f, exitStatus);
                continue;
            }

            File f;
            try {
                f = File(path, "r");
            } catch (Throwable) {
                if ((outOpts & OutputOpts.SUPPRESS_ERRS) == 0)
                    stderr.writefln("%s: %s", path, "No such file or cannot open");
                exitStatus = 2;
                continue;
            }
            scope(exit) f.close();

            grepFile(path, f, exitStatus);
        }
    }

    if (nTotalMatches && optOut == OutputType.NONE)
        return 0;
    if (exitStatus > 1)
        return exitStatus;
    if (nTotalMatches)
        return 0;
    return 1;
}
