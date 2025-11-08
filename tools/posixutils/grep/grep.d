// grep.d — D translation of the provided C++ grep
module grep_d;

version (OSX) {} // allow building on macOS

import std.stdio : File, stdin, stdout, stderr, writeln, write, writef, writefln, readln;
import std.getopt : getopt, config, defaultGetoptPrinter;
import std.string : indexOf, toStringz, fromStringz, splitLines, strip, split, endsWith;
import std.conv : to;
import std.algorithm : min;
import std.array : array;

// --------- POSIX interop (regex + string helpers) ------------
extern (C):
    import core.sys.posix.regex : regex_t, regmatch_t, regcomp, regexec, regfree,
                                  REG_NOSUB, REG_ICASE, REG_EXTENDED;
    import core.stdc.string : strcmp, strcasecmp, strstr;
    // strcasestr is available on glibc and BSD (macOS). Declare for interop:
    char* strcasestr(const char* s, const char* find);

// --------- CLI state / enums (mirroring original) ------------
enum MatchType { BRE, ERE, STRING }  // BRE=default, ERE with -E, fixed strings with -F
enum OutputType { NONE, CONTENT, PATH, COUNT } // -q, (default), -l, -c

enum OutputOpts : uint {
    LINENO        = 1 << 0,  // -n
    SUPPRESS_ERRS = 1 << 1,  // -s
}

final class Pattern {
    regex_t rx;         // compiled only for BRE/ERE
    string  pat;        // original pattern
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
__gshared int   nFiles = 0;

// -------------- Helpers for patterns -------------------------
void addPattern(string s) {
    patterns ~= new Pattern(s);
}

void addPatternsFromList(string liststr) {
    // split by newline (same as original's strsplit on '\n')
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
        // exit status 2 in original on pattern file error
        import core.stdc.stdlib : exit;
        exit(2);
    }

    scope(exit) f.close();

    foreach (line; f.byLine()) {
        auto s = line.idup;
        // strip trailing newline (byLine doesn't include '\n', so s is OK)
        addPattern(s);
    }
}

void compilePatterns() {
    int flags = REG_NOSUB;
    if (optIgnoreCase) flags |= REG_ICASE;
    if (optMatch == MatchType.ERE) flags |= REG_EXTENDED;

    foreach (p; patterns) {
        // If -x, anchor ^...$ unless already present at ends (like original)
        if (optWholeLine) {
            bool needPre = !(p.pat.length && p.pat[0] == '^');
            bool needSuf = !(p.pat.length && p.pat[$-1] == '$');
            if (needPre) p.pat = "^" ~ p.pat;
            if (needSuf) p.pat ~= "$";
        }

        // Compile POSIX regex
        auto rc = regcomp(&p.rx, p.pat.toStringz, flags);
        if (rc != 0) {
            // Construct error message
            // regerror signature: size_t regerror(int, const regex_t*, char*, size_t);
            extern(C) size_t regerror(int, const regex_t*, char*, size_t);
            char[1024] buf;
            regerror(rc, &p.rx, buf.ptr, buf.length);
            stderr.writefln("invalid pattern '%s': %s", p.pat, fromStringz(buf.ptr));
            import core.stdc.stdlib : exit;
            exit(2);
        }
    }
}

// -------------- Matching ------------------------------
bool matchString(const(char)* lineZ) {
    // -x : full line equality vs any pattern (case (in)sensitive)
    if (optWholeLine) {
        foreach (p; patterns) {
            auto rc = optIgnoreCase
                ? strcasecmp(lineZ, p.pat.toStringz)
                : strcmp(lineZ, p.pat.toStringz);
            if (rc == 0) return true;
        }
        return false;
    }

    // substring search (case (in)sensitive)
    foreach (p; patterns) {
        const(char)* found = optIgnoreCase
            ? strcasestr(lineZ, p.pat.toStringz)
            : strstr(lineZ, p.pat.toStringz);
        if (found !is null) return true;
    }
    return false;
}

bool matchRegex(const(char)* lineZ) {
    foreach (p; patterns)
        if (regexec(&p.rx, lineZ, 0, null, 0) == 0)
            return true;
    return false;
}

// -------------- Per-line processing --------------------
enum STOP_LOOP = 1 << 30;

int grepLine(string fn, string line) {
    // Ensure we pass a C string to C funcs
    auto lineZ = (line ~ "\0").ptr;

    bool matched = (optMatch == MatchType.STRING)
        ? matchString(lineZ)
        : matchRegex(lineZ);

    if (optInvert) matched = !matched;

    nLines++;
    if (matched) nMatches++;

    final switch (optOut) {
        case OutputType.NONE:
            // -q: stop on first match
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

    // CONTENT path
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

    // Read by line; strip trailing '\n' (byLine gives lines without '\n')
    foreach (line; f.byLine()) {
        auto s = line.idup;
        auto ret = grepLine(prFn, s);
        if ((ret & STOP_LOOP) != 0)
            break;
    }

    // Error detection: std.stdio doesn't expose ferror directly;
    // if an exception occurred we'd have thrown already.

    // -c: print count per file (with prefix for multi-file)
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

    string[] ePatterns; // from -e (can appear multiple times)
    string[] fPatternFiles; // from -f (can appear multiple times)

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
            config.caseSensitive, // match GNU short options exactly

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
        cli.positionals = help.args.dup;
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

    // Add patterns from -e
    foreach (p; cli.ePatterns)
        addPatternsFromList(p);

    // Add patterns from -f files
    foreach (pf; cli.fPatternFiles)
        addPatternsFromFile(pf);

    // If still no patterns, consume first positional as pattern (like original)
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

    // Compile regex if not fixed strings
    if (optMatch != MatchType.STRING)
        compilePatterns();

    // Determine number of files for prefixing behavior
    nFiles = files.length;
    if (nFiles == 0) nFiles = 1; // reading stdin counts as 1

    // Process files (or stdin if none)
    int exitStatus = 0;

    if (files.length == 0) {
        auto prFn = "(standard input)";
        // POSIX grep omits the filename when only stdin is read; we will not prefix (nFiles==1 ensures this).
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
                // original tracks errors and may return 2; we’ll set exitStatus=2 but continue other files
                exitStatus = 2;
                continue;
            }
            scope(exit) f.close();

            grepFile(path, f, exitStatus);
        }
    }

    // Final exit-status rules (mirror grep_post_walk in original):
    // If -q and any match => 0
    if (nTotalMatches && optOut == OutputType.NONE)
        return 0;
    // If errors occurred (exitStatus > 1) => return that (2)
    if (exitStatus > 1)
        return exitStatus;
    // If any matches => 0
    if (nTotalMatches)
        return 0;
    // No matches => 1
    return 1;
}
