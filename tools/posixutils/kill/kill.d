// kill.d — D translation of the provided C program (corrected)
module kill_d;

version (Posix) {} else static assert(0, "This program requires POSIX.");

import std.stdio : writeln, writefln, stderr;
import std.string : toUpper, startsWith, strip, format, cmp, fromStringz, toStringz;
import std.conv : to;
import std.algorithm : sort, map;
import std.array : array, idup;
import core.stdc.stdlib : exit;
import core.stdc.stdio : perror;
import core.stdc.errno : errno;
import core.sys.posix.unistd : pid_t;
import core.sys.posix.signal : kill, SIGTERM;

//
// ----- Platform signal tables -----
// We define a portable set and add OS-specific extras + aliases.
//

private struct SigPair { string name; int num; }

// Base POSIX-ish set
private immutable SigPair[] BASE_SIGS = [
    SigPair("HUP",   1),
    SigPair("INT",   2),
    SigPair("QUIT",  3),
    SigPair("ILL",   4),
    SigPair("TRAP",  5),
    SigPair("ABRT",  6),
    SigPair("BUS",   7),
    SigPair("FPE",   8),
    SigPair("KILL",  9),
    SigPair("USR1", 10),
    SigPair("SEGV", 11),
    SigPair("USR2", 12),
    SigPair("PIPE", 13),
    SigPair("ALRM", 14),
    SigPair("TERM", 15),
    // 16 is platform-specific (LINUX: SIGSTKFLT). macOS has no 16.
    SigPair("CHLD", 17),
    SigPair("CONT", 18),
    SigPair("STOP", 19),
    SigPair("TSTP", 20),
    SigPair("TTIN", 21),
    SigPair("TTOU", 22),
    SigPair("URG",  23),
    SigPair("XCPU", 24),
    SigPair("XFSZ", 25),
    SigPair("VTALRM", 26),
    SigPair("PROF", 27),
    SigPair("WINCH", 28),
    SigPair("POLL", 29), // == IO on some platforms
    SigPair("PWR",  30), // not on macOS
    SigPair("SYS",  31)  // not on macOS
];

// Linux extras
version (linux)
private immutable SigPair[] PLATFORM_EXTRAS = [
    SigPair("STKFLT",16),
    SigPair("IO",    29), // alias of POLL
    // RT signals vary; we don’t enumerate them by name
];
else version (OSX)
private immutable SigPair[] PLATFORM_EXTRAS = [
    // macOS doesn’t have STKFLT/PWR/SYS numerically like Linux
];
else
private immutable SigPair[] PLATFORM_EXTRAS = [];

// Aliases (name -> canonical name)
version (linux)
private immutable string[2][] ALIASES = [
    ["IOT",  "ABRT"],
    ["POLL", "IO"],     // treat POLL as alias to IO (and vice-versa handled below)
    ["CLD",  "CHLD"],
];
else version (OSX)
private immutable string[2][] ALIASES = [
    ["IOT",  "ABRT"],
    ["EMT",  "TRAP"],
    ["CLD",  "CHLD"],
    ["INFO", "USR1"],   // macOS SIGINFO is 29; we keep minimal mapping behavior
];
else
private immutable string[2][] ALIASES = [];

//
// ----- Utility: build maps -----
//
private struct Tables {
    int[string] nameToNum;      // "TERM" -> 15
    string[int] numToName;      // 15 -> "TERM"
}

private Tables buildTables() {
    Tables t;
    void add(SigPair p) {
        t.nameToNum[p.name] = p.num;
        // prefer first-seen canonical for a number
        if (p.num !in t.numToName) t.numToName[p.num] = p.name;
    }
    foreach (p; BASE_SIGS) add(p);
    foreach (p; PLATFORM_EXTRAS) add(p);

    // Normalize POLL/IO equivalence on Linux
    version (linux) {
        if ("POLL" in t.nameToNum) {
            auto n = t.nameToNum["POLL"];
            t.nameToNum["IO"] = n;
            t.numToName[n] = "POLL";
        }
    }

    // Apply aliases
    foreach (a; ALIASES) {
        auto from = a[0], to = a[1];
        auto toUpperTo = to.toUpper();
        if (toUpperTo in t.nameToNum)
            t.nameToNum[from.toUpper()] = t.nameToNum[toUpperTo];
    }
    return t;
}

//
// ----- CLI logic -----
//
private void usage(string prog) {
    stderr.writefln(
        "Usage:\n" ~
        "    %s -l [signal_number]\n" ~
        "    %s -s signal_name pid...\n" ~
        "    %s -signal_name pid...\n" ~
        "    %s -signal_number pid...\n",
        prog, prog, prog, prog
    );
    exit(1);
    assert(0);
}

private bool isDigits(string s) {
    if (s.length == 0) return false;
    foreach (i, c; s) {
        if (i == 0 && (c == '+' || c == '-')) continue;
        if (c < '0' || c > '9') return false;
    }
    return true;
}

private bool validSignum(int n, in Tables t) {
    return (n in t.numToName) !is null;
}

private int signameToNum(string signame, ref Tables t) {
    auto s = signame.strip;
    // support plain numbers
    if (isDigits(s)) {
        auto n = to!int(s);
        if (validSignum(n, t)) return n;
        return -1;
    }
    // allow optional leading "SIG"
    if (s.length >= 3 && s[0..3].toUpper() == "SIG")
        s = s[3..$];

    s = s.toUpper();
    if (auto p = s in t.nameToNum) return *p;

    // try aliases transitively
    foreach (a; ALIASES) {
        if (s == a[0]) {
            auto target = a[1].toUpper();
            if (auto q = target in t.nameToNum) return *q;
        }
    }
    return -1;
}

private void listSignal(int n, in Tables t) {
    if (auto p = n in t.numToName)
        writefln("%d) SIG%s", n, *p);
}

private void listSignals(in Tables t) {
    auto nums = t.numToName.keys.array.sort;
    foreach (n; nums)
        listSignal(n, t);

    if (ALIASES.length) {
        writeln();
        writeln("Aliases:");
        foreach (a; ALIASES)
            writefln("SIG%s -> SIG%s", a[0], a[1]);
    }
}

private void checkSignalList(string[] args, in Tables t) {
    // -l [signal_number]
    if (args.length >= 2 && args[1] == "-l") {
        if (args.length == 2) {
            listSignals(t);
            exit(0);
        }
        if (args.length > 3) usage(args[0]);
        if (!isDigits(args[2])) usage(args[0]);
        auto n = to!int(args[2]);
        if (!validSignum(n, t)) usage(args[0]);
        listSignal(n, t);
        exit(0);
    }
}

private void checkHelp(string[] args) {
    if (args.length >= 2 &&
       (args[1] == "-h" || args[1] == "-?" || args[1] == "--help"))
        usage(args[0]);
}

private int checkSignalName(string[] args, out size_t pidPos, ref Tables t) {
    if (args.length < 2) usage(args[0]);

    // default: SIGTERM
    int signum = SIGTERM;

    if (args[1] == "-s") {
        if (args.length < 4) usage(args[0]);
        auto name = args[2];
        pidPos = 3;
        signum = signameToNum(name, t);
        if (signum < 0) {
            stderr.writefln("invalid signal '%s'", name);
            exit(1);
        }
        return signum;
    }

    if (args[1].startsWith("-")) {
        auto nameOrNum = args[1][1..$];
        pidPos = 2;
        signum = signameToNum(nameOrNum, t);
        if (signum < 0) {
            stderr.writefln("invalid signal '%s'", nameOrNum);
            exit(1);
        }
        return signum;
    }

    pidPos = 1;
    return signum; // default SIGTERM
}

private int deliverSignals(string[] args, size_t pidPos, int signum) {
    int retval = 0;
    if (pidPos >= args.length) usage(args[0]);

    foreach (i; pidPos .. args.length) {
        auto token = args[i].strip;
        if (!isDigits(token)) {
            stderr.writefln("invalid pid '%s'", token);
            retval = 1;
            continue;
        }
        pid_t pid;
        // pid_t is signed; allow negative for process groups if supported
        pid = cast(pid_t) to!long(token);

        if (kill(pid, signum) < 0) {
            // Mimic perror(argv[i])
            perror(token.toStringz);
            retval = 1;
        }
    }
    return retval;
}

extern(C) int main(int argc, char** argv) {
    // Convert argv -> D string[]
    string[] args;
    args.length = cast(size_t)argc;
    foreach (i; 0 .. cast(size_t)argc) {
        args[i] = fromStringz(argv[i]).idup;
    }

    if (args.length < 2) usage(args[0]);

    auto tables = buildTables();

    checkHelp(args);
    checkSignalList(args, tables);

    size_t pidPos = size_t.max;
    auto signum = checkSignalName(args, pidPos, tables);

    return deliverSignals(args, pidPos, signum);
}
