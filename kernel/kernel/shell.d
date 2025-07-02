import mstd.stdio;
import mstd.string;
import mstd.array;
import mstd.algorithm;
import std.parallelism;
import mstd.range;
import mstd.file : chdir, getcwd, dirEntries, SpanMode, readText,
    copy, rename, remove, mkdir, rmdir, exists;
import mstd.process : environment;
import core.stdc.stdlib : system;
version(Posix) import core.sys.posix.unistd : execvp;
version(Posix) extern(C) int chroot(const char* path);
import mstd.regex : regex, matchFirst;
import mstd.path : globMatch;
import mstd.conv : to;
import core.thread : Thread;
import mstd.datetime : Clock, SysTime;
import core.time : dur;
import base32;
import base64;
import dirname;
import dir;
import dircolors;
import fgrep;
import find;
import bc;
import dc;
import expr;
import dd;
import ddrescue;
import fdformat;
import fdisk;
import df;
import du;
import dmesg;
import cal;
import chkconfig;
import cksum;
import md5sum;
import cmp;
import diff;
import diff3;
import comm;
import cron;
import crontab;
import csplit;
import cut;
import date;
import dos2unix;
import egrep;
import eject;
import expand;
import file;
import fmt;
import fold;
import fsck;
import awk;
import fuser;
import getopts;
import getfacl;
import groupadd;
import groupdel;
import groupmod;
import groups;
import gzip;
import iconv;
import id;
import ifcmd;
import ifconfig;
import ifdown;
import ifup;
import importcmd;
import install;
import iostat;
import ip;
import join;
import kill;
import killall;
import klist;
import less;
import letcmd;
import linkcmd;
import ln;
import local;
import locate;
import login;
import logname;
import logout;
import look;
import lsblk;
import lsof;
import ls;

string[] history;
string[string] aliases;

__gshared string[string] variables;
string[string] keyBindings;
string[string] hashedPaths;

string[string] colorCodes = [
    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m"
];

string[] builtinNames = [
    "*", "+", "-", "/", "alias", "animal_case", "apropos", "apt", "apt-get",
    "at", "atq", "atrm", "awk", "base32", "base64", "basename", "bc", "bg", "fg",
    "bind", "break", "builtin", "bunzip2", "bzcat", "bzip2", "bzip2recover",
    "cal", "caller", "cat", "cd", "cfdisk", "chattr", "chgrp", "chkconfig",
    "chmod", "chown", "chpasswd", "chroot", "cksum", "md5sum", "cmp", "comm", "command",
    "cp", "cron", "crontab", "csplit", "cut", "date", "dc", "dd", "ddrescue", "fdformat", "fdisk",
    "declare", "df", "diff", "diff3", "dir", "dircolors", "dirname", "dirs",
    "dmesg", "dos2unix", "du", "echo", "egrep", "eject", "env", "eval", "exec", "exit", "expand", "false", "expr", "export", "for", "getopts", "grep", "fgrep", "file", "find", "fmt", "fold", "fsck", "fuser", "getfacl", "groupadd", "groupdel", "groupmod", "groups", "gzip", "hash", "head",
    "help", "history", "iconv", "id", "if", "ifconfig", "ifdown", "ifup", "import", "install", "iostat", "ip", "jobs", "join", "kill", "killall", "klist", "less", "let", "link", "ln", "look", "login", "logname", "logout", "ls", "lsblk", "lsof", "mkdir", "mv", "popd", "pushd", "pwd", "rm",
    "rmdir", "tail", "touch", "unalias", "local", "locate"
];

bool[string] builtinEnabled;

struct AtJob {
    size_t id;
    string cmd;
    SysTime runAt;
    bool canceled;
}

AtJob[] atJobs;
size_t nextAtId;

struct BgJob {
    size_t id;
    string cmd;
    Thread thread;
    bool running;
}

BgJob[] bgJobs;
size_t nextBgId;

int loopDepth;
int breakCount;

/**
 * Simple interpreter skeleton for a Lisp-like language.
 * This implementation is intentionally minimal and is
 * provided as an example of building language tooling
 * with the D cross-compiler.
 */

struct CallFrame {
    size_t line;
    string file;
    string cmd;
}

CallFrame[] callStack;

string[] dirStack;

void runCommand(string cmd, bool skipAlias=false, size_t callLine=0, string callFile="");
void runParallel(string input);

void run(string input) {
    auto seqs = input.split(";");
    foreach(s; seqs) {
        auto trimmed = s.strip;
        if(trimmed.length == 0) continue;
        runParallel(trimmed);
    }
}

void runParallel(string input) {
    auto cmds = input.split("&");
    if(cmds.length > 1) {
        foreach(c; cmds) {
            taskPool.put(() { runCommand(c.strip, false, __LINE__, __FILE__); });
        }
        taskPool.finish();
    } else {
        runCommand(input.strip, false, __LINE__, __FILE__);
    }
}

string findInPath(string name) {
    import mstd.file : exists;
    auto searchPath = environment.get("PATH", "");
    foreach(p; searchPath.split(":")) {
        string candidate = p.length ? p ~ "/" ~ name : name;
        if(exists(candidate)) return candidate;
    }
    return "";
}

void runBackground(string cmd) {
    // Execute a command asynchronously without waiting and track it
    auto id = nextBgId++;
    size_t idx = bgJobs.length;
    auto thr = new Thread({
        run(cmd);
        bgJobs[idx].running = false;
    });
    bgJobs ~= BgJob(id, cmd, thr, true);
    thr.start();
    writeln("[", id, "] ", cmd, " &");
}

void runCommand(string cmd, bool skipAlias=false, size_t callLine=0, string callFile="") {
    callStack ~= CallFrame(callLine, callFile, cmd);
    scope(exit) callStack.popBack();

    history ~= cmd;
    auto tokens = cmd.split();
    if(tokens.length == 0) return;

    if(!skipAlias) {
        string lastAlias;
        int aliasDepth = 0;
        while(auto ali = tokens[0] in aliases) {
            if(tokens[0] == lastAlias || aliasDepth > 10) break;
            lastAlias = tokens[0];
            auto aliStr = *ali;
            auto aliTokens = aliStr.split();
            tokens = aliTokens ~ tokens[1 .. $];
            aliasDepth++;
        }
    }

    // variable expansion
    foreach(ref t; tokens) {
        if(t.length > 1 && t[0] == '$') {
            auto key = t[1 .. $];
            if(auto val = key in variables) t = *val;
        }
    }

    // variable assignment of form name=value
    auto eqPos = tokens[0].indexOf('=');
    if(eqPos > 0 && tokens.length == 1) {
        auto name = tokens[0][0 .. eqPos];
        auto value = tokens[0][eqPos + 1 .. $];
        variables[name] = value;
        return;
    }

    auto op = tokens[0];
    if(auto en = op in builtinEnabled) {
        if(!*en && op != "enable") {
            auto rc = system(cmd);
            if(rc != 0) writeln("Unknown command: ", op);
            return;
        }
    }
    if(op == "command") {
        bool useDefaultPath = false;
        bool verbose = false;
        bool veryVerbose = false;
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-")) {
            auto t = tokens[idx];
            if(t == "-p") useDefaultPath = true;
            else if(t == "-v") verbose = true;
            else if(t == "-V") veryVerbose = true;
            else break;
            idx++;
        }
        if(idx >= tokens.length) {
            writeln("command: missing command");
            return;
        }
        auto cmdName = tokens[idx];
        auto args = tokens[idx+1 .. $];
        auto subCmd = cmdName ~ (args.length ? " " ~ args.join(" ") : "");

        auto oldPath = environment.get("PATH", "");
        if(useDefaultPath)
            environment["PATH"] = "/bin:/usr/bin:/usr/local/bin";

        import mstd.file : exists;

        auto searchPath = environment.get("PATH", "");
        string cmdPath;
        foreach(p; searchPath.split(":")) {
            string candidate = p.length ? p ~ "/" ~ cmdName : cmdName;
            if(exists(candidate)) { cmdPath = candidate; break; }
        }

        if(verbose || veryVerbose) {
            if(cmdPath.length)
                writeln(veryVerbose ? cmdName ~ " is " ~ cmdPath : cmdPath);
            else
                writeln(cmdName, " not found");
        } else {
            auto rc = system(subCmd);
            if(rc != 0) {
                writeln(cmdName, " exited with status ", rc);
            }
        }

        if(useDefaultPath)
            environment["PATH"] = oldPath;
    } else if(op == "builtin") {
        if(tokens.length < 2) {
            writeln("Usage: builtin shell-builtin [args]");
            return;
        }
        auto subCmd = tokens[1 .. $].join(" ");
        runCommand(subCmd, true, __LINE__, __FILE__);
    } else if(op == "echo") {
        writeln(tokens[1 .. $].join(" "));
    } else if(op == "+" || op == "-" || op == "*" || op == "/") {
        if(tokens.length < 3) {
            writeln("Invalid arithmetic expression");
            return;
        }
        int a = to!int(tokens[1]);
        int b = to!int(tokens[2]);
        int result;
        final switch(op) {
            case "+": result = a + b; break;
            case "-": result = a - b; break;
            case "*": result = a * b; break;
            case "/": result = b == 0 ? 0 : a / b; break;
        }
        writeln(result);
    } else if(op == "bc") {
        if(tokens.length < 2) {
            writeln("Usage: bc expression");
            return;
        }
        auto expr = tokens[1 .. $].join(" ");
        try {
            auto res = bcEval(expr);
            writeln(res);
        } catch(Exception e) {
            writeln("bc: invalid expression");
        }
    } else if(op == "dc") {
        if(tokens.length < 2) {
            writeln("Usage: dc expression");
            return;
        }
        auto expr = tokens[1 .. $].join(" ");
        try {
            auto res = dcEval(expr);
            if(res.length > 0)
                writeln(res);
        } catch(Exception e) {
            writeln("dc: invalid expression");
        }
    } else if(op == "dd") {
        ddCommand(tokens);
    } else if(op == "ddrescue") {
        ddrescueCommand(tokens);
    } else if(op == "fdformat") {
        fdformatCommand(tokens);
    } else if(op == "fdisk") {
        fdiskCommand(tokens);
    } else if(op == "df") {
        dfCommand(tokens);
    } else if(op == "du") {
        duCommand(tokens);
    } else if(op == "dmesg") {
        dmesgCommand(tokens);
    } else if(op == "for") {
        if(tokens.length < 3) {
            writeln("Usage: for start..end command");
            return;
        }
        auto rangeParts = tokens[1].split("..");
        if(rangeParts.length != 2) {
            writeln("Invalid range");
            return;
        }
        int start = to!int(rangeParts[0]);
        int finish = to!int(rangeParts[1]);
        string sub = tokens[2 .. $].join(" ");
        loopDepth++;
        foreach(i; iota(start, finish + 1)) {
            if(breakCount > 0) { breakCount--; break; }
            runCommand(sub, false, __LINE__, __FILE__);
            if(breakCount > 0) { breakCount--; break; }
        }
        if(loopDepth > 0) loopDepth--;
    } else if(op == "break") {
        size_t n = 1;
        if(tokens.length >= 2) {
            try {
                n = to!size_t(tokens[1]);
            } catch(Exception) {
                writeln("break: numeric argument required");
                return;
            }
        }
        if(n < 1) {
            writeln("break: argument must be >= 1");
            return;
        }
        if(loopDepth == 0) {
            writeln("break: not in a loop");
            return;
        }
        breakCount = cast(int)n;
    } else if(op == "cd") {
        bool physical = false; // -P
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-") && tokens[idx] != "-") {
            auto t = tokens[idx];
            if(t == "--") { idx++; break; }
            else if(t == "-P") { physical = true; }
            else if(t == "-L") { physical = false; }
            else break;
            idx++;
        }

        string arg = idx < tokens.length ? tokens[idx] : "";
        string cwd = getcwd();
        string dest;
        bool printPath = false;
        if(arg.length == 0) {
            dest = environment.get("HOME", "");
            if(dest.length == 0) {
                writeln("cd: HOME not set");
                return;
            }
        } else if(arg == "-") {
            dest = environment.get("OLDPWD", "");
            if(dest.length == 0) {
                writeln("cd: OLDPWD not set");
                return;
            }
            printPath = true;
        } else {
            dest = arg;
        }

        if(!dest.startsWith("/") && !dest.startsWith("./") && !dest.startsWith("../")) {
            auto cdpath = environment.get("CDPATH", "");
            foreach(p; cdpath.split(":")) {
                if(p.length == 0) p = ".";
                auto candidate = p ~ "/" ~ dest;
                try {
                    chdir(candidate);
                    dest = candidate;
                    printPath = true;
                    break;
                } catch(Exception) {
                }
            }
            chdir(cwd);
        }

        string finalDest = dest;
        try {
            chdir(finalDest);
            string newPath;
            if(physical)
                newPath = getcwd();
            else {
                if(dest.startsWith("/"))
                    newPath = dest;
                else
                    newPath = cwd ~ "/" ~ dest;
            }
            environment["OLDPWD"] = cwd;
            environment["PWD"] = newPath;
            if(printPath) writeln(newPath);
        } catch(Exception e) {
            writeln("cd: cannot access ", dest);
        }
    } else if(op == "pushd") {
        string cwd = getcwd();
        string dest = tokens.length > 1 ? tokens[1] : environment.get("HOME", "");
        if(dest.length == 0) dest = ".";
        try {
            chdir(dest);
            auto newPath = getcwd();
            dirStack = [newPath] ~ dirStack;
            environment["OLDPWD"] = cwd;
            environment["PWD"] = newPath;
            foreach(i, d; dirStack) {
                write(d);
                if(i < dirStack.length - 1) write(" ");
            }
            writeln();
        } catch(Exception e) {
            writeln("pushd: cannot access ", dest);
        }
    } else if(op == "popd") {
        if(dirStack.length <= 1) {
            writeln("popd: directory stack empty");
        } else {
            string old = dirStack[0];
            dirStack = dirStack[1 .. $];
            string dest = dirStack[0];
            try {
                chdir(dest);
                environment["OLDPWD"] = old;
                environment["PWD"] = dest;
                foreach(i, d; dirStack) {
                    write(d);
                    if(i < dirStack.length - 1) write(" ");
                }
                writeln();
            } catch(Exception e) {
                writeln("popd: cannot access ", dest);
            }
        }
    } else if(op == "dirs") {
        foreach(i, d; dirStack) {
            write(d);
            if(i < dirStack.length - 1) write(" ");
        }
        writeln();
    } else if(op == "pwd") {
        writeln(getcwd());
    } else if(op == "ls") {
        ls.lsCommand(tokens);
    } else if(op == "dir") {
        dir.dirCommand(tokens);
    } else if(op == "dircolors") {
        dircolors.dircolorsCommand(tokens);
    } else if(op == "cat") {
        bool showEnds = false;
        bool number = false;
        bool numberNonBlank = false;
        bool squeezeBlank = false;
        bool showTabs = false;
        bool showNonPrint = false;
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-")) {
            auto t = tokens[idx];
            final switch(t) {
                case "-E": case "--show-ends": showEnds = true; break;
                case "-n": case "--number": number = true; break;
                case "-b": case "--number-nonblank": numberNonBlank = true; break;
                case "-s": case "--squeeze-blank": squeezeBlank = true; break;
                case "-T": case "--show-tabs": showTabs = true; break;
                case "-v": case "--show-nonprinting": showNonPrint = true; break;
                case "-A": case "--show-all": showEnds = true; showTabs = true; showNonPrint = true; break;
                case "-e": showEnds = true; showNonPrint = true; break;
                case "-t": showTabs = true; showNonPrint = true; break;
                case "--help":
                    writeln("Usage: cat [OPTIONS] [FILE]...");
                    return;
                case "--":
                    idx++;
                    goto filesStart;
                default:
                    if(t.length > 1)
                        writeln("cat: invalid option ", t);
                    else break;
            }
            idx++;
        }
        filesStart:
        if(numberNonBlank) number = false;
        auto files = tokens[idx .. $];
        if(files.length == 0) files = ["-"];
        size_t lineNum = 1;
        bool prevBlank = false;

        auto processLine = (ref string line) {
            bool blank = line.length == 0;
            if(showTabs) replace(line, "\t", "^I");
            if(showNonPrint) {
                string outStr;
                foreach(dchar c; line) {
                    if(c == '\t' || c == '\n') outStr ~= cast(char)c;
                    else if(c < 32) outStr ~= "^" ~ cast(char)(c + 64);
                    else if(c == 127) outStr ~= "^?";
                    else if(c > 127) {
                        auto code = c - 128;
                        outStr ~= "M-";
                        if(code < 32) outStr ~= "^" ~ cast(char)(code + 64);
                        else if(code == 127) outStr ~= "^?";
                        else outStr ~= cast(char)code;
                    } else outStr ~= cast(char)c;
                }
                line = outStr;
            }
            if(showEnds) line ~= "$";
            if(squeezeBlank) {
                if(blank) {
                    if(prevBlank) return;
                    prevBlank = true;
                } else {
                    prevBlank = false;
                }
            }
            if(numberNonBlank) {
                if(blank) writeln(line); else { writefln("%6d\t%s", lineNum, line); lineNum++; }
            } else if(number) {
                writefln("%6d\t%s", lineNum, line); lineNum++;
            } else {
                writeln(line);
            }
        };

        foreach(f; files) {
            if(f == "-") {
                string line;
                while((line = readln()) !is null) {
                    line = line.stripRight("\n");
                    processLine(line);
                }
            } else {
                try {
                    foreach(line; readText(f).splitLines) {
                        auto l = line;
                        processLine(l);
                    }
                } catch(Exception) {
                    writeln("cat: cannot read ", f);
                }
            }
        }
    } else if(op == "head") {
        if(tokens.length < 2) {
            writeln("head: missing file operand");
            return;
        }
        string file = tokens[1];
        size_t lines = 10;
        try {
            auto text = readText(file).splitLines;
            foreach(i, l; text) {
                if(i >= lines) break;
                writeln(l);
            }
        } catch(Exception e) {
            writeln("head: cannot read ", file);
        }
    } else if(op == "tail") {
        if(tokens.length < 2) {
            writeln("tail: missing file operand");
            return;
        }
        string file = tokens[1];
        size_t lines = 10;
        try {
            auto text = readText(file).splitLines;
            auto start = text.length > lines ? text.length - lines : 0;
            foreach(l; text[start .. $]) {
                writeln(l);
            }
        } catch(Exception e) {
            writeln("tail: cannot read ", file);
        }
    } else if(op == "grep") {
        if(tokens.length < 3) {
            writeln("grep pattern file...");
            return;
        }
        auto pattern = tokens[1];
        foreach(f; tokens[2 .. $]) {
            try {
                foreach(line; readText(f).splitLines) {
                    if(line.canFind(pattern)) writeln(line);
                }
            } catch(Exception e) {
                writeln("grep: cannot read ", f);
            }
        }
    } else if(op == "fgrep") {
        fgrep.fgrepCommand(tokens);
    } else if(op == "egrep") {
        egrep.egrepCommand(tokens);
    } else if(op == "file") {
        file.fileCommand(tokens);
    } else if(op == "find") {
        find.findCommand(tokens);
    } else if(op == "fmt") {
        fmt.fmtCommand(tokens);
    } else if(op == "fold") {
        fold.foldCommand(tokens);
    } else if(op == "fsck") {
        fsck.fsckCommand(tokens);
    } else if(op == "fuser") {
        fuser.fuserCommand(tokens);
    } else if(op == "getfacl") {
        getfacl.getfaclCommand(tokens);
    } else if(op == "groupadd") {
        groupadd.groupaddCommand(tokens);
    } else if(op == "groupdel") {
        groupdel.groupdelCommand(tokens);
    } else if(op == "groupmod") {
        groupmod.groupmodCommand(tokens);
    } else if(op == "groups") {
        groups.groupsCommand(tokens);
    } else if(op == "gzip") {
        gzip.gzipCommand(tokens);
    } else if(op == "hash") {
        bool reset = false;
        string filename;
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-")) {
            auto t = tokens[idx];
            if(t == "-r") { reset = true; idx++; }
            else if(t == "-p") {
                if(idx + 2 >= tokens.length) {
                    writeln("hash: option requires an argument -- p");
                    return;
                }
                filename = tokens[idx+1];
                hashedPaths[tokens[idx+2]] = filename;
                idx += 3;
                return;
            } else break;
        }
        if(reset) {
            if(idx < tokens.length) {
                foreach(name; tokens[idx .. $]) hashedPaths.remove(name);
            } else {
                hashedPaths.clear();
            }
        } else if(idx < tokens.length) {
            foreach(name; tokens[idx .. $]) {
                auto p = findInPath(name);
                if(p.length) hashedPaths[name] = p;
            }
        } else {
            foreach(name, path; hashedPaths) {
                writeln(path, "\t", name);
            }
        }
    } else if(op == "eject") {
        eject.ejectCommand(tokens);
    } else if(op == "env") {
        bool ignore = false;
        string[] unsets;
        string[string] assigns;
        size_t idx = 1;
        while(idx < tokens.length) {
            auto t = tokens[idx];
            if(t == "-" || t == "-i" || t == "--ignore-environment") {
                ignore = true;
                idx++;
            } else if(t == "-u" || t == "--unset") {
                if(idx + 1 >= tokens.length) {
                    writeln("env: option requires an argument -- 'u'");
                    return;
                }
                unsets ~= tokens[idx + 1];
                idx += 2;
            } else if(t.startsWith("-u") && t.length > 2) {
                unsets ~= t[2 .. $];
                idx++;
            } else if(t.startsWith("--unset=")) {
                unsets ~= t[8 .. $];
                idx++;
            } else if(t.indexOf('=') > 0 && !t.startsWith("-")) {
                auto pos = t.indexOf('=');
                assigns[t[0 .. pos]] = t[pos+1 .. $];
                idx++;
            } else {
                break;
            }
        }

        auto cmdArgs = tokens[idx .. $];
        auto oldEnv = environment.toAA;
        if(ignore) {
            foreach(name, _; oldEnv) environment.remove(name);
        }
        foreach(name; unsets) environment.remove(name);
        foreach(name, val; assigns) environment[name] = val;

        if(cmdArgs.length == 0) {
            foreach(name, val; environment.toAA) {
                writeln(name, "=", val);
            }
        } else {
            auto sub = cmdArgs.join(" ");
            runCommand(sub, false, __LINE__, __FILE__);
        }

        foreach(name, _; environment.toAA) environment.remove(name);
        foreach(name, val; oldEnv) environment[name] = val;
    } else if(op == "eval") {
        if(tokens.length > 1) {
            auto sub = tokens[1 .. $].join(" ");
            run(sub);
        }
    } else if(op == "exec") {
        if(tokens.length < 2) {
            writeln("exec: missing command");
            return;
        }
        version(Posix) {
            import mstd.string : toStringz;
            import core.stdc.stdlib : exit;
            const(char)*[] args;
            foreach(t; tokens[1 .. $]) args ~= t.toStringz;
            args ~= null;
            execvp(tokens[1].toStringz, args.ptr);
            writeln("exec: failed to execute ", tokens[1]);
            exit(127);
        } else {
            auto sub = tokens[1 .. $].join(" ");
            auto rc = system(sub);
            import core.stdc.stdlib : exit;
            exit(rc);
        }
    } else if(op == "exit") {
        int code = 0;
        if(tokens.length > 1) {
            try {
                code = to!int(tokens[1]);
            } catch(Exception) {
                // ignore invalid argument
            }
        }
        import core.stdc.stdlib : exit;
        exit(code);
    } else if(op == "expand") {
        expand.expandCommand(tokens);
    } else if(op == "false") {
        import core.stdc.stdlib : exit;
        exit(1);
    } else if(op == "expr") {
        exprCommand(tokens);
    } else if(op == "awk") {
        awkCommand(tokens);
    } else if(op == "cut") {
        cutCommand(tokens);
    } else if(op == "basename") {
        if(tokens.length < 2) {
            writeln("basename: missing operand");
            return;
        }
        auto path = tokens[1];
        string base;
        auto pos = path.lastIndexOf('/');
        if(pos >= 0)
            base = path[pos + 1 .. $];
        else
            base = path;
        if(tokens.length > 2) {
            auto suf = tokens[2];
            if(base.endsWith(suf))
                base = base[0 .. $ - suf.length];
        }
        writeln(base);
    } else if(op == "dirname") {
        if(tokens.length < 2) {
            writeln("dirname: missing operand");
            return;
        }
        auto path = tokens[1];
        auto dir = mstd.path.dirName(path);
        if(dir.length == 0) dir = ".";
        writeln(dir);
    } else if(op == "animal_case") {
        string animal;
        if(tokens.length >= 2) {
            animal = tokens[1];
        } else {
            write("Enter the name of an animal: ");
            auto inp = readln();
            if(inp is null) return;
            animal = inp.strip;
        }
        string legs;
        final switch(animal) {
            case "horse": case "dog": case "cat": legs = "four"; break;
            case "man": case "kangaroo": legs = "two"; break;
            default:
                writeln("The ", animal, " has an unknown number of legs.");
                return;
        }
        writeln("The ", animal, " has ", legs, " legs.");
    }
    else if(op == "base64") {
        bool decode = false;
        bool ignore = false;
        size_t wrapLen = 76;
        string[] files;
        size_t i = 1;
        while(i < tokens.length) {
            auto t = tokens[i];
            if(t == "-d" || t == "--decode") {
                decode = true;
            } else if(t == "-i" || t == "--ignore-garbage") {
                ignore = true;
            } else if(t.startsWith("--wrap=")) {
                wrapLen = to!size_t(t[7 .. $]);
            } else if(t == "-w" || t == "--wrap") {
                if(i + 1 < tokens.length) {
                    wrapLen = to!size_t(tokens[i + 1]);
                    i++;
                }
            } else if(t == "--help") {
                writeln("Usage: base64 [OPTION]... [FILE]");
                writeln("  -d, --decode          Decode data");
                writeln("  -i, --ignore-garbage  Ignore non-alphabet characters");
                writeln("  -w, --wrap=COLS       Wrap encoded lines after COLS (default 76)");
                return;
            } else if(t == "--version") {
                writeln("base64 (shell builtin) 1.0");
                return;
            } else {
                files ~= t;
            }
            i++;
        }

        auto process = (string txt) {
            if(decode) {
                auto bytes = base64Decode(txt, ignore);
                writeln(cast(string)bytes);
            } else {
                auto encoded = base64Encode(cast(ubyte[])txt, wrapLen);
                if(wrapLen == 0)
                    write(encoded);
                else
                    writeln(encoded);
            }
        };

        if(files.length == 0) {
            string line;
            while((line = readln()) !is null) {
                process(line);
            }
        } else {
            foreach(f; files) {
                try {
                    auto content = readText(f);
                    process(content);
                } catch(Exception e) {
                    writeln("base64: cannot read ", f);
                }
            }
        }
    } else if(op == "base32") {
        bool decode = false;
        bool ignore = false;
        size_t wrapLen = 76;
        string[] files;
        size_t i = 1;
        while(i < tokens.length) {
            auto t = tokens[i];
            if(t == "-d" || t == "--decode") {
                decode = true;
            } else if(t == "-i" || t == "--ignore-garbage") {
                ignore = true;
            } else if(t.startsWith("--wrap=")) {
                wrapLen = to!size_t(t[7 .. $]);
            } else if(t == "-w" || t == "--wrap") {
                if(i + 1 < tokens.length) {
                    wrapLen = to!size_t(tokens[i + 1]);
                    i++;
                }
            } else if(t == "--help") {
                writeln("Usage: base32 [OPTION]... [FILE]");
                writeln("  -d, --decode          Decode data");
                writeln("  -i, --ignore-garbage  Ignore non-alphabet characters");
                writeln("  -w, --wrap=COLS       Wrap encoded lines after COLS (default 76)");
                return;
            } else if(t == "--version") {
                writeln("base32 (shell builtin) 1.0");
                return;
            } else {
                files ~= t;
            }
            i++;
        }

        auto process = (string txt) {
            if(decode) {
                auto bytes = base32Decode(txt, ignore);
                writeln(cast(string)bytes);
            } else {
                auto encoded = base32Encode(cast(ubyte[])txt, wrapLen);
                if(wrapLen == 0)
                    write(encoded);
                else
                    writeln(encoded);
            }
        };

        if(files.length == 0) {
            string line;
            while((line = readln()) !is null) {
                process(line);
            }
        } else {
            foreach(f; files) {
                try {
                    auto content = readText(f);
                    process(content);
                } catch(Exception e) {
                    writeln("base32: cannot read ", f);
                }
            }
        }
    } else if(op == "bzip2" || op == "bunzip2" || op == "bzcat" || op == "bzip2recover") {
        auto args = tokens[1 .. $].join(" ");
        string cmdLine;
        if(op == "bunzip2")
            cmdLine = "bzip2 -d " ~ args;
        else if(op == "bzcat")
            cmdLine = "bzip2 -dc " ~ args;
        else
            cmdLine = op ~ (args.length ? " " ~ args : "");
        auto rc = system(cmdLine);
        if(rc != 0)
            writeln(op, " failed with code ", rc);
    } else if(op == "mkdir") {
        if(tokens.length < 2) {
            writeln("mkdir: missing operand");
            return;
        }
        foreach(dir; tokens[1 .. $]) {
            try {
                mstd.file.mkdir(dir);
            } catch(Exception e) {
                writeln("mkdir: cannot create directory ", dir);
            }
        }
    } else if(op == "rmdir") {
        if(tokens.length < 2) {
            writeln("rmdir: missing operand");
            return;
        }
        foreach(dir; tokens[1 .. $]) {
            try {
                mstd.file.rmdir(dir);
            } catch(Exception e) {
                writeln("rmdir: failed to remove ", dir);
            }
        }
    } else if(op == "touch") {
        if(tokens.length < 2) {
            writeln("touch: missing file operand");
            return;
        }
        foreach(f; tokens[1 .. $]) {
            try {
                auto file = File(f, "a");
                file.close();
            } catch(Exception e) {
                writeln("touch: cannot touch ", f);
            }
        }
    } else if(op == "cp") {
        if(tokens.length != 3) {
            writeln("cp source dest");
            return;
        }
        try {
            mstd.file.copy(tokens[1], tokens[2]);
        } catch(Exception e) {
            writeln("cp: failed to copy");
        }
    } else if(op == "mv") {
        if(tokens.length != 3) {
            writeln("mv source dest");
            return;
        }
        try {
            mstd.file.rename(tokens[1], tokens[2]);
        } catch(Exception e) {
            writeln("mv: failed to move");
        }
    } else if(op == "rm") {
        if(tokens.length < 2) {
            writeln("rm: missing operand");
            return;
        }
        foreach(f; tokens[1 .. $]) {
            try {
                mstd.file.remove(f);
            } catch(Exception e) {
                writeln("rm: cannot remove ", f);
            }
        }
    } else if(op == "chattr") {
        if(tokens.length < 2) {
            writeln("Usage: chattr [options] mode files...");
            return;
        }
        auto args = tokens[1 .. $].join(" ");
        auto rc = system("chattr " ~ args);
        if(rc != 0)
            writeln("chattr failed with code ", rc);
    } else if(op == "chgrp") {
        if(tokens.length < 3 &&
           !(tokens.length >= 2 && tokens[1].startsWith("--reference="))) {
            writeln("Usage: chgrp group file...");
            return;
        }
        auto args = tokens[1 .. $].join(" ");
        auto rc = system("chgrp " ~ args);
        if(rc != 0)
            writeln("chgrp failed with code ", rc);
    } else if(op == "chown") {
        if(tokens.length < 3 &&
           !(tokens.length >= 2 && tokens[1].startsWith("--reference="))) {
            writeln("Usage: chown owner[:group] file...");
            return;
        }
        auto args = tokens[1 .. $].join(" ");
        auto rc = system("chown " ~ args);
        if(rc != 0)
            writeln("chown failed with code ", rc);
    } else if(op == "chpasswd") {
        auto args = tokens[1 .. $].join(" ");
        auto cmdLine = "chpasswd" ~ (args.length ? " " ~ args : "");
        auto rc = system(cmdLine);
        if(rc != 0)
            writeln("chpasswd failed with code ", rc);
    } else if(op == "chmod") {
        if(tokens.length < 3 &&
           !(tokens.length >= 2 && tokens[1].startsWith("--reference="))) {
            writeln("Usage: chmod mode file...");
            return;
        }
        auto args = tokens[1 .. $].join(" ");
        auto rc = system("chmod " ~ args);
        if(rc != 0)
            writeln("chmod failed with code ", rc);
    } else if(op == "chroot") {
        if(tokens.length >= 2 && tokens[1] == "--help") {
            writeln("Usage: chroot NEWROOT [COMMAND [ARGS]...]");
            writeln("Run COMMAND with root directory set to NEWROOT.");
            return;
        } else if(tokens.length >= 2 && tokens[1] == "--version") {
            writeln("chroot (shell builtin) 0.1");
            return;
        } else if(tokens.length < 2) {
            writeln("Usage: chroot NEWROOT [COMMAND [ARGS]...]");
            return;
        }

        auto newroot = tokens[1];
        string cmdLine;
        if(tokens.length > 2)
            cmdLine = tokens[2 .. $].join(" ");

        try {
            version(Posix) {
                if(chroot(newroot.toStringz) != 0) {
                    writeln("chroot: unable to change root to ", newroot);
                    return;
                }
                chdir("/");
            }
        } catch(Exception e) {
            writeln("chroot failed: ", e.msg);
            return;
        }

        if(cmdLine.length)
            run(cmdLine);
        else
            repl();
    } else if(op == "cfdisk") {
        string optP;
        string device = "/dev/vda";
        size_t idx = 1;
        while(idx < tokens.length) {
            auto t = tokens[idx];
            if(t == "-P") {
                idx++;
                if(idx >= tokens.length) {
                    writeln("cfdisk: option requires an argument -- P");
                    return;
                }
                optP = tokens[idx];
            } else if(t == "-h" || t == "--help") {
                writeln("Usage: cfdisk [OPTIONS] [DEVICE]");
                writeln("  -P [t|r]   Print the partition table in text (t) or raw (r) format");
                writeln("  -h, --help Show this help message");
                writeln("  -v         Print version information");
                return;
            } else if(t == "-v" || t == "--version") {
                writeln("cfdisk (shell builtin) 0.1");
                return;
            } else if(t == "--") {
                idx++;
                break;
            } else if(t.startsWith("-")) {
                writeln("cfdisk: unknown option ", t);
                return;
            } else {
                device = t;
            }
            idx++;
        }
        if(idx < tokens.length)
            device = tokens[idx];
        if(device.startsWith("/dev/"))
            device = device[5 .. $];
        string sys = "/sys/block/" ~ device;
        import mstd.file : exists, dirEntries;
        if(!exists(sys)) {
            writeln("cfdisk: device /dev/" ~ device ~ " not found");
            return;
        }
        long sectorSize = to!long(readText(sys ~ "/queue/hw_sector_size").strip);
        long diskSectors = to!long(readText(sys ~ "/size").strip);
        long diskMB = (diskSectors * sectorSize) / 1024 / 1024;

        auto printTable = delegate() {
            writefln("%-12s %-10s", "Device", "Size(MB)");
            foreach(entry; dirEntries(sys, SpanMode.shallow)) {
                auto base = entry.name.split("/").back;
                if(!base.startsWith(device) || base == device) continue;
                auto sizePath = entry.name ~ "/size";
                if(!exists(sizePath)) continue;
                long sz;
                try { sz = to!long(readText(sizePath).strip); } catch(Exception) { continue; }
                auto mb = (sz * sectorSize) / 1024 / 1024;
                writefln("/dev/%-8s %10d", base, mb);
            }
        };

        auto printRaw = delegate() {
            writeln("Disk /dev/" ~ device ~ ": " ~ to!string(diskMB) ~ " MB");
            foreach(entry; dirEntries(sys, SpanMode.shallow)) {
                auto base = entry.name.split("/").back;
                if(!base.startsWith(device) || base == device) continue;
                auto sizePath = entry.name ~ "/size";
                if(!exists(sizePath)) continue;
                long sz;
                try { sz = to!long(readText(sizePath).strip); } catch(Exception) { continue; }
                writeln(base, " ", sz);
            }
        };

        if(optP == "t") {
            printTable();
        } else if(optP == "r") {
            printRaw();
        } else if(optP.length == 0) {
            writeln("Disk /dev/" ~ device ~ ": " ~ to!string(diskMB) ~ " MB");
            printTable();
        } else {
            writeln("cfdisk: invalid -P option");
        }
    } else if(op == "chkconfig") {
        chkconfigCommand(tokens);
    } else if(op == "cksum") {
        auto files = tokens[1 .. $];
        if(files.length == 0) {
            cksumStdin();
        } else {
            foreach(f; files)
                cksumFile(f);
        }
    } else if(op == "md5sum") {
        auto files = tokens[1 .. $];
        if(files.length == 0) {
            md5sum.md5sumStdin();
        } else {
            foreach(f; files)
                md5sum.md5sumFile(f);
        }
    } else if(op == "cmp") {
        bool optC = false;
        bool optL = false;
        bool optSilent = false;
        size_t ignore = 0;
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-")) {
            auto t = tokens[idx];
            if(t == "-c" || t == "--print-chars") optC = true;
            else if(t == "-l" || t == "--verbose") optL = true;
            else if(t == "-s" || t == "--quiet" || t == "--silent") optSilent = true;
            else if(t.startsWith("--ignore-initial="))
                ignore = to!size_t(t[17 .. $]);
            else if(t == "-v" || t == "--version") {
                writeln("cmp (shell builtin) 1.0");
                return;
            } else if(t == "--") {
                idx++;
                break;
            } else {
                break;
            }
            idx++;
        }
        if(idx >= tokens.length) {
            writeln("Usage: cmp [OPTION]... FILE1 [FILE2]");
            return;
        }
        string file1 = tokens[idx];
        string file2 = (idx + 1 < tokens.length) ? tokens[idx + 1] : "-";

        cmp.cmpFiles(file1, file2, ignore, optC, optL, optSilent);
    } else if(op == "diff") {
        diff.diffCommand(tokens);
    } else if(op == "diff3") {
        diff3.diff3Command(tokens);
    } else if(op == "dos2unix") {
        dos2unix.dos2unixCommand(tokens);
    } else if(op == "comm") {
        bool s1 = false;
        bool s2 = false;
        bool s3 = false;
        bool check = false;
        string delim = "\t";
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-")) {
            auto t = tokens[idx];
            if(t == "-1") s1 = true;
            else if(t == "-2") s2 = true;
            else if(t == "-3") s3 = true;
            else if(t == "--check-order") check = true;
            else if(t == "--nocheck-order") check = false;
            else if(t.startsWith("--output-delimiter="))
                delim = t[19 .. $];
            else if(t == "--output-delimiter") {
                if(idx + 1 < tokens.length) { delim = tokens[idx + 1]; idx++; }
            } else if(t == "--version") {
                writeln("comm (shell builtin) 1.0");
                return;
            } else if(t == "--help") {
                writeln("Usage: comm [OPTION]... FILE1 FILE2");
                return;
            } else if(t == "--") {
                idx++;
                break;
            } else {
                break;
            }
            idx++;
        }
        if(idx + 1 >= tokens.length) {
            writeln("Usage: comm [OPTION]... FILE1 FILE2");
            return;
        }
        string file1 = tokens[idx];
        string file2 = tokens[idx + 1];

        comm.commFiles(file1, file2, s1, s2, s3, check, delim);
    } else if(op == "cron") {
        cronCommand(tokens);
    } else if(op == "crontab") {
        crontabCommand(tokens);
    } else if(op == "csplit") {
        string prefix = "xx";
        int digits = 2;
        bool quiet = false;
        bool elide = false;
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-")) {
            auto t = tokens[idx];
            if(t == "-s" || t == "--silent" || t == "--quiet") {
                quiet = true;
            } else if(t == "-z" || t == "--elide-empty-files") {
                elide = true;
            } else if(t.startsWith("-f")) {
                if(t.length > 2)
                    prefix = t[2 .. $];
                else if(idx + 1 < tokens.length) { prefix = tokens[idx+1]; idx++; }
            } else if(t.startsWith("--prefix=")) {
                prefix = t[9 .. $];
            } else if(t.startsWith("-n")) {
                if(t.length > 2)
                    digits = to!int(t[2 .. $]);
                else if(idx + 1 < tokens.length) { digits = to!int(tokens[idx+1]); idx++; }
            } else if(t.startsWith("--digits=")) {
                digits = to!int(t[9 .. $]);
            } else if(t == "--") {
                idx++;
                break;
            } else {
                break;
            }
            idx++;
        }
        if(idx >= tokens.length) {
            writeln("Usage: csplit [OPTION]... FILE PATTERN...");
            return;
        }
        string file = tokens[idx];
        idx++;
        auto pats = tokens[idx .. $];
        csplit.csplitFile(file, pats, prefix, digits, quiet, elide);
    } else if(op == "cal") {
        bool monday = false;
        bool yearFlag = false;
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-")) {
            auto t = tokens[idx];
            if(t == "-m") monday = true;
            else if(t == "-s") monday = false;
            else if(t == "-y") yearFlag = true;
            idx++;
        }

        auto now = Clock.currTime();
        int month = now.month;
        int year = now.year;

        int args = cast(int)tokens.length - cast(int)idx;
        if(args == 1) {
            year = to!int(tokens[idx]);
            yearFlag = true;
        } else if(args >= 2) {
            month = to!int(tokens[idx]);
            year = to!int(tokens[idx + 1]);
        }

        if(yearFlag)
            printYear(year, monday);
        else
            printMonth(month, year, monday);
    } else if(op == "caller") {
        size_t level = 0;
        if(tokens.length > 1) {
            try {
                level = to!size_t(tokens[1]);
            } catch(Exception) {
                writeln("caller: invalid level");
                return;
            }
        }
        if(level >= callStack.length - 1) {
            // no output if level outside stack
        } else {
            auto frame = callStack[$ - 2 - level];
            if(frame.cmd.length)
                writeln(frame.line, " ", frame.cmd, " ", frame.file);
            else
                writeln(frame.line, " ", frame.file);
        }
    } else if(op == "date") {
        dateCommand(tokens);
    } else if(op == "bg") {
        if(tokens.length == 1) {
            if(bgJobs.length == 0) {
                writeln("bg: no current job");
            } else {
                auto ref job = bgJobs[$-1];
                if(!job.running) {
                    job.running = true;
                    job.thread.start();
                }
            }
        } else if(tokens[1].startsWith("%")) {
            auto id = to!size_t(tokens[1][1 .. $]);
            bool found = false;
            foreach(ref job; bgJobs) {
                if(job.id == id) {
                    found = true;
                    if(!job.running) {
                        job.running = true;
                        job.thread.start();
                    }
                }
            }
            if(!found) writeln("bg: ", tokens[1], ": no such job");
        } else {
            auto sub = tokens[1 .. $].join(" ");
            runBackground(sub);
        }
    } else if(op == "fg") {
        if(bgJobs.length == 0) {
            writeln("fg: no current job");
            return;
        }
        size_t idx;
        bool found = false;
        if(tokens.length == 1) {
            idx = bgJobs.length - 1;
            found = true;
        } else if(tokens[1].startsWith("%")) {
            auto id = to!size_t(tokens[1][1 .. $]);
            foreach(i, ref job; bgJobs) {
                if(job.id == id) {
                    idx = i;
                    found = true;
                    break;
                }
            }
        }
        if(!found) {
            writeln("fg: " ~ tokens[1] ~ ": no such job");
            return;
        }
        auto ref job = bgJobs[idx];
        if(!job.running) {
            job.running = true;
            job.thread.start();
        }
        job.thread.join();
        bgJobs = bgJobs.remove(idx);
    } else if(op == "at") {
        if(tokens.length < 3) {
            writeln("Usage: at seconds command");
            return;
        }
        auto delay = to!long(tokens[1]);
        auto sub = tokens[2 .. $].join(" ");
        auto runAt = Clock.currTime() + dur!"seconds"(delay);
        auto job = AtJob(nextAtId++, sub, runAt, false);
        atJobs ~= job;
        auto idx = atJobs.length - 1;
        taskPool.put(() {
            Thread.sleep(dur!"seconds"(delay));
            if(!atJobs[idx].canceled) {
                run(sub);
                atJobs[idx].canceled = true;
            }
        });
        writeln("job ", job.id, " scheduled for ", runAt.toISOExtString());
    } else if(op == "atq") {
        foreach(job; atJobs) {
            if(!job.canceled)
                writeln(job.id, "\t", job.runAt.toISOExtString(), "\t", job.cmd);
        }
    } else if(op == "atrm") {
        if(tokens.length < 2) {
            writeln("Usage: atrm jobid [jobid ...]");
            return;
        }
        foreach(idStr; tokens[1 .. $]) {
            auto jid = to!size_t(idStr);
            foreach(ref job; atJobs)
                if(job.id == jid) job.canceled = true;
        }
    } else if(op == "alias") {
        if(tokens.length == 1 || (tokens.length == 2 && tokens[1] == "-p")) {
            foreach(name, val; aliases) {
                writeln("alias ", name, "='", val, "'");
            }
        } else {
            size_t start = 1;
            if(tokens.length > 1 && tokens[1] == "-p") start = 2;
            foreach(arg; tokens[start .. $]) {
                auto eq = arg.indexOf('=');
                if(eq > 0) {
                    auto name = arg[0 .. eq];
                    auto value = arg[eq+1 .. $];
                    aliases[name] = value;
                } else {
                    auto name = arg;
                    if(auto val = name in aliases)
                        writeln("alias ", name, "='", *val, "'");
                }
            }
        }
    } else if(op == "declare") {
        bool print = false;
        bool exportVar = false;
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-")) {
            foreach(ch; tokens[idx][1 .. $]) {
                final switch(ch) {
                    case 'p': print = true; break;
                    case 'x': exportVar = true; break;
                    default: break;
                }
            }
            idx++;
        }

        if(idx >= tokens.length) {
            foreach(name, val; variables) {
                writeln(name, "=\"", val, "\"");
            }
        } else {
            foreach(arg; tokens[idx .. $]) {
                auto eq = arg.indexOf('=');
                string name;
                string value;
                if(eq > 0) {
                    name = arg[0 .. eq];
                    value = arg[eq+1 .. $];
                    variables[name] = value;
                    if(exportVar) environment[name] = value;
                } else {
                    name = arg;
                    if(auto val = name in variables) value = *val; else value = "";
                }
                if(print) writeln(name, "=\"", value, "\"");
            }
        }
    } else if(op == "export") {
        bool print = false;
        bool remove = false;
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-")) {
            foreach(ch; tokens[idx][1 .. $]) {
                final switch(ch) {
                    case 'p': print = true; break;
                    case 'n': remove = true; break;
                    default: break;
                }
            }
            idx++;
        }

        if(idx >= tokens.length || print) {
            foreach(name, val; environment.toAA) {
                writeln("declare -x " ~ name ~ "=\"" ~ val ~ "\"");
            }
        } else {
            foreach(arg; tokens[idx .. $]) {
                auto eq = arg.indexOf('=');
                string name;
                string value;
                if(eq > 0) {
                    name = arg[0 .. eq];
                    value = arg[eq+1 .. $];
                } else {
                    name = arg;
                    if(auto val = name in variables) value = *val; else value = environment.get(name, "");
                }
                if(remove) {
                    environment.remove(name);
                } else {
                    environment[name] = value;
                    variables[name] = value;
                }
            }
        }
    } else if(op == "getopts") {
        getopts.getoptsCommand(tokens);
    } else if(op == "unalias") {
        if(tokens.length == 2 && tokens[1] == "-a") {
            aliases.clear();
        } else if(tokens.length >= 2) {
            foreach(name; tokens[1 .. $]) {
                aliases.remove(name);
            }
        } else {
            writeln("unalias: usage: unalias [-a] name [name ...]");
        }
    } else if(op == "bind") {
        if(tokens.length == 1 || (tokens.length == 2 && (tokens[1] == "-p" || tokens[1] == "-P" || tokens[1] == "-X"))) {
            foreach(key, val; keyBindings) {
                writeln("bind -x ", key, ":", val);
            }
        } else if(tokens.length >= 3 && tokens[1] == "-x") {
            foreach(arg; tokens[2 .. $]) {
                auto pos = arg.indexOf(':');
                if(pos <= 0) {
                    writeln("bind: invalid binding '", arg, "'");
                    continue;
                }
                auto key = arg[0 .. pos];
                auto cmdStr = arg[pos+1 .. $];
                keyBindings[key] = cmdStr;
            }
        } else if(tokens.length == 3 && tokens[1] == "-r") {
            keyBindings.remove(tokens[2]);
        } else if(tokens.length == 3 && tokens[1] == "-f") {
            import mstd.file : readText;
            try {
                foreach(line; readText(tokens[2]).splitLines) {
                    auto trimmed = line.strip;
                    if(trimmed.length == 0 || trimmed[0] == '#') continue;
                    auto pos = trimmed.indexOf(':');
                    if(pos <= 0) continue;
                    auto key = trimmed[0 .. pos];
                    auto cmdStr = trimmed[pos+1 .. $];
                    keyBindings[key] = cmdStr;
                }
            } catch(Exception e) {
                writeln("bind: cannot read ", tokens[2]);
            }
        } else {
            writeln("bind: unsupported options");
        }
    } else if(op == "enable") {
        bool listAll = tokens.length == 1;
        bool printStatus = false;
        bool disable = false;
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-")) {
            auto t = tokens[idx];
            if(t == "-a") { printStatus = true; listAll = true; }
            else if(t == "-p") { listAll = true; }
            else if(t == "-n") { disable = true; }
            else if(t == "-s" || t == "-d" || t == "-f") {
                // unsupported options ignored
            } else {
                break;
            }
            idx++;
        }
        if(listAll && idx >= tokens.length) {
            foreach(name; builtinNames) {
                bool en = builtinEnabled.get(name, true);
                if(printStatus)
                    writeln((en ? "enable " : "enable -n ") ~ name);
                else if(en)
                    writeln(name);
            }
            return;
        }
        foreach(name; tokens[idx .. $]) {
            if(name in builtinEnabled) {
                builtinEnabled[name] = !disable;
            } else {
                writeln("enable: " ~ name ~ " not a shell builtin");
            }
        }
    } else if(op == "apropos") {
        if(tokens.length < 2) {
            writeln("Usage: apropos [-a] [-e|-r|-w] keyword [...]");
            return;
        }

        bool useRegex = false;
        bool useWildcard = false;
        bool useExact = false;
        bool requireAll = false;
        size_t idx = 1;
        while(idx < tokens.length && tokens[idx].startsWith("-")) {
            auto t = tokens[idx];
            if(t == "-r" || t == "--regex") useRegex = true;
            else if(t == "-w" || t == "--wildcard") useWildcard = true;
            else if(t == "-e" || t == "--exact") useExact = true;
            else if(t == "-a" || t == "--and") requireAll = true;
            idx++;
        }
        auto keywords = tokens[idx .. $];
        if(keywords.length == 0) {
            writeln("Usage: apropos [-a] [-e|-r|-w] keyword [...]");
            return;
        }

        string helpText;
        try {
            helpText = readText("commands.txt");
        } catch(Exception e) {
            writeln("commands.txt not found");
            return;
        }

        foreach(line; helpText.splitLines) {
            bool matched = requireAll ? true : false;
            foreach(kw; keywords) {
                bool local = false;
                auto lowerLine = line.toLower;
                auto lowerKw = kw.toLower;
                if(useRegex) {
                    try {
                        auto r = regex(lowerKw, "i");
                        local = matchFirst(lowerLine, r) !is null;
                    } catch(Exception) {
                        continue;
                    }
                } else if(useWildcard) {
                    local = globMatch(lowerLine, lowerKw);
                } else if(useExact) {
                    foreach(word; lowerLine.split()) {
                        if(word == lowerKw) { local = true; break; }
                    }
                } else {
                    local = lowerLine.canFind(lowerKw);
                }
                if(requireAll) matched &= local; else matched |= local;
            }
            if(matched) writeln(line);
        }
    } else if(op == "help") {
        string helpText;
        try {
            helpText = readText("commands.txt");
        } catch(Exception e) {
            helpText = "commands.txt not found";
        }
        writeln(helpText);
    } else if(op == "history") {
        foreach(i, cmdLine; history) {
            writeln(i + 1, " ", cmdLine);
        }
    } else if(op == "iconv") {
        iconv.iconvCommand(tokens);
    } else if(op == "id") {
        id.idCommand(tokens);
    } else if(op == "if") {
        ifcmd.ifCommand(tokens);
    } else if(op == "ifconfig") {
        ifconfig.ifconfigCommand(tokens);
    } else if(op == "ifdown") {
        ifdown.ifdownCommand(tokens);
    } else if(op == "ifup") {
        ifup.ifupCommand(tokens);
    } else if(op == "import") {
        importcmd.importCommand(tokens);
    } else if(op == "install") {
        install.installCommand(tokens);
    } else if(op == "iostat") {
        iostat.iostatCommand(tokens);
    } else if(op == "ip") {
        ip.ipCommand(tokens);
    } else if(op == "jobs") {
        foreach(job; bgJobs) {
            auto status = job.running ? "Running" : "Done";
            writeln("[", job.id, "]\t", status, "\t", job.cmd);
        }
    } else if(op == "join") {
        join.joinCommand(tokens);
    } else if(op == "kill") {
        kill.killCommand(tokens);
    } else if(op == "killall") {
        killall.killallCommand(tokens);
    } else if(op == "klist") {
        klist.klistCommand(tokens);
    } else if(op == "less") {
        less.lessCommand(tokens);
    } else if(op == "let") {
        letcmd.letCommand(tokens);
    } else if(op == "link") {
        linkcmd.linkCommand(tokens);
    } else if(op == "ln") {
        ln.lnCommand(tokens);
    } else if(op == "local") {
        local.localCommand(tokens);
    } else if(op == "locate") {
        locate.locateCommand(tokens);
    } else if(op == "login") {
        login.loginCommand(tokens);
    } else if(op == "logname") {
        logname.lognameCommand(tokens);
    } else if(op == "logout") {
        logout.logoutCommand(tokens);
    } else if(op == "look") {
        look.lookCommand(tokens);
    } else if(op == "lsblk") {
        lsblk.lsblkCommand(tokens);
    } else if(op == "lsof") {
        lsof.lsofCommand(tokens);
    } else if(op == "apt" || op == "apt-get") {
        auto rc = system(cmd);
        if(rc != 0) {
            writeln(op, " failed with code ", rc);
        }
    } else {
        // attempt to run external command
        if(auto p = op in hashedPaths) {
            auto runCmd = *p ~ (tokens.length > 1 ? " " ~ tokens[1 .. $].join(" ") : "");
            auto rc = system(runCmd);
            if(rc != 0) {
                writeln("Unknown command: ", op);
            }
        } else {
            auto rc = system(cmd);
            if(rc != 0) {
                writeln("Unknown command: ", op);
            } else {
                auto fp = findInPath(op);
                if(fp.length) hashedPaths[op] = fp;
            }
        }
    }
}

void repl() {
    auto ps1 = environment.get("PS1", "sh> ");
    auto colorName = environment.get("PS_COLOR", "");
    string colorCode;
    if(auto c = colorName in colorCodes) colorCode = *c;
    auto reset = colorCode.length ? "\033[0m" : "";
    for(;;) {
        write(colorCode, ps1, reset);
        auto line = readln();
        if(line is null) break;
        line = line.strip;
        if(line == "exit") break;
        if(line.length == 0) continue;
        if(auto b = line in keyBindings) {
            run(*b);
            continue;
        }
        if(line == "!!" && history.length) {
            line = history[$-1];
            writeln(line);
        }
        run(line);
    }
}

void main(string[] args) {
    dirStack ~= getcwd();
    foreach(name; builtinNames) builtinEnabled[name] = true;
    if(args.length < 2) {
        repl();
        return;
    }
    run(args[1]);
}
