module shell.executor;

import std.stdio;
import shell.ast;
import shell.job;

    import core.sys.posix.unistd;
    import core.sys.posix.sys.wait;
    import core.sys.posix.fcntl;
    import core.sys.posix.sys.types : mode_t;
    import core.sys.posix.signal;


import std.path;
import std.process : environment;
import std.string : toStringz, strip, stripRight;
import core.stdc.string : strdup;
import core.stdc.stdio : perror;
import std.conv : to;
import std.algorithm : remove;
import std.array : array, join;

// --- Globals for Job Management ---
    __gshared Job[] jobTable;
    __gshared int nextJobId = 1;
    __gshared pid_t shell_pgid;
    __gshared bool extglobEnabled = false;
    __gshared string[] shellHistory;
    __gshared long startTime;
    __gshared pid_t lastBackgroundPid = 0;
    __gshared string shellFlags = "i"; // Default to interactive for now
    __gshared int currentLineNo = 1;

import std.random;

// --- Forward Declarations ---
    int launchJob(Node ast);
    void execute_job_in_child(Node ast);


// --- Builtin Implementations ---
    Job findJob(int jobId) {
        foreach(job; jobTable) {
            if (job.jobId == jobId) return job;
        }
        return null;
    }

    string getVariable(string name) {
        import std.datetime : Clock;
        import std.random : uniform;

        if (name == "?") return interpreter.variables.get("?", "0");
        if (name == "#") {
            int count = 0;
            for (int i = 1; ; i++) {
                if (to!string(i) in interpreter.variables) count++;
                else break;
            }
            return to!string(count);
        }
        if (name == "$") return to!string(getpid());
        if (name == "!") return (lastBackgroundPid == 0) ? "" : to!string(lastBackgroundPid);
        if (name == "-") return shellFlags;
        if (name == "LINENO") return to!string(currentLineNo);
        if (name == "SECONDS") return to!string(Clock.currStdTime / 10000000L - startTime);
        if (name == "RANDOM") return to!string(uniform(0, 32768));
        if (name == "@" || name == "*") {
            string[] positional;
            for (int i = 1; ; i++) {
                if (auto v = to!string(i) in interpreter.variables) positional ~= *v;
                else break;
            }
            return positional.join(" ");
        }
        
        // Positional parameters $1, $2...
        if (name.length > 0 && name[0] >= '0' && name[0] <= '9') {
             return interpreter.variables.get(name, "");
        }

        return interpreter.variables.get(name, "");
    }

    Job findJobByRef(string refStr) {
        if (refStr.startsWith("%")) {
            try {
                int id = to!int(refStr[1..$]);
                return findJob(id);
            } catch(Exception e) {
                string prefix = refStr[1..$];
                foreach(job; jobTable) {
                    if (job.command.startsWith(prefix)) return job;
                }
            }
        }
        
        // Try numeric PGID (also handles negative numbers from expansion)
        try {
            int pid = to!int(refStr);
            if (pid < 0) pid = -pid;
            foreach(job; jobTable) {
                if (job.pgid == pid) return job;
            }
        } catch(Exception e) {}
        
        return null;
    }

    void builtin_jobs() {
        update_job_status();
        foreach(job; jobTable) {
            string statusStr;
            switch(job.status) {
                case JobStatus.Running: statusStr = "Running"; break;
                case JobStatus.Stopped: statusStr = "Stopped"; break;
                case JobStatus.Done: statusStr = "Done"; break;
                default: statusStr = "Unknown"; break;
            }
            writeln("[", job.jobId, "] ", statusStr, "  ", job.command);
        }
        // Purge Done jobs
        for(int i=0; i<cast(int)jobTable.length; i++) {
            if (jobTable[i].status == JobStatus.Done) {
                jobTable = jobTable.remove(i);
                i--;
            }
        }
    }

    void builtin_fg(SimpleCommand cmd) {
        Job job = null;
        if (cmd.arguments.length < 2) {
            if (jobTable.length > 0) job = jobTable[$-1];
        } else {
            job = findJobByRef(cmd.arguments[1]);
        }

        if (job is null) {
            writeln("fg: no such job");
            return;
        }

        writeln(job.command);
        tcsetpgrp(STDIN_FILENO, job.pgid);
        if (job.status == JobStatus.Stopped) {
            kill(-job.pgid, SIGCONT);
            job.status = JobStatus.Running;
        }
        
        int status;
        waitpid(job.pgid, &status, WUNTRACED);
        tcsetpgrp(STDIN_FILENO, shell_pgid);
        
        if (WIFSTOPPED(status)) {
            job.status = JobStatus.Stopped;
            writeln("\n[", job.jobId, "]+  Stopped                 ", job.command);
        } else {
            job.status = JobStatus.Done;
            // Immediate removal or list will handle it
        }
    }

    void builtin_bg(SimpleCommand cmd) {
        Job job = null;
        if (cmd.arguments.length < 2) {
            if (jobTable.length > 0) job = jobTable[$-1];
        } else {
            job = findJobByRef(cmd.arguments[1]);
        }

        if (job is null) {
            writeln("bg: no such job");
            return;
        }

        if (job.status == JobStatus.Stopped) {
            kill(-job.pgid, SIGCONT);
            job.status = JobStatus.Running;
        }
        writeln("[", job.jobId, "]+ ", job.command, " &");
    }

    void builtin_disown(SimpleCommand cmd) {
        if (cmd.arguments.length < 2) {
            jobTable = [];
            return;
        }
        foreach(arg; cmd.arguments[1..$]) {
            Job job = findJobByRef(arg);
            if (job) {
                for(int i=0; i<jobTable.length; i++) {
                    if (jobTable[i] is job) {
                        jobTable = jobTable.remove(i);
                        break;
                    }
                }
            }
        }
    }

    void builtin_exec(SimpleCommand cmd) {
        if (cmd.arguments.length < 2) return;
        char*[] args;
        foreach(arg; cmd.arguments[1..$]) { args ~= strdup(arg.toStringz); }
        args ~= null;
        execvp(args[0], args.ptr);
        perror("exec");
        _exit(127); // Reached only if exec fails
    }

    void builtin_wait(SimpleCommand cmd) {
        if (cmd.arguments.length < 2) {
            // Wait for all background jobs
            while (jobTable.length > 0) {
                update_job_status();
                // Filter out Done jobs
                for(int i=0; i<jobTable.length; i++) {
                    if (jobTable[i].status == JobStatus.Done) {
                        jobTable = jobTable.remove(i);
                        i--;
                    }
                }
                if (jobTable.length == 0) break;
                // Small sleep to avoid busy wait if update_job_status is not blocking
                import shell.syscalls : sys_nanosleep, timespec;
                timespec req = {0, 100_000_000}; // 100ms
                sys_nanosleep(&req, null);
            }
        } else {
            foreach(arg; cmd.arguments[1..$]) {
                Job job = findJobByRef(arg);
                if (job) {
                    while (job.status == JobStatus.Running || job.status == JobStatus.Stopped) {
                        int status;
                        waitpid(job.pgid, &status, WUNTRACED);
                        if (WIFEXITED(status) || WIFSIGNALED(status)) {
                            job.status = JobStatus.Done;
                            break;
                        }
                    }
                }
            }
        }
    }

    void builtin_source(SimpleCommand cmd) {
        if (cmd.arguments.length < 2) return;
        string file = cmd.arguments[1];
        try {
            import std.file : readText;
            string content = readText(file);
            import shell.parser : parseShellCommand;
            Node ast = parseShellCommand(content);
            if (ast) execute(ast);
        } catch (Exception e) {
            writeln("source: ", e.msg);
        }
    }

    void builtin_null() {
        // Do nothing
    }

    // POSIX wait macros as D functions
    bool WIFEXITED(int s) { return (s & 0x7f) == 0; }
    int WEXITSTATUS(int s) { return (s >> 8) & 0xff; }
    bool WIFSIGNALED(int s) { return (s & 0x7f) != 0 && (s & 0x7f) != 0x7f; }
    int WTERMSIG(int s) { return s & 0x7f; }
    bool WIFSTOPPED(int s) { return (s & 0xff) == 0x7f; }
    int WSTOPSIG(int s) { return (s >> 8) & 0xff; }
    bool WIFCONTINUED(int s) { return s == 0xffff; } // Implementation dependent

    public void update_job_status() {
        int status;
        pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED )) > 0) {
            foreach(job; jobTable) {
                bool found = false;
                foreach(jpid; job.pids) if (jpid == pid) { found = true; break; }
                if (found) {
                    if (WIFSTOPPED(status)) {
                        if (job.status != JobStatus.Stopped) {
                            job.status = JobStatus.Stopped;
                            writeln("\n[", job.jobId, "]+  Stopped                 ", job.command);
                        }
                    } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
                        if (job.status != JobStatus.Done) {
                            job.status = JobStatus.Done;
                            string msg = WIFEXITED(status) ? "Done" : "Terminated";
                            writeln("\n[", job.jobId, "]+  ", msg, "                 ", job.command);
                        }
                    }
                }
            }
        }
    }


// --- Additional Builtins ---
    void builtin_declare(SimpleCommand cmd) {
        if (cmd.arguments.length == 1) {
            foreach(k, v; interpreter.variables) {
                writeln("declare ", k, "=\"", v, "\"");
            }
            return;
        }

        bool exportVar = false;
        size_t startIdx = 1;
        while (startIdx < cmd.arguments.length && cmd.arguments[startIdx].startsWith("-")) {
            string opt = cmd.arguments[startIdx];
            if (opt == "-x") exportVar = true;
            else if (opt == "-i") { /* Integer flag - no-op for now */ }
            startIdx++;
        }

        for (size_t i = startIdx; i < cmd.arguments.length; i++) {
            string arg = cmd.arguments[i];
            auto eqIdx = arg.indexOf('=');
            if (eqIdx != -1) {
                string name = arg[0 .. eqIdx];
                string val = arg[eqIdx + 1 .. $];
                interpreter.variables[name] = val;
                if (exportVar) environment[name] = val;
            } else {
                if (exportVar) {
                    if (auto val = arg in interpreter.variables) environment[arg] = *val;
                }
            }
        }
    }

    void builtin_mapfile(SimpleCommand cmd) {
        string arrayName = "MAPFILE";
        bool trimNewline = false;
        int origin = 0;
        int count = -1;

        size_t idx = 1;
        while (idx < cmd.arguments.length && cmd.arguments[idx].startsWith("-")) {
            string opt = cmd.arguments[idx];
            if (opt == "-t") trimNewline = true;
            else if (opt == "-n" && idx + 1 < cmd.arguments.length) {
                count = to!int(cmd.arguments[++idx]);
            }
            else if (opt == "-O" && idx + 1 < cmd.arguments.length) {
                origin = to!int(cmd.arguments[++idx]);
            }
            idx++;
        }
        if (idx < cmd.arguments.length) arrayName = cmd.arguments[idx];

        string line;
        int i = origin;
        while ((count == -1 || i < origin + count) && (line = readln()) !is null) {
            if (trimNewline) line = line.stripRight("\n");
            interpreter.variables[arrayName ~ "[" ~ to!string(i) ~ "]"] = line;
            i++;
        }
    }

    void builtin_coproc(SimpleCommand cmd) {
        if (cmd.arguments.length < 2) return;
        
        string name = "COPROC";
        size_t startIdx = 1;
        if (cmd.arguments.length > 2) {
             name = cmd.arguments[1];
             startIdx = 2;
        }

        int[2] pipe_in; 
        int[2] pipe_out; 
        
        if (pipe(pipe_in) == -1 || pipe(pipe_out) == -1) { perror("pipe"); return; }

        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return; }

        if (pid == 0) {
            dup2(pipe_in[0], STDIN_FILENO);
            dup2(pipe_out[1], STDOUT_FILENO);
            close(pipe_in[1]);
            close(pipe_out[0]);
            
            string[] subArgs = cmd.arguments[startIdx .. $];
            auto subCmd = new SimpleCommand(subArgs);
            execute_job_in_child(subCmd);
            _exit(0);
        }

        close(pipe_in[0]);
        close(pipe_out[1]);

        interpreter.variables[name ~ "[0]"] = to!string(pipe_out[0]);
        interpreter.variables[name ~ "[1]"] = to!string(pipe_in[1]);
        interpreter.variables[name ~ "_PID"] = to!string(pid);

        auto newJob = new Job("coproc " ~ name, pid, nextJobId, [pid]);
        jobTable ~= newJob;
        nextJobId++;
    }
import std.algorithm : startsWith, endsWith;
import std.string : splitLines, indexOf, lastIndexOf, toUpper, toLower;
import std.regex : regex, replaceAll, replaceFirst, matchFirst;
import std.array : join, split;
import ls;
import find;
import du;
import df;
import cut;
import date;
import dirname;
import fold;
import killcmd = kill;
import local;
import lsof;
import base64;
import cron;
import dos2unix;
import cmd_false;
import groups;
import klist;
import locate;
import importcmd;
import bc;
import cal;
import chkconfig;
import cksum;
import cmp;
import crontab;
import csplit;
import cut;
import date;
import dc;
import diff;
import diff3;
import dir;
import dircolors;
import dirname;
import dparser;
import du;
import egrep;
import eject;
import example;
import fdisk;
import fdformat;
import fgrep;
import file;
import mkdir;
import rm;
import cp;
import mv;
import fileops;


import find;
import fsck;
import fuser;
import getfacl;
import getopts;
import groupadd;
import gzip;
import iconv;
import id;
import ifcmd;
import ifconfig;
import install;
import interpreter;
import iostat;
import ip;
import joincmd;
import less;
import letcmd;
import lfe;
import lferepl;
import linkcmd;
import login;
import logname;
import logout;
import look;
import lsblk;
import md5sum;
import objectsystem;
import shell.syscalls;
import shell.expansion;
alias stat_t = shell.syscalls.stat_t;

enum S_IFMT   = 0xF000;
enum S_IFIFO  = 0x1000;
enum S_IFCHR  = 0x2000;
enum S_IFDIR  = 0x4000;
enum S_IFBLK  = 0x6000;
enum S_IFREG  = 0x8000;
enum S_IFLNK  = 0xA000;
enum S_IFSOCK = 0xC000;

enum S_IRUSR = 0x0100;
enum S_IWUSR = 0x0080;
enum S_IXUSR = 0x0040;

void builtin_test(SimpleCommand cmd) {
    string[] args = cmd.arguments[1 .. $];
    if (cmd.arguments[0] == "[" || cmd.arguments[0] == "[[") {
        if (args.length > 0 && args[$ - 1] == (cmd.arguments[0] == "[" ? "]" : "]]")) {
             args = args[0 .. $ - 1];
        } else if (cmd.arguments[0] == "[") {
            writeln("[: missing ']'");
            interpreter.variables["?"] = "2";
            return;
        }
    }
    
    bool result = false;
    
    try {
        if (args.length == 0) {
            result = false;
        } else if (args.length == 1) {
            result = args[0].length > 0;
        } else if (args.length == 2) {
            string op = args[0];
            string file = args[1];
            stat_t st;
            
            switch (op) {
                case "-e": result = (sys_stat(file.toStringz, &st) == 0); break;
                case "-f": result = (sys_stat(file.toStringz, &st) == 0 && (st.st_mode & S_IFMT) == S_IFREG); break;
                case "-d": result = (sys_stat(file.toStringz, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR); break;
                case "-L": result = (sys_stat(file.toStringz, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK); break;
                case "-r": result = (sys_stat(file.toStringz, &st) == 0 && (st.st_mode & S_IRUSR)); break;
                case "-w": result = (sys_stat(file.toStringz, &st) == 0 && (st.st_mode & S_IWUSR)); break;
                case "-x": result = (sys_stat(file.toStringz, &st) == 0 && (st.st_mode & S_IXUSR)); break;
                case "-s": result = (sys_stat(file.toStringz, &st) == 0 && st.st_size > 0); break;
                case "-z": result = (file.length == 0); break;
                case "-n": result = (file.length > 0); break;
                default: result = false; break;
            }
        } else if (args.length >= 3) {
            string left = args[0];
            string op = args[1];
            string right = args[2];
            
            switch (op) {
                case "=": case "==": result = (left == right); break;
                case "!=": result = (left != right); break;
                case "=~": {
                    try {
                        auto r = regex(right);
                        auto m = matchFirst(left, r);
                        result = !m.empty;
                    } catch (Exception e) { result = false; }
                    break;
                }
                case "<": result = (left < right); break;
                case ">": result = (left > right); break;
                case "-eq": result = (to!long(left) == to!long(right)); break;
                case "-ne": result = (to!long(left) != to!long(right)); break;
                case "-lt": result = (to!long(left) < to!long(right)); break;
                case "-le": result = (to!long(left) <= to!long(right)); break;
                case "-gt": result = (to!long(left) > to!long(right)); break;
                case "-ge": result = (to!long(left) >= to!long(right)); break;
                case "-nt": {
                    stat_t st1, st2;
                    if (sys_stat(left.toStringz, &st1) == 0 && sys_stat(right.toStringz, &st2) == 0) {
                        result = (st1.st_mtime > st2.st_mtime);
                    } else result = false;
                    break;
                }
                case "-ot": {
                    stat_t st1, st2;
                    if (sys_stat(left.toStringz, &st1) == 0 && sys_stat(right.toStringz, &st2) == 0) {
                        result = (st1.st_mtime < st2.st_mtime);
                    } else result = false;
                    break;
                }
                default: result = false; break;
            }
        }
    } catch (Exception e) {
        result = false;
    }
    
    interpreter.variables["?"] = result ? "0" : "1";
}

void builtin_cd(SimpleCommand cmd) {
    string dest;
    if (cmd.arguments.length < 2) {
        dest = "/root";  // HOME
    } else {
        dest = cmd.arguments[1];
    }
    auto ret = sys_chdir(dest.toStringz);
    if (ret < 0) {
        writeln("cd: cannot access ", dest);
    }
}

void builtin_pwd() {
    char[256] buf;
    auto ret = sys_getcwd(buf.ptr, buf.length);
    if (ret >= 0) {
        // Find null terminator
        size_t len = 0;
        while (buf[len] != '\0' && len < 256) len++;
        writeln(buf[0..len]);
    } else {
        writeln("/");  // Fallback
    }
}

void builtin_echo(SimpleCommand cmd) {
    if (cmd.arguments.length > 1) {
        writeln(cmd.arguments[1 .. $].join(" "));
    } else {
        writeln();
    }
}

void builtin_cat(SimpleCommand cmd) {
    if (cmd.arguments.length < 2) {
        writeln("cat: missing file operand");
        return;
    }
    foreach (file; cmd.arguments[1 .. $]) {
        auto fd = sys_open(file.toStringz, 0);
        if (fd < 0) {
            writeln("cat: cannot read ", file);
            continue;
        }
        
        ubyte[4096] buffer;
        long nread;
        while ((nread = sys_read(cast(int)fd, buffer.ptr, buffer.length)) > 0) {
            sys_write(1, buffer.ptr, nread);
        }
        
        sys_close(cast(int)fd);
    }
}

void builtin_help() {
    writeln("AnonymOS Enhanced Shell - Available Commands:");
    writeln("");
    writeln("  Core Builtins:");
    writeln("    cd [dir]       - Change directory");
    writeln("    pwd            - Print working directory");
    writeln("    echo [args]    - Echo arguments");
    writeln("    cat [files]    - Concatenate and print files");
    writeln("    ls [path]      - List directory contents");
    writeln("    help           - Show this help");
    writeln("    exit [code]    - Exit shell");
    writeln("    :              - Null command (no-op)");
    writeln("    . / source file - Execute commands from file");
    writeln("    exec cmd       - Replace shell with command");
    writeln("    wait [job]     - Wait for background jobs");
    writeln("    select name in ...; do ...; done - Menu loop");
    writeln("");
    writeln("  File Operations:");
    writeln("    mkdir [-p] dir - Create directory");
    writeln("    rmdir dir      - Remove empty directory");
    writeln("    rm [-rf] file  - Remove files or directories");
    writeln("    cp src dst     - Copy files");
    writeln("    mv src dst     - Move/rename files");
    writeln("    touch file     - Create or update file timestamp");
    writeln("    find [path] [-name pattern] - Find files");
    writeln("    du [-hs] path  - Disk usage");
    writeln("    df             - Disk free space");
    writeln("    stat file      - File statistics");
    writeln("    file path      - Determine file type");
    writeln("    shopt -s|-u opt - Set/unset shell options (e.g. extglob)");
    writeln("    declare/typeset - Set variable attributes");
    writeln("    mapfile/readarray - Read lines into array");
    writeln("    coproc [NAME] cmd - Run coprocess");
    writeln("");
    writeln("  Text Processing:");
    writeln("    grep [-inv] pattern [files] - Search for pattern");
    writeln("    head [-n N] [files] - Output first N lines");
    writeln("    tail [-n N] [files] - Output last N lines");
    writeln("    wc [-lwc] [files]   - Count lines, words, characters");
    writeln("    sort [-rn] [files]  - Sort lines");
    writeln("    uniq [-c] [file]    - Remove duplicate lines");
    writeln("    cut -d delim -f fields [files] - Cut fields");
    writeln("    tr SET1 SET2   - Translate characters");
    writeln("    paste files    - Merge files line-by-line");
    writeln("    tee [-a] file  - Tee output to file");
    writeln("    cmp file1 file2 - Compare files");
    writeln("    comm file1 file2 - Compare sorted files");
    writeln("");
    writeln("  Shell Environment:");
    writeln("    alias [name=value] - Create command alias");
    writeln("    export VAR=value   - Set environment variable");
    writeln("    env            - Show environment");
    writeln("    set            - Show all variables");
    writeln("    unset VAR      - Remove variable");
    writeln("    printenv [VAR] - Print environment variables");
    writeln("");
    writeln("  Job Control:");
    writeln("    jobs           - List background jobs");
    writeln("    fg [%job]      - Move job to foreground");
    writeln("    bg [%job]      - Move job to background");
    writeln("    disown [%job]  - Remove job from list");
    writeln("");
    writeln("  Grouping & Blocks:");
    writeln("    ( cmd )        - Run in subshell");
    writeln("    { cmd; }       - Run in current shell");
    writeln("    [[ expr ]]     - Extended test");
    writeln("");
    writeln("  System Info:");
    writeln("    whoami         - Print current user");
    writeln("    hostname       - Print system hostname");
    writeln("    uname [-a]     - Print system information");
    writeln("    date           - Print current date/time");
    writeln("    uptime         - Show system uptime");
    writeln("    tty            - Print terminal name");
    writeln("    arch           - Print architecture");
    writeln("    nproc          - Print number of processors");
    writeln("");
    writeln("  Utilities:");
    writeln("    true           - Return success");
    writeln("    false          - Return failure");
    writeln("    yes [msg]      - Output message repeatedly");
    writeln("    seq [start] [step] end - Print number sequence");
    writeln("    basename path  - Strip directory from path");
    writeln("    dirname path   - Extract directory from path");
    writeln("    which cmd      - Show command location");
    writeln("    clear          - Clear screen");
    writeln("    sleep N        - Sleep for N seconds");
    writeln("    factor N       - Prime factorization");
    writeln("    expr a op b    - Evaluate expression");
    writeln("    printf fmt args - Formatted output");
    writeln("");
    version(ANONYMOS_MINIMAL) {
        writeln("  Total: 65+ commands (all shell builtins)");
        writeln("  Note: External programs and job control are not available.");
    }
}

// --- Builtin Dispatcher ---
bool handleBuiltin(SimpleCommand cmd) {
    if (cmd is null || cmd.arguments.length == 0) return false;

    auto commandName = cmd.arguments[0];
    
    version(ANONYMOS_MINIMAL) {
        // Minimal builtins only
        auto cmd_name = commandName;
        
        // Core shell builtins
        if (cmd_name == "cd") { builtin_cd(cmd); return true; }
        else if (cmd_name == ":") { builtin_null(); return true; }
        else if (cmd_name == "." || cmd_name == "source") { builtin_source(cmd); return true; }
        else if (cmd_name == "exec") { builtin_exec(cmd); return true; }
        else if (cmd_name == "wait") { builtin_wait(cmd); return true; }
        else if (cmd_name == "pwd") { builtin_pwd(); return true; }
        else if (cmd_name == "echo") { builtin_echo(cmd); return true; }
        else if (cmd_name == "test" || cmd_name == "[") { builtin_test(cmd); return true; }
        else if (cmd_name == "cat") { builtin_cat(cmd); return true; }
        else if (cmd_name == "ls") { ls.lsCommand(cmd.arguments); return true; }
    else if (cmd_name == "mkdir") { mkdir.mkdirCommand(cmd.arguments); return true; }
    else if (cmd_name == "rm") { rm.rmCommand(cmd.arguments); return true; }
    else if (cmd_name == "cp") { cp.cpCommand(cmd.arguments); return true; }
    else if (cmd_name == "mv") { mv.mvCommand(cmd.arguments); return true; }
    else if (cmd_name == "rmdir") { fileops.rmdirCommand(cmd.arguments); return true; }
    else if (cmd_name == "touch") { fileops.touchCommand(cmd.arguments); return true; }
    else if (cmd_name == "unlink") { fileops.unlinkCommand(cmd.arguments); return true; }


        else if (cmd_name == "help") { builtin_help(); return true; }
        else if (cmd_name == "exit") {
            int status = 0;
            if (cmd.arguments.length > 1) {
                try { status = to!int(cmd.arguments[1]); } catch (Exception e) {}
            }
            _exit(status);
            return true;
        }
        
        // File operations using existing modules
        else if (cmd_name == "find") { find.findCommand(cmd.arguments); return true; }
        else if (cmd_name == "du") { du.duCommand(cmd.arguments); return true; }
        else if (cmd_name == "df") { df.dfCommand(cmd.arguments); return true; }
        
        // Text processing
        else if (cmd_name == "cut") { cut.cutCommand(cmd.arguments); return true; }
        else if (cmd_name == "fold") { fold.foldCommand(cmd.arguments); return true; }
        
        // System utilities
        else if (cmd_name == "date") { date.dateCommand(cmd.arguments); return true; }
        else if (cmd_name == "dirname") { dirname.dirnameCommand(cmd.arguments); return true; }
        else if (cmd_name == "kill") { killcmd.killCommand(cmd.arguments); return true; }
        else if (cmd_name == "jobs") { builtin_jobs(); return true; }
        else if (cmd_name == "fg") { builtin_fg(cmd); return true; }
        else if (cmd_name == "bg") { builtin_bg(cmd); return true; }
        else if (cmd_name == "disown") { builtin_disown(cmd); return true; }
        else if (cmd_name == "local") { local.localCommand(cmd.arguments); return true; }
        
        // Utilities
        else if (cmd_name == "base64") { base64.base64Command(cmd.arguments); return true; }
        else if (cmd_name == "cron") { cron.cronCommand(cmd.arguments); return true; }
        else if (cmd_name == "dos2unix") { dos2unix.dos2unixCommand(cmd.arguments); return true; }
        else if (cmd_name == "false") { cmd_false.falseMain(cmd.arguments); return true; }
        
        else if (cmd_name == "groups") { groups.groupsCommand(cmd.arguments); return true; }
        else if (cmd_name == "klist") { klist.klistCommand(cmd.arguments); return true; }
        else if (cmd_name == "locate") { locate.locateCommand(cmd.arguments); return true; }
        else if (cmd_name == "import") { importcmd.importCommand(cmd.arguments); return true; }
        
        else if (cmd_name == "bc") { bc.bcCommand(cmd.arguments); return true; }
        else if (cmd_name == "cal") { cal.calCommand(cmd.arguments); return true; }
        else if (cmd_name == "chkconfig") { chkconfig.chkconfigCommand(cmd.arguments); return true; }
        else if (cmd_name == "cksum") { cksum.cksumCommand(cmd.arguments); return true; }
        else if (cmd_name == "cmp") { cmp.cmpCommand(cmd.arguments); return true; }
        else if (cmd_name == "crontab") { crontab.crontabCommand(cmd.arguments); return true; }
        else if (cmd_name == "csplit") { csplit.csplitCommand(cmd.arguments); return true; }
        else if (cmd_name == "cut") { cut.cutCommand(cmd.arguments); return true; }
        else if (cmd_name == "date") { date.dateCommand(cmd.arguments); return true; }
        else if (cmd_name == "dc") { dc.dcCommand(cmd.arguments); return true; }
        else if (cmd_name == "diff") { diff.diffCommand(cmd.arguments); return true; }
        else if (cmd_name == "diff3") { diff3.diff3Command(cmd.arguments); return true; }
        else if (cmd_name == "dir") { dir.dirCommand(cmd.arguments); return true; }
        else if (cmd_name == "dircolors") { dircolors.dircolorsCommand(cmd.arguments); return true; }
        else if (cmd_name == "dirname") { dirname.dirnameCommand(cmd.arguments); return true; }
        else if (cmd_name == "dparser") { dparser.dparserCommand(cmd.arguments); return true; }
        else if (cmd_name == "egrep") { egrep.egrepCommand(cmd.arguments); return true; }
        else if (cmd_name == "eject") { eject.ejectCommand(cmd.arguments); return true; }
        else if (cmd_name == "example") { example.exampleMain(cmd.arguments); return true; }
        else if (cmd_name == "fdisk") { fdisk.fdiskCommand(cmd.arguments); return true; }
        else if (cmd_name == "fdformat") { fdformat.fdformatCommand(cmd.arguments); return true; }
        else if (cmd_name == "fgrep") { fgrep.fgrepCommand(cmd.arguments); return true; }
        else if (cmd_name == "file") { file.fileCommand(cmd.arguments); return true; }
        else if (cmd_name == "find") { find.findCommand(cmd.arguments); return true; }
        else if (cmd_name == "fsck") { fsck.fsckCommand(cmd.arguments); return true; }
        else if (cmd_name == "fuser") { fuser.fuserCommand(cmd.arguments); return true; }
        else if (cmd_name == "getfacl") { getfacl.getfaclCommand(cmd.arguments); return true; }
        else if (cmd_name == "getopts") { getopts.getoptsCommand(cmd.arguments); return true; }
        else if (cmd_name == "groupadd") { groupadd.groupaddCommand(cmd.arguments); return true; }
        else if (cmd_name == "gzip") { gzip.gzipCommand(cmd.arguments); return true; }
        else if (cmd_name == "iconv") { iconv.iconvCommand(cmd.arguments); return true; }
        else if (cmd_name == "id") { id.idCommand(cmd.arguments); return true; }
        else if (cmd_name == "ifcmd") { ifcmd.ifCommand(cmd.arguments); return true; }
        else if (cmd_name == "ifconfig") { ifconfig.ifconfigCommand(cmd.arguments); return true; }
        else if (cmd_name == "install") { install.installCommand(cmd.arguments); return true; }
        else if (cmd_name == "iostat") { iostat.iostatCommand(cmd.arguments); return true; }
        else if (cmd_name == "ip") { ip.ipCommand(cmd.arguments); return true; }
        else if (cmd_name == "join") { joincmd.joinCommand(cmd.arguments); return true; }
        else if (cmd_name == "less") { less.lessCommand(cmd.arguments); return true; }
        else if (cmd_name == "let") { letcmd.letCommand(cmd.arguments); return true; }
        else if (cmd_name == "lfe") { lfe.lfeMain(cmd.arguments); return true; }
        else if (cmd_name == "lferepl") { lferepl.lfereplMain(); return true; }
        else if (cmd_name == "link") { linkcmd.linkCommand(cmd.arguments); return true; }
        else if (cmd_name == "login") { login.loginCommand(cmd.arguments); return true; }
        else if (cmd_name == "logname") { logname.lognameCommand(cmd.arguments); return true; }
        else if (cmd_name == "logout") { logout.logoutCommand(cmd.arguments); return true; }
        else if (cmd_name == "look") { look.lookCommand(cmd.arguments); return true; }
        else if (cmd_name == "lsblk") { lsblk.lsblkCommand(cmd.arguments); return true; }
        else if (cmd_name == "md5sum") { md5sum.md5sumCommand(cmd.arguments); return true; }
        else if (cmd_name == "objectsystem") { objectsystem.objectsystemCommand(cmd.arguments); return true; }
    } else {
        if (commandName == "shopt") {
            if (cmd.arguments.length >= 3) {
                if (cmd.arguments[1] == "-s") {
                    if (cmd.arguments[2] == "extglob") extglobEnabled = true;
                } else if (cmd.arguments[1] == "-u") {
                    if (cmd.arguments[2] == "extglob") extglobEnabled = false;
                }
            }
            return true;
        } else if (commandName == "jobs") {
            builtin_jobs();
            return true;
        } else if (commandName == "fg") {
            builtin_fg(cmd);
            return true;
        } else if (commandName == "bg") {
            builtin_bg(cmd);
            return true;
        } else if (commandName == "declare" || commandName == "typeset") {
            builtin_declare(cmd);
            return true;
        } else if (commandName == "mapfile" || commandName == "readarray") {
            builtin_mapfile(cmd);
            return true;
        } else if (commandName == "coproc") {
            builtin_coproc(cmd);
            return true;
        } else if (commandName == "disown") {
            builtin_disown(cmd);
            return true;
        } else if (commandName == ":") {
            builtin_null();
            return true;
        } else if (commandName == "." || commandName == "source") {
            builtin_source(cmd);
            return true;
        } else if (commandName == "exec") {
            builtin_exec(cmd);
            return true;
        } else if (commandName == "wait") {
            builtin_wait(cmd);
            return true;
        } else if (commandName == "cd") {
            builtin_cd(cmd);
            return true;
        } else if (commandName == "pwd") {
            builtin_pwd();
            return true;
        } else if (commandName == "echo") {
            builtin_echo(cmd);
            return true;
        } else if (commandName == "test" || commandName == "[") {
            builtin_test(cmd);
            return true;
        } else if (commandName == "cat") {
            builtin_cat(cmd);
            return true;
        } else if (commandName == "ls") {
            ls.lsCommand(cmd.arguments);
            return true;
        } else if (commandName == "mkdir") {
            mkdir.mkdirCommand(cmd.arguments);
            return true;
        } else if (commandName == "rm") {
            rm.rmCommand(cmd.arguments);
            return true;
        } else if (commandName == "cp") {
            cp.cpCommand(cmd.arguments);
            return true;
        } else if (commandName == "mv") {
            mv.mvCommand(cmd.arguments);
            return true;

        } else if (commandName == "help") {
            builtin_help();
            return true;
        } else if (commandName == "exit") {
            int status = 0;
            if (cmd.arguments.length > 1) {
                try {
                    status = to!int(cmd.arguments[1]);
                } catch (Exception e) {}
            }
            _exit(status);
            return true;
        }
    }
    return false;
}

// --- Main Execution Logic ---

public void execute(Node ast) {
    if (ast is null) return;
    int rc = executeRecursive(ast);
    interpreter.variables["?"] = to!string(rc);
    
    // Clean up finished process substitutions
    int status;
    for (int i = 0; i < cast(int)procSubPids.length; i++) {
        if (waitpid(procSubPids[i], &status, WNOHANG) > 0) {
            procSubPids = procSubPids.remove(i);
            i--;
        }
    }
    
    // Close process substitution FDs that were passed to children
    foreach(fd; procSubFds) close(fd);
    procSubFds = [];
}

private int executeRecursive(Node ast) {
    if (ast is null) return 0;

    if (auto sn = cast(SubshellNode)ast) return launchJob(sn);

    if (auto sel = cast(SelectNode)ast) {
        string[] items;
        foreach(w; sel.words) {
            foreach(exp; expandFull(w)) items ~= exp;
        }
        if (items.length == 0) {
            // Usually uses positional parameters if IN is missing, but for now just return
            return 0;
        }

        while (true) {
            // Show menu
            for (int i = 0; i < cast(int)items.length; i++) {
                writeln(i + 1, ") ", items[i]);
            }
            write("#? ");
            stdout.flush();
            string line = readln();
            if (line is null) return 0; // EOF
            line = line.strip;
            interpreter.variables["REPLY"] = line;
            if (line.length == 0) continue;

            try {
                int choice = to!int(line);
                if (choice >= 1 && choice <= items.length) {
                    interpreter.variables[sel.name] = items[choice - 1];
                } else {
                    interpreter.variables[sel.name] = "";
                }
            } catch (Exception e) {
                interpreter.variables[sel.name] = "";
            }

            executeRecursive(sel.body);
        }
    }

    if (auto seq = cast(Sequence)ast) {
        if (seq.background) {
            launchJob(seq);
            return 0;
        }
        int rc = 0;
        foreach(cmd; seq.commands) rc = executeRecursive(cmd);
        return rc;
    }

    if (auto log = cast(LogicNode)ast) {
        int left = executeRecursive(log.left);
        if (log.isAnd) return (left == 0) ? executeRecursive(log.right) : left;
        else return (left != 0) ? executeRecursive(log.right) : left;
    }

    if (auto cn = cast(CaseNode)ast) {
        string w = expandWord(cn.word);
        bool forceMatch = false;
        foreach(item; cn.items) {
             bool match = forceMatch;
             if (!match) {
                 foreach(pat; item.patterns) {
                     string expandedPat = expandWord(pat);
                     if (enhancedGlobMatch(w, expandedPat, extglobEnabled)) { match = true; break; }
                 }
             }
             
             if (match) {
                 int rc = executeRecursive(item.list);
                 forceMatch = false;
                 if (item.terminator == ";;") return rc;
                 if (item.terminator == ";&") { forceMatch = true; continue; }
                 if (item.terminator == ";;&") { continue; } // Continue testing patterns
                 return rc;
             }
        }
        return 0;
    }

    if (auto tnode = cast(TestNode)ast) {
        string[] expandedArgs;
        foreach(arg; tnode.arguments) {
            // In [[ ... ]], field splitting and globbing are suppressed on the words themselves
            expandedArgs ~= expandWord(arg);
        }
        auto tcmd = new SimpleCommand("[[" ~ expandedArgs);
        builtin_test(tcmd);
        try { return to!int(interpreter.variables.get("?", "0")); } catch(Exception e) { return 1; }
    }

    if (auto red = cast(Redirection)ast) {
        if (auto inner = cast(SimpleCommand)red.command) {
            string[] expandedArgs;
            foreach(arg; inner.arguments) {
                foreach(word; expandFull(arg)) expandedArgs ~= word;
            }
            auto ecmd = new SimpleCommand(expandedArgs);
            if (handleBuiltin(ecmd)) {
                try { return to!int(interpreter.variables.get("?", "0")); } catch(Exception e) { return 0; }
            }
        }
    }

    if (auto cmd = cast(SimpleCommand)ast) {

        string[] expandedArgs;
        foreach(arg; cmd.arguments) {
            foreach(word; expandFull(arg)) expandedArgs ~= word;
        }
        auto ecmd = new SimpleCommand(expandedArgs);
        
        interpreter.variables["?"] = "0";
        if (handleBuiltin(ecmd)) {
             try { return to!int(interpreter.variables.get("?", "0")); } catch(Exception e) { return 0; }
        }
    }

    return launchJob(ast);
}

int launchJob(Node ast) {
    bool background = false;
    if (auto seq = cast(Sequence)ast) {
        background = seq.background;
    }
    
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        setpgid(0, 0);
        if (!background) {
            tcsetpgrp(STDIN_FILENO, getpgrp());
        }
        execute_job_in_child(ast);
        _exit(127);
    }

    setpgid(pid, pid);
    if (background) {
        lastBackgroundPid = pid;
        auto newJob = new Job(ast.toString(), pid, nextJobId, [pid]);
        jobTable ~= newJob;
        writeln("[", newJob.jobId, "] ", pid);
        nextJobId++;
        return 0;
    } else {
        tcsetpgrp(STDIN_FILENO, pid);
        int status;
        waitpid(pid, &status, WUNTRACED);
        tcsetpgrp(STDIN_FILENO, shell_pgid);
        
        if (WIFSTOPPED(status)) {
            auto newJob = new Job(ast.toString(), pid, nextJobId, [pid]);
            newJob.status = JobStatus.Stopped;
            jobTable ~= newJob;
            writeln("\n[", newJob.jobId, "]+  Stopped                 ", newJob.command);
            nextJobId++;
            return 128 + WSTOPSIG(status);
        }

        if (WIFEXITED(status)) return WEXITSTATUS(status);
        if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
        return 0;
    }
}

void execute_job_in_child(Node ast) {
    signal(SIGINT, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGTSTP, SIG_DFL);
    signal(SIGTTIN, SIG_DFL);
    signal(SIGTTOU, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);

    if (auto cmd = cast(SimpleCommand)ast) {
        string[] expandedArgs;
        foreach(arg; cmd.arguments) expandedArgs ~= expandWord(arg);
        auto ecmd = new SimpleCommand(expandedArgs);
        
        if (handleBuiltin(ecmd)) {
            _exit(0);
        }
        char*[] args;
        foreach(arg; expandedArgs) { args ~= strdup(arg.toStringz); }
        args ~= null;
        execvp(args[0], args.ptr);
        perror("esh");
        _exit(127);
    } else if (auto pipeline = cast(Pipeline)ast) {
        int numCommands = cast(int)pipeline.commands.length;
        if (numCommands <= 0) _exit(0);
        int[2][] pipes;
        pipes.length = numCommands - 1;
        for (int i = 0; i < numCommands - 1; i++) {
            if (pipe(pipes[i]) == -1) { perror("pipe"); _exit(1); }
        }
        pid_t[] pids;
        for (int i = 0; i < numCommands; i++) {
            pids ~= fork();
            if (pids[i] == -1) { perror("fork"); _exit(1); }
            if (pids[i] == 0) {
                if (i > 0) { dup2(pipes[i - 1][0], STDIN_FILENO); }
                if (i < numCommands - 1) { 
                    dup2(pipes[i][1], STDOUT_FILENO);
                    if (i < pipeline.pipeStderrs.length && pipeline.pipeStderrs[i]) {
                        dup2(pipes[i][1], STDERR_FILENO);
                    }
                }
                for (int j = 0; j < numCommands - 1; j++) {
                    close(pipes[j][0]);
                    close(pipes[j][1]);
                }
                execute_job_in_child(pipeline.commands[i]);
                _exit(127);
            }
        }
        for (int i = 0; i < numCommands - 1; i++) {
            close(pipes[i][0]);
            close(pipes[i][1]);
        }
        for (int i = 0; i < numCommands; i++) {
            int status;
            waitpid(pids[i], &status, 0);
        }
        _exit(0);
    } else if (auto redir = cast(Redirection)ast) {
        string expandedFile = expandWord(redir.filename);
        int destFd = redir.ioNumber;
        if (destFd == -1) {
            // Defaults
            if (redir.type == RedirectionType.Input || redir.type == RedirectionType.DupInput || 
                redir.type == RedirectionType.HereDoc || redir.type == RedirectionType.HereString || 
                redir.type == RedirectionType.ReadWrite) destFd = 0;
            else destFd = 1;
        }

        if (redir.type == RedirectionType.DupInput || redir.type == RedirectionType.DupOutput) {
            if (expandedFile == "-") {
                close(destFd);
            } else {
                int srcFd = to!int(expandedFile);
                if (dup2(srcFd, destFd) == -1) { perror("dup2"); _exit(1); }
            }
        } else if (redir.type == RedirectionType.HereDoc || redir.type == RedirectionType.HereString || 
                   redir.type == RedirectionType.HereDocDash) {
            int[2] p;
            if (pipe(p) == -1) { perror("pipe"); _exit(1); }
            string content = (redir.type == RedirectionType.HereString) ? expandedFile : "";
            if (content.length > 0) {
                core.sys.posix.unistd.write(p[1], content.toStringz, content.length);
                core.sys.posix.unistd.write(p[1], "\n".ptr, 1);
            }
            close(p[1]);
            if (dup2(p[0], destFd) == -1) { perror("dup2"); _exit(1); }
            close(p[0]);
        } else {
            // File Redirections
            int flags = 0;
            mode_t mode = 438; // 0666
            if (redir.type == RedirectionType.Input) flags = O_RDONLY;
            else if (redir.type == RedirectionType.ReadWrite) flags = O_RDWR | O_CREAT;
            else if (redir.type == RedirectionType.Output || redir.type == RedirectionType.Clobber || redir.type == RedirectionType.OutputBoth)
                flags = O_WRONLY | O_CREAT | O_TRUNC;
            else if (redir.type == RedirectionType.OutputAppend || redir.type == RedirectionType.OutputBothAppend)
                flags = O_WRONLY | O_CREAT | O_APPEND;
            
            int fd = open(expandedFile.toStringz, flags, mode);
            if (fd == -1) { perror(expandedFile.toStringz); _exit(1); }
            
            if (redir.type == RedirectionType.OutputBoth || redir.type == RedirectionType.OutputBothAppend) {
                if (dup2(fd, 1) == -1) { perror("dup2"); _exit(1); }
                if (dup2(fd, 2) == -1) { perror("dup2"); _exit(1); }
            } else {
                if (dup2(fd, destFd) == -1) { perror("dup2"); _exit(1); }
            }
            if (fd != destFd && fd != 1 && fd != 2) close(fd);
        }
        execute_job_in_child(redir.command);
        _exit(127);
    } else if (auto seq = cast(Sequence)ast) {
        // In child, sequence executes
        foreach(cmd; seq.commands) {
            // Internal execute, no fork
            // We can call executeRecursive?
            // But executeRecursive calls launchJob -> fork.
            // Loop calling fork inside child? Yes, subshells fork.
            // Can we avoid it for simple commands? execvp replaces.
            // Only last command can replace. Others must wait.
            // Correct approach: fork for all but last?
            // Or just loop execute.
            // But `executeRecursive` will `fork` for external commands.
            // Simple: executeRecursive(cmd);
            executeRecursive(cmd);
        }
        _exit(0);
    } else if (auto log = cast(LogicNode)ast) {
        int rc = executeRecursive(log);
        _exit(rc); 
    } else if (auto cn = cast(CaseNode)ast) {
        int rc = executeRecursive(cn);
        _exit(rc);
    } else if (auto tnode = cast(TestNode)ast) {
        string[] expandedArgs;
        foreach(arg; tnode.arguments) expandedArgs ~= expandWord(arg);
        auto tcmd = new SimpleCommand("test" ~ expandedArgs);
        builtin_test(tcmd);
        try { _exit(to!int(interpreter.variables.get("?", "0"))); } catch(Exception e) { _exit(1); }
    } else if (auto an = cast(ArithmeticNode)ast) {
        long res = evaluateArithmetic(an.expression);
        _exit(res == 0 ? 1 : 0);
    } else if (auto sn = cast(SubshellNode)ast) {
        int rc = executeRecursive(sn.node);
        _exit(rc);
    } else if (auto sel = cast(SelectNode)ast) {
        int rc = executeRecursive(sel);
        _exit(rc);
    }
}

long evaluateArithmetic(string expr) {
    import std.string : strip, isNumeric;
    expr = expandWord(expr).strip;
    if (expr.length == 0) return 0;

    // Recursive descent helper for arithmetic
    struct Parser {
        string s;
        size_t p;
        
        long parse() { return parseAdd(); }
        
        void skip() { while(p < s.length && (s[p] == ' ' || s[p] == '\t')) p++; }
        
        long parseAdd() {
            long l = parseMul();
            while(true) {
                skip();
                if(p < s.length && s[p] == '+') { p++; l += parseMul(); }
                else if(p < s.length && s[p] == '-') { p++; l -= parseMul(); }
                else break;
            }
            return l;
        }
        
        long parseMul() {
            long l = parsePrim();
            while(true) {
                skip();
                if(p < s.length && s[p] == '*') { p++; l *= parsePrim(); }
                else if(p < s.length && s[p] == '/') { 
                    p++; 
                    long r = parsePrim();
                    l = (r == 0) ? 0 : l / r; 
                }
                else if(p < s.length && s[p] == '%') {
                    p++;
                    long r = parsePrim();
                    l = (r == 0) ? 0 : l % r;
                }
                else break;
            }
            return l;
        }
        
        long parsePrim() {
            skip();
            if(p < s.length && s[p] == '(') {
                p++;
                long l = parseAdd();
                skip();
                if(p < s.length && s[p] == ')') p++;
                return l;
            }
            size_t start = p;
            while(p < s.length && (s[p] >= '0' && s[p] <= '9' || s[p] >= 'a' && s[p] <= 'z' || s[p] >= 'A' && s[p] <= 'Z' || s[p] == '_')) p++;
            string tok = s[start .. p];
            if(tok.isNumeric) return to!long(tok);
            if(tok.length > 0) {
                // Try variable lookup
                return to!long(getVariable(tok).length ? getVariable(tok) : "0");
            }
            return 0;
        }
    }
    
    return Parser(expr, 0).parse();
}

string expandWord(string word) {
    import std.string : indexOf, lastIndexOf, endsWith, startsWith;
    import std.regex : regex, replaceAll, Captures;
    
    string result = "";
    bool inSQuote = false;
    bool inDQuote = false;

    for (int i = 0; i < cast(int)word.length; i++) {
        char c = word[i];

        // Backslash Escape
        if (c == '\\' && !inSQuote) {
            if (i + 1 < word.length) {
                char next = word[i+1];
                if (inDQuote) {
                    // In double quotes, only specific chars are escaped
                    if (next == '$' || next == '`' || next == '"' || next == '\\' || next == '\n') {
                        result ~= "\x01" ~ next; i++;
                    } else result ~= "\\";
                } else {
                    result ~= "\x01" ~ next; i++;
                }
            } else result ~= "\\";
            continue;
        }

        // Toggle Quotes
        if (c == '\'' && !inDQuote) { inSQuote = !inSQuote; continue; }
        if (c == '"' && !inSQuote) { inDQuote = !inDQuote; continue; }

        if (inSQuote) {
            result ~= "\x01" ~ c;
            continue;
        }

        // ANSI-C Quote: $'...'
        if (c == '$' && i + 1 < word.length && word[i+1] == '\'' && !inDQuote) {
            i += 2;
            while (i < word.length && word[i] != '\'') {
                if (word[i] == '\\' && i + 1 < word.length) {
                    char e = word[i+1];
                    switch(e) {
                        case 'n': result ~= "\x01\n"; break;
                        case 'r': result ~= "\x01\r"; break;
                        case 't': result ~= "\x01\t"; break;
                        case 'a': result ~= "\x01\a"; break;
                        case 'b': result ~= "\x01\b"; break;
                        case 'v': result ~= "\x01\v"; break;
                        case 'f': result ~= "\x01\f"; break;
                        case 'e': result ~= "\x01\033"; break;
                        case '\\': result ~= "\x01\\"; break;
                        case '\'': result ~= "\x01'"; break;
                        case '\"': result ~= "\x01\""; break;
                        default: result ~= "\x01" ~ e; break;
                    }
                    i++;
                } else result ~= "\x01" ~ word[i];
                i++;
            }
            continue;
        }
        
        // Locale Quote: $"..."
        if (c == '$' && i + 1 < word.length && word[i+1] == '"' && !inDQuote) {
            i++; // skip $, next loop will handle "
            continue;
        }

        if (c == '$') {
            if (i + 1 < word.length) {
                string val = "";
                if (word[i+1] == '(') {
                    // $(...) or $((...))
                    int depth = 1;
                    int j = i + 2;
                    bool isArith = (j < word.length && word[j] == '(');
                    if (isArith) j++;
                    int start = j;
                    while (j < word.length && depth > 0) {
                        if (word[j] == '(') depth++;
                        if (word[j] == ')') depth--;
                        j++;
                    }
                    string inner = word[start .. j - (isArith ? 2 : 1)];
                    if (isArith) val = to!string(evaluateArithmetic(inner));
                    else val = commandSubstitution(inner);
                    i = j - 1;
                } else if (word[i+1] == '{') {
                    // ${var...}
                    int j = i + 2;
                    while (j < word.length && word[j] != '}') j++;
                    string content = word[i + 2 .. j];
                    val = expandParameter(content);
                    i = j;
                } else {
                    // $var
                    int j = i + 1;
                    while (j < word.length && (word[j] >= 'a' && word[j] <= 'z' || word[j] >= 'A' && word[j] <= 'Z' || word[j] >= '0' && word[j] <= '9' || word[j] == '_' || word[j] == '?' || word[j] == '#' || word[j] == '!' || word[j] == '$' || word[j] == '-' || word[j] == '*' || word[j] == '@')) j++;
                    string var = word[i+1 .. j];
                    val = getVariable(var);
                    i = j - 1;
                }
                
                if (inDQuote) {
                    // Expansion in DQuote is protected from globbing
                    foreach(ch; val) result ~= "\x01" ~ ch;
                } else result ~= val;
                continue;
            }
        } else if (c == '%') {
             // Job reference expansion
             int j = i + 1;
             while (j < word.length && (word[j] >= '0' && word[j] <= '9' || word[j] >= 'a' && word[j] <= 'z')) j++;
             string jobRef = word[i .. j];
             Job job = findJobByRef(jobRef);
             if (job) {
                 string val = to!string(-job.pgid); // Kill negative PGID to signal entire group
                 if (inDQuote) foreach(ch; val) result ~= "\x01" ~ ch;
                 else result ~= val;
                 i = j - 1;
                 continue;
             }
        } else if ((c == '<' || c == '>') && i + 1 < word.length && word[i+1] == '(' && !inSQuote && !inDQuote) {
             bool isOut = (c == '>');
             i += 2;
             int depth = 1;
             int start = i;
             while (i < word.length && depth > 0) {
                 if (word[i] == '(') depth++;
                 else if (word[i] == ')') depth--;
                 i++;
             }
             string inner = word[start .. i - 1];
             string pipePath = processSubstitution(inner, isOut);
             result ~= pipePath;
             i--; 
             continue;
        } else if (c == '`') {
            int j = i + 1;
            while (j < word.length && word[j] != '`') j++;
            string val = commandSubstitution(word[i+1 .. j]);
            if (inDQuote) {
                 foreach(ch; val) result ~= "\x01" ~ ch;
            } else result ~= val;
            i = j;
            continue;
        }
        result ~= c;
    }
    return result;
}

pid_t[] procSubPids;
int[] procSubFds;

string processSubstitution(string cmdStr, bool isOut) {
    import shell.parser : parseShellCommand;
    int[2] p;
    if (pipe(p) == -1) { perror("pipe"); return ""; }
    
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); close(p[0]); close(p[1]); return ""; }
    
    if (pid == 0) {
        // Child
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        
        if (isOut) {
            dup2(p[0], STDIN_FILENO);
            close(p[1]);
            close(p[0]);
        } else {
            dup2(p[1], STDOUT_FILENO);
            close(p[0]);
            close(p[1]);
        }
        
        Node ast = parseShellCommand(cmdStr);
        if (ast) execute_job_in_child(ast);
        _exit(0);
    }
    
    // Parent
    procSubPids ~= pid;
    int fdToPass = isOut ? p[1] : p[0];
    procSubFds ~= fdToPass; // Track to close in parent after execution
    if (isOut) close(p[0]); else close(p[1]);
    
    return "/dev/fd/" ~ to!string(fdToPass);
}

string expandParameter(string content) {
    import std.string : indexOf, split, lastIndexOf, endsWith;
    
    // Handle array indexing: ${VAR[index]}
    auto lbIdx = content.indexOf('[');
    if (lbIdx != -1 && content.endsWith("]")) {
        return getVariable(content);
    }

    // content is like var:-default
    if (content.startsWith("#")) {
        string var = content[1 .. $];
        return to!string(getVariable(var).length);
    }
    
    // Check for operators
    static string[] ops = [":-", ":=", ":+", ":?", "%%", "%", "##", "#", "//", "/", "^^", "^", ",,", ","];
    foreach (op; ops) {
        auto idx = content.indexOf(op);
        if (idx != -1) {
            string var = content[0 .. idx];
            string arg = content[idx + op.length .. $];
            string val = interpreter.variables.get(var, "");
            bool unset = (val.length == 0);

            switch (op) {
                case ":-": return unset ? arg : val;
                case ":=": if (unset) interpreter.variables[var] = arg; return interpreter.variables[var];
                case ":+": return unset ? "" : arg;
                case ":?": if (unset) { writeln(var, ": ", arg.length ? arg : "parameter null or unset"); return ""; } return val;
                case "#": // Shortest prefix
                    for (size_t i = 1; i <= val.length; i++) {
                        if (globMatch(val[0 .. i], arg)) return val[i .. $];
                    }
                    return val;
                case "##": // Longest prefix
                    for (size_t i = val.length; i >= 1; i--) {
                        if (globMatch(val[0 .. i], arg)) return val[i .. $];
                    }
                    return val;
                case "%": // Shortest suffix
                    for (size_t i = 1; i <= val.length; i++) {
                        if (globMatch(val[$ - i .. $], arg)) return val[0 .. $ - i];
                    }
                    return val;
                case "%%": // Longest suffix
                    for (size_t i = val.length; i >= 1; i--) {
                        if (globMatch(val[$ - i .. $], arg)) return val[0 .. $ - i];
                    }
                    return val;
                case "/": 
                    auto parts = arg.split("/");
                    if (parts.length >= 2) return replaceFirst(val, regex(parts[0]), parts[1]);
                    return replaceFirst(val, regex(arg), "");
                case "//":
                    auto parts = arg.split("/");
                    if (parts.length >= 2) return replaceAll(val, regex(parts[0]), parts[1]);
                    return replaceAll(val, regex(arg), "");
                case "^": 
                    if (val.length == 0) return "";
                    return to!string(cast(char)toUpper(val[0])) ~ val[1..$];
                case "^^": return toUpper(val);
                case ",": 
                    if (val.length == 0) return "";
                    return to!string(cast(char)toLower(val[0])) ~ val[1..$];
                case ",,": return toLower(val);
                default: break;
            }
        }
    }
    return interpreter.variables.get(content, "");
}

string commandSubstitution(string cmd) {
    import shell.parser : parseShellCommand;
    int[2] p;
    if (pipe(p) == -1) return "";
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        dup2(p[1], 1);
        close(p[1]);
        auto ast = parseShellCommand(cmd);
        if (ast) execute_job_in_child(ast);
        _exit(0);
    }
    close(p[1]);
    string result;
    ubyte[1024] buf;
    long n;
    while ((n = core.sys.posix.unistd.read(p[0], buf.ptr, buf.length)) > 0) {
        result ~= cast(string)buf[0 .. n];
    }
    close(p[0]);
    waitpid(pid, null, 0);
    import std.string : stripRight;
    return result.stripRight("\n");
}

string removeQuoteMarkers(string s) {
    string res = "";
    for (int i = 0; i < cast(int)s.length; i++) {
        if (s[i] == '\x01') {
            if (i + 1 < s.length) { res ~= s[i+1]; i++; }
        } else {
            res ~= s[i];
        }
    }
    return res;
}

string[] expandFull(string word) {
    // Layer 2: Expansion Phase
    
    // Step 1: Brace Expansion
    string[] results;
    auto braced = braceExpand(word);
    
    foreach(b; braced) {
        // Step 2: Parameter Expansion, Command Substitution, Arithmetic Expansion
        // (Handled by expandWord which processes from left-to-right)
        string expanded = expandWord(b);
        
        // Step 3: Field Splitting (simple space-based, respecting \x01 markers)
        string[] fields;
        string currentField = "";
        for (int i = 0; i < cast(int)expanded.length; i++) {
            if (expanded[i] == '\x01') {
                currentField ~= expanded[i];
                if (i + 1 < expanded.length) { currentField ~= expanded[i+1]; i++; }
            } else if (expanded[i] == ' ' || expanded[i] == '\t' || expanded[i] == '\n') {
                if (currentField.length > 0) fields ~= currentField;
                currentField = "";
            } else {
                currentField ~= expanded[i];
            }
        }
        if (currentField.length > 0) fields ~= currentField;
        if (fields.length == 0 && expanded.length > 0) fields ~= "";

        // Step 4: Pathname Expansion (Globbing)
        foreach(f; fields) {
            auto matched = pathnameExpand(f, extglobEnabled);
            // Step 5: Quote Removal
            foreach(m; matched) results ~= removeQuoteMarkers(m);
        }
    }
    return results;
}

public void initializeShell() {
    import std.datetime : Clock;
    startTime = Clock.currStdTime / 10000000L;
    shell_pgid = getpid();
    
    // Ignore interactive signals for the shell itself
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    
    version(ANONYMOS_MINIMAL) {
        // Limited TTY support on AnonymOS potentially, but try what's possible
    } else {
        if (isatty(STDIN_FILENO)) {
            while (tcgetpgrp(STDIN_FILENO) != getpgrp()) {
                kill(-shell_pgid, SIGTTIN);
            }
            if (setpgid(shell_pgid, shell_pgid) < 0) {
                // perror("setpgid");
            }
            tcsetpgrp(STDIN_FILENO, shell_pgid);
        }
    }
}
