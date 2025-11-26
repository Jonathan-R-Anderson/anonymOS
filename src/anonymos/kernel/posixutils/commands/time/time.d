/+ 
  ptime.d — D port of posixutils “time”-like utility (GPL-2.0)

  Behavior mirrors the original C:
    - If invoked with no args, or exactly "-p", prints "no args" to stderr and exits 1.
    - Forks, execvp()s the target command in the child.
    - Parent wait4()s and prints real/user/sys times to stderr.
    - Returns child's exit status (or 126 if exec failed).
+/
module ptime;

version(Posix):

import std.stdio;
import std.string;
import std.conv;
import std.exception;
import core.stdc.stdlib : exit;
import core.stdc.string : strlen;
import core.stdc.config : c_long;
import core.sys.posix.unistd : execvp, fork, pid_t;
import core.sys.posix.sys.types;
import core.sys.posix.sys.time : timeval, gettimeofday;
import core.sys.posix.sys.resource : rusage;
import core.sys.posix.sys.wait : WIFEXITED, WEXITSTATUS;
import core.sys.posix.unistd;

extern(C) void perror(const char*);

// wait4 is not always declared in D's posix headers; declare it explicitly.
extern(C) pid_t wait4(pid_t pid, int* status, int options, rusage* rusage);

// --------- globals ----------
__gshared timeval start_time;

// --------- helpers ----------
int doChild(string[] argvSlice)
{
    // Build C argv: null-terminated array of const(char)*
    auto cargv = new const(char)*[argvSlice.length + 1];
    foreach (i, a; argvSlice) cargv[i] = a.ptr;
    cargv[$-1] = null;

    // execvp(argv[0], argv)
    execvp(argvSlice[0].ptr, cast(char**)cargv.ptr);
    perror("exec failed");
    return 126;
}

int doWait(pid_t pid)
{
    rusage ru;
    int status = 0;
    timeval end_time;

    auto rc = wait4(pid, &status, 0, &ru);
    if (rc < 0) {
        perror("wait4(child)");
        return 1;
    }

    if (WIFEXITED(status) && (WEXITSTATUS(status) == 126)) {
        stderr.writeln("exec failed");
        return 126;
    }

    if (gettimeofday(&end_time, null) < 0) {
        perror("gettimeofday 2");
        return 1;
    }

    // wall-clock delta
    ulong sec  = cast(ulong)(end_time.tv_sec  - start_time.tv_sec);
    long  usec = end_time.tv_usec - start_time.tv_usec;
    if (usec < 0) {
        usec += 1_000_000;
        if (sec > 0) --sec;
    }

    // Match original formatting (centiseconds by dividing by 10000)
    // NOTE: original C had a typo printing ru_stime.tv_sec twice; we correct to tv_usec here.
    stderr.writefln("real %s.%s", sec,  usec / 10_000);
    stderr.writefln("user %s.%s",
        cast(ulong)ru.ru_utime.tv_sec,
        cast(ulong)ru.ru_utime.tv_usec / 10_000UL);
    stderr.writefln("sys %s.%s",
        cast(ulong)ru.ru_stime.tv_sec,
        cast(ulong)ru.ru_stime.tv_usec / 10_000UL);

    return WEXITSTATUS(status);
}

int main(string[] args)
{
    // Keep the same odd -p handling as the original:
    // have_p := (argc == 2 && argv[1] == "-p"), then treat as "no args".
    immutable haveP = (args.length == 2 && args[1] == "-p");
    if (args.length == 1 || haveP) {
        stderr.writeln("no args");
        return 1;
    }

    if (gettimeofday(&start_time, null) < 0) {
        perror("gettimeofday");
        return 1;
    }

    auto pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        // child: exec target command (everything after program name)
        // Original code’s -p branch was unreachable; we mirror its effective behavior.
        return doChild(args[1 .. $]);
    }

    // parent
    return doWait(pid);
}
