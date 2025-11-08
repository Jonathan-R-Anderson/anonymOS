// nohup.d
module nohup;

import core.stdc.stdlib : getenv, exit;
import core.stdc.stdio : perror, fprintf, stderr;
import core.stdc.string : strlen;
import core.sys.posix.fcntl : open, O_WRONLY, O_CREAT, O_APPEND;
import core.sys.posix.sys.stat : S_IRUSR, S_IWUSR;
import core.sys.posix.unistd : dup2, isatty, execvp, STDOUT_FILENO, STDERR_FILENO;
import core.sys.posix.signal : signal, SIG_IGN, SIGHUP;
import std.stdio : writeln;
import std.string : toStringz;
import std.conv : to;

enum NOHUP_ERR = 127;
enum OUTPUT_FN = "nohup.out";

__gshared int redirect_fd = STDOUT_FILENO;

void redirect_stdout()
{
    const char* home_env = getenv("HOME");
    string fn = OUTPUT_FN;

    // Try ./nohup.out first
    int fd = open(fn.toStringz, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);

    // If that fails and $HOME exists, try $HOME/nohup.out
    if (fd < 0 && home_env !is null)
    {
        fn = (to!string(home_env) ~ "/" ~ OUTPUT_FN);
        fd = open(fn.toStringz, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    }

    if (fd < 0)
    {
        // perror needs a C string
        perror(fn.toStringz);
        exit(NOHUP_ERR);
    }

    if (dup2(fd, STDOUT_FILENO) < 0)
    {
        perror("stdout redirect failed".toStringz);
        exit(NOHUP_ERR);
    }

    // Match original: print notice to stderr
    // (using fprintf to keep exact stream semantics)
    fprintf(stderr, "nohup: appending output to '%s'\n".toStringz, fn.toStringz);

    redirect_fd = fd;
}

void redirect_stderr()
{
    if (dup2(redirect_fd, STDERR_FILENO) < 0)
    {
        // Might be lost if stderr already broken, but matches original
        perror("stderr redirect failed".toStringz);
        exit(NOHUP_ERR);
    }
}

int main(string[] args)
{
    // Rough equivalent of pu_init(); omitted since it's project-specific.
    // If you truly need it, declare extern(C) void pu_init(); and call it.

    if (args.length < 2)
    {
        // Match original message/exit code
        fprintf(stderr, "nohup: no arguments\n".toStringz);
        return NOHUP_ERR;
    }

    // Redirect stdout/stderr only if they’re terminals
    if (isatty(STDOUT_FILENO) == 1)
        redirect_stdout();
    if (isatty(STDERR_FILENO) == 1)
        redirect_stderr();

    // Ignore SIGHUP
    signal(SIGHUP, SIG_IGN);

    // Build argv for execvp: args[1..$] plus terminating null
    auto progAndArgs = args[1 .. $];
    const(char)*[] cargv;
    cargv.length = progAndArgs.length + 1; // +1 for the final null

    foreach (i, s; progAndArgs)
        cargv[i] = s.toStringz;
    cargv[$ - 1] = null; // last actual arg already set; we'll append null below

    // execvp expects **argv terminated by null pointer
    // We already ensured cargv[$-1] is null by allocating +1; if not, append explicitly:
    // (defensive)
    if (cargv.length == 0 || cargv[$-1] !is null)
        cargv ~= cast(const char*)null;

    // Execute
    execvp(cargv[0], cast(const(char**) ) cargv.ptr);

    // If we’re here, exec failed.
    perror("execvp(3)".toStringz);
    return NOHUP_ERR;
}
