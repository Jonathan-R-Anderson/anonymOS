module waitpid_tool;

import std.stdio : writeln, writefln, stderr;
import std.getopt : getopt, defaultGetoptPrinter, GetoptResult, config;
import std.conv : to, ConvException;

import core.sys.posix.sys.types : pid_t;
import core.sys.posix.sys.wait : waitpid, WNOHANG, WUNTRACED,
    WIFEXITED, WEXITSTATUS, WIFSIGNALED, WTERMSIG, WIFSTOPPED, WSTOPSIG;
import core.stdc.stdio : perror;

private void printStatus(pid_t pid, int status)
{
    writefln("pid %lld:", cast(long long)pid);

    if (WIFEXITED(status))
    {
        writefln("  exited with status %d", WEXITSTATUS(status));
        return;
    }
    if (WIFSIGNALED(status))
    {
        writefln("  terminated by signal %d", WTERMSIG(status));
        return;
    }
    if (WIFSTOPPED(status))
    {
        writefln("  stopped by signal %d", WSTOPSIG(status));
        return;
    }

    writefln("  status 0x%X", status);
}

int main(string[] args)
{
    bool optNoHang = false;
    bool optReportStopped = false;

    GetoptResult res;
    try
    {
        res = getopt(args,
            config.passThrough,
            "n|nohang", &optNoHang,
            "u|untraced", &optReportStopped
        );
    }
    catch (Exception)
    {
        defaultGetoptPrinter("waitpid - wait for a child process", res.options);
        return 2;
    }

    string[] positionals = (args.length > 1) ? args[1 .. $] : [];
    if (positionals.length != 1)
    {
        defaultGetoptPrinter("waitpid requires exactly one PID argument.", res.options);
        return 2;
    }

    pid_t targetPid;
    try
    {
        targetPid = cast(pid_t)to!long(positionals[0]);
    }
    catch (ConvException)
    {
        stderr.writefln("waitpid: invalid pid '%s'", positionals[0]);
        return 2;
    }

    int options = 0;
    if (optNoHang) options |= WNOHANG;
    if (optReportStopped) options |= WUNTRACED;

    int status = 0;
    auto waited = waitpid(targetPid, &status, options);
    if (waited < 0)
    {
        perror("waitpid");
        return 1;
    }

    if (waited == 0)
    {
        stderr.writeln("waitpid: no child process changed state");
        return 1;
    }

    printStatus(waited, status);
    return 0;
}
