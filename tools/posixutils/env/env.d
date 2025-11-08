// env.d — D translation of the provided C++ "env" tool
module env_tool;

import std.stdio : stderr, writef, writeln;
import std.getopt : getopt, defaultGetoptPrinter;
import std.string : indexOf, toStringz;
import std.conv : to;

// ---------- POSIX interop ----------
extern (C):
    __gshared char** environ; // current process environment

    // execve(path, argv, envp)
    int execve(const(char)*, const(char*)* /*argv*/, const(char*)* /*envp*/);

    // strerror / errno for error reporting on exec failure
    import core.stdc.string : strerror;
    import core.stdc.errno  : errno;

// ---------- Globals / options ----------
__gshared bool optNoInherit = false;

struct Lists {
    string[] envList; // ["KEY=VAL", ...]
    string[] argList; // ["utility", "arg1", ...]
}

bool isEnvKV(string s)
{
    auto pos = s.indexOf('=');
    // must have '=' and not start with '=' and not end right at '='
    return pos > 0 && pos < s.length - 1;
}

bool envListed(string key, in string[] envList)
{
    foreach (kv; envList)
    {
        auto pos = kv.indexOf('=');
        if (pos <= 0) continue;
        if (kv[0 .. pos] == key) return true;
    }
    return false;
}

int countEnv()
{
    int i = 0;
    while (environ !is null && environ[i] !is null) ++i;
    return i;
}

int doEnv(ref Lists L)
{
    // Build argv for execve (null-terminated)
    if (L.argList.length == 0)
        return 127;

    auto argc = L.argList.length;
    auto argv = new const(char)*[argc + 1];
    foreach (i, a; L.argList) argv[i] = a.toStringz;
    argv[$ - 1] = null; // last element before null
    argv[$]      = null; // explicit terminator

    // Build envp (null-terminated)
    // Start with provided pairs
    size_t nEnv = L.envList.length + 1; // +1 for terminator
    if (!optNoInherit) nEnv += countEnv();

    auto envp = new const(char)*[nEnv];
    size_t idx = 0;

    foreach (kv; L.envList)
        envp[idx++] = kv.toStringz;

    if (!optNoInherit)
    {
        for (int i = 0; environ !is null && environ[i] !is null; ++i)
        {
            // Keep inherited env only if not overridden by L.envList
            import std.string : fromStringz;
            auto kv = fromStringz(environ[i]);
            auto pos = kv.indexOf('=');
            if (pos <= 0) continue;
            auto key = kv[0 .. pos];
            if (!envListed(key, L.envList))
                envp[idx++] = environ[i];
        }
    }

    envp[idx] = null; // terminator

    // execve: path is argv[0]; on success, current process image is replaced
    auto rc = execve(argv[0], argv.ptr, envp.ptr);
    // If we’re here, exec failed
    auto err = errno;
    stderr.writef("execve(%s): %s\n", L.argList[0], to!string(strerror(err)));
    return 127;
}

int main(string[] args)
{
    // Parse: -i, then a sequence of name=value pairs
    // until the first non-env (or "=..."), then utility + its args.
    Lists L;
    bool parsingEnv = true;

    try
    {
        auto help = getopt(
            args,
            "i", &optNoInherit
        );

        // Remaining positionals:
        foreach (arg; help.args)
        {
            if (parsingEnv && (!isEnvKV(arg) || arg[0] == '='))
                parsingEnv = false;

            if (parsingEnv)
                L.envList ~= arg;
            else
                L.argList ~= arg;
        }
    }
    catch (Exception e)
    {
        stderr.writeln(e.msg);
        return 2;
    }

    // Validate like original:
    // if -i and no env pairs provided, usage;
    // if no utility provided, usage.
    if (optNoInherit && L.envList.length == 0)
    {
        stderr.writef("Usage: %s [name=value]... utility [args]...\n", args[0]);
        return 1;
    }
    if (L.argList.length == 0)
    {
        stderr.writef("Usage: %s [name=value]... utility [args]...\n", args[0]);
        return 1;
    }

    return doEnv(L);
}
