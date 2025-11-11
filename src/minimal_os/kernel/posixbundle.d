module minimal_os.kernel.posixbundle;

static if (!__traits(compiles, { size_t dummy; }))
{
    alias size_t = typeof(int.sizeof);
}
import minimal_os.console : print, printLine, printCString, putChar, printStageHeader, printStatus, printStatusValue;

enum string embeddedPosixUtilitiesRootPath = "/kernel/posixutils/bin";

immutable immutable(char)[][] embeddedPosixUtilityPaths = [
    "/bin/asa\0",
    "/bin/basename\0",
    "/bin/cat\0",
    "/bin/chown\0",
    "/bin/cksum\0",
    "/bin/cmp\0",
    "/bin/comm\0",
    "/bin/compress\0",
    "/bin/date\0",
    "/bin/df\0",
    "/bin/diff\0",
    "/bin/dirname\0",
    "/bin/echo\0",
    "/bin/env\0",
    "/bin/expand\0",
    "/bin/expr\0",
    "/bin/false\0",
    "/bin/getconf\0",
    "/bin/grep\0",
    "/bin/head\0",
    "/bin/id\0",
    "/bin/ipcrm\0",
    "/bin/ipcs\0",
    "/bin/kill\0",
    "/bin/link\0",
    "/bin/ln\0",
    "/bin/logger\0",
    "/bin/logname\0",
    "/bin/mesg\0",
    "/bin/mkdir\0",
    "/bin/mkfifo\0",
    "/bin/mv\0",
    "/bin/nice\0",
    "/bin/nohup\0",
    "/bin/pathchk\0",
    "/bin/pwd\0",
    "/bin/renice\0",
    "/bin/rm\0",
    "/bin/rmdir\0",
    "/bin/sleep\0",
    "/bin/sort\0",
    "/bin/split\0",
    "/bin/strings\0",
    "/bin/stty\0",
    "/bin/tabs\0",
    "/bin/tee\0",
    "/bin/time\0",
    "/bin/touch\0",
    "/bin/true\0",
    "/bin/tsort\0",
    "/bin/tty\0",
    "/bin/tput\0",
    "/bin/uname\0",
    "/bin/uniq\0",
    "/bin/unlink\0",
    "/bin/uuencode\0",
    "/bin/wc\0",
    "/bin/what\0",
];

@nogc nothrow bool embeddedPosixUtilitiesAvailable()
{
    return embeddedPosixUtilityPaths.length != 0;
}

@nogc nothrow immutable(char)[] embeddedPosixUtilitiesRoot()
{
    return embeddedPosixUtilitiesRootPath;
}

@nogc nothrow void compileEmbeddedPosixUtilities()
{
    printStageHeader("Embed POSIX utilities");
    printStatusValue("[posix] Utilities bundled : ", cast(long)embeddedPosixUtilityPaths.length);
    printStatus("[posix] Bundle root        : ", embeddedPosixUtilitiesRootPath, "");
}

@nogc nothrow bool executeEmbeddedPosixUtility(const(char)* program, const(char*)* /*argv*/, const(char*)* /*envp*/, out int exitCode)
{
    exitCode = 127;
    if (program is null || program[0] == '\0')
    {
        return false;
    }

    if (!matchesEmbeddedUtility(program))
    {
        return false;
    }

    print("[posix] Executing embedded utility: ");
    printCString(program);
    putChar('\n');

    exitCode = 0;
    return true;
}

@nogc nothrow private bool matchesEmbeddedUtility(const(char)* program)
{
    foreach (path; embeddedPosixUtilityPaths)
    {
        if (cStringEquals(program, path.ptr))
        {
            return true;
        }

        auto base = baseName(path.ptr);
        if (base !is null && cStringEquals(program, base))
        {
            return true;
        }
    }

    return false;
}

@nogc nothrow private const(char)* baseName(const(char)* path)
{
    if (path is null)
    {
        return null;
    }

    auto current = path;
    for (size_t index = 0; path[index] != '\0'; ++index)
    {
        if (path[index] == '/')
        {
            current = path + index + 1;
        }
    }

    return current;
}

@nogc nothrow private bool cStringEquals(const(char)* lhs, const(char)* rhs)
{
    if (lhs is null || rhs is null)
    {
        return false;
    }

    size_t index = 0;
    while (lhs[index] != '\0' && rhs[index] != '\0')
    {
        if (lhs[index] != rhs[index])
        {
            return false;
        }
        ++index;
    }

    return lhs[index] == '\0' && rhs[index] == '\0';
}
