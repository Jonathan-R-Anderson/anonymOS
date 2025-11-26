module anonymos.kernel.posixutils.process.process;

import core.stdc.errno : errno, EINVAL, ENOENT;
import core.sys.posix.sys.types : pid_t;
import core.sys.posix.sys.wait : posixWaitpid = waitpid;
import core.sys.posix.unistd : fork, execve, _exit;

extern(C) __gshared char** environ;

@nogc nothrow extern(C)
pid_t spawnRegisteredProcess(const(char)* path,
                             const(char*)* argv,
                             const(char*)* envp)
{
    if (path is null)
    {
        errno = EINVAL;
        return -1;
    }
    if (path[0] == '\0')
    {
        errno = ENOENT;
        return -1;
    }

    const(char*)[2] fallbackArgv = [path, null];
    const(char*)* argvVector = argv;
    if (argvVector is null || argvVector[0] is null)
    {
        argvVector = fallbackArgv.ptr;
    }

    const(char*)[1] emptyEnv = [null];
    const(char*)* envVector = envp;
    if (envVector is null)
    {
        envVector = cast(const(char*)*)environ;
        if (envVector is null)
        {
            envVector = emptyEnv.ptr;
        }
    }

    const pid_t child = fork();
    if (child < 0)
    {
        return child;
    }
    if (child == 0)
    {
        execve(path, cast(char**)argvVector, cast(char**)envVector);
        _exit(127);
    }

    return child;
}

@nogc nothrow extern(C)
pid_t waitpid(pid_t pid, int* status, int options)
{
    return posixWaitpid(pid, status, options);
}
