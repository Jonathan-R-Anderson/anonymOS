module kernel.host.container_runtime;

pragma(LDC_no_moduleinfo);

version(linux)
{
    private enum SYS_FORK   = 57;
    private enum SYS_EXECVE = 59;
    private enum SYS_WAIT4  = 61;
    private enum SYS_EXIT   = 60;

    private long linux_syscall(long num, long a1=0, long a2=0, long a3=0, long a4=0, long a5=0, long a6=0)
    {
        long ret;
        asm
        {
            mov RAX, num;
            mov RDI, a1;
            mov RSI, a2;
            mov RDX, a3;
            mov R10, a4;
            mov R8,  a5;
            mov R9,  a6;
            syscall;
            mov ret, RAX;
        }
        return ret;
    }
}

extern(C) int host_run_container(const(char)* image, const(char)* cmd)
{
    version(linux)
    {
        if(image is null || cmd is null)
            return -1;

        long pid = linux_syscall(SYS_FORK);
        if(pid == 0)
        {
            static immutable char[] shell = "/bin/sh";
            const(char)* argv[4];
            argv[0] = shell.ptr;
            argv[1] = "-c".ptr;
            char[256] command;
            size_t idx = 0;
            auto prefix = "docker run --rm -it ";
            foreach(c; prefix)
                command[idx++] = c;
            for(size_t i=0; image[i]; ++i)
                command[idx++] = image[i];
            command[idx++] = ' ';
            for(size_t i=0; cmd[i]; ++i)
                command[idx++] = cmd[i];
            command[idx++] = 0;
            argv[2] = command.ptr;
            argv[3] = null;
            linux_syscall(SYS_EXECVE, cast(long)shell.ptr, cast(long)&argv[0], 0);
            linux_syscall(SYS_EXIT, 1, 0, 0, 0, 0, 0);
        }
        else if(pid > 0)
        {
            long status = 0;
            linux_syscall(SYS_WAIT4, pid, cast(long)&status, 0, 0);
            return cast(int)status;
        }
    }
    return -1;
}
