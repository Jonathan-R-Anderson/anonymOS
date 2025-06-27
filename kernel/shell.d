module kernel.shell;

import kernel.terminal : terminal_writestring, terminal_writestring_color, terminal_putchar;
import kernel.keyboard : keyboard_getchar;
import kernel.fs : Node, NodeType, Stat, fsCurrentDir, fs_lookup, fs_chdir,
                   fs_open_file, fs_pread_file, fs_close_file, fs_stat,
                   fs_getcwd;

// Table of available syscalls and brief usage info.
__gshared const(char*)[] syscallHelp = [
    "0  WriteString(ptr,len)  - print string",
    "1  CreateUser(name)      - add user",
    "2  Open(path,mode)       - open file",
    "3  Create(path,mode,perm) - create file",
    "4  PRead(fd,buf,count,off) - read from position",
    "5  PWrite(fd,buf,count,off) - write at position",
    "6  Seek(fd,offset,whence)   - set file pos",
    "7  Close(fd)               - close file",
    "8  Dup(old,new)            - dup descriptor",
    "9  FD2Path(fd)             - fd -> path",
    "10 Stat(path,stat*)        - file stats",
    "11 FStat(fd,stat*)         - fstat",
    "12 WStat(path,stat*)       - write stat",
    "13 FWStat(fd,stat*)        - f wstat",
    "14 Remove(path)            - delete",
    "15 ChDir(path)             - change dir",
    "16 Mount(spec,target,flg,fs,aname) - mount",
    "17 Bind(old,new,flg)       - bind mount",
    "18 Unmount(target)         - unmount",
    "19 RFork(flags)            - fork proc",
    "20 Exec(path,argv)         - exec shell",
    "21 Exit(status)            - exit proc",
    "22 ErrStr(buf,n)           - last error",
    "23 Sleep(ticks)            - delay",
    "24 Await()                 - wait child",
    "25 Pipe(fds[2])            - create pipe",
    "26 Rendezvous(tag,val)     - sync",
    "27 SemAcquire(id)          - sem wait",
    "28 SemRelease(id)          - sem post",
    "29 Brk(addr)               - brk",
    "30 SegAttach(pid,seg,addr,len,ro) - map",
    "31 SegDetach(pid,seg)      - unmap",
    "32 SegBrk(pid,seg,len)     - grow seg",
    "33 SegFree(pid,seg,addr,len) - free seg",
    "34 SegFlush(pid,seg,addr,len) - flush",
    "35 FVersion(msize,ver,fid) - init 9P",
    "36 FAuth(afid,u,a)         - auth 9P",
    "37 Alarm(ticks)            - set alarm",
    "38 Notify(handler)         - set handler",
    "39 Noted(mode)             - note done"
];

private void printSyscalls()
{
    terminal_writestring("Syscall table (use do_syscall):\r\n");
    foreach(line; syscallHelp)
    {
        terminal_writestring(line);
        terminal_writestring("\r\n");
    }
}

private bool similar(const(char)[] a, const(char)[] b)
{
    size_t la = a.length;
    size_t lb = b.length;
    size_t minLen = (la < lb) ? la : lb;
    size_t diff = (la > lb) ? la - lb : lb - la;
    for(size_t i = 0; i < minLen; ++i) {
        if (a[i] != b[i]) diff++;
    }
    return diff <= 1;
}

private bool streq(const(char)* a, const(char)* b)
{
    size_t i = 0;
    while(a[i] && b[i])
    {
        if(a[i] != b[i]) return false;
        ++i;
    }
    return a[i] == 0 && b[i] == 0;
}

private void printPrompt()
{
    terminal_writestring("wcuser@default:");
    terminal_writestring(fs_getcwd());
    terminal_writestring("$ ");
}

private void listDir(Node* dir)
{
    auto c = dir.child;
    while(c !is null)
    {
        terminal_writestring(c.name);
        if(c.kind == NodeType.Directory)
            terminal_writestring("/");
        terminal_writestring(" ");
        c = c.sibling;
    }
    terminal_writestring("\r\n");
}

private void catFile(const(char)* path)
{
    Stat st;
    if(fs_stat(path, &st) != 0 || st.kind != NodeType.File)
    {
        terminal_writestring("File not found\r\n");
        return;
    }
    int fd = fs_open_file(path, 0);
    if(fd < 0)
    {
        terminal_writestring("Unable to open file\r\n");
        return;
    }
    size_t off = 0;
    char[128] buf;
    while(true)
    {
        long r = fs_pread_file(fd, buf.ptr, buf.length, off);
        if(r <= 0) break;
        for(size_t i = 0; i < cast(size_t)r; i++)
            terminal_putchar(buf[i]);
        off += cast(size_t)r;
    }
    fs_close_file(fd);
    terminal_writestring("\r\n");
}

/// Stub implementation for the Haskell ttyShelly shell entry point.
/// The real implementation is expected to come from the userland
/// Haskell code, but that is currently not linked in the kernel build.
extern(C) void ttyShellyMain()
{
    terminal_writestring("Welcome to ttyShelly stub shell.\r\n");

    char[256] line;

    while (true) {
        // Display shell prompt
        printPrompt();

        size_t idx = 0;
        // Clear buffer to avoid old data
        for (size_t i = 0; i < line.length; ++i)
            line[i] = 0;

        while (true) {
            char c = keyboard_getchar();

            if (c == '\n') {
                terminal_writestring("\r\n");
                line[idx] = '\0';
                break;
            } else if (c == '\b' || c == 127) {
                if (idx > 0) {
                    idx--;
                    terminal_writestring("\b \b"); // erase character visually
                }
            } else if (idx < line.length - 1) {
                line[idx++] = c;
                terminal_putchar(c); // echo character here instead of IRQ
            }
        }

        if (idx == 0) {
            continue; // Empty input, skip
        }

        size_t pos = 0;
        while(line[pos] && line[pos] != ' ') ++pos;
        char* arg = null;
        if(line[pos])
        {
            line[pos] = 0;
            arg = line.ptr + pos + 1;
        }

        if(streq(line.ptr, "help"))
        {
            terminal_writestring("Available commands:\r\n");
            terminal_writestring("  help - show this message\r\n");
            terminal_writestring("  exit - halt the system\r\n");
            terminal_writestring("  ls [dir] - list directory\r\n");
            terminal_writestring("  cd DIR - change directory\r\n");
            terminal_writestring("  pwd - print working directory\r\n");
            terminal_writestring("  cat FILE - show file contents\r\n");
            printSyscalls();
        }
        else if(streq(line.ptr, "exit"))
        {
            terminal_writestring("Bye!\r\n");
            asm { "hlt"; }
        }
        else if(streq(line.ptr, "pwd"))
        {
            terminal_writestring(fs_getcwd());
            terminal_writestring("\r\n");
        }
        else if(streq(line.ptr, "ls"))
        {
            Node* dir = fsCurrentDir;
            if(arg !is null && arg[0] != 0)
            {
                dir = fs_lookup(arg);
            }
            if(dir is null || dir.kind != NodeType.Directory)
            {
                terminal_writestring("No such directory\r\n");
            }
            else
            {
                listDir(dir);
            }
        }
        else if(streq(line.ptr, "cd"))
        {
            if(arg is null)
            {
                terminal_writestring("Usage: cd DIR\r\n");
            }
            else if(fs_chdir(arg) != 0)
            {
                terminal_writestring("Directory not found\r\n");
            }
        }
        else if(streq(line.ptr, "cat"))
        {
            if(arg is null)
            {
                terminal_writestring("Usage: cat FILE\r\n");
            }
            else
            {
                catFile(arg);
            }
        }
        else
        {
            terminal_writestring("Unknown command\r\n");
        }

        // Prompt will redraw at top of loop
    }
}




extern(C) void ttyShelly_shell()
{
    // Invoke the stub or real Haskell shell if linked.
    ttyShellyMain();
}
