module kernel.shell;

import kernel.terminal : terminal_writestring, terminal_writestring_color, terminal_putchar;
import kernel.keyboard : keyboard_getchar;

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

/// Return the current CPU privilege level (CPL) using the CS register.
private ubyte get_cpl()
{
    ushort cs;
    asm { "mov %%cs, %0" : "=r"(cs); }
    return cast(ubyte)(cs & 3);
}

/// Print the dynamic shell prompt in the form user@namespace:path(permission)
private void print_prompt()
{
    import kernel.user_manager : get_current_user;
    import kernel.fs : fs_getcwd;

    auto user = get_current_user();
    auto cwd = fs_getcwd();
    ubyte cpl = get_cpl();

    terminal_writestring(user);
    terminal_writestring("@default:"); // namespace placeholder
    terminal_writestring(cwd);
    terminal_writestring("(");
    terminal_putchar(cast(char)('0' + cpl));
    terminal_writestring(") ");
}

/// Simple first-time setup that installs the non-cross D compiler
/// and prepares the shell environment. This is only a stub that
/// prints status messages but represents running the real installer.
private void install_d_compiler()
{
    import kernel.logger : log_message;

    terminal_writestring("Running initial installer...\r\n");
    log_message("Installing D compiler\n");
    // In a full system this would unpack and build the native dmd
    // compiler so the shell can be compiled inside the OS.
    terminal_writestring("D compiler installed.\r\n");
}

private void setup_first_user()
{
    import kernel.user_manager : create_user, set_current_user, userCount;
    import kernel.fs : fs_create_file_desc, fs_pwrite_file, fs_close_file;
    import kernel.types : strlen;

    // Skip if a user already exists
    if(userCount > 1) return;

    // Automatically create a default account instead of prompting
    const(char)* username = "user1";
    const(char)* passhash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"; // "password"

    create_user(username);
    set_current_user(username);

    int fd = fs_create_file_desc("/etc/shadow", 0, 0);
    if(fd >= 0)
    {
        size_t ulen = strlen(username);
        fs_pwrite_file(fd, username, ulen, 0);
        char colon = ':';
        fs_pwrite_file(fd, &colon, 1, ulen);
        fs_pwrite_file(fd, passhash, strlen(passhash), ulen + 1);
        fs_close_file(fd);
    }

    terminal_writestring("Default user created\r\n");
}



/// Stub implementation for the Haskell ttyShelly shell entry point.
/// The real implementation is expected to come from the userland
/// Haskell code, but that is currently not linked in the kernel build.
extern(C) void ttyShellyMain()
{
    import kernel.process_manager : get_current_pid, process_exit;

    terminal_writestring("Welcome to ttyShelly stub shell.\r\n");
    setup_first_user();

    // Run the installer once and then exit to allow the scheduler to
    // continue. In a full build this would compile the shell using the
    // freshly installed D compiler.
    install_d_compiler();

    terminal_writestring("Setup complete. Exiting installer.\r\n");
    auto pid = get_current_pid();
    process_exit(pid, 0);
}

/// Original interactive loop preserved as a separate function. It
/// can be invoked explicitly once the installer has completed and
/// the shell has been compiled.
extern(C) void ttyShellyInteractive()
{
    char[256] line;

    while (true) {
        // Display shell prompt dynamically
        print_prompt();

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

        // Convert the null-terminated buffer to a slice without using
        // the GC-enabled std.string.fromStringz helper which is
        // incompatible with -betterC.
        auto cmd = line[0 .. idx];

        // Command matching
        if (cmd == "help") {
            terminal_writestring("Available commands:\r\n");
            terminal_writestring("  help - show this message\r\n");
            terminal_writestring("  exit - halt the system\r\n");
            printSyscalls();
        } else if (cmd == "exit") {
            terminal_writestring("Bye!\r\n");
            asm { "hlt"; }
        } else {
            bool suggested = false;
            if (similar(cmd, "help")) {
                terminal_writestring("Unknown command. Did you mean 'help'?\r\n");
                suggested = true;
            } else if (similar(cmd, "exit")) {
                terminal_writestring("Unknown command. Did you mean 'exit'?\r\n");
                suggested = true;
            }

            if (!suggested) {
                terminal_writestring("Unknown command. This is not a system call.\r\n");
            }
        }

        // Prompt will redraw at top of loop
    }
}




extern(C) void ttyShelly_shell()
{
    // Invoke the stub or real Haskell shell if linked.
    ttyShellyMain();
}
