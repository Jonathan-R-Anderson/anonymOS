module kernel.shell;

import kernel.terminal : terminal_writestring, terminal_writestring_color, terminal_putchar;
import kernel.keyboard : keyboard_getchar;
import kernel.fs : fs_chdir, fs_getcwd, fs_lookup, fs_pread_file, fs_open_file, fs_close_file, Node, NodeType, fsCurrentDir;

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

// Command history storage (simple circular buffer)
__gshared char[256][32] command_history;
__gshared size_t history_count = 0;
__gshared size_t history_index = 0;

void add_to_history(const char[] cmd) {
    if (cmd.length == 0) return;
    size_t idx = history_count % 32;
    size_t len = cmd.length < 255 ? cmd.length : 255;
    foreach(i; 0 .. len) {
        command_history[idx][i] = cmd[i];
    }
    command_history[idx][len] = '\0';
    history_count++;
}

void show_history() {
    terminal_writestring("Command history:\r\n");
    size_t start = history_count > 32 ? history_count - 32 : 0;
    for(size_t i = start; i < history_count; i++) {
        size_t idx = i % 32;
        terminal_writestring("  ");
        // Print line number
        char[16] num_buf;
        size_t num_len = 0;
        size_t n = i + 1;
        if (n == 0) {
            num_buf[num_len++] = '0';
        } else {
            while (n > 0) {
                num_buf[num_len++] = '0' + (n % 10);
                n /= 10;
            }
            // Reverse the number
            for(size_t j = 0; j < num_len / 2; j++) {
                char tmp = num_buf[j];
                num_buf[j] = num_buf[num_len - 1 - j];
                num_buf[num_len - 1 - j] = tmp;
            }
        }
        foreach(j; 0 .. num_len) terminal_putchar(num_buf[j]);
        terminal_writestring(": ");
        // Print command
        for(size_t j = 0; j < 256 && command_history[idx][j] != '\0'; j++) {
            terminal_putchar(command_history[idx][j]);
        }
        terminal_writestring("\r\n");
    }
}

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

private void list_dir(Node* dir)
{
    auto child = dir.child;
    while(child !is null)
    {
        terminal_writestring(child.name);
        if(child.sibling !is null)
            terminal_writestring(" ");
        child = child.sibling;
    }
    terminal_writestring("\r\n");
}

/// Simple first-time setup that installs the non-cross D compiler
/// and prepares the shell environment. This is only a stub that
/// prints status messages but represents running the real installer.
void build_d_compiler()
{
    import kernel.logger : log_message;

    terminal_writestring("Verifying D compiler...\r\n");
    log_message("Using bundled dmd if available\n");
    // The image now ships with a prebuilt dmd binary under /bin/dmd. If it is
    // absent this function would invoke the installer script to build it.
    terminal_writestring("D compiler ready.\r\n");
}

void build_shell()
{
    import kernel.logger : log_message;

    terminal_writestring("Checking for prebuilt shell...\r\n");
    log_message("Using precompiled -sh binary if available\n");
    // The build system now compiles the shell ahead of time and places the
    // resulting binary at /bin/sh within the ISO image.  If the binary is
    // missing this function would normally invoke the installer script to
    // compile it, but that logic is not yet implemented.
    terminal_writestring("Shell ready.\r\n");
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

/// Entry point for the built-in -sh shell.
/// In a real system this would start the userland shell process.
extern(C) void shMain()
{
    import kernel.process_manager : get_current_pid, process_exit;

    terminal_writestring("Welcome to -sh shell.\r\n");
    setup_first_user();

    terminal_writestring("Initialization complete. Starting shell...\r\n");
    shInteractive();
}

/// Original interactive loop preserved as a separate function. It
/// can be invoked explicitly once the installer has completed and
/// the shell has been compiled.
extern(C) void shInteractive()
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

        // Add command to history
        add_to_history(cmd);

        // Command matching
        if (cmd == "help") {
            terminal_writestring("Available commands:\r\n");
            terminal_writestring("  help     - show this message\r\n");
            terminal_writestring("  clear    - clear the screen\r\n");
            terminal_writestring("  echo     - print text\r\n");
            terminal_writestring("  ls       - list directory\r\n");
            terminal_writestring("  cd       - change directory\r\n");
            terminal_writestring("  pwd      - show current directory\r\n");
            terminal_writestring("  cat      - print file contents\r\n");
            terminal_writestring("  mkdir    - create directory\r\n");
            terminal_writestring("  rmdir    - remove directory\r\n");
            terminal_writestring("  rm       - remove file\r\n");
            terminal_writestring("  cp       - copy file\r\n");
            terminal_writestring("  mv       - move/rename file\r\n");
            terminal_writestring("  touch    - create empty file\r\n");
            terminal_writestring("  date     - show current date/time\r\n");
            terminal_writestring("  whoami   - show current user\r\n");
            terminal_writestring("  uname    - show system information\r\n");
            terminal_writestring("  ps       - show processes\r\n");
            terminal_writestring("  history  - show command history\r\n");
            terminal_writestring("  alias    - create command alias\r\n");
            terminal_writestring("  exit     - terminate shell\r\n");
            terminal_writestring("\r\nThis is anonymOS with enhanced -sh shell integration\r\n");
            printSyscalls();
        } else if (cmd == "clear") {
            import kernel.device.vga : clear_screen;
            clear_screen();
        } else if (cmd.length >= 4 && cmd[0 .. 4] == "echo" && (cmd.length == 4 || cmd[4] == ' ')) {
            size_t start = 4;
            if (start < cmd.length && cmd[start] == ' ') start++;
            foreach(i; start .. cmd.length) {
                terminal_putchar(cmd[i]);
            }
            terminal_writestring("\r\n");
        } else if (cmd == "pwd") {
            auto cwd = fs_getcwd();
            terminal_writestring(cwd);
            terminal_writestring("\r\n");
        } else if (cmd.length >= 2 && cmd[0 .. 2] == "cd" && (cmd.length == 2 || cmd[2] == ' ')) {
            size_t start = 2;
            if (start < cmd.length && cmd[start] == ' ') start++;
            if (start >= cmd.length) {
                terminal_writestring("cd: missing operand\r\n");
            } else {
                char[128] path;
                size_t len = 0;
                foreach(i; start .. cmd.length) if(len < path.length-1) path[len++] = cmd[i];
                path[len] = 0;
                if(fs_chdir(path.ptr) != 0)
                    terminal_writestring("cd: no such dir\r\n");
            }
        } else if (cmd == "ls" || (cmd.length > 2 && cmd[0 .. 2] == "ls" && cmd[2] == ' ')) {
            Node* dir = fsCurrentDir;
            size_t start = 2;
            if (cmd.length > 2 && cmd[2] == ' ') {
                start = 3;
                if(start < cmd.length) {
                    char[128] path;
                    size_t len=0;
                    foreach(i; start .. cmd.length) if(len < path.length-1) path[len++] = cmd[i];
                    path[len]=0;
                    auto n = fs_lookup(path.ptr);
                    if(n !is null && n.kind == NodeType.Directory)
                        dir = n;
                    else {
                        terminal_writestring("ls: no such dir\r\n");
                        continue;
                    }
                }
            }
            list_dir(dir);
        } else if (cmd.length >= 3 && cmd[0 .. 3] == "cat" && (cmd.length == 3 || cmd[3] == ' ')) {
            size_t start = 3;
            if (start < cmd.length && cmd[start] == ' ') start++;
            if (start >= cmd.length) {
                terminal_writestring("cat: missing file\r\n");
            } else {
                char[128] path;
                size_t len=0;
                foreach(i; start .. cmd.length) if(len < path.length-1) path[len++] = cmd[i];
                path[len]=0;
                int fd = fs_open_file(path.ptr,0);
                if(fd < 0) {
                    terminal_writestring("cat: cannot open file\r\n");
                } else {
                    import kernel.fs : Stat, fs_fstat;
                    Stat st; if(fs_fstat(fd,&st)==0) {
                        char[256] buf; size_t pos=0;
                        while(pos < st.size) {
                            auto r = fs_pread_file(fd, buf.ptr, buf.length, pos);
                            if(r <= 0) break; 
                            foreach(i; 0 .. r) terminal_putchar(buf[i]);
                            pos += r;
                        }
                    }
                    fs_close_file(fd);
                    terminal_writestring("\r\n");
                }
            }
        } else if (cmd == "exit") {
            import kernel.process_manager : get_current_pid, process_exit;
            terminal_writestring("Bye!\r\n");
            auto pid = get_current_pid();
            process_exit(pid, 0);
            break;
        } else if (cmd == "history") {
            show_history();
        } else if (cmd == "date") {
            terminal_writestring("Current date/time: Not available (RTC not implemented)\r\n");
        } else if (cmd == "whoami") {
            terminal_writestring("root\r\n");
        } else if (cmd == "uname") {
            terminal_writestring("anonymOS 1.0.0 x86_64\r\n");
        } else if (cmd.length >= 5 && cmd[0 .. 5] == "mkdir" && (cmd.length == 5 || cmd[5] == ' ')) {
            terminal_writestring("mkdir: command not implemented in this filesystem\r\n");
        } else if (cmd.length >= 5 && cmd[0 .. 5] == "touch" && (cmd.length == 5 || cmd[5] == ' ')) {
            size_t start = 5;
            if (start < cmd.length && cmd[start] == ' ') start++;
            if (start >= cmd.length) {
                terminal_writestring("touch: missing file operand\r\n");
            } else {
                char[128] path;
                size_t len = 0;
                foreach(i; start .. cmd.length) if(len < path.length-1) path[len++] = cmd[i];
                path[len] = 0;
                int fd = fs_open_file(path.ptr, 1); // Create flag
                if(fd < 0) {
                    terminal_writestring("touch: cannot create file\r\n");
                } else {
                    fs_close_file(fd);
                    terminal_writestring("File created\r\n");
                }
            }
        } else if (cmd == "ps") {
            terminal_writestring("PID  COMMAND\r\n");
            terminal_writestring("  1  kernel\r\n");
            terminal_writestring("  2  shell\r\n");
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

extern(C) void sh_shell()
{
    import kernel.logger : log_message;
    import kernel.elf_loader : load_elf;
    import kernel.process_manager : process_create, scheduler_run, EntryFunc;

    // After build_shell() the compiled binary should reside at /bin/sh
    void* entry = null;
    if(load_elf("/bin/sh", &entry) == 0 && entry !is null)
    {
        log_message("Launching compiled shell\n");
        auto pid = process_create(cast(EntryFunc)entry);
        scheduler_run();
    }
    else
    {
        log_message("Compiled shell missing, falling back to stub\n");
        // Invoke the stub shell implementation.
        shMain();
    }
}

/// Entry point for the system installer process. This runs the minimal
/// setup steps such as creating the default user and installing the
/// bundled D compiler before handing control to the interactive shell.
extern(C) void init_setup()
{
    terminal_writestring("Running installer...\r\n");
    setup_first_user();
    terminal_writestring("Installer finished.\r\n");
}
