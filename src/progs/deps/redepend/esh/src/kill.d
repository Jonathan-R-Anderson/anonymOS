module kill;

import std.stdio;
import std.conv;
import std.algorithm : startsWith;
import shell.syscalls;

// Add kill syscall
enum SYS_KILL = 62;

long sys_kill(int pid, int sig) {
    long ret;
    asm {
        mov RAX, SYS_KILL;
        mov RDI, pid;
        mov RSI, sig;
        syscall;
        mov ret, RAX;
    }
    return ret;
}

void killCommand(string[] tokens) {
    if (tokens.length < 2) {
        writeln("Usage: kill [-SIGNAL] PID");
        return;
    }
    
    int signal = 15; // SIGTERM
    size_t idx = 1;
    
    // Parse signal if provided
    if (tokens[idx].startsWith("-")) {
        try {
            signal = to!int(tokens[idx][1..$]);
        } catch (Exception e) {
            writeln("kill: invalid signal");
            return;
        }
        idx++;
    }
    
    if (idx >= tokens.length) {
        writeln("kill: missing PID");
        return;
    }
    
    // Send signal to each PID
    foreach (pidStr; tokens[idx..$]) {
        try {
            int pid = to!int(pidStr);
            auto ret = sys_kill(pid, signal);
            if (ret < 0) {
                writeln("kill: (", pid, ") - No such process");
            }
        } catch (Exception e) {
            writeln("kill: invalid PID: ", pidStr);
        }
    }
}
