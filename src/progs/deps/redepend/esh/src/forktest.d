module forktest;

import std.stdio;
import std.conv;
import shell.syscalls; // Ensure we have access to syscalls including sys_wait4, sys_fork, sys_exit

void forktestCommand(string[] tokens) {
    writeln("Fork Test starting...");

    int pid = cast(int)sys_fork();
    
    if (pid < 0) {
        writeln("fork failed!");
        return;
    }
    
    if (pid == 0) {
        // Child process
        writeln("  [Child] Hello from child! PID=0 (relative)");
        writeln("  [Child] Exiting with code 42...");
        sys_exit(42);
        
        writeln("  [Child] FATAL: Should not reach here!");
    } else {
        // Parent process
        writeln("  [Parent] Forked child with PID: ", pid);
        writeln("  [Parent] Waiting for child...");
        
        int status;
        int waitRes = cast(int)sys_wait4(pid, &status, 0); // 0 = blocking
        
        writeln("  [Parent] waitpid returned: ", waitRes);
        writeln("  [Parent] Child exit status: ", status);
        
        if (waitRes == pid && status == 42) {
            writeln("  [Parent] SUCCESS: Child exited correctly and was reaped.");
        } else {
            writeln("  [Parent] FAILURE: Unexpected wait result.");
        }
    }
}
