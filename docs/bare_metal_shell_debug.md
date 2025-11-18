# Debugging a frozen bare-metal shell

When the minimal OS build finishes and `[shell] Booting 'lfe-sh' interactive shell...` is the last message you see, the execution is stuck inside `minimal_os.posix.launchInteractiveShell()`'s `bareMetalShellLoop()` (see `src/minimal_os/posix.d`). The loop only prints that banner after successfully spawning `/bin/sh`, so the next step is to figure out whether the new process ever runs or exits. Because the environment often lacks `strace`, `printf`, or other conveniences, the `dbg` stream emitted by the kernel is the best way to inspect progress.

The snippets below assume the same console transcript you quoted:

```
[shell] Starting bare-metal shell on serial...
[posix-debug] createObjectFromBuffer object count: expected=256, actual=125
[posix-debug] createObjectFromBuffer object count: expected=256, actual=126
[shell] Booting 'lfe-sh' interactive shell...
```

That exact ordering means `bareMetalShellLoop()` is executing, `spawnRegisteredProcess()` keeps allocating registry slots, and the scheduler is trying to re-launch the shell without ever reaching `shellExecEntry()`.

## 1. Confirm which path you are in

`launchInteractiveShell()` has two code paths: a direct `execve` for host POSIX builds and a bare-metal loop that relies on the embedded scheduler. The presence of `[shell] Starting bare-metal shell on serial...` proves you are already inside the bare-metal branch **even if you implemented your own POSIX utilities**. From that point onward, only the hooks provided by `minimal_os.posix` (the ones declared in `src/minimal_os/posix.d`) are used. If you ever observe host-specific behavior after that banner, double-check that your build did not accidentally define `version (Posix)` and that no other module overwrote `g_spawnRegisteredProcessFn`/`g_waitpidFn` after `shell_integration` called `ensureBareMetalShellInterfaces()` (lines 332‑354 of `src/minimal_os/kernel/shell_integration.d`).

To confirm at runtime, halt in `launchInteractiveShell()` and inspect those globals:

```
(gdb) p g_spawnRegisteredProcessFn
(gdb) p g_waitpidFn
```

If either pointer is `NULL`, your integration never called `registerBareMetalShellInterfaces()`; wire that call into whichever module provides the real spawn/wait implementation before the kernel jumps into `bareMetalShellLoop()`.

## 2. Trace `spawnRegisteredProcess`

`bareMetalShellLoop()` launches the shell via the function pointer `g_spawnRegisteredProcessFn`. The default implementation (lines ~1814‑1835 of `src/minimal_os/posix.d`) emits these `dbg` labels:

* `spawnRegisteredProcess slot found` – the `/bin/sh` executable table entry was located.
* `spawnRegisteredProcess alloc success` – a `Proc` struct was reserved for the shell.
* `spawnRegisteredProcess pid assigned` – the new process received a pid greater than 0.

If any of these prints show `expected=1, actual=0`, focus on registration: the kernel only reaches the loop after `g_shellRegistered` becomes true, so a missing slot generally means `/bin/sh` was deregistered later or `registerProcessExecutable` failed. Fixing the registration is sufficient because the loop will automatically retry as soon as the call succeeds. When you see the `createObjectFromBuffer` counters increase without ever hitting 256 (like `actual=125`, `actual=126`), it means repeated spawn attempts are handing out registry slots but the children never progress far enough for `completeProcess` to reclaim them—another hint that execution never reached `shellExecEntry()`.

## 3. Observe `sys_waitpid`

Immediately after spawning, the loop waits for the shell with `g_waitpidFn(pid, &status, 0)`. On bare metal this resolves to `sys_waitpid` (lines ~1614‑1642), which prints `sys_waitpid child matched` with `actual=1` as soon as it reaps a zombie child. Seeing only the `actual=0` variant means the current process has no matching children, so either the spawn failed silently or another part of the kernel cleared the shell's `ppid`. If the label never reappears after a successful match, the shell is still running and has not called `_exit` yet. When your log shows `[shell] Booting 'lfe-sh' interactive shell...` again without any `sys_waitpid` success, it means the wait loop is never finding the pid it just spawned—set a breakpoint on `g_waitpidFn` and inspect the process table to confirm whether the kernel ever enqueued the child.

`sys_waitpid` falls back to `schedYield()` every iteration. If you never see `sys_waitpid child matched` with `actual=1`, use the scheduler's own `dbg` markers (`schedYield initialized`, `schedYield next selected`) to verify that at least one READY process exists in the run queue. A missing READY process indicates that the shell crashed before becoming RUNNING; check `completeProcess` logs for corresponding failures.

## 4. Validate the shell entry point

The default `shellExecEntry` simply invokes `runHostShellSession(argv, envp)` (lines ~2102‑2107). If your host integration forgot to provide that symbol, the process will fault immediately. Confirm that your linker map exports `runHostShellSession` and that your `dbg` stream contains the banner the host side prints before starting `lfe-sh`. If the symbol is missing, temporarily register an alternate entry point that just prints to the console to prove the scheduler works, then add the missing host bridge.

## 5. Iterate quickly

While debugging, keep GDB stopped on `launchInteractiveShell` and repeatedly single-step the `g_spawnRegisteredProcessFn`/`g_waitpidFn` calls. After each iteration, dump the recent `dbg` log (the monitor collects the last few kilobytes) so you can correlate every label with the code blocks above. This is faster than reflashing the entire image, and the deterministic labels make it clear which prerequisite failed without additional instrumentation. If you see the kernel immediately re-print `[shell] Booting 'lfe-sh' interactive shell...`, verify that `decodeShellExitStatus()` is running with the status returned by your `waitpid` implementation; a bogus status that always sets the signal bit will force the loop to restart without ever reaching `shellExecEntry()`.

Following this checklist lets you diagnose why the bare-metal shell never prints its prompt using only the built-in `dbg` telemetry.
