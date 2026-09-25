//! System call tracing via ptrace for behavioral analysis.
//!
//! Forks a child process, attaches via `PTRACE_TRACEME`, and records all
//! system calls made by the child until it exits or the timeout is reached.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, execvp, fork};
use serde::{Deserialize, Serialize};

// ── Syscall name table (architecture-specific) ──────────────────────────────

#[cfg(target_arch = "x86_64")]
fn syscall_name(nr: u64) -> String {
    match nr {
        0 => "read".into(),
        1 => "write".into(),
        2 => "open".into(),
        3 => "close".into(),
        4 => "stat".into(),
        5 => "fstat".into(),
        6 => "lstat".into(),
        7 => "poll".into(),
        8 => "lseek".into(),
        9 => "mmap".into(),
        10 => "mprotect".into(),
        11 => "munmap".into(),
        12 => "brk".into(),
        13 => "rt_sigaction".into(),
        14 => "rt_sigprocmask".into(),
        15 => "rt_sigreturn".into(),
        16 => "ioctl".into(),
        17 => "pread64".into(),
        18 => "pwrite64".into(),
        19 => "readv".into(),
        20 => "writev".into(),
        21 => "access".into(),
        22 => "pipe".into(),
        23 => "select".into(),
        32 => "dup".into(),
        33 => "dup2".into(),
        35 => "nanosleep".into(),
        39 => "getpid".into(),
        41 => "socket".into(),
        42 => "connect".into(),
        43 => "accept".into(),
        44 => "sendto".into(),
        45 => "recvfrom".into(),
        49 => "bind".into(),
        50 => "listen".into(),
        56 => "clone".into(),
        57 => "fork".into(),
        58 => "vfork".into(),
        59 => "execve".into(),
        60 => "exit".into(),
        62 => "kill".into(),
        63 => "uname".into(),
        78 => "getdents".into(),
        79 => "getcwd".into(),
        80 => "chdir".into(),
        82 => "rename".into(),
        83 => "mkdir".into(),
        84 => "rmdir".into(),
        85 => "creat".into(),
        86 => "link".into(),
        87 => "unlink".into(),
        88 => "symlink".into(),
        89 => "readlink".into(),
        90 => "chmod".into(),
        92 => "chown".into(),
        96 => "gettimeofday".into(),
        101 => "ptrace".into(),
        102 => "getuid".into(),
        105 => "setuid".into(),
        110 => "getppid".into(),
        157 => "prctl".into(),
        217 => "getdents64".into(),
        231 => "exit_group".into(),
        257 => "openat".into(),
        262 => "newfstatat".into(),
        288 => "accept4".into(),
        302 => "prlimit64".into(),
        318 => "getrandom".into(),
        _ => format!("syscall_{nr}"),
    }
}

#[cfg(target_arch = "aarch64")]
fn syscall_name(nr: u64) -> String {
    // aarch64 syscall table (Linux kernel, partial).
    // Note: aarch64 has no legacy open/stat/lstat — only openat/fstatat.
    match nr {
        17 => "getcwd".into(),
        23 => "dup".into(),
        24 => "dup3".into(),
        25 => "fcntl".into(),
        29 => "ioctl".into(),
        34 => "mkdirat".into(),
        35 => "unlinkat".into(),
        36 => "symlinkat".into(),
        37 => "linkat".into(),
        38 => "renameat".into(),
        48 => "faccessat".into(),
        49 => "chdir".into(),
        52 => "fchmodat".into(),
        54 => "fchownat".into(),
        56 => "openat".into(),
        57 => "close".into(),
        62 => "lseek".into(),
        63 => "read".into(),
        64 => "write".into(),
        65 => "readv".into(),
        66 => "writev".into(),
        67 => "pread64".into(),
        68 => "pwrite64".into(),
        72 => "pselect6".into(),
        73 => "ppoll".into(),
        78 => "readlinkat".into(),
        79 => "newfstatat".into(),
        80 => "fstat".into(),
        93 => "exit".into(),
        94 => "exit_group".into(),
        101 => "nanosleep".into(),
        129 => "kill".into(),
        134 => "rt_sigaction".into(),
        135 => "rt_sigprocmask".into(),
        139 => "rt_sigreturn".into(),
        160 => "uname".into(),
        172 => "getpid".into(),
        174 => "getuid".into(),
        175 => "geteuid".into(),
        198 => "socket".into(),
        200 => "bind".into(),
        201 => "listen".into(),
        202 => "accept".into(),
        203 => "connect".into(),
        206 => "sendto".into(),
        207 => "recvfrom".into(),
        210 => "shutdown".into(),
        214 => "brk".into(),
        215 => "munmap".into(),
        220 => "clone".into(),
        221 => "execve".into(),
        222 => "mmap".into(),
        226 => "mprotect".into(),
        242 => "accept4".into(),
        261 => "prlimit64".into(),
        278 => "getrandom".into(),
        281 => "execveat".into(),
        _ => format!("syscall_{nr}"),
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn syscall_name(nr: u64) -> String {
    format!("syscall_{nr}")
}

// ── SyscallEvent ────────────────────────────────────────────────────────────

/// A recorded system call event from ptrace tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// The system call number.
    pub number: u64,
    /// Human-readable name of the system call.
    pub name: String,
    /// Return value of the system call (-1 on error).
    pub return_value: i64,
    /// Timestamp in nanoseconds since the trace started.
    pub timestamp_ns: u64,
}

// ── Architecture-specific register access ───────────────────────────────────

/// Extract the syscall number from ptrace registers.
#[cfg(target_arch = "x86_64")]
const fn get_syscall_nr(regs: &libc::user_regs_struct) -> u64 {
    regs.orig_rax
}

#[cfg(target_arch = "aarch64")]
#[allow(clippy::indexing_slicing)] // fixed register index 8 is always in bounds
const fn get_syscall_nr(regs: &libc::user_regs_struct) -> u64 {
    // On aarch64, x8 holds the syscall number.
    regs.regs[8]
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const fn get_syscall_nr(_regs: &libc::user_regs_struct) -> u64 {
    0
}

/// Extract the syscall return value from ptrace registers.
#[cfg(target_arch = "x86_64")]
#[allow(clippy::cast_possible_wrap)] // rax holds the return value which may be negative errno
const fn get_syscall_ret(regs: &libc::user_regs_struct) -> i64 {
    regs.rax as i64
}

#[cfg(target_arch = "aarch64")]
#[allow(clippy::indexing_slicing, clippy::cast_possible_wrap)] // fixed register index 0
const fn get_syscall_ret(regs: &libc::user_regs_struct) -> i64 {
    // On aarch64, x0 holds the return value.
    regs.regs[0] as i64
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const fn get_syscall_ret(_regs: &libc::user_regs_struct) -> i64 {
    -1
}

// ── PtraceTracer ────────────────────────────────────────────────────────────

/// Traces system calls of a child process using ptrace.
pub struct PtraceTracer;

impl PtraceTracer {
    /// Execute a command and trace all its system calls.
    ///
    /// Forks a child process that calls `PTRACE_TRACEME` and then `execvp`'s
    /// the given command. The parent process uses `PTRACE_SYSCALL` to trace
    /// every system call entry/exit until the child exits or the timeout
    /// is reached.
    ///
    /// # Arguments
    ///
    /// * `cmd`     - Path to the executable.
    /// * `args`    - Arguments to pass (argv[1..]).
    /// * `timeout` - Maximum wall-clock time before the child is killed.
    ///
    /// Returns a list of all system calls that were observed.
    #[allow(clippy::similar_names)] // `c_args` and `args` are semantically distinct
    pub fn trace_child(cmd: &Path, args: &[&str], timeout: Duration) -> Result<Vec<SyscallEvent>> {
        let c_cmd = CString::new(cmd.as_os_str().as_bytes()).context("invalid command path")?;

        // Build the full c_args: [cmd, args...]
        let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
        c_args.push(c_cmd.clone());
        for arg in args {
            c_args.push(CString::new(*arg).context("invalid argument")?);
        }

        let start = Instant::now();

        // SAFETY: We immediately diverge in child (exec) and parent (trace loop).
        // No shared mutable state is accessed after fork.
        match unsafe { fork() }.context("fork failed")? {
            ForkResult::Child => {
                // Child: request to be traced, then exec.
                if let Err(e) = ptrace::traceme() {
                    tracing::error!("PTRACE_TRACEME failed: {e}");
                    std::process::exit(127);
                }

                // Raise SIGSTOP so the parent can set up tracing options.
                if let Err(e) = nix::sys::signal::raise(Signal::SIGSTOP) {
                    tracing::error!("raise SIGSTOP failed: {e}");
                    std::process::exit(127);
                }

                // Execute the target binary with PATH lookup and the provided arguments.
                let Err(e) = execvp(&c_cmd, &c_args);
                tracing::error!("execvp failed: {e}");
                std::process::exit(127);
            }
            ForkResult::Parent { child } => Self::trace_loop(child, timeout, start),
        }
    }

    /// Main tracing loop in the parent process.
    fn trace_loop(child: Pid, timeout: Duration, start: Instant) -> Result<Vec<SyscallEvent>> {
        let mut events = Vec::new();
        let mut in_syscall = false;
        let mut current_nr: u64 = 0;

        // Wait for the initial SIGSTOP from the child.
        match waitpid(child, None).context("waitpid for initial stop failed")? {
            WaitStatus::Stopped(_, Signal::SIGSTOP) => {}
            other => {
                anyhow::bail!("unexpected initial wait status: {other:?}");
            }
        }

        // Set ptrace options to trace syscalls.
        ptrace::setoptions(
            child,
            ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_EXITKILL,
        )
        .context("ptrace setoptions failed")?;

        // Resume with PTRACE_SYSCALL.
        ptrace::syscall(child, None).context("initial PTRACE_SYSCALL failed")?;

        loop {
            // Check timeout.
            if start.elapsed() > timeout {
                tracing::warn!("ptrace timeout reached, killing child");
                let _ = nix::sys::signal::kill(child, Signal::SIGKILL);
                let _ = waitpid(child, None);
                break;
            }

            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _)) => break,
                Ok(WaitStatus::PtraceSyscall(_)) => {
                    if in_syscall {
                        // Syscall exit: read the return value.
                        let return_value = ptrace::getregs(child).map_or(-1, |regs| get_syscall_ret(&regs));

                        let elapsed = start.elapsed();
                        #[allow(clippy::cast_possible_truncation)] // nanos within u64 for practical durations
                        let ts_ns = elapsed.as_nanos() as u64;
                        events.push(SyscallEvent {
                            number: current_nr,
                            name: syscall_name(current_nr),
                            return_value,
                            timestamp_ns: ts_ns,
                        });

                        in_syscall = false;
                    } else {
                        // Syscall entry: read the syscall number from registers.
                        match ptrace::getregs(child) {
                            Ok(regs) => {
                                current_nr = get_syscall_nr(&regs);
                                in_syscall = true;
                            }
                            Err(e) => {
                                tracing::debug!("getregs failed on entry: {e}");
                                break;
                            }
                        }
                    }

                    // Continue tracing.
                    if ptrace::syscall(child, None).is_err() {
                        break;
                    }
                }
                Ok(WaitStatus::Stopped(_, sig)) => {
                    // Forward any signal that isn't the ptrace stop.
                    let _ = ptrace::syscall(child, Some(sig));
                }
                Ok(_) => {
                    // Other status — keep going.
                    if ptrace::syscall(child, None).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("waitpid error: {e}");
                    break;
                }
            }
        }

        Ok(events)
    }
}
