//! Linux namespace isolation for executing suspicious binaries.
//!
//! Creates isolated PID, mount, network, and user namespaces using
//! `clone()` with namespace flags. The child process runs in a minimal
//! environment with its own PID space, filesystem view, and optionally
//! no network access.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::{SandboxConfig, SandboxResult, SandboxVerdict};

/// Stack size for the cloned child process (1 MiB).
const CHILD_STACK_SIZE: usize = 1024 * 1024;

/// Create isolated namespace environment for running suspicious binaries.
pub struct NamespaceSandbox {
    /// Temporary root directory for the mount namespace.
    root_dir: PathBuf,
    /// Whether to allow network access (if false, creates empty net namespace).
    network: bool,
    /// Additional bind mounts (source -> destination relative to root).
    bind_mounts: Vec<(PathBuf, PathBuf)>,
}

impl NamespaceSandbox {
    /// Create a new namespace sandbox from the given configuration.
    pub fn new(config: &SandboxConfig) -> Result<Self> {
        let root_dir = std::env::temp_dir().join(format!("prx-sandbox-{}", std::process::id()));

        std::fs::create_dir_all(&root_dir)
            .with_context(|| format!("failed to create sandbox root: {}", root_dir.display()))?;

        Ok(Self {
            root_dir,
            network: config.network_allowed,
            bind_mounts: Vec::new(),
        })
    }

    /// Add a bind mount from `source` to `dest` (relative to sandbox root).
    pub fn add_bind_mount(&mut self, source: PathBuf, dest: PathBuf) {
        self.bind_mounts.push((source, dest));
    }

    /// Execute a command in isolated namespaces (PID + MNT + NET + USER).
    ///
    /// Uses `libc::clone` with `CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUSER`
    /// to create a fully isolated child process. The child sets up its mount namespace,
    /// applies seccomp filters, and then exec's the target binary.
    #[allow(clippy::items_after_statements)] // clone_callback defined near its usage for readability
    pub fn execute(&self, cmd: &Path, args: &[&str], timeout: Duration) -> Result<SandboxResult> {
        let cmd_str = cmd.to_string_lossy().to_string();
        let args_owned: Vec<String> = args.iter().map(ToString::to_string).collect();
        let root_dir = self.root_dir.clone();
        let network = self.network;
        let bind_mounts = self.bind_mounts.clone();

        // Allocate a stack for the cloned child.
        let mut stack = vec![0u8; CHILD_STACK_SIZE];

        // The stack grows downward on x86_64, so pass the top of the buffer.
        let stack_top = stack.as_mut_ptr().wrapping_add(CHILD_STACK_SIZE);

        let mut flags = libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::CLONE_NEWUSER;
        if !network {
            flags |= libc::CLONE_NEWNET;
        }

        extern "C" fn clone_callback(arg: *mut libc::c_void) -> libc::c_int {
            // SAFETY: arg is a valid pointer to our Box<dyn FnOnce() -> i32> created above.
            // We take ownership back and call it exactly once.
            let closure = unsafe { Box::from_raw(arg.cast::<Box<dyn FnOnce() -> i32>>()) };
            closure()
        }

        // Closure that runs in the child (new namespace).
        let child_fn = Box::new(move || -> i32 {
            if let Err(e) = Self::child_setup(&root_dir, &bind_mounts, &cmd_str, &args_owned) {
                tracing::error!("namespace child setup failed: {e:#}");
                return 127;
            }
            // child_setup calls execve, so this is only reached on error
            127
        });

        // We need to pass the closure through the C callback. Use a Box leak pattern.
        let child_fn_ptr = Box::into_raw(Box::new(child_fn));

        // SAFETY: We provide a valid stack, valid flags, and a valid callback.
        // The child_fn_ptr is a heap-allocated closure that is consumed exactly once
        // by clone_callback. The stack is large enough (1 MiB) and properly aligned.
        let child_pid = unsafe {
            libc::clone(
                clone_callback,
                stack_top.cast::<libc::c_void>(),
                flags,
                child_fn_ptr.cast::<libc::c_void>(),
            )
        };

        if child_pid < 0 {
            // Clean up the leaked closure on error.
            // SAFETY: clone failed, so clone_callback was never called and the pointer is still valid.
            let _ = unsafe { Box::from_raw(child_fn_ptr) };
            return Err(std::io::Error::last_os_error()).context("clone() with namespace flags failed");
        }

        let pid = nix::unistd::Pid::from_raw(child_pid);

        // Wait for the child with timeout.
        let start = std::time::Instant::now();
        let exit_code = loop {
            if start.elapsed() > timeout {
                tracing::warn!("namespace sandbox timeout, killing child pid={child_pid}");
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(pid, None);
                return Ok(SandboxResult {
                    exit_code: -1,
                    syscalls: Vec::new(),
                    behaviors: Vec::new(),
                    verdict: SandboxVerdict::Timeout,
                    threat_score: 0,
                    network_attempts: Vec::new(),
                    file_operations: Vec::new(),
                    process_operations: Vec::new(),
                    #[allow(clippy::cast_possible_truncation)] // millis within u64 range for practical timeouts
                    execution_time_ms: timeout.as_millis() as u64,
                });
            }

            match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => break code,
                Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => break -(sig as i32),
                Ok(nix::sys::wait::WaitStatus::StillAlive | _) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(nix::errno::Errno::ECHILD) => break -1,
                Err(e) => {
                    return Err(anyhow::anyhow!("waitpid error in namespace sandbox: {e}"));
                }
            }
        };

        let elapsed = start.elapsed();

        // Clean up the temporary root directory.
        let _ = std::fs::remove_dir_all(&self.root_dir);

        Ok(SandboxResult {
            exit_code,
            syscalls: Vec::new(),
            behaviors: Vec::new(),
            verdict: SandboxVerdict::Clean,
            threat_score: 0,
            network_attempts: Vec::new(),
            file_operations: Vec::new(),
            process_operations: Vec::new(),
            #[allow(clippy::cast_possible_truncation)] // millis within u64 range for practical timeouts
            execution_time_ms: elapsed.as_millis() as u64,
        })
    }

    /// Setup function that runs inside the cloned child process.
    ///
    /// Sets up mount namespace (tmpfs root, bind mounts), then exec's the target.
    fn child_setup(root_dir: &Path, bind_mounts: &[(PathBuf, PathBuf)], cmd: &str, args: &[String]) -> Result<()> {
        use std::ffi::CString;

        // Setup mount namespace: mount tmpfs on our root.
        Self::setup_mount_namespace(root_dir, bind_mounts)?;

        // Apply seccomp filter for additional protection.
        let seccomp = super::seccomp::SeccompFilter::new();
        seccomp.apply().context("failed to apply seccomp in namespace child")?;

        // Build C strings for execve.
        let c_cmd = CString::new(cmd).context("invalid command for execve")?;
        let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
        c_args.push(c_cmd.clone());
        for arg in args {
            c_args.push(CString::new(arg.as_str()).context("invalid argument for execve")?);
        }

        // Exec the target binary.
        nix::unistd::execvp(&c_cmd, &c_args).context("execvp in namespace failed")?;

        Ok(())
    }

    /// Set up the mount namespace with a tmpfs root and bind mounts.
    fn setup_mount_namespace(root_dir: &Path, bind_mounts: &[(PathBuf, PathBuf)]) -> Result<()> {
        use std::ffi::CString;

        // Mount tmpfs on the sandbox root.
        let c_root = CString::new(root_dir.as_os_str().as_encoded_bytes()).context("invalid root path")?;
        let c_tmpfs = CString::new("tmpfs").context("CString creation failed")?;
        let c_none = CString::new("").context("CString creation failed")?;

        // SAFETY: All pointers are valid CStrings. MS_NOSUID | MS_NODEV are standard
        // mount flags that restrict setuid and device creation in the tmpfs.
        let ret = unsafe {
            libc::mount(
                c_tmpfs.as_ptr(),
                c_root.as_ptr(),
                c_tmpfs.as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                c_none.as_ptr().cast::<libc::c_void>(),
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error()).context("mount tmpfs on root failed");
        }

        // Create essential directories.
        for dir in &["proc", "dev", "tmp"] {
            let p = root_dir.join(dir);
            std::fs::create_dir_all(&p).with_context(|| format!("failed to create {}", p.display()))?;
        }

        // Process bind mounts.
        for (src, dest) in bind_mounts {
            let target = root_dir.join(dest);
            std::fs::create_dir_all(&target)
                .with_context(|| format!("failed to create bind mount target: {}", target.display()))?;

            let c_src = CString::new(src.as_os_str().as_encoded_bytes())
                .with_context(|| format!("invalid bind mount source: {}", src.display()))?;
            let c_target = CString::new(target.as_os_str().as_encoded_bytes())
                .with_context(|| format!("invalid bind mount target: {}", target.display()))?;

            // SAFETY: Valid CString pointers, MS_BIND | MS_RDONLY are standard bind mount flags.
            let ret = unsafe {
                libc::mount(
                    c_src.as_ptr(),
                    c_target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_RDONLY,
                    std::ptr::null(),
                )
            };
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("bind mount {} -> {} failed", src.display(), target.display()));
            }
        }

        Ok(())
    }
}

impl Drop for NamespaceSandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_dir);
    }
}
