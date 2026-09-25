use std::ffi::CString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::event::FileEvent;
use crate::monitor::FileSystemMonitor;

// ── fanotify constants ──────────────────────────────────────────────────────

const FAN_CLASS_CONTENT: libc::c_uint = 0x04;
const FAN_CLOEXEC: libc::c_uint = 0x01;
const FAN_NONBLOCK: libc::c_uint = 0x02;

const FAN_MARK_ADD: libc::c_uint = 0x01;
const FAN_MARK_MOUNT: libc::c_uint = 0x10;

const FAN_OPEN_PERM: u64 = 0x0001_0000;
const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
const FAN_ACCESS_PERM: u64 = 0x0002_0000;
const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;

const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

const FAN_EVENT_METADATA_LEN: usize = std::mem::size_of::<FanotifyEventMetadata>();
const FANOTIFY_METADATA_VERSION: u8 = 3;

const AT_FDCWD: libc::c_int = -100;

/// Raw fanotify event metadata structure matching the kernel ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

/// Response structure for fanotify permission events.
#[repr(C)]
struct FanotifyResponse {
    fd: i32,
    response: u32,
}

// ── syscall wrappers ────────────────────────────────────────────────────────

fn fanotify_init(flags: libc::c_uint, event_f_flags: libc::c_uint) -> Result<i32> {
    // SAFETY: fanotify_init takes two scalar arguments; no pointers are involved.
    let fd = unsafe { libc::syscall(libc::SYS_fanotify_init, flags, event_f_flags) };
    if fd < 0 {
        Err(std::io::Error::last_os_error()).context("fanotify_init failed")
    } else {
        #[allow(clippy::cast_possible_truncation)] // fanotify fd fits in i32
        Ok(fd as i32)
    }
}

fn fanotify_mark(
    fanotify_fd: i32,
    flags: libc::c_uint,
    mask: u64,
    dirfd: libc::c_int,
    path: Option<&CString>,
) -> Result<()> {
    let pathname = path.map_or(std::ptr::null(), |p| p.as_ptr());

    // SAFETY: All pointer arguments are either valid CString pointers or null.
    // fanotify_fd is a valid fd from fanotify_init. Scalar args are passed by value.
    let ret = unsafe { libc::syscall(libc::SYS_fanotify_mark, fanotify_fd, flags, mask, dirfd, pathname) };
    if ret < 0 {
        Err(std::io::Error::last_os_error()).context("fanotify_mark failed")
    } else {
        Ok(())
    }
}

/// Read the path for a file descriptor via /proc/self/fd/<fd>.
fn fd_to_path(fd: i32) -> Option<PathBuf> {
    let link = format!("/proc/self/fd/{fd}");
    std::fs::read_link(&link).ok()
}

/// Send a permission response (allow/deny) for a fanotify event.
///
/// Uses `poll` with a 5-second timeout to avoid blocking indefinitely
/// when the kernel fanotify queue is under pressure.  On timeout the
/// response defaults to ALLOW so legitimate processes are not blocked.
fn write_response(fanotify_fd: i32, event_fd: i32, allow: bool) {
    let resp = FanotifyResponse {
        fd: event_fd,
        response: if allow { FAN_ALLOW } else { FAN_DENY },
    };

    // Poll for writability with a 5-second timeout.
    let mut pfd = libc::pollfd {
        fd: fanotify_fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: pfd is a stack-allocated pollfd with a valid fd from fanotify_init.
    let poll_ret = unsafe { libc::poll(&raw mut pfd, 1, 5_000) };
    if poll_ret < 0 {
        let err = std::io::Error::last_os_error();
        tracing::error!(event_fd, ?err, "fanotify write_response: poll failed");
        // Attempt ALLOW as last resort to avoid blocking the process forever.
        let fallback = FanotifyResponse {
            fd: event_fd,
            response: FAN_ALLOW,
        };
        // SAFETY: valid fanotify fd and valid repr(C) struct.
        unsafe {
            libc::write(
                fanotify_fd,
                (&raw const fallback).cast::<libc::c_void>(),
                std::mem::size_of::<FanotifyResponse>(),
            );
        }
        return;
    }
    if poll_ret == 0 {
        tracing::warn!(
            event_fd,
            "fanotify write_response: poll timed out (5s), defaulting to ALLOW"
        );
        let fallback = FanotifyResponse {
            fd: event_fd,
            response: FAN_ALLOW,
        };
        // SAFETY: valid fanotify fd and valid repr(C) struct.
        unsafe {
            libc::write(
                fanotify_fd,
                (&raw const fallback).cast::<libc::c_void>(),
                std::mem::size_of::<FanotifyResponse>(),
            );
        }
        return;
    }

    // SAFETY: fanotify_fd is a valid fanotify fd. resp is a valid repr(C) struct
    // and the pointer and size are correct for the duration of the write call.
    let written = unsafe {
        libc::write(
            fanotify_fd,
            (&raw const resp).cast::<libc::c_void>(),
            std::mem::size_of::<FanotifyResponse>(),
        )
    };
    if written < 0 {
        let err = std::io::Error::last_os_error();
        tracing::error!(event_fd, ?err, "fanotify write_response: write failed");
    }
}

/// Process a single fanotify event — extracted to reduce nesting depth.
fn process_fanotify_event(
    fanotify_fd: i32,
    meta: &FanotifyEventMetadata,
    pid: u32,
    mask: u64,
    is_exec_perm: bool,
    is_perm: bool,
    hash_checker: Option<&HashChecker>,
    tx: &mpsc::Sender<FileEvent>,
) {
    let Some(path) = fd_to_path(meta.fd) else {
        // No path resolved — still need to respond to perm events.
        if is_perm {
            write_response(fanotify_fd, meta.fd, true);
        }
        return;
    };

    if is_exec_perm {
        // FAN_OPEN_EXEC_PERM: pre-execution blocking path.
        // Perform synchronous hash check if a checker is available.
        let allow = hash_checker.is_none_or(|checker| {
            let malicious = hash_file_from_fd(meta.fd).is_some_and(|digest| checker(&digest));
            if malicious {
                tracing::warn!("BLOCKED execution of malicious file: {} (pid={})", path.display(), pid,);
            }
            !malicious
        });

        write_response(fanotify_fd, meta.fd, allow);

        let event = FileEvent::Execute { path, pid };
        let _ = tx.try_send(event);
    } else {
        // Non-exec permission events: always allow (for now).
        if is_perm {
            write_response(fanotify_fd, meta.fd, true);
        }

        let event = if (mask & FAN_CLOSE_WRITE) != 0 {
            FileEvent::CloseWrite { path }
        } else {
            // FAN_OPEN_PERM, FAN_OPEN, or any other event — emit as Open.
            FileEvent::Open { path, pid }
        };

        let _ = tx.try_send(event);
    }
}

// ── FanotifyMonitor ─────────────────────────────────────────────────────────

/// Callback that receives a SHA-256 hash and returns `true` when the file is
/// known-malicious.
///
/// Used by the fanotify event loop to perform a synchronous
/// fast-path check before allowing an execution to proceed.
pub type HashChecker = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// Linux-specific file system monitor using the fanotify API.
///
/// Requires `CAP_SYS_ADMIN` capability or root privileges. Supports blocking
/// (permission-based) events, allowing the monitor to deny file access before
/// it completes.
pub struct FanotifyMonitor {
    fanotify_fd: Option<i32>,
    tx: mpsc::Sender<FileEvent>,
    rx: mpsc::Receiver<FileEvent>,
    running: Arc<AtomicBool>,
    event_loop_handle: Option<std::thread::JoinHandle<()>>,
    hash_checker: Option<HashChecker>,
}

impl FanotifyMonitor {
    /// Create a new `FanotifyMonitor`.
    pub fn new(channel_capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(channel_capacity);
        Self {
            fanotify_fd: None,
            tx,
            rx,
            running: Arc::new(AtomicBool::new(false)),
            event_loop_handle: None,
            hash_checker: None,
        }
    }

    /// Create a new `FanotifyMonitor` with a synchronous hash-check callback.
    ///
    /// The `checker` receives a SHA-256 digest (32 bytes) and must return
    /// `true` when the hash matches a known-malicious file.  It is invoked
    /// inside the fanotify event loop for every `FAN_OPEN_EXEC_PERM` event
    /// **before** the kernel is told to allow or deny the execution.
    pub fn with_hash_checker(channel_capacity: usize, checker: HashChecker) -> Self {
        let (tx, rx) = mpsc::channel(channel_capacity);
        Self {
            fanotify_fd: None,
            tx,
            rx,
            running: Arc::new(AtomicBool::new(false)),
            event_loop_handle: None,
            hash_checker: Some(checker),
        }
    }

    /// Return a mutable reference to the event receiver for draining events.
    pub const fn event_receiver_mut(&mut self) -> &mut mpsc::Receiver<FileEvent> {
        &mut self.rx
    }

    /// Start the event processing loop in a background thread.
    fn spawn_event_loop(
        fanotify_fd: i32,
        tx: mpsc::Sender<FileEvent>,
        running: Arc<AtomicBool>,
        hash_checker: Option<HashChecker>,
    ) -> Result<std::thread::JoinHandle<()>> {
        std::thread::Builder::new()
            .name("fanotify-loop".into())
            .spawn(move || {
                let mut buf = vec![0u8; 4096 * FAN_EVENT_METADATA_LEN];

                while running.load(Ordering::Relaxed) {
                    // SAFETY: fanotify_fd is a valid fd. buf is a valid mutable buffer
                    // and buf.len() is its exact capacity.
                    let bytes_read =
                        unsafe { libc::read(fanotify_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };

                    if bytes_read <= 0 {
                        if !running.load(Ordering::Relaxed) {
                            break;
                        }
                        // EAGAIN from non-blocking read — sleep briefly.
                        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                        if errno == libc::EAGAIN || errno == libc::EINTR {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        }
                        tracing::error!("fanotify read error: {}", std::io::Error::last_os_error());
                        break;
                    }

                    let mut offset = 0usize;
                    let total = bytes_read.cast_unsigned();

                    while offset + FAN_EVENT_METADATA_LEN <= total {
                        // SAFETY: We verified offset + FAN_EVENT_METADATA_LEN <= total,
                        // so the pointer is within the buf bounds. We use
                        // read_unaligned because the buffer is a byte array whose
                        // natural alignment is 1, while FanotifyEventMetadata
                        // contains u64 fields requiring 8-byte alignment. The
                        // kernel typically returns aligned event_len values, but
                        // we do not rely on that assumption.
                        let meta = unsafe {
                            std::ptr::read_unaligned(buf.as_ptr().add(offset).cast::<FanotifyEventMetadata>())
                        };

                        if meta.vers != FANOTIFY_METADATA_VERSION {
                            tracing::warn!("unexpected fanotify metadata version: {}", meta.vers);
                            break;
                        }

                        let event_len = meta.event_len as usize;
                        if event_len < FAN_EVENT_METADATA_LEN || offset + event_len > total {
                            break;
                        }

                        // Process the event.
                        if meta.fd >= 0 {
                            let pid = meta.pid.cast_unsigned();
                            let mask = meta.mask;
                            let is_exec_perm = (mask & FAN_OPEN_EXEC_PERM) != 0;
                            let is_perm = (mask & FAN_OPEN_PERM) != 0 || (mask & FAN_ACCESS_PERM) != 0 || is_exec_perm;

                            process_fanotify_event(
                                fanotify_fd,
                                &meta,
                                pid,
                                mask,
                                is_exec_perm,
                                is_perm,
                                hash_checker.as_ref(),
                                &tx,
                            );

                            // SAFETY: meta.fd is a valid fd provided by the kernel
                            // via fanotify for this event. We close it exactly once.
                            unsafe {
                                libc::close(meta.fd);
                            }
                        }

                        offset += event_len;
                    }
                }

                tracing::debug!("fanotify event loop exiting");
            })
            .context("failed to spawn fanotify event loop thread")
    }
}

#[async_trait]
impl FileSystemMonitor for FanotifyMonitor {
    async fn start(&mut self, paths: &[PathBuf]) -> Result<()> {
        if self.running.load(Ordering::Acquire) {
            anyhow::bail!("fanotify monitor is already running");
        }

        // Initialize fanotify with content class (for permission events) and non-blocking.
        let flags = FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK;
        let event_f_flags = (libc::O_RDONLY | libc::O_LARGEFILE) as libc::c_uint;
        let fd =
            fanotify_init(flags, event_f_flags).context("failed to initialize fanotify (requires CAP_SYS_ADMIN)")?;

        // Mark each path for monitoring.
        let mark_mask = FAN_OPEN_PERM | FAN_CLOSE_WRITE | FAN_OPEN_EXEC_PERM;

        for path in paths {
            let c_path = CString::new(path.as_os_str().as_bytes()).context("invalid path for fanotify")?;
            fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mark_mask, AT_FDCWD, Some(&c_path))
                .with_context(|| format!("failed to mark path: {}", path.display()))?;
        }

        self.fanotify_fd = Some(fd);
        self.running.store(true, Ordering::Release);

        let handle = Self::spawn_event_loop(fd, self.tx.clone(), self.running.clone(), self.hash_checker.clone())?;
        self.event_loop_handle = Some(handle);

        tracing::info!("fanotify monitor started, watching {} path(s)", paths.len());

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::Release);

        if let Some(fd) = self.fanotify_fd.take() {
            // SAFETY: fd is a valid fanotify fd obtained from fanotify_init.
            // We take() it to ensure it is closed exactly once.
            unsafe {
                libc::close(fd);
            }
        }

        if let Some(handle) = self.event_loop_handle.take() {
            let _ = handle.join();
        }

        tracing::info!("fanotify monitor stopped");
        Ok(())
    }

    fn event_receiver(&self) -> &mpsc::Receiver<FileEvent> {
        &self.rx
    }

    fn supports_blocking(&self) -> bool {
        true
    }

    fn respond(&self, event_fd: i32, allow: bool) {
        if let Some(fd) = self.fanotify_fd {
            write_response(fd, event_fd, allow);
        }
    }
}

impl Default for FanotifyMonitor {
    fn default() -> Self {
        Self::new(4096)
    }
}

/// Compute the SHA-256 hash of a file given its fd (via `/proc/self/fd/{fd}`).
///
/// Returns `None` if the file cannot be read, exceeds 128 MiB, or takes
/// longer than 5 seconds (e.g. file on a stalled network mount).
fn hash_file_from_fd(fd: i32) -> Option<[u8; 32]> {
    const MAX_HASH_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB
    const HASH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    let proc_path = format!("/proc/self/fd/{fd}");
    let mut file = std::fs::File::open(&proc_path).ok()?;
    let mut hasher = Sha256::new();
    let mut read_buf = [0u8; 8192];
    let deadline = std::time::Instant::now() + HASH_TIMEOUT;
    let mut total_read: u64 = 0;

    loop {
        if std::time::Instant::now() > deadline {
            tracing::warn!(fd, "hash_file_from_fd: timed out after 5s");
            return None;
        }
        if total_read > MAX_HASH_BYTES {
            tracing::warn!(fd, total_read, "hash_file_from_fd: exceeded 128 MiB limit");
            return None;
        }
        let n = file.read(&mut read_buf).ok()?;
        if n == 0 {
            break;
        }
        total_read += n as u64;
        // n is bounded by read_buf.len() (8192) from the read() call above.
        if let Some(slice) = read_buf.get(..n) {
            hasher.update(slice);
        }
    }
    let result = hasher.finalize();
    Some(result.into())
}

impl Drop for FanotifyMonitor {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(fd) = self.fanotify_fd.take() {
            // SAFETY: fd is a valid fanotify fd. take() ensures single close.
            unsafe {
                libc::close(fd);
            }
        }
    }
}
