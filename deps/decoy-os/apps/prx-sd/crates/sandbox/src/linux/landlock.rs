//! Landlock LSM sandboxing for restricting file system access.
//!
//! Landlock is a Linux Security Module (available since kernel 5.13) that
//! allows unprivileged processes to restrict their own file system access
//! without requiring root or any capabilities.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

// ── Landlock constants ──────────────────────────────────────────────────────

/// Landlock ABI version 1 (kernel 5.13+).
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

// Access rights for files.
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

/// All file access rights combined.
const LANDLOCK_ACCESS_FS_ALL: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;

/// Read-only access rights.
const LANDLOCK_ACCESS_FS_READ: u64 = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

/// Write access rights (includes read).
const LANDLOCK_ACCESS_FS_WRITE: u64 = LANDLOCK_ACCESS_FS_READ
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

// ── Landlock syscall structures ─────────────────────────────────────────────

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

// ── Syscall wrappers ────────────────────────────────────────────────────────

fn sys_landlock_create_ruleset(attr: *const LandlockRulesetAttr, size: usize, flags: u32) -> Result<i32> {
    // SAFETY: Valid pointer to a repr(C) LandlockRulesetAttr struct and correct size.
    // The syscall reads exactly `size` bytes from the pointer.
    let ret = unsafe { libc::syscall(444, attr, size, flags) };
    if ret < 0 {
        Err(std::io::Error::last_os_error()).context("landlock_create_ruleset failed")
    } else {
        // Landlock fd values are small non-negative integers; truncation is safe.
        #[allow(clippy::cast_possible_truncation)]
        Ok(ret as i32)
    }
}

fn sys_landlock_add_rule(
    ruleset_fd: i32,
    rule_type: u32,
    rule_attr: *const LandlockPathBeneathAttr,
    flags: u32,
) -> Result<()> {
    // SAFETY: ruleset_fd is a valid landlock fd, rule_attr points to a valid repr(C) struct.
    let ret = unsafe { libc::syscall(445, ruleset_fd, rule_type, rule_attr, flags) };
    if ret < 0 {
        Err(std::io::Error::last_os_error()).context("landlock_add_rule failed")
    } else {
        Ok(())
    }
}

fn sys_landlock_restrict_self(ruleset_fd: i32, flags: u32) -> Result<()> {
    // SAFETY: ruleset_fd is a valid landlock ruleset fd returned by create_ruleset.
    let ret = unsafe { libc::syscall(446, ruleset_fd, flags) };
    if ret < 0 {
        Err(std::io::Error::last_os_error()).context("landlock_restrict_self failed")
    } else {
        Ok(())
    }
}

/// Check whether the kernel supports Landlock.
pub fn is_landlock_supported() -> bool {
    // Pass flags=LANDLOCK_CREATE_RULESET_VERSION with null attr to query ABI version.
    // SAFETY: Passing null attr with size 0 and VERSION flag is the documented way to
    // query the supported ABI version. No memory is read through the null pointer.
    let ret = unsafe {
        libc::syscall(
            444,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    ret >= 1
}

// ── LandlockSandbox ────────────────────────────────────────────────────────

/// File system sandbox using the Linux Landlock LSM.
///
/// Add read/write rules for specific paths, then call [`apply`] to
/// enforce the restrictions on the current process. Once applied,
/// restrictions cannot be weakened.
pub struct LandlockSandbox {
    /// Paths allowed for read-only access.
    pub allowed_read_paths: Vec<PathBuf>,
    /// Paths allowed for read-write access.
    pub allowed_write_paths: Vec<PathBuf>,
}

impl LandlockSandbox {
    /// Create a new Landlock sandbox with no rules.
    ///
    /// By default all file system access will be denied once applied.
    pub const fn new() -> Self {
        Self {
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
        }
    }

    /// Allow read-only access to the given path and everything beneath it.
    pub fn allow_read(&mut self, path: &Path) {
        self.allowed_read_paths.push(path.to_path_buf());
    }

    /// Allow read-write access to the given path and everything beneath it.
    pub fn allow_write(&mut self, path: &Path) {
        self.allowed_write_paths.push(path.to_path_buf());
    }

    /// Add a Landlock rule for a single path with the given access rights.
    fn add_rule(ruleset_fd: i32, path: &Path, access: u64) -> Result<()> {
        let c_path =
            CString::new(path.as_os_str().as_bytes()).with_context(|| format!("invalid path: {}", path.display()))?;

        // SAFETY: c_path is a valid null-terminated CString. O_PATH | O_CLOEXEC are safe flags.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(err).with_context(|| format!("failed to open path: {}", path.display()));
        }

        let path_beneath = LandlockPathBeneathAttr {
            allowed_access: access,
            parent_fd: fd,
        };

        let result = sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &raw const path_beneath, 0);

        // SAFETY: fd is a valid open file descriptor returned by open() above.
        unsafe { libc::close(fd) };

        result.with_context(|| format!("failed to add landlock rule for: {}", path.display()))
    }

    /// Apply the Landlock rules to the current process.
    ///
    /// After this call, any file system access not covered by the rules
    /// will be denied. This is irreversible for the current process.
    pub fn apply(&self) -> Result<()> {
        if !is_landlock_supported() {
            anyhow::bail!("landlock is not supported on this kernel");
        }

        // Create the ruleset.
        let attr = LandlockRulesetAttr {
            handled_access_fs: LANDLOCK_ACCESS_FS_ALL,
        };
        let ruleset_fd = sys_landlock_create_ruleset(&raw const attr, std::mem::size_of::<LandlockRulesetAttr>(), 0)
            .context("failed to create landlock ruleset")?;

        // Add read-only path rules.
        for path in &self.allowed_read_paths {
            if let Err(e) = Self::add_rule(ruleset_fd, path, LANDLOCK_ACCESS_FS_READ) {
                // SAFETY: ruleset_fd is a valid fd from sys_landlock_create_ruleset.
                unsafe { libc::close(ruleset_fd) };
                return Err(e);
            }
        }

        // Add read-write path rules.
        for path in &self.allowed_write_paths {
            if let Err(e) = Self::add_rule(ruleset_fd, path, LANDLOCK_ACCESS_FS_WRITE) {
                // SAFETY: ruleset_fd is a valid fd from sys_landlock_create_ruleset.
                unsafe { libc::close(ruleset_fd) };
                return Err(e);
            }
        }

        // Set NO_NEW_PRIVS (required for landlock_restrict_self).
        // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is a safe operation that only restricts
        // the calling thread's ability to gain new privileges.
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            // SAFETY: ruleset_fd is a valid fd from sys_landlock_create_ruleset.
            unsafe { libc::close(ruleset_fd) };
            return Err(std::io::Error::last_os_error()).context("prctl(PR_SET_NO_NEW_PRIVS) failed");
        }

        // Enforce the ruleset.
        let result = sys_landlock_restrict_self(ruleset_fd, 0);
        // SAFETY: ruleset_fd is a valid fd from sys_landlock_create_ruleset.
        unsafe { libc::close(ruleset_fd) };
        result.context("landlock_restrict_self failed")?;

        tracing::debug!(
            read_paths = self.allowed_read_paths.len(),
            write_paths = self.allowed_write_paths.len(),
            "landlock sandbox applied"
        );

        Ok(())
    }
}

impl Default for LandlockSandbox {
    fn default() -> Self {
        Self::new()
    }
}
