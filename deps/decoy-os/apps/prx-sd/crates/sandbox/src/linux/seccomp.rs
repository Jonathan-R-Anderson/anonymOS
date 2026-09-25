//! Seccomp BPF (Berkley Packet Filter) sandboxing for restricting system calls.
//!
//! Provides a safe wrapper around the Linux seccomp-bpf mechanism to allow
//! only a whitelist of system calls for sandboxed processes.

use std::collections::BTreeSet;

use anyhow::{Context, Result};

// ── seccomp constants ───────────────────────────────────────────────────────

/// seccomp operation: set mode to filter.
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;

/// seccomp return value: allow the syscall.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// seccomp return value: kill the process.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// BPF instruction size.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// Offset of `nr` (syscall number) in `struct seccomp_data`.
const SECCOMP_DATA_NR_OFFSET: u32 = 0;

/// Offset of `arch` in `struct seccomp_data`.
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

/// Expected `seccomp_data.arch` value for the current architecture.
/// Rejecting unexpected architectures prevents x32 ABI bypass on `x86_64`
/// (where x32 syscall numbers are OR'd with `0x4000_0000`).
#[cfg(target_arch = "x86_64")]
const EXPECTED_AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64

#[cfg(target_arch = "aarch64")]
const EXPECTED_AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

/// BPF instruction.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilterInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilterInsn,
}

// ── Default allowed syscalls ────────────────────────────────────────────────

/// System call numbers — architecture-specific.
///
/// `x86_64` and aarch64 use completely different numbering schemes.
/// Adding a new architecture requires a new `#[cfg]` block here.
mod syscall_nr {
    #[cfg(target_arch = "x86_64")]
    pub const READ: i64 = 0;
    #[cfg(target_arch = "x86_64")]
    pub const WRITE: i64 = 1;
    #[cfg(target_arch = "x86_64")]
    pub const OPEN: i64 = 2;
    #[cfg(target_arch = "x86_64")]
    pub const CLOSE: i64 = 3;
    #[cfg(target_arch = "x86_64")]
    pub const STAT: i64 = 4;
    #[cfg(target_arch = "x86_64")]
    pub const FSTAT: i64 = 5;
    #[cfg(target_arch = "x86_64")]
    pub const MMAP: i64 = 9;
    #[cfg(target_arch = "x86_64")]
    pub const MPROTECT: i64 = 10;
    #[cfg(target_arch = "x86_64")]
    pub const MUNMAP: i64 = 11;
    #[cfg(target_arch = "x86_64")]
    pub const BRK: i64 = 12;
    #[cfg(target_arch = "x86_64")]
    pub const EXIT: i64 = 60;
    #[cfg(target_arch = "x86_64")]
    pub const EXIT_GROUP: i64 = 231;

    #[cfg(target_arch = "aarch64")]
    pub const READ: i64 = 63;
    #[cfg(target_arch = "aarch64")]
    pub const WRITE: i64 = 64;
    #[cfg(target_arch = "aarch64")]
    pub const OPEN: i64 = -1; // aarch64 uses openat(56) only, no legacy open
    #[cfg(target_arch = "aarch64")]
    pub const CLOSE: i64 = 57;
    #[cfg(target_arch = "aarch64")]
    pub const STAT: i64 = -1; // aarch64 uses fstatat(79) only
    #[cfg(target_arch = "aarch64")]
    pub const FSTAT: i64 = 80;
    #[cfg(target_arch = "aarch64")]
    pub const MMAP: i64 = 222;
    #[cfg(target_arch = "aarch64")]
    pub const MPROTECT: i64 = 226;
    #[cfg(target_arch = "aarch64")]
    pub const MUNMAP: i64 = 215;
    #[cfg(target_arch = "aarch64")]
    pub const BRK: i64 = 214;
    #[cfg(target_arch = "aarch64")]
    pub const EXIT: i64 = 93;
    #[cfg(target_arch = "aarch64")]
    pub const EXIT_GROUP: i64 = 94;
}

/// Default set of syscalls allowed in the sandbox.
fn default_allowed_syscalls() -> BTreeSet<i64> {
    let mut set = BTreeSet::new();
    set.insert(syscall_nr::READ);
    set.insert(syscall_nr::WRITE);
    // aarch64 has no legacy open/stat — only openat/fstatat. Skip -1 entries.
    if syscall_nr::OPEN >= 0 {
        set.insert(syscall_nr::OPEN);
    }
    set.insert(syscall_nr::CLOSE);
    if syscall_nr::STAT >= 0 {
        set.insert(syscall_nr::STAT);
    }
    set.insert(syscall_nr::FSTAT);
    set.insert(syscall_nr::MMAP);
    set.insert(syscall_nr::MPROTECT);
    set.insert(syscall_nr::MUNMAP);
    set.insert(syscall_nr::BRK);
    set.insert(syscall_nr::EXIT);
    set.insert(syscall_nr::EXIT_GROUP);

    // aarch64 needs openat and fstatat since legacy open/stat don't exist.
    #[cfg(target_arch = "aarch64")]
    {
        set.insert(56); // openat
        set.insert(79); // fstatat / newfstatat
    }

    set
}

// ── SeccompFilter ───────────────────────────────────────────────────────────

/// A seccomp BPF filter that restricts the system calls a process can make.
///
/// By default, only a minimal set of syscalls is allowed (read, write, open,
/// close, stat, fstat, mmap, mprotect, munmap, brk, exit, `exit_group`).
/// Additional syscalls can be added with [`allow_syscall`].
pub struct SeccompFilter {
    allowed: BTreeSet<i64>,
}

impl SeccompFilter {
    /// Create a new `SeccompFilter` with the default allowed syscalls.
    pub fn new() -> Self {
        Self {
            allowed: default_allowed_syscalls(),
        }
    }

    /// Add a syscall number to the allowed set.
    pub fn allow_syscall(&mut self, nr: i64) {
        self.allowed.insert(nr);
    }

    /// Build the BPF filter program from the allowed syscall set.
    ///
    /// The program first validates `seccomp_data.arch` to reject unexpected
    /// architectures (e.g. x32 on `x86_64` which could bypass the filter),
    /// then checks the syscall number against the allowed set.
    fn build_bpf_program(&self) -> Vec<SockFilterInsn> {
        let mut insns = Vec::new();
        let num_allowed = self.allowed.len();

        // ── Architecture validation (x32 bypass prevention) ──────────

        // Load architecture: LD [seccomp_data.arch]
        insns.push(SockFilterInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_ARCH_OFFSET,
        });

        // JEQ expected_arch: if match, skip KILL (jt=1); else fall through to KILL (jf=0).
        insns.push(SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: EXPECTED_AUDIT_ARCH,
        });

        // KILL: wrong architecture (x32 ABI, i386 compat, etc.)
        insns.push(SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        });

        // ── Syscall number validation ────────────────────────────────

        // Load the syscall number: LD [seccomp_data.nr]
        insns.push(SockFilterInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        });

        // For each allowed syscall: JEQ nr → ALLOW (skip remaining checks).
        // If JEQ matches (jt), jump forward to the ALLOW instruction.
        // If JEQ fails (jf), fall through to the next check.
        for (i, &nr) in self.allowed.iter().enumerate() {
            let remaining = num_allowed - i - 1;
            // jt = jump over remaining JEQs + KILL -> land on ALLOW
            // jf = 0 (fall through to next JEQ)
            // BPF jump offsets are u8 (max 255 allowed syscalls), syscall numbers fit u32.
            #[allow(clippy::cast_possible_truncation)]
            let jt = (remaining + 1) as u8;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let k = nr as u32;
            insns.push(SockFilterInsn {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt,
                jf: 0,
                k,
            });
        }

        // Default action: KILL
        insns.push(SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        });

        // ALLOW action
        insns.push(SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });

        insns
    }

    /// Apply the seccomp filter to the current process.
    ///
    /// After calling this, any syscall not in the allowed set will
    /// terminate the process. This is irreversible.
    ///
    /// # Safety
    ///
    /// This must be called in the child process before executing
    /// untrusted code. The filter cannot be removed once applied.
    pub fn apply(&self) -> Result<()> {
        let insns = self.build_bpf_program();

        // BPF programs are limited to 4096 instructions; u16 is sufficient.
        #[allow(clippy::cast_possible_truncation)]
        let prog = SockFprog {
            len: insns.len() as u16,
            filter: insns.as_ptr(),
        };

        // SAFETY: prctl with PR_SET_NO_NEW_PRIVS only restricts the calling thread's
        // ability to gain new privileges. No pointers are dereferenced.
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error()).context("prctl(PR_SET_NO_NEW_PRIVS) failed");
        }

        // SAFETY: prog points to a valid SockFprog with a valid filter array.
        // insns is alive for the duration of the syscall. The BPF program is well-formed.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0u64, // flags
                &raw const prog,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error()).context("seccomp(SET_MODE_FILTER) failed");
        }

        tracing::debug!(allowed_count = self.allowed.len(), "seccomp filter applied");

        Ok(())
    }
}

impl Default for SeccompFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_filter_new_has_default_allowed_syscalls() {
        let filter = SeccompFilter::new();
        // Default set includes: read, write, open (if >= 0), close, stat (if >= 0),
        // fstat, mmap, mprotect, munmap, brk, exit, exit_group
        // On x86_64: all 12 are valid (open=2, stat=4)
        // On aarch64: open=-1, stat=-1 are skipped, but openat(56) and fstatat(79) added => 12
        assert!(
            filter.allowed.len() >= 10,
            "expected at least 10 default syscalls, got {}",
            filter.allowed.len()
        );

        // These should always be present regardless of architecture
        assert!(filter.allowed.contains(&syscall_nr::READ));
        assert!(filter.allowed.contains(&syscall_nr::WRITE));
        assert!(filter.allowed.contains(&syscall_nr::CLOSE));
        assert!(filter.allowed.contains(&syscall_nr::FSTAT));
        assert!(filter.allowed.contains(&syscall_nr::MMAP));
        assert!(filter.allowed.contains(&syscall_nr::MPROTECT));
        assert!(filter.allowed.contains(&syscall_nr::MUNMAP));
        assert!(filter.allowed.contains(&syscall_nr::BRK));
        assert!(filter.allowed.contains(&syscall_nr::EXIT));
        assert!(filter.allowed.contains(&syscall_nr::EXIT_GROUP));
    }

    #[test]
    fn test_allow_syscall_adds_to_set() {
        let mut filter = SeccompFilter::new();
        let initial_count = filter.allowed.len();

        // Add a syscall not in the default set (e.g., getpid = 39 on x86_64)
        filter.allow_syscall(9999);
        assert_eq!(filter.allowed.len(), initial_count + 1);
        assert!(filter.allowed.contains(&9999));
    }

    #[test]
    fn test_allow_syscall_duplicate_is_noop() {
        let mut filter = SeccompFilter::new();
        let initial_count = filter.allowed.len();

        // Adding an already-present syscall should not change the count
        filter.allow_syscall(syscall_nr::READ);
        assert_eq!(filter.allowed.len(), initial_count);
    }

    #[test]
    fn test_build_bpf_program_instruction_count() {
        let filter = SeccompFilter::new();
        let program = filter.build_bpf_program();

        // Expected: 3 (arch check: LD arch + JEQ + KILL)
        //         + 1 (load nr) + N (one JEQ per allowed syscall) + 1 (KILL) + 1 (ALLOW)
        let expected_len = 3 + 1 + filter.allowed.len() + 2;
        assert_eq!(
            program.len(),
            expected_len,
            "BPF program should have {} instructions, got {}",
            expected_len,
            program.len()
        );
    }

    #[test]
    fn test_build_bpf_program_starts_with_arch_check() {
        let filter = SeccompFilter::new();
        let program = filter.build_bpf_program();

        // First instruction: load seccomp_data.arch
        assert_eq!(program[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(program[0].k, SECCOMP_DATA_ARCH_OFFSET);

        // Second instruction: JEQ expected architecture
        assert_eq!(program[1].code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(program[1].k, EXPECTED_AUDIT_ARCH);
        assert_eq!(program[1].jt, 1); // skip KILL
        assert_eq!(program[1].jf, 0); // fall through to KILL

        // Third instruction: KILL on wrong architecture
        assert_eq!(program[2].code, BPF_RET | BPF_K);
        assert_eq!(program[2].k, SECCOMP_RET_KILL_PROCESS);

        // Fourth instruction: load seccomp_data.nr
        assert_eq!(program[3].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(program[3].k, SECCOMP_DATA_NR_OFFSET);
    }

    #[test]
    fn test_build_bpf_program_ends_with_kill_and_allow() {
        let filter = SeccompFilter::new();
        let program = filter.build_bpf_program();
        let len = program.len();

        // Second-to-last: KILL
        assert_eq!(program[len - 2].code, BPF_RET | BPF_K);
        assert_eq!(program[len - 2].k, SECCOMP_RET_KILL_PROCESS);

        // Last: ALLOW
        assert_eq!(program[len - 1].code, BPF_RET | BPF_K);
        assert_eq!(program[len - 1].k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_build_bpf_program_with_extra_syscall() {
        let mut filter = SeccompFilter::new();
        let initial_program = filter.build_bpf_program();
        let initial_len = initial_program.len();

        filter.allow_syscall(9999);
        let new_program = filter.build_bpf_program();

        // One more JEQ instruction
        assert_eq!(new_program.len(), initial_len + 1);
    }

    #[test]
    fn test_seccomp_filter_default() {
        let filter = SeccompFilter::default();
        assert!(filter.allowed.contains(&syscall_nr::READ));
    }
}
