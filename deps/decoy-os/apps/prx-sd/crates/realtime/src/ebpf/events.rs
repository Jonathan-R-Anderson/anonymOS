//! Normalized runtime event model and BPF event decoding.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Kind of runtime event observed by eBPF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RuntimeEventKind {
    Exec,
    FileOpen,
    Connect,
    Exit,
}

impl RuntimeEventKind {
    /// Convert from the BPF `prxsd_event_kind` integer tag.
    pub fn from_bpf(kind: u32) -> Option<Self> {
        match kind {
            1 => Some(Self::Exec),
            2 => Some(Self::FileOpen),
            3 => Some(Self::Connect),
            4 => Some(Self::Exit),
            _ => None,
        }
    }
}

impl fmt::Display for RuntimeEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exec => write!(f, "exec"),
            Self::FileOpen => write!(f, "file_open"),
            Self::Connect => write!(f, "connect"),
            Self::Exit => write!(f, "exit"),
        }
    }
}

/// A normalized runtime event produced by the eBPF subsystem.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuntimeEvent {
    /// Monotonic timestamp in nanoseconds.
    pub ts_ns: u64,
    /// Process ID (thread group leader).
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Event kind.
    pub kind: RuntimeEventKind,
    /// Cgroup ID.
    pub cgroup_id: u64,
    /// Mount namespace inode number.
    pub mnt_ns: u64,
    /// PID namespace inode number.
    pub pid_ns: u64,
    /// Process command name (max 16 bytes).
    pub comm: String,
    /// Event-specific payload.
    pub detail: EventDetail,
}

/// Event-specific payload data.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type")]
pub enum EventDetail {
    Exec { filename: String, argv: String },
    FileOpen { path: String, flags: i32 },
    Connect { af: u32, port: u16, addr: IpAddr },
    Exit { exit_code: i32 },
}

impl fmt::Display for RuntimeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] pid={} ppid={} uid={} comm={} ",
            self.kind, self.pid, self.ppid, self.uid, self.comm
        )?;
        match &self.detail {
            EventDetail::Exec { filename, argv } => {
                write!(f, "exec={filename}")?;
                if !argv.is_empty() {
                    write!(f, " argv={argv}")?;
                }
            }
            EventDetail::FileOpen { path, flags } => {
                write!(f, "path={path} flags=0x{flags:x}")?;
            }
            EventDetail::Connect { af, port, addr } => {
                write!(f, "af={af} addr={addr}:{port}")?;
            }
            EventDetail::Exit { exit_code } => {
                write!(f, "exit_code={exit_code}")?;
            }
        }
        Ok(())
    }
}

// ── BPF event decoding ──────────────────────────────────────────────────

/// Decode a raw byte slice from the BPF ring buffer into a `RuntimeEvent`.
///
/// Returns `None` if the data is too short or has an unknown event kind.
pub fn decode_event(data: &[u8]) -> Option<RuntimeEvent> {
    // The minimum size is the common header (prxsd_event).
    // Header layout (from prxsd.h):
    //   u64 ts_ns      (0)
    //   u32 pid         (8)
    //   u32 tid        (12)
    //   u32 ppid       (16)
    //   u32 uid        (20)
    //   u32 gid        (24)
    //   u32 kind       (28)
    //   u64 cgroup_id  (32)
    //   u64 mnt_ns     (40)
    //   u64 pid_ns     (48)
    //   char comm[16]  (56)
    //   total: 72 bytes
    const HDR_SIZE: usize = 72;

    if data.len() < HDR_SIZE {
        return None;
    }

    let ts_ns = u64::from_ne_bytes(read_array(data, 0));
    let pid = u32::from_ne_bytes(read_array(data, 8));
    let tid = u32::from_ne_bytes(read_array(data, 12));
    let ppid = u32::from_ne_bytes(read_array(data, 16));
    let uid = u32::from_ne_bytes(read_array(data, 20));
    let gid = u32::from_ne_bytes(read_array(data, 24));
    let kind_raw = u32::from_ne_bytes(read_array(data, 28));
    let cgroup_id = u64::from_ne_bytes(read_array(data, 32));
    let mnt_ns = u64::from_ne_bytes(read_array(data, 40));
    let pid_ns = u64::from_ne_bytes(read_array(data, 48));
    let comm = read_cstr(data, 56, 16);

    let kind = RuntimeEventKind::from_bpf(kind_raw)?;

    let detail = match kind {
        RuntimeEventKind::Exec => {
            // exec_event: hdr(72) + filename[256](72) + argv[128](328)
            let filename = read_cstr(data, HDR_SIZE, 256);
            let argv = read_cstr(data, HDR_SIZE + 256, 128);
            EventDetail::Exec { filename, argv }
        }
        RuntimeEventKind::FileOpen => {
            // file_open_event: hdr(72) + path[256](72) + flags(328)
            let path = read_cstr(data, HDR_SIZE, 256);
            let flags = if data.len() >= HDR_SIZE + 256 + 4 {
                i32::from_ne_bytes(read_array(data, HDR_SIZE + 256))
            } else {
                0
            };
            EventDetail::FileOpen { path, flags }
        }
        RuntimeEventKind::Connect => {
            // connect_event: hdr(72) + af(72) + port(76) + addr4[4](78) + addr6[16](82)
            let af = if data.len() >= HDR_SIZE + 4 {
                u32::from_ne_bytes(read_array(data, HDR_SIZE))
            } else {
                0
            };
            let port = if data.len() >= HDR_SIZE + 6 {
                u16::from_ne_bytes(read_array(data, HDR_SIZE + 4))
            } else {
                0
            };
            let addr = if af == 2 {
                // IPv4
                let mut octets = [0u8; 4];
                if data.len() >= HDR_SIZE + 6 + 4 {
                    octets.copy_from_slice(&data[HDR_SIZE + 6..HDR_SIZE + 10]);
                }
                IpAddr::V4(Ipv4Addr::from(octets))
            } else {
                // IPv6
                let mut octets = [0u8; 16];
                if data.len() >= HDR_SIZE + 10 + 16 {
                    octets.copy_from_slice(&data[HDR_SIZE + 10..HDR_SIZE + 26]);
                }
                IpAddr::V6(Ipv6Addr::from(octets))
            };
            EventDetail::Connect { af, port, addr }
        }
        RuntimeEventKind::Exit => {
            let exit_code = if data.len() >= HDR_SIZE + 4 {
                i32::from_ne_bytes(read_array(data, HDR_SIZE))
            } else {
                0
            };
            EventDetail::Exit { exit_code }
        }
    };

    Some(RuntimeEvent {
        ts_ns,
        pid,
        tid,
        ppid,
        uid,
        gid,
        kind,
        cgroup_id,
        mnt_ns,
        pid_ns,
        comm,
        detail,
    })
}

/// Read a fixed-size array from a byte slice at the given offset.
fn read_array<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    let mut arr = [0u8; N];
    let end = (offset + N).min(data.len());
    if offset < end {
        let len = end - offset;
        arr[..len].copy_from_slice(&data[offset..end]);
    }
    arr
}

/// Read a C string (null-terminated) from a byte slice.
fn read_cstr(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = (offset + max_len).min(data.len());
    if offset >= end {
        return String::new();
    }
    let slice = &data[offset..end];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..nul]).into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Build a 72-byte BPF event header matching the C `prxsd_event` layout.
    fn build_header(pid: u32, kind: u32, comm: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(72);
        buf.extend_from_slice(&100u64.to_ne_bytes()); // ts_ns
        buf.extend_from_slice(&pid.to_ne_bytes()); // pid
        buf.extend_from_slice(&pid.to_ne_bytes()); // tid
        buf.extend_from_slice(&1u32.to_ne_bytes()); // ppid
        buf.extend_from_slice(&1000u32.to_ne_bytes()); // uid
        buf.extend_from_slice(&1000u32.to_ne_bytes()); // gid
        buf.extend_from_slice(&kind.to_ne_bytes()); // kind
        buf.extend_from_slice(&42u64.to_ne_bytes()); // cgroup_id
        buf.extend_from_slice(&7u64.to_ne_bytes()); // mnt_ns
        buf.extend_from_slice(&8u64.to_ne_bytes()); // pid_ns
        // comm: 16 bytes, null-padded
        let mut comm_buf = [0u8; 16];
        let comm_bytes = comm.as_bytes();
        let len = comm_bytes.len().min(15);
        comm_buf[..len].copy_from_slice(&comm_bytes[..len]);
        buf.extend_from_slice(&comm_buf);
        assert_eq!(buf.len(), 72);
        buf
    }

    #[test]
    fn test_event_kind_from_bpf() {
        assert_eq!(RuntimeEventKind::from_bpf(1), Some(RuntimeEventKind::Exec));
        assert_eq!(RuntimeEventKind::from_bpf(2), Some(RuntimeEventKind::FileOpen));
        assert_eq!(RuntimeEventKind::from_bpf(3), Some(RuntimeEventKind::Connect));
        assert_eq!(RuntimeEventKind::from_bpf(4), Some(RuntimeEventKind::Exit));
        assert_eq!(RuntimeEventKind::from_bpf(0), None);
        assert_eq!(RuntimeEventKind::from_bpf(99), None);
    }

    #[test]
    fn test_event_kind_display() {
        assert_eq!(format!("{}", RuntimeEventKind::Exec), "exec");
        assert_eq!(format!("{}", RuntimeEventKind::FileOpen), "file_open");
        assert_eq!(format!("{}", RuntimeEventKind::Connect), "connect");
        assert_eq!(format!("{}", RuntimeEventKind::Exit), "exit");
    }

    #[test]
    fn test_read_cstr() {
        let data = b"hello\0world\0padding";
        assert_eq!(read_cstr(data, 0, 20), "hello");
        assert_eq!(read_cstr(data, 6, 10), "world");
    }

    #[test]
    fn test_read_cstr_no_nul() {
        // String fills the entire max_len without null terminator.
        let data = b"ABCDEFGH";
        assert_eq!(read_cstr(data, 0, 8), "ABCDEFGH");
    }

    #[test]
    fn test_read_cstr_empty_at_boundary() {
        let data = b"abc";
        // offset == data.len() → empty string
        assert_eq!(read_cstr(data, 3, 10), "");
        // offset > data.len() → empty string
        assert_eq!(read_cstr(data, 100, 10), "");
    }

    #[test]
    fn test_read_array_at_boundary() {
        let data = [1u8, 2, 3, 4];
        // Exact boundary read
        let arr: [u8; 4] = read_array(&data, 0);
        assert_eq!(arr, [1, 2, 3, 4]);
        // Partial read (offset makes it short)
        let arr: [u8; 4] = read_array(&data, 2);
        assert_eq!(arr, [3, 4, 0, 0]);
        // Beyond boundary
        let arr: [u8; 4] = read_array(&data, 10);
        assert_eq!(arr, [0, 0, 0, 0]);
    }

    #[test]
    fn test_decode_too_short() {
        assert!(decode_event(&[0u8; 10]).is_none());
        assert!(decode_event(&[0u8; 71]).is_none());
    }

    #[test]
    fn test_decode_unknown_kind() {
        let buf = build_header(1, 0, "test");
        assert!(decode_event(&buf).is_none());

        let buf = build_header(1, 99, "test");
        assert!(decode_event(&buf).is_none());
    }

    #[test]
    fn test_decode_exec_event() {
        let mut buf = build_header(42, 1, "myproc");
        // filename: 256 bytes
        let mut filename = [0u8; 256];
        let fname = b"/tmp/malware";
        filename[..fname.len()].copy_from_slice(fname);
        buf.extend_from_slice(&filename);
        // argv: 128 bytes
        let mut argv = [0u8; 128];
        let args = b"--flag";
        argv[..args.len()].copy_from_slice(args);
        buf.extend_from_slice(&argv);

        let event = decode_event(&buf).unwrap();
        assert_eq!(event.pid, 42);
        assert_eq!(event.ts_ns, 100);
        assert_eq!(event.ppid, 1);
        assert_eq!(event.uid, 1000);
        assert_eq!(event.kind, RuntimeEventKind::Exec);
        assert_eq!(event.comm, "myproc");
        assert_eq!(event.mnt_ns, 7);
        assert_eq!(event.pid_ns, 8);
        assert_eq!(event.cgroup_id, 42);
        match &event.detail {
            EventDetail::Exec { filename, argv } => {
                assert_eq!(filename, "/tmp/malware");
                assert_eq!(argv, "--flag");
            }
            _ => panic!("expected Exec detail"),
        }
    }

    #[test]
    fn test_decode_file_open_event() {
        let mut buf = build_header(10, 2, "cat");
        // path: 256 bytes
        let mut path = [0u8; 256];
        let p = b"/etc/passwd";
        path[..p.len()].copy_from_slice(p);
        buf.extend_from_slice(&path);
        // flags: 4 bytes (O_RDONLY = 0)
        buf.extend_from_slice(&0i32.to_ne_bytes());

        let event = decode_event(&buf).unwrap();
        assert_eq!(event.pid, 10);
        assert_eq!(event.kind, RuntimeEventKind::FileOpen);
        match &event.detail {
            EventDetail::FileOpen { path, flags } => {
                assert_eq!(path, "/etc/passwd");
                assert_eq!(*flags, 0);
            }
            _ => panic!("expected FileOpen detail"),
        }
    }

    #[test]
    fn test_decode_file_open_write_flags() {
        let mut buf = build_header(10, 2, "sh");
        let mut path = [0u8; 256];
        let p = b"/tmp/out";
        path[..p.len()].copy_from_slice(p);
        buf.extend_from_slice(&path);
        // flags: O_WRONLY | O_CREAT | O_TRUNC = 0x241
        buf.extend_from_slice(&0x241i32.to_ne_bytes());

        let event = decode_event(&buf).unwrap();
        match &event.detail {
            EventDetail::FileOpen { flags, .. } => {
                assert_eq!(*flags, 0x241);
            }
            _ => panic!("expected FileOpen detail"),
        }
    }

    #[test]
    fn test_decode_connect_event_ipv4() {
        let mut buf = build_header(50, 3, "curl");
        // af: 4 bytes (AF_INET = 2)
        buf.extend_from_slice(&2u32.to_ne_bytes());
        // port: 2 bytes
        buf.extend_from_slice(&443u16.to_ne_bytes());
        // addr4: 4 bytes (1.2.3.4)
        buf.extend_from_slice(&[1, 2, 3, 4]);
        // addr6: 16 bytes (unused for IPv4)
        buf.extend_from_slice(&[0u8; 16]);

        let event = decode_event(&buf).unwrap();
        assert_eq!(event.pid, 50);
        assert_eq!(event.kind, RuntimeEventKind::Connect);
        match &event.detail {
            EventDetail::Connect { af, port, addr } => {
                assert_eq!(*af, 2);
                assert_eq!(*port, 443);
                assert_eq!(*addr, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
            }
            _ => panic!("expected Connect detail"),
        }
    }

    #[test]
    fn test_decode_connect_event_ipv6() {
        let mut buf = build_header(51, 3, "wget");
        // af: 4 bytes (AF_INET6 = 10)
        buf.extend_from_slice(&10u32.to_ne_bytes());
        // port: 2 bytes
        buf.extend_from_slice(&80u16.to_ne_bytes());
        // addr4: 4 bytes (skipped for v6)
        buf.extend_from_slice(&[0u8; 4]);
        // addr6: 16 bytes (::1)
        let mut addr6 = [0u8; 16];
        addr6[15] = 1;
        buf.extend_from_slice(&addr6);

        let event = decode_event(&buf).unwrap();
        match &event.detail {
            EventDetail::Connect { af, port, addr } => {
                assert_eq!(*af, 10);
                assert_eq!(*port, 80);
                assert_eq!(*addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
            }
            _ => panic!("expected Connect detail"),
        }
    }

    #[test]
    fn test_decode_exit_event() {
        let mut buf = build_header(99, 4, "done");
        // exit_code: 4 bytes
        buf.extend_from_slice(&137i32.to_ne_bytes());

        let event = decode_event(&buf).unwrap();
        assert_eq!(event.pid, 99);
        assert_eq!(event.kind, RuntimeEventKind::Exit);
        match &event.detail {
            EventDetail::Exit { exit_code } => {
                assert_eq!(*exit_code, 137);
            }
            _ => panic!("expected Exit detail"),
        }
    }

    #[test]
    fn test_decode_exit_event_short_payload() {
        // Header only, no exit_code payload — should default to 0.
        let buf = build_header(99, 4, "sh");
        let event = decode_event(&buf).unwrap();
        match &event.detail {
            EventDetail::Exit { exit_code } => {
                assert_eq!(*exit_code, 0);
            }
            _ => panic!("expected Exit detail"),
        }
    }

    #[test]
    fn test_decode_exec_header_only() {
        // Just header, no exec payload — filename and argv should be empty.
        let buf = build_header(1, 1, "x");
        let event = decode_event(&buf).unwrap();
        match &event.detail {
            EventDetail::Exec { filename, argv } => {
                assert!(filename.is_empty());
                assert!(argv.is_empty());
            }
            _ => panic!("expected Exec detail"),
        }
    }

    #[test]
    fn test_event_display() {
        let event = RuntimeEvent {
            ts_ns: 1000,
            pid: 42,
            tid: 42,
            ppid: 1,
            uid: 0,
            gid: 0,
            kind: RuntimeEventKind::Exec,
            cgroup_id: 1,
            mnt_ns: 1,
            pid_ns: 1,
            comm: "test".to_string(),
            detail: EventDetail::Exec {
                filename: "/bin/ls".to_string(),
                argv: "-la".to_string(),
            },
        };
        let s = format!("{event}");
        assert!(s.contains("exec"));
        assert!(s.contains("pid=42"));
        assert!(s.contains("/bin/ls"));
        assert!(s.contains("argv=-la"));
    }

    #[test]
    fn test_event_display_connect() {
        let event = RuntimeEvent {
            ts_ns: 1000,
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 0,
            gid: 0,
            kind: RuntimeEventKind::Connect,
            cgroup_id: 1,
            mnt_ns: 1,
            pid_ns: 1,
            comm: "nc".to_string(),
            detail: EventDetail::Connect {
                af: 2,
                port: 8080,
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            },
        };
        let s = format!("{event}");
        assert!(s.contains("connect"));
        assert!(s.contains("10.0.0.1:8080"));
    }
}
