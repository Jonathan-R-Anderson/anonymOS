// hello-wl — R0 validation: a "hello, Wayland" client in Rust, built static-musl for AnonymOS.
//
// Proves the Rust->musl toolchain (the analogue of musl-clang for the C Wayland clients) produces
// a working OS binary that speaks the Wayland wire protocol over the live Linux ABI.  Pure std (no
// crates, no libwayland) so it is reproducible and statically linked: it opens the compositor's
// Unix socket directly and enumerates the global registry.  The GPU/Ratatui terminal is R1+.
use std::env;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

// poll(fd, POLLIN, timeout_ms) via a raw syscall (SYS_poll=7) — a blocking wait that yields to the
// cooperative scheduler so the compositor runs; returns >0 readable, 0 timeout, <0 error.
fn poll_in(fd: i32, timeout_ms: i32) -> i64 {
    #[repr(C)]
    struct Pollfd { fd: i32, events: i16, revents: i16 }
    let mut p = Pollfd { fd, events: 0x1, revents: 0 };
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 7i64 => ret,
            in("rdi") &mut p as *mut Pollfd,
            in("rsi") 1i64,
            in("rdx") timeout_ms as i64,
            lateout("rcx") _, lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

fn send(s: &mut UnixStream, obj: u32, opcode: u16, args: &[u32]) -> std::io::Result<()> {
    let size = (8 + args.len() * 4) as u32;
    let mut msg = Vec::with_capacity(size as usize);
    msg.extend_from_slice(&obj.to_ne_bytes());
    msg.extend_from_slice(&(((size) << 16) | opcode as u32).to_ne_bytes());
    for a in args {
        msg.extend_from_slice(&a.to_ne_bytes());
    }
    s.write_all(&msg)
}

fn main() {
    // libwayland's connect logic: $WAYLAND_DISPLAY (absolute as-is) else $XDG_RUNTIME_DIR/<name>.
    let disp = env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-0".into());
    let path = if disp.starts_with('/') {
        disp
    } else {
        let rt = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run".into());
        format!("{}/{}", rt, disp)
    };
    println!("hello-wl: Rust on AnonymOS — connecting to {}", path);
    // route any panic to stdout (the terminal) — Rust panics default to stderr, which the terminal
    // does not surface, so a parse panic would otherwise look like a silent exit.
    std::panic::set_hook(Box::new(|i| println!("hello-wl: panic: {}", i)));

    let mut s = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(e) => {
            println!("hello-wl: connect failed: {}", e);
            std::process::exit(1);
        }
    };
    println!("hello-wl: connected; enumerating the registry");

    // wl_display(1).get_registry(new_id=2) ; wl_display(1).sync(new_id=3) -> done when enumerated.
    let _ = send(&mut s, 1, 1, &[2]);
    let _ = send(&mut s, 1, 0, &[3]);

    let fd = s.as_raw_fd();
    let mut buf = [0u8; 8192];
    let mut acc: Vec<u8> = Vec::new();
    let mut count = 0u32;
    let mut total = 0usize;
    'outer: loop {
        // wait (yielding) for the reply to be readable — like libwayland's poll-then-read; a bare
        // non-blocking read would just spin and starve the cooperative scheduler.
        let pr = poll_in(fd, 3000);
        if pr < 0 { println!("hello-wl: poll error"); break; }
        if pr == 0 { println!("hello-wl: no reply within 3s ({} globals)", count); break; }
        let n = match s.read(&mut buf) {
            Ok(0) => { println!("hello-wl: server closed (read {} bytes, {} globals)", total, count); break; }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => { println!("hello-wl: read error: {}", e); break; }
            Ok(n) => n,
        };
        total += n;
        acc.extend_from_slice(&buf[..n]);
        loop {
            if acc.len() < 8 {
                break;
            }
            let _obj = u32::from_ne_bytes([acc[0], acc[1], acc[2], acc[3]]);
            let w1 = u32::from_ne_bytes([acc[4], acc[5], acc[6], acc[7]]);
            let opcode = (w1 & 0xffff) as u16;
            let size = (w1 >> 16) as usize;
            if size < 8 || acc.len() < size {
                break;
            }
            let body = acc[8..size].to_vec();
            if _obj == 2 && opcode == 0 && body.len() >= 12 {
                // registry.global: name:u32, interface:string(len+NUL,pad4), version:u32
                let name = u32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
                let slen = u32::from_ne_bytes([body[4], body[5], body[6], body[7]]) as usize;
                let iend = (8 + slen.saturating_sub(1)).min(body.len()).max(8);
                let iface = String::from_utf8_lossy(&body[8..iend]);
                let voff = 8 + ((slen + 3) & !3);
                let version = if voff + 4 <= body.len() {
                    u32::from_ne_bytes([body[voff], body[voff + 1], body[voff + 2], body[voff + 3]])
                } else {
                    0
                };
                println!("hello-wl:   global {:>2} {} v{}", name, iface, version);
                count += 1;
            } else if _obj == 3 && opcode == 0 {
                println!(
                    "hello-wl: registry enumerated ({} globals) — Rust speaks Wayland over the live Linux ABI. OK",
                    count
                );
                break 'outer;
            }
            acc.drain(0..size);
        }
    }
    std::process::exit(0);
}
