// hos-term.rs — R1: a CPU/SHM Wayland terminal emulator in Rust (pure std, no crates).
//
// The companion to ratty (the GPU terminal, R2+). It proves the whole terminal loop in Rust on
// the OS's *software* stack: a Wayland xdg-shell window, an SHM framebuffer, a PTY hosting zsh, a
// minimal VT parser, an 8x8 bitmap font blitter, and keyboard input — with NO crates (a single
// `rustc` build, like R0's hello-wl), so there is zero dependency risk on the partial Linux ABI.
//
// Wayland is spoken raw over the wire (the same approach hello-wl.rs validated): each message is
// [object_id u32][ (size<<16)|opcode u32 ][args...]. The one fd we must *send* (the SHM pool) goes
// as SCM_RIGHTS ancillary data on sendmsg; received fds (the keyboard keymap) are simply dropped,
// since we map keycodes with a hardcoded US table (mirrored from wl-term.c) instead of xkb.

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

include!("term_font8x8.rs"); // pub static FONT8X8: [[u8;8];95]  (ASCII 32..126)

// ---- raw syscalls (x86_64) ------------------------------------------------------------------
#[inline]
unsafe fn sys3(n: i64, a: i64, b: i64, c: i64) -> i64 {
    let r;
    core::arch::asm!("syscall", inlateout("rax") n => r, in("rdi") a, in("rsi") b,
        in("rdx") c, lateout("rcx") _, lateout("r11") _, options(nostack));
    r
}
#[inline]
unsafe fn sys6(n: i64, a: i64, b: i64, c: i64, d: i64, e: i64, f: i64) -> i64 {
    let r;
    core::arch::asm!("syscall", inlateout("rax") n => r, in("rdi") a, in("rsi") b,
        in("rdx") c, in("r10") d, in("r8") e, in("r9") f,
        lateout("rcx") _, lateout("r11") _, options(nostack));
    r
}
const SYS_READ: i64 = 0; const SYS_WRITE: i64 = 1; const SYS_CLOSE: i64 = 3;
const SYS_POLL: i64 = 7; const SYS_MMAP: i64 = 9; const SYS_IOCTL: i64 = 16;
const SYS_DUP2: i64 = 33; const SYS_SENDMSG: i64 = 46; const SYS_FORK: i64 = 57;
const SYS_EXECVE: i64 = 59; const SYS_FTRUNCATE: i64 = 77; const SYS_SETSID: i64 = 112;
const SYS_OPEN: i64 = 2; const SYS_MEMFD_CREATE: i64 = 319;

unsafe fn read(fd: i32, buf: &mut [u8]) -> i64 { sys3(SYS_READ, fd as i64, buf.as_mut_ptr() as i64, buf.len() as i64) }
unsafe fn write(fd: i32, buf: &[u8]) -> i64 { sys3(SYS_WRITE, fd as i64, buf.as_ptr() as i64, buf.len() as i64) }
unsafe fn close(fd: i32) { sys3(SYS_CLOSE, fd as i64, 0, 0); }
unsafe fn ioctl(fd: i32, req: u64, arg: i64) -> i64 { sys3(SYS_IOCTL, fd as i64, req as i64, arg) }
unsafe fn open(path: &[u8], flags: i64) -> i32 { sys3(SYS_OPEN, path.as_ptr() as i64, flags, 0) as i32 }

// ---- poll -----------------------------------------------------------------------------------
#[repr(C)]
struct PollFd { fd: i32, events: i16, revents: i16 }
const POLLIN: i16 = 0x001;
unsafe fn poll(fds: &mut [PollFd], timeout_ms: i64) -> i64 {
    sys3(SYS_POLL, fds.as_mut_ptr() as i64, fds.len() as i64, timeout_ms)
}

// ---- the message we read from / write to the Wayland socket -------------------------------
fn put_u32(v: &mut Vec<u8>, x: u32) { v.extend_from_slice(&x.to_ne_bytes()); }
fn put_str(v: &mut Vec<u8>, s: &str) {
    let len = s.len() as u32 + 1; // includes NUL
    put_u32(v, len);
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    while v.len() % 4 != 0 { v.push(0); } // pad to 32-bit
}
// Build [obj][ (size<<16)|opcode ][body] with the size patched in.
fn msg(obj: u32, opcode: u16, body: &[u8]) -> Vec<u8> {
    let size = (8 + body.len()) as u32;
    let mut m = Vec::with_capacity(size as usize);
    put_u32(&mut m, obj);
    put_u32(&mut m, (size << 16) | opcode as u32);
    m.extend_from_slice(body);
    m
}

// sendmsg the bytes, optionally carrying one fd as SCM_RIGHTS ancillary data.
#[repr(C)] struct IoVec { base: *const u8, len: usize }
#[repr(C)] struct MsgHdr {
    name: *const u8, namelen: u32, _pad0: u32,
    iov: *const IoVec, iovlen: usize,
    control: *const u8, controllen: usize,
    flags: i32, _pad1: u32,
}
unsafe fn send_fd(sock: i32, bytes: &[u8], fd: Option<i32>) {
    let iov = IoVec { base: bytes.as_ptr(), len: bytes.len() };
    // cmsg buffer: struct cmsghdr { socklen_t len(u64); int level; int type; } + int fd, aligned.
    let mut cbuf = [0u8; 24]; // CMSG_SPACE(sizeof(int)) on x86_64 = 16(hdr)+ pad to hold one int
    let (ctrl, ctrl_len) = if let Some(f) = fd {
        // cmsg_len = 16 + 4 = 20 ; level=SOL_SOCKET(1) ; type=SCM_RIGHTS(1)
        cbuf[0..8].copy_from_slice(&(20u64).to_ne_bytes());
        cbuf[8..12].copy_from_slice(&(1i32).to_ne_bytes());  // SOL_SOCKET
        cbuf[12..16].copy_from_slice(&(1i32).to_ne_bytes()); // SCM_RIGHTS
        cbuf[16..20].copy_from_slice(&f.to_ne_bytes());
        (cbuf.as_ptr(), 20usize)
    } else { (core::ptr::null(), 0usize) };
    let hdr = MsgHdr {
        name: core::ptr::null(), namelen: 0, _pad0: 0,
        iov: &iov, iovlen: 1,
        control: ctrl, controllen: ctrl_len,
        flags: 0, _pad1: 0,
    };
    sys3(SYS_SENDMSG, sock as i64, &hdr as *const _ as i64, 0);
}

// ---- Wayland object id allocation + the bound globals ---------------------------------------
struct Wl {
    sock: i32,
    next_id: u32,
    // bound singletons
    compositor: u32, shm: u32, wm_base: u32, seat: u32,
    surface: u32, xdg_surface: u32, xdg_toplevel: u32, keyboard: u32,
    // shm — double-buffered (one pool, two buffers) so we always have a free buffer to render
    // into while the compositor holds the other; the buffer.release event ping-pongs them.
    buffers: [u32; 2], maps: [*mut u8; 2], busy: [bool; 2],
    map_len: usize, width: i32, height: i32,
    // state
    configured: bool, closed: bool,
    // input modifiers
    shift: bool, ctrl: bool,
    ptm: i32,
    rbuf: Vec<u8>, // accumulated unparsed bytes from the socket
}

impl Wl {
    fn alloc(&mut self) -> u32 { let id = self.next_id; self.next_id += 1; id }
    fn send(&self, m: &[u8]) { unsafe { send_fd(self.sock, m, None); } }
}

// Wayland opcodes we use (request side).
const WL_DISPLAY_GET_REGISTRY: u16 = 1;
const WL_REGISTRY_BIND: u16 = 0;
const WL_COMPOSITOR_CREATE_SURFACE: u16 = 0;
const WL_SURFACE_ATTACH: u16 = 1;
const WL_SURFACE_DAMAGE: u16 = 2;
const WL_SURFACE_COMMIT: u16 = 6;
const WL_SHM_CREATE_POOL: u16 = 0;
const WL_SHM_POOL_CREATE_BUFFER: u16 = 0;
const XDG_WM_BASE_PONG: u16 = 3;
const XDG_WM_BASE_GET_XDG_SURFACE: u16 = 2;
const XDG_SURFACE_GET_TOPLEVEL: u16 = 1;
const XDG_SURFACE_ACK_CONFIGURE: u16 = 4;
const XDG_TOPLEVEL_SET_TITLE: u16 = 2;
const WL_SEAT_GET_KEYBOARD: u16 = 1;

fn bind_arg(name: u32, iface: &str, version: u32, new_id: u32) -> Vec<u8> {
    let mut b = Vec::new();
    put_u32(&mut b, name);
    put_str(&mut b, iface);
    put_u32(&mut b, version);
    put_u32(&mut b, new_id);
    b
}

// ---- the terminal grid + VT parser -----------------------------------------------------------
const COLS: usize = 80;
const ROWS: usize = 24;
const CELL: i32 = 16;      // 8x8 font scaled 2x
const SCALE: i32 = 2;

#[derive(Clone, Copy)]
struct Cell { ch: u8, fg: u32, bg: u32 }
const DEF_FG: u32 = 0xff_d2d6db;
const DEF_BG: u32 = 0xff_10141a;

struct Term {
    grid: [[Cell; COLS]; ROWS],
    cx: usize, cy: usize,
    fg: u32, bg: u32,
    // parser
    state: u8,            // 0 ground, 1 esc, 2 csi
    params: [u32; 8], np: usize, has_param: bool,
    dirty: bool,
}
const PALETTE: [u32; 16] = [
    0xff_10141a, 0xff_e06c75, 0xff_98c379, 0xff_e5c07b, 0xff_61afef, 0xff_c678dd, 0xff_56b6c2, 0xff_c0c4cc,
    0xff_5c6370, 0xff_ff7b86, 0xff_b5e890, 0xff_ffd596, 0xff_7cc5ff, 0xff_e29bf2, 0xff_72d3df, 0xff_ffffff,
];

impl Term {
    fn new() -> Term {
        Term { grid: [[Cell { ch: b' ', fg: DEF_FG, bg: DEF_BG }; COLS]; ROWS],
               cx: 0, cy: 0, fg: DEF_FG, bg: DEF_BG,
               state: 0, params: [0; 8], np: 0, has_param: false, dirty: true }
    }
    fn scroll(&mut self) {
        for r in 1..ROWS { self.grid[r - 1] = self.grid[r]; }
        self.grid[ROWS - 1] = [Cell { ch: b' ', fg: self.fg, bg: self.bg }; COLS];
    }
    fn newline(&mut self) { if self.cy + 1 >= ROWS { self.scroll(); } else { self.cy += 1; } }
    fn put(&mut self, c: u8) {
        if self.cx >= COLS { self.cx = 0; self.newline(); }
        self.grid[self.cy][self.cx] = Cell { ch: c, fg: self.fg, bg: self.bg };
        self.cx += 1;
    }
    fn sgr(&mut self) {
        let n = if self.np == 0 { 1 } else { self.np };
        let mut i = 0;
        while i < n {
            let p = self.params[i];
            match p {
                0 => { self.fg = DEF_FG; self.bg = DEF_BG; }
                1 => {} // bold — ignore (palette already bright-ish)
                30..=37 => self.fg = PALETTE[(p - 30) as usize],
                90..=97 => self.fg = PALETTE[(p - 90 + 8) as usize],
                40..=47 => self.bg = PALETTE[(p - 40) as usize],
                100..=107 => self.bg = PALETTE[(p - 100 + 8) as usize],
                39 => self.fg = DEF_FG,
                49 => self.bg = DEF_BG,
                _ => {}
            }
            i += 1;
        }
    }
    fn erase_line(&mut self, mode: u32) {
        let (a, b) = match mode { 1 => (0, self.cx + 1), 2 => (0, COLS), _ => (self.cx, COLS) };
        for x in a..b.min(COLS) { self.grid[self.cy][x] = Cell { ch: b' ', fg: self.fg, bg: self.bg }; }
    }
    fn erase_disp(&mut self, mode: u32) {
        let blank = Cell { ch: b' ', fg: self.fg, bg: self.bg };
        match mode {
            2 | 3 => { for r in 0..ROWS { self.grid[r] = [blank; COLS]; } self.cx = 0; self.cy = 0; }
            1 => { for r in 0..self.cy { self.grid[r] = [blank; COLS]; } self.erase_line(1); }
            _ => { self.erase_line(0); for r in (self.cy + 1)..ROWS { self.grid[r] = [blank; COLS]; } }
        }
    }
    fn csi(&mut self, fc: u8) {
        let p0 = if self.np > 0 { self.params[0] } else { 0 };
        let p1 = if self.np > 1 { self.params[1] } else { 0 };
        match fc {
            b'A' => self.cy = self.cy.saturating_sub(p0.max(1) as usize),
            b'B' => self.cy = (self.cy + p0.max(1) as usize).min(ROWS - 1),
            b'C' => self.cx = (self.cx + p0.max(1) as usize).min(COLS - 1),
            b'D' => self.cx = self.cx.saturating_sub(p0.max(1) as usize),
            b'G' => self.cx = (p0.max(1) as usize - 1).min(COLS - 1),
            b'd' => self.cy = (p0.max(1) as usize - 1).min(ROWS - 1),
            b'H' | b'f' => {
                self.cy = (p0.max(1) as usize - 1).min(ROWS - 1);
                self.cx = (p1.max(1) as usize - 1).min(COLS - 1);
            }
            b'J' => self.erase_disp(p0),
            b'K' => self.erase_line(p0),
            b'm' => self.sgr(),
            _ => {}
        }
    }
    fn feed(&mut self, bytes: &[u8]) {
        self.dirty = true;
        for &b in bytes {
            match self.state {
                0 => match b {
                    0x1b => { self.state = 1; }
                    b'\r' => self.cx = 0,
                    b'\n' => self.newline(),
                    0x08 => self.cx = self.cx.saturating_sub(1),
                    b'\t' => { self.cx = ((self.cx / 8) + 1) * 8; if self.cx >= COLS { self.cx = COLS - 1; } }
                    0x07 => {}
                    0x20..=0x7e => self.put(b),
                    _ => {}
                },
                1 => match b { // after ESC
                    b'[' => { self.state = 2; self.np = 0; self.params = [0; 8]; self.has_param = false; }
                    b']' => { self.state = 3; } // OSC — swallow to ST/BEL
                    _ => { self.state = 0; }
                },
                2 => match b { // CSI params then a final byte
                    b'0'..=b'9' => {
                        if self.np == 0 { self.np = 1; }
                        let idx = self.np - 1;
                        self.params[idx] = self.params[idx].saturating_mul(10) + (b - b'0') as u32;
                        self.has_param = true;
                    }
                    b';' => { if self.np < 8 { self.np += 1; } }
                    b'?' | b'<' | b'>' | b'!' | b' ' => {} // private markers — ignore
                    0x40..=0x7e => { if self.has_param && self.np == 0 { self.np = 1; } self.csi(b); self.state = 0; }
                    _ => { self.state = 0; }
                },
                3 => { if b == 0x07 || b == 0x1b { self.state = 0; } } // OSC: swallow until BEL/ESC
                _ => self.state = 0,
            }
        }
    }
}

// ---- the US keymap, mirrored from wl-term.c --------------------------------------------------
static KMAP: [u8; 59] = [
    0,0,b'1',b'2',b'3',b'4',b'5',b'6',b'7',b'8',b'9',b'0',b'-',b'=',0,0,
    b'q',b'w',b'e',b'r',b't',b'y',b'u',b'i',b'o',b'p',b'[',b']',0,0,b'a',b's',
    b'd',b'f',b'g',b'h',b'j',b'k',b'l',b';',b'\'',b'`',0,b'\\',b'z',b'x',b'c',b'v',
    b'b',b'n',b'm',b',',b'.',b'/',0,0,0,b' ',0,
];
static KMAP_SHIFT: [u8; 59] = [
    0,0,b'!',b'@',b'#',b'$',b'%',b'^',b'&',b'*',b'(',b')',b'_',b'+',0,0,
    b'Q',b'W',b'E',b'R',b'T',b'Y',b'U',b'I',b'O',b'P',b'{',b'}',0,0,b'A',b'S',
    b'D',b'F',b'G',b'H',b'J',b'K',b'L',b':',b'"',b'~',0,b'|',b'Z',b'X',b'C',b'V',
    b'B',b'N',b'M',b'<',b'>',b'?',0,0,0,b' ',0,
];
fn special_seq(code: u32) -> Option<&'static [u8]> {
    Some(match code {
        103 => b"\x1b[A", 108 => b"\x1b[B", 106 => b"\x1b[C", 105 => b"\x1b[D",
        102 => b"\x1b[1~", 107 => b"\x1b[4~", 110 => b"\x1b[2~", 111 => b"\x1b[3~",
        104 => b"\x1b[5~", 109 => b"\x1b[6~",
        _ => return None,
    })
}

// ---- the renderer: blit the grid into the SHM map -------------------------------------------
fn render(map: *mut u8, width: i32, height: i32, t: &Term) {
    if map.is_null() { return; }
    let pitch = width as usize;
    let px = unsafe { core::slice::from_raw_parts_mut(map as *mut u32, (width * height) as usize) };
    for ry in 0..ROWS {
        for rx in 0..COLS {
            let cell = t.grid[ry][rx];
            let cursor = rx == t.cx && ry == t.cy;
            let (fg, bg) = if cursor { (cell.bg, cell.fg) } else { (cell.fg, cell.bg) };
            let glyph = if cell.ch >= 32 && cell.ch <= 126 { FONT8X8[(cell.ch - 32) as usize] } else { FONT8X8[0] };
            let ox = rx as i32 * CELL;
            let oy = ry as i32 * CELL;
            for gy in 0..8i32 {
                let row = glyph[gy as usize];
                for gx in 0..8i32 {
                    let on = (row >> (7 - gx)) & 1 != 0;
                    let color = if on { fg } else { bg };
                    for sy in 0..SCALE {
                        for sx in 0..SCALE {
                            let xx = ox + gx * SCALE + sx;
                            let yy = oy + gy * SCALE + sy;
                            if xx >= 0 && yy >= 0 && (xx as usize) < pitch && yy < height {
                                px[yy as usize * pitch + xx as usize] = color;
                            }
                        }
                    }
                }
            }
        }
    }
}

// Render the grid into a free buffer and present it. Returns false if both buffers are busy
// (the caller keeps `dirty` set and retries once the compositor releases one).
fn commit_frame(wl: &mut Wl, t: &Term) -> bool {
    if !wl.configured || wl.surface == 0 || wl.buffers[0] == 0 { return false; }
    let idx = if !wl.busy[0] { 0 } else if !wl.busy[1] { 1 } else { return false; };
    render(wl.maps[idx], wl.width, wl.height, t);
    // attach(buffer, 0, 0)
    let mut b = Vec::new(); put_u32(&mut b, wl.buffers[idx]); put_u32(&mut b, 0); put_u32(&mut b, 0);
    wl.send(&msg(wl.surface, WL_SURFACE_ATTACH, &b));
    // damage(0,0,w,h)
    let mut d = Vec::new(); put_u32(&mut d, 0); put_u32(&mut d, 0);
    put_u32(&mut d, wl.width as u32); put_u32(&mut d, wl.height as u32);
    wl.send(&msg(wl.surface, WL_SURFACE_DAMAGE, &d));
    wl.send(&msg(wl.surface, WL_SURFACE_COMMIT, &[]));
    wl.busy[idx] = true;
    true
}

// ---- event dispatch -------------------------------------------------------------------------
fn read_u32(b: &[u8], o: usize) -> u32 { u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) }

fn handle(wl: &mut Wl, t: &mut Term, obj: u32, opcode: u16, body: &[u8]) {
    // wl_display(1).error = 0, .delete_id = 1
    if obj == 1 && opcode == 0 {
        // protocol error — print and bail
        let _ = unsafe { write(2, b"hos-term: wl_display error\n") };
        wl.closed = true;
        return;
    }
    if obj == 2 && opcode == 0 {
        // wl_registry.global(name, interface, version)
        let name = read_u32(body, 0);
        let slen = read_u32(body, 4) as usize;
        let iface = &body[8..8 + slen.saturating_sub(1).min(body.len() - 8)];
        let ver_off = 8 + ((slen + 3) & !3);
        let version = if ver_off + 4 <= body.len() { read_u32(body, ver_off) } else { 1 };
        let want = |s: &str| iface == s.as_bytes();
        if want("wl_compositor") && wl.compositor == 0 {
            wl.compositor = wl.alloc();
            wl.send(&msg(2, WL_REGISTRY_BIND, &bind_arg(name, "wl_compositor", version.min(4), wl.compositor)));
        } else if want("wl_shm") && wl.shm == 0 {
            wl.shm = wl.alloc();
            wl.send(&msg(2, WL_REGISTRY_BIND, &bind_arg(name, "wl_shm", 1, wl.shm)));
        } else if want("xdg_wm_base") && wl.wm_base == 0 {
            wl.wm_base = wl.alloc();
            wl.send(&msg(2, WL_REGISTRY_BIND, &bind_arg(name, "xdg_wm_base", version.min(2), wl.wm_base)));
        } else if want("wl_seat") && wl.seat == 0 {
            wl.seat = wl.alloc();
            wl.send(&msg(2, WL_REGISTRY_BIND, &bind_arg(name, "wl_seat", version.min(5), wl.seat)));
        }
        return;
    }
    // xdg_wm_base.ping(serial) = event 0  -> pong
    if obj == wl.wm_base && opcode == 0 {
        let serial = read_u32(body, 0);
        let mut b = Vec::new(); put_u32(&mut b, serial);
        wl.send(&msg(wl.wm_base, XDG_WM_BASE_PONG, &b));
        return;
    }
    // xdg_surface.configure(serial) = event 0 -> ack + first commit
    if obj == wl.xdg_surface && opcode == 0 {
        let serial = read_u32(body, 0);
        let mut b = Vec::new(); put_u32(&mut b, serial);
        wl.send(&msg(wl.xdg_surface, XDG_SURFACE_ACK_CONFIGURE, &b));
        wl.configured = true;
        return;
    }
    // xdg_toplevel: configure = 0, close = 1
    if obj == wl.xdg_toplevel && opcode == 1 { wl.closed = true; return; }
    // wl_buffer.release = event 0  -> that buffer is free to render into again
    if opcode == 0 && (obj == wl.buffers[0] || obj == wl.buffers[1]) {
        if obj == wl.buffers[0] { wl.busy[0] = false; } else { wl.busy[1] = false; }
        return;
    }
    // wl_seat.capabilities(caps) = event 0
    if obj == wl.seat && opcode == 0 {
        let caps = read_u32(body, 0);
        if caps & 2 != 0 && wl.keyboard == 0 { // WL_SEAT_CAPABILITY_KEYBOARD
            wl.keyboard = wl.alloc();
            let mut b = Vec::new(); put_u32(&mut b, wl.keyboard);
            wl.send(&msg(wl.seat, WL_SEAT_GET_KEYBOARD, &b));
        }
        return;
    }
    // wl_keyboard.key(serial, time, key, state) = event 3
    if obj == wl.keyboard && opcode == 3 {
        let code = read_u32(body, 8);
        let state = read_u32(body, 12);
        let down = state == 1;
        match code {
            42 | 54 => { wl.shift = down; return; }
            29 | 97 => { wl.ctrl = down; return; }
            _ => {}
        }
        if down { key_to_pty(wl, code); }
        let _ = t;
        return;
    }
}

fn key_to_pty(wl: &mut Wl, code: u32) {
    if let Some(seq) = special_seq(code) { unsafe { write(wl.ptm, seq); } return; }
    let mut c: u8 = match code {
        1 => 0x1b, 14 => 0x7f, 15 => b'\t', 28 => b'\r',
        _ => { if (code as usize) < 59 { if wl.shift { KMAP_SHIFT[code as usize] } else { KMAP[code as usize] } } else { 0 } }
    };
    if c == 0 { return; }
    if wl.ctrl {
        let lower = c | 0x20;
        if lower >= b'a' && lower <= b'z' { c = lower - b'a' + 1; }
    }
    unsafe { write(wl.ptm, &[c]); }
}

// pull complete messages out of wl.rbuf and dispatch them
fn drain(wl: &mut Wl, t: &mut Term) {
    loop {
        if wl.rbuf.len() < 8 { break; }
        let obj = read_u32(&wl.rbuf, 0);
        let word = read_u32(&wl.rbuf, 4);
        let size = (word >> 16) as usize;
        let opcode = (word & 0xffff) as u16;
        if size < 8 || wl.rbuf.len() < size { break; }
        let body: Vec<u8> = wl.rbuf[8..size].to_vec();
        handle(wl, t, obj, opcode, &body);
        wl.rbuf.drain(0..size);
        if wl.closed { break; }
    }
}

// ---- PTY + shell ----------------------------------------------------------------------------
fn cstr(s: &str) -> Vec<u8> { let mut v = s.as_bytes().to_vec(); v.push(0); v }

fn spawn_shell(width: i32, height: i32) -> i32 {
    unsafe {
        let m = open(b"/dev/ptmx\0", 0x2 | 0o4000); // O_RDWR | O_NONBLOCK
        if m < 0 { let _ = write(2, b"hos-term: open /dev/ptmx failed\n"); return -1; }
        let lock: i32 = 0;
        ioctl(m, 0x40045431, &lock as *const _ as i64);     // TIOCSPTLCK
        let mut n: u32 = 0;
        if ioctl(m, 0x80045430, &mut n as *mut _ as i64) < 0 { // TIOCGPTN
            let _ = write(2, b"hos-term: TIOCGPTN failed\n"); close(m); return -1;
        }
        // /dev/pts/N
        let mut pts = Vec::from(&b"/dev/pts/"[..]);
        let mut numbuf = [0u8; 10]; let mut ni = 10; let mut v = n;
        if v == 0 { ni -= 1; numbuf[ni] = b'0'; } else { while v > 0 { ni -= 1; numbuf[ni] = b'0' + (v % 10) as u8; v /= 10; } }
        pts.extend_from_slice(&numbuf[ni..]); pts.push(0);
        // window size
        #[repr(C)] struct WinSz { row: u16, col: u16, xp: u16, yp: u16 }
        let ws = WinSz { row: ROWS as u16, col: COLS as u16, xp: width as u16, yp: height as u16 };
        ioctl(m, 0x5414, &ws as *const _ as i64); // TIOCSWINSZ

        // env + argv built BEFORE fork (no allocation in the child)
        let path = cstr("/bin/zsh");
        let arg0 = cstr("-zsh");
        let argv: [*const u8; 2] = [arg0.as_ptr(), core::ptr::null()];
        let mut envp_storage: Vec<Vec<u8>> = Vec::new();
        let mut have_term = false;
        for (k, val) in std::env::vars() {
            if k == "TERM" { have_term = true; }
            envp_storage.push(cstr(&format!("{}={}", k, val)));
        }
        if !have_term { envp_storage.push(cstr("TERM=xterm")); }
        let mut envp: Vec<*const u8> = envp_storage.iter().map(|e| e.as_ptr()).collect();
        envp.push(core::ptr::null());

        let pid = sys3(SYS_FORK, 0, 0, 0);
        if pid == 0 {
            // child: new session, slave as controlling tty on 0/1/2, exec zsh
            close(m);
            let slave = open(&pts, 0x2); // O_RDWR
            sys3(SYS_SETSID, 0, 0, 0);
            ioctl(slave, 0x540e, 0); // TIOCSCTTY
            sys3(SYS_DUP2, slave as i64, 0, 0);
            sys3(SYS_DUP2, slave as i64, 1, 0);
            sys3(SYS_DUP2, slave as i64, 2, 0);
            if slave > 2 { close(slave); }
            sys6(SYS_EXECVE, path.as_ptr() as i64, argv.as_ptr() as i64, envp.as_ptr() as i64, 0, 0, 0);
            sys3(SYS_WRITE, 2, b"hos-term: execve failed\n".as_ptr() as i64, 24);
            sys3(60, 127, 0, 0); // exit
        }
        m
    }
}

// ---- SHM buffer -----------------------------------------------------------------------------
fn make_buffer(wl: &mut Wl) {
    unsafe {
        let stride = wl.width * 4;
        let bufsz = (stride * wl.height) as i64;
        let size = bufsz * 2; // two buffers in one pool
        let fd = sys3(SYS_MEMFD_CREATE, b"hos-term-shm\0".as_ptr() as i64, 0, 0) as i32;
        if fd < 0 { let _ = write(2, b"hos-term: memfd_create failed\n"); return; }
        sys3(SYS_FTRUNCATE, fd as i64, size, 0);
        // mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)
        let addr = sys6(SYS_MMAP, 0, size, 0x1 | 0x2, 0x1, fd as i64, 0);
        if addr < 0 { let _ = write(2, b"hos-term: mmap failed\n"); close(fd); return; }
        wl.map_len = size as usize;
        wl.maps[0] = addr as *mut u8;
        wl.maps[1] = (addr + bufsz) as *mut u8;
        for i in 0..2 {
            let px = core::slice::from_raw_parts_mut(wl.maps[i] as *mut u32, (wl.width * wl.height) as usize);
            for p in px.iter_mut() { *p = DEF_BG; }
        }
        // wl_shm.create_pool(new_id pool, fd, size)  — fd via SCM_RIGHTS
        let pool = wl.alloc();
        let mut b = Vec::new(); put_u32(&mut b, pool); put_u32(&mut b, size as u32);
        send_fd(wl.sock, &msg(wl.shm, WL_SHM_CREATE_POOL, &b), Some(fd));
        // two buffers at offsets 0 and bufsz
        for i in 0..2 {
            wl.buffers[i] = wl.alloc();
            let mut c = Vec::new();
            put_u32(&mut c, wl.buffers[i]); put_u32(&mut c, (i as i64 * bufsz) as u32);
            put_u32(&mut c, wl.width as u32); put_u32(&mut c, wl.height as u32);
            put_u32(&mut c, stride as u32); put_u32(&mut c, 1); // XRGB8888
            wl.send(&msg(pool, WL_SHM_POOL_CREATE_BUFFER, &c));
        }
        close(fd); // the pool keeps it mapped
    }
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let s = format!("hos-term PANIC: {}\n", info);
        unsafe { write(2, s.as_bytes()); }
    }));

    let rt = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run".into());
    let disp = std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-0".into());
    let path = format!("{}/{}", rt, disp);
    let stream = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(e) => { let m = format!("hos-term: connect {} failed: {}\n", path, e); unsafe { write(2, m.as_bytes()); } return; }
    };
    let sock = stream.as_raw_fd();
    // keep `stream` alive for the duration; we drive the fd raw.
    std::mem::forget(stream);

    let mut wl = Wl {
        sock, next_id: 2,
        compositor: 0, shm: 0, wm_base: 0, seat: 0,
        surface: 0, xdg_surface: 0, xdg_toplevel: 0, keyboard: 0,
        buffers: [0, 0], maps: [core::ptr::null_mut(); 2], busy: [false, false],
        map_len: 0, width: (COLS as i32) * CELL, height: (ROWS as i32) * CELL,
        configured: false, closed: false,
        shift: false, ctrl: false, ptm: -1,
        rbuf: Vec::with_capacity(8192),
    };
    let mut t = Term::new();

    // wl_display.get_registry(new_id registry=2)
    let registry = wl.alloc(); // = 2
    let mut b = Vec::new(); put_u32(&mut b, registry);
    wl.send(&msg(1, WL_DISPLAY_GET_REGISTRY, &b));

    // round-trip until the singletons are bound
    pump(&mut wl, &mut t, 400);
    if wl.compositor == 0 || wl.shm == 0 || wl.wm_base == 0 {
        unsafe { write(2, b"hos-term: missing compositor/shm/xdg_wm_base\n"); }
        return;
    }

    // surface + xdg toplevel
    wl.surface = wl.alloc();
    { let mut s = Vec::new(); put_u32(&mut s, wl.surface);
      wl.send(&msg(wl.compositor, WL_COMPOSITOR_CREATE_SURFACE, &s)); }
    wl.xdg_surface = wl.alloc();
    { let mut s = Vec::new(); put_u32(&mut s, wl.xdg_surface); put_u32(&mut s, wl.surface);
      wl.send(&msg(wl.wm_base, XDG_WM_BASE_GET_XDG_SURFACE, &s)); }
    wl.xdg_toplevel = wl.alloc();
    { let mut s = Vec::new(); put_u32(&mut s, wl.xdg_toplevel);
      wl.send(&msg(wl.xdg_surface, XDG_SURFACE_GET_TOPLEVEL, &s)); }
    { let mut s = Vec::new(); put_str(&mut s, "AnonymOS Terminal (Rust / ratty-cpu R1)");
      wl.send(&msg(wl.xdg_toplevel, XDG_TOPLEVEL_SET_TITLE, &s)); }
    wl.send(&msg(wl.surface, WL_SURFACE_COMMIT, &[]));

    make_buffer(&mut wl);
    wl.ptm = spawn_shell(wl.width, wl.height);
    if wl.ptm < 0 { return; }

    unsafe { write(1, b"hos-term: up (Rust CPU/SHM terminal hosting zsh)\n"); }

    // main loop: poll the wayland socket + the pty master
    let mut ptbuf = [0u8; 4096];
    loop {
        if wl.closed { break; }
        // render if the grid changed and a buffer is free (double-buffered)
        if t.dirty && wl.configured && (!wl.busy[0] || !wl.busy[1]) {
            if commit_frame(&mut wl, &t) { t.dirty = false; }
        }
        let mut fds = [
            PollFd { fd: wl.sock, events: POLLIN, revents: 0 },
            PollFd { fd: wl.ptm, events: POLLIN, revents: 0 },
        ];
        unsafe { poll(&mut fds, 50); }
        if fds[0].revents & POLLIN != 0 { read_wl(&mut wl, &mut t); }
        if fds[1].revents & POLLIN != 0 {
            let n = unsafe { read(wl.ptm, &mut ptbuf) };
            if n > 0 { t.feed(&ptbuf[..n as usize]); }
            else if n == 0 { break; } // shell exited
        }
    }
}

fn read_wl(wl: &mut Wl, t: &mut Term) {
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { read(wl.sock, &mut buf) };
        if n > 0 { wl.rbuf.extend_from_slice(&buf[..n as usize]); if (n as usize) < buf.len() { break; } }
        else { break; }
    }
    drain(wl, t);
}

// round-trip helper used during setup: poll + read + dispatch for up to `ms` total.
fn pump(wl: &mut Wl, t: &mut Term, ms: i64) {
    let mut left = ms;
    while left > 0 {
        let mut fds = [PollFd { fd: wl.sock, events: POLLIN, revents: 0 }];
        let step = 50.min(left);
        let r = unsafe { poll(&mut fds, step) };
        if r > 0 && fds[0].revents & POLLIN != 0 { read_wl(wl, t); }
        left -= step;
        if wl.compositor != 0 && wl.shm != 0 && wl.wm_base != 0 && wl.seat != 0 { break; }
    }
}
