# GUI Desktop Roadmap

## NEW GOALS (2026-06-04) — interactive Hyprland: first client window, cursor, terminal

> **Direction set with the user.** Goal: an interactive Hyprland desktop — move the
> cursor, see a real window, type into a terminal. Bare Hyprland is a tiling WM with
> **no desktop icons/launcher** (nothing to click out of the box) and **no Wayland
> client has ever rendered a window** yet, so the empty workspace is the real blocker.
> The plan is **foundation-first**: get one Wayland client window to composite, then a
> cursor, then a software terminal.
>
> **ratty is PARKED (not viable here).** `orhun/ratty` is a GPU-rendered 3D terminal
> on **Bevy + wgpu + Vello/Parley** (Rust). This OS has only **Mesa softpipe** (CPU
> software GL, no Vulkan) *with the unresolved texture-sampling bug (see Known issues)*,
> no Rust→musl toolchain, and no working Wayland client path. ratty would be strictly
> harder than everything attempted so far. **Revisit only if a real GPU/Vulkan path
> lands.** The terminal we build instead is **software-rendered (wl_shm, no GPU)**.

**What already exists (foundation is mostly there — grounded in the tree):**
- Wayland socket: `WAYLAND_DISPLAY=wayland-0`, `XDG_RUNTIME_DIR=/run/user/1000`
  (`exports.d`); the kernel binds unix sockets at filesystem paths and explicitly knows
  `/run/user/1000/wayland-0` (`posix.d`).
- `wl_shm` transport pieces: `memfd_create` + shared (`aliased`) mmap, and
  **SCM_RIGHTS** fd-passing over `sendmsg` (`posix.d passedFiles[]`) — so a client can
  hand its shm buffer fd to the compositor and both mmap the same physical pages.
- Mouse input plumbing exists: PS/2 driver (`drivers/input/usb_hid.d`) → `g_mouse_ring`
  → `/dev/input/event1` returning Linux `input_event` structs (`posix.d`,
  `FD_INPUT_EVENT`); `/dev/input/event0/1` registered (`device.d`).
- Userland C clients build from `src/util/*.c`; the sysroot has `libwayland-client.a`
  + `wayland-client.h` + `xdg-shell.xml` (`deps/gtk-stack/sysroot`, `deps/.../wayland-protocols`).
- **G1 is implemented:** `wl-probe` is staged as a boot module, the kernel arms a
  Hyprland-only autostart hook, and a second task is spawned once the compositor's
  Wayland listener is ready. Verified in QEMU serial log:
  `WLPROBE: connected to /run/user/1000/wayland-0 OK -- G1 DONE`.
- **G2 is implemented:** `wl-shm-demo` is staged as a boot module and autostarted
  after Hyprland's listener settles. It binds `wl_compositor`/`wl_shm`/`xdg_wm_base`,
  creates an `xdg_toplevel`, passes a memfd-backed shm buffer, commits it, and
  Hyprland logs the mapped window (`EpinAnonymOS G2 wl_shm`) on `FALLBACK`.
- **G3 is implemented:** the sessionless headless backend (which has no
  libinput/libseat/udev) bridges the kernel's evdev mouse `/dev/input/event1`
  straight into an aquamarine pointer (patch `0004-headless-input.patch`). The
  cursor tracks the mouse and a left click is routed to the focused client
  surface. Verified in QEMU via `scripts/qemu-g3-verify.sh`.

**G1 — A client-launch mechanism. DONE.** Implemented via kernel boot-module
autostart: `wl-probe` is built from `src/util/wl-probe.c`, included in the ISO, and
spawned as a second userspace task after Hyprland exposes its Wayland listener.
Hyprland currently binds `wayland-1`, so the kernel aliases client connects to
`/run/user/1000/wayland-0` onto that live listener to preserve the boot environment.
*Proof:* QEMU serial showed `[g1] wl-probe launched as task ...` followed by
`WLPROBE: connected to /run/user/1000/wayland-0 OK -- G1 DONE`.

**G2 — First Wayland client window (the gating milestone). DONE.** Implemented by
`src/util/wl-shm-demo.c`, statically linked against the sysroot
`libwayland-client` and generated `xdg-shell` protocol. The kernel includes it in
the ISO and launches it after Hyprland's Wayland listener has settled. It binds
`wl_compositor`/`wl_shm`/`xdg_wm_base`, creates a memfd shm pool, creates an
`xdg_toplevel`, attaches the buffer, and commits.
*Proof:* QEMU serial showed `G2SHM: committed wl_shm xdg_toplevel 640x400 -- G2 COMMIT`,
followed by Hyprland mapping the window:
`Map request dispatched, monitor FALLBACK, window pos: [20.00000, 20.00000], window size: [600.00000, 360.00000]`.
QEMU HMP `screendump` currently captures the fallback/firmware framebuffer rather
than the DRM dumb-buffer content, so the serial map/commit trace is the reliable
verification artifact for this milestone.

**G3 — Cursor movement + click. DONE.** The path is QEMU mouse → PS/2 IRQ12 →
`/dev/input/event1` (kernel evdev ring) → **aquamarine headless input bridge** →
Hyprland pointer → cursor + `wl_pointer` to the focused surface.

*Architecture note (deviates from the original "via libinput/seat" sketch):*
Hyprland runs on the **sessionless Headless backend**, which never initializes
libseat/libinput/udev (the serial log shows `libseat: failed to open a seat` →
`Sessionless backend active`). There is therefore **no libinput device the seat
could enumerate**. Instead, mirroring how the headless **present** path bypasses
DRM/GBM with a custom kernel ioctl, the headless backend now opens
`/dev/input/event1` directly, exposes a `CHeadlessPointer : IPointer`, and
translates `input_event` frames (`EV_REL`→move, `EV_KEY`→button, `EV_SYN`→frame)
into aquamarine pointer events. Hyprland consumes it exactly like a libinput
pointer (`getLibinputHandle()` returns null, which Hyprland already guards). The
default fallback cursor (`XCursor … using default cursor instead`) renders through
the existing present blit, so the theme search already terminates. Kernel side:
`handleMouseIRQ` now emits `EV_KEY` only on button **transitions** (evdev
semantics) and `SYN_REPORT` only on non-empty frames, instead of re-emitting level
state every packet.

*Proof (`scripts/qemu-g3-verify.sh`, which boots headless with a QMP socket and
injects motion+click):* QEMU serial showed, in order:
`headless: bridging kernel evdev pointer /dev/input/event1 -> aquamarine pointer`,
`New mouse created, pointer AQ:` (Hyprland enumerated the pointer),
`G3PTR: wl_seat has pointer; subscribed` (client got the seat pointer capability),
`G3PTR: pointer enter … -- G3 ENTER` and `G3PTR: motion 89,56 / 249,168` (cursor
tracked the mouse into the window), and
`G3PTR: button 0x110 state 1 -- G3 CLICK` (left-button press delivered to the
focused client surface). The `wl-shm-demo` client was extended to bind
`wl_seat`/`wl_pointer` and log these for a serial-checkable artifact.

**G4 — Software terminal client. DONE.** `src/util/wl-term.c` is a software-rendered
`wl_shm` terminal: an 80×24 character grid (shared `gui_font.h` 8×8 font) blitted to an
shm buffer, `wl_keyboard` input, and an interactive **busybox `sh`** running on a real
kernel **PTY**. Autostarted in place of `wl-shm-demo`.

*Work done (the original sketch needed several gaps filled — `/dev/ptmx`/`TIOCGPTN`
were stubbed and there was no keyboard path):*
- **Kernel PTY subsystem** (`posix.d`): `/dev/ptmx` allocates a pty and returns the
  master; `TIOCGPTN`/`TIOCSPTLCK` work; `/dev/pts/N` opens the slave; master⇄slave
  ring buffers with a **termios line discipline** (`ICANON`/`ECHO`/`ICRNL`/`ONLCR`,
  VERASE/VKILL, per-pty stored termios so the shell's raw-mode `tcsetattr` is honored).
  Blocking slave reads use the same RIP-rewind cooperative-block path as the console
  (`ptyBlockingReadFd`). *Gotcha:* musl's `ioctl(int request)` sign-extends high-bit
  requests, so `TIOCGPTN` (0x80045430) arrives as `0xFFFFFFFF80045430` — `ptyIoctl`
  masks `cmd` to 32 bits.
- **Keyboard bridge** (aquamarine `0005-headless-keyboard.patch`): `/dev/input/event0`
  → `CHeadlessKeyboard : IKeyboard`, emitting key events; Hyprland derives modifiers
  via its own xkb state.
- **`shm_open` → memfd** (`hyprland-shm-memfd.patch`): the kernel has no POSIX
  `shm_open`, so Hyprland's keymap/shm helpers (`allocateSHMFile*`) now use
  `memfd_create`.  Without this, sending the `wl_keyboard` keymap fd failed
  (`fcntl(F_DUPFD_CLOEXEC)` → EBADF → *"error in client communication"* → the window was
  destroyed the instant a keyboard bound).
- **Terminal spawns the shell with `fork()` (not `posix_spawn`) before connecting to
  Wayland.** The kernel forces `argv[0]` to the boot-module basename, so the shell is
  staged as a boot module literally named **`-sh`** (a busybox copy) → `argv[0]="-sh"`
  → ash login-interactive prompt.  `fork()` routes through `forkTask`, which copies the
  fd table (so the child's `dup2` of the slave onto 0/1/2 doesn't clobber the parent);
  `vfork`/`posix_spawn` share the fd table and corrupted it.

*Proof (`scripts/qemu-g4-verify.sh`, which boots headless with QMP, clicks the window
to focus it, then types `echo g4pass`):* serial showed
`New keyboard created`, `G4TERM: … G4 COMMIT` (window mapped),
`G4OUT: BusyBox v1.36.1 … built-in shell (ash)` (shell on the pty),
`G4KEY: keyboard enter -- G4 FOCUS`, the per-key trace `code=18 -> 0x65 …` (e-c-h-o-…),
`G4OUT: $ echo g4pass` (the shell echoed the typed line) and finally
`G4OUT: g4pass` (**the typed command ran**).

**G5 — Identity-colored borders in the live present path. P: Medium · deps: G2.**
Carry the trusted identity border (already done for the in-house compositor, and
`IDENTITY_DOMAIN_ROADMAP.md` §6) into the Hyprland/aquamarine present path so every
client window is bordered by its owner's identity color.

**Parked / not on this path:** the softpipe textured-wallpaper bug (see Known issues —
low leverage, slow), dmabuf EGLImage import (efficiency), full desktop shell with icons
(needs a panel/launcher — large), and ratty (GPU/Bevy — needs Vulkan).

**Iteration reality:** every Hyprland boot is ~200–300 s headless and the wallpaper/
client timing is a lottery; favor changes that are checkable from the serial log
(client `connect`/`bind`/`commit` traces, present ioctls) over screendump-only signals.

---

## Known issues / notes

- **Input arrives via a direct evdev bridge, not libinput (G3/G4).** Because the
  backend is sessionless, libinput/libseat/udev never come up, so the headless
  backend reads the kernel evdev devices itself: the **pointer** from
  `/dev/input/event1` (`patches/0004-headless-input.patch`) and the **keyboard**
  from `/dev/input/event0` (`patches/0005-headless-keyboard.patch`,
  `CHeadlessKeyboard : IKeyboard` feeding `EV_KEY` → `IKeyboard::SKeyEvent`).
- **Keyboard focus is click-to-focus.** A freshly mapped window does not get
  keyboard focus until the pointer clicks it; the G4 verifier clicks the terminal
  before typing. (`G4KEY: keyboard enter -- G4 FOCUS` confirms focus.)
- **G3 verification is scripted, not screendump-based.** `scripts/qemu-g3-verify.sh`
  + `scripts/qemu-mouse-inject.py` boot headless with a QMP socket, wait for the
  window map, then inject PS/2 motion+click via `input-send-event`. The cursor is
  clamped to the monitor, so the injector pins it to the top-left corner first, then
  walks into the window interior — relative-motion injection is otherwise
  start-position dependent. Markers to grep: `New mouse created, pointer AQ`,
  `G3PTR: … G3 ENTER`, `G3PTR: … G3 CLICK`.
- **QEMU HMP screendump does not show the mapped Hyprland window yet.** G2 now proves
  the Wayland client path by serial (`wl_shm` commit + Hyprland map request), but
  `screendump` still captures the fallback/firmware-looking framebuffer (black
  interior with border gradient) instead of the DRM dumb-buffer content.
- **Softpipe textured-render bug (wallpaper, parked).** A decoded image renders only as
  a ~16–20 px border with a black interior; narrowed to softpipe dropping
  `v_texcoord.y` (the texcoord's 2nd component / vs→fs varying packing) — a solid-color
  quad fills cleanly, only the *textured* quad's interior is black. A de-interleave
  workaround failed. This is a deep Mesa softpipe source fix
  (`deps/mutter/build/mesa-23.3.5-epin`) with very slow iteration; **parked** unless the
  softpipe source is worth patching.
- **Compositor re-inits 2–3×** (one cause was the builtin seatd `fork`). Harmless now
  (no OOM) but a correctness wart; it also makes the wallpaper load very late, which is
  the meta-blocker for any softpipe iteration.
- **Syscall gaps:** `sigprocmask`/`sigaction` *with delivery* is partial (app error
  handling); `shm_open` / POSIX shm is still **not done in the kernel** — for G4 it was
  worked around by patching Hyprland's shm helpers to use `memfd_create`
  (`hyprland-shm-memfd.patch`); a real `shm_open` would need a named-shm registry.
  Implemented: **pty/ptmx (G4)**, memfd, timerfd, eventfd, sendmsg/recvmsg+SCM_RIGHTS,
  dup/dup2/dup3, nanosleep, clone/futex/**fork**, flock, getdents64, PRIME_HANDLE_TO_FD.
- DRM ioctl can `#GP` when the kernel writes a user pointer under SMAP. Mitigated via
  `-cpu qemu64,-smap,-smep` in `qemu-run.sh`; real fix = STAC/CLAC around copies.
- **Hyprland's `RASSERT` does `raise(SIGABRT)`, which the kernel does NOT make fatal**
  — a failed assertion *continues* and crashes downstream. When reading a crash, find
  the FIRST `Assertion failed!` + matching `libEGL debug:`/EGL error, not the final
  `[pf]`. The serial log has binary bytes → use `grep -a`.
- Hyprland uses a **lua** config (`/etc/hypr/hyprland.lua`); how it's served in the
  guest is unresolved (not in the `g_vfs` table) — blocks easy config-based tweaks.
- **Stale-binary trap:** a broken `ninja` leaves the old `Hyprland` in place (`make
  all` still says "Build complete") — always grep the fresh binary for your probe string.
- **Debug logging still on, trim once rendering works:** `[xkb]` unpack counts,
  `[mmap-einval]`, `[mmap-so]`, `[drm] nr=`, `[sc] t=`, `[futex-*]`, PF `rsp/ret0`, the
  `H`/`I`/`D` `console_putchar` in `linux_sys_ioctl`/`handleDrmIoctl`, `EGL_LOG_LEVEL=debug`.
- **Run:** `make all && ./qemu-run.sh` boots Hyprland as initial userspace. Rebuild
  note: top-level `make` no-ops when artifacts exist — after editing kernel source,
  delete the stale `build/d/.../*.o` + `build/libkernel_d.a` to force a recompile.
  *(In-house compositor demo instead, in busybox: `/compositor &` then `/hello-gui &`.)*
