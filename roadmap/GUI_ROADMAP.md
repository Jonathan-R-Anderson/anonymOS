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

**G1 — A client-launch mechanism. P: Critical.** Nothing currently starts a second
userspace process after Hyprland. *Need:* either honor Hyprland's `exec-once`/autostart
to spawn a client, or have the kernel launch a second boot-module process once the
compositor's `wayland-0` socket exists. *Done when:* a second process starts and
`connect()`s to `/run/user/1000/wayland-0`.

**G2 — First Wayland client window (the gating milestone). P: Critical.** Build a
minimal `wl_shm` client (weston-simple-shm–style C, linked against the sysroot
`libwayland-client` + xdg-shell) that binds `wl_compositor`/`wl_shm`/`xdg_wm_base`,
creates a pool from a memfd, makes an `xdg_toplevel`, attaches a buffer, and commits.
*Done when:* a solid-color client rectangle is **composited by Hyprland** (screendump
shows a non-background rectangle). This proves the whole client path end-to-end and
de-risks everything after it.

**G3 — Cursor movement + click. P: High · deps: G2.** Verify QEMU mouse → PS/2 →
`/dev/input/event1` → libinput → Hyprland pointer → **rendered cursor that moves**, and
that a button press reaches the focused surface. *Done when:* the cursor tracks the
mouse on screen and a click is delivered to the client window. (Likely work: confirm
`input_event` framing/`EV_SYN` batching, libinput device enumeration via the seat, and
a cursor sprite — ship/point at a minimal cursor so the theme search terminates.)

**G4 — Software terminal client. P: High · deps: G2, G3.** A lightweight,
**software-rendered** terminal (own minimal `wl_shm` client, or port a small one like
`st`/`foot` cut down to shm): a character grid blitted to an shm buffer, a **PTY**
(`openpty`/`forkpty` — check `/dev/ptmx` + `TIOCGPTN` support) running `-sh`/busybox,
keyboard input from `wl_keyboard`. *Done when:* a terminal window shows a prompt and
runs typed commands. (`Jonathan-R-Anderson/-sh` is the intended shell.)

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

- **Wayland client path is unproven** — Hyprland (the server) reaches its event loop
  and renders an empty workspace, but no client has ever connected + mapped a surface.
  This is the gating unknown for G1/G2.
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
  handling); `shm_open` / POSIX shm is **not done** — layer it on memfd if a client
  needs the shm_open path (Wayland prefers `memfd_create`, which works). Implemented:
  memfd, timerfd, eventfd, sendmsg/recvmsg+SCM_RIGHTS, dup/dup2/dup3, nanosleep,
  clone/futex, flock, getdents64, PRIME_HANDLE_TO_FD.
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
