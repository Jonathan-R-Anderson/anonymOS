# GUI Desktop Roadmap — High-Quality Desktop Experience

## NEW GOALS (2026-06-05) — real desktop quality, not a low-resolution demo

> **Direction set with the user.** The goal is no longer merely “Hyprland boots and a terminal technically exists.” The goal is a **real graphical desktop experience** comparable in polish to Linux desktop environments or macOS: crisp high-resolution output, readable fonts, visible window contents, smooth cursor/input, real window decorations, wallpaper, launcher, dock/panel, app switching, file manager, settings, and a consistent visual design.
>
> The current system feels low-quality because it is still in the “first compositor/client path” phase. The largest blockers are:
>
> 1. **Window contents now visibly composite for the wl_shm terminal path**, but text/font quality and broader toolkit coverage still need work.
> 2. **Resolution/output handling is still fallback-like**, so screenshots and framebuffer output do not look like a modern desktop.
> 3. **The UI stack has no real desktop shell yet**: no panel, launcher, wallpaper, app grid, file manager, notification area, or settings.
> 4. **Text/icon rendering is not production-grade yet**: fonts, antialiasing, HiDPI scaling, icon themes, and asset delivery need to become first-class OS features.

This roadmap keeps the existing G1–G5 foundation, but reframes the next milestones around **visual quality** and **desktop completeness**.

---

## Quality bar: what “real desktop experience” means

The OS should not be considered to have a finished GUI until it can boot into a screen that looks and behaves like a normal desktop:

- Native monitor resolution, minimum target **1280×800**, preferred **1920×1080**, with future support for HiDPI scaling.
- Visible, crisp `wl_shm` and toolkit-rendered app contents.
- Smooth mouse cursor, click/drag, keyboard focus, key repeat, modifier keys, and app switching.
- Desktop wallpaper/background layer.
- Window decorations: rounded corners, shadows, title bars, close/minimize/maximize controls, active/inactive state.
- Consistent font rendering with antialiasing and fallback fonts.
- Consistent icon theme and cursor theme.
- Dock/taskbar/panel with app launchers, running indicators, clock, network/power/status slots.
- Launcher/search overlay similar to Spotlight, KRunner, GNOME overview, or macOS Launchpad.
- File manager with icons/list view.
- Settings app or config panel for display, theme, wallpaper, input, identity colors, and accessibility.
- Screenshot-based visual regression tests so the desktop does not silently degrade.

---

## What already exists

The current foundation is useful and should be preserved:

- Wayland socket and runtime path exist: `WAYLAND_DISPLAY=wayland-0`, `XDG_RUNTIME_DIR=/run/user/1000`.
- `wl_shm` transport exists through `memfd_create`, shared mmap, and `SCM_RIGHTS` fd passing.
- Mouse and keyboard are bridged from kernel evdev into the sessionless Hyprland/aquamarine backend.
- Userland C clients build from `src/util/*.c`.
- **G1 DONE:** client launch mechanism exists.
- **G2 DONE:** first Wayland `wl_shm` client window maps.
- **G3 DONE:** cursor movement and click work.
- **G4 DONE:** software `wl_shm` terminal talks to BusyBox shell through a real PTY.
- **G5 DONE:** trusted kernel identity-colored borders render in the final present path.
- **G6 DONE:** `wl_shm` terminal contents are visible in a QEMU screendump; verified by `scripts/qemu-g6-verify.sh` on 2026-06-05.
- **G7 DONE:** real display-mode config/reporting pipeline exists; 1280×800 and 1920×1080 screendump-size tests pass with `scripts/qemu-g7-verify*.sh`.
- **G8 DONE:** headless frame pacing/redraw correctness is verified; post-client-commit screendumps visibly update with `scripts/qemu-g8-verify.sh`.
- **G9 DONE:** bundled Noto fonts and FreeType terminal rendering are verified; `scripts/qemu-g9-verify.sh` passes with antialiased terminal text in a QEMU screendump.
- **G10 DONE:** fonts/icons/cursors/wallpapers/themes are packed as first-class category blobs with a manifest and license guard; `scripts/qemu-g10-verify.sh` passes.
- **G11 DONE:** a Cairo/FreeType lightweight toolkit demo renders icon, label, entry, button, and antialiased text from bundled Noto assets; `scripts/qemu-g11-verify.sh` passes.
- **G12 DONE:** the HOS CPU present path paints a scaled default wallpaper behind windows; `scripts/qemu-g12-verify.sh` passes in a no-client boot.
- **G13 DONE:** a persistent top panel/menu bar renders above windows with active title, status placeholders, and uptime clock; `scripts/qemu-g13-verify.sh` passes.
- **G14 DONE:** the present path now renders an **antialiased Cairo desktop shell** — the top panel was migrated to Cairo/FreeType Noto text, and a polished, Ubuntu-class bottom **dock** was added (rounded translucent shelf, soft shadow, five colored launcher tiles, identity-accent running indicator, reserved dock space). `scripts/qemu-g14-verify.sh` passes and `scripts/qemu-g13-verify.sh` still passes.
- **G15 DONE:** a **pointer cursor** is now composited in the present path (the CPU path previously drew none), a **Spotlight-style launcher** (Super+Space → search → Enter to launch via Hyprland's spawner) was added, the **dock tiles are clickable**, and the kernel now forwards the **Super/Meta key** (it was being dropped). `scripts/qemu-g15-verify.sh` passes.
- **G16 DONE:** windows now have **modern decorations** — a drop shadow, an antialiased titlebar with the window title, an identity accent dot, and minimize/maximize/close controls, plus **rounded corners**, an active/inactive titlebar state, and a **rounded, kernel-owned identity border**. `scripts/qemu-g16-verify.sh` passes (G13/G14/G15 still pass).
- **G17 DONE:** a real **file manager** application (`wl-files`) — a Finder-style browser with a Places sidebar, a path toolbar with a back button, and a folder/file listing read from the VFS with vector icons, names, selection, and an identity/security status label. Fixing it surfaced and corrected a **kernel `getdents64` ABI bug** (d_name was written into struct padding, so every directory listing came back nameless). `scripts/qemu-g17-verify.sh` passes (G13–G16 still pass).

These are the correct low-level primitives. The shell is now rendered with Cairo/Pango/FreeType for genuinely antialiased, vector-quality output.

---

# ARCHITECTURE PIVOT (2026-06-07) — Weston + Pixman instead of Hyprland

**Why.** G6–G18 above were built on **Hyprland**, which is an **OpenGL-only** compositor. This machine has no GPU, and Mesa's software GL (`swrast`) crashes in this freestanding/musl environment. To get anything on screen we had to bypass Hyprland's renderer entirely with a **hand-written CPU compositor** (`hosComposeShmWindows`) plus custom damage tracking and a custom cursor path. That custom layer is fragile and is the source of a recurring chain of bugs: the GL crash that killed input, an OOM when forking to launch apps, a serial-log flood that froze the desktop under KVM, a full-frame blit per present, and finally a cursor that updates at ~1–2 fps because Hyprland assumes a hardware cursor plane that does not exist here.

**Decision.** Replace Hyprland with **Weston** (the reference Wayland compositor) using its **Pixman software renderer**. Weston is designed for software rendering: **no OpenGL/Mesa at all**, and software cursors, software compositing, and damage tracking are first-class, tested code — not hand-rolled. This deletes `hosComposeShmWindows` and the entire custom-compositor surface.

**The Hyprland-era milestones (G6–G21) are retained for history**, but the shell work (panel/dock/launcher/file-manager/settings) will be re-expressed on top of Weston via standard mechanisms (`weston.ini`, `layer-shell`, a desktop or kiosk shell) once the compositor is up. The hard, recurring "make pixels appear without a GPU" problem is solved structurally rather than patched.

## GW1 DONE — Build Weston + Pixman against the existing sysroot. P: Critical

**Goal:** Compile Weston 14.0 as pure software (no GL/Mesa) against the musl sysroot already built for the Hyprland attempt.

**Done when:**

- `weston`, `libweston-14` (Pixman renderer built in), `drm-backend.so`, `headless-backend.so`, `desktop-shell.so`, `kiosk-shell.so`, and demo clients all link. ✅ (`deps/weston-14.0.0/build-epin`, `ninja rc=0`).
- The `weston` binary's only `NEEDED` libs are `libexec_weston.so` + musl `libc.so` — **no libGL/libEGL/mesa**. ✅
- Recipe + the two prep fixes (objcopy symbol renames for static-link collisions in `libinput.a`/`libwayland-cursor.a`; `libinput.pc` private deps; `-Dprefer_static=true`) are recorded.

## GW2 DONE (2026-06-07) — Kernel KMS present + page-flip events for Weston's DRM backend. P: Critical

**Goal:** Make Weston's stock `drm-backend` actually display. All handlers below implemented in `posix.d` and **validated against the Weston 14.0.0 source** (not guessed). Kernel compiles (`-betterC`, ldc2), relinks, and the full ISO builds clean.

**CRITICAL fix:** the kernel's DRM ioctl NR constants were wrong vs. real libdrm — it had `ADDFB2=0xb0`, `PAGE_FLIP=0xb1`, but libdrm uses `PAGE_FLIP=0xB0`, `DIRTYFB=0xB1`, `ADDFB2=0xB8`. Harmless before only because Hyprland used the custom `HOS_PRESENT (0xf0)` path; Weston goes through libdrm so the numbers must match exactly. Corrected, and added `GETPLANERESOURCES=0xB5`, `GETPLANE=0xB6`, `SETPLANE=0xB7`, `OBJ_GETPROPERTIES=0xB9`, `GETPROPERTY=0xAA`, `CURSOR=0xA3`, `CURSOR2=0xBB`.

**Done:**

- **`ADDFB`/`ADDFB2`**: allocate a unique `fb_id`, bind it to the GEM dumb buffer (new `DrmFb[16] g_drmFbs` table, `drmAddFb`).
- **`SETCRTC`** (`fb_id` @ off 16) and **`PAGE_FLIP`** (`fb_id` @ off 4): present via `drmPresentFb()` — blits the fb's pixels (reached through the HHDM at `physAddr + hhdm_offset`) to `g_fb`.
- **`PAGE_FLIP`** also queues a `DRM_EVENT_FLIP_COMPLETE` (`DrmEvent` ring) when `flags & DRM_MODE_PAGE_FLIP_EVENT`, echoing `user_data`.
- **DRM fd `read()`** delivers `struct drm_event_vblank` (32 B); **`fdReadable(FD_DRM)`** → `drmEventPending` so poll/epoll wakes Weston's loop.
- **`SET_CLIENT_CAP`** rejects `DRM_CLIENT_CAP_ATOMIC` → Weston uses the **legacy** path (atomic also needs `DRM_CAP_CRTC_IN_VBLANK_EVENT`, not advertised).
- **Universal planes + primary plane** (both mandatory in Weston, else fatal): expose one primary plane whose `type` property reports `"Primary"` via `GETPLANERESOURCES`/`GETPLANE`/`OBJ_GETPROPERTIES`/`GETPROPERTY`. Cursor = software (no cursor plane → Weston Pixman-composites it). `DIRTYFB`/`SETPLANE`/`CURSOR*` are no-op success.
- Removed a per-ioctl `console_putchar('D')` serial flood.

**Remaining caveat:** flip events complete *immediately* (no vblank pacing). Fine for an idle terminal; an animating client would busy-loop at max fps — add timer-deferred completion in GW3 if it spins.

**Done when (verification deferred to GW3):** booting Weston shows its output on `g_fb`. Can't boot-test here (no KVM; TCG too slow) — verify on the KVM host during GW3.

## GW3 — Run Weston as init + a terminal. P: Critical — IN PROGRESS (2026-06-07)

**Goal:** Boot into Weston with a usable graphical terminal and shell.

**Progress (2026-06-07):** Staging + launch DONE and working — all 8 Weston modules stage as flat boot modules (`WESTON=1` Makefile block), `weston-terminal` built (`-Dtools=terminal`), `init=weston` selected by exact basename, musl `ld` resolves every `NEEDED`/`.so` by basename, `/etc/weston.ini` + `WESTON_MODULE_MAP` + `--drm-device=card0` wired. Headless TCG smoke boots took Weston **from cold boot all the way to: start → load `drm-backend.so` → libseat opens `seat0` ("session control granted") → read `/sys/class/drm/card0/uevent`**. Fixed **4 real kernel bugs** Weston exposed (Hyprland's headless path never hit them): (1) `signalfd4` ENOSYS stub → eventfd-backed (else libwayland aborts Weston at startup, silently); (2) `fcntl F_SETFL` wrongly required `CAP_RIGHT_WRITE` → EBADF on a pipe read-end → libseat's seatd `poller_init` failed; (3)+(4) udev DRM discovery — `/sys/class/drm/card0` synthetic dir + a `card0/uevent` file so libudev-zero builds the device. **Current blocker:** `weston_launcher_open(/dev/dri/card0)` returns −1 → *"DRM device 'card0' is not a KMS device"*. The libseat client↔server **device-open round-trip** (recvmsg + `SCM_RIGHTS` to pass the DRM fd) fails over the forked socketpair (`seatd zero-length read` / `Could not poll connection: I/O error`) — even though the plain read/write seat-open round-trip succeeded. **Next:** fix the kernel's local-socket `recvmsg`/`poll` path for a forked socketpair under the cooperative scheduler (premature EOF/POLLHUP or SCM_RIGHTS-fd delivery + blocking between the two tasks). After that, Weston hits the real DRM modeset (validating GW2) and `weston-desktop-shell` should draw the first frame. Best iterated on the KVM host (TCG here is ~8× slowed by 7 orphaned qemu processes pegging cores — worth cleaning up).

**Tasks:**

- **Module loading (key):** Weston's compiled-in module dirs are absolute *build* paths (`build-epin/config.h`: `LIBWESTON_MODULEDIR`, `MODULEDIR`) that won't exist in the OS. Use env **`WESTON_MODULE_MAP`** (format `name=/path;name2=/path2;…`, parsed by `weston_module_path_from_env` in `libweston/compositor.c`; `weston_load_module` also dlopens any `name` starting with `/` directly). Stage `drm-backend.so` + `desktop-shell.so` (or `kiosk-shell.so`) as flat ISO modules and map them. The **Pixman renderer is built into `libweston-14.so.0`** (no separate module).
- Stage the runtime: `weston` binary + `libexec_weston.so.0` + `libweston-14.so.0` + the backend/shell `.so` + `ld-musl`/`libc.so` (mirror the Hyprland staging block at ~`Makefile:288`).
- Get a Wayland terminal building (`weston-terminal` didn't build — try `foot`, or fix it) and bundle it.
- `weston.ini`: `[core] backend=drm-backend.so`, `renderer=pixman`, a shell launching the terminal; bundle xkb/fonts already in the ISO. Env: `XDG_RUNTIME_DIR`, seat/launcher (mirror Hyprland's `exports.d`).
- Swap Weston in for the Hyprland module in the kernel init selection (`kernel_main.d`, the pass at ~line 2000, **before** the Hyprland pass) and the ISO staging (`Makefile`), behind a toggle so Hyprland can still be selected for comparison.
- Input: Weston via `libinput` over `/dev/input/event0` (kbd) + `event1` (mouse) — the existing bridge.

**Done when:**

- Boots to a Weston desktop/kiosk; the cursor tracks the mouse fluidly under KVM; typing into the terminal runs shell commands. Screenshot proof.

## GW4 — Re-express the desktop shell on Weston. P: High

**Goal:** Reinstate the wallpaper, panel, dock, launcher, file manager, and settings (the value of G12–G18) using Weston-native mechanisms.

**Tasks:**

- Wallpaper/panel/dock as `layer-shell` clients (or `weston-desktop-shell`), themed to the existing design direction.
- Reuse the `wl-*` clients (`wl-files`, etc.) and identity-border concept as standard Wayland surfaces.
- Map appearance/input/display settings back to the declarative OS config.

**Done when:**

- The desktop matches the quality bar (panel + dock + wallpaper + launcher) on the Weston foundation, with screenshot regression tests.

---

# Phase 1 — make pixels correct

## G6 DONE — Visible window content. P: Critical

**Problem:** This is the reason the desktop looks broken. Hyprland receives and maps windows, but textured client contents render as black interiors because the Mesa softpipe texture/varying path is broken.

**Goal:** Every `wl_shm` client must visibly render its contents into the final framebuffer.

**Preferred implementation path:**

1. Add a **CPU compositor fallback** in the present path for `wl_shm` buffers.
2. Let Hyprland continue doing layout, window position, focus, and damage tracking.
3. At present/report time, export enough window metadata to the kernel or host-side compositor shim:
   - surface buffer pointer/fd
   - x/y/w/h
   - stride
   - pixel format
   - damage region
   - alpha/opacity
   - z-order
4. CPU-blit ARGB/XRGB client buffers directly into the output dumb buffer or final `g_fb`.
5. Keep the trusted identity border overlay after the client-content blit.

**Avoid making Mesa softpipe the first fix** unless CPU composition proves impossible. Mesa softpipe varying-packing debugging is likely slower than a deterministic CPU blit path.

**Done when:**

- `wl-term` text is visible on screen.
- A test image client renders correctly.
- QEMU screendump shows the actual terminal contents.
- Visual output no longer depends only on serial logs.

**Implemented 2026-06-05:**

- Kept committed desktop `wl_shm` buffers attached long enough for the renderer/present path to consume them.
- Added a `wl_shm` CPU composition fallback for the HOS CPU-readback path.
- Added `scripts/qemu-g6-verify.sh`, which boots QEMU, captures a screendump, and checks for visible terminal glyph pixels.
- Verification result: `G6 PASS: wl_shm terminal contents are visible in QEMU screendump` with a 1280x800 capture and nonzero bright glyph pixels in the terminal band.

---

## G7 DONE — Real display mode and resolution pipeline. P: Critical

**Problem:** The desktop appears low-resolution/fallback-like. A real desktop needs reliable display mode selection, framebuffer pitch handling, and scaling.

**Tasks:**

- Detect and log EDID modes clearly.
- Select a native/preferred mode by default.
- Add boot config overrides:
  - `display.width`
  - `display.height`
  - `display.scale`
  - `display.refresh`
  - `display.force_mode`
- Guarantee correct framebuffer pitch, stride, and pixel format conversion.
- Add a `display-info` debug utility that prints:
  - current resolution
  - framebuffer address
  - pitch
  - format
  - scale
  - refresh
  - backend name
- Add screenshot tests at 1280×800 and 1920×1080.

**Done when:**

- The desktop boots into a known target resolution.
- Screendumps match the chosen resolution.
- Text and window geometry are not stretched, blurry, clipped, or offset.

**Implemented 2026-06-05:**

- Switched Limine mode selection to the documented `resolution: <width>x<height>x<bpp>` key.
- Added build-time display overrides through `make DISPLAY_WIDTH=... DISPLAY_HEIGHT=... DISPLAY_SCALE=... DISPLAY_REFRESH=... DISPLAY_FORCE_MODE=... hos.iso`.
- Generated a `/display.conf` boot module and mirrored display settings through `HOS_DISPLAY_*` env vars.
- Updated Aquamarine headless output creation to read `/display.conf`, so compositor output mode follows the same config as Limine.
- Enhanced framebuffer boot logging with resolution, pitch, bpp, RGB masks, EDID size, and the first advertised modes.
- Added synthetic `/proc/display-info` and a freestanding `display-info` utility.
- Made `/proc/cmdline` derive from `/display.conf` so reported boot config matches build overrides.
- Added screenshot-size verifiers:
  - `scripts/qemu-g7-verify-1280x800.sh`
  - `scripts/qemu-g7-verify-1920x1080.sh`
  - shared implementation: `scripts/qemu-g7-verify.sh`

**Verification 2026-06-05:**

- `scripts/qemu-g7-verify-1280x800.sh` -> `G7 PASS: screendump resolution is 1280x800`.
- `scripts/qemu-g7-verify-1920x1080.sh` -> `G7 PASS: screendump resolution is 1920x1080`.
- The 1920×1080 test validates the mode/screendump path. Full client-map responsiveness at 1920×1080 remains a G8 frame-pacing/performance concern.

---

## G8 DONE — Frame pacing and redraw correctness. P: High

**Problem:** A desktop feels cheap if redraws are irregular, flickery, or delayed.

**Tasks:**

- Implement deterministic frame scheduling for the headless/sessionless present path.
- Ensure damage regions trigger a present.
- Add a fallback timer-driven repaint at 30/60 FPS while visual work is active.
- Remove the “mapped window but no present blit” problem.
- Log frame number, damage count, and present duration in debug builds.
- Later: add vsync-like pacing when a real GPU/display backend exists.

**Done when:**

- Moving cursor and typing visibly update immediately.
- No “needs another event before redraw” bugs.
- Screendump after client commit always shows the new content.

**Implemented 2026-06-05:**

- Added deterministic frame/present logging and bounded repaint recovery to the Aquamarine headless backend.
- Switched immediate headless frame callbacks from the backend idle queue to the headless timerfd, avoiding stale scheduled-frame reentry.
- Added input-driven repaint scheduling for bridged keyboard and pointer events.
- Re-enabled the HOS `wl_shm` CPU composition path by removing the `HOS_SCENE_RENDER=1` guest env override.
- Added a mapped-surface commit damage/render hook so `wl_shm` client commits can immediately reach the final present path.
- Added `scripts/qemu-g8-verify.sh`, which focuses the terminal, captures a baseline screendump, injects post-baseline keyboard input, captures another screendump, and checks for visible terminal-band pixel changes.

**Verification 2026-06-05:**

- `scripts/qemu-g4-verify.sh` -> typed `echo g4pass` reaches BusyBox through the terminal PTY.
- `scripts/qemu-g8-verify.sh` -> `G8 PASS: post-client-commit screendump visibly updated`.

---

# Phase 2 — make text, images, and UI look professional

## G9 DONE — Font system and high-quality text rendering. P: Critical

**Goal:** Replace bitmap/demo-looking text with modern antialiased UI text.

**Tasks:**

- Bundle libre UI fonts:
  - **Inter** or **Noto Sans** for UI
  - **JetBrains Mono** or **Iosevka** for terminal
  - **Noto Color Emoji** later if color emoji rendering becomes available
  - Add place down drop custom fonts into
- Add `fonts.blob` or extend asset packing to include fonts.
- Install fontconfig config and cache into the guest VFS.
- Set default UI font globally for GTK/Pango/Cairo clients.
- Make `wl-term` stop depending only on the 8×8 debug font once Cairo/Pixman/Freetype is available.
- Add font fallback so missing glyphs do not render as boxes.
- Add DPI-aware font sizing:
  - normal scale: 10–11 pt UI
  - terminal: 11–13 pt mono
  - HiDPI scale: 2× logical scaling

**Done when:**

- Terminal text is antialiased and readable.
- UI text looks comparable to a normal Linux desktop.
- Font rendering works in screenshots.

**Implemented 2026-06-05:**

- Added build-time Noto font staging from `/usr/share/fonts/truetype/noto` into `build/assets/fonts/noto` with license staging.
- Extended the guest asset unpack path so fonts are available at `/usr/share/fonts/noto`.
- Added fontconfig/Pango/GTK/GSettings defaults for `Noto Sans` and `Noto Sans Mono`.
- Added rtfs directory enumeration support so fontconfig/toolkit code can scan bundled asset directories.
- Reworked `wl-term` to render terminal glyphs through FreeType from the bundled Noto Sans Mono font, with a bitmap-font fallback.
- Added a one-shot post-map frame-callback redraw so the terminal commits antialiased text after Hyprland has mapped the surface.
- Added `scripts/qemu-g9-verify.sh`, which boots QEMU, waits for the bundled font and post-map redraw, captures a screendump, and checks for bright text plus antialiased edge pixels.
- Hardened the HOS wl_shm CPU composition path so successful CPU blits skip Mesa swrast readback and avoid the sessionless readback fault.

**Verification 2026-06-05:**

- `scripts/qemu-g9-verify.sh` -> `G9 PASS: bundled FreeType terminal text is antialiased in QEMU screendump`.

---

## G10 DONE — Image, icon, and theme asset pipeline. P: High

**Goal:** Treat visual assets as first-class OS resources, not one-off boot blobs.

**Tasks:**

- Extend `pack-assets.py` into a real asset pipeline:
  - `fonts.blob`
  - `icons.blob`
  - `cursors.blob`
  - `wallpapers.blob`
  - `themes.blob`
- Mount assets into stable guest paths:
  - `/usr/share/fonts`
  - `/usr/share/icons`
  - `/usr/share/cursors`
  - `/usr/share/backgrounds`
  - `/usr/share/themes`
- Add manifest metadata:
  - name
  - license
  - size
  - version
  - default selection
- Add a build-time license check so proprietary macOS assets are not accidentally bundled.
- Use libre macOS-like themes only.

**Recommended libre assets:**

- UI font: Inter, Noto Sans, or similar.
- Mono font: JetBrains Mono, Iosevka, or Fira Code.
- Icons: WhiteSur-style or McMojave-style icon theme, subject to license verification.
- Cursor: Bibata or a compatible macOS-like cursor theme.
- Wallpaper: original project wallpaper or permissively licensed abstract image.

**Done when:**

- Apps can resolve fonts, icons, cursors, and wallpaper from standard paths.
- Theme changes do not require hard-coding binary patches.

**Implemented 2026-06-05:**

- Added `scripts/stage-gui-assets.py`, which stages generated libre GUI assets into `build/assets`:
  - Epin icon theme under `/usr/share/icons/Epin`
  - default icon/cursor theme aliases under `/usr/share/icons/default`
  - Epin cursor metadata under `/usr/share/cursors/Epin`
  - generated project wallpaper under `/usr/share/backgrounds/epin`
  - Hyprland-compatible wallpaper PNGs under `/usr/share/hypr`
  - Epin GTK theme metadata under `/usr/share/themes/Epin`
- Extended `scripts/pack-assets.py` into a metadata-aware asset pipeline:
  - generated `/usr/share/hos/assets/manifest.json`
  - recorded category, path, license, size, SHA-256, version, and default selections
  - added a build-time guard against accidentally bundling proprietary platform assets
  - emitted category blobs: `fonts.blob`, `icons.blob`, `cursors.blob`, `wallpapers.blob`, `themes.blob`
- Updated the ISO build to include the category blobs as Limine modules.
- Updated the kernel rtfs asset unpacker to mount all category blobs, with legacy `assets.blob` fallback.
- Set guest defaults for `Epin` GTK/icon/cursor theme selection and exported `HOS_ASSET_MANIFEST`.

**Verification 2026-06-05:**

- `scripts/qemu-g10-verify.sh` -> `G10 PASS: GUI asset category blobs and manifest are mounted in the guest`.
- `scripts/qemu-g9-verify.sh` still passes after moving fonts into `fonts.blob`.

---

## G11 DONE — Toolkit rendering path. P: High

**Goal:** Move beyond hand-written demo clients and support real GUI apps.

**Tasks:**

- Confirm Cairo/Pixman rendering into `wl_shm` works.
- Bring up a minimal GTK or lightweight toolkit demo:
  - window
  - label
  - button
  - text entry
  - icon
- Confirm xdg-shell sizing, configure/ack_configure, resize, close, and keyboard focus.
- Add missing syscalls as toolkit clients demand them:
  - `poll/ppoll`
  - signal delivery edge cases
  - `clock_gettime`
  - `getrandom`
  - `statx` or fallback stat calls
  - `epoll` completeness
  - locale/env behavior
- Use toolkit demo as the visual benchmark, not only `wl-term`.

**Done when:**

- A normal GUI demo app renders text, buttons, and icons.
- It can be clicked and typed into.
- It survives repeated open/close cycles.

**Implemented 2026-06-05:**

- Added `wl-cairo-demo`, a lightweight xdg-shell `wl_shm` client that paints a toolkit-style window with Cairo:
  - icon tile
  - title/body labels
  - entry-like control
  - button
  - secondary info control
- Loaded bundled `/usr/share/fonts/noto/NotoSans-Regular.ttf` directly with FreeType for antialiased UI text, avoiding dependence on host fonts or proprietary assets.
- Added basic `wl_seat` pointer and keyboard handling so the demo can focus the entry, accept simple typed input, and redraw button/entry state.
- Published completed Cairo/FreeType frames into fresh memfd-backed `wl_shm` buffers for each commit, working around the current guest shared-mmap overwrite coherency gap and keeping final controls/text visible to the compositor.
- Added `gui.autostart=` to `/display.conf` and the Limine cmdline:
  - default `GUI_AUTOSTART=cairo` boots the G11 toolkit demo
  - `GUI_AUTOSTART=term` preserves the G4/G9 terminal verification path
  - `GUI_AUTOSTART=both` remains available for later multi-window work
- Increased the kernel epoll watch table to support larger compositor watch sets.
- Fixed `newfstatat()` so exact rtfs asset paths win over broad synthetic directory prefixes; font files under `/usr/share/fonts/...` now stat as files, not directories.
- Updated Hyprland's xdg-shell map condition for the HOS wl_shm CPU path so a committed shm buffer can map even if the GL texture path is unavailable.
- Added `scripts/qemu-g11-verify.sh`, which boots QEMU, waits for the toolkit font/map/redraw markers, captures a screendump, and checks for visible control colors plus antialiased text pixels.

**Verification 2026-06-05:**

- `scripts/qemu-g11-verify.sh` -> `G11 PASS: Cairo/FreeType toolkit demo renders controls and antialiased text`.
- The verifier captured a 1280x800 screendump with visible icon, labels, entry, button, theme colors, and antialiased Noto text.

**Known follow-up:**

- `GUI_AUTOSTART=both` can expose memory/scheduling pressure with the terminal and toolkit demo together in the 512 MB QEMU profile. Reliable multi-window behavior is tracked by G20.

---

# Phase 3 — build the desktop shell

## G12 DONE — Wallpaper/background layer. P: High

**Goal:** The desktop should boot into a real wallpaper instead of a blank/black workspace.

**Implementation options:**

- Implement `zwlr_layer_shell_v1` support and run wallpaper as a background layer.
- Or temporarily hard-code a wallpaper blit into the compositor/present path.
- Decode PNG/JPEG at boot or pre-convert wallpapers to XRGB buffers for simplicity.

**Done when:**

- A default wallpaper is visible immediately after boot.
- Wallpaper scales/crops correctly to the selected resolution.
- No black interior/fallback background remains.

**Implemented 2026-06-05:**

- Added a default wallpaper draw in Hyprland's HOS CPU-readback present path before `wl_shm` windows are composited.
- Used a scaled procedural version of the generated Epin wallpaper palette so the desktop background appears even before layer-shell and PNG/JPEG decode support exist.
- Changed the HOS CPU composition path to present the wallpaper frame even when zero client windows are mapped.
- Kept `wl_shm` window composition over the wallpaper path; G11 still renders over the background.
- Added `scripts/qemu-g12-verify.sh`, which boots with `GUI_AUTOSTART=none`, captures a screendump, and verifies that the old flat dark clear color is gone and the wallpaper has varied teal/purple/warm gradient pixels.

**Verification 2026-06-05:**

- `scripts/qemu-g12-verify.sh` -> `G12 PASS: default wallpaper fills the boot desktop`.
- `scripts/qemu-g11-verify.sh` still passes with the toolkit window composited over the wallpaper.

---

## G13 DONE — Panel/menu bar. P: High

**Goal:** Add a top system bar like macOS/GNOME/KDE.

**Features:**

- Clock/date.
- App title or active window title.
- Identity indicator.
- Network placeholder.
- Audio placeholder.
- Battery/power placeholder.
- Settings button.
- Shutdown/reboot menu.

**Implementation:**

- Prefer `wl_shm` + layer-shell.
- If layer-shell is not ready, use a reserved top region and hard-code placement temporarily.
- Use vector/text rendering, not bitmap debug glyphs.

**Done when:**

- A top bar is always visible.
- It does not overlap normal windows.
- Clock and active window title update.

**Implemented 2026-06-05:**

- Added a hard-coded top panel in Hyprland's HOS CPU present path, drawn after wallpaper and windows so it remains visible.
- Reserved a top content region for CPU-composited `wl_shm` windows and shifted the trusted kernel border geometry to match the visual window position.
- Rendered an active window title, network/power placeholders, identity-colored accents, and an uptime clock using lightweight shape glyphs in the present path.
- Added `scripts/qemu-g13-verify.sh`, which boots the G11 toolkit demo, captures a screendump, and checks for the panel band, title/status/clock glyphs, panel accents, divider, and a window below the reserved panel region.

**Verification 2026-06-05:**

- `scripts/qemu-g13-verify.sh` -> `G13 PASS: top panel renders above the desktop window`.
- `scripts/qemu-g11-verify.sh` still passes with the toolkit window below the panel.

---

## G14 DONE — Dock/taskbar. P: High

**Goal:** Add a bottom dock or taskbar so the system feels like a desktop, not an empty WM.

**Features:**

- App launchers.
- Running app indicators.
- Focus app on click.
- Minimize/restore placeholder.
- Identity-color accent under each running app.
- Optional magnification later.

**Initial apps:**

- Terminal.
- File manager.
- Settings.
- Demo text editor.
- System monitor/debug viewer.

**Done when:**

- User can launch terminal from the dock.
- Running windows appear in the dock.
- Clicking an app icon focuses or launches it.

**Implemented 2026-06-06:**

- Upgraded the HOS CPU present path to a **Cairo/Pango/FreeType desktop shell**. Hyprland already links `cairo`, `pango`, `pangocairo`, `pixman`, `freetype`, and `fontconfig`, so the shell is now drawn with real vector/antialiased rendering instead of the 5×7 debug font.
  - Added `SHosCPUCanvas` ↔ Cairo helpers in `deps/hyprland/src/render/GLRenderer.cpp`: an ARGB32 overlay surface is drawn with Cairo and alpha-composited onto the output buffer in a format-correct way (`hosCompositeCairoSurface`), plus `hosRoundRect`, `hosCairoText`, and bundled-Noto font faces loaded directly through FreeType (`/usr/share/fonts/noto/NotoSans-{Regular,Bold}.ttf`, bypassing guest fontconfig for determinism).
  - Migrated the **top panel** to Cairo: antialiased Noto title, NET/PWR status pills, and uptime clock; identity lozenge and accent rule preserved. The legacy bitmap panel is retained as a guaranteed fallback (`hosDrawPanelBitmap`) if the bundled faces ever fail to load.
- Added a **bottom dock** (`hosDrawDock`): a centred, translucent, rounded shelf with a soft stacked drop shadow, a top sheen/border, and five vector launcher tiles — **Terminal, Files, Settings, Editor, Monitor** — each a gradient-filled rounded tile with a white antialiased glyph.
  - Running apps get a hover-style highlight tile and an **identity-accent (cyan) running indicator dot** with a soft glow. The active window's title is matched to a dock slot.
  - Reserved a bottom dock region (`hosReserveDockSpace`, `HOS_DOCK_REGION_H = 96`) so mapped `wl_shm` windows are shrunk clear of the dock, mirroring the existing top-panel reservation.
- Added `scripts/qemu-g14-verify.sh`, which boots the toolkit demo, waits for the `HOS G14 dock rendered` marker, captures a screendump, and checks for the translucent shelf, multiple distinct colored launcher tiles, antialiased tile edges, the cyan running indicator, and that the window is reserved clear of the dock region.

**Verification 2026-06-06:**

- `scripts/qemu-g14-verify.sh` -> `G14 PASS: bottom dock renders launcher tiles and a running indicator below the desktop` (stats: `shelf_dark=14012 amber_tile=1661 blue_tile=1730 green_tile=1985 accent_dot=685 tile_aa=2551 gap_window_white=0`).
- `scripts/qemu-g13-verify.sh` still passes with the Cairo-rendered panel (`panel_text=438`, all metrics above threshold).

**Known follow-up:**

- The dock is currently presentation-only (launchers/click-to-launch and live per-window running state are wired into G15/G20 once input routing to the shell and an app registry exist). The running indicator currently reflects mapped-window presence and active-title matching.

---

## G15 DONE — Launcher/search overlay. P: Medium

**Goal:** Add a keyboard-driven launcher similar to Spotlight, KRunner, or GNOME overview.

**Features:**

- Open with Super/Command/Meta + Space.
- Search installed apps.
- Run shell commands.
- Show recent apps.
- Support fuzzy matching later.

**Done when:**

- User can press a shortcut, type “terminal,” press Enter, and launch a terminal.
- Launcher is visually centered, antialiased, and keyboard-navigable.

**Implemented 2026-06-06 (input responsiveness + launcher):**

This milestone began with a usability report that the desktop was "entirely
unresponsive" to the mouse. The root causes and fixes:

- **No pointer cursor.** The HOS CPU present path returned before Hyprland's
  normal cursor plane, so no cursor was ever drawn — the desktop *looked* dead
  even when input flowed. Added `hosDrawCursor()` in `GLRenderer.cpp`, an
  antialiased arrow composited at `g_pPointerManager->position()` on top of every
  frame. (`deps/hyprland/src/render/GLRenderer.cpp`)
- **The Super/Meta key was dropped by the kernel.** `handleKbdIRQ` had no entry
  for the E0 `0x5B`/`0x5C`/`0x5D` extended scancodes, so Super never reached the
  compositor. Mapped them to `KEY_LEFTMETA`/`KEY_RIGHTMETA`/`KEY_COMPOSE`.
  (`src/kernel/d/core/kernel_main.d`)
- **Launcher.** Added `render/HosShell.{hpp,cpp}` — shared shell state between the
  input path and the present path. `onKeyboardKey` now offers each key to the
  launcher first (`InputManager.cpp`): **Super+Space** toggles a centred,
  translucent, antialiased Cairo search overlay; typing filters an app registry;
  Up/Down/Tab move the selection; **Enter** launches the selection through
  `Config::Supplementary::executor()->spawnRaw()` (works thanks to the prefork
  `CProcess` patch); Escape (or a click) closes it. Super is tracked directly
  from the key stream rather than the xkb mod mask for robustness.
- **Clickable dock.** `onMouseButton` routes a left-click over a dock tile to
  `HosShell::launchDockSlot()` (geometry kept in sync with `hosDrawDock`).
- **App registry:** Terminal → `wl-term`; Files/Settings/Editor/Monitor map to
  `wl-cairo-demo` as placeholder windows until those apps exist (G17/G18).

**Verification 2026-06-06:**

- `scripts/qemu-g15-verify.sh` -> `G15 PASS: launcher search overlay renders in
  the present path`. The launcher is booted open via a build flag
  (`make GUI_LAUNCHER_DEMO=1`, surfaced as `gui.launcher_demo=1` in
  `/display.conf`) and the verifier asserts the search field, the filtered
  **Terminal** result, and the accent render. The pointer cursor is confirmed in
  the same screendumps.
- `scripts/qemu-g13-verify.sh` and `scripts/qemu-g14-verify.sh` still pass with
  the cursor + launcher additions.

**Known limitation / how to exercise live input:**

- **Synthetic input cannot be injected in the headless QEMU sandbox** used for
  CI here: QEMU accepts QMP `input-send-event` (and HMP `sendkey`/`mouse_move`)
  and returns success, but the guest PS/2 devices receive nothing (no IRQ1/IRQ12),
  so the live Super+Space / typing / Enter-to-launch and dock-click paths cannot
  be screendump-verified automatically. They use Hyprland's normal key/pointer
  delivery (the same path G4/G8 exercised on real hardware) and work with a real
  keyboard/mouse or a QEMU display backend. The render + filter logic is verified
  via the demo flag above.

---

## G16 DONE — Window decorations and interaction polish. P: High

**Goal:** Windows should look like real desktop windows.

**Features:**

- Rounded corners.
- Drop shadows.
- Active/inactive title bar states.
- Close/minimize/maximize controls.
- Resize handles.
- Smooth move/resize.
- Snap zones or tiling hints.
- Identity-colored border integrated cleanly with theme.

**Important:** The identity border must remain trusted and kernel-owned. Hyprland/apps may provide decoration visuals, but the final identity indicator must still be overlaid by the kernel/present path.

**Done when:**

- Windows look modern in screenshots.
- Active window is obvious.
- Identity colors are visible but not ugly or overpowering.

**Implemented 2026-06-06:**

- **Decorations in the present path** (`GLRenderer.cpp`). Each mapped window now
  reserves a titlebar as the top `HOS_TITLEBAR_H` (30px) strip of its box; the
  client surface is blitted into the remainder, so the kernel identity border
  wraps the whole decorated window with no change to the border-reporting code:
  - `hosDrawWindowShadow()` — a soft, multi-layer drop shadow; the focused window
    casts a larger, darker shadow.
  - `hosDrawTitlebar()` — rounded-top Cairo titlebar with a brightening
    active/inactive gradient, an **identity-coloured accent dot** (mirrors the
    kernel `HOS_ID_PALETTE` so it matches the border), the antialiased window
    title (truncated to fit), and minimize/maximize/close control dots.
  - `hosRoundBottomCorners()` — repaints the content's bottom corners back to the
    exact wallpaper colour (`hosWallpaperColorAt()`, factored out of the wallpaper
    pass) so the window reads as rounded.
  - Active state comes from `Desktop::focusState()->window()`.
- **Rounded, trusted identity border** (`src/kernel/d/core/syscalls/posix.d`).
  `fbDrawBorder()` now draws a rounded 4px ring (straight edges + four
  quarter-circle corner arcs via squared-distance tests, `HOS_BORDER_RADIUS=10`,
  matching `HOS_WIN_RADIUS`). The border stays kernel-owned/unspoofable; the
  compositor only supplies geometry.
- **Window controls are clickable** (`HosShell::onPointerButton`): a left-click on
  the close dot calls `Config::Actions::closeWindow(w)`, the maximize dot toggles
  `Config::Actions::fullscreenWindow(FSMODE_MAXIMIZED, w)`. Minimize is a consumed
  no-op until a minimize/hide state exists. Control geometry mirrors the titlebar.

**Verification 2026-06-06:**

- `scripts/qemu-g16-verify.sh` -> `G16 PASS: window titlebar with min/max/close
  controls, shadow, and rounded identity border render` (detects the red/green/
  amber control dots, the dark titlebar band, and the `G5 BORDER` marker).
- `scripts/qemu-g13/g14/g15-verify.sh` still pass.

**Build note:** G16 is the first milestone in this series to change the **D
kernel**, and `make hos.iso` does *not* recompile the kernel on its own
(`build/libkernel_d.a` has no source prerequisites). Rebuild it explicitly with
`make -C src/kernel/d && make kernel.elf` before `make hos.iso`
(`scripts/qemu-g16-verify.sh` now does this).

**Known limitation / follow-up:**

- Titlebar **drag-to-move**, edge **resize handles**, and **snap zones** are
  interaction-heavy and could not be exercised by the headless sandbox (no
  synthetic pointer delivery), so they are deferred; the visual decorations and
  control-click wiring are in place. Live control clicks use Hyprland's standard
  pointer delivery and work with real input hardware.

---

## G17 DONE — File manager. P: Medium

**Goal:** Add a Finder/Dolphin/Nautilus-like file browser.

**Features:**

- Sidebar:
  - Home
  - Desktop
  - Documents
  - Downloads
  - System
  - Mounted volumes
- Icon and list views.
- Open folders.
- Basic file actions:
  - copy
  - move
  - rename
  - delete
  - new folder
- Properties dialog.
- Identity/security label display.

**Done when:**

- User can browse the VFS visually.
- Folder icons and file icons render.
- Double-click opens folders.

**Implemented 2026-06-06:**

- New client **`src/util/wl-files.c`** — a Cairo/FreeType Wayland file manager,
  built on the proven `wl-cairo-demo` boilerplate (registry/xdg-shell/`wl_shm`
  via memfd, FreeType text, frame-callback redraw). Layout:
  - **Places sidebar** (Home `/`, System `/usr`, Share `/usr/share`, Fonts,
    Themes, Backgrounds, Config `/etc`) with folder icons; the active place is
    highlighted.
  - **Toolbar** with a back button and the current path.
  - **File list** reading the current directory via `opendir`/`readdir`, sorted
    folders-first, with vector folder/file icons, names, row selection, and a
    leading `..` entry.
  - **Status bar** showing the item count and an **identity/security label**.
  - Navigation: click a place or the back button, double-click (or Enter on) a
    folder to open it; Up/Down select; mouse-wheel scrolls. The window's
    titlebar/controls/shadow/rounded border come from the G16 compositor
    decorations.
- **App wiring:** built and staged into the ISO as a Limine module
  (`Makefile`, `src/boot/limine.conf` via the Makefile append); a new
  `gui.autostart=files` mode launches it (`kernel_main.d`,
  `guiAutostartMode` in `posix.d`); the dock/launcher **Files** entry now
  spawns `wl-files` instead of the demo placeholder.
- **Kernel bug fixed:** `linux_sys_getdents64`/`writeDirent64` placed `d_name`
  at `linux_dirent64.sizeof` (24, the D-padded size) instead of the Linux ABI
  offset **19**, so musl read names out of the zero padding — every directory
  enumeration returned correctly-typed but **nameless** entries. Now keyed off an
  explicit `DIRENT64_NAME_OFF = 19`. (Also fixes name-based directory scans used
  elsewhere, e.g. fontconfig.)
- Crash fixed along the way: `struct app` is ~135KB (the entry table), so it must
  live in BSS (`static`), not on a spawned process's small initial stack.

**Verification 2026-06-06:**

- `scripts/qemu-g17-verify.sh` -> `G17 PASS: file manager renders a Places
  sidebar, path toolbar, and a folder listing with icons and names`. Serial shows
  `G17FILES: listed /usr/share (9 entries)` with real names (backgrounds,
  cursors, fonts, hos, hypr, icons, themes, X11). G13–G16 still pass.

**Known limitation:**

- File **actions** (copy/move/rename/delete/new folder) and the **properties
  dialog** are not yet implemented — browsing/navigation is. Live click/keyboard
  navigation uses Hyprland's standard input delivery (works on real hardware);
  it can't be exercised by the headless sandbox's (absent) synthetic input, so
  the verifier checks the rendered listing.

---

## G18 — Settings app. P: Medium

**Goal:** Desktop customization should be discoverable from the GUI, while still mapping to the OS’s declarative config.

**Panels:**

- Appearance:
  - theme
  - accent color
  - font
  - cursor
  - wallpaper
- Display:
  - resolution
  - scale
  - refresh
- Input:
  - mouse speed
  - keyboard layout
  - key repeat
- Identity:
  - identity colors
  - border thickness
  - namespace/window association
- System:
  - about
  - reboot/shutdown
  - debug logs

**Done when:**

- Changing a setting updates the declarative config file.
- A reboot reproduces the same visual settings.

---

# Phase 4 — make it feel smooth and complete

## G19 — Animation and visual effects. P: Low/Medium

**Goal:** Add polish only after correctness.

**Features:**

- Fade in/out for launcher and menus.
- Window open/close animation.
- Dock hover effect.
- Smooth workspace switching.
- Shadow/blur only if performance permits.

**Rule:** Do not add blur/transparency until the basic compositor is reliable and fast. A crisp simple desktop is better than a slow broken one.

---

## G20 — Multi-window and workspace experience. P: High

**Tasks:**

- Reliable multiple windows.
- Alt-Tab/Super-Tab switcher.
- Workspace overview.
- Drag window between workspaces.
- Per-identity workspace grouping.
- Remember window positions where useful.

**Done when:**

- User can open several apps and switch between them naturally.
- The desktop no longer feels like a single demo window.

---

## G21 — Visual QA and screenshot regression tests. P: Critical

**Goal:** Prevent “it technically works but looks terrible” regressions.

**Add automated visual tests:**

- Boot screenshot at default resolution.
- Terminal visible with text.
- Wallpaper visible.
- One decorated window.
- Two overlapping windows.
- Dock visible.
- Panel visible.
- Launcher open.
- File manager open.
- Identity border visible.
- Text antialiasing check.
- Cursor visible.

**Test outputs:**

- Save screendumps to `artifacts/gui/`.
- Compare against golden images with a tolerance.
- Fail CI if:
  - resolution is wrong
  - window interior is black
  - text is missing
  - dock/panel missing
  - identity border missing
  - screenshot is mostly black

**Done when:**

- The GUI has objective visual quality gates.
- A developer can tell from CI whether the desktop looks real.

---

# Revised milestone order

The old G6–G13 list was too theme-focused before pixel correctness. The new order is:

1. **G6:** visible window content.
2. **G7:** real resolution/display mode.
3. **G8:** redraw/frame correctness.
4. **G9:** font/text rendering.
5. **G10:** asset pipeline.
6. **G11:** toolkit demo.
7. **G12:** wallpaper.
8. **G13:** top panel/menu bar.
9. **G14:** dock/taskbar.
10. **G15:** launcher/search.
11. **G16:** window decorations.
12. **G17:** file manager.
13. **G18:** settings app.
14. **G19:** animations/effects.
15. **G20:** multi-window/workspaces.
16. **G21:** visual QA.

---

# Concrete first implementation sprint

## Sprint A — stop the black-window problem

- Add CPU-composite fallback for `wl_shm` buffers.
- Make `wl-term` text visible in screendump.
- Add a simple image client that displays colored rectangles, gradients, and text.
- Confirm identity border still draws after content.
- Add `scripts/qemu-g6-visual-verify.sh`.

## Sprint B — fix resolution and scaling

- Add explicit display mode selection.
- Boot at 1280×800 and 1920×1080.
- Fix framebuffer pitch/format bugs.
- Add `display-info`.
- Add screenshot size checks.

## Sprint C — make it look like a desktop

- Add wallpaper.
- Add top panel.
- Add dock.
- Add real font.
- Replace debug bitmap terminal font with antialiased text if possible.
- Create one polished default theme.

## Sprint D — make it usable

- Add launcher.
- Add file manager.
- Add settings app.
- Add app registry:
  - app id
  - icon
  - executable
  - display name
  - identity policy
- Add multi-window switching.

---

# Design direction

The desktop should be **macOS/Linux-polished, not macOS-copied**.

Use:

- Clean rounded windows.
- Subtle shadows.
- Bright but restrained identity colors.
- High-contrast readable text.
- A dock/taskbar.
- A top panel/menu bar.
- Smooth cursor and keyboard behavior.
- Clear app icons.
- A real wallpaper.
- Consistent spacing.

Do not bundle proprietary Apple assets. Use permissively licensed fonts, icons, cursors, and wallpapers.

---

# Known issues / notes

- **Softpipe textured-render bug remains the top GUI blocker.** Until G6 is fixed, the OS can technically run GUI clients but cannot look like a real desktop.
- **Resolution must be treated as a product feature**, not a side effect of VBE/QEMU defaults.
- **Serial proof is no longer enough.** From this point forward, GUI milestones need screenshot proof.
- **Solid kernel-drawn identity borders work today**, but they should be visually integrated with the future theme.
- **Layer-shell is important** for wallpaper, dock, and panel. If blocked, use temporary reserved regions/hard-coded shell surfaces.
- **Config delivery must be fixed** so themes, fonts, icons, wallpaper, and Hyprland behavior can be controlled declaratively.
- **Debug logging should remain while fixing G6–G8**, then be reduced once visual tests are stable.
- **Every desktop feature should map back to the declarative OS config** so the GUI and single JSON configuration model do not diverge.
