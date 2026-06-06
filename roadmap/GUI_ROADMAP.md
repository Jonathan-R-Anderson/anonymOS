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

These are the correct low-level primitives. The next work should make them visually convincing.

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

## G14 — Dock/taskbar. P: High

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

---

## G15 — Launcher/search overlay. P: Medium

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

---

## G16 — Window decorations and interaction polish. P: High

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

---

## G17 — File manager. P: Medium

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
