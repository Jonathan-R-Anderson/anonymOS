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
