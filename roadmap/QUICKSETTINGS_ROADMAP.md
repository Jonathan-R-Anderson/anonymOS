# Quick Settings Panel Roadmap (GNOME-45 / Ubuntu-24.04 style, native to AnonymOS)

Turn the existing `src/util/wl-quicksettings.c` (320×472 `wl_shm` + FreeType card: WiFi row →
`wl-wifi-menu`, cosmetic volume slider, battery row, power/session action buttons via
`/run/session.action`) into a modern domain-aware Quick Settings panel.

## Guiding principles (honesty about the stack)
- **Toolkit is real, not aspirational:** `wl_shm` double-buffered buffers + FreeType, optionally cairo
  (as `wl-installer`/`wl-files` link it), + the kernel overlay cursor. No GTK/Qt/Electron. Compositor is
  **Weston + Pixman (software)**; virgl GPU is optional, not the desktop default.
- **The panel is ~10% of the work; providers are ~90%.** A tile is a *view over a backend*. On AnonymOS
  today most backends do not exist. A control that toggles nothing is worse than an honest "unavailable"
  tile. So we wire providers ONLY where a backend exists, and build new backends as their own subprojects.
- **Capabilities are the real model:** `DEVCLASS_*` device-class gates (`identity.d`) + object-tree
  `/objects` views + `/run` control files — NOT an invented `CAP_AUDIO_CONTROL` ACL. Each provider is
  "capable" by being allowed to touch a device class or write a control file.
- **Buildable increments only.** No dumping speculative files that don't compile against real APIs.

## Provider inventory (ground truth as of 2026-07)
| Tile group        | Backend today                                   | Status |
|-------------------|-------------------------------------------------|--------|
| WiFi              | `/run/wifi/*`, direct-wpa stack, `wl-wifi-menu` | LIVE   |
| Power / session   | `/run/session.action`, kernel `reboot(2)`       | LIVE   |
| Domain / Identity | Domain Manager objects, `identity.d`            | LIVE (needs a read path) |
| CPU / Mem / IP    | `/proc`, `/run/wifi/dhcp-ok` (`wl-sysmon` reads)| LIVE   |
| Clock / Calendar  | `wl-calendar`                                   | LIVE   |
| Volume / Mic      | none (no audio mixer)                            | COSMETIC → needs backend |
| Brightness/Display| none (no DRM backlight/mode control wired)       | COSMETIC → needs backend |
| Battery / Power-profile | none (AC under VM)                        | COSMETIC → needs backend |
| Bluetooth         | none (no BT stack)                              | MISSING subsystem |
| Media / album-art | none (no MPRIS/player)                          | MISSING subsystem |
| GPU / temp sensors| none                                            | MISSING subsystem |
| VPN / Tor / I2P   | I2P is roadmap DM12 (unbuilt)                    | MISSING subsystem |
| Notifications     | check for a notification daemon (likely none)    | MISSING subsystem |

## Reality gaps in the spec → realistic equivalent
- Glassmorphism / blur-behind → **flat translucent card** (alpha) + rounded corners + soft shadow (cairo).
  Real blur needs a GPU compositor pass that doesn't exist on Pixman.
- GPU spring physics @ 60–240 FPS → smooth **ease** transitions via frame-callback redraws. No physics
  engine; virgl is optional.
- Screen reader API, HDR → each a large independent subsystem; explicitly out of scope for v1.

---

## Phases

### Phase Q0 — Foundation & honest scaffold (buildable with existing primitives)
- **Q0.1** This roadmap + provider inventory. **[DONE]**
- **Q0.2** Panel shell restructure in `wl-quicksettings.c`: add a **header** (avatar block + username +
  current domain + current identity), a **tile grid** for connectivity, section headers, and honest
  "unavailable" styling for backend-less tiles. Uses existing `fill_rect`/`draw_text` (no new link dep) so
  it keeps compiling. Grow `WIN_H`, keep the renderer and hit-tester in lockstep.
- **Q0.3** Read paths for the header: current domain/identity/user from a `/run/*` or `/objects` source if
  present; graceful placeholders otherwise (real source wired in Q2.3). Object-tree: publish
  `/desktop/quicksettings` state + `/run/quicksettings.state`.

### Phase Q1 — Visual fidelity (needs build-test loop)
- **Q1.1** Move the renderer to **cairo** (rounded translucent card, soft shadow, rounded tiles, real icon
  glyphs) — add cairo to this client's link flags, mirroring `wl-installer`. Keep `wl_shm` present path.
- **Q1.2** Animation: slide-down + fade on open via frame callbacks; hover-scale + press states; smooth
  slider drag; optional ripple. Respect a `reduced_motion` config.
- **Q1.3** Declarative config `/config/quicksettings.json` (animation_speed, blur[→translucency],
  corner_radius, transparency, panel_width, icon_size, tile_spacing) with live reload.

### Phase Q2 — Wire the LIVE providers for real
- **Q2.1** WiFi provider: state (on/off, SSID, signal) from `/run/wifi/networks`; tile toggle; subpanel =
  fork `wl-wifi-menu`. (Partly exists.)
- **Q2.2** Power/session provider: Lock / Suspend / Restart / Power Off / Log Out / Switch User via
  `/run/session.action` (+ confirm dialogs).
- **Q2.3** Domain/Identity provider: current domain + identity, **switch domain** (fork
  `wl-domain-manager` or write a control file), show capability set + active containers/sandbox state.
  This is the AnonymOS-unique differentiator.
- **Q2.4** System stats provider: CPU / Mem / IP / net-speed from `/proc` + `/run/wifi`; virtualized lists;
  cached.
- **Q2.5** Ethernet / connectivity status row.

### Phase Q3 — New backends (each its own subproject, behind a device-class gate)
- **Q3.1** Audio mixer backend → Volume / Mic / output+input device / app mixer tiles.
- **Q3.2** Display backend: DRM backlight brightness + Night Light (gamma) + Dark Mode + Refresh Rate +
  external-display arrangement.
- **Q3.3** Notification Center: notification daemon + protocol + DND + history + per-app controls.
- **Q3.4** Battery / power-profile backend (real hardware): percentage, health, remaining time, profiles.

### Phase Q4 — Aspirational (gated on the underlying subsystem existing)
- Bluetooth stack, MPRIS media + album art, GPU/temp sensors, Tor/I2P status (DM12), plugin SDK
  (tile/icon/priority/callbacks/permissions), accessibility (screen reader, high-contrast, large-text,
  reduced-motion), full multi-monitor, HDR.

## Cross-cutting
- **Object tree:** one node per provider under `/desktop/quicksettings/{network,power,domain,audio,...}`
  exposing properties + events, once each provider is live.
- **Capabilities:** provider→device-class map documented as it lands (DEVCLASS_NET, DEVCLASS_DISPLAY, …).
- **Tests/docs:** per-provider state snapshot tests; a rendering smoke test; config-schema doc; plugin SDK
  doc — added alongside each phase, not upfront.

## Status
- Q0.1 DONE.
- Q0.2 AUTHORED (pending build): identity header (avatar + username + current domain + current identity);
  window 472→536, content grid shifted; `load_identity()` reads optional
  `/run/{session.user,domain.current,identity.current}` markers with graceful fallbacks. Header is
  display-only for now (switch-domain/user become clickable in Q2.3).
- Q0.3 AUTHORED (pending build): `publish_state()` writes `/run/quicksettings.state`
  (user/domain/identity/wifi/ssid/volume) at startup + on refresh — userspace half of the
  `/objects/desktop/quicksettings` view (kernel `/objects` node is the follow-up).
- Q1 (partial) AUTHORED (pending build): `fill_round_rect()` primitive + rounded tiles on every row/button
  and a **circular avatar** — the GNOME rounded-tile look within the existing `wl_shm` toolkit (no new
  link deps). DEFERRED to a build loop: the true cairo swap (anti-aliased curves + translucent card +
  soft shadow) because it also changes Makefile link flags + buffer format + compositor alpha, which
  can't be verified blind.
- Q2.4 AUTHORED (pending build): live **System** row (replaces the inert Hyprland top-bar toggle) —
  `load_stats()` reads CPU% (delta from `/proc/stat`), RAM% (`/proc/meminfo`), and IP (`/run/wifi/dhcp-ok`);
  refreshed every ~1s; click opens `/wl-sysmon`. Removed the dead `topbar_hidden/topbar_toggle`. Stats
  also flow into `/run/quicksettings.state`.
- ⚠️ BUILD CHECKPOINT DUE: Q0.2 + Q0.3 + Q1(rounded) + Q2.4 are a coherent batch but ALL unbuilt (session
  classifier blocks `make` for the agent). Build-verify this batch BEFORE the cairo work (Q1.1), since
  cairo is the one change that also touches Makefile link flags + buffer format and shouldn't be stacked
  on an unverified base.
- NEXT (with a compile loop): Q1.1 cairo (AA + translucent card), Q1.2 animation, Q2.3 live Domain
  Manager source + switch-domain, Q2.2 add Suspend/Switch-User actions.
- NOTE: builds are currently blocked in-session by the safety classifier; code is authored here and built
  by the user (`make <WLQUICKSET target>` then the ISO). Each phase is verified in the VBox repro loop.
