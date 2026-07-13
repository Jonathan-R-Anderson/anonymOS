I have verified the load-bearing anchors. Producing the plan.

---

# EpinAnonymOS Weston Desktop — Implementation Plan (panel fix, tiling WM, GNOME bar)

Verified against source: `deps/weston-14.0.0/clients/desktop-shell.c` (panel client), `deps/weston-14.0.0/desktop-shell/shell.c` + `shell.h` (compositor plugin), `src/util/wl-*.c` + `wl-deco.h` (app clients), `src/desktop.conf`, kernel `posix.d`/`kernel_main.d`.

---

## A. PANEL BUG — /wl-quicksettings won't launch

### Root cause (confirmed)
`epin_popover_toggle` (`clients/desktop-shell.c:331-351`) decides "my popover is already open" with `epin_popovers[i].pid > 0 && kill(pid,0)==0` (lines **339-340**). `kill(pid,0)==0` only proves *some* task owns that pid, not that it is *our* popover. The slot is cleared only by `epin_popover_reaped` (**321-329**), which runs only from `sigchild_handler` (**180-192**), and SIGCHLD on this kernel is delivered only at the next blocking read (memory: wifi-dropdown-menu). So:

1. Click → spawn, slot pid = P, stored at line **346**.
2. User closes the popover itself; task P exits but is not yet reaped.
3. This kernel reuses small pids fast (MAX_TASKS churn); P gets reassigned to an unrelated live task.
4. Next click: `kill(P,0)==0` is TRUE for that unrelated task → code SIGTERMs it and zeroes the slot (**342-343**) and **returns without spawning** → no popover. Classic "first click does nothing, second works."

`epin_spawn` guards only `if (pid < 0)` (**282-285**), so it is also vulnerable to the kernel fork-RAX bug (below): a bogus positive pid gets stored as a "live" child, producing the same dead-toggle permanently.

### Primary fix (client-side, self-contained — no kernel rebuild)
Stop trusting pid liveness; track an **owned-child flag** set only by spawn and cleared only by reap, and drain zombies synchronously at click time.

`clients/desktop-shell.c`:

- **311-319** add a field:
  ```c
  static struct { const char *path; volatile pid_t pid; volatile int owned; }
  epin_popovers[] = { {"/wl-quicksettings",0,0}, {"/wl-wifi-menu",0,0},
                      {"/wl-calendar",0,0}, {"/wl-overview",0,0} };
  ```
- **321-329** clear both in the reaper: `epin_popovers[i].pid = 0; epin_popovers[i].owned = 0;`
- **331-351** rewrite the toggle:
  ```c
  static void epin_popover_toggle(const char *path){
      int st; pid_t r;
      while ((r = waitpid(-1,&st,WNOHANG)) > 0)   /* drain now — don't wait for async SIGCHLD */
          epin_popover_reaped(r);
      for (unsigned i=0;i<N;i++){
          if (strcmp(epin_popovers[i].path,path)) continue;
          if (epin_popovers[i].owned && epin_popovers[i].pid>0){   /* OUR live child → collapse */
              kill(epin_popovers[i].pid,SIGTERM);
              epin_popovers[i].pid=0; epin_popovers[i].owned=0; return;
          }
          sigset_t s,o; sigemptyset(&s); sigaddset(&s,SIGCHLD);   /* close reap-before-store race */
          sigprocmask(SIG_BLOCK,&s,&o);
          pid_t p=epin_spawn(path);
          if (p>0){ epin_popovers[i].pid=p; epin_popovers[i].owned=1; }
          sigprocmask(SIG_SETMASK,&o,NULL); return;
      }
      epin_spawn(path);
  }
  ```
  The only "open" signal is now `owned` (set at spawn, cleared at reap). `kill(pid,0)` is gone, so a stale/reused pid can never eat a click.
- **~2014** replace `signal(SIGCHLD, sigchild_handler)` with `sigaction` using `.sa_flags = SA_RESTART | SA_NOCLDSTOP` for a durable persistent handler + auto-restarted poll.

### Companion fix (kernel — cures the silent failure + long-session exhaustion)
The panel-bug is real on a correct kernel, but two kernel defects amplify it:

- **Fork-RAX silent failure** — `kernel_main.d` fork/clone dispatch (case 57/58, ~**2812-2820**) writes `REG_RAX` only when `forkTask` returns `>0`, so on slot exhaustion `fork()` returns the syscall number **57** (a bogus positive pid), not `-ENOMEM`. Fix: on the `ret<=0` path set `task.regs[REG_RAX]=cast(ulong)ret` (mirror case 56 at ~2792). Makes exhaustion an errno, not a fake child.
- **Zombie slot leak** — `exitTask` (`kernel_main.d:539`) sets `exited=true` but not `active=false`; slots freed only by `wait4` (`releaseTask` `task.d:500`). The panel never `wait4()`s popovers → every popover ever opened leaks a slot until MAX_TASKS=256 (`task.d:51`) → `forkTask` returns -12. Fix: in `exitTask`, when the parent has SIGCHLD=SIG_IGN or is task 0, call `releaseTask(tid)` immediately (auto-reap). Add a periodic init-reaper for `parentId==0 && exited`.

Confirm cheaply: Logs app (SUPER+L) grep `[fork] no free task slot` / `[clone] no free task slot`.

---

## B. TILING ENGINE (master-stack + dwindle) inside desktop-shell.so

### Data model (add to `desktop-shell/shell.h` + `struct shell_surface`)
Weston 14 has a **single** `struct workspace workspace;` (`shell.h:128`). Introduce:

```c
#define EPIN_NWS 9
enum epin_layout { EPIN_MASTER_STACK, EPIN_DWINDLE };
struct epin_ws {
    struct wl_list tiles;      /* ordered list of struct epin_tile (head = master) */
    enum epin_layout layout;
    float  mfact;              /* master fraction, default 0.55 */
    int    nmaster;            /* windows in master area, default 1 */
    struct weston_layer layer; /* per-workspace view layer (show/hide on switch) */
};
```
On `struct desktop_shell` (near **128**): `struct epin_ws ws[EPIN_NWS]; unsigned cur_ws;` plus globals `int gap_out=12, gap_in=8, border=2;`. On `struct shell_surface`: `bool tiled; bool floating; int ws_index; struct wl_list tile_link;`. Focused tile = existing `shseat->focused_surface` (already maintained by `activate()`); no new focus field needed.

Window ordering IS the tree: master-stack reads the list directly; dwindle interprets the list as a spine (each window splits the remaining area, orientation alternating by depth).

### Functions to modify
1. **`map()` `shell.c:2248`** — the single first-map dispatch. Replace the plain `else { weston_view_set_initial_position(...); }` (**2262-2264**) with:
   ```c
   } else if (epin_is_tileable(shsurf)) {
       epin_tile_insert(shell, shsurf);   /* append to ws[cur_ws].tiles */
       epin_relayout(shell, &shell->ws[shell->cur_ws]);
   } else {
       weston_view_set_initial_position(shsurf->view, shell);  /* floats/popovers */
   }
   ```
   `epin_is_tileable`: normal toplevel, `weston_desktop_surface_get_parent()==NULL` (not a dialog/transient), not maximized/fullscreen, not `floating`, and not in a hardcoded float list (the popovers /wl-quicksettings, /wl-wifi-menu, /wl-calendar, /wl-overview, /wl-logview stay floating).
2. **`desktop_surface_removed()` `shell.c:2136`** — after the `if(!shsurf) return;` guard (**2145-2146**): `if (shsurf->tiled){ wl_list_remove(&shsurf->tile_link); epin_relayout(shell,&shell->ws[shsurf->ws_index]); }`. This is the reflow-on-close hook. (Do NOT rely on `desktop_surface_committed` — it early-returns on unchanged size, **2344-2349**.)
3. **New `epin_relayout(shell, ws)`** — the layout engine:
   - `get_output_work_area(shell, output, &area)` (`shell.c:372`) → the output minus the 28px panel. Inset by `gap_out`.
   - **master-stack**: n=count. n==0 → return. If n<=nmaster → split usable into n equal rows. Else master column width `= (usable.w - gap_in) * mfact`, full height, split into `nmaster` rows; stack column `= usable.w - masterw - gap_in`, split into `n-nmaster` rows; rows separated by `gap_in`.
   - **dwindle**: recursive — split current rect in half (even depth → vertical split, odd → horizontal), place head window in first half, recurse remainder into second half with `gap_in` between. Last window takes the whole remaining rect.
   - For each computed rect R and window: push geometry exactly like `set_tiled_orientation` does (**3229-3230**):
     ```c
     pos.c = weston_coord(R.x + border, R.y + border);
     weston_view_set_position(shsurf->view, pos);
     weston_desktop_surface_set_size(shsurf->desktop_surface, R.w - 2*border, R.h - 2*border);
     weston_desktop_surface_set_orientation(shsurf->desktop_surface, edges); /* tiled edges → client draws thin border, section D */
     ```
   Make it idempotent (safe to call repeatedly on commit).

### Focus-follows + swap
New handlers (registered in §C), all with signature `void(*)(weston_keyboard*, const timespec*, uint32_t, void*)`, getting the focused surface the way `maximize_binding` does (`shell.c:3154`): `weston_surface_get_main_surface(keyboard->focus)` → `get_shell_surface()`.

- **focus_dir(dir)**: from focused shsurf's rect, pick the tiled window on `cur_ws` whose center is nearest in `dir`; give it focus + raise via `activate(shell, target->view, seat, WESTON_ACTIVATE_FLAG_CONFIGURE)` — the same call `map()` uses (**2279**).
- **move_dir(dir)**: swap the focused tile with its neighbor in `dir` in `ws->tiles`, then `epin_relayout`; keep focus on the moved window.
- **swap_master**: move focused tile to list head, relayout (dwm SUPER+Return-style promote).
- **mfact ±**: `ws->mfact = clamp(ws->mfact ± 0.05, 0.15, 0.85)`, relayout.
- **nmaster ±**: `ws->nmaster = max(0, ±1)`, relayout.
- **toggle_float**: flip `shsurf->floating`; if now floating remove from tiles + `weston_view_set_initial_position`; else insert + relayout.
- **cycle_layout**: `ws->layout ^= 1`, relayout.
- **workspace switch(N)**: `weston_layer_unset_position(&ws[cur].layer)` (hide), set `cur_ws=N`, `weston_layer_set_position(&ws[N].layer, POSITION_NORMAL)` (show), restore focus to that ws's head.
- **move-to-workspace(N)**: unlink focused tile from cur_ws, move its view to `ws[N].layer`, insert into `ws[N].tiles`, relayout both.

### ⚠ Hard blocker (must fix or tiling is invisible)
Every app client **ignores** compositor-supplied size: `toplevel_configure` is a no-op — `wl-term.c:1056` `{ (void)w;(void)h; }`, and the same in every `wl-*.c`. So `weston_desktop_surface_set_size` sends a configure the client acks but never resizes to. Per-client fix (same function that §D uses):
- Store `w,h` from `toplevel_configure` (`wl-term.c:1056`) into the app struct.
- In `xdg_surface_configure` (`wl-term.c:1044-1053`) recreate the shm buffer when size changed (it already calls `create_shm_buffer` at **1047** on first commit — extend to re-create on size delta), re-layout content, re-commit.
- Fixed-size popovers: send `xdg_toplevel_set_min_size==set_max_size` and mark them floating so tiling skips them.
This touches ~15 clients (`gl-term.c` mirrors `wl-term.c` verbatim). Until it lands, geometry math is correct but windows won't visually resize.

---

## C. KEYBINDINGS — full SUPER set + exact registration

**Registration site:** `shell_add_bindings()` `shell.c:5009`, insert new calls between `mod = shell->binding_modifier;` (**5037**) and `weston_install_debug_key_binding` (**5082**). **API:** `weston_compositor_add_key_binding(ec, KEY_x, modifier, handler, data)` (`bindings.c:70`; handler typedef `libweston.h:2235`). Modifier match is **exact** (`bindings.c:328`) — SUPER+SHIFT must be `MODIFIER_SUPER | MODIFIER_SHIFT`. Dispatch fires **ALL** matching bindings, so conflicting `desktop.conf` exec lines co-fire and must be relocated first.

**Conflicts to clear first:**
- `desktop.conf:53` `SUPER+L=/wl-logview`, `:57` `SUPER+K=/wl-calc`, `:58` `SUPER+M=/wl-sysmon`, `:51` `SUPER+D=/wl-domain-manager`, `:60` `SUPER+I=/wl-imgview` → relocate these under SUPER+SHIFT+letter (or reach them only from the app grid).
- `shell.c:5079` `SUPER+K = force_kill_binding` → delete or move to SUPER+SHIFT+Q.
- `shell.c:5060-5067` `SUPER+SHIFT+arrows = set_tiled_orientation_*` → **replace** these four registrations with the move-window handlers (half-snap is obsolete under tiling).

**Final binding table (all registered in `shell_add_bindings`):**

| Chord | KEY_ code / mod | Handler |
|---|---|---|
| SUPER+H / J / K / L | KEY_H/J/K/L, `mod` | focus_dir(L/D/U/R) |
| SUPER+Left/Down/Up/Right | KEY_LEFT/DOWN/UP/RIGHT, `mod` | focus_dir (arrow alias — bare SUPER+arrows are FREE) |
| SUPER+SHIFT+H/J/K/L | `mod\|MODIFIER_SHIFT` | move_dir(L/D/U/R) |
| SUPER+SHIFT+Left/Right/Up/Down | `mod\|SHIFT` | move_dir (replaces set_tiled_orientation_* at 5060-5067) |
| SUPER+Return | (keep `desktop.conf:48` exec /hos-wifiterm) | spawn terminal |
| SUPER+SHIFT+Return | `mod\|SHIFT`, KEY_ENTER | swap_master (promote) |
| SUPER+Q | `mod`, KEY_Q (FREE) | close_binding → `weston_desktop_surface_close(shsurf->desktop_surface)` (`surface.c:532`, graceful) |
| SUPER+F | `mod`, KEY_F (FREE) | reuse `fullscreen_binding` (`shell.c:3166`) |
| SUPER+Space | `mod`, KEY_SPACE | toggle_float |
| SUPER+Backslash | `mod`, KEY_BACKSLASH | cycle_layout (master-stack ⇄ dwindle) |
| SUPER+Comma / Period | `mod`, KEY_COMMA/KEY_DOT | mfact − / + |
| SUPER+SHIFT+Comma / Period | `mod\|SHIFT` | nmaster − / + |
| SUPER+1..9 | `mod`, KEY_1..KEY_9 (FREE) | workspace_switch(N) |
| SUPER+SHIFT+1..9 | `mod\|SHIFT`, KEY_1..KEY_9 | move_to_workspace(N) |
| SUPER+SHIFT+Q | `mod\|SHIFT`, KEY_Q | force_kill_binding (moved from 5079) |

Keep existing SUPER+TAB switcher (5073) and SUPER+SHIFT+M maximize (5047).

**Optional — make tiling configurable from `desktop.conf`:** extend `epin_parse_bind` (`shell.c:4936`) with a small action table so `bind = SUPER, H, focus-left` etc. dispatch to the handlers. This requires relaxing the exec-only guard (**4944**) and the `mod==0` bare-key guard (**4947**). Not required for the hardcoded set above.

Kernel: **no change** — Super (KEY_LEFTMETA 125), Return, arrows, letters and digits all already reach `g_kbd_ring` via `ps2FeedKbdByte` (`kernel_main.d:2252`) / `input_enqueue` (`posix.d:365`).

---

## D. DECORATIONS — drop CSD titlebar, draw thin focus border

Decoration is 100% client-side, duplicated in 3 styles; the compositor cannot strip it. Drive tiled-mode off the **xdg_toplevel states array** that already arrives (and is currently discarded) in `toplevel_configure`'s `struct wl_array *s` (`wl-term.c:1056`): the compositor's `weston_desktop_surface_set_orientation` (called in `epin_relayout`, §B) sends TILED edge states, and the ACTIVATED state marks focus. So the same function that fixes resize also detects tiled/focused.

1. **Shared path — `wl-deco.h`:** add `wl_deco_border(px,stride,W,H,color,thickness)` built on `wl_deco_fill` (line **22**). In tiled mode: `wl_deco_draw` (**30**) draws only the border (skip the min/max/close glyphs); `wl_deco_hit` (**54**) returns 0 always (no buttons — move/close come from keybindings). Clients using it (`wl-files.c:519` draw / `:751` hit / `:759` drag; `wl-domain-manager.c:1066/:1244/:1252`) get it once they pass a tiled flag; drop the header-strip `xdg_toplevel_move` drag branches (`wl-files.c:759`, `wl-domain-manager.c:1252`) in tiled mode.
2. **`wl-term.c` / `gl-term.c` (inline deco):** set `DECO_BASE_H` (`wl-term.c:52`) to `2*scale` (or 0) in tiled mode; gut `draw_deco` (**328**) to paint only a focus-colored border; make `deco_hit` (**320**) return 0 (content) everywhere. Content offset keys off `a->deco_h` (**176, 592**) so space reclaims automatically. **KEEP** the IDENTITY_DOMAIN security border (**638-643**) — give the tiling focus border a *distinct* color/edge so the two never collide. Mirror every edit into `gl-term.c` (verbatim copy).
3. **Ad-hoc clients** (`wl-calc` TITLE_H=26, `wl-editor` 28, `wl-imgview`, `wl-sysmon`, `wl-chars`, `wl-clocks`, `wl-screenshot`, `wl-installer`): set their TITLE_H to thin/0 in tiled mode, remove titlebar fill + close-box hit-test. Long-term: migrate them all onto the `wl-deco.h` border helper so decoration lives in one place.

**Focus border:** 2px rectangle in an accent color when the toplevel has ACTIVATED state, dimmer otherwise — one implementation in `wl_deco_border`, called from every client redraw.

---

## E. GNOME BAR PARITY

The 28px top bar (`clients/desktop-shell.c`, Activities/clock/indicators) is structurally close. Gaps and where to build:

1. **Activities → real overview** (`wl-overview.c`, currently app-grid only, `draw_overview:223`): add live window thumbnails + a workspace strip. Weston has no client protocol to enumerate toplevels, so build it **compositor-side in `shell.c`** using the `shsurf_list` (`shell.h:156`) the shell already owns and the §B workspace model — render scaled view copies into a grid layer + a workspace row. Trigger via a **bare-Super tap** (`weston_compositor_add_modifier_binding`, `bindings.c:89`) and a **top-left hot-corner** pointer-motion listener, both registered in `shell_add_bindings` (**5009**).
2. **Aggregate Quick Settings** (`wl-quicksettings.c`, `draw_menu:345`, hit_region enum `:64`): add GNOME-43 toggle tiles — Bluetooth, Airplane, Power Mode, Night Light, Dark Style, Rotation lock. Wire real backends: brightness slider → backlight sysfs (`shell.c` already has `backlight_binding` at **5032**); battery → upower/sysfs into `epin_draw_battery` (`desktop-shell.c:441`) + BAT row (`draw_menu:393`); volume slider is currently **cosmetic** (no audio backend exists — needs one). For strict parity, route the **whole** indicator cluster to /wl-quicksettings (drop the left-third wifi split at `desktop-shell.c:550-561`) and reach Wi-Fi via a network sub-page.
3. **Calendar + notifications** (`wl-calendar.c`, `draw_calendar:163`, clock+month only): add a notification tray column. Needs a notification server — build `hos-notifyd` (org.freedesktop.Notifications over dbus, or a simpler `/run/notifications` spool) that a banner popover + the calendar tray read; add Do-Not-Disturb.
4. **Session actions:** Lock/Log Out are stubs writing `/run/session.action` (`wl-quicksettings.c:284`) with no consumer — build a session/lock daemon. Restart/Power already work (cap-gated `reboot(2)`).
5. **Styling:** bar is opaque black (`panel-color=0xff000000`, `posix.d:5882-5883`). GNOME's is translucent, opaque only under a maximized window — adjust the alpha in `posix.d` (KERNEL rebuild) + add maximized-aware opacity in `desktop-shell.c` panel redraw.
6. **Optional Ubuntu dock:** new persistent client + toplevel-enumeration protocol; lowest priority (`wl-layer-bar.c` is dead Hyprland code — do not use).

---

## F. BUILD / REBUILD

- **Panel client `clients/desktop-shell.c` (§A) + shell plugin `shell.c`/`shell.h` (§B, §C, §E):**
  `ninja -C deps/weston-14.0.0/build-epin` (produces `clients/weston-desktop-shell` and `desktop-shell.so`; `shell.h` struct changes recompile `shell.c`) → then `WESTON=1 make hos.iso` (re-stages `cd/{weston,desktop-shell.so,weston-desktop-shell,gl-renderer.so}` + clients + `desktop.conf`, Makefile **1078-1123**). Relink gotcha (memory): `weston-desktop-shell` has needed `-Wl,--allow-multiple-definition`.
- **App clients `wl-*.c` / `wl-deco.h` / `gl-term.c` (§B resize, §D):** Makefile `wl-%` pattern rule, or rebuilt during `WESTON=1 make hos.iso`. ~15 files touched for the resize fix — stage all via the ISO build.
- **`desktop.conf` only (§C relocations):** `WESTON=1 make hos.iso` (staged raw, Makefile **1103**; no ninja).
- **Kernel (§A companion fork-RAX in `kernel_main.d ~2812` + auto-reap `exitTask ~539`; §E panel alpha `posix.d:5882`):** `make -C src/kernel/d` → `make kernel.elf` → `make hos.iso`. `make kernel.elf` does **not** recompile `.d`; struct-size changes need `rm -rf build/d` first (memory).
- **Full clean weston reconfigure** (only if meson options change): `make deps-weston`.

**Risks / gotchas:**
- **Compositor death is fatal** to the desktop (`kernel_main.d:550-557`). A crash in the new `shell.c` tiling code kills everything — a shell-**client** crash is survived/respawned (`shell.c:4115-4139`), a shell-**plugin** crash is not. Guard `epin_relayout`/focus handlers defensively (NULL checks like the existing `maximize_binding`).
- Verify `shell->binding_modifier != 0`, else `shell_add_bindings` returns early (**5038**) and **all** SUPER binds silently vanish.
- QEMU needs MEM ≥ 2048 for `hos.iso` (memory).
- Two misleading `weston.ini` artifacts (`build-epin/frontend/weston.ini`, `weston.ini.in`) are NOT used at runtime — the live one is embedded in `posix.d:5871`.
- The §A client fix cures the *mis-toggle*, but long-session **task-slot exhaustion** (MAX_TASKS=256, `task.d:51`) persists until the kernel fork-RAX + auto-reap fixes land — ship both for the real cure.
- Tiling geometry is invisible until the per-client `toplevel_configure` resize fix (§B blocker) is applied.

**Key file anchors:** panel bug → `clients/desktop-shell.c:331-351,321-329,274-303,180-192,~2014`; tiling → `shell.c:2248(map),2136(removed),372(work-area),3229-3230(geometry-push primitive),5009-5082(bindings)`, `shell.h:128(workspace),143(modifier),156(shsurf_list)`; resize blocker → `wl-term.c:1044-1057`; decorations → `wl-deco.h:22,30,54`, `wl-term.c:52,320,328,638-643`; kernel → `kernel_main.d:~2812(fork-RAX),539(exitTask)`, `task.d:51,500`, `posix.d:5882`.