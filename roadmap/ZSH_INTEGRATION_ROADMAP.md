# Z Shell (zsh) Integration Roadmap

Goal: make the **real upstream Z Shell** the standard interactive shell across AnonymOS —
running both inside the Linux compatibility personality (the upstream `zsh` binary) and
**natively** (the same zsh source over an AnonymOS platform-abstraction layer) — while
preserving the object model, capability security, namespace isolation, identity domains,
and Linux compatibility. **Do not fork zsh.** All AnonymOS changes are isolated to a
platform layer.

> **Status & honesty.** This is a staged plan. Today the OS ships two *custom* shells:
> busybox `ash` (the Linux personality) and the native object shell `/hos-sh` (Track B,
> the AnonymOS personality, [NATIVE_OBJECT_ABI.md](../docs/NATIVE_OBJECT_ABI.md)). Both now
> carry the rich prompt (username · permissions · namespace · path) this roadmap calls for
> (Z6 milestone, already landed). The remaining work replaces them with real zsh in two
> stages: **Linux zsh first** (low risk — it's just another musl binary), **native zsh
> second** (the platform layer). zsh is large autoconf C; each phase keeps the shell
> functional.

Legend: **P** priority · **E** effort (1=hrs … 5=weeks) · status.

---

## Architecture (target)

```
/system/shell/zsh/{src,platform,modules,themes,plugins,completion,configs}
/etc/zsh/{zshenv,zprofile,zshrc,zlogin,zlogout}
/system/config/shell.json          # declarative config (a /config object-FS view)
/users/<user>/{.zshrc,.zprofile,.zlogin}
```

zsh compiled as shared libraries — `libzsh.so`, `libzshmodules.so`, `libzshcompletion.so` —
loaded by the existing dynamic linker. The **parser/expander/job-control core is upstream
and unchanged**; only the platform `#ifdef` surface is AnonymOS-specific.

### The platform abstraction layer (the only AnonymOS code in the zsh tree)

A single `platform/anonymos/` shim that zsh's configure selects, implementing the host
hooks zsh needs against AnonymOS primitives:

| zsh needs | Linux personality | Native personality |
|---|---|---|
| filesystem (`open/read/stat/readdir`) | Linux ABI ([SYSCALL_ABI.md](../docs/SYSCALL_ABI.md)) | `object_open/Stream/Container` ([NATIVE_OBJECT_ABI.md](../docs/NATIVE_OBJECT_ABI.md) §10) |
| terminal I/O + PTY | `/dev/ptmx`, termios ioctls (live) | `Device`/`Channel` PTY object (§12) |
| signals | `rt_sigaction`/`tgkill` (live, SIGINT/SIGQUIT) | `object_subscribe` to a signal channel (§13) |
| processes (`fork/exec/wait`) | clone/execve/wait4 (live) | `spawn_process`/`process_wait` (§4) |
| environment | the Linux env block | identity/namespace-bound env object |
| **capabilities** | read-only (Linux can't reach the native ABI) | `cap_*` (§7) — the prompt's permission flags |
| **namespaces** | read EPIN_DOMAIN env | `namespace_lookup` (§11) — the prompt's namespace |
| **object manager** | n/a | `object_*` (§6) — `objctl`, object-path completion |
| **IPC** | AF_UNIX sockets (live) | `channel_*` (§8) |
| dynamic loader / threads / malloc | musl + the kernel dynamic linker (live) | same (native userspace uses musl too) |

The two personalities share **one** zsh source; they differ only in which platform backend
the shim dispatches to (chosen at process start from the task personality, the same flag
that gates the native ABI).

---

## Z11 — Login flow + default shell · ☐ · P: Med · E: 2 · deps: Z1, Z5

- `display-manager → auth → identity → namespace → PTY → zsh → shell.json → .zshrc →
  plugins → theme → prompt`. New users get `/system/shell/zsh/zsh` as their login shell;
  the Domain Manager's per-domain Shell control gains a "zsh" option alongside linux/native.

## Phased delivery (Deliverable 20 — milestones + dependencies)

Each milestone leaves the shell fully functional:

1. **M-Z-Linux** (Z0→Z1→Z3): real upstream zsh is the Linux-personality interactive shell;
   wl-term launches it; no regressions vs upstream. *Lowest risk, highest immediate value.*
2. **M-Z-Dynamic** (Z2): zmodules load dynamically; libzsh.so split done.
3. **M-Z-Config** (Z5→Z6→Z7): shell.json + the anonymos theme + the four-field prompt as a
   zsh theme (the prompt data is already live, Z6 ✅).
4. **M-Z-Integrate** (Z8→Z9→Z10): completion + plugins + secure history wired to the object/
   identity/namespace/capability managers.
5. **M-Z-Native** (Z4): native zsh over the platform layer; `/hos-sh` retires into a plugin.
6. **M-Z-Harden** (Z11→Z12): login flow, default shell, security review, regression +
   benchmarks.

Order rationale: Linux zsh first (it's just another musl binary over the live ABI), the
config/prompt/theme layer next (mostly data + a theme function, and the prompt fields are
already implemented), then the deep native port last (it needs the most platform plumbing).

---

---

## Companion: the native shell — `-sh` (LFE / Lisp-Flavored Erlang)

AnonymOS has **two interactive shells, one per personality** (NATIVE_OBJECT_ABI §3):

- **zsh** — the **Linux personality** shell (POSIX): everything above. Familiar, scriptable,
  Oh-My-Zsh-customizable; runs ordinary Linux/POSIX programs.
- **`-sh`** — the **native (AnonymOS) personality** shell: it abides by the **syntax and
  structure of LFE (Lisp-Flavored Erlang)** as defined by the
  [`-sh` project](https://github.com/Jonathan-R-Anderson/-sh). Where zsh is line-oriented
  POSIX, `-sh` is **s-expression / Lisp**, which fits the object-capability model directly:
  objects, capabilities, identities, and namespaces are first-class **data** (atoms, lists,
  tuples), and every action is a **form** — `(verb target args…)` — that maps onto a native
  object-ABI call. This is the "actual OS shell" the Domain Manager offers as the **native**
  option; it drives the kernel object model the way zsh drives POSIX.

**Why LFE for the native shell.** The native ABI is object-oriented and message-passing
(§6/§8); LFE's homoiconic forms + pattern matching + immutable data are a natural surface
for it — an object query is a list, a capability is a tagged tuple, a method call is a form,
and policies/declarative config (`shell.json`, the `/config` views) are just data the shell
reads and writes. It keeps the native shell *introspectable and scriptable* (the AI-/agent-
friendly goal) without bolting POSIX onto the object model.

### LFE integration phases (parallel to the zsh phases)

  - **L4.1 — read forms (data)** · `(identity)` → a `#(user namespace caps)` tuple parsed from the
    kernel whoami; `(namespace)` → the namespace atom; `(caps)` → the rights as a list of atoms;
    `(cap-derive src rights)` → an alias for the attenuating `cap_grant`.  Pattern-matchable LFE.
  - **L4.2 — `(identity-switch <name>)`** · a new GATED kernel verb (`HOSQ_ID_SWITCH`):
    de-escalation-only (target identity trust ≤ current — never escalate), relabel the task's
    identity, and attenuate its capabilities to the new (lower) rights-ceiling so existing caps
    can't retain rights the new identity forbids.  **Verified live:** `(identity)` → `#(user System (fs:rw net:nat ipc exec admin))`,
    `(caps)` → `(fs:rw net:nat ipc exec admin)`; `(identity-switch Personal)` → `0` then `(identity)`
    → `#(user Personal (fs:rw net:nat ipc exec))` (**`admin` dropped** by the cap attenuation, prompt
    relabels to `user@Personal`); `(identity-switch System)` → `-1` (escalation back DENIED, trust
    100 > 50, kernel logged one `[id-switch … trust=0x32]` only); `(case (identity) ((tuple u n c) n))`
    → `Personal` (the security model is pattern-matchable LFE data).
  - **L5.1 — LFE embedded inside the native zsh** (corrected from "separate `-sh`") · `wl-term`
    launches `/hos-zsh` — the SAME zsh in the *native* personality — for `EPIN_SHELL=native`, NOT a
    separate `-sh`. Inside that native zsh, LFE is reachable three ways: `obj`/`id`/`ns`/`svc`/`sys`
    are **in-process** native-ABI builtins (the `zsh/anonymos` module, Z4c.4, issuing
    `HOS_SYS_QUERY` directly); `lfe '<form>'` evaluates the **full LFE language** (defun/let/case/
    lists/tuples/pattern-matching + the object-ABI forms, L2–L4) via the *same* betterC evaluator as
    the standalone `-sh`; and everything else is ordinary POSIX zsh. The DM Shell label is now
    **"Native (zsh+LFE)"**. (`hos-sh.d` gained a `version(LfeLib)` switch: the one source compiles
    either as the standalone `-sh` tool *or*, with `-d-version=LfeLib`, as `lfe.o` exporting
    `lfe_eval_line` — the foundation for a future truly-in-process `lfe` *builtin* linked into the zsh
    binary via `libanon.a`; today `lfe` reuses that evaluator through the shared object shell.)
  - **L5.2 — confine the Linux shell to Linux** (security, requested) · a Linux-personality shell
    must only run ordinary Linux programs + the Linux syscall surface — never the native object ABI,
    *even by exec'ing `/hos-sh`*.  The kernel already `ENOSYS`-gates direct `HOS_SYS_QUERY` from a
    Linux task (Z12), but a Linux shell could exec the trusted native image to become native.  New
    kernel gate: a per-task `g_taskNativeLaunch` authorization (inherited on fork, held by the
    trusted desktop/terminal chain) is now *required* to enter the native personality on exec, and
    is **dropped when the Linux interactive shell (`/bin/zsh`) is exec'd** — so the Linux shell and
    everything it spawns can never reach the object ABI (running `/hos-sh` from it runs Linux-
    personality → `ENOSYS`).  The legit native launch (desktop → `wl-term` → `/hos-sh`) keeps the
    authorization; a re-run `/wl-term` from a Linux shell inherits the dropped flag and cannot.
    **Verified live (corrected build):** the DM Shell control reads **"Native (zsh+LFE)"** and the
    panel status line reads `shell Native (zsh+LFE)`; a native-domain terminal is *zsh* — POSIX
    `echo hi-from-native-zsh` works, `whence -w obj lfe echo` reports `obj: builtin`, `lfe: function`,
    `echo: builtin` (all in the one shell) — with `obj` returning the live object table in-process,
    `lfe '(- 43 1)'` → `42`, and `lfe '(defun inc (n) (- n 1)) (inc 43)'` → `inc` / `42` (the full LFE
    language, inside zsh).  A **Linux-domain** terminal runs Linux fine (`echo hello-from-linux` → ok)
    but `/hos-sh obj` / `/hos-sh sys` → `native query failed` (kernel `ENOSYS` ×3) — the Linux shell
    cannot reach the object ABI.  **This closes the L-series (L0–L5): the native shell is zsh with LFE
    embedded inside it, cleanly isolated from the Linux zsh.**

> **One shell (zsh), LFE inside, two personalities.** The native shell is *not* a separate `-sh` —
> it is zsh in the native personality with LFE embedded: in-process `obj`/`id`/`ns`/`svc`/`sys`
> builtins + the `lfe` full-language evaluator, atop ordinary POSIX zsh. The Linux personality is the
> same zsh, confined to POSIX. The terminal (`wl-term`, later ratty) hosts it; both share the rich
> prompt and the customization config.

---

## Companion: ratty terminal emulator roadmap

[ratty](https://github.com/orhun/ratty) (orhun) is a Rust, GPU-accelerated terminal
emulator. It is the **terminal** layer, distinct from the **shell** (zsh) above: ratty
draws the grid and owns the PTY; zsh runs inside it. The goal is to make ratty the
AnonymOS terminal that *hosts* zsh — the same "the terminal contains no shell logic, only
PTY + rendering" split this roadmap mandates (Z3). It supersedes/augments the current
`wl-term`. This was Track C of `SHELL_AND_COMMANDS_ROADMAP.md`; gated on a Rust toolchain
+ a GPU stack the OS does not yet have (software Pixman only — see [[weston-perf-profiling]]).

  - **R1.1 — Rust Wayland SHM window** · bind `wl_compositor`/`wl_shm`/`xdg_wm_base`/`wl_seat`; create
    a surface + xdg-toplevel; **double-buffered** SHM (one pool, two buffers via `memfd_create`+
    `mmap`+`create_pool`, fd passed with `sendmsg`/`SCM_RIGHTS`) ping-ponged by `wl_buffer.release` —
    a single buffer deadlocks (the compositor never releases a re-attached buffer, so the grid froze).
  - **R1.2 — PTY + shell host** · `open(/dev/ptmx)` → `TIOCSPTLCK`/`TIOCGPTN` → `/dev/pts/N`,
    `TIOCSWINSZ`, `fork` → child `setsid`+`dup2`(slave→0/1/2)+`execve` zsh; parent reads the master.
  - **R1.3 — VT parser + cell grid** · printable + BS/TAB/LF/CR/BEL + CSI (CUU/CUD/CUF/CUB/CUP, ED/EL,
    SGR 16-colour) maintaining a `[ROWS][COLS]` grid of (glyph, fg, bg) with scroll.
  - **R1.4 — 8×8 bitmap font render** · reuse `gui_font.h` (extracted to `term_font8x8.rs`), 2× scale,
    fg/bg per cell + a block cursor.
  - **R1.5 — keyboard input** · `wl_keyboard` → reuse `wl-term`'s evdev `kmap`/`kmap_shift` +
    `special_key_seq` (arrows/Home/End) + ctrl/shift → write to the PTY master.
  - **R1.6 — stage + verify** · boot module + desktop autostart; verify live that the Rust terminal
    hosts zsh, renders its output, and accepts typed input.
- **R2 — GPU stack · 🚧 IN PROGRESS · E: 5 · R: high · deps: R1.** ratty renders via `wgpu`/Vulkan/GL.
  Today the OS is **software only**: `virtio_gpu.d` is a minimal *legacy* virtio-gpu driver that does
  **2D scanout** (`RESOURCE_CREATE_2D`/`SET_SCANOUT`/`TRANSFER_2D`) and Weston composites on the CPU
  (Pixman / `kms_swrast`). This is the same GPU stack tracked as R8 in `DESKTOP_RESPONSIVENESS_ROADMAP`
  — the largest dependency, where the Hyprland bring-up stalled on the dmabuf import. Real
  acceleration = QEMU `virtio-gpu-gl` (virgl) + a 3D-capable guest virtio-gpu driver + a Mesa virgl
  driver + EGL/dmabuf in the compositor. The host here CAN offer it (`virtio-gpu-gl`, `egl-headless`,
  `libvirglrenderer`, `/dev/dri/renderD128` all present). Multi-step sub-roadmap:
      + **`VIRGL_LOG_LEVEL=debug VIRGL_LOG_FILE=`** (host virglrenderer log; `VIRGL_DEBUG`/`VREND_DEBUG`
      alone don't set the log level). Desktop boot unaffected (virtio-gpu-gl is headless-test only).
  - **R2.4 — render node + Mesa virgl** · expose `/dev/dri/renderD128`; ship the guest Mesa virgl
    (`virtio_gpu`/`virpipe`) driver so GL/GLES programs get GPU acceleration.
        - **kernel** (`core/syscalls/posix.d`, `drivers/graphics/virtio_gpu.d`): `DRM_IOCTL_VERSION` major
          must be **0** (virgl winsys rejects `major != 0`); `VIRTGPU_GETPARAM` must write the result to
          **`*value`** (value is a *userspace pointer* per the Linux uABI), not into the value field — Mesa
          read garbage for `3D_FEATURES` and bailed to softpipe; `GET_CAPS` must return the **full 1376-B**
          capset (was truncated at 1024 → `virgl_create_screen` choked); `renderD128` must `fstat()` as
          **`makedev(226,128)`** (`minor>>6 == DRM_NODE_RENDER`), not minor 0 (card0 stays minor 0).
        - **env**: drm-gl-test must unset a **fourth** software-forcing var the kernel seeds,
          **`GBM_ALWAYS_SOFTWARE=1`** (forces gbm's `dri_screen_create_sw` → kms_swrast, never trying the
          HW path) — in addition to `LIBGL_ALWAYS_SOFTWARE`/`GALLIUM_DRIVER`/`MESA_LOADER_DRIVER_OVERRIDE`.
        - **Mesa** (`deps/mutter/patches/mesa-virgl-minimal-sysfs.patch`, wired into the mesa build): this
          guest exposes **no `/sys` PCI tree**, so every `drmGetDevice2`/`drmGetDevices2` in EGL's gbm
          render-device path fails (`MESA-LOADER: failed to retrieve device information` →
          `DRI2: failed to get compatible render device`/`failed to setup EGLDevice`). Patch
          `loader_is_device_render_capable()` + `_eglFindDevice()` to fall back to a **sysfs-free
          fstat/minor node-type test** so eglInitialize reaches the already-created virgl screen instead
          of `EGL_NOT_INITIALIZED`. (TRAP: `drmGetNodeTypeFromFd` is NOT sysfs-free — on Linux it stats
          `/sys/dev/char/<m:n>/device/drm`; use a direct `fstat`+`minor` check. TRAP: do NOT set
          `MESA_LOADER_DRIVER_OVERRIDE=virtio_gpu` — gbm misreads it as a backend name.)
- **R3 — ratty port · E: 4 (revised: much higher) · deps: R2.** Build ratty for AnonymOS: PTY against
  `/dev/ptmx` (live) or the native `Device` PTY object (§12), input via the Wayland seat, clipboard via
  OSC52, and the GPU backend from R2. Honour the unspoofable per-domain window border (the identity
  color) the kernel/compositor already enforce.
  - **★ Feasibility probe (done):** [ratty](https://github.com/orhun/ratty) is NOT a lightweight
    terminal — it is **"a GPU-rendered terminal with inline 3D graphics built on Bevy + Ratatui"**, so
    it pulls in the **entire Bevy game engine** (`bevy_pbr`/`gltf`/`animation`/`ecs`/`render`, ~400+
    crates) + `wgpu`(core/hal/types) + `naga` + `glow` + `winit`. **COMPILE = feasible:** `cargo build
    --target x86_64-unknown-linux-musl` with `PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_SYSROOT_DIR=deps/
    gtk-stack/sysroot PKG_CONFIG_LIBDIR=…/lib/pkgconfig` builds through wgpu/naga/glow/winit/bevy_* with
    no hard musl blocker (the only `-sys` wall, `wayland-sys`, is resolved by that sysroot, which has
    wayland/xkb/egl/gbm/udev/x11 `.pc`s). **RUN = NOT feasible on the OS now:** Bevy/wgpu need real GPU
    acceleration (the OS is on **softpipe/CPU** — R2's virgl-as-renderer is unfinished; a 3D engine on
    softpipe is unusable) AND a far more complete Linux ABI + a full `winit`/Wayland environment than the
    OS provides. So ratty *links* but cannot *run* usefully until (1) R2 GPU acceleration (virgl) lands
    and (2) the Linux ABI is substantially expanded. Realistic alternative for the R3 *spirit* (a
    GPU/GL-rendered terminal hosting zsh): a small **GLES2 terminal** on the R2 Mesa GL stack, not the
    Bevy behemoth. Until then `hos-term` (R1, CPU) remains the Rust terminal.
    + `wl_keyboard` input) with the **wl_shm present swapped for GLES2**: it renders the grid into the CPU
    framebuffer `a->pixels` as before, then uploads it as a `GL_RGBA` texture and draws a fullscreen quad
    to an EGL **window** surface (`eglSwapBuffers`), so the client runs the real GL pipeline + Weston's GL
    renderer composites it (fragment shader swizzles `.bgr` since `a->pixels` is XRGB8888). **Verified
    end-to-end** (screenshot + serial): the "EpinAnonymOS Terminal" window shows the zsh prompt with
    antialiased coloured text + syntax highlighting; typing `echo glterm_ok` runs in the shell and renders
    the output. `GL renderer=softpipe` for now (the virgl-client dmabuf path below is still pending) — so
    the text rendering is CPU via the GL pipeline, but the architecture is the true-GPU foundation.
    Launch-on-demand via SUPER+L. **REMAINING for R3:** get the client onto **virgl** instead of softpipe
    (the virgl-client progress below).
  - **★ R3 virgl-client progress (commit c9f5ff339) — Weston now identifies its EGL render device.**
    Traced (multi-agent) why GPU clients fell back to softpipe: Weston logged *"failed to query rendering
    device from EGL"* → *"dmabuf support: no"*, so it never advertised a render device to clients. Fixed
    the kernel sysfs so libdrm works: **`/dev/dri` is now getdents-enumerable** (it was a synthetic dir
    never tagged → libdrm's `opendir("/dev/dri")+readdir` in BOTH `drmGetDevice2` and `drmGetDevices2`
    saw zero nodes), plus a **PCI sysfs subtree** for the virtio-gpu (`/sys/dev/char/226:{0,128}/device/`
    subsystem→`/sys/bus/pci`, uevent `PCI_SLOT_NAME`, vendor/device/…). And **reverted** the egldevice.c
    `_eglFindDevice` software-head Mesa patch (now that drmGetDevice2 works it must match the real DRM
    EGLDevice, not the software one). Weston now logs **"Using rendering device: /dev/dri/renderD128"**;
    desktop still virgl, no regression. **STILL REMAINING (deep):** the EGL display lacks
    `EGL_WL_bind_wayland_display` + `EGL_EXT_image_dma_buf_import` (the compositor↔client GPU-buffer-share
    extensions → need the **virgl PRIME/dmabuf** path for virtgpu GEMs), so clients still get softpipe;
    and the single shared unlocked `gpuCtrl` control queue must be **serialised** before a client renders
    on virgl concurrently with Weston (a non-cli/sti lock). The softpipe GLES2 client still composites
    fine meanwhile, so the **terminal can be built now** on that path.
  - **24-bit color** — already (Z7.1 SGR `38;2;R;G;B` truecolor).
  - **UTF-8 / Unicode** — the cell grid widened `char`→`uint32_t` codepoints; a UTF-8 decoder in the VT
    input; FreeType renders any codepoint (box-drawing, powerline-via-Unicode, etc.).
  - **Nerd-Font glyphs** — vendored `NerdFontsSymbolsOnly` (`deps/fonts/SymbolsNerdFontMono…`, staged in
    `fonts.blob`); loaded as a **fallback FT_Face** that `render_ft_glyph` uses for any PUA/icon glyph the
    primary font lacks (verified: `G9FONT: loaded Nerd symbols fallback`).
  - **Mouse reporting** — DECSET `?1000/?1002/?1003` (+`?1006` SGR, `?25`, `?2004`); `wl_pointer`
    button/drag/wheel encoded to the PTY (SGR or legacy X10), grid-only (titlebar/scrollbar stay local).
  - **Bracketed paste + OSC 52 clipboard** — `wl_data_device`: OSC 52 sets the system clipboard (base64
    → `wl_data_source`); Ctrl+Shift+V / Shift+Insert paste (`wl_data_offer` receive), wrapped in
    `ESC[200~/201~` when `?2004` is set.
  - **OSC 8 hyperlinks** — parsed, a per-cell link id + a URI ring, underline-rendered, click-to-copy
    (no browser to "open" them, so a click copies the URI to the clipboard).
  - *Kitty graphics + Sixel remain "future" per the roadmap.*

**Ordering / honesty:** R0→R1 are achievable on today's software stack and give a working
Rust terminal early; R2 (GPU) is the gating blocker and shares the desktop-GPU effort, so
the GPU-accelerated ratty is the last milestone. Until then, `wl-term` (with its new
decorations + 4-field prompt) remains the terminal, and Ratatui-CPU (R1) is the
intermediate. zsh integration (Z*) is independent of ratty — zsh runs in `wl-term` today
and in ratty later; neither blocks the other.

---

## See also

- [NATIVE_OBJECT_ABI.md](../docs/NATIVE_OBJECT_ABI.md) — the native ABI the platform layer
  targets + the personality gate the security review relies on.
- [SYSCALL_ABI.md](../docs/SYSCALL_ABI.md) — the Linux ABI Linux-personality zsh runs on.
- `roadmap/SHELL_AND_COMMANDS_ROADMAP.md` — the current busybox + `/hos-sh` shells this
  replaces; [[shell-track-a]] for the syscall traps (getpgid==1, PTY line discipline) zsh
  will also need.
