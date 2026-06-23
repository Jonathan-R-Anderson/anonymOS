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

## Z0 — Toolchain + upstream fetch · ☐ · P: High · E: 2

- Add an offline-cached upstream zsh tarball under `deps/zsh/` (pinned version + checksum),
  mirroring how `deps/busybox` and the GUI deps are vendored.
- Wire `deps/zsh` into the Makefile: configure with the existing `musl-clang` cross
  toolchain (the one that builds the Wayland clients), `--enable-shared`, `--disable-dynamic-nss`.
- *Deliverable 5 (build), 1 (source tree).* No OS behaviour change yet.

## Z1 — Linux-personality zsh · ☐ · P: High · E: 3 · deps: Z0

- Build `zsh` as a static (then shared) musl binary; stage it as a boot module + into the
  rtfs at `/bin/zsh` and `/system/shell/zsh/zsh`.
- `exec("/bin/zsh")` runs upstream zsh **with no behavioural differences** — the Linux
  compatibility goal. Validate the upstream test suite subset that the live syscall set
  supports (globbing, expansion, arrays, assoc arrays, functions, aliases, completion).
- Make it the default `/etc/passwd` shell for `user`/`root` (replacing `/bin/sh`).
- *Deliverable 4 (Linux integration), 18 (regression vs upstream).*
- **Risk/dep:** zsh uses a handful of syscalls beyond busybox's set (e.g. `wait4` flags,
  job-control `tcsetpgrp`, `setpgid`, `poll`). Most are live; gaps get filled in posix.d
  exactly as busybox's were (the `getpgid/getpgrp==1` trap and PTY line discipline already
  exist — see [[shell-track-a]]).

## Z2 — Dynamic linking · ☐ · P: Med · E: 3 · deps: Z1

- Compile `libzsh.so` / `libzshmodules.so` / `libzshcompletion.so`; load zmodules via
  `zmodload` over the **existing kernel dynamic linker** (PT_INTERP/ET_DYN load, file-backed
  mmap, `.so` basename resolve + unique-inode fstat — all live, see [[project_gui_progress]]).
- *Deliverable 6 (dynamic linking).* Validates the loader against a second large dynamic
  program besides the GUI stack.

## Z3 — PTY / terminal split · ☐ · P: High · E: 2 · deps: Z1

- The terminal (`wl-term`) must contain **no shell logic** — it only creates a PTY and
  `exec`s the shell. wl-term already does exactly this (`spawn_shell`: `/dev/ptmx` →
  fork → `execve` the shell on the slave). Switch its default shell binary to `/bin/zsh`.
- Keep wl-term's responsibilities (keyboard, pointer, clipboard, PTY, Unicode, rendering,
  window decorations); everything else is zsh.
- *Deliverable 7 (PTY/terminal).* Mostly a one-line target change + termios coverage check.

## Z4 — Native platform layer · ☐ · P: High · E: 5 · deps: Z1, Z2

The big one: port zsh to native userspace via `platform/anonymos/`.

- Implement the host hooks (table above) dispatching to native ABI verbs when the process
  is native personality, Linux syscalls otherwise. **No change to zsh's parser/expander.**
- Native zsh gets its filesystem through `object_open` over namespaces (§10/§11), its PTY
  through a `Device` object (§12), processes through `spawn_process` (§4).
- *Deliverable 2 (platform design), 3 (native port).* Staged: (Z4a) FS+TTY+process hooks to
  reach an interactive prompt; (Z4b) signals/IPC; (Z4c) env/cap/namespace/object hooks.
- **Honest constraint:** this is multi-week C porting; until Z4 completes, the native
  personality keeps using `/hos-sh` (which already drives the object model and carries the
  rich prompt). zsh becomes the native shell when Z4a lands; `/hos-sh`'s object commands
  (`obj/id/ns/svc/sys`) survive as zsh builtins/plugins (Z9).

## Z5 — Configuration system · ☐ · P: Med · E: 3 · deps: Z1

- Standard zsh config files (`/etc/zsh/*`, `~/.z*`) **plus** the declarative `shell.json`.
- Resolution priority (a `zshenv` shim reads JSON and exports the derived settings before
  the user rc runs): **user JSON → user `.zshrc` → system JSON → system `zshrc` → defaults.**
- `shell.json` lives at `/system/config/shell.json` (and is surfaceable as a `/config`
  object-FS view — [FILESYSTEM.md](../docs/FILESYSTEM.md) F2). Ship the full default
  (theme/prompt/history/completion/autosuggestions/highlighting/plugins/aliases) from the
  brief.
- A small JSON→zsh translator (a native plugin or a `zshenv` function) maps `shell.json`
  keys to `setopt`/`zstyle`/`PROMPT`/`alias`. *Deliverable 9 (JSON parser).*

## Z6 — Prompt: identity / namespace / capabilities / path · ✅ DONE (current shells; carries to zsh) · P: High · E: 2

The prompt the brief asks for — **username, permissions, namespace, file path** — is **live
in both current shells today**, and the same data feeds the zsh theme later:

- **Linux shell (busybox):** wl-term builds `PS1="[<domain>] \u [<perms>]:\w\$ "` from the
  per-domain policy the Domain Manager passes (`EPIN_DOMAIN`/`EPIN_DISK`/`EPIN_NET`/
  `EPIN_SECURE_IPC`); `\u`/`\w` expand live (added the uid-1000 `/etc/passwd` entry so `\u`
  resolves). Example: `[System] user [fs:rw net:nat ipc]:/`.
- **Native shell (hos-sh):** `HOSQ_WHOAMI` now returns `user@namespace [perms]`, perms
  derived from the task identity's rights ceiling + net policy + brokered devices
  (`fs:rw net:nat ipc exec admin`); the prompt is `user@namespace [perms]:/path` and the
  path updates live on `cd`. Example: `user@System [fs:rw net:nat ipc exec admin]:/objects/identities`.
- **For zsh (Z7):** the same fields become a `prompt_anonymos_setup` theme function that
  reads the identity/namespace/caps via the platform layer (native) or the `EPIN_*` env
  (Linux), so the multi-line `╭─ user@machine … ├─ Identity … ├─ Namespace … ╰─ λ` layout
  from the brief is a theme, not hardcoded shell logic.

## Z7 — Theme engine · ☐ · P: Med · E: 3 · deps: Z5, Z6

- Oh-My-Zsh-style themes under `themes/`; ship `themes/anonymos.zsh-theme` with the
  multi-line layout (identity/namespace/capabilities/git/object/exit-status/exec-time).
- Nerd-Font glyphs when the terminal advertises them (an env/termcap probe), ASCII fallback.
- Window border color already matches the namespace (the unspoofable domain border in
  wl-term); the theme reads the same `EPIN_DOMAIN_COLOR`. *Deliverable 8 (theme engine).*

## Z8 — Completion engine · ☐ · P: Med · E: 3 · deps: Z2, Z5

- Upstream zsh completion + AnonymOS extensions (`_objctl`, `_identityctl`, `_nsctl`,
  `_capctl`, `_servicectl`, `_packagectl`): complete objects, capabilities, namespaces,
  services, packages, identities, permissions — driven by `object_enumerate`/`service_lookup`
  (native) or the `/objects` FS views (Linux). *Deliverable 11 (completion).*

## Z9 — Plugin system · ☐ · P: Med · E: 3 · deps: Z2

- Standard zsh plugins (`git`, `history`, `fzf`, `extract`) load unchanged. Native plugins
  (`objects`, `identity`, `namespace`, `capabilities`, `security`, `process`, `package`,
  `services`) wrap the object/native-ABI commands — the `/hos-sh` builtins reborn as zsh
  plugins. Integrate `zsh-autosuggestions` (history-driven) and `zsh-syntax-highlighting`
  (grammar extended for `objctl/identityctl/nsctl/servicectl/packagectl`).
- *Deliverable 10 (plugin architecture).* Plugins dynamically loaded (Z2).

## Z9b — Oh My Zsh + Powerlevel ("over 9000") · ☐ · P: Med · E: 3 · deps: Z5, Z7, Z9

The popular customization stack (cf. the `ni-c/install-zsh.sh` gist — oh-my-zsh +
powerlevel9k + zsh-autosuggestions + zsh-syntax-highlighting + Nerd Fonts), made
**available so anyone can customize their shell** the way they already know how. We vendor
the frameworks (no network at runtime) and wire them to the AnonymOS prompt data.

- **Oh My Zsh** — vendor the framework under `/system/shell/zsh/omz/` (cached, pinned). A
  default `~/.zshrc` sources `$ZSH/oh-my-zsh.sh`, sets `plugins=(…)` and `ZSH_THEME=…`. Users
  customize by editing `~/.zshrc` exactly as upstream — the whole point.
- **Powerlevel9k / Powerlevel10k** — vendor as a custom theme
  (`$ZSH/custom/themes/powerlevel10k`). The brief's segment layout maps cleanly to AnonymOS:
  ```
  POWERLEVEL9K_LEFT_PROMPT_ELEMENTS=(anonymos_identity anonymos_namespace dir vcs)
  POWERLEVEL9K_RIGHT_PROMPT_ELEMENTS=(anonymos_caps status background_jobs time)
  POWERLEVEL9K_MODE="nerdfont-complete"
  ```
  We add three **custom prompt segments** (a tiny `prompt_anonymos_*` each) that surface the
  same fields the live prompt already shows (Z6): `anonymos_identity` (the security domain),
  `anonymos_namespace` (with the domain color as the segment background), and `anonymos_caps`
  (the capability flags `fs:rw net:nat ipc …`). On native zsh they read the identity/namespace/
  caps via the platform layer (`object_query`/`namespace_lookup`/`cap_rights`); on Linux zsh
  they read the `EPIN_*` env. The `custom_live`-style example from the gist becomes an
  `anonymos_disposable` segment that flags disposable domains.
- **zsh-autosuggestions** + **zsh-syntax-highlighting** — vendor under `$ZSH/custom/plugins/`,
  enabled by default in the shipped `.zshrc` (this is Z9's "standard plugins load unchanged",
  pinned to the gist's choices). Syntax-highlighting grammar is extended for
  `objctl/identityctl/nsctl/servicectl/packagectl` (Z9).
- **Nerd Fonts** — bundle one patched Nerd Font into the asset blob (the GUI font path already
  ships TTFs); the terminal advertises it so the powerline glyphs render, ASCII fallback
  otherwise (Z7).
- **An installer for parity with the gist** — `omz-setup` (a native script, the AnonymOS
  analogue of `install-zsh.sh`): copies the default `.zshrc`, selects powerlevel10k, enables
  the two plugins, and is idempotent — so "set up my shell like the gist" is one command, but
  fully offline and capability-respecting (it never fetches from the network; everything is
  vendored).
- *Deliverables 8/10/11 (theme/plugin/completion) realized as the familiar OMZ experience.*

## Z10 — History (incl. secure) · ☐ · P: Med · E: 2 · deps: Z1

- Persistent shared history (`fc`, `Ctrl-R`). **Per identity / per namespace / per
  disposable** history files, encrypted when `shell.json` requests it (over the existing
  crypto: ChaCha20-Poly1305 in [`core/secipc.d`](../src/kernel/d/core/secipc.d)), with
  automatic expiration for disposable domains. History is shared across namespaces only when
  policy allows (a `namespace_bind` decision). *Deliverable 12–15 (the integration set).*

## Z11 — Login flow + default shell · ☐ · P: Med · E: 2 · deps: Z1, Z5

- `display-manager → auth → identity → namespace → PTY → zsh → shell.json → .zshrc →
  plugins → theme → prompt`. New users get `/system/shell/zsh/zsh` as their login shell;
  the Domain Manager's per-domain Shell control gains a "zsh" option alongside linux/native.

## Z12 — Security review + tests + benchmarks · ☐ · P: High · E: 3 · deps: all

- *Deliverable 16 (security review):* zsh never bypasses the capability/identity/namespace
  managers — every privileged op goes through the native ABI (which is itself gated to the
  native personality), and Linux-personality zsh simply cannot reach the object ABI
  (`ENOSYS`, NATIVE_OBJECT_ABI §3). Audit the platform layer for ambient-authority leaks.
- *Deliverable 17 (test plan) + 18 (regression):* run upstream zsh's test suite (the
  subset the syscall set supports) on Linux-personality zsh; golden-prompt + completion +
  plugin smoke tests headless via the QMP harness (relative-mouse + screendump,
  [[window-decorations]]); reboot/persistence checks for history.
- *Deliverable 19 (benchmarks):* startup time, prompt render latency, completion latency vs
  busybox `ash` and `/hos-sh`; ensure zsh's larger footprint fits the 512 MiB boot ceiling.

---

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

## Companion: ratty terminal emulator roadmap

[ratty](https://github.com/orhun/ratty) (orhun) is a Rust, GPU-accelerated terminal
emulator. It is the **terminal** layer, distinct from the **shell** (zsh) above: ratty
draws the grid and owns the PTY; zsh runs inside it. The goal is to make ratty the
AnonymOS terminal that *hosts* zsh — the same "the terminal contains no shell logic, only
PTY + rendering" split this roadmap mandates (Z3). It supersedes/augments the current
`wl-term`. This was Track C of `SHELL_AND_COMMANDS_ROADMAP.md`; gated on a Rust toolchain
+ a GPU stack the OS does not yet have (software Pixman only — see [[weston-perf-profiling]]).

- **R0 — Rust musl toolchain · E: 3.** Stand up a Rust→musl cross-compiler producing static
  AnonymOS binaries (the analogue of the `musl-clang` C toolchain that builds the Wayland
  clients). Validate with a "hello, Wayland" Rust client over the live Linux ABI. **Hard
  dependency for everything below — no Rust on the host today.**
- **R1 — CPU/Ratatui intermediate · E: 2 · deps: R0.** A CPU-rendered Ratatui terminal (the
  ratatui ecosystem ratty builds on) on the software Wayland/SHM path the GUI clients use —
  proves PTY + input + Unicode rendering in Rust without needing the GPU. A usable terminal
  on the current stack; de-risks the ratty port.
- **R2 — GPU stack · E: 5 · deps: R1.** ratty renders via `wgpu`/Vulkan/GL. The OS is
  software-Pixman only; this needs the GPU/Mesa work tracked under desktop responsiveness
  R8 (a real render node + EGL, the dmabuf import the Hyprland bring-up stalled on). The
  largest dependency and the reason ratty is later-stage.
- **R3 — ratty port · E: 4 · deps: R2.** Build ratty for AnonymOS: PTY against `/dev/ptmx`
  (live) or the native `Device` PTY object (§12), input via the Wayland seat, clipboard via
  OSC52, and the GPU backend from R2. Honour the unspoofable per-domain window border
  (the identity color) the kernel/compositor already enforce.
- **R4 — make ratty the terminal · E: 2 · deps: R3.** ratty launches `zsh` on a PTY and
  nothing else (Z3); the desktop's terminal keybinding + the Domain Manager "Launch Terminal"
  target ratty. Feature parity with `wl-term` (decorations, domain border, scrollback) plus
  ratty's extras (tabs, true-color, ligatures, GPU scrolling, Kitty-graphics/Sixel later).
- **R5 — advanced terminal features · E: 3.** 24-bit color, Nerd-Font glyphs (shared with
  Z9b), bracketed paste, OSC52 clipboard, hyperlinks, mouse, Kitty graphics + Sixel (future).

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
