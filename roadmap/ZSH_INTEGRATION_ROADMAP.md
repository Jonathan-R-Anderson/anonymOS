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

## Z0 — Toolchain + upstream fetch · ✅ DONE · P: High · E: 2

- **Vendored** the upstream `zsh-5.9.tar.xz` under `deps/zsh/`, pinned + SHA256-verified
  (`9b8d1ec…`), mirroring how `deps/busybox` vendors its tarball (offline-cached; the
  build never fetches if the tarball is present).
- **Term-lib prerequisite:** zsh needs a curses/termcap library, which the musl sysroot
  lacks, so the build also vendors + builds **ncurses-6.4** (`6931283…`) against musl —
  `libncursesw.a`/`libtinfow.a`, widechar, **with the terminal entries compiled in**
  (`--with-fallbacks=linux,xterm,xterm-256color,vt100,…`) so **no terminfo DB is needed**
  on the OS (TERM=linux, which wl-term sets, is built in).
- **Wired into the Makefile** (`deps/zsh/Makefile` + top-level `make zsh`): configures with
  the existing `musl-clang` toolchain (x86-64 musl runs on the x86-64 build host, so
  configure's test programs run natively — no cross-compile cache) and builds a **static**
  zsh with `--disable-dynamic` (modules linked in) + `--disable-dynamic-nss`. (The
  `--enable-shared`/dynamically-loaded-module split is Z2; static is the correct first
  build for musl and for Z1.)
- *Deliverable 5 (build), 1 (source tree).* **No OS behaviour change** — zsh is built but
  **not** staged into `hos.iso` yet (that's Z1).
- *Verified:* a clean `make zsh` produces a 1.8 MB static x86-64 musl ELF that runs —
  `zsh --version` = 5.9; arrays, associative arrays, and globbing/modifiers all work.

## Z1 — Linux-personality zsh · ✅ DONE · P: High · E: 3 · deps: Z0

- **Staged** the static-musl zsh (Z0) as a limine **boot module `/zsh`** + rtfs symlinks
  `/bin/zsh` and `/system/shell/zsh/zsh` → it (`rtInit`); the iso build copies it (`make`
  wired `$(ZSH_BIN)` into the `hos.iso` prereqs + `cd/zsh`).
- `exec("/bin/zsh")` runs upstream **zsh 5.9** as the default Linux shell — wl-term's
  `linux` flavour launches `/zsh` (argv0 `-zsh`, a login shell); busybox stays as `/bin/sh`
  and as the coreutils zsh execs. `/etc/passwd` shell for `user`/`root` is now `/bin/zsh`.
- *Verified live in the GUI:* prompt with all four fields (`[domain] user [perms]:cwd%`),
  builtins (`echo`, `for` loops, arrays), **external commands** (`whoami`, `uname`, `ls`,
  `id`, `tr`), **pipes** (`echo … | cat`), command sequences (`;`), `$var` expansion —
  all run, each returning cleanly to the prompt.
- **Three kernel fixes were required** (the syscall gaps the risk note predicted, plus two
  deeper ones), all in `posix.d`/`kernel_main.d`/`task.d`:
  1. **Blocking pipe reads** — zsh's `execcmd_fork` does a blocking `read_loop` on a
     `pipe()` to sync with the forked child; the kernel returned EAGAIN. Added
     `pipeBlockingReadFd` so the dispatcher rewinds+yields (like a PTY) until the child
     writes — the cooperative-scheduler blocking-read path now covers pipes.
  2. **Userspace SIGCHLD handler delivery** — zsh waits for jobs via SIGCHLD (it picked
     `BROKEN_POSIX_SIGSUSPEND`, so really `sigprocmask`+`pause`), but the kernel had no
     handler invocation at all (only default-terminate). Built x86-64 rt_sigframe delivery
     (`deliverUserSignal` + `rt_sigreturn`/`case 15`, handler/restorer stored by
     `rt_sigaction`), delivered from the `pause`/`sigsuspend` wait point (`case 34/130`)
     where SIGCHLD is unblocked. **General signal-handler delivery — benefits the whole OS.**
  3. **pid stability across exit** — `linuxPidForTask = processLeaderTid+1`, and exit
     cleanup zeroes `processLeaderTid`, so `wait4` returned pid 1 instead of the pid `fork`
     gave the parent; zsh matches reaped pids to its job table, so the job never went DONE.
     Snapshot the pid at `exitTask` entry (`g_childExitLinuxPid`) and return it from wait4.
  - Plus 3 already-implemented handlers wired into dispatch (98 `getrusage`, 138 `fstatfs`,
    439 `faccessat2`), and `unsetopt MONITOR` in `/etc/zshrc` (job control needs process
    groups the cooperative kernel doesn't fully model; `^Z`/`bg`/`fg` are a later item).
- *Deliverable 4 (Linux integration), 18 (regression vs upstream).* Remaining nuance:
  full job control (process groups + `tcsetpgrp`) and the upstream test-suite run are
  follow-ups; the interactive shell is fully usable.

## Z2 — Dynamic linking · ✅ DONE · P: Med · E: 3 · deps: Z1

- zsh is now built **dynamically** (`deps/zsh/Makefile`: `--enable-dynamic`, replacing Z1's
  static `--disable-dynamic`): a PIE `zsh` with `PT_INTERP=ld-musl` + `NEEDED libc.so`, plus
  **36 dlopen-able zmodule `.so`** (`zle`, `complete`, `compctl`, `computil`, `zutil`,
  `parameter`, `terminfo`, …).  (zsh keeps its core in the exe rather than a separate
  `libzsh.so`; the modules resolve the core symbols from the exe — see the export-dynamic
  note below.)
- **Loaded over the existing kernel dynamic linker:** the OS execs `/zsh` → ld-musl
  (PT_INTERP) loads `libc.so`; zsh then dlopens `/system/shell/zsh/lib/zsh/5.9/zsh/<m>.so`,
  which the kernel resolves by **basename → boot module** (the same `.so` path the GUI stack
  uses; [posix.d](../src/kernel/d/core/syscalls/posix.d) `isSharedObject`/basename resolve).
  The 36 modules + ld-musl are staged as boot modules by the iso build.
- *Verified live in the OS:* the serial shows zsh dlopening `zle.so`/`complete.so`/`compctl.so`
  from the module path; `zmodload` lists `zsh/zle zsh/complete zsh/compctl zsh/main` loaded;
  the shell is fully functional (prompt rendered by the dlopen'd zle, builtins, external
  commands, pipes) — no relocation failures.
- **Two cross-build gotchas** (recorded for Z4+ and any future dynamic dep):
  1. configure can't *run* its musl-dynamic probe programs on the glibc build host, so the
     dynamic-loading capabilities are passed as `zsh_cv_*` cache vars (true for ELF/musl);
     Z1's static build sidestepped this because static binaries run anywhere.
  2. the rdynamic flag that exports the exe's symbols to its modules is set only inside
     configure's (cache-skipped) rdynamic test, so it must be forced via
     `EXTRA_LDFLAGS=-Wl,--export-dynamic` — without it modules fail `hashgetfn: not found`.
- *Deliverable 6 (dynamic linking).* **Validates the kernel loader against a second large
  dynamic program besides the GUI stack** (zsh + 36 dlopen'd modules), as intended.

## Z3 — PTY / terminal split · ✅ DONE · P: High · E: 2 · deps: Z1

- **wl-term is a pure terminal** — `spawn_shell` only opens `/dev/ptmx`, forks, and
  `execve`s the shell on the slave (no parsing/builtins/command logic).  Its default
  Linux shell is now the canonical **`/bin/zsh`** (the rtfs symlink → the `/zsh` boot
  module).  It keeps keyboard/pointer/PTY/Unicode/rendering/window-decoration duties;
  everything line-editing is zsh.
- **termios line discipline** (kernel PTY, `posix.d` `ptyIoctl`/`ptyInputByte`) is complete
  for ZLE: `TCSETS` *applies* the termios so zsh's raw mode (ICANON/ECHO off) takes effect;
  raw passthrough, canonical VERASE/VKILL editing, ISIG (^C/^\), `TIOCGWINSZ/SWINSZ`, and
  `TIOC[GS]PGRP` all work.
- **The coverage check found + fixed two real gaps** (wl-term, both verified live):
  1. *Input:* `key_to_pty` didn't emit escape sequences for navigation keys — so Up/Down
     (history), Left/Right (cursor), Home/End/Del/PgUp/PgDn did nothing.  Added the
     linux-console sequences (`\E[A..D`, `\E[N~`).
  2. *Output:* the VT interpreter merely **swallowed** CSI sequences, so ZLE's line-redraw
     (cursor addressing + erase) was lost — recalling history over an existing line printed
     `second-cmdfirst-cmd`.  Added a real CSI interpreter (`vt_exec_csi`): cursor move
     (`A/B/C/D/G/H`), erase line/display (`K/J`), insert/delete chars (`@/P`).
- **^C** now aborts the line and interrupts a running foreground command.  This needed
  extending Z1's signal delivery to **SIGINT**: `deliverSignalToGroup` no longer skips a
  handler-bearing task (zsh), the run loop leaves a handler-signal pending so it is
  delivered at the next blocking read as an **EINTR** (POSIX), and zsh's own SIGINT handler
  then aborts ZLE.  A foreground command (default disposition) is still terminated.  (The
  fg-group is `lastReader`-scoped, so ^C hits the running command, not the shell behind it.)
- *Verified live:* history (Up/Down) with clean redraw, in-line cursor editing
  (`echo abcde` → Left×2 → insert → `echo abcXde`), **tab completion** (`ls /et`<Tab> →
  `/etc`), and ^C (aborts the line; interrupts `sleep 9` instantly) — external commands /
  pipes unregressed.
- *Deliverable 7 (PTY/terminal).*  Remaining job-control items (`^Z`/`bg`/`fg`, process
  groups + `tcsetpgrp`) stay deferred per Z1.

## Z4 — Native platform layer · ◐ IN PROGRESS · P: High · E: 5 · deps: Z1, Z2

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

**Decision (this pass): begin the true native-ABI port — start with the FS path.** Not the
pragmatic "zsh-in-native-personality-over-the-Linux-ABI" shortcut; the real platform layer.
The native ABI today is read-only `HOSQ_*` queries, so each phase below first adds the
needed kernel verbs, then the zsh host-hook that uses them. Tracked sub-steps:

### Z4a — FS + TTY + process hooks → interactive native prompt

- **Z4a.1 — Kernel native FS verbs** · ✅ DONE · `object_open`/`read`/`write`/`close`/`lseek`
  as `HOS_SYS_QUERY` ops (`HOSQ_OPEN`=7…`LSEEK`=11) in `hoscall.d`, with a per-task
  `g_nativeFd[]` native-handle table; the path resolves through the object FS (namespace-
  gated) and the handle reuses the VFS fd behind the scenes — the *surface* is pure native
  ABI (a native task never calls Linux `open`). Cleared on exec/exit (`hosClearHandles`).
- **Z4a.2 — Native FS test** · ✅ DONE · added a native `cat <path>` to `hos-sh` (already a
  native-personality task) that drives `object_open`+`object_read`+`object_close`. Verified
  live: `cat /etc/passwd` printed the file through the native ABI — proves the verbs +
  handle lifecycle end-to-end.
- **Z4a.3 — zsh `platform/anonymos/` host-hooks layer** · ☐ · add `Src/anon.c`/`anon.h` (built
  into zsh): `anon_open/read/write/close/lseek` that call the native ABI when the process is
  native personality, else fall through to the Linux syscall. The dispatch reads a one-time
  "am I native?" probe (a `HOSQ_SYS` success ⇒ native).
- **Z4a.4 — Wire zsh FS ops through the hooks** · ☐ · route zsh's file I/O (`open`/`read`/
  `write`/`close`/`lseek` in `zsh.h`/`utils.c`/`input.c`) through the `anon_*` shims. **No
  change to the parser/expander** — only the host I/O calls. Verify a sourced file
  (`source /etc/zshrc`) is read via `object_read`.
- **Z4a.5 — Native zsh launch** · ☐ · the Domain Manager's *native* shell flavor launches
  zsh in the **native personality** (the `HOS_SYS_QUERY` gate open) via a native-shell image
  marker, not `/hos-sh`; verify zsh's FS flows through the native ABI (serial: `object_open`).
- **Z4a.6 — Native TTY (Device-object PTY)** · ☐ · expose the shell's controlling terminal as
  a `Device` object (§12): `device_open`/`device_read`/`device_write` verbs over the PTY, and
  route zsh's terminal I/O through them when native.
- **Z4a.7 — Native process spawn** · ☐ · `spawn_process` verb (§4) — create a process from an
  image cap + args/env in a namespace under an identity; route zsh's external-command exec
  through it when native (fork/exec → `spawn_process`).
- **Z4a.8 — Interactive native-ABI prompt** · ☐ · the milestone: an interactive zsh whose FS,
  TTY, and process spawning all flow through the native object ABI, reached at a prompt.

### Z4b — signals + IPC · ☐ · deps: Z4a

- Native signal delivery (`object_subscribe`/`object_wait` for SIGCHLD/SIGINT, §6) and the
  message-passing IPC primitives (§8) behind zsh's job-wait + coproc/`zsh/zselect`.

### Z4c — env + cap + namespace + object hooks · ☐ · deps: Z4a

- Environment + capability passing on spawn, `namespace`/`object` hooks; the object commands
  (`obj/id/ns/svc/sys`) become first-class zsh builtins (overlaps Z9).

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

- **L0 — LFE reader (s-expressions) · ✅ DONE (first cut).** `hos-sh` now reads LFE forms:
  `(obj)`, `(id)`, `(ns)`, `(svc)`, `(sys)`, `(cd "/path")`, `(help)`, `(exit)` — outer parens
  dropped, `"string"` atoms unquoted, nested grouping flattened (`src/util/hos-sh.d`
  `lfeNormalize`). Bare words still work for convenience. Verified: `(sys)`/`(ns)`/
  `(cd "/objects/identities")` run and the prompt tracks the path.
- **L1 — vendor the `-sh` source · ☐ · E: 3.** Vendor the upstream `-sh` (LFE) project under
  `/system/shell/-sh/` (cached, pinned), like zsh under `/system/shell/zsh/`. Decide the
  runtime: a native LFE reader+evaluator in betterC D/Rust, OR LFE-on-BEAM if/when an Erlang
  VM is ported. (The current D `hos-sh` is the bootstrap; `-sh` upstream supersedes it.)
- **L2 — evaluator + builtins as LFE functions · ☐ · E: 4 · deps: L1.** The object commands
  become LFE functions over the native ABI: `(objects)` → `object_enumerate`, `(cap-grant cap
  proc)` → `cap_grant`, `(ns-bind ns path obj rights)` → `namespace_bind`, `(spawn manifest)`
  → `spawn_process`. Forms evaluate to data (lists/tuples) that further forms consume —
  pipelines as composition, not text streams.
- **L3 — full LFE language · ☐ · E: 5 · deps: L2.** Atoms, lists, tuples, maps, `defun`/
  `lambda`, `let`, pattern matching, guards, list comprehensions, macros — the real LFE so
  the native shell is a programmable Lisp over the object model (scripts, functions, the
  theme/prompt as LFE).
- **L4 — capability/namespace/identity-aware forms · ☐ · E: 3 · deps: L2.** First-class forms
  for the security model: `(identity)`/`(identity-switch …)`, `(namespace …)`, `(caps)`/
  `(cap-derive …)` — the same fields the prompt shows, manipulable as LFE. All gated by the
  native-personality gate (§3) and the identity ceiling — `-sh` never bypasses the managers.
- **L5 — make `-sh` the native shell · ☐ · E: 2 · deps: L3.** The Domain Manager's per-domain
  Shell control offers **linux (zsh)** / **native (`-sh`/LFE)**; `wl-term` (then ratty)
  launches whichever on the PTY. The native shell's prompt already shows the four fields
  (Z6) and now reads LFE.

> **Two shells, one terminal.** zsh and `-sh` are independent — zsh is POSIX for Linux
> programs, `-sh` is LFE for the object model; the terminal (`wl-term`, later ratty) hosts
> either. Neither blocks the other; both share the rich prompt and the customization config.

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
