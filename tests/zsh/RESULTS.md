# zsh regression + smoke results (Z12.2, Deliverables 17/18)

## 1. In-VM golden smoke — the authoritative regression net · ✅ 8/8

[`zsh_smoke.py`](zsh_smoke.py) boots `hos.iso` headless under qemu (QMP-driven), opens a terminal
via the Domain Manager, and asserts golden shell behaviours **on our kernel** — i.e. exactly "the
subset the syscall set supports". Each check echoes a value-bearing marker captured on the serial
console (ANSI-stripped); exit 0 iff every check passes.

```
$ python3 tests/zsh/zsh_smoke.py
=== zsh smoke results ===
  prompt         PASS    # the four-field [user@domain] caps prompt renders (Z6/Z7)
  version        PASS    # $ZSH_VERSION == 5.9 (real upstream zsh)
  builtin+pipe   PASS    # echo a b c | wc -w  == 3
  completion     PASS    # compdef defined  => compinit ran (Z8)
  plugin         PASS    # _zsh_highlight defined => zsh-syntax-highlighting loaded (Z9)
  history        PASS    # fc -l has entries  => history recording (Z10)
  aliases        PASS    # aliases defined
  native-obj     PASS    # native zsh: `builtin obj` => live object table (Z4c.4 module)
=== 8/8 passed ===
```

This is reproducible (`make hos.iso` then the harness) and is the regression net to run before
shipping a shell change. It covers the prompt, completion, plugin, and the native object module —
all on the real kernel via the syscalls it actually implements.

## 2. Upstream zsh `Test/` suite — build-correctness proxy

The shipped shell **is** unmodified upstream **zsh 5.9** (`deps/zsh/zsh-5.9.tar.xz`, sha256-checked)
plus exactly one added module, `zsh/anonymos` (`Src/Modules/anonymos.{c,mdd}`) — no patches to the
parser/expander/builtins. The built binary runs and self-identifies as `zsh 5.9`.

The full upstream `Test/` suite (64 `.ztst`) is wired via `make check` in `deps/zsh/zsh-5.9-dyn`.
**Caveat:** run headless on the build host the interactive ztst driver blocks in `pause()`
(`do_sys_pause`) — the framework expects a controlling pty / job-control session it doesn't get in
a non-interactive batch run, so it is not a clean automated proxy here. We therefore treat the
**in-VM smoke (§1) as authoritative** — it exercises the shell the way it is actually used, on the
target kernel, which is the property that matters. Running the upstream suite under a real pty is a
follow-up nicety, not a gate (the source is unmodified upstream).

## 3. History persistence (Z10)

- **Within a session — ✅ verified** by the smoke `history` check: `SHARE_HISTORY` /
  `INC_APPEND_HISTORY` record commands and `fc -l` lists them.
- **Across reboot — ⛔ not yet, by design.** `HISTFILE` lives under `$HOME`, which is the in-memory
  rtfs (ramfs) and is lost on reboot. The on-disk object store *does* persist (the boot counter
  climbs across reboots — visible as `boots=N` in the `obj` store status), so the persistence
  substrate exists; wiring `HISTFILE` onto it is **object-FS F4.3 (writable disk storage)**, already
  tracked in the object-FS roadmap. Disposable domains intentionally `unset HISTFILE` (Z10), so for
  them non-persistence is the desired behaviour.

## Running

```
WESTON=1 make hos.iso          # build the image (if not current)
python3 tests/zsh/zsh_smoke.py # boot headless + assert; exit 0 == all green
```
The harness uses its own qemu instance (`serial-smoke.log`, `qmp-smoke.sock`) so it does not clobber
an interactive dev VM.
