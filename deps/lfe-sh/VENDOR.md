# Vendored `-sh` (LFE native shell) — L1 of ZSH_INTEGRATION_ROADMAP.md

## What this is
The AnonymOS **native-personality** shell: `-sh`, an s-expression / LFE (Lisp-Flavored Erlang)
shell whose forms `(verb target args…)` map onto the native object-ABI (the counterpart to zsh,
which is the Linux-personality POSIX shell). Vendored here cached + pinned, the way `deps/zsh/`
carries `zsh-5.9.tar.xz`.

- **Upstream:** https://github.com/Jonathan-R-Anderson/-sh
- **Pinned commit:** `a44ee38bfa8771f665d1a39590325a29b328d045`
- **Tarball:** `lfe-sh-a44ee38bfa87.tar.gz` (source only — the upstream's prebuilt `lfe-sh`/`lfe-sh.o`
  and `.git` are excluded), sha256 `28ca96a57ef470f28d5a488fd95e8c375f7022e7a210d2d4525839dc333eaf26`
- **Build:** `make` unpacks + checksum-verifies; `make host-build` compiles a host binary to validate.

## Runtime decision (L1.2): **native D evaluator — NOT LFE-on-BEAM**

The roadmap left the runtime open: *a native LFE reader+evaluator in betterC D/Rust, OR LFE-on-BEAM
if/when an Erlang VM is ported.* **Decision: the native D evaluator** — and it is already written:
upstream `-sh` is itself a **D** Lisp/LFE interpreter (`src/interpreter.d` + `src/shell/`,
`evalString`, built with `ldc2`). Rationale:

1. **It matches the platform.** The kernel and the `hos-sh` bootstrap are D; reusing the D toolchain
   (`ldc2`) keeps one compiler for the whole native stack. No second language runtime.
2. **BEAM is impractical here.** LFE-on-BEAM needs the entire Erlang VM ported to the object/cap
   kernel — months of work for a GC'd, scheduler-heavy runtime — to get a Lisp the upstream already
   provides natively in D. Rejected (revisit only if a full BEAM port ever lands for other reasons).
3. **Validated.** The pinned source compiles with `ldc2 1.36` + libreadline and evaluates LFE — e.g.
   `(+ 3 4)` → `7` — so it is a real evaluator, not just a reader.

The current betterC `hos-sh` (with `lfeNormalize`, L0: it *reads* `(obj)`/`(ns)`/… forms) is the
**bootstrap**; vendored `-sh` **supersedes** it as the real LFE evaluator from L2 on.

## OS-build adaptations (the L2 follow-ups — NOT done here)
Upstream `-sh` is **full D (Phobos/druntime)** linking **libreadline**; to run as an AnonymOS native
shell it needs, in L2:
- an `ldc2` **musl** target with Phobos/druntime (the analogue of how `deps/zsh` builds musl-dynamic),
- **libreadline replaced** by the OS PTY line input (the `hos-sh` `fgets`/PTY path, or a vendored
  linenoise) — the OS has no readline,
- the LFE **object-ABI forms** (`(objects)`→`object_enumerate`, `(cap-grant …)`→`cap_grant`,
  `(ns-bind …)`→`namespace_bind`, `(spawn …)`→`spawn_process`) wired to `HOS_SYS_QUERY`, **behind the
  native-personality gate + identity ceiling** like every other native-ABI caller (L2/L4),
- staged at `/system/shell/-sh/` in the rtfs (the way the built zsh lives at `/system/shell/zsh/`),
  and offered as the **native (`-sh`/LFE)** option by the Domain Manager Shell control (L5).

The 91 coreutils-style command modules in `src/` are optional (busybox already covers those on the
Linux side); the core to bring up is the reader + evaluator + the object-ABI forms.
