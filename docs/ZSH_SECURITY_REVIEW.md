# zsh / native-ABI security review (Z12.1, Deliverable 16)

**Scope.** The zsh "platform layer" and the native object ABI it reaches: the per-task
personality gate, the native-exec binding, the six Z4 event/IPC/mutation verbs, the native
FS/device verbs, the `anon.c` `--wrap` hooks, the in-process `zsh/anonymos` zmodule, and the
native `zshrc` block. Method: four independent adversarial code audits of the platform layer,
each finding verified against the source (file:line) and the live build.

**Core invariant — VERIFIED SOUND.** A Linux-personality zsh cannot reach the native object ABI.
`HOS_SYS_QUERY` (syscall `0x4000`) is gated at [kernel_main.d:1952](../src/kernel/d/core/kernel_main.d#L1952):

```d
case HOS_SYS_QUERY: {
    const int ctid = cast(int)g_current_task_id;
    if (ctid < 0 || ctid >= MAX_TASKS || !g_taskNativeAbi[ctid]) { ret = -38; break; }
```

`g_taskNativeAbi` is written in exactly three sites (fork-inherit, clone-inherit, and the exec
binding) — never from env/argv/userspace data. Every HOSQ verb, including the six Z4 additions,
sits behind this single check. The shell-level `EPIN_SHELL=native` env check is **cosmetic UX,
not a security boundary**: a Linux shell can `export EPIN_SHELL=native`, but every native-ABI
call still returns `ENOSYS` because the *task* is `/bin/zsh`, not the native image. The kernel
personality flag is the sole enforcement.

## Findings

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| F1 | Native personality gate spoofable via a user-created `hos-zsh` symlink | **High** | ✅ Fixed |
| F2 | `cap_grant` rights-ceiling fails *open* when the identity record is missing | Low | ✅ Fixed |
| F3 | `ns_enter` could pass its owner-gate on a recycled (released+reused) object id | Low | ✅ Fixed |
| F4 | Read/write data path does not validate the user `buf` pointer (kernel-addr deref) | High* | 📋 Documented — pre-existing, OS-wide |
| F5 | "Namespace gating" of opens is nominal for the login shell (`/`→`uint.max` bind) | Medium | 📋 Documented — not a native-ABI escalation |
| F6 | rtfs has no per-file mode enforcement (RO file openable `O_RDWR`) | Low | 📋 Documented — pre-existing |
| F7 | `ns_clone` never reclaims un-entered clones (`NS_MAX=64` self-DoS) | Low | 📋 Documented |

### F1 — Native personality gate spoofable via `hos-zsh` symlink · **High** · ✅ Fixed
The native flag was set from the **request** basename, not the resolved image:
`g_taskNativeAbi[tid] = (execName=="hos-sh") || (origBase=="hos-zsh")`. `origBase` comes from the
caller-supplied path, while the loaded image is the symlink *target*. `symlinkat(2)` (syscall 266)
is reachable by an unprivileged task with no cap/uid gate ([posix.d `linux_sys_symlinkat`](../src/kernel/d/core/syscalls/posix.d)),
and `/tmp` is world-writable (mode 1777). So `symlinkat("/busybox","/tmp/hos-zsh"); execve("/tmp/hos-zsh")`
loads busybox (`execName=="busybox"`) yet sets the native flag (`origBase=="hos-zsh"`) — an arbitrary
boot module onto the native ABI. Impact is dominated by **information disclosure** (the ungated
`obj/id/ns/svc/sys` enumeration leaks the object table + identity domains with their trust levels
and rights-ceilings) — the mutation verbs are independently gated and non-escalating — but it breaks
the architectural invariant that the object ABI is unreachable outside the trusted native shell.

**Fix** ([kernel_main.d:844](../src/kernel/d/core/kernel_main.d#L844)): require the **trusted image**,
not just the request basename. `/hos-zsh` canonicalises to the `/zsh` boot module (`execName=="zsh"`);
a spoofed `/tmp/hos-zsh -> /busybox` has `execName=="busybox"` and is denied:

```d
g_taskNativeAbi[tid] = (execName !is null && cstrEqK(execName, "hos-sh")) ||
                       (execName !is null && cstrEqK(execName, "zsh") &&
                        origBase !is null && cstrEqK(origBase, "hos-zsh"));
```

### F2 — `cap_grant` ceiling fails open on missing identity · Low · ✅ Fixed
`hosCapGrant` computed `ceiling = (identity != null) ? identity.rightsCeiling : src.rights` — for an
identity-less task the rights-ceiling clamp silently vanished (still no escalation, since the result
is `≤ src.rights`, but it dropped a defence). **Fix** ([hoscall.d](../src/kernel/d/core/hoscall.d)):
a missing identity yields `ceiling = 0` ⇒ `newRights = 0` ⇒ deny (fail closed).

### F3 — `ns_enter` recycled-id hazard · Low · ✅ Fixed
Object ids are recycled with no generation tag. `ns_enter(N)` checked only `N == g_taskOwnedNs[tid]`;
if the cloned namespace `N` were released and `N` recycled to a non-namespace object, the gate would
pass. **Fix** ([hoscall.d](../src/kernel/d/core/hoscall.d)): also require `nsRecByObj(N) !is null` —
re-validate `N` still resolves to a live namespace before committing the switch (fail closed).

### F4 — Unchecked user `buf` in the read/write path · High* · 📋 Documented (pre-existing, OS-wide)
The data verbs (`object_send`/`recv`, `object_read`/`write`, `device_read`/`write`) forward `buf`
straight to `linux_sys_read`/`write` with no `access_ok` range check, so a caller can pass a *kernel*
address (SMAP is intentionally disabled in the dev config — `-cpu qemu64,-smap,-smep`). **This is not
introduced by, or specific to, the native ABI** — it is the *same* gap in `read`/`write` (syscalls
0/1) available to **every** Linux task; the native verbs are one-line pass-throughs to it and widen
nothing (after F1, the native surface is restricted to the trusted shell anyway). The correct fix is
an OS-wide `access_ok(buf, len)` helper applied at the `sys_read`/`sys_write` boundary plus enabling
SMAP — a kernel-hardening track orthogonal to the zsh layer. **Recommended as a separate effort;**
out of scope for Z12 (which audits the zsh/native-ABI layer, not the entire Linux-compat syscall
surface). Tracked here so it is not forgotten.

### F5 — Nominal namespace gating of opens · Medium · 📋 Documented (not a native-ABI escalation)
The roadmap describes native opens as "namespace-gated". The gate code exists and runs
(`namespaceCheckOpen` on every absolute open), but every runtime namespace carries the default
`bindRoot` binding `"/" → rtfs-root @ rights=uint.max`, which `bindMatches` treats as matching every
path — so the check always passes. The restricting builders (`idnsForIdentity`, `linuxAppCreate`) that
would narrow `/` are reachable only from boot self-tests on the live path. **Crucially this is not a
native-ABI escalation**: `hosOpen` is `linux_sys_open` over the *same* `sys_open`, fd table, and
namespace — a Linux `open()` from the same task reaches exactly the same paths. The weakness is in the
namespace *setup* and is identical in both personalities. **Recommended:** bind the per-domain login
shell into a restricted namespace (narrow/drop the catch-all `/` bind) so the claimed isolation is
enforced. Deferred — it is a behaviour change (could break the shell's legitimate file access) needing
its own design + testing pass.

### F6 — No per-file mode enforcement · Low · 📋 Documented (pre-existing)
An `RT_REG` file can be opened `O_RDWR` regardless of its stored mode (the synthetic `/system`, `/proc`,
and objfs views *do* strip write flags and are protected). Identical for Linux and native callers; not
native-specific. Recommended fix: enforce `g_rt[].mode` vs the requested access in the `RT_REG` open
branch. Deferred.

### F7 — `ns_clone` leaks un-entered clones · Low · 📋 Documented
Each `namespace_clone()` allocates an `NS_MAX=64`-table slot that is never reclaimed if the task never
enters/exits it — an unprivileged local DoS on the namespace table, though after F1 only the trusted
native shell can reach it (self-inflicted). Recommended fix: release the previously-owned-but-unentered
clone when a new one is made, and on task exit. Deferred.

## Verified safe (no action needed)

- **`cap_grant` attenuation is sound** — `newRights = want ∩ src.rights ∩ ceiling`, re-masked
  `& CAP_RIGHT_UNIVERSE` on install; cannot grant more than held, monotonic shrink, deny on empty.
  `src` is `capUsable`-checked (rejects OOB / revoked / `objId==0`) before its rights are read. The
  cap table is per-task (`g_activeCapTabId` = the caller's), so no cross-task aliasing.
- **`ns_enter`/`ns_clone` cannot reach another domain's namespace** — `g_taskOwnedNs` is written only
  by `ns_clone`, which clones the caller's *own* current namespace; there is no caller-supplied source.
- **`send`/`recv` cannot reach another task's fd** — `fd` indexes the caller's own active fd table and
  is additionally `requireCap`-checked against the caller's own cap rights.
- **`zsh/anonymos` module is memory-safe and minimal** — the kernel's `put()` strictly bounds buffer
  writes to `buflen`, so `hosbuf[n]=0` is always in-bounds; the module exposes only the five read-only
  enumeration verbs (no mutations); on the Linux personality the builtins get `ENOSYS` and print
  "unavailable" — harmless.
- **`anon.c --wrap` hooks are correct** — `is_native()` probes once and caches; the kernel flag is
  fixed per image and inherited on fork, so no TOCTOU and a Linux zsh never misroutes (worst case: a
  graceful `ENOSYS`). All wrappers fall through to `__real_*` when not native with no arg corruption,
  fd leak, or semantic change; no memory-safety issue in the wrappers themselves.
- **`.hos_id` prompt handling has no injection or secret leak** — `read -r` (no eval / command-subst),
  `%`-escaped before use in `PROMPT`, `PROMPT_SUBST` off, content is non-sensitive identity labels,
  file unlinked immediately.
- **No ambient-authority leak in the zshrc** — external data (`shell.json`) is parsed line-by-line, not
  sourced/eval'd; sourced paths are kernel-seeded read-only (`/system`, `/etc`) or the user's own
  `$HOME`; `fpath`/`PATH` carry no writable dir; expansions are quoted/sanitised.

## Summary

The native object ABI's enforcement boundary — the per-task `g_taskNativeAbi` kernel gate — is sound,
and the Z4 mutation verbs are non-escalating by construction. The one substantive vulnerability (F1,
the spoofable personality grant) and two fail-closed hardenings (F2, F3) are **fixed**. The remaining
items are pre-existing, OS-wide hardening gaps (F4 user-pointer validation, F6 file modes) or
namespace-setup weaknesses equally present in the Linux personality (F5) — documented with rationale
and recommended as orthogonal kernel-hardening work, not zsh-layer defects.
