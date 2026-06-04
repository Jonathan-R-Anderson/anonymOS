# Security Hardening Roadmap

> Grounded in the **current** `src/kernel/d/` tree. Goal: incrementally harden the
> existing kernel toward rootless / capability-based / immutable / security-first,
> without a rewrite. Every task maps onto code that exists today.
>
> Phase gates are stated as "required before X." Note up front: this system has
> **already passed** several gates (BusyBox, Hyprland, partial networking run today),
> so for those the listed work is **security debt / retrofit**, not greenfield. That
> is called out per phase.

---

# Current Security Posture

**Effectively unhardened.** Concrete, file-level findings:

- **W^X is violated by default.** `core/syscalls/mmap.d` `sys_mmap` maps every page
  `map_flags = 0x7` (`PTE_PRESENT|PTE_RW|PTE_USER`, **no `PTE_NX`**). The real mmap
  path (`kernel_main.d` case 9) likewise maps `PTE_PRESENT|PTE_RW|PTE_USER`. **All
  anonymous and file-backed pages are R+W+X.** `sys_mprotect` *can* set `PTE_NX`
  (`mmap.d`), but nothing is NX until a program asks — and the loader relies on RWX.
- **Executable stack, fixed address, no guard.** `execveTask` (`kernel_main.d` ~530)
  maps a 32-page stack at the **fixed** `stackBase = 0x700000000000`, `PTE_RW|PTE_USER`
  (no NX). No guard page above/below. **NX stack: violated. Stack guard: absent.**
- **No ASLR anywhere.** Stack base fixed (`0x700000000000`), mmap is a deterministic
  bump (`g_nextMmapAddr`/`Task.mmapNext` from fixed bases `0x700000000000` /
  `0x740000000000`), ELF loads at a fixed bias. Fully predictable layout.
  *(Bonus bug: `allocTask` sets `mmapNext = 0x700000000000` — identical to the execve
  `stackBase` — a latent overlap.)*
- **SMAP/SMEP disabled.** `qemu-run.sh` runs `-cpu qemu64,-smap,-smep` to dodge a #GP
  when the DRM ioctl writes a user pointer. This **removes kernel/user separation
  hardening** to paper over a missing STAC/CLAC.
- **No stack canaries in OS-built binaries.** `Makefile` `FREESTANDING_CFLAGS` uses
  `-fno-stack-protector`; no `__stack_chk_guard` randomization in the kernel.
- **No capabilities, no MAC, no syscall filtering.** `dispatchLinuxSyscall`
  (`kernel_main.d`) serves the full Linux surface to **every** task identically.
- **Everyone is root.** `posix.d` `getuid`/`geteuid` return `0`; `SO_PEERCRED` returns
  root for any fd. No subject/label notion.
- **Unverified boot.** Limine loads kernel + modules (`Hyprland`, `libc.so`,
  `xkb.blob`, `assets.blob`) with **no hash/signature** check. No A/B, no rollback.
- **No runtime integrity / audit.** A page fault just `exitTask(tid, 11)`; nothing is
  logged, measured, or attested.

**Net:** memory-corruption mitigations ~0; isolation/authority model ~0; boot trust
~0. The only positive primitives that already exist: a working **paging layer with
`PTE_NX` defined** (`arch/x86_64/arch.d`), a per-region **perms** field
(`AddrRegion.perms`), a **per-process fd table** (`g_fdTabs`), and `mprotect` honoring
NX — i.e. the *mechanisms* exist; the *policy* doesn't.

---

# Existing Components Relevant To Security

| Component | File / symbol | Security relevance |
|---|---|---|
| Page mapper + NX bit | `arch/x86_64/arch.d`: `map_page_hhdm`, `unmap_page_hhdm`, `PTE_NX` (bit 63) | The lever for W^X, NX stack, guard pages, PROT enforcement. |
| Anonymous mmap | `core/syscalls/mmap.d`: `sys_mmap` (`map_flags=0x7`), `sys_mprotect`, `g_nextMmapAddr` | Where W^X + ASLR + guard pages get enforced. |
| File/anon mmap (real) | `kernel_main.d` case 9 (`useDrmPhys`/`useMemfd`/`useFile`/anon) | Same; honors `prot`? **No** — ignores it, maps RWX. |
| Address space / regions | `core/task.d`: `Task.regions[MAX_REGIONS]`, `AddrRegion{start,end,type,perms,physBase,owned}`, `addRegion`/`removeRegion`/`findRegion` | Per-mapping perms = the place to record W^X/guard/tag metadata. |
| Phys allocator | `memory/mm.d`: `alloc_phys_page`/`free_phys_page`/`g_free_pages`/`g_next_phys_alloc` | Heap-hardening + tagging hooks; currently bump+freelist, no canaries/quarantine. |
| Process lifecycle | `kernel_main.d`: `execveTask`, `forkTask`, `cloneThread`, `exitTask`, `loadElf` | Stack/guard/canary/shadow-stack/ASLR setup; capability-narrowing on spawn. |
| Fault handler | `kernel_main.d`: PF path → `exitTask(tid, 11)` | The hook for canary/guard/shadow-stack violation handling + audit logging. |
| Syscall dispatch | `kernel_main.d`: `dispatchSyscall`/`dispatchLinuxSyscall` | The choke point for per-process syscall policy + capability checks. |
| Per-process fd table | `posix.d`: `g_fdTabs`/`g_fdTable`, `fdtabForkCopy` | Proto-capability table (see `OBJECT_OS_ROADMAP.md` P6). |
| Identity | `posix.d`: `getuid`/`geteuid`→0, `SO_PEERCRED` | Must become capability/label-based (rootless). |
| Boot | `cd/boot/limine/limine.conf`, `scripts/`, Makefile ISO staging | Where verified boot + rollback attach. |

---

# Missing Components

W^X/NX policy · guard pages · ASLR/randomized VA allocator · stack canaries +
`__stack_chk_fail` · shadow stack · hardened heap (canaries/quarantine/delayed reuse) ·
software memory tagging · **capability objects** · **per-process syscall policy** ·
**MAC labels + policy engine** · **verified boot / signing / rollback** · integrity
measurement + security event log · immutable/signed system objects · **rootless subject
model**. (Capabilities, MAC, rootless, immutability are shared with the other roadmaps
in this folder — this doc is the *memory-safety + boot-trust + enforcement* slice.)

---

# Critical Blockers

These gate large fractions of the rest; do first.

1. **B1 — Honor `prot` in the mmap paths (enable per-page NX).** *Blocks:* W^X, NX
   stack, guard pages, MAC-on-pages. Today `mmap.d` and `kernel_main.d` case 9 ignore
   `prot` and map RWX. The loader (musl ld.so) currently leans on RWX; it must instead
   map data RW|NX and `mprotect(PROT_EXEC)` code after relocation — which ld.so already
   does, so the kernel just has to *stop forcing executability*. Complexity: **Medium**.
2. **B2 — Capability type + `requireCap` in `dispatchSyscall`.** *Blocks:* syscall
   sandboxing, MAC, rootless, capability containment. (Shared with
   `OBJECT_OS_ROADMAP.md` P6 and `IMMUTABLE_ROOTLESS_ROADMAP.md` §1.3/§3.) Complexity:
   **High**.
3. **B3 — In-kernel crypto (hash + ed25519 verify).** *Blocks:* verified boot, signed
   objects, integrity measurement, rollback. Complexity: **High**.
4. **B4 — Per-region security metadata.** Extend `AddrRegion` (and the object header
   from the OO roadmap) with `flags` (guard, tag, canary, immutable). *Blocks:* guard
   pages, tagging, immutability. Complexity: **Low**.
5. **B5 — STAC/CLAC around kernel→user copies, then re-enable SMAP/SMEP.** *Blocks:*
   honest kernel/user isolation. Complexity: **Medium**.

---

# Phase 1 Tasks — foundational memory safety (the "before a trusted shell" baseline)

*(BusyBox already runs here; treat as retrofit. These are the cheapest, highest-value
mitigations and touch only the mmap/exec/fault paths.)*

- **1.1 W^X enforcement.** *Desc:* default-map data RW|NX; only file code segments
  R-X; reject `mmap`/`mprotect` that requests W and X simultaneously. *Files:*
  `mmap.d` (`sys_mmap` `map_flags`, `sys_mprotect`), `kernel_main.d` case 9 (honor
  `prot`). *Reason:* stops attacker-written pages from executing — the single biggest
  ROP/shellcode reduction. *Complexity:* Medium. *Deps:* B1. *Benefit:* removes RWX
  primitive system-wide.
- **1.2 NX stack.** *Desc:* map the execve/thread stacks `PTE_RW|PTE_USER|PTE_NX`.
  *Files:* `kernel_main.d` `execveTask` (~530), `cloneThread` stack setup. *Reason:*
  classic stack-shellcode defense. *Complexity:* Low. *Deps:* B1. *Benefit:* stack data
  non-executable.
- **1.3 Stack guard pages.** *Desc:* leave one unmapped page below the stack (and above
  thread stacks); a fault there = guard hit. *Files:* `execveTask`/`cloneThread` stack
  alloc; PF handler (`kernel_main.d`) classifies guard faults. *Reason:* deterministic
  stack-overflow/clash detection. *Complexity:* Medium. *Deps:* B4. *Benefit:* contains
  stack overflow / stack-clash.
- **1.4 Guard pages around large mmap/heap regions.** *Desc:* for allocations ≥
  threshold, map an unmapped guard at each end. *Files:* `mmap.d` `sys_mmap`,
  `kernel_main.d` case 9. *Reason:* heap/buffer overflow containment. *Complexity:*
  Medium. *Deps:* B4. *Benefit:* OOB-write detection at region edges.
- **1.5 `__stack_chk_fail` + canary plumbing.** *Desc:* provide a kernel
  `__stack_chk_guard` (randomized at boot) and a `__stack_chk_fail` that terminates the
  task; build OS binaries **with** `-fstack-protector-strong` (flip the
  `-fno-stack-protector` in `Makefile` `FREESTANDING_CFLAGS`). *Files:* `Makefile`,
  a new `core/stackguard.d`, exports of `__stack_chk_*`. *Reason:* detect contiguous
  stack-buffer overflows. *Complexity:* Medium. *Deps:* a RNG source (`getrandom`
  exists in `posix.d`). *Benefit:* canary on every protected frame.
- **1.6 Per-thread randomized canaries.** *Desc:* re-randomize `__stack_chk_guard` per
  process at `execveTask`. *Files:* `execveTask`, TLS setup. *Reason:* prevents canary
  reuse across processes. *Complexity:* Low. *Deps:* 1.5. *Benefit:* per-process secret.
- **1.7 Fault-handler hardening + audit hook.** *Desc:* PF handler distinguishes
  guard/W^X/NX/canary faults, logs a security event, then terminates. *Files:*
  `kernel_main.d` PF path. *Reason:* turn silent `exitTask(11)` into a detectable,
  attributable event. *Complexity:* Low. *Deps:* 1.1–1.5. *Benefit:* tamper visibility.

**Phase-1 prerequisite:** B1, B4.

---

# Phase 2 Tasks — ASLR + capability/identity foundation (required before multi-user)

*(Multi-user is **not** real yet — `getuid`→0. This phase makes "another subject"
meaningful.)*

- **2.1 Randomized VA allocator.** *Desc:* replace the deterministic `g_nextMmapAddr` /
  `Task.mmapNext` bump with a randomized base + randomized gaps; fix the
  `mmapNext == stackBase` overlap. *Files:* `mmap.d` `g_nextMmapAddr`, `task.d`
  `mmapNext` init, `kernel_main.d` `execveTask`/`forkTask`/`cloneThread`. *Reason:*
  foundation for all ASLR. *Complexity:* Medium. *Deps:* RNG. *Benefit:* unpredictable
  mappings.
- **2.2 ASLR: stack / heap / mmap / ELF image / shared libs.** *Desc:* randomize
  `stackBase`, brk base, mmap base, ELF load bias (`loadElf` in `kernel_main.d`), and
  `.so` load addresses. *Files:* `execveTask`, `loadElf`, `brkTask`, `mmap.d`. *Reason:*
  defeats fixed-address ROP/data targeting. *Complexity:* High. *Deps:* 2.1. *Benefit:*
  per-process layout entropy.
- **2.3 ASLR for capability tables.** *Desc:* place the per-process cap table (B2) at a
  randomized address; never at a guessable offset. *Files:* B2 cap table alloc.
  *Reason:* capability tables are high-value targets. *Complexity:* Low. *Deps:* 2.1,
  B2. *Benefit:* protects the authority store.
- **2.4 Capability objects + fine-grained rights.** *Desc:* `Capability{objId,rights,
  deriveParent}`, per-process cap table generalizing `g_fdTabs`; `capDerive` (subset
  only), `capRevoke`. *Files:* new `core/cap.d`, `posix.d` (fd table), `task.d`.
  *Reason:* the unit of authority for sandboxing/MAC/rootless. *Complexity:* High.
  *Deps:* B2. *Benefit:* least-authority substrate. *(= `OBJECT_OS_ROADMAP.md` P6.)*
- **2.5 Capability reduction on spawn + inheritance rules.** *Desc:* `forkTask`/
  `execveTask` copy a **narrowed** cap table (child ⊆ parent). *Files:* `kernel_main.d`
  `forkTask`/`execveTask`, `fdtabForkCopy`→`capCloneNarrowing`. *Reason:* damage
  containment — a child can't exceed the parent. *Complexity:* Medium. *Deps:* 2.4.
  *Benefit:* monotonic privilege.
- **2.6 Rootless subject model.** *Desc:* `getuid`/`geteuid`/`SO_PEERCRED` consult a
  subject object + caps; remove `uid==0` privilege. *Files:* `posix.d`. *Reason:* no
  ambient super-user. *Complexity:* Medium. *Deps:* 2.4. *Benefit:* eliminates root.
  *(= `IMMUTABLE_ROOTLESS_ROADMAP.md` §3.1.)*

**Phase-2 prerequisite:** Phase 1, B2.

---

# Phase 3 Tasks — sandboxing + heap/tagging (required before exposing networking)

*(A network stack hugely widens attack surface; gate it behind syscall policy + a
hardened allocator.)*

- **3.1 Per-process syscall policy.** *Desc:* a policy bitmap/object per Process;
  `dispatchSyscall` checks it (and the relevant capability) before serving. *Files:*
  `kernel_main.d` `dispatchSyscall`/`dispatchLinuxSyscall`, `task.d`. *Reason:* restrict
  each process to the syscalls it needs (seccomp-equivalent). *Complexity:* High.
  *Deps:* 2.4. *Benefit:* shrinks kernel attack surface per process.
- **3.2 Capability-aware syscall enforcement / restricted domains.** *Desc:* privileged
  syscalls (`mount`, `reboot`, raw device ioctl, future `bind`) `requireCap`. *Files:*
  `kernel_main.d`, `posix.d`. *Reason:* policy-driven least authority. *Complexity:*
  Medium. *Deps:* 2.4, 3.1. *Benefit:* no syscall without authority.
- **3.3 Hardened heap allocator (kernel objects).** *Desc:* add allocation canaries,
  metadata separation, free-time corruption detection, **quarantine + delayed reuse**,
  and randomized free-list selection to `mm.d`'s page/object allocators. *Files:*
  `memory/mm.d` (`alloc_phys_page`/`free_phys_page`/`g_free_pages`), object allocator.
  *Reason:* UAF/double-free/overflow detection for kernel allocations. *Complexity:*
  High. *Deps:* B4. *Benefit:* heap-corruption resistance.
- **3.4 Software memory tagging framework.** *Desc:* tag bits in pointers + per-region
  tag metadata (`AddrRegion.flags`), validated on access (software MTE; structured for
  future hardware MTE/CHERI). Per-process opt-in. *Files:* `task.d` (`AddrRegion`),
  `mmap.d`, allocator. *Reason:* probabilistic spatial/temporal safety. *Complexity:*
  Extreme. *Deps:* 3.3, B4. *Benefit:* tag-mismatch traps on OOB/UAF.

**Phase-3 prerequisite:** Phase 2.

---

# Phase 4 Tasks — MAC + shadow stack (required before trusting the Linux compat layer)

*(Linux compat already runs; this hardens the boundary so a compromised Linux app is
contained.)*

- **4.1 Object + process labels.** *Desc:* a security label on every object header
  (OO roadmap) and Process; default-deny cross-label access. *Files:* `core/object.d`
  (header), `task.d`, `posix.d` resolution paths. *Reason:* mandatory containment
  independent of caps. *Complexity:* High. *Deps:* 2.4. *Benefit:* MAC isolation.
- **4.2 Policy engine (capability-aware MAC).** *Desc:* central decision point
  consulted by `requireCap`/open/IPC; **immutable, signed** policy. *Files:* new
  `core/mac.d`, `kernel_main.d`, `posix.d`. *Reason:* system-wide, tamper-proof rules.
  *Complexity:* High. *Deps:* 4.1, B3. *Benefit:* enforced policy, not ad-hoc checks.
- **4.3 Shadow stack.** *Desc:* allocate a separate shadow stack per thread at creation;
  push/validate return addresses; structured for hardware CET/shadow-stack. *Files:*
  `kernel_main.d` `cloneThread`/`execveTask` (stack setup), context switch in `arch/`,
  fault handler. *Reason:* backward-edge CFI (defeats ROP). *Complexity:* Extreme.
  *Deps:* 1.2, 1.3, compiler/runtime support. *Benefit:* return-address integrity.
- **4.4 Linux-compat sandbox.** *Desc:* run the `LinuxObject` subtree
  (`OBJECT_OS_ROADMAP.md` P12) under a restricted syscall policy + label + ephemeral
  namespace. *Files:* `kernel_main.d` dispatch, `posix.d`. *Reason:* a Linux RCE can't
  reach native objects it wasn't delegated. *Complexity:* High. *Deps:* 3.1, 4.1.
  *Benefit:* blast-radius containment for Linux apps.

**Phase-4 prerequisite:** Phase 3, B3.

---

# Phase 5 Tasks — production-grade: verified boot, integrity, immutability

- **5.1 In-kernel crypto.** *Desc:* BLAKE3/SHA-256 + ed25519 verify, available
  pre-fs. *Files:* new `core/crypto/`. *Reason:* gates everything below. *Complexity:*
  High. *Deps:* —. (= B3.) *Benefit:* trust primitives.
- **5.2 Verified boot / kernel signing / trust chain.** *Desc:* sign the kernel + a
  module manifest; verify in early boot (Limine handoff) before executing modules.
  *Files:* `cd/boot/limine/limine.conf`, `scripts/` (build/sign), early `boot/`/
  `kernel_main` init. *Reason:* today modules load unverified. *Complexity:* High.
  *Deps:* 5.1. *Benefit:* boot-chain integrity.
- **5.3 Rollback protection.** *Desc:* monotonic rollback index; refuse older signed
  images. *Files:* boot/update path, persistent counter. *Reason:* anti-downgrade.
  *Complexity:* Medium. *Deps:* 5.2. *Benefit:* no re-flash to vulnerable versions.
- **5.4 Integrity measurement + tamper detection.** *Desc:* measure (hash) kernel,
  modules, policy, key objects into a log; detect runtime modification of immutable
  objects. *Files:* `core/object.d` (immutable flag), new `core/ima.d`, fault/audit
  path. *Reason:* attestation + tamper alarms. *Complexity:* High. *Deps:* 5.1.
  *Benefit:* runtime integrity assurance.
- **5.5 Security event log.** *Desc:* append-only log of cap denials, guard/canary
  faults, policy decisions, integrity events. *Files:* new `core/audit.d`, hooks in
  `requireCap`/PF handler/policy engine. *Reason:* detection + forensics. *Complexity:*
  Medium. *Deps:* 1.7, 3.1, 4.2. *Benefit:* observability.
- **5.6 Immutable / signed system objects.** *Desc:* read-only kernel objects,
  immutable capability definitions + security policies, signed object definitions
  (loaded only if signature verifies). *Files:* `core/object.d` (immutable+signature
  fields), `core/cap.d`, `core/mac.d`. *Reason:* policy/caps can't be mutated at
  runtime. *Complexity:* High. *Deps:* 5.1, 4.2. *Benefit:* tamper-proof security
  config. *(Converges with `IMMUTABLE_ROOTLESS_ROADMAP.md`.)*
- **5.7 Re-enable SMAP/SMEP + STAC/CLAC.** *Desc:* wrap kernel→user copies (DRM ioctl,
  stat writes, etc.) in STAC/CLAC; drop `-smap,-smep` from `qemu-run.sh`. *Files:*
  `posix.d` copy sites, `arch/x86_64/` (STAC/CLAC helpers), `qemu-run.sh`. *Reason:*
  restore HW kernel/user isolation removed as a workaround. *Complexity:* Medium.
  *Deps:* —. (= B5.) *Benefit:* SMEP blocks kernel exec of user pages; SMAP blocks
  inadvertent user access.

**Phase-5 prerequisite:** Phases 1–4 (5.1/5.7 can start immediately).

---

# File-Level Modification List

- `core/syscalls/mmap.d` — W^X (`map_flags`), honor `prot`, guard pages, randomized
  `g_nextMmapAddr`, NX default. *(1.1,1.4,2.1,2.2)*
- `core/kernel_main.d` — case 9 mmap honor `prot`; `execveTask` NX/guard/ASLR
  stack + canary re-randomize + shadow stack; `forkTask`/`cloneThread` cap-narrowing +
  shadow/guard; `dispatchSyscall`/`dispatchLinuxSyscall` syscall policy + `requireCap`;
  PF handler classification + audit; `loadElf` load-bias ASLR. *(1.1–1.7,2.2,2.5,3.1,
  3.2,4.3,4.4,5.5)*
- `arch/x86_64/arch.d` — STAC/CLAC helpers; ensure `map_page_hhdm` callers can set NX;
  context-switch shadow-stack save/restore. *(1.1,4.3,5.7)*
- `core/task.d` — `AddrRegion.flags` (guard/tag/canary/immutable); `mmapNext` ASLR +
  overlap fix; per-process cap-table/policy/label refs; shadow-stack ptr. *(1.3,2.1,
  2.4,3.1,3.4,4.1,4.3,B4)*
- `memory/mm.d` — hardened heap (canaries/quarantine/delayed reuse/randomized
  free-list); tagging hooks. *(3.3,3.4)*
- `core/syscalls/posix.d` — rootless `getuid`/`geteuid`/`SO_PEERCRED`; cap-table
  (ex-`g_fdTabs`); cap-gated device/ioctl; STAC/CLAC at user-copy sites; Linux-compat
  sandbox. *(2.4,2.6,3.2,4.4,5.7)*
- `core/exports.d` — userspace stack/env/aux setup for canary, ASLR bases. *(1.5,2.2)*
- `Makefile` — flip `-fno-stack-protector`→`-fstack-protector-strong`; add crypto/cap/
  mac/audit modules to the build; sign step in ISO staging. *(1.5,5.2)*
- `cd/boot/limine/limine.conf` + `scripts/` — signed manifest, verify modules, A/B,
  rollback counter. *(5.2,5.3)*
- `qemu-run.sh` — remove `-smap,-smep` once STAC/CLAC lands. *(5.7)*

# New Modules Required

`core/cap.d` (capabilities) · `core/mac.d` (labels + policy engine) ·
`core/stackguard.d` (`__stack_chk_guard`/`__stack_chk_fail`) · `core/crypto/`
(hash + ed25519) · `core/ima.d` (integrity measurement) · `core/audit.d` (security
event log) · `core/shadowstack.d` (per-thread shadow stacks) · `core/object.d`
(object header w/ label + immutable + signature fields — shared with OO roadmap).

# ABI Changes Required

- **Stack-protector ABI:** kernel must export `__stack_chk_guard` + `__stack_chk_fail`
  and seed the guard into TLS so `-fstack-protector` binaries link/run.
- **Aux vector / process start:** add `AT_RANDOM` (16 random bytes — musl uses it for
  its own canary + ASLR) to the initial stack in `exports.d`; today the seeded stack
  has no `AT_RANDOM`.
- **Shadow-stack thread ABI:** `clone`/thread creation gains shadow-stack allocation;
  context-switch saves/restores the SSP — touches `arch/` register save area.
- **Tagged-pointer ABI (Phase 3.4):** reserve top pointer bits for tags; all pointer
  consumers in `posix.d`/`mmap.d` must canonicalize before use.
- **Capability handle ABI:** fds become capability handles (rights-carrying); SCM_RIGHTS
  fd-passing becomes capability delegation — observable to Linux apps only as fds.

# Compiler Changes Required

- Build OS components with `-fstack-protector-strong` (and `-fstack-clash-protection`,
  `-D_FORTIFY_SOURCE`) — `Makefile` `FREESTANDING_CFLAGS`.
- For W^X-clean ELF: ensure no RWX `PT_LOAD`/`PT_GNU_STACK`; emit `PT_GNU_STACK` NX.
- Future: shadow-stack / CET codegen (`-fcf-protection`) and MTE/tagging instrumentation
  where the toolchain supports it (long-term).
- (No change to the JHC Haskell path required for Phase 1–2; D/C freestanding flags are
  the lever.)

# Runtime Changes Required

- musl ld.so must map data RW|NX and `mprotect(PROT_EXEC)` code post-relocation rather
  than relying on kernel-forced RWX (enabled by B1 honoring `prot`).
- Per-thread canary + shadow stack allocated in `cloneThread`/`execveTask`.
- A boot-time CSPRNG seed (reuse `getrandom` infra in `posix.d`) feeds canary, ASLR,
  and tag randomization.

# Boot Process Changes Required

- Early-boot crypto init **before** module execution.
- Limine config + manifest: hash/verify kernel and every module
  (`Hyprland`/`libc.so`/`xkb.blob`/`assets.blob`) against a signed manifest; refuse on
  mismatch.
- A/B slot selection + boot-success counter + rollback index (persistent store).
- Measure (hash) loaded components into the integrity log at handoff.

# Recommended Implementation Order

1. **B1** (honor `prot`/NX) → **1.1 W^X**, **1.2 NX stack** — immediate, isolated,
   huge payoff.
2. **B4** → **1.3/1.4 guard pages**; **1.5/1.6 canaries** (+`AT_RANDOM` ABI); **1.7**
   fault/audit hook. *(Phase 1 complete — a memory-safe baseline.)*
3. **2.1 randomized VA** → **2.2 ASLR** (image/heap/stack/libs).
4. **B2/2.4 capabilities** → **2.5 cap-narrowing on spawn** → **2.6 rootless** →
   **2.3 cap-table ASLR**. *(Phase 2 — authority model real.)*
5. **3.1 syscall policy** → **3.2 cap-gated syscalls** → **3.3 hardened heap** →
   **3.4 tagging**. *(Phase 3 — before networking.)*
6. **B3/5.1 crypto** (start early, lands here) → **4.1 labels** → **4.2 policy
   engine** → **4.4 Linux sandbox** → **4.3 shadow stack**. *(Phase 4.)*
7. **5.2 verified boot** → **5.3 rollback** → **5.4 integrity** → **5.5 audit** →
   **5.6 immutable/signed objects** → **5.7 SMAP/SMEP + STAC/CLAC**. *(Phase 5.)*

**Quick wins to do first (low risk, no new subsystem):** 1.1, 1.2, 1.5, 5.7 — and the
`mmapNext == stackBase` overlap fix.

# Security Architecture After Completion

```
Verified, signed boot (rollback-protected)  ── measured into integrity log
        │
        ▼
Immutable kernel: { Scheduler, Object Mgr, Capability Mgr (requireCap),
                    Memory Mgr (W^X, NX, guard pages, ASLR, hardened heap,
                    software tagging), HAL (SMAP/SMEP+STAC/CLAC) }
        │  authority only via delegated, narrowable, revocable capabilities
        ▼
Per-process: randomized ASLR layout · NX stack + guard pages + shadow stack ·
             per-thread canary · per-process syscall policy · MAC label ·
             least-authority cap table (ASLR'd)
        │
        ▼
Rootless subjects (no uid 0) ── all privilege = capabilities ── signed, immutable
                                 security policy enforced by the policy engine
        │
        ▼
Linux compatibility layer: sandboxed (restricted syscall policy + label +
                           ephemeral namespace); a Linux RCE cannot reach native
                           objects or capabilities it was never delegated
        │
        ▼
Every cap denial / guard / canary / integrity event ── append-only audit log
```

*Result:* memory-corruption exploitation is probabilistic-at-best (W^X + ASLR +
canaries + shadow stack + guard pages + hardened/tagged heap); a successful compromise
is **contained** by capabilities + MAC + syscall policy + Linux sandbox; the system
**boots only verified code**, **cannot be mutated at runtime** where it matters, and
**leaves an audit trail**.

*Companion roadmaps in this folder:* `IMMUTABLE_ROOTLESS_ROADMAP.md` (image
immutability + rootless admin — shares the capability manager and verified boot) and
`OBJECT_OS_ROADMAP.md` (the object/capability substrate this hardening attaches to —
B2/2.4 is its Phase 6).
