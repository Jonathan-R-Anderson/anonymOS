# Immutable, Rootless OS Architecture — Implementation Roadmap

> Scope: add an **immutable** system image and a **rootless, capability-only**
> security model to the existing kernel, fitting the current code rather than
> rewriting it. Written to be **critical**: assume nothing here is "done" until a
> capability object gates it.

---

## 0. Brutally honest assessment of where we actually are

The README advertises a capability-based, object-tree OS with user-space servers.
The **code does not implement any of that yet.** Ground truth from the source:

| Claimed property | Reality in `src/kernel/d/` |
|---|---|
| Capability-based security | **None.** No capability type, no grant/delegate, no enforcement. `grep capability` only hits Wayland strings. |
| Rootless / no UID 0 | **Opposite.** `linux_sys_getuid`/`geteuid`/`setuid` (posix.d:3911+) hardcode **0**. Every task is root. `SO_PEERCRED` was deliberately made to return root for *any* fd. |
| Object tree (everything is an object) | **None.** State lives in ad-hoc global tables: `g_tasks` (task.d), `g_fdTabs` (posix.d), `g_rt` rtfs nodes, sockets/pipes/memfd arrays. No unified object, ownership, or versioning. |
| Immutable system image | **None.** There is no image. The root fs is a *synthetic, read-only-by-accident* namespace + a **RAM-only writable `rtfs` overlay** (`FD_RTFILE`, posix.d). Nothing is persisted, signed, versioned, or rolled back. Boot modules (Hyprland, libc.so, xkb.blob, assets.blob) are loaded by Limine and trusted blindly. |
| Atomic update / rollback / A-B | **None.** `make` rebuilds an ISO; "update" = reflash. |
| Cryptographic verification | **None.** No hashing/signature anywhere in boot (`scripts/`, limine.conf). Limine loads modules unverified. |
| System vs user state separation | **None.** Everything is one ephemeral RAM tree. |
| Parent→child privilege inheritance | Only `fork` copying the **fd table** (`fdtabForkCopy`). That is descriptor inheritance, not capability delegation. |

**Conclusion:** "immutable" and "rootless" are at ~0%. We are building them, not
finishing them. The single biggest leverage point is that there is **no persistence
and no capability type yet** — so we can introduce both cleanly before a real disk
and real multi-user workloads lock in bad assumptions (a hardcoded UID 0 has already
metastasized through `getuid`, `SO_PEERCRED`, and file ownership defaults — see §G).

---

## A. How the reference systems actually do it (and what to steal)

**NixOS** — Immutable by *construction*, not by enforcement. The store
(`/nix/store/<hash>-name`) is content-addressed and read-only; a "generation" is a
symlink tree of store paths; rollback = repoint the symlink; atomic switch via a
single `switch-to-configuration`. *Steal:* content-addressed store + generations +
atomic pointer swap. *Reject:* it relies on a conventional rw kernel + root daemon
(`nix-daemon`) — not rootless.

**Qubes OS** — Security by *compartmentalization* (Xen VMs), TemplateVMs are
read-only roots, AppVMs get an ephemeral copy + a private volume for user data.
*Steal:* template-root / ephemeral-overlay / private-volume split (this maps almost
1:1 onto our needed system/user-state separation). *Reject:* hypervisor-per-app is
far heavier than a microkernel needs.

**Fedora Silverblue (ostree)** — "Git for the OS": commits of the whole `/usr` tree,
content-addressed objects, `/usr` mounted **read-only**, `/etc` is a 3-way-merged
overlay, `/var` is user state. A-B-ish via deployments + `rpm-ostree rollback`.
*Steal:* this is the **closest target** — read-only `/usr`, writable `/etc` overlay,
separate `/var`, content-addressed commit objects, atomic deployment swap.

**ChromeOS** — Hardware **A/B partitions**, dm-verity hash tree over the read-only
rootfs (every block verified on read), verified boot chain from firmware, stateful
partition for user data, automatic rollback on failed boot. *Steal:* **dm-verity
block-hash-tree** (cheapest path to "every read is verified"), A/B slots, boot-success
counter + auto-rollback.

**Android Verified Boot (AVB/vbmeta)** — Rollback-index anti-downgrade, signed
`vbmeta` chaining to dm-verity/hashtree, locked vs unlocked state, hardware
root-of-trust. *Steal:* **rollback index** (monotonic, prevents signing a new image
to ship an old vulnerable one) and the signed-metadata-chains-to-hashtree pattern.

**Plan 9** — *Everything is a file served over 9P*; per-process **namespaces** are
the core abstraction; no ambient global root namespace — you only see what was bound
into your namespace. *Steal:* this is our object tree done right — **per-process
namespaces assembled from mounts/binds**; a process's authority is exactly its
namespace. *Reject:* Plan 9 still has a uid model; we want capabilities instead.

**Genode** — The gold standard for *capability-only* construction. Strict
parent-child tree; a child **only has the capabilities its parent explicitly hands
it**; resources (RAM, caps) are sub-allocated from the parent ("everything is a
session to a service"); no ambient authority whatsoever. *Steal:* the **parent
delegates a closed set; no global namespace; resource = capability** model — this is
exactly design-goal #2 and should be the spine of our capability system.

**seL4** — Formally-verified capability kernel. Capabilities are kernel objects
held in **CNodes** (cap spaces); rights are per-cap; `Untyped` memory is retyped into
typed kernel objects; **no syscall succeeds without presenting a cap** with the right.
*Steal:* the **cap-table-per-task + typed-objects-from-untyped + rights bits**
mechanics, and "the only ambient authority is the current task's cap space."

**Synthesis (the target):** *Silverblue's immutable content-addressed store + A/B +
dm-verity (ChromeOS) + rollback index (AVB) for the **image**; Genode/seL4
capabilities + Plan 9 per-process namespaces for the **authority model**.*

---

## B. Map onto the current architecture

- **Microkernel-ish but not yet:** today most "services" (Wayland, DRM, fs) live
  **in-kernel** (`src/kernel/d/display/...`, posix.d). True rootless/immutable wants
  these as user-space capability-holding servers. This is the largest latent rewrite.
- **Single trust domain:** the Linux-personality init runs with full kernel reach and
  UID 0. There is no boundary to make "least privilege" meaningful yet.
- **No storage stack to make immutable:** there is an AHCI driver
  (`drivers/block/ahci.d`) but the live fs is RAM (`g_rt`/synthetic). Immutability
  must be designed *with* the first real on-disk fs, not retrofitted after.
- **Boot is Limine + unverified modules:** the verification chain has to start here.
- **The capability vacuum is an opportunity:** because nothing depends on a cap type
  yet, we can introduce `Capability` as a first-class object and route new subsystems
  through it before they accrete ambient-authority shortcuts.

---

## C. Have / Missing / Replace / Keep

**Already exists (reuse):**
- Per-task struct + scheduler (`task.d`, `g_tasks`), per-process fd tables
  (`g_fdTabs`) — the substrate a cap-space attaches to.
- `mmap`/CoW/page allocator (`mm.d`, now with a free list) — needed for
  untyped→typed memory and ephemeral overlays.
- fd-passing over `SCM_RIGHTS` — the transport for delegating capabilities between
  user-space servers.
- Boot-module loader (Makefile + limine.conf + `findBootModule`) — the hook point for
  measured/verified boot.
- AHCI block driver — the basis for a real, mountable, verifiable store.

**Missing (build):** capability type + cap space + enforcement; object manager /
object tree; per-process namespaces; content-addressed store; image
verification/signing; A/B + rollback; user-space service manager; persistent user
state; anti-downgrade rollback index.

**Should be replaced:** hardcoded UID 0 (`getuid`/`geteuid`/`SO_PEERCRED`);
ad-hoc global tables as the *authority* source (they can remain as *storage*, but
access must be gated by caps); "trust all boot modules"; treating the RAM rtfs as the
system root.

**Keep unchanged (for now):** the Linux syscall *surface* (it becomes a personality
that translates Linux ops into capability/object ops underneath); the JHC/D build
pipeline; the DRM/framebuffer bridge; the existing GUI stack work
(see `GUI_ROADMAP.md`).

---

## D. Dependency-aware phased TODO

Legend — **P**: Critical/High/Medium/Low · **D**: difficulty 1–10 · deps reference
task IDs below.

### Phase 0 — Foundation (decide the invariants before writing code)
- **0.1 Capability model spec** — P: Critical · D: 4 · deps: — · affects: docs,
  `core/`. *Why:* every later phase encodes these rules; getting "delegate only what
  you hold, rights are monotonically non-increasing, caps are unforgeable" wrong is
  unrecoverable. *Outcome:* written spec of cap structure, rights bits, derivation,
  revocation.
- **0.2 Object model spec** — P: Critical · D: 4 · deps: 0.1 · affects: docs. *Why:*
  defines the single object header (id, type, owner-cap, metadata, version) all
  subsystems adopt. *Outcome:* object ABI + lifecycle (create/retype/destroy).
- **0.3 Immutable-image + state-split spec** — P: High · D: 4 · deps: — · affects:
  docs, Makefile, boot. *Why:* locks the `/usr` read-only · `/etc` overlay · `/var`
  user-state split and the store layout *before* a real disk exists. *Outcome:*
  partition/slot/store layout doc.
- **0.4 Threat model + "rootless/immutable" acceptance tests** — P: High · D: 3 ·
  deps: 0.1–0.3 · affects: tests. *Why:* §F/§G become executable gates, not prose.
  *Outcome:* a test list that fails today and must pass to claim each property.

### Phase 1 — Kernel changes (make room for caps + objects)
- **1.1 `Object` header + object table** — P: Critical · D: 6 · deps: 0.2 · affects:
  new `core/object.d`, `task.d`. *Why:* unifies tasks/fds/etc. under one owned,
  versioned header. *Outcome:* objects allocatable with id/type/owner/version.
- **1.2 Per-task capability space (CNode-equiv)** — P: Critical · D: 7 · deps: 1.1,
  0.1 · affects: `task.d`, dispatch (`kernel_main.d`). *Why:* the task's authority set;
  the thing `fork`/`clone` copies and `execve` resets. *Outcome:* each task has a cap
  table; caps are indices/handles, not pointers.
- **1.3 Cap-checked syscall dispatch hook** — P: Critical · D: 6 · deps: 1.2 ·
  affects: `kernel_main.d` `dispatchLinuxSyscall`. *Why:* a single choke point where a
  syscall must present a cap; without it caps are decorative. *Outcome:* privileged
  ops route through `requireCap(task, kind, rights)`.
- **1.4 Untyped→typed memory** — P: High · D: 7 · deps: 1.1, `mm.d` · affects: `mm.d`,
  object alloc. *Why:* makes RAM itself a delegated, accountable capability (no ambient
  allocation). *Outcome:* tasks allocate objects only from untyped caps they hold.
- **1.5 Revocation** — P: High · D: 7 · deps: 1.2 · affects: object.d, cap space.
  *Why:* delegation is useless without recall (logout, service kill, downgrade).
  *Outcome:* revoking a cap invalidates all derived caps.

### Phase 2 — Capability system (the spine)
- **2.1 `Capability` object type + rights bits + derive** — P: Critical · D: 6 · deps:
  1.1–1.2 · affects: object.d. *Outcome:* `derive(cap, subsetRights)` only narrows.
- **2.2 Capability delegation over IPC (SCM_RIGHTS-style)** — P: Critical · D: 6 ·
  deps: 2.1, existing `sendmsg`/`SCM_RIGHTS` · affects: posix.d socket path. *Why:*
  user-space servers must hand caps to clients. *Outcome:* a cap can be sent on a
  channel; receiver gets an entry in *its* cap space, no forging.
- **2.3 Service/endpoint capability** — P: High · D: 6 · deps: 2.1. *Why:* "a
  capability to talk to service X" is the unit of authority (Genode sessions).
  *Outcome:* connecting to a server requires holding its endpoint cap.
- **2.4 Per-process namespace object** — P: High · D: 7 · deps: 1.1, 2.3 · affects:
  fs path resolution (posix.d `sys_open`/`rtResolve`), `task.d`. *Why:* Plan 9 model —
  a task sees exactly what's bound into its namespace; kills ambient global root.
  *Outcome:* `open()` resolves against the task's namespace caps, not a global tree.

### Phase 3 — Rootless administration (kill UID 0)
- **3.1 Replace UID-0 semantics with caps** — P: Critical · D: 6 · deps: 1.3, 2.1 ·
  affects: posix.d `getuid`/`geteuid`/`setuid`/`SO_PEERCRED`, file-owner defaults.
  *Why:* this is *the* rootless gate; today literally everything is root. *Outcome:*
  `getuid` returns a real, non-privileged subject id; privilege checks consult caps,
  never `uid==0`.
- **3.2 Admin capabilities (typed)** — P: Critical · D: 5 · deps: 3.1. *Why:*
  "install update", "mount", "reboot", "create user", "bind device" become *distinct*
  caps, not one root. *Outcome:* `reboot`/`mount`/update each `requireCap` a specific
  admin cap.
- **3.3 Subject (user) as an object, not a UID table** — P: High · D: 5 · deps: 1.1,
  3.1 · affects: `/etc/passwd` synthetic provider. *Why:* users are objects with owned
  caps; login = receiving a starting cap set. *Outcome:* no global uid→privilege map.
- **3.4 Least-privilege init/PID1** — P: High · D: 6 · deps: 3.2, Phase 5. *Why:* PID1
  today is omnipotent; it must start holding only the caps to launch services and hand
  each the minimum. *Outcome:* compromising a service ≠ compromising the system.

### Phase 4 — Immutable object store (the system image)
- **4.1 Content-addressed store on real storage** — P: Critical · D: 8 · deps:
  `ahci.d`, a real fs · affects: new `core/store/`, block driver. *Why:* the
  read-only, hash-named substrate (`store/<blake3>`); foundation of immutability.
  *Outcome:* objects/files addressed and fetched by hash; writes create new objects,
  never mutate.
- **4.2 dm-verity-style block hash tree** — P: Critical · D: 8 · deps: 4.1, Phase 8
  crypto. *Why:* every read of the system image is verified (ChromeOS). *Outcome:*
  tampering with a stored block faults the read.
- **4.3 Read-only `/usr` + writable `/etc` overlay + `/var` user state** — P: Critical
  · D: 6 · deps: 4.1, 2.4. *Why:* Silverblue split; the concrete meaning of
  "immutable system, mutable user". *Outcome:* `/usr` writes fail (no cap); `/etc`/`/var`
  writes go to overlays.
- **4.4 Generations / deployments** — P: High · D: 6 · deps: 4.1. *Why:* a named,
  immutable snapshot of the whole system tree; rollback target. *Outcome:* boot can
  select any prior generation pointer atomically.

### Phase 5 — Service management (user-space servers)
- **5.1 Service manager as a capability broker** — P: High · D: 7 · deps: 2.3, 3.4 ·
  affects: new `servicemgr`, replaces OpenRC-as-init assumptions. *Why:* spawns
  services, hands each its minimal cap set, brokers endpoint caps (Genode init).
  *Outcome:* dependency-ordered start with explicit per-service authority.
- **5.2 Move in-kernel services out (incremental)** — P: Medium · D: 8 · deps: 5.1,
  2.2 · affects: `display/`, DRM, fs providers. *Why:* in-kernel Wayland/DRM/fs are
  ambient authority; rootless wants them as cap-holding user servers. *Outcome:* each
  migrated service runs least-privilege; do FS first, display last.
- **5.3 Versioned services** — P: High · D: 5 · deps: 4.4, 5.1. *Why:* design-goal
  #1; services are store objects with versions. *Outcome:* a service = a pinned store
  hash; upgrade = new generation.

### Phase 6 — Update / rollback system
- **6.1 A/B slots** — P: Critical · D: 7 · deps: 4.1, 0.3, boot. *Why:* atomic upgrade
  with a known-good fallback. *Outcome:* two system slots; boot selects active.
- **6.2 Signed update bundles + apply** — P: Critical · D: 7 · deps: 6.1, 8.1, 4.1.
  *Why:* updates are signed, content-addressed, applied to the *inactive* slot only.
  *Outcome:* `requireCap(updateAdmin)` + signature check before any write.
- **6.3 Rollback index (anti-downgrade)** — P: High · D: 5 · deps: 6.2 (AVB). *Why:*
  prevents re-installing an older signed-but-vulnerable image. *Outcome:* monotonic
  counter blocks downgrades.
- **6.4 Boot-success counter + auto-rollback** — P: High · D: 6 · deps: 6.1, boot.
  *Why:* a bad update must not brick the box. *Outcome:* N failed boots → revert to
  other slot.
- **6.5 Snapshots of user state** — P: Medium · D: 5 · deps: 4.3. *Outcome:* `/var`
  snapshot/restore independent of system image.

### Phase 7 — Linux compatibility as capability objects
- **7.1 Personality layer maps Linux ops → object/cap ops** — P: High · D: 7 · deps:
  Phase 2–4 · affects: posix.d (the whole surface). *Why:* keep BusyBox/Hyprland
  working while the substrate becomes object/cap-based; Linux internals are *emulated*
  over objects, not exposed. *Outcome:* `open`/`mmap`/`socket` resolve to namespace +
  caps underneath; unchanged binaries still run.
- **7.2 Per-app ephemeral root + private volume** — P: Medium · D: 6 · deps: 4.3, 2.4
  (Qubes AppVM). *Why:* Linux apps get a disposable system view + a persistent private
  store. *Outcome:* an app cannot see or mutate the real system tree.
- **7.3 Capability-gated `/proc`,`/sys`,`/dev`** — P: Medium · D: 5 · deps: 3.1, 2.4.
  *Why:* today these synthetic trees are ambient. *Outcome:* device/proc access needs
  the matching cap.

### Phase 8 — Security hardening
- **8.1 Crypto primitives in kernel (hash + signature verify)** — P: Critical · D: 6 ·
  deps: — (gates 4.2/6.2). *Why:* nothing above is real without verified hashing/sigs.
  *Outcome:* BLAKE3/SHA-256 + ed25519 verify available pre-fs.
- **8.2 Measured/verified boot from Limine** — P: Critical · D: 7 · deps: 8.1, boot,
  Makefile. *Why:* the chain must start at the loader; today modules are trusted
  blindly. *Outcome:* kernel + modules hashed and checked against a signed manifest.
- **8.3 W^X / NX everywhere + cap-gated mmap(PROT_EXEC)** — P: High · D: 5 · deps:
  `mm.d`, 1.3. *Why:* immutability is meaningless if code pages are writable+exec.
  *Outcome:* no page is W and X; making exec memory needs a cap.
- **8.4 Audit log of capability use** — P: Medium · D: 5 · deps: 1.3. *Outcome:*
  every `requireCap` decision is recordable.

### Phase 9 — Distributed OS integration
- **9.1 Network-transparent object references** — P: Low · D: 8 · deps: Phase 1–2,
  net stack. *Why:* the object tree extends across nodes (Plan 9 9P-style). *Outcome:*
  remote objects addressed like local.
- **9.2 Capability delegation across nodes** — P: Low · D: 9 · deps: 9.1, 8.1. *Why:*
  caps must be unforgeable *and* delegable over the wire (cryptographic caps /
  macaroons). *Outcome:* a remote service grant that can't be forged or replayed.
- **9.3 Distributed content-addressed store** — P: Low · D: 8 · deps: 4.1, 9.1.
  *Outcome:* generations fetched by hash from peers; natural dedup.

---

## E. Target architecture

```
            ┌──────────────────────────────────────────────────────────┐
            │ Hardware root of trust / firmware                         │
            └───────────────┬──────────────────────────────────────────┘
                            │ verifies signature + rollback index
                   ┌────────▼─────────┐
                   │   Bootloader      │  (Limine + signed manifest, A/B slot select)
                   └────────┬──────────┘
                            │ measured/verified kernel + modules (§8.2)
                   ┌────────▼──────────────────────────────────────────┐
                   │ IMMUTABLE KERNEL (read-only, W^X)                  │
                   │   Capability Manager ── Object Manager            │
                   │   (cap spaces, rights,   (single object tree:      │
                   │    derive, revoke)        tasks/fds/mem/ns/...)     │
                   └───┬───────────────────────────────────┬───────────┘
                       │ requireCap()                       │ owns
              ┌────────▼─────────┐               ┌──────────▼───────────┐
              │ Service Manager   │  brokers caps │ Immutable Object Store│
              │ (cap broker,      │◄──────────────│ content-addressed,    │
              │  least-privilege) │  endpoint caps│ dm-verity, A/B, gens  │
              └───┬──────────┬────┘               │  /usr(ro) /etc(ovl)   │
                  │ min caps │ min caps           │  /var(user state)     │
          ┌───────▼───┐  ┌───▼────────┐           └───────────────────────┘
          │User service│  │User service│  ... (fs, net, display, devices —
          │ (per-svc   │  │ (versioned │       migrated out of kernel, §5.2)
          │  namespace)│  │  store obj)│
          └─────┬──────┘  └────────────┘
                │ endpoint cap + ephemeral root + private volume (§7.2)
       ┌────────▼─────────────────────┐
       │ Linux Compatibility Layer     │  (personality: Linux ops → object/cap ops;
       │  (BusyBox / Hyprland / apps)  │   no UID 0; sees only its namespace)
       └────────┬──────────────────────┘
                │ network-transparent object refs + cross-node caps (§9)
       ┌────────▼─────────┐
       │ Distributed       │
       │ Services / peers  │
       └───────────────────┘
```

Authority flows **down** the tree (a child only gets what its parent delegates);
data integrity flows **up** from the verified store; nothing has ambient authority.

---

## F. Minimum to *honestly* claim each property

**"Immutable" (all required):**
1. System tree on a **read-only, integrity-verified** backing (§4.1 + §4.2 + §8.1):
   a write to `/usr`/kernel/service objects is impossible, not just discouraged.
2. **State split** enforced — `/usr` ro, `/etc` overlay, `/var` user state (§4.3).
3. **Atomic** update + **rollback** to a prior generation/slot (§6.1 + §4.4).
4. **No W^X** pages and no in-place patching of running system code (§8.3).
   *Until all four hold, it is "read-mostly," not immutable. The current RAM rtfs
   fails 1–4 outright.*

**"Rootless" (all required):**
1. **No code path grants privilege from `uid==0`** — `getuid`/`SO_PEERCRED`/file-owner
   shortcuts removed (§3.1). (Today this is the whole model.)
2. Every privileged syscall/admin action **`requireCap`s a specific capability**
   (§1.3 + §3.2); there is no cap that means "everything."
3. Caps are **unforgeable and delegate-only-what-you-hold** (§2.1), enforced by the
   kernel, with **revocation** (§1.5).
4. **PID1/services start least-privilege** (§3.4) — a compromised service cannot
   obtain caps it was never delegated.
   *Until all four hold, it is "single-root with extra steps."*

---

## G. Most dangerous mistakes (these silently reintroduce root / mutability)

1. **Leaving `getuid()==0` anywhere.** It has already leaked into `SO_PEERCRED`
   (returns root for any fd) and default file ownership. One surviving `if (uid==0)`
   *is* root. Rip it out at the root (§3.1) before building on top.
2. **A "god" capability** (a cap that implies all others, or that the kernel auto-grants
   to PID1 "for convenience"). That is UID 0 wearing a capability costume. Admin must
   be **many narrow caps** (§3.2), never one.
3. **Ambient allocation / ambient namespace.** If any task can `mmap`, open a global
   `/`, or reach a device without a cap, least-privilege is theater. Untyped memory
   (§1.4) and per-process namespaces (§2.4) must gate *all* resource acquisition.
4. **Mutable "config" escape hatch in the immutable tree.** A writable file under
   `/usr` (or a service that re-reads a writable script as system policy) defeats
   immutability. Only `/etc` overlay + `/var` are writable, and neither may carry
   executable system policy without a cap (§4.3, §8.3).
5. **Trusting boot modules / updates without verification.** Limine currently loads
   modules unsigned; an update path that writes the *active* slot, or skips signature
   + rollback-index checks, is a remote-root backdoor (§8.2, §6.2, §6.3).
6. **Forgeable or non-revocable caps.** Caps as raw pointers/integers the holder can
   guess or mint, or delegation with no revoke, collapses the model (§2.1, §1.5).
7. **W+X pages.** Read-only `/usr` is pointless if running code can be patched in RAM
   or new exec pages minted freely (§8.3).
8. **Re-introducing a global mutable table as the *authority* source.** The existing
   `g_tasks`/`g_fdTabs`/`g_rt` are fine as storage, but the moment a check reads them
   *instead of* a cap, ambient authority is back. Authority = caps, always.
9. **Doing the kernel-service migration last/never.** While Wayland/DRM/fs live
   in-kernel with full reach, "rootless user services" is aspirational — the kernel is
   the root. Migrate FS first (§5.2).
10. **Persisting user state inside the system image.** Any `/var` content that ends up
    in a generation breaks rollback (rolling back the OS would roll back user data).
    Keep the split physical, not just logical (§0.3, §6.5).

---

*Companion: `GUI_ROADMAP.md` (desktop/compositor bring-up). This document assumes the
GUI stack continues in parallel; the kernel-service migration (§5.2) is where the two
roadmaps converge — the in-kernel Wayland/DRM bridge eventually becomes a
capability-holding user-space display service.*
