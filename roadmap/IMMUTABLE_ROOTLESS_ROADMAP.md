# Immutable, Rootless OS Architecture — Implementation Roadmap

> Scope: add an **immutable** system image and a **rootless, capability-only**
> security model to the existing kernel, fitting the current code rather than
> rewriting it. Written to be **critical**: assume nothing here is "done" until a
> capability object gates it.

---

## 0. Assessment of where we actually are

> **Updated.** The original assessment (preserved in the right column for the
> historical record) predated the `OBJECT_OS_ROADMAP.md` (Phases 2–13) and
> `OBJECT_REFERENCE_GRAPH_ROADMAP.md` (Phases 1–12) work, both now implemented. The
> capability/object substrate this roadmap assumed was missing **largely exists**;
> what remains is primarily the *immutability* stack (storage/store/verify/A-B) plus
> deeper service extraction. The "Now" column is
> ground truth; see `CAPABILITY_MODEL.md` (§0.1) for the cap details.

| Property | Now (ground truth) | Originally assessed |
|---|---|---|
| Capability-based security | **Implemented** (`core/cap.d`): first-class cap-slot objects, subset derive, transitive revoke, per-process cap tables; `requireCap` gates the fd surface; endpoint calls require `CAP_RIGHT_CALL`; namespace opens enforce binding rights; typed `ObjType.Admin` caps gate privileged admin actions; ORG enforces rights/label monotonicity (`[cap] revclosure PASS`). | "None." |
| Rootless / no UID 0 | **Implemented for the kernel personality boundary.** `getuid`/`geteuid`/`SO_PEERCRED` read the task's **User object** (`Task.userObjId`); the default subject is uid/gid 1000; file-owner defaults use the active subject; privileged actions consult typed admin caps, never `uid==0`. | "Opposite — every task is root." |
| Object tree (everything is an object) | **Implemented** (`core/objmgr.d` + ORG): one `ObjHeader` table; tasks/threads/fds/mem/vmo/dirs/devices/drivers/netifs/windows/users/services/namespaces/endpoints/Linux-compat are all objects in one typed reference graph with ownership, reachability, and a validator. | "None." |
| Per-process namespaces | **Implemented** (`core/namespace.d`): each process has a `Namespace` object; `open` resolves against it and checks binding read/write rights; fork clones it. | (not separately listed) |
| Immutable system image | **Mechanism built, not yet on real storage (Phase 4).** `core/store.d` is a content-addressed, de-duplicating, write-creates-never-mutates object store with a dm-verity-style block hash tree (`storeReadVerified` faults on a tampered block). Backing is still the in-kernel content arena, not a persisted/signed on-disk fs; boot modules still loaded by Limine unverified. Remaining: AHCI/disk backing + §8 verified boot. | "None." |
| Atomic update / rollback / A-B | **Generations + atomic deployment swap built (Phase 4.4); A/B + signed bundles still Phase 6.** `genCreate`/`genRollback` snapshot the tree and repoint the active deployment in a single store. `make` still rebuilds the ISO for the underlying image. | "None." |
| Cryptographic verification | **Hash-tree verification built with a stand-in digest (Phase 4.2).** 256-bit position-sensitive FNV-1a addresses content and detects tampering; the real BLAKE3/ed25519 primitives + signature/boot chain are Phase 8.1/8.2. | "None." |
| System vs user state separation | **Enforced logically (Phase 4.3), not yet physically.** The system namespace binds `/usr` read-only · `/etc`·`/var` read+write; `storeWritable` denies `/usr` writes. Still one ephemeral RAM tree underneath — a separate physical `/var` volume remains Phase 6.5. | "None." |
| Parent→child privilege inheritance | **Capability delegation now exists:** `fork` narrows the cap table (`capTableCloneNarrowing`), `SCM_RIGHTS` delegates caps by value — not just fd-table copying. | "Only fd-table copy." |

**Conclusion:** "rootless" went from ~0% to **substantially built** (capability
spine, object tree, endpoint caps, namespace rights, non-root User subjects, typed
admin caps, User/Service objects). Remaining rootless hardening is mostly service
extraction and broader capability coverage, not UID-0 semantics. "Immutable" went
from ~0% to **mechanism-complete in RAM (Phase 4)**: a content-addressed,
write-creates-never-mutates store with a dm-verity hash tree, a `/usr`·`/etc`·`/var`
rights split, and generations with atomic rollback all exist (`core/store.d`) and
self-test green. What is *not* yet true is the **physical** substrate the §F
"honestly immutable" bar demands — a persisted, on-disk, signature-/boot-verified
store with W^X — which is Phases 6/8. The capability/object substrate being ready
means the store was introduced *through* objects and namespace rights from the start,
exactly as intended.

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
- **The capability substrate is now ready:** new subsystems should enter through
  object/cap/namespace APIs from the start, not through raw global ids.

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

**Missing (build):** content-addressed store; image verification/signing; A/B +
rollback; user-space service manager; persistent user state; anti-downgrade rollback
index.

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
- **0.1 Capability model spec** — ✅ **DONE** → [`CAPABILITY_MODEL.md`](CAPABILITY_MODEL.md).
  P: Critical · D: 4 · deps: — · affects: docs, `core/`. *Why:* every later phase
  encodes these rules; getting "delegate only what you hold, rights are monotonically
  non-increasing, caps are unforgeable" wrong is unrecoverable. *Outcome:* written spec
  of cap structure, rights bits, derivation, revocation.
  > **Status:** ratified spec written, **grounded in the now-implemented
  > `core/cap.d`** (the capability manager that landed via `OBJECT_OS_ROADMAP.md`
  > P6 + `OBJECT_REFERENCE_GRAPH_ROADMAP.md` P7). It documents the cap structure
  > (`Capability{objId,rights,deriveParent,revoked,capObjId}`, per-process
  > `CapTable`), the rights lattice + meet-narrowing `capDerive`, IPC delegation
  > (`SCM_RIGHTS` via `ipcDelegateCap`/`ipcAcceptCap`), endpoint-cap service calls,
  > namespace binding-right checks, fork-narrowing, **transitive** revocation
  > (`capRevokeIn`, proven `[cap] revclosure PASS`), unforgeability, and the ten
  > invariants later phases must preserve. Corrects the stale §0 assessment below
  > and lists what is implemented vs. still spec-only (rootless admin §3.x and
  > cap-gated `mmap(PROT_EXEC)` §8.3).
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

### Phase 1 — Kernel changes (make room for caps + objects)  ✅ DONE
> **Status:** implemented through Object-OS/ORG plus the §1.4 allocator gate. The
> object table has `ObjType.Untyped`; every task carries an untyped-memory object and
> a reserved `CAP_RIGHT_RETYPE` cap outside the fd range; `memory/mm.d` charges
> `alloc_phys_page(s)` to the active task's untyped object and records per-frame
> untyped ownership so `free_phys_page` returns quota. Fork creates a child untyped
> budget, clone shares the process budget, and `[untyped] selftest PASS` proves
> denied allocation without a budget or past a small budget.
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
- **1.4 Untyped→typed memory** — ✅ **DONE** · P: High · D: 7 · deps: 1.1, `mm.d` · affects: `mm.d`,
  object alloc. *Why:* makes RAM itself a delegated, accountable capability (no ambient
  allocation). *Outcome:* tasks allocate objects only from untyped caps they hold.
- **1.5 Revocation** — P: High · D: 7 · deps: 1.2 · affects: object.d, cap space.
  *Why:* delegation is useless without recall (logout, service kill, downgrade).
  *Outcome:* revoking a cap invalidates all derived caps.

### Phase 2 — Capability system (the spine)  ✅ DONE
> **Status:** implemented. Live cap slots now have `ObjType.Capability` identities
> (`Capability.capObjId`) and are released on clear/revoke/table-clear. The rights
> universe includes fd rights plus explicit non-fd `CAP_RIGHT_RETYPE` and
> `CAP_RIGHT_CALL`, while `CAP_RIGHT_ALL` remains fd-only. `capDerive*` refuses to
> widen or derive from an absent source; SCM_RIGHTS delegates caps by value through
> `ipcDelegateCap`/`ipcAcceptCap`; service connect and `objCall` require a held
> endpoint cap with `CAP_RIGHT_CALL`; absolute `open()` resolves through the task's
> Namespace and checks the matching binding's read/write rights before the legacy
> resolver runs. `[ipc] selftest PASS` covers denied/no-cap service connect and
> successful endpoint-cap connect.
- **2.1 `Capability` object type + rights bits + derive** — ✅ **DONE** · P: Critical · D: 6 · deps:
  1.1–1.2 · affects: object.d. *Outcome:* `derive(cap, subsetRights)` only narrows.
- **2.2 Capability delegation over IPC (SCM_RIGHTS-style)** — ✅ **DONE** · P: Critical · D: 6 ·
  deps: 2.1, existing `sendmsg`/`SCM_RIGHTS` · affects: posix.d socket path. *Why:*
  user-space servers must hand caps to clients. *Outcome:* a cap can be sent on a
  channel; receiver gets an entry in *its* cap space, no forging.
- **2.3 Service/endpoint capability** — ✅ **DONE** · P: High · D: 6 · deps: 2.1. *Why:* "a
  capability to talk to service X" is the unit of authority (Genode sessions).
  *Outcome:* connecting to a server requires holding its endpoint cap.
- **2.4 Per-process namespace object** — ✅ **DONE** · P: High · D: 7 · deps: 1.1, 2.3 · affects:
  fs path resolution (posix.d `sys_open`/`rtResolve`), `task.d`. *Why:* Plan 9 model —
  a task sees exactly what's bound into its namespace; kills ambient global root.
  *Outcome:* `open()` resolves against the task's namespace caps, not a global tree.

### Phase 3 — Rootless administration (kill UID 0)  ✅ DONE
> **Status:** implemented. `Task.userObjId` is the per-task subject, inherited by
> fork/clone and selected by the syscall dispatcher. `core/user.d` now defaults to
> the non-root uid/gid 1000 User object; `getuid`/`geteuid`/`getgid`/`SO_PEERCRED`
> and stat owner defaults read that object. `core/admin.d` adds typed `ObjType.Admin`
> capability objects for mount, reboot, update, user, device, and inspect actions;
> `mount`/`umount2`/`chroot`, `reboot`, identity/ownership changes, and ORG graph
> export check the specific admin cap instead of `uid==0`. PID1 starts as uid 1000
> and receives only the mount/reboot/inspect admin caps needed by today's
> compatibility layer; forked children do not inherit those non-fd admin caps through
> fd-table cloning. `[admin] selftest PASS` proves action-specific admin caps are
> required.
- **3.1 Replace UID-0 semantics with caps** — ✅ **DONE** · P: Critical · D: 6 · deps: 1.3, 2.1 ·
  affects: posix.d `getuid`/`geteuid`/`setuid`/`SO_PEERCRED`, file-owner defaults.
  *Why:* this is *the* rootless gate; today literally everything is root. *Outcome:*
  `getuid` returns a real, non-privileged subject id; privilege checks consult caps,
  never `uid==0`.
- **3.2 Admin capabilities (typed)** — ✅ **DONE** · P: Critical · D: 5 · deps: 3.1. *Why:*
  "install update", "mount", "reboot", "create user", "bind device" become *distinct*
  caps, not one root. *Outcome:* `reboot`/`mount`/update each `requireCap` a specific
  admin cap.
- **3.3 Subject (user) as an object, not a UID table** — ✅ **DONE** · P: High · D: 5 · deps: 1.1,
  3.1 · affects: `/etc/passwd` synthetic provider. *Why:* users are objects with owned
  caps; login = receiving a starting cap set. *Outcome:* no global uid→privilege map.
- **3.4 Least-privilege init/PID1** — ✅ **DONE** · P: High · D: 6 · deps: 3.2, Phase 5. *Why:* PID1
  today is omnipotent; it must start holding only the caps to launch services and hand
  each the minimum. *Outcome:* compromising a service ≠ compromising the system.

### Phase 4 — Immutable object store (the system image)  ✅ DONE
> **Status:** implemented in `core/store.d` (module `core.store`), wired into the
> boot reconcile loop and mounted at PID1 bring-up. The store is **additive** and
> kernel-resident, mirroring the earlier phases: it lands the content-addressed
> substrate, the dm-verity hash tree, the `/usr`·`/etc`·`/var` rights split, and
> generations now, ahead of the real on-disk fs (`ahci.d`) and the §8.1 crypto it
> will ultimately use. Two object types were added (`ObjType.StoreObject`,
> `ObjType.Generation`). `storePut` is content-addressed and de-duplicating (identical
> bytes resolve to the same `StoreObject`; there is **no** API that mutates a stored
> blob — writes only create), `storeReadVerified` re-hashes every covering leaf block
> against the stored hash tree so a tampered backing byte **faults the read**,
> `storeMountSystem` builds the system namespace with `/usr` read-only (no WRITE
> right) · `/etc` and `/var` read+write overlays and `storeWritable` is the per-path
> write gate, and `genCreate`/`genSetActive`/`genRollback` snapshot the tree and swap
> the active deployment pointer in a single atomic store. The 256-bit content hash is
> a self-contained position-sensitive FNV-1a stand-in for BLAKE3 until §8.1 lands —
> strong enough to address content and detect a flipped block, which the self-test
> proves. `[store] selftest PASS` covers all four sub-properties (content-address +
> dedup, verity tamper-fault, `/usr` write-deny while `/etc`·`/var` allow, and atomic
> generation rollback).
- **4.1 Content-addressed store on real storage** — ✅ **DONE** · P: Critical · D: 8 · deps:
  `ahci.d`, a real fs · affects: new `core/store/`, block driver. *Why:* the
  read-only, hash-named substrate (`store/<blake3>`); foundation of immutability.
  *Outcome:* objects/files addressed and fetched by hash (`storePut`/`storeLookup`,
  digest = name); writes create new objects, never mutate; identical content dedups.
  *(Backing store is the in-kernel content arena for now; the on-disk/AHCI backing is
  the remaining work, gated on a real fs.)*
- **4.2 dm-verity-style block hash tree** — ✅ **DONE** · P: Critical · D: 8 · deps: 4.1, Phase 8
  crypto. *Why:* every read of the system image is verified (ChromeOS). *Outcome:*
  `storeReadVerified` re-hashes each covering leaf block before returning bytes;
  tampering with a stored block faults the read (`storeImageIntact` reports the break).
  *(Uses the FNV-1a digest stand-in pending the §8.1 BLAKE3/ed25519 primitives.)*
- **4.3 Read-only `/usr` + writable `/etc` overlay + `/var` user state** — ✅ **DONE**
  · P: Critical · D: 6 · deps: 4.1, 2.4. *Why:* Silverblue split; the concrete meaning of
  "immutable system, mutable user". *Outcome:* the system namespace binds `/usr`
  read-only and `/etc`·`/var` read+write; `storeWritable` denies a `/usr` write
  (no WRITE mount-right) and allows `/etc`·`/var` — no UID-0 / ambient-write hatch.
- **4.4 Generations / deployments** — ✅ **DONE** · P: High · D: 6 · deps: 4.1. *Why:* a named,
  immutable snapshot of the whole system tree; rollback target. *Outcome:*
  `genCreate` captures a numbered, parented snapshot of store-object ids; `genSetActive`/
  `genRollback` repoint the single active-deployment pointer atomically, so boot can
  select any prior generation.

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
   shortcuts removed (§3.1).
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
