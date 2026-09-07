# Immutable-image + state-split layout — specification

> **IMMUTABLE_ROOTLESS Phase 0.3.** Locks the `/usr` read-only · `/etc` overlay · `/var` user-state
> split, the A/B slot model, and the on-disk store layout in one place.
>
> Phase 0.3 was written to fix the layout *before* a real disk existed. A real disk now exists, so
> this document describes **what is actually built**, and marks the places where the implementation
> does not yet meet the §F bar. Every claim here is checked at boot by `core/acceptance.d`; run
> `scripts/boot-test.sh tests/immutable-rootless.txt` to see the current verdicts.

---

## 1. The three trees

| Tree | Rights | Backed by | Survives update? | Survives rollback? |
|---|---|---|---|---|
| `/usr` | read-only | content-addressed store blobs, verity-hashed | replaced wholesale | reverts with the generation |
| `/etc` | read + write (overlay) | writable overlay over the image's defaults | merged | reverts with the generation |
| `/var` | read + write | user state | **untouched** | **untouched** |

Bound by `storeMountSystem()` (`core/store.d`), which creates the system namespace and binds:

```
/usr  →  CAP_RIGHT_READ                      (read-only image)
/etc  →  CAP_RIGHT_READ | CAP_RIGHT_WRITE    (overlay)
/var  →  CAP_RIGHT_READ | CAP_RIGHT_WRITE    (user state)
```

`storeWritable(path)` resolves a path against those mount rights and is the single predicate for
"may this be written". A write to `/usr` is refused because the binding carries no `CAP_RIGHT_WRITE`
— not by a check somewhere that could be forgotten at a second call site.

**§10 rule — user state never enters a generation.** `/var` content must never be captured into a
generation; if it were, rolling the OS back would roll user data back with it. `/var` snapshots
exist (§6.5) but are *separate* store objects with their own lifecycle.

### 1.1 Known gap: the split is three subtrees, not a default

`storeMountSystem()` builds its namespace with `nsAlloc()`, and `nsAlloc` calls `bindRoot()`, which
binds `/` to the rtfs root with `rights = uint.max`. `/usr` is genuinely read-only — its own binding
is more specific and grants only `CAP_RIGHT_READ` — but **any path outside the three explicit
bindings inherits write rights from that catch-all root.**

This is §G mistake #3 (ambient namespace), and it is why the `IMMUTABLE-2` gate reports FAIL.

`nsAllocRestricted()` exists for exactly this case and omits the root binding. Switching to it is
the fix, but it denies every path outside `/usr`, `/etc` and `/var` to task 0 and everything that
inherits from it — `/dev`, `/proc`, `/run`, `/home` included — so it needs its own staged proof
rather than a one-line change.

---

## 2. Generations and A/B slots

A **generation** is an immutable list of store objects — the system tree at one version.
A **slot** is one of two positions a generation can be deployed into.

```
        ┌───────── slot A ─────────┐        ┌───────── slot B ─────────┐
        │ generation N   (active)  │        │ generation N-1 (good)    │
        └──────────────────────────┘        └──────────────────────────┘
                   ▲                                      ▲
                   │ boot selects                         │ update writes HERE, never the active slot
```

| Rule | Where | Why |
|---|---|---|
| The **inactive** slot is the only writable update target | `updateApply` | an update can never damage the running system |
| Activation is a single atomic swap | `updateActivateInactive` | no half-updated state is bootable |
| `CAP_RIGHT_ADMIN_UPDATE` **and** a valid signature are required *before any write* | `updateApply` | §G #5: an unverified update path is a remote-root backdoor |
| A monotonic rollback index rejects a validly-signed downgrade | `updateRollbackIndex` | anti-rollback (AVB) |
| N failed boots auto-revert to the other known-good slot | `bootBegin`/`bootConfirm`/`bootCheckRollback` | a bad update cannot brick the machine |

`genRollback(gen)` returns the active generation to a prior one. The `IMMUTABLE-3` gate proves both
directions by deploying a generation, rolling back, and reading `genActive()` back.

---

## 3. On-disk store layout

Sector = 512 B. **All LBAs below are relative to `g_baseLba`**, the absolute LBA of the store's
relative sector 0.

```
  LBA 0        superblock   — magic "HOSOBJFS", version, appCount, bootCount,
                              nextFreeLba, domainCount, fsBlob{Lba,Len,Cap}
  LBA 1..32    app directory     — ObjAppEntry, 256 B each (2/sector), 64 entries
  LBA 33..48   domain directory  — DomainEntry, 256 B each, 32 entries
  LBA 64..     blob region       — manifest / permissions / executable / storage,
                                   allocated sequentially, sector-granular
```

The superblock's on-disk layout must never depend on compiler padding: the alignment gap before
`fsBlobLba` is spelled out as an explicit `_rsv0` field and the struct size is checked by a static
assert.

### 3.1 Where the store lives on the disk

| Disk state | `g_baseLba` | Rationale |
|---|---|---|
| Raw / unpartitioned | 0 | the whole disk is the store |
| GPT-partitioned (installed) | offset into free space | the store only ever writes the free tail after the last partition, or failing that the unused gap between the partition array and the first partition |
| Install media + blank disk | *not mounted* | the disk is a free install target; claiming it would fight the installer |

A GPT disk is not out of bounds — only its first 34 sectors and its partitions are. Mounting on a
partitioned disk cannot damage a later reinstall, because the installer rewrites the partitions it
owns regardless.

**`bootCount`**, bumped on every mount, is the persistence proof: it climbs across reboots precisely
because it is read from and written back to disk.

### 3.2 Known gap: live media has no persistent backing

Booted from the install ISO with a blank target disk, the store stays in RAM by design — the disk is
reserved for the installer. That satisfies the rights check and the verity hash tree while still
losing everything at power off, so `IMMUTABLE-1` reports FAIL with `backing-on-disk=0`. On an
installed system the store mounts and the same gate is expected to pass. **This is the one gate
whose verdict legitimately differs between live and installed media.**

---

## 4. Content addressing and verity

`core/store.d` is content-addressed and de-duplicating: `storePut` hashes the payload and returns
the existing object if the digest matches, so identical content is stored once and a blob's identity
*is* its hash.

Integrity is a dm-verity-style block hash tree:

| Constant | Value | Meaning |
|---|---|---|
| `STORE_BLOCK` | 64 B | verity leaf-block size |
| `STORE_MAX_BLOCKS` | 256 | leaves per blob ⇒ 16 KiB max blob |
| `STORE_ARENA` | 64 KiB | shared content arena |
| `STORE_BLOB_MAX` | 64 | live content-addressed blobs |

`storeReadVerified` faults the read if any covered block was tampered with; `storeImageIntact`
answers the same question for a whole object. Both use real SHA-256, not a placeholder.

---

## 5. What must hold to call this "immutable"

§F lists four conditions. All four must hold; until then the correct word is **read-mostly**.

| # | Condition | Gate | Status |
|---|---|---|---|
| 1 | read-only, integrity-verified backing | `IMMUTABLE-1` | FAIL on live media (§3.2) — expected; unverified on installed media |
| 2 | state split enforced | `IMMUTABLE-2` | FAIL — ambient root binding (§1.1) |
| 3 | atomic update + rollback | `IMMUTABLE-3` | PASS |
| 4 | no W^X pages | `IMMUTABLE-4` | PASS |

The gates are executable and run at every boot. Adding a `require` line for a gate in
`tests/immutable-rootless.txt` is how a property gets *claimed*; weakening a gate to make the board
green defeats the purpose of Phase 0.4 entirely.
