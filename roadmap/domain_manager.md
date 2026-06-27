# Domain Manager Roadmap

Goal: turn a "domain" from today's **cosmetic, RAM-only label** (7 hardcoded entries in
the `cd/wl-domain-manager` GUI that only become `EPIN_*` env strings + a window border)
into a **first-class, persistent, cloneable/snapshottable object** that is a *complete
reusable OS environment* — a blend of Qubes templates (immutable template + disposable
clones), Docker images (a packaged, shippable environment), NixOS modules (declarative,
inheritable config), virtual desktops (per-domain appearance/startup/defaults) and
immutable snapshots (overlay commit/rollback). Every domain owns its installed apps,
packages, services, environment, appearance, identity inheritance, **and — the critical
requirement — a capability-mediated, default-deny restricted view of the single global
object/filesystem tree.** Nothing here forks a new security model: domains are built
**on top of** the existing object manager, capability/attenuation engine, per-process
namespaces, identity records, the on-disk object store, and the declarative-config
pipeline.

North star (user-chosen): a domain is a persisted object under `/objects/domains/<name>/`
with a full sub-object tree (Template, Overlay, Applications, Packages, Services,
Permissions, Identity, Networking, Filesystem{AllowedPaths, DeniedPaths, Mounts, Overlay,
RuntimeView}, Linux, PackageManager, Appearance, Policies, Snapshots), driven by a JSON
manifest, that **survives reboot** and whose launched apps run **inside** a kernel-enforced
identity + restricted namespace — not just with advisory env vars. We get there
**additively**: the restricted-FS view + the Domain object + the manifest first (the
substrate is ~70% latent), then on-disk persistence, then templates/overlays, then
package management and the marketplace.

## Why this fits EpinAnonymOS (already ~70% latent)

The kernel is already object/capability/immutable/namespace-based, and the GUI already
mirrors the kernel's 7 compiled-in identities. This is a **wiring + extension** job: the
restricted-FS engine (`core/namespace.d`, `core/idns.d`), the cap-attenuation engine
(`core/cap.d`), the identity model (`core/identity.d`), the on-disk store
(`core/objstore.d`), the declarative compiler (`anonymos-config/`) and the manifest bridge
(`core/configboot.d`) all exist — they are just **not connected to the domain GUI**, which
bypasses every one of them via raw `fork`+`setenv`+`execve`.

| Domain piece | Backed by today | State |
|---|---|---|
| Domain object + sub-tree | `objmgr.d` `objAlloc(ObjType.X)` + the F1/F5 `/objects/<kind>` synthetic-dir renderers | add `ObjType.Domain`; clone the `objfsParseDeep` view machinery |
| Restricted FS view (allowed/deny/mounts) | `core/namespace.d` `NsBinding{path,objId,rights}` + `nsResolveWithRights` + `namespaceCheckOpen` (posix.d) | enforcement chokepoint exists; default `/`→`uint.max` binding must flip to deny-by-default |
| Per-domain object root + cross-domain shares | `core/idns.d` `idnsForIdentity` / `idnsShare` / `ShareRule` (deny-by-default, audited) | reuse directly for mounted roots + shared folders |
| Capability mediation + least-privilege merge | `core/cap.d` `capDerive`(subset) / `capTableCloneNarrowing` / `capRevokeIn` / `requireCap` | the "child may reduce not expand" law is already enforced |
| Domain identity + ceiling + color + net/clip | `core/identity.d` `IdentityRec` (+ `templateId`, `disposable`, `policyEpoch`) | extend / wrap; `templateId` already models clone-from-template |
| Launch-into-domain authorization | `identityCanTransition` + `g_idLaunchRules` + `hosIdSwitch` (`HOSQ_ID_SWITCH`) | gate exists; the GUI launch path never calls it |
| On-disk persistence | `core/objstore.d` `ObjAppEntry` + `objstoreInstallApp`/`LoadExec`/`StorageWrite` over AHCI | persists apps; add a `DomainEntry` directory region |
| Declarative manifest pipeline | `anonymos-config/` JSON→validate→merge→TLV + `core/configboot.d` HMAC-verified applier | add a `domains[]`/`templates[]` schema section + TLV tags |
| `/config` live JSON views | `hoscall.d` `configfsRender` (hand-rolled JSON, no parser) | add `/config/domains.json` |
| Immutable template / snapshot / rollback | `core/store.d` Generations (`genCreate`/`genSetActive`/`genRollback`) + content-addressed StoreObjects | reuse for template immutability + overlay snapshot |
| Copy-on-write | `core/addrspace.d` PTE_COW + `core/mm.d` per-page refcounts | page-CoW algorithm to mirror for overlay file copy-up |
| Native lifecycle ABI | `core/hoscall.d` `HOS_SYS_QUERY=0x4000` + `HOSQ_*` verbs, gated by `g_taskNativeAbi[]` | add `HOSQ_DOMAIN_*`; the DM becomes a native-personality client |
| GUI shell | `cd/wl-domain-manager` Cairo+FreeType two-pass render + `wl-deco.h`; `wl-files.c` scrollable list/sidebar/double-click | extend for Create/Clone/Snapshot/FS/Marketplace panels |

Principles (grounded): everything is an object; **capabilities, not raw path access**;
default-deny restricted views; immutable template + writable overlay; child policy may
**reduce but never expand** authority (least privilege); declarative manifest is the
source of truth; the GUI/CLI talk to the kernel **only** through Domain Manager ABI verbs,
never by mutating domain internals; compat (`EPIN_*` env, window border) stays as the UX
layer but is **backed by** real kernel-enforced policy.

Legend: **P** priority · **E** effort (1=hrs … 5=weeks) · **R** risk · deps.

Citation convention: file references use basenames relative to their tree —
`core/*.d`, `display/*.d` ⟹ under `src/kernel/d/`; `posix.d` ⟹ `src/kernel/d/core/syscalls/posix.d`;
GUI clients (`wl-domain-manager.c`, `wl-files.c`, `wl-term.c`, `gl-term.c`, `store-app.c`) ⟹ under
`src/util/`; `schema.d`/`compiler.d`/`manifest.d` ⟹ under `anonymos-config/source/`; `cd/*` are the
built artifacts staged into the ISO. Line numbers are anchors at time of writing — grep the symbol if drifted.

References this roadmap builds on: [docs/FILESYSTEM.md](../docs/FILESYSTEM.md) (layered
VFS, `sys_open` resolution, EROFS views, object FS), [docs/NAMESPACING.md](../docs/NAMESPACING.md)
(per-process `Namespace` bindings + `idns` identity views + fork/clone inheritance),
[docs/NATIVE_OBJECT_ABI.md](../docs/NATIVE_OBJECT_ABI.md) (the `HOSQ_*` lifecycle/cap/ns
verb family + the N0 access gate), [docs/SYSCALL_ABI.md](../docs/SYSCALL_ABI.md) (the
syscall surface for new verbs), plus the design lineage in
[roadmap/CAPABILITY_MODEL.md](CAPABILITY_MODEL.md),
[roadmap/IDENTITY_DOMAIN_ROADMAP.md](IDENTITY_DOMAIN_ROADMAP.md),
[roadmap/IMMUTABLE_ROOTLESS_ROADMAP.md](IMMUTABLE_ROOTLESS_ROADMAP.md),
[roadmap/OBJECT_FILESYSTEM_ROADMAP.md](OBJECT_FILESYSTEM_ROADMAP.md),
[roadmap/DECLARATIVE_CONFIG_SPEC.md](DECLARATIVE_CONFIG_SPEC.md),
[roadmap/SECURE_IPC_ROADMAP.md](SECURE_IPC_ROADMAP.md).

---

## Target architecture (concrete, for THIS codebase) — Deliverable 1 (required architectural changes)

The required architectural changes (Deliverable 1) are the sum of §§1–10 below: a new
`core/domain.d` module + `ObjType.Domain/Template/Overlay/Snapshot`; a `denied`/deny-by-default
extension to `core/namespace.d`; a `domains[]`/`templates[]` schema + new TLV tags across the
`anonymos-config` compiler and `core/configboot.d`; a `DomainEntry` region in `core/objstore.d`;
the `HOSQ_DOMAIN_*` verb family in `core/hoscall.d`; and the conversion of the GUI launch path from
raw `fork`+`setenv`+`execve` into a native trusted launcher. Nothing replaces an existing subsystem.

### 1. The Domain object model + sub-object tree (Deliverable 2)

A domain is a new first-class kernel object. Add `ObjType.Domain` and `ObjType.Template`
(and `ObjType.Overlay`, `ObjType.Snapshot`) to the `ObjType` enum in `core/objmgr.d`
(`objmgr.d:22-54`) and to `g_objTypeNames` in `hoscall.d:197`. A new module
`core/domain.d` owns a fixed registry `g_domains[DOM_MAX=32]` of:

```d
struct DomainRec {
  bool   inUse, running, paused;
  uint   objId;            // ObjType.Domain
  uint   templateObjId;    // the immutable Template this domain references (0 = none)
  uint   identityObjId;    // the IdentityRec that carries ceiling/color/net/clip (core/identity.d)
  uint   nsObjId;          // the live restricted namespace (core/namespace.d), 0 until started
  uint   overlayObjId;     // ObjType.Overlay (writable layer), 0 until started
  ulong  manifestLba;      // on-disk JSON manifest blob (core/objstore.d), 0 = RAM-only
  uint   manifestLen;
  ubyte  persistMode;      // 0=ephemeral 1=home-only 2=full-segment  (the brief's perpetuation choice)
  uint   state;            // DomainState enum (see §4)
  char[24] name;
  ulong  policyEpoch;      // signed-mutation counter (mirrors IdentityRec.policyEpoch)
}
```

The sub-object tree is rendered as a **synthetic FS view** (the F1/F5 pattern, NOT one
`objAlloc` per leaf — the brief's per-domain leaf explosion would exhaust the 8192-slot
table). `/objects/domains/<name>/` is a `SYNTHDIR_DOM_ENTRY` directory whose children are
`Template Overlay Applications Packages Services Permissions Identity Networking Filesystem
Linux PackageManager Appearance Policies Snapshots meta`, and `Filesystem/` is itself a
synthetic dir of `AllowedPaths DeniedPaths Mounts Overlay RuntimeView`. The renderers live
in `core/hoscall.d` (`domfsField`/`domfsFieldId`, mirroring `objfsField`/`objfsFieldId`
`hoscall.d:288-379`) and resolve through `posix.d` (`domfsParseDeep`, mirroring
`objfsParseDeep` `posix.d:2030` + new `SYNTHDIR_DOM_*` tags mirroring `SYNTHDIR_OBJ_*`
`posix.d:2023`). This is the brief's "Domain Object Tree" (Deliverable, object tree).

### 2. The JSON manifest schema (Deliverable 3)

Authored host-side; never parsed in the `-betterC` kernel (that has no JSON parser, by
design — `configboot.d:8`). The full schema (every brief field) is added to
`anonymos-config/source/schema.d` `documentSchema()` as `domains[]` and `templates[]`
sections (mirror the existing `identities[]` block at `schema.d:194-207`):

```jsonc
{
  "name": "Development",
  "type": "domain",              // "domain" | "template"
  "template": "Developer",       // parent template (inheritance, §7); templates may set "extends"
  "persist": "full",             // "ephemeral" | "home-only" | "full"  (the perpetuation choice)

  "linux": { "distribution": "Arch", "packageManager": "pacman" },   // §8/§9
  "packages": ["git","clang","cmake","python","rust"],
  "packageProfiles": ["Development"],                                // reusable collections
  "repositories": [{ "name":"core","url":"…","signingKey":"…","pinned":false }],
  "applications": ["terminal","editor","browser"],
  "services": ["ssh-agent"],
  "startupPrograms": ["terminal"],

  "defaults": { "defaultBrowser":"browser","defaultTerminal":"terminal",
                "defaultEditor":"editor","defaultShell":"zsh","defaultCompiler":"clang",
                "defaultPDF":"…","defaultMusicPlayer":"…","defaultVideoPlayer":"…",
                "defaultFileManager":"…","defaultIDE":"…" },
  "environment": { "EDITOR":"editor", "SHELL":"/bin/zsh" },

  "filesystemAccess": {          // THE critical requirement (§6)
    "defaultPolicy": "deny",
    "readOnly":  ["/System/Templates/Developer","/Shared/Public"],
    "readWrite": ["/Domains/Development/Home","/Domains/Development/Overlay","/Shared/Projects/AnonymOS"],
    "deny":      ["/System/Kernel","/System/Secrets","/Domains/*/Private"],
    "mounts": [ {"source":"/Objects/Projects/AnonymOS","target":"/home/user/project","mode":"rw"},
                {"source":"/System/LinuxRoots/Arch","target":"/linux","mode":"ro"} ],
    "tempFolders": ["/tmp"],
    "sharedFolders": [{"path":"/Shared/Projects/AnonymOS","with":["Research"],"mode":"rw"}],
    "packageWritable": ["/var/cache/pacman"],
    "execPaths": ["/usr/bin","/bin"],
    "homeVisible": true,
    "allowTraversalOutsideMounts": false,
    "allowCrossDomainAccess": false
  },

  "networkPolicy": { "mode":"nat" },          // none|nat|vpn|tor|localOnly|disposable → NetPolicy
  "identity": { "inheritFrom":"Development", "trust":50, "ceiling":"0x503ff" },
  "permissions": {                            // §14 enforcement list
    "allowedPackageManagers":["pacman"], "allowedRepositories":["core"],
    "maxStorage":"4GiB", "usb":false, "gpu":false, "clipboard":"askApproval",
    "ipc":"sameDomain", "canInstallPackages":true, "canModifyTemplate":false,
    "canExport":true, "canImport":false },
  "appearance": { "color":"0xAARRGGBB", "wallpaper":"…", "colorScheme":"dark",
                  "desktopLayout":"…", "initialWindowLayout":"…" },
  "policies": { "autoInstallOnCreate":true, "frozenPackages":[], "autoUpdate":false }
}
```

`compiler.d` lowers this (Stages 4-8) into the existing `CompiledGraph` (`compiler.d:120`),
reusing `checkCapabilities()` (`compiler.d:526`, the subset-narrowing that already rejects
escalation) for the least-privilege merge, then `manifest.d buildManifest` emits new TLV
tags (`TAG_DOMAIN_CREATE`, `TAG_FS_POLICY`, `TAG_MOUNT`, `TAG_DOMAIN_PERSIST`) into the
HMAC-signed `manifest.blob`. `core/configboot.d applyOne()` (`configboot.d:182`) gains the
matching cases that call `domainCreate`/`fsPolicyInstall`.

### 3. The restricted per-domain filesystem/object view (Deliverable 6 — the critical one)

The single global object/FS tree, with each domain seeing **only** what its manifest
grants. Mechanism (all existing primitives):

- A domain's namespace is a `NamespaceRec` (`core/namespace.d`) built from the manifest:
  - `defaultPolicy:"deny"` ⟹ **do NOT bind `/` to the rtfs root.** Today every namespace
    inherits the wide-open `/`→`uint.max` binding (`namespace.d:81-89 bindRoot`); a
    restricted domain's namespace must omit it. ★ This single change is what makes
    deny-by-default actually bite — without it every "restricted" domain still sees the
    whole tree.
  - each `readOnly` path ⟹ `nsBind(ns, path, objId, CAP_RIGHT_READ|STAT)`.
  - each `readWrite` path ⟹ `nsBind(ns, path, objId, CAP_RIGHT_READ|WRITE|STAT|…)`.
  - each `mounts[]` entry ⟹ `nsBind(ns, target, resolve(source), mode==rw?RW:RO)`.
  - `deny[]` ⟹ a new **negative-binding** concept in `NsBinding` (a `denied` flag): on a
    longest-prefix match to a denied binding, `nsResolveWithRights` returns EACCES even if
    a shorter allow-binding would have matched. (New semantics — see DM2.)
  - shared folders ⟹ `idnsShare` + a `ShareRule` (`core/idns.d:102-133`) — cap-wrapped,
    rights-attenuated, audited, deny-by-default. `allowCrossDomainAccess:false` ⟹ install
    no ShareRules.
- Enforcement is already wired: `namespaceCheckOpen` (`posix.d:1995/2341`) calls
  `nsResolveWithRights` on every absolute `open()` and returns EACCES/ENOENT. No new gate
  — just the right bindings. Raise `NS_BIND_MAX` (16) and `NS_PATH_MAX` (64) for real
  manifests.
- `allowTraversalOutsideMounts:false` is the default-deny behaviour (no `/` binding); `true`
  re-adds a read-only `/` binding.
- The per-domain home (`/Domains/<name>/Home`) and overlay (`/Domains/<name>/Overlay`) are
  the only persisted writable roots when `persist != ephemeral` (DM6).

`Filesystem/RuntimeView` renders the merged, resolved view (the union of bindings) so the
user/CLI can inspect exactly what the domain can reach — the brief's
`domain fs inspect` (DM10).

### 4. The domain lifecycle state machine (Deliverable 4)

```
            CreateDomain                StartDomain
  (none) ───────────────▶ Defined ────────────────▶ Running ◀──┐
     ▲                       │  ▲                     │  │      │ ResumeDomain
     │ DeleteDomain          │  │ ShutdownDomain      │  │      │
     └───────────────────────┘  └─────────────────── ┘  │ PauseDomain
                                                         ▼
                                                       Paused
  Running ──SnapshotDomain──▶ (snapshot stored, stays Running)
  Running ──CommitOverlay──▶  Running   (overlay folded → template version+1)
  Running ──DiscardOverlay──▶ Running   (overlay reset to template)
  Defined ──CloneDomain/DuplicateDomain──▶ new Defined
  Defined ──ResetDomain──▶ Defined (overlay+home wiped per persist policy)
  any     ──ExportDomain──▶ signed bundle on disk
  (none)  ──ImportDomain──▶ Defined
  any     ──RestoreDomain(snap)──▶ Running at snapshot
```

`DomainState ∈ {Defined, Starting, Running, Paused, Stopping, Failed}`. Transitions are
authorized through the existing `identityCanTransition` gate (`identity.d:326`) +
`CAP_RIGHT_ADMIN_IDENTITY`, and every transition calls `auditLog` (`core/audit.d`). The 16
lifecycle ops (Deliverable, lifecycle APIs) become `HOSQ_DOMAIN_*` verbs (§ APIs below).

### 5. The overlay filesystem (Deliverable 5)

```
  Immutable Template (read-only lower)  →  Writable Overlay (upper)  →  Merged Runtime View
```

- **Lower (immutable):** the Template's content, captured as a `core/store.d` Generation
  (content-addressed `StoreObject`s) — `genCreate` freezes it; templates are immutable by
  construction (a frozen Generation + a frozen `IdentityRec`, `identityFreeze`).
- **Upper (writable):** a per-domain writable layer. v1 = a **per-domain rtfs subtree** (a
  dedicated `RtNode` root index in `g_rt`, `posix.d:3569`) selected by the task's domain;
  the resolver tries the overlay first, falls back to the template, and **copies up** the
  template node into the overlay on first write (`rtCreate` `posix.d:3623` is the copy-up
  insertion point; mirror the page-CoW copy-up algorithm in `addrspace.d:183-201` +
  `mm.d:40-64` refcounts — DM7). v2 = persist the overlay subtree to `core/objstore.d`.
- **Merged view:** a layered resolver (overlay → template) surfaced at
  `Filesystem/RuntimeView`.
- Ops map onto Generations: `snapshot overlay` = `genCreate` over the overlay nodes;
  `rollback overlay` = `genRollback`; `commit overlay` = fold overlay into a **new** template
  version (`policyEpoch++`, never mutate the existing immutable template); `discard overlay`
  = drop the overlay subtree; `promote to template` = freeze the committed Generation as a
  new Template object; `inspect diff` = compare overlay vs template StoreObject digests;
  `validate before commit` = a cap/policy check pass before the fold.

### 6. Template inheritance + least-privilege merge (Deliverable 7)

`Base → Developer → Rust → Embedded → Project` chains. Each manifest stores **only its
overrides**; `compiler.d` resolves the chain (reusing `detectNamedCycles` `compiler.d:408`
for inheritance-cycle detection, already used for namespaces/snapshots). Per-category merge:

| Category | Merge rule |
|---|---|
| packages, repositories, services, startup apps, environment, default apps, appearance, Linux compat | **union / child-overrides-parent** (additive convenience) |
| filesystem access, network rules, device access, capabilities/ceiling, identity inheritance | **least privilege — intersection.** child may *reduce* but not *expand*; expanding requires the parent policy explicitly allows it. Reuse `capTableCloneNarrowing` / `capDerive`(subset) (`cap.d:261-277,187-201`) and the `checkCapabilities` subset check (`compiler.d:526`). |

A child that requests rights ⊄ parent ceiling is rejected at compile time (escalation),
exactly as `checkCapabilities` already rejects it for the `capabilities{}` section.

### 7. Security / capability enforcement model (Deliverable 14)

- A launched app is placed in its domain **for real**: replace the GUI's bare
  `fork`+`setenv`+`execve` (`wl-domain-manager.c:537-567`) with a native
  `spawn-into-domain` flow — the DM runs as a **native-personality trusted launcher**
  (`g_taskNativeAbi`, holding `CAP_RIGHT_ADMIN_IDENTITY`) that, on launch, sets the child's
  `Task.identityObjId` (`task.d:153`), attaches the domain namespace (`task.namespaceObjId`),
  seeds its cap table (`capInstallIn` per granted object), then `capTableCloneNarrowing`
  clamps the whole table to `identity.rightsCeiling`. `EPIN_*` env stays as the UX/display
  channel (border color, prompt) but is now **redundant with** real kernel enforcement.
- Device/GPU/USB/network gating: the manifest's `usb`/`gpu`/`networkPolicy` derive a device
  cap per allowed class into the child table; the FD-open path (`capRightsForFile`
  `posix.d:721-766`, the `FD_INPUT_EVENT`/`FD_DRM` opens) consults the domain's
  `allowedDevices` (`identity.d:71`). (Today these are prompt-only — DM8 wires the check.)
- `maxStorage` ⟹ a per-domain quota on the overlay/home (objstore storageCap).
- Clipboard/IPC ⟹ `ClipPolicy` + `idipcMayConnect`/`IpcPairRule` (`core/idipc.d`).
- Every grant/deny/revoke/transition lands in the `core/audit.d` ring for free.

### 8. Multi-distro / multi-package-manager integration (Deliverables 8, 9 — honest scope)

★ **Realistic staging.** The OS today has **one** synthetic musl busybox+zsh userland built
in RAM by `rtInit` and **no** package manager. So:

- **FEASIBLE NOW (DM7):** a single native **`hos` package** format installed at runtime via
  the existing `objstoreInstallApp` (`objstore.d:120`, which already stores
  manifest+perms+exec-blob+caps+private storage and is cap-gated on launch) — currently
  only boot-seeds 2 test apps; give it a runtime caller (`domain install`). Per-domain
  package sets/caches/allowlists scope onto `ObjAppEntry.identity` (already a field) + the
  domain namespace. Signed packages reuse `crypto.d` SHA-256/HMAC + the `store.d`/`update.d`
  signed-bundle machinery.
- **MEDIUM (DM11):** a per-distro **package-manager shim** that drives real `pacman`/`apt`/
  `apk`/`dnf`/`xbps`/`emerge`/`nix` **inside a per-domain Linux root** mounted RO at `/linux`
  (`/System/LinuxRoots/<distro>` ⟹ an `nsBind` RO mount). The package DB/cache lives in the
  domain's `packageWritable` overlay paths. Repos/mirrors/pinning/signing-keys/freeze come
  from the manifest's `repositories[]`.
- **ASPIRATIONAL (out of near-term scope, flagged):** populating + *running* full glibc
  distro binaries (Arch/Debian/Fedora/Nix) — the OS is musl-only today; glibc dynamic-loader
  + ABI quirks are a separate large effort. The schema/manifest models all of it; the
  runtime starts with `hos` packages + the BusyBox-only and Nix(static) paths, which fit
  musl.

### 9. Snapshot / rollback / export / import (Deliverable 15)

- **Snapshot/rollback:** §5 (Generations over the overlay).
- **Export:** serialize `DomainRec` + manifest + overlay diff + identity policy into a
  signed bundle (`crypto.d` HMAC, the `update.d` bundle format) written to disk via
  `objstore.d`; gated by `permissions.canExport`.
- **Import:** verify signature, `domainCreate` from the bundle's manifest, restore the
  overlay; gated by `permissions.canImport`.

### 10. Marketplace (Deliverable 16)

A **local template registry** under `/objects/templates/` backed by `objstore.d`, with
signed downloadable templates installable **without rebuilding the OS** (install = write a
new Template object + manifest to disk via `objstoreInstallApp`'s pattern). Supports:
signature verification (`crypto.d`), publisher identities (an `IdentityRec` per publisher),
semantic versioning (`policyEpoch`/version field), dependency checking (the
`compiler.d` reference-resolution + `detectNamedCycles`), trust policies (per-publisher
ceiling), rollback (Generations), offline install (no network — bundle on disk).

### Internal APIs / IPC (Deliverable 12)

All domain operations are **native `HOSQ_DOMAIN_*` verbs** added to the `HOS_SYS_QUERY`
multiplexer `hosQuery` in `core/hoscall.d` (dispatch switch `hoscall.d:575/600`), automatically
behind the N0 native gate (`kernel_main.d:2038` — where `rax==0x4000` is routed and
`!g_taskNativeAbi[ctid]` ⟹ `-ENOSYS` for Linux tasks). No
component mutates a `DomainRec` directly; they all go through these verbs (the brief's
"interact exclusively through Domain Manager APIs"):

```
HOSQ_DOMAIN_LIST       = 24   // enumerate domains (the GUI's domain list source)
HOSQ_DOMAIN_CREATE     = 25   // from a manifest handle → DomainRec (Defined)
HOSQ_DOMAIN_DELETE     = 26
HOSQ_DOMAIN_CLONE      = 27   // = DuplicateDomain
HOSQ_DOMAIN_RENAME     = 28
HOSQ_DOMAIN_START      = 29   // materialize ns + identity (+ overlay once DM6 lands), run startup apps
HOSQ_DOMAIN_SHUTDOWN   = 30
HOSQ_DOMAIN_PAUSE      = 31
HOSQ_DOMAIN_RESUME     = 32
HOSQ_DOMAIN_SNAPSHOT   = 33
HOSQ_DOMAIN_RESTORE    = 34
HOSQ_DOMAIN_RESET      = 35
HOSQ_DOMAIN_COMMIT     = 36   // CommitOverlay
HOSQ_DOMAIN_DISCARD    = 37   // DiscardOverlay
HOSQ_DOMAIN_EXPORT     = 38
HOSQ_DOMAIN_IMPORT     = 39
HOSQ_DOMAIN_FS_GET     = 40   // read the resolved RuntimeView (fs inspect)
HOSQ_DOMAIN_FS_ALLOW   = 41   // add an allow binding (signed-policy txn, epoch++)
HOSQ_DOMAIN_FS_DENY    = 42
HOSQ_DOMAIN_FS_MOUNT   = 43
HOSQ_DOMAIN_FS_UNMOUNT = 44
HOSQ_DOMAIN_SPAWN      = 45   // launch an app INTO the domain (identity+ns+caps), replaces fork+setenv
HOSQ_DOMAIN_PKG_INSTALL= 46
HOSQ_DOMAIN_PKG_REMOVE = 47
HOSQ_DOMAIN_SUBSCRIBE  = 48   // domain-changed events → live GUI (reuses HOSQ_SUBSCRIBE plumbing)
```

These reuse the existing non-escalating verbs underneath: `HOSQ_CAP_GRANT`/`NS_CLONE`/
`NS_ENTER`/`ID_SWITCH` (`hoscall.d:119-195`). The GUI↔kernel path = the `store-app.c sc4()`
4-arg syscall shape (`store-app.c:19`). Reads (`HOSQ_DOMAIN_LIST`/`FS_GET`) may additionally
be exposed Linux-side via the read-only `/config/domains.json` + `/objects/domains/` views
so the (currently Linux-personality) GUI can read without first going native.

**The brief's 14 components interact with domains *only* through these verbs — never by mutating a
`DomainRec`** (Deliverable 12). Mapping each mandated component to its DM-API surface + the real
module it is implemented by:

| Brief component | Talks to domains via | Backed by (real module) |
|---|---|---|
| Object Manager | `HOSQ_DOMAIN_LIST/CREATE/DELETE` + the `/objects/domains/` synthetic view | `core/objmgr.d`, `core/domain.d` |
| Identity Manager | `HOSQ_DOMAIN_SPAWN`/`START` set `Task.identityObjId`; `identityCanTransition` gate | `core/identity.d` |
| Namespace Manager | `HOSQ_DOMAIN_FS_*` + `domainBuildNamespace` (start) | `core/namespace.d`, `core/idns.d` |
| Process Manager | `HOSQ_DOMAIN_SPAWN`/`SHUTDOWN`/`PAUSE`/`RESUME` (load/stop/signal tasks) | `kernel_main.d` `execveTask`, `core/task.d` |
| Linux Compatibility Layer | `linux`/`distribution` manifest → RO `/linux` `nsBind`; shim driven by `PKG_INSTALL` | `posix.d` resolution + DM11 shims |
| Package Manager | `HOSQ_DOMAIN_PKG_INSTALL/REMOVE` + `domain packages` | `core/objstore.d` `objstoreInstallApp` |
| Filesystem Manager | `HOSQ_DOMAIN_FS_GET/ALLOW/DENY/MOUNT/UNMOUNT`; enforced at `namespaceCheckOpen` | `posix.d`, `core/namespace.d` |
| GUI | `HOSQ_DOMAIN_LIST` + `HOSQ_DOMAIN_SUBSCRIBE` (live) + all action verbs | `cd/wl-domain-manager` |
| Window Manager | reads `IdentityRec.color` for the unspoofable per-domain border | `core/idwin.d`, the compositor |
| Security Manager | `requireCap`/`capTableCloneNarrowing` on every verb; ceiling clamp on spawn | `core/cap.d`, `core/audit.d` |
| Policy Engine | manifest `permissions`/`policies` compiled + asserted; `validate before commit` | `anonymos-config/compiler.d`, `core/configboot.d` |
| Installer | `HOSQ_DOMAIN_PKG_INSTALL` (`autoInstallOnCreate`) + bundle import | `core/objstore.d`, `core/update.d` |
| Update Manager | `HOSQ_DOMAIN_COMMIT`/`SNAPSHOT` template versions; signed bundle verify | `core/store.d` Generations, `core/update.d` |
| Configuration Manager | `domains[]`/`templates[]` manifest → TLV → `configBootApply`; `/config/domains.json` | `anonymos-config`, `core/configboot.d`, `hoscall.d` `configfsRender` |

### CLI command set (Deliverable 11)

Native-shell builtins (alongside `obj/id/ns/svc/sys`), each calling a `HOSQ_DOMAIN_*` verb:

```
domain create <manifest.json>     domain fs allow  <name> <path> <ro|rw>
domain delete <name>              domain fs deny   <name> <path>
domain clone  <src> <new>         domain fs mount  <name> <src> <tgt> <ro|rw>
domain snapshot <name> [tag]      domain fs unmount<name> <tgt>
domain restore  <name> <snap>     domain fs inspect<name>        # the RuntimeView
domain commit  <name>             domain fs policy <name>        # show defaultPolicy + lists
domain discard <name>
domain install   <name> <pkg>     domain export <name> <file>
domain uninstall <name> <pkg>     domain import <file>
domain packages  <name>           domain list
domain applications <name>        domain inspect <name>
domain services  <name>           domain reset   <name>
domain templates                  domain start|shutdown|pause|resume <name>
```

### On-disk data-storage layout (Deliverable 13)

Extend `core/objstore.d` (the AHCI store, superblock @ LBA0 + app directory @ LBA1-32 +
blob region @ LBA64+). Add a **domain directory region** (LBA33-63) of fixed `DomainEntry`
records (mirror `ObjAppEntry` `objstore.d:45-58`):

```d
struct DomainEntry {           // 256B, pad like ObjAppEntry
  uint inUse, nameLen; char[64] name;
  uint identityLen;  char[32] identity;
  uint templateLen;  char[32] template_;
  uint persistMode; uint rights;
  ulong manifestLba, manifestLen;     // JSON manifest blob
  ulong overlayLba,  overlayLen;      // serialized writable overlay (persist=full/home-only)
  ulong snapBaseLba; uint snapCount;  // snapshot Generations
  ulong storageCap;                   // maxStorage quota
}
```

`objstoreInstallDomain`/`objstoreLoadDomain`/`objstoreOverlayWrite` mirror
`objstoreInstallApp`/`LoadExec`/`StorageWrite` (`objstore.d:120,217,156`). Templates persist
under `/objects/templates/<name>/` the same way (a `TemplateEntry`, immutable). Mount-time
rehydration runs in `kernel_main.d:2845` (the `objstoreMount` call site): walk
`DomainEntry[]`, recreate each `DomainRec` + its `IdentityRec`/namespace. `persistMode`
governs what is reloaded: `full` = manifest + overlay + home; `home-only` = manifest +
`/Domains/<name>/Home` only (overlay reset to template); `ephemeral` = manifest only
(everything fresh) — the brief's perpetuation choice.

---

## DM0 — Domain object + RAM registry + read-only view (the foundation) · P: High · E: 3 · R: med · deps: —

Make a domain a real kernel object before anything else depends on it. No persistence, no
restriction yet — just the object, the registry, and a browsable tree.

**Status — DM0.a + DM0.c + DM0.d DONE + boot-verified.** `core/domain.d` (`DomainRec`,
`g_domains[32]`, `domainCreate`/`domainById`/`domainByName`/`domainCount`/`domainInitDefaults`),
`ObjType.Domain`/`Template`/`Overlay`/`Snapshot`, the 7-domain boot seed (one per identity), the
`/config/domains.json` view, AND the `/objects/domains/<name>/{meta,capabilities,relationships}`
synthetic tree. ★ Implementation insight: the `/objects/<kind>/<obj>/<field>` resolution
(`objfsParseDeep` + the `SYNTHDIR_OBJ_*` getdents handlers) is **fully generic**, so domains became
just a new `OBJFS_DOMAINS` kind in `core/hoscall.d` (`objfsKindId`/`objfsEnum`/`objfsRead`/`objfsField`)
+ `"domains"` in the posix.d `kinds[]` list — NOT a separate `domfsParseDeep`/`SYNTHDIR_DOM_*` machine
(that was the draft's guess; the simpler path is correct). The richer nested `Filesystem/{AllowedPaths,…}`
sub-tree the brief shows lands with DM2 (when the FS policy exists). Serial proofs: `[domain] selftest
PASS`; `/config/domains.json render OK: 7 domains`; `/objects/domains view OK: 7 entries; meta/rels/caps
render`; `read-path /objects/domains/Development/meta: kind=5 field=1 -> OK 133 bytes` (the exact parse+
render `cat` runs). `capabilities` correctly shows each domain's inherited identity ceiling (Banking =
`0x503ff`, no admin caps). *Remaining DM0 piece:* DM0.b (native `HOSQ_DOMAIN_LIST` verb) is deferred to
its first consumer (DM4 CLI / DM10 GUI) — the data is already exposed Linux-side via `/config/domains.json`
+ `/objects/domains/`, which the (Linux-personality) GUI reads without going native.

- Add `ObjType.Domain`/`Template`/`Overlay`/`Snapshot` to `core/objmgr.d` (`objmgr.d:22-54`)
  + `g_objTypeNames` (`hoscall.d:197`).
- New `core/domain.d`: `DomainRec` (§1), `g_domains[32]`, `domainCreate(name, identityObjId,
  templateObjId)` (parallels `identityCreate` `identity.d:148`), `domainById`/`domainByName`/
  `domainCount`. Seed the 7 existing identities as 7 RAM domains at boot
  (`kernel_main.d` init, after `identityInitDefaults`) so the GUI has live data.
- Render `/objects/domains/<name>/{meta,Template,Overlay,…,Filesystem/{…}}` as synthetic
  dirs: `core/hoscall.d` `domfsField`/`domfsFieldId` + `posix.d` `domfsParseDeep` +
  `SYNTHDIR_DOM_*` tags (clone the F5 machinery: `objfsField` `hoscall.d:288`,
  `objfsParseDeep` `posix.d:2030`).
- Add `HOSQ_DOMAIN_LIST=24` (enumerate `g_domains`) + a `/config/domains.json` render
  (`configfsRender` case, `hoscall.d:484`).
- **DM0.1 — partially done:** the GUI already mirrors these 7 by value
  (`wl-domain-manager.c:107`); the kernel already has the 7 `IdentityRec`s
  (`identity.d:213`). This phase *links* them.
- *Verify:* `ls /objects/domains` → the 7 domains; `ls /objects/domains/Development` →
  `Applications Appearance Filesystem Identity Linux … meta`; `cat
  /objects/domains/Development/meta` → `type=Domain name=Development template=… identity=…
  state=Defined`; `cat /config/domains.json` reflects the 7; native shell `domain list`
  prints them; `/bin/ls` + rtfs selftest 11/11 unaffected.

## DM1 — Manifest schema + host compiler + TLV bridge · P: High · E: 4 · R: med · deps: DM0

A domain is described by JSON (Deliverable 3), compiled host-side, applied to the kernel
through the existing parser-free TLV bridge.

**Status — DM1 DONE + verified (host-side + in-VM).** A JSON `domains[]` section now flows all the
way to a kernel domain object: `anonymos-config/source/schema.d` (a `domains[]` section — name/type/
identity/template/persist explicit + the richer fields free-form pending their milestones) → `compiler.d`
(`DomainRecFields` + `domainTable` + `buildDomainTable`) → `manifest.d` (`Tag.domainCreate=8` + the
`name\0 identity\0 template\0 u8 persist` HMAC-signed TLV record) → `core/configboot.d` (`TAG_DOMAIN_CREATE`
applyOne case → `domainCreate`, idempotent re-assert of the DM0 seed, sets `persistMode`). Verified:
host `anonymos-config check examples/system.json` → OK (validates `domains[]`); `emit-manifest` → a
309-byte signed blob whose TLV carries `DevSandbox`→`Personal` + `BankVault`→`Banking`. In-VM boot:
`[configboot] domain DevSandbox created -> identity Personal persist=0x2`, `BankVault ... persist=0x1`;
`config: applied … 2 domains`; the views grow to `9 domains` (7 DM0 seed + 2 manifest). The domain VIEW
boot proofs were moved to run *after* `configBootApply` so they reflect the manifest-applied registry.
*Scope note:* a domain inherits its identity's **already-validated** ceiling (identityCreate enforces
`⊆ universe`), so the roadmap's "ceiling ⊄ parent → reject" escalation check is a **domain-level**
least-privilege merge that belongs to **DM9** (template inheritance), not DM1; the identity-level check
already exists. `templates[]` + object-graph/reference-resolution wiring (`assignIds`/`objKindToType`)
also deferred to DM6/DM9 — DM1 needs only the create path.

- `anonymos-config/source/schema.d`: add `domains[]` + `templates[]` to `documentSchema()`
  with every field of §2 (mirror the `identities[]` block `schema.d:194-207`).
- `compiler.d`: `buildDomainTable()` + lower into `CompiledGraph` (`compiler.d:120`); reuse
  `objKindToType` (add Domain/Template) and `checkCapabilities` (`compiler.d:526`) for the
  least-privilege fields.
- `manifest.d`: add `TAG_DOMAIN_CREATE`/`TAG_FS_POLICY`/`TAG_MOUNT`/`TAG_DOMAIN_PERSIST` to
  the `Tag` enum (`manifest.d:42`) + emit in `buildManifest` (`manifest.d:126`); HMAC-signed
  with the shared `TRUSTED_KEY`.
- `core/configboot.d`: `applyOne()` (`configboot.d:182`) gains the matching cases calling
  `domainCreate` + (DM2) `fsPolicyInstall`. Idempotent re-assert like the identity case
  (`configboot.d:215`). Wired at the existing `configBootApply` call (`kernel_main.d:2874`).
- *Verify:* `anonymos-config check examples/domains.json` passes the schema; `… emit-manifest`
  produces a `manifest.blob`; boot with it → serial logs `[configboot] domain Development
  created`; `cat /objects/domains/Development/meta` shows the manifest-derived fields (not the
  DM0 seed); a manifest with `ceiling` ⊄ parent → `anonymos-config build` rejects it
  (escalation).

## DM2 — Restricted per-domain FS view (deny-by-default) · P: High · E: 4 · R: high · deps: DM0, DM1

★ **The critical requirement.** Each domain sees only its granted paths; default-deny.

**Status — DM2.1 (the enforcement primitive) DONE + boot-verified.** `core/namespace.d`: `NsBinding`
gained a `denied` flag; the resolver was split into `nsResolveCheck` (logic + `out denied`) with
`nsResolveWithRights`/`nsResolve` delegating to it (so the 11 existing callers are untouched);
`nsAllocRestricted()` creates a namespace with **no `/` binding** (the deny-by-default substrate);
`nsBindDeny()` adds a deny binding that overrides a shorter allow on a longest-prefix match; `NS_BIND_MAX`
16→32. Enforcement wired at `namespaceCheckOpen` (posix.d): it now calls `nsResolveCheck` and returns
**EACCES for an explicit deny, ENOENT for an unbound path** (both deny; the existing rights check already
gives EACCES on insufficient rights). ★ Key confirmation from reading the code: `namespaceCheckOpen`
already treats a 0 resolve as deny (ENOENT), so simply omitting the `/` binding genuinely enforces
deny-by-default — no new gate. Verified: `[ns] restricted selftest PASS (deny-by-default + ro-rights +
deny-override)` — a restricted ns denies an unbound path, a read-only allow grants READ-not-WRITE, and a
deny binding overrides a shorter allow. No regression.

**DM2.2 (domains get a restricted view) DONE + verified.** `core/domain.d` `domainBuildNamespace(domObjId)`:
`nsAllocRestricted()` + binds a default-deny policy — `/Domains/<name>/Home` (rw), `/tmp` (rw), `/Shared`
(ro), deny `/Shared/Private` + `/System` — and stores the `nsObjId` on the `DomainRec`. The allow-binding
target is the rtfs-root Directory object (the gate only needs `target!=0` + rights; the backing rtfs
resolver handles the real file since `namespaceCheckOpen` returns 0=proceed — it does NOT redirect via
`outRest`). Verified: `[domain] ns proof PASS: Development restricted view` — building Development's real
ns + resolving 5 paths (home rw allowed, `/Shared` ro, `/Shared/Private`+`/System` denied, unbound
`/etc/passwd` deny-by-default).

**DM2.3 (manifest drives the restricted view) DONE + verified — host + in-VM.** The `filesystemAccess`
block now flows from JSON to an enforced restricted namespace: `schema.d` gave it an explicit schema
(`defaultPolicy`/`readOnly`/`readWrite`/`deny`/`allowTraversalOutsideMounts`/`homeVisible`, allowUnknown for
the deferred mounts/shared/…); `compiler.d` `DomainRecFields` gained the fs lists + `buildDomainTable` reads
them; `manifest.d` emits `Tag.fsPolicy=9` (domainName\0 u8 flags) + `Tag.fsBind=10` (domainName\0 u8 mode
path\0) records per domain; `configboot.d` `TAG_FS_POLICY` builds a fresh `nsAllocRestricted()` for the
domain (overriding the DM2.2 default) and `TAG_FS_BIND` does `nsBind`(ro/rw)/`nsBindDeny`. Verified: host
`check` OK + the 512-byte TLV carries the fs paths; in-VM `[configboot] domain DevSandbox fs policy →
restricted ns` + `[domain] fs manifest proof PASS: DevSandbox ns from manifest (Home+Projects rw,
/System/Templates ro, secrets denied, unbound deny-by-default)`.

**DM2.4 (RuntimeView inspection) DONE + verified.** A domain object gained a `filesystem` field —
`cat /objects/domains/<name>/filesystem` renders the **RuntimeView**: the resolved restricted view
(`defaultPolicy=deny`, then `ro`/`rw`/`deny` per binding). `core/namespace.d` `nsBindingAt` (enumerate a
ns's bindings) + `nsHasRootMount`; `core/hoscall.d` `OBJF_FS` field + `objfsFieldId("filesystem")` + the
renderer in `objfsField`; `posix.d` the `/objects/<kind>/<obj>` getdents tag now encodes the kind
(`SYNTHDIR_OBJ_ENTRY + okind`) so domains (kind 5) also LIST `filesystem` (others unchanged). Verified:
`[domain] /objects/domains/DevSandbox/filesystem (DM2.4 RuntimeView)` shows exactly the manifest policy. The
native `HOSQ_DOMAIN_FS_GET` verb is deferred to its DM10 GUI consumer (the data is already cat-able Linux-side
via this field, like DM0.b). **★ DM2 is COMPLETE** — the brief's central requirement (capability-mediated,
default-deny restricted filesystem visibility) is declarative end-to-end + enforced + inspectable. The live
"a real task gets EACCES" test is **DM3** (it needs `Task.namespaceObjId` = the domain ns). Deferred fields:
`mounts`/`sharedFolders`/`tempFolders`/`packageWritable`/`execPaths` (schema-accepted, compiled in later milestones).

- `core/namespace.d`: add a `denied` flag to `NsBinding`; make `nsResolveWithRights`
  (`namespace.d:174`) return EACCES on a longest-prefix match to a denied binding even when
  a shorter allow-binding exists. Raise `NS_BIND_MAX` 16→64, `NS_PATH_MAX` 64→128.
- New `core/domainfs.d` (or in `core/domain.d`): `domainBuildNamespace(domObjId)` compiles
  the manifest's `filesystemAccess` into a fresh `NamespaceRec`: **no `/` binding** unless
  `allowTraversalOutsideMounts`; one `nsBind` per `readOnly`/`readWrite`/`mounts[]` with the
  right cap rights; `deny[]` ⟹ denied bindings; `sharedFolders`/`allowCrossDomainAccess`
  ⟹ `idnsShareRuleAdd`+`idnsShare` (`idns.d:102-133`).
- Reuse `idnsForIdentity` (`idns.d:71`) for the private object-root + `/Domains/<name>/Home`.
- Enforcement is already at `namespaceCheckOpen` (`posix.d:1995/2341`) — no new gate.
- `Filesystem/RuntimeView` + `HOSQ_DOMAIN_FS_GET=40` render the resolved union; `FS_ALLOW`/
  `FS_DENY`/`FS_MOUNT`/`FS_UNMOUNT` (41-44) mutate via the signed-policy-txn (`policyEpoch++`,
  audited) — fail-closed, attenuation-only.
- *Verify (in a domain-bound test task):* with `defaultPolicy:deny` + `readWrite:[/Domains/X/Home]`
  only — `cat /Domains/X/Home/f` works, `ls /System/Kernel` → EACCES, `cat /etc/shadow` →
  ENOENT/EACCES, `ls /Domains/Y/Private` (in `deny`) → EACCES; `domain fs inspect X` lists
  exactly the granted paths; a sibling domain cannot see X's home (`allowCrossDomainAccess:false`);
  audit ring shows the denials.

## DM3 — Launch INTO a domain (real identity + ns + caps) · P: High · E: 4 · R: high · deps: DM2

Replace the cosmetic `EPIN_*`-only launch with kernel-enforced placement (Deliverable 14).

**Status — DM3 kernel core DONE + verified.** `core/task.d` `domainBindTaskNs(tid, domObjId)` gives a task
a PRIVATE clone of the domain's restricted ns (`nsClone(domain.nsObjId)`) + the domain's identity — so its
absolute opens are enforced against the domain policy (`namespaceCheckOpen` reads
`g_tasks[tid].namespaceObjId`). `domainEnterTask(childTid, domObjId, launcherIdentity, launcherCapTab)`
wraps it with the `identityCanTransition` gate (needs `CAP_RIGHT_ADMIN_IDENTITY` + a compiled launch rule —
deny-by-default; the gate itself is proven by `idprocSelfTest`). Verified: `[domain] enter proof PASS: task
bound to DevSandbox restricted ns + identity Personal (opens enforced)` — a spare task slot bound into
DevSandbox resolves `/etc/passwd`→deny, `/Domains/DevSandbox/Home`→allow, and carries identity Personal.
This is the mechanism that makes isolation REAL. *Remaining DM3 (the user-visible integration):* the
`HOSQ_DOMAIN_SPAWN=45` verb (the trusted launcher's native entry point) + making `cd/wl-domain-manager` a
native-personality launcher that calls it instead of bare `fork`+`setenv`+`execve` (`wl-domain-manager.c`),
so a real terminal launched into "Banking" gets EACCES on `/Domains/Work/Home` — the live interactive test.
`EPIN_*` env stays as the UX/border display, now backed by real enforcement. (Cap-table clamping to the
ceiling = DM8.)

- `HOSQ_DOMAIN_SPAWN=45`: a §4-style `spawn-into-domain` — load the image (reusing
  `execveTask` `kernel_main.d:750` + the F4.2 cap-gate), set the child's `Task.identityObjId`,
  attach `domainBuildNamespace`'s namespace as `Task.namespaceObjId`, seed caps via
  `capInstallIn` then `capTableCloneNarrowing` to `identity.rightsCeiling`. Authorize through
  `identityCanTransition` (`identity.d:326`).
- `cd/wl-domain-manager` `launch_app` (`wl-domain-manager.c:537-567`): the DM becomes a
  native-personality trusted launcher (`g_taskNativeAbi`, `CAP_RIGHT_ADMIN_IDENTITY`) and
  calls `HOSQ_DOMAIN_SPAWN` instead of bare `fork`+`setenv`+`execve`. Keep `EPIN_*` env for
  the unspoofable border (`wl-term.c:1088`, `gl-term.c`) + prompt — now redundant with real
  enforcement.
- *Verify:* launch a terminal into "Banking" → `id` in that terminal shows
  `Task.identityObjId == Banking`; the terminal cannot `cat /Domains/Work/Home/*` (EACCES);
  `/objects/processes/<pid>/relationships` shows the Banking namespace; the window border is
  Banking-colored; a cap exceeding the Banking ceiling is absent from the child's cap table.

## DM4 — Lifecycle state machine + verbs · P: High · E: 3 · R: med · deps: DM3

Create/Delete/Clone/Rename/Start/Shutdown/Pause/Resume/Reset (Deliverable 4) as verbs +
the `DomainState` machine (§4).

**Status — DM4 lifecycle CORE DONE + verified** (the kernel side of the verbs; the registry/state ops that
don't need spawning). `core/domain.d`: the `DomainState` machine — `domainStart` (Defined→Running, builds
the DM2 restricted ns), `domainShutdown` (Running/Paused→Defined), `domainPause` (Running→Paused),
`domainResume` (Paused→Running); plus `domainClone` (copy identity/template/persist into a new Defined
domain), `domainRename` (unique-name checked), `domainDelete` (releases the ns + the object + frees the
slot). Deny-by-default: a bad transition returns false. Verified: `[domain] lifecycle proof PASS:
clone/start/pause/resume/shutdown/rename/delete + bad transitions rejected` (a throwaway clone of Development
driven through the full cycle; `start` on a Running domain + `resume` on a Defined domain both rejected). No
regression. *Remaining DM4:* `Start`'s actual launch-into-domain (runs `startupPrograms` via DM3's
`HOSQ_DOMAIN_SPAWN`) + exposing all of these as `HOSQ_DOMAIN_*` verbs / `domain` CLI builtins (the ABI
layer, paired with the DM10 GUI / native-shell consumer like DM0.b). The `Reset` op (wipe overlay+home per
persist policy) lands with DM6's overlay.

- `core/domain.d`: the `DomainState` enum + transition table; `HOSQ_DOMAIN_{CREATE,DELETE,
  CLONE,RENAME,START,SHUTDOWN,PAUSE,RESUME,RESET}` (25-32, 35). Start = build ns + identity +
  run `startupPrograms` via `HOSQ_DOMAIN_SPAWN` — **the overlay is ephemeral at this milestone**
  (the writable layer + copy-up persistence is wired into Start by DM6, which has the overlay
  subsystem; DM4 must not forward-depend on it). Delete/Shutdown = `capRevokeIn`
  the domain's whole authority subtree (`cap.d:227`). Clone reuses `IdentityRec.templateId`/
  `disposable` semantics.
- CLI builtins `domain create/delete/clone/start/shutdown/pause/resume/reset/list/inspect`.
- *Verify:* `domain clone Development Dev2` → a new Defined domain in `ls /objects/domains`;
  `domain start Dev2` → state Running + its startup terminal appears; `domain pause Dev2` /
  `resume`; `domain delete Dev2` removes it + its caps are revoked (audit shows the
  revocation closure); invalid transition (`resume` a Defined domain) → EINVAL.

## DM5 — On-disk persistence + perpetuation policy · P: High · E: 4 · R: high · deps: DM1, DM4, OBJECT_FS F4 (disk)

Domains + the choice to persist full segment / home-only / fresh (Deliverable 13 + the
brief's perpetuation requirement).

**Status — DM5 persistence CORE DONE + 2-boot verified.** `core/objstore.d`: a **domain directory** region
(LBA 33–48, `DomainEntry` 256B × 32) added to the AHCI object store; superblock gained `domainCount` +
bumped to v2 (an old v1 disk is handled gracefully — empty domain dir). `objstoreInstallDomain(name,
identity, template, persist)` persists a domain's DEFINITION (name/identity/template/persistMode);
`objstoreDomainAt`/`objstoreDomainCount` read it back; `flushMeta`/`objstoreMount` write/load the domain dir
alongside the app dir. `core/domain.d` `domainRehydrateFromDisk()` (run after the seed+manifest domains, so
identity links resolve + names dedup) recreates the persisted domains. Verified with the **F4 two-boot
method** (same `hos-disk.img`, separate QEMU processes — the boot-counter 1→2 proves it): boot 1
`[domain] persist proof: PersistProbe created + persisted to disk`; boot 2 `[domain] rehydrated 1 domain(s)
from disk` + `[domain] persist proof PASS: PersistProbe rehydrated from disk across reboot`. *Remaining DM5:*
honoring `persistMode` differences (full vs home-only vs ephemeral) governs the **overlay+home** blob
reload — which needs the overlay (DM6); persisting the full `filesystemAccess` policy (re-derived from the
manifest for now); `maxStorage`→`DomainEntry.storageCap` quota. The domain DEFINITION persistence (the core)
is done.

- `core/objstore.d`: `DomainEntry` directory region (LBA33-63), `objstoreInstallDomain`/
  `objstoreLoadDomain`/`objstoreOverlayWrite` (mirror `objstoreInstallApp`/`LoadExec`/
  `StorageWrite`). Mount-time rehydration in `kernel_main.d:2845`.
- `persistMode` honored on rehydrate: `full`/`home-only`/`ephemeral`.
- `maxStorage` ⟹ `DomainEntry.storageCap` quota on writes.
- *Verify (two QEMU boots, same `hos-disk.img`):* boot 1 `domain create`, write a file in the
  domain home; boot 2 (no reformat) → the domain + (for `persist:full`) the file survive;
  a `persist:home-only` domain keeps the home but the overlay resets to template; a
  `persist:ephemeral` domain comes back empty. The on-disk boot counter climbing across
  separate QEMU processes proves real persistence (the F4 method).

## DM6 — Templates + immutability + overlay (commit/discard/snapshot) · P: Med · E: 5 · R: high · deps: DM5

First-class immutable Template Domains; running domains reference one; changes live in a
writable overlay (Deliverables 5, the Template-Domains section).

**Status — DM6.1 (first-class immutable Templates) DONE + verified.** A manifest `"type": "template"`
entry now becomes an immutable Template that a domain references. `core/domain.d` `DomainRec.isTemplate` +
`domainSetTemplate`/`domainIsTemplate`; `domainRename` refuses a template (immutable). Pipeline: `schema.d`
the `template` field is a plain name (no longer a false identity-ref); `manifest.d` emits templates **first**
(two-pass) + a `type` byte on the `domainCreate` record (backward-compatible); `configboot.d` reads the type
byte → `domainSetTemplate`, and resolves the `template` name → `templateObjId` (templates exist first). The
`/config/domains.json` + `/objects/domains/<name>/meta` views show `type`. `examples/system.json` got a
`DevTemplate` that `DevSandbox` references. Verified: `[configboot] template DevTemplate created`;
`[configboot] domain DevSandbox created -> identity Personal template DevTemplate`; `[domain] template proof
PASS: DevTemplate immutable template + DevSandbox references it` (rename refused). No regression. *Remaining
DM6 (the deeper half — the writable overlay):* `ObjType.Overlay` per running domain = a CoW writable layer
over the immutable template (the roadmap §5 design: a per-domain rtfs subtree with copy-up at `rtCreate`,
mirroring `addrspace.d` page-CoW + `core/store.d` Generations), with `HOSQ_DOMAIN_{SNAPSHOT,RESTORE,COMMIT,
DISCARD}` (commit folds the overlay into a NEW template version, never mutating the existing one) +
`inspect diff` + `validate before commit`. This unlocks DM5's persistMode-driven overlay+home reload. The
template catalog (Developer/Gaming/Research/… as manifests) seeds alongside it.

- `ObjType.Template` objects under `/objects/templates/<name>/`, persisted like domains
  (immutable: a frozen Generation + frozen `IdentityRec`).
- Overlay = per-domain rtfs subtree (a dedicated `g_rt` root index, `posix.d:3569`) with
  copy-up on first write at `rtCreate` (`posix.d:3623`), mirroring the page-CoW algorithm
  (`addrspace.d:183-201`, `mm.d:40-64`).
- `HOSQ_DOMAIN_{SNAPSHOT,RESTORE,COMMIT,DISCARD}` (33,34,36,37) over `core/store.d`
  Generations (`genCreate`/`genSetActive`/`genRollback`); commit folds the overlay into a
  **new** template version (`policyEpoch++`) — never mutates the existing template; promote
  freezes a committed Generation as a new Template; `inspect diff` compares StoreObject
  digests; `validate before commit` = a policy pass.
- Seed the brief's template catalog as manifests: Developer, Gaming, Research, Forensics,
  Office, Anonymous-Browsing, Media-Editing, Minimal, Recovery, Windows-Compat, AI-Dev (the
  Windows + heavy-distro ones are manifest stubs pending §8 scope).
- *Verify:* `domain snapshot Development pre-edit`; edit a file in the domain; `domain fs
  inspect` shows the overlay diff; `domain discard Development` → file reverts to template;
  re-edit + `domain commit Development` → a new template version (the old one's
  StoreObjects unchanged); `domain restore Development pre-edit` rolls back.

## DM7 — Native package install (the `hos` format) · P: Med · E: 3 · R: med · deps: DM3, DM5

Runtime install of native apps into a domain (Deliverable 8, the feasible-now path).

- Give `objstoreInstallApp` (`objstore.d:120`) a **runtime caller**: `HOSQ_DOMAIN_PKG_INSTALL=46`
  / `PKG_REMOVE=47` + `domain install/uninstall/packages`. The installed app is cap-gated on
  launch (F4.2) and scoped to the domain via `ObjAppEntry.identity` + the domain namespace.
- Per-domain package cache/allowlist/denylist + `frozenPackages` from the manifest; signed
  packages verified with `crypto.d`.
- `policies.autoInstallOnCreate` ⟹ the domain's manifest packages install on first
  `domain create`, subject to `permissions.canInstallPackages` (the brief's "automatically
  install required software … subject to policy approval").
- *Verify:* `domain install Development hello` → `ls /objects/apps` shows it scoped to
  Development; another domain cannot launch it (cap/ns denied); `domain packages Development`
  lists it; survives reboot (DM5); a package exceeding the domain ceiling → EPERM + audit.

## DM8 — Permissions & policy enforcement (devices/net/clip/IPC/quota) · P: Med · E: 3 · R: med · deps: DM3

Wire the manifest's permission knobs to real gates (Deliverable 14, full list).

- Device/USB/GPU: derive a device cap per allowed class into the child table; the FD-open
  path (`capRightsForFile` `posix.d:721`, `FD_INPUT_EVENT`/`FD_DRM`) consults
  `allowedDevices` (`identity.d:71`).
- Network: `NetPolicy` enforced at the socket/connect path (not just the prompt).
- Clipboard: `ClipPolicy`; IPC: `idipcMayConnect`/`IpcPairRule` (`core/idipc.d`).
- Allowed package managers/repos/software, template-modification, export/import perms
  checked at the corresponding verbs.
- *Verify:* a `usb:false` domain → opening `/dev/input/event*` EACCES; a `gpu:false` domain
  → `gl-term` falls back to sw (DRM open denied); a `networkPolicy:none` domain → connect()
  EACCES; `clipboard:deny` blocks cross-domain paste; audit ring records each.

## DM9 — Template inheritance + least-privilege merge · P: Med · E: 4 · R: med · deps: DM1, DM6

`Base→Developer→Rust→Embedded→Project` chains, overrides-only, least-privilege security
merge (Deliverable 7).

- `compiler.d`: resolve the `template`/`extends` chain, store only overrides, merge per §6's
  table; reuse `detectNamedCycles` (`compiler.d:408`) for inheritance cycles and
  `checkCapabilities` (`compiler.d:526`) for the subset (least-privilege) categories.
- Reject any child that expands fs/net/device/cap access beyond the parent (escalation).
- *Verify:* `anonymos-config build` on a 4-level chain emits a merged manifest whose packages
  are the union and whose fs-access is the intersection; a child adding a `readWrite` path the
  parent denies → rejected; a child *removing* network access → accepted.

## DM10 — GUI Domain Manager (live, full panels) · P: Med · E: 4 · R: med · deps: DM4, DM2

Expand `cd/wl-domain-manager` into the brief's full GUI (Deliverable 10), updating live.

- Make the DM a native-personality `HOSQ` client (the `store-app.c sc4` shape); replace the
  hardcoded `DOMAINS[]`/`DEFAULTS[]` (`wl-domain-manager.c:107/127`) with a
  `HOSQ_DOMAIN_LIST` read; subscribe via `HOSQ_DOMAIN_SUBSCRIBE=48` (reuse the
  `HOSQ_SUBSCRIBE`/`RECV` plumbing `hoscall.d:105,587`) and add the channel fd to the main
  loop (`wl-domain-manager.c:792`) alongside `wl_display_get_fd` ⟹ **live updates**.
- New panels (built from the existing Cairo/FreeType two-pass + `wl-deco.h`, borrowing the
  scrollable list / sidebar / double-click from `wl-files.c`): Create Domain, Delete, Clone
  Template, Create Template, Snapshot, Rollback, Commit, Discard, Install/Remove Software,
  Select Distribution, Select Package Manager, Configure Networking/Permissions/Filesystem
  Access/Allowed Folders/Shared Folders, Select Appearance (color picker → `IdentityRec.color`),
  Manage Startup Apps, Export, Import, Template Browser, Marketplace Browser.

Wireframes (Deliverable 10) — the existing left-list + right-panel layout, extended with a toolbar
and tabbed sub-panels; ▮ = the unspoofable per-domain color swatch:

```
┌─ Domain Manager ───────────────────────────────────────[_][□][x]┐
│ [ +New ] [ Clone ] [ Template▾ ] [ Import ] [ Marketplace ]      │  ← toolbar (verbs)
├───────────────┬──────────────────────────────────────────────────┤
│ DOMAINS       │  Development            ● Running    ▮ #6A1B9A     │
│ ▮ System    ● │  ┌ Overview | Filesystem | Packages | Network |   │
│ ▮ Personal  ○ │  │          Permissions | Startup | Appearance ┐  │  ← tabs
│ ▮ Work      ○ │  │ Template : Developer  (immutable)            │  │
│▸▮ Developmnt● │  │ Persist  : ( ) ephemeral (•) home  ( ) full │  │
│ ▮ Banking   ○ │  │ Shell    : [ zsh ▾ ]   Terminal: [ gl-term▾]│  │
│ ▮ Untrusted ○ │  │ Memory   : [ 4 GiB ▾ ]  Net: [ local ▾ ]    │  │
│ ▮ Disposabl ○ │  │ [ Start ] [ Pause ] [ Snapshot ] [ Reset ]  │  │  ← lifecycle verbs
│               │  └─────────────────────────────────────────────┘  │
│ [ Delete ]    │  status: overlay 12MB · snapshot pre-edit · last  │
└───────────────┴──────────────────────────────────────────────────┘
   Filesystem tab (the critical panel)        Packages tab
  ┌ defaultPolicy: ( ) allow (•) deny ┐      ┌ [git] [clang] [cmake] [+]┐
  │ Read-only :  /Shared/Public    [x] │      │ profile: [Development ▾]  │
  │ Read-write:  /Domains/Dev/Home [x] │      │ [ Install… ] [ Remove ]   │
  │ Deny      :  /System/Secrets   [x] │      │ source: pacman (RO /linux)│
  │ Mounts    :  →/home/user/project rw│      └───────────────────────────┘
  │ Shared    :  with [Research▾] rw   │       Appearance: color ▣ wallpaper
  │ [ +Allow ] [ +Deny ] [ +Mount ]    │       Startup: [terminal] [+ add]
  │ RuntimeView ▸ (resolved union)     │       Export ▸ signed .hosdt bundle
  └────────────────────────────────────┘
```

Workflow: select domain → tab → edit a control → the GUI issues the matching `HOSQ_DOMAIN_*` verb →
`HOSQ_DOMAIN_SUBSCRIBE` pushes the change back → every open panel repaints (live). No control writes a
`DomainRec` field directly; each is a verb call whose result re-reads `HOSQ_DOMAIN_LIST`/`FS_GET`.

- *Verify live (`roadmap/assets/dm10-gui.png`):* create a domain in the GUI → it appears in
  `domain list` + `/objects/domains`; configure an allowed folder → reflected in `domain fs
  inspect`; the list updates live when a domain is created from the CLI in another terminal;
  QMP-driven click test (the rel-event trick from [[window-decorations]]) exercises each panel
  headlessly.

## DM11 — Multi-distro / package-manager shims · P: Low · E: 5 · R: high · deps: DM7, DM6

Per-domain Linux compat config driving real package managers in a per-domain Linux root
(Deliverables 8, 9 — the medium-scope path).

- `/System/LinuxRoots/<distro>` (BusyBox-only + Nix-static first, the musl-compatible ones)
  mounted RO per domain via `nsBind`; the manifest's `distribution`/`packageManager` select
  it; package DB/cache in the domain's `packageWritable` overlay paths; repos/mirrors/pinning/
  signing-keys/freeze from `repositories[]`.
- Package profiles (Development/Office/Gaming/Research/Security/Minimal/AI/Media) as reusable
  manifest fragments (Deliverable, package profiles).
- ★ Honest limit: full glibc distros (Arch/Debian/Fedora) need glibc-loader support — out of
  scope here; the schema models them, the runtime ships the musl-fit subset.
- *Verify:* a `BusyBox-only` domain resolves `/linux` RO; a `Nix` domain installs a static
  package into its overlay cache; switching the domain's `packageManager` re-roots `/linux`;
  allowlist/denylist + freeze honored.

## DM12 — Marketplace / signed downloadable templates · P: Low · E: 4 · R: high · deps: DM6, DM5

Installable templates without rebuilding the OS (Deliverables 15 export/import, 16
marketplace).

- Local registry `/objects/templates/` (objstore-backed); `ExportDomain`/`ImportDomain`
  (`HOSQ_DOMAIN_EXPORT/IMPORT` 38/39) as signed bundles (`crypto.d` HMAC + `update.d` bundle
  format); install = write a Template object + manifest to disk. Signature verification,
  publisher identities (an `IdentityRec` per publisher), semver (`policyEpoch`), dependency
  checking (`compiler.d` resolution), trust policies, rollback (Generations), offline install.
- *Verify:* `domain export Development dev.hosdt` → a signed bundle; tamper a byte → `domain
  import` rejects (bad HMAC); a valid import on a fresh boot reconstructs the domain; an
  unsigned/untrusted-publisher template is refused; version rollback works.

---

## Compatibility mapping (the UX/display layer over real enforcement)

- `EPIN_DOMAIN`/`EPIN_DOMAIN_COLOR` (env) ↔ `Task.identityObjId` + `IdentityRec.color`
  (kernel-enforced; the env is the *display* of it; border drawn unspoofably by the
  compositor via `idwin.d`).
- `EPIN_MEM_CAP` (env → `setrlimit`) ↔ `maxStorage`/quota + the cap ceiling (real).
- `EPIN_DISK`/`EPIN_NET`/`EPIN_CLIP`/`EPIN_SECURE_IPC` (prompt-only today) ↔
  `filesystemAccess` bindings / `NetPolicy` / `ClipPolicy` / `IpcPairRule` (real, DM2/DM8).
- The zsh prompt + per-domain `.zsh_history` (`posix.d:4136`) stay as the UX surface, now
  backed by the kernel identity.

## Milestones — Deliverable 17 (prioritized implementation checklist)

Each milestone carries its **P** priority (High → Med → Low) above; this is the prioritized checklist.

- **M-DM0 Domain object.** `/objects/domains/<name>/` is a browsable kernel object tree;
  `domain list` + `/config/domains.json` live. (foundation)
- **M-DM1 Manifest pipeline.** JSON domain manifests compile + apply through the signed TLV
  bridge; escalation rejected at compile.
- **M-DM2 Restricted FS.** ★ Default-deny per-domain view enforced at `namespaceCheckOpen`;
  allowed/deny/mounts/shared honored; `domain fs inspect` shows the RuntimeView. (the critical
  requirement)
- **M-DM3 Real launch.** Apps run *inside* a kernel-enforced identity + restricted namespace
  + clamped cap table — not advisory env.
- **M-DM4 Lifecycle.** Create/Delete/Clone/Rename/Start/Shutdown/Pause/Resume/Reset via verbs
  + the state machine; delete revokes the authority subtree.
- **M-DM5 Persistence.** Domains + per-domain perpetuation (full / home-only / ephemeral)
  survive reboot on the AHCI object store.
- **M-DM6 Templates + overlay.** Immutable templates; writable overlay with snapshot /
  rollback / commit (new version) / discard / promote / diff.
- **M-DM7 Native packages.** Runtime `domain install` of cap-gated, domain-scoped apps.
- **M-DM8 Policy enforcement.** Device/USB/GPU/network/clipboard/IPC/quota gated for real.
- **M-DM9 Inheritance.** Override-only template chains with least-privilege security merge.
- **M-DM10 GUI.** Full live GUI for every operation.
- **M-DM11 Multi-distro.** Per-domain Linux roots + package-manager shims (musl-fit subset).
- **M-DM12 Marketplace.** Signed, versioned, importable/exportable templates without rebuild.

## Order (sequencing + dependency graph) — Deliverable 18 (dependencies between milestones)

```
DM0 ─┬─▶ DM1 ─┬─▶ DM2 ─▶ DM3 ─▶ DM4 ─▶ DM5 ─▶ DM6 ─┬─▶ DM7 ─▶ (feeds DM11)
     │        │                                     ├─▶ DM9
     │        └────────────────────────────────────┘
     └─▶ (DM10 GUI needs DM2+DM4) ; DM8 needs DM3 ; DM11 needs DM6+DM7 ; DM12 needs DM5+DM6
```

| Milestone | Depends on | Priority | Make-or-break? |
|---|---|---|---|
| DM0 Domain object | — | High | foundation |
| DM1 Manifest | DM0 | High | foundation |
| DM2 Restricted FS | DM0, DM1 | High | ★ **critical** — the brief's core requirement |
| DM3 Real launch | DM2 | High | ★ turns cosmetic isolation into real |
| DM4 Lifecycle | DM3 | High | |
| DM5 Persistence | DM1, DM4, OBJECT_FS F4 | High | unlocks templates/marketplace |
| DM6 Templates+overlay | DM5 | Med | the Qubes/Docker/snapshot blend |
| DM7 Native packages | DM3, DM5 | Med | |
| DM8 Policy enforcement | DM3 | Med | |
| DM9 Inheritance | DM1, DM6 | Med | |
| DM10 GUI | DM4, DM2 | Med | |
| DM11 Multi-distro | DM7, DM6 | Low | partly aspirational (glibc) |
| DM12 Marketplace | DM6, DM5 | Low | |

DM0 → DM1 → **DM2** → **DM3** are the critical path (object → manifest → restricted view →
real placement); everything else hangs off them. **DM2 is the make-or-break milestone** — it
is the brief's central "restricted filesystem visibility, capability-mediated, default-deny"
requirement, and DM3 is what makes domain isolation *real* rather than the decorative
`EPIN_*` border it is today.

## Validation + testing strategy (Deliverables 19, 20)

Per-phase validation lives in each phase's *Verify* line; the global strategy, matching the
repo's headless-QEMU / serial / screendump style:

- **Object/FS tests** (DM0–DM2, DM6): drive from the native shell in-VM — `ls`/`cat` over
  `/objects/domains`, `/config/domains.json`, `domain fs inspect`; assert EACCES/ENOENT on
  denied paths; keep the rtfs selftest green (11/11) and `/bin/ls` working as the
  no-regression baseline (the F-roadmap convention).
- **Enforcement tests** (DM2, DM3, DM8): a domain-bound test task that *attempts* forbidden
  reads/devices/sockets and asserts the gate fires, cross-checked against the `core/audit.d`
  ring (`auditLog` entries for each deny). Add a `domainSelfTest`/`domainfsSelfTest` printing
  `PASS` in the reconcile loop (the `identitySelfTest`/`idnsSelfTest` pattern).
- **Persistence tests** (DM5, DM7, DM12): two-boot, same `hos-disk.img` (the F4 method) — the
  on-disk boot counter + a written file proving cross-reboot survival; `persist` modes assert
  full vs home-only vs ephemeral.
- **Lifecycle/inheritance** (DM4, DM9): host-side `anonymos-config` unit checks (schema reject
  on escalation, cycle detect, merge correctness) + in-VM `domain clone/start/snapshot/restore`
  state assertions.
- **GUI tests** (DM10): headless GPU=1 QEMU + QMP rel-event mouse driving (the
  [[window-decorations]] trick) + `screendump` PNGs into `roadmap/assets/dm10-*.png`; assert a
  GUI action reflects in the CLI/`/objects` (e.g. GUI "create" → `domain list` shows it).
- **Security review** (gates DM3, DM6, DM12 — the high-R phases): a `docs/DOMAIN_SECURITY_REVIEW.md`
  pass (the `ZSH_SECURITY_REVIEW.md` precedent) confirming: deny-by-default actually omits the
  `/` binding; launch-into-domain cannot escalate past the ceiling; overlay commit never mutates
  an immutable template; cross-domain shares are attenuation-only + audited; marketplace imports
  are signature- and publisher-verified, fail-closed.
