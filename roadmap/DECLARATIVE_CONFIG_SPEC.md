# Declarative Configuration System — ratified spec (DECLARITIVE_MODEL_ROADMAP.md)

> **Deliverable of the whole of `DECLARITIVE_MODEL_ROADMAP.md`** (all 17 sections): the
> written specification of how anonymOS treats one JSON file as the single
> declarative source of truth for constructing the entire running system state —
> the "NixOS spirit, object-tree body" the roadmap's Goal demands.
>
> **Grounded in the current `src/kernel/d/` tree.** Unlike a green-field design,
> every subsystem this spec has to drive **already exists and is named**: the
> object manager and `ObjType` family (`core/objmgr.d`), the capability lattice
> (`core/cap.d`), identities and the freeze/epoch model (`core/identity.d`), the
> service manager with dependency-ordered start and endpoint brokering
> (`core/servicemgr.d`), Plan-9 namespaces (`core/namespace.d`), the
> content-addressed store + generations + dm-verity (`core/store.d`), A/B update
> + rollback (`core/update.d`), the secure-IPC broker (`core/secipc.d`), and the
> object-reference-graph validator (`core/org_validator.d`). This spec is the
> *compiler* that lowers one JSON document into calls on those APIs.

---

## 0. Framing — what is already in the tree, what is not

The roadmap was written against an early, sparser kernel. Most of what it
assumed was missing is **implemented**. Ground truth today:

| Roadmap claim ("Reality") | Now |
|---|---|
| "no object tree to instantiate" | `core/objmgr.d`: `ObjHeader{id,type,...}`, central `g_objects[8192]`, `objAlloc/objGet/objRetain/objRelease`, 20+ `ObjType` families. |
| "no service manager" | `core/servicemgr.d`: `ServiceRec`, `serviceRegister`, `serviceAddDep`, **`serviceStartAll()`** (dependency-ordered), `serviceBrokerEndpoint` (cap-table brokering), `serviceSetVersion` (pins a `StoreObject`+`Generation`). |
| "no namespaces" | `core/namespace.d`: `NamespaceRec`, `nsAlloc/nsClone/nsBind/nsResolve`, per-process root, `NS_BIND_MAX` mount bindings. |
| "no immutable store / rollback" | `core/store.d` `genCreate/genSetActive/genRollback`; `core/update.d` `slotActive/slotInactive/updateActivateInactive/bootCheckRollback` (A/B + anti-rollback). |
| "no capability system" | `core/cap.d`: 19 rights bits, `capDerive` (subset), `capRevoke` (transitive), per-task `CapTable[64]`, `requireCap`. |
| "no IPC policy" | `core/secipc.d` broker + HMAC-SHA256 session descriptors; `core/idipc.d` `IpcPairRule` deny-by-default table. |

**What is genuinely still missing** (the work this spec directs):

1. A **config compiler** — a component that parses one JSON document,
   validates it, and lowers it into the `objAlloc`/`identityCreate`/
   `serviceRegister`/`nsBind`/`genCreate` calls above. None exists yet; today
   those calls are driven by hand-coded init/boot logic, not by a declared graph.
2. A **trusted-config boot path** — the kernel locating and verifying the JSON
   at boot (§4). The `bundle.d` archive exists; a `.json` member and a measured
   read of it do not.
3. **CLI tools** (`anonymos-config check|build|diff|switch|rollback|graph`, §14).
   The host has `scripts/orgctl`; there is no config-side equivalent.
4. **Generations keyed to *config*** — `core/store.d` generations snapshot the
   *system tree*, not the *config document*. This spec defines the config-side
   generation that selects which system generation to boot.

So this spec is **not** "design capabilities/namespaces/services" — those exist.
It is "design the **declarative compiler** that lowers JSON into the existing
object/cap/identity/service/store APIs," plus the boot + CLI integration that
makes it the source of truth.

### Toolchain reality (why this is a spec, not yet code)

The native userland build path (`src/progs/os/**` Haskell programs via JHC) is
declared **"Legacy: Haskell userspace programs (optional, not part of main
build)"** in the top-level `Makefile`; its include target
`src/progs/build/build-prog.mk` is **absent from the tree**, and the tools
(`jhc`, `ldc2`) are not present on the build host. The running OS image (`cd/`)
is staged with static musl binaries. Consequently a native userland
`anonymos-config` binary **cannot currently be built or tested in this
environment**. This document is therefore the **ratified design**: the artifact
that, once the userland toolchain is restored (or the compiler is written in
musl-C against the same APIs), implements every section below.

---

## 1. Core philosophy  (roadmap §1)

**The JSON file is a declarative system graph, not a runtime config.**

- **Declarative, not imperative.** The document does not say "now mount this,
  now start that." It describes the *desired* object tree, and a compiler
  derives the sequence of `objAlloc`/`serviceRegister`/`nsBind` calls that
  construct it. Construction order is a **compiler output** (the boot plan,
  §4/§6), never hand-written by the user.
- **Differs from traditional runtime config** in three ways:
  1. **Total** — every customizable aspect is present (kernel boot options
     *and* GUI colors *and* IPC policies in one file; §2 lists all 16 sections).
  2. **Derived state** — running state is *computed* from the document, so it
     is reproducible: the same document yields the same system (§17 constraint).
     Runtime-only state is explicitly marked (§10), never silently ad-hoc.
  3. **Validated before apply** — a config that would create a privilege
     escalation, a dependency cycle, or a dangling reference is **rejected at
     compile time**, never half-applied (§12).
- **Resembles NixOS, but object-native.** Where NixOS lowers a configuration
  into a store path + systemd units, anonymOS lowers it into the **live object
  tree**: every service/user/namespace/mount becomes an `ObjType.*` object with
  a stable id, reachable through capabilities, owned by the object graph the
  `org_validator.d` daemon already polices. The "module system" (§11) is the
  NixOS `imports` analogue; the "generation" (§10) is the NixOS generation
  analogue — but realized as a `core/store.d` `Generation` object, not a filesystem path.

---

## 2. JSON schema design  (roadmap §2)

### 2.1 Top-level shape

Every section the roadmap names appears as a top-level key. The schema is
**strict at the top level** (unknown keys are errors) so a typo is caught, but
**free-form where the kernel already accepts free-form data** (the
`objects{}` tree, `kernel.options{}`, `gui.themes{}`, `capabilities{}`).

```
{
  "system":        { … },   // §2 machine identity + generation linkage
  "kernel":        { … },   // §2 enabled features + boot options
  "boot":          { … },   // §4 trusted-config discovery + verification
  "objects":       { … },   // §5 the declarative object tree (free-form, name→node)
  "identities":    [ … ],   // §7 Qubes-style domains
  "namespaces":    [ … ],   // §5/§7 object-tree roots
  "services":      [ … ],   // §6 object-native services
  "processes":     [ … ],   // §6 one-shot tasks
  "capabilities":  { … },   // §8 named capability lattice
  "ipc":           [ … ],   // §9 secure-IPC policy + audit
  "storage":       [ … ],   // §5 object-store / fs mounts
  "networking":    { … },   // §2 network configuration
  "gui":           { … },   // §2 GUI / window identity colors (roadmap §9 topic)
  "compatibility": { … },   // §2 Linux + Windows/ReactOS layers
  "security":      { … },   // §2 profiles + immutable-image
  "logging":       { … },   // §2 logging / auditing
  "snapshots":     [ … ],   // §10 rollback generations
  "distributed":   { … },   // §2 distributed-OS features
  "imports":       [ … ]    // §11 module files (consumed, removed after merge)
}
```

### 2.2 Field → kernel mapping

Each field maps to a concrete kernel struct/function (the right-hand column is
the *call* the compiler emits, not a wishlist):

| Section / field | Lowered to (kernel API) |
|---|---|
| `identities[].name/color/trust/net/clip/gui` | `identityCreate(name,color,trust,ceiling,ns,net,clip,gui)` → `ObjType.Identity`; then `identityFreeze()` after policy load (`core/identity.d`) |
| `identities[].rightsCeiling` | a named entry in `capabilities{}`, materialized via `capDerive` into the identity's ceiling mask |
| `identities[].namespace` | an `ObjType.Namespace` from `namespaces[]`, bound at the identity's process root |
| `identities[].devices` | brokered `ObjType.Admin`/`CAP_RIGHT_ADMIN_DEVICE` caps (§8) |
| `namespaces[].root` (`$name`) | `nsAlloc()` + `nsBind("/", objGet($name))` (`core/namespace.d`) |
| `namespaces[].inherits` | `nsClone(parent)` then overlay binds — Plan-9 per-process mount inheritance |
| `services[].name/executable` | `serviceRegister(name, ownerUserObjId, endpointRights)` → `ObjType.Service` (`core/servicemgr.d`) |
| `services[].depends[]` | `serviceAddDep(svc, dep)` — edges the validator cycle-checks |
| `services[].capabilities[]` | `serviceBrokerEndpoint` into a narrowed cap table; rights ⊆ manager's |
| `services[].identity` | binds the service's Process object under that `ObjType.Identity` |
| `services[].restart` | recorded in `ServiceRec`; honoured by the service supervisor |
| `ipc[].allow[]{from,to,broker}` | `IpcPairRule{from,to,brokerSvcObjId}` rows (`core/idipc.d`) |
| `ipc[].dh` | forces `brokerRequestSession` (DH) for that pair (`core/secipc.d`) |
| `ipc[].keyBroker` | the service holding the broker signing key (`g_brokerKey`) |
| `storage[].kind=immutable, generation` | `genSetActive(genObjId)` + `storeMountSystem` (`core/store.d`) |
| `storage[].kind=object-store` | `storePut`/`storeGet` content-addressed objects |
| `capabilities.{name}.rights/inherits` | `capDerive(parent, subset)` — **subset checked at compile time** (§8) |
| `snapshots[].base` | `genCreate(base)` chain; `genRollback()` on rollback |
| `system.generation` | selects `slotActive()` generation at boot (`core/update.d`) |
| `boot.configPath/signature` | the trusted read + HMAC verify path (§4) |
| `security.rootless=false` | emits a **compile warning** (violates §17 constraint); does not silently escalate |
| `kernel.features[]` | compile-time flags (require a matching `kernel.elf`); reboot-class |

### 2.3 Realistic example document

```json
{
  "system":  { "name": "thinkpad-x1", "hostname": "anon", "generation": 3 },
  "kernel":  { "features": ["smp", "wayland", "linux-compat"],
               "options": { "console": "serial0", "mem": "2048M" } },
  "boot":    { "configPath": "/system.json", "measured": true,
               "signature": "hmac-sha256:9f3a…" },
  "security":{ "rootless": true, "immutableImage": true,
               "profiles": ["default-deny-net"] },
  "objects": {
    "root":     { "_type": "Directory", "source": "bundle:/" },
    "usr":      { "_type": "Directory", "source": "store:/usr@gen3" },
    "var":      { "_type": "Directory", "source": "store:/var", "writable": true }
  },
  "capabilities": {
    "fs-ro":   { "rights": ["read","stat"] },
    "fs-rw":   { "inherits": "fs-ro", "rights": ["write"] },
    "net-out": { "rights": ["call"] },
    "admin":   { "inherits": "net-out", "rights": ["admin_reboot"] }
  },
  "identities": [
    { "name": "System",   "color": "#2A2A2A", "trust": "system",
      "rightsCeiling": "admin",   "namespace": "system-ns", "net": "none" },
    { "name": "Personal", "color": "#3478F6", "trust": "personal",
      "rightsCeiling": "fs-rw",   "namespace": "user-ns",   "net": "nat",
      "clip": "same" },
    { "name": "Banking",  "color": "#E02020", "trust": "banking",
      "rightsCeiling": "fs-ro",   "namespace": "bank-ns",   "net": "vpn",
      "clip": "deny", "gui": ["borderAlways","noScreenshotAcrossId"] }
  ],
  "namespaces": [
    { "name": "system-ns", "root": "$root", "isolated": true },
    { "name": "user-ns",   "root": "$root", "inherits": "system-ns" },
    { "name": "bank-ns",   "root": "$root", "isolated": true }
  ],
  "services": [
    { "name": "init",        "executable": "/init",        "identity": "System",
      "capabilities": ["admin"], "restart": "never" },
    { "name": "net-broker",  "executable": "/sbin/netd",   "identity": "System",
      "capabilities": ["net-out"], "depends": ["init"] },
    { "name": "ipc-broker",  "executable": "/sbin/ipcd",   "identity": "System",
      "capabilities": ["call"],    "depends": ["init"], "ipc": "secure" }
  ],
  "ipc": [
    { "name": "secure", "dh": true, "keyBroker": "ipc-broker", "audit": true,
      "allow": [ { "from": "Personal", "to": "System", "broker": "ipc-broker" } ] }
  ],
  "storage": [
    { "name": "system-base", "kind": "immutable", "generation": "gen3", "readOnly": true },
    { "name": "user-state",  "kind": "object-store", "source": "/var", "readOnly": false }
  ],
  "snapshots": [ { "name": "gen3", "base": "gen2", "auto": true } ],
  "gui":      { "compositor": "mutter", "borderPolicy": "always",
                "defaultColor": "#2A2A2A" },
  "compatibility": { "linux":   { "enabled": true,  "personality": "x86_64" },
                     "windows": { "enabled": false, "backend": "wine" } },
  "logging":  { "level": "info", "audit": true, "sink": "/var/log/audit" },
  "networking":{ "hostname": "anon", "dns": ["10.0.0.1"],
                 "interfaces": [ { "name": "eth0", "dhcp": true } ] },
  "distributed": { "enabled": false }
}
```

---

## 3. Config compiler  (roadmap §3)

The compiler is a **pure function** `compile : JSON → CompiledGraph ⊎ [Error]`.
It has no side effects; applying the graph to the kernel is a separate step
(§4 boot integration / §14 `switch`). Seven stages, each able to emit errors;
**all** errors are collected and reported in one pass (§12 "fail once"):

### Stage 1 — parse
JSON decode. Malformed JSON is a single fatal error with the byte offset.

### Stage 2 — schema-validate (structural)
Walk the document against §2's schema. Type mismatches, bad enums, malformed
`#RRGGBB` colors, unknown top-level keys, missing required fields. Implemented
as a recursive checker over the schema tree (no third-party dependency; the
schema carries richer `kind`/`ref` annotations than stock JSON-Schema).

### Stage 3 — normalize + resolve imports (§11)
Apply defaults; deep-merge the `imports[]` list left-to-right (later imports
win on scalar conflict; arrays of `{name}`-keyed objects merge by name; the
file's own body wins over its imports). Detect **import cycles** (a module
importing itself transitively) by tracking the resolution stack.

### Stage 4 — resolve references
Build name tables per section (`identities`, `namespaces`, `services`, `ipc`,
`storage`, `snapshots`, `capabilities`, plus the free-form `objects{}`). Walk
every `ref`-annotated field and every `$name` object-reference and confirm the
target exists. Dangling references are reported with the exact path
(`services[2].depends[0]`).

### Stage 5 — assign stable object IDs
Assign a deterministic, dense logical id to every declared object so that
**two compiles of the same input produce byte-identical ids** (§17
reproducibility). Assignment order is fixed:
`system → objects → namespaces → identities → services → processes →
ipc → storage → snapshots → capabilities`. These logical ids are *not* kernel
`objId`s; the boot loader maps logical→`objAlloc` at apply time.

### Stage 6 — detect cycles  (§3 "circular dependency detection")
3-color DFS (WHITE/GRAY/BLACK) over three independent edge sets, pinpointing
the closing edge rather than just reporting "a cycle exists":

- **service dependencies** — `depends[]` ∪ `after[]` (roadmap §6 startup order);
- **namespace inheritance** — `inherits` chains (§5);
- **snapshot base** — `base` chains (§10);
- **capability inheritance** — `inherits` chains (§8).

A GRAY back-edge → `service dependency cycle: netd -> ipcd -> netd`.

### Stage 7 — check capabilities  (§8 "reject unsafe privilege escalation")
Resolve the capability lattice. For each `capabilities.{name}`:
- `inherits` must name an existing capability (and not form a cycle — Stage 6);
- the child's rights mask must be a **bitwise subset** of the parent's
  (`own & ~parent == 0`). This is exactly the kernel's `capDerive`
  subset-narrowing rule (`core/cap.d`), enforced **at compile time** so the
  kernel never receives an escalation request. A violation names the excess
  rights and is rejected: *"rights [admin_reboot] exceed inherited parent
  'net-out' (privilege escalation rejected, §8)"*.
- `identities[].rightsCeiling` and `services[].capabilities[]` must reference
  declared capabilities; a service's held rights must be ⊆ its identity's
  ceiling (no identity can hold more than its declared ceiling — §8 "reducible
  by child objects").

### Stage 8 — lower to graph
Materialize the `CompiledGraph`: object list (with stable ids), the **boot
plan** (§4), the **service graph** + topological **startup order** (§6), the
**capability manifest** (rights masks + derivation parents), the materialized
**IPC rules** (`IpcPairRule` rows), the identity/namespace tables, and a
per-section **live-vs-reboot classification** (§13). Emit a stable
`configHash = sha256(canonical_json)` so a generation can be content-addressed.

### Compiler data structures

```
CompiledGraph {
  objects:          [ ObjectNode{ id, name, kind, obj_type, payload, source } ]
  boot_plan:        [ {phase, kind, …} ]            // §4
  service_graph:    { svc → [deps] }                // §6
  startup_order:    [ svc ]                         // topological, deterministic
  capability_manifest:{ name → {mask, parent, bits} }
  ipc_rules:        [ {policy, from, to, broker, dh, audit} ]  // §9
  identity_table:   { name → IdentityRec-fields }
  namespace_table:  { name → NamespaceRec-fields }
  config_hash:      sha256(canonical)[:16]
  live_reconfig:    { section → "live"|"reboot" }   // §13
  warnings:         [ str ]                         // e.g. rootless=false
}
```

---

## 4. Boot integration  (roadmap §4)

**Locate + verify (kernel-side, trusted subset):**
1. The D bootstrap (`core/kmain.d`) already unpacks the Limine boot module
   archive (`core/bundle.d`: `initBundle(base,size)`, linear file lookup). The
   config is a **named member** of that bundle — `boot.configPath`, default
   `/system.json` — read via the same trusted path that already delivers
   `init.elf`. No new trust channel is invented.
2. **Minimal trusted subset first.** Early boot reads only `boot` + `system` +
   `kernel`: enough to select the generation (`system.generation` →
   `slotActive()`), pick the kernel features, and verify the signature. This is
   the "minimal trusted subset" the roadmap asks for; it runs before any
   user-space object exists.
3. **Verification.** `boot.signature` is an HMAC-SHA-256 over the canonical
   JSON, verified with the same kernel-held trusted-key seam
   `core/update.d` already uses for update bundles (`updateApply` requires a
   valid HMAC before any write). A mismatch is a hard boot failure (§12 safe
   failure: fall back to the previous known-good slot via
   `bootCheckRollback()`). `boot.measured` extends the measurement into the
   boot-success counter that guards auto-rollback.

**Kernel vs user-space split:**

| Done by the **kernel** (trusted, early) | Done by **user-space init** (object tree) |
|---|---|
| read bundle member `/system.json` | parse + schema-validate the full document (Stage 1–2) |
| verify HMAC signature | resolve references + imports (Stage 3–4) |
| select generation `slotActive()` | assign object ids + build boot plan (Stage 5–8) |
| measure + arm auto-rollback | `objAlloc` every declared object (§5) |
| hand the verified JSON to PID1 | `identityCreate` … `identityFreeze()` (§7) |
| | `nsAlloc/nsBind` (§5) |
| | `serviceRegister`/`serviceAddDep`/`serviceStartAll()` (§6) |
| | install `IpcPairRule` rows (§9) |

The split honours the roadmap's constraint (§17): *the kernel stays minimal and
immutable*; *most policy lives outside the kernel*. The kernel only does the
**trusted** parts (find, verify, select generation, measure); everything else
is the user-space compiler driving existing kernel APIs.

---

## 5. Declarative object tree  (roadmap §5)

**Every declared entity becomes one `ObjType.*` object.** The compiler emits,
per object, a logical-id → `objAlloc(type, impl)` mapping the loader runs:

| Declaration | `ObjType` |
|---|---|
| `services[]` entry | `Service` |
| `processes[]` entry | `Process` |
| `identities[]` entry | `Identity` |
| `namespaces[]` entry | `Namespace` |
| `ipc[]` entry | `Endpoint` |
| `storage[]` mount | `File` / `Directory` |
| `snapshots[]` entry | `Generation` |
| `capabilities{}` entry | `Capability` (one per live handle) |
| `objects{}` entry | its declared `_type` (default `Directory`) |

**Parent/child inheritance rules (§5):**
- A service's Process object is a child of its `identity`'s domain; its cap
  table is `capDerive`d from the identity's ceiling → **rights can only
  narrow, never widen** (§8).
- A namespace with `inherits` is `nsClone(parent)` then overlay-binds the
  child's own mounts — Plan-9 per-process mount inheritance, already
  implemented by `nsClone`.
- A process spawned by a service inherits the service's identity and a
  *subset* of its cap table (fork-narrowing already exists in `core/cap.d`).
- A `Generation` snapshot with `base` is `genCreate(base)` — a content-addressed
  child of the base generation; rollback walks the chain.

The object graph so produced is exactly the graph `core/org_validator.d`
already polices (edge kinds, SCCs, ownership roots), so the declarative tree
inherits ORG's invariant checks for free.

---

## 6. Declarative services  (roadmap §6)

`servicemgr.d` is the object-native service manager (the roadmap's "like
systemmd/NixOS modules but object-native"). Each `services[]` entry maps:

```
serviceRegister(name, ownerUserObjId, endpointRights)   // → ObjType.Service
serviceAddDep(svc, dep)                                 // for each depends[]
serviceBrokerEndpoint(tableId, svc, handle, rights)     // for each capability[]
serviceSetVersion(svc, storeObjId, genObjId)            // §10 version pinning
serviceStartAll()                                        // dependency-ordered start
```

**Service fields** (all present in `ServiceRec` or its payload):

| Field | Meaning | Restart/live class |
|---|---|---|
| `name` | unique service name (`SVC_NAME_MAX`) | — |
| `executable` | path in the bundle/store | reboot if the binary hash changes |
| `identity` | the `ObjType.Identity` it runs under | reboot (security boundary) |
| `namespace` | its `ObjType.Namespace` root | reboot (mount topology) |
| `capabilities[]` | endpoint + narrowed cap table | live (re-broker) |
| `depends[]` | hard ordering edges (`serviceAddDep`) | live |
| `after[]` | weak ordering hint (non-dependency) | live |
| `restart` | `always` / `on-failure` / `never` | **live** (§13 example) |
| `ipc` | the IPC policy governing it | live |
| `mounts[]` | object-store binds into its namespace | reboot (mount) |

**Startup ordering + dependency resolution (§6):** Kahn's topological sort over
the `depends`∪`after` graph, with **declaration order as the deterministic
tie-break** so two compiles yield the same order. Cycles are caught in Stage 6.
`serviceStartAll()` already consumes such an order; the compiler's job is to
produce the edge set (`serviceAddDep`) and the ordered list it is started in.

---

## 7. Declarative identity and namespace system  (roadmap §7)

Identities are **Qubes-style security domains inside anonymOS**, realized as
`ObjType.Identity` records in `core/identity.d`:

```
identityCreate(name, color, trust, rightsCeiling, nsTemplate, net, clip, gui)
… install IpcPairRule / ShareRule rows …
identityFreeze()        // registry becomes immutable after policy load (g_idFrozen)
```

Each `identities[]` entry declares:

- **GUI border color** (`color`, `#RRGGBB`) → `IdentityColor` field; the trusted
  compositor draws it (`core/idwin.d` / `core/window.d`). The roadmap's "GUI
  border colors per identity" and "different subsystems have colored borders"
  (README) are this field.
- **Per-identity filesystem view** (`namespace`) → a private `ObjType.Namespace`
  root; the identity sees exactly the objects bound into it (Plan-9 model).
- **Network policy** (`net`: none/nat/vpn/tor/localonly/disposable) →
  `NetPolicy` enum; brokered by the net service, never ambient.
- **Process permissions** (`rightsCeiling`) → the max rights any process in this
  identity may hold; enforced by `capDerive` narrowing at fork/exec.
- **Clipboard rules** (`clip`: deny/ask/same/down) → `ClipPolicy` enum; "down"
  flows only toward lower trust.
- **IPC permissions** → deny-by-default `IpcPairRule` rows; only declared pairs
  may talk (§9).
- **Devices** (`devices[]`) → brokered `ObjType.Admin`/`ADMIN_DEVICE` caps; a
  process never gets ambient device access.
- **Trust level** (`trust`) → a *flow hint* only (e.g. clipboard down-trust),
  never an ambient authority check (the module comment is explicit: trust is
  not authority).
- **Disposable** (`disposable: true`) → §8 throwaway domain, cloned from a
  `templateId`, destroyed on close.

`identityFreeze()` is the single point that makes the registry immutable after
policy load — the declarative "source of truth" guarantee: nothing in user
space can mutate identities after the compiled config is applied, except via a
signed policy transaction (`policyEpoch`, §9/§13 live reconfig).

---

## 8. Declarative capability security  (roadmap §8)

**Permissions are capabilities, never ambient root.** The lattice is
`core/cap.d`'s 19 rights bits under bitwise-AND (meet). The compiler:

1. **Declares** named capabilities in `capabilities{}` with `rights` (a name,
   list, or `"all"`) and optional `inherits` (a parent name).
2. **Checks subset at compile time** (Stage 7): a child's mask must be ⊆ its
   parent's — the `capDerive` invariant. Privilege escalation is rejected
   *before* the kernel ever sees it.
3. **Grants** them by `capDerive` into per-process cap tables; a service's
   table is a subset of the manager's (`servicemgr.d` invariant
   `serviceRightsInvariant()`).
4. **Ceilings**: `identities[].rightsCeiling` bounds every process in that
   identity; a service holding rights beyond its identity's ceiling is a
   compile error.
5. **No ambient root**: the default task identity is uid/gid 1000 (non-root);
  PID1 holds only explicit admin caps (`ObjType.Admin`, one right per action:
  `ADMIN_MOUNT/REBOOT/UPDATE/USER/DEVICE/INSPECT/IDENTITY`). This is already
  true in the tree; the config simply *declares* which admin caps each service
  holds, rather than leaving it implicit.

**Inheritance rules (§8):** capabilities are *explicit*, *inherited only when
`inherits` names a parent*, and *reducible by child objects* (subset meet).
Revocation is transitive (`capRevoke` walks the derive-DAG) — the compiler does
not need to model this, but the declared graph must be acyclic so the derive-DAG
is well-defined (Stage 6).

---

## 9. Declarative IPC security  (roadmap §9)

Lowered into the secure-IPC broker (`core/secipc.d`) + the identity IPC table
(`core/idipc.d`):

- **Who may talk to whom** — `ipc[].allow[]{from,to}` installs deny-by-default
  `IpcPairRule{from,to,brokerSvcObjId}` rows. An undeclared pair is refused by
  `secipcKernelRoute` (the kernel routing gate is key-free and parses no
  descriptor — invariant K1).
- **Diffie-Hellman required** — `ipc[].dh: true` forces `brokerRequestSession`
  to perform DH session setup; the broker returns a **broker-signed
  `SessionDescriptor`** binding {A,B,channelCap,suite,policy,epoch,notAfter}
  (`core/secipc.d`).
- **Key broker** — `ipc[].keyBroker` names the service holding the broker
  signing key (`g_brokerKey`); it delegates keys, never exposes them.
- **Audit** — `ipc[].audit: true` routes every allowed exchange through
  `core/audit.d` (`auditLog`, `AuditKind`), the same log the ORG validator
  writes to.

The compiler materializes one `IpcPairRule` per allowed pair and records the
`dh`/`broker`/`audit` flags the broker consults at runtime.

---

## 10. Immutable system and rollback  (roadmap §10)

A config change creates a **new generation**; previous generations remain
bootable; the kernel + core system are immutable; runtime state is separated.

- **New generation per change.** Compiling a config produces a `configHash`;
  the host CLI (`build`, §14) writes a new `core/store.d` `Generation` whose
  content is the canonical JSON. The generation is content-addressed, so an
  identical config dedups to the same generation (`storePut` dedup semantics).
- **Previous generations stay bootable.** `genCreate`/`genSetActive` never
  delete; `core/update.d`'s A/B slots (`slotActive`/`slotInactive`) keep the
  previous generation as the known-good fallback. `bootCheckRollback()`
  auto-reverts after N failed boots.
- **Kernel + core immutable.** `/usr` is mounted read-only via
  `storeMountSystem` (§4.3 of the immutable roadmap); a write to it is
  impossible (not discouraged). Only `/etc` (overlay) and `/var` (user state)
  are writable, and only behind a rights gate (`storeWritable`).
- **Runtime vs declared state separated.** Declared state = the JSON + the
  generation it produces. Runtime state = `/var` + per-process mutable state,
  snapshotted independently (`update.d` §6.5: rolling back the OS never rolls
  back user data). The config explicitly marks the few runtime-only fields.
- **Rollback strategy.** `anonymos-config rollback` (§14) calls
  `genRollback()` → points the active slot at the parent generation, atomically;
  the next boot loads it. No state is mutated destructively.

---

## 11. Module system  (roadmap §11)

Avoid one giant file. `imports[]` lists module files (`base.json`,
`hardware.json`, `identities.json`, `services.json`, `gui.json`, …) resolved
recursively in Stage 3:

- **Deep merge, left-to-right**, later imports win on scalar conflict.
- **Arrays of `{name}` objects merge by name** (two modules can each
  contribute services without clobbering); other arrays concatenate.
- **`imports` is consumed and removed** from the merged output.
- **Cycles detected** (a module importing itself transitively) via the
  resolution stack.
- **The final build still compiles into one canonical resolved JSON graph**
  (roadmap requirement): merging produces a single document, which is then
  hashed and stored as one generation (§10).

---

## 12. Validation and safety  (roadmap §12)

Checks that **must** run before applying config (all but #1 are the compiler's
Stages 4–7):

1. **Schema validation** — Stage 2 (types, enums, colors, required fields).
2. **Object reference validation** — Stage 4 (every `ref` and `$name` resolves).
3. **Dependency cycle detection** — Stage 6 (services, namespaces, snapshots,
   capabilities).
4. **Privilege escalation detection** — Stage 7 (cap rights ⊆ parent; service
   rights ⊆ identity ceiling).
5. **Invalid IPC rule detection** — Stage 4 (`from`/`to` identities exist,
   `keyBroker` service exists) + a broker check that a declared pair does not
   contradict deny-by-default ordering.
6. **Namespace isolation checks** — a namespace marked `isolated` must not
   inherit from a lower-isolation namespace; an identity's namespace must not
   bind objects outside its declared object root.
7. **Service boot ordering checks** — Stage 8: the topological sort must cover
   every service (an unsatisfiable order ⇒ a cycle was missed — defensive).

**Safe failure behavior (§12):** a rejected config is **never partially
applied**. The compiler is pure; *applying* is the separate `switch` step
(§14), which runs inside a generation: the new generation is built and
verified first; only a fully-verified generation is `genSetActive`'d. A failed
apply leaves the running system on its previous generation untouched. Boot-time
failure triggers A/B auto-rollback (`bootCheckRollback`).

---

## 13. Live reconfiguration  (roadmap §13)

The compiler classifies each section **live** vs **reboot** (Stage 8's
`live_reconfig` table). Classification is conservative (unknown → reboot):

| Setting | Class | Why |
|---|---|---|
| GUI color / border policy | **live** | `IdentityColor` is compositor-drawn; bump `policyEpoch` |
| service `restart` policy | **live** | supervisor field, no boot impact |
| add/remove a service | **live** | `serviceRegister`/`serviceStartAll` are runtime ops |
| `ipc` allow rules | **live** | install/withdraw `IpcPairRule` rows |
| `logging` level/sink | **live** | runtime |
| `kernel.features` / `kernel.options` | **reboot** | compiled into `kernel.elf` |
| **kernel memory layout** (`mem`/address-space) | **reboot** | baked into the active `kernel.elf` + generation; matches the roadmap §13 example |
| `boot.*` | **reboot** | trusted boot path |
| `system.generation` / immutable image | **reboot** | selects the boot generation |
| namespace mount topology | **reboot** | mount semantics |
| `compatibility` layer enable | **reboot** | process-tree restructure |

**Transaction/rollback for live changes:** a live change is staged as a *new
generation*; if applying it (e.g. starting a new service) fails, the supervisor
falls back to the prior generation's service set without rebooting. Identity
mutations require a **signed policy transaction** that bumps `policyEpoch`
(`identityFreeze` prevents unsigned mutation), so live identity reconfig is
auditable and reversible.

---

## 14. CLI tools  (roadmap §14)

`anonymos-config` — the host + guest CLI that drives the compiler + generations.
(Subcommands map 1:1 to the roadmap's list.)

| Command | Does |
|---|---|
| `check system.json` | parse + validate (Stages 1–7); print all errors; exit non-zero if any. Pure, no writes. |
| `build system.json` | `check` then write a new **generation** (§10): canonical JSON + compiled manifest, content-addressed by `configHash`. Does not switch. |
| `diff old.json new.json` | compile both, print structured changes per section, and label each changed section **live**/**reboot** (§13) so the user knows if a switch needs a reboot. |
| `switch system.json` | `build` then atomically `genSetActive` the new generation; live sections applied now, reboot sections armed for next boot. |
| `rollback` | `genRollback()` → point active slot at parent generation; reboot to load it. |
| `graph system.json` | emit the compiled object graph as Graphviz DOT (nodes = `ObjType` objects with stable ids, edges = depends/inherits/cap-derive/ipc-allow), reusing the `scripts/orgctl` rendering conventions. |

The CLI is the *only* intended mutation path for system state, so the system
state is always derivable from a generation in the store (§17 "avoid ad-hoc
runtime configuration").

---

## 15–16. Implementation phases + per-phase deliverables  (roadmap §15, §16)

The roadmap's 12 phases map onto the compiler's stages + the integration work.
For each: **goal / files affected / data structures / APIs / tests / failure
cases.**

### Phase 1 — JSON parser + schema validator  (Stages 1–2)
- **Goal:** parse + structurally validate any document against §2.
- **Files (new):** `anonymos-config/{schema,validator}.«lang»`, plus the
  schema data + `export_json_schema` (for editor autocomplete).
- **Data structures:** schema tree (`type/props/items/enum/kind/ref/required`);
  `ValidationError{path,msg}`.
- **APIs:** `parse(text)→doc`, `validate(doc)→[ValidationError]`.
- **Tests:** every section present/absent; bad enum; bad color; unknown key;
  wrong type; collect-multiple-errors-in-one-pass.
- **Failure cases:** malformed JSON (byte offset); non-object top level;
  truncation.

### Phase 2 — internal object graph  (Stage 5)
- **Goal:** represent every declared entity as an `ObjectNode` with a stable id.
- **Files:** `compiler.«lang»` (`ObjectNode`, id-assignment).
- **Data structures:** `ObjectNode{id,name,kind,obj_type,payload,source}`;
  `OBJ_KIND_TO_TYPE` map to `ObjType` names.
- **APIs:** `assign_ids(doc)→{ (kind,name)→ObjectNode }`.
- **Tests:** deterministic ids across runs; id uniqueness; all 9 kinds emitted.
- **Failure cases:** duplicate names within a section.

### Phase 3 — config compiler  (Stages 3–4, 6–7)
- **Goal:** imports, reference resolution, cycle detection, capability checks.
- **Files:** `compiler.«lang»`, `modules.«lang»`.
- **Data structures:** name tables; 3-color DFS state; cap-lattice resolver.
- **APIs:** `load_with_imports(path)`, `resolve_refs`, `resolve_objrefs`,
  `detect_cycles`, `check_capabilities`.
- **Tests:** dangling ref (per ref-kind); service cycle; namespace-inherits
  cycle; snapshot-base cycle; cap-inherits cycle; cap subset violation; cap
  escalation beyond ceiling; import cycle; import merge precedence.
- **Failure cases:** missing import file; circular import; scalar-vs-object
  merge conflict (right-wins, documented).

### Phase 4 — declarative service manager lowering  (Stage 8 + §6)
- **Goal:** produce service graph + topological startup order; map to
  `serviceRegister`/`serviceAddDep`/`serviceStartAll`.
- **Files:** `compiler.«lang»` (`build_service_graph`, `build_boot_plan`).
- **Data structures:** `service_graph`, `startup_order`, `boot_plan`.
- **APIs:** `build_service_graph(doc)→(graph,order)`, `build_boot_plan`.
- **Tests:** diamond dependency; `after`-only hint doesn't impose hard dep;
  tie-break by declaration order; unsatisfiable order detected.
- **Failure cases:** self-dependency; depends-on-unknown (caught in Stage 4).

### Phase 5 — identity + namespace declaration  (§7 + Stage 4/8)
- **Goal:** lower `identities[]`/`namespaces[]` into `identityCreate`/`nsAlloc`.
- **Files:** `compiler.«lang»` (identity/namespace table builders).
- **Data structures:** `identity_table`, `namespace_table` mirroring
  `IdentityRec`/`NamespaceRec`.
- **APIs:** `build_identity_table`, `build_namespace_table`; map to
  `identityCreate(...)`/`identityFreeze()` and `nsAlloc/nsClone/nsBind`.
- **Tests:** per-identity net/clip/gui enum mapping; namespace inheritance
  clone; isolated-namespace isolation check; freeze-immutability invariant.
- **Failure cases:** color not `#RRGGBB`; namespace inherits unknown;
  identity ceiling references unknown cap.

### Phase 6 — declarative capability system  (§8 + Stage 7)
- **Goal:** compile-time capability lattice with subset enforcement.
- **Files:** `compiler.«lang»` (`check_capabilities`, cap-manifest).
- **Data structures:** `capability_manifest{name→{mask,parent,bits}}`;
  `CAP_RIGHTS` map mirroring `core/cap.d`.
- **APIs:** `check_capabilities(doc)→(manifest, errors)`; map to
  `capDerive(parent, subset)`.
- **Tests:** `"all"` expands to universe; subset child accepted; superset child
  rejected with named excess rights; service rights ⊆ identity ceiling.
- **Failure cases:** inherits unknown cap; inherits cycle; ceiling cap missing.

### Phase 7 — secure IPC policy integration  (§9 + Stage 8)
- **Goal:** materialize `IpcPairRule` rows + DH/broker/audit flags.
- **Files:** `compiler.«lang»` (`build_ipc_rules`).
- **Data structures:** `ipc_rules[]{policy,from,to,broker,dh,audit}`.
- **APIs:** `build_ipc_rules(doc)→[rule]`; map to `IpcPairRule` install +
  `brokerRequestSession` (when `dh`).
- **Tests:** allow-pair with unknown from/to rejected; `dh` flagged;
  `keyBroker` resolves; audit default true.
- **Failure cases:** allow references unknown identity; keyBroker unknown
  service.

### Phase 8 — immutable generations + rollback  (§10 + §14 build/switch/rollback)
- **Goal:** generation store keyed by `configHash`; atomic set-active + rollback.
- **Files:** `generations.«lang»`; maps to `genCreate`/`genSetActive`/
  `genRollback` + `slotActive`/`bootCheckRollback`.
- **Data structures:** `GenerationMeta{id,created,parent,config_hash,live}`;
  store layout (`gens/<id>/{system.json,manifest.json,meta.json}`, `current`
  symlink, `journal.log`).
- **APIs:** `build`, `switch(gid)`, `rollback`, `list_generations`,
  `diff_generations(a,b)`.
- **Tests:** build dedups identical config; switch updates `current`; rollback
  follows `parent`; diff between two generations.
- **Failure cases:** switch to missing gen; rollback with no parent; corrupt
  meta.json.

### Phase 9 — GUI identity colors  (§7 `color` + §13 live)
- **Goal:** declare per-identity border colors; live-reconfigurable.
- **Files:** schema `identities[].color` + `gui.{defaultColor,borderPolicy}`;
  maps to `IdentityColor` + compositor draw path.
- **Data structures:** `IdentityColor` (packed `0xAARRGGBB`); `GuiPolicy` flags.
- **APIs:** color parse/validate (Stage 2); live apply via `policyEpoch` bump.
- **Tests:** `#RRGGBB` and `#AARRGGBB` accepted; bad hex rejected; color change
  classified **live**.
- **Failure cases:** malformed color string.

### Phase 10 — module/import system  (§11 + Stage 3)
- **Goal:** multi-file configs merging into one canonical graph.
- **Files:** `modules.«lang»`.
- **Data structures:** merge rules (object∪object, name-keyed array merge,
  scalar right-wins).
- **APIs:** `load_with_imports(path)`.
- **Tests:** base+hardware+identities merge; name-keyed array merge; scalar
  override; import cycle rejected; relative-path resolution.
- **Failure cases:** missing import; invalid JSON in import; top-level non-object.

### Phase 11 — live reconfiguration  (§13 + Stage 8)
- **Goal:** classify sections live/reboot; transactional apply.
- **Files:** `compiler.«lang»` (`classify_live`); `switch` applies live sections
  immediately.
- **Data structures:** `live_reconfig{section→"live"|"reboot"}`.
- **APIs:** `classify_live(doc)`; `switch` honours the classification.
- **Tests:** GUI=live, kernel=reboot, generation=reboot, ipc=live; live-failure
  falls back without reboot; identity mutation requires signed txn.
- **Failure cases:** applying a reboot-class change without reboot (must arm,
  not apply).

### Phase 12 — full system validation + testing  (§12 + integration)
- **Goal:** end-to-end: example `system.json` compiles, builds a generation,
  switches, rolls back, and the object graph validates under `org_validator`.
- **Files:** `tests/`, example configs, CLI wiring, `anonymos-config graph` DOT.
- **Data structures:** the integration harness reuses `CompiledGraph` and
  `GenerationMeta` unchanged; adds an end-to-end `SwitchResult{gen, live_applied,
  armed_for_reboot, errors}` record capturing what `switch` applied live vs
  deferred to next boot, plus a DOT `GraphDoc{nodes,edges}` for `graph`.
- **APIs:** `run_pipeline(path)→(CompiledGraph,[ValidationError])` (the full
  Stage 1–8 chain), `graph_to_dot(CompiledGraph)→DOT`, and
  `end_to_end_check(path)→SwitchResult` tying `check`→`build`→`switch`→`rollback`
  together so one call exercises every §12 check and the rollback path.
- **Tests:** the §2.3 example compiles clean; each Phase 1–11 test suite; a
  deliberately-broken config is rejected with the right error; the DOT graph
  renders; diff between two example configs labels sections correctly.
- **Failure cases:** rejected config never partially applied; corrupt generation
  rejected at switch; boot-time failure auto-rolls back.

---

## 17. Constraints  (roadmap §17)

| Constraint | How this spec honours it |
|---|---|
| **Stay rootless** | default task = uid 1000; PID1 holds only explicit `ObjType.Admin` caps; `security.rootless=false` is a compile warning. §8. |
| **Kernel minimal + immutable** | kernel only does trusted find/verify/select-generation/measure; all policy is user-space compiler → existing kernel APIs. §4 split table. |
| **Most policy outside the kernel** | the compiler + CLI + generations are all user-space; the kernel sees only verified JSON + `objAlloc` calls. |
| **Auditable + reproducible** | stable object ids; `configHash`; append-only `journal.log`; content-addressed generations; `graph` emits the full object graph. §3 Stage 5, §10. |
| **No hidden mutable global state** | system state is derived from a generation in the store; runtime state explicitly marked and isolated in `/var`. §10. |
| **No ad-hoc runtime config** | the CLI is the only mutation path; every change is a new generation. §14. |
| **State derived from config unless marked runtime** | declared state = JSON+generation; runtime state = `/var`/per-process, snapshotted independently. §10. |

---

## Appendix A — Object-kind → kernel ObjType table

| config kind | `ObjType` | kernel module |
|---|---|---|
| service | `Service` | `core/servicemgr.d` |
| process | `Process` | `core/task.d` |
| identity | `Identity` | `core/identity.d` |
| namespace | `Namespace` | `core/namespace.d` |
| endpoint (ipc) | `Endpoint` | `core/secipc.d` |
| storage (immutable) | `Generation` | `core/store.d` |
| storage (object-store) | `StoreObject` | `core/objstore.d` |
| directory | `Directory` | `core/objmgr.d` |
| capability | `Capability` | `core/cap.d` |
| snapshot | `Generation` | `core/store.d` |

## Appendix B — Capability rights → `CAP_RIGHT_*`  (`core/cap.d`)

`read,write,close,stat,ioctl,mmap,dup,pass,retype,call,
admin_mount,admin_reboot,admin_update,admin_user,admin_device,admin_inspect,
exec,admin_identity,id_share` — all 19 bits; `"all"` expands to the fd-surface
universe (`CAP_RIGHT_ALL`), **not** a god-right (admin rights are separate,
typed `ObjType.Admin` caps).

## Appendix C — Section coverage map (audit)

Every numbered section of `DECLARITIVE_MODEL_ROADMAP.md` is addressed:

| Roadmap § | This spec § |
|---|---|
| 1 Core Philosophy | §1 |
| 2 JSON Schema Design | §2 (incl. realistic example §2.3) |
| 3 Config Compiler | §3 (8 stages, cycle detection §3 Stage 6) |
| 4 Boot Integration | §4 (locate/verify, minimal subset, kernel/userspace split) |
| 5 Declarative Object Tree | §5 (every entity → ObjType; inheritance) |
| 6 Declarative Services | §6 (fields, startup ordering) |
| 7 Identity + Namespace | §7 (colors, fs view, net, clip, perms, ipc) |
| 8 Capability Security | §8 (subset, no ambient root, escalation rejection) |
| 9 IPC Security | §9 (who-talks-to-whom, DH, broker, audit) |
| 10 Immutable + Rollback | §10 (generations, immutability, runtime split, rollback) |
| 11 Module System | §11 (imports, merge, one canonical graph) |
| 12 Validation + Safety | §12 (7 checks, safe failure) |
| 13 Live Reconfiguration | §13 (live/reboot table, transactions) |
| 14 CLI Tools | §14 (check/build/diff/switch/rollback/graph) |
| 15 Implementation Phases | §15–16 (Phase 1–12) |
| 16 Deliverables | §15–16 (goal/files/data/APIs/tests/failure per phase) |
| 17 Constraints | §17 (rootless, minimal kernel, auditable, no hidden state) |
