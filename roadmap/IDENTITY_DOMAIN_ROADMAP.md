# Identity / Security-Domain Roadmap

> Scope: add a **Qubes-style identity (security domain) model** to anonymOS — every
> user-facing process belongs to a named, colored **identity**, every window is
> bordered with that identity's color by the **trusted compositor**, and isolation is
> enforced by the existing **capability + object + namespace** substrate, not by Unix
> uids or VMs. Deny-by-default; capabilities are the primary enforcement mechanism;
> the compositor is trusted; apps can never spoof their identity or its color.
>
> This is **identity-domain isolation inside anonymOS** — it reuses the object tree,
> cap tables, per-process namespaces, and secure-IPC broker already in the tree. It is
> *not* a port of Linux users, Unix permissions, or Qubes' hypervisor-per-VM design.

---

## 0. What already exists (reuse — do not reinvent)

The substrate for this is largely built. Identity is a thin, authoritative layer over
it:

| Need | Already in tree | Reuse as |
|---|---|---|
| First-class typed objects | `core/objmgr.d` (`ObjType`, `objAlloc/objGet/objRelease`, `ObjHeader{id,type,owner,version,...}`) | add `ObjType.Identity`; an identity **is an object** |
| Per-process authority | `core/cap.d` (per-task `CapTable`, `CAP_RIGHT_*`, `requireCapIn`, `capDerive*`, `capRevokeIn`, `CAP_RIGHT_UNIVERSE`) | identity = a **cap-rights ceiling** + a set of held caps |
| Per-process namespaces | `core/namespace.d` (`Namespace` objects, `nsAlloc/nsClone/nsBind/nsResolveWithRights`, per-binding rights) | each identity owns a **namespace template / object-tree root** |
| Process/thread model | `core/task.d` `Task{objId,processObjId,parentObjId,capTabId,fdTabId,namespaceObjId,userObjId,untypedObjId}` | add `identityObjId`; inherit on fork/clone |
| Subjects | `core/user.d` (`User` objects, `Task.userObjId`, `USER_RIGHT_*`) | identity is **orthogonal to** user (a user may own several identities) |
| Typed admin authority | `core/admin.d` (`ObjType.Admin`, `CAP_RIGHT_ADMIN_*`) | add `CAP_RIGHT_ADMIN_IDENTITY` for privileged identity transitions / policy load |
| Per-app sandbox (ephemeral root + private volume + gated /dev) | `core/linuxpers.d` (`linuxAppCreate`, ephemeral `/`, `/private`, `linuxAppGrantSynthetic`) | the **disposable-identity** substrate (§8) |
| Content store + signed bundles + generations | `core/store.d`, `core/update.d` (A/B, `updateApply` cap+signature gated) | **signed policy transactions** (§9) reuse the bundle/verify pattern |
| Real crypto | `core/crypto.d` (SHA-256, HMAC), `core/libsecipc.d` (X25519/HKDF/ChaCha20-Poly1305) | policy signatures + IPC session keys |
| Identity-aware secure IPC | `core/secipc.d` (CA certs, broker-signed `SessionDescriptor`, `brokerAuthorizePair`, `secipcKernelRoute` cap gate), `core/secsession.d` (signed-DH + AEAD) | make `brokerAuthorizePair` **identity-pair-aware** (§5) |
| Window objects + trusted compositor | `core/window.d` (`WinRec{objId,ownerObjId,parentObjId}`, `winRegister`), `display/compositor/compositor.d` (`borderColor`, `fillRect`, `drawRect`) | add `identityObjId` + `identityColor` to `WinRec`; compositor draws the border (§6) |
| Static audit ring | `core/audit.d` (`AuditKind`, `auditLog`, fixed `AuditEvent[256]` ring) | add identity `AuditKind`s — **no dynamic logging** |
| ORG (object reference graph) | `core/org.d` (ownership/label/rights-monotonicity edges, validator) | identity becomes an object **label**; cross-identity edges are flagged |

**Kernel build constraints (hard):** `-betterC` (ldc2, no GC/druntime/exceptions),
plain structs, `__gshared` fixed-size tables, `@nogc nothrow`, `-O0`. Every new module
follows the established pattern: one `core/<name>.d`, fixed tables, a one-shot boot
**self-test** printing `[<tag>] selftest PASS`, wired into the reconcile loop in
`core/kernel_main.d`. No heap, no dynamic logging.

---

## A. Design principles

1. **Identity is an object, enforced by capabilities.** An `Identity` is `ObjType.Identity`.
   A process is "in" an identity because `Task.identityObjId` names it and its cap table
   holds only caps derived under that identity's ceiling. There is no ambient "current
   identity" check that reads a global — authority is the cap, always.
2. **Deny-by-default.** No namespace binding, IPC pair, device, or network is reachable
   unless policy explicitly grants it to the identity. Cross-identity is *always* brokered.
3. **Immutable labels.** `Task.identityObjId` is set once at launch and never changes;
   `IdentityRec` is immutable once `active`. Changes happen only via a **signed policy
   transaction** (§9) carrying `CAP_RIGHT_ADMIN_IDENTITY`.
4. **Trusted compositor, unspoofable border.** The window's `identityObjId` is stamped by
   the kernel from the *owning process's* identity at `winRegister` time — never from an
   app-supplied value. The compositor reads it and draws the border. Apps have no cap to
   set/clear/recolor it.
5. **Object-native, not Unix.** Object-tree roots (`/identities/<name>/...`), not file
   permissions. Sharing is a capability to a specific object, audited — not a mode bit.
6. **Simple, auditable, static.** Fixed tables, ring-buffer audit, signed declarative
   policy loaded early in boot. Static identities first; reloadable policy later.

```
                 signed policy (HMAC/Ed25519, loaded early in boot, §9)
                              │  CAP_RIGHT_ADMIN_IDENTITY
                              ▼
                    ┌───────────────────┐     owns      ┌──────────────────────┐
                    │ Identity Manager  │──────────────▶│ Identity objects      │
                    │ core/identity.d   │   ceiling +   │ (Personal/Work/Bank/  │
                    │ (read-only after  │   ns template │  Dev/Untrusted/Disp/  │
                    │  policy load)     │   + color +   │  System)              │
                    └───────┬───────────┘   net/clip…   └──────────┬───────────┘
            label at launch │                                       │ ns template
        (immutable, inherit)▼                                       ▼ object-tree root
   ┌──────────────┐   Task.identityObjId   ┌────────────────────────────────────┐
   │ Process Mgr  │───────────────────────▶│ per-identity Namespace (core/ns.d)  │
   │ launch hook  │  cap ceiling enforced  │  /identities/<name>/… + shared caps │
   └──────┬───────┘                         └────────────────────────────────────┘
          │ window owner = process               cross-identity? broker only
          ▼                                            │
   ┌──────────────────────┐    identityColor    ┌──────▼─────────────────────────┐
   │ Compositor (trusted) │◄────────────────────│ Secure-IPC broker (core/secipc) │
   │ draws border + label │  (kernel-stamped)   │ identity-pair authz, cap-gated  │
   └──────────────────────┘                     └────────────────────────────────┘
                 every decision → core/audit.d ring (static, identity-tagged)
```

---

## B. Core data model (Phase 1 types)

All ids are object ids (`uint`) to stay native to the object tree. New file
`core/identity.d` unless noted.

```d
// --- identifiers (all are object ids; 0 = none) ------------------------------
alias IdentityId   = uint;   // objId of an ObjType.Identity
alias NamespaceId  = uint;   // objId of an ObjType.Namespace (core/namespace.d)
alias GuiContextId = uint;   // objId grouping an identity's windows/surfaces
alias IdentityColor = uint;  // packed 0xAARRGGBB, drawn by the compositor

enum ubyte TRUST_SYSTEM = 100, TRUST_BANKING = 80, TRUST_WORK = 60,
           TRUST_PERSONAL = 50, TRUST_DEV = 40, TRUST_UNTRUSTED = 10,
           TRUST_DISPOSABLE = 5;   // higher = more trusted; used for default flow rules

enum NetPolicy : ubyte { None=0, NAT, VPN, Tor, LocalOnly, Disposable }
enum ClipPolicy : ubyte { Deny=0, AskApproval, AllowSameIdentity, AllowDownTrust }
enum GuiPolicy  : uint  { BorderAlways=1, TitleLabel=2, NoScreenshotAcrossId=4,
                          NoGlobalGrab=8 }

// --- the identity object (immutable once `active`) ---------------------------
enum int ID_NAME_MAX = 24;
struct IdentityRec {
    bool          inUse;
    bool          active;        // once true: immutable except via signed txn (§9)
    bool          disposable;    // §8 throwaway domain
    IdentityId    objId;         // ObjType.Identity
    uint          templateId;    // disposable: the template it was cloned from (else 0)
    uint          nameLen;
    char[ID_NAME_MAX] name;      // "Personal","Work","Banking",…
    IdentityColor color;         // border color (compositor-drawn)
    ubyte         trust;         // TRUST_*
    uint          rightsCeiling; // max cap rights any process in this identity may hold
    NamespaceId   nsTemplate;    // object-tree root / namespace template to clone per proc
    uint          objRootObjId;  // /identities/<name> Directory object
    uint          allowedDevices;// bitmask of brokered device classes (see §7)
    NetPolicy     net;
    ClipPolicy    clip;
    uint          gui;           // GuiPolicy flags
    ulong         policyEpoch;   // bumped by each signed policy transaction
}

// --- per-identity allow-lists (deny-by-default; small fixed tables) ----------
struct IpcPairRule  { bool inUse; IdentityId from, to; uint brokerSvcObjId; } // 0 broker = direct allow
struct ShareRule    { bool inUse; IdentityId owner; uint objId; uint rights; IdentityId grantee; }
// allowed namespaces / object-roots are expressed as ns bindings on nsTemplate.
```

### Process / window / Task additions

```d
// core/task.d — Task gets one new field (mirrors namespaceObjId/userObjId):
//   uint identityObjId;   // immutable label; inherited by fork/clone

// Logical "process identity table" view (printed by the debug command, §10):
//   process_id        = Task.objId / pid
//   parent_process_id = Task.parentId
//   identity_id       = Task.identityObjId
//   namespace_id      = Task.namespaceObjId
//   capability_set    = Task.capTabId
//   object_root       = IdentityRec.objRootObjId (via identity)
//   ipc_policy        = identity IPC rules
//   gui_context_id    = per-process GuiContextId

// core/window.d — WinRec gets identity fields, STAMPED BY KERNEL, not the app:
//   IdentityId    identityObjId;   // = owner process's identity at winRegister
//   IdentityColor identityColor;   // snapshot of IdentityRec.color
//   GuiContextId  guiContextId;
//   uint          titleLen; char[…] title;   // app-supplied text only (never the color)
//   ubyte         inputPolicy;  ubyte clipPolicy;  // from identity
```

---

## C. File-by-file implementation plan

New modules (each: `__gshared` tables + boot self-test + stats, wired into
`kernel_main.d` reconcile loop exactly like `core/store.d`, `core/secipc.d`, …):

| File | Responsibility | Phase |
|---|---|---|
| **`core/identity.d`** (new) | Identity Manager: registry, create-from-policy, lookup by id/name, validation, rights-ceiling, read-only after load. `[identity] selftest PASS`. | 1–2 |
| **`core/idpolicy.d`** (new) | Declarative policy parser + signed-transaction verify (reuses `core/crypto.d` HMAC / `core/update.d` bundle+sig pattern); early-boot load; epoch bump. `[idpolicy] selftest PASS`. | 9 |
| **`core/idns.d`** (new) | Per-identity namespace assembly on top of `core/namespace.d`: clone `nsTemplate`, bind `/identities/<name>` object-root, visibility checks, controlled shared-object caps. `[idns] selftest PASS`. | 4 |
| **`core/idipc.d`** (new) | Identity-aware IPC policy layer wrapping `core/secipc.d`: deny cross-identity by default, brokered exceptions, identity-pair authz, pre-delivery cap check. `[idipc] selftest PASS`. | 5 |
| **`core/idbroker.d`** (new) | Clipboard / device / network broker services with per-identity policy + audit. `[idbroker] selftest PASS`. | 7 |
| **`core/iddispose.d`** (new) | Disposable identities: template clone, ephemeral ns/object-root (reuses `core/linuxpers.d`), teardown on exit. `[iddispose] selftest PASS`. | 8 |

Edits to existing files:

| File | Edit |
|---|---|
| `core/objmgr.d` | add `ObjType.Identity` (append-only enum). |
| `core/cap.d` | add `CAP_RIGHT_ADMIN_IDENTITY` (privileged transition/policy) and `CAP_RIGHT_ID_SHARE` (hold a cross-identity share); extend `CAP_RIGHT_UNIVERSE`. |
| `core/task.d` | add `uint identityObjId`; init to System identity for task 0. |
| `core/kernel_main.d` | at boot: load policy → build identities → stamp PID1's identity; at `fork`/`clone`: copy `identityObjId` (inherit); at process launch: identity-transition check; wire the 6 new self-tests + stats into the reconcile loop. |
| `core/admin.d` | register the `CAP_RIGHT_ADMIN_IDENTITY` admin cap object; PID1 holds it (only). |
| `core/namespace.d` | (no API change) `idns.d` calls `nsClone`/`nsBind`; optionally tag a binding as cross-identity-shared. |
| `core/secipc.d` | `brokerAuthorizePair` consults `idipc.d` (identity-pair rule) before authorizing; `SessionDescriptor` gains `aIdentity,bIdentity`. |
| `core/window.d` | `winRegister` stamps `identityObjId`/`identityColor` from the **owner process's** identity; add `winIdentity(objId)` getter for the compositor. |
| `display/compositor/compositor.d` | per-window border uses `IdentityRec.color` (via `winIdentity`); draw `"[Work] Terminal"` title label; border is composited **after/over** app content and cannot be overpainted by the app surface. |
| `core/audit.d` | add `AuditKind`: `IdLaunch, IdTransitionDeny, IdIpcDeny, IdNsDeny, IdShare, IdDeviceReq, IdNetReq, IdClipboard, IdWindowCreate`. |
| `core/org.d` | treat `identityObjId` as an object **label**; flag/deny cross-identity ownership edges that lack a `ShareRule`. |

---

## D. Phased roadmap

Legend — **P**: Critical/High/Med · **D**: difficulty 1–10 · each phase ends with a green
boot self-test.

### Phase 1 — Data model  · P: Critical · D: 3 · ✅ DONE (commit 69c914e27)
- `ObjType.Identity`; `IdentityRec`, `IpcPairRule`, `ShareRule`, the enums (§B).
- `Task.identityObjId`; `WinRec` identity fields; `CAP_RIGHT_ADMIN_IDENTITY`/`CAP_RIGHT_ID_SHARE`.
- *Outcome:* types compile; task 0 carries a System identity id. No behavior yet.
- **Done:** new `core/identity.d` holds the types + fixed tables (`g_identities`/
  `g_idIpcRules`/`g_idShareRules`, identity-prefixed because the `-betterC extern(C)`
  blanket exports module globals as flat C symbols — `g_ids` clashed with `secipc`).
  `ObjType.Identity` appended; `CAP_RIGHT_ADMIN_IDENTITY`/`CAP_RIGHT_ID_SHARE` folded
  into `ADMIN_ALL`/`UNIVERSE`; `Task.identityObjId` + `WinRec.{identityObjId,
  identityColor,guiContextId}` reserved (zero until §2/§3/§6). Builds, links, boots
  with the desktop unchanged. (Task-0 = System is actually stamped in Phase 2/§3.)

### Phase 2 — Identity Manager (`core/identity.d`)  · P: Critical · D: 5 · deps: 1 · ✅ DONE
- `identityCreate(name,color,trust,ceiling,nsTemplate,net,clip,gui)` → builds an
  `ObjType.Identity` object; `identityActivate(id)` makes it immutable.
- `identityById(id)`, `identityByName(name)`, `identityValidate(id)` (ceiling ⊆ universe,
  color set, ns template live, name unique).
- Static **boot identities** created from compiled-in defaults first (System, Personal,
  Work, Banking, Development, Untrusted, Disposable). Registry is **read-only** after
  `identityFreeze()`.
- *Outcome:* `[identity] selftest PASS` — create/lookup/validate; mutation after freeze
  refused; duplicate name refused.
- **Done:** registry accessors + create/activate/validate/freeze implemented;
  `identityInitDefaults()` builds the 7 compiled-in identities (colors/trust/net/clip/gui
  per §F; each gets an `nsAlloc()` template so `identityValidate` passes; System is the
  only one whose ceiling includes admin). Wired into boot (`kernel_main.d` after
  `windowRegistryInit`), and **task 0 is stamped with the System identity** there.
  `identitySelfTest()`/`identityStats()` run in the reconcile loop. Boot-verified:
  `[identity] selftest PASS`, `count=7 created=8 frozen=0 idobj=7`, no fault, all 27
  existing self-tests still pass. (Private helpers `idCstrLen`/`idNameEq`/`idCopyName`
  are id-prefixed for the same flat-C-symbol reason.)

### Phase 3 — Process Manager integration  · P: Critical · D: 6 · deps: 2 · ✅ DONE
- `fork`/`clone` copy `identityObjId` (inheritance by default).
- `identityCanTransition(parentId, targetId, capTabId)`: allowed **iff** the launcher holds
  `CAP_RIGHT_ADMIN_IDENTITY` *and* a policy launch rule permits `parent→target`; otherwise
  the child stays in the parent's identity. Untrusted→anything = denied.
- On launch, derive the child's cap table narrowed to `targetIdentity.rightsCeiling`
  (reuse `capTableCloneNarrowing`), and assign its namespace from the identity template
  (Phase 4). Audit `IdLaunch` / `IdTransitionDeny`.
- Debug command `idps` prints the process-identity table (§10).
- *Outcome:* `[idproc] selftest` (in `identity.d`): child inherits; impersonation/transition
  without the admin cap denied; cap set is ⊆ ceiling.
- **Done:** `forkTask`/`cloneThread` copy `identityObjId` (inheritance). `admin.d` registers
  `CAP_RIGHT_ADMIN_IDENTITY` (handle 1038) and PID1 holds it via `adminInstallInitCaps`.
  `identityCanTransition` + compiled-in launch rules (`identityInitLaunchRules`, per §F) +
  `policyLaunchAllowed` implement the gate (same-identity inherit; else needs the admin cap
  AND a launch rule; Untrusted denied); `IdLaunch`/`IdTransitionDeny` + the rest of §H added
  to `core/audit.d`. `idps` (`identityDumpProcesses` in `kernel_main.d`) prints the table;
  the interactive command waits for §10. Boot-verified: `[idproc] selftest PASS`; `idps`
  shows PID1 + its forked children all `[System]` (inheritance proven); cap-narrow strips
  the admin cap (⊆ ceiling); no fault, desktop unchanged. **The cap-table-narrowing launch
  of a child into a *different* identity (the full `launchInto`) is left until a launcher
  actually requests a cross-identity spawn (needs Phase 4 namespaces) — the gate it calls is
  done and tested.**

### Phase 4 — Namespace Manager (`core/idns.d`)  · P: Critical · D: 6 · deps: 2,3
- `idnsForIdentity(id)`: `nsClone(identity.nsTemplate)`; bind `/identities/<name>` →
  `objRootObjId` (RW), bind shared system roots read-only per policy. Process gets its own
  clone (rebinds don't leak across processes — already true in `namespace.d`).
- `idnsVisible(taskNs, path)`: a path resolves **only** if bound; nothing global by default.
- `idnsShare(ownerId, objId, granteeId, rights)`: requires a `ShareRule` + installs a
  capability-wrapped binding into the grantee's ns; audited `IdShare`. Rights ⊆ owner's.
- *Outcome:* `[idns] selftest PASS` — two identities get disjoint roots; a path in identity
  A's root is invisible to B; a shared object is reachable by B only with the cap.

### Phase 5 — IPC policy enforcement (`core/idipc.d`)  · P: Critical · D: 6 · deps: 2,5(secipc)
- `idipcMayConnect(fromId, toId)`: **deny by default**; allow only if same identity or an
  `IpcPairRule` exists (optionally via `brokerSvcObjId`).
- Hook `secipc.brokerRequestSession`: refuse to mint a descriptor across identities without
  a rule; stamp `aIdentity/bIdentity` into the descriptor.
- Hook `secipc.secipcKernelRoute`: the channel-cap check stays key-free; the identity check
  happens at descriptor issuance + endpoint admission (`secsession.sessionProcessHandshake`
  also verifies peer identity matches the descriptor). Audit `IdIpcDeny`.
- *Outcome:* `[idipc] selftest PASS` — same-identity IPC OK; cross-identity denied; a
  brokered pair (Dev→Disposable via sanitizer) allowed; descriptor carries both identities.

### Phase 6 — GUI / window-manager borders  · P: Critical · D: 6 · deps: 2,3
- `winRegister` stamps `WinRec.identityObjId = ownerProcess.identityObjId`,
  `identityColor = IdentityRec.color` — app cannot supply either.
- Compositor: for each window draw a persistent N-px border in `identityColor` **after**
  blitting the app surface (app pixels can't reach the border region); draw the title label
  `"[<name>] <appTitle>"`. No syscall/cap lets an app modify the border or its own
  `identityObjId`.
- `winIdentity(objId)`, `idwin` debug command (window-identity table).
- *Outcome:* `[idwin] selftest` — a window's stamped identity == its owner's; an app's
  attempt to re-register with a different identity id is ignored (owner-derived);
  border-color lookup returns the identity color.

### Phase 7 — Clipboard / device / network brokers (`core/idbroker.d`)  · P: High · D: 6 · deps: 4,5
- Devices and clipboard are **brokered objects**, never directly bound. `idbrokerDevice(id,
  class)` / `idbrokerNet(id)` consult `IdentityRec.allowedDevices`/`net`; `idbrokerClipboard(
  fromId,toId,bytes)` applies `ClipPolicy` (Deny / AskApproval / AllowDownTrust). Each call
  audits `IdDeviceReq`/`IdNetReq`/`IdClipboard`.
- Net policies map to namespace bindings: `None` (no `/net`), `NAT`, `VPN`, `Tor`,
  `LocalOnly`, `Disposable` (temporary, torn down on exit).
- *Outcome:* `[idbroker] selftest PASS` — Banking VPN-only; Untrusted clipboard-paste from
  Personal denied unless approved; device request without the class denied.

### Phase 8 — Disposable identities (`core/iddispose.d`)  · P: High · D: 6 · deps: 4,7,linuxpers
- `disposeCreate(templateId)`: clone an identity from a template, allocate an **ephemeral**
  namespace + object-root via `linuxpers.linuxAppCreate` (ephemeral `/` + `/private`),
  a temporary process group, a `Disposable` net namespace, and a distinct border color/pattern.
- `disposeDestroy(dispId)`: tear down ns + object-root + caps + windows; nothing persists
  unless exported through a sanitizer broker (§5/§7). Audit lifecycle.
- *Outcome:* `[iddispose] selftest PASS` — a disposable boots from a clean template, its
  object-root is distinct + writable, and after destroy nothing of it resolves.

### Phase 9 — Policy engine (`core/idpolicy.d`)  · P: High · D: 6 · deps: 2,8
- Declarative policy (see §F) parsed at **early boot** into the identity registry before
  PID1's first syscall (mirrors `storeMountSystem()`/`updateInit()` placement).
- Policy updates are **signed transactions**: verified with `crypto.cryptoVerify` (HMAC
  stand-in today; Ed25519 later) under `CAP_RIGHT_ADMIN_IDENTITY`, applied to the *frozen*
  registry only by bumping `policyEpoch` and re-validating — reuses the `update.d`
  inactive-slot/verify pattern so a bad policy can't brick the running set.
- *Outcome:* `[idpolicy] selftest PASS` — a signed policy loads identities; an unsigned/forged
  update is refused; epoch advances on a valid signed transaction.

### Phase 10 — Test suite & audit/debug  · P: High · D: 4 · deps: all
- The §9-test-suite items become the explicit asserts inside the per-module self-tests
  (inheritance, impersonation-deny, cross-identity-IPC-deny, brokered-allow, ns isolation,
  border correctness, border-spoof-deny, disposable cleanup, clipboard denial, net policy).
- `core/audit.d` identity `AuditKind`s; debug commands `idls` (identities), `idps`
  (process-identity table), `idns` (namespace table), `idwin` (window-identity table),
  `iddeny` (recent denied policy events) — all reading fixed tables / the static ring.

---

## E. Pseudocode

### Identity Manager (`core/identity.d`)
```d
public IdentityId identityCreate(const(char)* name, IdentityColor color, ubyte trust,
                                 uint ceiling, NamespaceId nsTemplate,
                                 NetPolicy net, ClipPolicy clip, uint gui) {
    if (g_idFrozen) return 0;                       // read-only after policy load
    if (identityByName(name) != 0) return 0;        // unique name
    if ((ceiling & ~CAP_RIGHT_UNIVERSE) != 0) return 0;
    foreach (ref e; g_ids) if (!e.inUse) {
        uint oid = objAlloc(ObjType.Identity, &e);
        if (oid == 0) return 0;
        e = IdentityRec.init; e.inUse = true; e.objId = oid;
        e.color=color; e.trust=trust; e.rightsCeiling=ceiling;
        e.nsTemplate=nsTemplate; e.net=net; e.clip=clip; e.gui=gui;
        copyName(e, name);
        return oid;
    }
    return 0;
}
public void identityActivate(IdentityId id){ auto r=byId(id); if(r) r.active=true; }
public bool identityValidate(IdentityId id){
    auto r=byId(id);
    return r!=null && r.color!=0 && (r.rightsCeiling & ~CAP_RIGHT_UNIVERSE)==0
                   && objGet(r.nsTemplate)!=null;
}
public void identityFreeze(){ g_idFrozen = true; }   // registry immutable
```

### Process Manager hook (`core/kernel_main.d` launch / fork)
```d
// fork/clone: inherit by default
child.identityObjId = parent.identityObjId;

// explicit launch into another identity (e.g. PID1 spawning a Work terminal)
bool launchInto(Task* parent, IdentityId target, int childTid) {
    if (!identityValidate(target)) return false;
    if (target != parent.identityObjId) {
        // privileged transition: need the admin cap AND a policy launch rule
        if (!requireCapIn(parent.capTabId, ADMIN_ID_HANDLE, CAP_RIGHT_ADMIN_IDENTITY)
            || !policyLaunchAllowed(parent.identityObjId, target)) {
            auditLog(AuditKind.IdTransitionDeny, target, parent.identityObjId);
            return false;                            // deny → child stays in parent id
        }
    }
    Task* c = &g_tasks[childTid];
    c.identityObjId = target;
    c.namespaceObjId = idnsForIdentity(target);                 // §4
    c.capTabId = capTableCloneNarrowing(parent.capTabId,
                     identityById(target).rightsCeiling);       // ⊆ ceiling
    auditLog(AuditKind.IdLaunch, c.objId, target);
    return true;
}
```

### Namespace Manager (`core/idns.d`)
```d
public NamespaceId idnsForIdentity(IdentityId id) {
    auto r = identityById(id);
    NamespaceId ns = nsClone(r.nsTemplate);                 // private clone
    nsBind(ns, identityRootPath(r), r.objRootObjId, CAP_RIGHT_READ|CAP_RIGHT_WRITE);
    // shared system roots are bound read-only ONLY if policy lists them; else absent
    return ns;
}
public bool idnsShare(IdentityId owner, uint objId, IdentityId grantee, uint rights) {
    if (!shareRuleExists(owner, grantee, objId)) { auditLog(AuditKind.IdNsDeny,objId,grantee); return false; }
    if ((rights & ownerRightsFor(owner,objId)) != rights) return false;   // ⊆ owner
    nsBind(idnsOf(grantee), sharedPath(objId), objId, rights);            // cap-wrapped
    auditLog(AuditKind.IdShare, objId, grantee);
    return true;
}
```

### IPC check (`core/idipc.d`, hooking `secipc.d`)
```d
public bool idipcMayConnect(IdentityId from, IdentityId to, out uint brokerSvc) {
    brokerSvc = 0;
    if (from == to) return true;                            // same identity: allowed
    foreach (ref rl; g_ipcRules)
        if (rl.inUse && rl.from==from && rl.to==to) { brokerSvc = rl.brokerSvcObjId; return true; }
    auditLog(AuditKind.IdIpcDeny, from, to);                // deny-by-default
    return false;
}
// in brokerRequestSession(A,B): refuse unless idipcMayConnect(idOf(A), idOf(B)); a
// brokered pair routes through brokerSvc (e.g. Dev→Disposable via a sanitizer service).
```

### GUI border (compositor, trusted)
```d
// winRegister (kernel): stamp identity from the OWNER, never the caller's argument
w.identityObjId = taskOf(ownerProcess).identityObjId;
w.identityColor = identityById(w.identityObjId).color;

// compositor render pass, AFTER blitting the app surface for window w:
void drawIdentityChrome(WinRec* w) {
    uint col = w.identityColor;                 // from the kernel, not the app
    drawRect(w.x, w.y, w.w, w.h, col);          // N-px border over app pixels
    drawRect(w.x+1, w.y+1, w.w-2, w.h-2, col);
    if (identityById(w.identityObjId).gui & GuiPolicy.TitleLabel)
        drawLabel(w.x+4, w.y+2, "[", identityName(w.identityObjId), "] ", w.title, col);
}
// There is no syscall/cap that lets the app set w.identityColor or skip drawIdentityChrome.
```

---

## F. Example identity policy (`/etc/identities.policy`, declarative)

Loaded early in boot; a signed transaction header authorizes updates (§9). Parser is a
small fixed-grammar reader (no heap); unknown keys rejected (deny-by-default).

```ini
# header: signature over the body, verified with the trusted key (crypto.cryptoVerify)
policy_epoch = 1
signature    = <hmac-sha256-or-ed25519-hex>

[identity System]
color = 0xFF808080      # gray
trust = 100
ceiling = ALL+ADMIN     # full (the only identity that may hold admin caps)
net = NAT
clipboard = AllowDownTrust
gui = BorderAlways,TitleLabel

[identity Personal]
color = 0xFF2E7D32      # green
trust = 50
ceiling = ALL           # fd rights only, no admin
root  = /identities/personal
net = NAT
clipboard = AskApproval
gui = BorderAlways,TitleLabel

[identity Work]
color = 0xFF1565C0      # blue
trust = 60
root  = /identities/work
net = VPN
clipboard = AllowSameIdentity
gui = BorderAlways,TitleLabel,NoScreenshotAcrossId

[identity Banking]
color = 0xFFFFD600      # yellow
trust = 80
root  = /identities/banking
net = VPN
clipboard = Deny        # nothing in/out without explicit approval
gui = BorderAlways,TitleLabel,NoScreenshotAcrossId,NoGlobalGrab

[identity Development]
color = 0xFF6A1B9A      # purple
trust = 40
root  = /identities/development
net = LocalOnly
clipboard = AskApproval

[identity Untrusted]
color = 0xFFB71C1C      # red
trust = 10
root  = /identities/untrusted
net = Tor
clipboard = Deny
gui = BorderAlways,TitleLabel

[identity Disposable]
template = true
color = 0xFFFF6D00      # orange (distinct disposable hue)
trust = 5
net = Disposable        # temp namespace, destroyed on exit
clipboard = Deny

# --- allowed identity transitions (launch rules; deny-by-default) ---
[launch] System -> Personal,Work,Banking,Development,Untrusted,Disposable
[launch] Development -> Disposable

# --- allowed IPC pairs (deny-by-default; "via" = brokered through a service) ---
[ipc] Development -> Disposable via sanitizer
[ipc] Work -> Work                       # intra-identity (implicit, listed for clarity)
# Personal -> Banking : (absent) => denied

# --- explicit cross-identity object shares (cap-wrapped, audited) ---
[share] Work grants /identities/work/reports/q3.obj to Personal : READ
```

---

## G. Milestones

- **M0 — Static identities + labels (minimal first pass).** Phases 1–3: `ObjType.Identity`,
  compiled-in System/Personal/Work/Banking/Dev/Untrusted/Disposable, `Task.identityObjId`
  inherited on fork, `idps` prints `pid → [identity] name`. **No GUI, no policy file.**
  Boots and shows process identity labels. *(This is the smallest useful slice — start here.)*
  **✅ M0 COMPLETE (2026-06-08).** Phases 1–3 done: types + Identity Manager + 7 boot
  identities + task-0=System; fork/clone inherit `identityObjId`; the privileged transition
  gate + launch rules; `idps` prints the process-identity table. Boot shows every process
  labelled `[System]` (inherited from PID1). `[identity] selftest PASS` + `[idproc] selftest
  PASS`. Next: M1 (Phase 4 per-identity namespaces + Phase 5 cross-identity IPC).
- **M1 — Isolation.** Phases 4–5: per-identity namespaces (disjoint object roots) +
  deny-by-default cross-identity IPC with brokered exceptions.
- **M2 — Trusted borders.** Phase 6: compositor draws unspoofable colored borders + title
  labels; first honestly "Qubes-like" visual.
- **M3 — Brokers + disposables.** Phases 7–8: clipboard/device/network brokers; disposable
  identities with ephemeral state destroyed on exit.
- **M4 — Signed policy + full audit.** Phases 9–10: declarative policy loaded at boot,
  signed updates, identity-aware audit + debug commands.

---

## H. Audit & debug (static, no dynamic logging)

- New `AuditKind`s in `core/audit.d`: `IdLaunch, IdTransitionDeny, IdIpcDeny, IdNsDeny,
  IdShare, IdDeviceReq, IdNetReq, IdClipboard, IdWindowCreate`. Each `auditLog(kind,
  subjectObj, detail)` into the existing fixed 256-entry ring; per-kind counters in
  `auditStats`. **No allocation, no string formatting on the hot path.**
- Debug commands (read fixed tables / the ring; print via `klog`): `idls`, `idps`, `idns`,
  `idwin`, `iddeny`. These satisfy "print active identities / process-identity table /
  namespace table / window-identity table / denied policy events."

---

## I. Security invariants & threat model

**Invariants**
- **I1** A process's identity (`Task.identityObjId`) is set once at launch and never mutated
  by any syscall; only `fork`/`clone` copy it. No code path derives privilege from a
  mutable global "current identity."
- **I2** A process holds only caps ⊆ its identity's `rightsCeiling` (enforced by
  `capTableCloneNarrowing` at launch + monotonic `capDerive`).
- **I3** Cross-identity reach (namespace object, IPC, clipboard, device) requires an explicit
  policy rule **and** a capability; default is deny, every denial is audited.
- **I4** A window's identity + color are kernel-stamped from the owner; no app cap can set,
  clear, recolor, or hide the border. The compositor is trusted and draws it last.
- **I5** The identity registry is immutable after `identityFreeze()`; changes require a
  signed policy transaction under `CAP_RIGHT_ADMIN_IDENTITY`.

**In scope:** a malicious app trying to impersonate another identity, read another identity's
objects, IPC across identities, exfiltrate via clipboard/screenshot, or spoof its window
border; a child trying to escape its parent's identity. **Out of scope (stated):** a
compromised compositor/kernel (trusted for isolation), side channels, and the
signing-key compromise of the policy authority (mitigated by epoch + re-sign).

---

## J. Non-goals / honest caveats

- **Not Linux/Unix/Qubes.** No uid-based checks (identity is orthogonal to `core/user.d`),
  no Unix mode bits, no per-app VM/hypervisor. Isolation = caps + namespaces + object labels.
- **Signatures** start as the HMAC-SHA-256 stand-in already used by `secipc`/`update`;
  Ed25519 is the later asymmetric upgrade (shared with `SECURE_IPC_ROADMAP.md` §0.1).
- **Compositor is in-kernel today** (`display/compositor`); the border logic lands there now
  and migrates with it when the display server moves to user space
  (`IMMUTABLE_ROOTLESS_ROADMAP.md` §5.2) — the trusted-compositor assumption is unchanged.
- **First pass is static.** Start at M0 (compiled-in identities + labels); the policy file,
  reloads, brokers, and disposables come later. Do not over-build the first slice.

*Companion roadmaps:* `OBJECT_OS_ROADMAP.md` (object/cap substrate), `CAPABILITY_MODEL.md`
(rights lattice + derive/revoke), `IMMUTABLE_ROOTLESS_ROADMAP.md` (namespaces, per-app
ephemeral sandboxes §7, store/signed-bundles §4/§6), `SECURE_IPC_ROADMAP.md` (identity
certs, brokered cap-gated IPC, signed-DH/AEAD), and `GUI_ROADMAP.md` (compositor bring-up).
```
