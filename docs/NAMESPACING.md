# Namespacing Reference

EpinAnonymOS namespacing is **capability-based**, not the Linux mount/PID/net-namespace
model. There are two cooperating layers:

1. **Per-process `Namespace` objects** (`core/namespace.d`) — a set of path *bindings*,
   each granting specific rights to a target object. Every absolute `open` is resolved
   and gated through the calling process's namespace.
2. **Per-identity object-tree views** (`core/idns.d`) — each security identity (System,
   Personal, Work, …) gets an object-tree *view* built on top of the namespace layer, so
   two domains can see different roots and share objects only via explicit rules.

A process therefore sees a path namespace that is the intersection of *what its identity
exposes* and *what its namespace bindings permit*.

---

## 1. Per-process namespaces (`core/namespace.d`)

### The data
```d
struct NsBinding   { bool inUse; char[..] path; uint pathLen; uint targetObjId; uint rights; }
struct NamespaceRec{ bool inUse; uint objId /*ObjType.Namespace*/; NsBinding[NS_BIND_MAX] binds; }
__gshared NamespaceRec[NS_MAX] g_namespaces;
```
A namespace is just a list of **bindings**: "this path prefix maps to this target object,
with these rights." A `Namespace` is itself a first-class object (`ObjType.Namespace`,
visible at `/objects/namespaces/<objId>`).

Each task carries `namespaceObjId` (`core/task.d`). The default boot namespace has a
single `/` binding granting all rights, so early boot behaves like an open system; more
restricted namespaces are clones with narrowed bindings.

### Resolution — `nsResolveWithRights(nsObjId, path, out rest, out rights)`
- Requires an **absolute** path (`path[0] == '/'`).
- Scans the namespace's bindings and picks the **longest-prefix match** (`bindMatches`,
  preferring the binding with the larger `pathLen`).
- Returns that binding's `targetObjId` and `rights`, and sets `rest` to the path *suffix*
  beyond the mount boundary (for a `/` mount, `rest` is the whole path).
- No matching binding → returns `0` (resolution fails).

### The open gate — `namespaceCheckOpen(path, flags)` (in `posix.d`)
Runs early in `sys_open` for every absolute path:
1. `objEnsureNamespace(tid)` — lazily give the task a namespace if it has none.
2. `nsResolveWithRights(task.namespaceObjId, path, …)` → target + granted rights.
3. Compute the rights the open *needs* (`openRightsForFlags`: `O_RDONLY`→`READ`,
   `O_WRONLY`→`WRITE`, `O_CREAT|O_TRUNC|O_APPEND`→`WRITE`).
4. If `(granted & need) != need` → **`EACCES`**. If nothing resolves → **`ENOENT`**.

Only after this gate passes does the layered backing resolver (RT ramfs, object views,
boot modules — see [FILESYSTEM.md](FILESYSTEM.md)) run. So a namespace can deny access to a
path *before* the path is even looked up.

> ⚠ Relative paths bypass the namespace gate (they go through the cwd shim). Absolute
> paths are the gated surface.

### Operations
- `nsClone(srcObjId)` — copy a namespace (the basis for per-process restriction; a child
  starts from a clone and bindings are narrowed).
- `nsBind(nsObjId, path, targetObjId, rights)` — add/replace a binding.
- Counters `g_nsCloneTotal` / `g_nsBindTotal` / `g_nsResolveTotal` track usage (a boot
  self-test in `namespace.d` proves clone + bind + resolve + a restricted deny).

---

## 2. Per-identity object-tree views (`core/idns.d`)

Built **on top of** the namespace layer. Each identity domain gets its own object-tree
root view so that, e.g., the Banking domain and the Untrusted domain don't share a
filesystem world by default.

- `idnsInitRoots()` — at boot, stand up one object-tree view per compiled-in identity.
- `idnsForIdentity(identityId) -> NamespaceId` — the namespace/view backing an identity.
- `idnsVisible(taskNs, path)` — whether a path is visible in a given identity's view.
- **Sharing is explicit:** `idnsShareRuleAdd(owner, objId, grantee, rights)` /
  `idnsShare(...)` add a `ShareRule` so an object owned by one identity becomes reachable
  (with capped rights) from another. No ambient cross-domain visibility.

The identity itself defines the *ceiling* (`rightsCeiling`) — the maximum rights any
process in that domain may hold — and a namespace **template** (`nsTemplate`) cloned per
process. So "what a process can see and do" is bounded by:

```
process rights  ⊆  identity.rightsCeiling          (the capability ceiling)
process paths   ⊆  identity view (idns)  ∩  namespace bindings (nsResolveWithRights)
```

See [IDENTITY_AND_CAPABILITIES.md](IDENTITY_AND_CAPABILITIES.md) (planned) and
`roadmap/IDENTITY_DOMAIN_ROADMAP.md` for the identity side; the live data is browsable at
`/objects/identities/<name>/relationships` (which prints `namespace=<id>` — the
identity's `nsTemplate`).

---

## 3. Inheritance across fork / clone

`core/task.d` ties it together. Relevant per-task fields:

| field | meaning |
|-------|---------|
| `namespaceObjId` | the process's `Namespace` object (the path bindings) |
| `identityObjId`  | the security domain it runs under (the rights ceiling + view) |
| `userObjId`      | the POSIX `User` object (uid/gid/admin rights) |
| `capTabId`       | the per-process capability table (per-fd rights) |
| `fdTabId`        | the per-process file-descriptor table |

- **`fork`** — the child inherits the parent's `namespaceObjId` and `identityObjId`
  (deep-copied fd table; CoW address space).
- **`clone` (thread, `CLONE_VM`)** — a thread **shares** the leader's namespace, identity,
  fd and cap tables (`task.namespaceObjId = leader.namespaceObjId`).
- **Identity transition** (running under a *different* domain) is privileged: it needs
  `CAP_RIGHT_ADMIN_IDENTITY` + a matching launch rule (`core/idproc.d`), so a process can't
  silently escalate out of its domain. fork/clone *inherit* the label; they never *change*
  it.

The desktop Domain Manager uses this: each per-domain terminal/app is launched under that
domain's identity, so its namespace view, rights ceiling, and the compositor's window
border colour all follow the domain.

---

## 4. Observing it live

- `/objects/namespaces/` — the live `Namespace` objects (by objId).
- `/objects/identities/<name>/relationships` — the identity's `namespace=` template + edges.
- `HOSQ_NAMESPACES` (op 3) and `HOSQ_WHOAMI` (op 6) via the native ABI
  ([SYSCALL_ABI.md](SYSCALL_ABI.md) §5); the native shell prompt `user@<namespace>:/path$`
  is `HOSQ_WHOAMI`.

---

## See also

- [FILESYSTEM.md](FILESYSTEM.md) — the gate in step 4 of `sys_open`, and what backs paths.
- [SYSCALL_ABI.md](SYSCALL_ABI.md) — `open`/`fork`/`clone`/`execve` and the native ABI.
- `roadmap/IDENTITY_DOMAIN_ROADMAP.md`, `roadmap/CAPABILITY_MODEL.md` — the design.
