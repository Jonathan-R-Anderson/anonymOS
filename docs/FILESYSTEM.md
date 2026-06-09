# Filesystem Reference

EpinAnonymOS has **no single on-disk root filesystem** in the Linux sense. The path
namespace is a stack of layers, assembled and resolved in `core/syscalls/posix.d`
(chiefly `sys_open`, `getdents64`, and `newfstatat`). Linux paths (`/bin`, `/etc`,
`/proc`) are **generated compatibility views**; the native shape is the object tree
(`/objects`, `/system`, `/config`, `/state`, `/compat`).

> ⚠ = behaviour that differs from a normal Linux FS.

---

## 1. The layers (highest-priority first)

| Layer | Backing | Writable? | What lives here |
|-------|---------|-----------|-----------------|
| **RT ramfs** (`g_rt`) | in-RAM tmpfs (`RtNode[]`, ≤64 MiB) | yes | the FHS tree (`/bin`,`/sbin`,`/usr`,`/lib`,…), the 381 busybox symlinks (`/bin/<applet>`→`/busybox`), `/run`,`/var`,`/tmp`, unpacked xkb + GUI assets, native-root dirs |
| **Object FS views** | live kernel tables (F0–F5) | mostly no (`EROFS`) | `/objects/*`, `/system/*`, `/config/*` — see §3 |
| **Persisted object store** | AHCI SATA disk (`objstore.d`) | app `storage/` only | `/objects/apps/<app>/{manifest.json,permissions.json,executable,storage/}` — survives reboot |
| **Static synthetic VFS** (`g_vfs`) | compiled-in table | no | exact `/proc/*`, `/sys/*`, `/etc/*`, `/dev/*` entries |
| **Boot modules** | Limine-loaded blobs | no (exec/read) | `/busybox`, `/init.elf`, `/hos-sh`, `/store-app`, the GUI clients, `*.so` libs |

The RT ramfs is the only **general-purpose writable** filesystem. Everything else is a
read-mostly view; writing to it returns `EROFS` (or silently no-ops for `mount`).

---

## 2. `sys_open` resolution order

This is the actual order a path is tried (simplified from `posix.d:sys_open`). The first
layer that claims the path wins:

1. **cwd rewrite** — a relative path is prefixed with the global cwd (`g_cwd_buf`).
   ⚠ The cwd is a single global shim, not per-process.
2. **`/objects/processes` → `/proc` prefix-rewrite** — so per-pid paths reach procfs
   (the dir symlink alone can't traverse synthetic `/proc`).
3. **RT symlink chain follow** (`rtFollowSymlinks`) — e.g. `/bin/ls` → `/busybox`.
4. **Namespace gate** (`namespaceCheckOpen`) — the calling process's `Namespace` object
   must have a binding covering the path that grants the requested rights, else `EACCES`/
   `ENOENT`. See [NAMESPACING.md](NAMESPACING.md).
5. **RT ramfs** — an existing `g_rt` file/dir.
6. **Object field file** (F1/F5) — `/objects/<kind>/<obj>/{meta,capabilities,relationships}`.
7. **App blobs** (F4) — `/objects/apps/<app>/{manifest.json,permissions.json,
   identity-binding.json,executable,storage/data}` read from the on-disk store.
8. **`/objects/store`** (F4) — the store info file (incl. the persistence boot counter).
9. **Config docs** (F2) — `/config/{system,identities,users,services}.json`. ⚠ write-open
   → `EROFS`.
10. **System base** (F3) — `/system/generations`, `/system/current/...`. ⚠ any
    create/write under `/system` → `EROFS`.
11. **Synthetic directory** — if `isSyntheticDirectoryPath(path)` (a `/proc`, `/sys/...`,
    `/objects/<kind>`, `/objects/<kind>/<obj>`, `/objects/apps[/<app>[/storage]]`,
    `/system/current` directory), open a dir fd whose `getdents64` enumerates it.
12. **`/proc/self/exe`** → the task's own image.
13. **Boot modules** (`findBootModule` / `findBootModuleLib`).
14. **RT create** — with `O_CREAT`, create a new RT file under a writable overlay dir.
15. **Static VFS** (`g_vfs`) — exact `/proc`/`/sys`/`/etc`/`/dev` files.
16. otherwise `ENOENT`.

⚠ Order matters: an `EROFS`/synthetic branch is placed **before** the RT-create path so a
write can't shadow a synthetic view with a real RT file (e.g. `echo x > /system/...`).

---

## 3. The native object tree (OBJECT_FILESYSTEM_ROADMAP F0–F5)

Generated, mostly read-only views over the kernel's live tables. Full design +
verification: `roadmap/OBJECT_FILESYSTEM_ROADMAP.md`.

### `/objects` — live object views (F1) + each object as a directory (F5)
```
/objects/
  identities/  services/  namespaces/  users/   # live object collections (DT_DIR)
  processes/   -> /proc (per-pid; rewrite in sys_open)
  apps/        -> persisted app objects (F4, on disk)
  store        -> object-store info file (F4)
```
Each object is a **directory of fields** (F5):
```
/objects/identities/System/
  meta            # type/name/objId/trust/ceiling/state/namespace/policyEpoch
  capabilities    # rights bitmask decoded into the 19 named CAP_RIGHT_* bits
  relationships   # graph edges: namespace, objRoot, trust, devices, policyEpoch
```
`cat /objects/identities/Untrusted/capabilities` shows an **attenuated** ceiling
(`0x503ff`, no `admin-*` bits) versus System's `0x7ffff` — the live capability graph.

### `/config` — declarative JSON (F2, read-only)
`/config/{system,identities,users,services}.json`, rendered **live** from the same tables
each `open`. Writing returns `EROFS` (the writable, signed-transaction path is F2.2).

### `/system` — immutable base (F3, read-only)
```
/system/
  generations         # every captured Generation, the active one marked
  current/
    generation        # the active Generation's metadata
    <component>...     # the running base = the boot modules (kind=server/interface/data)
```
Any create/write under `/system` → `EROFS`.

### `/state`, `/compat` (F0)
`/state/{logs,cache,sessions}` symlink onto `/var/log`,`/var/cache`,`/run`.
`/compat/linux/{bin,sbin,usr,lib,lib64}` symlink onto the Linux FHS — so the Linux tree is
reachable under `/compat` while `/bin` etc. keep working.

---

## 4. The persisted object store (F4, on disk)

A custom on-disk format on the AHCI SATA disk (`core/objstore.d`):
```
LBA 0       superblock  (magic "HOSOBJFS", version, appCount, bootCount, nextFreeLba)
LBA 1..32   app directory (ObjAppEntry × 64)
LBA 64..    blob region (manifest / permissions / executable / storage), sector-granular
```
Apps are first-class objects whose manifest, declared permissions, identity binding,
executable, and private `storage/` **survive reboot**. Launching
`/objects/apps/<app>/executable` is **cap-gated** (the app's declared rights must be ⊆ the
launching task's identity ceiling) — see [SYSCALL_ABI.md](SYSCALL_ABI.md) `execve` and
[IDENTITY_AND_CAPABILITIES.md](IDENTITY_AND_CAPABILITIES.md). The `bootCount` (climbing
across reboots) is the persistence proof. Details: [PERSISTENCE.md](PERSISTENCE.md)
(planned) + the roadmap.

---

## 5. The RT ramfs (`g_rt`) in detail

- Node types: `RT_DIR`, `RT_REG`, `RT_LNK` (symlink). Up to 8192 nodes / 64 MiB.
- Seeded at boot (`rtInit`): the FHS dirs, `/bin/<applet>→/busybox` for all 381 applets,
  the F0 native root, and the `/compat`/`/state` symlinks. xkb + GUI assets are unpacked
  into it from boot-module blobs.
- `rtResolve` follows **intermediate directory symlinks** (bounded depth) so paths
  *through* a dir symlink resolve (e.g. `/compat/linux/bin/ls`).
- A one-shot `[rtfs] selftest` (11/11 checks: create/write/read-back/chmod/stat/unlink +
  symlink ops) runs at boot — a good liveness signal in the serial log.

⚠ Synthetic directories (`/proc`, `/sys`, `/etc`, `/dev`) are **not** RT children, so they
do not appear in `ls /` unless also seeded as RT nodes; they resolve via the static VFS /
synthetic-dir machinery instead.

---

## See also

- [SYSCALL_ABI.md](SYSCALL_ABI.md) — the open/read/getdents/stat syscalls themselves.
- [NAMESPACING.md](NAMESPACING.md) — the per-process gate in step 4 above.
- `roadmap/OBJECT_FILESYSTEM_ROADMAP.md` — design + per-phase verification.
