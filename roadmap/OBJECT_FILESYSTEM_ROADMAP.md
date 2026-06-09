# Object Filesystem Roadmap

Goal: replace the Linux-historical root (`/bin /etc /usr /var …`) with a **native,
object-based filesystem** — objects with identity, capabilities, relationships and
data — over an **immutable system base** and **declarative config**, while Linux/POSIX
paths become **generated compatibility views, not the real design**.

North star (user-chosen): `/objects` is a **persisted object store** — apps are
first-class objects (`/objects/apps/<app>/{manifest.json, executable, permissions.json,
identity-binding.json, storage/, ipc/}`) whose objects + data survive reboot. We get
there **additively**: live generated views first (achievable now), real persistence
later (needs the disk layer, A5 of the shell roadmap).

## Why this fits EpinAnonymOS (already ~70% latent)

The kernel is already object/capability/immutable-based, and most Linux paths are
already synthetic views — so this is a re-rooting + a few new views, not a rewrite:

| Native path | Backed by today | State |
|---|---|---|
| `/objects/processes` | task table → already `/proc/<pid>` | exists (A4), re-root |
| `/objects/identities` `/services` `/devices` `/windows` `/users` | `g_identities` / `g_svcs` / Device / Window / `g_users` objects | enumerable now (native `hos_query`); no FS view yet |
| `/compat/linux/{bin,sbin,usr,lib}` | the busybox FHS tree (A3) | exists — *becomes* the compat view |
| `/etc` `/dev` `/proc` | `g_vfs` / device shims / task table | already "fake views" |
| `/state` | `g_rt` writable ramfs (`/run`,`/var`,`/tmp`) | exists, re-root |
| `/system` (immutable) | Generation + StoreObject (IMMUTABLE_ROOTLESS) | primitives exist, no view |
| `/config/*.json` | `g_identities`/`g_svcs`/`g_users` tables | generate declarative views |
| `/objects/apps/<app>/manifest.json + storage/` | — | needs a **persisted** store (disk, A5) |

Principles (grounded): everything is an object; capabilities, not global perms;
immutable system base; user/app state separate from system; **compat paths are views**;
declarative config; logs/cache/secrets/runtime separated; identities/namespaces are
first-class objects.

Legend: **P** priority · **E** effort (1=hrs … 5=weeks) · **R** risk · deps.

---

## F0 — Native root layout (additive, nothing breaks) · P: High · E: 2 · R: low · deps: —

Make the object-OS tree appear at `/` without disturbing the working Linux FS.

- Seed the native top level in `rtInit` (posix.d): `/objects /system /state /config
  /compat /compat/linux /volumes` (keep `/home`, `/root`).
- `/compat/linux/{bin,sbin,usr,lib,lib64}` as RT symlinks onto the existing canonical
  dirs, so the Linux tree is reachable under `/compat` while `/bin` etc. stay put and
  keep working (PATH, exec, busybox unaffected). *(Later: flip canonical home to
  `/compat`, making `/bin` the alias.)*
- `/state/{logs,cache,sessions}` as symlinks onto `/var/log`, `/var/cache`, `/run`.
- **Enabler:** make `rtResolve` follow **intermediate directory symlinks** (today only
  the final component is followed) so paths *through* a dir symlink resolve
  (`cat /compat/linux/bin/ls`, `ls /state/logs`). Bounded depth.
- *Verify:* `ls /` shows the native tree; `ls /compat/linux/bin` + `cat /compat/linux/
  bin/<applet>` work; `/bin/ls` still execs; the shell + busybox are unchanged.

## F1 — `/objects` live views (generated, read-mostly) · ✅ DONE (2026-06-09) · P: High · E: 3 · R: med · deps: F0

The real native model: a synthetic object tree over the kernel's live tables.

- `/objects/<kind>/` directories — `processes` (= reframed `/proc`), `identities`,
  `services`, `namespaces`, `users` — each enumerating live objects.
  - **Implemented:** `objfsEnum`/`objfsRead`/`objfsKindId` in core/hoscall.d render the
    live `g_identities`/`g_svcs`/`g_users` (+ object) tables; posix.d `sys_open` resolves
    `/objects/<kind>/<obj>` to a generated metadata file (`SYNTHDIR_OBJ_BASE` getdents for
    `/objects/<kind>`, kind list `identities/services/namespaces/users` as DT_DIR for
    `/objects`). `/objects/processes` is an RT dir-symlink onto `/proc`, **plus** a
    `sys_open` prefix-rewrite `/objects/processes/… → /proc/…` so per-pid paths reach the
    procfs handler (the symlink alone only covers the final component / synthetic `/proc`).
- Each object renders as a metadata file: `type`, `name`, `objId`, plus kind-specific
  fields (identities: `trust`, `ceiling`, `state`, `disposable`, `namespace`,
  `policyEpoch`; users: `uid/gid/rights`). Per-field dirs + `capabilities/`,
  `relationships/` are F5.
- *Verified (GUI):* `ls /objects` → `identities namespaces processes services users`;
  `ls /objects/identities` → the 7 domains; `cat /objects/identities/System` →
  `type=Identity name=System trust=100 ceiling=0x7ffff state=active …`;
  `ls /objects/processes` → live pids (clean, no errors); `cat /objects/processes/<pid>/
  comm` → the process name; `/bin/ls` + rtfs selftest 11/11 unaffected.

## F2 — `/config` declarative views · ✅ DONE (read-only render, 2026-06-09) · P: Med · E: 3 · R: med · deps: F1

System configuration as declarative data generated from (and applied back to) the
kernel object tables.

- **DONE:** generated `/config/{system,identities,users,services}.json` rendered from
  `g_identities`/`g_svcs`/`g_users` + the object table (`system.json` = kernel/model +
  object/identity/namespace/service counts). Read = **live render** (verified: the object
  count changed between two reads). core/hoscall.d `configfsId`/`configfsEnum`/
  `configfsRender` (JSON via the UB text builder, `jstr` for names, hex strings for
  rights/ceilings); posix.d `configfsParse` + a `sys_open` branch renders into
  `g_configBuf` (8 KB) as an `FD_FILE`; getdents over the `/config` RT dir
  (`g_configDirIdx`) lists the four documents. **Read-only:** a write-open returns EROFS
  (verified `echo x > /config/system.json` → "Read-only file system", no shadowing RT
  file created — the EROFS guard precedes the RT-create path).
- **F2.2 remaining (writable):** make the mutable docs writable via the
  **signed-policy-transaction** path (the identity `policyEpoch` mechanism) — parse the
  edited JSON, apply to the object (epoch bumped, audited).
- **F2.3 remaining (`/etc` view):** make `/etc` a generated view derived from `/config`
  (replacing the static `g_vfs` `/etc/*`); add a `permissions.json` doc.
- *Verified:* `ls /config` lists the four docs; `cat /config/identities.json` reflects the
  live 7 domains (name/objId/trust/ceiling/state/disposable/namespace/policyEpoch);
  `cat /config/system.json` live counts; write → EROFS; `/bin/ls` + rtfs selftest 11/11
  unaffected.

## F3 — `/system` immutable base · P: Med · E: 3 · R: med · deps: IMMUTABLE_ROOTLESS

A read-only view over the content-addressed Generation / StoreObject objects.

- `/system/<generation>/{kernel,servers,drivers,interfaces}` from the boot
  modules + StoreObject blobs; `/system/current` → the running Generation. Writes
  denied (immutable); updates land as new Generations (anti-rollback already exists).
- *Verify:* `ls /system/current` lists the base components; a write under `/system`
  returns EROFS; an applied update appears as a new generation.

## F4 — Persisted object store (the north star) · P: High · E: 5 · R: high · deps: F1, SHELL A5 (disk)

Back `/objects` with real storage so objects + their data survive reboot.

- A real backing FS on disk (AHCI + ext2/own FS — shell-roadmap **A5**) + a
  content-addressed object store (StoreObject) for object bodies.
- **Apps as first-class objects:** `/objects/apps/<app>/{manifest.json, executable,
  permissions.json, identity-binding.json, storage/, ipc/}`. Launch reads the manifest
  + declared capabilities + identity binding; per-app `storage/` is the only writable
  area, separate from system files.
- *Verify:* install an app object, reboot, it persists and launches with exactly its
  declared capabilities; its `storage/` round-trips across reboot.

## F5 — Capabilities + relationships as first-class FS · P: Med · E: 3 · R: med · deps: F1

Expose the cap/relationship graph the kernel already maintains as filesystem objects.

- `/objects/<kind>/<obj>/capabilities/` — the cap set the object holds (rights, target,
  derivation), derivable/attenuable; `/relationships/` — owner, identity, namespace,
  IPC peers (the ORG/cap edges).
- The native shell `cap`/`obj` mutating commands (Track B remainder) operate here,
  cap-gated on the identity ceiling.
- *Verify:* `ls /objects/processes/<pid>/capabilities` lists its caps; grant/attenuate
  via the native shell is reflected; a denied grant (exceeds ceiling) fails + audits.

---

## Compatibility mapping (the "fake views")

- `/bin /sbin /usr /lib` ↔ `/compat/linux/...` (symlinks; F0).
- `/etc` ← generated from `/config` (F2).
- `/proc` ← `/objects/processes`; `/dev` ← `/objects/devices` (F1).
- `/var /run /tmp` ↔ `/state` (F0).

## Milestones

- **M-F0 Native root.** ✅ `ls /` is the object-OS tree; Linux still runs via `/compat`.
- **M-F1 Live object FS.** ✅ Browse `/objects/*` reflecting live kernel state.
- **M-F2 Declarative config.** ✅ (read-only) `/config/*.json` generated from the object
  tables; writable + `/etc`-from-`/config` are F2.2/F2.3.
- **M-F3 Immutable system.** `/system` read-only Generation view.
- **M-F4 Persisted objects.** Apps with manifests + `storage/` survive reboot (north star).
- **M-F5 Capability FS.** Caps + relationships browsable and mutable via the native shell.

Order: F0 → F1 → F2 → F3 → (F4 needs A5 disk) → F5.
