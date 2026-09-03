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

## Compatibility mapping (the "fake views")

- `/bin /sbin /usr /lib` ↔ `/compat/linux/...` (symlinks; F0).
- `/etc` ← generated from `/config` (F2).
- `/proc` ← `/objects/processes`; `/dev` ← `/objects/devices` (F1).
- `/var /run /tmp` ↔ `/state` (F0).

## Milestones

Order: F0 ✅ → F1 ✅ → F2 ✅ → F3 ✅ → F4 ✅ (A5 disk + on-disk object store) → F5 ✅
(read views). Remaining: F2.2/F2.3 (writable config + /etc view), F4.3 (writable storage +
dedup), F5.2 (cap-graph mutation via the native shell).
