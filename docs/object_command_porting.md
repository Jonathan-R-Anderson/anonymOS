# Object-based command porting plan

The guest OS needs object-native equivalents for both the Plan 9 userland and
the POSIX compatibility layer so that binaries can be provisioned from the
immutable object store instead of relying on the host filesystem. This document
tracks the inventory and the scaffolding required to wire everything into the
`ServicePlan` structures defined in `src/minimal_os/userland.d`.

## Plan 9 system inventory

The following Plan 9 commands and services are the initial targets for
conversion. They cover namespace manipulation, distributed sessions, and the
windowing/shell stack:

- `bind` / `mount` – namespace composers for exposing object-backed services.
- `cpu` / `rcpu` – remote CPU sessions that should launch against object-backed
  binaries.
- `import` / `exportfs` – file service bridges that are currently hardwired to
  host filesystems.
- `factotum` – credential agent that needs to fetch its keys from the object
  store.
- `9fs` – namespace fetcher; in the object model it becomes a manifest loader
  that resolves object IDs.
- `rio` – window system executable; treating it as an object allows headless
  testing and future display servers to share the same byte-for-byte hash.
- `acme` – editor/UI shell expected by higher-level tooling.
- `venti` – archival object server that becomes the natural backing store for
  immutable binaries.
- `auth/factotum`, `auth/wrkey`, `auth/pem` – authentication helpers that must
  pull credentials from sealed objects.
- `ndb/dns` and `ndb/cs` – network directory services that should read their
  database from VMOs instead of `/lib/ndb`.

Each of these commands is represented as a standalone binary today; the porting
work involves expressing the canonical byte stream for each binary as an object
ID and teaching the init sequence how to spawn them via capability grants.

## POSIX command coverage

The existing POSIX compatibility layer already mirrors dozens of utilities under
`src/minimal_os/posixutils/commands`. They are the next candidates for object
conversion because the shell expects them to be present before falling back to
Plan 9 tooling. The current tree contains the following binaries:

```
asa, basename, cat, chown, cksum, cmp, comm, compress, date, df, diff,
dirname, echo, env, expand, expr, false, getconf, grep, head, id, ipcrm,
ipcs, kill, link, ln, logger, logname, ls, mesg, mkdir, mkfifo, mv,
nice, nohup, pathchk, pwd, renice, rm, rmdir, sleep, sort, split,
strings, stty, tabs, tee, time, touch, true, tput, tsort, tty, uname,
uniq, unlink, uuencode, waitpid, wc, what
```

These names are the canonical keys emitted into `build/posixutils/objects.tsv` by
`tools/build_posixutils.py`. Converting them to object-backed processes simply
requires teaching the runtime where each binary lives in the packaged ISO.

## Integration scaffolding

Two glue layers now exist to keep the kernel and init sequence informed:

1. `src/minimal_os/posixutils/registry.d` parses the object manifest at
   compile time and exposes helpers such as `embeddedPosixUtilitiesAvailable()`,
   `embeddedPosixUtilityPaths()`, and `findPosixUtilityObjectId()` so that
   higher-level code can translate command names into object IDs without touching
   the host filesystem.
2. `src/minimal_os/userland.d` already describes the boot-time `ServicePlan`
   records for `init`, `vfsd`, `pkgd`, `netd`, and `lfe-sh`. Porting a command is
   now a matter of using the registry helpers to request capabilities for the
   appropriate object ID before invoking `launchService()`.

The combination of these inventories and the manifest-backed registry ensures we
can iterate on object-native processes without hard-coding host paths.
