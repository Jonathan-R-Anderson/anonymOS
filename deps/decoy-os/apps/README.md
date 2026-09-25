# apps/ — your own programs in the decoy OS

Anything in `apps/<name>/` is installed into **both** decoy rootfs variants at build
time by [`../stage-apps.sh`](../stage-apps.sh), which the Makefile runs right after
`stage-synth-logs.sh`. There is nothing to register: create the directory and it is
picked up.

## Layout

All four parts are optional — use what your program needs.

| You put it here | It lands here |
|---|---|
| `apps/<name>/bin/*` | `/usr/local/bin/*`, mode 755 (already on the default PATH) |
| `apps/<name>/files/...` | merged into `/`, keeping the tree — `files/etc/foo.conf` → `/etc/foo.conf` |
| `apps/<name>/service` | `/etc/init.d/<name>`, enabled in the `default` runlevel → **starts at boot** |
| `apps/<name>/install.sh` | not copied; run as `install.sh <ROOTFS>` for anything else |

See `sysmon/` for a worked example using the first three.

Real apps in this tree:

- **`log-synth/`**, **`evidenceforge/`** — the synthetic-log generators. Each has an
  `install.sh` that stages its payload under `/opt` (idempotent: a `.installed` stamp
  makes a second run a no-op).
- **`qafs/`** — a Python FUSE filesystem (single `qafs.py`). Its `install.sh` stages the
  script under `/opt/qafs` (idempotent `.installed` stamp) and drops a `/usr/local/bin/qafs`
  launcher. It is *mounted* at boot by the `synthetic-logs` service (below), which then
  writes the host's real disk size to the mount's `/.control`.
- **`synthetic-logs/`** — a `service`-only app: the shared OpenRC script that runs the two
  log generators and mounts qafs at boot, plus `files/etc/synthetic-logs.conf`.
- **`blackpill/`** — an `install.sh` that builds and installs a kernel module.
- **`disk-reclaim/`** — a `bin/` duress tool + the `snoop-monitor` daemon. On a snoop-detection
  trigger it wipes every non-Linux/non-boot (hidden-OS) partition and grows the decoy's
  dm-crypt+ext4 to fill the disk, so the decoy becomes the only OS. Dry-run/disarmed by default;
  `snoop-monitor` (launched by synthetic-logs-run) is the single audited thing that fires it. See
  its README.
- **`argus/`, `spectre/`, `orin/`, `prx-sd/`** — vendored third-party detectors (eBPF tracer / HIDS
  / forensics / AV). Each has an `install.sh` that clones+builds upstream and is launched by
  `synthetic-logs-run` like the generators; their alerts feed `snoop-monitor` via
  `/etc/disk-reclaim/detectors.json`. **All disabled by default**, need `chmod +x` on their
  install.sh, and argus/prx-sd need real cross-build porting. Their presence is a deniability tell —
  read apps/disk-reclaim/README before shipping.

## Adding one

```
apps/myapp/bin/myapp          # your program
apps/myapp/files/etc/myapp.conf
apps/myapp/service            # optional, to run at boot
```

Then rebuild. **The rootfs targets do not depend on the Makefile**, but they *do*
depend on every file under `apps/`, so editing one of your files is enough to
re-trigger a build:

```sh
make -C deps/decoy-os desktop-rootfs     # graphical decoy (this is the one that ships)
make -C deps/decoy-os rootfs             # headless variant
```

## Running at boot

Name the OpenRC script `service` and it is symlinked into `/etc/runlevels/default/`.
The minimum useful script:

```sh
#!/sbin/openrc-run
name="myapp"
command="/usr/local/bin/myapp"
command_background=true          # only if it loops forever; omit for a one-shot
pidfile="/run/myapp.pid"
output_log="/var/log/myapp.log"
error_log="/var/log/myapp.log"

depend() { need localmount; after bootmisc; }
```

`command_background=true` matters: without it a program that never exits will wedge
the boot. Verify inside the booted decoy with `rc-update show default` and
`rc-service myapp status`.

> **Only the desktop rootfs runs services.** OpenRC arrives with `alpine-base`, which
> is in `DESKTOP_PKGS` but not `DECOY_PKGS`. In the headless `rootfs` the init script
> is installed and never started; `stage-apps.sh` warns when that happens. Add
> `alpine-base` to `DECOY_PKGS` if you need boot services there too.

## Constraints

- **Link against musl, not glibc.** There is no `/lib64/ld-linux-x86-64.so.2` in the
  decoy. Build static, or build inside an `alpine:3.19` container. A binary compiled
  on the Ubuntu host will not run. Check with
  `readelf -l ./myapp | grep interpreter` — it must say `/lib/ld-musl-x86_64.so.1`.
- **`/bin/sh` is busybox ash**, not bash. Use `#!/bin/bash` explicitly if you need it
  (bash is installed via `DECOY_PKGS`).
- **Never name anything `*decoy*` or `*fakelog*`.** `make h4` scans the whole rootfs
  and fails the build; `stage-apps.sh` warns earlier.
- **Stay in the cover story.** `make consistency` checks the decoy hangs together as
  "an ordinary used workstation". A program in `/usr/local/bin` that nothing in the
  shell history, configs or logs ever references is the kind of loose end §H1 is
  trying to avoid — consider adding a matching line to the seeded `.bash_history` in
  [`../customize.sh`](../customize.sh).
