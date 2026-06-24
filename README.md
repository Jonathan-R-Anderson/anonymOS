# anonymOS

**A capability-secured, object-graph operating system** — a from-scratch x86_64
kernel that boots a real Linux desktop while, underneath, reducing everything
(tasks, files, windows, identities, services, even the Linux personality itself)
to a single capability-gated object model with a declarative configuration system.

The kernel boots Limine → a D kernel (no GC, `-betterC`) → a **Linux
personality** that runs unmodified musl binaries, BusyBox, Weston, GTK apps and
the real Z Shell — all answering to ~160 syscall numbers. Beneath that surface,
*nothing* is a Unix uid or a file inode: every resource is an **Object** with
identity, capabilities, and typed edges in a validated **Object-Reference-Graph**.
One JSON file (`system.json`) is the declarative source of truth for the whole
running system.

> The boot banner reads `=== EpinAnonymOS ===`. Code and docs use the names
> interchangeably.

---

## What works today

The system boots, renders a desktop, and runs Linux programs. Every subsystem
below is **implemented and self-tested** (each prints `[<tag>] selftest PASS` at
boot), unless explicitly marked 🚧 (in progress) or 🔵 (planned).

| Area | Status | Roadmap |
|------|:------:|---------|
| Object-capability kernel (6 pillars, 16 object families) | ✅ | [`OBJECT_OS_ROADMAP`](roadmap/OBJECT_OS_ROADMAP.md) |
| Capability model (19 rights, derive, revoke, typed admin) | ✅ | [`CAPABILITY_MODEL`](roadmap/CAPABILITY_MODEL.md) |
| Object-Reference-Graph + cycle-detecting GC | ✅ | [`OBJECT_REFERENCE_GRAPH_ROADMAP`](roadmap/OBJECT_REFERENCE_GRAPH_ROADMAP.md) / [`ORG_ARCHITECTURE`](roadmap/ORG_ARCHITECTURE.md) |
| Identity / security domains (Qubes-style, no VMs) | ✅ | [`IDENTITY_DOMAIN_ROADMAP`](roadmap/IDENTITY_DOMAIN_ROADMAP.md) |
| Native object filesystem (`/objects`, `/config`, `/system`) | ✅ | [`OBJECT_FILESYSTEM_ROADMAP`](roadmap/OBJECT_FILESYSTEM_ROADMAP.md) |
| Declarative config compiler + verified-config boot | ✅ | [`DECLARATIVE_CONFIG_SPEC`](roadmap/DECLARATIVE_CONFIG_SPEC.md) / [`anonymos-config/`](anonymos-config/) |
| Secure IPC (X25519 / HKDF / ChaCha20-Poly1305) | ✅ | [`SECURE_IPC_ROADMAP`](roadmap/SECURE_IPC_ROADMAP.md) |
| Immutable store + A/B updates + rollback | ✅ | [`IMMUTABLE_ROOTLESS_ROADMAP`](roadmap/IMMUTABLE_ROOTLESS_ROADMAP.md) |
| Rootless administration (no UID 0) | ✅ | [`IMMUTABLE_ROOTLESS_ROADMAP`](roadmap/IMMUTABLE_ROOTLESS_ROADMAP.md) |
| Weston 14 desktop (Pixman software renderer) | ✅ | [`GUI_ROADMAP`](roadmap/GUI_ROADMAP.md) / [`DESKTOP_RESPONSIVENESS_ROADMAP`](roadmap/DESKTOP_RESPONSIVENESS_ROADMAP.md) |
| Real Z Shell (Linux + native-ABI port) | ✅ | [`ZSH_INTEGRATION_ROADMAP`](roadmap/ZSH_INTEGRATION_ROADMAP.md) |
| Shell & command set (`hos-sh`, `esh`, busybox 381 applets) | ✅ | [`SHELL_AND_COMMANDS_ROADMAP`](roadmap/SHELL_AND_COMMANDS_ROADMAP.md) |
| Memory-safety hardening (W^X, ASLR, NX stack) | 🚧 | [`SECURITY_ROADMAP`](roadmap/SECURITY_ROADMAP.md) |

---

## Architecture at a glance

```
                ┌─────────────────────────────────────────────┐
                │            system.json  (declarative)        │
                │   → anonymos-config compiler (host, D)       │
                │   → manifest.blob (HMAC-signed TLV)          │
                └────────────────────┬────────────────────────┘
                                     │ verified at boot
        ┌────────────────────────────▼───────────────────────────┐
        │   anonymOS kernel  (D, -betterC, no GC)  · x86_64       │
        │                                                          │
        │   ┌─────────────── 6 native pillars ───────────────┐    │
        │   │ Scheduler · Object Mgr · Capability Mgr        │    │
        │   │ IPC Router · Memory Mgr · HAL                  │    │
        │   └────────────────────────────────────────────────┘    │
        │                      ▲                                   │
        │   Linux personality   │  Native object ABI (0x4000)      │
        │   (~160 syscalls) ────┘  deny-by-default unless /hos-sh  │
        └───────────┬───────────────────────────────┬─────────────┘
                    │                               │
        ┌───────────▼───────────┐         ┌─────────▼──────────┐
        │  Linux userland        │         │  Native shell       │
        │  busybox · zsh · Weston│         │  hos-sh · esh · LFE │
        │  GTK · Hyprland        │         │  (object model)     │
        └────────────────────────┘         └─────────────────────┘
```

The **native kernel is six pillars**: Scheduler, Object Manager, Capability
Manager, IPC Router, Memory Manager, HAL. Everything else — including the entire
Linux personality — is implemented *as objects* and can be gated off
(`g_linuxEnabled`). A live boot census confirms exactly this:
`[census] PASS native kernel = 6 pillars; families=0x10 are objects` — 16
distinct object families populated.

---

## Features

### 🧩 Object-capability kernel
*Roadmap: [`OBJECT_OS_ROADMAP`](roadmap/OBJECT_OS_ROADMAP.md) — Phases P2–P13 all implemented.*

Everything is an `Object` (`core/objmgr.d`): processes, threads, fds, memory
regions, VMOs, directories, devices, drivers, network interfaces, windows,
users, services, namespaces, endpoints, and the Linux-compat singletons. The
syscall surface dispatches through `ObjOps` method tables (`g_objOps`) rather
than `switch(file.type)` chains. A live boot holds a steady object population
(`[obj] live=39`) reconciled every 256 syscalls. Three milestones reached: MVOO,
Linux Compatibility Object, and a structurally Fully Object-Oriented OS.

### 🔐 Capability security model
*Roadmap: [`CAPABILITY_MODEL`](roadmap/CAPABILITY_MODEL.md) — ratified + implemented.*

- **19 rights bits** in a monotone lattice; every derived capability must be a
  bitwise subset of its parent (`capDerive` rejects escalation).
- **Transitive revocation** walks the derive-DAG to fixpoint — `[cap] revclosure PASS`.
- **Typed admin capabilities** (`ObjType.Admin`) gate mount/reboot/update/user/
  device/inspect. There is **no god-capability** and **no `uid==0` privilege
  predicate** — authority is split across distinct typed caps.
- **Unforgeable**: capabilities only come into existence via `capInstall` /
  `capDerive` against a live object; IPC passes them **by value** (`{objId,rights}`),
  never as raw pointers.
- Every fd is a capability; `requireCap` gates the fd surface; endpoint calls
  require `CAP_RIGHT_CALL`; namespace binds enforce binding rights; fork narrows.

### 🕸️ Object-Reference-Graph (ORG) + GC
*Roadmap: [`OBJECT_REFERENCE_GRAPH_ROADMAP`](roadmap/OBJECT_REFERENCE_GRAPH_ROADMAP.md) — all 12 phases implemented; design in [`ORG_ARCHITECTURE`](roadmap/ORG_ARCHITECTURE.md).*

A directed graph over the object model with five typed edge kinds
(`StrongOwn`, `StrongRef`, `Weak`, `Cap`, `Observer`). Features live in-kernel:

- **Online cycle prevention** at the `edgeAdd` chokepoint (bounded DFS) +
  iterative **Tarjan SCC** (no recursion → no kernel-stack blowup).
- **Mark-sweep GC** integrated with `free_phys_page`, with a complete root set
  that yields **zero false GC candidates** in production.
- **Validator daemon** (`core/org_validator.d`): budgeted epoch-driven state
  machine (Reach → SCC → Invariant → GC → Audit), quarantines invariant
  violations as `[org] SECURITY`.
- **8 invariants (I1–I8)** + **threat model (T1–T10)**; the canonical
  SCM_RIGHTS in-flight cycle is proven collectable.
- **DOT visualization** + the `orgctl` userspace tool (stats/dump/render/sccs).
- Live Linux fd/socket/epoll/SCM operations create real ORG edges.

### 🎭 Identity / security domains (Qubes without VMs)
*Roadmap: [`IDENTITY_DOMAIN_ROADMAP`](roadmap/IDENTITY_DOMAIN_ROADMAP.md) — M0–M2 complete.*

Every process belongs to a named, colored **identity**, inherited at fork and
immutable thereafter. Seven compiled-in domains: `System` (gray), `Personal`
(green), `Work` (blue), `Banking` (yellow), `Development` (purple), `Untrusted`
(red), `Disposable` (orange).

- **Per-identity namespaces** (`core/idns.d`): disjoint object roots with
  rule-gated, cap-wrapped cross-domain shares.
- **Deny-by-default cross-identity IPC**: both domains signed into the 50-byte
  session descriptor at broker issuance.
- **Unspoofable window borders**: `winRegister` stamps `identityObjId` +
  `identityColor` from the owning process — apps cannot supply them.

### 📁 Native object filesystem
*Roadmap: [`OBJECT_FILESYSTEM_ROADMAP`](roadmap/OBJECT_FILESYSTEM_ROADMAP.md) — F0–F5 done.*

A native root replaces the Linux-historical tree; POSIX paths are *generated
compatibility views*:

```
/objects   live kernel object views   (processes, identities, services, …)
/config    *.json rendered from kernel tables
/system    immutable base + generations
/state     logs · cache · sessions
/compat    /bin /sbin /usr /lib  →  Linux symlinks
```

- `/objects/<kind>/<obj>` directories render each object as fields: `meta`,
  `capabilities` (19 decoded bits), `relationships` (graph edges).
- **Persisted object store** (`core/objstore.d`, custom HOSOBJFS on a 32 MiB
  AHCI SATA disk): apps persist as `/objects/apps/<app>/{manifest, permissions,
  identity-binding, executable, storage}` — **verified surviving reboot**.
- **Capability-gated launch**: `execve` of `/objects/apps/<app>/executable` is
  intercepted and checked against the identity's rights ceiling (`hello`
  launches, `rogue` is denied with EPERM + audit).

### ⚙️ Declarative configuration
*Roadmap: [`DECLARATIVE_CONFIG_SPEC`](roadmap/DECLARATIVE_CONFIG_SPEC.md); tool in [`anonymos-config/`](anonymos-config/).*

"NixOS spirit, object-tree body." **One JSON file** is the single declarative
source of truth for the whole running system — services, identities, namespaces,
capabilities, mounts, IPC rules, GUI colors, storage, snapshots.

- **`anonymos-config`** — a host-side D+Phobos compiler with **8 stages**:
  parse → schema-validate (collect-all) → imports deep-merge → resolve refs →
  assign stable deterministic IDs → detect cycles (3-color DFS over 4 edge sets)
  → check capability subsets (escalation rejected at *compile* time) → lower to a
  `CompiledGraph`. Pure function `JSON → CompiledGraph ⊎ [Error]`.
- **CLI**: `check | build | diff | switch | rollback | graph | schema |
  emit-manifest`.
- **Content-addressed generations** (sha256 of canonical JSON) with atomic
  switch + parent-chain rollback; a module/import system.
- **Verified boot integration**: `emit-manifest` lowers the graph to a flat
  HMAC-SHA-256-signed TLV `manifest.blob`; the kernel (`core/configboot.d`)
  locates the boot module, HMAC-verifies it, and walks records calling the
  existing `serviceRegister` / `identityCreate` / `nsAlloc` / `genSetActive`
  APIs. Policy is authored outside the kernel; the kernel only *applies a
  verified, pre-compiled plan*. Missing/tampered manifest falls through safely.
- 87/87 host tests across 13 phases.

### 🔒 Secure IPC
*Roadmap: [`SECURE_IPC_ROADMAP`](roadmap/SECURE_IPC_ROADMAP.md) — all 5 phases implemented.*

Capability-gated channels where the **kernel holds no keys and does no crypto**
(`K1`). A privileged broker issues signed `SessionDescriptor`s; each endpoint
performs its own X25519 DH — keys never leave the process.

- **RFC-vector-proven** X25519 (RFC 7748), HKDF-SHA256 (RFC 5869),
  ChaCha20-Poly1305 AEAD (RFC 8439) in `core/libsecipc.d`.
- **SIGMA-style signed-DH** handshake, per-direction monotonic counter + 64-entry
  sliding replay window, downgrade resistance via signed transcript.
- **Lifecycle**: key rotation/rekey, epoch-bump revocation, fail-closed on
  auth-flood / counter exhaustion / peer death + zeroize.
- 6 proven invariants (K1–K6): forward secrecy, no (key,nonce) reuse,
  delegated-only authority. *Production wiring note:* broker/identity services
  run in-kernel today; relocating them to userspace is the remaining seam.

### 🗄️ Immutable store + A/B updates
*Roadmap: [`IMMUTABLE_ROOTLESS_ROADMAP`](roadmap/IMMUTABLE_ROOTLESS_ROADMAP.md) — Phases 1–9 done.*

- **Content-addressed store** (`core/store.d`): write-creates-never-mutates,
  de-duplicating, with a **dm-verity-style block hash tree**
  (`storeReadVerified` faults on a tampered block).
- **A/B slots** (`core/update.d`): inactive-only, capability-gated,
  signature-verified, anti-downgrade `updateApply`; boot-success counter +
  **auto-rollback**. Real HMAC-SHA-256 signatures.
- **Rootless**: PID1 starts as uid/gid 1000 with only mount/reboot/inspect admin
  caps. `getuid`/`geteuid`/`SO_PEERCRED` read the task's `User` object; no
  `uid==0` code path exists. *Honest caveat:* backing is RAM, not yet real disk
  for the system image; the "truly immutable on storage" bar is not yet met.

### 🖥️ Weston desktop
*Roadmaps: [`GUI_ROADMAP`](roadmap/GUI_ROADMAP.md), [`DESKTOP_RESPONSIVENESS_ROADMAP`](roadmap/DESKTOP_RESPONSIVENESS_ROADMAP.md).*

A pivot from Hyprland (2026-06-07) to **Weston 14.0 + Pixman software renderer** —
no OpenGL/Mesa dependency, which crashes in this freestanding/musl environment.

- Full desktop renders through a kernel **KMS** backend (ADDFB2/SETCRTC/
  PAGE_FLIP/universal planes), screenshot-verified (background + top panel +
  live clock).
- **Input**: visible, snappy mouse cursor — the kernel draws an 11×17 `left_ptr`
  sprite directly on the framebuffer, decoupled from Weston's repaint.
- **Input→present latency 8–14 ms** (was multi-second; root cause was
  `timerfd_settime` ignoring `TFD_TIMER_ABSTIME`).
- Desktop shell: persistent panel/menu bar, Cairo antialiased text, default
  wallpaper, decorated windows (drop shadow + titlebar + identity-accent dot +
  min/max/close + rounded corners), a Spotlight-style launcher (Super+Space),
  and a real Finder-style **file manager** (`wl-files`).
- Bundled assets: Noto fonts, icons, cursors, wallpapers, themes (license-guarded).

### 🐚 Shells & command set
*Roadmaps: [`ZSH_INTEGRATION_ROADMAP`](roadmap/ZSH_INTEGRATION_ROADMAP.md), [`SHELL_AND_COMMANDS_ROADMAP`](roadmap/SHELL_AND_COMMANDS_ROADMAP.md).*

- **Real upstream Z Shell 5.9** — vendored + built both static and dynamic (PIE
  exe + 36 dlopen-able zmodules) against musl. The default Linux shell: ZLE
  editing, tab completion, history, pipes, `^C`, job control. Termios line
  discipline + VT/CSI interpreter added so ZLE redraw works.
- **Native-ABI zsh port (Z4)**: the same zsh, filesystem (`object_open`),
  terminal I/O (`device_read`/`device_write`), and external-command spawn
  (`spawn_process`) all flow through the **native object ABI** at a working
  prompt. Z4a fully done; Z4b/Z4c largely done.
- **`shell.json` declarative config** (Z5): a pure-zsh translator
  (`__hos_apply_shell_json`) applies system → user → user-zshrc at startup. The
  **four-field prompt** `[domain] user [perms]:cwd` is live in every shell.
- **`hos-sh`** (`src/util/hos-sh.d`) — the native object shell in D; drives the
  kernel model via `syscall(0x4000, …)`. Reads LFE s-expression forms:
  `(obj)`, `(id)`, `(ns)`, `(svc)`, `(whoami)`.
- **`esh`** — a from-scratch D Unix shell with ~94 applets (awk, ls, cp, grep,
  find, dd, …) and an LFE REPL.
- **BusyBox 1.36.1** — 381 applets on a hardened FHS tmpfs, fully interactive
  (multi-command, pipelines, `vi`, `^C`, job control).

### 🔑 Cryptography
*Roadmap: [`IMMUTABLE_ROOTLESS_ROADMAP`](roadmap/IMMUTABLE_ROOTLESS_ROADMAP.md) §8.*

Real **SHA-256** and **HMAC-SHA-256** (`core/crypto.d`), proven against NIST /
RFC test vectors — used by the content store, A/B signatures, config manifest,
and secure IPC. A PCR-like measurement register + signed module manifest + an
audit log of capability use (~466k decisions on a live boot). *Ed25519
asymmetric signing is pending (HMAC stand-in today).*

### 🌐 Networking
A complete in-kernel network stack: Ethernet, ARP, IPv4/IPv6, ICMP/ICMPv6, TCP,
UDP, DNS, DHCP, HTTP, HTTPS, TLS — plus VirtIO and VeraCrypt driver stubs.

---

## Build & run

The kernel is **D + x86_64 assembly** (`-betterC`, no GC/druntime), built with
LDC2 and linked with a custom `linker.ld`. The old Haskell kernel has been
migrated to D (`kernel_main.d` opens with *"D replacement for the Haskell
kernel"*); Haskell now survives only as userspace services and the jhc RTS.

```sh
# Full build (serialized/low-resource by default; memory-heavy dep builds)
make                        # → kernel.elf + busybox + Wayland utils + hos.iso

# Declarative config tool (host toolchain, needs ldc2 + Phobos)
make anonymos-config        # or: make -C anonymos-config
make anonymos-config-test   # 87/87 host tests

# Emit + sign the verified boot manifest, then build the ISO
anonymos-config/build/anonymos-config emit-manifest -o manifest.blob \
    anonymos-config/examples/system.json
make hos.iso

# Run (Linux host, KVM)
./qemu-run.sh

# Run (macOS / Apple Silicon — TCG software emulation, no /dev/kvm)
./qemu-run-mac.sh              # native cocoa window + serial.log
./qemu-run-mac.sh --serial     # serial console in the terminal
./qemu-run-mac.sh --vnc        # headless + VNC on :0

# Verify the declarative config applied at boot (greps serial for the marker)
./scripts/qemu-config-verify.sh
```

Containerized builds: `Dockerfile` + `build-in-docker.sh`; host prep via
`setup_host.sh`. Builds require the Docker/Linux cross-toolchain; the ISO +
QEMU boot gate is not reproducible on macOS alone.

### Useful targets

| Target | Builds |
|--------|--------|
| `make` / `make all` | `kernel.elf` → `hos.iso` |
| `make build/libkernel_d.a` | the D kernel archive |
| `make zsh` | static + dynamic upstream zsh 5.9 |
| `make anonymos-config` | the declarative-config compiler CLI |
| `make build-config-manifest` | signed `manifest.blob` |
| `make progs-haskell` | Haskell userspace services |
| `make build-gui-assets` | fonts/icons/cursors/wallpapers blobs |

---

## Repository layout

```
src/
├── boot/            Limine config + BIOS/UEFI binaries (SYSLINUX/GRUB fallbacks)
├── kernel/d/        THE KERNEL — D + x86_64 asm
│   ├── arch/x86_64/ gdt, idt, paging, context switch, bootstrap
│   ├── core/        ~60 subsystem .d files + syscalls/  (objmgr, cap, org,
│   │                ipc, identity, namespace, store, update, servicemgr,
│   │                crypto, secipc, configboot, …)
│   ├── display/     compositor, framebuffer, freetype/harfbuzz, wayland server
│   ├── drivers/     ahci, drm, virtio_gpu, hid, pci, network
│   ├── memory/      paging, physmem, dma
│   └── network/     ethernet → tls full stack
├── libs/            Haskell RTS (jhc) + D userland glue + vendored containers
├── progs/           esh D-shell, Haskell userspace services (init/storage/pci/ata)
├── util/            userspace tools: hos-sh, wl-term, wl-files, wl-domain-manager,
│                    store-app, idle, hello-gui, compositor, …
└── test-dyn/        dynamic-linker verification harness
anonymos-config/     declarative-config compiler (D + Phobos) + examples + tests
cd/                  staged boot image contents (kernel modules, GUI, shells)
deps/                busybox, musl, zsh, weston, hyprland, gtk-stack, …
docs/                SYSCALL_ABI · NATIVE_OBJECT_ABI · FILESYSTEM · NAMESPACING
roadmap/             the feature roadmaps this README is grounded in
scripts/             qemu-*-verify harnesses + asset packers + orgctl
```

---

## Honesty: what is *not* yet done

anonymOS is honest about its gaps (each roadmap names them):

- **Memory hardening** ([`SECURITY_ROADMAP`](roadmap/SECURITY_ROADMAP.md)) — W^X
  is partial (enforced on `mprotect` tighten; the inline mmap path still maps
  W+X for ld.so relocation); **no ASLR**, no NX stack, no guard pages, no stack
  canaries, SMAP/SMEP disabled in QEMU. This is the headline remaining work.
- **Truly immutable image on real storage** — the content store is RAM-backed
  today; real disk-backed verification + physical `/var` separation pending.
- **Ed25519 + Limine verified boot** — HMAC stand-in today.
- **Kernel-mode IRQ handling** ([`DESKTOP_RESPONSIVENESS`](roadmap/DESKTOP_RESPONSIVENESS_ROADMAP.md))
  — IRQs caught only in userspace; the scheduler is **cooperative** (no
  preemption), single-core, polled. This blocks true `hlt`-idle, SMP, and
  preemption.
- **GPU compositing** — Weston composites every pixel on CPU (Pixman); virtio-gpu
  + Mesa (R8) pending.
- **Userspace relocation** of Wayland/DRM/fs into user-space servers — the
  in-kernel services work but are not yet demoted (the "honestly rootless"
  finish line).
- **ratty Rust/GPU terminal** — blocked on a Rust musl toolchain + GPU stack.
- **Disposable identities, brokers, signed identity policy** (Identity M3/M4);
  **zsh theme/plugin/secure-history/login flow** (Z7–Z12); **desktop settings
  app, animations, multi-window workspaces** (G18–G21).

---

## Design influences

anonymOS synthesizes several traditions:

- **seL4 / Genode** — capability-based authority, no ambient privilege.
- **Plan 9** — per-process namespaces; the `/objects` live-view tree.
- **Qubes OS** — security domains — but **without VMs**, via identities +
  namespaces + capability labels.
- **NixOS** — declarative single-source-of-truth configuration + generations.
- **Silverblue / ChromeOS / AVB** — immutable content-addressed store, A/B
  updates, dm-verity, anti-rollback index.

See [`ORG_ARCHITECTURE`](roadmap/ORG_ARCHITECTURE.md) for the threat model and
[`DECLARATIVE_CONFIG_SPEC`](roadmap/DECLARATIVE_CONFIG_SPEC.md) for the config
philosophy.

## License

See individual files; vendored third-party components under `deps/` retain their
upstream licenses (busybox GPLv2, musl MIT, zsh ISC-style, Weston MIT, etc.).
