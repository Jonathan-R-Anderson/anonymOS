# anonymOS

[![Discord](https://img.shields.io/badge/Discord-Join%20the%20community-5865F2?logo=discord&logoColor=white)](https://discord.gg/bDRHfBCcBN)

💬 **Join the community on Discord:** [discord.gg/bDRHfBCcBN](https://discord.gg/bDRHfBCcBN)

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
| Domain Manager — cloneable domains: restricted FS, device/peripheral gates, cap-gated packages, per-domain Linux distros, signed exportable templates + inheritance, full tabbed GUI | ✅ | [`domain_manager`](roadmap/domain_manager.md) |
| Native object filesystem (`/objects`, `/config`, `/system`) | ✅ | [`OBJECT_FILESYSTEM_ROADMAP`](roadmap/OBJECT_FILESYSTEM_ROADMAP.md) |
| Declarative config compiler + verified-config boot | ✅ | [`DECLARATIVE_CONFIG_SPEC`](roadmap/DECLARATIVE_CONFIG_SPEC.md) / [`anonymos-config/`](anonymos-config/) |
| Secure IPC (X25519 / HKDF / ChaCha20-Poly1305) | ✅ | [`SECURE_IPC_ROADMAP`](roadmap/SECURE_IPC_ROADMAP.md) |
| Immutable store + A/B updates + rollback | ✅ | [`IMMUTABLE_ROOTLESS_ROADMAP`](roadmap/IMMUTABLE_ROOTLESS_ROADMAP.md) |
| Rootless administration (no UID 0) | ✅ | [`IMMUTABLE_ROOTLESS_ROADMAP`](roadmap/IMMUTABLE_ROOTLESS_ROADMAP.md) |
| Weston 14 desktop (Pixman software renderer) | ✅ | [`GUI_ROADMAP`](roadmap/GUI_ROADMAP.md) / [`DESKTOP_RESPONSIVENESS_ROADMAP`](roadmap/DESKTOP_RESPONSIVENESS_ROADMAP.md) |
| Real Z Shell (Linux + native-ABI port) | ✅ | [`ZSH_INTEGRATION_ROADMAP`](roadmap/ZSH_INTEGRATION_ROADMAP.md) |
| Shell & command set (`hos-sh`, `esh`, busybox 381 applets) | ✅ | [`SHELL_AND_COMMANDS_ROADMAP`](roadmap/SHELL_AND_COMMANDS_ROADMAP.md) |
| Memory-safety hardening (W^X, ASLR, NX stack) | 🚧 | [`SECURITY_ROADMAP`](roadmap/SECURITY_ROADMAP.md) |
| SMP / multi-core — a secondary core runs a **preemptible userspace task in parallel** with the desktop (BKL + per-CPU APIC timer + cross-CPU IPIs) | 🚧 | [`SMP_ROADMAP`](roadmap/SMP_ROADMAP.md) |
| TCP/IP network stack + I2P P2P template marketplace — **NIC + Ethernet/ARP up (box is on the network); IPv4/ICMP/UDP/DHCP TX proven; RX blocked on a real network** | 🚧 | [`NETWORK_AND_MARKETPLACE_ROADMAP`](roadmap/NETWORK_AND_MARKETPLACE_ROADMAP.md) |
| Disk installer + **hidden/decoy-OS disk encryption** — install a second OS in a deeper encryption layer for plausible deniability (VeraCrypt-derived, an *optional* install step). **Proven: GPT + FAT32 ESP partition engine (host `sgdisk`/`fsck.fat`-validated); the stripped VeraCrypt crypto core cross-builds + passes NIST AES-256/SHA-512 KATs.** Full encrypted hidden-OS install + EFI pre-boot auth in progress | 🚧 | [`INSTALLER`](roadmap/INSTALLER.md) |
| **Blockchain-anchored boot integrity** (zkSync anti-rootkit) — at boot, verify the `/system` file hashes against a Merkle root published to a zkSync Era smart contract; anchored *off-machine* so a rootkit that rewrites local files (and the local manifest) still can't forge it, and re-published on every system update. *Optional* step. Specified (F0–F7); gated on the network stack (RX) + a Wi-Fi path, contract yet to be written | 🔵 | [`INSTALLER`](roadmap/INSTALLER.md) |
| **Perlin-noise decoy histories** — deterministic, lazily-generated fake system activity (logs, processes, users, services, network, security/audit events) so a plausible-deniability decoy environment looks lived-in. The fake universe is a pure function of `seed = KDF(password)` — never stored, so it's reboot-deterministic and snapshot-trivial. **Boot-required** via a honey-hashed, **typo-tolerant** matcher: a password close to a decoy boots that decoy's universe; anything else is rejected. Specified (G1–G6) | 🔵 | [`INSTALLER`](roadmap/INSTALLER.md) |
| **Linux decoy OS + concealed activity synthesis** — the decoy OS is a *real Linux distribution* (most believable); the fake history is produced *inside* it by a concealed program (the Linux port of the Perlin generator), a full-disk-illusion block driver hides the hidden volume's space from the decoy, and the generator is concealed from the decoy's root user. Plausible-deniability / anti-coercion on the user's own decoy (VeraCrypt-Hidden-OS threat model); the security review treats *detectability of the concealment itself* as the primary risk. Specified (H1–H5) | 🔵 | [`INSTALLER`](roadmap/INSTALLER.md) |

---

## Architecture at a glance

```
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │   system.json  — one declarative source of truth for the whole system          │
  │   anonymos-config compiler (host, D)  →  manifest.blob (HMAC-signed TLV)        │
  └───────────────────────────────────────┬────────────────────────────────────────┘
                                           │ verified at boot
  ┌────────────────────────────────────────▼───────────────────────────────────────┐
  │ BOOT   Limine → [ optional §E pre-boot auth (UEFI .efi): password →             │
  │                  DECOY | HIDDEN, decrypt + chain-load the chosen OS ] → kernel    │
  └────────────────────────────────────────┬───────────────────────────────────────┘
                                           │
  ┌────────────────────────────────────────▼───────────────────────────────────────┐
  │ anonymOS kernel   (D · -betterC · no GC)   x86_64 · SMP (preemptive, N cores)     │
  │   ┌──────────────────────── 6 native pillars ────────────────────────┐           │
  │   │ Scheduler · Object Mgr · Capability Mgr · IPC · Memory · HAL      │           │
  │   └───────────────────────────────────────────────────────────────────┘          │
  │   Linux personality (~160 syscalls)  ║  Native object ABI 0x4000 (deny-by-default)│
  │   rootless (no uid 0) · W^X/ASLR · X25519 + ChaCha20-Poly1305 secure IPC          │
  └──────────┬─────────────────────────────────────────────────────────┬────────────┘
             │                                                          │
  ┌──────────▼──────────────── object model ─────────────────┐  ┌──────▼────────────────┐
  │ Object-Reference-Graph · cap rights/derive/revoke · GC    │  │ Identity / security    │
  │ Object FS:  /objects · /config · /system  (immutable)     │  │ domains (Qubes-style)  │
  │ A/B updates + rollback                                    │  │ + Domain Manager (clone)│
  └──────────┬───────────────────────────────────────────────┘  └──────┬────────────────┘
             │                                                          │
  ┌──────────▼───────────────────────┐              ┌──────────────────▼────────────────┐
  │ Linux userland                    │              │ Native userland                    │
  │ busybox · zsh · Weston desktop    │              │ hos-sh · esh · LFE (object shell)  │
  │ (GPU: virgl/GL or Pixman) · GTK   │              │ gl-term / ratty terminals          │
  └──────────┬───────────────────────┘              └────────────────────────────────────┘
             │
  ┌──────────▼──────────────── hardware / persistence ──────────────────────────────────┐
  │ AHCI SATA → on-disk object store (persists across reboot) · e1000 NIC (Ethernet/ARP) │
  │ virtio-gpu / virgl (host GPU) · LKL bridge → reuse real Linux drivers on bare metal   │
  └──────────────────────────────────────────────────────────────────────────────────────┘

  ╔════════════ Installer + plausible deniability  (🚧 roadmap/INSTALLER.md) ════════════╗
  ║ Calamares (static Qt) + native GPT/ESP partition engine (rootless, no libparted)      ║
  ║ §E Hidden-OS encryption — VeraCrypt-derived AES/Serpent/Twofish-XTS, decoy + hidden    ║
  ║    volumes, cap-gated 3-partition install, UEFI pre-boot loader (top of diagram)       ║
  ║ §G Perlin decoy generator — deterministic fake logs/procs/net/security, keyed per pwd  ║
  ║ §H Linux decoy OS + concealed synthesis   ·   §F zkSync blockchain boot integrity      ║
  ╚════════════════════════════════════════════════════════════════════════════════════════╝
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

### 🏛️ Domain Manager (cloneable OS-environment domains)
*Roadmap: [`domain_manager`](roadmap/domain_manager.md) — DM0–DM12 complete (to the feasible substrate).*

A **domain** is a first-class, persistent, cloneable object — a complete reusable OS
environment blending Qubes templates, Docker images, NixOS modules, and immutable
snapshots, all on the identity/capability/namespace/object-store substrate. Declared in
`system.json`, every domain is driven from the data, not hardcoded:

- **Restricted, deny-by-default filesystem** (`core/namespace.d`): each domain sees only
  its granted paths (`/objects/domains/<name>/filesystem` is the resolved RuntimeView);
  real host paths can be granted/denied at runtime (`fsro`/`fsrw`/`fsdeny`).
- **Lifecycle + content-addressed CoW overlays**: start/stop/pause/snapshot/commit/clone;
  commit folds into a *new* immutable base (the old one is never mutated). Persists across
  reboot.
- **Peripheral device gates** (`§7` device classes): per-domain GPU / camera / mic / audio /
  USB / input toggles enforced at `open()` — a `usb:false` domain physically cannot open
  the node.
- **Cap-gated package manager** + per-domain **Linux distros** (BusyBox/Nix/Alpine, a RO
  `/linux` compat root) + package profiles.
- **Signed exportable templates** (`.hosdt`, HMAC-signed): export/import/verify/trust/
  rollback, with **least-privilege inheritance** (a child template can only narrow its
  parent's access, never escalate).
- **Full tabbed GUI** (`util/wl-domain-manager.c`): a Wayland client with Overview /
  Filesystem / Packages / Network / Permissions / Startup / Appearance tabs — every feature
  above is clickable and writes back through `/config/domain.action`.

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
  terminal I/O (`device_read`/`device_write`), external-command spawn
  (`spawn_process`), child-wait, event subscription, the cap-grant/namespace
  mutation verbs, and an in-process `zsh/anonymos` builtin module all flow
  through the **native object ABI** at a working prompt. **Z4 fully done.**
- **`shell.json` declarative config** (Z5): a pure-zsh translator
  (`__hos_apply_shell_json`) applies system → user → user-zshrc at startup. The
  **four-field prompt** `[domain] user [perms]:cwd` is live in every shell.
- **`hos-sh`** (`src/util/hos-sh.d`) — the native object shell in D, the `-sh`
  (LFE) bootstrap; drives the kernel model via `syscall(0x4000, …)`. **Evaluates**
  LFE s-expressions to data (L2): object-ABI verbs are composable functions —
  `(obj)`/`(ns)`/`(id)`, `(ns-enter (ns-clone))`, `(cap-grant h r)`, `(+ 1 (* 2 3))`.
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
*Roadmap: [`NETWORK_AND_MARKETPLACE_ROADMAP`](roadmap/NETWORK_AND_MARKETPLACE_ROADMAP.md) — in progress.*

**Working today:** AF_UNIX sockets (`syscalls/posix.d` — the full BSD-socket shape:
`socket`/`bind`/`listen`/`accept`/`connect`/`send`/`recv` + poll/epoll), used by
Weston/Wayland and IPC. And, behind a `NET=1` boot gate, the **box is on the network**:
the **e1000 driver is up** (`drivers/network/network.d` — MMIO via the HHDM, bus-master
DMA, MAC read, rx/tx rings) and **Ethernet + ARP work end-to-end** — a frame round-trips
and the gateway MAC resolves (verified: `who-has 10.0.2.2` → slirp reply → ARP resolved).
The IPv4 / ICMP / UDP / DNS / **DHCP** *transmit* paths are all proven correct on the wire
(pcap shows a well-formed ICMP echo, a DNS `A?` query, and a textbook 552-byte DHCP
DISCOVER). The default boot stays `-nic none`, so the desktop is never at risk.

**⚠️ Current blocker — the receive path can't be verified in this sandbox:** the inbound
IPv4 dispatch (IP-header parse → per-protocol demux) runs in code but cannot be proven
end-to-end here, because the test host's QEMU **slirp replies *only* to ARP** — ICMP is
host-disabled (`/proc/sys/net/ipv4/ping_group_range = 1 0`), DNS has no upstream internet,
and even slirp's *internal* DHCP server stays silent. ARP is the one service slirp answers
with no host interaction, so the Ethernet RX *is* proven but the IP RX is not. **Unblocking
it needs a real NIC, a tap device, or a non-sandboxed host** — then TCP (which depends on a
SYN-ACK arriving), AF_INET behind the existing socket syscalls (today `connect` rejects
`AF_INET`), per-domain `NetPolicy` enforcement at `connect()`, and the **I2P P2P template
marketplace** on top can be built and verified. *(N0 NIC + N1 ARP done; N2/N3/N6 TX proven;
N2+ RX gated on an RX-capable network environment.)*

### ⚙️ SMP / multi-core
*Roadmap: [`SMP_ROADMAP`](roadmap/SMP_ROADMAP.md) — in progress.*

The kernel was written single-threaded; SMP is being brought up in verified, one-commit
increments, the BSP's working desktop path protected at every step (each phase boot-verified
`SMP=N` with the desktop still loading its 11 domains, 0 faults, and `SMP=1` degrading
gracefully).

**Working today — a secondary core (AP) runs a *preemptible userspace task in parallel* with
the desktop:**
- **Dynamic discovery + bringup** (S0–S1) — the kernel reads the live core count from the
  Limine SMP request (never a hardcoded number) and brings every AP online.
- **Per-CPU state + Big Kernel Lock** (S2–S3) — each CPU has a GS-addressed per-CPU area; a
  cross-core-proven BKL is taken across the kernel-handling portion of the run loop (released
  only around the userspace run), so the BSP and an AP are mutually excluded *in the kernel*
  while running userspace in true parallel.
- **An AP runs a real task** (S4) — a secondary core `iret`s into ring 3 through its own
  per-CPU entry path (GDT/TSS/IST, IDT, syscall MSRs — the BSP's `context.S` stays untouched),
  runs a userspace stub that issues real `getpid` syscalls dispatched through the *shared*
  handler under the BKL, all concurrently with the desktop — and the task is **pinned** to its
  core.
- **Preemption** (S5) — each AP enables x2APIC and runs its own local-APIC timer, so its task
  is preemptible (interrupts on, the timer fires and is handled on the AP's own stack).
- **Cross-CPU IPIs** (S7) — the BSP sends inter-processor interrupts (x2APIC ICR) that the AP
  handles, with a TLB-shootdown action.
- **Fine-grained locking, first slice** (S6) — the page allocator has its own leaf lock, so a
  core can allocate without holding the BKL.

What is **not** finished (the per-CPU run-queue/balancer, the full per-subsystem lock split,
and running a real per-device LKL on a pinned core) is detailed under
[Honesty: what is *not* yet done](#honesty-what-is-not-yet-done).

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
- **Kernel-mode IRQ handling on the boot CPU** ([`DESKTOP_RESPONSIVENESS`](roadmap/DESKTOP_RESPONSIVENESS_ROADMAP.md))
  — on the BSP, hardware IRQs are caught in userspace (the run loop returns on the
  PIC IRQ) and its scheduler is **PIC-driven + cooperative**, polled — so the BSP
  still can't true-`hlt`-idle. (Secondary cores **do** now have real per-CPU
  **local-APIC** IRQ handling — timer + IPIs — see the SMP section; the BSP's PIC
  path is the part that remains.)
- **GPU acceleration — kernel path done; guest GL renders, but on the CPU not yet
  the GPU** ([`ZSH_INTEGRATION_ROADMAP`](roadmap/ZSH_INTEGRATION_ROADMAP.md) R2).
  What works: the kernel drives the virtio-gpu **virgl** 3D pipeline end-to-end and
  renders on the *host* GPU (context → 3D resource → `SUBMIT_3D` clear →
  `TRANSFER_FROM_HOST` readback = red), exposed to userspace through a
  `/dev/dri/renderD128` **virtgpu DRM ioctl uABI** (GETPARAM/GET_CAPS/RESOURCE_CREATE/
  MAP/EXECBUFFER/TRANSFER/WAIT/GEM_CLOSE); **Mesa is built with the virgl driver** and
  a real **GLES2 program renders in the guest** (`glClear`→`glReadPixels` = red — the
  *dual-glapi* blocker is fixed by shipping a shared `libglapi.so`). **What is NOT
  finished:** guest GL apps currently run on **softpipe (CPU)**, not virgl (GPU) —
  Mesa's gbm-on-render-node path falls back to swrast because the host's `egl-headless`
  display **can't export fence sync fds**, so virgl's GLES screen-create fails over to
  softpipe. Finishing GPU acceleration needs (a) the Mesa driver override
  (`MESA_LOADER_DRIVER_OVERRIDE=virtio_gpu`) passed at process *launch* via the kernel's
  `envp` (an in-app `setenv` is read too late), and (b) a working fence-export path —
  likely a real-display QEMU config (`-display gtk,gl=on`/`sdl,gl=on`) instead of
  `egl-headless`. Weston itself still composites on CPU (Pixman) until then.
- **Userspace relocation** of Wayland/DRM/fs into user-space servers — the
  in-kernel services work but are not yet demoted (the "honestly rootless"
  finish line).
- **ratty Rust/GPU terminal** (R3) — the GPU stack now renders guest GL (on softpipe
  until virgl-as-renderer lands, above); the CPU intermediate `hos-term` ships today.
  Porting upstream [ratty](https://github.com/orhun/ratty) needs a Rust **crate**
  toolchain (cargo + crates.io for `wgpu`/winit/etc., beyond R0's single-`rustc`
  no-crates build) and its `wgpu` GLES backend wired to the guest Mesa GL above.
- **Full LFE native shell `-sh`** ([`ZSH_INTEGRATION_ROADMAP`](roadmap/ZSH_INTEGRATION_ROADMAP.md),
  L-series) — the native-personality Lisp shell is up to **L2**: a `-betterC` D evaluator in
  `hos-sh` where object-ABI verbs are *composable* LFE functions (`(ns-enter (ns-clone))`,
  `(+ 1 (* 2 3))`). The **full** upstream `-sh` — the complete LFE language (tuples/maps,
  `defun`/`let`, pattern matching, macros — **L3**) and the capability/namespace/identity forms
  (**L4**) — is gated on **toolchain work**, because upstream `-sh` is *full-D* (Phobos/druntime)
  while only `-betterC` D builds for the OS today:
  - a **musl-targeted D runtime** — build `druntime` + Phobos + the LLVM unwinder (`libunwind`)
    for the OS's musl target so `ldc2` can link a full-D **static** binary (today
    `ldc2 -mtriple=x86_64-linux-musl` on a full-D program fails with `cannot find -lunwind`, and
    no musl druntime/Phobos is present). This is the analogue of the musl **C** toolchain that
    already builds zsh/busybox.
  - a **`libreadline` replacement** — upstream `-sh` links readline for line editing; wire its
    input to the OS PTY line discipline instead (the `hos-sh`/`fgets` path, or a vendored
    linenoise), since the OS ships no readline.
  Until that lands `-sh` runs on the betterC evaluator; **L5** (the Domain Manager's *native
  (-sh/LFE)* shell option) can ship on that, but the full language + rich forms need the runtime
  port. The vendored upstream source + this decision live in [`deps/lfe-sh/`](deps/lfe-sh/VENDOR.md).
- **Functional TCP/IP + P2P marketplace — partial**
  ([`NETWORK_AND_MARKETPLACE_ROADMAP`](roadmap/NETWORK_AND_MARKETPLACE_ROADMAP.md)).
  **Done + verified:** the e1000 NIC driver is up and **Ethernet + ARP work end-to-end**
  (a frame round-trips; the gateway MAC resolves) — the box is on the network behind a
  `NET=1` gate. The IPv4 / ICMP / UDP / DNS / DHCP **transmit** paths are all proven
  correct on the wire. **Not done — the receive path is blocked on the test environment:**
  this sandbox's QEMU slirp answers *only* ARP (ICMP host-disabled, DNS no upstream, DHCP
  silent), so the inbound IPv4 dispatch can't be proven here — it needs a real NIC / a tap
  device / a non-sandboxed host. Until RX is verified, **TCP** (which needs a SYN-ACK to
  arrive), **AF_INET** behind the socket syscalls (today `connect` rejects `AF_INET`),
  per-domain `NetPolicy` enforcement, and the **I2P P2P template marketplace** (DM12 §8–17)
  remain unbuilt. The marketplace's *offline* signed-bundle half
  (export/import/verify/trust/rollback) **is** done.
- **SMP / multi-core — partial** ([`SMP_ROADMAP`](roadmap/SMP_ROADMAP.md)). **Done + verified:**
  dynamic core discovery, AP bringup, per-CPU state, the Big Kernel Lock (wired into the run
  loop), an AP running a *preemptible userspace task in parallel* with the desktop, per-CPU
  local-APIC timer preemption, and cross-CPU IPIs + TLB-shootdown (see the SMP section above).
  **Not done yet — the three long-tail / integration pieces I did *not* implement:**
  - **A real per-CPU scheduler** (S4 remainder) — the AP today runs *one* hard-pinned task; per-CPU
    run queues + a load balancer + work-stealing so a core picks from *multiple* tasks are not done.
  - **Full fine-grained locking** (S6 remainder) — only the page allocator is split out of the BKL;
    object/cap tables, fd tables, namespace tables, and scheduler queues are still all under the one
    Big Kernel Lock. Replacing it per-subsystem (each with a lock-order audit, driven by profiling)
    is the explicit long game.
  - **Real per-device LKLs on dedicated cores** (S8 remainder) — the pinning + SMP-safe-device-cap
    *mechanisms* exist, but actually running usb-lkl / gpu-lkl / net-lkl each on its own core (the
    production payoff) needs the bare-metal-LKL bring-up to run on an AP — a separate integration.
  - The AP task also still uses a **disjoint** address space and runs **without `swapgs`** (single
    active AP); multiple APs running real tasks would need `swapgs` + per-CPU entry buffers
    generalized to the full core count, and automatic TLB shootdown wired into `fork`/`mmap`/`munmap`.
- **Domain Manager substrate limits** ([`domain_manager`](roadmap/domain_manager.md)) —
  network/clipboard *runtime* gates (need the stack above / Weston hooks) and on-disk
  per-distro Linux roots remain; the device/fs/package/template core is done + verified.
- **Disposable identities, brokers, signed identity policy** (Identity M3/M4);
  **desktop settings app, animations, multi-window workspaces** (G18–G21).

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
