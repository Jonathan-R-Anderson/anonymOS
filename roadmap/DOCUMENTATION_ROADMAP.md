# Documentation Roadmap

Goal: a complete, **source-grounded** reference for EpinAnonymOS — how the kernel
presents itself to userspace (the Linux ABI + the native object ABI), how the
filesystem is layered and resolved, how namespacing/identity/capabilities gate
access, and how the system boots, schedules, and is built/tested.

Each doc lives under `docs/` and is verified against the code (file:line references),
not invented. This roadmap is the index + the plan; the ✅ docs already exist.

Legend: **P** priority · **E** effort (1=hrs … 5=weeks) · status. Source of truth is
always the code — when a doc and the code disagree, the code wins; fix the doc.

---

## D4 — Identity & capability model · ☐ docs/IDENTITY_AND_CAPABILITIES.md · P: High · E: 3 · deps: D3

The security spine: identity domains (System/Personal/Work/Banking/Development/
Disposable/Untrusted), `rightsCeiling`, the 19 `CAP_RIGHT_*` bits, per-fd capabilities,
typed admin caps, identity transitions + launch rules, the cap-gate on app launch
(F4.2). Sources: `core/cap.d`, `core/identity.d`, `core/admin.d`, `core/idproc.d`.
*(roadmap/CAPABILITY_MODEL.md + IDENTITY_DOMAIN_ROADMAP.md already cover the design;
this doc is the user-facing how-it-works distilled from them + the code.)*

## D5 — Object model & reference graph · ☐ docs/OBJECT_MODEL.md · P: Med · E: 3 · deps: D4

`ObjType` (File/Process/Identity/Service/Namespace/Capability/Endpoint/…), `g_objects`,
per-fd Object mirroring, the typed-edge ORG reference graph + GC. How `/objects/*`
(D2) is a live view over these tables. Sources: `core/objmgr.d`, the ORG roadmaps.

## D6 — IPC & services · ☐ docs/IPC_AND_SERVICES.md · P: Med · E: 3 · deps: D4

Endpoints + service registration (rights-narrowing), the secure-IPC channel
(X25519/HKDF/ChaCha20-Poly1305), cross-identity IPC policy (same-domain allow /
cross deny / brokered), the AF_UNIX/socketpair Linux-compat path. Sources:
`core/servicemgr.d`, `core/secipc.d`, `core/idipc.d`, SECURE_IPC_ROADMAP.md.

## D7 — Boot, memory & scheduling · ☐ docs/BOOT_MEMORY_SCHED.md · P: Med · E: 3

Limine handoff (HHDM, modules), the physical allocator + free list (`mm.d`), address
spaces + CoW fork (`addrspace.d`), the cooperative single-core scheduler, signals, and
the "no kernel-mode IRQ" model (polled drivers, can't HLT-idle). Sources: `core/kmain.d`,
`memory/mm.d`, `core/addrspace.d`, `core/task.d`.

## D8 — Persistence & disk · ☐ docs/PERSISTENCE.md · P: Med · E: 2 · deps: D2

The AHCI SATA driver (HHDM phys/virt model, `GHC.AE`, polled), the block layer
(`disk.d`), and the on-disk object-store format (superblock + app directory + blob
region; `objstore.d`). How `/objects/apps` survives reboot. Cross-links D2.

## D9 — Drivers & display · ☐ docs/DRIVERS_AND_DISPLAY.md · P: Low · E: 3

PCI enumeration, input (USB-HID / PS2 / evdev shim), the framebuffer + KMS/DRM shim,
the kernel overlay cursor, and the Weston/Pixman desktop bring-up. Sources:
`drivers/`, `display/`, GUI_ROADMAP.md, weston-pivot notes.

## D10 — Build, run & test · ☐ docs/BUILD_AND_TEST.md · P: Med · E: 2

The build graph (the D-lib rebuild gotcha: `make -C src/kernel/d` first), the boot
modules + limine.conf, `make hos.iso` / `qemu-run.sh` (incl. the persistent SATA disk),
and the headless QMP screenshot test harness. Sources: `Makefile`, `qemu-run.sh`.

---

## Conventions for these docs

- **Grounded:** every nontrivial claim cites a source file (and line where stable).
- **ABI tables are generated-from-truth:** the syscall list mirrors the dispatcher; if a
  case is added/removed in `dispatchSyscall`, update [docs/SYSCALL_ABI.md](../docs/SYSCALL_ABI.md).
- **EpinAnonymOS-specific behaviour is flagged** (⚠) wherever the OS deviates from stock
  Linux semantics (e.g. `getpgid`/`getpgrp` return a constant 1; `mount` is a no-op view).
- Design rationale lives in the topic roadmaps (`roadmap/*_ROADMAP.md`); these `docs/` are
  the *how it actually works today* reference.

## Order

D1 ✅ → D2 ✅ → D3 ✅ (the three the brief named) → D4 → D5 → D6 → D7 → D8 → D9 → D10.
