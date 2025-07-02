# AnonymOS — House Rules (v2025‑07‑01)

These guidelines codify **how we work on AnonymOS**, a micro‑kernel & experimental user‑space written in **D** with a sprinkling of x86 assembly.  They supersede the generic Cursor rules and are tightly coupled to the concrete repository you shared.

---

## 0. Top‑Level Repository Layout

```
/        ┐
│ build/         – all *generated* artifacts (never hand‑edit)
│ ├── anonymOS.iso      final bootable ISO (CI artifact)
│ ├── kernel.bin        ELF-bootable kernel
│ ├── fs.img            root FS for tests
│ └── obj/              object files mirror kernel tree
│ docs/         – design notes, specs & public docs
│ etc/          – system configuration blobs (e.g. shadow)
│ hypervisor/   – micro‑hypervisor companion (builds to build/hypervisor)
│ kernel/       – **source** for the micro‑kernel (see §1)
│ modules/      – loadable or out‑of‑tree components (e.g. distributed‑fs)
│ object-tree/  – user‑space object‑capability helpers
│ scripts/      – bash helpers for building & dev‑env
│ third_party/  – vendored projects (dmd, druntime, …) → read‑only
│ Makefile      – single entry‑point; wraps `dub`, `ldc`, `nasm`, etc.
└ LICENSE, README.md
```

### Invariants

* **Nothing under `build/` or `obj/` is checked in**; CI wipes them each run.
* **Paths are stable**: scripts & CI rely on exact directory spellings.
* **Each directory owns its own README.md** describing purpose & how to test.

---

## 1. Kernel Source Tree (`kernel/`)

```
kernel/
├── arch/x86/           – architecture‑specific code
│   ├── boot/           – NASM stage‑0 loader + linker script
│   └── cpu/            – GDT/IDT/TSS/port I/O (D + .s stubs)
├── kernel/             – portable core (D only)
│   ├── core/, memory/, process_manager.d, …
│   ├── include/kernel/ – public headers (D interfaces) for C FFI
│   └── lib/            – freestanding libc shim (`@nogc @system`)
└── README.md
```

**Rules**

* Modules must compile **`@safe @nogc nothrow`** unless under `version(NeedsGC)`.
* Assembly lives next to the D file that imports it (e.g. `thread_switch.s`).
* No direct references across `arch/` boundaries; use `kernel/arch_interface/*`.

---

## 2. Hypervisor (`hypervisor/`)

Lightweight VMM that boots AnonymOS inside QEMU or on bare‑metal SVM.

* Builds with its own `dub.json`; output to `build/hypervisor/kernel`.
* Exposes a **VFIO stub** for PCI passthrough in tests.

---

## 3. Modules (`modules/`)

Used for features that *can* live outside the trusted TCB.

* **Must not** import from `kernel.*`; use the public IPC or object‑tree APIs.
* Provide independent `Makefile`s; CI builds them after kernel.
* Example: `distributed-fs/` implements a Plan‑9‑style network FS.

---

## 4. Build & Tooling

| Task                  | Entrypoint                 |
| --------------------- | -------------------------- |
| Complete build (+ISO) | `make iso`                 |
| Clean worktree        | `make distclean`           |
| Launch QEMU debug     | `scripts/run_with_gdb.sh`  |
| Developer shell       | `scripts/setup_dev_env.sh` |

* **Cross‑compiler:** `ldc` patched via `ldc_port/` (see `scripts/build_dmd.sh`).
* **Boot chain:** NASM → LD → `kernel.bin` → `grub.cfg` → `anonymOS.iso`.

---

## 5. Coding Standards

| Aspect   | Guideline                                                       |
| -------- | --------------------------------------------------------------- |
| Naming   | `CamelCase` types, `snake_case` functions, `UPPER_SNAKE` consts |
| Line len | 100 chars                                                       |
| Imports  | Absolute (`kernel.memory.virtmem`) – *never* relative dots      |
| Memory   | No heap in kernel fast‑path; use `slab_alloc` in `memory/`      |
| Logging  | `kernel.logger` only; guards w/ `version(TRACE)`                |

---

## 6. Testing & Coverage

### Unit Tests (D `unittest {}` blocks)

* Compiled **out** of `release`.
* Live adjacent to code; run via `make test-unit`.

### Integration / Kernel‑boot Tests

* Harness in `tests/` (generated at build) boots ISO under QEMU.
* Results streamed over COM1 in **TAP v14**; parser in `scripts/tap_parse.py`.

### Coverage Targets

* 80 % for `kernel/` & `modules/distributed-fs/server` lines.
* Report via `d-profile-gcov`; HTML summary pushed to `build/coverage/`.

---

## 7. Continuous Integration (GitHub Actions)

1. Cache & build cross toolchain (ldc + druntime)
2. `make iso` on matrix {`x86_64`,`aarch64`}
3. Run unit + QEMU tests
4. Artifact upload: `anonymOS.iso`, `kernel.sym`, coverage HTML

Push to `main` also uploads nightly ISO to `releases/nightly/`.

---

## 8. Commit & Review Policy

* **Feature branches** only; PR requires one core dev + one rotating reviewer.
* Commit message: `scope: short present‑tense summary` (e.g. `memory: fix slab free()`).
* CI must be green & review comments resolved before merge.

---

## 9. Security & Capabilities

* All IPC uses **secure capability handles** (`ipc/secure_ipc.d`).
* `object-tree/` provides validation helpers for user‑space.
* Memory maps default **read‑only**; write requires capability flag.

---

## 10. Documentation

* Source **Ddoc** required for every exported symbol.
* Nightly CI publishes docs to GitHub Pages (`docs/` ➜ `gh-pages` branch).
* Design RFCs live under `docs/rfcs/`; propose via PR.

---
