# anonymos-config — the declarative system configuration compiler

This is the implementation of `roadmap/DECLARITIVE_MODEL_ROADMAP.md` (the whole
of it), realized as the host-side compiler that `roadmap/DECLARATIVE_CONFIG_SPEC.md`
specified and was awaiting: a tool that treats **one JSON file as the single
declarative source of truth** for constructing the entire running anonymOS
system state — "NixOS spirit, object-tree body."

It is written in **D with Phobos** (`std.json`, `std.digest.sha`, `std.file`),
the project's own language (`build.opts`: `DC ?= ldc2`). It deliberately does
*not* use the kernel's cross `-betterC -mtriple` flags — like the in-tree `esh`
dependency, it is a plain host `ldc2`+Phobos build needing the full runtime.
**No Python** anywhere in this tool.

## What it does

Lowers one resolved JSON document into the **existing** kernel object model in
`src/kernel/d/core/` — every declared service/user/namespace/mount/capability
becomes an `ObjType.*` object, validated and ordered before the kernel ever sees
it. The compiler is a **pure function** `JSON → CompiledGraph ⊎ [Error]`;
*applying* it is the separate `switch` step, so a rejected config is never
partially applied.

### The 8 compiler stages (spec §3)
1. **parse** — JSON decode (fatal on malformed input).
2. **schema-validate** — structural; strict top level, free-form where the kernel
   is free-form. Collects ALL errors in one pass.
3. **imports** — deep-merge module files left-to-right (name-keyed arrays merge
   by name; later wins on scalars); `imports` consumed and removed; import
   cycles detected.
4. **resolve references** — every cross-section name (`identity`, `namespace`,
   `service`, `capability`, `$object`) must exist.
5. **assign stable object IDs** — deterministic, dense, fixed order, so two
   compiles of the same input yield byte-identical ids (§17 reproducibility).
6. **detect cycles** — 3-color DFS over four edge sets: service `depends`∪`after`,
   namespace `inherits`, snapshot `base`, capability `inherits`. Pinpoints the
   closing edge.
7. **check capabilities** — the lattice is `core/cap.d`'s 19 rights bits; a
   child's mask must be a bitwise subset of its parent (`capDerive`); a service's
   rights must be ⊆ its identity's ceiling. Escalation is rejected at compile
   time.
8. **lower to CompiledGraph** — object list, boot plan, service graph +
   topological startup order, capability manifest, IPC rules, identity/namespace
   tables, per-section live/reboot classification, `configHash`.

## Build & test

```sh
make anonymos-config        # from the repo root, or `make` in this dir
make anonymos-config-test   # 78/78 phase tests
```

Requires `ldc2` on the host (the Dockerfile installs `ldc`; on macOS `brew install ldc`).

## CLI (spec §14)

```sh
anonymos-config check   system.json   # parse+validate+compile; print all errors
anonymos-config build   system.json   # check then write a new generation
anonymos-config diff    old.json new.json   # per-section changes, live/reboot labelled
anonymos-config switch  system.json   # build then atomically activate the generation
anonymos-config rollback               # activate the parent of the current generation
anonymos-config graph   system.json   # emit the object graph as Graphviz DOT
anonymos-config schema                # emit the JSON-Schema document (editor autocomplete)
```

`--store <dir>` (or `$ANONYMOS_CONFIG_STORE`) selects the generation store
(default `./anonymos-generations`): `gens/<id>/{system.json,manifest.json,meta.json}`,
a `current` symlink, and an append-only `journal.log`. Generations are
content-addressed by `sha256(canonical_json)`, so an identical config dedups.

## Layout

```
source/
  schema.d        Phase 1 — schema tree + exportJsonSchema
  validator.d     Phase 1 Stage 2 — structural validation (collect-all)
  modules.d       Phase 10/Stage 3 — imports deep-merge + import-cycle detection
  compiler.d      Phases 2–7,9,11 — object graph, refs, 4× cycle DFS, cap subset,
                  service graph + topological order, boot plan, ipc, identity/
                  namespace tables, live classification, graph_to_dot
  caplattice.d    Phase 6 — the 19 CAP_RIGHT_* bits mirroring core/cap.d
  generations.d   Phase 8 — content-addressed generation store + rollback
  main.d          Phase 12/§14 — the CLI
examples/         the spec §2.3 system.json + a 5-file modular config (§11)
tests/run_tests.d 78 host tests covering every phase
```

## Spec coverage

Every section of `DECLARITIVE_MODEL_ROADMAP.md` (1–17) is addressed; see the
section-coverage map at the foot of `DECLARATIVE_CONFIG_SPEC.md`. The lowering
column in spec §2.2 names the exact kernel API each field maps to
(`identityCreate`, `serviceRegister`/`serviceAddDep`/`serviceStartAll`,
`nsAlloc`/`nsBind`, `genCreate`/`genSetActive`/`genRollback`, `capDerive`,
`brokerRequestSession`) — all verified present in `src/kernel/d/core/`.

## §4 Boot integration (Option 1: in-kernel lowering)

The spec's §4 "hand JSON to PID1" assumes a config-driven PID1 that does not
exist yet — today's PID1 is a hardcoded boot-module scan and the in-kernel
service manager is exercised only by self-tests. Rather than block on building
a PID1 from scratch, the verified config is lowered **in-kernel in
`d_kernel_main`** via a parser-free binary manifest:

- **`emit-manifest <system.json>`** lowers the `CompiledGraph` to a flat TLV
  `manifest.blob` (header + records + a 32-byte HMAC-SHA-256 trailer), signed
  under the kernel's compiled-in trusted key.
- The kernel (`src/kernel/d/core/configboot.d`) locates the `manifest.blob` boot
  module, HMAC-verifies it with `cryptoVerify`, and walks the records calling the
  existing `serviceRegister`/`identityCreate`/`nsAlloc`/`genSetActive` APIs — so
  a declared config, not hardcoded init, constructs running state. A missing or
  tampered manifest logs + falls through safely (never half-applied).

```sh
anonymos-config emit-manifest -o manifest.blob system.json   # build + sign
make hos.iso                   # stages manifest.blob (unless DECLARATIVE_CONFIG=none)
./scripts/qemu-config-verify.sh   # boots ISO, greps serial for the apply marker
```

The **policy is still authored outside the kernel** (in `system.json` via the
host compiler); the kernel only *applies* a verified, pre-compiled plan —
honouring §17 "most policy lives outside the kernel." What this does *not* do:
build a PID1 that parses JSON at runtime, or make the config per-boot-editable
without a rebuild (those are future §4 work).

