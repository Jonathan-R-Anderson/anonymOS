# Build Loop, Automated Testing, and llvmpipe — Roadmap

Three workstreams, ordered by hours-saved per hour-spent. The ordering is deliberate: A makes
every later result trustworthy, B makes results cheap to obtain, C is the one big win that needs
a long build.

**Why this exists.** A single debugging session on 2026-09-04 lost roughly four rounds to *"is
the change even in the ISO?"* and several more to hand-reading `serial.log` for facts a script
could assert. None of that was the bug. See
[WINDOWS_DISAPPEARING_ROADMAP.md](WINDOWS_DISAPPEARING_ROADMAP.md) §5 for the specific traps.

---

## Track A — Make the build loop trustworthy

The failure mode: a change is committed, the ISO is newer than the commit, the behaviour is
unchanged, and 20 minutes go into diagnosing a stale binary.

| # | Item | Why | Effort |
|---|---|---|---|
| A1 | ✅ DONE — **`scripts/iso-verify.sh`** — assert named string literals are present in `hos-install.iso` before booting | The one check that actually works. Comments do **not** survive compilation; `__DATE__` build stamps are frozen by `SOURCE_DATE_EPOCH` (both tried, both failed) | S |
| A2 | ✅ DONE — **Build manifest baked into the ISO + printed at boot** — git HEAD, dirty flag, and the mtime of `kernel.elf` | Turns "which build is this?" into one `grep`. Must come from the *build*, not from a compiler macro | S |
| A3 | ✅ DONE (16 scripts) — **Repair the stale `qemu-*-verify.sh` scripts** — they reference `hos.iso`; the artifact is `hos-install.iso` | 13 scripts that cannot run as written | S |
| A4 | ✅ DONE — **`make verify`** — run A1 against a default marker set | Makes it the default habit, not a thing to remember | S |

**Exit criterion:** it is impossible to boot a stale ISO without being told.

---

## Track B — Automated boot testing

The failure mode: every check is a human booting a VM and reading a 5,000-line log.

| # | Item | Why | Effort |
|---|---|---|---|
| B1 | ✅ DONE — **`scripts/boot-test.sh`** — generic harness: boot headless, poll `serial.log` for required markers, fail on forbidden ones, hard timeout, meaningful exit code | The existing `qemu-g*-verify.sh` scripts each reimplement this. One harness, many suites | M |
| B2 | ✅ DONE — **`tests/desktop-smoke.txt`** — the default suite: compositor alive, domain manager launched, apps.blob unpacked, ≥N presents, 5 windows mapped | Catches every class of regression seen this session in ~90 s, unattended | S |
| B3 | ✅ DONE — **`make test`** | One command | S |
| B4 | ✅ DONE — **Regression assertions for bugs already fixed** — `cursor null failed` = 0, no `COMPOSITOR DIED`, freeze HUD silent, present count above floor | These regressed or hid twice already | S |
| B5 | *(later)* **Screenshot capture + compare** via the QMP monitor | Roadmap 3.3 marks visual QA Critical; a two-month-old binary once shipped unnoticed | M |

**Exit criterion:** `make test` gives a pass/fail verdict on a boot with no human reading a log.

---

## Track C — llvmpipe (the graphics ceiling)

Mesa is built `-Dllvm=disabled` with `-Dgallium-drivers=swrast,virgl`
([deps/mutter/Makefile:561](../deps/mutter/Makefile#L561)), so only **softpipe** exists — a
reference rasteriser with no JIT. llvmpipe is typically **10–30×** faster on the same CPU. That
is the single largest available graphics win, and it is a *build* problem, not an OS design
problem.

| # | Item | Why | Effort |
|---|---|---|---|
| C1 | ◑ WIRED, UNVERIFIED — **Cross-build LLVM for the musl target** — X86 target only, no tools/tests/docs, static libs | The prerequisite. Multi-GB, hours-long; the reason this is last | L |
| C2 | ✅ DONE (gated on `LLVMPIPE=1`) — **Mesa `-Dllvm=enabled`, `-Dgallium-drivers=llvmpipe,softpipe,virgl`** | Keeps softpipe as the fallback so a bad llvmpipe boot is one env var from recovery | S |
| C3 | ✅ DONE (via `g_galliumDriver`) — **Export `GALLIUM_DRIVER=llvmpipe`** on the no-GPU path (`exports.d`, where softpipe is exported today) | The switch | S |
| C4 | **Verify the JIT runs under this kernel** | llvmpipe generates machine code at runtime and `mprotect`s it executable. `g_wxEnforceExecCap = false` (hardening.d:48) so R+X is permitted — but this is the real risk item and must be proven, not assumed | M |
| C5 | **Measure** — `fps_x100` before/after on the same scene | The claim is 10–30×; verify it rather than assert it | S |

**Risks, stated up front:**
* LLVM is the largest dependency in the tree by far. If it does not cross-build cleanly against
  musl, C is dead and softpipe stands.
* llvmpipe uses more memory per context than softpipe; the VM runs `MEM=2048`.
* If the JIT trips a W^X or `mmap`-flags assumption in the kernel, C4 becomes kernel work.
* **C is not required for correctness.** The desktop's current problems are stalls and a debug
  overlay, not raw fill rate. Do A and B first regardless.

**Exit criterion:** `GALLIUM_DRIVER=llvmpipe` boots to the desktop and `fps_x100` improves
measurably against the same scene.

---

## Execution order

1. A1, A3, A4 — immediate, unblocks trustworthy iteration
2. B1, B2, B3, B4 — the harness and the default suite
3. A2 — build manifest (needs a Makefile hook)
4. C1 … C5 — only once A and B are green
