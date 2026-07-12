# Decoy OS: Selectable Linux Distribution Roadmap

## Goal (user, 2026-07-12)

Today the Hidden-OS decoy is a single hard-wired Alpine image. Let the user **choose which
Linux distribution the decoy OS is** — Ubuntu, Linux Mint, Fedora, NixOS, Debian, Alpine,
etc. — at install time, so the decoy that a coerced user reveals is a believable everyday
desktop of their choosing, not always the same minimal Alpine.

## North star

The installer's Decoy-OS page offers a **distribution picker**. The chosen distro's root
filesystem is produced as a `decoy-<distro>.ext4` image, seeded with the same deterministic
fake history (§G/§H2), and the existing Hidden-OS install path encrypts **that** image into
the decoy system partition. Everything downstream of "a decoy ext4 image exists" already
works — this roadmap is about **producing a believable rootfs for each distro** and
**wiring the choice through the wizard → install.json → kernel install backend**.

---

## What already exists to build on (verified 2026-07-12)

| Piece | State | Notes |
|---|---|---|
| Decoy rootfs builder | ✅ `deps/decoy-os/` (Alpine minirootfs → `customize.sh` → `decoy-rootfs.tar.gz` → `decoy.ext4`) | fakeroot-based; single distro (Alpine) hard-wired in the Makefile |
| Fake history seeding | ✅ `deps/decoy/` (`decoy.c`, `h2/fakelogd.c`) — deterministic §G/§H2 lived-in history | distro-agnostic content; re-runnable per rootfs |
| Hidden-OS install path | ✅ `veracrypt_impl.d` streams+encrypts `decoy-linux.ext4` into the decoy system partition (E2E-verified in QEMU) | consumes ONE decoy image; distro-blind |
| Installer Decoy page | ✅ `wl-installer.c` SCREEN_DECOY (user/fullname/password/hostname + size slider) | no distro picker yet |
| install.json plumbing | ✅ wizard → `/config/install.action config …` → persisted `install.json` → first-boot apply | add a `decoyDistro` field |
| Driver/firmware detect | ✅ `/config/hardware.detect` (PCI) + driver-install roadmap | a heavier distro decoy may need matching drivers (cross-ref) |

The decoy is a REAL distro precisely so it's believable (INSTALLER §E0/§H1). This roadmap
generalizes "REAL distro" from "Alpine only" to "one of several".

---

## Architecture decisions (resolve before X2)

### D1 — How is each distro's rootfs produced?
- **A. Prebuilt cloud/container base images per distro** (Ubuntu cloud image, Fedora
  container base, Debian debootstrap tarball, Linux Mint via Ubuntu base + Mint layer,
  NixOS via `nix build` of a system closure). Each has a canonical, scriptable base.
- **B. Bootstrap each from its native tool** (`debootstrap`, `dnf --installroot`,
  `pacman -r`, `nixos-generate`). More faithful, heavier host deps.
- **→ A for most, B for NixOS.** Use each distro's official minimal base image where one
  exists (smallest believable footprint), fall back to the native bootstrapper only where
  no clean base image ships. Each distro is one pluggable recipe (D2).

### D2 — Build shape: one recipe per distro behind a common interface
- `deps/decoy-os/distros/<name>.sh` implementing a fixed contract: `fetch`, `unpack`,
  `customize <rootfs> <fakelogd> <password>`, `pack → decoy-<name>.ext4`. The top Makefile
  loops over the SELECTED distro(s). `customize.sh` becomes the shared step (accounts,
  hostname, fake history) that each recipe calls, so §H2 seeding stays identical across
  distros.
- Only distros the user selects are built (they're large) — the installer requests one.

### D3 — Believability: each decoy must look daily-driven, not freshly bootstrapped
- Per-distro desktop presence (Ubuntu/Mint → a GNOME/Cinnamon session skeleton; Fedora →
  GNOME; NixOS → its configuration.nix that yields a desktop). The §H2 fake-history seeding
  (browser history, recent files, shell history, logs) is distro-agnostic and reused; the
  distro-specific part is package set + desktop + default apps so the story matches the
  brand (INSTALLER §H4: never anything that says "decoy").

### D4 — Size/entropy vs. the deniability envelope
- Bigger distros (Ubuntu/Fedora GNOME) inflate the decoy image → the decoy partition must
  be large enough, and the hidden OS gets what's left (existing decoy/hidden size slider).
  The picker must show each distro's rootfs size and re-derive the slider bounds so the
  hidden OS still fits. Featureless-entropy requirement (§F2) is unchanged — the encrypted
  decoy partition stays random-looking regardless of distro.

### D5 — Where the images live (build-time vs. download)
- **Build-time bundling** (each selected `decoy-<distro>.ext4` staged as an install module)
  keeps installs offline but bloats the ISO per distro. **Download-on-demand** (fetch the
  chosen distro's base at install time over the network) keeps the ISO small but needs
  connectivity + provenance. **→ Hybrid:** bundle a small default (Alpine/Debian-min);
  offer the heavier desktops (Ubuntu/Mint/Fedora/NixOS) as a network fetch through the
  same signed-artifact path the system-update + driver-install roadmaps establish
  (cross-ref SYSTEM_UPDATE `UpdateRegistry` / driver-install). Verify the fetched base by
  hash before it becomes a decoy.

---

## Milestones

Each ends with a proof (a built `decoy-<distro>.ext4` that mounts + shows the seeded
history) and, where wired, a QEMU Hidden-OS install using the chosen distro.

## X0 — Refactor the builder to a pluggable per-distro interface (no new distro yet)
Split `deps/decoy-os/Makefile` + `customize.sh` so Alpine becomes
`distros/alpine.sh` implementing the D2 contract; the top Makefile builds
`decoy-$(DECOY_DISTRO).ext4` (default `alpine`). Pure refactor — Alpine output byte-stable
vs. today (or functionally identical + still passes `make decoy-os verify`).
**Verify:** `DECOY_DISTRO=alpine make decoy-os` reproduces the current image + passes verify.

## X1 — Second distro: Debian (debootstrap) — proves the interface generalizes
Add `distros/debian.sh` (debootstrap minimal + shared `customize`). Debian first: closest
to Alpine in effort, no desktop yet, cleanest bootstrap.
**Verify:** `DECOY_DISTRO=debian make decoy-os` → `decoy-debian.ext4` mounts, has the seeded
user/hostname/§H2 history, boots in a throwaway QEMU.

## X2 — Wizard distro picker → install.json → kernel
Add a **Distribution** control to `wl-installer` SCREEN_DECOY (list from a new synthetic
`/config/decoy.distros` the kernel serves, like `hardware.detect`). Persist `decoyDistro`
in install.json; the install backend selects `decoy-<distro>.ext4` (module name keyed by
distro) instead of the hard-wired `decoy-linux.ext4`.
**Verify:** QEMU Hidden-OS install with distro=debian → `[install]` streams
`decoy-debian.ext4`; unlocking the decoy password boots Debian.

## X3 — Desktop distros: Ubuntu + Linux Mint (Ubuntu base + Mint layer)
`distros/ubuntu.sh` (Ubuntu cloud/base image + a minimal GNOME session skeleton) and
`distros/mint.sh` (Ubuntu base + Cinnamon/Mint layer). First heavy, believable desktops.
Wire size into the decoy/hidden slider bounds (D4).
**Verify:** built images mount; the picker shows realistic sizes; a Hidden-OS install with
Ubuntu selected reveals an Ubuntu desktop under the decoy password.

## X4 — Fedora (dnf --installroot)
`distros/fedora.sh`. Different package manager + GNOME; proves the interface spans the
rpm world.
**Verify:** `decoy-fedora.ext4` builds + mounts + seeded; optional QEMU install.

## X5 — NixOS (declarative closure)
`distros/nixos.sh`: a `configuration.nix` describing a believable desktop, built via
`nixos-generate`/`nix build` into an ext4 closure. The declarative model is a natural fit
for reproducibility; heaviest host dependency (needs `nix`).
**Verify:** `decoy-nixos.ext4` boots to the declared desktop; seeded history present.

## X6 — Download-on-demand for heavy distros (D5 hybrid) + provenance
Move the desktop distros off the ISO: fetch the chosen base at install time, hash-verify it
(reuse the SYSTEM_UPDATE signed-artifact/`UpdateRegistry` path), then build the decoy.
Keeps the installer ISO small while still offering every distro.
**Verify:** offline install falls back to the bundled default with a clear message; online
install fetches + verifies + builds the selected desktop distro.

## X7 — Hardening + polish
Per-distro §H4 audit (nothing leaks "decoy"/"hidden"); reproducible builds so
`decoy-<distro>.ext4` is re-derivable; a "randomize believable defaults" option (locale,
installed apps, wallpaper) so two decoys of the same distro differ; driver/firmware match
so the decoy has plausible drivers for the real hardware (cross-ref driver-install roadmap).

---

## Dependency graph

```
X0 ─→ X1 ─→ X2                 (refactor → Debian → wizard wiring: the usable core)
             ├─→ X3 ─→ X4 ─→ X5   (Ubuntu/Mint → Fedora → NixOS: more distros)
             └─→ X6 ─→ X7          (download-on-demand + hardening)
```

X0–X2 deliver a working "pick your decoy distro" (Alpine + Debian) end-to-end before the
heavy desktop distros land. Share the §H2 seeding and the Hidden-OS install path unchanged
throughout — this roadmap only swaps which rootfs gets encrypted into the decoy partition.

## Honest risks
- **Per-distro believability is real work**, not just bootstrapping — a decoy that boots to
  a bare TTY isn't believable. X3+ carry desktop-session skeletons; budget accordingly.
- **ISO bloat vs. offline installs**: every bundled desktop distro adds ~1–2 GiB. X6's
  download path is the pressure valve but adds a connectivity dependency at install.
- **NixOS host dependency** (`nix`) is heavy; keep it opt-in so the common build doesn't
  require it.
- **Size interacts with deniability**: a huge decoy shrinks the hidden OS; the slider bounds
  (D4) must be recomputed per distro or the hidden install can fail to fit.
