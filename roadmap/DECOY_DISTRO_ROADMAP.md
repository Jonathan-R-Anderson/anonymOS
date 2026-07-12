# Decoy OS: Runtime Network Install of an Official Distro ISO

## Goal (user, 2026-07-12)

Today the Hidden-OS decoy is a single hard-wired Alpine image baked into the build. Instead:
let the user **choose a Linux distribution** — Ubuntu, Linux Mint, Fedora, NixOS, Debian,
Alpine — and, **at install time, download that distro's OFFICIAL ISO directly from the
distro's official servers onto the installation medium, then install it into the VeraCrypt
decoy partition.** The decoy a coerced user reveals is a genuine, official distro they chose,
fetched live — and nothing distro-related is bundled in or re-hosted by EpinAnonymOS.

**Hard requirements (user, 2026-07-12):**
1. The decoy ISO is **downloaded from the distro's OFFICIAL servers** (not project-hosted).
2. It is downloaded **onto the installation medium at runtime** (during the install).
3. It is then **installed into the decoy partition, encrypted under VeraCrypt.**
4. **Two USBs:** USB #1 boots the installer; USB #2 is dedicated read/write scratch for the
   download + extraction, so the target disk never holds decoy residue (D4).

## North star

The installer's Decoy-OS page offers a **distribution picker**. Choosing one makes the
running installer: (a) **download that distro's official ISO** from its official mirror over
the network; (b) **verify** it against the distro's own **GPG-signed checksums** (each
distro's release signing key is pinned in the installer — no project signing, no
re-hosting); (c) **extract the distro's root filesystem** from the ISO; (d) build a
populated ext4 and **stream it through the existing VeraCrypt encryption path into the decoy
system partition**; (e) the user's decoy account/hostname/password and the §G/§H2 fake
history are applied on the **decoy's first boot** from a tiny install-time seed. **No decoy
images ship in the ISO and nothing is fetched from EpinAnonymOS servers** — only the distros'
official ones.

---

## What already exists to build on (verified 2026-07-12)

| Piece | State | Notes |
|---|---|---|
| VeraCrypt decoy install path | ✅ `veracrypt_impl.d` streams + encrypts `decoy-linux.ext4` sector-by-sector into the decoy system partition (Hidden-OS, E2E-verified in QEMU) | **the endpoint**: give it a runtime-produced ext4 instead of a bundled one |
| Decoy rootfs builder | ✅ `deps/decoy-os/` (Alpine minirootfs → `customize.sh` → `decoy.ext4`); already fetches its base over the net | today it runs at BUILD time; this roadmap moves the fetch+assemble to INSTALL time |
| Fake history seeding | ✅ `deps/decoy/` (`decoy.c`, `h2/fakelogd.c`) — deterministic §G/§H2 history | distro-agnostic; runs at decoy first-boot here |
| Installer Network page + net | ✅ `wl-installer.c` SCREEN_NETWORK; LKL Wi-Fi/DHCP (real lease proven); native e1000 + **in-kernel HTTPS** (`network/https.d`, used by boot-integrity) | the connectivity + HTTPS the download needs already exist |
| Installer Decoy page | ✅ SCREEN_DECOY (user/fullname/password/hostname + size slider) | add the distro picker |
| install.json plumbing | ✅ wizard → `/config/install.action config …` → persisted install.json → first-boot apply | add `decoyDistro` + a decoy seed blob |
| Content hashing / sig | ✅ `core/crypto.d` SHA256; SYSTEM_UPDATE adds Ed25519 | need GPG/RSA + SHA256SUMS verify against distro release keys (D3) |
| Object store / target disk | ✅ AHCI/NVMe block I/O, cap-gated writes; the target disk is available during install | scratch space for the multi-GB ISO + extracted rootfs (D4) |

The decoy is a REAL distro precisely so it's believable (INSTALLER §E0/§H1); fetching the
**official ISO live** makes it as authentic as possible.

---

## Architecture decisions

### D1 — Source: the distro's OFFICIAL ISO from its OFFICIAL servers (per-distro)
Each distro is a pinned recipe: official ISO URL(s) + the checksum/signature files + the
release **signing key** to verify them. No mirror is trusted without checksum+signature.

| Distro | Official artifact | Verify with |
|---|---|---|
| Ubuntu | `releases.ubuntu.com/<ver>/ubuntu-<ver>-desktop-amd64.iso` | `SHA256SUMS` + `SHA256SUMS.gpg`, Ubuntu CD signing key |
| Linux Mint | `mirrors.kernel.org`/official Mint mirror `linuxmint-<ver>-cinnamon-64bit.iso` | `sha256sum.txt` + `sha256sum.txt.gpg`, Mint signing key |
| Fedora | `download.fedoraproject.org/.../Fedora-Workstation-Live-...iso` | `Fedora-...-CHECKSUM` (GPG-clearsigned), Fedora release key |
| Debian | `cdimage.debian.org/.../debian-<ver>-amd64-netinst.iso` (or DVD) | `SHA256SUMS` + `SHA256SUMS.sign`, Debian CD key |
| Alpine | `dl-cdn.alpinelinux.org/.../alpine-standard-<ver>-x86_64.iso` | `.iso.sha256` + `.iso.asc`, Alpine signing key |
| NixOS | `channels.nixos.org`/`releases.nixos.org` graphical ISO | `.iso.sha256`, published hash |

Release signing keys are **pinned in the installer image** (a small keyring). The URLs +
current versions come from a small built-in catalog, refreshable later (X6).

### D2 — Runtime pipeline: ISO → rootfs → ext4 → VeraCrypt decoy partition
On the running installer, per download:
1. **Download** the ISO over HTTPS (Ethernet-first, Wi-Fi fallback) to scratch (D4).
2. **Verify** SHA256 against the signed checksum file; verify that file's GPG signature
   against the pinned release key. Refuse on any mismatch (logged to `/run/installer.log`).
3. **Extract the root filesystem.** Desktop ISOs carry a live **squashfs** (Ubuntu/Mint:
   `casper/filesystem.squashfs`; Fedora: `LiveOS/squashfs.img` → rootfs ext4; Debian/Alpine
   netinst: no live squashfs → run the distro's bootstrap into a rootfs instead, D2a). Read
   ISO9660 + decompress squashfs into a rootfs tree.
4. **Populate an ext4** image sized to the decoy partition from that rootfs.
5. **Stream it through the existing VeraCrypt encryption path** into the decoy system
   partition (the `veracrypt_impl.d` decoy-image step, unchanged — it just gets a
   runtime-built ext4 instead of `decoy-linux.ext4`).

### D2a — Distros with no live squashfs (Debian/Alpine netinst)
Their ISOs are installers, not live images. Two options: prefer a distro-provided **rootfs
tarball / cloud image** from the same official servers (Debian rootfs, Alpine minirootfs —
smaller, directly extractable), or run the bootstrap (`debootstrap`/`apk`) at install time.
**→ Prefer the official rootfs artifact** where the distro ships one; it's still the
official server, still verified, and avoids running a bootstrapper on-device.

### D3 — Verification against the DISTROS' OWN keys (not a project key)
Trust roots are the distros' release signing keys, pinned in the installer keyring. This is
the standard secure-download chain (GPG-signed `SHA256SUMS`) and means EpinAnonymOS neither
re-hosts nor re-signs any distro — it only verifies the official artifact. Needs a small
signature-verify path (GPG/RSA-SHA256) on the installer; SHA256 already exists.

### D4 — Scratch storage: a SECOND USB (read/write), not the target disk
A desktop ISO is 2–4 GiB and its extracted rootfs several GiB more — too big for RAM alone.
**Decision (user, 2026-07-12): use a SECOND USB stick as dedicated read/write scratch.** The
install uses **two USBs**: USB #1 = the EpinAnonymOS installer (boot medium); USB #2 = a
read/write **work volume** where the installer downloads the ISO, extracts the rootfs, and
builds the ext4 — which is then streamed through VeraCrypt into the decoy partition.
- **Why it's better than target-disk scratch:** the decoy ISO/rootfs **never touches the
  target disk**, so there is no scratch region to reclaim and no ISO residue to betray the
  hidden setup (§F2/deniability). USB #2 can be **physically removed and wiped after
  install**, leaving zero decoy-provisioning trace on the machine.
- The installer **detects USB #2** (a second USB mass-storage device with enough free
  space), formats/uses a work filesystem on it, and streams download→extract→ext4 there.
- **Fallback:** if only one USB is present, offer target-disk transient scratch (old D4) with
  a mandatory §F2 wipe afterward, clearly flagged as less deniable. Default is two USBs.
- Requires **USB mass-storage read/write** in the installer (LKL xHCI + usb-storage). ★ RISK
  (from memory): usb-storage bulk DMA hard-froze the FW13 on the no-IOMMU path — this path
  must be stabilized (or IOMMU-gated) before real-HW use; fine in QEMU. See D8.

### D5 — Turning an extracted live-ISO rootfs into a bootable installed decoy
A live squashfs is a working rootfs but needs install-time finishing that a distro installer
normally does: generate `/etc/fstab`, a machine-id, remove live-session/installer packages,
and install the distro's bootloader **inside the decoy volume** so unlocking the decoy
password boots it (the VeraCrypt preboot chain already hands off to the decoy's loader). The
per-user account/hostname/password + §H2 history are applied at **decoy first boot** (D6).

### D6 — Per-user personalization at decoy FIRST BOOT (image stays generic)
The extracted rootfs is generic; the installer writes a tiny **decoy seed** (account, full
name, hostname, password hash, §H2 timestamps) into a known offset of the decoy volume, and
a **first-boot service** injected during extraction consumes it — creates the account, sets
hostname/password, runs `fakelogd` to lay down the lived-in history, then self-erases (§H4:
no trace it was provisioned). Mirrors how the real OS applies install.json at first boot.

### D7 — Size vs. the deniability envelope, known before download
The catalog carries each distro's ISO + rootfs size, so the picker shows the real footprint
and re-derives the decoy/hidden size-slider bounds **before** download, guaranteeing the
hidden OS still fits. Featureless-entropy (§F2) is unchanged — the encrypted decoy partition
stays random-looking regardless of distro.

### D8 — New installer userland tools (musl binaries staged in the installer) — INTEGRATING
Extraction runs on the RUNNING installer, so each is a **musl-cross binary staged into the
installer ISO** (like busybox/zsh), invoked by the install flow. Chosen implementations +
their codec deps, and the second USB they read/write:

| Component | Impl (musl-cross, `deps/<name>/`) | Deps | Status |
|---|---|---|---|
| ext4 create+populate | **e2fsprogs** `mke2fs -d <dir> <img>` (dir → populated ext4) | (none exotic; opt. libz) | ✅ **DONE+verified** — `deps/e2fsprogs/` builds a musl-static `mke2fs`; `-d` round-trips a rootfs tree into a valid ext4 (debugfs-verified: tree, ownership, file contents); staged into the ISO (`cd/mke2fs`, limine module) |
| squashfs decompress | **squashfs-tools** `unsquashfs` | **liblzma (xz) + libzstd + zlib** | ✅ **DONE+verified** — `deps/xz/` (liblzma) + `deps/zstd/` (libzstd) built musl-static; `deps/squashfs-tools/` links them + reused zlib → musl-static `unsquashfs`; **all 3 codecs round-trip byte-identical** (gzip/xz/zstd mksquashfs→unsquashfs); staged `cd/unsquashfs` + limine module |
| ISO9660 read | **libarchive** `bsdtar` (reads ISO9660 + Rock Ridge/Joliet) | zlib (+xz) | ✅ **DONE+verified** — `deps/libarchive/` musl-static `bsdtar` (`-all-static` at make-link, not configure); lists ISO9660 + extracts inner `casper/filesystem.squashfs` byte-identical; staged `cd/bsdtar` + limine module. **★ FULL CHAIN VERIFIED: ISO → bsdtar → unsquashfs(xz) → mke2fs -d → valid decoy ext4 (rootfs contents intact).** |
| GPG/RSA-SHA256 verify | **gpgv** (GnuPG 1.4, self-contained) w/ pinned distro keyring; ISO-hash integrity via busybox `sha256sum` | (none — 1.4 has its own mpi/cipher) | ✅ **DONE+verified** — `deps/gnupg/` musl-static `gpgv` (`-fcommon` for old-C tentatives); verifies a real RSA-4096/SHA-512 detached sig against a pinned keyring (`Good signature`, exit 0) + rejects a tampered file (`BAD signature`, exit 1); staged `cd/gpgv` + limine module. (busybox `sha256sum` already covers the ISO-hash integrity half.) |
| USB #2 read/write | LKL xHCI + **usb-storage** block device + a FAT/ext work FS the installer mounts (D4) | — | planned — see **USB stack bring-up (US0–US6)** below; ★ FW13 bulk-DMA freeze risk |

> **musl build trap (e2fsprogs):** `lib/blkid/llseek.c`'s `(!HAVE_LLSEEK && long==long
> long)` branch defines `llseek` but not `my_llseek`, so clang errors on the (dead,
> size-guarded) `my_llseek` call. The `deps/e2fsprogs/Makefile` seds it to
> `#define my_llseek lseek` after extract; `--disable-libblkid` is WRONG (means "use
> external blkid" → configure fails); keep the bundled blkid + the sed.

zlib is already in-tree (`deps/gtk-stack/sysroot/lib/libz.a`); **liblzma + libzstd are NOT**
and must be added (small musl builds) for squashfs. These ports are the biggest technical
cost and pace X1; they land incrementally (ext4 → squashfs → iso → gpgv) via the milestones.

---

## Milestones

Each ends with a proof. "Network-installed decoy" = the running installer downloaded the
official ISO, verified it, extracted it, and encrypted it into the decoy partition —
confirmed by `/run/installer.log` + unlocking the decoy password → that distro boots.

## X0 — Installer userland tools port (D8) + second-USB work volume (D4) — ◑ TOOLS ✅ DONE; USB ⬜
Port the four extraction tools as musl-cross binaries staged in the installer, landing
incrementally: **(a) e2fsprogs `mke2fs -d`** (dir→ext4, terminal step) — ✅ **DONE+verified**
(`deps/e2fsprogs/` → musl-static `mke2fs`, debugfs-verified dir→ext4, staged `cd/mke2fs` +
limine module); **(b) liblzma + libzstd + squashfs-tools `unsquashfs`** — ✅ **DONE+verified**
(`deps/xz` + `deps/zstd` + `deps/squashfs-tools`, all 3 codecs byte-identical round-trip,
staged `cd/unsquashfs`); **(c) libarchive `bsdtar`** (ISO9660) — ✅ **DONE+verified**
(`deps/libarchive`, staged `cd/bsdtar`; **full ISO→bsdtar→unsquashfs→mke2fs chain proven**);
**(d) gpgv** + pinned distro keyring — ✅ **DONE+verified** (`deps/gnupg` GnuPG 1.4 self-
contained; real RSA-4096/SHA-512 sig verified + tamper rejected; staged `cd/gpgv`). **ALL 4
EXTRACTION/VERIFY TOOLS COMPLETE.** Plus the **second USB** read/write work volume (LKL
usb-storage + a mountable work FS) — see **USB stack bring-up (US0–US6)** below.
**Verify (host smoke-tests as each lands):** `mke2fs -d <dir> img && mount` round-trips a
tree; `unsquashfs` extracts a real squashfs; `bsdtar -tf` lists an ISO9660; `gpgv` accepts a
good SHA256SUMS.gpg + rejects a tampered one. In QEMU: installer mounts a 2nd USB, writes+
reads a file.

## USB stack bring-up (US0–US6) — prerequisite for the two-USB model (D4)
The two-USB model stands or falls on USB **mass-storage read AND write** working reliably —
and the known ★ blocker is that usb-storage bulk/scatter-gather DMA on the FW13's no-IOMMU
path corrupted kernel memory and hard-froze the machine (input via usbhid = tiny DMA was
fine; bulk transfers were not; see memory `desktop-freeze`/`bare-metal-lkl`). These steps
bring the USB stack up deliberately, QEMU-first then real hardware, and make the multi-GB
sustained transfer the acceptance test. All ride the proven LKL xHCI + usb-storage path.

- **US0 — Enumerate mass-storage.** ✅ **DONE+verified (QEMU).** xHCI grant to the LKL is now
  gated on a `/epin-usb.conf` boot marker (`USB=1 make iso`; kernel `debugUsbBootPresent()` —
  OFF by default to preserve the FW13 freeze fix). A `-device usb-storage` 512 MB stick
  enumerates as `/dev/sda` in the LKL (`usblog: 8 0 524288 sda`); usb-storage binds.
- **US1 — Read path + integrity.** ✅ **DONE+verified (QEMU).** The LKL mounts a FAT32 stick
  (reads the boot sector + FAT metadata) and streams from it — proven together with US2/US3.
- **US2 — Write path + round-trip.** ✅ **DONE+verified (QEMU).** The LKL wrote a **1 MB
  `hoslog.txt`** to `/dev/sda` and `fsync`'d it; the backing image, read back **on the host**,
  contains the file byte-correct (the real kernel boot log). Full write→flush→read round-trip.
- **US3 — Work filesystem on USB #2.** ✅ **DONE+verified (QEMU).** LKL mounted a host-formatted
  FAT32 work FS, created + wrote a file, flushed to the device; host `mtype` reads it back
  intact. (Reusing the musl `mke2fs` to format ext4 on-device is the installer-side variant,
  wired in X1–X3.)
- **US4 — Two-USB detection + role assignment.** ◑ DETECTION ✅ **DONE+verified (QEMU)** — two
  usb-storage devices enumerate distinctly (`sda` 256 MB + `sdb` 1 GB) and the size-preference
  picks the larger as scratch. The **boot-medium exclusion** (don't clobber USB #1 the
  installer booted from) is installer-side logic (X1–X3): when booted from USB, exclude that
  device from scratch candidates. Original detail below:
  Enumerate BOTH mass-storage devices;
  distinguish USB #1 (the boot medium — the one the installer booted from) from USB #2
  (scratch — the other one, with enough free space). Surface the choice on the Decoy page;
  refuse to proceed if only one USB is present (fall back per D4). **Verify:** with two USBs
  attached, the installer identifies each correctly and picks #2 as scratch.
- **US5 — ★ FW13 bulk-DMA stabilization (the hard part).** Fix the no-IOMMU bulk-DMA freeze:
  constrain usb-storage DMA to a bounce/identity-mapped low region (or gate behind the
  IOMMU when present), cap transfer sizes, and prove a large sequential read+write on real
  hardware does NOT freeze or corrupt memory. This is make-or-break for real-HW use.
  **Verify (FW13):** a sustained multi-hundred-MB read+write completes with the desktop
  responsive throughout (no `[freeze]`/`HOG:` storm) and data intact.
- **US6 — Multi-GB soak (acceptance).** Download+write a real multi-GB distro ISO to USB #2
  and run the extraction chain on it, on real hardware, with no freeze or corruption — the
  real-world acceptance test for the two-USB decoy install. **Verify (FW13):** full
  ISO→ext4 pipeline on USB #2 succeeds end to end.

**STATUS 2026-07-12:** ✅ US0–US3 DONE+verified in QEMU (enumerate + read + write + work-FS —
LKL round-trips a 1 MB file to a FAT32 stick, host confirms); ◑ US4 detection DONE (two USBs
enumerate + selected), role-exclusion is installer-side. **US5–US6 are BLOCKED on FW13
hardware** — the no-IOMMU bulk-DMA freeze does NOT reproduce in QEMU (QEMU has working DMA),
so the fix can't be verified here; needs the physical FW13 to reproduce + validate.

## X1 — Download + verify + extract → ext4 on the second USB (the pipeline, end to end)
On the running installer: HTTPS-download the chosen Ubuntu ISO to USB #2 (Ethernet-first),
verify SHA256 + `SHA256SUMS.gpg` against the pinned Ubuntu key (gpgv), read the ISO9660
(bsdtar), decompress `casper/filesystem.squashfs` (unsquashfs), and build `decoy.ext4` on
USB #2 (`mke2fs -d`).
**Verify (QEMU, NET=1, 2 USBs):** a real Ubuntu ISO is downloaded, verified (tamper → logged
refusal), extracted, and the produced ext4 mounts on the host as a real Ubuntu rootfs — all
on USB #2, target disk untouched.

## X2 — Feed the runtime ext4 into the VeraCrypt decoy path + boot it
Wire the extracted ext4 into `veracrypt_impl.d`'s decoy-image step (replacing the bundled
`decoy-linux.ext4`); add D5 finishing (fstab/machine-id/bootloader-in-decoy-volume).
**Verify (QEMU):** a Hidden-OS install with distro=Ubuntu, downloaded+extracted at runtime →
unlocking the decoy password **boots Ubuntu** from the encrypted decoy partition.

## X3 — Wizard distro picker + install.json + first-boot personalization
Distro control on SCREEN_DECOY (catalog + sizes via a synthetic `/config/decoy.distros`);
persist `decoyDistro`; write the decoy seed (D6); inject the first-boot personalization
service during extraction.
**Verify:** install with a custom decoy user/hostname → the decoy boots Ubuntu **as that
user, with that hostname and a lived-in §H2 history**; no "decoy"/provisioning trace (§H4).

## X4 — Add the squashfs-live distros: Linux Mint + Fedora
Per-distro recipes (URL + key + squashfs path): Mint (`casper/filesystem.squashfs`) and
Fedora (`LiveOS/squashfs.img`). Flow through X0–X3 unchanged; add codec coverage
(Fedora zstd) to the squashfs step.
**Verify:** runtime install of Mint and of Fedora each boots that desktop under the decoy pw.

## X5 — Add the non-live distros: Debian + Alpine (+ NixOS)
D2a path: use the official **rootfs artifact** (Debian rootfs tarball, Alpine minirootfs) from
the official servers, verified, extracted straight to ext4 — no squashfs. NixOS via its
official graphical ISO/closure (heaviest; may need `nix`-built rootfs — keep opt-in).
**Verify:** runtime install of Debian and Alpine boots each under the decoy pw; NixOS tracked
separately if its extraction proves too heavy for on-device.

## X6 — Robustness: resumable download, catalog freshness, mirror failover
Resumable/chunked HTTPS with mirror failover (official mirrors only); the
`/config/decoy.distros` catalog (URLs + current versions + keys) is a small refreshable,
signed record so new distro versions appear without an ISO rebuild. Free-space +
connectivity preflight on the Decoy page with clear errors.
**Verify:** an interrupted download resumes; a stale catalog version still verifies against
the pinned keys; offline shows a clear "network required for decoy" message.

## X7 — Hardening + polish
Per-distro §H4 audit (no "decoy"/"hidden"/"live-session" leakage; installer/live packages
removed in D5); scrub the target-disk scratch region (§F2 entropy) after use so no ISO
residue survives; "randomize believable defaults" (locale/apps/wallpaper); driver/firmware
match so the decoy has plausible drivers for the real hardware (cross-ref driver-install).

---

## Dependency graph

```
X0 (download+verify official ISO) ─→ X1 (ISO→rootfs→ext4 extraction) ─→ X2 (feed VeraCrypt decoy + boot)
                                                                          └─→ X3 (picker + first-boot personalize)
                                                                                ├─→ X4 (Mint, Fedora: squashfs)
                                                                                ├─→ X5 (Debian, Alpine, NixOS: rootfs artifact)
                                                                                └─→ X6 → X7 (robust transport + hardening)
```

X0–X3 deliver one distro (Ubuntu) **downloaded from Ubuntu's servers at runtime, verified,
extracted, and installed into the encrypted decoy partition** — the whole authentic path —
before the other distros, which are mostly per-distro recipes on the same pipeline.

## Honest risks
- **The extraction userland (D8) is the big cost.** ISO9660 + squashfs (multi-codec) + ext4
  build + GPG verify are real ports into the musl userland on a device that has none of them
  today. This dominates X1 and is the pacing item — budget it as the hard part.
- **Multi-GB scratch on the target disk (D4):** downloading + extracting several GiB during
  an install needs transient scratch and careful wiping (§F2) so no decoy-ISO residue betrays
  the hidden setup. Streaming reduces but doesn't eliminate this.
- **Live-ISO ≠ installed system (D5):** a squashfs still needs fstab/bootloader/cleanup to
  boot as a real install; getting each distro's bootloader to live inside the VeraCrypt decoy
  volume is fiddly per distro.
- **Network dependency at install:** no connectivity ⇒ no decoy (there is no bundled
  fallback under this model). The Decoy page must state this up front.
- **Distro key/URL drift:** official URLs and release keys rotate; the pinned keyring + the
  refreshable catalog (X6) must be maintained or downloads start failing verification.
- **NixOS** doesn't fit the squashfs model and its closure build is heavy; likely the last
  distro and possibly opt-in.
