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

## USB stack bring-up (US0–US6) — prerequisite for the two-USB model (D4)
The two-USB model stands or falls on USB **mass-storage read AND write** working reliably —
and the known ★ blocker is that usb-storage bulk/scatter-gather DMA on the FW13's no-IOMMU
path corrupted kernel memory and hard-froze the machine (input via usbhid = tiny DMA was
fine; bulk transfers were not; see memory `desktop-freeze`/`bare-metal-lkl`). These steps
bring the USB stack up deliberately, QEMU-first then real hardware, and make the multi-GB
sustained transfer the acceptance test. All ride the proven LKL xHCI + usb-storage path.

- **US5 — ★ FW13 bulk-DMA stabilization.** ◑ **FIX IMPLEMENTED + PROVEN-CORRECT in QEMU;
  FW13 trigger-validation pending.** ROOT CAUSE FOUND: op5 (`lklDmaMap`, posix.d) returns a
  SINGLE physical address for a DMA buffer, but the LKL's phys-mem (memfd) is backed by pages
  allocated one-at-a-time (`mmap.d`/`dma.d`) → a multi-page buffer contiguous in the LKL's view
  is backed by PHYSICALLY-SCATTERED host pages → the device DMAs `sz` bytes linearly past the
  first page into unrelated memory (the corruption). Works in QEMU only because a fresh boot's
  sequential allocations happen to be contiguous; the FW13's fragmented map scatters them.
  FIX: op5 checks physical contiguity of `[va, va+sz)`; a **non-contiguous** multi-page buffer
  is DMA'd through a truly-contiguous **bounce** (`alloc_phys_pages`), copy-on-BOTH-ends
  (caller→bounce on map, bounce→caller on unmap op12) → direction-agnostic. Contiguous maps
  (all QEMU, all small WiFi DMA ≤1 page) take the fast path unchanged → non-regressive.
  `epin_pci_map_page` now passes `sz`; `epin_pci_unmap_page` calls op12. **VERIFIED in QEMU:**
  (a) fast-path non-regression — the US1–3 FAT32 1 MB round-trip still works, zero bounces;
  (b) bounce-path correctness — a `g_lklForceBounce` flag forced EVERY 64 KB bulk DMA through
  the bounce; the full FAT mount (read path) + a 651 KB `hoslog.txt` write (write path) both
  came back byte-valid on the host (147 boot-marker lines, no corruption). Diagnostic
  `[lkl-dma] NON-CONTIGUOUS map …` logs the trigger. **Remaining (FW13):** boot with the fix +
  a USB stick, confirm the diagnostic fires on the real fragmented map and the freeze is gone.
- **US6 — Multi-GB soak (acceptance).** ◑ **QEMU proxy done; real soak FW13-gated.** The
  forced-bounce run above sustained many bulk 64 KB bounced transfers through a full boot with
  a correct file round-trip (a bounded soak). The real multi-GB distro-ISO-on-USB-#2 soak on
  the physical FW13 (no freeze, data intact, desktop responsive) needs the hardware.

**STATUS 2026-07-12:** ✅ US0–US4 DONE+verified in QEMU (enumerate/read/write/work-FS/two-USB).
◑ **US5 fix IMPLEMENTED + its bounce path PROVEN CORRECT in QEMU** (fast-path non-regressive +
forced-bounce read/write round-trip byte-valid) — only the FW13-specific trigger validation is
hardware-gated (the freeze doesn't reproduce in QEMU's contiguous memory). US6 real soak FW13-gated.

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
