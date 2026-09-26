#!/bin/sh
# boot/gatekeeper/build-uki.sh — assemble the boot GATEKEEPER as a self-contained UKI.
#
# Unlike the decoy UKI (static busybox + init; the real rootfs is a separate encrypted ext4), the
# gatekeeper must RUN tor + wpa_supplicant + python(attest-unseal) + curl itself, so its initramfs
# is a full minimal Alpine rootfs (apk.static), not just busybox. Steps mirror deps/decoy-os:
#   apk.static a rootfs  ->  drop in init + attest-unseal + torrc + wifi modules + firmware
#   ->  cpio|gzip  ->  ukify (kernel + initrd + cmdline -> one PE the §E5 loader StartImages).
#
# ┌ !!! UNTESTED DRAFT. Boot-critical. Build it, then iterate against a THROWAWAY VM, never a real ┐
# │ install first. Several things below are per-hardware / per-deployment and marked TODO/VERIFY.  │
# └───────────────────────────────────────────────────────────────────────────────────────────────┘
set -e
HERE="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO="$(CDPATH= cd -- "$HERE/../.." && pwd)"

# ── knobs (override in the environment) ──────────────────────────────────────────────────────
OUT="${OUT:-$REPO/build/gatekeeper-uki.efi}"
GKROOT="${GKROOT:-$REPO/build/gk-initramfs}"
APK_STATIC="${APK_STATIC:-$REPO/deps/decoy-os/build/apk.static}"      # reuse decoy-os's apk.static
ALPINE_BRANCH="${ALPINE_BRANCH:-v3.19}"
APKMAIN="${APKMAIN:-https://dl-cdn.alpinelinux.org/alpine/$ALPINE_BRANCH/main}"
APKCOMM="${APKCOMM:-https://dl-cdn.alpinelinux.org/alpine/$ALPINE_BRANCH/community}"
UKI_STUB="${UKI_STUB:-/usr/lib/systemd/boot/efi/linuxx64.efi.stub}"
# WiFi at pre-boot needs a kernel WITH wireless + the NIC's modules. The from-scratch decoy kernel
# has no wireless, so default to Alpine's linux-lts (ships every wireless module) baked in below.
GK_KERNEL="${GK_KERNEL:-}"                                            # empty -> use linux-lts from the rootfs
# linux-firmware is huge. Install ONLY your NIC's subpackage — run `apk search linux-firmware` to
# find its exact name (Alpine's split naming varies); linux-firmware-none is the no-blobs default.
GK_FIRMWARE="${GK_FIRMWARE:-linux-firmware-none}"                     # VERIFY: set to your chipset's pkg
SUDO="${SUDO:-sudo}"; [ "$(id -u)" = 0 ] && SUDO=""

[ -x "$APK_STATIC" ] || { echo "[gk] need apk.static at $APK_STATIC (build deps/decoy-os first, or set APK_STATIC)"; exit 1; }
test -f "$UKI_STUB" || { echo "[gk] missing $UKI_STUB — apt install systemd-boot-efi systemd-ukify"; exit 1; }

# ── 1. minimal rootfs (the initramfs contents) ───────────────────────────────────────────────
$SUDO rm -rf "$GKROOT"; mkdir -p "$GKROOT"
$SUDO "$APK_STATIC" --root "$GKROOT" --repository "$APKMAIN" --repository "$APKCOMM" \
  --no-scripts --no-cache --update-cache --initdb add \
  busybox musl \
  tor curl wpa_supplicant wireless-tools kexec-tools \
  python3 py3-cryptography py3-argon2-cffi \
  linux-lts "$GK_FIRMWARE"
# (linux-lts brings the kernel + /lib/modules/<ver> incl. cfg80211/mac80211 + every NIC driver.)

# ── 2. our payload ───────────────────────────────────────────────────────────────────────────
$SUDO install -m 755 "$HERE/init" "$GKROOT/init"
$SUDO install -m 755 "$REPO/scripts/attest-unseal.py" "$GKROOT/bin/attest-unseal"
$SUDO mkdir -p "$GKROOT/etc/tor" "$GKROOT/esp"
printf 'SocksPort 9050\nDataDirectory /tmp/tor\nLog notice stderr\n' | $SUDO tee "$GKROOT/etc/tor/torrc" >/dev/null
# The init loads /mod/*.ko flat (multi-pass insmod). Copy the net + wireless + crypto modules from
# the linux-lts tree into /mod so wired + WiFi + dm-crypt bring-up have their drivers. TODO: prune
# to what your hardware needs — copying the whole tree bloats the UKI.
KVER="$(basename "$(ls -d "$GKROOT"/lib/modules/* 2>/dev/null | head -1)")"
if [ -n "$KVER" ]; then
  $SUDO mkdir -p "$GKROOT/mod"
  $SUDO sh -c "find '$GKROOT/lib/modules/$KVER' \\( -path '*/net/*' -o -path '*/crypto/*' -o -name 'cfg80211.ko*' -o -name 'mac80211.ko*' \\) -name '*.ko*' -exec cp {} '$GKROOT/mod/' \\;" || true
fi

# ── 3. initramfs cpio | gzip ─────────────────────────────────────────────────────────────────
INITRD="$REPO/build/gatekeeper-initramfs.gz"
$SUDO sh -c "( cd '$GKROOT' && find . | cpio -o -H newc 2>/dev/null | gzip -9 ) > '$INITRD'"
echo "[gk] initramfs: $(du -h "$INITRD" | cut -f1) (WARNING: python+tor+firmware make this large)"

# ── 4. kernel + ukify ────────────────────────────────────────────────────────────────────────
[ -n "$GK_KERNEL" ] || GK_KERNEL="$(ls "$GKROOT"/boot/vmlinuz-lts 2>/dev/null | head -1)"
[ -f "$GK_KERNEL" ] || { echo "[gk] no kernel (set GK_KERNEL, or linux-lts didn't install one)"; exit 1; }
# The §E5 loader REPLACES this cmdline via LoadOptions at StartImage (gkpass=/gkvault=/gkrpc=…); this
# is only the fallback. rdinit=/init runs the gatekeeper as PID 1.
mkdir -p "$(dirname "$OUT")"
ukify build --linux="$GK_KERNEL" --initrd="$INITRD" \
  --cmdline="console=ttyS0,115200 rdinit=/init loglevel=4" \
  --stub="$UKI_STUB" --output="$OUT"
echo "[gk] built $OUT ($(du -h "$OUT" | cut -f1))"
echo "[gk] NEXT: (1) §E5 loader must StartImage THIS instead of the OS, passing gk* params;"
echo "[gk]       (2) finish init's boot_real/boot_decoy (kexec real/decoy); (3) boot-test in a VM."
