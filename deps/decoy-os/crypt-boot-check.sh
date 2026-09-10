#!/bin/bash
# deps/decoy-os/crypt-boot-check.sh — prove the decoy XFCE desktop boots from an ENCRYPTED on-disk
# root through the crypt initramfs (init-crypt), the way it will after the §E5 pre-boot loader
# hands the master key forward. We encrypt decoy-desktop.squashfs with dm-crypt aes-xts-plain64 (the
# exact on-disk format the installer's XTS produces), lay it at a known LBA on a raw disk, then
# direct-kernel-boot vmlinuz-decoy + initramfs-crypt.gz with the key + geometry on the cmdline and
# assert a painted XFCE desktop (screen variance) — isolating the crypt+desktop stage from the
# UKI/loader/LoadOptions plumbing. Needs root (losetup/dmsetup). (roadmap/INSTALLER.md §E5d/§H1)
#   usage: crypt-boot-check.sh <build-dir>
set -u
B="${1:?usage: crypt-boot-check.sh <build-dir>}"
cd "$B"
command -v dmsetup >/dev/null || { echo "  [FAIL] host dmsetup missing (apt install dmsetup)"; exit 1; }
[ -f decoy-desktop.squashfs ] || { echo "  [FAIL] decoy-desktop.squashfs not built"; exit 1; }
[ -f vmlinuz-decoy ] || { echo "  [FAIL] vmlinuz-decoy not built"; exit 1; }

KEY=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')      # 64-byte XTS key -> 128 hex
RL=2048                                                        # rootfs starts at LBA 2048
SZ=$(( $(stat -c%s decoy-desktop.squashfs) / 512 ))               # rootfs length in 512B sectors
echo "  key=${KEY:0:16}… rl=$RL sz=$SZ ($(( SZ/2048 )) MiB)"

rm -f enc.raw serial-crypt.log qmp-crypt.sock shot-crypt.ppm shot-crypt.png
dd if=/dev/zero of=enc.raw bs=512 count=$((RL+SZ)) status=none
LOOP=$(losetup --find --show enc.raw)
cleanup(){ dmsetup remove enctest 2>/dev/null || true; losetup -d "$LOOP" 2>/dev/null || true; }
trap cleanup EXIT
# write decoy-desktop.squashfs THROUGH a dm-crypt mapping (iv_offset 0, device offset RL) so the raw
# disk holds exactly aes-xts-plain64(key, sector) — what init-crypt will map back.
dmsetup create enctest --table "0 $SZ crypt aes-xts-plain64 $KEY 0 $LOOP $RL" || { echo "  [FAIL] host dmsetup create"; exit 1; }
dd if=decoy-desktop.squashfs of=/dev/mapper/enctest bs=1M status=none
sync; dmsetup remove enctest; losetup -d "$LOOP"; trap - EXIT

qemu-system-x86_64 -enable-kvm -cpu host -m 2560 -smp 2 \
  -kernel vmlinuz-decoy -initrd initramfs-crypt.gz \
  -append "console=tty0 console=ttyS0,115200 rw rdinit=/init loglevel=4 decoykey=$KEY decoyrl=$RL decoyiv=0 decoysz=$SZ" \
  -drive file=enc.raw,format=raw,if=virtio \
  -vga virtio -serial file:serial-crypt.log -display none \
  -qmp unix:qmp-crypt.sock,server,nowait >/dev/null 2>&1 &
QPID=$!
for _ in $(seq 1 30); do [ -S qmp-crypt.sock ] && break; sleep 1; done
sleep 500          # autologin -> startx -> XFCE; dm-crypt (software-AES reads) is slower than plaintext
printf '{"execute":"qmp_capabilities"}\n{"execute":"screendump","arguments":{"filename":"%s/shot-crypt.ppm"}}\n' "$B" \
  | nc -U -q4 qmp-crypt.sock >/dev/null 2>&1 || true
sleep 2
kill -9 "$QPID" 2>/dev/null || true

echo "  --- init-crypt serial markers ---"
grep -aE 'decoy-crypt|DECOY-CRYPT-OK|MOUNT-FAIL|DMSETUP-FAIL|NO-DISK|MISSING-CMDLINE' serial-crypt.log 2>/dev/null | tail -6 | sed 's/^/    /'
if [ ! -f shot-crypt.ppm ]; then echo "  [FAIL] no screendump captured"; exit 1; fi
convert shot-crypt.ppm shot-crypt.png 2>/dev/null
SD=$(convert shot-crypt.png -colorspace Gray -format '%[fx:standard_deviation]' info: 2>/dev/null)
if awk "BEGIN{exit !($SD > 0.05)}" 2>/dev/null; then
  echo "  [PASS] decoy XFCE booted from the ENCRYPTED on-disk root via dm-crypt (variance $SD) -> shot-crypt.png"
  exit 0
else
  echo "  [FAIL] blank/flat screen (variance $SD) -- crypt-mount or desktop did not paint"
  exit 1
fi
