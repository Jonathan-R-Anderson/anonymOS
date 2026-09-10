#!/usr/bin/env python3
# deps/decoy-os/wrap-decoy-payload.py — assemble the decoy region the installer writes at
# sysFirst+1 (roadmap/INSTALLER.md §E5d/§H1 Level 2). The installer XTS-encrypts these bytes with
# the decoy master key, one 512B sector per XTS data unit (unit = offset from sysFirst+1), and the
# §E5 pre-boot loader decrypts them back. Layout:
#
#   sector 0            : boot descriptor  — "ANOSBOOT" + u64 LE uki_bytes + u64 LE rootfs_sectors
#   sectors 1..U        : decoy-crypt-uki.efi  (the desktop UKI the loader StartImages)
#   sectors U+1..       : decoy-desktop.ext4   (the believable rootfs; init-crypt dm-crypt-mounts it)
#
# The loader reads uki_bytes to load just the UKI, and hands rootfs_sectors + the region geometry
# to init-crypt on the kernel cmdline so it can dm-crypt-mount the ext4 that follows. Keeping the
# ext4 in the SAME encrypted region (not a second GPT slot) means the installer writes it with no
# code change — it already streams this module at sysFirst+1.
#   usage: wrap-decoy-payload.py <uki.efi> <rootfs.ext4> <out.img>
import struct, sys, os

if len(sys.argv) != 4:
    sys.exit("usage: wrap-decoy-payload.py <uki.efi> <rootfs.ext4> <out.img>")
uki_path, ext4_path, out_path = sys.argv[1:4]

uki = open(uki_path, "rb").read()
ext4_size = os.path.getsize(ext4_path)
rootfs_pad = (-ext4_size) % 512               # pad the rootfs image up to a 512B sector boundary
rootfs_sectors = (ext4_size + rootfs_pad) // 512

desc = b"ANOSBOOT" + struct.pack("<QQ", len(uki), rootfs_sectors)
desc += b"\0" * (512 - len(desc))
uki_pad = (-len(uki)) % 512          # pad the UKI so the ext4 starts on a sector boundary

with open(out_path, "wb") as out:
    out.write(desc)
    out.write(uki)
    out.write(b"\0" * uki_pad)
    with open(ext4_path, "rb") as f:  # stream the multi-GB rootfs, don't slurp it into RAM
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
    if rootfs_pad:
        out.write(b"\0" * rootfs_pad)

uki_sectors = (len(uki) + 511) // 512
total = 512 + uki_sectors * 512 + ext4_size
print("[wrap] descriptor + UKI(%d B, %d sec) + rootfs(%d B, %d sec) -> %s (%.1f MiB)"
      % (len(uki), uki_sectors, ext4_size, rootfs_sectors, out_path, total / (1 << 20)))
print("[wrap] loader will hand init-crypt: decoyiv=%d decoysz=%d (decoyrl = region_lba + %d)"
      % (1 + uki_sectors, rootfs_sectors, 1 + uki_sectors))
