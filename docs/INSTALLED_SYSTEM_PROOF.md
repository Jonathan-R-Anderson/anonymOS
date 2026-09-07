# Proving §F on a real installed system

`tests/immutable-rootless.txt` measures a **live-media** boot, where the object store deliberately
stays in RAM because the disk is reserved for the installer. That is why `IMMUTABLE-1` reports
`backing-on-disk=0` there and the honest summary is 3/4.

This is the other half: install the OS to a disk, boot **that**, and read the same gates. Verified
2026-09-07 — every line below came out of a real boot.

## Procedure

```bash
# 1. Build a TEST image carrying the unattended-install trigger.
#    AUTOINSTALL=1 stages a boot module named "autoinstall"; a shipped ISO never has it, so the
#    trigger is absent from the image rather than disabled inside it.
make AUTOINSTALL=1 all

# 2. Boot it against a blank disk.  The installer runs unattended, through the SAME
#    installBegin/step path the GUI uses.
rm -f hos-disk.img
HEADLESS=1 MEM=3072 ./qemu-run.sh          # wait for "[install] AUTOINSTALL complete"

# 3. Boot the INSTALLED disk, no ISO attached, under UEFI (the installed system boots
#    BOOTX64.EFI, so SeaBIOS will not do).
cp /usr/share/OVMF/OVMF_VARS_4M.fd /tmp/ovmf_vars.fd
qemu-system-x86_64 -machine q35 -m 3072 -smp 1 -enable-kvm -no-reboot -no-shutdown \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=/tmp/ovmf_vars.fd \
  -drive file=hos-disk.img,if=none,id=hosdisk,format=raw \
  -device ahci,id=ahci0 -device ide-hd,drive=hosdisk,bus=ahci0.0 \
  -serial file:/tmp/installed-serial.log -display none

# 4. Restore the blank fixture, or every other suite starts measuring an installed system.
cp /tmp/hos-disk.backup.img hos-disk.img
```

## Result

```
[objstore] installed system (GPT) — store in the free tail, LBA 0x144800..0x7fffde (3446 MiB)
[objstore] mounted: apps=0x2 boots=0x2

[F]     immutable-1 parts: usr-write-refused=1 usr-readable=1 verity-verifies=1 backing-on-disk=1
[F] IMMUTABLE-1 system-tree-read-only-and-verified  PASS
[F] EROFS: write refused to the read-only system tree: /usr/lib/libc.so
[F]     immutable-2 parts: usr-ro=1 etc-rw=1 var-rw=1 usr-write-enforced=1 (openW=30 openR=0)
[F] IMMUTABLE-2 state-split-enforced  PASS
[F] IMMUTABLE-3 atomic-update-and-rollback  PASS
[F] IMMUTABLE-4 no-w-xor-x-pages  PASS
[F] ROOTLESS-1..4  PASS

[F] SUMMARY immutable 4/4 -> IMMUTABLE;  rootless 4/4 -> ROOTLESS

[4.4] D2 slot resolve: targetSlot=1 firstLba=673792 sectors=655360 -- inactive slot located
```

Two things worth noting beyond the summary.

`boots=0x2` is the persistence proof: the store's boot counter is read from and written back to
disk, so it climbing across reboots is what "the store is really on the disk" means.

The D2 line resolves a **real** slot — `firstLba=673792` is exactly where the installer put
partition 3 — and it is the slot the system is *not* running from. That is the A/B invariant
holding on actual hardware layout rather than on a fixture.

## Installed layout

```
1   2048       18431      8.0 MiB    EF00   boot ESP (arbiter → chainloads a slot)
2   18432      673791     320 MiB    0700   slot A
3   673792     1329151    320 MiB    0700   slot B
```
