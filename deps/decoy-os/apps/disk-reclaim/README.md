# disk-reclaim — collapse the machine to the decoy OS

A duress / anti-forensic tool for the decoy OS. When the snoop-detection heuristics fire,
it **deletes every partition that is not Linux and not boot-related** (the foreign /
hidden-OS partitions — i.e. anonymOS), **securely destroys their contents**, and **grows
the decoy's own storage to fill the reclaimed space**. Afterwards the partition table shows
only the ESP/boot + one decoy Linux partition spanning the disk: the decoy is now the only
OS, and there is no unexplained region to suggest a hidden one ever existed.

This is the same concept VeraCrypt calls a decoy/hidden OS pair (vendored at
`deps/VeraCrypt`); disk-reclaim is the "burn the hidden OS on duress" half.

## What it does, precisely

1. **Discovers** the disk backing `/` and its partitions **from the block/partition layer**
   (`lsblk -J`, `sfdisk -J`, `blockdev`) — see *Real geometry* below.
2. **Classifies** each partition on that disk:
   - **KEEP** if its GPT type is Linux/boot (ESP, BIOS-boot, XBOOTLDR, Linux fs/root/
     swap/LVM/RAID/LUKS/home/srv/…), **or** it is the running root's own partition, **or**
     anything on it is currently mounted / in use.
   - **RECLAIM** otherwise (non-Linux, non-boot, idle) — this is where the hidden OS lives,
     appearing as a foreign type (e.g. Microsoft basic data) or an unknown/random blob.
3. **Destroys** each RECLAIM partition (default `--wipe shred`): first overwrites the first
   and last 16 MiB (kills the dm-crypt/VeraCrypt key material immediately, so an interrupted
   run still leaves the data undecryptable), erases signatures, `blkdiscard`s (SSD), then
   overwrites **every byte**.
4. **Deletes** the RECLAIM partition entries, then **grows the decoy**:
   `growpart` (partition) → `cryptsetup resize` (plain dm-crypt) → `resize2fs` (ext4).

Only space **contiguous and trailing** to the root partition can be absorbed by the grow;
any RECLAIM partition that isn't gets wiped and deleted but left as unallocated space (still
achieves "only the decoy remains" — there's just free space, not a second OS). The plan
prints this explicitly.

## Real geometry (why never `df`)

The decoy runs **qafs** (`apps/qafs`), a FUSE filesystem that spoofs `statfs` on its mount so
`df` reports a chosen size. disk-reclaim therefore **never** reads `df`/`statvfs`; all sizes
and offsets come from `sfdisk -J`, `blockdev`, and `/sys/class/block/*/size`, which qafs
cannot influence. A qafs mount is a FUSE mount, not a partition, so it never appears as a
reclaim target either.

## Safety model

- **Dry-run is the default.** With no `--commit`/`--fire` it only reads and prints the plan
  (KEEP/RECLAIM per partition, bytes destroyed, resulting layout). Nothing is written.
- **A partition is never wiped if it is mounted or in use**, regardless of type — re-checked
  immediately before execution.
- Refuses non-GPT disks (`--allow-mbr` to override), refuses if it can't resolve the root's
  own disk/partition, and never deletes the root or a KEEP partition.
- `--commit` requires typing `RECLAIM` at a prompt (`--yes` to skip).

## Triggering

**Manual (operator):**
```sh
disk-reclaim                       # dry-run: show the plan, change nothing
disk-reclaim --commit              # execute, after typing RECLAIM
disk-reclaim --commit --yes        # execute, no prompt
```

**Armed auto (the heuristic engine):** the non-interactive path is gated by an arming key so
a stray `--fire` can't nuke the disk. Provision once, as the operator:
```sh
install -d -m 700 /etc/disk-reclaim
head -c32 /dev/urandom | xxd -p -c64 > /etc/disk-reclaim/arm.key   # the arming secret
chmod 600 /etc/disk-reclaim/arm.key
```
Then the snoop-detection code fires it with the matching key:
```sh
disk-reclaim --fire --key "$(cat /etc/disk-reclaim/arm.key)"
#   or:  DISK_RECLAIM_KEY=... disk-reclaim --fire
```
Without `/etc/disk-reclaim/arm.key`, or on a key mismatch, `--fire` refuses. Leaving the key
unprovisioned keeps the auto-path **disarmed** by default.

Options: `--wipe {shred,header,none}` (default `shred`), `--passes N`, `--random`,
`--disk /dev/X`, `--keep <kname|gptname>` (repeatable), `--allow-mbr`.

## Install / packaging

- Staged by `stage-apps.sh` via the `bin/` convention: `bin/disk-reclaim` →
  `/usr/local/bin/disk-reclaim` (mode 755). No service — it is triggered on demand.
- Runtime tools are added to both rootfs variants via `RECLAIM_PKGS` in the decoy Makefile
  (`sfdisk lsblk util-linux-misc e2fsprogs-extra cryptsetup gptfdisk`). **Verify those exact
  package names against your Alpine version** — Alpine splits util-linux (blockdev/wipefs/
  blkdiscard/partx are in `util-linux-misc`); `resize2fs` is in `e2fsprogs-extra`; `sgdisk`
  is in `gptfdisk`. `growpart` (cloud-utils) is optional; without it the tool falls back to
  `sfdisk` for the partition grow.

## Assumptions that must hold on the installed system

The installer that lays anonymOS + decoy onto a disk is still Phase-work, so confirm these
once it exists (they drive the tool's correctness):

- The disk is **GPT**.
- The decoy root is **ext4** on a **plain dm-crypt** mapping (matches
  `deps/decoy-os` today: `mkfs.ext4 -L decoyroot`, aes-xts dm-crypt). If the installed root
  is instead directly on a partition, the tool auto-detects that and skips the crypt-resize
  step. Other fs/crypt layouts (btrfs, LVM, LUKS) would need their own resize path added.
- The hidden-OS partition(s) sit **after** the decoy root, so the freed space is contiguous
  and can be absorbed. If they sit before it or interleave with KEEP partitions, they are
  still wiped+deleted but the space is left unallocated (see the plan's `note:` line).

## Testing (do NOT test on a real disk)

Use a throwaway loopback GPT disk in a VM:
```sh
truncate -s 8G /tmp/t.img
sgdisk -n1:0:+64M -t1:ef00 -n2:0:+1G -t2:8300 -n3:0:0 -t3:0700 /tmp/t.img   # ESP + Linux + "foreign"
losetup -Pf /tmp/t.img
disk-reclaim --disk /dev/loopXpN...      # inspect the plan; then --commit to rehearse
```
A fixture unit-test of the classification/grow math (no root, no real disk) is straightforward
to run by importing the script and stubbing `out()`/`have()` with synthetic `lsblk`/`sfdisk`
JSON; I could not execute one here because this session's safety classifier blocks running the
tool. Recommended before shipping.

## Deniability caveat (important)

The **existence of this tool in the decoy is itself a tell**: a forensic examiner who finds
`/usr/local/bin/disk-reclaim` (a readable Python script that deletes non-Linux partitions and
grows the decoy) learns that a hidden OS was expected. A kill-switch is evidence of what it
guards. Before shipping, decide how to handle that — e.g. compile/obfuscate it under an
innocuous name, deliver it only into RAM at boot, fold it into an existing admin tool, or
have the heuristic engine carry the logic itself rather than a standalone named binary. Left
as-is it is clear and auditable, which is right for development but not for the field.
