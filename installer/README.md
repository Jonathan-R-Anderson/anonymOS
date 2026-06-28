# EpinAnonymOS — disk installer

Install the OS onto a **bootable hard disk** (UEFI/GPT) and boot it with no ISO/CD.

```sh
make hos.iso                      # build the boot payload (the cd/ tree)
installer/install-to-disk.sh      # → hos-installed.img  (GPT + ESP + limine UEFI)
installer/boot-installed.sh       # boot it in QEMU via OVMF (HEADLESS=1 for windowless)
```

To install onto a **real disk / USB stick**:

```sh
sudo dd if=hos-installed.img of=/dev/sdX bs=4M conv=fsync   # /dev/sdX = your target
```
then boot that disk on a UEFI machine — it loads straight into EpinAnonymOS.

## What it does

`install-to-disk.sh` turns the live boot payload into a self-booting disk:

1. a raw image with a **GPT** label and one **EFI System Partition** (FAT32),
2. the **limine UEFI** bootloader at `/EFI/BOOT/BOOTX64.EFI`,
3. the whole boot payload (`kernel.elf` + every module + `limine.conf`) copied onto the
   ESP, preserving the `cd/` layout so `limine.conf`'s `boot():/…` paths resolve.

No root is needed: the ESP is formatted and filled in place with **mtools**
(`mformat`/`mcopy` via the `image@@offset` syntax), never a loopback mount.

`boot-installed.sh` boots the result under **OVMF** (UEFI firmware) with the image
attached as **virtio-blk** — UEFI boots it, while the kernel ignores it (it is not AHCI,
so the object-store driver leaves it alone, and not one of the device classes
`0x0380`/`0x0c03`/`0x0108` that trigger the in-kernel LKL launch). A separate AHCI disk
(`hos-disk.img`) remains the persistent object store, exactly as on an ISO boot.

Verified: the installed disk boots via UEFI → limine → kernel → full desktop
(`DOMAINMGR: loaded 11 domains`), 0 faults.

## Relationship to the Calamares plan (`roadmap/INSTALLER.md`)

`roadmap/INSTALLER.md` describes a richer, **in-OS graphical** installer based on
Calamares (Welcome/Disk/Identity/Summary pages, a declarative `install.json` consumed on
first boot). That is a separate, much larger effort: Calamares is Qt-based and, while it
builds fine against musl, it pulls in the **entire Qt runtime + KPMcore/libparted
partitioning stack**, none of which is built in this repo (the GUI stack here is
GTK/Cairo on Weston, not Qt). A good architectural fit would be a **native Wayland/GTK
installer client** (in the style of the Domain Manager) that drives this OS's own object
filesystem + declarative config rather than dragging in KPMcore.

This host-side installer is the **working foundation**: it is exactly the disk-layout +
bootloader-install + payload-copy logic that any in-OS installer's "Installation" phase
would ultimately call.
