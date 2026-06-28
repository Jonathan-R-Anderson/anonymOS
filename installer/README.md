# EpinAnonymOS — disk installer

Install the OS onto a **bootable hard disk** (UEFI/GPT) and boot it with no ISO/CD.

```sh
make hos.iso                      # build the boot payload (the cd/ tree)
installer/install-to-disk.sh      # → hos-installed.img  (GPT + ESP + limine UEFI)
installer/boot-installed.sh       # boot it in QEMU via OVMF (HEADLESS=1 for windowless)
```

## Real hardware

Two ways to get onto a physical machine — **both are bootable on real BIOS *and* UEFI**:

```sh
# A) Live boot — write the ISO to a USB stick (it is isohybrid: MBR + GPT/ESP).
sudo dd if=hos.iso of=/dev/sdX bs=4M conv=fsync status=progress

# B) Installed disk — write the GPT/UEFI image to the target disk or a USB stick.
sudo dd if=hos-installed.img of=/dev/sdX bs=4M conv=fsync status=progress
```
`/dev/sdX` is the **whole device** (e.g. `/dev/sdb`), not a partition — double-check with
`lsblk` first; `dd` to the wrong device destroys it.

What to expect on real hardware (this is the [bare-metal](../roadmap/BARE_METAL_ROADMAP.md)
bring-up edge — "continue development" territory):

- **Boot + display:** limine sets up the firmware framebuffer (GOP under UEFI / VBE under
  BIOS) at the panel's native mode; the kernel renders the Weston/Pixman desktop into it
  in software. No GPU acceleration on metal yet (virgl is QEMU-only; nouveau is future
  work) — the desktop is software-composited.
- **Input:** modern boards are USB-only (no PS/2). The kernel auto-launches the embedded
  **LKL** when it sees a USB xHCI controller (class `0x0c03`) and bridges USB HID →
  keyboard/mouse. This is the part most likely to need iteration on specific hardware.
- **Storage:** the AHCI driver backs the object store on a real SATA disk; NVMe is driven
  via LKL.

Prefer **UEFI** boot mode in the firmware setup if the machine offers both.

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
