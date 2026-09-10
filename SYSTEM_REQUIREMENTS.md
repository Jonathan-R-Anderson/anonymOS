# anonymOS (EpinAnonymOS) — System Requirements

A deniable operating system: one disk holds a **decoy OS** (a believable Alpine Linux + XFCE
workstation) and a **hidden OS** (anonymOS / Hyprland). A pre-boot password chooses which one
boots; a wrong password reveals nothing, and the decoy is indistinguishable from an ordinary
encrypted machine.

## The install VM is heavier than the running OS

The installer ISO (`hos-install.iso`, ~2 GB) **embeds the entire decoy desktop** (compressed) so it
can be encrypted onto the disk. The bootloader loads that ~1 GB decoy image into RAM at install
time, so the **install VM needs a bit more RAM than the installed OS ever does.** This is a one-time
cost — after install, the decoy lives encrypted on disk and boots by loading only a ~14 MB kernel
image plus on-demand `dm-crypt` reads.

### Install VM (booting `hos-install.iso`)

| Resource | Minimum | Recommended | Why |
| --- | --- | --- | --- |
| RAM | 6 GB | 8 GB | The bootloader loads the ~1 GB compressed decoy image plus the anonymOS payload into memory. |
| Disk | 20 GB | 40 GB+ | Holds the boot ESP + the decoy system + the outer volume (which hides the hidden OS and is random-filled for deniability). |
| Firmware | **UEFI** | UEFI | The ISO is UEFI-only. There is no legacy-BIOS boot path. |
| CPU | x2APIC on, **4 vCPU** | x2APIC on, 4 vCPU | The kernel **requires x2APIC**; without it the boot faults immediately. AES-NI strongly recommended (the disk is XTS-encrypted). **4 vCPU, not 2** — the desktop is software-rendered (llvmpipe) and the compositor keeps a core busy; with only 2 cores it starves input handling and the installer's text fields become unresponsive while typing. |
| Graphics | — | 128 MB VRAM | The installer runs a graphical (Hyprland) desktop. |
| CD/DVD bus | **SATA/AHCI** | SATA/AHCI | Attach the ISO on an AHCI controller, not legacy IDE — the bootloader's IDE path is slow reading a large image. VirtualBox's default SATA is fine. |

### VirtualBox setup (CLI — some settings are not in the GUI defaults)

```sh
VM="anonymOS"
VBoxManage createvm --name "$VM" --ostype Linux_64 --register
VBoxManage modifyvm "$VM" --firmware efi --x2apic on --memory 6144 --cpus 4 --vram 128
VBoxManage createhd --filename "$HOME/VirtualBox VMs/$VM/disk.vdi" --size 20480
VBoxManage storagectl "$VM" --name SATA --add sata --controller IntelAhci
VBoxManage storageattach "$VM" --storagectl SATA --port 0 --device 0 --type hdd --medium "$HOME/VirtualBox VMs/$VM/disk.vdi"
VBoxManage storageattach "$VM" --storagectl SATA --port 1 --device 0 --type dvddrive --medium /path/to/hos-install.iso
VBoxManage modifyvm "$VM" --boot1 dvd --boot2 disk
```

The two non-obvious settings that will otherwise break the boot: **`--firmware efi`** (the ISO is
UEFI-only) and **`--x2apic on`** (VirtualBox leaves x2APIC off on new VMs; the kernel needs it).

### QEMU setup

```sh
qemu-system-x86_64 -enable-kvm -cpu host -m 6144 -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=OVMF_VARS.fd \
  -device ahci,id=ahci \
  -drive id=cd,file=hos-install.iso,format=raw,if=none,media=cdrom -device ide-cd,drive=cd,bus=ahci.0 \
  -drive id=hd,file=disk.raw,format=raw,if=none -device ide-hd,drive=hd,bus=ahci.1
```

## Running the installed OS (after install)

Once installed, boot the disk (remove the ISO). The requirements drop:

| OS | RAM | Notes |
| --- | --- | --- |
| Decoy (Alpine + XFCE) | 2–3 GB | Boots via the pre-boot password → `dm-crypt` → the compressed rootfs → XFCE. The decoy's writes are kept in RAM (a live/overlay root), so **changes do not persist across reboots** yet — see the note below. |
| Hidden (anonymOS / Hyprland) | 4 GB | The real system; software-rendered desktop (llvmpipe). |

Firmware/CPU are the same as the install (UEFI + x2APIC). You can lower the VM's RAM to 4 GB once
the OS is installed.

## Notes / limitations

- **Decoy persistence:** the decoy currently boots its rootfs read-only with a RAM (tmpfs) overlay
  for writes, so files created in the decoy are lost on reboot. This keeps the install light (the
  full desktop ships as a ~1 GB compressed image instead of a ~3 GB raw one). A persistent on-disk
  overlay is a planned follow-up.
- **Why compressed:** the raw 2.4 GB desktop could not be loaded as a single bootloader module
  (the bootloader ran out of memory / stalled). Shipping it as a squashfs the kernel decompresses
  at mount time keeps every file while making the install work in a normal VM.
