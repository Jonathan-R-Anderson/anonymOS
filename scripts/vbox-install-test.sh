#!/usr/bin/env bash
# Create (or recreate) a VirtualBox VM that boots hos-install.iso and lets you install
# EpinAnonymOS to a virtual disk, then boot the installed disk — the full in-OS installer
# flow, end to end, on real UEFI firmware.
#
#   Build first:   make hos-install.iso          (or: scripts/mk-install-iso.sh)
#   Then:          scripts/vbox-install-test.sh   [--start]
#
# The VM has TWO SATA disks:
#   port 0  "store"   — the live session's object store (scratch; not the install target)
#   port 1  "system"  — the INSTALL TARGET; EpinAnonymOS is installed here and booted after
# and the installer ISO on port 2 (DVD).  Boot it, open "Install to Disk" on the desktop,
# click Install, wait for "[install] DONE" on the VM serial, then power off, detach the ISO
# (this script's --boot-disk does that) and boot the system disk.
set -euo pipefail
cd "$(dirname "$0")/.."

VM="EpinAnonymOS-Install"
ISO="$PWD/hos-install.iso"
VMDIR="${VBOX_VMDIR:-$HOME/VirtualBox VMs/$VM}"
STORE_VDI="$VMDIR/store.vdi"
SYS_VDI="$VMDIR/system.vdi"
MEM_MB="${MEM_MB:-3072}"
SYS_GB="${SYS_GB:-8}"

[ -f "$ISO" ] || { echo "ERROR: $ISO not found — run 'make hos-install.iso' first." >&2; exit 1; }

# Tear down any prior VM of this name (and its disks) so the script is re-runnable.
if VBoxManage showvminfo "$VM" >/dev/null 2>&1; then
    echo "==> removing existing VM '$VM'"
    VBoxManage controlvm "$VM" poweroff >/dev/null 2>&1 || true
    sleep 1
    VBoxManage unregistervm "$VM" --delete >/dev/null 2>&1 || true
fi

echo "==> creating VM '$VM'"
VBoxManage createvm --name "$VM" --ostype Linux_64 --register >/dev/null
# 64-bit + UEFI firmware (the installed disk is UEFI/limine) + x2APIC (the kernel requires it).
VBoxManage modifyvm "$VM" \
    --memory "$MEM_MB" --cpus 2 --firmware efi \
    --x2apic on --longmode on --ioapic on \
    --graphicscontroller vmsvga --vram 64 \
    --uart1 0x3F8 4 --uartmode1 file "$VMDIR/serial.log" >/dev/null

echo "==> AHCI SATA controller + disks (store + system) + installer DVD"
VBoxManage storagectl "$VM" --name SATA --add sata --controller IntelAhci --portcount 4 --bootable on >/dev/null
VBoxManage createmedium disk --filename "$STORE_VDI" --size 2048 --format VDI >/dev/null
VBoxManage createmedium disk --filename "$SYS_VDI"   --size $((SYS_GB*1024)) --format VDI >/dev/null
VBoxManage storageattach "$VM" --storagectl SATA --port 0 --device 0 --type hdd     --medium "$STORE_VDI" >/dev/null
VBoxManage storageattach "$VM" --storagectl SATA --port 1 --device 0 --type hdd     --medium "$SYS_VDI"   >/dev/null
VBoxManage storageattach "$VM" --storagectl SATA --port 2 --device 0 --type dvddrive --medium "$ISO"       >/dev/null

cat <<EOF

==> VM '$VM' is ready.
    RAM ${MEM_MB} MiB · UEFI · x2APIC · SATA(AHCI): port0=store(2G) port1=system(${SYS_GB}G) port2=DVD
    Serial log: $VMDIR/serial.log

  Install:
    1. VBoxManage startvm "$VM"            (or: $0 --start)
    2. On the desktop, open "Install to Disk" → click Install.
    3. Watch the install:   tail -f "$VMDIR/serial.log"   → wait for "[install] DONE".
    4. Power off the VM.

  Boot the installed system (detach the DVD so it boots the system disk):
    $0 --boot-disk
EOF

case "${1:-}" in
    --start)     VBoxManage startvm "$VM" ;;
    --boot-disk) VBoxManage storageattach "$VM" --storagectl SATA --port 2 --device 0 --type dvddrive --medium none >/dev/null
                 echo "DVD detached. Starting '$VM' from the installed system disk..."
                 VBoxManage startvm "$VM" ;;
esac
