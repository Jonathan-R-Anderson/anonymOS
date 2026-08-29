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
#   port 1  "system"  — the INSTALL TARGET during the live install
# and the installer ISO on port 2 (DVD).  Boot it, open "Install to Disk" on the desktop,
# click Install, wait for "[install] DONE" on the VM serial, then power off, detach the ISO
# (this script's --boot-disk does that), move the system disk to port 0, and boot it.
set -euo pipefail
cd "$(dirname "$0")/.."

VM="EpinAnonymOS-Install"
# Which ISO to attach.  $1 is the action, so the ISO comes from $ISO or is auto-detected:
# `make iso` leaves it in the repo root, ./build-in-docker.sh writes it to dist/.
ISO="${ISO:-}"
if [ -z "$ISO" ]; then
    for candidate in "$PWD/hos-install.iso" "$PWD/dist/hos-install.iso"; do
        [ -f "$candidate" ] && { ISO="$candidate"; break; }
    done
fi
# Where the VM's disks live.  Do not assume "$HOME/VirtualBox VMs/$VM": VirtualBox's
# default machine folder is configurable, and a VM created earlier (or by hand) can
# have its VDIs anywhere.  Resolution order for each disk:
#   1. an explicit SYS_VDI= / STORE_VDI= from the environment
#   2. whatever is actually attached to the VM, asked of VBoxManage
#   3. $VMDIR/<name>.vdi, with VMDIR taken from VirtualBox's own default folder
VBOX_DEFAULT_DIR="$(VBoxManage list systemproperties 2>/dev/null \
    | sed -n 's/^Default machine folder: *//p' | head -1)"
VMDIR="${VBOX_VMDIR:-${VBOX_DEFAULT_DIR:-$HOME/VirtualBox VMs}/$VM}"

# vdi_attached <name-fragment> — path of an attached .vdi whose filename matches, if any.
vdi_attached() {
    VBoxManage showvminfo "$VM" --machinereadable 2>/dev/null \
        | sed -n 's/^"SATA-[0-9]*-[0-9]*"="\(.*\.vdi\)"$/\1/p' \
        | grep -i "$1" | head -1
}

# resolve_vdi <env-value> <name> — print the disk path to use, or nothing.
resolve_vdi() {
    local explicit="$1" name="$2" found
    if [ -n "$explicit" ]; then printf '%s\n' "$explicit"; return; fi
    found="$(vdi_attached "$name")"
    [ -n "$found" ] && { printf '%s\n' "$found"; return; }
    printf '%s\n' "$VMDIR/$name.vdi"
}

STORE_VDI="$(resolve_vdi "${STORE_VDI:-}" store)"
SYS_VDI="$(resolve_vdi "${SYS_VDI:-}" system)"
MEM_MB="${MEM_MB:-3072}"
SYS_GB="${SYS_GB:-8}"
ACTION="${1:-}"

[ -n "$ISO" ] && [ -f "$ISO" ] || {
    echo "ERROR: no installer ISO found (looked for hos-install.iso and dist/hos-install.iso)." >&2
    echo "       Build one with 'make iso' / ./build-in-docker.sh, or set ISO=/path/to/hos-install.iso" >&2
    exit 1
}
[ -r "$ISO" ] || {
    echo "ERROR: $ISO is not readable by $USER (a sudo build leaves it root-owned)." >&2
    echo "       Fix with: sudo chown $USER $ISO" >&2
    exit 1
}
echo "[vbox] using ISO: $ISO"

case "$ACTION" in
    --boot-iso)
        # Re-attach the installer ISO to the EXISTING VM and boot from it, without
        # recreating anything.  This is the non-destructive counterpart to a bare run:
        # it keeps store.vdi and system.vdi exactly as they are.  Use it to boot a new
        # ISO against a VM you already installed into, or when the DVD slot is empty.
        if ! VBoxManage showvminfo "$VM" >/dev/null 2>&1; then
            echo "ERROR: VM '$VM' does not exist — create it first with: $0" >&2
            exit 1
        fi
        VBoxManage controlvm "$VM" poweroff >/dev/null 2>&1 || true
        sleep 1
        # Disks back to their install-time ports (a prior --boot-disk moves system to 0).
        VBoxManage storageattach "$VM" --storagectl SATA --port 0 --device 0 --type hdd --medium none >/dev/null 2>&1 || true
        VBoxManage storageattach "$VM" --storagectl SATA --port 1 --device 0 --type hdd --medium none >/dev/null 2>&1 || true
        [ -f "$STORE_VDI" ] && VBoxManage storageattach "$VM" --storagectl SATA --port 0 --device 0 --type hdd --medium "$STORE_VDI" >/dev/null
        [ -f "$SYS_VDI" ]   && VBoxManage storageattach "$VM" --storagectl SATA --port 1 --device 0 --type hdd --medium "$SYS_VDI"   >/dev/null
        VBoxManage storageattach "$VM" --storagectl SATA --port 2 --device 0 --type dvddrive --medium "$ISO" >/dev/null
        VBoxManage modifyvm "$VM" --boot1 dvd --boot2 disk --boot3 none --boot4 none >/dev/null
        echo "[vbox] attached $ISO to the DVD drive; booting '$VM' from it"
        echo "[vbox] serial log: $VMDIR/serial.log"
        VBoxManage startvm "$VM"
        exit 0
        ;;
    --boot-disk)
        if ! VBoxManage showvminfo "$VM" >/dev/null 2>&1; then
            echo "ERROR: VM '$VM' does not exist — install first with: $0 --start" >&2
            exit 1
        fi
        if [ ! -f "$SYS_VDI" ]; then
            echo "ERROR: installed system disk not found: $SYS_VDI" >&2
            echo "" >&2
            echo "Disks currently attached to '$VM':" >&2
            VBoxManage showvminfo "$VM" --machinereadable 2>/dev/null \
                | sed -n 's/^"SATA-[0-9]*-[0-9]*"="\(.*\)"$/  \1/p' >&2 || true
            echo "" >&2
            echo "Point at it explicitly if it lives elsewhere:" >&2
            echo "  SYS_VDI=/path/to/system.vdi $0 --boot-disk" >&2
            echo "Or, if you have not installed to disk yet, do that first: $0 --start" >&2
            exit 1
        fi
        echo "[vbox] system disk: $SYS_VDI"
        [ -f "$STORE_VDI" ] && echo "[vbox] store disk:  $STORE_VDI"
        VBoxManage controlvm "$VM" poweroff >/dev/null 2>&1 || true
        sleep 1
        # Clear the three slots.  These are "make sure nothing is here" calls, so a slot
        # that is already empty (or has no drive at all) must not abort the script under
        # set -e — VBoxManage errors with VBOX_E_OBJECT_NOT_FOUND in exactly that case.
        VBoxManage storageattach "$VM" --storagectl SATA --port 2 --device 0 --type dvddrive --medium none >/dev/null 2>&1 || true
        VBoxManage storageattach "$VM" --storagectl SATA --port 0 --device 0 --type hdd --medium none >/dev/null 2>&1 || true
        VBoxManage storageattach "$VM" --storagectl SATA --port 1 --device 0 --type hdd --medium none >/dev/null 2>&1 || true
        VBoxManage storageattach "$VM" --storagectl SATA --port 0 --device 0 --type hdd --medium "$SYS_VDI" >/dev/null
        if [ -f "$STORE_VDI" ]; then
            VBoxManage storageattach "$VM" --storagectl SATA --port 1 --device 0 --type hdd --medium "$STORE_VDI" >/dev/null
        fi
        VBoxManage modifyvm "$VM" --boot1 disk --boot2 none --boot3 none --boot4 none >/dev/null
        echo "DVD detached. System disk moved to SATA port 0. Starting '$VM' from the installed disk..."
        VBoxManage startvm "$VM"
        exit 0
        ;;
    ""|--start) ;;
    *)
        echo "Usage: $0 [--start|--boot-iso|--boot-disk]" >&2
        echo "  (no args)    recreate the VM from scratch — DELETES store.vdi and system.vdi" >&2
        echo "  --start      same, then start it" >&2
        echo "  --boot-iso   boot the existing VM from the ISO, keeping its disks" >&2
        echo "  --boot-disk  boot the installed system disk, DVD detached" >&2
        exit 2
        ;;
esac

# Tear down any prior VM of this name (and its disks) so the script is re-runnable.
if VBoxManage showvminfo "$VM" >/dev/null 2>&1; then
    echo "" >&2
    echo "!!  VM '$VM' already exists.  Recreating it DELETES its disks:" >&2
    [ -f "$STORE_VDI" ] && echo "      $STORE_VDI" >&2
    [ -f "$SYS_VDI" ]   && echo "      $SYS_VDI   <- any installed system on it" >&2
    echo "    To boot the existing VM instead, Ctrl-C now and run:  $0 --boot-iso" >&2
    echo "    Continuing in 5s..." >&2
    sleep 5
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
    --boot1 dvd --boot2 disk --boot3 none --boot4 none \
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

  Boot the installed system (detach the DVD and move system.vdi to SATA port 0):
    $0 --boot-disk
EOF

case "$ACTION" in
    --start)     VBoxManage startvm "$VM" ;;
esac
