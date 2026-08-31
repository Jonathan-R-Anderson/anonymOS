#!/usr/bin/env bash
# Use KVM hardware acceleration when the host exposes /dev/kvm. Without it QEMU
# falls back to TCG pure software emulation, which runs the (already software-
# rendered) desktop ~10-100x slower — the dominant cause of a sluggish cursor and
# UI. The OS requires SMAP/SMEP disabled, so strip them from whichever CPU model
# we use.
# Keep the qemu64 CPU model in both cases: it exposes SSE2 (which the kernel sets
# up) but not AVX/AVX-512, whose extended state the kernel does not enable — using
# -cpu host under KVM exposed those and faulted Hyprland immediately. KVM still
# accelerates execution; only the advertised feature set is constrained.
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  ACCEL=(-enable-kvm -cpu qemu64,-smap,-smep)
  echo "[qemu-run] KVM acceleration enabled"
else
  ACCEL=(-cpu qemu64,-smap,-smep)
  echo "[qemu-run] /dev/kvm unavailable — using slow TCG emulation (expect a sluggish desktop)"
fi

# QEMU binary: prefer the locally-built virgl-capable QEMU >= 9.1 (~/.local/qemu-virgl), which is
# REQUIRED for the GPU/blob path — the Ubuntu repo only ships 8.2.2, which refuses virgl+blob
# ("blobs and virgl are not compatible (yet)").  Built from source, no sudo.  Falls back to system.
QEMU_BIN="${QEMU_BIN:-$HOME/.local/qemu-virgl/bin/qemu-system-x86_64}"
[ -x "$QEMU_BIN" ] || QEMU_BIN="qemu-system-x86_64"
echo "[qemu-run] using $("$QEMU_BIN" --version | head -1)"

# GPU=1 = the virgl GPU desktop in an INTERACTIVE window (gtk + gl=on) -- you can actually see + use it.
# Set HEADLESS=1 alongside GPU=1 to run it windowless (egl-headless + QMP) for automated/remote testing.
# GPU unset = the interactive gtk software (Pixman) desktop.
if [ "${GPU:-0}" = "1" ]; then
  MEM="${MEM:-1024}"
  if [ "${HEADLESS:-0}" = "1" ]; then
    GFX=(-vga std -device virtio-gpu-gl-pci,blob=true,hostmem=256M
         -display egl-headless,rendernode=/dev/dri/renderD128
         -qmp unix:qmp.sock,server,nowait)
    echo "[qemu-run] GPU=1 HEADLESS=1: egl-headless virgl (no window; read serial.log; QMP at qmp.sock)"
  else
    GFX=(-vga std -device virtio-gpu-gl-pci,blob=true,hostmem=256M
         -display gtk,gl=on
         -qmp unix:qmp.sock,server,nowait)
    echo "[qemu-run] GPU=1: interactive virgl desktop (gtk window, gl=on)"
  fi
else
  MEM="${MEM:-512}"
  # HEADLESS=1 on the software path too: no window, serial only.  Needed to boot this
  # from a non-interactive shell (CI, an agent, or over ssh) and just read serial.log.
  if [ "${HEADLESS:-0}" = "1" ]; then
    GFX=(-display none)
    echo "[qemu-run] HEADLESS=1: no window; read serial.log"
  else
    GFX=(-display gtk)
  fi
fi

# A5/F4 persistence: a 32 MiB raw SATA disk on an AHCI controller backs the object
# store across reboots (created on first run; kept out of git via .gitignore).
DISK_IMG="hos-disk.img"

# Which ISO to boot.  Order: first positional arg, then $ISO, then the ISO the build
# actually produces (hos-install.iso), then the legacy hos.iso name this script used to
# hardcode.  `make iso` builds hos-install.iso in the repo root; ./build-in-docker.sh
# writes it to dist/ (or wherever OUT_DIR pointed).
ISO="${1:-${ISO:-}}"
if [ -z "$ISO" ]; then
  for candidate in hos-install.iso dist/hos-install.iso hos.iso dist/hos.iso; do
    [ -f "$candidate" ] && { ISO="$candidate"; break; }
  done
fi
if [ ! -f "$ISO" ]; then
  echo "[qemu-run] no ISO found. Pass one:  ./qemu-run.sh path/to/hos-install.iso" >&2
  echo "[qemu-run] (or set ISO=path; looked for hos-install.iso, dist/hos-install.iso, hos.iso)" >&2
  exit 1
fi
echo "[qemu-run] booting $ISO"
if [ ! -f "$DISK_IMG" ]; then
  qemu-img create -f raw "$DISK_IMG" 32M >/dev/null 2>&1 || dd if=/dev/zero of="$DISK_IMG" bs=1M count=32 status=none
  echo "[qemu-run] created $DISK_IMG (32M) for persistent object store"
fi

# L3b LKL bring-up: a conflict-free NVMe device for LKL to drive (EpinAnonymOS uses AHCI and
# ignores NVMe).  Opt-in via LKL_NVME=1 so the normal desktop boot is unchanged.
NVME=()
if [ "${LKL_NVME:-0}" = "1" ]; then
  NVME_IMG="${NVME_IMG:-$HOME/lkl-build/lkl-nvme.img}"
  [ -f "$NVME_IMG" ] || truncate -s 16M "$NVME_IMG"
  NVME=( -drive file="$NVME_IMG",if=none,id=lklnvme,format=raw
         -device nvme,drive=lklnvme,serial=lkl-nvme-0 )
  echo "[qemu-run] LKL_NVME=1: attaching NVMe $NVME_IMG for the LKL driver"
fi

# L5 LKL bring-up: an xHCI USB controller + a USB keyboard/mouse for LKL's xhci+usbhid to drive.
# Opt-in via LKL_USB=1 so the normal desktop boot is unchanged.
USBDEV=()
if [ "${LKL_USB:-0}" = "1" ]; then
  USBDEV=( -device qemu-xhci,id=xhci
           -device usb-kbd,bus=xhci.0
           -device usb-mouse,bus=xhci.0 )
  echo "[qemu-run] LKL_USB=1: attaching xHCI + usb-kbd + usb-mouse for the LKL driver"
fi

# L6.1 LKL GPU: a secondary bochs-display (class 0x0380) for LKL's bochs-drm to drive -- the QEMU
# proxy for nouveau (EpinAnonymOS keeps the primary VGA).  Opt-in via LKL_GPU=1.
GPUDEV=()
if [ "${LKL_GPU:-0}" = "1" ]; then
  GPUDEV=( -device bochs-display,id=lklgpu )
  echo "[qemu-run] LKL_GPU=1: attaching bochs-display for the LKL DRM driver"
fi

# NETWORK_AND_MARKETPLACE_ROADMAP N0: a NIC for the IPv4 stack.  OPT-IN via NET=1 so the default
# desktop boot has NO NIC (the in-kernel network init is skipped → desktop is never at risk while
# the driver is brought up).  QEMU user-net gives the guest 10.0.2.15, gateway/DNS 10.0.2.2/3.
# e1000 (the fuller driver draft) by default; NET=virtio selects virtio-net once that lands.
NETDEV=( -nic none )
if [ "${NET:-0}" = "1" ] || [ "${NET:-0}" = "e1000" ]; then
  NETDEV=( -netdev user,id=net0 -device e1000,netdev=net0
           -object filter-dump,id=netdump,netdev=net0,file=net.pcap )
  echo "[qemu-run] NET=1: e1000 + user-net (guest 10.0.2.15, gw 10.0.2.2); frames dumped to net.pcap"
elif [ "${NET:-0}" = "virtio" ]; then
  # virtio-net on USER-MODE networking, same as NET=1 but with the paravirtual NIC.
  # This used to be `-netdev socket,listen=127.0.0.1:5609`: a VM-to-VM cable with nothing on
  # the other end, so it could never carry traffic no matter how good the driver was.  virtio
  # is the DEFAULT NIC model on Proxmox, so this is the configuration worth being able to test.
  NETDEV=( -netdev user,id=net0 -device virtio-net-pci,netdev=net0
           -object filter-dump,id=netdump,netdev=net0,file=net.pcap )
  echo "[qemu-run] NET=virtio: virtio-net + user-net (guest 10.0.2.15, gw 10.0.2.2) -- the Proxmox"
  echo "[qemu-run]             default NIC model; frames dumped to net.pcap"
elif [ "${NET:-0}" = "pfsense" ]; then
  # Route this guest through a pfSense (or OPNsense) VM running on the HOST.
  #
  # anonymOS has no hypervisor -- no VT-x/VMCS/EPT anywhere in src/kernel/d -- so it cannot
  # run pfSense itself, and the LKL is a Linux-kernel-as-a-library, not a VMM, so it cannot
  # boot FreeBSD either.  The workable topology is two SIBLING QEMU guests joined by a
  # socket "cable": pfSense holds the WAN and hands out DHCP on its LAN, anonymOS sits
  # behind it and takes a lease.  Nothing in the OS changes -- our DHCP client already works,
  # so it simply leases from pfSense instead of QEMU's built-in 10.0.2.2 user-net.
  #
  # Start pfSense FIRST (it must be listening before this guest connects):
  #
  #   qemu-system-x86_64 -m 2048 -accel kvm -smp 2 \
  #     -drive file=pfsense.img,if=virtio,format=raw \
  #     -netdev user,id=wan -device virtio-net-pci,netdev=wan \
  #     -netdev socket,id=lan,listen=127.0.0.1:${PFPORT:-5610} \
  #     -device virtio-net-pci,netdev=lan
  #
  # Assign in the pfSense console: WAN = vtnet0 (DHCP from QEMU user-net),
  # LAN = vtnet1 (192.168.1.1/24 with its DHCP server on, which is the default).
  # Then boot this side; the HUD should show an ip= in pfSense's LAN subnet and gw=192.168.1.1.
  NETDEV=( -netdev "socket,id=net0,connect=127.0.0.1:${PFPORT:-5610}"
           -device virtio-net-pci,netdev=net0
           -object filter-dump,id=netdump,netdev=net0,file=net.pcap )
  echo "[qemu-run] NET=pfsense: virtio-net cabled to a pfSense VM on 127.0.0.1:${PFPORT:-5610}"
  echo "[qemu-run]              start pfSense FIRST (see the recipe in qemu-run.sh), then this."
  echo "[qemu-run]              Expect a DHCP lease from pfSense's LAN, not QEMU's 10.0.2.x."
fi

# USB log capture: a 2nd FAT USB stick that lkl-boot mounts (via the LKL's usb-storage) and dumps
# /run/klog to (hoslog.txt), so the log survives a hard reset — for debugging the desktop freeze.
# Opt-in via LOGUSB=1; auto-creates + FAT-formats a 64 MiB image.  On real HW: plug in a FAT32 stick.
LOGUSBDEV=()
if [ "${LOGUSB:-0}" = "1" ]; then
  LOGUSB_IMG="$PWD/logusb.img"
  if [ ! -f "$LOGUSB_IMG" ]; then
    dd if=/dev/zero of="$LOGUSB_IMG" bs=1M count=64 status=none
    mkfs.vfat "$LOGUSB_IMG" >/dev/null 2>&1 && echo "[qemu-run] created + FAT-formatted $LOGUSB_IMG"
  fi
  LOGUSBDEV=( -device qemu-xhci,id=logxhci
              -drive if=none,id=logusb,format=raw,file="$LOGUSB_IMG"
              -device usb-storage,drive=logusb,bus=logxhci.0 )
  echo "[qemu-run] LOGUSB=1: FAT USB stick for /run/klog capture -> hoslog.txt on $LOGUSB_IMG"
fi

# A stale server socket makes QEMU fail to bind (and it exits without an obvious error);
# clear them so a relaunch always starts cleanly.
rm -f "$PWD/qmp.sock" "$PWD/mon.sock"

# Forward the HOST's real WiFi (nmcli scan + connect) into the guest over a dedicated COM2
# serial port.  QEMU exposes COM2 as a listening UNIX socket; the host bridge
# (src/util/wifi-host-bridge.py) connects to it and runs real nmcli, while the guest kernel
# maps COM2 <-> /run/wifi/{networks,connect} so the desktop Wi-Fi menu shows REAL nearby
# networks and picking one really connects the host card.  (COM1 stays serial.log/klog;
# COM2 is the second -serial → 0x2F8 in the guest.)
#
# DEFAULT ON when the host actually has a WiFi device (else the guest would gate its own
# fallback off and show an empty menu).  Force with WIFI=1, disable with WIFI=0.
WIFI_DEFAULT=0
if command -v nmcli >/dev/null 2>&1 && nmcli -t -f TYPE dev 2>/dev/null | grep -qx 'wifi'; then
  WIFI_DEFAULT=1
fi
WIFISERIAL=()
if [ "${WIFI:-$WIFI_DEFAULT}" != "0" ]; then
  WIFIBR_SOCK="$PWD/wifibr.sock"
  rm -f "$WIFIBR_SOCK"
  WIFISERIAL=( -chardev "socket,id=wifibr,path=$WIFIBR_SOCK,server=on,wait=off"
               -serial chardev:wifibr )
  # Kill any prior bridge, then launch a fresh one in its OWN session (setsid + stdin from
  # /dev/null) so it is fully independent of this script's exec of QEMU below — a plain
  # background subshell here left QEMU tied to the job and it exited when the launcher
  # detached.  The bridge retries until QEMU creates the socket.
  pkill -f 'wifi-host-bridge.py' 2>/dev/null || true
  setsid python3 "$PWD/src/util/wifi-host-bridge.py" "$WIFIBR_SOCK" \
      > "$PWD/wifi-host-bridge.log" 2>&1 < /dev/null &
  disown 2>/dev/null || true
  echo "[qemu-run] host-WiFi bridge ON via COM2 ($WIFIBR_SOCK); bridge log wifi-host-bridge.log (WIFI=0 to disable)"
else
  echo "[qemu-run] host-WiFi bridge OFF (no host WiFi device, or WIFI=0)"
fi

# HMP monitor on a UNIX socket, ALWAYS — the one thing that turns a wedged guest from a
# rebuild-and-guess loop into a measurement.  When the serial log goes silent you can ask
# the running VM where its CPU actually is, without rebuilding the ISO:
#
#   for i in $(seq 5); do echo "info registers" | nc -N -U mon.sock | grep -E '^[RE]IP'; sleep 1; done
#
# The -N is load-bearing: OpenBSD nc does not shutdown(SHUT_WR) its socket on stdin EOF
# without it, and an HMP session never closes its side, so a plain `nc -U` receives the
# whole register dump and then blocks forever -- the sampling loop wedges on iteration 1,
# which reads exactly like the guest hang you are trying to measure.  (Do NOT append
# `quit` the way scripts/qemu-g*-verify.sh do: that kills the VM, so you get one sample
# and no VM.  `timeout 2 nc -U` also works but costs 2s per sample.)  ^[RE]IP rather than
# ^RIP because QEMU prints EIP= while the vCPU is still in 16/32-bit mode, so a real-mode
# dump would otherwise grep to nothing and look like a hang.
#
# RIP in kernel space and MOVING  -> the kernel loop is alive; userspace is blocked.
# RIP in kernel space and PINNED  -> the kernel is wedged inside one syscall handler.
# RIP in the userspace range      -> the guest process is spinning; no syscall involved.
#
# (`info registers` / `x/20i $pc` / `info mem` all work.  QMP stays on qmp.sock for the
# GPU path — QMP and HMP are separate sockets and coexist fine.)
exec "$QEMU_BIN" \
  -boot d \
  -cdrom "$ISO" \
  -serial file:serial.log \
  "${WIFISERIAL[@]}" \
  -m "$MEM" \
  -smp "${SMP:-1}" \
  -no-reboot \
  -no-shutdown \
  -monitor "unix:$PWD/mon.sock,server=on,wait=off" \
  -d int,cpu_reset,guest_errors \
  -D qemu-debug.log \
  "${ACCEL[@]}" \
  -drive file="$DISK_IMG",if=none,id=hosdisk,format=raw \
  -device ahci,id=ahci0 \
  -device ide-hd,drive=hosdisk,bus=ahci0.0 \
  "${NVME[@]}" \
  "${USBDEV[@]}" \
  "${LOGUSBDEV[@]}" \
  "${GPUDEV[@]}" \
  "${NETDEV[@]}" \
  "${GFX[@]}"
# R2 (GPU stack) is OFF by default: `gtk,gl=on` + a virtio-gpu-gl device gives a BLACK SCREEN on
# many hosts (the GL display path doesn't present the firmware-VGA framebuffer the desktop renders
# to).  To exercise the kernel's virgl path, run HEADLESS instead and read serial.log:
#   ... -vga std -device virtio-gpu-gl-pci -display egl-headless -serial file:serial.log ...
# then look for "[virtio-gpu] R2..." (R2.1 detect, R2.2 transport).  See roadmap R2.
# NOTE: the guest exposes only a RELATIVE PS/2 mouse (no USB/virtio tablet), so
# QEMU must *grab* the host pointer to deliver motion + keystrokes. `show-cursor=on`
# was suppressing that grab — you saw the host cursor float over a frozen guest
# cursor. With it removed: CLICK inside the window to grab input (the host cursor
# hides and the guest cursor starts tracking + the keyboard reaches the guest);
# press Ctrl+Alt+G to release the grab.
