# Bare-metal roadmap — run EpinAnonymOS on real hardware

**North star (user, 2026-06-26):** run the OS on an actual machine without a VM, with a
software-rendered desktop, and drive real peripherals **and the GPU** by **reusing Linux's drivers
via LKL** (the Linux Kernel Library) rather than writing native drivers. **Architecture decision:
EMBED LKL** (chosen over minimal-native-drivers and Linux-underneath).

## Target machine (the dev box — inventoried 2026-06-26)
- **Boot:** Legacy BIOS (limine BIOS path already in the ISO).
- **Storage:** Intel 200-series SATA, AHCI mode `[8086:a282]` (no NVMe). 2× SATA disk.
- **GPU:** NVIDIA GTX 1080 (GP104, **Pascal**) `[10de:1b80]` — the only GPU (i9-9900**KF**, no iGPU).
- **Input:** USB HID only (Intel xHCI `[8086:a2af]` + ASMedia xHCI). **No PS/2.**
- **CPU:** i9-9900K (8c/16t), ACPI present.

## The two layers (key architecture)
1. **The software desktop needs NO LKL.** limine boots → VBE/GOP framebuffer → Weston **pixman**
   (CPU) → the desktop renders. Hardware-agnostic; works on this machine today. Storage for boot can
   stay native AHCI (already implemented).
2. **LKL provides the device drivers** — USB input, the GPU, networking, etc. — by running the Linux
   kernel as a library *inside* EpinAnonymOS and reusing Linux's driver tree. This is the device track,
   layered on top of the working software desktop.

## What LKL is, and the honest scope
LKL = the Linux kernel compiled as a library (`liblkl.a`) with a host-operations interface
(`struct lkl_host_operations`: memory, threads, timers, console, IRQs). Its **standard** use is
software subsystems (filesystems, TCP/IP) over **virtio**, in a host process. **Driving real PCI
hardware through it is non-standard** — you must build a bridge that hands LKL: PCI config + BARs
(MMIO), real interrupt delivery (`lkl_trigger_irq`), and DMA-able physical memory. That bridge is the
hard, research-grade part — written **once**, it inherits Linux's entire driver tree. The GPU (nouveau
+ real DMA + display scanout on Pascal) is the hairiest target. **This is a multi-month effort.**

---

## BM0 — Boot + software desktop on real hardware (verify; no LKL)
Write the ISO to a USB stick, boot the machine (BIOS), confirm: limine → kernel boots → framebuffer
comes up on the 1080 (VBE) → the software desktop renders; AHCI finds the SATA disk. Expected to work;
establishes the baseline + flushes real-HW boot quirks (memory map, ACPI, framebuffer mode). **Input
won't work yet** (no PS/2; that's the LKL track). The user runs this; report back.

## L1 — Build LKL (`liblkl.a`) — the feasibility gate  *(in progress)*
Clone `github.com/lkl/linux`, `make -C tools/lkl`. Deps: flex + bison + elfutils (no-sudo via conda).
**Verify:** `liblkl.a` builds; a host smoke test (`lkl_start_kernel` → boots → mounts a tmpfs) runs.
Proves the LKL toolchain works in this environment.

## L2 — LKL host ops + boot inside EpinAnonymOS
Implement `struct lkl_host_operations` against kernel primitives: memory (from the phys allocator),
threads/sched (EpinAnonymOS tasks), timers, console (→ `klog`), panic, mutex/sem. Link `liblkl.a` into
the kernel (or a privileged component), call `lkl_start_kernel`. **Verify:** the Linux kernel boot log
appears on serial — "Linux version …" from inside EpinAnonymOS.

## L3 — The hardware bridge (the hard, research-grade core)
Give LKL real hardware access, one capability at a time, proven on the SIMPLEST device first (AHCI):
- **PCI:** an LKL PCI host bridge that forwards config-space + BAR reads/writes to EpinAnonymOS's PCI
  (we already enumerate PCI for virtio-gpu).
- **MMIO:** map the device BARs into LKL's address space (ioremap → EpinAnonymOS page mapping).
- **Interrupts:** route the device's IRQ (MSI/IOAPIC) into `lkl_trigger_irq` — needs real interrupt
  handling (the OS currently polls; this is the piece that may force proper IRQ support, [[weston-perf-profiling]]).
- **DMA:** LKL's DMA allocations must be physically contiguous + device-reachable (identity region or IOMMU).
**Verify:** LKL's `ahci` driver reads a sector off the real SATA disk (or QEMU AHCI first).

## L4 — Bridge LKL's devices to EpinAnonymOS
LKL has its own VFS/`/dev`. Reach its device nodes via the LKL syscall interface
(`lkl_sys_open`/`read`/`write`/`ioctl`) and surface them as EpinAnonymOS devices, so the existing
userspace + desktop use them unchanged. **Verify:** an EpinAnonymOS `/dev/*` backed by an LKL device.

## L5 — USB HID via LKL (the usable-desktop unlock)
LKL's `xhci_hcd` + `usbhid` drive the real USB keyboard/mouse → bridge LKL's `/dev/input/event*` to
EpinAnonymOS's input rings (`g_kbd_ring`/`g_mouse_ring`). **Develop/verify in QEMU first**
(`-device qemu-xhci -device usb-kbd -device usb-mouse`), then it works on real xHCI unchanged.
**Verify:** typing/moving drives the desktop with PS/2 removed.

## L6 — GPU via LKL (the research frontier)
LKL's `nouveau` drives the GTX 1080: real PCI BARs + MSI + large DMA + **display scanout / mode-setting**
to the physical monitor — the hardest integration. Mesa's `nouveau`/`nvk` userspace runs on top via the
Linux ABI (this is the half that "comes from the Linux compatibility layer"). Bridge LKL's `/dev/dri/cardN`
to the existing DRM-uABI seam. **Verify:** the desktop composites on the real GPU. (Pascal's signed-firmware
limits apply, same as upstream nouveau.)

## Sequencing
BM0 (verify) → L1 (build LKL) → L2 (boot LKL inside) → L3 (hardware bridge, on AHCI) → L4 (device bridge)
→ L5 (USB HID — usable desktop) → L6 (GPU — long). L3 is the make-or-break research milestone; everything
device-related rides on it.
