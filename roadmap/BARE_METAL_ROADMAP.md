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

## L1 — Build LKL (`liblkl.a`) — the feasibility gate  ✅ **DONE (2026-06-26)**
Cloned `github.com/lkl/linux`, `make -C tools/lkl` (deps flex+bison+elfutils, no-sudo via conda env
`lkl`). Built `liblkl.a` (351 MB) + `liblkl.so` + headers (`~/lkl-build/linux/tools/lkl/`). **Verified:
`./tests/boot` boots `Linux version 6.12.0+` inside the library** (irqs/timers/memory/console/`Run
/init`), and the `lkl_sys_*` interface works (`getpid()=1`, `creat()=0`) — the call-in path EpinAnonymOS
will use. **★ De-risk: L3 has a defined interface.** LKL ships `lkl_pci_ops` (config rd/wr, MMIO, IRQ,
DMA-map) and **`lib/vfio_pci.c` is a working reference implementation** (Linux VFIO uABI) — so L3 is
"implement `lkl_pci_ops` for EpinAnonymOS," not an open research problem. `lkl_pci` core probes already.

## L2 — Boot LKL inside EpinAnonymOS  ✅ **DONE (2026-06-26, commit 06d115387)**
**The Linux kernel (6.12) boots inside EpinAnonymOS:** serial shows `Linux version 6.12.0+ …musl`,
`LKL up inside EpinAnonymOS. getpid()=1`, `lkl_sys_openat=0`, `LKL halted cleanly`. Built musl (musl-gcc
cross, `lkl.h` +`<sys/types.h>`, non-PIE static). Two fixes beyond the embedder: a **custom timer host-op**
(thread that sleeps + calls the kernel timer cb, replacing LKL's POSIX-timer/`rt_sigtimedwait` clock), and
a **real `nanosleep` in the kernel** (it was a no-op; now parks the task via the poll/epoll park + PIT-tick
wake — benefits every program). Details below + in `src/lkl/`.

**Approach (decided in L2): userspace LKL**, not in-kernel. LKL's default POSIX host-ops
(`lib/posix-host.c`) use ordinary Linux syscalls (mmap, clone/futex for pthreads, clock_gettime) — which
EpinAnonymOS's Linux personality already provides (it runs threaded musl: Weston/Mesa). So **no custom
`lkl_host_operations` are needed** — run an LKL binary on the Linux personality, and later give it
hardware via a kernel `/dev/vfio` (LKL's existing `vfio_pci` backend → L3).
- **Embedder ✅ (`src/lkl/lkl-boot.c`):** `lkl_init(&lkl_host_ops)` → `lkl_start_kernel("mem=32M …")` →
  `lkl_sys_*`. **Validated on the host** (boots `Linux version 6.12.0+`, `getpid()=1`,
  `lkl_sys_openat`/`write` work). Built **static** with `-Wl,--whole-archive liblkl.a`; **stripped = 13 MB**
  (from 147 MB) — stageable on EpinAnonymOS.
- **Next (on-target):** stage the 13 MB static binary on EpinAnonymOS (boot module or grow the AHCI disk),
  run it, capture how far LKL boots. **Verify:** "Linux version …" on the *EpinAnonymOS* serial. Failures
  reveal the Linux-syscall gaps in the personality that LKL needs — fill those (the real L2 work is making
  EpinAnonymOS's Linux ABI complete enough to host LKL, not writing host-ops).

## L3 — The hardware bridge: a CUSTOM `lkl_dev_pci_ops` backend (the core)  *(scoped 2026-06-26)*
**Decision: a custom backend, NOT VFIO.** LKL's PCI backend contract is the small `struct
lkl_dev_pci_ops` (lib/vfio_pci.c): `.add` / `.remove` / `.read`,`.write` (PCI **config** space) /
`.resource_alloc` (BAR) / `.map_page`,`.unmap_page` (DMA) / `.irq_init`. vfio_pci.c implements it over
Linux VFIO; we write our OWN backend (in lkl-boot.c, alongside the timer host-op) over EpinAnonymOS's
native PCI — no VFIO uABI, no IOMMU.
**★ Key simplifier (L3 scoping finding):** BAR access does NOT need an mmap. `.resource_alloc` calls
LKL's `register_iomem(addr, size, ops)` (lib/iomem.c) — the LKL kernel routes every BAR MMIO read/write
through the backend's iomem `.read`/`.write`. So the backend just *forwards* each MMIO to EpinAnonymOS
(which does the real MMIO to the BAR phys). And many drivers (AHCI) run **POLLED — no IRQ** — so the hard
IRQ piece is deferrable.
Four EpinAnonymOS-native capabilities to expose to the userspace LKL (a small custom device/syscall):
1. **PCI config r/w** (by bus/dev/func+offset) — the kernel already has `pciConfigRead32`. → `.read`/`.write`.
2. **MMIO r/w at a phys addr** — for BAR access via the iomem-forward. → `.resource_alloc` iomem ops.
3. **virt→phys** of an LKL buffer (no-IOMMU IOVA = phys) — → `.map_page` for DMA.
4. **IRQ forward** (device IRQ → `lkl_trigger_irq`) — the ONLY hard one (EpinAnonymOS polls, no kernel IRQ
   handling, [[weston-perf-profiling]]); **deferred** — prove with a polled driver first.
**Incremental:** L3a config+MMIO+virt→phys (the 3 easy caps) + the backend → L3b **LKL's `ahci` reads a
sector POLLED** (QEMU AHCI first, then the real Intel SATA). L3c = IRQ forward (for drivers that need it).
**Verify:** LKL's `ahci` driver reads a sector off the disk.

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
