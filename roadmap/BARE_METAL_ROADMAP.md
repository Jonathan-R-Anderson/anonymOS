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

## Device isolation — one LKL per device, capability-gated (REQUIRED, user 2026-06-26)
**Each LKL-driven peripheral runs in its OWN LKL instance** — a separate EpinAnonymOS process/sandbox, one
per device (or device class: a usb-lkl, a gpu-lkl, a net-lkl, …). **An LKL instance sees and touches ONLY
the device(s) explicitly granted to it via the AnonymOS capability system; by default it sees NO devices
at all.** So a compromised or buggy driver (e.g. the USB stack) cannot reach the GPU, the disk, or the NIC
— strong per-driver isolation, matching EpinAnonymOS's capability-based security.

Concretely:
- A **device capability** names one PCI device (its bdf) + the BAR ranges (and later the IRQ line) it is
  allowed to touch. A privileged **device-manager** enumerates PCI, mints one device-cap per device, and
  hands each cap to the LKL instance that should drive it — per the user's policy. This grant is the *only*
  way an LKL gets a device.
- The **`0x4100` PCI-bridge syscall is CAP-GATED**: every op checks the calling task's cap table holds a
  device-cap for the target, else `-EPERM`. `op2` (scan) returns ONLY the caller's granted device(s), never
  the whole bus; `op0/op1` (config) and `op3/op4` (MMIO) only succeed for a granted device's bdf / inside
  its granted BAR ranges; `op5` (virt→phys) acts on the caller's own memory so it's unrestricted.
- Builds on the existing cap system (per-task `capTabId`, the cap graph + attenuation from the object-FS /
  native-ABI work — see [[shell-track-a]] for `cap_grant`); the device-cap is a new capability/object type.
- **Status:** the L3a/b bridge is currently **UN-gated** — a deliberate bring-up shortcut (one LKL, scans
  the whole bus). **Cap-gating + per-device LKL spawning is a required phase before any untrusted driver
  runs** — it slots in at **L4** (the device-manager mints device-caps and spawns one cap-scoped LKL per
  peripheral; the bridge enforces the caps).

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
**Incremental:**
- **L3a ✅ DONE (commit ad1273c88): LKL ENUMERATES real PCI hardware via the backend.** Kernel syscall
  `EPIN_SYS_LKL_PCI=0x4100` (config read/write/scan over `pciConfigRead32`/`scanPCIDevices`); `lkl-boot.c`
  custom `lkl_dev_pci_ops` (`.add` scans, `.read`/`.write`→syscall) as `ops.pci_ops`, cmdline `lkl_pci=epin`.
  Serial: `epin_pci: device 00:01.1 vendor/device=0x70108086` + `pci 0000:00:00.0:` (LKL read its BARs).
- **L3b ✅ DONE — a real Linux driver does MMIO+DMA through the bridge.** LKL's NVMe driver fully
  initializes the controller via EpinAnonymOS. Serial-verified register trace: reads **CAP=0x0f0107ff** +
  **VS=0x10400 (NVMe 1.4.0)** (op3 MMIO read), DMA-maps the admin CQ/SQ (`map_page → phys 0x2ec7000 /
  0x2ec8000`, op5 virt→phys), writes **ASQ/ACQ** = those phys addrs + **AQA**, then **CC.EN=1** to enable
  the controller (op4 MMIO write) — zero QEMU guest-errors (the BAR accesses are valid). The probe then
  waits on the Identify *completion* = an IRQ → **L3c**. NVMe = the conflict-free device (LKL has `nvme`;
  EpinAnonymOS uses AHCI). Run: `LKL_NVME=1 ./qemu-run.sh` (or a direct headless `-device nvme`).
  - **Kernel (0x4100 syscall):** op3 = MMIO read at phys (`*(shared*)(phys + hhdm_offset)`),
    op4 = MMIO write at phys, op5 = virt→phys (`addrspace.activeVirtToPhys`, the calling task's page table).
  - **Backend (`lkl-boot.c`):** `.resource_alloc(dev, size, idx)` reads BAR[idx] from config → the BAR phys,
    then `register_iomem((void*)bar_phys, size, &epin_iomem_ops)` where `epin_iomem_ops.read/.write` forward
    `(bar_phys + offset)` to op3/op4 — **no BAR mmap** (the iomem layer routes every MMIO through these).
    `.map_page(vaddr, size)` → op5 (virt→phys) = the IOVA (no-IOMMU). `.add` scans by class (op2, 0x0108).
  - **★ Device decision (the gotcha):** LKL's driver must NOT share a controller with an EpinAnonymOS
    driver — LKL's `ahci` would HBA-reset the shared AHCI and break the OS's disk. So give LKL a
    CONFLICT-FREE device EpinAnonymOS doesn't drive: a **2nd `-device ahci,id=ahci1` + its own disk**, or a
    **`virtio-blk-pci`** (LKL has virtio_blk+virtio_pci; needs the virtqueue in DMA mem via op5). Make op2
    (scan) target it (by class+index, or skip the OS's controller). Also note: the IDE at 00:01.1 found in
    L3a uses **I/O-space BARs (port I/O), not MMIO** — so it won't exercise `.resource_alloc`; pick a device
    with a MEMORY BAR. **Verify:** LKL's block driver reads a sector off its dedicated disk, POLLED.
  - **DMA contiguity caveat:** the device DMAs to guest-phys; LKL's buffers are EpinAnonymOS userspace
    pages — but observed admin CQ/SQ got *consecutive* phys (0x2ec7000/0x2ec8000), so LKL RAM is roughly
    contiguous. A single large contiguous DMA may still need a contiguous allocation.
- **L3c ✅ IRQ forward DONE (polled INTx → `lkl_trigger_irq`; commit ca4afbb96).** LKL has no MSI/MSI-X
  (`pci.c` only does `lkl_get_free_irq` + `irq_init`), so the device uses a legacy INTx pin. EpinAnonymOS
  polls (no kernel-mode interrupt delivery), so `.irq_init` spawns a thread that polls the device's **PCI
  Status register (cfg 0x06 bit 3 = Interrupt Status)** and raises the Linux IRQ via `lkl_trigger_irq`,
  with a ~4ms periodic safety trigger. **RESULT: LKL's nvme admin Identify COMPLETES** (`nvme nvme0: 1/0/0
  default/read/poll queues` + namespace identify + `Abort status: 0x0`) — a real Linux driver now
  initializes a device AND completes admin commands through the bridge, where before it hung forever.
  - **KNOWN REMAINING (diagnosed, low-priority):** an I/O-queue READ (QID 1, opcode 0x2, 4096B) times out
    at ~30s. Doorbell instrumentation pinned it: of 31 doorbell writes, **ALL are admin queue** (0x1000/
    0x1004) and **ZERO are the I/O queue** (0x1008/0x100c) — so the read is queued in blk-mq but **never
    dispatched to the hardware I/O SQ**, with no error (the I/O queue is created fine). So it is **NOT a
    bridge defect** (config/MMIO/DMA/IRQ all proven — admin commands complete end to end); it's a deep
    nvme/blk-mq submission quirk under LKL+INTx (the request never reaches `nvme_queue_rq`/never rings the
    SQ doorbell). Diagnosing further needs LKL-internal blk-mq instrumentation. **Low priority — NVMe isn't
    on the target hardware** (it was only the conflict-free bring-up vehicle); the real driver targets are
    USB (L5) and the GPU (L6), which the proven bridge already supports.

## L4 — Per-device LKL isolation (cap-gating) + bridge LKL's devices to EpinAnonymOS
**★ CAP-GATING ✅ DONE (commit 9ec3379b2) — the user's isolation requirement, verified.** The `0x4100`
bridge is now **default-deny**: a per-PROCESS device capability (`struct DeviceCap` = bdf + sized MMIO BAR
ranges; `g_taskDevCap[MAX_TASKS]` in posix.d) gates every op — `op2` scan returns ONLY granted devices (an
ungranted LKL enumerates nothing), `op0/op1` config + `op3/op4` MMIO → `-EPERM` unless the caller holds a
cap for that bdf / a phys inside its granted BAR, `op5` virt→phys is the caller's own memory (unrestricted).
Keyed on the **process leader** (`devCapLeader`) so an LKL's timer + IRQ-poller pthreads (separate tasks)
share the one grant. `grantDeviceCap` sizes the BARs (write-1s/readback/restore) for exact MMIO gating;
it is privileged (kernel/device-manager only, never via the ABI). Bootstrap policy in `maybeSpawnLklTest`:
grant lkl-boot a cap for **NVMe only**. **VERIFIED:** serial shows the grant + `config-read non-granted
bdf 0 -> -1 (DENIED)`, while the granted NVMe still drives fully (scan + BAR MMIO + IRQ + 37 doorbells).
- **Follow-ups (not yet):** (a) a **userspace device-manager** that enumerates PCI, mints a cap per device,
  and **spawns one LKL per peripheral** (the kernel mechanism + a hardcoded bootstrap grant are in; this is
  the orchestration layer + `cap_grant`-driven policy — [[shell-track-a]]). (b) **Bridge LKL `/dev/*`**:
  each LKL has its own VFS/`/dev`; reach its nodes via `lkl_sys_open`/`read`/`write`/`ioctl` and surface
  them as EpinAnonymOS devices so the desktop uses them unchanged. **Verify:** two LKLs each see only their
  own device; an EpinAnonymOS `/dev/*` backed by an LKL device.

## L5 — USB HID via LKL (the usable-desktop unlock)
LKL's `xhci_hcd` + `usbhid` drive the real USB keyboard/mouse → bridge LKL's `/dev/input/event*` to
EpinAnonymOS's input rings (`g_kbd_ring`/`g_mouse_ring`). **Develop/verify in QEMU first**
(`-device qemu-xhci -device usb-kbd -device usb-mouse`), then it works on real xHCI unchanged.
**Verify:** typing/moving drives the desktop with PS/2 removed.

**★ GATING (checked 2026-06-26): the current `liblkl.a` has NO USB host stack** — only the HID layer
(`CONFIG_HID=y`, `hid_init`) + a `CONFIG_USB_PCI=y` stub; `CONFIG_USB` itself is OFF and `xhci_hcd_init`/
`usb_hcd` are absent. So **L5 step 0 = reconfigure LKL + rebuild `liblkl.a`**: enable `CONFIG_USB=y`,
`CONFIG_USB_XHCI_HCD=y`, `CONFIG_USB_XHCI_PCI=y`, `CONFIG_USB_HID=y`, `CONFIG_INPUT_EVDEV=y` (in
`~/lkl-build/linux/.config` → `make -C tools/lkl olddefconfig` + rebuild, ~10 min), then relink lkl-boot.
After that the bring-up mirrors NVMe: point `.add` at the xHCI class (0x0c0330), let LKL's `xhci_hcd`
probe it through the proven bridge (config/MMIO/DMA/IRQ all work), enumerate `usb-kbd`, then read
`/dev/input/event*` via `lkl_sys_read` and feed `g_kbd_ring`/`g_mouse_ring`.

**★ STEP-0 ✅ DONE (commit cce199384): liblkl.a rebuilt with the USB stack** (added the 5 CONFIGs to
`arch/lkl/configs/defconfig`; `xhci_hcd_init`/`usb_init`/`usbhid`/`evdev_connect` now in liblkl.a). Build
env = conda `lkl` (flex/bison) + the musl cross. **★ BRING-UP ✅ (commit cce199384): LKL's xHCI/USB stack
runs through the bridge** — serial: `xhci_hcd 0000:00:00.0: xHCI Host Controller` + `new USB bus registered`
(USB 2.0 + 3.0) + `usbcore: registered new interface driver usbhid` + BOTH devices detected (`usb 1-1`
kbd, `usb 1-2` mouse) — same config/MMIO/DMA/IRQ + L4 cap-gate as NVMe (granted xHCI; bdf 0 DENIED).
**★ KNOWN ISSUE (deeply diagnosed): enumeration never reaches `New USB device found`.** QEMU `--trace
'usb_xhci_*'` is decisive — **the host xHCI COMPLETES the transfers**: `usb_xhci_xfer_success … len 18`
(the full 18-byte device descriptor) with **zero error/stall completion codes**. So config/MMIO/DMA/IRQ all
work end-to-end and the controller does real USB — it is **NOT a bridge defect or a dead controller**. The
failure is on the **guest completion side and it is NON-DETERMINISTIC**: across runs the LKL hangs at
*different* points (max LKL-time t≈1.5s / 3s / 8s; sometimes both devices are detected, sometimes neither),
and once wedged it makes no progress for hundreds of wall-seconds. That variance is the signature of a
**lost-wakeup RACE in the polled-INTx completion path** (the host posts a completion, but the guest's
`wait_for_completion` races my IRQ-poller's `lkl_trigger_irq`, dropping the wakeup → the enumeration thread
blocks forever). **Tested + ruled out:** the poller frequency (250µs vs 1ms changed nothing / the early
hang persisted) — so it is not a simple tunable. **Robust fix needs reliable interrupt delivery, not
polling:** either (a) the EpinAnonymOS *kernel* poll-loop detects the device INTx and reliably wakes the
LKL (vs a userspace poller thread that races + competes for CPU), or (b) **SMP** so the IRQ thread and the
enumeration thread each get a real core — see `SMP_ROADMAP.md`.

**★ KERNEL-SIDE INTx WAKE DONE (commit 4b44fdc5f) — and it RULES OUT the IRQ mechanism.** Implemented (a):
`0x4100` op6 PARKs the LKL IRQ thread in the kernel (reusing the poll park + wakePollers PIT-tick re-check)
until `deviceIntxAsserted(grantedBdf)`; the LKL thread blocks on op6 + fires `lkl_trigger_irq` — no
userspace busy-poll. **VERIFIED WORKING: intx=971 tmo=29 live** (~97% real INTx detections). Kept — the
right model for per-device LKLs + SMP.

**★★ ROOT CAUSE of the "stall" (found via LKL `CONFIG_DYNAMIC_DEBUG`+dyndbg) — it was NOT the IRQ mechanism
and NOT inside LKL's xHCI:** `lkl-boot` called `lkl_sys_halt()` right after `lkl_start_kernel`, while USB
enumeration runs ASYNCHRONOUSLY in the kernel's hub work-thread → the kernel REBOOTED mid-enumeration
(`reboot: Restarting system` at ~t=3s) every run. The intermediate steps are `dev_dbg` (invisible without
dyndbg) so it only LOOKED stuck; dyndbg showed it reading descriptors+strings + registering the devices,
then getting rebooted. **FIX (commit c3dd8ff97): main() stays RESIDENT (no halt) — also the correct design
(a USB-driver LKL must live as long as it serves input).** → LKL's xHCI+usbhid **FULLY enumerate the kbd+
mouse** and create `/dev/input/event0/1` (`input: QEMU USB Keyboard/Mouse`).

**★★★ L5 INPUT BRIDGE ✅ DONE + VERIFIED END-TO-END (commit 8bab6afe4): live USB keystrokes reach the OS.**
`0x4100` op7 = inject an evdev event → `input_enqueue(g_kbd_ring/g_mouse_ring)` (cap-gated to a granted LKL
driver). lkl-boot spawns two reader threads that mknod+open the LKL's `/dev/input/event0` (kbd)+`event1`
(mouse) and `lkl_sys_read` the 24-byte `input_event` → op7. **VERIFIED: QMP `send-key h/e/l/l/o` → usb-kbd →
LKL → op7 → kernel log `[lkl-input] inject kbd EV_KEY KEY_H/E/L` (codes 35/18/38 = exactly the keys sent).**
So the FULL USB-input data path — xHCI + USB core + HID + evdev, ALL LKL, ALL through the proven EpinAnonymOS
bridge — delivers real keystrokes into the OS's input rings (which Weston reads). **On the USB-only target
box this is THE input path. L5 DONE.** Polish remaining: input is slow (the LKL is CPU-starved on one core →
`SMP_ROADMAP.md`); full keymap/scancode coverage.

## L6 — GPU via LKL (the research frontier)
LKL's `nouveau` drives the GTX 1080: real PCI BARs + MSI + large DMA + **display scanout / mode-setting**
to the physical monitor — the hardest integration. Mesa's `nouveau`/`nvk` userspace runs on top via the
Linux ABI (this is the half that "comes from the Linux compatibility layer"). Bridge LKL's `/dev/dri/cardN`
to the existing DRM-uABI seam. **Verify:** the desktop composites on the real GPU. (Pascal's signed-firmware
limits apply, same as upstream nouveau.)

**★★ GATING FINDING (checked 2026-06-26): L6 needs LKL's MMU first.** The current `liblkl.a` is **NOMMU**
(`# CONFIG_MMU is not set`), but **every real GPU DRM driver depends on `MMU`** — `DRM_BOCHS` (the QEMU GPU
proxy for nouveau) `depends on DRM && PCI && MMU` and `select`s `DRM_TTM`; **nouveau** likewise needs TTM/MMU.
The DRM *core* + `DRM_KMS_HELPER` + `DRM_FBDEV_EMULATION` do build NOMMU, but there is **no usable PCI-GPU
driver** without MMU (`simpledrm` only adopts a pre-existing firmware framebuffer — it doesn't drive the GPU's
PCI). LKL **has** an MMU option (`config MMU` in `arch/lkl/Kconfig`), so it's possible — but enabling it is a
**substantial prerequisite, not an increment**: LKL gains real virtual memory, which changes the model the
DMA bridge relies on (`.map_page`/op5 today = the host-chunk linear offset; with an LKL MMU the page-table
walk changes) and **risks the proven NOMMU L3/L5**. So L6 is its own phase:
- **L6.0 ✅ DONE (commit d7803181d): LKL MMU works through the bridge.** Enabled `CONFIG_MMU`+`DRM`+
  `DRM_BOCHS`+`TTM` in the LKL build; **TTM needed a 1-line patch** (`ttm_module.c`: guard the x86-only
  `boot_cpu_data.x86` line with `CONFIG_LKL`, like UML's `CONFIG_UML` guard). The MMU host-op (`shmem_init`/
  `shmem_mmap`, which back LKL "physical" memory with a host shm it mmaps at kernel-VAs) was overridden in
  lkl-boot.c to use a **memfd** (EpinAnonymOS has no `shm_open`/`/dev/shm`) with **`MAP_FIXED`** (LKL remaps
  pages; `MAP_FIXED_NOREPLACE` → `BUG_ON(res!=va)` panic). **The bridge DMA SURVIVES the MMU** — the
  shmem-mmap'd pages are real host mappings so `op5` virt→phys still resolves; **USB still fully enumerates +
  creates input devices under MMU** (verified). Build needs `make -k` (the unused `lib/hijack` glibc-isms).
- **L6.1 ⚠️ PARTIAL — bochs-drm PROBES the GPU through the bridge, blocked on the framebuffer map.** The LKL
  finds `bochs-display` (`0x11111234`, class 0x0380, scan/grant prefer 0x0380) and reads BAR0 (16MB fb at
  0xfd000000), but bochs-drm fails: `Cannot map framebuffer` (-ENOMEM). **ROOT CAUSE (genuine GPU frontier):
  the LKL iomem layer (`lib/iomem.c`) is unsuited to a GPU framebuffer** — `lkl_ioremap` routes EVERY access
  through `lkl_iomem_access → ops->read/write` (i.e. an op3/op4 syscall *per access* — impractical for the
  millions of accesses a framebuffer needs), AND caps a region at 16MB (`IOMEM_OFFSET_BITS=24`; the fb is
  exactly 16MB). **NEEDED: DIRECT-map the framebuffer into the LKL** (EpinAnonymOS already maps phys→user-VA
  for its own DRM mmap, posix.d:10193). Options: (a) bridge op8 = map a BAR's phys→the LKL process VA, +
  patch the LKL ioremap/iomem to return that direct VA for large BARs; (b) a **shadow framebuffer** (render
  in RAM, blit to VRAM via the bridge on flush); (c) re-architect `lib/iomem.c` for large direct-mapped BARs.
  This is a substantial, deep piece — the GPU is "the hardest integration" per the north star.
- **L6.2 — scanout/mode-setting + the desktop composites on the LKL's GPU** (Weston → `/dev/dri/card0`; the
  full integration) — beyond L6.1, far larger.
**Honest status:** L6.0 (the MMU unlock) is DONE + proven; L6.1 reaches the GPU and reads its BARs but the
**usable framebuffer + L6.2 are a multi-week research effort** (the iomem/framebuffer re-architecting + the
desktop integration). L6 is also fundamentally **bare-metal** (nouveau needs the real GTX 1080; bochs-display
is only the L6.1 proxy). `SMP_ROADMAP.md` remains the more immediate, higher-leverage win.

## Sequencing
BM0 (verify) → L1 (build LKL) → L2 (boot LKL inside) → L3 (hardware bridge, on AHCI) → L4 (device bridge)
→ L5 (USB HID — usable desktop) → L6 (GPU — long). L3 is the make-or-break research milestone; everything
device-related rides on it.
