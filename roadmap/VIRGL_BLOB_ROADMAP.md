# Host-Visible `RESOURCE_CREATE_BLOB` — cross-process virgl sharing roadmap

**Goal:** let a GPU Wayland *client* (gl-term / gl-wl-test) render into a virgl resource that
the Weston compositor can **import and sample**, zero-copy. This is the only uABI-clean way to
composite a GPU client's pixels (see "Why" below). Estimated **~9 phases / 3–4 sessions.**

Designed by a multi-agent investigation (workflow `virgl-blob-design`); every load-bearing claim
was cross-checked against on-disk source (Mesa `mesa-23.3.5-epin`, virglrenderer 1.8.8,
QEMU's `hw-display-virtio-gpu-gl.so`, the kernel).

## Why blob (the architectural finding that motivated this)

The prior attempt (R3 M1–M3, committed) got a client to **render** on virgl
(`GL renderer=virgl (NVIDIA GTX 1080)`) but Weston's compositor-side dmabuf **import fails**
("importing the supplied dmabufs failed"). Root cause, settled from virglrenderer source: a
classic virgl resource keeps its pixels in a **host GL texture** (`VREND_STORAGE_GL_TEXTURE`),
while our PRIME alias shares the resource's **guest backing pages** (`VREND_STORAGE_GUEST_MEMORY`),
which stay **stale** — virgl never writes rendered pixels back to guest pages. So Weston imports
empty memory → `EGL_NO_IMAGE`. The host GL texture *is* shareable across virgl contexts by
`res_handle`, but the stock Mesa/virtio-gpu import path never cross-attaches an imported fd's
resource. The supported cross-process primitive is a **host-visible blob** (`BLOB_MEM_HOST3D`):
the resource lives in a host-visible BAR window both processes map.

---

## ⛔ B0 — Upgrade QEMU and expose host-visible blob memory (THE GATE; do first)

**The host runs QEMU 8.2.2, which CANNOT do virgl + blob.** Verified: the GL module
`hw-display-virtio-gpu-gl.so` contains the hard gate string `"blobs and virgl are not
compatible (yet)"` — `virtio_gpu_device_realize` errors out if both are enabled. That check was
**removed in QEMU 9.1** (Collabora "Support blob memory and venus" series, merged Aug 2024); on
≥9.1 the only remaining gate is "need rutabaga or udmabuf for blob resources", and the host
already has **both** escape hatches: virglrenderer 1.8.8 (exports `virgl_renderer_resource_create_blob`
/ `_map` / `_get_map_info` / `_export_blob`) **and** `/dev/udmabuf`.

**No blob kernel code can be tested until QEMU ≥9.1 exists.** Do nothing past B1 until B0c is green.

**Changes**
1. Build/install QEMU ≥9.1 (prefer 9.2 / 10.x) with `--enable-virglrenderer --enable-opengl`
   into a **separate prefix** (e.g. `/opt/qemu-9.2/bin`) — do **not** clobber `/usr/bin`.
2. Promote the GPU launch line (today a commented note in `qemu-run.sh`) to active:
   `-vga std -device virtio-gpu-gl-pci,blob=true,hostmem=256M -display egl-headless,rendernode=/dev/dri/renderD128`
   (`max_hostmem=` defaults 256M; raise for more/larger blobs. The host-visible window lands on
   BAR4, 64-bit prefetchable — the existing 64-bit-BAR handling covers it. `-vga std` is fine.)
3. Keep `${ACCEL[@]}` (KVM), serial, AHCI disk.

**Verify (in order)**
- **B0a** — new QEMU boots the *existing* desktop **without** `blob=,hostmem=`: R2.5 still
  composites, serial `GL renderer: virgl ... NVIDIA GTX 1080` (proves the upgrade didn't regress GL).
- **B0b** — add `blob=true,hostmem=256M`: the device **realizes** (no "blobs and virgl are not
  compatible" in the QEMU log), desktop still composites.
- **B0c** — confirm a new **BAR4 SHM region of size 0x10000000 (256M)** appears (QMP `info pci` or
  the B1 cap-walk klog).

**Risk: HIGH.** Fallbacks if virgl+blob still won't realize: (a) udmabuf is present, the relaxed
check accepts it; (b) prove the window with plain `virtio-gpu-pci,blob=true,hostmem=256M` then
diagnose the gl path; (c) worst case — host-visible virgl unsupported → STOP, reconsider
rutabaga/gfxstream.

---

## B1 — Cap-walk the host-visible SHM region (smallest code; proves the window)

**File:** `virtio_gpu.d` cap-walk loop (202-217). **Mostly mechanical.**

Add a `cfgType == 8` (SHARED_MEMORY_CFG) branch to the existing `capId == 0x09` block. The struct
is `virtio_pci_cap64`, mapping onto the existing dword reads exactly:
`+3 cfg_type`, `+4 bar`, `+5 id`, `+8 offset(lo)`, `+12 length(lo)`, `+16 offset_hi`, `+20 length_hi`.
For `id == 1` (HOST_VISIBLE): `shmBar = dw1 & 0xFF`; `off = read(cap+8) | (read(cap+16) << 32)`;
`len = read(cap+12) | (read(cap+20) << 32)`. Resolve BAR4 with the existing 64-bit logic; set new
globals `g_gpuShmBase = barBase + off + hhdm_offset`, `g_gpuShmLen = len`. Klog all four.

**Verify:** serial logs `bar=4 id=1 off=0 len=0x10000000`.
**Risk:** the HHDM may not span the 64-bit BAR4 phys range — if reading `[g_gpuShmBase]` faults,
add an explicit ioremap-style mapping of `[barBase+off, len)`.

## B2 — Negotiate `VIRTIO_GPU_F_RESOURCE_BLOB` (+ `CONTEXT_INIT`)

**File:** `virtio_gpu.d` feature negotiation (241-258). **Mechanical.**
Test `featLo` bit 3 (RESOURCE_BLOB) and bit 4 (CONTEXT_INIT); OR them into the driver-features ACK
(line 257) **only if offered**. **Verify:** `FEATURES_OK` still accepted with bit 3 ACKed.

## B3 — Fix the hardcoded `fence_id` (cheap; must land before B7)

**File:** `virtio_gpu.d` 424/456/580/593/607. **Mechanical, hot path.**
Add `__gshared ulong g_gpuFence = 1; ulong nextFence() => g_gpuFence++;`; replace each hardcoded
fence id. Not required to create/map blobs (defer past B4–B6), but blob producer→consumer sync
needs ordering — **must land before B7**. **Verify:** monotonic fence ids, R2.5 still renders.

## B4 — Kernel transport: `gpuCreateBlob` + `gpuMapBlob` (GENUINELY RISKY)

**File:** `virtio_gpu.d` — new enums/structs + two functions over `gpuCtrl`/`gpuCtrlChained`.
- Enums: `RESOURCE_CREATE_BLOB=0x010C`, `RESOURCE_MAP_BLOB=0x0208`, `RESOURCE_UNMAP_BLOB=0x0209`,
  `RESP_OK_MAP_INFO=0x1107` (`SET_SCANOUT_BLOB=0x010D` for later).
- Structs (little-endian): `ResourceCreateBlob{hdr; u32 resource_id; u32 blob_mem; u32 blob_flags;
  u32 nr_entries; u64 blob_id; u64 size}`; `ResourceMapBlob{hdr; u32 resource_id; u32 padding;
  u64 offset}`; `RespMapInfo{hdr; u32 map_info; u32 padding}`.
- `gpuCreateBlob`: **SUBMIT_3D the Mesa `cmd` (`VIRGL_CCMD_PIPE_RESOURCE_CREATE`) stream on ctx 1
  FIRST** (so vrend correlates `blob_id`→pipe_resource — `vrend_renderer.c:12806`), THEN
  RESOURCE_CREATE_BLOB with `blob_mem=0x2 (HOST3D)`, `blob_flags=0x1 (USE_MAPPABLE)` (Mesa uses
  MAPPABLE only, *not* SHAREABLE), `nr_entries=0`, `ctx_id=1`.
- `gpuMapBlob`: RESOURCE_MAP_BLOB, return `map_info`.
- Offset allocator: bump/free-list over `[0, g_gpuShmLen)`.

**Verify:** a kernel self-test creates a 256×256 blob, maps at offset 0, gets `RESP_OK_MAP_INFO`,
CPU writes a pattern into `g_gpuShmBase+0`, reads it back identical.
**Risk:** the `blob_id↔pipe_resource` ordering (the cmd MUST precede CREATE_BLOB) is the most
error-prone piece — trace with `VIRGL_LOG_LEVEL=debug` + QEMU `--trace 'virtio_gpu_*'`.

## B5 — GETPARAM advertises blob + honor map cache mode

**File:** `posix.d` GETPARAM `case 0x43` (10063); FD_DRM mmap cache-type. **Mechanical (flip).**
`param==3 → 1` (RESOURCE_BLOB), `param==4 → 1` (HOST_VISIBLE) [flips Mesa `supports_coherent`],
optionally `param==6 → 1` (CONTEXT_INIT). Honor `map_info` cache mode (WC=0x03 vs CACHED=0x01).
**Do NOT set param 4 before B4 is green** — else Mesa creates a blob it can't mmap.
**Verify:** client GETPARAM 3==1 && 4==1, Mesa `supports_coherent=1`, desktop still composites.

## B6 — DRM ioctl `case 0x4a` (RESOURCE_CREATE_BLOB) + MAP/INFO for blobs

**File:** `posix.d` — `DrmGem` (10009), new `case 0x4a`, edits to MAP (0x41) + RESOURCE_INFO (0x45).
- `DrmGem += {uint blobMem; ulong shmemOffset;}`.
- `case 0x4a` (`drm_virtgpu_resource_create_blob`): read `blob_mem@0`, `blob_flags@4`, `size@16`,
  `cmd_size@28`, `cmd@32`, `blob_id@40`; validate `blob_mem==0x2 && size>0`; alloc resId + window
  offset; `gpuCreateBlob` (submitting cmd) then `gpuMapBlob`; `drmGemAlloc(phys = BAR4 guest-phys +
  shmemOffset, blobMem=2)`; write `bo_handle@8`, `res_handle@12`. **No guest backing pages.**
- `case 0x41` MAP: for a blob, return `offset = BAR4_guestphys + g.shmemOffset` (not `g.phys`).
- `case 0x45` RESOURCE_INFO: write `g.blobMem` at `arg+12` (not 0).

**Verify:** a client renders into a blob and reads its own pixels back.
**Risk:** Mesa only takes the blob path for `MAP_PERSISTENT/COHERENT` resources
(`virgl_resource.c:509-515`) — a plain render target stays classic. The test client may need to
request a persistent/coherent buffer (or be patched).

## B7 — Cross-process import: Weston samples the client's blob (THE PAYOFF)

**File:** mostly verification; the PRIME fd↔handle round-trip (M2) already returns the device-global
`g_drmGems` handle. Correctness comes from B6's RESOURCE_INFO returning `blob_mem=2`. **B3 must be
landed first.** **Resolved risk:** host virglrenderer sets `VIRGL_CAP_V2_UNTYPED_RESOURCE` on the
egl path (`vrend_renderer.c:12257`).
**Verify:** a GPU client renders into a blob; **a screenshot shows the client's content composited
by Weston** — the zero-copy goal. Confirm via `VIRGL_LOG_LEVEL=debug` that `set_type` ran and both
processes bind the same host pipe_resource.

## B8 — Cleanup / lifecycle / polish (lowest risk, last)

`RESOURCE_UNMAP_BLOB` on gem close; free the window offset; UNREF the blob; optionally
`SET_SCANOUT_BLOB` for direct scanout; consistent WC barriers. **Verify:** churn 100 blobs without
window exhaustion; desktop stable across domain open/close.

---

## Cross-cutting

- **Prove the riskiest first:** B0 (realize) → B1 (window visible) → B4 (create/map round-trip).
  If any fails, stop — everything downstream is blocked.
- **Still-open risks:** HHDM coverage of BAR4 (B1); `blob_id↔pipe_resource` ordering (B4, the most
  error-prone); map cache mode WC/WB (B5); Mesa only blobs persistent/coherent buffers (B6).
- **Wire codes:** CREATE_BLOB=0x010C, MAP_BLOB=0x0208, UNMAP_BLOB=0x0209, OK_MAP_INFO=0x1107;
  blob_mem HOST3D=0x2, blob_flags USE_MAPPABLE=0x1; feature bits RESOURCE_BLOB=3, CONTEXT_INIT=4;
  SHM cap cfg_type=8, id HOST_VISIBLE=1.

## Key source anchors
- `src/kernel/d/drivers/graphics/virtio_gpu.d` — cap-walk 202-217, feature ACK 257, fences 424/456/580/593/607
- `src/kernel/d/core/syscalls/posix.d` — DrmGem 10009, GETPARAM 10056, virtgpu ioctls 10082-10157, PRIME 10271-10359
- `qemu-run.sh` — promote the commented GPU launch (B0)
- `deps/mutter/build/mesa-23.3.5-epin/src/gallium/winsys/virgl/drm/virgl_drm_winsys.c` — gating 1297-98, blob create 166-229, import 485-573
- `deps/mutter/build/mesa-23.3.5-epin/src/gallium/drivers/virgl/virgl_resource.c` — blob_mem honor 737, blob-path gate 509-515
- `/tmp/virglrenderer-src/src/vrend_renderer.c` — UNTYPED cap 12257, get_blob 12806
