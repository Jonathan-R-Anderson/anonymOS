# EpinAnonymOS WiFi (Intel AX210) — Full Debugging Notes

Chronological + categorized record of the AX210 WiFi bring-up on EpinAnonymOS, what was
tried, and when it worked vs. didn't. Kept deliberately detailed. Newest findings at the
bottom of each section. Companion to the persisted memory note `wifi-direct-wpa-no-nm.md`.

---

## 1. Goal & Hardware

- **Target:** Framework 13 laptop, **Intel Wi-Fi 6 AX210** (PCI `8086:2725`, rev 0x420,
  RF type **GF**, crf-id `0x400410`, cnv-id `0x400410`, rfid `0x10d000`).
- **Goal:** WiFi working **end to end** on real hardware (scan → associate → DHCP lease),
  no shortcuts.
- **OS model:** EpinAnonymOS is a custom object-capability OS (D + some Rust/C) running a
  Weston/Pixman desktop. It has **no native Linux drivers**; instead it embeds **LKL**
  (Linux Kernel Library) as a userspace process (`lkl-boot`, built static-musl) and bridges
  the real PCI device into LKL so the stock `iwlwifi` driver can run.

---

## 2. Architecture — the LKL ↔ EpinAnonymOS bridge

- **`lkl-boot`** = the LKL kernel-as-a-library, built from `src/lkl/lkl-boot.c` linked against
  `liblkl.a` (`~/lkl-build/linux/tools/lkl/liblkl.a`) with the **musl cross-gcc**
  (`~/lkl-build/musl-build.sh`: `make CC=<musl-gcc> HOSTCC=gcc`). **Build trap:** building
  `liblkl.a` with the host gcc instead of musl-gcc pulls glibc `_FORTIFY_SOURCE`
  (`__fprintf_chk`, `__snprintf_chk`, `__strcpy_chk`, `__fdelt_chk`) into the userspace glue
  and the final musl link fails `undefined reference`. Always build with `CC=$MUSLGCC`.
  (The tools default target also fails on `tests/test-dlmopen.c` — musl lacks `LM_ID_NEWLM` —
  which is harmless; `liblkl.a` is built before it. Target `$(pwd)/liblkl.a` directly to skip.)
- **The `0x4100` syscall (`EPIN_SYS_LKL_PCI`)** carries all bridge ops between LKL and the
  EpinAnonymOS kernel:
  - op0/op1 — PCI config read/write
  - op3/op4 — **routed** MMIO (kernel dereferences the BAR via `bdf + hhdm_offset`; ~1000× a
    real MMIO because each access is a syscall)
  - op5 — `map_page` DMA (returns the real host-phys of an LKL page via `activeVirtToPhys`)
  - op6 — **block-until-IRQ** (parks a thread until the granted device's interrupt is pending;
    returns 1 = real interrupt, 0 = 50 ms safety timeout)
  - op8 — **direct-map** a register BAR into the LKL process (strong-UC) so `readl`/`writel`
    are real MMIO, not routed syscalls
  - op9 — legacy **single-MSI** setup (MSI-X is refused by `arch/lkl` `arch_setup_msi_irqs`)
- **LKL memory:** a 256 MB memfd, allocated as **one contiguous host-phys region** (single
  `alloc_phys_pages` in `linux_sys_ftruncate`). This is why DMA can never be scattered.
- **No IOMMU/VT-d:** the OS never programs VT-d; DMA is raw host-phys identity. (The AX210
  boots by autonomous device-DMA of ctxt-info/fw-sections, proving DMA addressing is correct.)
- **Interrupt delivery to the LKL `iwlwifi` driver:** `op6` wakes on either a real MSI
  (`g_msiIrqCount` / `lklMsiPending`) **or** the **CSR poll backstop** `wifiCsrPending`
  (`posix.d`), which reads `CSR_INT` and wakes if `(CSR_INT & CSR_INT_MASK) != 0`. On real
  HW the MSI fires rarely (`FIRES` ~1–2); the **CSR poll is the primary wake mechanism**.

---

## 3. WiFi user-space stack (works, separate from firmware bring-up)

- **NetworkManager removed** for WiFi (opt-out `/epin-use-nm.conf`). NM hung on its platform
  cache + registered its D-Bus name too late → permanent churn + "Wi-Fi unavailable" + a
  CPU-hog freeze storm. Replaced by:
  - `hos-wpa-agent` (static-musl, no dbus) drives `wpa_supplicant` via config file + SIGHUP
    (wpa_ctrl is unusable — its ctrl iface is AF_UNIX **DGRAM**, and this kernel's AF_UNIX is
    STREAM-only).
  - `hos-wpa-launch` execs `wpa_supplicant -i wlan0 -c /run/wpa-net.conf -D nl80211`.
  - Kernel-supervised `udhcpc` for the lease (NM's n-dhcp4 stalls).
  - Menu backend publishes `/run/wifi/networks`; connect via `/run/wifi/connect`.
- **Status:** QEMU-verified for boot integrity (no NM churn, agent runs, wpa reads config).
  The scan/associate/lease is UNTESTABLE in QEMU (no AP). **Blocked only by firmware
  bring-up** (below) — until the AX210 fw comes up there is no `wlan0` to drive.

---

## 4. Firmware bring-up timeline — the core saga

### 4.1 Baseline: WORKED once (2026-07-09)
- The box **worked end-to-end on 2026-07-09** loading `iwlwifi-ty-a0-gf-a0-89.ucode`. WiFi
  scanned + connected. This is the proof it *can* work on this hardware.
- The ucode **byte content has not changed since 2026-04-15** (the `.gen.o` embedded objects
  were rebuilt 07-12 but from the same files). **So every later regression is environmental
  (our bridge changes) or the `.pnvm` file — NOT the ucode bytes.**

### 4.2 AX210 firmware `-110` (INIT ucode never ALIVE) — a long chain of fixes

The firmware failed with `Failed to start RT ucode: -110` (ETIMEDOUT), `LMAC1 PC 0xd0`
(lower-MAC stuck at reset). Fixes applied, each real, in order:

| Fix | What | Result |
|-----|------|--------|
| **Register-access speed** | Every `iwl_read32`/`write32` was a routed op3/op4 syscall (~1000× slow); the RF/FSEQ sequencer polls CSRs in tight timed loops and timed out. Direct-map the register BAR (op8) so `readl` is real MMIO. | Necessary + correct. **Not sufficient alone.** |
| **`lkl_iomem_access` direct branch** | `iomem.c` had no host-VA branch; a direct BAR VA was decoded as a bogus token → returned `0xFFFFFFFF` (uninitialized stack), so `iwl_read32(HW_REV)` was garbage and direct-map looked "regressed". Fixed with range discrimination (addr ≥ 4 GiB = direct → real volatile MMIO). | Fixed the `0xFFFFFFFF`. |
| **Strong-UC mapping (op8)** | Register BARs mapped `PTE_CD\|PTE_WT` (PAT UC, strongly ordered). | Correct. |
| **Cache-attribute aliasing (clflush)** | `wifiCsrRead` read `CSR_INT` via the WB HHDM alias while the driver used strong-UC op8 → two mappings of the same phys page with conflicting cacheability → the poll read a **stale** `CSR_INT` and MISSED the ALIVE bit. Fixed: `clflush + mfence` before every CSR poll read. | **Real bug**, fixed. Interrupt plumbing then worked (`FIRES=2`, `CSR_WAKES=212`). Did NOT resolve -110. |
| **ASPM off** | The LKL has `CONFIG_PCIEASPM=y` but no port bus, and enumerates the AX210 with no parent bridge, so `iwlwifi` can't disable ASPM itself. Added `pciDisableAspmAll()` (drivers/pci.d) — EpinAnonymOS owns the real links, walks every PCIe cap and clears ASPM Control. Confirmed on HW (AX210 lnkctl `0x142→0x140`, 8 links). | Correct + kept. Did NOT resolve -110. |

- **RULED OUT with proof (workflows):** DMA scatter (contiguous memfd), scheduling / 160 ms
  hrtimer (cosmetic), VT-d (never programmed; boot DMA works), interrupt MODE (fails in both
  single-MSI and MSI-X), register path (routed A/B `NET_ROUTED_MMIO=1` gives an **identical**
  fault → op8 direct-map exonerated).

### 4.3 The FSEQ / RF-sequencer death (firmware-version-sensitive)
- With `-89`: `FSEQ_ERROR_CODE 0x20000000 → 0x60000000` (worsens on warm retry),
  `FSEQ Version 0.0.2.42`. FSEQ = the CNVI/RF companion-chip **power-up sequencer** (an
  RF-firmware register, no driver-side bit decode). OTP + image + `FSEQ_ALIVE_TOKEN`
  (`"ERAN"`) all healthy → the fault is purely the RF sequencer. A **known AX210 signature**
  (Ubuntu LP#2007369, Arch, linux-wireless).
- Cold power-cycle did NOT clear it. ASPM-off did NOT clear it. So `-89` dies **pre-ALIVE**
  on FSEQ, consistently.

### 4.4 Firmware version `-89 → -83` : BREAKTHROUGH — firmware came ALIVE (2026-07-14)
- Dropped `-89` from `CONFIG_EXTRA_FIRMWARE`; driver falls back to `-83`
  (`iwlwifi-ty-a0-gf-a0-83.ucode`, `FSEQ Version 0.0.2.41`).
- **`-83` gets past FSEQ and comes ALIVE.** `loaded PNVM version 581d4936` (PNVM push only
  happens post-ALIVE → ALIVE + RX-notification delivery work).
- **But `-83` then dies on the PNVM handshake:** `Timeout waiting for PNVM load!` → `-110`.
  So: `-89` = pre-ALIVE FSEQ death; `-83` = ALIVE OK, dies only on `PNVM_INIT_COMPLETE`.

### 4.5 The PNVM-removal shortcut — and why it was WRONG
- Field folklore for "Timeout waiting for PNVM load" is "remove the `.pnvm` file". Tried it:
  dropped `.pnvm` from `CONFIG_EXTRA_FIRMWARE`.
- Our kernel's `iwl_pnvm_load` was **pre-skip-era**: it rang the ISR6 doorbell + waited
  unconditionally whenever `sku_id` was set. Patched `fw/pnvm.c` to skip the wait when nothing
  was pushed (`if (!pnvm_loaded && !reduce_power_loaded) return 0`).
- **Result:** firmware ALIVE + RUNNING (UMAC PC `0xd05c18`, LMAC1 `0xd05c1c`) but the FIRST
  post-alive host command **`INIT_EXTENDED_CFG_CMD` timed out** — `CMD queue read_ptr 0
  write_ptr 1`, `rxq0 closed_rb=3`, no fw response. The command was **never fetched**.
- **TFD-dump diagnostic** (tx-gen2.c) on real HW: `DIAG TFD#1 q0 idx0 ringDMA=0x547d000 nTB=1
  tb0=0x46dd000:12 hdr=0302000004000000` = the command is **perfectly well-formed**
  (`INIT_EXTENDED_CFG_CMD`, 12 bytes) at valid host-phys. So NOT a malformed-descriptor bug.
- **Workflow verdict:** the skip patch itself was the wall — for a non-empty-sku AX210 the
  firmware **needs** the PNVM; skipping the ISR6 doorbell leaves it parked post-ALIVE, never
  draining the command ring. **Removing the PNVM is never a valid end state anyway** (it holds
  RF calibration / regulatory / reduced-power tables). **Reverted → restored the `.pnvm`.**

### 4.6 PNVM restored + timeout bumped (2026-07-17)
- Restored `iwlwifi-ty-a0-gf-a0.pnvm` to `CONFIG_EXTRA_FIRMWARE` (in **both** `.config` and
  `arch/lkl/configs/defconfig`; also dropped `-89` from both so a config-regen can't re-embed
  the bad ucode). File was already in `firmware/iwlwifi/` (55052 bytes).
- Bumped `MVM_UCODE_PNVM_TIMEOUT` `HZ/4` (250 ms) → `2*HZ` (2 s), matching the ALIVE window,
  in case our bridge's RX latency was dropping a late completion.
- Instrumented `fw/pnvm.c` (IWL_INFO): push state, doorbell, handshake result, and promoted
  `iwl_pnvm_complete_fn` to IWL_INFO.
- **Boot result:** `loaded PNVM version 581d4936`, `pnvm_loaded=1`, doorbell rung, but
  **`PNVM handshake wait returned -110`** — full 2 s elapsed, **no** completion notification.
  So the push is correct; the completion genuinely never arrives; 2 s proves it's NOT latency.

### 4.7 Is it a firmware crash? — unmask the fw errors (Fix A)
- Discovery: `iwl_enable_fw_load_int_ctx_info` (internal.h:953) masks everything except
  `ALIVE | FH_RX` during fw-load — **`SW_ERR` (uCode crash) and `HW_ERR` are MASKED**. So a
  firmware crash during PNVM load raises `SW_ERR` into a masked register → silent `-110`. We'd
  been **blind to firmware crashes this entire saga.**
- **Fix A (internal.h:953):** unmask `SW_ERR | HW_ERR` during fw-load →
  `inta_mask = 0xa2000001` (verified compiled as `movl $0xa2000001,inta_mask`). Now the ISR
  runs `iwl_pcie_irq_handle_error` and dumps the fw assert/error table on a real crash.
- **Fix B (posix.d):** sticky-OR raw `CSR_INT` → `INT_SEEN` + `FWERR` flag in the `wifi-irq`
  diagnostic (independent confirmation of `SW_ERR`/`HW_ERR`).
- **Boot result:** the dump showed **`0x00000084 | NMI_INTERRUPT_UNKNOWN`** = the **driver's
  own forced-NMI** after its 2 s timeout, **NOT a spontaneous fw assert**. So **the `-83`
  firmware does NOT crash — it is ALIVE + RUNNING but HANGS/ignores the handshake.** (A
  genuine crash would fire the ISR early with a specific SYSASSERT code, not `0x84`
  post-timeout.) `wifi-irq` also showed `CSR_INT=0x80000000` (FH_RX) with `FIRES` stuck at 1.

### 4.8 The decisive probe — POSTED-BUT-MISSED (bridge bug, not firmware) (2026-07-17)
- Added a probe in `fw/pnvm.c` that reads the interrupt state at the **exact** timeout moment.
- **Boot result — the decisive datum:**
  `PNVM -110 probe: CSR_INT=0x90000000 FH_INT=0x00010000 INT_MASK=0x00000000`
  - `CSR_INT=0x90000000` = `FH_RX` (bit31, Rx/cmd-response ready) **+** `RX_PERIODIC` (bit28)
  - `FH_INT=0x00010000` = RX DMA **channel-0 transfer COMPLETE** (the completion packet is in
    host RAM)
  - `INT_MASK=0x00000000` = **all host interrupts DISABLED**
- **Conclusion:** the `-83` firmware **DID** process the PNVM and DMA the `PNVM_INIT_COMPLETE`
  notification into the RX ring. **We had interrupts masked off, so nobody picked it up.**
  Not a firmware/ucode fault — the bridge masks itself. This retroactively explains the whole
  saga (the earlier "command not fetched" wall = the same masked-off mechanism starving the
  command-completion RX).

### 4.9 Root cause of `INT_MASK=0` — and two failed fix attempts
- **The mechanism:**
  - `iwl_pcie_isr` (top-half, rx.c:2209) writes **hardware** `CSR_INT_MASK=0` on entry and
    returns `IRQ_WAKE_THREAD` (registered via `devm_request_threaded_irq(iwl_pcie_isr,
    iwl_pcie_irq_handler, IRQF_SHARED)`, trans.c:3735). The threaded bottom-half
    (`iwl_pcie_irq_handler`) is supposed to re-enable the mask at the end.
  - The CSR poll `wifiCsrPending` gates on the **hardware** `CSR_INT_MASK` (reads 0x00C). So
    once HW mask = 0, the poll is **dead**.
  - Our bridge registers **two IRQ vectors** (irq 2 + irq 3) and raises **both** on every op6
    wake ("trigger all"). So each interrupt runs the ISR **twice**: the first drains the RX
    and clears `CSR_INT`; the **second sees `inta == 0`** and takes the early-return
    (rx.c:1871) which — during fw-load (`STATUS_INT_ENABLED` not set) — re-enables
    **nothing** → HW `CSR_INT_MASK` stays 0.
  - Once HW mask = 0: MSI can't fire (masked) and the poll can't wake → the post-ALIVE
    completion RX is never delivered → `-110`.
- **Fix attempt 1 (rx.c:2076):** changed the main re-enable chain's last `else if (handled &
  (ALIVE|FH_RX))` to an unconditional `else`. **ZERO effect** — the probe was byte-identical.
  It was unreachable: the `inta == 0` path returns at 1881 first.
- **Fix attempt 2 (rx.c:1877):** re-arm fw-load ints in the `inta == 0` early-return during
  fw-load. **ALSO zero effect** — probe byte-identical again.
- **What this means:** both fixes are compiled in (verified: extra `0xa2000001` stores) but
  have no runtime effect → the ISR code paths I patched **are not executing** during the PNVM
  wait. The deadlock is tighter than modeled: **once HW mask = 0, the threaded ISR that would
  restore it never gets woken** (the poll — its only trigger on this bridge — is gated on the
  very mask that is 0). No fix *inside* the ISR can break it. **The fix must come from the
  bridge poll (or by not zeroing the HW mask in the top-half, or by collapsing to a single
  IRQ vector for single-MSI).** ← current position.

---

## 5. What is CONFIRMED WORKING vs NOT

**Working / proven correct:**
- Bridge register access (fw boots via it), direct-map op8, strong-UC, clflush CSR read.
- DMA addressing (fw boots by DMA-ing ctxt-info/fw-sections from the LKL memfd; `op5` returns
  true host-phys; `ringDMA`/`tb0` verified correct).
- ASPM disabled on the real links.
- `-83` firmware: loads, passes FSEQ, comes **ALIVE**, delivers the ALIVE notification (RX).
- PNVM push: `pnvm_loaded=1`, `loaded PNVM version 581d4936`, ISR6 doorbell reaches fw.
- Firmware **processes the PNVM and DMAs the completion into host RAM** (`FH_INT=0x00010000`).
- WiFi userspace stack (wpa-agent/wpa/udhcpc) — boot-integrity verified in QEMU.

**Not working / blocker:**
- **The PNVM completion RX is never delivered to the driver because the hardware
  `CSR_INT_MASK` is stuck at 0 during the PNVM wait** → `PNVM handshake wait returned -110` →
  RT ucode never starts → **no `wlan0`.** This is the single remaining blocker.

**Regression note:** `-89` worked E2E on 2026-07-09 with the same ucode bytes. It now dies
pre-ALIVE on FSEQ, and `-83` dies on the (masked-off) PNVM completion. The masked-interrupt
deadlock is the best current explanation for the environmental regression; a `.pnvm`-file
change is also possible (not yet ruled out).

---

## 6. Diagnostics reference (real HW, no serial — use the Logs app)

- Logs app = `SUPER+L` / `wl-logview`, reads `/run/klog`. Filter with `/` + text, Enter to
  apply, Tab cycles sources. Any `/run/*.log` write is mirrored into klog.
- Key filters: `iwlwifi`, `pnvm`/`PNVM`, `probe`, `wifi-irq`, `fseq`, `error`, `assert`,
  `pci-aspm`, `secboot`.
- `[wifi-irq]` line (`wifiIrqDiagKlog`, ~1 Hz): `FIRES` (g_msiIrqCount), `CSR_INT`, `MASK`,
  `MSIX_FH/HW`, `ALIVE`, `CSR_WAKES`, `INT_SEEN` (sticky raw CSR_INT), `FWERR` (SW_ERR|HW_ERR
  ever seen). **Note: the line is wider than the screen — `INT_SEEN`/`FWERR` scroll off.**
- `PNVM -110 probe:` line (`fw/pnvm.c`): `CSR_INT`, `FH_INT`, `INT_MASK`, `MSIX_HW/FH` read
  at the exact timeout.
- **Win condition (filter `PNVM`):** `PNVM complete notification received status 0x0` +
  `PNVM handshake wait returned 0 (complete)` + no `-110` → RT ucode starts → `wlan0`.

**Boot-cycle hygiene (learned the hard way):**
- Verify the ISO `md5` before flashing; verify the in-ISO `lkl-boot` md5 == the build.
- A boot with **zero** `iwlwifi`/`ucode` lines = the card is **wedged** from a prior failing
  boot → cold power-off (unplug ~30 s), not a warm reboot. That boot is an invalid test.
- `pkill -9 qemu` (not `pkill -f qemu-system`, which self-kills the shell).

---

## 7. Build recipe (quick reference)

- **LKL / `liblkl.a`** (embeds firmware + iwlwifi):
  `cd ~/lkl-build/linux/tools/lkl && make -j$(nproc) CC=~/lkl-build/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc HOSTCC=gcc "$(pwd)/liblkl.a"`
  (Changing a header touches many objects; the FORCE on `lib/lkl.o` always re-enters the
  kernel sub-make. Changing `CC` invalidates every `.cmd` → full kernel recompile ~6 min.)
- **lkl-boot:** `make build/lkl-boot-musl` (relinks from `src/lkl/lkl-boot.c` + `liblkl.a`).
- **D kernel (`posix.d` etc.):** `make -C src/kernel/d` **then** `make kernel.elf`
  (`make kernel.elf` alone does NOT recompile `.d`; struct-size changes need `rm -rf build/d`).
- **ISO:** `make iso` → `hos-install.iso` (= `hos.iso`). Firmware config lives in
  `~/lkl-build/linux/.config` (`CONFIG_EXTRA_FIRMWARE`) and `arch/lkl/configs/defconfig`.

---

### 4.10 DEFINITIVE root cause + the fix (2026-07-17)

The `inta==0` fix (§4.9 attempt 2) was **also** a byte-identical no-op. A 6-agent,
source-cited investigation nailed why and found the real fix:

- **RX firmware notifications are NOT drained in `iwl_pcie_irq_handler`.** Every `FH_RX`
  sets `polling = true` (`rx.c:2044`, `napi_schedule_prep`) which **skips that handler's
  entire re-enable block** (`if (!polling)` at `rx.c:2079`). So **both** my patches were
  dead code for RX — that's exactly why the probe never changed.
- **The RX drain + mask re-enable live in `iwl_pcie_napi_poll` (rx.c:1008)**, which runs on
  the irqthread. It is **proven to execute** because the ALIVE notification is delivered
  through it every boot (so the irqthread is NOT starved).
- **The bug:** `iwl_pcie_napi_poll` (rx.c:1023-1027) re-enables the mask **only if
  `STATUS_INT_ENABLED`**, and that bit is **not set during firmware load** (it's set by
  `iwl_enable_interrupts` at `mvm/fw.c:433`, *after* `iwl_pnvm_load` returns). So after
  draining the ALIVE notification, `napi_poll` re-arms **nothing** → HW `CSR_INT_MASK`
  stays 0 (`iwl_pcie_isr` zeroed it) → the PNVM completion posts as `FH_RX` into a masked
  device → the CSR poll (HW-mask-gated) never wakes → never drained → `-110`.
- **THE FIX (rx.c:1023, `iwl_pcie_napi_poll`):** add
  `else iwl_enable_fw_load_int_ctx_info(trans);` so the RX drain re-arms the fw-load mask
  (`0xa2000001`, incl `FH_RX`) during firmware load. This is on the **proven-to-run** ALIVE
  drain path, so after ALIVE it re-arms the mask; the completion then arrives with the mask
  live → op6 wakes → drained → delivered.
- **REFUTED — do NOT do the bridge-poll fix.** Making `wifiCsrPending` wake on raw `FH_RX`
  ignoring the HW mask is **documented in the code** (`wifiCsrPending` comment, posix.d) to
  have already **livelocked** (a hot op6 starves the irqthread; `CSR_INT` stuck at `0x3`).
  The HW-mask gate is correct and must stay; the `napi_poll` fix works *with* it.
- Reverted the two inert `rx.c` edits (1877, 2076). Kept Fix A / Fix B / the probe.
- **Fix ISO:** md5 `b4c73bbd349b82fa0cb629c0d0c5ca8f`, lkl-boot md5 `9775cdb6`. Confirm
  print (filter `napi`): `napi q0 fw-load re-arm: mask=0x a2000001`, then (filter `PNVM`)
  `PNVM complete notification received status 0x0` + `handshake returned 0` + `wlan0`.

## 8. Current status — SOLVED ✅ (2026-07-17)

**The `iwl_pcie_napi_poll` re-arm fix WORKS. The AX210 firmware is fully up and `wlan0` is
created.** Real-HW klog confirmed, in order:
- `napi q0 fw-load re-arm: ret=2 mask=0xa2000001` — the re-arm ran; the mask is live.
- `PNVM complete notification received with status 0x5001`
- **`PNVM handshake wait returned 0 (complete)`** — no `-110`.
- **`wlan0 exists`** → `wpa_supplicant … -i wlan0 -D nl80211` → `[wpa-agent] wlan0 up
  (if=3), starting nl80211…`

So: RT ucode started → mac80211 registered `wlan0` → the wpa/udhcpc userspace stack is
running on it. The entire multi-week firmware-bring-up saga is resolved. (The PNVM completion
status `0x5001` is non-zero but the wait returns 0/complete — the driver accepts it; the
notification *arriving* is what matters.)

**Ship firmware `-83` + the restored `.pnvm`.** The load-bearing fixes (all real, keep all):
register-speed direct-map (op8) + `iomem.c` range-discriminate + strong-UC, cache-aliasing
clflush in `wifiCsrRead`, ASPM-off, `SW_ERR/HW_ERR` unmask during fw-load, PNVM restore + 2 s
timeout, and the `napi_poll` re-arm (§4.10).

**Remaining work → see §9.** The firmware/driver layer came up once, but the **scan** does not
work and `wlan0` registration now looks **intermittent**. §9 documents the whole scan
investigation (2026-07-17 → 2026-07-18) and where it currently stands.

**Optional cleanup:** the diagnostics can stay (the `napi` print is fw-load-gated; the `PNVM
-110 probe` only prints on `-110`, which no longer happens; `[wifi-irq]` is ~1 Hz). Remove if
a quieter log is wanted.

---

## 9. Scan does not work + wlan0 registration intermittent (2026-07-17 → 2026-07-18)

After the firmware bring-up (§4–§8) the wifi menu still shows **no networks**. This section
records the full scan investigation. **Bottom line as of the last boot: the scan-trigger root
cause is understood and a fix is written, but the last boot regressed to `wlan0` never
registering, so the fix could not be exercised. Firmware/`wlan0` bring-up appears intermittent.**

### 9.1 Two self-inflicted detours (both cost real time)

1. **`loglevel=5` hides ALL `IWL_INFO`.** The loglevel was dropped 7→5 (§ the freeze fix) to
   stop a printk flood. But `loglevel=5` = only KERN_WARNING(4) and below reach the console →
   klog tee, so **every `IWL_INFO`(6) line is suppressed**: `Detected AX210`, `loaded firmware
   version 83`, `PNVM complete`, `napi re-arm`, and the added `SCAN sent/complete` were all
   *invisible*, not absent. Hours were wasted asking for lines that couldn't print. **Lesson:
   at loglevel=5, any driver diagnostic you need to SEE must be `IWL_WARN`/`IWL_ERR`, not
   `IWL_INFO`. The agent's own `slog()` goes to `/run/*.log` (mirrored to klog) so it always
   shows regardless of loglevel.** The `DIAG kick#` / `DIAG TFD#` lines DO show because they're
   `IWL_ERR` — a boot showing those + no `Detected AX210` is loglevel hiding INFO, NOT a dead card.

2. **Bundling `regulatory.db` BROKE `wlan0`.** Reasoning "world domain restricts scanning", the
   build added `regulatory.db` + `regulatory.db.p7s` to `CONFIG_EXTRA_FIRMWARE`
   (`CFG80211_REQUIRE_SIGNED_REGDB=y` is forced-on — its prompt is gated behind
   `CFG80211_CERTIFICATION_ONUS` which is off — so it can't be disabled; the kernel ships
   `net/wireless/certs/sforshee.hex` and the host `.p7s` is sforshee-signed, so it verifies).
   **Result: `wlan0` stopped registering.** The forced signed-regdb PKCS#7 verification
   (`select SYSTEM_DATA_VERIFICATION`) almost certainly hangs the regulatory setup during
   `ieee80211_register_hw` on the single-CPU LKL. **Reverted** (`.config` + `defconfig` back to
   `ucode + pnvm`); `wlan0` came back. **regdb was never needed anyway** — the `scan while LAR
   regdomain is not set` IWL_ERR never fired, so `lar_regdom_set` was already TRUE via cfg80211's
   built-in WORLD domain. ⚠ **Do NOT re-add `regulatory.db`.**

### 9.2 The scan never reaches the driver — ROOT CAUSE (workflow-verified, 6 agents)

With diagnostics finally visible (`SCAN sent to fw` / `SCAN complete` / `REG SCAN START` promoted
to `IWL_WARN` in `mvm/scan.c`), on a boot where `wlan0` DID come up:
- The agent scans every cycle (`scanning... BSS=0`) but **none** of `REG SCAN START` /
  `SCAN sent to fw` / `SCAN complete` ever fire → **the scan never reaches the driver's
  `->hw_scan`.** cfg80211 rejects it upstream.
- The agent's `nl80211_trigger` (which builds `NL80211_CMD_TRIGGER_SCAN`) was fire-and-forget;
  adding `NLM_F_ACK` + reading the reply showed **`TRIGGER_SCAN: short/no reply` / no ACK**.

**ROOT CAUSE:** `NL80211_CMD_TRIGGER_SCAN` is a genl **doit** gated by
`NL80211_FLAG_NEED_WDEV_UP` (`net/wireless/nl80211.c`). `nl80211_pre_doit` returns **`-ENETDOWN`
BEFORE `->hw_scan`** when the netdev is not `IFF_UP`/running. **`wlan0` is not `IFF_UP`.** That is
the *only* structural difference from the working `GET_SCAN` (a **dumpit** with no `NEED_WDEV_UP`
gate) — which is why the cache *read* works but the scan *trigger* is silently rejected.
- **Nothing in the direct-wpa path brings `wlan0` up.** `epin_wifi_bringup` (lkl-boot.c:788,
  `SIOCSIFFLAGS|IFF_UP`) runs once at boot and isn't on the agent's nl80211 path; the provider's
  copy (lkl-boot.c:1099) is `NSP_SCAN`-only (WEXT) which the nl80211 agent never calls; idle
  `wpa_supplicant` (`ap_scan=1`, no configured network) does no auto-scan and doesn't keep it up.
- The request **encoding is byte-correct** (nlmsg_len=36 self-consistent) and the **routed
  transport is fine** (proven: `CTRL_CMD_GETFAMILY`, itself a doit whose portid-unicast reply
  routes back, resolves `g_famid=22`). So neither is the bug.

### 9.3 The `link_up` fix (agent) — two iterations, not yet proven

**Fix idea:** bring `wlan0` `IFF_UP` right before each trigger so `NEED_WDEV_UP` is satisfied.
Added `link_up(s)` to `src/util/hos-wpa-agent.c`: `RTM_NEWLINK` with `ifi.flags=IFF_UP(0x1),
change=0x1` on the routed `NETLINK_ROUTE` socket.

- **v1 (waited for the ACK) BROKE the shared provider socket.** Real-HW: `link_up wlan0: no ack
  r=-1001`, then **no `TRIGGER_SCAN` line at all**. The RTM_NEWLINK *did* bring `wlan0` up, but
  the first interface-up is HEAVY (`iwl_mvm_mac_start` = firmware commands) on the single LKL cpu
  → the provider didn't answer the ACK `RECVFROM` within ~20 parks → `nsp()` returned `-1001`
  (rd_full header fail) → that **broke the shared provider connection `s`**, so the immediately
  following `nl80211_trigger`'s `NSP_SOCKET` failed → the trigger bailed. (This also proved
  `wlan0` really was DOWN — the heavy op only happens bringing a down interface up.)
- **v2 = FIRE-AND-FORGET** (current, ISO `4e9b070f1504767ee63083a56ec9a7ed`, agent `ffe4c5da`):
  dropped `NLM_F_ACK` + the `RECVFROM`; just `SENDTO` (dev_change_flags runs inline during the
  provider's sendto so `wlan0` comes up) + `CLOSE`. No ACK wait → no `-1001` → the shared socket
  stays healthy for the trigger. Per-cycle (cheap no-op once up); logs once via `g_linkUpLogged`.

### 9.4 CURRENT STATE (last boot, ISO `4e9b070f`) — blocked on wlan0 registration

`/run/wpa-agent.log` was stuck at **`waiting for wlan0 (adapter coming up)...`** (only:
`Wi-Fi agent starting` → `provider connected` → `waiting for wlan0`). The agent never resolved
`wlan0`'s ifindex, so it never reached the scan block — `link_up` never ran, no `TRIGGER_SCAN`,
no `REG SCAN START`. `/run/wpa.log` shows `wpa_supplicant` initialized on `wlan0` but stuck at
`ap_scan=1` (9 lines). User waited; **nothing changed.** So on this boot `wlan0` did not register
far enough for `resolve_ifindex` (RTM_GETLINK) to find it. The agent build only changed the scan
path (not `resolve_ifindex`), so this is a **firmware/`wlan0` registration regression/intermittency**,
not the agent. This matches the long-standing intermittency of the AX210 bring-up on bare LKL —
some cold boots complete the PNVM/RT-ucode handshake and register `wlan0`, some do not.

### 9.5 Open items / next steps (for whoever picks this up)

1. **Confirm the `link_up` fix on a boot where `wlan0` DOES register.** Expected chain
   (`/run/wpa-agent.log` + `/run/klog` filter `reg scan`): `link_up wlan0 (IFF_UP,
   fire-and-forget)` → `TRIGGER_SCAN accepted err=0` → `REG SCAN START` → `SCAN sent to fw` →
   `SCAN complete: OK` → `scan OK: N network(s)` → networks in the menu.
2. **If `link_up` v2 still doesn't get the trigger through** (async interface-up work persistently
   stalls the provider): move the one-time `IFF_UP` into the **kernel** at boot —
   `epin_wifi_bringup` (lkl-boot.c) already has the `SIOCSIFFLAGS|IFF_UP` pattern; make it run on
   the nl80211/provider path (not just the WEXT `NSP_SCAN` path) and/or re-assert it periodically,
   so the heavy interface-up happens once off the agent's per-scan path and `wlan0` stays up.
3. **Investigate the `wlan0`-registration intermittency directly.** The napi_poll fix (§4.10)
   made the PNVM handshake complete on the boot it was verified, but later boots regressed to
   `wlan0` never appearing. Check on a failing boot (all `IWL_WARN`/`ERR`, visible at loglevel=5,
   or temporarily raise to 7): does `PNVM handshake wait returned 0` fire? does the RT ucode
   start? does `ieee80211_register_hw` complete? This may be a residual RF/FSEQ intermittency
   (the pre-napi FSEQ history) or a second interrupt-path gap after the PNVM completion.
4. **`link_up` errno capture** (if a boot triggers but is refused): the retry-3× ACK read (before
   it was made fire-and-forget) would show `-16 EBUSY` (wpa holds `rdev->scan_req` → gate/abort
   wpa's scan) vs `-1 EPERM` (`GENL_UNS_ADMIN_PERM` caps).

### 9.6 Firmware version note (unchanged, still true)

Ship `-83` + the matched `.pnvm` (`iwlwifi-ty-a0-gf-a0.pnvm`, restored to `CONFIG_EXTRA_FIRMWARE`).
`-89` dies pre-alive on FSEQ; `-83` reaches ALIVE + (with the napi fix) completes PNVM. Do **not**
re-add `regulatory.db`. `loglevel=5` (do not raise unless debugging — it re-introduces the freeze;
promote specific diags to `IWL_WARN` instead).
