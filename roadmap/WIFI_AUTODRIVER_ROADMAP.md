# WiFi + Auto-Driver Provisioning Roadmap

## Goal (user, 2026-06-30)

1. Get **WiFi working** on the Framework 13 (real hardware).
2. Once online, **auto-detect which Linux drivers the machine needs** and download them.
3. **Incorporate those drivers into the OS at install time**, so the installed system
   has exactly the drivers this hardware requires.

## Design principle

EpinAnonymOS reuses Linux drivers by embedding **LKL** (the Linux Kernel Library).
WiFi is the canonical "reuse a Linux driver" case, so the WiFi driver lives **in LKL**,
driven over the existing `0x4100` PCI/MMIO/DMA/IRQ bridge (already proven for NVMe, USB
xHCI, and GPU on this laptop). The auto-driver feature (goal 2–3) is the *general* form
of the same idea: detect hardware → get the right Linux driver+firmware into the image.

---

## Current state (recon, 2026-06-30)

| Area | State | Notes |
|---|---|---|
| LKL wireless | ❌ `# CONFIG_WIRELESS is not set` | no cfg80211/mac80211/driver |
| LKL firmware | ❌ `# CONFIG_FW_LOADER is not set` | can't load `.ucode`/`.bin` blobs |
---

## Architecture decisions (resolve before Phase W1)

### D1 — Where does the IP stack live for WiFi?
- **A. LKL TCP/IP** (WiFi → LKL cfg80211/mac80211 → LKL net stack → a socket bridge to
  EpinAnonymOS userspace). Reuses Linux's mature stack; WPA already forces us into LKL, so
  keep the whole path there. Needs a socket/netlink bridge syscall.
- **B. Bridge raw wlan frames** to the native `network/` stack (e1000-style). Reuses the
  native stack, but its RX is unproven on real HW and 802.11→802.3 handling is extra work.
- **→ Recommend A.** Native stack stays for the wired/e1000 fast path.

### D2 — WPA / WPA2 / WPA3 association (the hard part the recon underweighted)
`mac80211` does the 802.11 MAC, but the **4-way handshake / SAE** needs a supplicant.
- **A. wpa_supplicant** (static-musl), driven over nl80211 + its control socket. The
  reference; handles WPA2/WPA3/enterprise. Biggest, but battle-tested.
- **B. iwd** — smaller, but needs specific kernel crypto configs.
- **C. minimal embedded WPA2-PSK-only supplicant** — smallest; no WPA3/enterprise.
- **→ Recommend A** (wpa_supplicant), start against WPA2-PSK, WPA3 falls out for free.

### D3 — Driver distribution model ("download drivers, incorporate at install")
- **A. Fat LKL + fetch firmware.** Build ONE LKL with all common laptop WLAN/eth/USB
  drivers **built-in**; at install, detect hardware and fetch only the **firmware** blobs
  it needs. Firmware is the genuinely per-device, license-restricted, too-big-to-bundle-all
  part. "Incorporate drivers at install" ⇒ *fetch firmware + record which built-in driver
  binds each device*. Simplest, ships soonest.
- **B. LKL loadable modules.** `CONFIG_MODULES=y`; ship a `.ko` repo; at install fetch only
  the needed `.ko` + firmware. Truer to "download a driver," but LKL+modules is finicky and
  a bigger attack surface.
- **→ Recommend A now, evolve to B later.** Under A, "drivers to download" = firmware blobs
  + a manifest mapping each detected device to its built-in driver.

---

## Phases

### W1 — LKL wireless rebuild
Config fragment ready: **`src/lkl/wifi-lkl.config`** (Model A, all common WLAN drivers +
`FW_LOADER` + WPA crypto). Merge into `~/lkl-build/linux/arch/lkl/configs/defconfig`, then
`make ARCH=lkl olddefconfig` + rebuild `liblkl.a` + relink `lkl-boot-musl`. Grant the
class-0x02 BDF to `lkl-boot` (extend the `findDeviceByClass` preference chain / add a WiFi
grant). **Verify:** driver probes, a `wlanN` netdev appears, `nl80211` scan returns APs.

**★ W1 BLOCKER — MSI/MSI-X.** The LKL↔kernel IRQ bridge (`lkl-boot.c` L3c) is **legacy INTx
only** (userspace-polled via op6). **Modern WiFi (Intel AX2xx, most PCIe WLAN) requires
MSI/MSI-X and does NOT support INTx** — so the driver will load but get no interrupts and
never come up. So W1 really needs, FIRST, an **MSI-X path in the bridge**: allocate the MSI-X
vectors on the real device (config-space capability + BAR table writes), and deliver those
interrupts from the native kernel into LKL via `lkl_trigger_irq`. This is a real subsystem
(new `0x4100` ops for MSI-X setup + per-vector wake). Older cards (ath9k, some rtw88, iwlwifi
≤7260) can do INTx and could prove the software path first. **The W0 survey chip decides
whether we can bootstrap on INTx or must do MSI-X up front.**

### W1-pre — toolchain
The musl cross-compiler (`x86_64-linux-musl-gcc`) is NOT installed; `liblkl.a` is ~400 MB.
W1's build needs: fetch `x86_64-linux-musl-cross` from musl.cc, apply the fragment, and a
long `make -j` (16 cores here). Heavy + only verifiable on the FW13.

### W2 — Firmware provisioning (bridge)
Add a `request_firmware` host-op in `lkl-boot.c`: LKL asks for `iwlwifi-*.ucode` (etc.),
EpinAnonymOS serves the bytes from an in-image path (objstore/memfd). Bundle a **starter
firmware set for the FW13's own chip** in the ISO (general fetch is W6). **Verify:** firmware
loads, radio powers on (regdomain/MAC visible).

### W3 — Association (WPA)
Bring up `wpa_supplicant` (static musl) beside `lkl-boot`, talking nl80211 to the driver;
feed SSID/passphrase from a config file (later: the installer's network page). **Verify:**
associates to a WPA2 AP — EAPOL 4-way completes, carrier/"connected" up.

### W4 — IP + connectivity
DHCP over `wlanN` (LKL `udhcpc`, or bridge `network/dhcp.d`), DNS, a test HTTPS GET.
**Verify:** reach the internet from the FW13 over WiFi (ping + HTTPS 200).

### W5 — Installer network page
Enable the disabled **"Wi-Fi"** option in `wl-installer.c`: nl80211 scan → SSID list →
passphrase entry → associate → confirm online; write creds/choice into `/install.json`.

### W6 — Auto-driver detection + provisioning (the general feature)
- **W6.1** Enumerate ALL hardware (PCI + USB) → build `modalias` strings (Linux-style).
- **W6.2** Map modalias → needed driver + firmware via a manifest (a `modules.alias`-like
  table shipped in-image, refreshable online).
- **W6.3** Once online (W4), fetch the needed **firmware** (model A) — and `.ko` (model B) —
  over **HTTPS from a pinned, signed mirror**; verify signatures before use.
- **W6.4** Incorporate at install: write firmware into the target's `/lib/firmware`
  (LKL-visible) + a driver-bind manifest; record it in `install.json`; first boot binds them.
- **W6.5** Cross-machine verify: a second laptop with a *different* WiFi chip provisions
  itself end-to-end from the installer.

---

## Security / trust (this is a privacy OS — non-negotiable)
Downloading + incorporating drivers/firmware at install is a **supply-chain surface**:
- HTTPS + **signature verification against a pinned key** before anything is used; record
  provenance. Reuse `boot_integrity` + `template_bundle` HMAC/signing.
- Cap-gated: only the installer, under an explicit **user-approved** action, may fetch/bundle.
- Firmware blobs are proprietary/opaque — **surface to the user** what's fetched, from where,
  and get consent.

## Decisions — LOCKED (user, 2026-06-30)
- **D2 → wpa_supplicant** (static musl), **WPA2-PSK first** (WPA3 later).
- **D3 → Model A: fat LKL** — build ALL common laptop WLAN drivers built-in (iwlwifi,
  rtw88, rtw89, mt76, ath9k/10k/11k/12k, brcmfmac) + `FW_LOADER=y`; at install fetch only
  the **firmware** the detected hardware needs. "Incorporate drivers" = fetch firmware +
  a driver-bind manifest. (D1 defaults to **A: LKL's own TCP/IP** as a consequence.)
- **W6.3 mirror → upstream `linux-firmware`** over HTTPS. NOTE: still sign/verify + pin the
  fetch (see Security) and record provenance — pulling upstream ≠ skipping verification.

## Chip CONFIRMED (W0, 2026-06-30)
`WIFI 8086:2725 WiFi bdf=aa:00.0 Intel -> iwlwifi` = **Intel Wi-Fi 6E AX210** (device 0x2725,
"Typhoon Peak"). Driver: **iwlwifi + iwlmvm**. Firmware: **`iwlwifi-ty-a0-gf-a0-*.ucode`**
(+`.pnvm`) from upstream `linux-firmware`. **★ IRQ: AX210 is MSI-X (no INTx)** → the W1 MSI-X
bridge work is REQUIRED (not the INTx escape hatch). PCI bus 0xaa.
