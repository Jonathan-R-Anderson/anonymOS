# System Upgrade + Rollback over I2P/DHT with zkSync-Anchored Releases

## Goal (user, 2026-07-12)

1. **Upgrade the installed system** and **roll back** when an upgrade is bad.
2. **No centralized server**: distribution over a **Kademlia DHT** where every node
   operates **under I2P**.
3. Files published to the DHT are **signed**; the **signature record is anchored on the
   zkSync (Ethereum L2) network**.

## North star

An installed EpinAnonymOS checks a release channel, discovers the newest signed system
image via a Kademlia DHT whose nodes are I2P destinations, downloads it peer-to-peer over
I2P, verifies (a) the publisher's Ed25519 signature locally and (b) the release's anchor
record on zkSync (authenticity + anti-rollback + transparency), stages it to the
**inactive A/B slot**, and reboots into it. If the new slot fails to prove a healthy boot,
the firmware path **falls back to the previous slot automatically**. Publishing a release
requires only a signing key, a zkSync transaction, and any node willing to seed — no
server anywhere.

## Progress at a glance (updated 2026-07-12)
- ✅ **U0** — version identity + boot proof — DONE + QEMU-verified.
- ◑ **U1** — A/B slots + rollback: **U1-A** (boot-state machine, verbs, selftests) ✅ verified
  headless; **U1-B** (A/B GPT + dual-slot install + boot-state init) ✅ verified on raw disk;
  **U1-C** (slot-arbiter EFI) BUILT (PE32+) — 2 documented OVMF boot-chain blockers remain
  (arbiter bypass; pre-existing NVMe-BAR-high HHDM fault). See U1 STATUS.
- ◑ **U4** — `contracts/UpdateRegistry.sol` (permissionless) WRITTEN + consolidated with
  `DhtBootstrapRegistry.sol` + `BootIntegrityRegistry.sol` into top-level `contracts/`;
  deploy + in-kernel reader + wallet flow pending.
- ⬜ **U2, U3, U5–U9** — not started.

---

## What already exists to build on (verified 2026-07-12)

| Area | State | Notes |
|---|---|---|
| Install engine | ✅ `drivers/veracrypt_impl.d` — batched GPT+ESP streaming to AHCI/**NVMe**, progress contract (-1/0/1..1000), capability-gated writes (`install_cap.d`), install logging | E2E-verified in QEMU incl. Hidden OS (2026-07-11); THE staging engine for slot writes |
| GPT layout | ✅ `core/diskpart.d` — builds/writes/validates GPT (plain + Hidden OS encrypted layout) | A/B = a second ESP entry + a state region; all ours to change |
| Own EFI stages | ✅ `preboot.efi` / `stage2.efi` (veracrypt-efi, Hidden OS password gate) | proof we can ship a first-stage boot chooser (slot arbiter) |
| zkSync anchoring | ✅ `core/boot_integrity.d` — SHA256 boot-module merkle vs **`BootIntegrityRegistry.sol`** read via in-kernel HTTPS JSON-RPC (`eth_call`); publisher side = `scripts/compile-boot-integrity-contract.sh` + `zksync-wallet-vue` blob | the on-chain read/write pattern for the release registry is ALREADY PROVEN |
| Signed bundles + rollback | ✅ DM12 `core/template_bundle.d` — export/sign/verify, tamper reject, publisher trust, generation/rollback epochs | pattern to reuse; but HMAC (symmetric) — release signing needs **Ed25519** |
| Crypto | ✅ `core/crypto.d` — SHA256, HMAC, X25519, HKDF, ChaCha20-Poly1305 | ❌ no Ed25519 yet (needed: publisher signatures verifiable by everyone) |
| Package repo | ✅ DM7 `core/pkgrepo.d` (cap-gated, per-domain) | later rides the same pipeline for per-package updates |
| Native net stack | ◑ e1000+ARP proven (N0/N1); TCP RX host-blocked in QEMU (N2); in-kernel HTTPS exists (used by boot_integrity, `NET=1`) | one of two transports |
| LKL net path | ✅ the path that works on the FW13 today: LKL WiFi + userspace sockets via the nshim (`wpa`, `udhcpc` lease, `scp` upload all proven) | userspace daemons (i2p, updater) should ride THIS |
| I2P + DHT plan | 📋 `NETWORK_AND_MARKETPLACE_ROADMAP.md` Part B (M0 SAM bridge, M2 Kademlia over I2P datagrams) — **planned, not built** | SHARED infrastructure: build once, serve marketplace + updates |
| Update GUI surface | ✅ `wl-installer` wizard scaffold, Settings app, `store-app`, quicksettings | the user-visible layer (build it alongside — DM lesson) |
| Test loop | ✅ headless QEMU NVMe install repro + QMP wizard driving (see memory `installer-nvme-target`) | extend to upgrade/rollback cycles |

---

the blockchain needs to have a series of i2p addresses saved to it used for bootstrapping. the namespaces used for dispersing the updates need to be fully validated as unmodified. and the hashes of the files they contain for pushing updates need to be signed. 

## Architecture decisions (resolve before U2)

### D1 — Update unit: whole-image A/B, not package surgery
- **A. Image-based A/B**: an update = a complete signed `esp-image` (kernel + modules +
  limine) written to the inactive slot. Atomic by construction; rollback = boot the other
  slot; verification = one hash tree. The object store (user data) lives outside the
  slots and is untouched.
- **B. Package-based**: mutate the running system per-package. Smaller downloads, but
  rollback becomes a database problem and a half-applied update is a bricked system.
- **→ A.** Matches the immutable-system philosophy (`/system` is already an immutable
  view). Per-package updates come later (U8) for *domain* software via DM7, riding the
  same signed-artifact pipeline — never for the base system.

### D2 — Slot mechanism: two ESPs + a boot-state sector, arbitrated by our own first stage
- GPT gains **ESP-A**, **ESP-B**, and a tiny **boot-state region** (slot to try, retry
  counter, boot-ok flag — one sector, CRC'd, written atomically).
- Ship our own `BOOTX64.EFI` **slot arbiter** (we already build preboot/stage2 EFI
  binaries): read state → decrement retry counter → chainload the chosen slot's limine.
  A slot only becomes *permanent* when the booted OS proves health and writes `boot-ok`
  (see U1 health check). Counter hits 0 without boot-ok → arbiter flips back. No UEFI
  BootOrder games, no firmware NVRAM dependence.
- Hidden OS installs: the decoy/hidden layout keeps its existing chain; slot logic applies
  to the *hidden* OS's ESP pair inside the encrypted region (deferred detail → U9; plain
  installs first).

### D3 — Signing: Ed25519 release keys, pinned root, offline-verifiable
- HMAC (DM12) is symmetric — verifier holds the signing secret; unusable for OS releases.
- **Ed25519** added to `crypto.d` (compact, no bignum-RSA; reference impl ports cleanly to
  `@nogc` D). **Root release pubkey pinned in the kernel image**; release manifests are
  signed offline by the publisher key (root can rotate keys via on-chain record, U9).
- Local signature verification MUST pass **offline** — the chain anchor adds freshness,
  anti-rollback, and transparency, but a node with no connectivity can still verify and
  apply an update from a USB stick (U3) on signature alone (with local monotonicity).

### D4 — What zkSync provides, exactly (and what it must not become)
- The **`UpdateRegistry` contract** (`contracts/UpdateRegistry.sol`, deployed) stores per
  `(publisher, channel)`: monotonically-increasing `version`, `artifactRoot` (SHA256
  merkle root of the bundle), `manifestSigHash`, optional publisher signing key, and a
  per-publisher revocation flag.
- **Trust model — "creator deploys once, everyone else just interacts" (locked):** the OS
  creator deploys the contract a **single time**; the deployer is recorded as `creator`
  for provenance and holds **no** authority over anyone else. Thereafter the contract is
  **permissionless**: (a) any account calls `publish(channel, version, artifactRoot,
  manifestSigHash)` to register a release under its **own address-namespace** (versions
  monotonic per `(publisher, channel)` → a publisher can only move its own channel
  forward); (b) anyone calls `getRelease` / `validate` as **free `view` calls** to
  authenticate a candidate — no account, no gas, no gatekeeper. The base OS pins the
  creator's address and trusts only the creator's `stable` channel for system images;
  third-party software publishers use their own address and users opt into those. No
  admin, no owner-gated publishing, no pause switch.
- Nodes read via `eth_call` JSON-RPC — the reader exists in `boot_integrity.d`; factor it
  into a reusable `core/zkanchor.d`. Publishing = one wallet transaction (extend the
  existing zksync-wallet flow); anyone with a key can publish, from anywhere.
- **RPC endpoints are availability dependencies, not trust dependencies**: the record's
  meaning is enforced by contract logic + the locally-verified Ed25519 signature; a lying
  RPC can at worst serve a *stale* head. Mitigate: query **N-of-M independent RPC
  endpoints** and require agreement on the head; route queries **through I2P outproxies**
  so chain reads don't deanonymize the node. True light-client storage proofs = U9 stretch.
- Anti-rollback rule: a node never applies `version <= localVersion`, and when online it
  refuses any candidate that is not the on-chain head for its `(publisher, channel)`.
- **Contract consolidation:** every Solidity/ZKsync contract now lives in the top-level
  **`contracts/`** folder (moved out of `installer/contracts/`), compiled together by
  `scripts/compile-contracts.sh` → `build/contracts/<Name>.artifact.json`. Both
  `UpdateRegistry.sol` (this, permissionless) and the pre-existing
  `BootIntegrityRegistry.sol` (single-owner, per-machine boot attestation) live there.

### D5 — I2P: SAM v3 to a router; embedded i2pd is a later port, not a prerequisite
- All DHT/transfer code speaks **SAM v3** (same decision as marketplace M0): dev loop uses
  a router on the host/LAN; the shipped OS gets a **userspace i2pd port** (C++/musl — a
  large but bounded port, staged in U5b) running as a domain-isolated service.
- Node identity = the I2P destination; `nodeId = SHA256(destination)` (marketplace M1).

### D5a — DHT bootstrap: on-chain seed list + pinned peers (two sources, no central server)
- A node joining the DHT for the first time needs some peer destinations to dial. Two
  complementary, server-less sources: (a) a small list of long-lived destinations **pinned
  in the image**; (b) the **`DhtBootstrapRegistry` contract** (`contracts/`) — a
  **creator-controlled, open-registration** seed list: any node calls `register(i2pDest)`
  to advertise its own I2P destination, anyone reads the active set via free `view` calls.
- Trust model here is deliberately DIFFERENT from `UpdateRegistry`: the creator OWNS this
  registry (curates/removes spam/stale entries) because a bootstrap seed list is an
  availability/anti-abuse surface, not a per-publisher authenticity claim. It is only a
  *hint* — a fresh node still authenticates DHT records by signature, so a malicious seed
  can waste a connection attempt but cannot forge a release. Losing the contract only costs
  the on-chain seed source; the pinned peers still bootstrap the network.

### D6 — Where the updater runs: userspace daemon on the LKL socket path
- `hos-updated` (+ `hos-i2pd`) are **userspace services** using the socket path that
  already works on real hardware (LKL + nshim — same as wpa/udhcpc/scp). The in-kernel
  native stack/HTTPS remains the QEMU `NET=1` dev path and the boot-integrity reader.
- Kernel keeps only what must be privileged: slot writes (via the existing cap-gated
  install engine), boot-state writes, pinned-key signature verification of the manifest
  before any sector is written (`/config/update.action` control file, mirroring the
  installer's `install.action` contract — deny-by-default).

---

## Threat model (what each layer buys)

| Layer | Defends against |
|---|---|
| Ed25519 signature (pinned root) | forged/tampered images, malicious mirrors/peers |
| zkSync anchor (monotonic version) | rollback/freeze attacks, split-view (targeted old-version) attacks; public transparency of every release |
| Kademlia DHT + swarm over I2P | central-server takedown/censorship; download privacy; publisher/subscriber anonymity |
| A/B slots + boot-ok watchdog | bad-but-genuine updates (bricking); power loss mid-update |
| Cap-gated kernel write path | a compromised updater daemon writing arbitrary sectors |

---

# Milestones

Each milestone ends with a **proof at the init site** (klog line / Logs-app filter) and a
QEMU verification recipe — same discipline as the installer work.

## U0 — System version identity (tiny, do first) — ✅ DONE + VERIFIED (2026-07-12)
Built: `core/sysversion.d` (monotonic `SYSTEM_VERSION`, channel, boot slot); `/config/system.json`
gained version/versionString/channel/slot. Boot proof confirmed in QEMU:
`[update] system version=0x1 (0.1.0) channel=stable slot=A`.

`/config/system.json` gains `version` (build-embedded, monotonic integer + human string),
`channel` (`stable`), `slot` (`A`/`B`), `bootCount`. Build stamps the version into the
kernel + into `esp-image` at ISO/bundle build time.
**Verify:** boot proof line `[update] system version=… channel=stable slot=A`; visible in
Settings → About.

## U1 — A/B slots + boot-state + automatic rollback (LOCAL; no network, no crypto) — ◑ MOSTLY DONE (U1-A/B ✅ verified; U1-C built, 2 boot-chain blockers — see STATUS below)
1. `diskpart.d`: GPT v2 layout — ESP-A + ESP-B + 1-sector boot-state (magic, seq, CRC,
   `trydSlot`, `triesLeft`, `bootOkSlot`). Installer writes both slots (B = copy of A).
2. **Slot-arbiter EFI**: read/decrement state, chainload A or B; flip on exhaustion.
3. Kernel health gate: `boot-ok` written only after the boot proofs pass + the desktop
   compositor is up (reuse the `[freeze]`/watchdog instrumentation to define "healthy").
4. `/config/update.action` verbs: `stage <slot>` (dev: copy running image), `switch`,
   `rollback`, `status` → `/config/update.status` JSON.
**Verify (QEMU NVMe loop):** install → `switch` → reboots into B (klog says slot=B) →
corrupt B's kernel via a dev verb → reboot → arbiter falls back to A after N tries →
`[update] AUTO-ROLLBACK to A` in klog. This milestone alone ends "a bad flash bricks it".

**STATUS 2026-07-12 — mostly built + verified; OVMF end-to-end boot has 2 open blockers:**
- ✅ U1-A boot-state machine (`core/bootstate.d` @ LBA 34, `core/sysupdate.d` verbs
  switch/rollback/boot-ok/status/init-state, `/config/update.action`+`.status`) — PASS
  headless (`[bootstate] selftest PASS`, `[update] engine selftest PASS`).
- ✅ U1-B A/B GPT + dual-slot install (`diskpart.d gptWriteABToDisk`; `veracrypt_impl.d`
  streams slot-A→slot-B→ESP-boot then `bootStateInit(SLOT_A)`) — VERIFIED on the raw disk
  (`sgdisk`: p1 8 MiB EF00 arbiter, p2/p3 320 MiB 0700 slots; LBA 34 = `EUBS` try=A ok=A
  tries=3 active=A). `mk-install-iso.sh` builds `esp-boot.img` (arbiter as BOOTX64.EFI),
  staged as module `esp-boot-image`; `boot/arbiter/` builds `arbiter.efi` (PE32+).
- ⛔ **BLOCKER 1 (arbiter bypass):** OVMF boots `\EFI\BOOT\BOOTX64.EFI` from the first FAT
  partition it enumerates; the SLOTS also carry limine at that path, so a slot's limine
  runs directly and the arbiter never executes. FIX: the slots must not expose the fallback
  path — put the **arbiter at `\EFI\BOOT\BOOTX64.EFI` in every partition** (it reads the
  shared LBA-34 state and redirects), and relocate each slot's limine to
  `\EFI\anonymos\limine\BOOTX64.EFI` (arbiter's `LIMINE_PATH`). Robust against OVMF's
  partition-pick. (Needs a slot-flavored esp-image + limine-relocation check.)
- ⛔ **BLOCKER 2 (pre-existing, not A/B-specific): NVMe BAR-high fault under UEFI.** OVMF
  maps the NVMe BAR0 at phys `0x800000000` (8 GiB); the kernel HHDM doesn't cover it →
  page fault in `nvme.d` at first boot. The `-cdrom`/BIOS path placed the BAR low
  (`0xfebb0000`), so booting an *installed* disk under UEFI is the first time it's hit —
  this ALSO blocks installed-system boot on the FW13 regardless of A/B. FIX: map the NVMe
  BAR region on demand (same class as the AHCI HHDM fix) instead of assuming HHDM coverage.

## U2 — Signed update bundle (`.hosupd`) + kernel-verified staging
1. `crypto.d`: **Ed25519** verify (+ host-side signing tool `scripts/sign-update.py`).
2. Bundle = `manifest.json` (channel, version, prevVersion, chunk list w/ SHA256s,
   artifactRoot, publisher key id) + `esp-image` payload + detached signature.
3. Kernel: pinned root pubkey; `update stage-bundle` control path verifies manifest sig +
   every chunk hash **before/while** streaming to the inactive slot via the cap-gated
   install engine (batched, `-1/0/1..1000` progress, heartbeat logging — all reused).
   Version monotonicity enforced here (`version > local`), persisted like `policyEpoch`.
**Verify:** stage a signed bundle from a file → switch → boot new version; tamper 1 byte
→ `[update] FAIL: chunk hash` + refusal; re-sign with wrong key → refusal; replay older
version → `[update] FAIL: rollback` refusal.

## U3 — Updater UI + offline medium (user-visible layer, built now not last)
`wl-settings` → **System Update** page (or `store-app` tab): current version/slot/health,
"Install from file/USB", stage/apply/rollback buttons, progress bar riding
`/config/update.progress`, log tail from `/run/updater.log` (ilog pattern). USB stick with
a `.hosupd` = fully offline upgrade path (and the fallback story forever).
**Verify:** QMP-driven GUI upgrade + rollback in QEMU; logs in Logs app filter `update`.

## U4 — zkSync `UpdateRegistry` anchor (network read; publishing tools) — ◑ CONTRACT DONE (`contracts/UpdateRegistry.sol` written + consolidated; deploy/reader/wallet pending)
1. **`contracts/UpdateRegistry.sol` (DONE — written + consolidated):** permissionless
   `(publisher, channel) → {version, artifactRoot, manifestSigHash, revoked}` with the
   "creator deploys once, anyone publishes/validates" model (D4). Remaining: deploy it to
   zkSync testnet from the creator key; add `publish`/`revoke` flows to the zksync-wallet
   blob (reuses the boot-integrity wallet plumbing).
2. Factor `boot_integrity.d`'s JSON-RPC `eth_call` reader into `core/zkanchor.d`; the
   updater calls `validate(creatorAddr, channel, minVersion, artifactRoot)` (free view),
   with N-of-M endpoint agreement on the head.
3. Offline behavior explicit: no chain ⇒ signature + local monotonicity only (log says so).
**Verify:** publish v(N+1) on zkSync testnet → node refuses a signed v(N+2) NOT anchored,
refuses anchored-but-old vN, accepts anchored v(N+1); a SECOND publisher key writes its
own channel without touching the creator's. All cases klog-proven.

## U5 — I2P transport (shared with marketplace M0/M1)
- **U5a**: SAM v3 client (userspace, LKL socket path): persistent destination, STREAM
  connect/accept, DATAGRAM send/recv. Dev router on host/LAN. `hos-updated fetch
  i2p://<dest>/<artifactRoot>` downloads a bundle from a peer node running the seeder.
- **U5b**: port **i2pd** (musl, domain-isolated service, NetPolicy-gated) so shipped nodes
  need no external router. Staged: build → tunnels up → reseed file pinned in image.
**Verify:** two QEMU nodes (or node + host seeder) exchange a bundle purely over I2P;
tcpdump on the host sees only I2P/router traffic, no clearnet HTTP.

## U6 — Kademlia DHT: release discovery + swarm download (shared with marketplace M2)
1. Kademlia over I2P datagrams: k-buckets, PING/STORE/FIND_NODE/FIND_VALUE,
   `nodeId = SHA256(destination)`; bootstrap from BOTH the destinations pinned in the
   image AND the on-chain **`DhtBootstrapRegistry`** seed list (D5a) — a joining node
   reads the active set (free view call), dials a few, then refreshes from live peers.
   Nodes optionally `register(i2pDest)` themselves to grow the seed set.
2. Two record types under DHT keys:
   `releasePtr = SHA256("epin-release:"+channel)` → **signed** release pointer (version,
   artifactRoot, sig — self-certifying, so the DHT needs no trust);
   `providers(artifactRoot)` → seeder destinations (BEP5-style).
3. Chunked swarm fetch over I2P streams from multiple providers, per-chunk hashes from the
   manifest; every completed node re-seeds (configurable).
**Verify:** 3-node QEMU mesh + host router: node A publishes pointer+seeds; nodes B,C
discover via DHT (no address of A configured anywhere), download, verify, stage.

## U7 — End-to-end decentralized upgrade + rollback (the north-star demo)
Publish flow: `scripts/release.py` → sign bundle → zkSync anchor tx → seed on any node.
Consume flow: fresh install (QEMU NVMe) → `hos-updated` discovers v(N+1) via DHT over I2P
→ verifies sig + anchor → stages to inactive slot → user clicks Apply → reboots healthy →
boot-ok. Then the negative: publish a deliberately-broken v(N+2) (panics at boot) →
node upgrades → arbiter auto-rolls back to v(N+1) → updater marks v(N+2) bad locally and
(optionally) gossips the failure.
**This closes the user's goal statement.**

## U8 — Efficiency + scope growth
Delta bundles (`prevVersion`-based binary diff of esp-image), resumable/partial chunk
fetch, DM7 package + driver/firmware artifacts (driver-install roadmap) published through
the SAME sign→anchor→DHT pipeline, update checks on a jittered timer under NetPolicy.

## U9 — Hardening + research tail
On-chain key rotation + revocation drills; multiple channels (stable/testing) with
independent heads; transparency auditor (walk all registry events, verify sig chain);
light-client/storage-proof chain reads (drop RPC-quorum assumption); **Hidden OS update
story** (update the hidden slot without observable writes that break deniability —
research: all writes must look like outer-volume free-space churn); reproducible builds
so `artifactRoot` is independently re-derivable from source.

---

## Dependency graph (what can start now)

```
U0 ─→ U1 ─→ U2 ─→ U3           (fully local: start immediately, QEMU NVMe loop)
             │
             ├─→ U4             (needs zkSync testnet + existing wallet/contract tooling)
             └─→ U5a ─→ U5b     (needs working LKL socket path — exists on FW13/QEMU)
                   └─→ U6 ─→ U7 ─→ U8 ─→ U9
```

U0–U3 deliver standalone value (atomic upgrades + auto-rollback + offline USB updates)
before any network, chain, or I2P work lands. U5/U6 are built ONCE, shared with the
DM12 marketplace (`NETWORK_AND_MARKETPLACE_ROADMAP.md` Part B) — keep the module
boundaries (`sam.d`/`dht.d` equivalents in the userspace daemon) marketplace-agnostic.

## Honest risk register

- **i2pd port size** (U5b): the biggest single port since Weston/NM; mitigated by SAM
  abstraction (everything above it works against a host router meanwhile).
- **Single-core CPU pressure**: i2pd + DHT + desktop on one core — the NM-churn freeze
  lesson applies; run i2pd nice'd/domain-gated, and SMP work (S4/S6/S8) helps.
- **zkSync RPC over I2P outproxy**: latency/availability; N-of-M + cached head + offline
  mode keep the updater usable regardless.
- **Boot-state write atomicity on NVMe**: single-sector write + CRC + seq is atomic
  enough; verify explicitly in U1's power-cut test (QEMU `quit` mid-write).
- **Hidden OS + updates** is genuinely hard (deniability vs. observable writes) — parked
  in U9, plain installs first; do not let it block U0–U7.
