# ORIGIN_SERVER_ROADMAP — one server that publishes the OS, its software and the dendritic network

**Goal (user, 2026-10-01).** A mechanism to push updates to every computer running anonymOS: a
server that doubles as the software repository and OS distribution point, coordinates the dendritic
network, and collects crash metadata that users can opt out of — plus a crash-reporting system to
produce it, and the dendritic node fully working inside the OS.

**Decisions (user, 2026-10-01).**
- A **wallet owns a smart contract** that records the hash of every file pushed as an update, and the
  locators used to fetch it (magnet URIs, or the dendritic network's own sharing). **Ethereum
  mainnet**, not ZKsync (read as "the newest Ethereum": L1, where gas is now cheap and the dendritic
  proof-of-facilitation contracts already live). The contract is chain-agnostic; moving chains is a
  deployment change.
- Computers reach the server **through the dendritic network**, never by direct connection.
- **No I2P (user, 2026-10-01).** The dendritic network runs on **its own Tor/I2P-style routing**
  -- AXON, the overlay `deps/dendritic` is building (onion circuits, tunnel pools, guards, a blinded
  DHT) -- with **its own on-chain naming**: domains registered on Ethereum under namespaces anyone
  can propose (`.anonymous`, or whatever gets registered), resolving to AXON service keys.  i2pd is
  not part of the build, and there is no non-anonymous fallback transport.
- **syndichan.org plays no part.** The coordinator role the node used to get from it moves to the new
  server, which also pushes updates into the peer-to-peer network.
- The server is **a single VPS**.

This supersedes the "no centralized server" goal of `SYSTEM_UPDATE_ROADMAP.md`, but keeps what that
goal protected: the server is never trusted for *content*. It distributes and coordinates; authority
over what is a release belongs to the wallet alone.

---

## 1. Trust model

```
 release wallet (offline, the owner)            signs the manifest, owns the contract
        │  publish(version, manifestHash) ─────────────▶ ReleaseRegistry (Ethereum mainnet)
        │  signed manifest + artifacts                         ▲ read by clients (transparency,
        ▼                                                      │  anti-rollback, revocation)
 origin server (VPS) ── seeds into ──▶ dendritic network ──▶ every anonymOS node
   coordinator · crash intake           (AXON circuits; names on   verifies the WALLET signature
   an AXON service: origin.<ns>.axon     Ethereum)
```

- **The wallet is the only release authority.** A release is a manifest (§3) that the wallet signs
  (EIP-191 `personal_sign`) and records on-chain. Every OS image pins the wallet's address; a client
  installs nothing whose manifest the wallet did not sign, whatever delivered it.
- **The VPS holds no publishing key.** It stores and seeds what the wallet already signed and runs
  the coordinator. Taking it over lets an attacker withhold updates or go quiet — not ship one.
- **Anti-rollback is local and on-chain.** Each computer keeps a persisted monotonic counter
  (§6.3); the contract only moves a channel forward and can revoke a release.
- The OS image's own Ed25519 signature stays as a second, independent check — with a new **offline**
  key. The committed development key and the forgeable HMAC format (`imgupdate.d` format 1) are
  removed before the first real release (§8, P6).

## 2. ReleaseRegistry (contract)

Owner-gated, replacing the permissionless `contracts/UpdateRegistry.sol` for system releases.

| Call | Who | Effect |
|---|---|---|
| `publish(channel, version, manifestHash, files[])` | owner | channel moves to `version` (must increase); stores the header; emits one `File` event per artifact |
| `revoke(channel, version)` | owner | marks a release withdrawn; clients refuse it and fall back |
| `setLocator(channel, version, fileIndex, locator)` | owner | adds a mirror (another magnet / dendritic id) after the fact |
| `latest(channel)`, `release(channel, version)` | anyone (`eth_call`) | header: version, manifestHash, fileCount, timestamp, revoked |
| `transferOwnership(newOwner)` | owner, two-step | key rotation |

- Per file, the `File` event carries `sha256`, `size`, `kind` (os-image, catalog, package, …),
  `name`, and locators: a **magnet URI** and a **dendritic object id**. Events, not storage: a few
  hundred bytes per file at event prices, readable with `eth_getLogs`.
- Header in storage: what a client needs in one `eth_call` (latest version + manifest hash + revoked).
- Channels: `stable`, `testing`; `catalog` and `packages` publish independently of OS images so the
  software catalog can change without a new OS image.

## 3. Release manifest

Canonical JSON (sorted keys, no whitespace), its keccak256 recorded on-chain as `manifestHash`, the
wallet's signature over it shipped next to it.

```json
{"channel":"stable","created":1790816536,"files":[
  {"kind":"os-image","name":"anonymos-0.2.0.hosupd","sha256":"…","size":536870912,
   "locators":["dendritic:obj:…","magnet:?xt=urn:btih:…"]},
  {"kind":"catalog","name":"software-catalog.bin","sha256":"…","size":…, "locators":[…]}],
 "minVersion":1,"notes":"…","version":2}
```

`minVersion` refuses to update a system too old to take this image directly (slot size, §6.3).

## 4. The origin server (VPS)

One Go binary, **`hos-origin`**, beside a dendritic node in origin mode — a systemd unit each, one
deploy script.  Reachable only as an **AXON hidden service**: its self-certifying address
(`<key>.key.axon`, which needs no chain) and a registered name (`origin.<namespace>.axon`).  No
public HTTP; it listens on loopback and the node's rendezvous path carries requests to it.

| Part | Does |
|---|---|
| **Coordinator** | what nodes previously asked syndichan.org for: a signed bootstrap document (live peers), heartbeats, the peer list, network directives — re-implemented with the same signed formats so the node needs only an endpoint change. Signed by a coordinator Ed25519 key that the OS pins (rotatable by a wallet-signed directive). |
| **Release push** | watches ReleaseRegistry; when the wallet publishes, fetches the manifest + artifacts from the publisher's upload, verifies them against the chain, **seeds them into the dendritic network** (object manifests in the DHT), and announces `{channel, version, manifestHash}` to connected nodes. Nodes also learn it on their next heartbeat, so a missed push costs at most one interval. Optional BitTorrent seeding for the magnet locators. |
| **Repository** | the signed software catalog and a **mirror of every pinned `.apk`** the catalog names, so installs keep working when Alpine rotates versions, served through the dendritic network instead of plain HTTP to Alpine's CDN. |
| **Crash intake** | accepts scrubbed crash reports (§5) over the dendritic network: schema-checked, size-capped (unknown fields refused), rate-limited per circuit; stored as JSON lines and grouped by crash signature. No IP is ever seen -- reports arrive through AXON circuits. |

The publisher side is **`hos-release`**, a CLI on the owner's machine: packs the manifest from build
outputs, has the wallet sign it (`personal_sign`), sends the `publish` transaction, uploads the
artifacts to the origin. The wallet key never touches the VPS.

## 5. Crash reporting (opt-out)

**On the computer**
1. **The kernel records crashes as data**, not only log text: a structured record (time, OS version,
   program, fault kind — segfault vs exception vs abort vs signal — faulting address *relative to its
   binary* + build id, a symbolised backtrace, uptime) published as `/run/crash/<n>`, and for
   **kernel faults** written to a reserved object-store sector before the machine halts, so the next
   boot can report it. Today crashes are only RAM log lines lost on reset.
2. **`hos-crashd`** (System domain) reads them, **scrubs** them, queues them in `/home` (persisted),
   and sends them in batches with a random delay through the local dendritic node.
3. **Scrubbing (whitelist, not blacklist):** only the fields above. Never: IP/MAC addresses, Wi-Fi
   names, hostnames, user or domain names, file paths under `/home` or `/Domains`, the machine-id,
   window titles, raw log text. Each report gets a fresh random id; nothing links two reports from the
   same computer.
4. **Opt-out:** on by default on installed systems, as asked. A switch on the installer's review
   screen and in Settings → Privacy; turning it off deletes the queue. "Show me what is sent" lists the
   exact pending reports.
5. **Never sent:** from live media (it stores nothing), and from a hidden-OS boot (deniability:
   network behaviour must not differ from the decoy's).

**On the server:** grouped by signature (program + build id + top frames), counts per OS version,
first/last seen; reports kept 90 days.

## 6. The dendritic node inside the OS

Today it is a wallpaper only: nothing builds, launches or networks the node. What "fully functional"
needs, all found in the survey (2026-10-01):

### 6.1 Build
- `make syndichan-node` points at `dendritic/` — moved to `deps/dendritic/`; fix the path. Static,
  `CGO_ENABLED=0` (no cgo anywhere in the node).
- Endpoints hardcoded to syndichan.org (`config.go:22`, `heartbeat.go:37`, `p2p/node.go:111`,
  `p2p/recall.go:119`, `config.go:591`, `computeimage/loader.go:83`) become config, defaulting to
  the origin's AXON name.  The heartbeat -- deliberately sent DIRECT today so the coordinator sees
  the node's real address -- goes through AXON like everything else.

### 6.2 Kernel and runtime gaps that block it
| Gap | Fix |
|---|---|
| **No loopback** — TCP to 127.x is refused | loopback interface in the in-kernel stack, domain-isolated (done 2026-10-01): the S3/dashboard/operator ports, and the OS's own clients talking to the node |
| `bind` ignores the address — "loopback-only" listeners are reachable from outside | honour the bound address |
| **File `mmap` is a copy** — bbolt (the node's store) needs `MAP_SHARED` to see its own `pwrite`s | share the file's pages for shared file mappings (rtfs payloads are already page-scattered) |
| **Node data must persist** — identity keys + store; `/home` snapshots cap at 1 MiB | a disk-backed data volume for the node on installed systems, the `/vmstore` pattern |
| TCP limited to 32 connections system-wide, accept queue 8 | raised to 1024 / 64, buffers per connection (done 2026-10-01) |
| Go runtime: a small Go program runs (verified 2026-10-01); the node crashes in package init with `rip=0` | `sigaltstack` (a stub that never fills its result, which Go's signal setup reads), real signal delivery |
| AXON's link layer is QUIC over UDP | UDP that carries QUIC: `recvmsg`/`sendmsg` with control messages, socket buffer sizes, bound-address checks |
| The node's storage, coordinator and heartbeat paths are I2P-only (`internal/i2p`, `/garlic32` addresses) | moved onto AXON -- the dendritic roadmap's 2.9 + 2.13, gated on its session layer (5.2) |
| No CA bundle — the node's Go TLS needs one for any HTTPS it still does | stage Alpine's `ca-certificates-bundle` |

### 6.3 OS update path (kernel + client)
The `.hosupd` format and A/B fallback exist; nothing can install one yet.
- A kernel staging sink modelled on `/vmstore`: streamed write into the inactive slot, hash and
  signature checked as it streams (no 512 MiB buffer), header last, commit on `fsync`.
- Re-write the machine's `install.json` into the new slot (an update would otherwise erase the
  user's configuration), automatic `boot-ok` once the desktop is healthy, a persisted rollback
  counter the EFI arbiter preserves, a `SYSTEM_VERSION` bump in the release tooling.
- **`hos-update`** (System): learns of releases from the node (pushed) and the contract, fetches the
  artifacts through the dendritic network, verifies wallet signature → manifest hash → file hashes →
  Ed25519 image signature, stages, asks before rebooting. Settings → Updates shows it.
- The software catalog updates the same way, overriding the one in the image when newer.
- Not covered by A/B today: encrypted installs (FDE / hidden) — a separate phase.

## 7. "Push", precisely

Computers behind home routers cannot be reached, and over AXON nobody is addressed by IP anyway, so
"push" is: the wallet publishes → the origin sees the chain event, seeds the files and **announces to
every node connected to it**; any node that missed it learns at its next heartbeat (minutes) or from
the chain. Files flow peer to peer, so the VPS is not the bottleneck.

## 8. Phases

Each ends with a falsifiable exit.

- **P1 — The node runs in the OS.** §6.1 + §6.2: build, Go runtime, loopback, shared file mmap,
  persistent data volume, UDP for QUIC, connection limits; launched as a System service with logs
  and the dashboard. **Exit:** on a booted anonymOS the node starts, its AXON link layer handshakes
  with a node on another machine, and it survives a reboot with its identity.
- **P1b — AXON carries the network** (in `deps/dendritic`, its own roadmap): the session layer
  (5.2), storage and DHT over circuits (2.9, 2.10b), `internal/i2p` deleted (2.13), the registrar
  (1.10) and resolver wired, so a name like `origin.<ns>.axon` resolves and a request reaches a
  hidden service.  **Exit:** two anonymOS VMs fetch an object from each other through AXON circuits,
  and resolve a registered name.
- **P2 — Origin server.** `hos-origin` coordinator + origin node (an AXON hidden service) on a VPS, deploy script,
  the node's endpoints pointed at it. **Exit:** OS nodes bootstrap and heartbeat only via the origin.
- **P3 — ReleaseRegistry + `hos-release`.** Contract (Foundry tests), deploy from the owner wallet,
  manifest format, publisher CLI. **Exit:** a release published on a testnet is visible to `eth_call`
  and its files resolve from the origin.
- **P4 — Updates reach computers.** Kernel staging sink, `install.json` carry-over, boot-ok,
  rollback counter, `hos-update`, Settings → Updates; catalog + package mirror. **Exit:** VM A on
  version N installs N+1 pushed by the origin, reboots into it, and a deliberately broken N+2 rolls
  back by itself.
- **P5 — Crash reporting.** Kernel crash records (+ kernel-fault record across reboot),
  `hos-crashd`, scrubbing, opt-out UI, server intake + grouping. **Exit:** a crashing test program on
  a VM appears, scrubbed, in the server's report list; with opt-out on, nothing leaves the VM.
- **P6 — Hardening.** New offline release keys (drop the committed dev key and HMAC format), live
  media silent (it still looks up example.com and pool.ntp.org at boot today), hidden-OS behaviour
  review, threat review of the origin.

## 9. Open questions
- AXON is ~110 items from done upstream, and its **session layer (a byte stream over cells) is still
  research** (`deps/dendritic/roadmap/OUTSTANDING.md` 5.2).  Every request/response service here --
  coordinator, release fetch, crash upload -- waits on it.  There is deliberately no non-anonymous
  stand-in.
- Naming: AXON's design has one fixed root suffix (`.axon`) under which voted namespaces live
  (`updates.anonymous.axon`).  If `.anonymous` itself must be the last label, that is a change to
  §11.0 of the AXON spec (R15-R17), not just a registration.
- Encrypted (FDE / hidden) installs have no A/B slots: their update path is unresolved.
- Older installs have 320 MiB slots; images larger than that need `minVersion` gating or delta updates.
