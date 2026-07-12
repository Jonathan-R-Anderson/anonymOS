# EpinAnonymOS zkSync Smart Contracts

Canonical home for **every** Solidity / ZKsync Era contract in the project. Contracts
used to live under `installer/contracts/`; they were consolidated here so there is one
place to find, compile, and deploy them.

All contracts are dependency-free (no OpenZeppelin, no framework) so they compile with a
stock `solc` and deploy on ZKsync Era's EVM path.

## Contracts

### `UpdateRegistry.sol` — decentralized update authenticity (SYSTEM_UPDATE_ROADMAP U4)

The release registry for system + software updates. **Trust model: the OS creator
deploys it once; everyone else just interacts with it.**

- **You (the creator) deploy it a single time.** The deployer is recorded as `creator`
  for provenance only — it grants **no** authority over anyone else's records. There is
  no admin, no owner-gated publishing, no pause switch.
- **Anyone publishes.** Any account calls `publish(channel, version, artifactRoot,
  manifestSigHash)` to register a release under its **own address-namespace**. Versions
  are monotonic per `(publisher, channel)`, so a publisher can only move its own channel
  forward (anti-rollback / anti-freeze). You publish the base OS under your address;
  third parties publish apps under theirs.
- **Anyone validates.** `getRelease(...)` / `validate(...)` are `view` calls — free via
  `eth_call`, no account or gas required. The base OS pins the creator's address and
  trusts only the creator's `stable` channel for system images; users opt into other
  publisher addresses for third-party software.

The record stores only hashes (artifact merkle root + signature hash); authenticity is
proven off-chain by the publisher's Ed25519 signature. The chain adds anti-rollback,
freshness, and public transparency — never trust of the RPC endpoint itself.

### `DhtBootstrapRegistry.sol` — DHT bootstrap seed list (SYSTEM_UPDATE_ROADMAP U6)

Creator-controlled registry of I2P destinations used to **bootstrap** into the
Kademlia-over-I2P DHT. **Trust model: only the creator controls it; anyone may register.**

- **You (the creator) own it** and are the sole admin — curate/`remove` spam or stale
  entries, `transferOwnership`. Unlike `UpdateRegistry`, the set here is governed.
- **Anyone registers.** A node calls `register(i2pDest)` to submit its **own** I2P
  destination and advertise itself as a willing bootstrap peer; `deactivate()` to leave.
- **Anyone reads** the active set (free `view` calls: `nodeCount`, `nodesPage`, `getNode`)
  to obtain I2P destinations to dial when first joining the DHT — the on-chain seed list,
  complementing the peer destinations pinned in the image.

### `BootIntegrityRegistry.sol` — boot-module attestation (existing)

Anchors an EpinAnonymOS boot-module hash manifest. Unlike `UpdateRegistry`, this one is
single-owner (`onlyOwner`): the wallet deploys it with the manifest Merkle root and
stores per-file hashes; the kernel (`src/kernel/d/core/boot_integrity.d`) compares the
staged manifest root against `systemRoot()` by JSON-RPC when `bootIntegrity=zksync`.
See `BootIntegrityRegistry.README.md` for the wallet flow.

> Three contracts, three trust models, on purpose:
> - **`UpdateRegistry`** — *permissionless*: any publisher serves any consumer under its
>   own sovereign per-publisher namespace; the creator holds no special power.
> - **`DhtBootstrapRegistry`** — *creator-governed, open registration*: anyone submits
>   their I2P destination, but the creator curates the seed set.
> - **`BootIntegrityRegistry`** — *single-owner*: attests one machine's own image under one
>   owner (the installer).

## Building

Compile every `*.sol` here to `build/contracts/<Name>.artifact.json` (ABI + bytecode):

```sh
scripts/compile-contracts.sh
```

Requires `solc`. ZKsync Era supports standard Solidity/EVM bytecode on the Era EVM path,
so no framework is needed. Deploy/interact from the integrated wallet staged at
`/system/web/zksync-wallet/` (or the Nuxt route when building `deps/zksync-wallet-vue`).
