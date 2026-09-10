# Proof of Facilitation

A Ethereum-settled service ledger that pays a utility token — **AxonToken** (`AXON`),
called **credits** everywhere a person reads it
— for independently verified infrastructure contribution to the Syndichan network
(running the DHT, gateways, storage, load balancing, or Docker workloads).

Full design + phased plan: [`../roadmap/proof-of-facilitation.md`](../roadmap/proof-of-facilitation.md).

This project lives inside the maniwani folder as its **own git repo** (gitignored
by maniwani), alongside `storage-client/`.

## Architecture (decided)

- **Website runs the chain-access layer** so node operators run a *lightweight*
  client: a **pruned Ethereum mainnet External Node** (self-hosted RPC) + a **paymaster**
  (gas sponsorship, so nodes need no ETH) + a **relayer** (accepts signed intents,
  submits txs) + an **event indexer**. The EN's DB stays on fast local disk
  (Postgres/RocksDB can't live on the DHT); periodic **DB snapshots are pushed to
  the DHT** as the durable + bootstrap copy, so the server keeps only a small,
  prunable live working set.
- **The lightweight client lives in `storage-client`** (`internal/facilitation`):
  the node holds one secp256k1 wallet key, signs a registration/claim digest, and
  POSTs it to the website gateway. No chain sync, no ETH, no Ethereum tx encoding.
- **Settlement, identity, staking, disputes, rewards** are on Ethereum; the
  receipt-heavy operational data stays in the DHT.

```
storage-client (lightweight node)                Website chain gateway
  internal/facilitation:                           - pruned Ethereum External Node (RPC)
    wallet key + sign REGISTER digest   ──POST──▶   - paymaster (sponsors gas)
    (no ETH, no chain)                              - relayer -> registerWithSig(...)
                                                    - indexer + EN snapshot -> DHT
                                                              │
                                                              ▼  Ethereum mainnet
                                          AxonToken · NodeRegistry · (Stake/Epoch/Reward/Dispute…)
```

## Status

### Done + validated (Phase 0)
- **`contracts/Treasury.sol`** — the sole minter. Minting is permissionless
  but bounded (`fundEpoch` releases exactly one settled epoch's rewards, capped
  by the per-epoch budget and an immutable supply cap); spending is owner-only
  but cannot mint (`release` moves an already-minted allocation). That split is
  what makes the cap mean anything.
- **`contracts/AxonToken.sol`** — ERC-20 `AXON`; only the Treasury may
  mint/burn (nodes never mint; they earn a share of a fixed epoch budget).
- **`contracts/NodeRegistry.sol`** — wallet↔p2p-key binding, capabilities bitmap,
  privacy-preserving endpoint commitment, key rotation, duplicate-key prevention,
  and **`registerWithSig`** (meta-tx: a lightweight node signs; the relayer submits;
  the owner is recovered on-chain from the signature).
- **`test/`** — 3 passing tests (EVM): treasury-only mint/burn; register /
  uniqueness / capabilities / ownership / rotation; relayer-signature registration.
- **`storage-client/internal/facilitation`** — the Go lightweight client: secp256k1
  wallet (load/create), Ethereum-style address, `nodeId = keccak256(ed25519 p2p
  key)`, endpoint commitment, the registration digest (byte-identical to the
  contract's `abi.encode`), an `ecrecover`-compatible signature, and the gateway
  HTTP client. Builds + tests pass (sign→recover→address is self-consistent).
- **`deploy/00_phase0.ts`** — deploys AxonToken + NodeRegistry to a Ethereum network.

### Phase 1 contracts — done + tested (optimistic service ledger)
- **`StakeVault`** — provider/witness/aggregator bonds in AXON, delayed
  withdrawals, slashable by an authorized slasher (the DisputeManager).
- **`EpochManager`** — the aggregator submits receipt/reward/state roots + epoch
  randomness + budget; an optimistic challenge window; freeze/invalidate on
  dispute; anyone finalizes after the window to unlock claims.
- **`RewardDistributor`** — Merkle-proof claims against a finalized epoch's
  rewardRoot, once per (epoch, nodeId), paid from a Treasury-funded balance.
- **`DisputeManager`** — bonded fraud challenges freeze an epoch; arbiter resolve
  upholds (invalidate + slash aggregator → challenger) or rejects (lift + forfeit).
- **`ServicePolicyRegistry`** — versioned epoch budget / per-service split /
  witness thresholds / per-node cap / formula hash; activates at epoch boundaries.
- `test/Phase1.test.ts` — 4 passing tests covering the whole loop.

### Next (Phase 0c + rest of Phase 1)
- **Website chain gateway**: `/pof/register` relayer endpoint (submits
  `registerWithSig` via the paymaster to the EN), the Ethereum **paymaster** contract
  (`IPaymaster`, allowlisted methods + per-node rate limits), and the event indexer.
- **EN + snapshots**: stand up the pruned External Node; the snapshot→DHT pipeline.
- **Node + aggregator (Go)**: `challenge_agent`, `receipt_store`, the DHT/gateway/
  storage proofs, and the aggregator that scores receipts → Merkle roots →
  `EpochManager.submitEpoch`.

## Go-live checklist (gates, not code)
1. A **funded deployer key** on Ethereum Sepolia → `DEPLOYER_PRIVATE_KEY` in `.env`;
   `npm run deploy:sepolia`.
2. Pin the **zksolc** version in `hardhat.config.ts` (currently `1.5.7`) to one
   available for download; the EVM tests already validate contract logic.
3. Provision the **pruned External Node** host (disk for the live working set) and
   the **paymaster** funding.

## Develop
```
npm install        # Hardhat + Ethereum toolchain + OpenZeppelin
npm test           # EVM unit tests (fast)
npm run deploy:sepolia   # once DEPLOYER_PRIVATE_KEY is set + funded
# Go lightweight client:
cd ../storage-client && go test ./internal/facilitation/...
```
