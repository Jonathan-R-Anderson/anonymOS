# P14.6 — local execution node: measured performance validation

**Answer to the acceptance question: YES, and the conclusion is robust.** A local
node takes one-week catch-up from a measured **3h 24m to ~8 minutes**, entirely
behind the existing verification boundary, with no local-node trust path.

**But the reason is not the one the design assumed**, and that changes the
recommendation: local `eth_getBlockReceipts` is only **2.9×** faster than
Alchemy, not the order of magnitude projected. ~90% of the current catch-up cost
is rate-limit backoff, so the win comes from *removing throttling*. **A higher
Alchemy tier removes the same 90% at no hardware cost** and should be priced
before anything is bought.

Nothing was purchased, deployed, or configured in production. No production code
changed — the only addition is `internal/ethproof/p146_localnode_test.go`. The
watchtower, `challengePeriod`, the evidence rules and the deployment gate are
untouched.

## The setup

A disposable geth **v1.17.5** devnet in Docker on loopback, datadir in scratch,
deleted afterwards. Loaded with a log-emitting contract to mainnet-like density:
**209 consecutive full blocks, 470 receipts each, 3.0 logs per receipt,
1,324 KB/block of JSON.**

For comparability the local blocks are **heavier** than the mainnet sample they
are measured against (1,324 KB vs 919 KB per block, and 3.0 logs/receipt vs 1.2).
The local node is doing ~44% more work per block and is still faster, so the
comparison runs against the conclusion rather than for it.

## Measurement 1 — `eth_getBlockReceipts`, 200 consecutive blocks

| | local (loopback) | Alchemy (pooled, same session) |
|---|---:|---:|
| median | **28.42 ms** | **81.57 ms** |
| p95 | 37.34 ms | 97.50 ms |
| max | 44.92 ms | 121.82 ms |
| min | 23.99 ms | — |
| receipts/block | 470 (min 470, max 470) | 518 |
| payload | 1,324 KB/block | 919 KB/block |

**Speedup on the fetch: 2.9×.** Not 10×, not 40×.

That number is the finding. Serving ~470 receipts costs ~28 ms even from a
database entirely in page cache, because a megabyte of JSON has to be serialised
regardless of where it comes from. Latency is dominated by payload, not distance.

## Measurement 2 — the complete C+E pipeline, not just the RPC

| stage | median | p95 |
|---|---:|---:|
| `eth_getBlockReceipts` | 28.42 ms | 37.34 ms |
| decode JSON → typed | 8.65 ms | 9.95 ms |
| encode receipts (EIP-2718) | 1.17 ms | 1.37 ms |
| trie construction | 2.26 ms | 2.60 ms |
| **authenticate (the gate)** | **2.17 ms** | 2.47 ms |
| **full pipeline per block** | **39.25 ms** | — |

`encode` and `build` are diagnostics *inside* `authenticate`, which calls
`ReceiptsRoot` itself — adding all five would count the trie construction three
times. The pipeline figure counts each stage once.

**Headers**, the other half of catch-up: local **0.46–1.56 ms** per header
depending on batch size, against Alchemy's 3.94 ms batched / 43 ms unbatched.
Batching barely helps locally — there is no round trip to amortise.

## Measurement 3 — real `ChainFollower.Advance()`, both extremes

The shipped follower, with bloom filtering, batched header walking, parentHash
verification, receipt authentication and checkpoint persistence:

| | per block | 1 hour | 24 hours | 1 week |
|---|---:|---:|---:|---:|
| **worst case** — contract in ~every block (3% skipped) | 41.44 ms | 12 s | 4m 58s | **34m 49s** |
| **best case** — contract absent (100% skipped) | 1.68 ms | 1 s | 12 s | **1m 25s** |
| *mainnet-realistic* (80% skipped, measured in P14.5) | ~9.6 ms | ~3 s | ~69 s | **~8m 5s** |
| Alchemy, measured, **with** rate limits | 243 ms | 1m 13s | 29m 11s | **3h 24m** |

**~25× on the realistic case.** Zero rate-limit events across every local run.

### The conclusion survives the devnet's biggest weakness

The devnet DB fits in page cache, so 28 ms is a **lower bound**, not a forecast
for a 1.2 TB mainnet dataset. So take the pessimistic case: assume a real local
node is *exactly as slow as Alchemy* (81.6 ms). Catch-up becomes ~19.9 ms/block
→ **1 week ≈ 17 minutes**, still **12× better** than 3h 24m.

The improvement does not depend on the local node being fast. It depends on the
local node not refusing.

## Measurement 4 — the same gate, no local-node exemption

Every step is the shipped P14.5 implementation:

- `ExecutionForkAt(1337)` **refuses** — unrecorded chains do not get a layout
  inferred for them. The Prague layout is supplied explicitly by the test.
- the node's header was re-encoded and **hashed to the value it claimed**;
- the parentHash link verified through `BlockFromParentLink` — the catch-up path;
- **470 receipts rebuilt to the receiptsRoot bound into that verified header**;
- a **tampered local receipt was still refused**.

There is no branch, flag or shortcut for local data anywhere in the path. The
node is an untrusted supplier exactly as Alchemy is.

## Measurement 5 — the proof window, and the finality-distance requirement

Reproduced identically on **five independent chains**:

```text
  0 … 128 blocks back : ok
        129 blocks back : REFUSED
        "historical state <hash> is not available"
```

**The window is exactly 128 blocks.** Our requirement, from
[client.go:191](../../storage-client/internal/ethproof/client.go#L191), is a
proof at the **authenticated finalised block** — 64–96 blocks behind head on
mainnet.

| | |
|---|---|
| normal finality (64–96 back) | **fits**, 33 blocks (~6.6 min) of margin |
| finality **stall** | **does not fit** — the distance is unbounded |

### A correction to the P14.6 investigation

That document blamed a generic "128-block state window". geth v1.17.5 has **two
independent knobs**, and the distinction matters:

| flag | default | retains |
|---|---|---|
| `--history.state` | **90,000 blocks** | flat state — `eth_getStorageAt` |
| `--history.trienode` | **-1 (disabled)** | Merkle nodes — `eth_getProof` |

State history does **not** give you proofs. And measured here,
`eth_getStorageAt` failed at the *same* 128-block boundary, so the advertised
90,000 did not take effect in this configuration either — **confirm both on a
real mainnet node before relying on either number.**

The fix for proofs is `--history.trienode=N`, off by default. Sizing N for a
24-hour finality stall means ~7,200 blocks of trie history. **Its disk cost is
NOT MEASURED** and is the single biggest open question for hardware sizing.

## Measurement 6 — CPU, RAM, disk I/O, database size

Sampled every 6 s across the 15.7-minute load (16-core host):

| | |
|---|---|
| CPU | median **0.8%**, p95 66.7%, peak **113.9%** of one core |
| RSS | median **257 MB**, peak **468 MB** |
| DB growth | 1,409 → 2,554 MB (**+1,145 MB** over 209 full blocks) |
| block I/O | 24.6 kB read / **132 MB written** |

**None of this extrapolates to mainnet** and it should not be used to size
hardware. A devnet has no peer set, no state trie of 300M accounts, and its
DB fits in RAM. What it does establish is that **serving our query load is
trivial** — CPU sat at 0.8% median. Sizing is dominated by *running a mainnet
node at all*, not by answering the watchtower.

## What this does and does not answer

| | class |
|---|---|
| local `eth_getBlockReceipts` median/p95/max, 200 consecutive blocks | **MEASURED** |
| receipts per block, logs per receipt, payload size | **MEASURED** |
| full C+E pipeline, stage by stage | **MEASURED** |
| real `ChainFollower` catch-up, both bloom extremes | **MEASURED** |
| same gate passes; tampering still refused | **MEASURED** |
| proof window = 128 blocks (5 independent chains) | **MEASURED** |
| CPU/RAM/DB/IO on a devnet | **MEASURED**, not extrapolatable |
| mainnet-realistic catch-up ≈ 8 min | **DERIVED** (measured extremes × measured 80% skip rate) |
| local latency on a **1.2 TB** mainnet dataset | **NOT MEASURED** — devnet is page-cached |
| `--history.trienode=N` disk cost | **NOT MEASURED** — the key sizing unknown |
| mainnet sync time on real hardware | **NOT MEASURED** |
| whether `--history.state=90000` works on a synced mainnet node | **NOT MEASURED** — it did not here |

## Recommendation

**Do not buy hardware yet. Price the Alchemy tier upgrade first.**

The measured decomposition makes this the cheaper experiment: ~90% of the current
3h 24m is backoff, so removing the rate limit alone gets catch-up to **~20
minutes** (24.5 ms/block of measured actual work). A local node then improves
that to ~8 minutes — a further 2.5×, for a machine, a sync, and a new operational
dependency.

If a local node still looks right after that, the minimum practical configuration
derived from these measurements:

| | minimum | why |
|---|---|---|
| disk | **2 TB NVMe** | ~1.2 TB full node + 14 GB/week; SATA syncs in ~3 days and our only spare volume is NTFS-over-FUSE |
| RAM | **16 GB** (32 GB comfortable) | published requirement; our query load needs almost none |
| CPU | **4 cores** (8 comfortable) | serving measured at 0.8% median of one core |
| state retention | **`--history.trienode=N`, N ≥ 7,200** | the 128-block default fails during a finality stall — cost unmeasured |
| network | 25 Mbps, no cap | published requirement |

And regardless of which path is taken: **keep Alchemy configured as a second
untrusted supplier.** Both sources go through the identical gate — demonstrated
above on both legs — so choosing between them changes nothing about what is
believed. That is not an RPC fallback; the rule forbids falling back to
*unverified* data, which nothing here does.

**Before committing to hardware, measure `--history.trienode` disk cost on a real
mainnet node.** It is the one number that could change the answer, and it is the
one a devnet cannot produce.
