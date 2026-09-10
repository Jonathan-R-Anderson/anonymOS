# P14.5 — measurements 2, 3, 4 and 6

**Every measurement passed. C+E remains viable. But three numbers in the design
document were measured the wrong way and are superseded here, one of them in the
proposal's favour and one against it.**

No production code changed. The harness is
`storage-client/internal/ethproof/p145_receipts_measure_test.go`, a `_test.go`
file, run with:

```sh
P145=1 CHAIN_PROBE=1 ETH_RPC_URL=<alchemy> BEACON_API_URL=https://lodestar-mainnet.chainsafe.io \
  go test ./internal/ethproof/ -run TestP145 -v
```

---

## Measurement 6 — EIP-2718 round-trip against the AUTHENTICATED root

The test the instruction asked for, in the shape it asked for. The reference root
does **not** come from whoever supplied the receipts:

```text
beacon (lodestar)                          execution RPC (alchemy)
      │                                              │
  finality_update                          eth_getBlockReceipts
      │ finalized_header.beacon                      │
      │ .body_root                                   ▼
      ▼                                       our decoder
  SSZ execution_branch @ index 25                    │
  VerifyBranch(payloadRoot, …)                       ▼
      │                                       our receipts trie
      ▼                                              │
  authenticated receiptsRoot  ◄───── MUST EQUAL ─────┘
```

**Result: exact.**

```text
block 25743471 (beacon slot 14980704), 441 receipts, 524 logs
types: legacy 16, EIP-1559 421, EIP-4844 blob 1, EIP-7702 setcode 3
rebuilt root b0e48159ec5c66a5dc73d228a75dabbd828abe324790bc7ec94f59667404ec8a
             == the root proven into the finalised beacon block
```

An independent second check on the same data: the **union of the 441 receipt
blooms equals the authenticated `logsBloom`**, which the SSZ payload root also
commits to. Two authenticated fields, both reproduced from the provider's bytes.

**Type coverage**, 12 consecutive blocks: `{legacy: 280, 1559: 4657, blob: 21,
setcode: 44}`. Every receipt type on current mainnet round-trips through the same
encoder — not just the common one.

### Negative tests — all ten caught

Because a rebuild that matched regardless would prove nothing:

| alteration | caught |
|---|---|
| status flipped | yes |
| cumulativeGasUsed off by one | yes |
| one bloom bit flipped | yes |
| transaction type changed 0x2 → 0x3 | yes |
| **receipt omitted** | yes |
| transaction index renumbered | yes |
| receipt duplicated over another index | yes |
| log address changed | yes |
| log topic changed | yes |
| log dropped from a receipt | yes |

And the one alteration that must **not** change the root — reversing the receipt
array while keeping the declared indices — did not. The key is the declared
`transactionIndex`, so a trie is a set, not a sequence.

**A harness bug found on the first run, worth recording.** The initial `clone()`
copied each log's `Topics` slice but shared the topic *bytes*, so the
"log topic changed" case mutated the baseline every later case was compared
against. The reorder check failed and looked like a real finding. There is now an
explicit assertion that the baseline is still intact after every mutation — a
test whose reference value moves is worse than no test.

---

## Measurement 2 — rebuild cost

20 consecutive blocks, 8,737 receipts (437/block), 9,803 logs, 4.1 MB of encoded
receipt bytes. Phases timed separately as instructed:

| phase | median | p95 | max |
|---|---:|---:|---:|
| decode JSON → typed | 2.33 ms | 3.88 ms | 3.89 ms |
| encode receipts (EIP-2718) | 2.03 ms | 3.63 ms | 4.81 ms |
| **trie construction** | 2.42 ms | 3.55 ms | 3.55 ms |
| root verification | 10.9 µs | 15.6 µs | 18.1 µs |
| **local total** | **6.79 ms** | — | — |

```text
CPU     1.343 s over 11.4 s wall = 12% of one core
memory  heap 2 MB; 143 MB allocated across 20 blocks (~7 MB/block, all garbage)
```

Sustained across 20 consecutive blocks with no drift. Root verification is a
32-byte compare and rounds to nothing — the cost is decode, encode and build, in
roughly equal thirds.

**At ~437 receipts/block the rebuild is 6.79 ms.** Against a 30-second sweep
covering ~2.5 blocks that is **17 ms of local work**, 0.06% of the interval.

---

## The three numbers that were measured the wrong way

### `getBlockReceipts` is 79 ms, not 1.111 s

Measurement 1 sampled with fresh connections. A watchtower is a long-running
process that keeps its connection pool warm, so the representative figure is the
pooled one:

| | design doc (cold) | measured (pooled) |
|---|---:|---:|
| `eth_getBlockReceipts` | 1.111 s | **79.4 ms** |

### …but so was the baseline, and that cuts the other way

The 196 ms per `eth_call` the whole P14 bottleneck rests on was sampled the same
cold way. Measured through the **same pooled client**, both sides:

| | median | p95 |
|---|---:|---:|
| `eth_call channels(id)` | **34.4 ms** | 42.3 ms |
| `eth_getBlockReceipts` | **79.4 ms** | 113.6 ms |

`getBlockReceipts` is **2.3× an `eth_call`**, not the 5.7× the design document
claims.

### So the corrected comparison, both sides measured identically

| | status quo (A) | proposed (C+E) |
|---|---:|---:|
| per 30 s sweep at 10,000 channels | **344 s** (5m44s) | **216 ms** |
| against the interval | 11× over | 0.7% of it |
| reduction | — | **1,592×** |

**The 706× figure is superseded by 1,592×.** It was comparing a cold sample
against a cold sample and happened to understate the gain.

**And the status quo is less broken than filed.** At 34.4 ms per pooled read the
boundary of the current implementation is **~872 channels per watchtower**, not
the ~153 in `p14-load-ramp.md`. Still 11× short of the 10,000 envelope — the
finding stands and the envelope still does not hold — but the recorded number was
pessimistic by 5.7×, and it is corrected here rather than left standing because
it happened to favour the conclusion.

---

## Measurement 3 — bloom false-positive rate

100 blocks, our contract `0xae70526931FF460894133201f6C8cA91bbA0E177`, tested
against the block's `logsBloom`:

```text
negative (block skipped outright)  82   82%
positive                           18   18%
  of which TRUE                     0
  of which FALSE                   18   100% of positives

average bloom saturation  1177/2048 bits (57%)
```

The contract is deployed on mainnet but currently idle, so every positive is a
false one. That makes this a clean measurement of the **cost floor**: even with
zero activity, 18% of blocks trigger a receipts fetch that finds nothing.

The measured rate matches theory closely — 0.575³ ≈ 19% for three hash positions
at 57% saturation — so this is a property of mainnet's bloom saturation, not an
artefact of the sample.

### This corrects the design document

The complexity table claims **"steady state, no activity → 0 reads"**. That is
wrong. The real figure is:

| | design doc claimed | measured |
|---|---|---|
| blocks needing no fetch | 100% | **82%** |
| blocks costing a wasted fetch | 0 | **18%** |

Still an enormous reduction, and the direction of the error is safe — a false
positive costs one wasted fetch, and a bloom has no false negatives, so a
*negative* remains authoritative and the skip remains sound. But "zero reads"
overstated it and the table should say 82%.

**The rule the instruction demanded is preserved in the harness:** a bloom hit is
never treated as a channel event. Every positive is confirmed against the
receipts before it counts, and absence from an RPC response is never treated as
evidence of absence on-chain — only an authenticated bloom *negative* is, and
that is a cryptographic property rather than a provider's say-so.

---

## Measurement 4 — catch-up after an outage

### First, a problem the design document did not see

The light-client API serves the **current** finality update and one update per
sync-committee period. It cannot hand back the execution payload header for an
arbitrary past block. So there is no way to ask "what was block N's receiptsRoot"
and get an authenticated answer.

Catching up therefore requires **walking `parentHash` backwards** from an
authenticated block, re-encoding each execution header and checking that it
hashes to what the block after it declared. That needs a third piece of code
(below) and it was measured rather than assumed:

```text
BACKWARDS HEADER WALK: 25 consecutive headers re-encoded and hashed,
each matching the parentHash of the block after it, anchored at the
AUTHENTICATED block hash 6c16e6916fe3.
```

It works, and the post-Prague 21-field header encoding is exact. This is also
**reorg-safe by construction**: each step is bound by *hash*, not by number, so a
walk cannot wander onto a competing branch.

### The costs

| | |
|---|---:|
| header, one at a time (network) | 43.1 ms |
| header, local RLP + keccak | **10.9 µs** |
| header, batched 100 per request | **3.94 ms** |
| receipts fetch + rebuild, on a bloom hit | 84 ms |

| outage | blocks | serial | batched |
|---|---:|---:|---:|
| 1 hour | 300 | 17 s | **6 s** |
| 24 hours | 7,200 | 7m 00s | **2m 18s** |
| 1 week | 50,400 | 48m 57s | **16m 04s** |

**The chain is serial to *verify* but not to *fetch*.** Verification costs 10.9 µs
per header — five thousand times less than the round trip — so batching removes
essentially all of it. A week-long outage costs 16 minutes of catch-up, and an
hour costs 6 seconds.

That makes the fail-closed option affordable. A watchtower that refuses to run
until caught up is not a watchtower that is down for hours.

---

## What implementing C+E actually requires

Not visible before the harness was written. P12 has an RLP **decoder** and an MPT
proof **verifier**; neither is usable here. Verifying a proof walks one path a
provider chose. Rebuilding a receipts trie constructs every node.

| component | exists? | why it is needed |
|---|---|---|
| RLP **encoder** | **no** — `rlp.go` decodes only | receipts, trie nodes, trie keys |
| MPT **builder** | **no** — `proof.go` verifies only | the receipts trie itself |
| execution **header RLP** encoder | **no** | the backwards walk for catch-up |
| receipts-trie key derivation | no | `RLP(transactionIndex)`, unhashed |
| bloom test | no | the 82% skip |

All five are small and all five are frozen encodings checkable against published
data — but they are new code on the trust path, and the header encoder carries
the same fork-dependency trap as `ExecutionPayloadHeader`: a wrong field *count*
hashes to something real-looking and matches nothing.

---

## An operational constraint the design did not account for

The first run of this harness was **refused by the provider** for exceeding
compute units per second. `eth_getBlockReceipts` is a heavyweight call, and a
fleet of watchtowers sweeping every 30 seconds would live against that limit
permanently — worse during catch-up, which is exactly when the watchtower most
needs to work.

Recorded rather than worked around: the harness throttles and counts its retries,
and no latency figure above includes a backoff. But rate limiting is a real
constraint on C, it does not exist for A at the same intensity, and it belongs in
the design before implementation rather than after the first outage.

---

## Reorg handling

Everything above was measured against **finalised** blocks, so the depth-1 reorgs
the P12-8 observer is seeing cannot reach it. Two properties preserve that, and
both must survive into any implementation:

1. **Only finalised blocks are processed.** Below finality nothing is acted on.
2. **Observations are keyed by block *hash*, not number.** The backwards walk
   already works this way. A record of "block N had these channel events" that
   names only a height is exactly the thing that survives a reorg it should not
   have survived.

---

## Classification

| measurement | value | class |
|---|---|---|
| authenticated round-trip exactness | exact | **MEASURED** |
| receipt types round-tripping | 0x0, 0x2, 0x3, 0x4 | **MEASURED** |
| negative cases caught | 10/10 | **MEASURED** |
| decode / encode / build / verify | 2.33 / 2.03 / 2.42 ms / 10.9 µs | **MEASURED** |
| local rebuild per block | 6.79 ms | **MEASURED** |
| CPU, sustained | 12% of one core | **MEASURED** |
| memory | 2 MB heap, ~7 MB/block garbage | **MEASURED** |
| `eth_call`, pooled | 34.4 ms | **MEASURED** |
| `eth_getBlockReceipts`, pooled | 79.4 ms | **MEASURED** |
| bloom negative rate | 82% | **MEASURED** |
| bloom false-positive rate | 18% of blocks, 100% of positives | **MEASURED** |
| header walk, per header | 43.1 ms serial / 3.94 ms batched | **MEASURED** |
| local header verification | 10.9 µs | **MEASURED** |
| status-quo sweep at 10,000 | 344 s | DERIVED (34.4 ms × 10,000) |
| proposed sweep at 10,000 | 216 ms | DERIVED |
| status-quo boundary | ~872 channels | DERIVED |
| catch-up 1 h / 24 h / 1 week | 6 s / 2m18s / 16m04s | DERIVED (batched, measured per-block) |
| bloom rate for an ACTIVE contract | — | **NOT MEASURED** (ours is idle) |
| worst case, 10,000 channels changing at once | — | **NOT MEASURED** |
| behaviour under a real provider rate limit | — | **NOT MEASURED** (throttled around it) |

---

## Verdict

**C+E remains viable.** Every property the instruction required was demonstrated
against real mainnet data, and nothing was adjusted to make a measurement pass.

The design document needs four corrections before implementation:

1. `getBlockReceipts` is 79 ms, not 1.111 s — and the baseline is 34.4 ms, not
   196 ms. The gain is **1,592×**, not 706×.
2. The status-quo boundary is **~872 channels**, not ~153. The envelope still
   fails, by 11× rather than 65×.
3. Steady state is **82% zero-fetch**, not 100%. An idle contract still costs a
   wasted fetch on 18% of blocks.
4. Catch-up needs a **backwards header walk** and a third encoder. It is
   affordable — 16 minutes for a week — but it was not in the design.

Two things remain unmeasured and should not be waved through: the bloom rate for
an *active* contract, and behaviour when the provider's rate limit is actually
hit rather than throttled around.
