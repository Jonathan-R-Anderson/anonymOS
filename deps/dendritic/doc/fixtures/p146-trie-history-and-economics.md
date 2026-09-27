# P14.6c — trie-node history requirement, and the A-vs-B economics

**Headline: the trie-history measurement is not the blocker it looked like, and
the economics have changed the recommendation decisively.**

Two findings, both from our own code and Alchemy's published numbers:

1. **`--history.trienode` is not required for normal operation.** Our proof path
   never asks for a historical proof. It is needed only to tolerate a finality
   stall longer than ~25 minutes.
2. **We are on Alchemy's FREE tier.** The rate limit that costs 3h 24m is a
   500 CU/s cap, and `eth_getBlockReceipts` costs **500 throughput CU** — so we
   are limited to **exactly one receipts call per second**. Pay-As-You-Go raises
   that to 10,000 CU/s (20×) and would cost us **~$3/month** at our measured
   volume.

Nothing purchased, nothing deployed, no production configuration changed.

---

## 1. What `--history.trienode=N` value do we actually need?

### The finding that moots most of the question

Traced through our own code rather than assumed:

```text
ACQUISITION  ethproof.VerifiedRead(…, block)
               c.Header(ctx, block)          <- "latest", or a fresh height
               c.GetProof(…, header.Number)  <- pinned to THAT header
                     │
                     ▼  sealed, stored
                   DHT evidence
                     │
WATCHTOWER   EvidenceChainReader.ReadChannel
               r.Index.Lookup(…)             <- NO RPC. Ever.
```

`evidencereader.go` says it outright: *"No path here reaches an RPC."* The
watchtower reads **stored** evidence. `eth_getProof` is called only at
**acquisition** time, and `VerifiedRead` pins the proof to the header it just
fetched — a *fresh* block, not an old one.

**So there is no code path that requests a historical proof.** The 128-block
default window covers "prove against a block at most 128 blocks old", and
acquisition always uses a block far younger than that.

### Where it still matters

One case survives: **acquiring new evidence while finality is stalled.**

During a stall the finalised block stops advancing while the head moves on. After
~128 blocks (~25 minutes) of stall, a full node can no longer serve a proof at
that last-finalised block. If a channel needs evidence it does not already have,
acquisition fails and the watchtower fails closed.

| tolerance target | required N | rationale |
|---|---:|---|
| normal operation | **0 — not needed** | acquisition always uses a fresh block |
| 25 min stall | 128 (default) | the free window |
| **4 hours** | **1,200** | matches the `Outage` term in `MainnetChallengeBudget` |
| 24 hours | 7,200 | comfortable margin |

**Recommended N = 7,200** if a node is built — sized to the budget term with
margin, not to the whole chain.

## 2. Actual disk consumption at that setting

**NOT MEASURED, and I could not measure it.** This needs stating plainly because
it is a circular dependency:

> Measuring mainnet trie-history growth requires a **synced mainnet node**, which
> requires the ~1.2 TB of NVMe this measurement exists to justify. We have 64 GB
> free on the workstation and 27 GB on prod. There is no configuration of what we
> own that can produce this number.

What I *can* do is bound it, and the bound is decisive:

| | |
|---|---|
| published: trie history for the **entire chain** | ~4.5 TB (6.5 TB total vs 2 TB flat-state archive) |
| chain length | ~25.75M blocks |
| implied average | ~175 KB/block |
| **N = 7,200 (24h)** | **~1.3 GB** |
| same, at 10× the historical average | ~13 GB |
| as a fraction of a 2 TB disk | **0.05% – 0.65%** |

The 4.5 TB figure everyone quotes is for **the whole chain**. We need 0.028% of
it. Modern blocks are heavier than the all-history average, so treat 1.3 GB as a
floor — but even an order of magnitude out, this is **noise against the 1.2 TB
the node needs anyway.**

**`--history.trienode` is not a reason to buy a bigger disk.** The disk is sized
by the node itself, not by our proof window.

## 3. Growth rate

**NOT MEASURED** for trie history specifically. The node's overall growth is
published at **+14 GB/week**, and trie history at N=7,200 is a *rolling window* —
it does not grow, it stays at its steady-state size once N blocks are retained.
That is a meaningful property: the setting has a bounded cost, not a growing one.

## 4. Do `eth_getProof` and `eth_getStorageAt` stay available across the window?

**Measured, on five independent chains** (P14.6b): with the default settings,
both fail at **exactly the same 128-block boundary**:

```text
128 blocks back : ok
129 blocks back : "historical state <hash> is not available"
```

Notably `eth_getStorageAt` failed there too, even though `--history.state`
defaults to 90,000 blocks. **That default did not take effect in the tested
configuration**, and whether it does on a snap-synced mainnet node is
**NOT MEASURED**. Do not rely on the 90,000 figure without confirming it.

## 5. What happens when finality falls behind the retained trie history?

**Measured.** The node returns `historical state <hash> is not available`, the
acquisition layer gets an error, no evidence is produced, and the watchtower
returns `ErrNoVerifiedEvidence` — *"we cannot see"*, never *"there is nothing
there"*. It fails closed, which is correct.

The risk is not correctness, it is **correlation**: a finality stall is exactly
when a watchtower is most needed, and it is the condition that breaks this. That
is the entire argument for setting N at all.

## 6. Can the database go on a dedicated NVMe without interfering with the website?

**Yes, trivially — because they would not be the same machine.**

| | |
|---|---|
| website / prod | `51.79.71.153` — 8 cores, 22 GB RAM, **27 GB free** |
| a mainnet node | needs ~1.2 TB |

Prod cannot host a node at all, so there is no interference question to answer
there. Any node would be separate hardware, and separate hardware cannot contend
for prod's disk.

The one caveat if that ever changed: sync is the I/O-heavy phase (sustained
writes for hours to days), not steady-state operation. Measured on the devnet,
steady-state write volume was ~140 KB/s.

## 7. Minimum practical configuration

| | minimum | rationale |
|---|---|---|
| disk | **2 TB NVMe** | ~1.2 TB node + 14 GB/week; **not** driven by trie history |
| RAM | **16 GB** (32 comfortable) | published; our query load needs almost none |
| CPU | **4 cores** (8 comfortable) | serving measured at **0.8% median of one core** |
| `--history.trienode` | **7,200** | ~1.3 GB derived; sized to the 4h outage budget |
| `--history.chain` | `postmerge` | we need one week; PHE keeps ~5 months minimum |
| network | 25 Mbps, no cap | published |

SATA is excluded: ~3-day sync, and our only spare volume is NTFS-over-FUSE.

---

# The economic question: A vs B

## We are on the free tier, and that is the whole story

| | Free (current) | Pay As You Go |
|---|---|---|
| throughput | **500 CU/s** | **10,000 CU/s** (20×) |
| monthly allowance | 30M CU | usage-based |
| price | $0 | $0.45/M CU (first 300M) |

`eth_getBlockReceipts` costs **20 CU billed but 500 CU of throughput**. On 500 CU/s
that is **exactly one call per second** — which is precisely the ceiling the
P14.5 measurement ran into, and why catch-up is 90% backoff.

## What we would actually pay

Measured workload, at published CU weights:

```text
STEADY STATE (30s sweeps, 2.5 blocks each, 20% bloom-hit rate)
  headers   7,200 blocks/day x 20 CU        =   144,000 CU/day
  receipts  1,440 fetches/day x 20 CU       =    28,800 CU/day
                                              ------------------
                                                ~173,000 CU/day
                                                ~5.2M CU/month
ONE-WEEK CATCH-UP
  50,400 headers x 20 CU                    = 1,008,000 CU
  10,080 receipt fetches x 20 CU            =   201,600 CU
                                              ------------------
                                                ~1.2M CU  =  $0.54
```

**~5.2M CU/month is inside the free tier's 30M allowance.** Our problem was never
volume — it is *purely* throughput. On PAYG the same workload costs **~$2.34/month**,
plus about **54 cents per one-week catch-up**.

## The comparison, with measured numbers on both sides

| | **A — pay for throughput** | **B — own the node** |
|---|---|---|
| 1-week catch-up | **~20 min** | **~8 min** |
| capex | £0 | 2 TB NVMe machine |
| running cost | **~$3/month** | power, disk replacement, sync time |
| maintenance | none | client upgrades, resync on corruption, monitoring |
| recovery from data loss | n/a | **days** to resync |
| provider dependency | yes | no |
| rate limits | gone at 10,000 CU/s | none |
| verification boundary | **identical** | **identical** |

Both sit behind the same gate — demonstrated on both legs in P14.6b, where local
and Alchemy data went through the identical `AuthenticateReceipts` path and a
tampered local receipt was still refused. **This is an operational and economic
choice, not a security one.**

## Recommendation

**Take A first.** It costs about three dollars a month, needs no hardware, no
sync, and no new failure mode, and it closes ~92% of the gap: 3h 24m → ~20 min
against the local node's ~8 min. The remaining 12 minutes are not worth a machine
that takes days to rebuild if its disk dies.

Two things that would change this:

- **Provider independence becomes a requirement**, not a preference. That is a
  legitimate reason to choose B, and it is the *only* argument B wins outright.
  It should be argued on those terms rather than on catch-up speed.
- **PAYG has no spending cap.** A runaway loop bills unboundedly. Set an alert
  before switching.

**Consequence for the outstanding measurement:** the trie-history disk number
only matters under B. Measuring it costs either the hardware in question or a
temporary cloud instance with 2 TB NVMe (roughly $50–150 for a week). **Do not
spend that until A-vs-B is decided** — under A it is never needed, and under B
the derived bound (~1.3 GB, 0.05% of the disk) already shows it is not a sizing
constraint.

### Classification

| finding | class |
|---|---|
| acquisition proves against a fresh block; watchtower reads stored evidence | **MEASURED** (our code) |
| proof/storage window = 128 blocks, both methods | **MEASURED** (5 chains) |
| behaviour past the window: fail-closed refusal | **MEASURED** |
| free tier = 500 CU/s; `eth_getBlockReceipts` = 500 throughput CU | published (Alchemy) |
| our steady-state volume ≈ 5.2M CU/month | **DERIVED** from measured sweep behaviour |
| PAYG cost ≈ $3/month, $0.54 per week-long catch-up | **DERIVED** from published weights |
| trie history at N=7,200 ≈ 1.3 GB | **DERIVED** from a published whole-chain total |
| **actual mainnet trie-history disk at N=7,200** | **NOT MEASURED** — needs a synced node |
| whether `--history.state=90000` works on synced mainnet | **NOT MEASURED** — it did not in test |
| mainnet sync time on real hardware | **NOT MEASURED** |
