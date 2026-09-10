# P12-1 — The minimum Ethereum evidence a watchtower needs

**Result: ~2.7 GB/year, append-only, and independent of how many channels are
held.** Not 750 GB. The DHT-backed data layer is the right architecture, and
this is the arithmetic that says so.

Everything below is derived from the code and the compiler. What has *not* been
verified against a live deployment is marked as such.

---

## 1. The entire chain dependency

Every chain access in the whole payment system, enumerated from the source:

```text
READS   ReadChannel(contract, id)  ->  eth_call channels(bytes32)
        ...and that is all. One call. Nothing else reads the chain.

WRITES  eth_sendRawTransaction     ->  challenge / checkpoint / close / claim
```

The watchtower does not need history, receipts for arbitrary contracts, account
balances, or anything else Ethereum stores. It needs the current value of one
mapping entry, and the ability to broadcast a transaction.

That is why a general-purpose node is the wrong shape for this: we would be
carrying 750 GB to answer a question about eleven storage slots.

## 2. Where those eleven slots are

From `solc --storage-layout` (the compiler, not a guess):

```text
slot 0   channels      mapping(bytes32 => Channel)
slot 1   lockResolved  mapping(bytes32 => mapping(bytes32 => bool))
```

`token` and `challengePeriod` are `immutable`, so they live in the contract code
and occupy no storage. `channels` is therefore at slot **0**, and for a channel
id `k`:

```text
base = keccak256(k ‖ uint256(0))

base+0   partyA          base+6   balanceB
base+1   partyB          base+7   nonce
base+2   depositA        base+8   challengeEnds
base+3   depositB        base+9   htlcRoot
base+4   status          base+10  lockedTotal
base+5   balanceA
```

Eleven slots, matching the eleven words `decodeChannelsReturn` already reads
from the ABI getter.

> **Verified against mainnet (P12-2).** The slot arithmetic was exercised with
> a real `eth_getProof` at block 25,737,778 — account proof verified against the
> header's `stateRoot`, storage proofs verified against the recovered
> `storageRoot`, and every recovered value compared against the provider's own
> claim. See `internal/ethproof`.

## 3. The trust anchor

To believe a storage value without trusting whoever served it:

```text
weak-subjectivity checkpoint      (a trusted starting point, once)
        │
        ▼
sync-committee updates            ~24 KB per ~27h period
        │
        ▼
verified beacon header
        │
        ▼
execution payload header
        ├── stateRoot      → verifies eth_getProof storage proofs
        ├── receiptsRoot   → verifies logs
        └── logsBloom      → tells us cheaply whether to bother
```

Nothing here trusts an RPC provider. The provider supplies data; the sync
committee's signatures are what make it believable. A provider that lies
produces proofs that do not verify against the state root, which is a detectable
failure rather than a silent one.

## 4. Two strategies, costed

**A — prove every channel's storage every sweep**

```text
full struct per channel   38 KB
10,000 channels, full     0.4 GB per 30-second sweep
status slot only          29 MB per sweep = 1.0 MB/s sustained
```

Scales with channel count. At the production envelope it is untenable.

**B — follow verified headers, bloom-filter, prove receipts on a hit**

```text
per block   ~1 KB     headers always; receipts only when the bloom matches
per day     7.1 MB
per year    2.73 GB
```

**Independent of channel count.** One `CloseStarted` log tells us *which*
channel closed, and only then do we fetch a storage proof for that one channel.

Plus the anchor: **7.6 MB/year** of sync-committee updates.

B wins by three orders of magnitude, and it wins *more* as channels grow.

## 5. This changes the detection design — and resolves a tension

P10 chose polling over events, on the grounds that "an event is a notification;
the mapping is the fact", and that a dropped websocket subscription is silent.

That reasoning was about *subscriptions*, and it does not apply here:

```text
subscription   a gap is invisible; you cannot tell you missed one
header chain   a gap is IMPOSSIBLE to miss — headers are linked, so a missing
               block is a broken chain, and you know exactly where you stopped
```

Following a verified header chain gives the completeness that polling was
protecting. It is strictly better than both: it cannot silently miss a close,
and it does not cost one `eth_call` per channel per sweep.

**Detection then becomes:**

```text
verified header  →  logsBloom says "no ChannelManagerV2 logs"  →  done, ~0 cost
                 →  bloom hit  →  fetch receipts, verify against receiptsRoot
                                →  CloseStarted for channel X
                                →  eth_getProof(X's slots) against stateRoot
                                →  challenge if we hold better
```

Detection latency becomes *block time plus verification*, not the sweep
interval — which would let the `detection` term in the challenge budget come
down, though that is a measurement (P12-8), not an assumption.

## 6. Why this belongs in the DHT

```text
sync-committee updates   append-only, immutable, ~8 MB/year
verified headers         append-only, immutable, ~2.7 GB/year
channel storage proofs   immutable, fetched on demand, kept as audit trail
```

All of it content-addressable and never rewritten — the same properties that
made the vault a good fit, at a scale the network can actually hold. Contrast
the Geth database: 750 GB of *mutable* random-access state, continuously
rewritten, which is the opposite of what this store is for.

The local index stays small: a map from block number to the DHT key of its
header, plus the current sync-committee state. Megabytes.

## 6b. P12-2 — measured, not assumed

Read-only against Ethereum mainnet, block 25,737,778:

| Quantity | Doc assumed | **Measured** | |
|---|---|---|---|
| account proof | 5120 B | **3879 B** (9 nodes) | doc overestimated |
| storage slot, populated | 3072 B | **2989 B** (7–9 nodes) | close |
| storage slot, absent | — | **160 B** (1–2 nodes) | absence terminates early |
| 11-slot channel | ~38 KB | **36.8 KB** | doc was accurate |
| verified read, end to end | — | **~210–290 ms** | account + 11 slots |
| header fetch | — | **41 ms** worst of 5 | |

**The Strategy A/B conclusion is unchanged.** At 10,000 channels a full-struct
sweep is 0.37 GB, and status-slot-only is 29 MB per sweep — 1.0 MB/s sustained.
Strategy B is untouched by any of this, because it does not read per-channel
storage in the common case.

Two honest caveats on the measurement:

- **The channel slots measured were all ABSENT.** ChannelManagerV2 is not
  deployed, so the V1 contract stood in and those slots have never been written.
  Proofs of absence terminate at the first divergent node and are ~19× smaller,
  so the populated figures come from WETH instead.
- **WETH is a conservative upper bound.** Its storage trie holds millions of
  entries; V2 with 10,000 channels holds ~110,000, so depth ≈ log₁₆(110,000)
  ≈ 4.2 against WETH's ≈ 5.6. Real V2 proofs will be *shallower* than measured.

What the verifier establishes, and it is the point of the phase: a hostile
provider can refuse, stall, or return something that fails to verify. It cannot
make `VerifyProof` return a value the state root does not commit to. Confirmed
against mainnet by flipping one bit in a real proof (rejected) and by verifying
a real proof against a fabricated root (rejected).

## 7. What this does NOT yet establish

This is P12-1 — the requirement, and the arithmetic that says it is feasible.
It is not proof that it works.

- **Proof sizes are estimates.** 5 KB account, 3 KB per storage slot, 8 KB
  receipts are typical mainnet figures, not measurements. P12-2 must measure them.
- **The slot arithmetic is unverified** against a real `eth_getProof`.
- **Sync-committee verification is not written.** It is the whole trust anchor,
  and until it exists this design trusts the provider exactly as much as a plain
  RPC call does.
- **Transaction broadcast is still trust-requiring.** We can verify what we
  *read*; we cannot verify that a provider actually *broadcast* what we sent —
  only that it later appeared in a verified block. That is a real asymmetry and
  it belongs in the challenge budget, not hidden here.
- **It may still fail.** If verifying the necessary evidence turns out to need
  more local state than expected, the answer is a light client or an external
  execution source, and this document should say so rather than be defended.

## 8. The order of work

```text
P12-2  acquisition + measure real proof sizes; verify the slot arithmetic
P12-3  DHT persistence for headers, committee updates, proofs
P12-4  local index
P12-5  sync-committee verification  ← the trust anchor; nothing is
                                      trust-minimised until this exists
P12-6  watchtower integration behind the existing ChainReader interface
P12-7  failure testing (shard loss, corruption, reorg, stale data, malice)
P12-8  re-measure the challenge budget on the real system
```

P12-6 is deliberately cheap: the watchtower already talks to a `ChainReader`
interface, so this layer slots in behind it without the watchtower learning
anything new.
