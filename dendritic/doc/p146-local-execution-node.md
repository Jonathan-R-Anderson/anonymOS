# P14.6 — can a local execution node remove the rate-limit dependency?

> **SUPERSEDED IN PART by measurement** — see
> `doc/fixtures/p146-local-node-validation.md`. Three corrections: local
> `eth_getBlockReceipts` is **2.9×** Alchemy, not the order of magnitude
> projected here; the "128-block state window" is really **two** knobs
> (`--history.state` = 90,000 for flat state, `--history.trienode` = **off** for
> the proofs we actually need); and the recommendation changes — **price an
> Alchemy tier upgrade first**, because ~90% of the catch-up cost is rate-limit
> backoff rather than latency. The 128-block proof window and the fail-during-a-
> finality-stall risk were both confirmed exactly.

**Investigation only. Nothing deployed, nothing configured, no code changed. The
watchtower, `challengePeriod`, the evidence rules and the deployment gate are
untouched.**

The question comes from a measured problem: P14.5 catch-up runs at 243 ms/block,
of which roughly **90% is waiting on the provider's rate limit**. A week-long
outage costs 3h24m against a 4-hour outage budget. The proposal is to keep the
beacon light client as the source of canonicality and replace Alchemy as the
supplier of untrusted execution data.

**Answer up front: architecturally yes, and it is the right shape. But it cannot
run on any machine we currently have, and a plain full node would break the
*existing* proof path in the one situation where it matters most.**

---

## The architecture is already what is being asked for

Nothing needs redesigning to accommodate a local node:

```text
beacon light client (independent checkpoint, sync-committee verified)
        │
        └── AUTHENTICATED: stateRoot, receiptsRoot, logsBloom, blockHash, parentHash
                                    ▲
                                    │  must match
                                    │
        execution node ──────► receipts, headers, proofs   ◄── UNTRUSTED
        (Alchemy today, ours tomorrow — same status)
```

`AuthenticateReceipts`, `AuthenticateHeader` and `VerifyProof` do not know or
care who supplied the bytes. Swapping the supplier is a **configuration change**
(`ETH_RPC_URL`), not a code change. That is the payoff from having built the
verification as a gate rather than a comparison.

---

## 1–6. What it would actually take

### Storage

| | size | notes |
|---|---|---|
| snap-synced full node, post-merge history | **~1.2 TB** | geth: >650 GB and **+14 GB/week** |
| path-based archive, flat state (geth v1.16+) | ~2 TB | ~2 weeks to sync |
| path-based archive **with historical trie nodes** | ~6.5 TB | needed for historical `eth_getProof` |
| hash-based archive (legacy) | >20 TB | months to sync; not a candidate |

Growth matters as much as the starting point: **+14 GB/week is ~730 GB/year**, so
a 2 TB disk is a two-year decision, not a permanent one.

### CPU, RAM, network

| | minimum | comfortable |
|---|---|---|
| CPU | 4 cores | 8 |
| RAM | 16 GB (geth alone) | 32 GB |
| disk | 2 TB **NVMe** | 4 TB NVMe |
| network | 25 Mbps, no data cap | — |

### Sync time

Hours to about a day on NVMe. On SATA the community guidance is blunt: only some
client combinations sync at all, and those take **~3 days**. Path-based archive
is ~2 weeks.

### Does snap/pruned operation give us what we need?

Two different questions, and they have different answers.

**History (receipts) — YES, comfortably.** We need at most one week: 50,400
blocks. Partial history expiry (live since May 2025) drops only **pre-merge**
bodies and receipts. The proposed rolling window for the next phase is **~5
months**, and the EIP requires serving one year on p2p. A one-week requirement is
two orders of magnitude inside any retention policy under discussion. This is the
easy half and it is genuinely easy.

**State (proofs) — NO, and this is the finding.**

A full node retains **128 blocks** of state. Beyond that, `eth_getProof` returns
`missing trie node`.

Our proofs are not taken at `latest`. [`client.go:191`](storage-client/internal/ethproof/client.go#L191)
requests them at `header.Number` — the **authenticated finalised block**, which
sits 64–96 blocks behind the head. That is inside 128, with roughly **32 blocks
(~6.4 minutes) of margin**.

That margin is thin, and it disappears exactly when it must not:

- **If finality stalls**, the finalised block falls arbitrarily far behind the
  head. This has happened on mainnet. A full node will have pruned that state; an
  archive provider still serves it.
- A stalled or degraded network is precisely when a watchtower needs to work, so
  the failure is *correlated with the attack conditions*, which is the worst
  property a dependency can have.

**Alchemy is hiding this today.** The current proof path works because a
commercial provider runs archive-grade infrastructure. Swapping in a plain full
node would fail closed — correctly, but it would take out the existing evidence
path, not just the new receipts path.

Mitigations, in order of cost: geth **v1.17+ `--history.trienode=N`** (retains
historical trie nodes, default `-1` = off), or path-based archive with trie
history (~6.5 TB). Neither is free and both must be chosen deliberately.

---

## 6. Can it run on our infrastructure? No.

Measured, not assumed:

| host | CPU | RAM | free disk | verdict |
|---|---:|---:|---:|---|
| prod `51.79.71.153` | 8 | 22 GB (7 available) | **27 GB** of 193 GB (87% used) | **no** — 45× short |
| workstation `/` | 16 | 31 GB | **64 GB** of 1.8 TB (97% used) | **no** |
| workstation `/mnt/backup` | — | — | 1.7 TB of 1.9 TB | **no** — see below |

`/mnt/backup` is the only volume with room, and it is disqualified twice over:

- it is **NTFS mounted through FUSE** (`fuseblk`, `/dev/sdb`, `TYPE="ntfs"`).
  Running an LevelDB/MDBX workload of this size on NTFS-over-FUSE is not a
  performance question, it is a correctness one — the fsync and locking semantics
  a chain database depends on are not what that stack provides;
- it is a **SATA** SSD (Samsung 860 EVO), and it already holds 133 GB of backups.

Reformatting the backup drive to ext4 would fix the filesystem and leave the SATA
problem, a ~3-day sync, and the loss of the backup volume.

**Conclusion: this needs new hardware or a new provider VM — a 2 TB NVMe machine
with 32 GB RAM.** There is no configuration of what we own that hosts it.

---

## 7. Should the DHT be involved in the node's database? No — absolutely not.

Firmly, and for reasons that are not about policy:

- **It is mutable and rewritten constantly.** The DHT is content-addressed
  immutable storage. A chain database is the opposite of content-addressed: the
  same logical thing has a different byte representation on every node and after
  every compaction.
- **It is not our content.** Every byte is reconstructible from Ethereum's p2p
  network by anybody. Publishing ~1.2 TB of it would multiply our storage cost by
  a factor of the erasure-coding overhead to store what is already free.
- **It would create a rebuild dependency in the wrong direction.** The DHT
  existing to serve our content must not come to depend on a database whose
  authority is Ethereum's.

The DHT stores **evidence** — the sealed, verified records the watchtower
produces. That boundary is right and this investigation does not move it. The
execution node's data directory is local scratch: losable, resyncable, and worth
nothing to anyone.

---

## 8. Does a local node become a trust anchor? No, if nothing else changes.

The safety argument is unchanged and does not depend on who runs the node:

- receipts must rebuild to the **authenticated** `receiptsRoot`;
- headers must hash to the **authenticated** `parentHash`;
- proofs must verify against the **authenticated** `stateRoot`;
- canonicality comes from the beacon light client, anchored at an independently
  obtained checkpoint.

An **eclipsed** local node — fed a fabricated chain by hostile peers — produces
data that fails all four checks. So the security properties survive; what does
not survive is availability, which is question 10.

Two risks that are real and are about people rather than cryptography:

- **Complacency.** "It's our own node" is the argument that eventually removes a
  verification step. The gate shape (`AuthenticateReceipts` returns receipts or
  an error, with no boolean to ignore) exists to make that hard, and it should
  stay that way. A local node makes the temptation stronger, not weaker.
- **Single supplier.** Alchemy is at least somebody else's infrastructure with
  somebody else's failure modes. One local node is one machine.

---

## 9. How fast would catch-up be? Projected 20–40× faster.

Decomposing the measured 200-block run (48.6 s total) into work and waiting,
using the per-operation costs measured in P14.5:

```text
41 receipt fetches x 79.4 ms      3.26 s
41 local rebuilds  x 6.79 ms      0.28 s
~9 header batches  x ~150 ms      1.35 s
200 header verifies x 10.9 us     0.002 s
                                 -------
actual work                       ~4.9 s   =  24.5 ms/block
measured wall clock              48.6 s    = 243 ms/block
                                 -------
rate-limit waiting               ~43.7 s   =  90% of the run
```

| outage | measured today | no rate limit (DERIVED) | local node (PROJECTED) |
|---|---:|---:|---:|
| 1 hour | 1m 13s | 7 s | **~2 s** |
| 24 hours | 29m 11s | 2m 56s | **~40 s** |
| 1 week | **3h 24m** | 20m 36s | **~5–10 min** |

The middle column is derived from measured per-operation costs. The right column
is **projected and not measured**: it assumes a local `eth_getBlockReceipts`
costs 20–40 ms (JSON serialisation of ~500 receipts does not become free just
because the socket is loopback) and that header batches cost single-digit
milliseconds. Those two assumptions are the whole estimate and neither can be
confirmed without a node.

What *is* measured and does not move: the local rebuild floor of **6.79 ms per
block**, paid only on the ~20% of blocks the authenticated bloom admits.

Against a 4-hour outage budget, a week-long catch-up would go from consuming
**85%** of it to roughly **4%**.

---

## 10. What if the local node is unavailable?

The watchtower **fails closed** — refuses to answer rather than serving a cache
it cannot vouch for. That is already the behaviour and it does not change.

But a single local node makes unavailability more likely, not less: one machine,
one disk, one resync. A node that loses its database is days from being useful
again, and "days" is longer than the outage budget.

**The mitigation is a second untrusted supplier, and it is not a fallback.** This
deserves stating precisely, because "no RPC fallback" is a standing rule:

> The rule forbids falling back to **unverified** data — the shortcut where a
> failure to authenticate is answered by believing somebody instead. Having two
> suppliers whose bytes both go through the identical gate is not that. Neither
> is trusted, so choosing between them changes nothing about what is believed.

So: local node primary, Alchemy retained as a second untrusted source, both
verified identically, with a metric counting which one served. That keeps the
rate-limit dependency off the critical path while keeping a supplier that exists
on somebody else's hardware.

---

## Recommendation

**Worth doing, but it is a hardware purchase, not a configuration change**, and
it must be scoped to include the state problem rather than only the receipts one.

If it goes ahead:

1. **2 TB NVMe, 32 GB RAM, 8 cores.** Not the backup drive, not prod, not the
   workstation.
2. **Decide the state-retention mode deliberately** — geth v1.17+ with
   `--history.trienode`, or path-based archive with trie history at ~6.5 TB.
   A plain full node is the option that looks cheapest and breaks the existing
   proof path during a finality stall.
3. **Keep Alchemy as a second untrusted supplier**, not a fallback.
4. **The DHT stays out of it entirely.**
5. Verification code changes **not at all**. If it needs to, something is wrong.

**Do not proceed on the basis of question 9 alone.** The 20–40× catch-up
improvement is projected from two unmeasured assumptions, and the cheapest way to
learn the truth is to sync one node and measure `eth_getBlockReceipts` against
it before committing to the architecture.

### Classification

| finding | class |
|---|---|
| prod free disk 27 GB, workstation 64 GB, backup 1.7 TB | **MEASURED** |
| `/mnt/backup` is NTFS-over-FUSE on SATA | **MEASURED** |
| proofs are requested at the finalised block, not `latest` | **MEASURED** (in our code) |
| catch-up work vs rate-limit waiting, 24.5 vs 243 ms/block | **DERIVED** from P14.5 measurements |
| full node retains 128 blocks of state | published client behaviour |
| post-merge receipts retained; rolling window ~5 months | published EIP-4444 status |
| full node ~1.2 TB, +14 GB/week; archive 2–6.5 TB | published client figures |
| local-node catch-up 5–10 min for a week | **PROJECTED, NOT MEASURED** |
| local `eth_getBlockReceipts` latency | **NOT MEASURED** — needs a node |
| behaviour during a real finality stall | **NOT MEASURED** |

Sources: [geth archive modes](https://geth.ethereum.org/docs/fundamentals/archive),
[geth hardware requirements](https://geth.ethereum.org/docs/getting-started/hardware-requirements),
[EIP-4444](https://eips.ethereum.org/EIPS/eip-4444),
[partial history expiry announcement](https://blog.ethereum.org/2025/07/08/partial-history-exp),
[SSD guidance for Ethereum nodes](https://gist.github.com/yorickdowne/f3a3e79a573bf35767cd002cc977b038),
[eth_getProof and missing trie node](https://support.chainstack.com/hc/en-us/articles/4440543903257-EVM-node-returns-Missing-trie-node).
