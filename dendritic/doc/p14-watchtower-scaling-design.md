# P14 — watchtower scaling: design investigation

**Design only. Recommendation at the end.**

> **STATUS: approved and implemented.** C+E is built, adversarially tested and
> measured — see `doc/fixtures/p145-implementation.md`. Two figures below are
> superseded by that document: catch-up is **13× slower** than estimated here
> once the provider's rate limit is included (1 week = 3h24m, not 16m), and the
> bloom skip rate is **0% for an active contract** rather than 82%. Neither
> changes the recommendation; both change the numbers.

Competing against a measured baseline, not a guess: **34.4 ms** per pooled chain
read, **~872 channels** per watchtower at a 30-second sweep, 11× over the
declared 10,000-channel envelope.

> **Superseded figures.** This document originally used 196 ms/read and ~153
> channels. Both came from cold-connection samples; measured through a pooled
> client, as a long-running watchtower would use, the read is 34.4 ms. The
> envelope still fails, by 11× rather than 65×. See
> `doc/fixtures/p145-receipts-measurements.md`.

---

## The two facts the whole investigation turns on

**1. Every state change emits an event carrying the channel id.**

| function | event | id indexed |
|---|---|---|
| `openChannel` | `ChannelOpened` | yes |
| `deposit` | `Deposited` | yes |
| `applyCheckpoint` | `CheckpointApplied` | yes |
| `closeCooperative` | `ClosedCooperatively` | yes |
| `closeUnilateral` | **`CloseStarted`** | yes |
| `challenge` | `Challenged` | yes |
| `claimLock` | `LockClaimed` | yes |
| `expireLock` | `LockExpired` | yes |
| `settle` | `Settled` | yes |

Checked for completeness rather than assumed: every write to `ch.*` in
`ChannelManagerV2.sol` occurs inside one of these nine functions.
`_reduceCollateral` writes `depositA`/`depositB` but is a private helper called
only from `applyCheckpoint`, which emits. **There is no silent state change.**

**2. The receipts root is already authenticated by the P12 chain.**

`ExecutionPayloadHeader` carries `ReceiptsRoot` *and* `LogsBloom`
(`execution.go:70`), and both are merkleised into the payload's hash tree root
(`execution.go:109`). So the same SSZ branch that authenticates `stateRoot`
authenticates `receiptsRoot` and `logsBloom` — **at no additional trust cost and
no additional proof**.

That is the crux. Events become usable for security precisely because their
container is already inside the trust boundary we built for state.

---

## Candidate architectures

### A — status quo: poll every channel

Read `channels(id)` for all 10,000 each sweep, storage-proved against the
authenticated state root.

- **Trusts:** nothing beyond P12. Correct today.
- **Reorgs:** immune — only finalised state is read.
- **Forgery:** impossible; every read is MPT-proved against an authenticated root.
- **Complexity:** O(channels) per sweep, always. 10,000 reads / 30 s.
- **Removes the bottleneck:** no. It *is* the bottleneck.

### B — RPC `eth_getLogs`, used directly

Ask the provider which channels changed.

- **Trusts:** the RPC, completely. A provider that omits one `CloseStarted` makes
  the watchtower blind to exactly the event it exists to catch.
- **Forgery:** trivial. Omission is undetectable — there is no proof of absence.
- **Verdict: REJECTED.** Not "slower to verify" — *unauthenticatable*. This is
  the shape the instruction warns against, and it fails on omission rather than
  on fabrication, which is the harder failure to notice.

### C — authenticated receipts (recommended)

Per finalised block, from the P12 chain:

```text
verified sync committee → finalised beacon header → execution payload
      → authenticated {stateRoot, receiptsRoot, logsBloom}
                                     │
       ┌─────────────────────────────┴──────────────┐
       ▼                                            ▼
  logsBloom test                        rebuild receipts trie from
  (authenticated)                       RPC-supplied receipts, compare
       │                                root to authenticated receiptsRoot
       │ contract absent → SKIP BLOCK          │ mismatch → REFUSE
       ▼                                       ▼
   zero further work                    every log now authenticated
                                               ▼
                                     channel ids that changed
                                               ▼
                                  storage proofs for THOSE ONLY,
                                  against the authenticated stateRoot
```

- **Trusts:** nothing new. Receipts arrive from an untrusted RPC and are
  *verified*, not believed: the locally rebuilt trie root must equal the
  authenticated `receiptsRoot`. A lying or incomplete provider produces a
  mismatch.
- **Omission is caught**, which B cannot do: a missing receipt changes the trie
  root. That is the property that makes events safe here and unsafe in B.
- **Reorgs:** only finalised blocks are processed. Below finality a reorg cannot
  occur by definition; above it, nothing is acted on. Unchanged from today.
- **Forgery attempts:** fabricate a receipt → root mismatch → refuse. Omit a
  receipt → root mismatch → refuse. Replay a real receipt from another block →
  it is not in *this* block's trie → mismatch. Serve a different block → the
  header is not the one finality authenticated.

### D — bloom-only

Use the authenticated `logsBloom` alone to decide which channels changed.

- **Fails:** a bloom filter has false positives and gives set-membership, not
  values. It cannot yield channel *ids*. Usable only as C's pre-filter.

### E — event-driven with local deadline scheduling

C, plus: `CloseStarted(id, by, nonce, challengeEnds)` **carries the deadline**.
Once that event is authenticated, the watchtower knows when the window closes and
can schedule locally — no polling to discover a deadline it was already told.

This matters more than it first appears. Time-driven state (a challenge window
expiring) is not a storage write and emits nothing, so a naive event-only design
would miss it. It does not need to be discovered: it was announced when the close
started, with its deadline attached.

---

## Complexity, at 10,000 channels

| | status quo (A) | recommended (C+E) |
|---|---|---|
| steady state, no activity | 10,000 reads / 30 s | **0 reads on 82% of blocks** — bloom says the contract is absent |
| steady state, light activity | 10,000 reads / 30 s | ~2.5 `getBlockReceipts` + proofs for changed channels |
| worst case, all 10,000 change in one window | 10,000 reads | 10,000 proofs + ~2.5 receipt fetches |
| per finalised block | — | O(receipts in block), **~437 measured** on mainnet |

Mainnet produces ~2.5 blocks per 30 s. The common case collapses from 10,000 RPC
calls to **almost zero**: the authenticated bloom answers "did this contract
appear at all" without any further request, and a bloom's *negative* is
authoritative (no false negatives), which is exactly the direction needed.

**Measured, not assumed: the bloom is negative on 82% of blocks, not 100%.** At
mainnet's 57% bloom saturation the false-positive rate for our address is 18%,
matching theory (0.575³). Each false positive costs one wasted receipts fetch and
finds nothing. The direction of the error is safe — never a missed event — but
"zero reads" overstated it.

**Does it remove the 65× bottleneck?** In the common case, yes — by roughly three
orders of magnitude. The worst case is unchanged, and that is correct: if all
10,000 channels really did change, 10,000 proofs is the honest cost. The design
makes the common case cheap without making the worst case unsafe.

---

## What the verifier must require

1. A finalised beacon header, sync-committee verified — unchanged from P12.
2. An execution payload proven into it at `EXECUTION_PAYLOAD_INDEX` — unchanged.
3. **New:** receipts, RLP-encoded per EIP-2718 typed-receipt rules, assembled
   into an MPT keyed by `RLP(transactionIndex)`, whose root equals the
   authenticated `receiptsRoot`. Anything else → refuse.
4. Logs filtered by contract address and topic0, with the channel id read from
   `topics[1]` (it is `indexed`).
5. Storage proofs for the affected channels against the authenticated
   `stateRoot` — unchanged from P12-2.

Nothing here relaxes a finality requirement and nothing introduces a fallback.

---

## Fail-closed behaviour

The existing distinction must survive, and does:

| condition | error | meaning |
|---|---|---|
| no authenticated header yet, or receipts do not match the root | `ErrNoVerifiedEvidence` | we cannot *see*; refuse |
| authenticated state proves the channel absent | `ErrChannelNotOnChain` | we can see, and it is not there |

The separation is preserved because they answer different questions: the first is
about the watchtower's own evidence, the second is a fact proven against an
authenticated root. A receipts mismatch must map to the first — treating "the
provider gave me bad receipts" as "the channel does not exist" would be the
dangerous conflation.

---

## New persistent state

| state | why | on loss |
|---|---|---|
| last processed finalised block | resume point | resync from the last authenticated checkpoint |
| per-channel last authenticated status + `challengeEnds` | avoids re-proving unchanged channels | re-prove on next relevant event |
| pending deadlines from `CloseStarted` | local scheduling | **must** be rebuilt by scanning back |

**Restart and evidence loss is the sharp edge.** A watchtower that restarts with
no state cannot know whether a `CloseStarted` fired while it was down. It has
three options, and only one is safe:

- scan back from the last known finalised point to now — cost proportional to the
  gap, correct;
- start fresh from current finality — **silently blind** to any window opened
  during the outage, which is the exact failure the watchtower exists to prevent;
- refuse to run until caught up — fail-closed and honest.

The design must take the first or third. This is a genuine cost the polling
design does not have: A is stateless and self-healing, C is not. It is the
strongest argument in A's favour and must not be waved away.

---

## Measurements 1, 2, 3, 4 and 6 — all done

Full results and method: `doc/fixtures/p145-receipts-measurements.md`.

| | measured |
|---|---|
| **6** — EIP-2718 round trip vs the AUTHENTICATED root | **exact**; all four mainnet receipt types; 10/10 alterations caught |
| **2** — rebuild cost | decode 2.33 ms, encode 2.03 ms, build 2.42 ms, verify 10.9 µs = **6.79 ms/block**; 12% of one core; 2 MB heap |
| **3** — bloom | **82% negative** (zero work); 18% false positive; 57% saturation |
| **4** — catch-up | 1 h **6 s**, 24 h **2m 18s**, 1 week **16m 04s** (batched) |
| **1** — `eth_getBlockReceipts` | **79.4 ms** pooled (the 1.111 s figure was cold-connection) |
| baseline `eth_call` | **34.4 ms** pooled (the 196 ms figure was cold-connection) |

```text
per 30s sweep at 10,000 channels, BOTH SIDES measured through one pooled client
  status quo (A)   344 s      11x over the interval
  proposed  (C+E)  216 ms     0.7% of the interval
  reduction        1592x
```

**The 706× figure is superseded by 1,592×** — it compared cold against cold and
understated the gain. `getBlockReceipts` is **2.3×** an `eth_call`, not 5.7×.

### What the measurements changed in this design

- **Catch-up needs a backwards header walk.** The light-client API serves the
  *current* finality update and one update per sync-committee period; it cannot
  authenticate an arbitrary past block. Catching up means re-encoding each
  execution header and checking it hashes to the `parentHash` the block after it
  declared — verified over 25 consecutive real headers, anchored at an
  authenticated block hash. Reorg-safe by construction, because each step binds
  by hash rather than height.
- **Three encoders must be written.** `rlp.go` decodes only; `proof.go` verifies
  only. C needs an RLP *encoder*, an MPT *builder*, and an execution-header RLP
  encoder — the last carrying the same fork-dependent field-count trap as
  `ExecutionPayloadHeader`.
- **Provider rate limits are a real constraint.** The first harness run was
  refused for exceeding compute units per second. A watchtower fleet sweeping
  every 30 s lives against that limit permanently, and hardest during catch-up.

## What must still be measured before implementing

1. Bloom false-positive rate for an **active** contract — ours is idle, so every
   positive measured was a false one.
2. Behaviour when the provider's rate limit is actually **hit** rather than
   throttled around.
3. The worst case: 10,000 channels changing inside one window.

---

## Recommendation

**Adopt C with E's deadline scheduling.** Measurements 1, 2, 3, 4 and 6 are done
and all pass: the round trip against the authenticated root is exact, the rebuild
costs 6.79 ms per block, the bloom skips 82% of blocks outright, and a week-long
outage costs 16 minutes to catch up. 216 ms per sweep against a 30-second
interval, a 1,592× reduction, both sides measured identically.

It preserves the P12 trust boundary exactly — the receipts root was already
inside it — introduces no new trusted party, catches omission as well as
fabrication, and reduces the common case from 10,000 reads to almost zero. B is
rejected outright as unauthenticatable. A stays correct and stays the fallback,
at ~872 channels per watchtower.

**Two things I would not let pass into implementation unexamined:**

- The **restart-blindness** above. C trades statelessness for speed, and the
  trade is only acceptable with a catch-up scan or a refusal to run. Measurement
  4 makes the honest option affordable: 6 s after an hour, 16 minutes after a
  week, so "refuse until caught up" does not mean hours of downtime.
- **Event completeness is a contract invariant that must be pinned by a test.**
  Today every mutator emits; nothing enforces that it stays true. A future
  function that writes channel state without emitting would make the watchtower
  silently blind, and no amount of correct verification downstream would notice.
  That test belongs in the same change as the implementation, not after it.

No production code has been changed. `challengePeriod`, the deployment gate and
ChannelManagerV2 are untouched.
