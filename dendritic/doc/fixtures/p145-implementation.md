# P14.5 — C+E implemented, tested and measured

**Built, adversarially tested against real mainnet, and measured under the three
workload cases that were outstanding. Two bugs in my own code were found by the
live runs and are recorded below. One measurement came out 13× worse than the
design estimate.**

## What was built

| file | what it is | why it had to be new |
|---|---|---|
| `ethproof/rlpencode.go` | RLP **encoder** | `rlp.go` decodes only |
| `ethproof/triebuild.go` | MPT **builder** | `proof.go` verifies one path, never builds |
| `ethproof/receipts.go` | EIP-2718 receipts, `AuthenticateReceipts` | the trust gate |
| `ethproof/bloom.go` | the 2048-bit filter | negative-only, by construction |
| `ethproof/headerrlp.go` | fork-aware header encoder | catch-up needs block hashes |
| `ethproof/blockscan.go` | `AuthenticatedBlock` | the two authentication routes, and no third |
| `ethproof/chainfollower.go` | restart-safe follower + checkpoint store | the statefulness C introduces |
| `ethproof/rpcsource.go` | untrusted acquisition | adaptive batching, rate-limit accounting |
| `ethproof/beaconsource.go` | authenticated finalised source | the SSZ branch, verified |
| `channel/eventreader.go` | `EventChainReader` | a `ChainReader`, so nothing above it changes |
| `channel/followermetrics.go` | aggregate-only bridge | four methods that cannot express an identifier |
| `contracts/…completeness.test.ts` | the contract invariant | pins the assumption the cache rests on |

**The decoder was not reused as an encoder.** A decoder that accepts a
non-canonical encoding, run backwards, reproduces its input rather than the
canonical form — and the whole job is computing what Ethereum *would* have
computed. Both encoders are written forwards from the specification and checked
against real mainnet data.

### Constraints, verified

`ChainReader` unchanged. `watchtower.go` unchanged. `evidencereader.go`
unchanged. Contracts unchanged. `DefaultWatchInterval` still 30 s,
`challengePeriod` untouched, the 10,000-channel envelope unchanged. The only
edits to existing files are four additive counters in `metrics.go` and their
entry in the privacy allowlist.

The watchtower still calls `ReadChannel` once per channel per sweep and knows
nothing about blocks, receipts or logs. What changed is what that call costs.

## The contract completeness invariant

The cache is sound for exactly one reason: **every function that writes `ch.*`
emits an event carrying `bytes32 indexed id`**. Given that, "no authenticated
event named this channel since block B" is a *proof* the channel is unchanged.
Without it, the same sentence is a guess that happens to be right.

`ChannelManagerV2.completeness.test.ts` reads the source and enforces it:

- every state writer emits, directly or through every one of its callers
  (`_reduceCollateral` and `_payout` are silent but private, and every caller
  emits);
- every event's first parameter is `bytes32 indexed`;
- the contract's event set **equals** the Go decoder's list — not "contains", so
  a new event that the watchtower would silently ignore fails the build;
- and two self-tests inject the exact mistakes being guarded against — a silent
  external mutator, and a silent private write reached from a non-emitting caller
  — and assert the real check catches both. A completeness test that cannot fail
  is decoration.

## The adversarial matrix — all 16 cases

| case | result | mechanism |
|---|---|---|
| real mainnet receipts | **exact** | rebuilt root == beacon-authenticated root |
| legacy + typed (0x0/0x2/0x3/0x4) | **exact** | 309/3010/19/43 over 12 blocks |
| omitted receipt | REFUSED | root mismatch |
| reordered receipts | **accepted** | correct — the key is the declared index |
| modified receipt | REFUSED | root mismatch |
| modified log | REFUSED | root mismatch |
| modified topic | REFUSED | root mismatch |
| fabricated event | REFUSED | root mismatch |
| missing event | REFUSED | the suppressed-CloseStarted attack |
| wrong contract address | ignored, cache intact | address filter, after authentication |
| wrong channel ID | ignored, cache intact | only the named channel is invalidated |
| wrong receipts root | REFUSED | header hash mismatch |
| wrong logs bloom (receipt) | REFUSED | root mismatch |
| **forged header bloom** | REFUSED | header hash — see below |
| restart after downtime | **catches up** | resumes from the persisted checkpoint |
| catch-up 1 h / 24 h / 1 week | measured | below |
| reorg during observation | REFUSED | two cases: at finality, and off-checkpoint |

Plus: no checkpoint → refuses to run; an interrupted catch-up resumes at the
exact block that failed; a catch-up beyond `MaxCatchUp` is a **refusal, never a
truncation**.

### Mutation-tested

Eight deliberate breaks of the safety properties. Seven were caught immediately;
**one survived**, and it mattered:

> Removing the header hash check in `AuthenticateHeader` changed nothing. Every
> existing test still passed, because each was already refused for some *other*
> reason.

The attack that needs it specifically: a provider serves a header with the
contract's **bloom bits cleared**. A forged receipt is caught by the root
comparison — but a forged bloom makes the follower *skip the block*, and a
skipped block is never fetched, so nothing downstream ever gets the chance to
notice. `TestP145ForgedHeaderBloomCannotHideAnEvent` now covers it and the
mutation is caught.

## Measurement A — bloom rate for an ACTIVE contract

60 authenticated blocks, 60% average saturation:

| contract | blocks skipped | receipt fetches per 30 s sweep |
|---|---:|---:|
| WETH | **0%** | 2.50 |
| USDC | **0%** | 2.50 |
| Uniswap V3 router | 65% | 0.88 |
| ChannelManagerV2 (ours, idle) | 75% | 0.62 |

**A busy contract is in every block, and the bloom saves nothing.** That is the
honest worst case, and the design survives it: 2.5 fetches × 79 ms + 2.5 × 6.8 ms
local = **215 ms per sweep, 0.7% of the interval**.

The conclusion is that **the bloom is not what makes this work.** It removes
75–82% of the work for an idle contract and 0% for a busy one, and the design is
comfortable either way. The earlier "82% skip" figure was never load-bearing.

## Measurement B — what the provider does at its limit

Unthrottled burst of 40 `eth_getBlockReceipts`:

```text
succeeded 13, refused 27, first refusal at request 11 (~0.5 s in)
=> sustainable rate ≈ 5-6 receipt fetches per second
recovery: 1 s pause still refused; 2 s pause recovered
throttled to a 120 ms floor: 10 blocks took 10.2 s and still hit the limit 4 times
```

Rate-limit events are counted **separately** from latency and surfaced in
`RPCStats.RateLimited` and the aggregate metric `chain_rate_limited`. No latency
figure in this document includes a backoff.

**Steady state is nowhere near the limit.** 2.5 fetches per 30 s is 0.08/sec
against a ~6/sec ceiling — two orders of magnitude of headroom. **Catch-up is a
different story**, and it is measured rather than assumed:

## Measurement 4, redone — real catch-up, with the limit in it

200 finalised blocks through the production `ChainFollower`:

```text
48.6 s total = 243 ms per block
bloom-skipped 159/200 (80%), receipts fetched 41
provider: 93 calls, 20 RATE-LIMIT events, 16 retries, 4 batch shrinks
```

| outage | design estimate | **measured** |
|---|---:|---:|
| 1 hour | 6 s | **1m 13s** |
| 24 hours | 2m 18s | **29m 11s** |
| 1 week | 16m 04s | **3h 24m** |

**13× worse than the design phase, and the whole difference is the rate limit.**
The earlier figure extrapolated from clean-run latency, which describes a
catch-up that cannot actually happen on this account.

### The finding that needs a decision

`MainnetChallengeBudget` allows **4 hours** for `Outage`. A one-week catch-up
costs **3h 24m — 85% of that allowance** — and the watchtower is fail-closed for
the whole of it, because serving from a cache it cannot vouch for is the exact
blindness this design removes.

Nothing was changed in response. `challengePeriod` is untouched, the budget terms
are untouched, and the sweep interval is untouched. It is recorded because a
week-long outage plus a slow provider is inside the envelope only barely, and the
margin belongs to whoever sets the budget rather than to me.

The limit is a property of this Alchemy plan, not of the design. A dedicated node
or a higher tier moves it, and that is the cheapest available mitigation.

## Measurement C — many channels changing in one window

First, what the chain can actually produce: `closeUnilateral` is **143,869 gas**,
so a 30M block holds at most **208** of them and a 30-second window caps at
**~520 closes**. Ten thousand in one window is not reachable.

Measured anyway, well past the reachable range:

| events in one block | build | authenticate | extract | alloc |
|---:|---:|---:|---:|---:|
| 208 | 1.1 ms | 1.3 ms | 1.2 ms | 2 MB |
| 1,000 | 3.8 ms | 4.1 ms | 4.4 ms | 11 MB |
| 5,000 | 22.1 ms | 20.8 ms | 21.6 ms | 60 MB |
| 10,000 | 42.6 ms | 38.3 ms | 43.0 ms | 124 MB |

The receipt work is local and cheap even at 48× what a block can hold.

**The honest floor:** every distinct channel named by an authenticated event is
re-read from the inner reader, so N changed channels costs N chain reads — the
same as the status quo. This design makes the *common* case cheap; it does not
improve the worst case, and it was never going to.

## Two bugs the live runs found in my own code

**A rate-limit detector that read response bodies.** `isRateLimit` scanned for
markers including `"429"` and a bare `"exceeded"`, and the batch path handed it
the *entire response body* — where `429` appears inside ordinary block hashes. A
successful 60-header batch was read as a refusal, retried five times, and failed
after a minute of backoff. Fail-closed made it safe and made it look like a
permanent provider outage, which is the expensive kind of safe. The detector now
only ever sees a decoded error message, the loose markers are gone, and
`TestRateLimitDetectorIgnoresResponseBodies` pins it.

**An adaptive batch that gave up at size 1.** When per-item refusals appeared,
the batch halved correctly — and then, at a single header, returned the error
instead of waiting. That abandons a catch-up for a condition that clears in two
seconds, at the moment a watchtower can least afford to stop. It now backs off
and retries at minimum size.

Both were found by running against the real endpoint, not by review.

## Production capacity

| | measured |
|---|---:|
| steady-state sweep, 10,000 channels, **busy** contract | **215 ms** (0.7% of the interval) |
| steady-state sweep, idle contract | ~90 ms |
| status quo (A), same measurement method | 344 s (11× over) |
| reduction | **~1,600×** |
| catch-up, 1 week | 3h 24m (85% of the outage budget) |

The 215 ms figure is now filed with measurements A, B and C behind it: A
establishes it holds when the bloom saves nothing, B establishes that steady
state sits two orders of magnitude below the provider's ceiling, and C
establishes that the worst case degrades to the status quo rather than to
something worse.

**What is still not measured:** behaviour against a provider with a materially
different rate limit, and a real ChannelManagerV2 under real load — ours is idle,
so every event exercised in the live tests was synthesised.
