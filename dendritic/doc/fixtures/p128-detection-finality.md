# P12-8 — what actually blocks the gate, and a latent problem in detection

**Formally, one term blocks: reorg depth, at 7/30, running unattended on a clock.
Nothing can hurry it.**

**But the detection term is marked VALIDATED on evidence that does not meet the
gate's own stated standard**, and that is worse than an unmeasured term — when
reorg depth completes, the gate would open on it.

Nothing here changes any budget term, `challengePeriod`, the watchtower, the
verification boundary or the gate.

---

## Gate state, from the roadmap's own table

| term | budget | filed | status |
|---|---|---|---|
| local work | — | in-process | VALIDATED |
| **detection** | **30m** | **31s / FakeChain** | **VALIDATED — see below** |
| inclusion | 30m | 33s worst, 30 mainnet txs | VALIDATED |
| rpc failure | 30m | 267ms / 80 | VALIDATED |
| watchtower outage | 4h | operational commitment | VALIDATED |
| repricing | 30m | 48s worst, 30 samples | VALIDATED |
| **reorg depth** | **30m** | **7 events / 30 needed** | **NOT MEASURED — the blocker** |

## The problem with the detection evidence

`doc/deployment-gate.md` requires detection to be measured

> "at the channel count this deployment will hold, **against a real RPC**"

The filed 31s comes from `TestDetectionAtProductionEnvelope`, which builds its
10,000-channel envelope on **`NewFakeChain()`** — an in-memory map with no
latency and, decisively, **no concept of finality**.

That last part is why the number is not merely optimistic. It measures a
different quantity.

### Detection is floored by consensus, not by our code

`AuthenticatedStateRoot` refuses any header that is not finalised:

```go
if level != HeaderFinalized {
    return Root{}, 0, Root{}, fmt.Errorf("%w: header is %s", ErrNotFinalized, level)
}
```

So the watchtower **cannot see a channel state change until the block carrying it
finalises**. A zero-latency chain finalises instantly and therefore cannot
express the dominant term at all.

### Measured, on mainnet

Twelve consecutive readings of the beacon finality update:

```text
head slot - finalized slot
  min     64 slots  = 12.8 min
  median  74 slots  = 14.8 min
  max     87 slots  = 17.4 min
```

Against the 30-minute detection budget, **finality alone consumes 43–58%** before
the watchtower does anything.

The filed 31s understates real detection by roughly **25–35×**, and the part it
omits is the part nothing can optimise. Not the PAYG upgrade, not a local
execution node, not receipt parallelism. It is Ethereum's.

### Does the term still hold?

On the evidence so far, **yes**:

```text
worst observed finality lag    17.4 min
+ sweep interval                0.5 min
+ sweep + advance (measured)   ~0.03 min   (38 ms local sweep at 10,000 channels,
                                            44.7 ms/block advance, PAYG)
= ~17.9 min against a 30 min budget         60% of it
```

**The budget is not refuted and must not be changed.** What is wrong is the
evidence, not the term. That distinction is the whole point of the gate.

## What is running

A proper measurement is under way: `TestP128FinalityLagForDetection` gathers **30
independent samples**, waiting for the finalised slot to actually change between
observations.

That guard matters. Finality advances once per epoch (32 slots, 6.4 min), so
polling every 20 seconds returns the same answer a dozen times over — my initial
12-sample probe contained only **three** distinct finality updates. Counting
repeats would let a 12-sample run masquerade as 30, which is exactly the
sample-count rule the gate exists to enforce.

Thirty independent epochs need **~3.2 hours**. It is running.

The test asserts against the budget rather than reporting past it: if worst-case
detection exceeds 30 minutes it **fails**, with the instruction to raise the term
and re-derive `challengePeriod` — never to adjust the measurement.

## Priority, and what I did not start

1. **reorg depth** — the only formal blocker. On a clock at 7/30, running
   unattended. Nothing to do but wait; it cannot be hurried and an absence
   validates nothing.
2. **detection** — actionable, and now being measured properly. Highest-priority
   item that can actually be worked on.
3. Everything else is filed and within budget.

**One thing I noticed and deliberately did not pursue:** the rpc-failure evidence
is filed as "267ms / 80". The gate requires failover endpoints to be *genuinely
independent providers* plus an explicit operator attestation of independence.
Worth confirming what two providers that measurement used — but it is a separate
check, it is not blocking, and chasing it now would be exactly the sprawl to
avoid.

**No optimisation work was started.** The parallelism headroom found in P14.6g
remains unused, as instructed. Detection is dominated by finality, so it would
not have helped anyway.

## Classification

| | class |
|---|---|
| filed detection evidence uses `NewFakeChain` | **MEASURED** (source) |
| `AuthenticatedStateRoot` requires finalised headers | **MEASURED** (source) |
| finality lag 12.8 / 14.8 / 17.4 min (12 readings, 3 distinct epochs) | **MEASURED — sample too small to file** |
| finality lag over 30 independent epochs | **IN PROGRESS** |
| end-to-end detection ~17.9 min worst | **DERIVED** from the above |
| the 30-minute detection term | **UNCHANGED, and not refuted** |
| reorg depth | **7/30, running** |
