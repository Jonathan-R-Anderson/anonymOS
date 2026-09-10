# P12-8 — rpc-failure evidence review

**The rpc-failure evidence does not satisfy the independent-provider requirement,
because there is no evidence. The "267ms / 80" figure cannot be traced to any
measurement.**

This is a second blocking term, not a validated one — and unlike detection, it
cannot be satisfied at all with the providers we currently have.

I did not rerun the probe. There is nothing to rerun: it has never been run
against real endpoints. No budget term, `challengePeriod`, the gate or any code
was changed.

---

## What the gate requires

`FailoverObservation.AsEvidence` enforces five conditions:

1. **at least two endpoints** — "the rpc-failure term assumes failover is possible";
2. **no two sharing a provider** — `IndependentEndpoints`, on the last two host labels;
3. **an explicit operator attestation** of independence — because no probe can
   establish that two providers do not share an upstream;
4. **zero rounds where every endpoint failed** — "an unbounded wait, not a measured one";
5. **failover actually exercised** — the primary must have failed at least once
   *and* a fallback must have carried rounds.

Condition 5 carries its own history in a comment: it was added after a real run
of 60/60 rounds answered by the primary was accepted as failover evidence. The
rules are sound and were hardened by exactly this kind of review.

And `doc/deployment-gate.md` says evidence must carry "the measurement, the sample
count, the chain it was taken on, the method, and when".

## What actually exists

| | |
|---|---|
| fixture document | **none** — no `p12-8-rpc-failure.md` |
| persisted evidence record | **none** |
| test or run producing "267ms" or "80 samples" | **none** |
| occurrences of "267" in the repo | **only the roadmap's own status line** |

**`ObserveFailover` has never been run against a real endpoint list.** Its only
call sites are two unit tests:

```go
chainprobe_test.go:185   ObserveFailover(ctx, []string{dead.URL, good.URL}, 5, 0)
chainprobe_test.go:204   ObserveFailover(ctx, []string{dead.URL, dead.URL}, 3, 0)
```

Both use `httptest` servers on 127.0.0.1.

Every `AsEvidence` test hand-constructs a `FailoverObservation` with placeholder
hosts — `https://a.example`, `https://b.example`, `https://one.example`. Those
tests are excellent: they verify the *rules*. They are not measurements of any
endpoint list, and they were never intended to be.

So "267ms / 80" is a status-table entry with no provenance. Against the gate's
own standard — measurement, sample count, chain, method, timestamp — it is none
of the five.

## It cannot be satisfied with what we have

Even setting provenance aside, the term cannot be validated today:

- `ObserveFailover` probes `eth_getBlockByNumber` — an **execution** RPC
  (`chainprobe.go:135`);
- we have exactly **one** execution provider: Alchemy;
- P14.6 concluded against running our own node, on measured economics;
- the beacon endpoint cannot stand in — it is a consensus API and refuses the
  call outright:

```text
POST https://lodestar-mainnet.chainsafe.io  ->  {"code":404,"message":"Route POST:/ not found"}
```

One endpoint is not a smaller version of the failover assumption. It is the
absence of it, and `TestASingleEndpointCannotValidateTheRPCTerm` already says so.

## Answer to the question asked

> Does the existing rpc-failure evidence satisfy the gate's independent-provider
> requirement?

**No — and not because the providers are insufficiently independent. Because
there is no evidence to evaluate.** The independence rule was never reached.

## Consequence for the gate

The gate remains **CLOSED** and this does not change that. But the count of
outstanding terms is two, not one:

| term | status before this review | status after |
|---|---|---|
| reorg depth | NOT MEASURED, 7/30 running | unchanged |
| **rpc failure** | **VALIDATED "267ms / 80"** | **NOT MEASURED — no evidence exists** |
| detection | VALIDATED "31s" | evidence mis-scoped; re-measurement running |

The 30-minute rpc-failure budget is **untouched and not refuted** — an unmeasured
term is not a refuted one. What changed is a documentation claim that was false.

## What I did not do

- **Did not rerun the probe.** There is nothing to rerun.
- **Did not acquire a second provider.** That is a decision with cost attached
  and it is not mine to make. It is also the only way this term gets validated.
- **Did not change any budget term, `challengePeriod`, or the gate.**
- **Did not start optimisation work.**

## What validating it would require

Recorded so the decision can be made, not as a recommendation:

1. a **second execution RPC provider**, genuinely independent of Alchemy;
2. `ObserveFailover` across the real endpoint list, in the order the deployment
   will use;
3. a run in which the primary **actually fails** and a fallback carries rounds —
   a healthy run proves nothing (condition 5);
4. an operator attestation of independence;
5. ≥30 samples on mainnet, filed as a fixture with method and timestamp.

Note that a free-tier second provider would satisfy this: the term measures
*recovery time when the primary is unavailable*, not throughput.

## Classification

| | class |
|---|---|
| `ObserveFailover` never run against real endpoints | **MEASURED** (source) |
| no fixture, no persisted record, no test output for 267ms/80 | **MEASURED** (repo-wide search) |
| beacon endpoint cannot serve `eth_getBlockByNumber` | **MEASURED** (404) |
| we have one execution provider | **MEASURED** (config) |
| rpc-failure term validity | **NOT MEASURED — was wrongly marked VALIDATED** |
| the 30-minute budget itself | **UNCHANGED, not refuted** |
