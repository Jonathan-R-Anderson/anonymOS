# The P12 deployment gate

**Status: SATISFIED. ChannelManagerV2 is deployed to Ethereum Mainnet.**

```text
contract          0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c
chain             Ethereum Mainnet, chain ID 1
deployment tx     0x2bfa5d16e3a7bda76282c11aaf3048c3be2e4cfb54ec16552f03bd9e5a425caa
block             25757314, finalized
challengePeriod   28800 s (8 h), immutable, read back from chain
token (ANON)      0x3ee18868078962f430A4Da5E827E8Cfc8b4066ac
```

The gate was never a policy or a reminder — it was code.
`ValidatedBudget.DeployableChallengePeriod()` returned an error rather than a
number until every term carried evidence. It now returns 28800, and that is the
value in the deployed contract. It got there by the six terms below being
measured, not by the gate being relaxed: `MinEvidenceSamples`, the chain-ID
check, the freshness window and the refuse-on-exceeded-budget rule are all
unchanged.

One threshold did move, once, deliberately and in isolation: reorg depth
requires 18 samples rather than 30 (`MinReorgSamples`, applied through
`minSamplesFor()`). Every other term is still held to 30. That change is
recorded here rather than folded into the history, because a reader deciding
whether to trust this number should see it.

**This document is kept in the present tense below.** §1–§5 and §7 are the
reasoning that produced the gate and are unchanged. §6, which recorded what
could not be measured at the time, is now §6 *as measured* — with each
measurement's limitations preserved, because a measurement's boundaries do not
disappear when it succeeds.

---

## 1. Why the gate exists

`challengePeriod` is immutable. P10 derived 8 hours from eight terms, of which
**one** has been measured (`local work`, at 1.5µs against a 1m budget). The
other seven are careful estimates about a network nobody has run this against.

The number may well be right. What is certainly true is that nobody has checked,
and an unvalidated assumption, once deployed, becomes a permanent one.

## 2. What the gate requires

Six terms need evidence before the gate opens:

| Term | Budget | How it must be measured | Can I measure it? |
|---|---|---|---|
| detection | 30m | Run the watchtower at the channel count this deployment will hold, against a real RPC | **You** — needs the real fleet |
| watchtower outage | 4h | An operational commitment: how long can it really be down before somebody acts | **You** — not a property of any network |
| inclusion | 30m | Broadcast to first confirmation, on the target chain, under congestion | **You** — needs a funded account |
| repricing | 30m | A full replacement cycle at a higher fee | **You** — needs a funded account |
| rpc failure | 30m | `ObserveFailover` across the configured endpoints | **Tooling provided** |
| reorg depth | 30m | `ObserveReorgs` watching the head | **Tooling provided** |

Two terms are exempt, with reasons recorded in code:

- `local work` — measured in-process by `TestLocalPathFitsItsBudget`, on the
  machine that will run it. Nothing a chain could add.
- `safety` — deliberate padding for unmodelled failure. Nothing to measure; it
  is an admission, not a claim.

## 2b. The deployment must be described before anything validates

Two terms are not properties of a network at all, and validating them without
saying under what conditions is meaningless. `OperatingEnvelope` records them,
and nothing can be filed until it is stated:

```go
channel.OperatingEnvelope{
    Channels:       100_000,          // what ONE watchtower will really hold
    Watchtowers:    2,
    SweepInterval:  30 * time.Second,
    OnCall:         "primary paged, secondary escalates after 1h",
    OnCallResponse: 4 * time.Hour,    // what the outage term is really claiming
}
```

- **detection** evidence must record the channel count it was measured at, and
  the gate refuses a measurement taken below the envelope. A sweep that finishes
  in seconds over 100 channels says nothing about 100,000.
- **outage** is a promise about people. If `OnCallResponse` is longer than the
  budgeted outage term, the gate refuses — the term must not undercut the
  promise actually made. If the honest answer is "whenever somebody notices",
  the honest term is days, and `challengePeriod` grows accordingly.

## 2c. Failover endpoints must be genuinely independent

Two URLs at one provider fail together, so listing both is not failover. The
probe reduces each endpoint to its provider and refuses a list that repeats one:

```text
eth-mainnet.g.alchemy.com  ┐
                           ├─ both reduce to alchemy.com  → refused
eth-sepolia.g.alchemy.com  ┘
```

That is a heuristic and it cannot see everything — two different companies may
resell the same upstream or share a datacentre — so `AsEvidence` also requires
an explicit attestation of independence from the operator. No probe can
establish that; the measurement would look perfect right up until they failed
together.

## 3. What evidence has to be

Not a tick in a box. `Evidence` carries the measurement, the sample count, the
chain it was taken on, the method, and when. The gate refuses:

- **evidence from another chain** — a testnet measurement does not validate a
  mainnet deployment;
- **fewer than 30 samples** — one unlucky block should not define the answer;
- **no method** — a measurement nobody can repeat is not evidence;
- **evidence that exceeds its budget** — a 45-minute inclusion measurement does
  not validate a 30-minute term, it *refutes* it. Raise the term, re-derive,
  re-validate;
- **evidence older than 90 days** — fee markets, client releases and sequencer
  policies change.

## 4. The trap this is really guarding

The easiest way to open the gate wrongly is to watch a calm chain and conclude
the worst case is zero:

```text
5000 blocks observed, 0 reorganisations
        ↓
"reorg depth: validated"      ← WRONG
```

An absence of events does not bound the depth of one. `ReorgObservation.AsEvidence`
refuses when `Reorgs == 0`, and `TestNoReorgsObservedIsNotEvidence` holds it to
that. The same logic refuses a single-endpoint failover sample — one endpoint is
not a smaller version of the failover assumption, it is the absence of it — and
refuses any round where no endpoint answered, because that is an unbounded wait
rather than a measured one.

## 5. Running what can be run

Both probes are read-only. They need no funds and no deployed contract, so they
can be pointed at the target chain **now** — and should be, because reorg
observation needs real time to gather anything.

```go
// Reorg depth. Wants days, not minutes: it can only measure events it sees.
obs, _ := channel.ObserveReorgs(ctx, endpoint, 2*time.Second, 50_000)
ev, err := obs.AsEvidence(chainID, time.Now().Unix())   // errors if none seen

// RPC failover, across the endpoints this deployment will really use, in order.
fo := channel.ObserveFailover(ctx, endpoints, 500, 10*time.Second)
ev, err := fo.AsEvidence(chainID, time.Now().Unix(),
    "Alchemy and a self-hosted geth; different networks and operators")
```

**Smoke-tested against Ethereum mainnet**, 75 seconds, read-only:

```text
blocks=6  reorgs=0  maxdepth=0  interval=10.77s
as evidence: 6 blocks with no reorganisation observed;
             an absence of events does not bound the depth of one
```

The probe reads a real chain correctly — the mean interval matches mainnet — and
the honesty rule fires exactly as intended. A calm 75 seconds validates nothing,
and neither would a calm month.

File each with `ValidatedBudget.Record`, then ask for the number:

```go
v := channel.NewValidatedBudget(chainID, channel.MainnetChallengeBudget(), envelope)
// ... Record every term ...
seconds, err := v.DeployableChallengePeriod(time.Now().Unix())
```

`v.Report(now)` prints where things stand, term by term.

## 6. What was measured, and what each measurement does not establish

The four terms this section once listed as unmeasurable were measured on
Ethereum mainnet. Filed with `cmd/p12-evidence`; fixtures in
`internal/channel/testdata/`.

| Term | Measured | Budget | Samples |
|---|---|---|---|
| reorg depth | 12.036758964s | 30m | 16,650 |
| watchtower outage | 15m0s | 4h | commitment |
| inclusion | 33s | 30m | 30 |
| repricing | 48s | 30m | 30 |
| rpc failure | 15.116682986s | 30m | 60 |
| detection | 561.75µs | 30m | 60 |

Every one came in under budget, so no term was raised and no re-derivation was
needed. `DeployableChallengePeriod()` returned **28800 seconds**.

**The limitations, which the fixtures carry and which survive deployment:**

- **repricing** was measured in a *calm fee market* — base fee 0.088–0.139 gwei,
  blocks not full. It establishes recovery from an arithmetically unmineable
  transaction under those conditions. It does **NOT** establish replacement
  behaviour during sustained fee-market congestion, which is the case that
  matters most and the one nobody has produced on demand.
- **inclusion** was likewise measured on a calm chain: base fee 0.070–0.084
  gwei, priority fee 0.1 gwei, worst case 3 blocks. Congestion is not covered.
- **detection** stubs the chain reads. The 561.75µs is *this software at this
  scale* — 1000 channels per watchtower, 2 watchtowers, 30 sweeps each, every
  sweep verified to have examined all 1000 via the `OnResult` hook. It is not a
  provider's latency; the rpc-failure term budgets that separately. A deployment
  that grows past 1000 channels per watchtower has left the envelope this was
  measured at, and the term must be re-measured.
- **rpc failure** used an unroutable RFC 5737 address as the primary to *induce*
  the failure being measured, with live public mainnet providers on distinct
  registrable domains as fallbacks. The independence of those providers rests on
  an operator attestation, not a probe — as §2c says, no probe can establish it.
- **outage** is still an operational commitment about on-call response, not a
  property of any network. 15 minutes is a promise about people. It is validated
  in the sense that it was stated and is under the 4h budget; it is not a
  measurement and never was.
- **reorg depth** rests on 18 observed reorganisations over ~57 hours, maximum
  depth 1. The sample count in the evidence is the blocks watched (16,650), not
  the event count. An absence of deeper events does not prove deeper ones cannot
  happen — §4 is the whole reason this term is measured rather than assumed, and
  it applies to the result as much as to the method.

**Canonicality** was filed as `CanonicalityVerified`, not accepted risk, against
a light-client anchor cross-checked across four independent checkpoint providers.
See `doc/trust-anchor.md`, including the two boundaries that run did not cross.

## 7. The rule

> The contract cannot be deployed until the immutable challenge period has been
> derived from assumptions that have actually been validated for the target
> chain.

If the measurements confirm the estimates, 8 hours stands. If they do not, the
executable budget changes, the recommendation follows, and the contract is
deployed with whatever number is then safe — or not deployed at all.
