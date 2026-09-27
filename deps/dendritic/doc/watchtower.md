# The watchtower, and where `challengePeriod` comes from

**`challengePeriod`: 8 hours (28800 seconds) — DEPLOYED AND IMMUTABLE.**

This value is no longer provisional and no longer changeable. Every
network-dependent term below was measured against Ethereum mainnet, the gate
returned 28800, and `ChannelManagerV2` was deployed with it to
`0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c` (chain 1, block 25757314). The
figure was read back from the chain after deployment.

The measurements came in under budget, so the 8 hours these terms were estimated
at is the 8 hours they measured to. What each measurement does **not** establish
— congestion for inclusion and repricing, stubbed chain reads for detection, an
attestation rather than a probe for RPC independence — is recorded in
`doc/deployment-gate.md` §6 and still applies. An assumption that survived
measurement is not the same as one that was never tested, but neither is it
proof about conditions the measurement did not cover.

Derived, not chosen. The derivation lives in
`storage-client/internal/channel/challengebudget.go` and is checked by
`challengebudget_test.go`, so it can be re-run and argued with rather than
remembered. This document is the reasoning; the code is the answer.

---

## 1. Why this number cannot be fixed later

`challengePeriod` is a constructor argument to `ChannelManagerV2` and it is
**immutable**. Every channel that contract will ever hold is defended for
exactly as long as the value chosen at deployment.

Too long is an inconvenience: a recipient closing a channel without cooperation
waits longer for their money. Too short is permanent: an honest party who cannot
get their state on chain in time loses the difference, and there is no appeal
and no upgrade path.

So the whole of P10 exists to answer one question:

> Can an honest participant reliably get the latest valid state on chain
> before a stale one becomes final?

## 2. The asymmetry that makes a watchtower necessary

A recipient runs a node; it watches its own channels. A tipper is a person who
opened a browser tab:

```text
make one tip  →  close the tab  →  leave for six months
```

Nobody in that sequence is watching anything. But `closeUnilateral` lets either
party publish a state and start the clock, and if a **stale** state wins that
clock, the difference is simply taken. A payment system whose safety depends on
the payer staying awake is not a payment system.

## 3. Why delegating is safe

The contract does not restrict `challenge` to the channel's parties — it checks
the signatures, not the sender:

```text
can:     submit a state both parties have already signed
cannot:  create a state, alter one, or redirect a payment
```

A watchtower holds no key of the party it defends. The worst a hostile one can
do is **nothing**, which is exactly what happens with no watchtower at all — so
delegating is never worse than not delegating. That is what makes it safe to
hand this job to somebody else's infrastructure.

## 4. Polling, not events

The watchtower reads the `channels` mapping on a timer rather than subscribing
to `CloseStarted`.

An event is a notification; the mapping is the fact. A watchtower that was down
for an hour, or whose websocket subscription silently dropped — the normal
failure mode of websocket subscriptions — has no way to discover a close it
missed. Polling costs one `eth_call` per channel per interval and cannot miss a
close that is still open.

It also makes detection latency **a number this system chooses** rather than a
property of somebody's RPC provider, which matters because it is the first term
below.

## 5. The budget

Every term is an upper bound, and they are **added, not combined
statistically**. A budget built on expected values fails precisely when two
things go wrong at once, which is the situation it exists for.

| Term | Value | Why |
|---|---|---|
| detection | 30m | Sweep interval is 30s, so this is 60× headroom. Not set to 30s because the interval is a floor on detection, not a ceiling — a node tracking thousands of channels sweeps slower. |
| watchtower outage | 4h | Deploys, crash loops, an unattended weekend incident. The largest term, and rightly: it is the only one covering "nobody was watching". Assumes somebody is on call. |
| local work | 1m | **Measured at 1.5µs**, worst realistic shape (a channel with a full lock set). Four orders of magnitude of headroom for a node under severe IO pressure. |
| inclusion | 30m | L1 at a fee chosen to confirm. Ordinary inclusion is ~12s; this covers sustained congestion. |
| repricing | 30m | One full replacement cycle at a higher fee. Counted separately because it is a second full wait, not a longer first one — and the market where the first estimate fails is the congested one the previous term assumes. |
| rpc failure | 30m | A dead or lying endpoint, plus failover. **Assumes more than one endpoint is configured.** |
| reorg depth | 30m | Far beyond anything L1 has sustained post-merge, where finality is ~13 minutes. |
| safety | 1h | Unmodelled failure. Every real incident involves something nobody had a term for. |
| **total** | **7h31m** | |
| **recommended** | **8h** | Rounded **up**; rounding a margin down is how it stops being one. |

The local term is the only one this codebase controls, and it is the only one
that is measured. `TestLocalPathFitsItsBudget` fails if the local path ever
grows past its budget — the budget is a promise about the code, and a promise
nothing checks is a guess.

## 6. The watchtower's own margin

A watchtower that has *just noticed* a stale close still has most of the path
ahead of it. It refuses to attempt a challenge with less runway than that:

```text
margin = local + inclusion + repricing + rpc failure + reorg
       = 2h1m
```

**Derived from the same budget**, not picked. A round number here would let the
two drift, and the direction they drift is a watchtower confidently broadcasting
challenges that cannot arrive.

Inside the margin it **refuses loudly** rather than trying hopefully. A
transaction sent two minutes before a deadline it needs an hour to meet spends
gas to lose — and writes "challenge sent" into a log somebody later reads as
"we were fine".

## 7. What would change the number

- **A chain with slower or less certain finality** raises inclusion and reorg.
- **A single RPC provider** makes the rpc term unbounded. Fix the deployment,
  not the number.
- **A watchtower with nobody on call** raises outage to the real detection time
  for an unattended service, which is days rather than hours.

Change the term in `MainnetChallengeBudget()` and re-run the tests; the
recommendation and the watchtower's margin both follow.

## 8. What this does not cover

- **Cooperative closes are unaffected.** Both parties sign, settlement is
  immediate, there is no challenge window. This number is the price of the path
  taken once cooperation has already broken down.
- **State availability is P11.** A watchtower can only submit a state it holds.
  Getting the latest state to whoever is watching — and doing it without handing
  them the ability to do anything else — is backup and recovery, not this.
- **The measured term is local only.** Inclusion, repricing, RPC and reorg are
  assumptions about a network, stated so they can be disputed. They have not
  been measured against a live chain, and doing so is a precondition of P12.
