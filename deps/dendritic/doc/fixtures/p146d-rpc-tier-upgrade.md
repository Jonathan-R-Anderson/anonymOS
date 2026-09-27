# P14.6d — RPC throughput upgrade: pre-change record

**Option A accepted. This documents the expected cost and the alert threshold
BEFORE anything changes, so the post-upgrade measurement has something to be
checked against rather than compared to a memory.**

**Status: waiting on the account change, which I cannot make.** The upgrade and
the billing alert live in the Alchemy dashboard behind billing details. Steps for
you are at the end.

---

## What we are actually buying

**Throughput, not volume.** This is the crux and it is worth being exact:

| | billed CU | throughput CU |
|---|---:|---:|
| `eth_getBlockReceipts` | 20 | **500** |
| `eth_getBlockByNumber` | 20 | 20 |
| `eth_getProof` | 20 | 20 |

The free tier allows **500 CU/s**, so `eth_getBlockReceipts` costs the entire
per-second budget: **exactly one call per second.** That is the whole of the
measured 3h 24m — 90% of it was backoff against that ceiling.

Pay-As-You-Go raises the cap to **10,000 CU/s → 20 receipt fetches/sec, a 20×
increase.**

## Expected monthly consumption, from the measured workload

Derived from measured inputs, not assumed: 7,200 blocks/day (12s slots) and the
**20% bloom-hit rate measured in P14.5** (159 of 200 blocks skipped).

`ChainFollower.Advance` makes **zero** provider calls when the finalised head has
not moved, and finality advances one epoch (~6.4 min) at a time. The beacon calls
go to lodestar and cost nothing here.

```text
PER WATCHTOWER, STEADY STATE
  headers   7,200/day x 20 CU  =  144,000 CU/day
  receipts  1,440/day x 20 CU  =   28,800 CU/day
                                 ---------------
                                   172,800 CU/day  =  5.18M CU/month

FLEET OF TWO (the declared P12-8 envelope)   10.37M CU/month
```

**10.37M CU/month is 35% of the free tier's own 30M allowance.** We were never
near a volume limit. We are buying speed, not headroom.

| | CU | cost at $0.45/M |
|---|---:|---:|
| steady state, 2 watchtowers | 10.37M/month | **$4.67/month** |
| one-week catch-up | 1.21M | **$0.54** |
| steady state + one catch-up/month | 11.58M | **$5.21/month** |

**Expected monthly cost: about $5.** One caveat to confirm at signup — if PAYG
carries the 30M free allowance, our usage falls entirely inside it and the cost
is **$0**. The published pricing page describes PAYG as usage-based with no
allowance, so $5 is the figure to plan against.

## The billing alert

Sized against what a runaway would actually cost, not picked round:

```text
RUNAWAY CEILING — a loop fetching receipts flat out at PAYG throughput
  20 fetches/sec x 20 CU = 400 CU/s
  = 34.6M CU/day = $15.55/day = $467/month
```

| | |
|---|---|
| expected spend | ~$5/month |
| **recommended alert** | **$25/month** |
| what that catches | a runaway within ~2 days, at ~5× expected spend |

A daily threshold as well, if the dashboard offers one, would catch it inside
24 hours. PAYG has **no spending cap** — the alert is the only backstop, which is
why it goes in before the tier change rather than after.

## Verification boundary: unchanged, and structurally so

Nothing about this touches verification. The endpoint is a string; the gate is
code. Switching providers or tiers changes **which untrusted party supplies
bytes**, and every byte still goes through `AuthenticateReceipts`,
`AuthenticateHeader` and `VerifyProof` against roots the beacon light client
authenticates.

Demonstrated rather than asserted, in P14.6b: local-node and Alchemy data went
through the identical path, and a tampered local receipt was still refused.

**No RPC fallback is being introduced.** There is none today and none is added.
The rule stands: a failure to authenticate is never answered by believing
somebody instead.

## The change surface is smaller than it sounds

Checked rather than assumed:

```text
ETH_RPC_URL consumed outside tests : NONE
RPCSource wired into a binary      : NOT YET
```

`RPCSource` was built in P14.5 and is not yet in a running binary; V2 deployment
remains gated. **There is currently no production configuration to change.** The
key lives in `.env` (tracked, private repo), and today only tests read it.

So this upgrade carries no production risk. It changes what the *measurement*
can do, and it pre-positions the config for when the watchtower is wired up.

---

## What has to happen, and by whom

**You, in the Alchemy dashboard:**

1. Upgrade the app from Free to **Pay As You Go** (500 → 10,000 CU/s).
2. Set a **billing alert at $25/month**, plus a daily one if offered.
3. Confirm whether the 30M free allowance carries over — it decides whether the
   bill is ~$5 or $0.
4. If the upgrade issues a new key/URL, update `ETH_RPC_URL` in `.env`.

**Me, afterwards:**

```sh
P146D=1 CHAIN_PROBE=1 ETH_RPC_URL=... BEACON_API_URL=... P146D_BLOCKS=2000 \
  go test ./internal/ethproof/ -run TestP146DCatchUp -v -timeout 60m
```

The harness is written and ready (`internal/ethproof/p146d_cu_test.go`). It runs
**unthrottled** — `MinInterval: 0` — because the question is whether the limit
still binds. It reports:

- measured ms/block and total catch-up time;
- **rate-limit events, counted separately**, and it **fails the test if any
  occur** — if refusals remain, the measured time still contains backoff and must
  not be reported as clean;
- **actual CU consumed**, counted per method invocation (a 100-header batch is
  100 billable invocations, not one), against the projection above;
- extrapolation to 1h / 24h / 1 week from the measured per-block rate.

## What this does NOT establish

Stating it plainly because the temptation is real:

> **The 4-hour outage budget is not validated by any of this.** The projection
> says PAYG *should* bring one-week catch-up to ~20 minutes. That is a
> projection. Until the measurement above has run against the upgraded endpoint,
> `Outage` and `challengePeriod` stay exactly as they are.

A measured catch-up time is also not a validated outage budget on its own — it is
one provider, on one day, under one load. The budget covers more than throughput.

### Classification

| | class |
|---|---|
| free tier = 500 CU/s; `eth_getBlockReceipts` = 500 throughput CU | published (Alchemy) |
| 20% bloom-hit rate | **MEASURED** (P14.5, 159/200 skipped) |
| `Advance` makes no calls when finality has not moved | **MEASURED** (our code) |
| 10.37M CU/month for a two-watchtower fleet | **DERIVED** from the above |
| ~$5/month expected, $25/month alert | **DERIVED** from published weights |
| runaway ceiling $15.55/day | **DERIVED** |
| **catch-up time on the upgraded tier** | **NOT MEASURED — pending the upgrade** |
| **actual CU consumed in a real catch-up** | **NOT MEASURED — pending the upgrade** |
| outage budget validity | **NOT ESTABLISHED, and not by this** |
