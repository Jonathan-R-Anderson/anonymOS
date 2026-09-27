# P14.6g — PAYG measured: the throughput bottleneck is gone

**Answer: YES.** Under the same workload and protocol, unthrottled and with
**zero rate limiting**, a one-week catch-up now measures **37m 33s** against the
existing 4-hour requirement — **15.6% of budget**, down from ~9h 54m.

Nothing else changed. `challengePeriod`, every challenge-budget term, the 4-hour
Outage term, the verification boundary and the deployment gate are all untouched,
and no RPC fallback exists or was added.

---

## Endpoint verification

| check | Free (before) | PAYG (now) |
|---|---|---|
| 25 concurrent `eth_getBlockReceipts` | 13 served / 12 × HTTP 429 | **25 served / 0 refused** |
| highest clean sustained rate | **1.00/s** | **≥ 29.54/s** — ceiling not reached |
| effective throughput CU/s | 500 | **14,769** |

Measured with an **offered-rate** probe (each request on its own schedule rather
than sequentially — a sequential prober tops out at 1/latency ≈ 12/s and would
have reported its own bound as the provider's):

```text
offered  5/s -> served  4.99/s   0 refused   CLEAN
offered 10/s -> served  9.95/s   0 refused   CLEAN
offered 15/s -> served 14.83/s   0 refused   CLEAN
offered 20/s -> served 19.77/s   0 refused   CLEAN
offered 25/s -> served 24.70/s   0 refused   CLEAN
offered 30/s -> served 29.54/s   0 refused   CLEAN
```

**The upgrade exceeds its own specification.** 29.54/s × 500 throughput CU =
14,769 CU/s against a documented 10,000 CU/s cap. Either the cap is higher than
published or `eth_getBlockReceipts` costs less than 500 throughput CU on this
plan. **I did not find the ceiling** — 30/s is simply more than the workload
needs, so I stopped rather than spend CU hunting it.

**One discrepancy, reported rather than explained away:** `debug_traceBlockByNumber`
and `trace_block` still return *"not available on the Free tier"*. Throughput is
unambiguously upgraded, so this is most likely a separate Debug/Trace entitlement
rather than a stale plan. Neither method is used by any of our code, so it does
not affect this result — but the message is inconsistent with the plan state and
is worth a glance in the dashboard.

## The catch-up — clean

Same workload, same protocol, unthrottled (`MinInterval: 0`), same 2,000 blocks,
same `MaxBatch`/`BatchSize` of 100, same `MaxRetries: 5`.

| | Free (previous) | **PAYG (measured)** |
|---|---:|---:|
| blocks caught up | 2,000 | **2,000** |
| **elapsed wall-clock** | 23m 33.4s | **1m 29.4s** |
| per block | 706.7 ms | **44.7 ms** |
| `eth_getBlockReceipts` calls | 929 | **877** |
| `eth_getBlockByNumber` calls | 1,999 | **1,999** |
| **CU consumed** | 58,560 | **57,520** |
| **effective receipts/sec** | 0.657 | **9.81** |
| **HTTP 429 responses** | 476 | **0** |
| **retries** | 428 | **0** |
| **backoff time** | ≥ 856 s | **0 — no refusal was ever entered** |
| batch shrinks | 48 | **0** (settled at 99) |
| bloom skip rate | 54% | 56% (1,123/2,000) |

**This is a CLEAN result** by the stated definition: zero rate-limit events, zero
provider-caused retries, zero backoff.

Corroborated by the latency distribution rather than asserted — a call that had
waited on a backoff would appear as a multi-second outlier:

```text
receipt call latency: median 91 ms, p95 124 ms, max 178 ms
calls >= 2s: 0
```

**Improvement: 15.8×** (1,413.4 s → 89.4 s on identical work).

## Against the existing 4-hour Outage budget

```text
one-week equivalent (50,400 blocks) at the measured 44.7 ms/block
  = 37m 33s     =  15.6% of the 4-hour budget
  free tier     =  9h 54m  =  248% of it
```

**The requirement is met with 3h 22m of margin.**

**This does not validate the 4-hour term and is not offered as validation.** It
measures one input — catch-up throughput — against one provider, on one day, at
one skip rate. The budget covers more than throughput and is unchanged. Equally,
a passing number does not license *reducing* the budget.

**The deployment gate is not opened by this.** Catch-up performance improving is
not the gate's criterion.

## Where the bottleneck moved

It is no longer the provider:

| | |
|---|---:|
| provider serves, clean | ≥ 29.54 receipts/sec |
| **the follower achieved** | **9.81 receipts/sec** |
| sequential ceiling at 91 ms median | ~11/s |
| time inside receipt calls | 1m 20s of 1m 29s wall (**90%**) |

`ChainFollower.Advance` fetches receipts **one block at a time**, so its ceiling
is `1 / latency` ≈ 11/s regardless of what the provider can serve. It reached
9.81/s — close to its own limit and **3× below the provider's**.

So there is ~3× of headroom available from parallelising receipt fetches. **That
is a code change and it is not needed** — 37 minutes already fits four hours with
large margin — so it is recorded as a known option, not proposed. No production
code was changed.

## Cost at the current fleet workload

From the **measured** 28.76 CU/block and 56% skip rate (not the earlier 20%-hit
assumption, which understated it):

```text
PER WATCHTOWER   7,200 blocks/day x 28.76 CU  =   207,072 CU/day
                                              =     6.22M CU/month
FLEET OF TWO                                  =    12.44M CU/month
```

| | |
|---|---:|
| steady state, 2 watchtowers | 12.44M CU/month → **$5.60/month** |
| one-week catch-up | 1.45M CU → **$0.65** |
| **realistic monthly total** | **~$6.25/month** |

If the 30M free allowance carries over on PAYG, this falls **inside it** and the
cost is **$0** — still worth confirming on the first invoice.

### Does the $25/month alert have adequate headroom?

**Yes, and it matters more now than before.**

| | |
|---|---:|
| expected spend | ~$6.25/month |
| alert | $25/month — **4× headroom** |
| runaway ceiling (loop at 29.54/s × 20 CU) | 591 CU/s = 51M CU/day = **$23/day** |
| time for a runaway to trip the alert | **~1.1 days** |

The runaway ceiling **rose with the throughput** — $23/day now versus $15.55/day
on Free — so the alert is doing more work than it was. $25/month remains the
right threshold: comfortably above normal operation including catch-ups, and it
fires inside about a day on a runaway. A daily alert, if available, would halve
that.

## Volume and throughput remain separate

| | |
|---|---|
| **monthly volume** | 12.44M CU/month projected; was never the constraint |
| **throughput** | was 1.00/s (binding), now ≥29.54/s (not binding) |

The upgrade bought **throughput**. Volume was inside the free allowance before and
is still inside it now.

## Classification

| | class |
|---|---|
| PAYG active: 25/25 concurrent, ≥29.54/s clean | **MEASURED** |
| catch-up 2,000 blocks / 1m29.4s / 877 receipts / 57,520 CU | **MEASURED** |
| 0 × HTTP 429, 0 retries, 0 backoff, 0 shrinks | **MEASURED** |
| receipt latency median 91 ms, p95 124 ms, 0 calls ≥2s | **MEASURED** |
| bloom skip 56% (1,123/2,000) | **MEASURED** |
| one-week equivalent 37m 33s | **DERIVED** from the measured per-block rate |
| 12.44M CU/month, ~$6.25 | **DERIVED** from measured CU/block |
| provider throughput ceiling | **NOT FOUND** — clean at every rate tested |
| **the 4-hour Outage term** | **NOT VALIDATED — and not by this** |
| deployment gate | **UNCHANGED** |
