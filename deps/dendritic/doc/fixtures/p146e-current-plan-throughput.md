# P14.6e — current-plan throughput, measured

**The current plan's throughput is confirmed at exactly 1.00
`eth_getBlockReceipts`/sec (500 CU/s). At the measured bloom skip rate it does
NOT meet the four-hour outage requirement — and no channel activity is needed to
breach it. Mainnet congestion alone already does.**

Nothing upgraded, nothing deployed. No production code, verification boundary,
`challengePeriod`, outage budget or deployment gate changed.

---

## Monthly volume and throughput, reported separately

They are different resources and conflating them buys the wrong plan.

| | |
|---|---|
| **Monthly volume** | 2,785,778 / 30,000,000 CU used; ~27.2M remaining |
| projected fleet steady state | 10.37M CU/month (2 watchtowers) |
| **verdict** | **not a constraint, and never was** |

| | |
|---|---|
| **Throughput** | **1.00 `eth_getBlockReceipts`/sec = 500 CU/s** |
| **verdict** | **this is the binding constraint** |

## Measurement 1 — the actual throughput limit

A **paced** probe: offer a fixed rate, read the refusals. (My first attempt
hammered at fixed concurrency and got 98–100% refusals at every rung — that
measures what happens when you spam a provider, not what it will sustain.)

| offered | ok | refused | HTTP 429 | served | |
|---:|---:|---:|---:|---:|---|
| 0.5/s | 15 | 0 | 0 | 0.50/s | **clean** |
| **1.0/s** | **30** | **0** | **0** | **1.00/s** | **clean** |
| 1.5/s | 37 | 8 | 8 | 1.23/s | refusals |
| 2.0/s | 39 | 21 | 21 | 1.30/s | refusals |
| 3.0/s | 23 | 67 | 67 | 0.76/s | refusals |

**Exactly 1.00/s clean.** The documented 500 CU/s cap and 500 throughput-CU
weight for `eth_getBlockReceipts` are both precisely right, now confirmed rather
than assumed.

The ceiling is hard and **punitive above it**: offering 3/s *served fewer*
requests than offering 1/s, because refused requests still consume budget.

Refusals arrive as **HTTP 429**. Alchemy exposes no rate-limit headers.

## Measurement 2 — the confirmatory catch-up, unthrottled

`MinInterval: 0`, exactly as requested. **This is not a clean throughput result
and is not filed as one** — the test fails its own assertion because refusals
occurred.

| | measured |
|---|---:|
| blocks | 2,000 |
| **elapsed** | **23m 33.4s** (706.7 ms/block) |
| **receipt calls** | **929** |
| header calls | 1,999 |
| **CU consumed** | **58,560** (29.28 CU/block, **$0.026**) |
| **HTTP 429 / rate-limit events** | **476** |
| **retries / backoff** | **428 retries, 48 batch shrinks** |
| bloom-skipped | 1,071 / 2,000 (54%) |
| **effective throughput** | **0.657 receipts/sec** |
| effective throughput CU/s | 357 of a 500 cap |

**Running unthrottled is worse than pacing: 0.657/s achieved versus 1.00/s
clean.** 476 refusals and 428 backoffs left the connection idle for a third of
the budget. If this workload is ever wired into production, `MinInterval` must
pace it at ~1/s rather than letting it race the limiter.

Extrapolated from this throttled rate: one week = **9h 54m**.

## Measurement 3 — the skip rate was wrong, and it matters

The 4-hour budget's viability turns entirely on the bloom skip rate, and my
earlier figure was drawn from samples too small to decide it.

| sample | blocks | skip rate |
|---|---:|---:|
| bloom sample (P14.6b) | 100 | 82% |
| catch-up (P14.5) | 200 | 80% |
| bloom rate (P14.6b) | 60 | 75% |
| confirmatory catch-up | 2,000 | 54% |
| **authenticated sample** | **3,000** | **56.0%** |

**Break-even is 75.4%.** The small samples and the large ones fall on *opposite
sides of the line*, so the early figure was not merely imprecise — it pointed the
wrong way.

Why: average bloom saturation is **69.2%**, not the 57–60% the small samples saw.
The distribution over 3,000 blocks:

```text
  60-70%:  671 blocks
  70-80%:  733     <- largest bucket
  80-90%:  685
  90-100%: 213
```

At 80% saturation a three-hash bloom false-positives 51% of the time; at 90%,
73%. The early samples caught quiet windows.

## What that means against the 4-hour budget

At the measured 1.00 receipts/sec:

```text
one-week catch-up, by skip rate           total     vs 4h budget
  56.0%  (3,000-block sample, MEASURED)   6.72 h        168%
  75.4%  (break-even)                     4.00 h        100%
  82%    (small sample, superseded)       3.08 h         77%
```

**At the measured skip rate the requirement is missed by 68%** — 6h 43m paced,
9h 54m as actually measured unthrottled.

## The upgrade trigger

The trigger was meant to be "watch for channel activity pushing the skip rate
under 75.4%". It cannot be, because:

```text
skip = (1 - ourEmitRate) x (1 - falsePositiveRate)
false-positive rate, measured: 33-44%
```

**The false-positive floor alone already puts skip below break-even. Zero channel
activity is required to breach it — other people's mainnet congestion did.**

So the operational trigger is not a channel-activity threshold. The measured
statement is:

> **The current throughput does not meet the four-hour outage requirement today,
> with an idle contract.** It is breached by mainnet bloom saturation, which we
> do not control and cannot reduce.

For monitoring rather than triggering, the quantity to watch is
`chain_blocks_skipped_by_bloom / chain_blocks_authenticated` — both already
exported by the P14.5 metrics layer. Sustained below **75%** means a one-week
catch-up will not fit four hours. It is currently ~56%.

If our contract *does* become active, it compounds: at a 33% false-positive floor
the contract may emit in at most **0%** of blocks before breach — there is no
headroom left to spend.

## What this does and does not establish

| | class |
|---|---|
| throughput = 1.00 receipts/sec clean, 429 above | **MEASURED** |
| unthrottled achieves 0.657/s — worse than paced | **MEASURED** |
| catch-up: 2,000 blocks, 23m33s, 929 receipts, 58,560 CU, 476 × 429, 428 retries | **MEASURED** |
| skip rate 56.0% over 3,000 authenticated blocks | **MEASURED** |
| bloom saturation 69.2% average, distribution above | **MEASURED** |
| one-week catch-up 6.72 h paced / 9h 54m unthrottled | **DERIVED** from the above |
| break-even skip rate 75.4% | **DERIVED** |
| **the 4-hour outage term itself** | **NOT VALIDATED — and nothing here validates it** |

**The four-hour budget is unchanged.** These measurements cover one input to it —
catch-up throughput — against one provider over one window. That is not the same
as validating the term, and a number that misses the budget does not license
changing the budget either.

## Recommendation

The stated condition for upgrading was *"unless the measurement demonstrates that
the current throughput limit is actually preventing the required catch-up
performance."*

**It does.** 6h 43m against a 4-hour requirement, with an idle contract, caused by
congestion we do not control. On PAYG's 10,000 CU/s the same work is **~20
minutes** (~8% of budget), and at our volume costs about **$5/month**.

I have not upgraded and cannot — it needs your dashboard. The decision is now
supported by measurement rather than projection.

**Correction on the record:** my interim report said 3h 22m fits inside four
hours and recommended not upgrading. That used the 75–82% skip rate from 60–200
block samples. The 3,000-block sample says 56%, and the conclusion inverts.
