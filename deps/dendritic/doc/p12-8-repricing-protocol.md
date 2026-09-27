# P12-8 repricing — revised measurement protocol

**PROPOSED. NOT ADOPTED. No evidence filed. No sample taken.**

Supersedes the 1-wei-tip protocol, which could not produce a stuck transaction
(`doc/fixtures/p12-8-repricing-attempt1.md`). The below-base-fee method was
validated as *producible* by the exploratory run
(`doc/fixtures/p12-8-repricing-exploratory.md`), which is not a sample.

The 30-minute budget, the evidence rules, the deployment gate and the definition
of a validated measurement are all unchanged by this document.

---

## 1. Stuck definition

> A transaction is **stuck** from the moment of submission if its
> `maxFeePerGas` is strictly below the base fee of the chain head at the time of
> submission.

No block-count threshold. The old 3-block rule described a transaction competing
for space; this one describes a transaction that is **arithmetically ineligible**
for any block while the condition holds. Waiting three blocks to say so would
add latency to the measurement without adding information.

Recorded per sample: head block number, its base fee, and the transaction's
`maxFeePerGas`, so the condition is checkable after the fact rather than
asserted.

**Stuck is established from the receipt and the account nonce, never from pool
visibility.** The exploratory run showed `eth_getTransactionByHash` still
reporting a replaced transaction as pending long after its nonce was consumed —
a provider's pool view lags and cannot decide this.

## 2. Replacement fee rule

Same nonce, same sender, same recipient, `value` 0, same 21,000 gas limit.

```text
priority fee   0.1 gwei
maxFeePerGas   2 x base_at_replacement + priority fee
```

This must simultaneously satisfy three constraints, all checked and logged
before the replacement is sent:

| constraint | source |
|---|---|
| `maxFeePerGas` ≥ 1.1 × original | Ethereum client replacement rule |
| `maxPriorityFeePerGas` ≥ 1.1 × original | Ethereum client replacement rule |
| `maxFeePerGas` > current base fee | otherwise the replacement is stuck too |

The ≥1.5× tip rule from the earlier specification is satisfied trivially and by a
very wide margin (1 wei → 0.1 gwei), so it is not a binding constraint here. It
is retained in the checks rather than dropped.

**The replacement fee is the inclusion protocol's fee**, deliberately — so the
replacement leg is measuring the same thing the validated inclusion term
measured, and any difference between them is attributable to the repricing
mechanics rather than to a different fee policy.

## 3. Recovery-time definition

> **recovery = original submission → replacement inclusion**

measured from the timestamp of the block that was head at original submission,
to the timestamp of the block containing the replacement. Block timestamps
throughout; the local clock is used for ordering only, never for the interval.

### The honest problem with this number

Recovery decomposes into:

```text
recovery  =  decide-to-replace  +  build/sign/broadcast  +  replacement inclusion
             ^^^^^^^^^^^^^^^^^                              ^^^^^^^^^^^^^^^^^^^^
             operator policy                                network (already
             NOT a network property                         measured: 33s worst)
```

In the exploratory run recovery was 300s, of which ~12s was the replacement
reaching a block. **The other ~288s was how long I took to decide to replace.**
A campaign that does not pin that term down will measure its own script's
latency thirty times and report it as a property of Ethereum.

So the protocol fixes it:

> **The replacement is submitted as soon as one block has been produced after
> the original submission without including it.** One block, not three: it
> confirms non-inclusion against a real block rather than against a clock, and
> is the smallest delay that does so.

With that pinned, the measured quantity is
`one block (~12s) + replacement inclusion`, and the campaign's spread reflects
network behaviour rather than operator dithering.

**This means the number will be close to the inclusion term plus one block, by
construction.** That is not a defect being hidden — it is what a repricing cycle
costs when the replacement is priced to confirm, and the 30 samples establish
the distribution of it rather than assuming it. If that is not the quantity the
30-minute term is meant to bound, the term needs rethinking rather than the
measurement.

## 4. Sample validity

A sample counts **only** if all five hold. Anything else is **discarded**, not
recorded as fast, slow, or zero.

1. The original was genuinely unmineable at submission — `maxFeePerGas` < base
   fee of the head block, recorded at submission.
2. The original remained unconfirmed until the replacement was sent — no
   receipt, verified immediately before replacing.
3. The replacement was actually required — the original never obtained a
   receipt at any point.
4. The replacement was included — receipt present with `status: 0x1`.
5. The account nonce advanced by exactly one across the sample.

Discard conditions, stated explicitly:

| condition | disposition |
|---|---|
| base fee falls and the original mines before replacement | **DISCARD.** Not a fast repricing sample — no repricing occurred |
| RPC rejects the original at submission | **DISCARD.** Measures admission policy, not a lifecycle |
| original pending but replacement fails or is rejected | **DISCARD.** A failed recovery is not a successful one |
| replacement mines with `status: 0x0` | **DISCARD.** Reverted is not included-successfully |
| campaign aborted mid-sample | **DISCARD** that sample |

Discarded samples are **counted and reported** — a campaign that quietly retries
until it has 30 survivors is selecting for a favourable answer. The report states
attempts, discards, and the reason for each.

Reaching 30 valid samples is what completes the campaign; a run that cannot
reach 30 without excessive discards is a finding about the method, not a
shortfall to be papered over.

## 5. Exposure

| | |
|---|---|
| Account | `0xB9727D31F59D7D5C69578642B5124Fb1fC033866`, dedicated |
| Balance | 0.002382367 ETH |
| Value per transaction | **0** — self-to-self; no ETH is ever in flight |
| Gas limit | 21,000 per transaction |
| Max simultaneously pending | **1** — strictly sequential; a sample completes or is discarded before the next begins |
| Nonce gaps | none, ever |
| Manufactured congestion | none |

**Maximum ETH exposure: the fee expenditure only.** A `value` 0 self-transfer
cannot lose principal; the only way to spend is gas, and the only way to strand
the account is an unresolved nonce, which the one-pending-at-a-time rule and the
mandatory replacement together prevent.

### Expected transaction count

```text
30 samples x 2 transactions (original + replacement)   = 60 submitted
of which mined and billed                              = 30 replacements
originals are never mined and cost nothing             = 30
plus discards and their replacements                   = unbounded but reported
```

### Expected gas expenditure

```text
gas submitted   60 x 21,000  = 1,260,000
gas billed      30 x 21,000  =   630,000
```

Originals cost nothing because a transaction that is never mined is never
charged.

### Expected cost, at observed conditions (base ≈ 0.09 gwei)

| | |
|---|---|
| per sample, effective (0.19 gwei) | 0.000003990 ETH |
| per sample, worst case (0.28 gwei cap) | 0.000005880 ETH |
| **campaign expected** | **0.000119700 ETH** |
| **campaign worst case** | **0.000176400 ETH** |

Headroom against the 0.002382367 ETH balance:

| gas level | worst-case campaign cost |
|---|---|
| current | 0.000176 ETH |
| 2× | 0.000353 ETH |
| 5× | 0.000882 ETH |
| 10× | 0.001764 ETH |
| **13.5×** | **exhausts the balance** |

The tool enforces a hard ceiling and stops before a sample that would cross it,
so a fee spike ends the campaign rather than draining the account. **The funded
balance is a ceiling, not a target.**

## 6. What happens if the base fee falls before replacement

The original becomes mineable and may be included. That is **discard condition
1**: no repricing occurred, so there is nothing to measure. The sample is
dropped and reported as a discard with its reason.

It is not recorded as a fast recovery. A transaction that resolved itself did
not exercise the replacement path, and counting it would pull the measured
distribution toward zero using samples in which the mechanism under test never
ran.

Two mitigations, both cheap:

- Set `maxFeePerGas` to **50% of the current base fee**, as the exploratory run
  did. The base fee would have to halve within one block for the original to
  become mineable; EIP-1559 caps the per-block decrease at 12.5%, so this cannot
  happen inside the one-block window.
- Verify no receipt immediately before sending the replacement, which is
  validity rule 2.

With the one-block replacement delay and a 50% cap, discard condition 1 should
be rare on arithmetic grounds rather than on hope. If it turns out not to be,
that is reportable.

## 7. What this protocol still does not measure

It measures a repricing cycle **at a fee chosen to confirm, in a calm fee
market**. It does not measure recovery during sustained congestion, where the
replacement itself may need repricing — the recursive case. The 30-minute term
was set to cover that scenario and this campaign does not validate that headroom;
it validates that an ordinary repricing cycle does not consume it.

Same limitation the inclusion term carries, stated in the same place, for the
same reason.

---

**Awaiting approval. No samples will be taken until then.**
