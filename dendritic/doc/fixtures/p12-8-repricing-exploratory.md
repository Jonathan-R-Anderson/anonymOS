# P12-8 exploratory — a transaction below the base fee

**EXPLORATORY. No Evidence filed. Counts toward no sample. Nothing in the
protocol, budget, evidence rules or deployment gate was changed.**

The question: does a transaction whose `maxFeePerGas` is below the current base
fee get stopped by our send path, and if so, where?

Answer: **it is not stopped anywhere.** It signs, it is admitted by the RPC, it
propagates, and it sits in the mempool unmined because no block can legally
include it.

## Pre-submission record

| field | value |
|---|---|
| head block | 25,738,709 |
| base fee | 96,335,525 wei (0.0963 gwei) |
| `maxFeePerGas` | 48,167,762 wei (0.0482 gwei) — **50% of base** |
| `maxPriorityFeePerGas` | 1 wei |
| nonce | 31 |
| type | `0x02` (EIP-1559) |
| gas limit | 21,000 |
| to / value | self (`0xB972…3866`) / 0 |
| provider | Alchemy mainnet |

Submitted through `channel.RawTxSender.Send` — the production path — so the
layer named below is a real one.

## Layer by layer

| layer | outcome |
|---|---|
| wallet signing | **OK** — 105 bytes, hash `0xdc1914e7…6b97f` |
| local validation | **OK** — and only because `RawTxSender` performs no fee checks at all |
| RPC admission | **ACCEPTED** — returned the hash, no error |
| propagation | **PENDING IN POOL** — `eth_getTransactionByHash` returns it with `blockNumber: null` |
| inclusion | **NOT INCLUDED** — still pending 8+ blocks later |

I expected the RPC to reject this. It did not. Alchemy admitted a transaction
that cannot be mined at the prevailing base fee, and the mempool is holding it.

The block is refusing it, not any component we control or any component the
provider controls. A block whose base fee exceeds a transaction's
`maxFeePerGas` cannot include that transaction — it is a consensus rule, which
is why no layer above it needed an opinion.

## The observation worth noting about our own path

`RawTxSender` has no fee validation. It signs whatever the injected `SignTx`
produces and posts it. That is defensible — fee policy belongs to whoever owns
the key, not to the transport — but it does mean **an underpriced settlement
transaction leaves this system without complaint** and is discovered only by
watching for a receipt that never comes.

Recorded as an observation. Not acted on: adding a check here would change the
production path being measured.

## Complete lifecycle, including recovery

The exploratory transaction was recovered by replacement. **This is not a
measurement sample and counts toward none of the 30.**

| stage | value |
|---|---|
| original submission | block 25,738,709 (ts 1786535183) |
| original `maxFeePerGas` | 48,167,762 wei (0.0482 gwei) |
| original priority fee | 1 wei |
| base fee at submission | 96,335,525 wei (0.0963 gwei) |
| original hash | `0xdc1914e7…6b97f` |
| blocks pending | **24** (25,738,709 → 25,738,733) |
| time pending | **300s** |
| replacement submitted | block 25,738,732 |
| replacement `maxFeePerGas` | 244,150,706 wei (0.2442 gwei) |
| replacement priority fee | 100,000,000 wei (0.1 gwei) |
| replacement hash | `0x3e8497d0…3338f` |
| replacement inclusion | block 25,738,733, status `0x1` |
| effective gas price paid | 0.1774 gwei |
| fee paid | 0.000003725 ETH |
| **total recovery time** | **300s** (original submission → replacement inclusion) |

Replacement rule satisfied on both caps, checked before sending:

```text
maxFeePerGas  48,167,762 -> 244,150,706   needed >= 52,984,538   ok
priorityFee            1 -> 100,000,000   needed >= 1            ok
includable at base 0.0721 gwei                                   ok
```

The replacement was mined in the **next block** after submission.

### The 300s is mostly me, and that matters

Of the 300 seconds, roughly 12 were the replacement reaching a block. The rest
was the interval between establishing that the transaction was stuck and
deciding to replace it — an operator-latency figure, not a property of Ethereum.

This is the central design problem for the campaign and is dealt with in the
protocol below.

## Account state after recovery

```text
original     0xdc1914e7…6b97f   NO RECEIPT — never mined, now unmineable
replacement  0x3e8497d0…3338f   mined, block 25,738,733, status 0x1
nonce        latest 32, pending 32 — no backlog
balance      0.002382367 ETH
```

### Pool visibility is not authoritative

`eth_getTransactionByHash` still returns the original with `blockNumber: null`
even though its nonce is consumed and it can never be mined. The provider's pool
view lags and cannot be used to decide whether a transaction is unconfirmed.

**The authoritative signals are the receipt and the account nonce**, and the
sample-validity rules below are written against those.

**No funds are stranded.** The transaction carries `value` 0, so nothing is
locked in it; the account's entire balance is untouched and spendable. The only
consequence is that nonce 31 is occupied, so nothing else can be sent from this
account until that nonce resolves.

Two ways it resolves:

1. **By itself** — if the base fee falls to ≤ 0.0482 gwei the transaction
   becomes mineable and will be included. Mainnet base fee reaches that level
   during quiet periods, so this is a live possibility rather than a theoretical
   one. It was 0.0838 gwei at the time of writing.
2. **By replacement** — a same-nonce transaction at a higher fee. That action
   *is* the repricing event, and it was deliberately not taken.

No replacement was sent, and the transaction has not been manipulated.

## What this means for the 30-sample campaign — proposed, not adopted

The stuck condition the campaign needs is now demonstrably producible on mainnet
without manufacturing congestion and without a nonce gap: set `maxFeePerGas`
below the prevailing base fee and the transaction stays pending on its own.

That is a change to the repricing protocol — it drives `maxFeePerGas` rather
than the priority fee — and it is **not adopted here**. It is also not free of
questions worth settling before it becomes the method:

- The stuck threshold is currently "3 blocks". With a below-base-fee transaction
  the transaction is stuck until the market moves, so the threshold stops being
  the thing that decides and the measurement becomes "how long from declaring
  it stuck to the replacement landing". That is arguably the right measurement,
  but it is a different one.
- Each sample leaves a pending transaction that must be replaced to advance the
  nonce, so the campaign's failure mode is a blocked account rather than a lost
  fee.
- A sample where the underpriced transaction gets mined mid-experiment (because
  the base fee fell) is not a successful sample and must be discarded, not
  recorded as a fast one.

## Standing

`repricing` remains **NOT MEASURED**. No `Evidence` was constructed from this
experiment. The 30-minute term, the evidence rules, the 3-block threshold and
the deployment gate are all unchanged.
