# P12-8 fixture — repricing, attempt 1: condition NOT observable

**Term: `repricing`. Budgeted 30m. NOT MEASURED. The prescribed stuck condition
did not occur.**

This is a negative result, recorded because it is evidence about the method
rather than about the chain, and because the obvious next steps are all ones
that would quietly change what is being measured.

## The protocol, as specified

| | |
|---|---|
| Priority fee | 1 wei |
| Chain | Ethereum Mainnet, chain ID 1 |
| Account | `0xB9727D31F59D7D5C69578642B5124Fb1fC033866` |
| Transaction | self-to-self, `value` 0, 21,000 gas |
| Replacement | same nonce, tip ≥ 1.5× |
| Stuck threshold | not mined within 3 blocks |

`maxFeePerGas` was set to 2 × base + tip, so the transaction was validly
mineable and paid the builder essentially nothing. Underpriced in the sense that
matters, not malformed.

## What happened

```text
submitted   block 25,738,690   tip 1 wei   maxFee 0.1826 gwei
included    block 25,738,691   +1 block    15s
threshold   would have been declared stuck at block 25,738,693
```

Transaction
[`0x6c4392ccb94570c6432c718ec3cda366c0b4c52bb9dee594317bbcfe4234f78a`](https://etherscan.io/tx/0x6c4392ccb94570c6432c718ec3cda366c0b4c52bb9dee594317bbcfe4234f78a) —
`maxPriorityFeePerGas` 1 wei on chain, effective gas price 0.0846 gwei, which is
the block's base fee plus the 1 wei. Fee paid 0.000001778 ETH.

**The run stopped there, as specified.** No nonce gap was created, the
transaction was not suppressed, and neither the fee nor the 3-block threshold was
adjusted to force a result.

## Why it was included, and why that is the interesting part

```text
block 25,738,690    21% full    139 txs
block 25,738,691    82% full    578 txs   <- included the 1-wei transaction
block 25,738,692    20% full    220 txs
```

The including block was **82% full**. This is not a case of an empty block
sweeping up anything available. A builder assembling a substantially full block
still preferred a transaction offering a 1 wei tip over leaving 21,000 gas
unused, because at 0.09 gwei base fee there was no queue of better-paying
transactions competing for that space.

**A near-zero tip does not make a transaction unmineable on a chain with spare
block space.** Any positive tip beats an empty slot.

## What this says about the measurement, not just the result

The term being validated is *"a transaction that was underpriced and has to be
replaced"*. The protocol probes that by driving the **priority fee** to
approximately zero — but the priority fee is not the variable that strands a
transaction. A transaction becomes genuinely unmineable when its
`maxFeePerGas` falls below the prevailing **base fee**, which is what happens
when a fee estimate is overtaken by a rising market. That is the real failure
mode the budget term describes, and this protocol does not exercise it.

Stating that is not the same as acting on it. Changing which variable is driven
is a change to the measurement protocol and is held pending approval.

## Options, none implemented

| # | Approach | What it would measure | Cost |
|---|---|---|---|
| 1 | `maxFeePerGas` below current base fee | The real underpricing failure. Most providers reject such a transaction at submission, and that rejection is itself a finding | Cheap; may not be submittable |
| 2 | Wait for genuine congestion, then run the campaign unchanged | The real thing under real conditions. The only option requiring no protocol change | Unbounded wait — days to weeks |
| 3 | Nonce gap | The replacement *mechanics* only. The stuck state comes from ordering, not from fees, so it does not measure a fee market at all | Cheap; changes the meaning of the term |
| 4 | Decompose the term analytically | `repricing ≤ stuck threshold + inclusion`, both known (≈36s + 33s) | Free, but it is a derivation, not a measurement — it would change what counts as validated |

Options 3 and 4 both weaken the claim while looking like progress, which is
precisely the failure the evidence rules exist to prevent. Option 4 in
particular would require redefining a validated measurement, and that is out of
scope by instruction.

## Standing

`repricing` remains **NOT MEASURED**. The 30-minute term is unchanged, the
evidence rules are unchanged, and the deployment gate remains closed — it still
refuses on header canonicality first, with `repricing` and `reorg depth`
unvalidated behind it.

An attempt that produced no stuck transaction is not a sample. It is not a fast
sample, and it is not a zero. The same standard applied to inclusion applies
here: an incomplete or abandoned observation is not a successful one.
