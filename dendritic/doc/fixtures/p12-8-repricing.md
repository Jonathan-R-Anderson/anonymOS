# P12-8 fixture — repricing, measured on Ethereum Mainnet

**Term: `repricing`. Budgeted 30m. Worst observed 48s. VALIDATED — with the
limitation in §"What this does not establish", which is not optional context.**

Thirty full recovery cycles, really sent, really mined. Raw capture:
`storage-client/internal/channel/testdata/p12-8-repricing-mainnet.json`.
Scored by `TestMainnetRepricingFitsItsBudget`. Protocol:
`doc/p12-8-repricing-protocol.md`, approved before the campaign ran.

## Provenance

| | |
|---|---|
| Chain | Ethereum Mainnet, chain ID 1 |
| Account | `0xB9727D31F59D7D5C69578642B5124Fb1fC033866` (dedicated to P12-8) |
| Original | EIP-1559, `maxFeePerGas` = 50% of base fee — arithmetically unmineable |
| Replacement | same nonce, priority 0.1 gwei, `maxFeePerGas` = 2 × base + tip |
| Trigger | one block produced without inclusion |
| Recovery | original submission block timestamp → replacement inclusion block timestamp |
| Blocks spanned | 25,738,753 – 25,738,820 |
| Base fee during the run | 0.088 – 0.139 gwei |
| Concurrency | one pending transaction at a time; no nonce gaps |
| Provider | Alchemy mainnet |
| **Total spent** | **0.000133743 ETH** |
| Worst case had every replacement paid its cap | 0.000241311 ETH |
| Tool | `storage-client/cmd/p12reprice` |

## Result

| statistic | value |
|---|---|
| attempts | 30 |
| **valid samples** | **30** |
| **discarded** | **0** |
| min | 24s |
| median | 24s |
| p95 | 36s |
| **max (the evidence)** | **48s** |

Recovery distribution: 24s ×26, 36s ×3, 48s ×1 — that is 2 blocks ×26, 3 ×3,
4 ×1. Every sample: original never mined, replacement `status 0x1`, nonce
advanced by exactly one.

`Evidence.Measured` is the **worst** sample, 48s. Against the 30-minute term
that is 2.67% of budget.

## Zero discards is a result, not an absence of one

The protocol predicted discard condition 1 (base fee falls and the original
mines) would be rare on arithmetic grounds: EIP-1559 caps a single-block base
fee decrease at 12.5%, and the original was priced at 50% of base, so it cannot
become mineable inside the one-block window. It never did, across 30 attempts.

Attempts, valid and discarded are all recorded and cross-checked — a test
asserts `attempts == valid + discarded`, so samples cannot go missing between
the campaign and the evidence.

## The measured quantity, stated plainly

```text
recovery  =  one block (trigger)  +  replacement inclusion
             ~12s, protocol         24s median total
```

This was predicted before the campaign and is visible in the result: 26 of 30
samples are exactly two blocks. **The number is close to "inclusion plus one
block" by construction**, because the trigger delay is fixed by protocol rather
than left to operator latency.

That is deliberate. The alternative — letting the replacement decision drift —
measures how fast the operator noticed, not how fast Ethereum recovers. The
exploratory run made the case: its 300s recovery was ~288s of me deciding and
~12s of chain.

So what these 30 samples establish is the **distribution** of a repricing cycle
whose policy is pinned, not a discovery of some unknown network latency. The
tail is the interesting part: 3 samples took an extra block and 1 took two
extra, at a base fee that rose to 0.139 gwei mid-campaign.

## What this does NOT establish

**This is not a measurement of sustained mainnet congestion.** It measures
recovery from an *arithmetically unmineable* transaction under the fee
conditions observed during the run — a calm market, 0.088–0.139 gwei, blocks not
full.

It says nothing about how the replacement behaves when the fee market is moving
fast enough that the replacement itself becomes underpriced — the recursive
case, which is the scenario the 30-minute term was sized for. That headroom
remains an unvalidated judgement.

The limitation is enforced structurally, not editorially:
`RepricingObservation.AsEvidence` refuses a campaign that does not state its fee
conditions, and embeds them plus an explicit congestion disclaimer inside
`Evidence.Method`, so the figure cannot be quoted apart from its regime.
`TestRepricingEvidenceCarriesItsConditions` pins that.

## The guards

| refusal | why |
|---|---|
| a sample whose original was **mined** | Then nothing was repriced. The cycle "completes" fast for the one reason that makes it meaningless, and admitting it drags the distribution toward zero with samples where the mechanism never ran |
| a sample whose replacement **failed or reverted** | A failed recovery is not a recovery, however quickly it was mined |
| a campaign with **no stated conditions** | The number is only meaningful relative to its fee market, and would otherwise be read as a general claim |

Same family as `ReorgObservation.AsEvidence` refusing "no reorgs observed" and
`InclusionObservation.AsEvidence` refusing an abandoned transaction: in each,
something that is not a measurement is being offered as one.

## Reproducing

```sh
export ETH_RPC_URL=... P12_MEASUREMENT_PRIVATE_KEY=... OUT=run.json
go run ./cmd/p12reprice
```

Hard spend ceiling 0.0012 ETH; the campaign stops before a sample that would
cross it. The funded balance is a ceiling, not a target.

## Samples

| # | original | replacement | submit blk | base gwei | orig maxFee gwei | repl maxFee gwei | incl blk | recovery | gas paid ETH |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `0xfb2fd0fccf66…` | `0x86f41eae9ad0…` | 25738755 | 0.1028 | 0.0514 | 0.2893 | 25738757 | 24s | 0.000004283 |
| 2 | `0xa7c3ddb36652…` | `0xb5c89777888c…` | 25738757 | 0.1040 | 0.0520 | 0.3144 | 25738759 | 24s | 0.000004194 |
| 3 | `0x5323e788134b…` | `0xf0c44175e7ea…` | 25738759 | 0.0997 | 0.0499 | 0.3140 | 25738761 | 24s | 0.000004406 |
| 4 | `0x83c7d2d31d57…` | `0x99d95db06877…` | 25738761 | 0.1098 | 0.0549 | 0.3173 | 25738763 | 24s | 0.000004239 |
| 5 | `0x78ef3bb600a3…` | `0xd7ca1b277cea…` | 25738763 | 0.1018 | 0.0509 | 0.3215 | 25738765 | 24s | 0.000004274 |
| 6 | `0xa1f3a612cab1…` | `0x2b77ffcfa7d7…` | 25738765 | 0.1035 | 0.0518 | 0.3181 | 25738767 | 24s | 0.000004221 |
| 7 | `0xe2a1c7d055e5…` | `0xce593af1a7dc…` | 25738767 | 0.1010 | 0.0505 | 0.3217 | 25738769 | 24s | 0.000004438 |
| 8 | `0x3dd5bc4b5505…` | `0xe74d1e9b341c…` | 25738769 | 0.1113 | 0.0557 | 0.3144 | 25738771 | 24s | 0.000004474 |
| 9 | `0xb9b8bd3c873a…` | `0x346439724abb…` | 25738771 | 0.1131 | 0.0565 | 0.3172 | 25738773 | 24s | 0.000004451 |
| 10 | `0x7ca4f2f1e2ab…` | `0x4546d6be694f…` | 25738773 | 0.1119 | 0.0560 | 0.3164 | 25738776 | 36s | 0.000004179 |
| 11 | `0xa9052c9f8e2c…` | `0x7c5ff05cd030…` | 25738776 | 0.0990 | 0.0495 | 0.3122 | 25738778 | 24s | 0.000004356 |
| 12 | `0xc3e1b99c9ef8…` | `0x4ae0de076efa…` | 25738778 | 0.1074 | 0.0537 | 0.3322 | 25738780 | 24s | 0.000004811 |
| 13 | `0x04af33ecffe5…` | `0x5be1975eef6a…` | 25738780 | 0.1291 | 0.0646 | 0.3657 | 25738782 | 24s | 0.000004848 |
| 14 | `0x03a5a4d9226b…` | `0x5e413a33194d…` | 25738782 | 0.1308 | 0.0654 | 0.3735 | 25738784 | 24s | 0.000005023 |
| 15 | `0xa19ec0709629…` | `0x619f47e02710…` | 25738784 | 0.1392 | 0.0696 | 0.3830 | 25738787 | 36s | 0.000004711 |
| 16 | `0x33b384574af7…` | `0xd8830e052b11…` | 25738787 | 0.1244 | 0.0622 | 0.3731 | 25738789 | 24s | 0.000004999 |
| 17 | `0x919a5a33fcae…` | `0xed5d10370828…` | 25738789 | 0.1381 | 0.0690 | 0.3774 | 25738791 | 24s | 0.000004971 |
| 18 | `0xf319a955a7bc…` | `0x4db531b49689…` | 25738791 | 0.1367 | 0.0684 | 0.3698 | 25738793 | 24s | 0.000004683 |
| 19 | `0x44e1c5bff296…` | `0x57c50525ce93…` | 25738793 | 0.1230 | 0.0615 | 0.3614 | 25738795 | 24s | 0.000004844 |
| 20 | `0xedb4867d3bba…` | `0x56e5cfc96d31…` | 25738795 | 0.1307 | 0.0653 | 0.3560 | 25738797 | 24s | 0.000004791 |
| 21 | `0x5c7fc15f2c98…` | `0xf70ff440959c…` | 25738797 | 0.1281 | 0.0641 | 0.3615 | 25738799 | 24s | 0.000004854 |
| 22 | `0x91a7257962e5…` | `0x3898e71aae21…` | 25738799 | 0.1311 | 0.0656 | 0.3551 | 25738801 | 24s | 0.000004705 |
| 23 | `0xaf112ec45d5b…` | `0xd5c6c28958c7…` | 25738801 | 0.1240 | 0.0620 | 0.3466 | 25738805 | 48s | 0.000004217 |
| 24 | `0x35f915ed0c9f…` | `0x4d388b8fe8c8…` | 25738805 | 0.1008 | 0.0504 | 0.3254 | 25738807 | 24s | 0.000004301 |
| 25 | `0x36d39d594194…` | `0x0f7d3c601a80…` | 25738807 | 0.1048 | 0.0524 | 0.3107 | 25738809 | 24s | 0.000004334 |
| 26 | `0x2b96272b1610…` | `0xbf236ac7e9f8…` | 25738809 | 0.1064 | 0.0532 | 0.3042 | 25738812 | 36s | 0.000004016 |
| 27 | `0x7b78d09246b9…` | `0xf8f6638d6bfa…` | 25738812 | 0.0912 | 0.0456 | 0.2904 | 25738814 | 24s | 0.000004134 |
| 28 | `0xabb667a825df…` | `0x4a349b04466f…` | 25738814 | 0.0968 | 0.0484 | 0.2945 | 25738816 | 24s | 0.000004054 |
| 29 | `0xc6864483e185…` | `0x241bfd14974e…` | 25738816 | 0.0931 | 0.0465 | 0.2809 | 25738818 | 24s | 0.000003949 |
| 30 | `0x64fd23cced16…` | `0xc33c4355c96d…` | 25738818 | 0.0881 | 0.0440 | 0.2770 | 25738820 | 24s | 0.000003984 |
