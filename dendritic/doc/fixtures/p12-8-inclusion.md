# P12-8 fixture — inclusion, measured on Ethereum Mainnet

**Term: `inclusion`. Budgeted 30m. Worst observed 33s. VALIDATED.**

Thirty transactions, really sent, really mined. Raw capture:
`storage-client/internal/channel/testdata/p12-8-inclusion-mainnet.json`.
Scored by `TestMainnetInclusionFitsItsBudget`.

## Provenance

| | |
|---|---|
| Chain | Ethereum Mainnet, chain ID 1 |
| Account | `0xB9727D31F59D7D5C69578642B5124Fb1fC033866` (dedicated to P12-8; used for nothing else) |
| Transaction | EIP-1559 (type 0x2) self-transfer, `value` 0, 21,000 gas |
| Fee policy | `maxPriorityFeePerGas` 0.1 gwei; `maxFeePerGas` = 2 × base + tip |
| Nonces | 0–29, sequential |
| Blocks spanned | 25,738,610 – 25,738,647 |
| Base fee during the run | 0.070 – 0.084 gwei |
| Broadcast/read endpoint | Alchemy mainnet |
| Total spent | **0.000112130 ETH** of 0.0025 funded (4.5%) |
| Balance after | 0.002387870 ETH |
| Tool | `storage-client/cmd/p12measure` |

The account's private key is held only in the environment. It is not in this
document, the fixture, the tool, the tests, or the repository.

## Result

| statistic | value |
|---|---|
| samples | 30 |
| min | 6s |
| median | 9s |
| p95 | 23s |
| **max (the evidence)** | **33s** |
| blocks waited | 1 block ×22, 2 blocks ×5, 3 blocks ×3 |

`Evidence.Measured` is the **worst** sample, 33s — not the median. Against the
30-minute term that is 1.8% of budget.

## What this does and does not establish

**Establishes:** on mainnet, at a fee deliberately chosen to confirm, a 21,000-gas
transaction reaches a block in seconds, and the 30-minute `inclusion` term has
roughly a 55× margin over the worst of thirty consecutive attempts.

**Does not establish:** behaviour when the fee turns out to be too low. Every
sample here paid 2× the prevailing base fee into a quiet fee market (0.07–0.08
gwei) and every one was mined within three blocks. A transaction that becomes
underpriced after broadcast is the `repricing` term, measured separately, and
nothing in this run bounds it.

**Not a congestion measurement.** The run happened to fall in a calm period. The
30-minute term was chosen to cover sustained congestion and that headroom is
still an unvalidated judgement — what is validated is that ordinary inclusion
does not consume it. The term was **not** lowered to match these numbers; per
the P12-8 terms, measurements do not move the budget.

## The guard

`InclusionObservation.AsEvidence` refuses a run containing any transaction that
was abandoned unconfirmed, rather than reporting the worst of the ones that
landed. Pinned by `TestInclusionEvidenceRefusesAnAbandonedTransaction`.

Taking the maximum over successes is the natural way to write this and it is
wrong: the abandoned transaction is the worst case, and its duration is unknown.
A run with a hole in it does not measure a worst case at all. This mirrors
`ReorgObservation.AsEvidence` refusing to read "no reorgs observed" as "reorg
depth zero" — in both places an absence is being mistaken for a bound.

## Reproducing

```sh
export ETH_RPC_URL=...          # any mainnet execution RPC
export P12_MEASUREMENT_PRIVATE_KEY=...
export OUT=run.json
go run ./cmd/p12measure
```

The tool caps total spend at 0.0012 ETH and stops before a sample that would
cross it, so a fee spike ends the run rather than draining the account. The
funded balance is a ceiling, not a target.

## Transactions

| # | tx hash | submitted @ | included @ | blocks | delay | fee paid (ETH) |
|---|---|---|---|---|---|---|
| 1 | `0x5cdacc19d87fa7b1461b87604f98c6fb191fb2b8eb55ec4ee679ef6f2d3a1826` | 25738608 | 25738610 | +2 | 14s | 0.000003755 |
| 2 | `0x6f938a506e102cd33a617e40e0ac27bf504d30210a6e3c545d748a2e41b858e0` | 25738610 | 25738611 | +1 | 7s | 0.000003784 |
| 3 | `0x713d633746bb8855c5513e9b1b8e426c58013b0da5bdffe0db5b5434b5990f4e` | 25738611 | 25738612 | +1 | 10s | 0.000003763 |
| 4 | `0xd01854250fadf4454c1bf259b28431b8c742cb358c980b01c9b1de5467d10650` | 25738612 | 25738613 | +1 | 6s | 0.000003730 |
| 5 | `0x45a1ee7516b852c5e998c7266dfd548e2d78078caf65b784ef19b6df66d35f60` | 25738613 | 25738614 | +1 | 9s | 0.000003833 |
| 6 | `0x865a4156dbd34feeb4e68df97b486a21bd5eac1bdc85448f830a6526ac70b822` | 25738614 | 25738615 | +1 | 9s | 0.000003865 |
| 7 | `0xbe6e791332638cc27b60df28495f7d22f82d511df5945618d4255acf9ace4d3c` | 25738615 | 25738616 | +1 | 8s | 0.000003878 |
| 8 | `0xb658e473444a31fe90d61509d3b49983fbad32fbb370efdf95e252728eb50ec4` | 25738615 | 25738618 | +3 | 23s | 0.000003762 |
| 9 | `0x1fa67558cf7597ef448b8dcd41bd431f8faf9486434933fa0e6351cace00c64f` | 25738618 | 25738620 | +2 | 22s | 0.000003632 |
| 10 | `0x995c7b253d509ac13c9e0941f4b5f94399acfcf7ee9505cc5ace147b5ca29ab3` | 25738620 | 25738621 | +1 | 9s | 0.000003747 |
| 11 | `0x0b8fbc058669f16dfba794af41dd98944dd8d98954a229fc8b4a5128f5ffa3e1` | 25738621 | 25738623 | +2 | 21s | 0.000003582 |
| 12 | `0x3e60d5bcd45620de706801a61f60e22808779a675af36888e7359cd32310a9f2` | 25738623 | 25738624 | +1 | 8s | 0.000003705 |
| 13 | `0xf549d78dca519fcc60cb648c93250d03dec2c5d1a8ea8c66a0351edbe6d6c110` | 25738624 | 25738625 | +1 | 8s | 0.000003639 |
| 14 | `0xc69c07797d0318b003bf8d98d7c8394a0f9f09041c1022b35ae9413f3ac479ef` | 25738624 | 25738626 | +2 | 10s | 0.000003578 |
| 15 | `0x64bb1f17efd7038a8c493e1315faf696200976f5e117fdbc17609981524924fe` | 25738626 | 25738627 | +1 | 7s | 0.000003744 |
| 16 | `0xaede6f6acfd8a3da5593658f9b12c553be377c0df371aaceced194b0f27bf6a7` | 25738627 | 25738628 | +1 | 9s | 0.000003697 |
| 17 | `0x6cadf83da839a01251a301297675fce180537714136f0f70f96f2afb712d0934` | 25738628 | 25738629 | +1 | 9s | 0.000003689 |
| 18 | `0xf3c9567cd89845613dda8157c8ea5068bfa9ac9edce2a0c48ff606d7de86fbe3` | 25738629 | 25738630 | +1 | 9s | 0.000003619 |
| 19 | `0xe7a73966decb1c26e591d7aa6743b79139ece8ddd2be8aeaf183556a58dc5b2a` | 25738630 | 25738633 | +3 | 32s | 0.000003675 |
| 20 | `0x6d3aee61d92707ab97de3cf8f1636ef05aea7bef82e8d7ad0569115ee20a1dbe` | 25738633 | 25738634 | +1 | 10s | 0.000003832 |
| 21 | `0x932dde7cd1b4a9426db025355ae3ba4498b504908fec2fd78b8c016db88f558c` | 25738634 | 25738635 | +1 | 10s | 0.000003766 |
| 22 | `0xa56fc6d9219f6eff43d17d79068899c4c2302e0dcd2326c65665a9053d1b00c7` | 25738635 | 25738637 | +2 | 22s | 0.000003786 |
| 23 | `0x7d45a3ecd5949f1d953636ad51c7e48f4abe32a755a4e519964d273bb34eae2d` | 25738637 | 25738640 | +3 | 33s | 0.000003607 |
| 24 | `0xd51841619aacc854607daf92bece08e81fb6325f66595bef9de73c3b5c76f90f` | 25738640 | 25738641 | +1 | 8s | 0.000003766 |
| 25 | `0xb46b635b9cbfb10a8784ec20d21290beeccb8d9c849df5c3f1889a914cc37587` | 25738641 | 25738642 | +1 | 8s | 0.000003707 |
| 26 | `0x1521832e432e1ff9b813bec6e1a03e928a3e77a3b87f9f570c0a557b698d8bb0` | 25738642 | 25738643 | +1 | 7s | 0.000003791 |
| 27 | `0x1dffb5e5be360807a3093a6f68d0bb9a57519e94a975b64a3de5767fd7818aac` | 25738643 | 25738644 | +1 | 10s | 0.000003755 |
| 28 | `0xfae032d857658e50edeb3dadcd2e240e6c1884c54396642b1bc3c0ccbc4cfbeb` | 25738644 | 25738645 | +1 | 7s | 0.000003827 |
| 29 | `0x13c35809dacdb4d967d57f6967c9517bd2d0d88807f7f183ca902c278be1b3e8` | 25738645 | 25738646 | +1 | 9s | 0.000003792 |
| 30 | `0x89e19a5b3cb2edce8b5ba1a1e539426b3e64ccfc7cf53f75a5c887085657f6b7` | 25738646 | 25738647 | +1 | 9s | 0.000003824 |
