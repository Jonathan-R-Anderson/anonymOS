# P14 — when each payment path is worth using, measured

**Break-even: 10 tips.** Below that an ERC-20 transfer costs less on chain;
at or above it a channel does.

The roadmap asks this so the routing layer can be judged "rather than guessing".
Nothing had measured the contract, so the answer was a guess. This is the
measurement.

## Gas — real contract, real EVM

`npx hardhat run scripts/p14-gas.ts` against the compiled `ChannelManagerV2` and
`AxonToken`.

| path | operation | gas | note |
|---|---|---:|---|
| erc20 | transfer, first to a recipient | 51,665 | cold `SSTORE`, balance 0 → non-zero |
| erc20 | transfer, subsequent | 34,565 | warm `SSTORE` |
| channel | `openChannel` | 152,149 | one-off, per counterparty |
| channel | `deposit` | 72,180 | one-off, per top-up |
| channel | `closeCooperative` | 117,373 | one-off; settles **any** number of off-chain payments |
| dispute | `closeUnilateral` | 143,869 | opens the challenge window |
| dispute | `challenge` | 68,820 | the watchtower's transaction |
| dispute | `settle` | 65,586 | after the challenge period |

Both ERC-20 figures are quoted deliberately. A first transfer to an address
writes its balance slot from zero and costs 49% more than every later one, and
quoting only the warm number would flatter the on-chain path. A first attempt at
this measurement sent the "cold" transfer to an address that had already been
funded and reported 34,565 twice — the fix was a recipient that has never held
the token.

## Break-even

```text
channel lifecycle   open 152,149 + deposit 72,180 + close 117,373 = 341,702 gas
one ERC-20 tip                                                    =  34,565 gas
                                                                    ──────────
                                                                    10 tips
```

| comparison | break-even |
|---|---:|
| vs. warm ERC-20 transfers | **10 tips** |
| vs. cold transfers (each to a new recipient) | **7 tips** |
| worst case — the channel is disputed | **15 tips** |

The dispute row matters. `open + deposit + closeUnilateral + challenge + settle`
is 502,604 gas, so a channel that ends in a challenge needs 15 tips to have been
worth opening. A model that quoted only the cooperative path would make channels
look cheaper than they are in exactly the case the watchtower exists for.

## In money, at fees measured on mainnet

Base fees are not modelled — they are the range P12-8 actually observed while
sending 60 real transactions: **0.070–0.139 gwei**.

| | 0.070 gwei | 0.090 gwei | 0.139 gwei |
|---|---:|---:|---:|
| one ERC-20 tip | 0.0000024 ETH | 0.0000031 ETH | 0.0000048 ETH |
| channel lifecycle | 0.0000239 ETH | 0.0000308 ETH | 0.0000475 ETH |
| worst case (disputed) | 0.0000352 ETH | 0.0000452 ETH | 0.0000699 ETH |
| **100 tips on chain** | 0.0002420 ETH | 0.0003111 ETH | 0.0004805 ETH |
| **100 tips via one channel** | 0.0000239 ETH | 0.0000308 ETH | 0.0000475 ETH |
| saving | **90.1%** | **90.1%** | **90.1%** |

The saving is 90.1% at every fee level, because both sides scale linearly with
the base fee. **The break-even is a property of the contract, not of the fee
market** — gas prices change what a tip costs, not how many tips justify a
channel. That is worth knowing before anyone tries to time a deployment around
gas.

## What this says about the roadmap's example

The roadmap guesses that "5 ANON one-time" suits ERC-20 and "5 ANON × 100" suits
a channel. Both hold, and now with a number: the crossover is **10**, so a
hundred tips is an order of magnitude past it and a single tip is nowhere near.

## What is NOT measured here

- **Hub routing.** Whether routing beats direct channels is a question about how
  many *counterparties* a payer has, not how many tips — a payer who tips 50
  recipients once each pays 50 channel lifecycles direct, versus one channel to a
  hub. The measurement needs the hub's own liquidity cost, which is capital, not
  gas, and this fixture does not model capital.
- **Capital cost.** A channel locks funds. That is a real cost with a real rate
  and it is not gas; treating a channel as strictly cheaper because it uses less
  gas ignores it.
- **Failed transactions.** A reverted transaction still burns gas. The failure
  rates that would put a number on this are the operational metrics P14 collects,
  and they do not exist yet.
- **L2.** Every figure is mainnet L1. On a rollup the absolute costs fall and the
  break-even ratio does not, for the reason above.

## Reproducing

```sh
cd proof-of-facilitation
npx hardhat run scripts/p14-gas.ts
```

Gas is a property of the contract and stable across fee markets, so the script
prints gas and this document does the money arithmetic. Baking a price into the
script would make it stale the moment the fee market moved.
