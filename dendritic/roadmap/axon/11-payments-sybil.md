## 14. Payments, Accounting, and Incentives

**The finding that shapes this section: the accounting plane is the most
finished code in the project and the least necessary part of AXON v1.** The
contracts are written and unit-tested, the channel protocol is specified and
implemented, one contract is live on mainnet — and none of it can be put on the
relay data path without handing every relay a payer identifier. Constitution
ruling R11 is not a style preference. It is the observation that the incentive
layer and the anonymity layer want opposite things, and that the way most
designs in this space resolve it is by quietly conceding the anonymity.

So this section does three things: inventory what exists and what it is
actually tested against; specify the only payment shape that can touch a relay
(blind-signed tokens, redeemed off the data path) and state exactly what
unlinkability it buys; and then argue that none of it ships in v1.

---

### 14.1 What already exists

> **RENAMED (2026-08-16): `ChannelManagerV2` is now `AxonChannels`, and V1 is
> deleted.**
>
> The name described a position in a sequence, and the sequence no longer
> exists. `AxonChannels` names what it does — bilateral channels, hash-locked
> routing, delegated signing, checkpoints — and matches `AxonToken` /
> `AxonRegistry`.
>
> **A rename is a SOURCE change and moves nothing on chain.** Both instances are
> still deployed and still verified under their original names:
>
> | | Address | Status |
> |---|---|---|
> | **AxonChannels** (was `ChannelManagerV2`) | `0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c` | **Live on mainnet**, block 25757314. The one deployed contract in the whole set. |
> | V1 (`ChannelManager`) | `0xae70526931FF460894133201f6C8cA91bbA0E177` | **Still deployed.** Source removed from the tree. |
>
> **Deleting V1's source does not close V1's channels.** Anyone holding funds in
> a V1 channel needs V1's ABI to settle, and it is recoverable from git history
> rather than gone. That is stated because "we removed V1" and "V1 is finished"
> are different claims and only the first is true.
>
> **The rename found a live defect.** `deploy/02_channels.ts` was still deploying
> **`ChannelManager`** — V1 — and had been stale for as long as V2 existed.
> Running it would have deployed the contract **without hash locks**, so routed
> tipping would have failed at the first hop with nothing to explain why.
> Deploying the wrong contract is not a build error and nothing caught it.
>
> Everything else that named the contract was a comment: the backend resolves it
> by `CHANNEL_MANAGER_ADDRESS`, never by name, so no lookup changed. 127 contract
> tests pass, and the one that had been failing was V1's mainnet-fork test, which
> went with V1.

Everything below was read, not recalled. Test counts are `grep -c 'it('` over
the named file, which counts declared cases, not passing assertions.

| Component | Path | Status, honestly |
|---|---|---|
| `AxonToken` (ERC-20 `ANON`, "credits") | `proof-of-facilitation/contracts/AxonToken.sol` (84 lines) | EVM unit tests only (`test/AxonToken.test.ts`, 2 cases). **Not deployed.** |
| `Treasury` — sole minter, permissionless bounded `fundEpoch`, owner-only non-minting `release` | `contracts/Treasury.sol` (351 lines) | 31 test cases. **Not deployed.** |
| `NodeRegistry` — wallet↔Ed25519 binding, capability bitmap, endpoint commitment, `registerWithSig` meta-tx | `contracts/NodeRegistry.sol` (205 lines) | 5 test cases. **Not deployed.** |
| `StakeVault` — bond / delayed withdraw / slash-by-authorised-slasher | `contracts/StakeVault.sol` (92 lines) | Covered inside `test/Phase1.test.ts`. **Not deployed.** |
| `EpochManager` — receipt/reward/state roots + randomness + budget, optimistic window, freeze/invalidate, permissionless `finalize` | `contracts/EpochManager.sol` (139 lines) | Same. **Not deployed.** |
| `RewardDistributor` — Merkle claim, once per `(epoch, nodeId)` | `contracts/RewardDistributor.sol` (76 lines) | Same. **Not deployed.** |
| `DisputeManager` — bonded fraud challenge, arbiter resolve, slash-to-challenger | `contracts/DisputeManager.sol` (108 lines) | Same. **Not deployed.** |
| `ServicePolicyRegistry` — versioned budget / split / witness thresholds / per-node cap / formula hash, activating at epoch boundaries | `contracts/ServicePolicyRegistry.sol` (83 lines) | Same. **Not deployed.** |
| `ChannelManagerV2` — deposits, HTLC lock root, cooperative/unilateral close, challenge, `claimLock`/`expireLock`, checkpoints, delegated signing | `contracts/ChannelManagerV2.sol` (710 lines) | **Deployed, chain 1, `0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c`, block 25757314, `challengePeriod` = 28800 s and immutable** (`doc/watchtower.md`). 22 + 6 + 32 + 4 test cases across four files. |
| SCPP/1 off-chain protocol | `doc/channel-payment-protocol.md`; `storage-client/internal/channel/{scpp,state,session,store,transition}.go` | Implemented; ten ordered validity checks; crash table specified. |
| Multipath planning + executor | `internal/channel/{multipath,multipath_exec}.go`; `doc/p13-multipath-security-table.md` | See the warning below. |
| Watchtower | `doc/watchtower.md`, `doc/p14-watchtower-scaling-design.md`, `internal/channel/{eventreader,chainprobe,challengebudget}.go` | Measured baseline 34.4 ms per pooled chain read, ~872 channels per watchtower at a 30 s sweep — 11× short of the declared 10,000-channel envelope. |
| Facilitation client (node half) | `storage-client/internal/facilitation/` — `receipt.go`, `witness.go`, `challenge_agent.go`, `storage_proof.go`, `register.go`, `payout.go`, `scheduler.go`, `receipt_store.go`, `attest_exchange.go` | Go unit tests including golden vectors pinned against the aggregator. |
| Aggregator (separate Go module) | `proof-of-facilitation/aggregator/` — `score.go`, `merkle.go`, `epoch.go`, `settlement.go`, `witness.go`, `randomness.go`, `payouts.go` | Golden-vector tested against the client's duplicate implementations. |
| Self-measured throughput | `storage-client/internal/traffic/traffic.go` | A drained window, one legitimate caller, self-reported. |
| Blinded **recipient** invoices | `internal/channel/blinded.go` + `blinded_test.go` | Real, and the right instinct — but it hides the *payee*, not the payer. |
| Diversity-constrained payment routing | `internal/channel/route.go` | Refuses rather than degrades when three distinct operators cannot be drawn. |

**What does not exist anywhere in either repository:** blind-signature token
issuance, probabilistic/lottery micropayments, and any payment path a relay
could be on. A `grep -ril` for `chaumian|blind signature|privacy pass|lottery|
probabilistic micropay` across both trees returns nothing. §14.3 and §14.4 are
specification, not description.

**Three corrections to the existing documentation, from reading the code:**

1. `doc/p13-multipath-security-table.md` opens with "34 rows, ALL ENFORCED, 0
   GAPS" and closes with a summary listing rows 11, 14, 16, 17, 19, 20 as GAP.
   The header and the summary contradict each other. Nothing in this roadmap
   should cite either until the row list is re-derived from
   `multipath_exec_test.go`.
2. The same document's "NOT FIXED — no settle deadline anywhere" is **stale**.
   `PeerSession.checkTiming` in `internal/channel/session.go` now rejects a
   `LOCK_SETTLE` whose lock expiry is `<= now + skew` with `LOCK_EXPIRED`,
   deriving the boundary from `ChannelManagerV2.claimLock`. `SCPP/1` §4.2 check
   9b is the current statement.
3. The aggregator's epoch randomness is `keccak256(seed ‖ uint64_be(epoch))`
   where `seed` is fetched over HTTP from the website
   (`aggregator/randomness.go`, `FetchGenesisSeed`) — a single trusted server
   choosing the value that selects auditors. Incompatible with R13; must become
   the light-client-verified SRV. [BUILD NOW], as a substitution.

---

### 14.2 R11 developed: why paying a relay is a de-anonymisation channel

A relay will not forward for free forever, so it must be paid. To be paid it
must verify that payment happened. Verification is a check against *something
the payer holds*, and anything the payer holds that the relay can check twice is
an identifier.

```text
                       what the hop learns about the payer
  ────────────────────────────────────────────────────────────────────────
  on-chain transfer      wallet address. Adversary observes the chain
  per relay-pair channel completely (§4), so this is a permanent,
                         globally joinable label on the payer, attached to
                         the exact hop that saw their traffic.
  ────────────────────────────────────────────────────────────────────────
  signed voucher from    a public key. Unlinkable only if the key is fresh
  the payer              per payment; if it is fresh per payment it proves
                         nothing about solvency and the relay must check it
                         somewhere, which puts the checker on the path.
  ────────────────────────────────────────────────────────────────────────
  bearer token, blind-   a random 32-byte string plus the issuer's key
  signed by an issuer    epoch and the denomination. That is the target.
  ────────────────────────────────────────────────────────────────────────
```

A second, quieter leak survives the cryptography: **payment splits the client
population into those who pay and those who do not, and then by how much.** An
adversary running a guard observes a client's spend rate across days — a
behavioural fingerprint independent of what the token reveals. This is the
intersection-attack family §4 already declines to defend against for persistent
low-churn users; payment sharpens it rather than creating it.

The third leak is structural and §14.7 returns to it: whoever issues value knows
who bought it. A blind signature makes the *spend* unlinkable from the
*purchase*; it does not make the purchase invisible.

---

### 14.3 Blind-signed unlinkable tokens [NEEDS RESEARCH]

> **RESOLVED (2026-08-16) — P15. The construction is CHAUM-STYLE BLIND RSA.**
> `internal/axon/token`, 14 tests. This subsection ended with "the choice
> between blind RSA and a VOPRF construction turns on T2 versus token size in a
> 1024 B cell, and that trade has not been measured here." Both candidates are
> now implemented as measurement vehicles and both axes are measured:
>
> | | token on the wire | % of a 984 B relay payload | relay-side verification |
> |---|---|---|---|
> | **A** blind RSA-2048 | **296 B** | 30.1 % | **37.8 µs, public key, issuer absent** |
> | **B** VOPRF (ed25519) | **72 B** | 7.3 % | **impossible — needs the issuer's secret** |
>
> **Axis 1 favours B and decides nothing.** The question is not which token is
> smaller but whether either is too big, and neither is: a token rides once per
> circuit, not once per cell (§14.4 is why).
>
> **Axis 2 decides it.** Under B a relay has three options and all three are
> worse than not being paid — hold the issuer's secret (every relay can mint),
> call the issuer per token (T2's "the verification path becomes the correlation
> path", and the issuer then learns in real time which relay carries whose
> traffic), or forward first and find out at redemption, having already done the
> work. `voprf.go`'s relay-side verifier therefore **returns false for
> everything**, which is the accurate answer rather than an unfinished corner.
>
> **What the ruling does NOT settle: the implementation.** `blindrsa.go` is
> classical RSA-FDH. **Production must be RFC 9474** (PSS-based), which is a
> different encoding with different issuer-side checks. The FAMILY is settled;
> the SPECIFICATION within it is RFC 9474 and is not implemented here. The file
> names what else is short of it: no PSS encoding, no blinding-factor validity
> check, and **no epoch key schedule at all** — and the epoch length is the
> denominator of the anonymity set, which this subsection also leaves open.
>
> **Built and tested:** T1 (denomination and epoch are signed, so rewriting
> either invalidates the token; a relay refuses unknown denominations), T2, T3
> (double-spend caught at redemption — both relays accept the same token because
> neither can do otherwise, and the honest tokens in the batch are still paid),
> T4 (a batch of one is refused), T5's minimum age enforced **client-side**,
> because the issuer cannot verify when a relay says it accepted a token and the
> payer is the party whose privacy the rule protects. E15.2 holds against an
> adversary holding the complete issuance and redemption logs.
>
> **The arithmetic this subsection states is the reason none of it is in v1.**
> The anonymity set is at most `P·B` and is dominated by `P`. The deployed
> population is **9 nodes and zero paying clients**, so the set is zero and no
> window, denomination or delay changes that. T15.5's test logs the product
> rather than asserting a number, because there is no purchase rate to assert
> against.

The construction is not new and must not be invented here. Two candidate
families, both standard:

| Family | Token on the wire | Issuer state | Note |
|---|---|---|---|
| Chaum-style blind RSA signature | ~256 B signature (RSA-2048) + 32 B nonce | public key epoch + spent-set | Largest token; simplest verification; long history |
| Privacy-Pass-style anonymous tokens (verifiable OPRF over a prime-order group) | ~32 B group element + 32 B nonce + 32 B MAC | secret key epoch + spent-set | Small enough to ride in a cell; verification needs the issuer's secret, so redemption is centralised at the issuer or a shard of it |

Neither is chosen here. What *is* fixed is the shape:

```text
  DEPOSIT                     ISSUE                    SPEND                REDEEM
  (identified, on chain)      (identified, off path)   (anonymous, on path) (off path, batched)

  payer wallet ──deposit──▶ Issuer
        │                     │  n blinded requests
        │                     │◀─────────────────────── payer, over a circuit
        │                     │  n blind signatures
        │                     ├──────────────────────▶ payer unblinds, holds n tokens
        │                     │
        │                     │                    payer ──token──▶ relay
        │                     │                    (relay checks the signature
        │                     │                     LOCALLY; forwards; keeps it)
        │                     │
        │                     │◀── relay submits a batch of spent tokens ──┐
        │                     │    every T (see cadence below)             │
        │                     │                                            │
        │                     └── issuer credits relay's nodeId ────────────┘
        │                            → aggregator → EpochManager → RewardDistributor
```

Five properties this must have, each of which is a check somewhere:

| # | Property | Where enforced |
|---|---|---|
| T1 | A token is one denomination from one issuer key epoch. Mixed denominations partition the anonymity set. | Token encoding; relay refuses unknown denominations. |
| T2 | The relay verifies **offline**, with no network call, or the verification path becomes the correlation path. | Public-key verification (blind RSA) or a cached batched-verification key. This is why a pure OPRF scheme is awkward: verification wants the issuer's secret. |
| T3 | Double-spend is detected at **redemption**, not at spend. The relay's exposure is bounded by its redemption interval, not by zero. | Issuer spent-set. Relay prices the risk by redeeming often. |
| T4 | Redemption is **batched and delayed**. Immediate redemption reconstructs the timing link the blinding removed. | Redemption cadence, below. |
| T5 | The purchase circuit and the spend circuit are different circuits and different isolation contexts. | Client policy; the token buy is `BULK` (R2), the spend is on `INTERACTIVE`. |

**The exact unlinkability property, stated so it cannot be overclaimed.**

> Given a token presented at a relay, the issuer — colluding with that relay —
> can narrow the payer to the set of payers who were issued a token of that
> denomination under that issuer key epoch and whose token has not yet been
> redeemed. Within that set, the blind signature gives no information at all.
> That is the entire guarantee.

What it does **not** give:

- **The issuer still sees every purchase.** Wallet, count, timing, and total
  value. If a user buys 400 tokens once and nobody else does, the anonymity set
  is one and the blinding accomplished nothing. Token *counts* must be quantised
  (buy in fixed batch sizes) or the count is the identifier.
- **Purchase-time versus spend-time correlation.** If tokens are bought and spent
  within minutes, an issuer who is also a relay intersects two small windows. The
  defence is a mandatory *minimum age* before a token may be spent, and a
  redemption delay after. Both cost usability and neither is free: a delay of D
  gives an anonymity set of everyone who bought within D of the same moment,
  which at low network volume may still be one person.
- **No protection against a hostile issuer.** It cannot link a specific token,
  but it can starve, refuse, or over-issue. Over-issuance is an IOU against a
  deposit pool and is discovered only at redemption; the bond that would make it
  irrational is `StakeVault`, and the amount is [UNSOLVED] — a function of
  issuance volume, not a constant.
- **Nothing about traffic analysis.** A token proves payment; it says nothing
  about correlation of the traffic it paid for.

**Denomination and set-size arithmetic.** With `P` payers each buying `B` tokens
of denomination `d` per issuer key epoch, the anonymity set for one spent token
is at most `P·B`, less what has already been redeemed. **The dominant term is
`P`.** A network with 50 paying clients cannot be rescued by a clever token; the
set is 50. This is the argument for not building it until there are enough
payers for the set to mean something, and it is quantitative rather than
aesthetic.

Marked [NEEDS RESEARCH]: the choice between blind RSA and a VOPRF construction
turns on T2 (offline verification at the relay) versus token size in a 1024 B
cell, and that trade has not been measured here.

---

### 14.4 Probabilistic micropayments, and why per-cell granularity may not need them

Blind tokens do not solve granularity. A token has a denomination; a circuit
consumes cells. A 256 B token inside a 1024 B cell is absurd per cell, and one
token per 10,000 cells means the relay extends 10 MB of credit to an anonymous
party. The standard answer is a lottery ticket: every unit of work carries a
ticket worth `V` that wins with probability `p`, so the expected transfer is
`pV` per ticket and only winners are settled. Settlement volume falls by `1/p`.

**Variance is the whole analysis.** For `N` tickets received, the relay's
receipts have coefficient of variation

```text
  CV(N) = sqrt( (1 - p) / (p · N) )
```

which is independent of `V`. With `p = 10⁻³`:

| Tickets received `N` | Bytes relayed at 1024 B/cell | CV | Interpretation |
|---:|---:|---:|---|
| 10³ | 1.0 MB | 1.00 | earnings are noise |
| 10⁴ | 10.2 MB | 0.32 | ±32 % |
| 10⁵ | 102 MB | 0.10 | ±10 % |
| 10⁶ | 1.02 GB | 0.032 | ±3 % |
| 10⁷ | 10.2 GB | 0.010 | ±1 % |

(Derived from the formula above, not measured.)

So a relay must move on the order of a gigabyte before its income resembles its
work. That is fine for a busy relay and hostile to a small one — a
**centralising pressure**, since small operators are exactly the diversity the
anonymity layer depends on. Lowering `p` makes settlement cheaper and the small
operator's position worse; raising `p` inverts it.

**The de-anonymisation trap specific to lotteries.** A winning ticket must be
redeemable against *someone's* funds. If it is drawn against the payer's escrow,
the winning relay learns the payer's on-chain account — the exact leak R11
forbids, arriving at a rate of `p` per cell rather than never. If it is drawn
against a pooled issuer instead, the scheme has collapsed back into 14.3 with
extra variance. **A lottery does not avoid the issuer; it only avoids per-token
issuance cost.**

**Compared with a payment channel per relay pair.** Take the Constitution's
parameters: 3 hops, 10-minute tunnel lifetime, a pool of 3 inbound + 3 outbound
+ 1 spare each per destination (8 tunnels), guard-constrained so hop 1 is one of
2 pinned guards.

```text
  tunnel builds per day     8 × (24 × 60 / 10)        = 1,152
  non-guard hop slots/day   1,152 × 2                 = 2,304
  distinct relays touched   min(2,304, |R|)
```

Each relay pair needs a channel, and the measured on-chain lifecycle cost of one
channel (`doc/fixtures/p14-economics.md`, real EVM against the compiled
contracts) is:

| Operation | Gas |
|---|---:|
| `openChannel` | 152,149 |
| `deposit` | 72,180 |
| `closeCooperative` | 117,373 |
| **lifecycle** | **341,702** |
| disputed lifecycle (`open + deposit + closeUnilateral + challenge + settle`) | 502,604 |

One client touching 1,000 distinct relays in a day costs 341.7 M gas in channel
lifecycles — several full blocks of the chain, for one user, for one day. And
each of those channels is a permanent on-chain edge from that user to that
relay. The state explosion is not merely a scaling problem; **the state itself
is the de-anonymisation.** Payment channels per relay pair are rejected on both
counts.

Channels remain correct for the shapes they were built for: a client to *one*
long-lived counterparty (an issuer, a storage provider, a gateway), where the
relationship is already an identified one. That is how SCPP/1 is reused —
§14.5, not on the relay path.

**Verdict on lotteries:** [NEEDS RESEARCH], and probably not needed. At AXON's
plausible v1 volumes the variance table says a lottery buys nothing a coarser
token denomination plus a per-circuit prepayment does not, and it adds a
settlement path that leaks. Revisit only if measured per-relay throughput makes
`N ≥ 10⁶` per settlement interval routine.

---

### 14.5 The accounting data flow — reuse, do not redesign

The epoch pipeline exists and is tested. AXON adds inputs to it; it does not
replace it.

```text
  relay / storage node
    │  work happens
    ▼
  ServiceReceipt                     internal/facilitation/receipt.go
    ProviderNodeID  VerifierNodeID  ServiceType  JobID
    ChallengeHash   ResultHash      Epoch        StartedAt/CompletedAt
    Quantity        Quality         Nonce
    │  keccak256 over the fields in fixed order (CanonicalReceiptHash)
    │  Ed25519 signature by the p2p key whose keccak256 IS the nodeId
    ▼
  witness attestations               facilitation/witness.go + aggregator/witness.go
    SelectWitnesses(randomness, provider, svc, challengeIndex, threshold, cands)
    thresholds: DHT 2-of-3 · Gateway 3-of-5 · Storage 3-of-5
                LoadBalance 3-of-5 · Docker 4-of-7
    │
    ▼
  aggregator                         aggregator/score.go, merkle.go, epoch.go
    Score(): per service, share ∝ quality-weighted quantity, capped at
             ServicePolicyRegistry.perNodeCapBps
    leaf = keccak256(keccak256(abi.encode(nodeId, recipient, amount,
                                          serviceBreakdownHash)))
    │
    ▼
  EpochManager.submitEpoch(epoch, receiptRoot, rewardRoot, nodeStateRoot,
                           randomness, totalRewards)
    │  challengeWindow — 24 h in deploy/01_phase1.ts
    │  DisputeManager.challenge() freezes; bond 100 ANON in that script
    │  arbiter resolve → invalidateEpoch + StakeVault.slash → challenger
    ▼
  EpochManager.finalize()            permissionless after the window
    │
    ▼
  RewardDistributor.claim(epoch, nodeId, recipient, amount, svcHash, proof)
    once per (epoch, nodeId); paid from a Treasury-funded balance
```

**Four changes AXON forces on this pipeline, all concrete:**

| # | Change | Why | Difficulty |
|---|---|---|---|
| A1 | **New capability bits.** `NodeRegistry.CAP_ALL = (1 << 7) - 1` — bits 0..6 are all assigned (DHT, Gateway, Storage, LoadBalance, DockerWorker, DockerController, Witness). There is **no spare bit** for relay, introduction point, or rendezvous point. `ServicePolicyRegistry` hardcodes `uint16[7]` and `uint8[7]`. | AXON's roles cannot be expressed. | [BUILD NOW] — new contract version, not a patch. |
| A2 | **A relay receipt has no verifier.** `ServiceReceipt` carries `VerifierNodeID` and a witness threshold. A witness cannot observe a circuit without being on it, and a node on the circuit is a hop, not a witness. The storage model's third-party attestation does not transfer. | The fraud model differs — see §14.6. | [UNSOLVED] as an attestation problem; [BUILD NOW] as a token-redemption problem (the redeemed token *is* the receipt). |
| A3 | **Epoch randomness from the verified SRV.** `DeriveEpochRandomness(seed, epoch)` with an HTTP-fetched genesis seed must become the RANDAO mix read through the existing light client (R13). | A server that picks the auditors picks the audit. | [BUILD NOW] |
| A4 | **The aggregator is a single trusted role.** `EpochManager.setAggregator` is owner-gated and `DisputeManager.resolve` is `onlyOwner`. Today's arbitration is a governance multisig. | Named as a centralisation point, not hidden. | [NEEDS RESEARCH] — on-chain fraud proofs are the drop-in the contract comment already anticipates. |

The receipt encoding is duplicated across two Go modules by necessity
(`internal/facilitation/receipt.go` and the aggregator's copy) and pinned by a
shared golden vector; `witness.go` is duplicated the same way. Any AXON change
to either must change both in the same commit. That constraint is already
written into the files and is repeated here because it is the kind of thing a
new section author breaks.

---

### 14.6 Storage payments and relay payments are different instruments

| | **Storage** | **Relay** |
|---|---|---|
| What is bought | Custody of a shard over time | Forwarding of `n` cells now |
| Verifiable by a third party? | **Yes.** Challenge–response against held bytes: `internal/facilitation/storage_proof.go`, `internal/p2p/challenge.go`, and the existing lying-holder test | **No.** Any verifier is a hop; any hop is a trust assumption |
| Existing enforcement | Audited recall, `recall_lying_holder_test.go`; witness threshold 3-of-5 | None. Nothing measures relay work today |
| Measurement source | Challenge outcomes (adversarial) | Self-report (`traffic.Meter`) or spent tokens |
| Fraud shape | Claim to hold what you do not; collude with witnesses; report capacity you lack | Claim traffic you did not carry; take payment and drop; selectively drop to shape the path selection of others |
| Fraud detection | Retrospective, cheap, and provable | Only via the payer noticing failure; **not provable** |
| Payment direction | Post-paid against proof | **Pre-paid**, in small units, or credit is extended to an anonymous party |
| Settlement cadence | Epoch (24 h), Merkle claim | Token redemption batch, hours; independent of the circuit's lifetime |
| Failure of non-payment | Data becomes less durable — measurable, contracted (R8) | Circuit fails; client rebuilds; nothing durable is lost |
| Correct instrument | Epoch receipts + witnesses (exists) | Bearer tokens (does not exist) |

The asymmetry that matters: **storage fraud is detectable and relay fraud is
not.** That is why the storage side can be post-paid and audited, and why the
relay side has to be pre-paid in units small enough that being cheated of one is
uninteresting. Trying to run relays through the receipt-and-witness pipeline
would require witnesses on circuits, which is a de-anonymisation mechanism with
a reward attached.

A consequence for pricing: relay payment must be **per-hop and per-unit**, never
per-circuit-end-to-end, because an end-to-end price requires someone to know
both ends.

---

### 14.7 Payments are not in v1

**The argument.** Tor and I2P carry real traffic, at scale, for years, with no
payment layer at all. Their relay capacity comes from operators who want the
network to exist. This is not a temporary state that grew out of an inability to
build payments — it is a property that has held under sustained load, and it is
strictly simpler than any alternative. AXON must be built so that it works at
exactly zero payment, on volunteer capacity, because:

1. **An unpaid network has no issuer.** No solvency, no redemption, no spent-set,
   no bank, no arbiter, no aggregator. The list of trusted parties is shorter by
   one, and it is the one with a legal identity.
2. **An unpaid relay has nothing to sell and nothing to steal.** Receipt forgery,
   aggregator fraud, and free-riding are all *absent*, not *mitigated*.
3. **Payment cannot be removed later, but it can be added later.** A network that
   ships without it retains the option; a network that ships with it has a token
   in circulation, holders with expectations, and a legal posture that is
   expensive to unwind.
4. **The accounting plane is explicitly off the latency budget (§6 layer stack).**
   If it is off the critical path by construction, then not building it changes
   no data-path design.

The correct v1 posture is: relaying is capability-advertised and credited
(R3) — a node's contribution is *recorded* — and nothing is paid. Recording
without paying is cheap, keeps the receipt plumbing exercised, and produces the
measurement that would later justify a currency.

**Criteria that would trigger building the economic layer.** Each is a
measurement, not an opinion. Until one is met, the answer is no.

| # | Trigger | Threshold | Measured by |
|---|---|---|---|
| E1 | Relay capacity shortfall | Sustained median circuit-build failure > 5 % for 30 days attributable to capacity, not reachability | Client-side build telemetry |
| E2 | Guard scarcity | Fewer than 10 distinct-ASN guard-eligible relays per 1,000 active clients | Relay descriptor census |
| E3 | Storage durability below the contracted tier | Repair loop cannot restore `r = 8` within its declared window, for lack of volunteer capacity rather than lack of code | The existing repair/rebalance loops |
| E4 | Volunteer churn | Median relay lifetime under 14 days with a declining trend over 90 days | Descriptor observation |
| E5 | Paying-population floor | At least `P` payers such that a token anonymity set of `P·B` is defensible (§14.3). If `P` is small, payment is a *labelling* mechanism, not a funding one | Issuance count |

E5 is the one most likely to be skipped and is the one that voids the whole
scheme if unmet. **Do not build an anonymity-degrading mechanism for a set of
fifty users.**

**The attack surface an economic layer adds.** All six are new, none exist
today, and each is a reason the trigger criteria are strict.

| Attack | Mechanism | Damage | Mitigation, and its cost |
|---|---|---|---|
| Payment-based de-anonymisation | Any identified value transfer touching a hop; also issuer↔relay collusion narrowing a token to a purchase batch | Direct client identification | Blind tokens + batching + delay (§14.3). Costs latency, usability, and an issuer |
| Wealth-based path bias | Path selection is bandwidth-weighted (R14) with weights bounded by bonded stake; an attacker who buys the most advertised-and-bonded bandwidth is selected most | Attacker raises its share of first and last hops with money rather than with machines | Cap per-operator weight; diversity constraints (§15). Costs throughput on legitimately large relays |
| Free-riding | Clients consume relay capacity without buying tokens | Capacity starvation; the paying users subsidise the rest | Token-gated circuit extension — which *requires* every client to buy, which raises E5's floor and shrinks the anonymity set |
| Receipt forgery | A node signs receipts for work it did not do, or colludes with its selected witnesses | Reward theft, and corruption of the bandwidth weights that path selection reads | Witness thresholds (3-of-5, 2-of-3), group-diversity in selection, `DisputeManager`. Does not transfer to relaying (§14.6, A2) |
| Aggregator fraud | The single `setAggregator` role submits a reward root that pays itself | Whole-epoch theft, bounded by the epoch budget and the 24 h window | Optimistic challenge + `StakeVault` slash. Requires a watching challenger with a 100 ANON bond and an off-chain fraud proof |
| Issuer insolvency | Blind tokens issued beyond deposits | Relays work unpaid; discovered only at redemption | Bond the issuer; publish issued-vs-deposited. Neither exists |

**The regulatory and legal surface, directly.** This is the part that is
usually omitted, and it is the part that falls on the node operator rather than
on the protocol author.

- A token that pays people for **relaying anonymous traffic** is not the same
  instrument as a token that pays people for running a DHT for a content network,
  even if it is the same contract. The existing `AxonToken` was written for the
  latter. Repointing it at the former changes what the operator is being paid to
  do, and that is what a regulator, a hosting provider's acceptable-use team, and
  a prosecutor all look at.
- **A paid relay operator is on weaker ground than a volunteer one.** Mere-conduit
  and intermediary-liability defences generally lean on the operator being a
  neutral, automated, non-selective transmitter. Taking per-byte payment for
  transmitting specific traffic is a factor that cuts against neutrality in
  several jurisdictions. This roadmap does not claim to know how any specific
  case resolves; it claims that the volunteer posture is strictly safer and that
  moving away from it is a decision with legal consequences, not merely economic
  ones.
- **The issuer is a money business.** An entity taking deposits and issuing
  transferable bearer instruments redeemable for value is, in most jurisdictions,
  performing a regulated activity — registration, record-keeping, and
  customer-identification obligations that are *directly incompatible* with the
  anonymity set the tokens exist to create. This is the sharpest contradiction in
  the whole section: **the compliance obligations on the issuer are precisely the
  records that shrink the anonymity set.**
- **A token in circulation is a seizure and pressure surface.** Contract owner
  keys, the Treasury, the aggregator, and the issuer are all identifiable
  parties. `DisputeManager.resolve` being `onlyOwner` means there is a named
  human who decides fraud outcomes. That person can be compelled.
- **Operators earning a token acquire tax and reporting obligations** they did not
  have as volunteers, in jurisdictions they may not have chosen. That reduces the
  operator pool, which reduces diversity, which reduces anonymity.

None of the above is legal advice and none of it is settled by this document.
What is settled is the ordering: **the legal analysis is a prerequisite for the
economic layer, not a follow-up to it.**

---

### 14.8 Decision table — §14

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| **No payments in v1**; relaying is credited but unpaid | Payment is a de-anonymisation channel and a legal surface | Tor and I2P both run at zero payment; Freenet likewise | We keep the accounting *plumbing* (receipts, epochs) running unpaid, so the measurement exists if payment is ever justified | Ship a token with v1 (adds every row of the attack table before any traffic exists); "pay later, design now" without trigger criteria | Volunteer capacity may not arrive; there is no fallback, and E1–E4 exist to detect that rather than fix it |
| **Blind-signed bearer tokens** for any relay payment that ever exists | R11 — a relay must verify payment without learning a payer | None of the three: Tor and I2P have no payment layer, so this is imported from the anonymous-credential literature | Redemption is batched, delayed, and off the data path; the issuer is bonded via `StakeVault` | On-chain payment per hop (permanent public edge); per-relay-pair channels (§14.4); signed payer vouchers (a public key is an identifier) | An issuer: a solvency risk, a compliance surface, and a party that sees every purchase |
| **Payment channels are kept only for identified, long-lived counterparties** | Channels are correct and deployed; they are just the wrong instrument for anonymous hop payment | Not applicable — this is the existing SCPP/1 asset | Restricted in scope rather than extended | Channel per relay pair: 341,702 gas per lifecycle × up to 2,304 hop-slots/day/client, and a public edge per hop | The identified relationships (issuer, storage provider) become the linkage points |
| **Reuse `EpochManager`/`RewardDistributor` unchanged; add capability bits and swap the randomness source** | Do not reinvent settlement | Not applicable | `CAP_ALL` is full at 7 bits; a new registry version is required. `DeriveEpochRandomness`'s HTTP seed becomes the verified SRV (R13) | A new settlement contract family for AXON (throws away tested code and the golden vectors) | A contract migration is an ownership and upgrade event, i.e. another trusted moment |
| **Storage post-paid and audited; relay pre-paid in small units** | The two have different fraud models (§14.6) | Storage audit derives from the existing challenge machinery, itself a hardening of Freenet-style best-effort retrieval | Explicitly two instruments with two cadences, rather than one ledger | A single unified receipt for all services (would require witnesses on circuits) | Two settlement paths to keep consistent, and a relay-side credit exposure bounded only by the redemption interval |
| **Lottery tickets deferred** | Per-cell granularity | Not applicable | Deferred behind a measured threshold (`N ≥ 10⁶` per interval) rather than dismissed | Building it now: adds variance that penalises small relays and a winning-ticket redemption path that leaks the payer's escrow | If deferred wrongly, coarse denominations force relays to extend more credit |

---

### What this section does NOT establish

- **It does not choose a blind-signature construction.** Blind RSA versus a
  VOPRF-based anonymous token turns on offline relay verification against token
  size in a 1024 B cell, and that trade has not been measured here.
- **It gives no anonymity-set number for any real deployment.** The set size is
  `P·B` minus redemptions, and `P` is unknown and will be small at launch. The
  section states the formula and refuses to state a value.
- **It does not cost the issuer's bond.** The bond that makes over-issuance
  irrational is a function of issuance volume and redemption lag; neither exists.
- **No gas figures are given for the PoF contracts.** The measured gas in §14.4 is
  `ChannelManagerV2`/`AxonToken` only, from `doc/fixtures/p14-economics.md`.
  `submitEpoch`, `finalize` and `claim` are unmeasured — TBD, measure with the
  same harness.
- **The legal analysis is named, not performed.** The section asserts that the
  volunteer posture is safer and that the issuer's obligations conflict with the
  anonymity set; it does not resolve any jurisdiction.
- **It does not reconcile `doc/p13-multipath-security-table.md` with itself.**
  The header claims zero gaps and the summary lists six; until that is settled
  from the tests, multipath must not be relied on for anything in AXON.

---

## 15. Sybil Resistance and Admission Control

**The finding that shapes this section: Sybil resistance without a central
authority is not solved, and nothing below solves it.** In an open network where
identities are cryptographic keys, one party can hold arbitrarily many at
essentially zero marginal cost; the only known general defence is a trusted
party that certifies distinctness, which is precisely what a decentralised
overlay refuses to have. Every mechanism in this section does one of two things:
raises the *cost* of an identity, or bounds the *damage* a set of identities can
do. Neither is a proof, and this whole area is marked **[UNSOLVED]**.

What follows is therefore defence in depth, with the cost and the failure mode
stated for each layer, and the arithmetic for what a funded attacker still
achieves.

---

### 15.1 What already exists

| Mechanism | Path | State |
|---|---|---|
| One p2p key per registration, duplicate prevention | `proof-of-facilitation/contracts/NodeRegistry.sol` — `p2pKeyUsed[keccak256(pubkey)]`, `_register` reverts `KeyAlreadyRegistered` | Written, 5 test cases, **not deployed**. Registration itself is **free**: no bond, no puzzle. With `registerWithSig` plus the planned paymaster, the node pays no gas either |
| Bond / slash / delayed withdrawal | `contracts/StakeVault.sol`; `WITHDRAW_DELAY = 24 h` in `deploy/01_phase1.ts`; slashing takes active bond first, then pending withdrawals | Written, tested via `Phase1.test.ts`, **not deployed**. **Nothing requires a bond to join** — `StakeVault` is opt-in |
| Stake- and reputation-weighted selection with group diversity | `storage-client/internal/facilitation/witness.go` — `selectionWeight = sqrt(effectiveStake) × ReputationBps`; a first pass excludes candidates sharing a `Group`, a second pass fills the remainder without the constraint | Implemented, golden-vector pinned against the aggregator's duplicate |
| Bootstrap stake floor | `BootstrapStakeFloorWei = 1` — an unstaked but registered node counts as stake 1 | Implemented. This is what makes an unbonded network work, and it is also what makes an unbonded identity free |
| Shard placement distinctness | `internal/placement/plan.go` — never two shards of one chunk to one peer; returns *fewer* assignments rather than doubling up | Implemented and pure |
| Route diversity by self-declared operator / fault domain | `internal/channel/route.go` — refuses rather than degrades; the file states the rule plainly: claims are "weighted and used to EXCLUDE, never to prove independence" | Implemented |
| Per-node admission limits on the compute side | `internal/dcs/admission.go` — simultaneous-container cap, one instance per owner, FIFO queue, hard TTL | Implemented (not a network-layer control) |
| Opaque challenge transport | `internal/p2p/challenge.go` — carries challenge bytes over the existing storage protocol; 90 s timeout | Implemented; the *content* of any admission puzzle would live in `internal/facilitation` |

**What must be replaced or built.**

- **Prefix and ASN diversity do not exist.** Constitution §5 specifies DHT
  replication `r = 8` across distinct /24 (v4), /48 (v6) and distinct ASNs, and
  calls for reusing "the existing placement engine's diversity levels".
  `internal/placement` has no such levels: `grep` for `ASN`, `CIDR`, `/24` or
  `net.ParseCIDR` across `internal/placement`, `internal/store/placement.go` and
  `internal/p2p/disperse.go` returns nothing. Placement distinctness is
  **per-peer only**. The diversity level the roadmap assumes is [BUILD NOW], not
  a reuse.
- **`route.go`'s diversity is self-declared.** Its own comment is the correct
  statement of the limit: a Sybil swarm declares exactly what an honest diverse
  set declares. Observed prefix and ASN are the only non-self-declared signals
  available, and they are weak (§15.4).

---

### 15.2 The layered mechanism

> **AS BUILT (2026-08-16) — P14.** `internal/axon/sybil`, 17 tests, plus the
> §17.2 contract fix and the DHT's caps moved into `params`.
>
> **The property that makes the bond worth anything is enforced by a type, not
> by care.** T14.2 requires that a bond come from the light client's verified
> state root and never from a provider's word. `ProofSource` therefore returns
> **proof nodes and nothing else** — no balance, no decoded slot, no `Amount`
> field — so there is no value a caller could take from a provider and use, and
> trusting one is not expressible. The slots are read from
> `solc --storage-layout` (`bonded` = 1, `pendingWithdraw` = 2), not counted by
> hand: `Ownable` packs `_owner` with `withdrawDelay` in slot 0, so a reading of
> `StakeVault.sol` alone would put the mappings one slot too early.
>
> **T14.3's composition found a live drift.** `internal/axon/dht` declared
> `MaxPerPrefixPerBucket = 2` and `MaxPerASNPerBucket = 8` as its own literals
> while path, replica set and guard set each had their own idea of the same
> rule. Four copies of a policy drift, and a cap that has drifted at one
> selection point out of four is not a weaker cap — the adversary uses that
> point. The figures now live in `params` and `sybil.CapsFor` is the one
> function; an audit fails the build on a re-introduced literal, and it was
> verified to do so.
>
> **T14.5 is measured, and the measurement's limit is recorded with it.** At the
> configured 18 bits the puzzle costs ~262 144 hashes: **0.10 s** on the
> development machine at 2.7 MH/s, ~1.9 s on a machine 20× slower. **That is
> not the low-end hardware T14.5 names**, so the exclusion the difficulty causes
> on a low-end device remains unmeasured and is stated as such in the test's own
> output.
>
> **A pending withdrawal is reported, not refused.** StakeVault moves stake from
> `bonded` to `pendingWithdraw`, where it is still slashable, so a node with one
> still backs its claim — but a client about to pin a 45-day guard should know
> the operator has announced an exit, and only the client can weigh that.
>
> **Deliberately NOT claimed. E14.2 is not discharged.** `AdmitStore` is built
> and tested — bond plus local policy, no coordinator, no network import, and an
> audit forbidding one — but **nothing calls it in production and nothing
> usefully could**: `StakeVault` is written and **deployed nowhere**, so
> `VerifyBond` has no chain to prove against and every writer would present an
> unprovable bond and be refused. Switching `internal/p2p`'s coordinator lease
> to this before the contracts are deployed would replace a working centralised
> gate with a closed one. **The sequencing is the deployment, not the code.**
>
> **And the calibration is still `[UNSOLVED]`.** Every bond floor is a
> placeholder. E14.3 is discharged by an audit that requires the block to carry
> its blanket provisional statement and every constant to state a derivation —
> including "derivation: none available", which is the honest answer for the
> floors and the most useful thing the audit records. The audit was itself found
> vacuous on first writing (it accumulated one comment across the whole block so
> every constant inherited every other's documentation) and was fixed after an
> injected-violation check failed to fail.

```text
  L6  randomised selection        attacker cannot CHOOSE to be on a given path
  L5  age + measured contribution weight, never a gate
  L4  proof of work               cheap admission where a bond is too heavy
  L3  bonded stake (StakeVault)   roles that carry consequence
  L2  diversity constraints       caps damage from many identities in one place
  L1  KadID derivation (§7.2)     identities cannot be freely PLACED
  ────────────────────────────────────────────────────────────────────────
  L0  identity is free            the fact none of the above changes
```

Each layer, with what it costs the honest node, what it costs the attacker, and
how it fails.

#### L1 — KadID binds identity to a prefix and an epoch [BUILD NOW]

`KadID = H(NodeIdentity ‖ SRV_epoch ‖ network-prefix)`, rotating each 24 h epoch
(§7.2). An attacker cannot choose where in the keyspace an identity lands,
because two of the three inputs are outside its control: the SRV comes from the
verified beacon RANDAO (R13) and the prefix is observed, not declared.

- **Honest cost:** one hash per epoch; a full DHT routing-table refresh every 24 h
  and the churn that implies. Non-trivial: every node's neighbours change daily.
- **Attacker cost:** grinding must be redone every epoch, and it is bounded by
  the number of `(NodeIdentity, prefix)` pairs the attacker can hold — not by
  hashing.
- **How it fails:** *within one prefix, the attacker can generate unlimited
  NodeIdentity keys.* The prefix term does nothing on its own. L1 only converts
  "grind for free" into "grind per prefix per epoch", and is worthless unless
  something caps identities per prefix. **This is the single most important
  honest statement in the section**, and §15.4's arithmetic depends on it.

#### L2 — diversity constraints in path and placement selection [BUILD NOW]

Cap how many selected slots one /24 (v4), /48 (v6), or ASN may occupy in a
circuit, a replica set, or a witness draw.

- **Honest cost:** an honest operator running several nodes in one datacentre is
  throttled to one slot. Real, and it is the price. A small network may fail to
  build a diverse path at all — `route.go`'s answer (refuse, do not degrade) is
  the right one and must be kept.
- **Attacker cost:** must acquire address space in distinct prefixes/ASNs rather
  than distinct keys.
- **How it fails:** IPv6 (below), cloud address rental, and the fact that ASN
  data comes from an external mapping that must itself be obtained and trusted.
  An attacker inside one large cloud provider's ASN is throttled the same way an
  honest operator is — meaning the constraint hurts the honest more, since the
  attacker chooses their hosting to defeat it and the honest operator does not.

#### L3 — bonded stake via `StakeVault`, for consequential roles [BUILD NOW]

Relay, storage holder, introduction point. The contract exists; the policy does
not.

- **Honest cost:** capital locked, plus a 24 h withdrawal delay, plus exposure to
  slashing for faults that may be operational rather than malicious. This is the
  layer most likely to exclude exactly the volunteer operators §14.7 depends on.
- **Attacker cost:** linear in identity count. Budget `M`, bond floor `F` →
  `M/F` identities. This is the only layer with an unambiguous price.
- **How it fails — the plutocracy objection:** stake-weighted selection means the
  richest party is selected most, which for an anonymity network means the
  richest party sees the most traffic. Weight caps blunt it and do not remove it.
- **How it fails — the sublinear-weighting trap, present in the existing code:**
  `selectionWeight` in `facilitation/witness.go` is `sqrt(stake) × reputation`.
  Splitting stake `S` across `k` identities yields total weight
  `k·sqrt(S/k) = sqrt(k)·sqrt(S)` — a **`sqrt(k)` gain for splitting**. The sqrt
  is presumably there to limit plutocracy, and it does; it also makes Sybil
  splitting strictly profitable. Both effects are real. The fix is not to change
  the curve (linear weighting is Sybil-neutral but maximally plutocratic) but to
  impose a **minimum bond per identity**, which caps `k ≤ S/F`. Recorded here as
  a finding against the existing implementation, not a hypothetical.

#### L4 — proof of work for cheap admission [BUILD NOW]

Where a bond is too heavy: client-side circuit extension under load, intro-point
access (R10), DHT record publication, first contact with a guard.

- **Honest cost:** seconds of CPU on first contact, near-zero steady state; worst
  on a phone.
- **Attacker cost:** linear in identity count and in request count, and it is the
  only layer that costs an attacker *per action* rather than per identity.
- **How it fails:** the honest/attacker hardware asymmetry is enormous (a GPU or
  a rented fleet against a phone), so the puzzle difficulty that inconveniences an
  attacker is the difficulty that excludes a mobile client. Memory-hard functions
  narrow the gap and do not close it. PoW is a **rate limiter**, and Tor's real
  DoS experience is that it is worth having as exactly that and nothing more.

#### L5 — age and measured contribution as weight, never a gate [BUILD NOW]

An identity's selection weight rises with observed uptime and delivered work.

- **Honest cost:** new honest nodes are underweighted for a warm-up period. The
  network is slower to absorb new capacity.
- **Attacker cost:** patience. An attacker who registers a fleet and waits 90
  days pays only hosting.
- **How it fails:** it is a *delay*, not a barrier, and it must never be a gate —
  a hard age requirement freezes the relay set, which is worse for diversity than
  the Sybils it excludes. "Measured contribution" also has no third-party
  measurement for relaying (§14.6, A2), so for relays this reduces to observed
  reachability and uptime, which are cheap to fake favourably.

#### L6 — randomised selection [BUILD NOW]

Path and replica selection draw from a weighted sample seeded by the SRV; an
attacker cannot choose to be on a *specific* client's path, only to raise its
probability of being on *some* path.

- **Honest cost:** none, beyond losing the ability to prefer fast peers
  deterministically.
- **Attacker cost:** converts a targeted attack into a probabilistic one, which is
  the single largest structural win in this list.
- **How it fails:** it does nothing against an attacker who is content to
  compromise *some* users, which describes most real adversaries. And guard
  pinning (R1) deliberately reduces re-randomisation: two pinned guards for 45
  days means a bad draw persists.

---

### 15.3 Cost table

**These figures are illustrative and parameterised, not measured.** Prices for
address space and hosting move, and this document does not have a priced quote.
Re-price before any of it is used to set a bond.

| Resource an identity needs | Rough order | Comment |
|---|---|---|
| Ed25519 keypair + hash (a KadID candidate) | microseconds, free | The reason identity count must be gated elsewhere |
| A registration in `NodeRegistry` | one transaction; **zero** for the node under `registerWithSig` + paymaster | The paymaster's "per-node rate limits" are listed as *not yet built* in the PoF README |
| A distinct IPv4 address in a cloud | a few dollars per month per address, list price | Verify against current provider pricing before use |
| A distinct /24 | 256 addresses' worth, or a lease | The unit L2 actually constrains |
| A distinct ASN | registration fee plus an upstream willing to announce | The most expensive unit, and the one an attacker least needs |
| A distinct IPv6 /48 | **effectively zero** | See below |
| A bond of `F` credits | `F`, plus a 24 h withdrawal delay | The only layer with a clean price |

**The "IP addresses are cheap in the cloud" objection, stated at its strongest.**

- IPv4 is metered and therefore has a real price, which is why /24-level
  constraints have any force at all in v4.
- **IPv6 defeats prefix diversity structurally, not economically.** A routed /48
  contains 65,536 /64s and 256 /56s. A hosting provider's typical RIR allocation
  is a /32, which contains 65,536 /48s. If the diversity unit is a /64, one
  ordinary allocation yields tens of thousands of "distinct" identities for the
  cost of one VPS. Choosing /48 as the v6 unit (as Constitution §5 does) is
  correct and still leaves an attacker inside a large provider with as many /48s
  as the provider is willing to sub-allocate.
- ASN diversity is stronger and much coarser: there are on the order of a hundred
  thousand ASNs globally, but a handful of cloud ASNs host a large fraction of all
  reachable capacity, so ASN-diverse and *actually* independent are different
  properties. An attacker in three large clouds satisfies a three-distinct-ASN
  constraint completely.

The honest summary: **prefix diversity prices an attacker in IPv4, embarrasses
itself in IPv6, and is defeated in both by anyone willing to buy hosting from
three providers.** It is still worth having, because it converts "free" into
"non-zero" and because — per `route.go` — excluding on a weak signal is safe
while trusting one is not.

---

### 15.4 Eclipse arithmetic

#### Against a specific target key

The `r = 8` replicas of a record live at the 8 KadIDs closest to the key. With
`N` nodes distributed uniformly over the keyspace, the ball containing the 8
closest covers approximately `8/N` of the space. A single grinding attempt — one
Ed25519 keypair, one hash — lands inside that ball with probability `8/N`, so:

```text
  expected candidates to place ONE identity in the top 8   ≈ N / 8
  expected candidates to place ALL 8                       ≈ N
```

| `N` (network size) | Candidates to own one of the top 8 | Candidates to own all 8 |
|---:|---:|---:|
| 1,000 | 125 | 1,000 |
| 10,000 | 1,250 | 10,000 |
| 100,000 | 12,500 | 100,000 |
| 1,000,000 | 125,000 | 1,000,000 |

Each candidate costs a keypair and a hash. **If identities are free, eclipsing a
chosen key is free**, for any network size in the table. This is why L1's
epoch/prefix binding matters only in combination with a cap: it forces the
grinding to be redone every 24 h and, critically, forces each candidate to come
with a prefix the attacker controls.

Now add a cap of `m` identities per /24 (or per /48, or per ASN). The attacker's
candidate pool per epoch is `m × c` for `c` controlled prefixes, so:

```text
  prefixes needed to own all 8 replicas of a chosen key   c ≈ N / m
```

| `N` | `m = 1` | `m = 4` | `m = 16` |
|---:|---:|---:|---:|
| 10,000 | 10,000 prefixes | 2,500 | 625 |
| 100,000 | 100,000 | 25,000 | 6,250 |

In IPv4 those are real numbers — 2,500 /24s is 640,000 addresses. In IPv6 with a
/48 unit and a cooperative provider, 2,500 prefixes is a configuration file. The
same table is therefore a defence and a joke depending on the address family,
and the roadmap must say so rather than quote the v4 column alone.

**What this arithmetic assumes and does not prove:** uniformity of KadIDs
(reasonable under a hash), that the attacker cannot influence the SRV (R13 notes
RANDAO's last-revealer bias — a few bits of bias shifts *which* keys are
convenient, not the cost structure), and that lookups actually reach the closest
nodes, which is exactly what a partitioned view (R14) breaks.

#### Against a specific node

Two targets with different costs: capture a node's **routing table** by filling
its k-buckets, or capture its **traffic** by being its guards. Routing-table
capture is bounded by `d = 3` disjoint lookup paths — a lookup survives if any
one path is honest. Under independent selection with attacker share `f` of
*selectable, diversity-distinct* slots:

| `f` | P(one path hostile) = `f` | P(all `d = 3` hostile) ≈ `f³` | P(both pinned guards hostile) ≈ `f²` |
|---:|---:|---:|---:|
| 0.05 | 5 % | 0.0125 % | 0.25 % |
| 0.10 | 10 % | 0.1 % | 1.0 % |
| 0.20 | 20 % | 0.8 % | 4.0 % |
| 0.30 | 30 % | 2.7 % | 9.0 % |

Two caveats that matter more than the table:

1. **`f` is a share of weighted slots, not of nodes.** Under bandwidth weighting
   (R14) an attacker with 10 % of advertised-and-bonded capacity has `f = 0.10`
   regardless of how many machines that is. Money buys `f` directly — the
   wealth-based path bias of §14.7.
2. **Disjointness is over node identity, not over operator, prefix or ASN.**
   Three "disjoint" paths through one cloud provider are one path. `d = 3` is
   worth what the diversity constraint underneath it is worth, which §15.3 says
   is not much in the worst case.

#### The bootstrap case, which is the worst one

A node joining for the first time has no peer set, no history, and no basis to
judge what it is told. Its entire view of the network comes from whoever answers
first. Guard pinning then makes a bad first contact durable for 45 days. This is
the epistemic-partition problem R14 refuses to paper over, and no layer in
§15.2 addresses it: KadID derivation, diversity constraints, bonds and PoW all
presuppose an approximately correct view of the network in order to be checked.
**[UNSOLVED].** The palliatives — multiple independent bootstrap sources,
required agreement between them, and comparison of the observed relay-set size
against the chain-anchored registry snapshot — reduce the chance of a *silent*
partition without eliminating it.

---

### 15.5 What a large budget still achieves

Stated plainly, because the layered defence above can read as more than it is. An
attacker with substantial funding, operating within the adversary model of §4,
can still:

- **Hold a stable, non-trivial `f`.** Bonds are purchasable; bandwidth is
  purchasable; ASNs and prefixes are purchasable. Nothing here caps `f` at a
  small number — it only makes `f` cost money instead of nothing.
- **Own the replica set of a chosen key** whenever the per-prefix cap `m` and the
  address family make `N/m` prefixes affordable — which in IPv6 is usually.
- **Be the first hop for a predictable fraction of clients**, permanently for 45
  days at a time, per the guard table above.
- **Wait.** Age-based weighting (L5) is defeated by patience, and an attacker who
  registers a fleet and behaves perfectly for three months arrives with maximum
  reputation and maximum weight.
- **Partition new nodes**, per §15.4's bootstrap case, which is the cheapest
  high-value attack in the whole list.
- **Degrade rather than break.** Selective dropping, slow forwarding and
  intermittent unreachability are cheap, hard to attribute, and push honest
  clients toward whichever paths remain fast — which the attacker also controls.

What the layers do buy: none of it is *free*, none of it is *reliably targeted
at a named individual*, and none of it is *silent* — bonded identities are
enumerable, prefixes are observable, and a shift in the relay set's diversity
distribution is a detectable event. Cost, bounded damage, and observability. Not
resistance.

---

### 15.6 Decision table — §15

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| **KadID = H(NodeIdentity ‖ SRV_epoch ‖ prefix)**, rotating every 24 h | Free placement in the keyspace next to a target key | S/Kademlia's constrained node-id generation; I2P's floodfill placement is the counter-example to avoid | Prefix and a chain-verified SRV as inputs, so neither the operator nor a directory authority chooses position | Freely chosen node ids (I2P-style floodfill placement, Sybil-prone); ids from a central authority (refused by R14) | Daily full routing-table churn; and the prefix term is inert against unlimited keys inside one prefix |
| **Cap selected slots per /24, /48, ASN** in paths, replica sets and witness draws | Many identities in one place | Tor's `/16` and family-based path restrictions | Applied to DHT replica placement and witness selection too, not only circuits — and the placement engine must be *built*, since `internal/placement` has no prefix awareness | Self-declared operator labels as proof (`route.go` explicitly refuses this); no constraint at all | Throttles honest multi-node operators; ASN data is an external dependency; near-useless in IPv6 |
| **Bond via `StakeVault` for consequential roles, with a minimum bond per identity** | Unbounded free identities in roles that carry consequence | None — neither Tor nor I2P bonds relays | A per-identity **floor** rather than a weight curve, specifically because `sqrt(stake)` weighting makes splitting profitable by `sqrt(k)` | Weight-curve-only defences (sublinear rewards splitting; superlinear is maximally plutocratic); bonding *everything* (excludes volunteers, contradicts §14.7) | Plutocracy: the richest party sees the most traffic. Excludes exactly the volunteer operators the network depends on |
| **PoW as a rate limiter, not an admission gate** | Cheap flooding of intro points, DHT publishes, circuit extends | Tor's onion-service DoS defence (R10) | Scoped to per-action rate limiting; never a substitute for a bond or an identity price | PoW-as-identity-price (a rented fleet beats a phone by orders of magnitude) | Excludes weak clients under load — exactly when they most need the network |
| **Age and contribution as weight, never a gate** | New identities arriving at full power | Tor's guard/stable/fast flags earned over time | Explicitly a weight; a hard age gate is refused because it freezes the relay set | Age as a hard requirement | Defeated by patience; and for relays there is no third-party contribution measurement (§14.6, A2) |
| **Randomised, SRV-seeded selection** | An attacker choosing to be on a specific path | Tor's weighted random path selection | Seeded from the verified beacon SRV rather than a directory authority's commit-reveal (R13) | Deterministic "best peer" selection (lets an attacker advertise its way onto chosen paths) | Nothing against an attacker satisfied with *some* victims; guard pinning makes a bad draw durable for 45 days |
| **Mark the whole area [UNSOLVED] in the document** | Overclaiming | — | An explicit statement rather than an implied one | Presenting defence-in-depth as a solution | None, and this is the point |

---

### What this section does NOT establish

- **It does not solve Sybil resistance, and does not claim to.** Every mechanism
  raises cost or bounds damage. An attacker with a budget still obtains a stable
  fraction of the network, and §15.5 enumerates exactly what that fraction buys.
- **No bond amount, no PoW difficulty, no per-prefix cap `m` is set.** All three
  are policy numbers that depend on network size and on a real price for address
  space, and none of that exists yet. `m` appears in §15.4 as a parameter, never
  as a value.
- **The cost figures are illustrative.** No address-space or hosting price in
  §15.3 was quoted from a supplier. They are orders of magnitude to be replaced.
- **The eclipse arithmetic assumes uniform KadIDs, honest lookup routing, and an
  unbiased SRV.** A partitioned view (R14) invalidates the third assumption in the
  most damaging way, and the bootstrap case has no defence at all.
- **`f` is not derived.** Every probability in §15.4 is conditioned on an attacker
  share of weighted, diversity-distinct slots, and this section does not estimate
  what share is purchasable at what price.
- **The prefix/ASN diversity engine is specified, not reused.**
  `internal/placement` enforces distinct *peers*, not distinct prefixes; the
  Constitution's "reuse the existing placement engine's diversity levels" does not
  describe the code as it stands.

> **Objection to Constitution §5 (DHT replication row):** the parameter table
> states `r=8 across distinct /24 (v4), /48 (v6) and distinct ASNs` and §0
> describes the placement engine as "diversity-aware", implying reuse. Read from
> `internal/placement/{plan,level}.go` and `internal/store/placement.go`, the
> engine's guarantee is that no two shards of one chunk go to the same *peer*;
> there is no prefix, CIDR or ASN handling anywhere in it. This is a build, not a
> reuse, and any section that budgets it as reuse will be wrong about the work.

> **Objection to Constitution §6 R11 (scope):** R11 fixes blind-signed tokens as
> the payment mechanism and separately rules that the economic layer is not in v1.
> Those are consistent, but the ordering matters: §14.3's anonymity set is `P·B`
> where `P` is the paying population, so a token scheme deployed to a small
> network is a *labelling* mechanism rather than a private one. The recommendation
> is that trigger criterion E5 (a paying-population floor) be treated as binding
> alongside R11, not as advisory — otherwise a future author can satisfy R11 to
> the letter and reduce anonymity.
