# ChannelManagerV2 — Ethereum Mainnet readiness

A NEW roadmap, not a patch to `channel-payments.md`. That one records what was
built. This one records what is missing between here and a deployed contract,
in an order an agent can execute phase by phase without rediscovering the same
gaps.

Scope: the infrastructure around P15, not P15 itself. P15 is complete and
committed (Repo A `2e2b132`). Nothing here redesigns it.

```text
STATUS      P12 gate OPEN. DeployableChallengePeriod() returns 28800 s (8 h).
            ChannelManagerV2 is DEPLOYED to Ethereum Mainnet.
CONTRACT    0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c   block 25757314
TREASURY    0xE36e04b6Df20C00479005ba23233F67192f38421   (key never enters an agent)
CHAIN       Ethereum Mainnet, chain ID 1
NODE        release 9fdf30d published, Linux only
SITE        Repo A 2e2b132 deployed
NEXT        Phase 12 — P15 was validated against chain 31337, not this contract.
            Deployment proves nothing about P15 until Phase 12 re-establishes it.
```

---

# Current state and blockers

## The finding that reorders the phases

`DeployableChallengePeriod()` checks **header canonicality first**, before it
looks at a single piece of evidence:

```go
if err := v.Headers.Check(); err != nil { return 0, err }   // canonicality
missing := v.Unvalidated(now)                                // then the six terms
```

Its own comment: *"A perfectly measured challenge period defends a channel on a
chain we cannot prove is Ethereum, which is not a smaller problem than an
unmeasured one."*

`HeaderTrust` requires `Status: CanonicalityVerified`, an `Implementation` and
an `Anchor`. Proving canonicality is what `internal/ethproof` does — through
BLS sync-committee verification, which is now behind the `ethbls` build tag.
**The seven published release binaries contain no BLS at all.**

So there is a real possibility that the gate's first check cannot be satisfied
by any binary currently shipped. Nobody has traced it.

This is the highest-priority unknown, and it is Phase 0. It is **not** an
assertion — it is the question that must be answered before the ordering of
everything below can be trusted, because the answer may change the release
architecture.

## The evidence model is not incomplete — the runners are missing

`Evidence`, `Record()`, `Unvalidated()`, `AsEvidence()`, `ObserveFailover()`,
`IndependentEndpoints()` and `OperatingEnvelope` all exist and are tested. What
does not exist anywhere in the tree:

```text
no CLI or cmd/ entry point for ANY probe   ObserveFailover is library-only
no transaction construction or broadcast   for inclusion or repricing
no secure signer abstraction               only DEPLOYER_PRIVATE_KEY, a raw env key
no spend budget, ceiling, or dry-run       nothing anywhere defines a limit
no detection harness at production scale
```

Phase 1 is therefore **evidence filing runners**, not "evidence model
completion". Three of the six terms need no measurement at all — only filing.

## Blockers

Every blocker below was closed in Phases 0-11. Kept as the record of what had to
be built, not as outstanding work.

| Blocker | Kind | Closed by |
|---|---|---|
| Canonicality may require `ethbls`; release binaries have no BLS | **unknown — audit first** | Phase 0 — `HeaderTrust.Check()` is declarative and never calls `ethproof` |
| No secure signer; only a raw private key in an env var | engineering + human | Phase 2 — `ExternalSigner`, Web3Signer on loopback |
| No inclusion/repricing transaction implementation | engineering | Phases 5-6 — `SendMeasured`/`AwaitInclusion` |
| No measurement spend budget defined anywhere | **human decision** | Phase 3 — `SpendBudget`, zero value refuses |
| No probe CLI or runner | engineering | Phase 1 — `cmd/p12-evidence` and the per-term runners |
| No detection harness at 1000 channels x 2 watchtowers | engineering | Phase 7 — `cmd/p12-detection`, 30 sweeps, every sweep audited |
| RPC list has 3 same-provider clusters; 5 are `wss://`, prober is HTTP | engineering | Phase 4 — `cmd/p12-failover` over 4 distinct registrable domains |
| 18 reorg observations exist but are not filed as Evidence | engineering (small) | Phase 1 |
| Envelope and outage commitment supplied but not filed | engineering (small) | Phase 1 |

The one thing still open is not a gate: **source verification is not published to
a block explorer**, because no API key is configured. The bundle that does it is
committed and proven to recompile (Phase 11).

## What is genuinely done

Reorg policy reduced 30 -> 18, scoped to reorg depth alone (`MinReorgSamples`,
`minSamplesFor()`), tested, other terms untouched at 30. Website deployed. Node
release published and verified for Linux. P15 complete and browser-validated on
devnet.

## User-supplied inputs, on record

```text
RPC attestation   "The selected RPC providers are intended to be operationally
                   independent and are not known to share a common upstream
                   provider."
envelope          1000 channels/watchtower, 2 watchtowers, 30s sweep
on-call           "A designated operator is responsible for watchtower incidents."
response          "Incident response begins within 15 minutes of an outage alert."
reorg             18 mainnet observations, max depth 1, ~57h, ~17,163 blocks
                  raw: /home/bruns/p12-reorg/data/events.jsonl
```

An input being supplied does not make a gate pass. It makes the gate
*fileable*. The repository's validation code is the only authority on whether a
term is validated.

---

# Phases

Legend: **[CODE] [TEST] [INFRA] [MAINNET] [HUMAN]**

---

## PHASE 0 — Canonicality and gate audit — **ANSWERED**

**Result: canonicality does NOT require an `ethbls` build. The hypothesis at the
top of this document was wrong, and the release architecture is unaffected.**

`HeaderTrust.Check()` is a DECLARATION, not a computation. It never calls into
`internal/ethproof`. It checks only:

```text
CanonicalityVerified      -> Implementation must be non-empty
                             Anchor must be non-empty
CanonicalityAcceptedRisk  -> AcceptedBy and Reason must be non-empty
anything else             -> refuse: "header canonicality is UNVERIFIED"
```

`Implementation` names WHAT establishes canonicality ("native sync committee
verifier", "helios sidecar v0.x") so that, in the field's own words, *"a vendored
light client cannot pass as a native one."* `Anchor` is where the trust anchor
came from and **must not be the RPC being verified**.

So the gate does not verify canonicality itself — it requires an operator to
STATE what did, and to name the anchor. That is a deliberate design: the check
exists so the claim is on record with something answerable behind it.

**Consequences for this roadmap.**

1. Phase 0 no longer blocks or reorders anything. Delete the "highest-priority
   unknown" framing at the top of this file when convenient.
2. There is a THIRD path nobody had noticed: `CanonicalityAcceptedRisk`, which
   permits deployment with a named person and a stated reason. It is a
   legitimate, auditable escape hatch — and precisely the kind of thing that
   should be used deliberately or not at all. **Do not reach for it merely
   because verification is inconvenient.**
3. A new **[HUMAN]** input is required that was not previously on the list:
   the `Implementation` and `Anchor` strings, or an accepted-risk declaration.
   Whoever supplies them is asserting that canonicality really was established.
4. The `ethbls` question remains operationally real — if `Implementation` says
   "native sync committee verifier", the binary doing that verification must
   actually contain BLS. The gate will not catch a false claim here. That is a
   review responsibility, not a code one.

Original phase brief follows, retained for the record.

No Mainnet side effects. No human approval unless the answer forces one.

**Objective.** Determine what `HeaderTrust.Check()` actually requires, and
whether a release binary can produce it.

**Why required.** It is the first check in the gate. If it needs `ethbls`, the
release matrix, the published artifacts and the deploying host's architecture
all change, and every later phase is built on a wrong assumption.

**Files.** `internal/channel/validation.go` (`HeaderTrust`, `Check`,
`CanonicalityVerified`), `internal/ethproof/{lightclient,finality,rotation,
bls.go,bls_stub.go}`, `scripts/build-release.sh`, `SECURITY.md`.

**[CODE-audit].**
1. Trace every path that can set `Status: CanonicalityVerified`.
2. Determine whether any of them reaches `SyncCommitteeVerifier`.
3. Determine what `Anchor` and `Implementation` must contain and who supplies them.
4. Establish whether a no-BLS binary can ever set it.
5. Establish whether canonicality is verified once and recorded, or continuously.

**[TEST].** None new. This phase reads.

**Acceptance.** A written answer with the call path: *canonicality is / is not
reachable without `ethbls`*.

**Security risk.** Getting this wrong means deploying against a chain whose
canonicality was never actually proven — the exact failure the check exists to
prevent.

**Rollback.** N/A, read-only.

**STOP if** canonicality requires BLS. Then a human decides whether the
deploying host runs an `ethbls` build, and whether that build is published.

---

## PHASE 1 — Evidence filing runners — **COMPLETE**

**Delivered.** `cmd/p12-evidence/{main.go,main_test.go}`. 10/10 tests pass.

```text
reorg depth        FILED    measured 12.036758964s   samples 16,650
watchtower outage  FILED    measured 15m0s
envelope           STATED   1000 channels / 2 watchtowers / 30s / 15m response
unvalidated         detection, inclusion, repricing, rpc failure   (6 -> 4)
gate                ERROR — header canonicality UNVERIFIED
```

**How the reorg numbers were derived.** `ReorgObservation.AsEvidence()` already
existed, so nothing was hand-computed: it sets `Measured: MaxDepthTime` and
`Samples: Blocks` itself. The runner only reconstructs the observation from the
raw log, using the same formula as `chainprobe.finishObservation`:

```text
Blocks        = (last head - first head) + 1   = 16,650   (span is INCLUSIVE)
BlockInterval = window / (Blocks - 1)          = 12.0368s (one fewer gap than blocks)
MaxDepthTime  = MaxDepth x BlockInterval       = 12.0368s -> Measured
```

Both divisors bit during development — `Blocks` instead of `Blocks-1`, and a
non-inclusive span — so the test states the expected interval as a literal over
a hand-chosen span rather than recomputing it the same way.

**Two findings worth carrying forward.**

1. `Samples` is `Blocks` (16,650), **not the reorg event count** (18). The
   30 -> 18 policy reduction was therefore probably never the real blocker on
   this term. It does no harm, but nobody should treat it as load-bearing.
2. The gate now fails on **canonicality**, which runs before the terms. The
   runner deliberately does NOT set `HeaderTrust`: a filing tool asserting that
   the chain was verified would be the tool making that claim. See
   `doc/trust-anchor.md`, referenced by the refusal and still unread.

**Tests.** Reconstruction vs. a stated literal · deepest-not-last · malformed
line refused rather than skipped · empty log refused · single event refused as
"costless" · raw log never modified · production envelope `Stated()` · every
missing envelope field refused · filing leaves exactly the four measurements ·
the gate still refuses without canonicality.

Original phase brief follows, retained for the record.

No Mainnet side effects.

**Objective.** Turn the three already-supplied inputs into state the validation
code accepts. Shrinks the outstanding gate list from six terms to three.

**Why required.** These need no measurement. Filing them first exercises the
whole `Record()` path before any money is at risk, and surfaces schema
mismatches while they are cheap.

**Files.** `internal/channel/validation.go`.
**New.** `cmd/p12-evidence/main.go`; possibly `internal/channel/p12file.go`.

**[CODE].**
1. **Production `OperatingEnvelope`** — `Channels: 1000`, `Watchtowers: 2`,
   `SweepInterval: 30s`, `OnCall`, `OnCallResponse: 15m`. Decide where it lives
   (config file vs. constant). `Stated()` must pass. Must NOT reuse
   `testEnvelope()`.
2. **Reorg filing** — read `events.jsonl` READ-ONLY. Derive `Samples` (18),
   `Measured` (from max observed depth, in the reorg term's unit — read the
   budget to learn which), `ChainID: 1`, `Method` (a real description of how the
   observer ran), `TakenAt`. Never mutate the raw file.
3. **Outage filing** — determine whether the outage term takes `Evidence`
   (it IS in `termsNeedingEvidence`) with `Measured = OnCallResponse`, or is
   satisfied by the envelope alone. Inspect; do not assume.

**[TEST].**
- reorg file -> Evidence round trip
- a tampered/truncated file is refused
- fewer than `MinReorgSamples` refused
- envelope `Stated()` passes with production values
- outage evidence accepted, and refused when `OnCall` is empty
- `Unvalidated()` drops exactly the filed terms and no others

**Acceptance.** `Unvalidated()` returns exactly
`{rpc failure, inclusion, repricing, detection}`.

**Security risk.** Mis-deriving `Measured` from reorg depth files a wrong number
into an immutable derivation. Requires a second independent reading of the unit
before filing.

**Rollback.** Delete the evidence record; raw observations untouched.

---
   
## PHASE 2 — Secure measurement signer

**[HUMAN] required.** No Mainnet side effects in this phase.

**Objective.** A signer that proves
`address() == 0xE36e04b6Df20C00479005ba23233F67192f38421`
without the key entering the agent, the source, the logs or the session.

**Why required.** Phases 5 and 6 broadcast ~90 real transactions.
`DEPLOYER_PRIVATE_KEY` is a raw key in an env var — adequate for a one-off
deploy under a human's eye, not for scripted repetition.

**Options, least invasive first. Do not pick blindly — audit, then choose.**
1. **External signer process over a local socket**, clef-compatible JSON-RPC
   (`account_signTransaction`). No key in this repository at all.
2. **Hardware wallet via clef.**
3. **Keystore file + passphrase supplied out of band at runtime.**
4. **A remote-signer implementation of the existing `ChainWriter` interface.**

The repository already has the right shape: `ChainWriter` is an interface, and
`StateSigner` is `func([32]byte) ([]byte, error)`. A signer abstraction fits the
existing grain rather than cutting across it.

**[CODE].** Define `MeasurementSigner` with the full pipeline:

```text
construct -> estimate gas -> spend check -> ADDRESS CHECK -> sign
          -> broadcast -> confirm -> record evidence
```

Address verification is a hard precondition that refuses, never a log line.

**[TEST].**
- mocked signer, happy path
- wrong-address signer REFUSES
- wrong chain ID refuses
- nil signer refuses
- no test file contains a private key

**Acceptance.** `signer.Address()` returns the treasury address, cross-checked
against a live `eth_getBalance`, with no secret written anywhere the agent reads.

**Security risk.** This is the phase where a mistake exposes a funded key.
Nothing here may print, copy, export or persist key material.

**STOP if** no mechanism can prove the address without exposing the key.

---

## PHASE 3 — Spend safety

**[HUMAN] required.** Blocks every Mainnet phase.

**Objective.** A financial safety layer that refuses before it spends.

**Why required.** No budget exists anywhere in the repository. A ceiling must be
introduced as required configuration, never invented by an agent.

**[CODE].** Configuration: `MaxTotalWei`, `MaxPerTxWei`, `MaxTransactions`,
`DryRun bool`. Preflight refusals, each its own error:

```text
signer address != treasury          refuse
chain ID != 1                       refuse
balance < projected spend           refuse
projected spend > MaxTotalWei       refuse
tx count > MaxTransactions          refuse
no ceiling configured               refuse
```

`DryRun` defaults TRUE. Live requires explicit opt-in.

**[TEST].** Every refusal has a test. A dry run broadcasts nothing — assert zero
calls reach the sender. Ceiling arithmetic tested at the boundary, not near it.

**Acceptance.** With no ceiling configured, the measurement refuses to start.

**[HUMAN].** The operator supplies the ETH ceiling. Order of magnitude: >=30
inclusion samples plus >=30 repricing cycles, each cycle being an original AND a
replacement, is **90+ Mainnet transactions**. At 21,000 gas for simple
self-transfers the cost is dominated by base fee, so the ceiling must be set
against a measured estimate at execution time, not a guess written here.

**Rollback.** None once spent. This is why the phase precedes any broadcast.

---

## PHASE 4 — RPC failover measurement

Read-only. No Mainnet side effects (no transactions).

**Objective.** >=30 rounds across >=2 independent providers, `AllFailed == 0`,
filed through `AsEvidence`.

**Why first among the measurements.** It costs nothing, needs no signer, and
exercises the observation -> evidence -> filing path end to end.

**Files.** `internal/channel/chainprobe.go`.
**New.** `cmd/p12-failover/main.go`.

**What `AsEvidence` refuses**, verified in source:

```text
fewer than 2 endpoints        "the rpc-failure term assumes failover is possible"
endpoints sharing a provider  IndependentEndpoints/providerOf
empty attestation             "a probe cannot establish that two providers do
                               not share an upstream"
AllFailed > 0                 an unbounded wait is not a measured one
```

**Endpoint selection [CODE + HUMAN].** Exclude same-provider clusters:
`rpc.mevblocker.io` (x4), `blxrbdn.com` (x4), `rpc.flashbots.net` (x2), plus
duplicate `tenderly` / `publicnode` / `drpc` / `0xrpc` entries. Exclude `wss://`
endpoints unless a WebSocket adapter is written — `ObserveFailover` uses
`http.Client`. Distinct providers available: `publicnode`, `drpc`, `llamarpc`,
`lava.build`, `meowrpc`, `blockpi`, `zan.top`, `1rpc`, `blastapi`, `tenderly`,
`onfinality`, `pocket.network`, `nodereal`, `stakely`.

**[CODE].** CLI taking endpoints, rounds, gap, attestation; runs
`ObserveFailover`; calls `AsEvidence`; files through `Record`. Dry-run mode.

**[TEST].**
- `IndependentEndpoints` rejects two mevblocker URLs
- a single endpoint is refused
- empty attestation refused
- `AllFailed > 0` refused
- deterministic run against a stub HTTP server

**Acceptance.** rpc-failure leaves `Unvalidated()`.

**STOP if** no two endpoints survive independence checking.

---

## PHASE 5 — Inclusion measurement

**[MAINNET].** Depends on Phases 2 and 3.

**Objective.** >=30 live samples of broadcast -> first confirmation under real
conditions.

**Files.** `internal/channel/inclusion*.go` (observation types exist and
reference `obs.Samples`).
**New.** `cmd/p12-inclusion/main.go`.

**[CODE].** Build the transaction type the existing methodology specifies —
inspect before choosing; likely a minimal self-transfer. Per sample record:
submission timestamp, tx hash, nonce, gas parameters, block number, inclusion
timestamp, latency.

**Critical semantics.** `Record()` refuses evidence that EXCEEDS its budget:
*"A 45-minute inclusion measurement does not validate a 30-minute term; it
refutes it."* If the measured worst case exceeds the budgeted inclusion term,
the correct response is to RAISE THE TERM and re-derive — which lengthens
`challengePeriod`. Never to discard the sample, never to retry until a lucky
number appears.

**[TEST].** Mocked-RPC sample collection; the refutation path (measured >
budget -> refused with "raise the term"); dry run broadcasts nothing;
insufficient sample count refused.

**Acceptance.** >=30 samples, chain ID 1, method recorded, accepted by `Record()`.

**Rollback.** None. Spent ETH is spent.

---

## PHASE 6 — Repricing measurement

**[MAINNET].** Depends on Phases 2, 3, 5.

**Objective.** >=30 genuine replacement cycles at a higher fee.

**[CODE].** Original at a deliberately low fee, then a replacement at the SAME
nonce with a sufficient bump (>=12.5% is the common node minimum; confirm against
the methodology). Confirm the replacement landed and the original did not.
Record both hashes, both fee sets, and the delay.

**[TEST].** Nonce reuse; insufficient bump rejected by the node; the case where
the ORIGINAL confirms instead — handled as a failed sample, not a success;
simulated replacements explicitly inadmissible as evidence.

**Security risk.** Nonce management against a live funded account is the
sharpest edge in this roadmap. A stuck nonce blocks the treasury for every other
use.

**Acceptance.** >=30 completed cycles accepted by `Record()`.

---

## PHASE 7 — Watchtower detection measurement

Heavy infrastructure. Probably no Mainnet side effects — confirm in Phase 0/7.

**Objective.** Sweep latency measured at **1000 channels / 2 watchtowers / 30s**,
with `AtChannels >= Envelope.Channels`.

**Why hardest.** `Record()` enforces
`e.AtChannels < v.Envelope.Channels -> refuse`, and the code is explicit:
*"a sweep that completes in seconds over 100 channels says nothing about
100,000."*

**[INFRA + CODE].**
1. Generate 1000 channel records in a real store.
2. Instantiate 2 watchtowers through the supported mechanism.
3. Inject a breach condition.
4. Time the complete path: event -> chain observation -> detection ->
   evidence/state processing -> actionable response available.
5. Repeat for the required sample count.

**Open question to settle before building.** Detection is a property of the
WATCHTOWER, not of the chain. Devnet chain data may therefore be legitimate here
where it is not for inclusion. Confirm from the validation code — if `Record()`
accepts detection evidence with `ChainID: 1` only, that answers it.

**[TEST].** Detection at 999 channels refused; at 1000 accepted; multi-watchtower
coordination; reproducibility across runs.

**STOP if** detection cannot be measured at the stated envelope.

---

## PHASE 8 — Challenge-period derivation

**[HUMAN] approval required. Absolute stop.**

Run `DeployableChallengePeriod(now)`. **Never compute the value by hand.**

Report: every input term, its measured value, sample count, method, age, chain
ID; which terms were raised due to refutation; the returned value in seconds.

If any term was raised in Phase 5 or 6, re-derive — the answer moves.

**STOP unconditionally** at the derived value for explicit human approval. This
number is immutable once deployed.

---

## PHASE 9 — Deployment preflight — **COMPLETE**

**[HUMAN] required.**

```text
source revision pinned and recorded    2e2b132, contracts/ChannelManagerV2.sol clean
bytecode compiled from that revision   solc 0.8.24+commit.e11b9ed9, optimizer 200, evm paris
constructor arguments                  token 0x3ee18868…4066ac, challengePeriod 28800
deployer address == treasury           0xE36e04b6Df20C00479005ba23233F67192f38421
deployer balance sufficient for gas    0.004954199 ETH vs 0.002532940 max cost
chain ID verified == 1                 recovered from the signature, not asserted
gas estimate                           2,127,195; limit 2,339,914 (+10%)
deployment spend ceiling configured    SpendBudget, refuses by default
DeployableChallengePeriod() re-run     28800 s at the moment of broadcast
```

Signing ran through Web3Signer 26.7.0 bound to `127.0.0.1:9500`. The treasury key
stayed in the encrypted v3 keystore; the signed transaction was verified offline
before it left the workstation — sender recovered from the signature, chain ID,
nonce, `to == null`, and the creation payload matched byte for byte against the
artifact.

---

## PHASE 10 — Mainnet deployment — **COMPLETE**

**[MAINNET] [HUMAN].** Authorized separately, and broadcast under that authorization.

```text
contract address    0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c
transaction hash    0x2bfa5d16e3a7bda76282c11aaf3048c3be2e4cfb54ec16552f03bd9e5a425caa
block number        25757314  (0xfff32e99…53170, 2026-08-15T01:59:47Z)
status              1
gas used            2,109,287 of 2,339,914 at 1.0395 gwei effective
deployer            0xE36e04b6Df20C00479005ba23233F67192f38421, nonce 9
FINALIZED           yes — finalised head reached 25757341
```

Confirmation depth was not taken to be enough on its own. `eth_getCode` at the
`finalized` tag returns the full 9,504-byte runtime, so the contract exists in
consensus-finalised state rather than only in the canonical head.

One transaction was broadcast. Nothing else was sent from the treasury.

Full record: `proof-of-facilitation/deployments/mainnet/ChannelManagerV2.json`.

---

## PHASE 11 — Contract verification — **COMPLETE except publication**

```text
deployed bytecode == reviewed revision   yes — see the immutables note below
challengePeriod() read BACK FROM CHAIN   28800, equals the derived value
constructor/initialization events        none — the constructor emits nothing, receipt has 0 logs
source verification published            NOT DONE — no explorer API key configured
post-deployment smoke tests              pass
```

**The bytecode comparison, stated precisely.** `eth_getCode` does not hash equal
to the artifact runtime, and that is the correct result, not a discrepancy. Both
are 9,504 bytes and they differ in exactly 144 bytes across 9 contiguous runs.
Every run is an `immutable` slot the constructor writes: two 2-byte
`challengePeriod` slots holding `0x7080` (28800), and seven 20-byte `token` slots
holding `0x3ee18868078962f430a4da5e827e8cfc8b4066ac`. Zeroing those 9 runs
reproduces `f5393d99…948608` — the artifact hash, byte for byte. Nothing else in
the deployed code differs from the reviewed source.

**Verification bundle, proven rather than assumed.** The standard-json input in
`deployments/mainnet/` was fed back through `solc 0.8.24 --standard-json` on its
own, and the recompile reproduced both the creation hash `9b68d4fe…b517f1` and
the runtime hash `f5393d99…948608`. The bundle is known to be sufficient; only
submitting it to an explorer remains, and that needs an API key this repo does
not have.

**Smoke tests.** `challengePeriod()` → 28800. `token()` → the ANON ERC-20, which
answers `symbol() = ANON`, `decimals() = 18`, `totalSupply() = 21,000,000`.
`closeUnilateral` against a channel that was never opened reverts rather than
silently succeeding.

**STOP if** bytecode differs, constructor arguments differ, or the on-chain
`challengePeriod` differs by even one second. It is immutable; a mismatch is
unrecoverable and the contract must be abandoned rather than used. None of these
conditions hold.

---

## PHASE 12 — P15 against a real contract

**Deploying the contract does not prove P15 works.** P15 was validated against
Hardhat chain 31337. Every claim must be re-established against Mainnet.

Four tiers, kept separate:

```text
1 contract-level          no user funds, no product surface
2 Mainnet smoke           operator-only, minimal value
3 controlled real-value   small, operator-owned, deliberately bounded
4 end-to-end user flows   real creators, real contributors
```

Retest: channel open and deposit; pooled tipping; mailbox transport; recipient
node-console collection; multi-contributor; checkpoint and withdrawal; failure
and recovery; watchtower behaviour; browser Tips console; privacy properties.

**Do not proceed from tier N to N+1 on the strength of tier N-1.**

---

## PHASE 13 — Lightning integration

**Audit first.** No Lightning implementation was found during the inspection
that produced this roadmap. Phase 13 begins by establishing whether one exists.
If it does not, this is a new project with its own roadmap, not a testing phase
of this one.

---

## PHASE 14 — End-to-end Tips console

Real Firefox against Mainnet, mirroring the devnet validation already completed:
review -> accept -> STATE_ACCEPT -> publish -> `Pool.View()`. Plus the
contributor repeat-tip path at nonce N+1.

**Darwin/Windows publication.** From the evidence, this is a SEPARATE RELEASE
TASK, not a prerequisite: Mainnet P15 testing needs one working node, and Linux
is published and verified at `9fdf30d`. But the deployed site describes a
node-served console that only Linux users can install. That asymmetry should be
settled before real value flows, as a product decision rather than a technical
gate.

---

## PHASE 15 — Production hardening

- Release-gate automation with an actual trigger. `scripts/check-release.sh`
  exists and is green; nothing invokes it. Two release-matrix defects reached
  `main` because nothing cross-compiled.
- Watchtower monitoring and alerting.
- Evidence-freshness alerting at 90 days — the gate reopens silently otherwise.
- An incident runbook that matches the 15-minute response commitment. A
  commitment nobody has written down is not one.

---

# STOP conditions

Never recommend bypassing any of these.

```text
signer cannot prove the treasury address
no secure signer mechanism available
measurement budget not supplied by a human
RPC providers cannot establish independence
chain ID mismatch at any point
evidence rejected by the existing validation code
insufficient Mainnet balance
detection cannot be measured at the stated envelope
DeployableChallengePeriod() returns an error
deployed bytecode differs from the reviewed source
constructor argument differs from the approved value
on-chain challengePeriod differs from the derived value
canonicality cannot be established for the target chain
```

The correct response to a stop condition is to report it and halt. Not to
lower a threshold, not to substitute an estimate, not to re-run until the number
is convenient.

---

# Summary

## 1. Current blockers

None for deployment — Phases 0-11 are done and the contract is live. What
remains is everything Phase 12 onward: **P15 has never run against this
contract.** It was validated on chain 31337, and a deployed address is not
evidence about it.

Also open, neither of them gates: source verification is unpublished (no explorer
API key), and `doc/trust-anchor.md` still reads "MAINNET UNVERIFIED" with a stale
endpoint table in §5b.

## 2. Required engineering work

Done: `cmd/p12-evidence`, `cmd/p12-failover`, `cmd/p12-detection`,
`ExternalSigner` (clef and Web3Signer dialects), `SpendBudget`, and the
production `OperatingEnvelope`. Inclusion and repricing were measured through
`SendMeasured`/`AwaitInclusion` rather than separate commands.

## 3. Required human inputs

All supplied: measurement ETH ceiling · Web3Signer chosen and stood up on the
workstation · RPC endpoints selected · `challengePeriod` 28800 approved ·
deployment authorized. The Darwin/Windows publication decision is still open and
unrelated to the contract.

## 4. Required Mainnet resources

Held: funded treasury · 4 RPC providers on distinct registrable domains · gas
for the measurement transactions and deployment, all spent within budget.

## 5. Order of implementation

```text
0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 -> 11 -> 12 -> 13/14 -> 15
   ^-------------------- complete --------------------^   ^-- here
```

Phase 0 did reorder things, though not as feared: it found `HeaderTrust.Check()`
declarative, so canonicality never depended on shipping BLS in the release
binaries.

## 6. When Mainnet deployment becomes permissible — **all satisfied**

Only when ALL of the following hold at the same moment:

```text
DeployableChallengePeriod() returns a value, not an error   28800 s
all six terms validated and FRESH (< 90 days) at broadcast  re-run at broadcast
canonicality established for chain 1                        verified, not accepted-risk
bytecode compiled from a pinned, reviewed revision          2e2b132, solc 0.8.24
deployer address, balance and chain ID verified             recovered from the signature
spend ceiling configured                                    SpendBudget
explicit human authorization for that revision and value    given
```

## 7. Tests required after deployment before P15/Lightning end-to-end

Contract-level lifecycle against the deployed address · on-chain
`challengePeriod` read back and asserted · Mainnet smoke tests with no user
funds · controlled real-value tests with operator-owned funds only · then the
full P15 sequence re-proven against Mainnet: pooled tipping, mailbox transport,
node-console collection, multi-contributor, checkpoint and withdrawal, watchtower
behaviour, browser Tips console, privacy properties.

Tier by tier. Never skipping one because the tier below passed.
