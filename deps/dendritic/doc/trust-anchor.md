# P12-5 — The trust anchor, and why there is no cheap version

**Status: option A was built. CODE COMPLETE, MAINNET VERIFIED — with two
boundaries named in §5b.**

This document began as the scoping of a boundary we could not close. The
decision was taken to write a native light client (option A in §5), and 5.1–5.8
are now implemented — see the roadmap. §1–§3 remain the reasoning that shaped
it and are still accurate; §4 and §5 record what was decided and are kept for
that history.

The live mainnet sync has now happened. Against an anchor four independent
providers agree on, our BLS implementation verified a **512/512 sync-committee
signature over real mainnet consensus data** and established finality. The
consensus implementation has seen a real signature; the fixtures are no longer
all synthetic. `ChannelManagerV2` was deployed on that basis to
`0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c`.

Two things the run did **not** exercise are stated in §5b rather than left to be
inferred: committee rotation across a period boundary, and head advancement.

---

## 1. The finding

Post-merge, an execution header contains no proof of work:

```text
difficulty   0x0
nonce        0x0000000000000000
```

*(read from mainnet block 25,737,778)*

Fabricating a self-consistent chain of execution headers therefore costs nothing
but hashing. An attacker controlling the RPC can produce:

- correct `parentHash` linkage, to any depth;
- any `stateRoot` they like;
- storage proofs that **verify perfectly** against those roots — our own
  verifier will confirm them, correctly, because they are internally consistent.

So every execution-layer check is worthless against a lying provider:

| Check | Cost to fabricate |
|---|---|
| parentHash chain continuity | free |
| stateRoot + storage proofs beneath it | free |
| timestamps, gas limits, block numbers | free |
| difficulty / nonce (pre-merge PoW) | **no longer exists** |

**The only thing that makes a header canonical is signatures from the beacon
chain's validators.** There is no approximation of that, and a partial verifier
would be indistinguishable from a real one at the moment it mattered.

## 2. What P12-5 actually requires

```text
weak-subjectivity checkpoint     from OUTSIDE the RPC being verified
        ↓
LightClientBootstrap             the sync committee at that checkpoint
        ↓
LightClientUpdate × N            one per ~27h period, each signed by the
                                 previous committee, proving the next
        ↓
LightClientFinalityUpdate        a finalised beacon header, signed
        ↓
execution_branch                 SSZ Merkle proof: beacon block → execution
                                 payload header → stateRoot
        ↓
[everything P12-2 and P12-3 already do]
```

Four pieces of machinery, none of which exists here:

1. **BLS12-381 aggregate signature verification.** 512-key sync committee,
   participation bitfield, pairing check. Not in the standard library and not in
   this module — the only cryptographic dependencies today are secp256k1 and
   `golang.org/x/crypto`. Options are `blst` (cgo, the reference), or a pure-Go
   pairing library. Either is a substantial new dependency in a module that has
   deliberately kept them few, and it is dependency *on the security path*.
2. **SSZ merkleisation.** `hash_tree_root` for the beacon containers, plus
   generalized-index branch verification.
3. **The light client protocol itself.** Bootstrap, period transitions, fork
   awareness — the containers changed shape across Altair, Bellatrix, Capella,
   Deneb and Electra, so this is not one format but a schedule of them.
4. **Anchor management.** Below.

This is a light client. It is what Helios, Nimbus's verified proxy and the
Lodestar light client each are, and it is measured in thousands of lines plus
ongoing maintenance against Ethereum's fork schedule.

## 3. The anchor cannot come from the provider

Taking the checkpoint from the endpoint being verified moves the trust boundary
without shrinking it:

```text
before   provider → channel value
after    provider → "trusted" header → channel value
```

`HeaderVerifier.SetAnchor` refuses an anchor whose source shares a registrable
domain with the RPC endpoint. That refusal is the only security this file
provides today, and it is worth having because the mistake is so natural to
make.

Note the residual even with a light client: the *initial* checkpoint is a
subjective input. Someone must obtain it from a source they trust — a client
release, several independent explorers, a peer they know. That is inherent to
weak subjectivity and not a defect in the design.

## 4. What was built first — the gate

Before the light client existed, a gate, in the same spirit as the P12
deployment gate. It is still there and still the fallback when no client is
attached:

```go
HeaderVerifier.VerifyHeader(h)  →  ErrNoTrustAnchor
```

It fails closed and will keep failing closed until a sync-committee anchor
exists. It deliberately does **not** fall back to checking parentHash linkage
and calling that good enough, because §1 says that proves nothing.

`ChainAt` exists for chain-gap detection and is documented, named and tested as
a *consistency check, not a security check* — with a test that passes on a
wholly fabricated pair, to pin the distinction in place.

An `AnchorOperator` kind is available for a human-pinned block hash checked
against several explorers. It is honest input to a risk decision and it does
**not** satisfy the gate: it is a narrow claim about one block at one moment,
and says nothing about the header a watchtower reads six months later.

## 5. The options, honestly

**A. Implement the light client.** Real independence. Thousands of lines, a BLS
dependency on the security path, and ongoing fork maintenance. Correct, and the
largest single piece of work remaining in the project.

**B. Vendor one.** Run Helios or a verified proxy as a sidecar and point the
existing `Client` at it. Gets real verification for a fraction of the effort;
the trade is a third-party dependency in the security path, which needs the same
scrutiny as writing it would.

**C. Multi-provider corroboration.** Require N independent providers to agree on
a header. This is a **trust reduction, not a proof** — it raises the cost of an
attack from one compromised provider to N colluding ones, and provides nothing
against a network-level adversary who can answer for all of them. It must not be
described as verification.

**D. Accept the assumption, explicitly.** Run with `AnchorNone`, documented, and
treat the RPC as trusted for header canonicality. Defensible for a system whose
worst case is bounded — but the worst case here is a watchtower that fails to
defend a channel because it was shown a fabricated chain, and the loss is a
user's money.

**Recommendation at the time: B, then A.**

**DECIDED: A.** A native light client was built rather than vendoring one, on
the grounds that a third party on the security path needs the same scrutiny as
writing it would. The BLS primitive is the one exception, and the reasoning for
that line is recorded in the roadmap and in `doc/bls-library-evaluation.md`.

**C was not built and should not be** — it would produce something that looks
like verification in the code and in the logs, which is worse than an honest
`AnchorNone`.

## 5b. P12-5.9 — the live validation, and what it did and did not cover

The harness is `internal/ethproof/beacon.go` and `live_mainnet_test.go`. It ran.

```text
CHAIN_PROBE=1 \
BEACON_API_URL=https://lodestar-mainnet.chainsafe.io \
MAINNET_CHECKPOINT=0x5bfa989e1f2c7e9af42781a01ba90fe51ce4e521ee48171cc6d2bc6d72be1d42 \
ETH_RPC_URL=https://eth.drpc.org \
CGO_ENABLED=1 go test -tags ethbls ./internal/ethproof/ -run LiveMainnet -v
```

All three tests pass. Fixture:
`internal/ethproof/testdata/live-mainnet-summary.json`.

**What was established.**

```text
chain identity        MainnetGenesisValidatorsRoot matches the live node
                      0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95
committee keys        512 real pubkeys through the production KeyValidate path,
                      where blst's subgroup check matters with real keys
REAL SIGNATURE        finality update applied, 512/512 participation,
                      attested slot 14994657, signature slot 14994658
finality              TrustLevelOf == HeaderFinalized at slot 14994592
adversarial half      a valid execution header against an unadopted root is
                      still refused
```

**The anchor, and why it is not circular.** `0x5bfa989e…be1d42` was taken from
four checkpoint providers that all returned the same finalized root —
`mainnet.checkpoint.sigp.io`, `beaconstate.ethstaker.cc`,
`mainnet-checkpoint-sync.attestant.io`, `sync-mainnet.beaconcha.in`. None of them
is `chainsafe.io`, which served the light-client data, and none is `drpc.org`,
which served execution. The provider being checked did not choose the value it
was checked against.

**Two boundaries this run did not cross.** Both are logged by the test itself
rather than left to inference:

1. **Committee rotation across a period boundary was not exercised.** A rotation
   update exists only for a *completed* sync-committee period. The anchor is at
   slot 14994592, inside period 1830, which has not completed — so there is no
   rotation update ahead of it and `ApplyRotatingUpdate` correctly refused the
   one for period 1830 as not advancing the head. Exercising rotation needs an
   anchor at least one full period (8192 slots, ~27 h) behind the head, and the
   checkpoint providers serve only `finalized`. This is a property of what is
   obtainable, not a defect.
2. **Head advancement was not exercised.** The anchor was already the finalized
   head, so the verified finality update carried it no further. The signature
   was checked against it; the head had nowhere to move.

**The harness bug this exposed.** The test previously counted only rotation
updates and, finding none, failed with *"no real sync committee update
authenticated — the consensus path does not work"*. That diagnosis was wrong: a
real 512/512 signature verifies on the very same run. Rotation and signature
authentication are now counted separately, the assertion is that at least one
real committee signature was verified by *either* path, and a run that cannot
exercise rotation says so instead of quietly claiming it did.

**The endpoint finding, which still holds.** A responding Beacon API is NOT a
light-client-capable one. Of the candidates probed:

| Endpoint | `/eth/v1/node/version` | `/eth/v1/beacon/light_client/finality_update` |
|---|---|---|
| **lodestar-mainnet.chainsafe.io** | **200** | **200** |
| mainnet.checkpoint.sigp.io | 200 | 404 |
| www.lightclientdata.org | 503 | 503 |
| beaconstate.info | — | unreachable |
| mainnet-checkpoint-sync.attestant.io | — | 404 |
| sync-mainnet.beaconcha.in | — | 404 |
| beaconstate.ethstaker.cc | — | 404 |
| checkpoint-sync.mainnet.ethpandaops.io | — | unreachable |

Checkpoint-sync providers exist to serve state downloads; the light-client REST
routes are a separate opt-in that most do not enable. An endpoint must not be
chosen because it responds — it must demonstrably serve `bootstrap`, `updates`
and `finality_update`.

**Still worth doing.** Running our own consensus node would remove the
third-party dependency on chainsafe.io and, by retaining history, make rotation
testable on demand rather than only in a 27-hour window. It does **not** need to
be an archive node and does not need the ~750 GB execution database.

The harness enforces the independence properties: it refuses to run if
`BEACON_API_URL` and `ETH_RPC_URL` share a provider, and it never fetches the
checkpoint.

## 6. What this means for the deployment gate

The term this section added to the gate:

> ChannelManagerV2 must not be deployed while header canonicality rests on
> `AnchorNone`, unless that assumption is recorded as an accepted risk with the
> same explicitness the challenge-budget terms require.

**It was satisfied, not waived.** Canonicality was filed as
`CanonicalityVerified` with a stated implementation and the anchor above — not
`CanonicalityAcceptedRisk`. `DeployableChallengePeriod()` then returned 28800 s
and `ChannelManagerV2` was deployed to
`0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c` at block 25757314.

Phase 0 of the mainnet-readiness roadmap resolved the fear that hung over this
document: `HeaderTrust.Check()` is *declarative*. It never calls `ethproof`. So
canonicality never depended on shipping BLS inside the seven release binaries,
and the `ethbls` build tag being absent from them was never the blocker it
looked like. What `ethproof` provides is the evidence a human files — which is
exactly what §3 said the anchor had to be.

P12-4 (local index), P12-6 (watchtower integration) and P12-7 (failure testing)
are written against the `HeaderVerifier` interface, so substituting a
self-hosted consensus node later is a substitution rather than a redesign.
