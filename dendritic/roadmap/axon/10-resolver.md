## 13. The Resolver

> **AS BUILT (2026-08-16).** `internal/axon/resolver`, 10 tests. T10.1–T10.6 and
> E10.1–E10.3 discharged in-process: resolves with the chain absent and reports a
> real staleness, refuses an unauthenticated chain, purges cached artefacts on
> revocation, and answers absence with an authenticated proof flagged
> `PENDING_POSSIBLE`. SNAPSHOT-WARM and SNAPSHOT-COLD are separate modes and a
> COLD answer reports staleness **-1** rather than a comforting number.
>
> **Deliberately NOT claimed:** it is wired to **fakes, not the real sources**.
> `internal/ethproof`'s mainnet-verified light client and the P4 DHT are not
> connected, so `alice.lab.axon` has never resolved end to end against anything
> real and **E10.4 / M3 are not claimed**.

**The finding that shapes this section: the resolver is the only component in
AXON that a user's security depends on and that runs on the user's own machine.
Everything else can be adversarial. The resolver therefore has exactly one job —
to convert a string into a destination while never once believing anything it was
told — and the hard part is not the lookup, it is the honest accounting of what
was verified against what root of trust at each step.**

The second finding is that the expensive half is already built.
`doc/trust-anchor.md` records a native Ethereum light client that verified a
**512/512 sync-committee signature over real mainnet consensus data**, and
`doc/ethereum-data-layer.md` records `eth_getProof` verification measured against
mainnet block 25,737,778. The naming layer does not need a new trust anchor; it
needs to read different storage slots through the one that exists, and to be
disciplined about the four places where verification is not available at all:
DHT absence, broadcast, liveness, and the subjectivity of the initial checkpoint.

The third finding is dealt with in §13.8 rather than deferred: `https://alice.lab.axon`
cannot show a padlock without either a locally installed root certificate — a
serious new asset on the user's machine — or a multi-year browser-vendor track.
There is no third option that works in a shipping browser today.

---

### What already exists

Read before writing; every claim below comes from the file named.

| Asset | Path | What the resolver takes from it |
|---|---|---|
| Light client | `internal/ethproof/lightclient_verifier.go`, `lightclient.go`, `rotation.go`, `finality.go`, `execution.go`, `ssz.go`, `bls.go` | `LightClient.VerifyExecutionHeader`, `AdoptExecutionPayload`, `AuthenticatedExecution(number) (Root, Root, bool)`, `LightClientState.TrustLevelOf` returning `HeaderObserved`/`HeaderVerified`/`HeaderFinalized`. `ExecutionPayloadIndex = 25`. `SlotsPerSyncCommitteePeriod = 32 * 256`. |
| Trust anchor gate | `internal/ethproof/anchor.go` | `AnchorNone`/`AnchorOperator`/`AnchorSyncCommittee`, `Anchor.Trustworthy()`, `HeaderVerifier.VerifyHeader` returning `ErrNoTrustAnchor`, `SetAnchor` returning `ErrAnchorNotIndependent` when anchor and RPC share a registrable domain. |
| State proofs | `internal/ethproof/proof.go`, `client.go` | `VerifyProof(root, key, proof)`, `StorageSlotKey(key, position)`, `SlotAt(base, n)`, `AccountStorageRoot`, `DecodeSlotValue`, and `VerifiedRead` — which walks `header.stateRoot → account proof → storageRoot → storage proof → value` and records the RPC's own `value`/`storageHash` fields **for comparison only**. |
| Chain following | `internal/ethproof/chainfollower.go`, `beaconsource.go`, `rpcsource.go`, `transport.go` | `ChainFollower.Advance`, `FollowerCheckpoint`, `FileCheckpointStore`, `BeaconFinalizedSource.FinalizedBlock`, and `Endpoints.Post` with `ErrChainUnreachable`/`UnreachableError`. |
| Verified-evidence store | `internal/ethproof/evidence.go`, `index.go` | The construction rule: an unexported `verified` flag nothing outside the package can set, so a hand-built `Evidence` is refused by `Put`. The resolver's cache copies this pattern exactly. |
| Live mainnet fixture | `internal/ethproof/live_mainnet_test.go`, `testdata/live-mainnet-summary.json` | The harness that refuses to run when `BEACON_API_URL` and `ETH_RPC_URL` share a provider. |
| Signed-snapshot machinery | `internal/gateway/snapshot.go` | `SnapshotManifest{Sequence, CreatedAt, RefreshAfter, StaleAfter, ExpiresAt, RootHash, Signature}`, the four freshness states `fresh`/`stale`/`emergency-stale`/`expired`, `Usable()`, and `Revocations{RevokedSequences, RevokedSnapshotIDs, Sequence}` with its "never accept an older record" rule. This is the prior art for §13.3 SNAPSHOT and §13.5. |
| DHT record validation | `internal/gateway/dht.go` | `DHTValidator.Validate` rejecting a record whose `NodeID` does not match the key it was stored under; `Select` choosing the highest `Sequence` among *valid* records. Both rules survive into §13.1 step R8. |
| Request-handling shape | `internal/gateway/contentproxy.go`, `validator.go` | GET/HEAD only; cookies stripped in both directions; redirects returned and never followed (`http.ErrUseLastResponse`); the snapshot "lookup guard" that answers unknown paths with a flat 404 *and no lookup at all* so the store cannot be used as an amplifier; and `Validator.audit`'s four verdicts `pass`/`unsigned`/`mismatch`/`stale`. |
| Today's naming | `internal/gateway/acme.go`, `registry.go` | `NewACMEManager` — an exact-host Let's Encrypt policy over conventional DNS. This is what §13.8 is replacing, and the honest baseline it must be compared against. |

### What must be replaced

Conventional DNS plus a publicly trusted CA, in `internal/gateway/acme.go` and
the `gateway-controller` name.com sync. Both work and both put a third party
between a reader and a name. Nothing in `internal/ethproof` is replaced; it is
re-pointed at a different contract's storage.

---

### Decisions in this section

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Name→DomainIdentity read **only at the finalized head** | A transfer that reorgs would move a name under an attacker's key | Neither — Tor/I2P have no ownership layer; this is the blockchain half | Ownership is never read optimistically, even when the optimistic header is committee-signed | Reading at head with a confirmation count (arbitrary, and wrong under finality-reversion); reading at head and re-checking later (a window of wrong answers) | Registrations and transfers are invisible for up to 19.2 min; a resolver is structurally behind the chain |
| Descriptors fetched under **blinded keys over a circuit** | A DHT node otherwise learns which name is being resolved, and by whom | Tor v3 onion-service descriptors (blinded key per time period); I2P for the pool that carries the lookup | Blinding factor derived from the *verified* RANDAO SRV (R13), not a directory-authority commit-reveal | Plaintext DHT keys (enumerable namespace); PIR (cost, and no deployed construction we would trust) | Lookup depends on SRV agreement; a client with the wrong epoch's SRV silently finds nothing |
| **Three declared modes**, and the mode is in every answer | A resolver silently degrading to a weaker trust basis is the classic naming failure | Freenet's honesty about best-effort retrieval | The mode is a field the caller must read, not a log line; UI surfaces must render it | A single "just works" mode (hides which trust basis answered) | Callers can ignore the field; a UI that does is a downgrade attack with no code change |
| SNAPSHOT mode with a **declared freshness bound** | Chain outage or RPC censorship must not take the namespace down (R7) | Freenet's tolerance of a partial view; `SnapshotCache` in the existing gateway | Four freshness states copied from `SnapshotManifest.State`, with a hard `expired` refusal instead of a warning | Serving stale bindings indefinitely; failing hard on any chain gap | A snapshot publisher becomes a censorship point for *new* names, and SNAPSHOT-COLD is a shipped trust anchor (§13.3) |
| A DELEGATED answer **must carry its evidence** | Delegation would otherwise be full trust wearing a protocol's clothes | Tor's directory-cache model, inverted | The delegate transports proofs; the client checks them against a root it obtained itself | Trusting a "resolver you configured"; N-of-M delegate agreement as verification (`doc/trust-anchor.md` §5C: "must not be described as verification") | Delegates see every name a client asks for; that privacy loss is not fixed by evidence |
| **Authenticated absence ≠ lookup failure** | "No such name" and "I could not find it" have opposite security meanings | Neither; Kademlia and Freenet cannot prove absence at all | A Merkle-Patricia proof of absence (measured at **160 B**, 1–2 nodes) is a positive fact and is cached; a DHT miss is not and is not | Treating a miss as NXDOMAIN (lets one silent node delete a name from a user's world) | Negative caching of authenticated absence delays a *new* registration becoming visible by up to the negative TTL |
| A **trust-state lattice**; a lower state never overwrites a higher one | Cache poisoning by racing a weak answer against a strong one | Tor's guard/consensus separation of "signed by whom" | Every cache entry stores the state it was admitted at, mirroring `AdoptExecutionPayload` refusing to change an authenticated entry | Last-write-wins; timestamp-wins | An attacker who lands a *high*-state wrong answer (compromised checkpoint) is now sticky and hard to displace |
| Cache is **memory-first, encrypted on disk, padded** | A resolver cache is a browsing-history log (§13.4) | Neither — all three prior systems have this hazard and none solves it | Only the binding tier persists; descriptors and negatives are RAM-only by default | Plaintext cache file with 0600; no persistence at all (cold start needs chain access) | A key in the OS keystore is one compromise away; write timing still leaks activity to a local observer |
| **Rotation overlaps 48 h; revocation does not overlap at all** | A rotation must not break live sessions; a revocation must not be softened | Tor's descriptor time-period overlap (12 h) | Two different windows for two different events, rather than one policy | A single overlap for both (a revoked key stays live for the overlap — unacceptable) | A stolen key is valid until revocation *finalises*, which is the honest floor (§13.5) |
| **Local root CA, name-constrained to `.axon`** for the padlock | Browsers have no other path to a secure context for a non-DNS name | Neither; this is the `.onion` problem and Tor solved it by special-casing the TLD with vendors | The root is name-constrained and the leaf carries the DomainIdentity so an extension can compare | Raw-public-key TLS (no browser implements it); plain HTTP (loses secure-context features) | A root on the user's machine that, if the constraint is not enforced by that platform, signs anything |
| **SOCKS5 before the DNS shim** | The DNS shim is the classic `.axon` leak | Tor's SOCKS-with-remote-DNS and `.onion` handling | We ship the leak-free surface first and the fragile one last | DNS-first (fastest to demo, leaks by default) | Applications that cannot speak SOCKS are unserved until the shim ships |
| **Fail closed on no anchor**, inheriting `ErrNoTrustAnchor` | A resolver that falls back to believing an RPC is worse than one that stops | The existing gate in `anchor.go` | The naming layer reuses the same error and the same refusal, rather than inventing a lenient path | A "best effort" mode; parentHash-linkage checking (`anchor.go` §1: free to fabricate) | Availability is now coupled to the anchor; a broken checkpoint is an outage, not a degradation |

Component status:

```text
[BUILD NOW]        resolution pipeline, binding reader over ethproof, record
                   validator, trust-state cache, daemon socket API, SOCKS5,
                   HTTP CONNECT
[BUILD NOW]        snapshot consumer (the gateway SnapshotCache pattern,
                   re-rooted on a chain-anchored Merkle root)
[NEEDS RESEARCH]   browser extension under MV3 request-interception limits;
                   platform-by-platform enforcement of X.509 name constraints;
                   DoH-bypass behaviour and vendor canary mechanisms
[NEEDS RESEARCH]   snapshot publication: who computes it, what stops a
                   publisher omitting names, and whether omission is provable
[UNSOLVED]         a secure-context origin for `.axon` without installing a
                   local root — needs a special-use TLD registration and
                   browser-vendor adoption, on a multi-year timescale
[UNSOLVED]         proving DHT absence; a descriptor that d=3 disjoint paths
                   fail to find is indistinguishable from one that was never
                   published
```

---

### 13.1 The resolution pipeline

The trust states, which are referenced by number for the rest of the section.
They form a lattice; an answer's state is the *minimum* over the states of the
facts it rests on.

```text
T0  UNTRUSTED        bytes from a peer, an RPC, a delegate. No property at all.
T1  WELL-FORMED      parses, canonical encoding, within size caps. Says nothing
                     about truth; only that no parser was attacked.
T2  CHAIN-BOUND      committed by a stateRoot inside an execution payload that
                     LightClient.AdoptExecutionPayload authenticated into a
                     FINALIZED beacon header. The strongest state available.
T3  SNAPSHOT-BOUND   committed by a snapshot root that was T2 when this client
                     verified it, at a recorded time, now F seconds old.
T4  OWNER-BOUND      Ed25519-verified under the DomainIdentity that a T2 or T3
                     fact says holds the name. Inherits min(T2|T3, signature).
T5  SELF-CERTIFYING  BLAKE3 root matches the bytes. Needs no external trust and
                     is not weakened by anything above it.
```

The pipeline. `ROOT_SUFFIX` is the single compile-time constant (§11.3);
**namespace labels are read from the root registry at runtime and a resolver that
hardcodes them is non-conformant**, because the set changes by vote (§12.0a).

```text
  "alice.lab.axon"     (or flat "alice.lab" — see R0)
       │
   R0  root-suffix disposition ─────────────────► T1
       │  ends in ROOT_SUFFIX          → strip it, continue
       │  flat form, flat mode enabled → is "lab" delegated in the public
       │      DNS root?   YES → PUBLIC DNS WINS. Do not answer. Warn. STOP.
       │                   NO → rewrite to alice.lab.axon, continue
       │  neither                      → not ours. Pass through. STOP.
       │  [§11.0.2 R16. This rule is not operator-configurable.]
       ▼
   R1  normalise ───────────────────────────────► T1
       │  UTS-46 / IDNA2008 restricted profile, NFC, single-script
       │  label, reject confusables and mixed scripts
       │  applied to the registrable AND the namespace label
       ▼
   R2  cache probe ──────────────────────────────► state as stored
       │  hit at required state and freshness → jump to R11
       ▼
   R3  namespace resolution ─────────────────────► T2 (FULL)
       │  nsKey = keccak256("lab")                  T3 (SNAPSHOT)
       │  prove Namespace{registrar, class, status, recordSchema}
       │  out of the PINNED TLDRegistry (§12.5, §13.3)
       │
       │  status ACTIVE    → continue
       │  status FROZEN    → continue; existing names still resolve
       │  status RETIRING  → continue; warn with retiresAt
       │  status RETIRED   → refuse. The name is gone; the SERVICE is not
       │                     (§11.9 — offer the Layer 1 address if known)
       │  status NONE      → NXNAMESPACE. Never fall through to public DNS
       ▼
   R3a nameKey = keccak256( TLD_NODE(namespace) ‖ keccak256(label) )
       │  TLD_NODE is per-namespace (§12.5); the registrar address came
       │  from R3 and is NOT taken from configuration or from the answer
       ▼
   R4  binding lookup ───────────────────────────► T2 (FULL)
       │    FULL:      eth_getProof at the finalized head             T3 (SNAPSHOT)
       │    SNAPSHOT:  Merkle branch under a verified snapshot root
       │    DELEGATED: delegate supplies one of the above; we check it
       ▼
   R5  binding validation ───────────────────────► T2/T3 retained
       │  registered? not revoked? rotation window? pending transfer?
       ▼
   R6  blinded key = blind(DomainIdentity_pk, period, SRV_epoch)
       │
       ▼
   R7  DHT GET over a circuit, d=3 disjoint paths ► T0
       │  L3 returns bytes. The storing node learns neither the name
       │  nor the requester (R4 of the Constitution).
       ▼
   R8  record validation ────────────────────────► T4
       │  signature under DomainIdentity (or a depth-1 delegation),
       │  name field matches, period matches, not expired, revision
       │  monotonic against cache
       ▼
   R8a mutual-binding check ─────────────────────► T4
       │  fetch NameAcceptance signed by the ServiceIdentity the record
       │  points at (§11.0.3 rule 4). Does its name set contain this name?
       │    both directions agree → present the name as canonical
       │    forward only          → MISMATCH. Do not render the name as
       │                            the service's identity. Connect only
       │                            on explicit user override (§13.9)
       │    backward only         → the service claims a name it does not
       │                            hold. Ignore the claim
       ▼
   R9  select ───────────────────────────────────► T4
       │  ServiceDescriptor │ ContentPointer │ Alias(loop ≤ 4)
       │  an Alias MAY cross namespaces; each hop repeats R0–R8a in full,
       │  and the loop bound is over the whole chain, not per namespace
       ▼
   R10 cache admit ──────────────────────────────► recorded with state
       │
       ▼
   R11 hand off
       │   ServiceDescriptor → L5  (intro points, rendezvous)
       │   ContentPointer    → L6  (BLAKE3 root; verification is T5 and
       │                            does not depend on anything above)
       ▼
   R12 answer to caller: {value, trust_state, mode, as_of, expires_at,
                          warnings[]}
```

Step by step, with what is verified and against what root:

| # | Step | Verified against | Result state | Failure |
|---|---|---|---|---|
| R1 | Normalise | Nothing external — a pure function | T1 | `ErrName` — reject, never guess. A name that does not normalise is not a name. |
| R2 | Cache probe | The state recorded at admission (§13.4) | as stored | A hit below the caller's required state is treated as a miss. |
| R4/FULL | `eth_getProof(registry, slots, finalizedBlock)` verified by `VerifiedRead` | `stateRoot` of an execution payload authenticated by `LightClient.AdoptExecutionPayload` into a beacon header at `HeaderFinalized` | **T2** | A lying provider produces a proof that fails `VerifyProof`. Detected, never silent (§13.2). |
| R4/SNAPSHOT | Merkle branch for `nameKey` under `snapshot.RootHash` | A snapshot root this client verified at T2 at time T0, age now `F` | **T3** | Branch mismatch → discard the whole snapshot, as `SnapshotCache` does: "a snapshot that fails verification is discarded, not quarantined". |
| R4/DELEGATED | Whichever of the above the delegate carried | Same roots as above — the delegate contributes no authority | T2 or T3 | Evidence missing or failing → answer refused, delegate demoted (§13.3). |
| R5 | Binding validation | The values recovered in R4 only; never the RPC's own `value` field | T2/T3 | Revoked → `ErrRevoked`. Absent → authenticated NXNAME (T2) or "not found" (T0). |
| R6 | Blinding | Ed25519 scalar blinding, Tor rend-spec-v3 construction; period and SRV are inputs both sides compute | T1 | A wrong SRV yields a key nobody published under — indistinguishable from absence. This is the sharpest edge in the pipeline. |
| R7 | DHT GET | Nothing. Bytes from strangers. | **T0** | All `d=3` paths empty → `ErrNoDescriptor`, which is *not* proof of absence. |
| R8 | Record validation | `DomainIdentity` from R5 | **T4** | Any check fails → discard that candidate and continue with the next; do not abort the lookup on the first bad record, or one hostile responder becomes a denial of service. |
| R9/R10 | Select, cache admit | Type tag in the validated record | T4 | Alias loop > 4 → `ErrAliasLoop`. A lower state never displaces a higher one (§13.4). |
| R11 | Handoff | L5 verifies the descriptor's own contents; L6 verifies content at **T5** | T4 / T5 | Content that fails its BLAKE3 root is rejected at L6 regardless of how well the name resolved. |

Record validation (R8), in full, because this is where a valid-looking answer
gets rejected:

```text
1  ≤ 8 KiB and canonically encoded. Two valid encodings of one record would
   split the cache and let an attacker hold both.
2  version known; unknown CRITICAL fields → reject; unknown others → ignore
3  signature over "axon-record:v1" ‖ nameKey ‖ period ‖ revision ‖ body,
   domain-separated, verified under the DomainIdentity from R5
4  delegation: depth ≤ 1, signed by DomainIdentity, own notBefore/notAfter,
   may not re-delegate
5  name field inside the record == nameKey requested. This is
   DHTValidator.Validate's rule ("gateway record stored under another node
   ID") applied to names: a genuine record for bob.lab.axon served in answer to a
   query for alice.lab.axon must not be accepted.
6  period field == the period whose blinded key was queried
7  notBefore ≤ now ≤ notAfter, ±120 s slack, lifetime ≤ 3 h (§5)
8  revision strictly greater than any cached revision. A replayed older record
   is the one attack a signature cannot see — the case
   internal/gateway/validator.go files as "stale".
9  among survivors, highest revision wins (DHTValidator.Select)
```

---

### 13.2 The trust-minimised chain path

This path already exists and works against mainnet. It is restated here only to
fix what the resolver may conclude from it, and is not re-argued;
`doc/trust-anchor.md` is the authority.

```text
weak-subjectivity checkpoint      obtained OUTSIDE the RPC being verified.
        │                         In the live run: four providers
        │                         (sigp.io, ethstaker.cc, attestant.io,
        │                         beaconcha.in) agreed on one finalized root,
        │                         and none of them served the data checked.
        ▼
LightClientBootstrap              the 512-key sync committee at that checkpoint,
        │                         through blst's KeyValidate subgroup check
        ▼
LightClientUpdate × N             one per SlotsPerSyncCommitteePeriod
        │                         (32 * 256 = 8192 slots, ~27 h), ~24 KB each,
        │                         each signed by the previous committee
        ▼
LightClientFinalityUpdate         a finalised beacon header, BLS-verified.
        │                         Live run: 512/512 participation, attested
        │                         slot 14994657, signature slot 14994658,
        │                         TrustLevelOf == HeaderFinalized at 14994592
        ▼
execution_branch @ index 25       SSZ Merkle proof into the execution payload
        │                         header (ExecutionPayloadIndex = 25)
        ▼
stateRoot                         AdoptExecutionPayload records it; nothing
        │                         else in the package may write that map
        ▼
eth_getProof(AxonRegistry, slots) VerifiedRead walks account proof → storageRoot
                                  → storage proof → value, and uses the RPC's
                                  own `value`/`storageHash` only for comparison
```

The registry slots are §12's. The resolver's requirement on §12 is that the
binding is reachable by mapping arithmetic the client can compute offline —
`base = keccak256(nameKey ‖ uint256(slot))`, which is exactly
`ethproof.StorageSlotKey`, with fields at `SlotAt(base, n)`. **The value of
`slot` must come from `solc --storage-layout`, as `doc/ethereum-data-layer.md`
did for `ChannelManagerV2` — TBD, read from §12's storage layout; do not assume
0.**

What the resolver needs from each binding, as a requirements list on §12 rather
than a duplicate specification: `domainIdentity` (Ed25519, 32 B), `prevIdentity`,
`rotatedAtBlock`, `revokedAtBlock`, `expiresAt`. Five words, so a binding read is
an account proof plus five slots at worst and two in the common case.

**A lying RPC provider fails loudly.** This is established, not asserted:
`doc/ethereum-data-layer.md` §6b records that flipping one bit in a real proof
was rejected, and a real proof against a fabricated root was rejected. A provider
can refuse, stall, or return garbage. It cannot make `VerifyProof` return a value
the state root does not commit to, and it cannot make `VerifyExecutionHeader`
accept a header the light client did not authenticate — that function looks up
what *it* holds for the block number and requires the header to match, with the
stored value as the authority and the header as the claim.

**What the light client does not protect.** Stated as flatly as `trust-anchor.md`
states it:

| Not protected | Consequence for the resolver |
|---|---|
| **Broadcast** | We can verify what we read; we cannot verify that a provider broadcast what we sent. A registration or revocation transaction can be dropped silently. The resolver is a reader, so this is §12's problem — but a *revocation* that never lands is this section's problem, and §13.5 states the floor. |
| **Liveness** | A provider that stalls produces no proof and no answer. Verification says nothing about availability, and every mode's fallback exists for this reason. |
| **The initial checkpoint** | Subjective, by construction. Someone must obtain it from a source they trust. `SetAnchor` refuses an anchor sharing a registrable domain with the RPC — that catches the natural mistake and nothing more. A user given a fabricated checkpoint at install time is inside a coherent fake chain and every proof will verify. This is weak subjectivity, not a defect, and it is the resolver's true root. |
| **Which names exist** | The chain commits to the registry's storage. It does not stop an RPC from refusing to serve a proof for one particular name. Censorship of a single name is cheap and looks exactly like a timeout. |
| **Anything in the DHT** | R7 returns T0 bytes. The chain path authenticates the *key* those bytes must verify under, and nothing else. |

Costs, from the measurements in `doc/ethereum-data-layer.md` §6b at mainnet block
25,737,778 — these are that document's numbers for `ChannelManagerV2`-shaped
reads, reused here as the closest available estimate and **not re-measured for a
registry read**:

| Quantity | Measured | Registry-read estimate |
|---|---|---|
| Account proof | 3879 B, 9 nodes | Same order; the registry's account is one account |
| Populated storage slot | 2989 B, 7–9 nodes | Shallower — a registry with 10⁵ names is depth ≈ log₁₆(10⁵) ≈ 4.2, versus WETH's ≈ 5.6 |
| Absent slot | **160 B**, 1–2 nodes | An unregistered name is ~4 KB total and terminates early |
| Verified read, end to end | ~210–290 ms for account + 11 slots | A 2-slot binding read is a strict subset; **not separately measured** |
| Anchor upkeep | ~24 KB per ~27 h period, 7.6 MB/year | Unchanged — one anchor serves the whole resolver |

---

### 13.3 The three operating modes

The mode is a field in every answer. A caller that does not read it is choosing
to be downgraded.

```text
FULL       light client + eth_getProof. Trusts: the initial checkpoint, and
           the BLS assumption. Trusts NO RPC.
SNAPSHOT   a Merkle root over the name→DomainIdentity map, replicated in the
           DHT (R7). No chain access at all while running.
DELEGATED  asks a remote resolver, which is UNTRUSTED, and checks the evidence
           it returns against a root obtained independently.
```

| | FULL | SNAPSHOT | DELEGATED |
|---|---|---|---|
| Root of trust | Sync committee, via a checkpoint from outside the RPC | A snapshot root that was T2 when *this client* verified it (WARM), or a publisher key (COLD) | Whatever the client already has; the delegate adds none |
| Answer state | T2 → T4 | T3 → T4 | inherits, capped at the evidence carried |
| First-run cost | Bootstrap + one update per elapsed 27 h period, ~24 KB each | One snapshot fetch; size is `O(names)` for a full copy or `O(log n)` per name for branch-only | One round trip |
| Steady state | 7.6 MB/year anchor + ~4–13 KB per uncached name | ~1 KB per name (branch of ~20 × 32 B at 10⁶ names, plus leaf and header) | ~1–2 KB per name |
| Added latency per uncached name | Chain read, of the order of the 210–290 ms measured for a heavier read | One DHT lookup over a circuit | One round trip over a circuit |
| Local storage | Committee state + follower checkpoint (`FileCheckpointStore`); megabytes | Snapshot or branch cache | Cache only |
| Requires chain access | Yes | **No** | No |
| Max staleness | ≤ 19.2 min (finality) | `F`, declared; refuse at 24 h | Unbounded unless freshness evidence is required |
| Max revocation latency | **30 min** | **25 h** | 25 h with evidence; unbounded without (§13.5) |
| Can a wrong answer be forged? | No, absent a compromised checkpoint | No, absent a compromised snapshot root | **No** — the record must still verify under the DomainIdentity the evidence binds |
| Can the answer be withheld? | Yes | Yes, for names newer than the snapshot | Yes, trivially |
| Privacy | RPC learns which registry slots are read — that is which names, since the key is derived from the name | Nothing leaks per name if the whole snapshot is held; a branch fetch leaks the name to the DHT | **The delegate learns every name** |
| Fitness | Desktop daemon, relay operators, anyone minting TLS leaves (§13.8) | Mobile, embedded, offline, chain outage | Constrained clients that already accept a privacy cost |

**SNAPSHOT has two sub-cases and conflating them would be dishonest.**

```text
SNAPSHOT-WARM   this client verified a snapshot root against the chain at time
                T0 and now runs without chain access. Staleness = now − T0,
                exactly, and the client knows T0. Sound; the mode R7 describes.

SNAPSHOT-COLD   this client has NEVER had chain access, so it accepts a
                snapshot root on a publisher signature — a trusted third party,
                and precisely what SnapshotCache.PublisherKey already is. Same
                KIND of object as the weak-subjectivity checkpoint, but relied
                on CONTINUOUSLY rather than once, which is strictly weaker. It
                must be labelled in the answer, must never be the default where
                network access exists, and its publisher key must be shipped in
                the client rather than fetched.
```

Snapshot acceptance rules, taken from `SnapshotCache` because they were right
there: four states `fresh` / `stale` / `emergency-stale` / `expired`; `expired`
is refused outright rather than warned about; a snapshot failing verification is
discarded, not quarantined; a lower `Sequence` never replaces a higher one.

**What a DELEGATED answer can and cannot be trusted for.**

| Property | Trustworthy? | Why |
|---|---|---|
| The DomainIdentity for a name | **Only with evidence** | The delegate returns the `eth_getProof` nodes or the snapshot branch; the client runs `VerifyProof` against a root it holds. Without a root of its own, the client *is* trusting the delegate and the mode label must say so. |
| The record's contents | Yes | R8 verifies under DomainIdentity. A delegate cannot forge a record. |
| "This name does not exist" | **No** | Absence needs a chain proof of absence. A bare delegate NXNAME is a refusal wearing a fact's clothes. Never cached, and rendered as "could not resolve", never "does not exist". |
| Freshness / "this is current" | **No** | A delegate can replay a whole valid answer from before a rotation or revocation. Mitigated, not solved, by a client nonce echoed in the delegate's signature and by requiring an `as_of` the client can compare against its own view. |
| TTL | **No** | Clamped to local policy. A delegate that could set TTLs could pin a stale answer for a week. |
| Which names you asked for | — | The delegate learns all of them. Query over a circuit (L4) so it learns the names but not the client; that is the whole mitigation and it is partial. |

So delegation **cannot forge; it can censor, stall, and serve stale**. That is
the entire security statement, and it holds only while the evidence requirement
holds. Asking two independent delegates and requiring agreement raises the cost
of an attack; per `doc/trust-anchor.md` §5C it **must not be described as
verification**.

---

### 13.3a The pinned root, and what the resolver must show the user `[BUILD NOW]`

**The pinned root is configuration, deliberately.** A resolver holds a
`TLDRegistry` address, and that address is the entirety of its opinion about
which namespaces exist. This is not an implementation detail to be hidden behind
a default — it is the mechanism of the fork right (§12.0a). If governance is
captured, resolvers repoint and the captured root governs nothing. Requirements:

| Requirement | Reason |
|---|---|
| The pinned address is displayed in `axonctl resolver status` | A user cannot exercise a fork right they cannot see |
| Changing it requires an explicit action, never an auto-update | An auto-updating root address *is* the centralisation the design removes |
| A resolver MAY hold several roots and refuse when they disagree | Disagreement is the signal of a capture or a fork; failing loudly beats picking |
| The namespace → registrar binding is cached long and revalidated on governance events | It changes at most once per governance action (§12.5) |

**Display rules, which are security requirements and not UI preferences.**
Sections §11.9.2 and §11.0.3 both fail without them:

| Rule | Defends against |
|---|---|
| Never abbreviate a Layer 1 address. No `nzt4f…q7d` in any surface | Vanity-prefix collision phishing (§11.9.2) |
| Render a fingerprint — colour block or word list over the full 35-byte body — beside every address | Gives a comparison target a prefix grind does not control |
| Prefer the verified name; show the address secondary | Moves humans off Layer 1 identifiers for routine use |
| Show the namespace's `registrarClass` at registration and on demand | `UPGRADEABLE`/`STEWARDED` means someone can change the rules under a holder (§12.0) |
| Show `RETIRING` with its `retiresAt`, and surface the Layer 1 address | The service survives the namespace; the user should learn that before the name dies |
| Render a mutual-binding MISMATCH as a refusal to attribute, not a connection error | The name is a claim by a stranger about someone else's service (§11.0.3) |
| Never render a name from a namespace whose status is `NONE` | Prevents a stale client presenting a namespace the root does not have |

**The cross-namespace confusion the resolver cannot fix.** `alice.lab.axon` and
`alice.corp.axon` are different parties. No registrar can police the other's
namespace, and the root deliberately does not try (§11.0.3 rule 1). A resolver
can render the full canonical name and refuse to abbreviate it; it cannot make a
user read the middle label. This is a genuine, unmitigated cost of the governed
multi-namespace design `[UNSOLVED]`, and it is the strongest argument in the
document for keeping the number of namespaces small.

### 13.4 Caching

Five tiers, because they have different lifetimes, different trust states and
different privacy consequences.

| Tier | Key | Value | State | TTL source | Persisted? |
|---|---|---|---|---|---|
| Normalisation | raw string | normalised label | T1 | none, pure function | no |
| **Binding** | `nameKey` | DomainIdentity, prev, rotatedAt, revokedAt, `as_of` block | T2/T3 | **pinned**: 7-day ceiling, revalidated every 600 s in FULL | **yes**, encrypted |
| Descriptor | blinded key | signed record | T4 | the record's own `notAfter`, capped at 3 h and at the time-period boundary | no (RAM) |
| Negative — authenticated | `nameKey` | proof of absence | **T2** | 600 s | no |
| Negative — lookup failure | `nameKey` or blinded key | nothing | **T0** | 60 s, exponential backoff ×2, cap 600 s, ±25 % jitter | no |
| Content pointer | BLAKE3 root | manifest | **T5** | immutable; evict on space only | yes, plaintext (it is public and self-certifying) |

**Why the binding is pinned and the descriptor is not.** A DomainIdentity changes
when an owner rotates or revokes — events measured in months. A descriptor
changes every republish, hourly, with a 3 h lifetime. Pinning the binding is what
lets a resolver work through a chain outage; pinning a descriptor would just
serve dead intro points. The asymmetry is the point: the slow, authoritative fact
is held, the fast, cheap fact is refetched.

**Pin does not mean trust forever.** A pinned binding older than its revalidation
interval is still served, with `warnings: [STALE_BINDING]` and its `as_of` in the
answer, until the 7-day ceiling — after which the resolver refuses rather than
answers. Refusing is correct: a week-old ownership fact is not a fact.

**Cache poisoning defences.**

```text
1  Every entry stores the trust state it was admitted at; a T0 answer never
   displaces a T2/T3/T4 entry. Mirrors AdoptExecutionPayload, which refuses to
   change an authenticated entry rather than preferring the newer.
2  Keyed by nameKey and DomainIdentity, never the display string, so two
   normalisations of one name cannot occupy two entries.
3  Revision monotonicity per name, persisted: a lower revision is dropped even
   if perfectly signed.
4  Sequence monotonicity for snapshots and revocation lists, exactly as
   SnapshotCache does — "replaying a validly signed empty list would otherwise
   un-revoke everything, which is the cheapest possible attack on a revocation
   system."
5  Per-isolation-context namespaces; a shared cache lets one origin prime
   another's answers and observe timing.
6  Bounded — 4096 bindings, 16384 descriptors, segmented LRU with a pinned
   segment eviction may not touch while unexpired. An unbounded cache is a
   memory-exhaustion surface reachable by any local process with socket access.
7  Negative entries are never created from DELEGATED answers.
8  No prefetch, no speculative resolution, no cache-warming task: each would be
   a DHT lookup the user did not ask for and that is attributable to them.
```

**The privacy hazard, stated plainly: a resolver cache is a browsing-history log
on disk.** Every prior system has this problem and none of them solved it. The
defences here are ordinary and none is complete.

```text
DEFAULT       descriptors and negative entries never touch disk. Only the
              binding tier persists, and it is the least revealing tier: it
              records that a name was resolved, not that it was visited.
ENCRYPTION    one file, ChaCha20-Poly1305 (RFC 8439), 32 B random key held in
              the OS keystore (Keychain / DPAPI / kernel keyring) and never
              written beside the file; HKDF-SHA256 with the label
              "axon-resolver-cache-v1" derives per-record subkeys.
PADDING       fixed 4096-slot table, every slot the same ciphertext length,
              written occupied or not, so size and mtime leak no count.
PERMISSIONS   0600 inside a 0700 directory, atomic rename, O_NOFOLLOW —
              internal/gateway/acme.go tightens an existing directory rather
              than trusting the umask; do the same.
LIFECYCLE     forget(name) and forget_all() in the socket API; optional
              wipe-on-clean-shutdown; expiry DELETES rather than tombstones.
NOT SOLVED    a local adversary watching write timing learns when the user
              resolved something, encrypted or not; a memory-only cache leaks
              to swap unless mlock succeeds, and mlock often does not.
```

Eviction: segmented LRU. Pinned bindings occupy a protected segment and are
evicted only when expired or explicitly forgotten. Descriptors and negatives
share a probationary segment. On memory pressure the probationary segment is
dropped whole rather than sampled — partial eviction leaks which entries were
recently used to anyone who can time the resolver.

---

### 13.5 Revocation and key rotation

Two different events with two different rules, and conflating them is a security
bug rather than a naming inconvenience.

```text
ROTATION    planned. The owner publishes a new DomainIdentity while the old one
            remains valid for an OVERLAP of 48 hours. Both keys validate
            records during the overlap; a record signed by either is accepted.
            48 h = two full 24 h time periods, chosen so that the 12 h blinded-
            key overlap (§5 of the Constitution) drains completely inside it.

REVOCATION  unplanned — key compromise. NO overlap. The moment the revocation
            is final, the old key is dead: cached records signed by it are
            dropped, descriptors under its blinded keys are ignored, and TLS
            leaves minted for it (§13.8) are torn down.
```

Propagation of a rotation:

```text
t=0     owner transaction sets identity := new, prev := old,
        rotatedAtBlock := N                             [chain, §12]
t≈12.8m block N finalises. FULL resolvers see it within 600 s of that.
t=0..48h both keys validate. The domain republishes descriptors signed by the
        NEW key immediately; the OLD key's descriptors expire naturally
        within 3 h, so the practical overlap is far shorter than 48 h.
t>48h   resolvers reject records signed by prev. A domain that failed to
        republish is now unresolvable, which is the correct outcome — the
        alternative is an indefinite window in which a retired key still
        speaks for a name.
```

Propagation of a revocation, and reaching a client that holds a cached record:

```text
1  revokedAtBlock is set on-chain.
2  A FULL resolver's binding revalidation (600 s) reads it and IMMEDIATELY
   invalidates: the binding entry, every descriptor entry signed by that key,
   every negative entry for the name, and any minted TLS leaf.
3  A SNAPSHOT resolver learns when the next snapshot it accepts includes the
   revocation. The snapshot format therefore MUST carry revocations as a
   cumulative signed list with a monotonic Sequence — the Revocations record
   in internal/gateway/snapshot.go, unchanged in shape.
4  A DELEGATED resolver learns only if the delegate chooses to tell it. This
   is why an answer without freshness evidence is refused: the refusal
   converts silent censorship into a visible stall.
5  There is no push. There is no revocation notification channel. A client
   that never checks the chain, a snapshot, or a delegate CANNOT learn about
   a revocation, and no protocol change fixes that.
```

**Maximum revocation latency, derived — not measured.** `T_final` = 2 epochs =
64 slots × 12 s = 768 s = 12.8 min in the normal case, 3 epochs = 1152 s =
19.2 min when an epoch fails to justify; `SlotsPerEpoch = 32` is in
`internal/ethproof/rotation.go`.

| Mode | Arithmetic | Declared bound |
|---|---|---|
| FULL | `T_final(19.2 min)` + binding revalidation (600 s) | **30 minutes** |
| SNAPSHOT-WARM | snapshot publication period (1 h) + freshness ceiling (24 h) | **25 hours** |
| SNAPSHOT-COLD | as above, **if** the publisher is honest and reachable | 25 h, else **unbounded** |
| DELEGATED, evidence required | inherits the client's own root freshness | 30 min or 25 h, per root |
| DELEGATED, evidence not required | the delegate decides | **unbounded — forbidden for this reason** |
| Offline / cache-only | the 7-day pin ceiling, then refusal | **7 days** |

These are ceilings on *learning*, not on exposure. The floor nobody can remove:
between a key being stolen and the revocation transaction finalising, the thief
speaks for the domain with full authority, and the resolver has no way to know.
Broadcast is not verifiable (§13.2), so a revocation that a provider drops is a
revocation that never happened.

---

### 13.6 Stale records, reorgs, and chain unavailability

**Bindings are read at the finalized head only.** Not at the optimistic head,
even though `LightClientState.TrustLevelOf` can return `HeaderVerified` for a
committee-signed header that is not yet final. `HeaderVerified` means "authentic
and still reorgeable", and a reorgeable ownership fact is not an ownership fact.

The consequences, exactly:

| Situation | Resolver behaviour |
|---|---|
| Name registered 1 block ago | Not visible. Authenticated NXNAME at the finalized head. Registration is "pending" for up to 19.2 min and the registrant must be told that at registration time, by §12's tooling, not discover it here. |
| **Name transferred 1 block ago** | The resolver answers with the **previous** owner's DomainIdentity, because that is what finalized state says. If the resolver can also see the optimistic head and it disagrees, the answer carries `warnings: [PENDING_TRANSFER]` and the binding TTL is shortened to the expected time to finality instead of the usual 600 s. It does **not** act on the pending value. |
| A record arrives signed by the *new* owner during that window | R8 fails. The error is `ErrIdentityMismatch`, and the user-visible text is "this name changed hands recently and the change is not yet final" — not "invalid signature", which would be true and useless. |
| Reorg below the finalized head | Does not happen without a ≥1/3 slashable finality reversion. `AdoptExecutionPayload` already refuses to record two different execution states for one block number, calling it "a reorg past finality, which does not happen", and refusing rather than silently preferring the newer. The resolver inherits that refusal: a conflict is a hard error and a reason to stop, not to re-resolve. |
| Reorg above the finalized head | Irrelevant to bindings — we never read there. The **reorg risk window is therefore the depth from head to finalized checkpoint, 64–96 slots (12.8–19.2 min), and our binding exposure inside it is zero by construction** at the cost of that much latency. |
| Descriptor published before a transfer, fetched after | Rejected at R8 under the new DomainIdentity. Descriptors do not survive a transfer, which is correct — the new owner did not sign them. |

Chain unavailability, in order:

```text
1  RPC unreachable            Endpoints.Post returns ErrChainUnreachable and
                              fails over to the next configured endpoint.
2  All endpoints unreachable  Fall back to SNAPSHOT if a snapshot within F is
                              held. Answers are T3 and say so.
3  No usable snapshot         Serve pinned bindings with STALE_BINDING, up to
                              the 7-day ceiling. Descriptors still resolve
                              normally — day-to-day records need no chain
                              access at all (R7).
4  Past the ceiling           Refuse. ErrNoTrustAnchor's discipline, applied
                              to names: an outage is the correct behaviour for
                              a system that cannot tell what it is looking at.
5  Never                      Fall back to believing an RPC. There is no
                              degraded mode that accepts a provider's word;
                              VerifyHeader has no such path and neither does
                              this.
```

---

### 13.7 Integration surfaces

Each is a different attack surface, and the order they ship in is a security
decision rather than a scheduling one.

**(a) Local daemon with a socket API — [BUILD NOW], the MVP.**

```text
socket   $XDG_RUNTIME_DIR/axond.sock, mode 0600, in a 0700 directory
framing  newline-delimited JSON in v1 (debuggable), length-prefixed binary
         reserved by a version field
calls    resolve(name, {mode, min_state, max_staleness, isolation}) → Answer
         forget(name) | forget_all()
         status() → {mode, anchor kind, finalized block, snapshot age}
Answer   {value, kind, trust_state, mode, as_of_block, expires_at, warnings[]}
```

Security analysis: a Unix socket is reachable by every process running as that
user, so the API is a browsing-history oracle to any of them, and `resolve` is a
network action a malicious local process can trigger. Mitigations: `SO_PEERCRED`
checked and the uid recorded; a per-uid socket; no TCP listener by default and,
if enabled, loopback-only plus a capability token from a 0600 file; per-caller
rate limits; and the amplification guard `ContentProxy.serveSnapshot` uses — a
malformed or unregistered name is answered locally with **no lookup at all**, so
the daemon cannot be pointed at the DHT as an amplifier by a loop over random
strings.

**(b) SOCKS5 / HTTP CONNECT proxy — [BUILD NOW], second.**

Why second and not last: SOCKS5 carries a **hostname** (ATYP `0x03`), so the
application never resolves anything and there is no DNS to leak. This is the
leak-free surface, and it is why it precedes the shim.

Security analysis: the proxy is an open door on loopback — bind 127.0.0.1 only,
and require SOCKS5 username/password not as authentication but as the
**isolation context** key, so two applications get different guards, different
circuits and different cache namespaces (R1). Refuse `CONNECT` to non-`.axon`
names by default; a proxy that silently forwards clearnet is a proxy that leaks
when a page loads one absolute URL. Refuse SOCKS4 outright: it has no hostname
form and would force local resolution. `Host:` headers must be rewritten
consistently with the CONNECT target or a virtual-host mismatch becomes a
fingerprint.

**(c) Browser extension — [NEEDS RESEARCH], fourth.**

Two jobs only: render the trust state and mode next to the URL, since the browser
UI cannot express "verified by your own daemon at T2"; and pin the origin's
DomainIdentity so a changed key is visible to the user rather than silently
accepted. It must not be responsible for resolution — an extension that resolves
is an extension that can be disabled to disable security.

Security analysis: MV3 restricts blocking request interception, so the redirect
and header work an older extension would have done may be unavailable — **[NEEDS
RESEARCH]: what interception remains, per browser.** An extension sees every
page's URL, the same browsing-history hazard as the cache with worse storage
guarantees, and its update channel is a vendor-controlled push into a
security-relevant component.

**(d) System DNS shim — [NEEDS RESEARCH], last, and the classic failure.**

The failure: an application resolves `alice.lab.axon` through the normal OS path, the
query reaches a public resolver, and the name — the one thing the whole overlay
exists to protect — is disclosed in cleartext to an operator who logs it, along
with the client's IP. It has happened to every naming overlay that shipped a DNS
integration.

```text
THE SHIM
  bind 127.0.0.1:53535, install a split-horizon rule so ONLY .axon reaches it:
    systemd-resolved   a ~axon routing domain on a dedicated link
    macOS              /etc/resolver/axon
    Windows            an NRPT rule for .axon
  answer A/AAAA from a dedicated handle pool (we choose 127.28.0.0/16) that
  the daemon has bound; the address is a HANDLE with a 120 s lifetime, mapped
  to the resolved destination. Tor's automap-on-resolve behaviour is the
  prior art. Every other qtype gets NOERROR/empty; NS/SOA/AXFR are refused.

THE MITIGATION THAT MATTERS — PROVE YOU ARE AUTHORITATIVE, DO NOT ASSUME IT
  On start, and every 5 minutes, the daemon queries <random-32-hex>.axon
  through the SYSTEM resolver path, not its own socket.
    no answer, or the answer is ours   → the split horizon is installed; run
    anything else answers              → the split horizon is NOT installed,
                                         a query just left this machine.
                                         DISABLE THE SHIM, raise a visible
                                         error, and fall back to (b).
  The canary name is random per probe so it cannot be pre-answered, and the
  probe itself is the leak it is testing for — one random label per five
  minutes, which reveals that AXON is installed and nothing about the user's
  names. That trade is stated rather than hidden.

THE PART THE SHIM CANNOT FIX
  A browser with DNS-over-HTTPS enabled bypasses the OS resolver entirely.
  No OS-level rule reaches it. Vendors expose canary/exclusion mechanisms of
  varying reliability — [NEEDS RESEARCH: the exact mechanism and name per
  browser, to be read from vendor documentation and verified, not recalled].
  Until then the honest position is: if DoH is on, the shim is not a
  supported configuration and the daemon says so loudly, because a shim that
  silently does not apply is worse than no shim.
```

Further shim hazards: the handle→destination map is itself a browsing-history log
and lives under §13.4's rules; a handle must never be reused inside its lifetime
or one origin inherits another's connection; and a VPN or captive portal that
re-points DNS mid-session must re-trigger the canary probe.

**(e) Native application support via the L8 API — [BUILD NOW], parallel track.**

No DNS, no proxy, no certificate: the application calls `resolve` and gets a
destination and a public key. This is the only surface where the *right* TLS
answer (raw public keys, §13.8) is actually available, and the only one where the
trust state can be enforced rather than displayed.

**Recommended order and MVP.**

```text
MVP   (a) daemon socket API  +  (b) SOCKS5
      Everything else is a client of (a). SOCKS5 makes a real browser work
      with no trust-store change and no DNS involvement, which means the MVP
      has no leak of the kind (d) exists to prevent.
then  (b') HTTP CONNECT — for tools that cannot speak SOCKS
then  (e) L8 native — no browser constraints, and it unblocks §13.8's clean path
then  (c) extension — needed before the local root in §13.8 is defensible
last  (d) DNS shim — most fragile, biggest leak risk, and made optional by (b)
```

---

### 13.8 The `https://alice.lab.axon` problem

A browser shows a padlock only if the certificate chains to a root it trusts.
There is no CA that issues for `.axon` and there will not be one, because no CA
can validate control of a name in a namespace it cannot see. No option here is
simultaneously secure, standard, and available today. The honest baseline:
`internal/gateway/acme.go` gets a padlock today by having a real DNS name and a
real Let's Encrypt certificate — which works perfectly, and is exactly the
trusted third party this project exists to remove.

| Option | How it works | What the padlock would mean | Cost |
|---|---|---|---|
| **A. Local root, name-constrained** | The daemon generates a root at install, installs it in the system/browser store, and mints a short-lived leaf for `alice.lab.axon` after resolving to T4. The proxy terminates TLS locally. | "My own daemon verified this name against the chain." Which is *stronger* than a public CA's meaning — and the browser UI cannot say so. | A root private key on the user's machine. |
| **B. Raw public keys / DANE-style** | TLS with the server's key learned from the DomainRecord instead of a certificate chain. | "This key is the one the name commits to." Cryptographically the correct answer. | **No shipping browser implements it.** DANE was never adopted in browsers and raw-public-key TLS is not exposed to web content. |
| **C. No TLS; rely on the overlay** | L1/L4/L5 already provide authenticated encryption end to end to a ServiceIdentity the descriptor binds. TLS would be a second, weaker layer over a stronger one. | Nothing — the browser shows "Not Secure". | **Loses secure context.** Service workers, much of WebCrypto, storage partitioning behaviour, and mixed-content rules all key off a secure origin. `.onion` obtained this by being registered as a special-use TLD and then being added to browsers' potentially-trustworthy list. That is the precedent and it is a standards-plus-vendor track measured in years. |
| **D. A clearnet gateway with a real certificate** | What exists today. | "A CA validated a DNS name someone else controls." | Reintroduces the trusted third party, and the gateway sees plaintext. Rejected for the overlay; retained only as a bridge for readers who have no client. |

**Ruling for v1: A, with constraints, plus B for native clients via L8, plus the
standards track for C started immediately and expected to outlive v1.**

Option A's constraints, all of which are load-bearing:

```text
1  NAME CONSTRAINTS. The root carries an X.509 nameConstraints extension with
   permittedSubtrees limited to dNSName ".axon" and excludedSubtrees for
   everything else. A root that can only sign .axon cannot MITM a bank.
   [NEEDS RESEARCH] Enforcement varies by platform and trust store, and a
   platform that ignores name constraints on a locally-installed root turns
   this mitigation off silently. The daemon must TEST enforcement at install
   time — mint a leaf for a name outside the constraint and confirm the
   browser rejects it — and refuse to install where it cannot.
2  KEY STORAGE. Non-exportable in a TPM/Secure Enclave/keychain where the
   platform offers it. Otherwise 0600 beside the cache, encrypted with a key
   from the OS keystore, and never in the same file as the cache.
3  LEAF BINDING. The leaf carries the resolved DomainIdentity in an extension
   so the extension in §13.7(c) can display it and pin it. A padlock that
   does not name the key it stands for is decoration.
4  LEAF LIFETIME. 10 minutes, minted per resolution, never persisted. A
   revocation (§13.5) tears down the leaf and the TLS session with it. Short
   leaves are how revocation actually reaches a browser, since browsers do
   not check revocation reliably.
5  MODE FLOOR. A leaf is minted from a T2 answer normally. From T3 the
   lifetime drops to 10 min and the extension shows the snapshot age. From a
   DELEGATED answer whose evidence did not verify, NO leaf is minted at all —
   the connection is refused rather than decorated.
6  SCOPE. The root signs only for the loopback listener the daemon owns.
   Uninstalling the daemon must remove the root; an orphaned root that
   outlives the software is the worst outcome of this design.
```

The residual, without softening: **installing a local root is a real reduction in
the user's security posture, traded for the browser's cooperation.** If the name
constraint is not enforced on that platform, malware that steals the root key can
impersonate any site to that user. This is the same bargain enterprise TLS
interception makes, and a better purpose does not change the shape of the asset
created. It is why option C's standards track starts now, and why the native L8
path (option B) is recommended to anyone who can use it.

---

### 13.9 Failure modes and user-visible behaviour

| Failure | Detected by | Resolver behaviour | User sees | Open/closed |
|---|---|---|---|---|
| RPC unreachable | `ErrChainUnreachable` from `Endpoints.Post` | Fail over; then SNAPSHOT; then pinned bindings | Works, marked `STALE_BINDING` with an age | Open, bounded |
| RPC lying about a value | `VerifyProof` rejects | Discard, try the next endpoint, mark the provider | Slower resolve, or a hard error naming the provider | Closed |
| RPC lying about a header | `VerifyExecutionHeader` → `ErrNotAuthenticated` | Refuse; never accept a header the light client did not authenticate | "Cannot confirm this is Ethereum mainnet" | Closed |
| No trust anchor configured | `ErrNoTrustAnchor` | Refuse all binding reads. No degraded mode exists | Setup error at first run, not a silent weaker mode | Closed |
| Light client behind the chain | Requested block > authenticated | Answer from the finalized point it has, with `as_of` | Slightly old answer, age shown | Open, bounded |
| Checkpoint is a fake | **Nothing detects this** | Everything verifies inside a coherent fake chain | Nothing. This is the residual of weak subjectivity | — |
| Name not registered | Proof of absence (~160 B), T2 | Authenticated NXNAME, negative-cached 600 s | "No such name" — a fact | Closed |
| Name registered 1 block ago | Absent at the finalized head | Authenticated NXNAME with `PENDING_POSSIBLE` | "Not found yet; registrations take about 13 minutes" | Closed |
| Name transferred 1 block ago | Optimistic ≠ finalized | Answer the **old** owner, `PENDING_TRANSFER`, short TTL | Old destination, with a visible warning | Closed on the new value |
| DomainIdentity revoked | `revokedAtBlock` set | Purge binding, descriptors, negatives, TLS leaf; refuse | "This name's key was revoked" | Closed |
| Record signed by a rotated-out key, in overlap | `prevIdentity` matches | Accept; warn `ROTATED_KEY` | Works | Open, 48 h |
| Record signed by a rotated-out key, past overlap | Neither identity matches | Reject → `ErrIdentityMismatch` | "This name changed keys; the service has not updated" | Closed |
| DHT lookup: all `d=3` paths empty | No candidates | `ErrNoDescriptor`. **Not** cached as absence | "Could not find this service" — explicitly not "does not exist" | Closed, weak |
| DHT returns hostile records | R8 rejects each | Continue through remaining candidates; never abort on the first | Slower resolve | Closed |
| Descriptor expired | `notAfter` | Discard; retry once; then `ErrNoDescriptor` | "Service is not currently published" | Closed |
| Replayed older record, or a poisoning attempt | Revision/sequence monotonicity, state lattice | Rejected at admission | Transparent | Closed |
| Wrong SRV / wrong epoch | **Nothing** — looks identical to absence | `ErrNoDescriptor` | "Could not find this service" | Closed, and the diagnosis is invisible |
| Snapshot expired | `State() == expired` | Refuse the snapshot entirely; drop to pinned bindings | Degraded, with an age | Closed on the snapshot |
| Snapshot fails verification | Root or signature check | **Discard, do not quarantine** | Transparent, logged | Closed |
| Delegate returns no evidence | Evidence check | Refuse the answer; demote the delegate | "Your configured resolver did not prove its answer" | Closed |
| Delegate censors one name | Indistinguishable from a timeout | Retry, then try another delegate, then fail | "Could not resolve" | Closed, undiagnosable |
| Delegate serves a stale valid record | `as_of` too old, or nonce not echoed | Refuse | "Answer was too old to trust" | Closed |
| Local root not installed / constraint unenforced | Install-time enforcement test | Refuse to install; fall back to SOCKS + plain overlay | "HTTPS for .axon is unavailable on this system" | Closed |
| DNS shim not authoritative | Random-label canary probe | **Disable the shim**, fall back to SOCKS, raise a visible error | "A .axon lookup left this machine — DNS integration disabled" | Closed |
| Confusable / mixed-script name | Normalisation profile | Reject before any lookup | The name is shown in punycode with a warning | Closed |
| Alias loop | Depth counter > 4 | `ErrAliasLoop` | "This name points at itself" | Closed |

---

### What this section does NOT establish

- **No part of the naming path has been measured.** Every latency and size figure
  here is either quoted from `doc/ethereum-data-layer.md` §6b (measured against
  block 25,737,778, for `ChannelManagerV2`-shaped reads) or derived from
  protocol constants. A registry binding read has not been measured, the DHT
  descriptor lookup over a circuit has not been measured, and the 30-minute and
  25-hour revocation bounds are arithmetic, not observations.
- **The registry slot layout is §12's and is not settled here.** The mapping
  arithmetic is `ethproof.StorageSlotKey`, but the slot index must come from
  `solc --storage-layout`. Until §12 fixes it, the binding read is specified in
  shape only.
- **Snapshot publication is unspecified.** Who computes the snapshot, what
  prevents a publisher from omitting a name, and whether omission is provable to
  a client are open. Without a proof of omission, SNAPSHOT mode is censorship-
  resistant only against a publisher who is honest about *what it includes*.
- **DHT absence cannot be proven.** A descriptor that `d=3` disjoint paths fail
  to find is indistinguishable from one that was never published, and a wrong SRV
  produces the same symptom. Nothing here fixes that; it is bounded by retries
  and honest error text.
- **The `https://` answer is a liability, not a solution.** A name-constrained
  local root is the only thing that works in a browser today, its constraint
  enforcement is platform-dependent and unverified, and the durable fix is a
  special-use TLD registration plus vendor adoption that this project does not
  control.
- **The initial checkpoint is still subjective, and the resolver inherits that
  whole.** Every T2 claim in this section is conditional on the user having
  obtained a genuine weak-subjectivity checkpoint. `SetAnchor` catches the
  circular case and nothing catches the fabricated one.

> **Objection to Constitution §2:** the fixed primitive table lists HKDF-SHA256
> as the only KDF. §13.4 needs a *password* KDF for the fallback path where no OS
> keystore is available and the cache key must be derived from a user passphrase;
> HKDF is the wrong tool for that and using it would be a real weakness. Request
> that Argon2id (RFC 9106) be added to §2 for passphrase-derived local storage
> keys only, explicitly out of the protocol data path.

> **Objection to Constitution §5:** the parameter table fixes a 24 h time period
> with 12 h overlap for blinded descriptor keys, but says nothing about
> DomainIdentity rotation, which is a different event on a different timescale.
> §13.5 asserts a 48 h rotation overlap and a zero-length revocation overlap.
> Both belong in §5 so §12 and this section cannot drift apart.
