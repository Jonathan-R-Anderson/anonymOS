## 23. Phased Development Plan (P0–P16, plus P9b)

**The finding that shapes the calendar: the phases are not a line. They are three
tracks that touch in four places, and only one of the three contains work nobody
here has done before.** The anonymity track (P1→P7) is serial, novel, and the
schedule. The naming track (P8→P10) needs exactly one artefact from it — the
Ed25519 record format frozen in P1 — and otherwise stands on an Ethereum light
client that is already written and mainnet-verified (§1.3 row 16). The
chain/accounting track touches the data path nowhere at all, by ruling R11.
Treating the seventeen phases as a sequence would add roughly two years of
elapsed time to a programme that does not need them.

Second finding: **the exit criteria are the deliverable of this section, not the
phase descriptions.** A phase whose completion cannot be falsified on a running
network is a phase that will be declared complete when the budget runs out. Every
criterion below names an observation that would prove the phase is not finished,
and every one is executable on the `axon-lab` harness specified in §24.1.

### What already exists

Read for §23–§25, in `github.com/syndichan/maniwani/storage-client` and
`dendritic.network/proof-of-facilitation`:

| File read | What it contributes to the plan |
|---|---|
| `internal/p2p/node.go:333-504` | `openI2PNode` / `openNode` / `finishNode`. The transport seam every phase from P2 attaches to; `openNode` is the non-I2P constructor that already works. |
| `internal/p2p/node_test.go:63-70`, `recall_test.go:69`, `disperse_test.go:168`, `recall_failure_test.go:75`, `compute_test.go:47` | Five multi-node harnesses over `/ip4/127.0.0.1/tcp/0`. `axon-lab` (§24.1) is these generalised, not a new idea. |
| `internal/p2p/recall_lying_holder_test.go` | The adversarial register the phase tests match: a holder that lies about deletion and tells the truth about possession, caught by the follow-up. |
| `internal/store/store.go:41-45` | `shardFetchTimeout = 3 * time.Minute`, commented as needing to exceed `p2p.i2pDialTimeout`. A P11 deliverable, not a survivor. |
| `internal/gateway/protocol.go` | `EvaluateQuorum`, `VerifyProbeResult`, `PublicAddress`, `NormalizeAddresses` — the reachability oracle P3 reuses. |
| `internal/p2p/challenge.go` | `challengeOperation = "pof-challenge"`, `challengeTimeout = 90s`, `SendChallenge`/`SetChallengeHandler`. The frame P14 extends. |
| `internal/ethproof/` (49 files) | The light client. P4's SRV and P10's whole trust path consume code that exists and is mainnet-verified. |
| `go.mod` | `quic-go v0.59.1`, `lukechampine.com/blake3 v1.4.1`, `go-libp2p-asn-util v0.4.1` present as indirect dependencies. P2, P11 and P3 each start with their primary library on disk. |
| `proof-of-facilitation/package.json`, `hardhat.config.ts`, `test/` (11 files), `deploy/` | Hardhat + OpenZeppelin 5.1 with deploy scripts. P9 adds contracts to a working build. |
| `proof-of-facilitation/aggregator/` | Go epoch/merkle/settlement code with golden tests. P15's off-chain half is largely written. |
| `scripts/build-release.sh`, `check-release.sh`, `dist/` | Seven cross-compiled binaries with `.sha256` files. P16's release mechanics exist; their *trust* properties do not (§18.14). |

**What must be replaced:** the ordering implied by the existing roadmap files
(`doc/p12-*`, `proof-of-facilitation/README.md` §Next), which sequences work
around a website-run chain gateway that §1.8 rules out.

### 23.1 How to read a phase

Every phase carries the same twelve fields. Three conventions make them
comparable. **Exit criteria are falsifiable** — each names the observation that
disproves it; "circuits work" is not a criterion, "the cell entering hop 1 and
the cell leaving hop 3 share no payload bytes, by loopback capture" is. **"Must
NOT be built yet" is a scope fence** — every entry is something a competent
engineer will be tempted to build because it is adjacent, and that costs more
than it saves before its own dependencies settle. **A phase carrying a
`[NEEDS RESEARCH]` component cannot exit on schedule confidence**; those phases
are named in §23.3.

Package names assumed, under a new module path `axon/`: `axon/identity`,
`axon/link`, `axon/peer`, `axon/dht`, `axon/cell`, `axon/circuit`, `axon/tunnel`,
`axon/rendez`, `axon/name`, `axon/registry`, `axon/resolver`, `axon/path`,
`axon/token`. `axon/rendez` is deliberately not `rendezvous`:
`internal/p2p/storage_capacity.go:33` already uses that word for a DHT provider
key (§1's objection to Constitution §3).

### 23.2 The dependency DAG

```text
                                   P0  architecture + threat model
                                   (gate — nothing starts before it exits)
                                                │
    ┌───────────────────────────────────────────┼───────────────────────────────┐
    ▼  TRACK A — ANONYMITY                      ▼  TRACK B — NAMING             ▼  TRACK C — CHAIN
       (serial, novel, the schedule)               (parallel from month 0)         (parallel, off-path)
    │                                           │                               │
  P1 cryptographic identities ─────────────┬───▶ P8 .axon namespace             │
    │                                      │     │                              │
  P2 secure transport (QUIC/TLS 1.3)       │   P9 Ethereum registry ───┐        │
    │                                      │     │                     │        │
  P3 peer discovery + NAT                  │   P10 decentralised ◀─────┘        │
    │                                      │       resolver                     │
  P4 DHT ◀──── SRV ────────────────────────┘       │  ▲                         │
    │          (existing light client)              │  └── existing ethproof     │
    ├────────────────────────┐                      │                           │
    ▼                        │                      │                     P14 sybil hardening
  P5 basic circuits          │                      │                     (contract half from P0;
    │                        │                      │                      path half waits on P12)
    ├──────────────▶ P11 storage integration ◀──────┘                           │
    │                        │                                                  │
  P6 rendezvous              │                                            P15 incentive layer
    │                        │                                                  │
  P7 services + tunnel pools │                                                  │
    │                        │                                                  │
    ├────────┬───────────────┤                                                  │
    ▼        ▼               │                                                  │
  P12      P13               │                                                  │
  path     traffic-analysis  │                                                  │
  diversity  defences        │                                                  │
    └────────┴───────────────┴──────────────────┬───────────────────────────────┘
                                                ▼
                                  P16  production network
```

**Edges, stated exactly.** An edge means the downstream phase cannot *exit*
without the upstream phase having exited; several may *start* earlier against a
frozen interface, and the table says which.

| Phase | Cannot exit without | May start against | Runs in parallel with |
|---|---|---|---|
| P0 | — | — | — |
| P1 | P0 | — | P8 |
| P2 | P0, P1 | P1 key formats frozen | P8, P9, P14-contracts |
| P3 | P2 | P2 link interface frozen | P8, P9, P10 |
| P4 | P1, P3 | P3 peerbook interface | P8, P9, P10 |
| P5 | P2, P4 | P4 `RelayDescriptor` format | P9, P10 |
| P6 | P5 | P5 circuit API | P10, P11 |
| P7 | P6 | — | P10, P11 |
| P8 | P1 | P0 | all of Track A |
| P9 | P8 | P8 name grammar frozen | all of Track A |
| P10 | P4, P9 | P9 contract ABI frozen | P5, P6, P7 |
| P11 | P4, P5 | P5 stream API | P9, P10 |
| P12 | P3, P7 | P7 pool API | P10, P11 |
| P13 | P7, P12 | — | P14, P15 |
| P14 | P4, P12 (path half); P0 only (contract half) | P0 | P5–P11, for the contract half |
| P15 | P14 | P14 bond interface | P12, P13 |
| P16 | P7, P10, P11, P13 | — | — |

**What this buys.** Track B (P8→P9→P10) is roughly 12 engineer-months occupying
zero days on the critical path. Track C's contract half is another 4–6 that
blocks nothing. The registry contract work is independent of the circuit work in
the strongest sense available: they share no file, no library, no test harness
and no engineer's attention.

**The critical path is P0 → P1 → P2 → P3 → P4 → P5 → P6 → P7 → P12 → P13 → P16.**
Every phase on it is in Track A except the last. Staffing B or C does not shorten
it.

### 23.3 Effort, confidence, and where the schedule breaks

One engineer-month (em) is one engineer at full time for one month including
review, test and documentation. **These are estimates from a specification, not
measurements; no phase below has been prototyped.**

| Phase | Range (em) | Mid | Confidence | What drives the variance |
|---|---|---|---|---|
| P0 architecture + threat model | 1.5–3 | 2.2 | **High** | Review turnaround, not writing. This document is most of the deliverable. |
| P1 cryptographic identities | 2–4 | 3.0 | **High** | Ed25519 scalar blinding is small and delicate; the risk is the `p2p.key` migration preserving the PoF node id (§5). |
| P2 secure transport | 4–8 | 6.0 | Medium | Whether RFC 7250 raw public keys exist in the target TLS stack (§6 marks it `[NEEDS RESEARCH]`); whether libp2p is replaced or wrapped. |
| P3 peer discovery + NAT | 3–6 | 4.5 | Medium | The NAT-behaviour distribution in the real population is unknown (§6). Hole punching may be worthless here and is budgeted as if it is not. |
| P4 DHT | 4–7 | 5.5 | Medium-high | kad-dht carries the routing; KadID rotation, d=3 disjoint paths and six validators are new. Epoch-boundary churn is the unknown. |
| P5 basic anonymous circuits | 6–12 | 9.0 | **Low-medium** | Nothing comparable in the tree. Cell format and key schedule are specified (§8); flow control across 3 hops under R12 is not. |
| P6 rendezvous | 3–6 | 4.5 | Medium | Two-stage intro+RP is well documented; the intro-point puzzle is `[NEEDS RESEARCH]`. |
| P7 services + tunnel pools | 5–10 | 7.5 | **Low-medium** | The session layer that survives circuit death (R9) is the largest unknown in Track A after P5. |
| P8 domain identities + `.axon` | 2–4 | 3.0 | **High** | Grammar, normalisation, encoding. Confusable policy is the only judgement call. |
| P9 Ethereum registry | 3–6 | 4.5 | Medium-high | Contract writing is bounded; **external audit is calendar, not effort**, and is excluded. |
| P10 decentralised resolver | 3–6 | 4.5 | Medium | The light client exists and is verified. Snapshots, freshness accounting and the three modes (§13.3) are the work. |
| P11 storage integration | 3–6 | 4.5 | Medium | The store is unchanged. Re-deriving I2P-calibrated timeouts and resolving the encryption-origin contradiction (§1) is the work. |
| P12 pools + path diversity | 4–9 | 6.5 | **Low-medium** | Path selection is `[NEEDS RESEARCH]` (§1.5). Diversity levels do not exist in `internal/placement` and must be built, not reused. |
| P13 traffic-analysis defences | 4–10 | 7.0 | **Low** | No deployed system has a settled answer; padding-schedule evaluation methodology is itself open. |
| P14 Sybil hardening | 4–9 | 6.5 | **Low** | Contracts are written; **calibration is unsolved** — nobody can say what bond makes 20 % of relays infeasible (§18.22). |
| P15 incentive layer | 5–10 | 7.5 | Low-medium | SCPP/1 and PoF exist; blind relay tokens are `[NEEDS RESEARCH]` (§14.3); a second audit is calendar again. |
| P16 production network | 6–14 | 10.0 | **Low** | Open-ended by nature. Packaging exists; operating a network does not have an end state. |
| **Total** | **62–130** | **96** | — | Ranges do not sum to a confidence interval; the sum of the extremes is not a 95 % bound and is not offered as one. |

**The five schedule risks.** **P5 (circuits)** — everything at L5, L6-descriptors,
L7-blinding and every milestone from M2 waits on it; it is the largest genuinely
new component and its design errors surface late (a flow-control mistake is a
throughput cliff at thirty nodes, not a failing unit test at three). **P7 (session
layer)** — R9 requires streams bound to sessions, libp2p streams die with their
connection (§1.5), so there is no prior art in the tree, and a redesign here slips
P12 and P13 together. **P13** — the risk is not overrun but that it finishes and
nobody can say whether it worked; a 30-node lab cannot evaluate a fingerprinting
defence. **P16** — 6–14 em because it is not a build phase; it ends when someone
decides it has. **P2, conditionally** — without raw public keys it grows a
certificate path and §16's fingerprint analysis must be redone against it.

**Elapsed time, with its assumption.** The critical path sums to roughly 49 em of
mostly serial work, and Track A parallelises badly: P5 and P7 are small-team,
high-coherence pieces where a third engineer costs more in interface churn than
they contribute. A realistic figure is **28–42 months to P16 with four to six
engineers**, and the honest version of that sentence is that no software estimate
at this range has ever been worth much. What is defensible is the *shape*: Track B
finishes long before Track A, and adding people to Track B does not help.

### 23.4 The phases

#### P0 — Architecture and threat model `[BUILD NOW]`

**Objective.** Freeze the layer stack, identity taxonomy, adversary model and the
fourteen rulings, and emit the interface declarations that let three tracks start
in parallel without integrating.

| Field | Content |
|---|---|
| **Architecture** | No implementation. An interface-only `axon/api` package plus a single constants file, so P1/P8/P14-contracts compile against each other. |
| **Components** | This document (§1–§22); `axon/api`; the Constitution §5 parameter table as typed Go constants; the `axon-lab` harness (§24.1). |
| **Protocols** | None. Wire formats are *declared* here and specified in their own phases. |
| **Data structures** | `RelayDescriptor`, `ServiceDescriptor`, `DomainRecord`, `StorageLocation`, `RegistrySnapshot`, `IntroPointRecord` — declarations only, from §7. |
| **APIs** | `type Link interface`, `type Circuit interface`, `type Pool interface`, `type Resolver interface`, `type Store interface` — signatures, no bodies. |
| **Depends on** | Phases: none. Code: `SECURITY.md` (the trust-boundary register being superseded); §1's inventory. |
| **Shortened by** | §1 has already inventoried the tree and measured the I2P coupling at 10 call sites; §18 has already written the threat model. P0 is a review, not a discovery. |

**Tests.** T0.1 `axon/api` compiles with zero implementations and zero imports of
`internal/i2p`. T0.2 Cell size, guard count, tunnel lifetime and DHT k/α/d appear
only in the constants file; a grep for the literals elsewhere fails the build.
T0.3 Every §18 threat row maps to at least one later exit criterion, checked by
script over the two documents.

**Security considerations / failure modes.** The only security work is refusing to
leave a decision open: an unresolved ruling becomes two incompatible
implementations in two tracks. The failure mode is a document that is agreed and
then quietly diverged from, and an `axon/api` that accumulates implementations
and stops being a contract.

**Exit criteria.** E0.1 Three engineers state the adversary model without
consulting the document and agree. E0.2 `go build ./axon/api` and `go vet` are
clean from a fresh checkout on all three release platforms. E0.3 Every
`[UNSOLVED]` marker has a named owner and a stated "what we do instead", verified
by script — falsified by one marker without both.

**Must NOT be built yet.** Any implementation. The temptation is to prototype the
cell format while the document settles; a prototype predating P1's key schedule
gets rewritten and teaches nothing.

#### P1 — Cryptographic identities `[BUILD NOW]`

**Objective.** Implement the eight identity classes of Constitution §3 with their
derivations, serialisations, blinding and rotation, such that no two classes are
ever the same key and every relationship is a hash or a signed delegation.

| Field | Content |
|---|---|
| **Architecture** | One package owns all eight classes of Constitution §3 so cross-class equality is testable in one place: `OwnerIdentity → DomainIdentity → ServiceIdentity → BlindedPub` by delegation and blinding; `NodeIdentity → KadID` by hash and `→ RoutingIdentity` by epoch certificate. |
| **Components** | `axon/identity`: keygen, at-rest storage, serialisation, Ed25519 scalar blinding, delegation certificates, revocation records, `p2p.key` migration. |
| **Protocols** | None on the wire. The canonical encoding rules and the HKDF label table (§5.3) are the protocol. |
| **Data structures** | `IdentityRotation` (0x02), `Revocation` (0x03), `DelegationCertificate` (0x04) per §5.2. |
| **APIs** | `Blind(pub ed25519.PublicKey, period uint64) (BlindedPub, error)`; `BlindSigner(priv, period) crypto.Signer`; `DeriveKadID(NodeID, srv [32]byte, prefix []byte) KadID`; `MigrateP2PKey(path string) (NodeIdentity, error)`. |
| **Depends on** | Phases: P0. Code: `internal/gateway/identity.go` `LoadOrCreateFileIdentity`; `internal/facilitation/register.go` for `nodeId = keccak256(ed25519 pubkey)`. |
| **Shortened by** | The Ed25519 key file, its loader and the PoF node-id derivation all exist and are tested; P1 builds classes around an existing first one. |

**Tests.** T1.1 Golden vectors for every KDF label; a changed label fails the
vector. T1.2 Blinding round-trip — a signature from the blinded signer verifies
under `Blind(pub, period)` and not under `period ± 1`. T1.3 Property test: no two
of the eight classes ever produce equal key bytes from one seed. T1.4 Migration —
an existing `p2p.key` yields the `nodeId` `internal/facilitation` computes today,
byte for byte, so a bonded node keeps its bond. T1.5 A `DelegationCertificate`
signed by the wrong class is rejected.

**Security considerations / failure modes.** Scalar blinding is the delicate
part: an implementation that blinds the public key correctly but leaks the
unblinded key through a signature nonce is catastrophic and passes T1.2 — test
the scalar arithmetic, not only the round trip. Failure modes: a blinding bug
visible only at a period boundary; a migration that silently mints a new node id
and abandons a bond; a non-canonical serialisation, so one record yields two DHT
keys. Key files stay 0600, and §5.7's objection about a missing password KDF is
unresolved.

**Exit criteria.** E1.1 A node started from an existing `syndichan-node` data
directory reports a PoF `nodeId` identical to the pre-migration value — falsified
by any byte difference. E1.2 A service key blinded across 30 consecutive periods
yields 30 distinct keys, and a period-*n* signature verifies only under period
*n* — falsified by any cross-period verification succeeding. E1.3 An audit
walking every struct reachable from L5 upward finds no `ServiceIdentity` private
key — falsified by one.

**Must NOT be built yet.** Post-quantum descriptor signing (deferred by
Constitution §2); hardware-token support; revocation *propagation*, which is
`[UNSOLVED]` (§5) and must not be pre-empted by a partial implementation that
looks like it works.

#### P2 — Secure transport `[BUILD NOW]`; raw public keys `[NEEDS RESEARCH]`

**Objective.** A QUIC link authenticated to NodeIdentity, with one QUIC stream per
circuit (R12), carrying fixed 1024-byte cells identically over QUIC and over the
TCP+TLS fallback.

| Field | Content |
|---|---|
| **Architecture** | `NodeIdentity` authenticates a QUIC+TLS 1.3 link; each circuit gets its own stream, so a stalled circuit cannot block its neighbours; the TCP fallback carries byte-identical framing. |
| **Components** | `axon/link`: dialer, listener, handshake, stream manager, cell framer, link-padding hook (schedule owned by §16). |
| **Protocols** | AXON link handshake over TLS 1.3; version negotiation with the hybrid X25519+ML-KEM-768 slot reserved but unselected in v1 (Constitution §2). |
| **Data structures** | Cell: 16 B header (circuit id 8, cmd 1, flags 1, len 2, reserved 4) + payload; 16 B per-hop AEAD tag reserved for *every* hop position, so capacity does not leak path length. |
| **APIs** | `Dial(ctx, addr NetAddr, expect NodeID) (Link, error)`; `(Link).OpenCircuitStream(id CircuitID) (CellStream, error)`; `(CellStream).WriteCell(*Cell) error`. |
| **Depends on** | Phases: P0, P1. Code: the `transport.Transport` seam at `internal/p2p/node.go:366-375`; `openNode` as the non-I2P host path. |
| **Shortened by** | `quic-go v0.59.1` is already in `go.mod`, and the seam it must satisfy is proven by five test files running the full storage stack over loopback TCP. |

**Tests.** T2.1 Cell size invariant: a loopback capture shows only 1024-byte cell
bodies regardless of payload or hop count. T2.2 Head-of-line isolation (R12): with
circuit A's stream stalled by a peer that stops reading, circuit B sustains
throughput. T2.3 A link presenting a different NodeIdentity than requested is
refused before any cell is sent. T2.4 QUIC and TCP paths produce byte-identical
cell sequences for one input. T2.5 0-RTT is off, by configuration test and by
capture. T2.6 Two independently built binaries emit byte-identical QUIC Initials
(§16).

**Security considerations / failure modes.** The ALPN string identifies the
network to any observer — a censorship exposure, not an anonymity one (§6.8). Raw
public keys are `[NEEDS RESEARCH]`; the fallback is a self-signed Ed25519
certificate with constant subject and validity, carrying no distinguishing
content. Per-stream relay state is a new DoS surface created by R12 and must be
capped in the commit that introduces it. Failure modes: the 1200 B QUIC datagram
floor means a cell maps to one stream frame and may span datagrams; connection
migration leaking a stable connection ID across an address change; a stalled peer
converting flow control into memory exhaustion.

**Exit criteria.** E2.1 Two nodes exchange 10⁶ cells over QUIC and over TCP with
zero framing errors and identical byte sequences — falsified by any divergence.
E2.2 Circuit B's median throughput while A is stalled is within 10 % of its
unstalled median — falsified by a larger drop. E2.3 A relay under 1000 concurrent
circuit-streams from one peer stays under its declared memory cap and refuses the
1001st — falsified by unbounded growth. E2.4 `grep -r internal/i2p axon/` returns
nothing.

**Must NOT be built yet.** Onion layering (P5 owns the key schedule; a link that
knows what a hop is has the wrong abstraction). Padding *schedules* (§16/P13 — P2
builds the mechanism only). Circuit-level congestion control.

#### P3 — Peer discovery, reachability and NAT `[BUILD NOW]`

**Objective.** A peerbook that knows which peers are reachable, from which address
family, in which /24, /48 and ASN — the inputs diversity has never had here,
because under I2P no node ever saw an IP (§1.4).

| Field | Content |
|---|---|
| **Architecture** | Observations enter the peerbook only with a diversity-quorum of independent probers behind them; reachability gates the relay role (R3). |
| **Components** | `axon/peer`: peerbook, reachability state machine, address discovery with quorum, NAT mapping (UPnP/NAT-PMP/PCP, off by default), prefix/ASN annotation, bootstrap. |
| **Protocols** | Peer-mutual address discovery with an *n*-of-*m* network-diversity quorum, derived from the existing gateway probe protocol. |
| **Data structures** | `PeerEntry{NodeID, Addrs[], ReachState, PrefixV4/24, PrefixV6/48, ASN, LastProbe, ProbeQuorum}`. |
| **APIs** | `(*Peerbook).Observe(NodeID, NetAddr, Evidence)`; `(*Peerbook).Sample(k int, c DiversityConstraint) []PeerEntry`; `Reachability(ctx) (ReachState, error)`. |
| **Depends on** | Phases: P0, P2. Code: `internal/gateway/protocol.go` (`EvaluateQuorum`, `VerifyProbeResult`, `NewVerificationRequest`, `PublicAddress` reused verbatim for anti-SSRF); `internal/bootstrap/`. |
| **Shortened by** | The probe challenge/response, its signature envelope, its short validity window and its diversity quorum are written and tested; P3 re-points them at relay descriptors instead of hostnames. `go-libp2p-asn-util v0.4.1` is vendored. |

**Tests.** T3.1 ASN/prefix annotation agrees with a fixture table for 100 known
addresses. T3.2 A peer claiming reachability that refuses the probe is marked
unreachable within one probe interval. T3.3 `Sample` with a /24-distinct
constraint never returns two peers sharing a /24 when alternatives exist. T3.4 A
3-node prober coalition cannot produce a false *positive* reachability mark, since
the quorum requires network diversity. T3.5 An adversarial bootstrap set is
*detected*: the node emits a partition warning rather than proceeding silently.

**Security considerations / failure modes.** Probers see the probed node's IP and
uptime pattern; a large prober coalition builds exactly the relay-availability map
an eclipse wants (§1.8). Bootstrap is the worst case — a node whose first view is
adversarial is adversarially bootstrapped, and nothing later fixes it (§7,
`[UNSOLVED]`). Failure modes: dynamic-IP churn invalidating the ASN annotation
mid-epoch; CGNAT peers sharing a /24 with thousands of unrelated nodes, so
/24-distinctness over-counts diversity; UPnP opening a port the operator did not
intend.

**Exit criteria.** E3.1 Over 10⁴ draws of `Sample(20, distinct/24 ∧ distinct-ASN)`
on synthetic address blocks, zero violating pairs where alternatives existed —
falsified by one (S12). E3.2 A node with inbound UDP blocked classifies itself
unreachable and refuses the relay role within 120 s — falsified by it advertising
`relay`. E3.3 No peerbook entry has `ProbeQuorum < 2` — falsified by one.

**Must NOT be built yet.** Bandwidth measurement (there is no measurement
authority by R14 and there will not be one; §25(c)). Path selection (P12). Any
reputation score — P3 records observations, it does not weight them.

#### P4 — DHT `[BUILD NOW]`

**Objective.** Re-scope the existing Kademlia for hostile, anonymous use: a KadID
that cannot be freely chosen and rotates each epoch, d=3 disjoint lookup paths,
six typed record classes with validators, and two separate keyspaces (R4).

```text
light client ─▶ verified RANDAO mix ─▶ SRV_epoch ─▶ KadID = H(NodeID ‖ SRV ‖ prefix)
 keyspace A: descriptors, blinded keys, k=20 α=3 d=3 │ keyspace B: storage, r=8 across
                                                     │ distinct /24, /48 and ASN
```

| Field | Content |
|---|---|
| **Architecture** | Above. One implementation, two keyspaces, separate record types and validators; client lookups traverse circuits once P5 exists. |
| **Components** | `axon/dht`: KadID derivation and rotation, SRV consumer, disjoint-path lookup, six record validators, republication scheduler. |
| **Protocols** | S/Kademlia-style disjoint lookup; signed routing entries; per-prefix and per-ASN caps per bucket. |
| **Data structures** | The six §7 record classes: `RelayDescriptor` (0x01), `ServiceDescriptor` (blinded), `DomainRecord`, `StorageLocation` (multi-writer set), `RegistrySnapshot` anchor, `IntroPointRecord`. |
| **APIs** | `(*DHT).Put(ctx, class RecordClass, key RecordKey, val []byte) error`; `(*DHT).Get(ctx, class, key) ([][]byte, error)`; `(*DHT).SetSRV(epoch uint64, srv [32]byte)`. |
| **Depends on** | Phases: P0, P1 (KadID, blinding), P3 (prefix/ASN). Code: `go-libp2p-kad-dht v0.42.1` as wired in `finishNode`; `internal/dcs/dht.go` `WorkerDHTValidator` as the validator shape; `internal/ethproof` for the verified RANDAO mix. |
| **Shortened by** | A working Kademlia with a working validator interface is already in production, and the light client supplying SRV is already mainnet-verified — both halves of the hardest input exist. |

**Tests.** T4.1 KadID is not freely chosen: the grinding cost to place within 8,
16 and 24 bits of a target key is measured and reported. T4.2 KadID changes at
the epoch boundary for every node and routing tables converge within a bounded
number of refreshes. T4.3 An eclipse attempt with 100 sibling identities in one
/24 occupies at most one slot per bucket. T4.4 Each record class rejects wrong
signer, expired, replayed lower `seq`, oversized, and wrong key derivation. T4.5
`StorageLocation` entries merge rather than overwrite. T4.6 An audit of what a
storing node holds for a `ServiceDescriptor` cannot recover the domain or the
service (S5). T4.7 `GO-2024-3218` (provider-record hiding, no upstream fix) is met
by a stated design constraint with a test, not by advisory suppression.

**Security considerations / failure modes.** The epoch boundary is the dangerous
moment: every node's position moves at once, so a lookup crossing it can fail
consistently rather than randomly. RANDAO's last-revealer bias is tolerable for
keyspace rotation and not for anything needing unbiasable randomness (R13) — that
statement belongs where the SRV is consumed, not only in this document. Failure
modes: beacon unavailability stalling rotation, where the fallback must be to
continue on the last verified SRV with a declared staleness rather than invent
one; republication storms at the boundary; routing tables that never converge
under churn.

**Exit criteria.** E4.1 On 30 `axon-lab` nodes, a record put in epoch *n* is
retrievable in epoch *n+1* with ≥ 99 % success over 10³ trials — falsified by a
lower rate. E4.2 The measured grind to sit adjacent to a chosen key within one
epoch is reported and non-trivial — falsified by cheap placement (S8). E4.3 With
20 % adversarial colluding nodes, d=3 lookups return the honest value in ≥ 95 %
of trials — falsified by a lower rate. E4.4 T4.6's audit finds nothing (S5).

**Must NOT be built yet.** Client lookups over circuits (R4(b) requires them, but
circuits are P5; until then lookups are direct and the code must *log* that as a
known unsafe mode rather than pretend otherwise). Storage contracts. Reputation
weighting of routing entries.

#### P5 — Basic anonymous circuits `[BUILD NOW]`; flow control `[NEEDS RESEARCH]`

**Objective.** Telescoping 3-hop onion circuits with per-hop X25519 + HKDF-SHA256
key derivation and ChaCha20-Poly1305 layers over P2's link, such that no relay
learns more than its two neighbours.

```text
 client ──CREATE──▶ G ──EXTEND──▶ M ──EXTEND──▶ T
    │  X25519 with G  │ relayed     │ relayed
    │  X25519 with M ─┘             │
    │  X25519 with T ───────────────┘
    ▼   three layers, peeled one per hop; each hop sees only prev/next;
        circuit IDs re-mapped at every relay so they do not join across links
```

| Field | Content |
|---|---|
| **Architecture** | Above. The path is an explicit argument in this phase — selection is P12's and must not leak into P5. |
| **Components** | `axon/circuit`: CREATE/CREATED, EXTEND/EXTENDED, RELAY handling, per-hop key schedule, circuit table, teardown, `INTERACTIVE`/`BULK` class tagging (R2). |
| **Protocols** | Telescoping construction; one circuit ID per link hop, re-mapped at each relay. |
| **Data structures** | `CircuitState{ID, Prev, Next, Keys[3], Class, Created, Bytes}`; RELAY cell with running digest and stream id. |
| **APIs** | `Build(ctx, path []RelayDescriptor, class TrafficClass) (*Circuit, error)`; `(*Circuit).OpenStream(StreamTarget) (Stream, error)`; `(*Circuit).Extend(ctx, RelayDescriptor) error`. |
| **Depends on** | Phases: P2 (link, cells), P4 (`RelayDescriptor`). Code: none that carries traffic. `internal/channel/onion.go` (`MaxHops = 3`, `SlotSize = 1024`, explicitly not Sphinx) is prior art and a test-vector source only, per §1.3 row 19. |
| **Shortened by** | Nothing. This is the phase with no existing code behind it, and the estimate reflects that. |

**Tests.** T5.1 Layer independence: bytes entering hop 1 and bytes leaving hop 3
share no common substring outside the fixed header, by loopback capture. T5.2 A
relay's process memory mid-circuit contains its two neighbours' identities and no
third. T5.3 The circuit ID on link G→M differs from the ID on client→G, and a
correlator holding both cannot join them without the relay's table. T5.4 Golden
key-schedule vectors, so a KDF label change fails the build. T5.5 Teardown
propagates both ways and frees state at every hop within one second. T5.6 A
replayed RELAY cell is caught by the digest chain. T5.7 An EXTEND targeting the
circuit's own previous hop is refused.

**Security considerations / failure modes.** The terminal hop never reaches
clearnet — no exit role exists in v1 (§18.3). `INTERACTIVE` is explicitly
vulnerable to end-to-end correlation and the API must force the caller to declare
the class (R2); a default class is a design error, not a convenience. The per-hop
AEAD tag is reserved for every hop position, so capacity does not leak path length.
Failure modes: a half-dead circuit (hop 2 gone, 1 and 3 alive) leaking the failure
position by timing; flow control collapsing under loss; circuit-table exhaustion at
a popular relay.

**Exit criteria.** E5.1 M1 of §24 passes with T5.1 satisfied — falsified by any
shared payload bytes. E5.2 A 3-hop circuit sustains a stated throughput floor for
10 minutes with zero cell loss, and no hop retains circuit state 5 s after
teardown — falsified by a residual entry. E5.3 After 1000 build/teardown cycles,
relay memory returns within 5 % of baseline — falsified by monotone growth. E5.4 A
capture at hop 2 cannot distinguish `INTERACTIVE` from `BULK` by cell size —
falsified by any size difference; only timing may differ.

**Must NOT be built yet.** Tunnel pools and guards (P7), rendezvous (P6), path
*selection* (P12 — P5 takes an explicit path and must keep taking one), padding
schedules (§16/P13).

#### P6 — Rendezvous `[BUILD NOW]`; intro puzzle `[NEEDS RESEARCH]`

**Objective.** Two-stage service contact (R10): a client learns intro points from a
blinded descriptor, sends a rendezvous request through one, and both sides meet at
a rendezvous point neither hosts.

| Field | Content |
|---|---|
| **Architecture** | Service publishes IP1–IP3 in its descriptor; client picks an RP, builds to it, passes a cookie via an IP; service builds to the RP and presents the cookie; the RP joins two circuits and sees neither endpoint's address. |
| **Components** | `axon/rendez`: RP protocol, cookie handling, INTRODUCE/RENDEZVOUS cell commands, intro-point registration, the intro admission puzzle. |
| **Protocols** | INTRODUCE1/2, RENDEZVOUS1/2, shaped after the v3 onion-service design, with a proof-of-work or token puzzle gating INTRODUCE1 (R10). |
| **Data structures** | `RendezvousCookie[20]`; `IntroRequest{blinded_key, cookie, rp_descriptor, puzzle_solution}`. |
| **APIs** | `(*Client).Rendezvous(ctx, *ServiceDescriptor) (Stream, error)`; `(*Service).Listen(ctx, ips []RelayDescriptor) (net.Listener, error)`. |
| **Depends on** | Phases: P5 (circuits), P4 (descriptor retrieval). Code: `internal/p2p/challenge.go`'s request/response frame shape as a pattern for the puzzle exchange. |
| **Shortened by** | Very little. The framing pattern is reusable; the protocol is not in the tree. |

**Tests.** T6.1 An audit of every struct reachable at either endpoint after a
successful rendezvous finds no IP and no `/ip4`,`/ip6` component (S2). T6.2 The
RP's state contains two circuit IDs and a cookie, nothing more. T6.3 An INTRODUCE1
without a valid puzzle solution is dropped before any circuit work. T6.4 A
replayed cookie is refused. T6.5 An intro point can refuse to forward and can do
nothing else — it cannot impersonate the service. T6.6 Under 10³ INTRODUCE1/s from
one source, intro-point CPU stays bounded and honest clients still succeed.

**Security considerations / failure modes.** The RP is by construction a
correlation point between the two legs: it sees both halves' volume and timing at
zero cost (§18.8, T-L4-03). It cannot locate either endpoint, but it can confirm
that this client leg and that service leg are one conversation. That is the price
paid for not publishing service tunnel endpoints directly, and it is not removed.
Failure modes: intro-point DoS, the failure that shaped Tor's operational history
and the reason for the puzzle; a puzzle difficulty high enough to exclude
low-power clients, which is a censorship outcome rather than a security one;
cookie collision.

**Exit criteria.** E6.1 M2 of §24 passes — falsified by either endpoint's process
holding the other's address at any point. E6.2 With one adversarial intro point of
three, service reachability stays above 95 % — falsified by a lower rate. E6.3 An
INTRODUCE1 flood at 10³/s does not reduce honest rendezvous success below 90 %.
E6.4 The RP's serialised state at the join contains no address and no service
identity.

**Must NOT be built yet.** Pools of RPs; descriptor *publication* strategy (P7);
client authorisation to services; any bandwidth accounting at the RP.

#### P7 — Anonymous services and tunnel pools `[BUILD NOW]`; session layer `[NEEDS RESEARCH]`

**Objective.** Guard-constrained tunnel pools (R1) with I2P's failover and Tor's
guard property, plus a session layer under which streams survive circuit death
(R9).

```text
 isolation context
   ├─ guards: 2 primary, 45-day rotation, 90-day list        (Tor property)
   │     ├─ inbound  tunnels ×3 + 1 spare ─┐
   │     └─ outbound tunnels ×3 + 1 spare ─┤ 10-min life, rebuild at 70 %  (I2P)
   ▼                                       ▼
 session (survives any single tunnel's death) ── streams bind here, not to circuits
```

| Field | Content |
|---|---|
| **Architecture** | Above. Every tunnel in a pool begins at one of that context's two pinned guards; hops 2..n churn freely (R1). |
| **Components** | `axon/tunnel`: pool manager, guard store and rotation, tunnel lifecycle, spare promotion. `axon/session`: session ids, stream rebinding, replay-safe resumption. Service-side descriptor publication. |
| **Protocols** | Pool rebuild schedule; session resumption handshake; descriptor publication at 8 replica positions (§7). |
| **Data structures** | `Pool{Context, Guards[2], In[4], Out[4]}`; `Session{ID, Keys, StreamTable, LastSeq}`. |
| **APIs** | `(*Pool).Get(role TunnelRole) (*Circuit, error)`; `(*Session).Rebind(*Circuit) error`; `Publish(ctx, *ServiceDescriptor, period uint64) error`. |
| **Depends on** | Phases: P6, P5, P4, P3. Code: `internal/placement/plan.go`'s distinctness predicate, reusable for hop distinctness within a tunnel. |
| **Shortened by** | Only that predicate. Guards, pools and sessions have no analogue: libp2p streams die with their connection, which is exactly what R9 forbids. |

**Tests.** T7.1 Every tunnel in a pool begins at a pinned guard — falsified by one
exception (R1). T7.2 Killing the tunnel carrying a live stream continues the
stream on a replacement within a stated bound, with no byte loss and no
duplication. T7.3 Guard rotation at 45 days is deterministic from stored state and
survives restart. T7.4 Two isolation contexts share no guard and no tunnel. T7.5
Publication reaches all 8 replica positions and a client fetching any 1 of 8
succeeds. T7.6 Pool exhaustion degrades to a stated failure, not a hang.

**Security considerations / failure modes.** Guard rotation without a plausible
gap in publication makes RoutingIdentity rotation cosmetic — a continuously-up
relay that rotates every epoch is trivially re-linked by uptime (§16,
`[UNSOLVED]`). The isolation-context count trades usability against guard exposure
and is `[NEEDS RESEARCH]` (§18.8). Failure modes: both guards down at once, where
the pool must *not* silently pick new guards, because that is the exact behaviour
guards exist to prevent; session resumption used as a linkability oracle across
circuits; republication timing revealing service uptime.

**Exit criteria.** E7.1 A 10-minute transfer through a pool survives three forced
tunnel deaths with zero application-visible error and zero duplicated bytes —
falsified by either. E7.2 Over 10³ builds, 100 % begin at a pinned guard —
falsified by one exception. E7.3 A service stays reachable across a full
descriptor-period rollover including the 12 h overlap — falsified by any
unreachable window. E7.4 With both guards killed, the node reports a hard guard
failure and builds no tunnel through an unpinned first hop — falsified by a tunnel
appearing.

**Must NOT be built yet.** Path-selection weights (P12 — P7 selects uniformly at
random from the diversity-filtered set and says so). Bandwidth-weighted guard
choice. Padding (P13). Any accounting hook in the pool manager.

#### P8 — Domain identities and the `.axon` namespace `[BUILD NOW]`

**Objective.** The name grammar, normalisation, canonical encoding and the
DomainIdentity binding — with the TLD reachable only through one constant, so
nothing depends on the literal string.

| Field | Content |
|---|---|
| **Architecture** | An encoding and a policy, not a protocol. `name_hash = SHA-256(normalised)` is the only form any lower layer ever sees. |
| **Components** | `axon/name`: grammar, normalisation, confusable policy, canonical encoding, DomainIdentity binding records, delegation to ServiceIdentity. |
| **Protocols** | None on the wire. |
| **Data structures** | `DomainRecord` per §7: `{ver, name_hash[32], domain_identity_pub[32], records[], snapshot_root[32], inclusion_proof, seq, exp, sig}`. |
| **APIs** | `const ROOT_SUFFIX = "axon"` (namespace labels come from `TLDRegistry` at runtime, never a constant); `Normalise(string) (Name, error)`; `(Name).Hash() [32]byte`; `(Name).String() string`. |
| **Depends on** | Phases: P1 (DomainIdentity, delegation certificates). Code: `internal/gateway/registry.go`'s hostname reservation/validation as the closest analogue. |
| **Shortened by** | Little carries over; the saving is that record signing and delegation arrive complete from P1. |

**Tests.** T8.1 `Normalise` is idempotent and total: fuzzing over arbitrary UTF-8
either errors or reaches a fixed point. T8.2 Names that normalise equal produce one
`name_hash`, and the test pins which inputs collide — the collision is the point.
T8.3 A grep for the literal `"axon"` outside `name/const.go` fails the build
(Constitution §1). T8.4 A stated homoglyph list is rejected or folded, per pair,
rather than delegated to a library default. T8.5 Golden encodings for 100 names
including the hard ones (hyphens, digits, maximum length, empty labels).

**Security considerations / failure modes.** Homoglyph attacks have no clean
answer; a restrictive policy (LDH-only, or a small explicit script set) is the only
defensible v1 position and it excludes legitimate non-Latin names. State which was
chosen and what it costs rather than adopting IDNA and calling it solved. Failure
modes: a normalisation change after names are registered, silently re-pointing or
orphaning them; a non-canonical `name_hash`, so one name yields two DHT keys.

**Exit criteria.** E8.1 A corpus of 10⁴ names round-trips
normalise→hash→encode→decode with zero divergences — falsified by one. E8.2 The
TLD constant can be changed to `"test"` and the whole suite passes unmodified —
falsified by any test referencing the literal. E8.3 Two independent
implementations written from the specification agree on the corpus — falsified by
any disagreement; this is the test that catches an under-specified grammar.

**Must NOT be built yet.** Registration (P9), resolution (P10), and any DNS
interoperation including a `.axon` DoH bridge, which would recreate the dependency
this layer exists to remove.

#### P9 — Ethereum registry `[BUILD NOW]`

**Objective.** `AxonRegistry` and `AxonResolverRegistry`: commit–reveal
registration, name→DomainIdentity binding, rotation, revocation, transfer, and the
on-chain anchor for the registry snapshot (R7).

| Field | Content |
|---|---|
| **Architecture** | `commit(H(name‖salt‖owner))`, wait ≥ N blocks, `reveal(name, salt, domain_identity_pub)`. A snapshot builder Merkleises the name→DomainIdentity map and anchors the root on chain; resolution reads the snapshot, not the chain (R7). |
| **Components** | `AxonRegistry.sol`; `AxonResolverRegistry.sol`; snapshot builder; owner multisig + timelock (§18.22). |
| **Protocols** | Commit–reveal with a minimum block delay; snapshot anchoring at a stated cadence. |
| **Data structures** | `mapping(bytes32 nameHash => Binding{bytes32 domainIdentity; address owner; uint64 expires; uint64 revokedAtBlock; bytes32 prevIdentity;})`; `mapping(uint64 => bytes32 snapshotRoot)`. |
| **APIs** | `commit(bytes32)`, `reveal(string,bytes32,bytes32)`, `rotate(bytes32,bytes32)`, `revoke(bytes32)`, `transfer(bytes32,address)`, `anchorSnapshot(uint64,bytes32,bytes32 bodyCID)`. |
| **Depends on** | Phases: P8. Code: `proof-of-facilitation/` Hardhat + OZ 5.1 harness, 11 test files, `deploy/*.ts`; `internal/facilitation/register.go`'s digest, byte-identical to `abi.encode`, and its ecrecover-compatible signing. |
| **Shortened by** | The contract build/test/deploy toolchain exists and is exercised by eleven test files. `hardhat.config.ts` pins `zksolc 1.5.7`, which the PoF go-live checklist already flags as unavailable — inherit that known issue rather than rediscovering it. |

**Tests.** T9.1 An observer with full mempool visibility cannot recover the name
from the commit — falsified by any recovery (S7). T9.2 A reveal before the minimum
delay reverts. T9.3 Front-running a reveal fails: the attacker's commit does not
match. T9.4 Rotation preserves the binding and records `prevIdentity` for the 48 h
overlap §13.5 depends on. T9.5 `revokedAtBlock` is monotone and cannot be unset.
T9.6 Gas per operation is measured into a golden file, so a refactor tripling
registration cost fails. T9.7 The anchored root equals a root computed
independently over the same block.

**Security considerations / failure modes.** R6 stands: registering from a funded
wallet links the name to a payer through the funding graph — a **residual risk
documented, not solved**. The recommendation is an unlinked account, and the
document must not claim anonymous ownership. The contract owner key is a single
point of failure until multisig and timelock exist. Failure modes: a reorg between
commit and reveal; gas prices making registration unaffordable, which is a
censorship outcome; an upgrade path that lets the owner rewrite bindings.

**Exit criteria.** E9.1 On the local chain, the full lifecycle (commit, reveal,
rotate, revoke, transfer) executes with the assertions above — falsified by any
unexpected revert. E9.2 A scripted front-runner watching every pending transaction
fails in 10³ attempts — falsified by one success. E9.3 A snapshot anchored at block
*b* verifies against an independently rebuilt tree — falsified by a root mismatch.
E9.4 No function changes a binding without the owner's signature, by a negative
test per function.

**Must NOT be built yet.** Deployment to mainnet or a public testnet. Any economic
parameter (registration price, renewal period) — those are P15's argument, and
setting them here bakes in an economics nobody has designed. Auctions. Secondary
transfer markets.

**Amended by §12.4a (2026-08-16).** Three requirements were added after this
phase was written and it cannot be considered done without them:

1. **Acquisition is paid, in the network token, by exactly two routes** —
   primary from the DAO, secondary from the current owner. This supersedes
   §12.4's ETH denomination ruling; that ruling's circularity objection is
   retained in §12.4a as an accepted cost.
2. **A bulk-squatting guard is required**, not `[UNSOLVED]`. §12.4a lists the
   design space (escalating per-acquirer cost, bonded registration, per-epoch
   rate limits, reveal-rate limiting) and the mechanisms that stay rejected. The
   claim to be made is "expensive and slow", never "impossible".
3. **The contracts must actually be deployed.** The token is written and
   undeployed (`AxonToken.sol`, ERC20, ticker ANON); the
   registry and registrar are unwritten; the Proof-of-Facilitation set is
   written, unit-tested and undeployed EXCEPT `ChannelManagerV2`, which is live
   on Ethereum Mainnet and carries tipping today. **T9.x and E9.x cannot be
   discharged against a local test chain alone** — a phase that claims an
   on-chain check works while nothing is on chain has claimed nothing.

#### P9b — Root registry and namespace governance `[NEEDS RESEARCH]`

**Objective.** Turn the single hardcoded namespace of P9 into a governed set:
`TLDRegistry` as the root zone, `IRegistrar` as the per-namespace interface, and a
governor that can create, freeze and retire namespaces under quorum and timelock —
without ever acquiring a path to a name (§12.0a).

| Field | Content |
|---|---|
| **Architecture** | Root registry holds `label → Namespace{registrar, registrarClass, status, steward, charter, bond, recordSchema}`. `AxonRegistry` from P9 becomes the reference `IRegistrar`, deployed once per namespace with a per-namespace `TLD_NODE`. Resolution becomes two verified reads (§12.5). Governance is a separate contract holding the only mutating keys on the root. |
| **Components** | `TLDRegistry.sol`; `IRegistrar.sol`; `AxonGovernor.sol`; guardian multisig with expiry; eligibility predicate seeded with an IANA root snapshot; namespace charter publication into L6 storage. |
| **Protocols** | propose → eligibility check → discussion → vote → quorum + supermajority → timelock → activate. Retirement on ≥ 90 days' notice with grandfathering. |
| **Data structures** | `mapping(bytes32 labelHash => Namespace)` at slot 0 (§12.5 layout); `mapping(bytes32 => bool) ineligible`; proposal and vote records; `NameAcceptance` record type in the DHT (§11.6.3). |
| **APIs** | `namespaceOf(bytes32)`, `isEligible(string)`, `propose(...)`, `castVote(...)`, `execute(...)`, `freeze(bytes32)`, `beginRetire(bytes32)`; resolver-side `R3` namespace resolution. |
| **Depends on** | Phases: P8, P9, P10 (the resolver must read two levels). Code: `StakeVault.sol` and `EpochManager.sol` for voting weight; OZ Governor/TimelockController as the base rather than a bespoke vote. |
| **Shortened by** | `StakeVault` and `EpochManager` already produce bonded stake and a verified per-epoch contribution record — the two inputs to the weighting function — so no new token and no new measurement system is required. |

**Tests.** T9b.1 No sequence of governor calls changes an owner, a `domainKey`, or
an expiry on any registrar — a property test over the whole ABI, falsified by one
counterexample; this is the §12.0a invariant and it is the most important test in
the phase. T9b.2 A proposal for an ineligible label (IANA snapshot, special-use,
length ≤ 2, reserved) reverts at proposal time. T9b.3 Execution before the timelock
expires reverts. T9b.4 `FREEZE` blocks new registrations and leaves existing name
resolution byte-identical. T9b.5 A retired namespace stops resolving at
`retiresAt` and not before, and the services behind it remain reachable at Layer 1.
T9b.6 The guardian can veto and cannot enact — negative test per mutating function.
T9b.7 A resolver pinned to root A and a resolver pinned to root B disagree without
either crashing, and both report the disagreement. T9b.8 Mutual binding: a name
pointing at a service whose `NameAcceptance` omits it yields MISMATCH, not a
rendered page. T9b.9 Governance simulation: a capture attempt at *q* % of weight
against turnout *t* is measured rather than assumed, over a parameter sweep.

**Security considerations / failure modes.** The dominant risk is **governance
capture at low turnout** (§18.17a G1), and it is not solved — the timelock makes
capture visible and the fork right makes it survivable, both reactive. The
guardian is a standing centralisation point (G9). Namespace squatting (G5) and
cross-namespace impersonation (G7) are unmitigated. `registrarClass` must be
correct and visible or holders cannot price the risk they are taking (G3). The
eligibility predicate goes stale as the IANA root grows (G4). Failure modes: a
quorum that cannot be met, freezing governance entirely; a namespace activated
with a buggy registrar and no upgrade path; a charter that says one thing and a
registrar that does another.

**Exit criteria.** E9b.1 The §12.0a invariant holds under an exhaustive ABI
property test — falsified by any state change to a name reachable from a governor
call. E9b.2 A namespace goes proposed → voted → timelocked → active on the local
chain, and a name registers beneath it. E9b.3 Two-level verified resolution
completes against the local chain within the budget in §12.5 — falsified by a
missing proof or an unverified registrar address. E9b.4 A retirement runs its full
notice period with grandfathering, and the service behind a retired name is still
reachable by its Layer 1 address. E9b.5 A published governance simulation report
states the turnout at which capture becomes affordable; **the phase does not exit
on a number, it exits on the number being known and written down.**

**Must NOT be built yet.** Live governance with real weight — v1 ships the root
registry with the governor stubbed to a multisig and a published migration path,
because §12.0a's weighting function is explicitly unsettled. Cross-namespace
transfers, namespace mergers, secondary markets in namespaces, and any automatic
sunrise or trademark mechanism at the root (§11.0.3 rule 1 forbids it).

#### P10 — Decentralised resolver `[BUILD NOW]`

**Objective.** `alice.lab.axon` → DomainIdentity → records, from a locally verified
registry snapshot with a declared freshness bound, working when no chain RPC is
reachable (R7).

| Field | Content |
|---|---|
| **Architecture** | cache → DHT `DomainRecord` → local verified snapshot → (slow path only) light client → Ethereum. The chain is never on the request path. |
| **Components** | `axon/resolver`: pipeline, three operating modes (§13.3), cache with authenticated negative caching, freshness accounting, revocation handling, snapshot verification. |
| **Protocols** | Snapshot fetch and verify; DHT record fetch over a circuit (R4(b)). |
| **Data structures** | `Answer{Name, DomainIdentity, Records[], Mode, AsOf, FreshnessBound, Flags}`. |
| **APIs** | `Resolve(ctx, Name) (*Answer, error)`; `(*Answer).StalenessSeconds() int64`. |
| **Depends on** | Phases: P9, P4, P8. Code: `internal/ethproof/` entire — `lightclient.go`, `execution.go`, `checkpoint.go`, `finality.go` — mainnet-verified with a 512/512 sync-committee signature (`doc/trust-anchor.md`). `HeaderVerifier.SetAnchor`'s refusal of an anchor sharing a registrable domain with the RPC is reused verbatim. |
| **Shortened by** | **The largest single saving in the programme.** The trust anchor is the expensive part of any chain-verifying resolver, and it is finished, measured and documented. |

**Tests.** T10.1 With every RPC blackholed, resolution succeeds from the snapshot
and reports a non-zero staleness — falsified by failure, or by success without a
staleness figure (S6). T10.2 A valid-looking but unauthenticated header is refused
with `ErrNotAuthenticated`. T10.3 A revoked DomainIdentity is refused within the
stated bound and every cached artefact is purged. T10.4 A name registered one
block ago returns an authenticated NXNAME with `PENDING_POSSIBLE`. T10.5 Negative
answers are authenticated proofs of absence, not merely missing. T10.6 Every path
is exercised with the chain unreachable, the DHT unreachable, and both.

**Security considerations / failure modes.** The initial checkpoint is a
subjective input and a fake one is undetectable — everything verifies inside a
coherent fake chain (`doc/trust-anchor.md` §3, §13.9). That belongs in the release
documentation, not only here. There is no DNS fallback, by design: a fallback is a
downgrade attack with a friendly name. Failure modes: a stale snapshot serving a
revoked or transferred name up to the freshness bound — the direct cost of R7,
where shortening the bound reintroduces the chain dependency it removed; and
beacon endpoints that respond but do not serve light-client routes
(`doc/trust-anchor.md` §5b measured 1 of 8 candidates serving `finality_update`).

**Exit criteria.** E10.1 `alice.lab.axon` resolves with the chain container stopped and
an age is reported — falsified by failure or a missing age (S6). E10.2 With a
hostile RPC serving a fabricated chain, resolution refuses rather than answering —
falsified by any answer. E10.3 No `/ip4` or `/ip6` component appears anywhere in
the resolution path above L4, by struct audit (S2). E10.4 M3 of §24 passes.

**Must NOT be built yet.** The local-root TLS shim of §13.8 — it is a real
reduction in the user's security posture and must not ship before its name
constraints are tested for enforcement per platform. Browser extensions. Any DNS
bridge.

#### P11 — Distributed storage integration `[BUILD NOW]`

**Objective.** Run the existing erasure-coded store over AXON transport and
circuits with BLAKE3 content addressing, and re-derive every timeout that was
calibrated to an I2P dial.

| Field | Content |
|---|---|
| **Architecture** | The store is unchanged; the transport beneath it is replaced, `StorageLocation` records replace provider records, and retrieval runs over `BULK`-class circuits. |
| **Components** | Transport swap in `finishNode`; BLAKE3/Bao CID at the object layer; `StorageLocation` records; explicit encryption-mode contract; re-derived latency budgets. |
| **Protocols** | `/syndichan/storage/1.0.0` versioned to `/axon/storage/1.0.0`; retrieval over `BULK` circuits. |
| **Data structures** | Existing manifest v1 (`internal/store/types.go:5`); `ObjectManifest`; `StorageLocation` multi-writer set. |
| **APIs** | Store API unchanged; `Retrieve(ctx, cid CID, class TrafficClass) (io.ReadCloser, error)`. |
| **Depends on** | Phases: P4, P5. Code: `internal/store/` (5,893 L), `internal/p2p/disperse.go`, `recall.go`, `repair.go`, `rebalance.go`, `drain.go`, `internal/placement/`; RS **6+3** and **1 MiB** chunks read from `internal/config/config.go:572-574`. |
| **Shortened by** | **The whole storage layer is written, tested and transport-agnostic** — 0 of 210 test files import `internal/i2p` (§1.4), and five already run the full dispersal/recall/repair stack over loopback TCP. The adversarial tests come along unchanged. |

**Tests.** T11.1 The existing storage suite passes unmodified over AXON, changing
only the constructor — falsified by any test needing a deeper change (S3). T11.2
`shardFetchTimeout` is re-derived from measured AXON circuit latency and the
derivation replaces the current `i2pDialTimeout` comment — falsified by the old
comment surviving. T11.3 A holder that lies about deletion is still caught, over
the new transport. T11.4 Retrieval works with the publisher offline (M4). T11.5 An
audit establishes who holds plaintext, resolving the `SECURITY.md` /
`internal/store/types.go` contradiction §1 flags — falsified by the ambiguity
persisting. T11.6 A holder cannot read a shard it holds without the CID and key
(R5).

**Security considerations / failure modes.** R5: no node caches plaintext it did
not request; path caching is opt-in per node and only of encrypted shards; local
operator blocklists are supported; a global blocklist is refused as
re-centralisation and the abuse problem is named `[UNSOLVED]` (§25(c)). Failure
modes: timeouts relaxed rather than re-derived, hiding a latency regression; and
RS 6+3 with peer-distinct-only placement treating three correlated losses in one
datacentre as three independent failures (§1.8) — true until P12's diversity
levels land.

**Exit criteria.** E11.1 `go test ./internal/store/... ./internal/p2p/...` passes
over AXON with no test-body changes — falsified by one. E11.2 M4 of §24 passes with
the publisher's process killed. E11.3 No timeout constant in the storage path
references I2P — falsified by a grep hit. E11.4 A stored shard on a holder's disk
does not yield the object without the key — falsified by recovery.

**Must NOT be built yet.** Storage *contracts* with expiry and renewal
(`[NEEDS RESEARCH]`, §10). Proof of retrievability with an extraction argument.
Payment for storage (P15). Segmented manifests for very large objects.

#### P12 — Advanced pools and path diversity `[NEEDS RESEARCH]` core, `[BUILD NOW]` mechanics

**Objective.** Locally computed path selection with bandwidth-and-diversity
weighting and no consensus document (R14), and the failure-domain diversity
`internal/placement` has never had.

| Field | Content |
|---|---|
| **Architecture** | Candidates are filtered by diversity constraints first and weighted second; weights are self-reports capped by bonded stake and lowered by delivery receipts. No measurement authority exists at any point. |
| **Components** | `axon/path`: candidate sampling, diversity constraints (/24, /48, ASN, family), weighting; the same levels added to `internal/placement`. |
| **Protocols** | Delivery receipts as a bounded, non-authoritative capacity signal. |
| **Data structures** | `DiversityConstraint{DistinctPrefixV4, DistinctPrefixV6, DistinctASN, DistinctFamily}`; `Weight{Claimed, BondCap, ReceiptObserved}`. |
| **APIs** | `SelectPath(ctx, n int, c DiversityConstraint, w WeightPolicy) ([]RelayDescriptor, error)`. |
| **Depends on** | Phases: P3, P7, P4. Code: `internal/placement/plan.go` (`DistinctHolders`, `SurvivesHolderLosses`, `RemotelyRecoverable`) as the predicate shape; `level.go` for the levelling discipline. |
| **Shortened by** | The planner's *shape* and its distinctness tests. Its *inputs* are not reusable: §1's objection establishes that no subnet, prefix or ASN notion exists anywhere in `internal/placement`, so Constitution §5's "reuse the existing diversity levels" is not available. Budget this as new work. |

**Tests.** T12.1 No two hops of a circuit share a /24, /48 or ASN when
alternatives exist — falsified by one violation (S12). T12.2 The same holds for
shard placement, which is the half that regresses silently. T12.3 A relay claiming
10 Gb/s on a minimal bond is weighted at the bond's cap, not its claim. T12.4
Receipts can only lower a weight, never raise it above the claim. T12.5 A crude
partition is detected: two clients given disjoint descriptor sets both emit a
diversity warning. T12.6 Selection is not deterministic given one view.

**Security considerations / failure modes.** R14's residual is here in full:
without a consensus, clients can be shown different networks, and nothing in this
phase fixes that. T12.5 catches a crude partition and not a careful one. Weighting
by anything an adversary can inflate cheaply reintroduces the problem bandwidth
authorities exist to solve, which is why the weight is capped by bond. Failure
modes: constraints so tight that no path exists on a small network, so the code
relaxes them silently — the relaxation must be logged and counted; weighting that
concentrates traffic on a few large relays.

**Exit criteria.** E12.1 Over 10⁴ selections on 60 nodes with synthetic address
diversity, zero constraint violations where alternatives existed — falsified by one
(S12). E12.2 The relaxation counter is non-zero only when the harness deliberately
exhausts alternatives — falsified by silent relaxation. E12.3 With 20 %
adversarial relays, the measured fraction of circuits with a compromised
first-and-last pair matches the published model within a stated tolerance —
falsified by a materially higher rate (S9). E12.4 A published simulator reproduces
E12.3 from the published parameters, so a third party can falsify it.

**Must NOT be built yet.** Any central measurement (§25(c)). Reputation carried
across RoutingIdentity rotation (`[NEEDS RESEARCH]`, §5). Weight derived from
payment volume, which would make the accounting plane a routing input and break
Constitution §4's layering rule.

#### P13 — Traffic-analysis defences `[NEEDS RESEARCH]`

**Objective.** Implement the `INTERACTIVE`/`BULK` split (R2) with padding
mechanisms and wire-profile uniformity, plus an honest statement of what is not
defended.

| Field | Content |
|---|---|
| **Architecture** | Padding machines at link and circuit layers; a batched `BULK` path; one canonical wire profile for the whole network, since divergence is itself a fingerprint. |
| **Components** | Padding machines; the `BULK` batching path; wire-profile freezing (QUIC Initial, TLS extension order, ALPN, congestion control, version strings) per §16. |
| **Protocols** | Padding parameters as protocol constants, never operator-tunable (§16). |
| **Data structures** | `PaddingState{Machine, Tokens, NextAt}`; `TrafficClass{INTERACTIVE, BULK}`. |
| **APIs** | `(*Circuit).SetClass(TrafficClass) error` — set once at build, immutable afterwards. |
| **Depends on** | Phases: P7, P12, P2. Code: `internal/traffic/traffic.go` counts bytes; it does not shape them. The saving is a metering interface and nothing more. |
| **Shortened by** | Almost nothing. |

**Tests.** T13.1 Two independently built binaries emit byte-identical QUIC
Initials — falsified by any difference. T13.2 No operator-settable configuration
changes a byte visible before the handshake completes. T13.3 Padding is on by
default and disabling it is a single visible bit, not a tunable. T13.4 A `BULK`
transfer's timing distribution differs from an `INTERACTIVE` session's on the same
path, and the difference is the *designed* one. T13.5 The documentation build fails
if *perfect*, *untraceable*, *unbreakable* or *impossible to block* appear (S13).

**Security considerations / failure modes.** This is the phase most likely to
produce a defence nobody can evaluate: a padding machine that survives a 30-node
lab test says nothing about a fingerprinting adversary with a real traffic corpus.
The correct posture is to build the mechanism, publish the parameters, and state
plainly that effectiveness is unmeasured (§25(c)). Failure modes: padding that
costs bandwidth without measurable benefit, which volunteers disable, which makes
*not* padding the fingerprint; and a padding machine whose own state is a
distinguisher.

**Exit criteria.** E13.1 T13.1 passes across the three release platforms —
falsified by one byte. E13.2 A link capture cannot distinguish an idle circuit
from a lightly-loaded one within a stated bound — falsified by a classifier
exceeding it. E13.3 The shipped documentation contains no unquantified anonymity
claim, by script (S13). E13.4 Every padding parameter appears exactly once, in the
constants file — falsified by a second definition.

**Must NOT be built yet.** A mixnet-style batching layer for `INTERACTIVE` —
Constitution §7 forbids claiming mixnet properties for it, and building one
implies the claim. Fingerprinting defences validated only against a synthetic
corpus.

#### P14 — Sybil resistance hardening `[BUILD NOW]` mechanics, `[UNSOLVED]` calibration

**Objective.** Compose §15's six layers — KadID binding, diversity constraints,
bonded stake, proof of work, contribution weighting, randomised selection — into
an admission and selection policy, and state honestly that its parameters are
uncalibrated.

| Field | Content |
|---|---|
| **Architecture** | Bond verified through the light client's state root, never an RPC's word; caps applied at every selection point simultaneously (path, placement, DHT bucket, replica set). |
| **Components** | Bond verification against `StakeVault`; PoW admission for cheap roles; per-prefix and per-ASN caps; replacement of coordinator-issued storage leases with bond + local policy. |
| **Protocols** | `bond_ref` in `RelayDescriptor`; the challenge frame extended for PoW. |
| **Data structures** | `BondRef{Chain, Contract, NodeID, Amount, VerifiedAt}`. |
| **APIs** | `VerifyBond(ctx, BondRef) (Weight, error)`; `AdmitStore(ctx, StoreRequest) error`. |
| **Depends on** | Phases: contract half P0 only; path half P4, P12; storage-admission half P11. Code: `proof-of-facilitation/contracts/StakeVault.sol`, `NodeRegistry.sol` (written, unit-tested, **not deployed**); `internal/facilitation/` (28 files); `internal/dcs/admission.go`; `internal/p2p/challenge.go`. |
| **Shortened by** | Staking, slashing and registration contracts are written with passing EVM tests, and the Go client that signs their digests is byte-compatible with them. What is missing is deployment and calibration, not code. |

**Tests.** T14.1 A descriptor referencing a non-existent or withdrawn bond is
refused. T14.2 Bond verification uses the light client's verified state root —
falsified by any path that trusts a provider. T14.3 Per-ASN caps hold at every
selection point simultaneously. T14.4 Storage admission works with no coordinator
reachable — falsified by any dependence on `syndichan.org`. T14.5 The PoW cost is
measured on low-end hardware and recorded, so the exclusion it causes is a known
quantity.

**Security considerations / failure modes.** The calibration problem is the
phase's honest centre: nobody can state what bond makes 20 % of relays infeasible,
because it depends on a token price, an adversary's budget and a population that
does not exist (§18.22). Shipping a number implies a claim the number does not
support; the deliverable is a mechanism with parameters marked provisional.
Failure modes: a bond high enough to be meaningful is high enough to exclude
volunteers — the capital gate §25(c) names — and a bond low enough to be inclusive
buys the adversary a relay fleet cheaply.

**Exit criteria.** E14.1 A node without a bond cannot enter any consequential role
— falsified by entry. E14.2 The coordinator container can be stopped and storage
admission continues — falsified by refusal; this retires the last centralised
control point in the storage path. E14.3 Every provisional parameter is documented
with its derivation and marked provisional — falsified by one with no stated
derivation. E14.4 An adversary with 100 identities in one /24 occupies at most one
slot per bucket and one hop per path.

**Must NOT be built yet.** Any slashing automation firing on evidence gathered over
circuits — attribution over an anonymity network is a research problem, and
automated slashing on weak attribution is a denial-of-service weapon. Reputation
portability across identity rotation.

#### P15 — Incentive and economic layer `[NEEDS RESEARCH]`

**Objective.** Blind-signed, unlinkable relay tokens redeemed in aggregate off the
critical path and settled through the existing PoF epoch machinery (R11) — added
to a network that already works without it.

| Field | Content |
|---|---|
| **Architecture** | Issuance and redemption are batched and off-path; the data path has no payment call at all, which is what makes the subsystem removable. |
| **Components** | `axon/token`: blind issuance, spend, aggregate redemption; relay accounting hooks off the data path; PoF epoch settlement; storage payment as a separate instrument (§14.6). |
| **Protocols** | Chaumian / Privacy-Pass-style issuance and redemption; batched settlement at epoch boundaries. |
| **Data structures** | `BlindToken{Issuer, BlindedSig, Nonce}`; existing PoF `Receipt` and epoch roots. |
| **APIs** | `Issue(ctx, n int) ([]BlindToken, error)`; `Redeem(ctx, []BlindToken) (Credit, error)`. |
| **Depends on** | Phases: P14, and nothing on the data path. Code: `internal/channel/` SCPP/1 (43,914 L, 135 files) with HTLCs, multipath and watchtowers; `blinded.go`, `pedersen.go`; PoF `EpochManager`, `RewardDistributor`, `Treasury`; `proof-of-facilitation/aggregator/`. |
| **Shortened by** | The settlement half is largely written: epoch roots, Merkle claims, a budget-capped Treasury and an aggregator with golden tests. The unlinkable *relay* token is the missing piece, marked `[NEEDS RESEARCH]` in §14.3. |

**Tests.** T15.1 A relay redeeming tokens cannot link them to the circuits that
paid it, under the stated batching. T15.2 A build with the token package removed
still relays, stores and resolves — falsified by any payment-required error (S10).
T15.3 Double-spends are caught at redemption. T15.4 Epoch settlement matches the
aggregator's golden vectors. T15.5 The batching window's effect on linkability is
pinned by test, since the window is the privacy parameter.

**Security considerations / failure modes.** A payment identifies a payer to a
relay, which is a de-anonymisation channel (R11) — the entire reason for blind
tokens and for keeping redemption off the critical path. The batching window
trades privacy against relay cash flow: an operator who wants to be paid quickly
is asking to be linked. Failure modes: token issuance becoming a chokepoint or a
censorship point; an economy that pays enough to attract Sybils and not enough to
attract honest capacity.

**Exit criteria.** E15.1 The v1 network runs with the token subsystem disabled and
every other exit criterion still passes — falsified by any regression (S10). E15.2
Tokens issued in window *w* and redeemed in *w+k* cannot be linked by an adversary
holding both logs — falsified by linkage. E15.3 M6 of §24 is *demonstrated*, not
inferred.

**Must NOT be built yet.** Any token-price mechanism, exchange or market
(Constitution §8). Payment as a routing input (§4's layering rule). Mandatory
payment for any data-path operation, ever.

#### P16 — Production network `[BUILD NOW]` mechanics, open-ended in practice

> **PARTIAL (2026-08-16).** `internal/axon/release` + `cmd/axon-release`, 6 tests
>
> **T16.3 — the metrics schema audit now exists (2026-08-17).**
> `internal/axon/telemetry`, 3 tests, 56 transmitted fields checked. §23 names
> the failure exactly: *"monitoring that is useful precisely because it is
> deanonymising"* — the useful field and the dangerous field are the same field,
> so it cannot be left to judgement at the call site.
>
> The rule: aggregate counts and **this node's own identity** are allowed (a node
> signs its reports, so its id is attribution, not surveillance); anything naming
> a **third party or a unit of work** is not — circuit id, resolved name, object
> or shard id, another peer's identity, an address. The audit was verified to
> fail on injected `PeerID`/`CircuitID` fields rather than trusted.
>
> **It found a real leak that a schema rule cannot see.** `Result.Detail` is free
> text and passes every name check. It was assigned `err.Error()` from Go's HTTP
> client, which reads
> `Get "https://x": dial tcp 203.0.113.9:443: connect: connection refused` —
> **carrying the resolved address of the target**. Now bounded at 200 bytes and
> IP-redacted, with the audit asserting that *every* assignment goes through the
> sanitiser rather than just the first.
>
> **Still outstanding:** the audit's `transmitting` list is manual. A companion
> test reports any package that POSTs JSON and is not on it, so the gap is
> visible rather than silent — but it reports rather than fails, because not
> everything that posts is telemetry.
> covering **13 distinct tampering attacks**. T16.1 and the in-process half of
> E16.3 are discharged.
>
> **THIS CARD UNDERSTATED THE PROBLEM.** It credits the tree with "dist/ (7
> platform binaries with `.sha256`)" and observes that "a `.sha256` beside a
> binary is not a signature". It was worse: `scripts/build-release.sh` emitted
> **no checksums at all**, and `scripts/update-from-github.sh` downloaded and
> installed with **no verification of any kind** — no hash, no signature, no
> version check. §18.14's strongest adversary had an open door.
>
> **Built:** an Ed25519-signed manifest over the whole artifact set, verified
> fail-closed. It refuses an unsigned release, a signature that is not hex, a
> truncated signature, a release signed by an unpinned key, a key id relabelled
> to a pinned one, a version bumped after signing, a digest rewritten in the
> manifest, a **replaced binary of identical size**, a truncated binary, a
> removed artifact, an **added unsigned artifact**, a path-traversal artifact
> name that survived a valid signature, and a **rollback to an older validly
> signed release**. Three design rules carry it: fail closed, **keys pinned and
> never fetched**, and **sign the set** rather than each file. The signing
> encoding is built by hand rather than by `json.Marshal`, because a signature
> over "whatever the encoder produced" breaks when the encoder changes and
> presents as a supply-chain attack.
>
> **`manifest` and `sign` are separate commands on purpose.** A build can
> compute hashes; only a keyholder can sign. Merging them puts the signing key
> on the machine an attacker who compromised the build already owns.
>
> **Deliberately NOT claimed — and G1–G7 in `roadmap/OUTSTANDING.md` track all
> of it.** **E16.2 is FALSE**: 9 files still import `internal/i2p`. **The
> updater does not call the verifier yet** — no key has been generated, no
> public key is pinned in any client, so the update path still verifies nothing
> in practice; the verifier exists and is unreached. **E16.3** needs the test on
> all three platforms, which is C1's harness again. **T16.2 HOLDS as of 2026-08-19**:
> `internal/bootstrap`'s peer cache persists the last accepted peer set and the
> node dials it when every source is unreachable, tested through the node's own
> refresh path (`TestT162NodeJoinsFromCacheWhenTheDocumentIsUnreachable`).
> **The cache holds peers and never the coordinator key**, because reading a
> trust root back from a file is not the same act as verifying a signature — it
> would convert "verified once, months ago" into "trusted now" across a restart,
> with nothing able to tell the difference. The two payloads therefore degrade
> differently on purpose: a routing hint is recoverable from disk, a trust root
> is not, so a node running on cache joins the DHT while refreshing no key at
> all. A cache older than seven days is refused rather than dialled.
> **`BootstrapDocument` still carries the `CoordinatorPublicKey` trust root P16
> is meant to replace, and dropping it is NOT free-standing work**: `coordKey`
> verifies storage LEASES (`validateLeaseForRecipient`) and storage REVOCATIONS
> (`recall.go`). The lease half is `OUTSTANDING.md` 2.7, blocked on StakeVault
> being deployed because `sybil.AdmitStore` requires a verified bond; the
> revocation half had no item at all until now. Both are tracked as 4.8b. **T16.3**'s metrics
> schema audit does not exist. **T16.4/T16.5** need the lab fleet. **E16.1** and
> **E16.4** need a network and a written, exercised incident-response procedure.

**Objective.** Operate it: signed releases with a fail-closed verifier, a diverse
bootstrap set, monitoring that does not deanonymise, incident response, and the
migration off the current `syndichan.org`-coordinated deployment.

| Field | Content |
|---|---|
| **Architecture** | The L8 surface frozen at five operations; the bootstrap document replaces its coordinator-key trust root with a diversity requirement; releases are signed and verified fail-closed. |
| **Components** | Release signing and verification; bootstrap-set governance; aggregate-only metrics; version negotiation and deprecation; the I2P→AXON migration for existing nodes; documentation. |
| **Protocols** | Version negotiation; deprecation windows. |
| **Data structures** | Release manifest; a bootstrap document replacing `BootstrapDocument{Version, Peers, CoordinatorPublicKey, ExpiresAt}` and its coordinator key. |
| **APIs** | resolve, publish, retrieve, tunnel, pay — frozen. |
| **Depends on** | Phases: P7, P10, P11, P13. Code: `scripts/build-release.sh`, `check-release.sh`, `dist/` (7 platform binaries with `.sha256`), `packaging/`, `scripts/update-from-github.sh`. |
| **Shortened by** | Cross-compilation, checksumming and packaging exist for seven targets. What does not exist is the *trust* property: §18.14 identifies the update channel as the strongest adversary against a real deployment, and a `.sha256` beside a binary is not a signature. |

**Tests.** T16.1 The updater refuses an unsigned or wrongly-signed release and
fails closed. T16.2 A node with the bootstrap document unreachable still joins from
cached peers. T16.3 Metrics contain no per-circuit, per-name or per-peer
identifier, by schema audit. T16.4 A node upgraded across a version boundary keeps
its NodeIdentity, bond and guards. T16.5 An existing I2P-mode node migrates with
storage intact and PoF node id unchanged.

**Security considerations / failure modes.** The supply chain voids every other
property in the document if it fails (§18.14), and it is the one adversary
Constitution §7 omits. Bootstrap diversity is the epistemic-partition problem in
its most concrete form: whoever controls the bootstrap set controls what a new node
believes the network is. Failure modes: a bootstrap set ossifying into a de facto
authority; a deprecation window short enough to partition the network by version;
monitoring that is useful precisely because it is deanonymising.

**Exit criteria.** E16.1 A node joins, resolves, retrieves and serves with **no I2P
router, no SAM bridge, no DNS entry and no coordinator reachable** — falsified by
any dependency (S1). E16.2 `grep -r internal/i2p` over the tree returns nothing
(S1). E16.3 The updater rejects a tampered release in an automated test on all
three platforms. E16.4 A published incident-response procedure exists and has been
exercised once against a simulated relay compromise.

**Must NOT be built yet.** Nothing — P16 is terminal. What must not happen is
declaring it complete: §25.5 states what this network would and would not deliver,
and P16's exit is where those limits become operational facts rather than
predictions.

### 23.5 Decision table — §23

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| **Three parallel tracks, not one sequence** | A serial 17-phase plan adds ~2 years of elapsed time for no technical reason; naming and chain work share nothing with circuit work | None — a consequence of the layer stack (Constitution §4), not of prior art | Made the parallelism explicit in a DAG with an edge table, so the schedule is auditable rather than asserted | A single sequence (simpler, far slower); full parallelism (P5 has no substitute and does not parallelise internally) | Three tracks integrate late. P10 consumes P4 records and P11 consumes P5 streams, and both integrations happen after months of independent work against interfaces that will have drifted |
| **Exit criteria as falsifiable observations on a local network** | "Phase complete" is otherwise a budget event | Tor's practice of specifying properties as testable invariants; this tree's adversarial-test culture (`recall_lying_holder_test.go`) | Every criterion names the observation that disproves it, and every one runs on `axon-lab` | Milestone sign-off by review; coverage targets, which measure the wrong thing | A local test network is not the Internet. Criteria that pass at 60 loopback nodes can fail at 600 real ones, and §24 says so rather than implying otherwise |
| **P5 named as the schedule risk, with its range published** | Estimates that hide their variance get believed | Neither — an engineering judgement | Published the range (6–12 em), the confidence, and the reason (nothing comparable in-tree) | A single-point estimate; a padded estimate presented as confident | Naming one phase as the risk invites the other four to be under-managed, which is why §23.3 lists five |
| **Payments last (P15), and the network must work without them** | A network that needs an economy to bootstrap has no bootstrap | Freenet and I2P work with zero payments; Tor runs on donated relays | Made "runs with the token package removed" an exit criterion (E15.1), not an aspiration | Payment-gated relaying from v1 — it makes the first hundred nodes impossible | Without bonds, v1 Sybil resistance rests on diversity heuristics alone, which is weaker than what later phases assume. §25(c) does not narrate this away |
| **Registry contracts start at month 0, gated only on the name grammar** | The chain track is otherwise idle for a year waiting for circuits it does not need | None of the three has a naming layer of this shape | Track B's only dependency on Track A is P1's Ed25519 record format | Sequencing naming after the overlay: idle engineers, later audit, later feedback | Contracts frozen early are contracts written before the resolver's real requirements are known; E10.x may force a P9 revision after audit, which is expensive |
| **No phase may exit while its `[UNSOLVED]` components are described as solved** | The characteristic roadmap failure: a hard problem quietly downgraded to a completed task | Neither | Made the marker audit an exit criterion at P0 (E0.3) and the language audit one at P13 (E13.3) | Trusting review to catch it | Marker discipline can become theatre: the label is applied and the problem then ignored because it is "known". §25 exists to keep the list short and specific |

### What this section does NOT establish

- **No estimate here is measured.** Every engineer-month figure is a judgement
  from a specification and no phase has been prototyped. The confidence column is
  not a statistical interval and the totals are not a bound.
- **The DAG is a dependency claim, not a plan of record.** It says what blocks
  what. It does not account for staffing, hiring, the audit calendar, or the fact
  that interfaces frozen in P0 will change.
- **Exit criteria are stated, not run.** Every one is executable in principle on
  `axon-lab`; none has been executed, because `axon-lab` does not exist. The first
  real deliverable of P0 is the harness that makes the rest of this section
  checkable.
- **The phases assume the existing code behaves as read.** Claims about
  `internal/store`, `internal/p2p` and `internal/ethproof` come from reading files,
  not running them — §1's disclaimer, applied here with more force because this
  section commits schedule to those readings.
- **Nothing here establishes that the anonymity properties are achievable.** The
  plan sequences the work, §18 assesses the threat, and §25(c) names the problems
  no phase solves. A completed P16 is a running network, not a private one.

---

## 24. The Minimal Viable Network

**The finding: the first three milestones prove the machinery works, and nothing
more. M1, M2 and M3 can all pass on a network with no anonymity whatsoever —
sixty processes on one laptop, all honest, all observable by whoever runs the
laptop. They are function tests wearing anonymity vocabulary.** Anonymity is a
property of a population: its size, its geographic and jurisdictional spread, its
ownership diversity, its traffic mix. The first network will have none of those.
Each milestone below states its pass condition precisely so that the temptation to
over-read it has something concrete to fail against.

### What already exists

| File read | Contribution |
|---|---|
| `internal/p2p/node_test.go:63-70`, `recall_test.go:69`, `disperse_test.go:168`, `recall_failure_test.go:75`, `compute_test.go:47` | Five multi-node harnesses over `/ip4/127.0.0.1/tcp/0`. `axon-lab` is these generalised, not a new idea. |
| `internal/p2p/recall_lying_holder_test.go` | The adversarial pattern the milestone scripts extend: plant a lie, prove the system catches it, log the catch. |
| `proof-of-facilitation/hardhat.config.ts`, `deploy/00_phase0.ts` | A local EVM chain and deploy scripts, so M3's chain half runs offline. |
| `internal/store/store.go`, `internal/p2p/disperse.go`, `recall.go` | M4's storage half already works over loopback TCP today. |

**What must be replaced:** nothing. `axon-lab` is additive.

### 24.1 `axon-lab` — the local test network

```text
axon-lab up --nodes 60 --adversarial 12 --chain local --topology diverse

  ├─ 60 × axond, separate data dirs, loopback or per-container addresses
  ├─ 12 marked adversarial (behaviour selected per scenario)
  ├─ 1 × anvil/hardhat node with AxonRegistry deployed
  ├─ 1 × beacon stub serving a deterministic SRV in place of the live RANDAO
  ├─ synthetic /24, /48 and ASN annotation, so diversity constraints have inputs
  └─ per-node pcap on loopback, retained per scenario
```

Three properties make it useful and one makes it dangerous:

| Property | Consequence |
|---|---|
| Every packet is capturable | Pass conditions are capture assertions, not log assertions. A log says what the code believed; a capture says what it sent. |
| Every process is inspectable | "Neither side learns the other's address" is checked by dumping structs, not by trusting the design. |
| Chain and beacon are deterministic | Epoch boundaries, SRV values and registrations are reproducible, so a failure is re-runnable. |
| **The operator sees everything** | Which is exactly the adversary the design does not defend against. `axon-lab` can never demonstrate anonymity; it can only demonstrate the absence of specific leaks. |

### 24.2 The demonstration ladder

#### M1 — Three nodes forward a cell

| | |
|---|---|
| **What must exist** | P2 (link, cells), P5 (circuit construction). Not P4, not P6, not P7 — the path is supplied by the script. |
| **The demonstration** | `axon-lab m1` starts A, B, C and a trivial echo service at C. A builds a 3-hop circuit A→B→C with a hardcoded path, opens a stream, sends 4 KiB, receives it back. Loopback capture retained for all three links. |
| **Pass condition** | (a) The echoed bytes match. (b) Cell bodies on A→B and on B→C share no common 16-byte substring outside the fixed header. (c) B's process state holds A's and C's identities and no fourth identity. (d) Every framed unit on every link is exactly 1024 bytes. (e) No hop retains circuit state more than 5 s after teardown. |
| **Does not prove** | Anything about anonymity. Three cooperating processes on one host, on a path chosen by the test script, prove the onion construction is self-consistent and nothing else. It does not prove B cannot infer A's role from timing — on loopback it almost certainly can. It does not test path selection, guards, pools or a hostile hop. |

#### M2 — Client to service through a circuit and a rendezvous point

| | |
|---|---|
| **What must exist** | M1, plus P4 (descriptor publication and retrieval) and P6 (intro points, RP). Guards and pools may be pinned by the script. |
| **The demonstration** | `axon-lab m2` starts 12 nodes. One runs a service publishing a blinded descriptor. A client resolves the descriptor from the DHT, sends INTRODUCE1 through an intro point with a valid puzzle solution, both sides build 3-hop circuits to a chosen RP, and the client fetches 1 MiB. Six relay hops plus the RP. |
| **Pass condition** | (a) The transfer completes and the bytes verify. (b) A struct audit of the client process finds no field holding the service's IP or an `/ip4`/`/ip6` component, and the same audit of the service finds nothing for the client (S2). (c) The RP's serialised state at the join holds two circuit IDs and a cookie — no address, no identity. (d) The intro point's state holds no client address. (e) An INTRODUCE1 with an invalid solution is dropped before circuit work, and counted. |
| **Does not prove** | Anonymity against anyone who can see more than one link — which, on `axon-lab`, is everyone. It does not prove the six-hop path resists correlation; it is *known* not to for `INTERACTIVE` traffic (R2, §18.8). It does not prove the descriptor hides the service from an adversary who already holds a candidate ServiceIdentity (§5). It does not test guard pinning, pool failover or period rollover. |

#### M3 — `alice.lab.axon` resolves to that service

| | |
|---|---|
| **What must exist** | M2, plus P8 (names), P9 (registry on the local chain), P10 (resolver), and P4's `DomainRecord` class. |
| **The demonstration** | `axon-lab m3` registers `alice.lab.axon` by commit–reveal against the `lab` registrar on the local chain, binds it to a DomainIdentity, publishes a `DomainRecord` delegating to M2's ServiceIdentity, anchors a registry snapshot, then resolves the name from a *different* node and fetches the same 1 MiB. Then it stops the chain container and resolves again. |
| **Pass condition** | (a) Both resolutions succeed and return the same DomainIdentity. (b) The second reports a non-zero staleness and a `SNAPSHOT` mode flag (S6). (c) A scripted front-runner watching every pending transaction fails to register the name first in 100 attempts (S7). (d) The resolver refuses a fabricated chain served by a hostile RPC container. (e) No `/ip4` or `/ip6` component appears anywhere in the resolution path above L4 (S2). |
| **Does not prove** | That registration is anonymous. R6 stands: the funding graph of the registering account links the name to a payer, and the local chain hides this precisely because `anvil` has no funding graph. It does not prove the snapshot mechanism scales — a 60-name snapshot has no relationship to a 10⁶-name one. It exercises no reorg, no gas market and no real checkpoint. **M3 proves naming works, not that ownership is private.** |

#### M3b — A second namespace, created by vote, and a name registered beneath it

| | |
|---|---|
| **What must exist** | P9b: `TLDRegistry`, `IRegistrar`, the governor with a timelock, and two-level resolution in the resolver (§12.5, R3). |
| **The demonstration** | `axon-lab m3b` proposes the namespace `research` against the local chain, votes it past quorum, waits out a compressed timelock, and activates it. A second registrar is deployed beneath it. `bob.research.lab.axon` is registered and resolved from a node that was never told the namespace existed — it learns it from the root registry alone. Then: the governor attempts, through every mutating function in its ABI, to alter `alice.lab.axon`. Then the namespace is frozen, and then put into retirement. |
| **Pass condition** | (a) The new namespace is resolvable only after the timelock expires, never before. (b) A resolver with no hardcoded namespace list resolves `bob.research.lab.axon` correctly. (c) **No governor call changes any field of any name under any registrar** — the §12.0a invariant, falsified by a single state change. (d) A proposal for a label in the IANA snapshot, a special-use label, or a two-character label reverts at proposal time. (e) `FREEZE` blocks new registrations while existing names resolve byte-identically. (f) A retiring namespace resolves for its full notice period, and after retirement the service behind `bob.research.lab.axon` is still reachable at its Layer 1 address. (g) A resolver pinned to a different `TLDRegistry` reports disagreement rather than picking. |
| **Does not prove** | Anything about real governance. A local chain has no turnout, no lobbying, no capital and no adversary with a budget, so it tests the *mechanism* and not the *politics* — and the politics is where §18.17a G1 says the risk actually is. It does not prove the eligibility predicate stays correct as the IANA root grows. It does not prove that a namespace with a hostile registrar is survivable; it proves only that the root can freeze new registrations into one. |

#### M4 — Content retrieved by CID with the publisher offline

| | |
|---|---|
| **What must exist** | P4, P5, P11: erasure coding, dispersal, recall, and the `StorageLocation` record class. |
| **The demonstration** | `axon-lab m4` publishes a 64 MiB object from node P. Dispersal places RS 6+3 shards across ≥ 9 distinct holders. **Node P is then killed** — process terminated, data directory made unreadable. A client that never contacted P retrieves the object by CID over `BULK` circuits and verifies it against the BLAKE3 root. Repeated with 3 of the 9 holders killed. |
| **Pass condition** | (a) Retrieval succeeds with P dead. (b) Retrieval succeeds with P dead and 3 holders dead (RS 6+3 tolerates 3 losses). (c) Retrieval *fails cleanly* with 4 holders dead — a stated error, not a hang, and not a silent partial object. (d) A shard on a holder's disk does not yield object plaintext without the key (R5). (e) A holder that lies about deletion is caught by the existing follow-up check, over AXON transport (T11.3). |
| **Does not prove** | Durability. Nine holders alive for four minutes say nothing about availability over months, and §10 marks the measurement of real per-holder availability `[NEEDS RESEARCH]` — the whole erasure-coding-versus-replication argument rests on a number nobody has. It does not prove repair works under sustained churn. It does not address abuse: a holder storing an encrypted shard it cannot read still stores it, and §25(c) says why that is not a legal answer. |

#### M5 — The hybrid site

| | |
|---|---|
| **What must exist** | M2, M3 and M4 together, plus P7. This is the first milestone that requires the session layer, and the one that tests it. |
| **The demonstration** | `axon-lab m5` serves `alice.lab.axon` with two paths: a **live path** (a request handled by the running service through the rendezvous) and a **stored path** (a CID fetched from distributed storage). A client fetches both. **Mid-session the publisher's process is killed.** The client repeats both requests. |
| **Pass condition** | (a) Before the kill, both paths return correct bytes. (b) After the kill, the stored path still returns correct bytes and the live path returns a stated, distinguishable error — not a hang, not a silent fallback. (c) A stream open across a forced *relay* death continues on a replacement tunnel with no byte loss and no duplication (T7.2). (d) The `DomainRecord` distinguishes the two record kinds, so the client knows which failure it got. (e) The whole sequence completes with the chain container stopped, from the snapshot. |
| **Does not prove** | That the hybrid model is usable — nothing here measures latency against a user's patience, and a 6-hop `INTERACTIVE` path plus an RP has a latency floor this milestone deliberately does not report as acceptable or otherwise. It does not prove graceful degradation when *both* paths fail. It does not test the browser-facing problem of §13.8, which is unsolved and outside P16's scope. |

#### M6 — The full stack including accounting `[DEFERRED]`

| | |
|---|---|
| **What must exist** | M5, plus P14 (bonds) and P15 (tokens). Deliberately last. |
| **The demonstration** | `axon-lab m6` repeats M5 on a network where every relay is bonded, every relayed cell accrues a blind-signed token, and tokens are redeemed in aggregate at an epoch boundary against the local chain. It is then repeated **with the token subsystem compiled out**. |
| **Pass condition** | (a) M5's pass conditions hold in both runs — this is the criterion that matters (S10). (b) A relay's redeemed tokens cannot be linked to the circuits that paid it by an adversary holding both the issuance and redemption logs. (c) Double-spends are rejected at redemption. (d) Epoch settlement matches the aggregator's golden vectors. (e) No data-path operation returns a payment-required error in either run. |
| **Does not prove** | That the economics work. A local chain with no token price, no cost of capital and no budgeted adversary cannot say whether the bond is meaningful or whether relaying pays. §25(c) treats sustainable economics for volunteer infrastructure as unsolved and M6 does not change that. **M6 demonstrates mechanism, not viability.** |

### 24.3 What the ladder is honest about

```text
M1  proves  the onion construction is self-consistent
M2  proves  the two-stage rendezvous hides addresses FROM THE ENDPOINTS
M3  proves  naming resolves without DNS and survives a chain outage
M4  proves  content outlives its publisher, within one erasure-coding generation
M5  proves  the two paths compose and the session survives circuit death
M6  proves  the accounting plane can be attached and detached

NONE of them proves anonymity.
```

Three reasons, stated so they cannot be softened later.

1. **Anonymity requires a population, and `axon-lab` has processes.** The
   anonymity set of a 60-process loopback network is one machine. Every property
   the design claims is conditional on a diverse relay population; the first real
   network will have perhaps dozens of operators, concentrated in a few hosting
   providers and a few jurisdictions, and its anonymity will be correspondingly
   weak. That is not a defect of this plan — it is the starting condition of every
   overlay network, and it is why §1.8 records that the anonymity set shrinks
   before it grows.
2. **The attacks that matter are not run by the party running the test.**
   End-to-end correlation, long-term intersection, guard discovery and website
   fingerprinting need either a global view or months of observation. `axon-lab`
   supplies a global view trivially, so every such test "passes" for the adversary
   instantly and therefore tells you nothing. They can only be evaluated by
   simulation against published parameters (E12.3, E12.4) or by adversarial
   research on a live network.
3. **A leak test is not an anonymity test.** Every pass condition above has the
   form "this specific information was not in this specific place". That is
   valuable and checkable — it is what S2 and S5 are. It is not "the adversary
   cannot determine who is talking to whom", and the two must not be conflated in
   any release note.

### Decision table — §24

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| **A single scripted lab network as the acceptance substrate** | Exit criteria that cannot be executed are not criteria | The existing tree's loopback multi-node tests, generalised | Milestones are scripts with capture-based pass conditions, not review meetings | Testnet-first (slow feedback, unreproducible failures); unit tests only (never exercises composition) | The lab becomes the definition of correct. Behaviour that appears only at real latency, loss and churn stays invisible until P16 |
| **Pass conditions as capture and struct-dump assertions** | A log records what the code believed; a capture records what it sent | Neither — the existing adversarial-test culture applied to the network layer | Assertions read the wire and the heap, not the logs | Log-based assertions, which are cheap and pass when the code is confidently wrong | Struct-dump assertions are brittle across refactors, and brittle tests get deleted. They must be few and load-bearing |
| **M1–M3 declared function tests in the document itself** | The predictable failure of a demo ladder is that a working demo is reported as a working anonymity network | Neither | Every milestone carries a "does not prove" block with the same weight as its pass condition | Presenting the ladder without the caveats: shorter, and dishonest | Saying "this does not prove anonymity" repeatedly can read as false modesty and then be discounted. The specific reasons in §24.3 exist so that it cannot be |
| **M6 deferred to last and made removable** | An economy attached early becomes load-bearing before anyone knows whether it works | Tor, I2P and Freenet all run without payments | The removability of the token subsystem is itself a pass condition | Building accounting alongside the data path — R11 forbids it on the critical path anyway | A subsystem that must stay removable constrains every interface it touches, and that constraint will be argued against for the whole programme |

### What this section does NOT establish

- **`axon-lab` does not exist.** It is specified here and is the first deliverable
  of P0. Every pass condition is written to be executable and none has been
  executed.
- **No milestone tests anonymity, and M1–M3 do not even test hostility.** The
  adversarial nodes are behaviourally scripted per scenario, and a scripted
  adversary tests the mitigations that were anticipated and no others.
- **Latency is not a pass condition anywhere in the ladder.** A six-hop path plus
  a rendezvous point has a cost that has not been measured, budgeted or compared
  against any usability threshold. M5 could pass and the result could still be too
  slow to use.
- **Scale is untested by construction.** Sixty processes on one host share a
  clock, a scheduler and a network stack. DHT convergence, republication load and
  epoch-boundary churn all behave differently three orders of magnitude up, and
  nothing here predicts how.
- **The milestones assume their phases exited honestly.** M4 depends on P11's
  claim that the storage suite passes unmodified; that claim is a plan, not an
  observation.

---

## 25. Practicality Triage

**The honest summary before the lists: roughly three-quarters of this document is
ordinary engineering, about a fifth needs prototyping or literature work before
anyone should commit to it, and eight problems have no good answer anywhere — not
in Tor, not in I2P, not in Freenet, and not here.** The distinction that matters
is not difficulty. It is whether failure is a schedule event or a property the
system will simply not have.

### What already exists

This section synthesises the component markers already assigned by §5, §6, §7,
§10, §13, §14, §15, §16, §17 and §18 and adds durations and open questions. It is
consistent with §18.22's difficulty index; where a subsystem section marks a
component differently, that section governs its own subsystem.

### 25.1 (a) `[BUILD NOW]` — well-understood engineering, no research risk

Durations are for the component alone, in engineer-weeks (ew), and carry §23.3's
caveat: estimated from a specification, not measured.

| Component | § | ew | Note |
|---|---|---|---|
| Eight-class key generation, storage, serialisation | §5 | 4 | The classes are the easy part. |
| KDF label table + golden vectors; record encoding and canonicalisation for six classes | §5, §7 | 4 | |
| Ed25519 scalar blinding + address codec | §5 | 3 | Small, delicate, fully specified. Test the scalar arithmetic, not only the round trip. |
| `p2p.key` migration preserving the PoF node id | §5 | 2 | Existing loader; the risk is a silent new identity. |
| QUIC link, TLS 1.3, NodeIdentity pinning, 0-RTT off | §6 | 8 | `quic-go` vendored. |
| Cell framing identical over QUIC and TCP; TCP+TLS fallback | §6, §8 | 5 | The fallback is small once framing is shared. |
| One QUIC stream per circuit, with paired state caps | §6 | 3 | R12. Caps must land in the same commit as the streams. |
| Connection migration with connection-ID rotation; UPnP/NAT-PMP/PCP off by default | §6 | 4 | Mostly configuration and existing libraries. |
| Peer-mutual address discovery + diversity quorum | §6 | 4 | Reuses `internal/gateway/protocol.go`. |
| Reachability state machine + role gating | §6 | 3 | |
| Prefix/ASN annotation of peers | §2 | 2 | `go-libp2p-asn-util` vendored; the data it feeds does not exist today. |
| KadID derivation + epoch rotation; SRV from the verified RANDAO mix | §7 | 6 | Light client exists. |
| d=3 disjoint lookup paths | §7 | 4 | S/Kademlia, well documented. |
| Six DHT record validators | §7 | 5 | Shape proven by `internal/dcs/dht.go`. |
| Blinded descriptor storage (storer learns nothing) | §7 | 3 | |
| Onion circuit construction + per-hop key schedule | §8 | 12 | Well understood in the literature; new to this tree. |
| CREATE/EXTEND/RELAY state machines, teardown, circuit-ID remapping | §8 | 9 | |
| Guard selection, pinning, 45-day rotation, persistence | §9 | 4 | |
| Tunnel pools: 3+1 in/out, 10-min life, 70 % rebuild | §9 | 6 | I2P's proven figures. |
| Introduction points + rendezvous, two-stage; publication at 8 replicas | §7, §9 | 10 | |
| `.axon` grammar, normalisation, canonical encoding | §11 | 4 | Confusable policy is the only judgement call. |
| `AxonRegistry` commit–reveal, rotation, revocation, transfer | §12 | 6 | Existing Hardhat harness. Excludes audit. |
| `AxonResolverRegistry` anchoring; owner multisig + timelock | §12, §18 | 3 | The multisig turns one key into a governance problem. |
| Registry snapshot builder + inclusion proofs | §13 | 4 | |
| Resolver pipeline, three modes, freshness accounting | §13 | 6 | Light client exists and is verified. |
| Authenticated negative caching; revocation handling + cache purge | §13 | 4 | The mechanism; propagation completeness is (c). |
| BLAKE3 CID + Bao verified streaming; binary `ObjectManifest` | §10 | 5 | Library vendored. |
| CONTRACT/CACHE pool split with eviction; Bao slice spot-check audit | §10 | 6 | |
| Transport swap for the storage layer | §10 | 2 | 0 of 210 test files import `internal/i2p`. |
| Re-derivation of the I2P-calibrated timeouts | §10 | 2 | Derived and documented, not relaxed. |
| Diversity constraints in path and placement selection | §15 | 5 | New work; §1 establishes the levels do not exist. |
| Randomised selection with per-prefix and per-ASN caps | §15 | 2 | |
| Proof of work for cheap admission | §15 | 3 | Cost on low-end hardware must be measured. |
| Bond verification against `StakeVault` via the light client | §15 | 3 | Contracts written and unit-tested. |
| Wire-profile freezing (QUIC/TLS/CC/version strings) | §16 | 4 | Byte-identical binaries is the test. |
| Padding mechanism (not the schedule) | §16 | 4 | |
| Traffic-class API that forces the caller to choose | §16 | 1 | R2. A default class is a design error. |
| Release signing + fail-closed verifier | §18, §22 | 3 | **v1 blocker.** Everything else depends on it. |
| Aggregate-only metrics with schema audit | §22 | 2 | |
| `axon-lab` harness | §24 | 6 | First deliverable of P0. |

Total: roughly **190 ew ≈ 44 engineer-months**, a little under half the
programme's midpoint. The remainder is integration, test, documentation, the (b)
list and P16.

### 25.2 (b) `[NEEDS RESEARCH]` — the design is not settled

| Component | § | The open question | How it could be answered |
|---|---|---|---|
| RFC 7250 raw public keys in the target TLS stack | §6 | Does the stack expose raw public keys at all, and if not, does the minimal-certificate fallback carry distinguishing content? | A one-week spike. The cheapest unknown in the document, and it gates P2. |
| Circuit flow control across 3 hops under loss | §8, P5 | What scheme keeps a 3-hop circuit from collapsing under loss without reintroducing the cross-circuit head-of-line blocking R12 removes? | Prototype two schemes on `axon-lab` with injected loss; measure. Nothing in the tree informs this. |
| Session layer under which streams survive circuit death | §9, P7 | What is the resumption handshake, and does it create a linkability oracle across circuits? | Design plus adversarial review. libp2p offers nothing: its streams die with the connection. |
| Isolation-context count vs. guard exposure | §9, §18 | How many contexts before the guard set is large enough that some context reliably starts hostile? | Analytic model plus simulation over published parameters. |
| Intro-point admission puzzle | §9 | What difficulty excludes a flood without excluding a phone? The parameter is the design. | Measure solve cost across a hardware range, then decide whether the exclusion is acceptable. |
| Path weighting from bounded self-reports | §15, P12 | Can a weighting capped by bond and lowered by receipts approximate bandwidth-weighted selection usefully, with no measurement authority? | Simulation against a synthetic population; publish the simulator (E12.4). |
| Blind-token issuance and redemption batching | §14 | How wide must the window be before the two logs cannot be linked, and does that width leave relays tolerable cash flow? | Analysis plus a prototype with a scripted linking adversary. |
| Probabilistic micropayments vs. per-cell granularity | §14 | Is per-cell accounting needed at all, or does coarse granularity remove a whole class of timing leak? | Analysis; likely resolves in favour of coarse. |
| Behavioural unlinkability across blinding periods | §5, §18 | Does a service's traffic pattern re-link it across descriptor periods, making blinding cosmetic? | Requires a traffic corpus that does not exist. |
| Storage contracts with expiry and renewal | §10 | What does a contract commit to, who enforces it, and what happens when the payer disappears? | Design work. |
| Proof of retrievability with an extraction argument | §10 | Can the existing audit machinery be upgraded to a real extraction argument at acceptable cost? | Literature work; the constructions exist, their cost at 1 MiB chunks does not. |
| Measuring real per-holder availability `p` | §10 | What is `p`? **The whole erasure-coding-versus-replication argument rests on it and nobody has measured it.** | Instrument the existing production deployment. This is measurable today and is not being measured. |
| Segmented manifests for objects > ~1.5 GiB | §10 | Format and repair semantics. | Design work. |
| Bond-backed storage admission replacing leases | §10, §15 | What local policy replaces a lease, and does it hold without an issuer? | Design plus an `axon-lab` scenario with the coordinator stopped (E14.2). |
| Coordinated hole punching | §6 | What is the success rate for this population, given anonymity confines it to already-public peers? | Measure. It may have no worthwhile use case. |
| Clock-skew exposure via QUIC ACK delay | §16 | How identifying is per-machine crystal offset at protocol level, and is any of it mitigable? | Literature plus measurement. Not fully mitigable at the protocol layer. |
| Binary transparency log | §18 | What gossip does a transparency log depend on that the adversary does not control? | Design work; the dependency is the whole problem. |
| Name-constraint enforcement for the local TLS root | §13 | Does each platform actually enforce X.509 `nameConstraints` on a locally installed root? One that ignores them turns the mitigation off silently. | Test per platform at install time and refuse where unenforced. Testable today. |
| Reputation continuity across a compromise rotation | §5, §15 | How does a node keep earned standing across a rotation without making the rotation linkable? | Design work; the two goals are in direct tension. |
| Verifiable routing without a membership consensus | §7 | Is there a secure-routing construction giving per-hop forwarding proofs without the authority R14 refuses? | Literature review. If one exists it dominates the current design. |

### 25.3 (c) `[UNSOLVED]` — no deployed system has a good answer

For each: the best known partial answer, and what AXON actually does. The second
half is deliberately unflattering, because the alternative is a document that
reads as though these were handled.

**1. Sybil resistance without a central authority or a capital gate.**
*Best known partial answer.* Three families, none sufficient. (i) Identity cost —
PoW, proof of stake, bonded deposits: raises the price of *n* identities linearly,
which an adversary with capital simply pays and which excludes the volunteers the
network needs. (ii) Social-graph constructions: they work in the literature and
have never survived contact with an open network, because the graph itself must be
bootstrapped and attacked. (iii) Resource diversity — treating a /24 or an ASN as
the scarce resource: cheap to apply, cheap to evade with a hosting budget.
*What AXON does.* Layers all three weakly (§15): KadID binds position to identity
and epoch; diversity caps limit how much of a path, bucket or replica set one
prefix or ASN occupies; bonded stake gates consequential roles; PoW gates cheap
ones. **It does not solve the problem and the parameters are uncalibrated** —
nobody can say what bond makes 20 % of relays infeasible, because that depends on
a token price, an adversary's budget and a population that does not exist
(§18.22). AXON raises the cost of a Sybil fleet by an unknown factor and makes a
large one *visible* in the diversity statistics, which is not the same as
preventing it.

**2. End-to-end correlation for low-latency traffic.**
*Best known partial answer.* There is none for low latency. An adversary observing
traffic entering the first hop and leaving the last correlates it by volume and
timing with high accuracy and little data — the foundational limit of onion
routing, known since the design was first published. The only real defences are
high-latency mixing, which destroys interactivity, and cover traffic, whose cost is
proportional to the protection and which has never been shown worth it at scale.
*What AXON does.* Declares two traffic classes and claims nothing for the
low-latency one (R2). `INTERACTIVE` is explicitly vulnerable and the API forces the
caller to acknowledge the class; `BULK` is batched and padded and gets a weaker but
real claim. Guards reduce the *probability* of ever selecting a hostile first hop —
a lifetime probability reduction, not a defence against an adversary who already
holds that position. **AXON does not defend against a global passive adversary and
Constitution §7 says so explicitly.**

**3. A consistent view of the relay set without directory authorities.**
*Best known partial answer.* Tor's nine directory authorities produce a signed
consensus and are why Tor clients agree about what the network is; they are also
nine machines whose operators are known and whose compromise or coercion is the
network's largest single risk. I2P's floodfill peers avoid the authority and pay in
Sybil exposure: whoever becomes floodfill for a key controls what everyone learns
about it. There is no third option in production anywhere.
*What AXON does.* Refuses the authority (R14), stores relay descriptors in the DHT,
and computes path selection locally from a bandwidth-and-diversity-weighted sample.
**Clients can therefore be given different views of the network, and nothing in the
design detects a careful partition.** §7 marks the eclipse of a node's first view
`[UNSOLVED]`; P12's E12.5 catches only a crude split. With (1) this is the hardest
problem in the document, and the answer is to accept a weaker property in exchange
for removing nine machines from the trust base. Whether that trade is correct is
not established anywhere in this document.

**4. Measured bandwidth without a measurement authority.**
*Best known partial answer.* Tor measures relay capacity with bandwidth
authorities — measuring machines whose observations become consensus weights. It
works, and it is a centralisation and a manipulation target. Peer-measurement
schemes exist in the literature and are gameable by colluding measurers, cheaply,
in exactly the population that matters.
*What AXON does.* Weights self-reported capacity **bounded above by bonded stake
and lowered by delivery receipts** (R14), so receipts can never inflate a claim.
**It does not produce a measurement.** A relay that claims modest capacity and
delivers it is indistinguishable from one that could deliver far more, so the
network under-uses honest capacity, while an adversary willing to bond and actually
deliver gets exactly the weight it paid for. Load balancing will be worse than
Tor's; that is the price of the missing authority.

**5. Abuse and operator liability for storage and exit.**
*Best known partial answer.* Nobody has one. Freenet's answer is that nodes cannot
know what they hold — a technical statement that has never been a legal defence.
Tor's answer for exits is exit policies, a well-organised legal FAQ, and operators
who accept the risk, which works because that community is small, motivated and
advised. Global blocklists are the only mechanism that actually removes content,
and they are a re-centralisation and a censorship channel by construction.
*What AXON does.* (i) **No clearnet exit role in v1** (§18.3), which deletes the
largest category of the problem and also deletes the capability that would make the
overlay generally useful — users needing clearnet reach will run their own bridges
and get worse isolation than a designed exit would have given them. (ii) Holders
store encrypted shards they cannot read (R5): true, and not a legal defence.
(iii) Local operator blocklists are supported. (iv) **A global blocklist is refused
as re-centralisation and the abuse problem is named as unsolved.** An operator in a
jurisdiction that assigns liability for possession has a real exposure this design
does not remove.

**6. Guard discovery and long-term intersection attacks.**
*Best known partial answer.* Guards are themselves the partial answer to guard
discovery: pinning few, long-lived first hops means an adversary must be *selected*
rather than merely present. Against a service that is online continuously and
reachable on demand, an adversary who can cause traffic locates the guards over
time, and Tor's answer — vanguards, layered guard sets — raises the cost without
closing it. Long-term intersection against a persistently-online, low-churn user
has no defence at all: every session narrows the candidate set and it converges.
*What AXON does.* Pins 2 primary guards per isolation context with 45-day rotation
and a 90-day list (Constitution §5), deliberately between Tor's single long-lived
guard and I2P's per-tunnel churn (R1). **Guard discovery against an online service
is `[UNSOLVED]` (§18.22) and long-term intersection is explicitly outside the
adversary model (Constitution §7).** There is a self-inflicted version too: a relay
rotating its RoutingIdentity every epoch while up continuously is trivially
re-linked by uptime (§16), so rotation without a plausible gap is cosmetic, and
AXON has no mechanism for plausible gaps.

**7. Sustainable economics for volunteer infrastructure.**
*Best known partial answer.* Tor runs on donated relays funded by grants and
goodwill, and has never had enough exit capacity. I2P runs because participation is
a side effect of use; Freenet the same. Every attempt to pay relays in a
decentralised network hits the same three walls: paying identifies the payer to the
recipient; the payment mechanism becomes the censorship point; and any payment
large enough to attract capacity also attracts adversaries happy to provide it.
*What AXON does.* Defers the economy entirely (R11), makes zero-payment operation a
hard exit criterion (S10, E15.1), and specifies blind-signed unlinkable tokens
redeemed off the critical path for later. The substrate is real — SCPP/1,
`blinded.go`, `pedersen.go` and the PoF epoch machinery are written. **What is not
established is that any of it produces a sustainable economy.** The bond that makes
Sybils expensive is the capital gate that excludes volunteers; this document does
not resolve that tension, it schedules it (P14, P15) and marks the calibration
unsolved.

**8. Bootstrap and trust on first use.**
*Best known partial answer.* Every network ships a hardcoded list — Tor ships
directory authority keys in the binary, I2P ships reseed hosts, Bitcoin ships DNS
seeds. The list is the trust root, and whoever controls what a new node first
believes controls what that node's network *is*. The weak-subjectivity checkpoint
is the same problem in another domain, and `doc/trust-anchor.md` §3 states it
plainly: the initial checkpoint is a subjective input and a fake one is
undetectable, because everything verifies inside a coherent fake chain.
*What AXON does.* Diversifies rather than solves: a bootstrap set with a diversity
requirement, a partition warning when a node's first view fails that check (T3.5),
and a checkpoint that must come from outside the RPC being verified — a refusal
already implemented in `HeaderVerifier.SetAnchor`, which rejects an anchor sharing
a registrable domain with the RPC endpoint. **None of this solves TOFU.** §7 states
it as bluntly as it can be stated: a node whose first view of the network is
adversarial is adversarially bootstrapped, and no later hardening fixes it. The
release-signing key is the same problem again (§18.14), and it is the one adversary
Constitution §7 omits.

**Also unsolved, listed for completeness** — each developed in its own section:

| Problem | § | AXON's actual position |
|---|---|---|
| Revocation propagation with any completeness property | §5 | Short lifetimes bound the damage. A partitioned client may never learn. The same gap OCSP has. |
| Symmetric-NAT traversal without a relay | §6 | "Use a tunnel" — a real answer with a real latency cost, not a solution. |
| Blocking resistance | §6 | Out of scope for v1. The ALPN string identifies the network to any observer. |
| Relay and anonymous client on one IPv6 prefix | §6 | Linkable at the /64. Operational mitigation only. |
| Distinguishing a slow holder from an outsourcing holder over circuits | §10 | No mechanism. |
| Timing/size correlation of `BULK` shard transfers by a partial observer | §10 | Shard sizes are fixed and known. Nothing hides them. |
| Uptime pattern defeating RoutingIdentity rotation | §16 | Rotation without a plausible gap is cosmetic; no gap mechanism exists. |
| Decentralised chain access | §1, §12 | The light client removes the trust, not the dependency: 1 of 8 measured checkpoint providers served light-client routes. |
| Post-quantum descriptor blinding | §5 | Deferred. No construction chosen. |
| Funding-graph linkage of a name to a payer | §12 | Documented as residual. Commit–reveal breaks the timing link, not the funding link. Do not claim anonymous ownership. |

### 25.4 Decision table — §25

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| **Three explicit lists, with `[UNSOLVED]` given the most space** | A roadmap's characteristic failure is that hard problems become tasks and then become "done" | Tor's practice of publishing what its design does not defend against | Each unsolved item names the best partial answer *and* what we actually do, so the gap is legible | A single risk register, where everything becomes medium; omitting the list, which would make the document dishonest | A published list of what does not work is a target list for an adversary and a quotation source for a critic. Both are acceptable; neither is zero |
| **No clearnet exit role in v1** | Exit sniffing, exit-side abuse liability and exit deanonymisation are Tor's largest operational costs | Tor has exits; I2P largely does not | Deleted the role rather than defaulting it off | An exit capability behind a flag — a flag that exists gets turned on | The overlay is unusable for clearnet fetch, so users build their own bridges with worse isolation than a designed exit would have provided |
| **Ship mechanisms with provisional parameters, not confident numbers** | A bond figure or padding schedule stated confidently implies a threat analysis nobody has done | Neither | Parameters that cannot be derived are marked provisional, with their derivation stated as absent | Picking plausible numbers and moving on — the normal practice, which manufactures false confidence | "Provisional" parameters ship and then never get revisited, because revisiting needs the measurement that was missing in the first place |
| **Measure `p` (per-holder availability) on the existing deployment now** | The erasure-coding-versus-replication argument rests entirely on a number nobody has measured, and the deployment that could measure it runs today | Freenet's availability is emergent and unmeasured; this is the specific improvement claimed over it | Made it a named research item with an available method rather than an assumption | Continuing to assume it, which is the current state | A `p` measured on a small, friendly, I2P-transported deployment may not transfer to AXON at all |

### 25.5 The honest overall assessment

If this system is built exactly as specified:

**It would deliver.** A working overlay in which a service is reachable by a
self-certifying name through a six-hop path plus a rendezvous point, where
**neither endpoint learns the other's network address**, and where that property
is checkable by struct audit rather than by argument. A namespace owned by nobody
who can be subpoenaed for a DNS record, which **keeps resolving during a chain
outage** from a locally verified snapshot with an explicit staleness figure — built
on a light client that has already verified a real mainnet sync-committee
signature. Content that **survives its publisher going offline**, with availability
as a contracted, measured, repaired property rather than an emergent hope, which
is a real improvement on Freenet's model and the one place the existing codebase is
already ahead of the prior art. Removal of hard external dependencies: no I2P
router, no SAM bridge, no DNS registrar, no ACME certificate authority, no
coordinator — **every one of those is a control point that exists today.** And an
engineering artefact that says what it does not do, with every anonymity claim
scoped to a stated adversary class.

**It would not deliver.** **Anonymity against a global passive adversary**, or
against anyone who can see both ends of a low-latency conversation; that is not an
implementation gap but the known limit of onion routing, and nothing in this plan
changes it. **Anonymity at the scale that makes anonymity meaningful**, for a long
time: a new overlay's anonymity set starts at approximately its operator count, so
the design is sound in a way that pays off only after adoption that may never
arrive, and §1.8 already concedes that discarding I2P's two decades of operational
hardening shrinks the anonymity set before it grows it. **A consistent view of the
network**: refusing directory authorities means accepting that clients can be shown
different networks and that a careful partition goes undetected — a real reduction
in a property Tor has, taken deliberately, and nothing here establishes the trade
is correct. **Sybil resistance with a stated cost**: the mechanisms are layered and
real, the parameters are guesses, and "an adversary needs *X* to control 20 % of
relays" is a sentence this document cannot complete. **A solution to abuse,
liability or economics**: storage operators carry real legal exposure that
encryption does not remove, relay operators are publicly enumerable and are the
first people anyone can find, nobody is paid, and the design for paying them is
unfinished by choice. **Usability**: no latency budget is established anywhere in
this document, and a six-hop path plus a rendezvous point, over QUIC, with padding,
has a cost never measured against any threshold a user would recognise.

**The one-sentence version.** Built as specified, AXON would be a technically
sound, honestly documented overlay that removes several real centralisation points
and delivers endpoint-address hiding and publisher-independent content — and it
would be a network whose anonymity properties are strictly weaker than Tor's for as
long as it is smaller than Tor, with four unsolved problems at its centre that no
other deployed system has solved either.

### What this section does NOT establish

- **The durations in (a) are estimates, not measurements**, and they are for
  components in isolation. Integration, review and rework are not in them, which is
  why the (a) total is under half the programme estimate in §23.3.
- **The boundary between (a) and (b) is a judgement.** Several rows in (a) —
  circuit construction, tunnel pools, the resolver pipeline — are well understood
  in the literature and have never been implemented by this team. "No research
  risk" is a claim about the design's settledness, not about execution.
- **The (c) list is not exhaustive.** It collects what the preceding sections
  found. A problem nobody in this document thought of is not on it, and the
  compound attacks §18 declines to analyse are precisely where such a problem would
  be.
- **No partial answer in (c) has been evaluated against AXON's parameters.** The
  descriptions of what Tor, I2P and Freenet do come from their published designs;
  no comparison here is quantitative.
- **The overall assessment is an assessment, not a result.** Nothing in it has been
  demonstrated, because nothing in this document has been built. It is written down
  so the claim can be checked against the system later, which is the only thing
  that makes it worth writing down.

> **Objection to Constitution §5 (content chunk size), concurring with §1.** §23
> P11 and §24 M4 are written against **RS 6+3 and 1 MiB chunks**, read from
> `internal/config/config.go:572-574`, not the 256 KiB in the parameter table. If
> synthesis rules for 256 KiB, P11's estimate must grow to include a manifest
> migration (`FormatVersion = 1`, `internal/store/types.go:5`) and M4's shard
> arithmetic changes. The roadmap cannot cost a re-tune that has not been decided.

> **Objection to Constitution §0 (Proof of Facilitation status).** §23 P9, P14 and
> P15 treat the PoF contracts as *written and unit-tested but not deployed*, which
> is what `proof-of-facilitation/README.md`'s own go-live checklist says: item 1 is
> a funded deployer key, item 2 is un-pinning `zksolc 1.5.7`. Constitution §0's
> phrasing reads, in a roadmap, as availability. It is not availability, and P14's
> exit criteria depend on that distinction being maintained.

> **Objection to Constitution §7 (adversary model).** Concurring with §18: the
> canonical adversary model omits the supply-chain adversary, and P16's E16.3 makes
> release signing an exit criterion for the terminal phase. If the model does not
> name that adversary, the strongest attack on the finished system is the one the
> plan is not obliged to defend against.

---

### 23.4 Parity phases (Part IX)

These close the register in §80. Nine are new; four amend phases above. Each
carries the same structure as every phase above it, because a phase without exit
criteria is an intention rather than a plan.

**Every parameter adopted from Tor or I2P is given as a number here and lives in
`internal/axon/params` (T0.2).** Where a number is *ours* rather than theirs it
says so: the published designs give a shape and a rationale, and several of their
exact defaults come from measurements of networks that do not resemble this one.
Adopting a shape and inventing a value is honest; adopting a value and implying
it was measured here is not.

**Sequencing.** P5a blocks P5's completion, P6 and P7 — all three would
otherwise be built against a cell format §81.1 withdraws.

```text
P5a ──blocks──▶ P5 ──▶ P6 ──▶ P7 ──▶ P7a
                              ├──▶ P17 ──▶ P20
                              └──▶ P5b
P3 ──▶ P12a ──▶ P12 ──▶ P19
P2 ──▶ P18            ──▶ P16 ──▶ P21
```

---

#### P5a — Non-malleable cell construction `[BUILD NOW]`

**Objective.** Replace the rotating tag stack with a construction that has no
mutable unauthenticated field, closing PAR-01.

```text
withdrawn:  [hdr 16][TAG0..TAG3 = 64][onion 944]   tags mutable, unauthenticated,
                                                    hop-chosen bytes flow downstream
option (a): [hdr 16][      permuted block 1008   ]  wide-block PRP per hop, no tags
option (b): [hdr 16][   header+filler   ][payload]  Sphinx-style, MACs cover
                                                    downstream material
```

| Field | Content |
|---|---|
| **Architecture** | One of two admissible constructions, selected on evidence. **(a) Wide-block / tweakable PRP:** each hop applies a strong pseudorandom permutation over the whole 1008-byte body, so any modification randomises the block and there is no unauthenticated field to abuse. **(b) Sphinx-style precomputed filler:** constant-size cells whose per-hop MACs cover the downstream material, with filler the client computes at build time. |
| **Components** | `axon/circuit`: layer construction, cell layout, and the written security argument for whichever is chosen. `axon/link`: `Cell.Tags` and `TagStackSize` removed or redefined. |
| **Protocols** | §8.1's cell diagram is reissued. This is a wire break; nothing is deployed to break. |
| **Data structures** | Cell layout; per-hop layer state; for (b), the filler table. |
| **APIs** | `SealForward`, `OpenForwardAtHop`, `SealBackwardAtHop`, `OpenBackwardAtClient` keep their shapes; internals change entirely. |
| **Depends on** | Phases: P2. Code: `internal/axon/circuit/onion.go` and its suite, which already contains the failing property as `TestTagStackFillerIsACrossHopChannel`. |
| **Shortened by** | The defect is characterised and reproduced by a test, and both candidates have published literature. What is absent is a wide-block cipher in the Go standard library, which is the decision this phase turns on. |

**Parameters.**

| Name | Value | Source |
|---|---|---|
| `CellSize` | 1024 | unchanged (§8.1) |
| `CellBodySize` | 1008 | unchanged |
| `RelayPayloadSize` | 944 | unchanged — capacity must not move, or a format change becomes observable |
| `MaxHops` | 4 | unchanged |

**Tests.** T5a.1 No byte a hop can choose reaches any downstream hop unaltered —
the direct inverse of `TestTagStackFillerIsACrossHopChannel`, which must be
rewritten as an assertion or the phase is not done. T5a.2 A single bit flipped at
hop *k* randomises the payload at hop *k+1* and is detected before forwarding.
T5a.3 Position-hiding is preserved: a relay handling data cells has no
format-level evidence of circuit length or of its own position. T5a.4 Cell size
and relay payload capacity are identical for H = 1..4. T5a.5 Golden vectors, so a
parameter change fails the build.

**Security considerations / failure modes.** Option (a) rests on a PRP property
harder to argue informally than "this is an AEAD", and §8.3 deferred it for
exactly that reason — the argument must be written, not assumed. Option (b)
carries the "filler must be computable at build time" hazard that
`internal/channel/onion.go` explicitly declined. Failure modes: a wide-block
construction assembled from primitives with no security argument; a filler scheme
whose precomputation leaks path length through timing; a replacement that fixes
malleability and quietly reintroduces position leakage.

**Exit criteria.** E5a.1 Over 10⁶ cells, no 4-byte-or-longer sequence chosen by
hop 1 appears anywhere in what hop 3 receives — falsified by one. E5a.2 The
security argument is written, cites published analysis, and names its
assumptions. E5a.3 Cell bytes are identical in length and distinguishability for
every H in 1..4 — falsified by any distinguisher.

**Must NOT be built yet.** Padding (P13), bundling (P20). Both sit on this layout
and must wait for it to settle.

---

#### P5b — Measured congestion control `[NEEDS RESEARCH]` then `[BUILD NOW]`

**Objective.** Replace §8.8's unmeasured window defaults with an RTT-signalled
algorithm, closing PAR-11. Performance is an anonymity property: a network too
slow to use has no users, and a network with no users has no anonymity set.

| Field | Content |
|---|---|
| **Architecture** | Circuit-level congestion control signalled by RTT measured between authenticated `SENDME`s, replacing fixed windows. Per-circuit, not per-link: the link is QUIC and already has its own control loop, and stacking two fixed-window schemes is how the current defaults became unmeasurable. |
| **Components** | `axon/circuit`: RTT estimator, window controller, `SENDME` accounting against `Af`/`Ab`. |
| **Protocols** | Authenticated `SENDME` (§8.8) carries the delivery proof the estimator needs. |
| **Data structures** | Per-circuit `{rtt_min, rtt_ewma, cwnd, inflight}`. |
| **APIs** | Internal to the circuit; no L8 surface. |
| **Depends on** | Phases: P5, P5a. Code: none. |
| **Shortened by** | Nothing. The algorithm class is published and deployed elsewhere; the tuning is not transferable, because it was measured on a network with different relay capacity and different path lengths. |

**Parameters.** All **[NEEDS RESEARCH]** — this phase exists to measure them.
The current §8.6 table (`STREAM_WINDOW_INIT` 500/2000, `CIRC_WINDOW_INIT`
1000/4000) is a starting point explicitly labelled unmeasured, and shipping it as
though it were tuned is the failure this phase prevents.

**Tests.** T5b.1 The RTT estimator is not fooled by a relay that delays `SENDME`
to inflate the window. T5b.2 Window growth is bounded when the estimator has no
sample. T5b.3 `SENDME`, `DROP` and control commands remain exempt from windows —
otherwise flow control throttles the mechanism that opens flow control.

**Security considerations / failure modes.** An RTT-based controller is a
measurement channel: a relay that can influence RTT can influence the client's
window and therefore its traffic shape, which is a fingerprint. Failure modes:
collapse under loss; oscillation across the 10-minute circuit lifetime; a
controller tuned on a LAN that fails on real paths.

**Exit criteria.** E5b.1 A stated throughput floor is met over a 3-hop circuit
for 10 minutes with zero cell loss, **measured on `axon-lab`** rather than
specified. E5b.2 Throughput degrades gracefully and does not collapse at 5 %
loss. E5b.3 The measured parameters are written into `params` with the date and
the topology they were measured on — a tuning constant with no provenance is a
guess with a decimal point.

**Must NOT be built yet.** Multipath scheduling (Part VI), which changes the
control loop entirely.

---

#### P7a — Vanguards and guard-discovery resistance `[BUILD NOW]`

**Objective.** Pin second- and third-layer guards for anonymous services with
staggered rotation, closing PAR-04 — the most serious mechanism gap for the thing
AXON exists to host.

```text
service ──▶ L1 guard ──▶ L2 vanguard ──▶ L3 vanguard ──▶ RP (attacker-chosen)
            pinned         pinned,          pinned,
            (P7)           small set,       larger set,
                           long-lived       short-lived
```

**Why it exists.** A service builds circuits continuously, to rendezvous points
an adversary chooses. Free reselection beyond the first hop means an adversary
who induces enough builds eventually observes enough second-hop relays to locate
the guard, and then the service. Pinning the next layers bounds what those builds
reveal.

| Field | Content |
|---|---|
| **Architecture** | Above. Layer sets are per-service, persisted, and rotated on independent randomised schedules so no instant replaces a whole layer. |
| **Components** | `axon/guard`: layered set management, staggered rotation, persistence. |
| **Protocols** | None new — path construction only. |
| **Data structures** | `VanguardSet{Layer, Members[], Added, Expires}` per layer per service. |
| **APIs** | `(*Service).Path(ctx, rp RelayDescriptor) ([]RelayDescriptor, error)` draws L1–L3 from the pinned sets and only the final hop freely. |
| **Depends on** | Phases: P7. Code: none. |
| **Shortened by** | The published vanguard design gives the shape and the reasoning. Its exact defaults do not transfer, because they were chosen against a relay population three orders of magnitude larger than this one. |

**Parameters.** Shape adopted; **values are ours** and are marked as such.

| Name | Value | Provenance |
|---|---|---|
| `VanguardL2Size` | 4 | shape adopted (small, long-lived); value ours |
| `VanguardL2Lifetime` | 1–12 days, uniformly randomised per member | shape adopted; range ours |
| `VanguardL3Size` | 8 | shape adopted (larger, shorter-lived); value ours |
| `VanguardL3Lifetime` | 1–48 hours, uniformly randomised per member | shape adopted; range ours |
| `VanguardDiversity` | distinct /24, /48 and ASN within a layer, and across layers | ours — reuses P3's `DiversityConstraint` |

Randomised per-member lifetimes are the point: a fixed lifetime replaces a whole
layer at one instant, which is itself an observable event.

**Tests.** T7a.1 A service that builds 10⁴ circuits to attacker-chosen rendezvous
points exposes a bounded set of second-layer relays, not a sample of the
population. T7a.2 Layer rotation is staggered — no two members of a layer expire
in the same hour. T7a.3 A vanguard that goes down is replaced without replacing
the layer. T7a.4 Layers satisfy the diversity constraint, and a layer that cannot
be filled diversely is reported short rather than filled correlated.

**Security considerations / failure modes.** Pinning trades one risk for another:
a compromised vanguard is compromised for its whole lifetime, and a long-lived L2
set is a long-lived correlation opportunity for whoever holds one. That is the
accepted trade — bounded exposure to a few relays beats unbounded exposure to
many. Failure modes: a set that cannot be filled under the diversity constraint
and is silently filled anyway; rotation schedules that correlate across services
run by one operator; persistence that survives a compromise it should not.

**Exit criteria.** E7a.1 Over 10⁴ adversary-induced builds, the number of
distinct relays observed at layer 2 does not exceed `VanguardL2Size` — falsified
by drift. E7a.2 No two layer members share a /24 or an ASN — falsified by one.
E7a.3 Over 10³ simulated rotations, no instant replaces more than one member of a
layer.

**Must NOT be built yet.** Reputation-weighted vanguard selection — it would make
the set predictable to anyone who can influence reputation.

---

#### P12a — Local peer profiling `[BUILD NOW]`

**Objective.** Capacity measurement without a measurement authority, closing
PAR-03 by importing I2P's answer wholesale.

```text
R14 forbids a measurement authority.  I2P has run without one for two decades.
   ┌──────────────────────────────────────────────────────────────┐
   │  every node profiles ONLY the peers it actually uses,         │
   │  ONLY from its own observations, and the profile NEVER        │
   │  leaves the node — so there is no global metric to game       │
   └──────────────────────────────────────────────────────────────┘
```

| Field | Content |
|---|---|
| **Architecture** | Above. The scoring layer sits on top of P3's peerbook, which records observations and deliberately does not score them — the separation this phase needs, and the reason a raw observation still exists to disagree with. |
| **Components** | `axon/profile`: observation intake, exponential decay, tiering, selection weights, uniform fallback. |
| **Protocols** | **None.** That is the design: no profile is transmitted, requested, or gossiped. |
| **Data structures** | `Profile{NodeID, Speed, Capacity, Reliability, Samples, LastSeen, Tier}`. |
| **APIs** | `(*Profiles).Observe(nodeID, ObservationKind, value, at)`; `(*Profiles).Tier(nodeID) Tier`; `(*Profiles).Weight(nodeID) float64`. |
| **Depends on** | Phases: P3, P12. Code: `internal/axon/peer/peerbook.go`. |
| **Shortened by** | I2P's design is public and two decades proven. P3's observation/score separation already exists and was built for this. |

**Parameters.** Structure adopted from I2P; **values ours**.

| Name | Value | Meaning |
|---|---|---|
| `ProfileHalfLife` | 1 h | exponential decay on every metric, so a relay that was fast yesterday does not coast |
| `ProfileMinSamples` | 10 | below this the peer is untiered and selection falls back to uniform |
| `TierFast` | top 10 % by speed among peers meeting `TierHighCapacity` | I2P's "fast" tier |
| `TierHighCapacity` | top 25 % by accepted-build ratio | I2P's "high capacity" tier |
| `TierStandard` | everything else not failing | — |
| `TierFailing` | ≥ 3 consecutive build refusals or delivery failures | excluded from selection, re-probed at `RepromoteInterval` |

**Observation inputs**, all first-hand: circuit-extend round-trip; build
accept/refuse ratio; cells delivered vs. cells sent; and reachability state from
P3. **`RelayDescriptor.claimed_bw` is explicitly NOT an input** — it is the
self-report this phase exists to stop trusting.

**Tests.** T12a.1 A profile is derived only from observations the node made
itself; no profile input arrives over the network. T12a.2 A fresh node with an
empty profile falls back to uniform selection rather than to whatever it heard
first. T12a.3 Profiles are never serialised into any message — enforced by a
schema audit over every wire type, not by a code-review promise. T12a.4
`claimed_bw` appears nowhere in the scoring path, by source audit. T12a.5 Decay
is applied on read as well as on write, so a node that stops observing does not
freeze a stale tier.

**Security considerations / failure modes.** Adopted along with the design:
profiling measures only peers you use, so a peer that behaves well toward its
measurers and badly toward everyone else is invisible to it; a fresh node's
profile is empty and it is at its most vulnerable exactly then; and a capacity
tier derived from your own traffic is a fingerprint of your own traffic if it
ever escapes the node — which is what T12a.3 exists to prevent. Failure modes:
a feedback loop where fast peers get more traffic and therefore more samples and
therefore look faster; tiers that concentrate selection onto few relays and
undo P3's diversity work.

**Exit criteria.** E12a.1 With 20 % of relays inflating self-reported capacity,
path selection weighted by local profiles shows no measurable shift toward them —
falsified by any shift. E12a.2 Over 10⁴ selections, tiering does not reduce
/24-or-ASN diversity below what uniform selection achieves — falsified by a
reduction. E12a.3 A node with fewer than `ProfileMinSamples` observations selects
indistinguishably from uniform.

**Must NOT be built yet.** Any inter-node sharing of profiles, ever. Sharing
recreates the global metric the design exists to avoid.

---

#### P17 — Directional path separation `[BUILD NOW]`

**Objective.** Offer I2P-style separation of inbound and outbound paths per
isolation context, mandatory for anonymous services (PAR-07); and reduce the
observability of the client/relay distinction (PAR-13).

```text
bidirectional (default, INTERACTIVE):  client ──▶ G ──▶ M ──▶ T ──▶ dest
                                              ◀── same three relays ◀──

directional (services, mandatory):     service ──out──▶ Go ──▶ Mo ──▶ To ──▶
                                       service ◀──in─── Gi ◀── Mi ◀── Ti ◀──
                                       no relay appears in both paths
```

| Field | Content |
|---|---|
| **Architecture** | Above. Directional separation is a property of an isolation context, not of the network: contexts that need it get it, contexts that do not keep bidirectional circuits. |
| **Components** | `axon/circuit`: paired-path construction, path-disjointness enforcement, reply-path descriptors. |
| **Protocols** | An inbound path must be advertised to the peer that will use it, which is the rendezvous mechanism (P6) generalised. |
| **Data structures** | `PathPair{Out *Circuit, In *Circuit, Disjoint bool}`. |
| **APIs** | `Build(ctx, path, class)` gains a `Directional bool`; services get it set and cannot unset it. |
| **Depends on** | Phases: P5a, P6, P7. Code: none. |
| **Shortened by** | I2P has run unidirectional tunnels since inception; the design is public and its costs are documented by two decades of its own operators. |

**Parameters.**

| Name | Value | Rationale |
|---|---|---|
| `DirectionalDefault` | off for `INTERACTIVE` | doubling build cost and latency for browsing buys less than it costs, and a network people will not use protects nobody |
| `DirectionalForServices` | **on, mandatory** | services face an adversary who induces arbitrary builds and benefits most from seeing both directions |
| `PathDisjointness` | no shared relay, /24 or ASN between the paired paths | ours; reuses P3's constraint |

**Tests.** T17.1 A service's inbound and outbound paths share no relay, /24 or
ASN. T17.2 A node classified unreachable still carries other nodes' traffic
through its own tunnels, so "no inbound" does not imply "originates everything it
sends". T17.3 A service cannot disable directional separation through any API
path. T17.4 A directional pair that cannot be built disjointly fails rather than
falling back to a shared path.

**Security considerations / failure modes.** Directional separation doubles the
number of relays a conversation touches, which is more draws against the hostile
fraction — the same trade §8.6 makes for stream isolation, and accepted for the
same reason: the linkage it prevents is certain, while the extra exposure is
statistical. Failure modes: a fallback to a shared path under pressure, which
silently voids the property; congestion control that assumes a symmetric path;
correlation of the two paths by their build times.

**Exit criteria.** E17.1 Over 10³ service path pairs, zero share a relay, /24 or
ASN — falsified by one. E17.2 A capture at any single relay on either path
observes traffic in one direction only. E17.3 An unreachable node's on-wire
behaviour is not distinguishable from a reachable node's by role advertisement
alone.

**Must NOT be built yet.** Directional multipath (Part VI), which composes with
this and must not be designed before it settles.

---

#### P18 — Bridges and pluggable transports `[BUILD NOW]`

**Objective.** Unlisted entry points and transport obfuscation, closing PAR-06.

> **RULING.** R4(a) makes DHT membership public by design, which means the relay
> list is not merely discoverable — it is *published*, and a censor blocks AXON
> by enumerating it. **R4(a) is amended to carve out `bridge`-role nodes, which
> are never published to the DHT and are learned only through the distribution
> mechanism below.** This is a deliberate exception with a stated cost: a bridge
> is invisible to the diversity accounting that every other role is subject to.

| Field | Content |
|---|---|
| **Architecture** | Three separable pieces: an **unlisted entry role** exempt from DHT publication; a **transport interface** so obfuscation layers are pluggable rather than baked in; and a **distribution mechanism** that makes harvesting the set expensive without making it hard for a real user to obtain one. |
| **Components** | `axon/bridge`: role, descriptor handling, distribution client. `axon/transport`: the pluggable interface plus at least one obfuscating transport. |
| **Protocols** | Transport negotiation before the L2 handshake; a distribution protocol with per-requester rate limiting. |
| **Data structures** | `BridgeLine{Transport, Addr, Params, RoutingID}` — a descriptor that never enters the DHT. |
| **APIs** | `RegisterTransport(name string, t Transport)`; `(*Dialer).DialBridge(ctx, BridgeLine)`. |
| **Depends on** | Phases: P2, P3. Code: `internal/axon/link` (transport selection). |
| **Shortened by** | The transport interface pattern and several obfuscation designs are public and deployed. The distribution problem is not solved by anyone and this phase inherits it. |

**Parameters.**

| Name | Value | Rationale |
|---|---|---|
| `BridgeDistributionRate` | ≤ 3 bridge lines per requester per 24 h | ours; makes bulk harvesting slow without blocking a real user |
| `BridgePublishToDHT` | **never** | the R4(a) exception above |
| `TransportDefault` | direct QUIC | obfuscation costs throughput and is not needed where it is not needed |

**Tests.** T18.1 A bridge-role node never appears in any DHT record, by record
audit across all six classes. T18.2 An obfuscated transport's first flight is not
distinguishable from random by a fixed-signature classifier. T18.3 The
distribution mechanism rate-limits per requester and the limit cannot be reset by
re-requesting from a new identity for free. T18.4 A client with only bridge lines
and no DHT access still bootstraps.

**Security considerations / failure modes.** A distribution mechanism is a
censorship target and an enumeration target simultaneously, and every design
trades between them — Tor has spent a decade in that tension and this phase
inherits it rather than solving it. A bridge is exempt from diversity accounting,
so a bridge operator's concentration is invisible. Failure modes: a distribution
channel that becomes the single point a censor blocks; obfuscation with a
distinguishable signature, which is worse than none because it identifies AXON
specifically; bridges that leak into the DHT through a role-advertisement bug.

**Exit criteria.** E18.1 Zero bridge identities appear in a full DHT crawl of a
test network containing bridges — falsified by one. E18.2 A classifier trained on
100 obfuscated and 100 random flows achieves no better than chance. E18.3
Harvesting 100 bridge lines takes at least 33 requester-days under the rate
limit.

**Must NOT be built yet.** A domain-fronting transport, which depends on a third
party's willingness and cannot be a v1 dependency.

---

#### P19 — Partition detection without a consensus `[NEEDS RESEARCH]`

**Objective.** Detect an epistemic partition without a ground truth, per §81.3's
bounded option, closing as much of PAR-02 as is closable while R14 stands.

```text
no consensus  ⇒  no ground truth  ⇒  prevention is impossible
                                 ⇒  DETECTION is not
view A  via circuit 1, bootstrap source 1 ─┐
view B  via circuit 2, bootstrap source 2 ─┼─▶ divergence ⇒ alarm
view C  via circuit 3, bootstrap source 3 ─┘
```

| Field | Content |
|---|---|
| **Architecture** | Above. Sample the relay population repeatedly through independently chosen circuits and different bootstrap sources, compare the samples, and alarm on divergence beyond what churn explains. |
| **Components** | `axon/partition`: sampler, comparator, churn baseline, alarm. |
| **Protocols** | None new — it reuses DHT lookups over distinct paths. |
| **Data structures** | `View{Source, At, Relays[], Sampled}`; `Divergence{Jaccard, Explained, Alarm}`. |
| **APIs** | `(*Detector).Check(ctx) (Divergence, error)`. |
| **Depends on** | Phases: P4, P12a. Code: `internal/axon/peer/bootstrap.go`, whose structural audit is the same idea one level down. |
| **Shortened by** | P3's `AuditBootstrap` already establishes the pattern of emitting a warning with evidence rather than a verdict, and its honest framing — structural signals an adversary can defeat and an honest deployment can trip — transfers directly. |

**Parameters.** All provisional; establishing them is the research.

| Name | Value | Status |
|---|---|---|
| `ViewSampleCount` | 3 | ours, matching `DisjointPaths` |
| `ViewDivergenceThreshold` | **[NEEDS RESEARCH]** | must be derived from a measured churn baseline, not chosen |
| `ChurnBaselineWindow` | **[NEEDS RESEARCH]** | — |

**Tests.** T19.1 Views obtained through the three paths share no relay used to
obtain them — otherwise the samples are not independent and the comparison is
theatre. T19.2 Honest churn at a stated rate does not raise an alarm. T19.3 A
simulated partition raises one.

**Security considerations / failure modes.** **Detection is not prevention, and
a fully consistent adversary is undetectable by this or any method without a
ground truth.** An adversary who controls all three bootstrap sources and enough
DHT positions shows three consistent poisoned views and the detector reports
health. Failure modes: an alarm rate high enough that operators disable it; a
churn baseline learned during an attack; samples that are not actually
independent.

**Exit criteria.** E19.1 A simulated partition in which a client is shown a relay
population 80 % controlled by one adversary is detected and reported. E19.2 The
false-positive rate under honest churn is stated and bounded. **E19.3 If the
false-negative rate cannot be brought below a stated useful level, the finding is
recorded as "R14 costs more than it buys" and the Constitution is amended — not
the claim.**

**Must NOT be built yet.** Any automatic response to a detected partition.
A node that reconfigures itself on divergence hands the adversary a lever.

---

#### P20 — Message bundling `[BUILD NOW]`

**Objective.** Bundle multiple relay messages into one unit with independent
delivery instructions, closing PAR-12.

> **This is not a mixnet and must never be described as one.** Bundling changes
> what a message *count* reveals. It does not add the delays that would make
> timing correlation hard, because Constitution §7 scopes the end-to-end
> correlating adversary out and claiming mixnet properties without mixnet delays
> is the specific dishonesty this document exists to avoid.

| Field | Content |
|---|---|
| **Architecture** | A bundle carries 1..N cloves, each with its own delivery instruction, inside one onion payload. Applies to control and service traffic, where message counts are small and structured enough to be revealing. |
| **Components** | `axon/circuit`: clove encoding, per-clove dispatch, bundle-size padding. |
| **Protocols** | A new `RCMD` for a bundle; per-clove instructions inside it. |
| **Data structures** | `Bundle{Cloves []Clove}`; `Clove{Instruction, Payload}`. |
| **APIs** | `(*Circuit).SendBundle(cloves []Clove) error`. |
| **Depends on** | Phases: P5a, P6. Code: none. |
| **Shortened by** | I2P's garlic construction is public and its clove/instruction split transfers directly. |

**Parameters.**

| Name | Value | Rationale |
|---|---|---|
| `MaxClovesPerBundle` | 8 | ours; bounded so a bundle cannot be a reassembly DoS |
| `BundlePadToFixed` | true | a bundle that is not padded to a fixed size reveals its clove count, which is the thing bundling exists to hide |
| `ClovesForControl` | mandatory | control traffic is the most structured and therefore the most revealing |

**Tests.** T20.1 A bundle of 1 clove and a bundle of 8 are identical in size and
in every observable field. T20.2 A clove whose instruction is malformed is
dropped without affecting its siblings. T20.3 Bundles are refused above
`MaxClovesPerBundle` rather than truncated.

**Security considerations / failure modes.** Bundling adds a reassembly buffer,
which is an amplification target; §8.6's existing cap (one in-progress message,
10 s timeout) is the model. Failure modes: variable-size bundles that leak the
count they exist to hide; a clove failure that tears down siblings; bundling
described in user-facing material as anonymity it is not.

**Exit criteria.** E20.1 A capture cannot distinguish a 1-clove from an 8-clove
bundle by size, timing granularity or any header field — falsified by any
distinguisher. E20.2 Reassembly memory per circuit is bounded by a constant.

**Must NOT be built yet.** Per-clove delays. That is a mixnet, and it is out of
scope by Constitution §7.

---

#### P21 — Wire specification freeze `[BUILD NOW]`

**Objective.** A protocol specification independent of this implementation,
closing PAR-14, so that a bug does not silently become protocol.

| Field | Content |
|---|---|
| **Architecture** | A normative document per layer — cell format, handshake, DHT records, circuit lifecycle, tunnel and rendezvous — written so that an implementer who has never read the Go can produce an interoperating node. |
| **Components** | `spec/` in-tree, versioned with the wire, plus machine-readable test vectors extracted from the golden tests already written for P1, P2 and P5. |
| **Protocols** | The frozen versions of all of them. |
| **Data structures** | Test-vector format; version negotiation. |
| **APIs** | None — this phase ships a document and vectors. |
| **Depends on** | Phases: P5a (nothing can be frozen before the cell format settles), P16. Code: the golden vectors in `internal/axon/*/`. |
| **Shortened by** | Golden vectors already exist for identity derivation, the cell codec and the ntor key schedule; they were written as regression guards and become the conformance suite. |

**Parameters.** None. This phase adds no tunables; it freezes the ones that exist.

**Tests.** T21.1 Every wire structure has at least one published test vector.
T21.2 The vectors are generated from the spec document's own examples and
verified against the implementation, not the reverse — otherwise the spec
documents the bugs. T21.3 A deliberately non-conforming implementation fails the
suite.

**Security considerations / failure modes.** A specification that documents the
implementation rather than constraining it is worse than none: it launders bugs
into protocol and makes them permanent. T21.2 is the whole defence against that.
Failure modes: a spec that drifts from the code with no test forcing them
together; vectors that cover the happy path only; freezing before P5a and
enshrining the withdrawn cell format.

**Exit criteria.** E21.1 An implementer working from the document alone, with no
access to the Go, produces a node that completes a 3-hop circuit against a
reference node. E21.2 Every golden vector in the tree appears in the published
suite — falsified by one that does not.

**Must NOT be built yet.** A second implementation. It is the *purpose* of the
spec, not a deliverable of this phase, and pretending otherwise would make the
phase unschedulable.

---

### 23.5 Amendments to existing phases

| Phase | Amendment | Closes |
|---|---|---|
| **P5** | **T5.8:** `RELAY_BUILD` cells are capped at `RelayBuildBudget = 8` per circuit, decremented at every hop, refused at zero; and an `EXTEND` arriving in a plain `RELAY` is refused. **The number: `MaxHops` (4) extends, plus §8.4's ≤ 2 permitted redraws, plus 2 spare = 8** — the same figure Tor arrived at, by the same reasoning. Both halves are tested: the cap alone leaves the class-confusion path open, and the refusal alone leaves an unbounded extension attack. | PAR-08 |
| **P7** | Add the bounded **sampled** guard set: `SampledGuardSize = 20`, persisted for `GuardListLifetime` (90 days, the value §8.5 already fixes — one home per tunable, T0.2), with the invariant that **a client never connects to a guard outside its sampled set**. That invariant is the property Tor's structure buys and §8.5 currently lacks — it bounds how much of the relay population a client will ever have touched, so an adversary cannot enumerate it by attrition. Filtered/confirmed/primary layering sits above, with `PrimaryGuards = 2` unchanged. Also add pre-built pool spares (`PoolSpares = 2` per context) so a first request never pays the 35 s cold build. | PAR-05, PAR-10 |
| **P13** | Netflow-level link padding is promoted **ahead of** circuit padding machines: it is simpler, needs no negotiation, and defends a real and currently undefended observation. `LinkPadIdleGap = 1.5–9.5 s` randomised — shape and range adopted, chosen to keep a netflow record alive and merge adjacent ones. Circuit padding machines follow. | PAR-09 |
| **P16** | Release signing gains a second signer and a published, verifiable key set with a stated threshold. **One signer is one subpoena**, and §18.14 already names the update channel as the strongest adversary against a real deployment. | — |


---

### 23.6 Parity phases, second tranche

Closing PAR-16 through PAR-28. The first tranche (§23.4) came from comparing
AXON's headline mechanisms against Tor's and I2P's; this one came from the
coverage check in §80.1, which is the pass that catches what a headline
comparison misses. **Two of these are `critical`** — PAR-16 and PAR-21 — and
both are defences against an adversary who simply sends more traffic than the
network can absorb, which is the least sophisticated attack in the register and
the one AXON is currently least equipped for.

```text
P6 ──▶ P6a  (service PoW)          P5a ──▶ P22 (variable length)
P12a ──▶ P12b (operator diversity)  P6 ──▶ P23 (sessions) ──▶ P26 (client auth)
P2 ──▶ P24 (relay DoS)              P16 ──▶ P25 (sandboxing)
```

---

#### P6a — Proof-of-work admission for services `[BUILD NOW]`

> **BUILT (2026-08-17) — P6a.** `internal/axon/intro`, 14 tests, five injections
> verified. **T6a.1–T6a.6 hold.** PAR-16 closes at the mechanism level; its
> parameters do not.
>
> **§9.6 and §23.6 both specify this and disagree three times.**
>
> 1. **Who sets difficulty.** §23.6: "the intro point publishes a seed and a
>    difficulty". §9.6: "The service, not the intro point, sets effort — only the
>    service knows whether it is overloaded." **§9.6 wins**: the intro point sees
>    introductions, but only the service sees whether they are turning into work
>    it cannot do. An intro point setting its own difficulty raises it under a
>    flood the service is absorbing fine.
> 2. **The controller.** §23.6 specifies `±1 bit per 10 s, asymmetric: rise fast,
>    fall slow` — **and that parameter contradicts its own rationale.** ±1 bit is
>    ×2 up and ÷2 down, symmetric in log space, so it falls exactly as fast as it
>    rises and permits precisely the pulsing attack §23.6 warns about. §9.6's
>    `×1.5+1 / ×0.75` is genuinely asymmetric (+0.58 vs −0.42 bits) and is what
>    §23.6 meant. **§9.6 wins.**
> 3. **The threshold.** §23.6's depth > 50 and §9.6's `q_target = 6` are
>    different queues at different hops; per (1) the controller runs on the
>    service's, so 6 is the operative figure.
>
> **`RisesFasterThanItFalls` was wrong in exactly the way it existed to catch.**
> It first compared LINEAR deltas — and for a multiplicative controller every
> step looks asymmetric that way, since ×2 from 1000 gains 1000 while ÷2 loses
> only 500. It scored §23.6's ±1 bit as passing. Now measured in log space, where
> the question is how many ticks it takes to travel a distance in bits.
>
> **NO SCHEME IS CHOSEN, and none is registered by default.** §9.6 marks
> Equihash `(n,k)` `[NEEDS RESEARCH]` because "this document must not pick
> numbers it cannot defend", and that holds. A package shipping hashcash as the
> default would pass every test here and be the failure §9.6 names — "targeted
> exclusion of exactly the users who most need the service". So `ReferenceHashcash`
> reports `MemoryHard() false`, `New` **refuses** it unless the caller passes
> `AllowNonMemoryHardScheme`, which exists to be greppable, and `Verify` with no
> scheme fails closed.
>
> **`PoWDifficulty` is defined as QUARTER BITS**, this being its first definition
> — the field has existed since §7.1 and the mechanism never has. Whole bits is
> the obvious reading and is too coarse: the smallest representable change would
> be a doubling, which quantises the ×1.5 rise and ×0.75 fall to one step and
> destroys the asymmetry conflict (2) exists to preserve.
>
> **T6a.3 measured: solve 3.31 ms, verify 2.0 µs — 1656×**, so E6a.2's 1 % bound
> holds with room. That measures **the effort dial, not memory-hardness**; the
> reference scheme is a SHA-256 preimage and establishes nothing about resistance
> to specialised hardware.
>
> **A test gap found by injection and closed.** Deleting the effort-dial check
> from `Verify` broke *nothing*: effort is bound into the challenge, so a forged
> claim yields a proof for a different challenge and dies one line earlier at the
> scheme check. The dial — the thing making a high effort cost something rather
> than merely be asserted — had no test. `TestEffortDialIsWhatCostsTheClient`
> constructs the only case that reaches it: a proof correct for its challenge and
> simply not lucky enough.
>
> **Still open.** `EffortCeiling` is §23.6's 2^24 held as a hard backstop, not a
> measured value — §9.6 defines the ceiling as the largest effort whose measured
> solve time on reference hardware is acceptable, which cannot be computed
> without a scheme. **E6a.1 and E6a.3 are not claimed**: both require a real
> puzzle. §23.6's own named failure — "effort-ordered queueing that a well-funded
> attacker simply wins" — is real and unmitigated; what the ordering buys is that
> the adversary must keep paying continuously at a cost rising with the pressure
> it applies, which is not a claim that the attacker loses.

**Objective.** A load-adaptive client puzzle at the introduction point, closing
PAR-16. R10 requires it; §7.1 already carries `pow_seed` and `pow_difficulty` in
`IntroPointRecord` for it; the mechanism does not exist.

```text
no flood      difficulty 0        client connects, no puzzle, no latency cost
under load    difficulty rises    each INTRODUCE1 costs the attacker CPU
                                  proportional to the pressure it is applying
```

| Field | Content |
|---|---|
| **Architecture** | The intro point publishes a seed and a difficulty in its `IntroPointRecord`, which has a 30 min TTL and a 10 min republish specifically so difficulty can move faster than a 3 h descriptor (§7.1's stated reason for the record existing at all). Clients solve before `INTRODUCE1`; the intro point verifies before doing any asymmetric work. |
| **Components** | `axon/intro`: puzzle definition, difficulty controller, verification, and the queue that orders admitted clients by effort. |
| **Protocols** | `INTRODUCE1` carries the solution (§8.1 already notes it "carries the rate-limit token (R10)"). |
| **Data structures** | `Puzzle{Seed[32], Difficulty uint8, Expires}`; `Solution{Nonce, Effort}`. |
| **APIs** | `(*IntroPoint).Verify(sol Solution) (effort uint64, err error)`; `(*Client).Solve(ctx, p Puzzle) (Solution, error)`. |
| **Depends on** | Phases: P4 (the record), P6 (the intro protocol). Code: `internal/axon/dht` `IntroPointRecord`. |
| **Shortened by** | The record, its TTL, its republish interval and its fields already exist and were designed for this. The deployed design in Tor gives the difficulty-controller shape. |

**Parameters.** Function adopted; **values ours**.

| Name | Value | Rationale |
|---|---|---|
| `PuzzleFunction` | memory-hard, fixed cost parameters | a CPU-only puzzle favours the attacker's hardware over the user's phone |
| `PuzzleDifficultyMin` | 0 | **no puzzle when not under attack.** A permanent puzzle taxes every honest user to defend against an attack that is not happening |
| `PuzzleDifficultyMax` | 24 bits | ours; bounds the worst case a legitimate client must pay |
| `DifficultyRaiseAt` | queue depth > 50 pending introductions | ours |
| `DifficultyStep` | ±1 bit per 10 s, asymmetric: rise fast, fall slow | ours; falling fast lets an attacker pulse the load |
| `SeedRotation` | every `IntroPointRecord` republish (10 min) | forces re-solving, so a solution bank has a 10-minute shelf life |

**Tests.** T6a.1 With difficulty 0 an honest client's introduction latency is
unchanged. T6a.2 A solution for one seed is refused against the next. T6a.3
Verification is asymmetric — verifying costs the intro point orders of magnitude
less than solving costs the client. T6a.4 The intro point performs no asymmetric
cryptography before verifying the solution. T6a.5 Difficulty rises under
synthetic flood and returns to 0 afterwards. T6a.6 A client that solves at higher
effort is admitted ahead of one that solves at lower effort.

**Security considerations / failure modes.** A puzzle transfers cost to *every*
client, so a badly-tuned controller is a self-inflicted denial of service against
the users it protects — which is why `PuzzleDifficultyMin` is zero and why
falling slowly matters less than rising fast. The puzzle is also a fingerprint:
observed difficulty tells anyone watching the DHT that a given service is under
attack, which is information an attacker wants. Failure modes: memory-hard
parameters that exclude low-power devices; a difficulty controller that
oscillates; effort-ordered queueing that a well-funded attacker simply wins.

**Exit criteria.** E6a.1 Under a flood of 10⁴ introductions/s, an honest client
willing to spend 1 s of CPU still completes an introduction — falsified by
starvation. E6a.2 Intro-point CPU per rejected introduction is under 1 % of
client CPU per solution. E6a.3 With no attack in progress, measured introduction
latency is within 5 % of the no-puzzle baseline.

**Must NOT be built yet.** Payment-based admission — it collapses the anonymity
set into "who can pay" and belongs to P15's analysis, not here.

---

#### P12b — Operator diversity, the fourth rung `[BUILD NOW]`

**Objective.** Implement the §7.5 diversity ladder's fourth rung — operator, from
`NodeRegistry.Node.owner` — closing PAR-17.

**Why it matters, in §7.2's own words:** *"ASN diversity is not operator
diversity"* — a large cloud provider spans many ASNs, so a path that satisfies
distinct-/24 and distinct-ASN can still be three machines with one owner and one
subpoena.

| Field | Content |
|---|---|
| **Architecture** | The owner address is read from the bonded on-chain registry, verified through the existing light client, and added as a fourth `Domain` alongside prefix and ASN. |
| **Components** | `axon/peer`: `DomainOperator` added to the `Domain` ladder; `axon/registry`: owner lookup with proof. |
| **Protocols** | None new — the owner is already on chain and already bonded. |
| **Data structures** | `Annotation` gains `Operator [20]byte` and `OperatorSource`. |
| **APIs** | `SameDomain(a, b, DomainOperator)`; `DiversityConstraint{Domains: [...DomainOperator]}`. |
| **Depends on** | Phases: P3, P9, P12a. Code: `internal/axon/peer/annotate.go`, `internal/ethproof`, `proof-of-facilitation/contracts/NodeRegistry.sol`. |
| **Shortened by** | P3's `Domain` ladder, `SameDomain` and `DiversityConstraint` were built to be extended, and `ConstraintReport` already exists to report a constraint that could not be applied. |

**Parameters.**

| Name | Value | Rationale |
|---|---|---|
| `MaxPerOperatorPerPath` | 1 | the whole point of the rung |
| `MaxPerOperatorInReplicaSet` | 1 | matches §7.2's replica-set rule for /24 and ASN |
| `UnknownOperatorPolicy` | never treated as equal | identical to `ASNUnknown`'s rule — two unknowns are not known to be the same, and collapsing them would under-count diversity in the flattering direction |

**Tests.** T12b.1 Two relays with the same on-chain owner never appear in one
path. T12b.2 An unverifiable owner yields `OperatorSource = none` and is reported
through `ConstraintReport`, not silently substituted. T12b.3 A relay that changes
its declared owner without a chain transaction is refused. T12b.4 `SameDomain`
treats two unknown operators as distinct.

**Security considerations / failure modes.** An adversary can register many
owners — bonds are a price, not a barrier (§7.7) — so this rung raises the cost
of concentration rather than preventing it. It is nonetheless strictly stronger
than a self-declared family, because the owner carries a bond that can be
slashed. Failure modes: a chain outage making every operator unknown at once and
silently degrading the constraint to ASN-only; owner churn invalidating
annotations mid-epoch, exactly as §25's dynamic-IP note warns for ASN.

**Exit criteria.** E12b.1 Over 10⁴ path selections against a synthetic
population where one operator holds 30 % of relays, no path contains two of that
operator's relays — falsified by one. E12b.2 With the chain unreachable, the
degradation is reported through `ConstraintReport` and no path is claimed to be
operator-diverse.

**Must NOT be built yet.** Operator reputation. This rung is a diversity
constraint, not a trust judgement.

---

#### P22 — Variable path length and build indistinguishability `[BUILD NOW]`

**Objective.** Vary path length with a random component (PAR-18) and recover what
telescoping permits of build indistinguishability (PAR-19).

> **RULING on PAR-19.** Telescoping is retained. §8.4 chose it for forward
> secrecy per hop, no filler hazard, and failure attribution by position, and
> those reasons stand. **What is not retained is the pretence that it costs
> nothing:** hop *k* learns it is not the terminal, and the guard sees every
> extension. This phase recovers the recoverable part — length — and records the
> rest as an accepted cost of a chosen construction.

| Field | Content |
|---|---|
| **Architecture** | Path length is drawn per circuit from a distribution rather than fixed at 3, within `MaxHops`. The tag stack was designed so the cell format carries no length evidence (§8.3); that effort is wasted while every circuit is the same length, and this phase is what makes it pay. |
| **Components** | `axon/circuit`: length selection; `axon/guard`: pool composition across lengths. |
| **Protocols** | None new. |
| **Data structures** | Per-circuit `Length`. |
| **APIs** | `Build` already takes an explicit path; the *caller* (P12) draws its length. |
| **Depends on** | Phases: P5a, P12. Code: none. |
| **Shortened by** | I2P has varied tunnel length since inception. `MaxHops = 4` and the fixed tag-stack size already accommodate it — the format was built for this and never used it. |

**Parameters.**

| Name | Value | Rationale |
|---|---|---|
| `PathLengthMin` | 3 | never fewer: 2 hops lets the guard and terminal collude with no third party |
| `PathLengthMax` | 4 | `MaxHops`; the tag stack already reserves for it |
| `PathLengthDistribution` | 3 with p=0.7, 4 with p=0.3 | ours. Not uniform: a uniform draw at these bounds makes length a coin flip an observer can average out over a client's circuits |
| `LengthPerCircuit` | drawn independently per circuit | a per-client fixed length would be a client fingerprint, which is worse than a fixed network-wide length |

**Tests.** T22.1 Over 10⁴ circuits the observed length distribution matches the
configured one. T22.2 Length is drawn per circuit, not per client — two circuits
from one client differ in length at the expected rate. T22.3 Cells from a 3-hop
and a 4-hop circuit are byte-indistinguishable at every hop. T22.4 A relay at
position 2 of a 4-hop circuit cannot determine from any cell whether it is the
middle or the penultimate hop.

**Security considerations / failure modes.** Variable length costs latency on the
longer draws and complicates every latency budget in §8.4. It also interacts with
P12a's profiling: a 4-hop path has more chances to include a slow relay, so
naive weighting will drift toward 3 and silently undo the variation. Failure
modes: a distribution so skewed it is effectively fixed; length correlating with
traffic class, which would make the class observable; per-client length becoming
a fingerprint through pool reuse.

**Exit criteria.** E22.1 A relay holding 20 % of the network cannot infer its own
position better than chance from cell contents alone, over 10⁴ observations —
falsified by any edge. E22.2 The realised length distribution is within 2 % of
the configured one over 10⁴ builds. E22.3 P12a weighting does not shift the
realised distribution by more than 5 % — falsified by drift toward the cheaper
length.

**Must NOT be built yet.** Lengths above `MaxHops`, which would break the fixed
tag reservation and therefore leak length through capacity.

---

#### P23 — Forward-secret sessions above the circuit `[BUILD NOW]`

**Objective.** A ratcheting session between endpoints that survives circuit
death, closing PAR-20 and discharging R9's requirement that "streams are bound to
sessions, not circuits" — which no phase currently owns.

| Field | Content |
|---|---|
| **Architecture** | A session keyed between client and service, ratcheted forward per message, living above L4. Circuit death migrates the session's streams to a fresh circuit in the same pool without a new rendezvous and without a new public-key operation. |
| **Components** | `axon/session`: ratchet, session table, migration, replay window across circuits. |
| **Protocols** | Session establishment folded into the existing rendezvous handshake; resumption carries a session id and a ratchet step. |
| **Data structures** | `Session{ID, SendChain, RecvChain, Step, Streams[]}`. |
| **APIs** | `(*Session).Migrate(c *Circuit) error`; `(*Session).OpenStream(target) (Stream, error)`. |
| **Depends on** | Phases: P5a, P6. Code: `internal/axon/identity` (HKDF labels, which the ratchet reuses under its own `-vN` label). |
| **Shortened by** | I2P's ratcheting session design is public. AXON's HKDF label discipline and its blinding machinery already exist. |

**Parameters.**

| Name | Value | Rationale |
|---|---|---|
| `SessionLifetime` | 30 min | longer than a circuit (10 min), so migration is the normal case rather than the exception |
| `RatchetStepPerMessage` | true | forward secrecy within a session, not merely between sessions |
| `SessionResumptionWindow` | 60 s after circuit death | beyond this, a full rendezvous. Bounds how long a session id is a linkable token |
| `MaxStreamsPerSession` | 64 | matches §8.6's per-circuit stream cap |

**Tests.** T23.1 A session survives circuit death and resumes on a new circuit
without a rendezvous. T23.2 A compromised session key does not decrypt earlier
messages in the same session. T23.3 A session id observed on one circuit and
replayed on another is refused outside the resumption window. T23.4 Session state
is destroyed at `SessionLifetime` even if traffic continues.

**Security considerations / failure modes.** **A session id is a linkability
token by construction**: it is the thing that lets two circuits be recognised as
one conversation, which is the feature, and it means the rendezvous point of a
resumed session learns that two circuits belong together. `SessionResumptionWindow`
bounds that exposure and does not remove it. Failure modes: a session outliving
the isolation context that created it, joining streams §8.6 works to keep apart;
a ratchet that desynchronises under loss and falls back to a static key; session
state surviving a process restart it should not.

**Exit criteria.** E23.1 Over 10³ induced circuit deaths, sessions resume with no
rendezvous and no observable gap beyond one circuit build. E23.2 Recovered
session state at step *n* decrypts no message from step *n−1* — falsified by one.
E23.3 No session spans two isolation contexts — falsified by one.

**Must NOT be built yet.** Cross-device session resumption, which is a key-sync
problem and a much larger threat model.

---

#### P24 — Relay resource control and DoS mitigation `[BUILD NOW]`

**Objective.** Admission control, rate limiting and bandwidth caps at the relay,
closing PAR-21 and PAR-27. **§8.4 names circuit-table exhaustion at a popular
relay as a failure mode and nothing in the design addresses it.**

| Field | Content |
|---|---|
| **Architecture** | Four independent limiters, each with its own budget and its own refusal: per-source connection cap, circuit-creation token bucket, per-circuit cell rate, and an operator-set bandwidth rate/burst. Refusal is always cheaper for the relay than the request was for the attacker. |
| **Components** | `axon/limits`: the limiters, their accounting, and the refusal responses. |
| **Protocols** | `DESTROY(REASON_RESOURCE)` and a link-level refusal that does not require a handshake to be completed first. |
| **Data structures** | `Budget{Rate, Burst, Now}` per dimension; `SourceKey` derived from the /24 or /48, **never** from a full address, so the limiter itself does not become a per-client log. |
| **APIs** | `(*Limiter).Admit(kind, source) (bool, Reason)`. |
| **Depends on** | Phases: P2, P3. Code: `internal/axon/link` (`MaxCircuitsPerLink = 1000`, currently the only limit and the wrong shape — it is per link, so an attacker opens more links). |
| **Shortened by** | Tor's DoS subsystem gives the shape and the dimensions worth limiting. P3's prefix annotation gives the source key without retaining addresses. |

**Parameters.** Shape adopted; **values ours and explicitly unmeasured** — every
one is a starting point for E24.3.

| Name | Value | Rationale |
|---|---|---|
| `MaxConnectionsPerPrefix` | 8 | per /24 or /48, not per address, so a botnet in one prefix is one budget |
| `CircuitCreateRate` / `Burst` | 20 /s, 60 | per prefix |
| `MaxCircuitsPerRelay` | 65536 | the missing global cap; `MaxCircuitsPerLink` stays as a secondary bound |
| `CellRatePerCircuit` | class-dependent, from §8.6's windows | a circuit that exceeds its own window is misbehaving by definition |
| `BandwidthRate` / `Burst` | operator-set, no default | an operator who has not chosen a limit has not consented to a bill |

**Tests.** T24.1 Refusing a connection costs the relay less CPU than accepting
one — measured, not asserted. T24.2 A flood from one /24 does not degrade service
to other prefixes. T24.3 The limiter's source key is a prefix, never a full
address, by source audit — the limiter must not become the per-client log the
rest of the design refuses to keep. T24.4 A relay at `MaxCircuitsPerRelay` refuses
new circuits and keeps existing ones working. T24.5 Bandwidth limits are enforced
without dropping mid-cell.

**Security considerations / failure modes.** **Every limiter is a
denial-of-service tool aimed at honest users if it is wrong**, and a prefix-keyed
limiter punishes shared-address users — CGNAT clients in particular, which §6.5
already identifies as thousands of unrelated nodes behind one /24. That is a real
cost and it is accepted because the alternative is a relay that falls over. A
limiter is also an oracle: refusal timing tells an attacker where the budgets
are. Failure modes: limits so tight the network cannot grow into them; a global
cap that makes the largest honest relays the first to refuse; accounting that
retains per-address state.

**Exit criteria.** E24.1 Under a 10⁵ circuit/s flood from 100 prefixes, a relay
continues serving established circuits with no measurable added latency —
falsified by degradation. E24.2 Memory is bounded under sustained attack — no
monotone growth over 1 h. E24.3 Every parameter above is re-derived from
measurement on `axon-lab` and the measured values replace the guesses, with their
provenance recorded.

**Must NOT be built yet.** Reputation-based admission. A limiter that consults a
reputation score is a limiter an adversary can aim at a competitor.

---

#### P25 — Process hardening and privilege separation `[BUILD NOW]`

**Objective.** Bound what a relay compromise yields, closing PAR-22. **Today a
memory-safety bug or a logic flaw in any component yields the node's identity
keys, its bond, and every circuit it carries.**

| Field | Content |
|---|---|
| **Architecture** | Syscall filtering on platforms that support it, a non-privileged runtime user, no capability the node does not need, and long-term key material held in a separate address space from cell processing. |
| **Components** | `axon/sandbox`: platform filters and a fail-closed loader; key custody split. |
| **Protocols** | None. |
| **Data structures** | The filter policy, versioned with the binary. |
| **APIs** | `Sandbox(ctx, Policy) error`, called before the first network read and never after. |
| **Depends on** | Phases: P16. Code: `cmd/syndichan-node/main.go` startup path, `internal/axon/identity` `SaveSeed`/`LoadSeed` (which already refuses permissions wider than 0600 — the same instinct, one level up). |
| **Shortened by** | Tor's sandbox demonstrates both the design and its limits, including the honest one: a sandbox that must be disabled to use a common feature is a sandbox nobody runs. |

**Parameters.**

| Name | Value | Rationale |
|---|---|---|
| `SandboxDefault` | **on** | off-by-default hardening protects the operators who least need protecting |
| `SandboxFailure` | fail closed, refuse to start | a node that silently starts unsandboxed gives an operator a guarantee they do not have |
| `KeyCustody` | separate address space; cell processing never maps the long-term seed | limits what a parser bug reaches |

**Tests.** T25.1 With the sandbox active, an attempt to open an unexpected file
or socket fails. T25.2 The node refuses to start if the filter cannot be
installed. T25.3 The cell-processing path cannot read the identity seed, by
address-space audit. T25.4 Every syscall the node legitimately needs is in the
policy — verified by running the full test suite sandboxed, not by inspection.

**Security considerations / failure modes.** A sandbox is a bound on damage, not
a prevention of compromise, and claiming otherwise is the failure mode this
phase is most likely to produce in documentation. Platform coverage is uneven, so
some operators get less. Failure modes: a policy so tight that a legitimate
operation fails in production and operators disable it wholesale; a policy so
loose it bounds nothing; key separation that leaks through a shared allocator.

**Exit criteria.** E25.1 The full test suite passes with the sandbox active on
every supported platform — falsified by any test needing it disabled. E25.2 A
deliberately introduced file-read primitive in the cell path cannot reach the
identity seed. E25.3 Platforms without support are named in the release notes
rather than silently degraded.

**Must NOT be built yet.** Full-VM or container isolation as a *requirement*. It
raises the operator bar, and relay count is an anonymity property.

---

#### P26 — Client authorisation for services `[BUILD NOW]`

**Objective.** Let a service restrict itself to holders of an authorisation
secret, closing PAR-23. **The primitive is already built:**
`identity.BlindWithAuth` and `BlindSignerWithAuth` take a client-authorisation
secret and nothing calls them.

| Field | Content |
|---|---|
| **Architecture** | The descriptor's blinded key is derived with a client-auth secret mixed in, so only holders of the secret can compute the descriptor key at all — an unauthorised client cannot even find the descriptor, let alone decrypt it. The inner layer is additionally encrypted per authorised client. |
| **Components** | `axon/service`: auth-key management, per-client inner encryption, revocation by period. |
| **Protocols** | None new — it changes the key derivation, not the wire. |
| **Data structures** | `ClientAuth{ID, Secret[32], Added, Revoked}`. |
| **APIs** | `(*Service).Authorise(ClientAuth) error`; `(*Service).Revoke(id) error`. |
| **Depends on** | Phases: P6, P7. Code: `internal/axon/identity/blind.go`, already implemented and tested. |
| **Shortened by** | The blinding primitive, its label discipline and its tests exist. This phase is the layer that uses them. |

**Parameters.**

| Name | Value | Rationale |
|---|---|---|
| `AuthRevocationLatency` | one time period | revocation takes effect when the blinded key rotates; there is no faster path without an online check, which would defeat the offline property |
| `MaxAuthorisedClients` | 512 | ours; the inner layer is per-client and the descriptor is 8 KiB (§7.1) |

**Tests.** T26.1 A client without the secret cannot compute the descriptor key.
T26.2 A revoked client cannot compute it in the next period. T26.3 A revoked
client *can* still compute it in the current period — the honest limit, asserted
so nobody believes revocation is instant. T26.4 Descriptor size does not reveal
the number of authorised clients.

**Security considerations / failure modes.** Revocation is not instant and
cannot be without an online check that would break the design's offline property;
T26.3 exists so that limit is in the suite rather than in a footnote.
Distributing the secret is out of scope and is where this mechanism usually
fails in practice. Failure modes: a descriptor whose size counts the authorised
clients; auth secrets reused across services, linking them.

**Exit criteria.** E26.1 An adversary holding the service's public identity but
not the auth secret cannot locate the descriptor — falsified by any derivation
that succeeds. E26.2 Descriptor size is constant in the number of authorised
clients up to `MaxAuthorisedClients`.

**Must NOT be built yet.** An online authorisation check. It reintroduces a
liveness dependency and a per-client oracle.

---

### 23.7 Amendments to existing phases, second tranche

| Phase | Amendment | Closes |
|---|---|---|
| **P5** | **T5.9:** count structurally valid cells arriving in impossible states — `SENDME` for a closed stream, `DATA` for a stream that never opened, `TRUNCATED` for a hop already gone — and tear down the circuit past a threshold (`DropCellThreshold = 10`). §8.9 argues injection is detected and localised, which holds for cells that must be *decrypted* and says nothing about cells that are valid and merely unexpected. **A droppable event nobody counts is a signalling channel.** | PAR-28 |
| **P7** | Add liveness probing of idle pool spares (`SpareProbeInterval = 60 s`), so a pool of spares is not a pool of dead circuits. A spare that fails its probe is replaced before a user needs it, which is the entire reason to hold spares. | PAR-25 |
| **P18** | **RULING: obfuscation becomes the default transport for every node, not a mode for censored users.** I2P's posture, and the reason is exactly why PAR-06's bridges are insufficient on their own — a transport used only by the censored partitions the population into "normal" and "suspicious", and the partition is the signal. TLS 1.3 raw public keys (§6.1) is a comparatively rare extension and fingerprintable. The cost is throughput and complexity for every node including those who do not need it, and it is accepted because a minority-obfuscation design protects the minority worst. | PAR-26 |
| **Part VI** | Traffic splitting (sections 41–51) is registered as PAR-24 and is a **schedule** gap, not a design gap: the multipath substrate is specified in more depth than Tor deploys and none of it is built. No design change; the register records it so it is not mistaken for an oversight. | PAR-24 |

