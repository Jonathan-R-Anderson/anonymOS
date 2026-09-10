## 21. Testing strategy

**The finding that shapes this section: the existing suite already tests the
right way, and it cannot test the thing AXON adds.** Every adversarial test in
the codebase is a *two-party* test — one honest node, one node that lies, over a
real libp2p stream (`recall_lying_holder_test.go`). Anonymity properties are not
two-party properties. "No relay learns both ends" is a claim about what a *set*
of nodes jointly cannot reconstruct, and no unit test can express it. It needs a
multi-node environment with a scripted adversary and a deterministic seed. That
environment does not exist, and building it is the prerequisite for every
anonymity claim in §4, §8, §9 and §16.

The second finding: the strongest habit in this codebase is not its tests, it is
its **refusal to accept a green suite as evidence**.
`doc/p13-multipath-security-table.md` records ten deliberate mutations, one of
which survived and exposed a real missing property, and four independent
reviewers — each told to default to *refuted* — all returning fatal *after* the
suite was green. That practice transfers directly and is worth more than any tool.

### 21.1 What already exists

| Asset | Path | What it gives us |
|---|---|---|
| Adversarial unit pattern | `internal/p2p/recall_lying_holder_test.go` | A peer whose stream handler is replaced with one that lies in a specific, realistic way. The template for every "hop lies" test below. |
| Unknown ≠ favourable outcome | same file, `:64` | `TestAnUnverifiableDeletionClaimIsNotRecordedDeleted` — an unverifiable claim must not collapse into the answer we hoped for. The most reusable idea in the suite. |
| Structural tests | `internal/p2p/refusal_test.go:91` | `TestBothCandidateTiersConsultTheRefusalFilter` **reads `disperse.go` as text** and counts guard-call sites. Ugly, and it works. §21.4 rows 21–22 depend on the technique. |
| Input-validation regression | `internal/store/traversal_audit_test.go` | A 64-character traversal string that passed a length-only check and reached `os.Remove`. Pins that a length check is not a format check. |
| Fuzz precedent | `internal/gateway/frontend/sni_test.go:237` | `FuzzPeekSNI`, the only Go fuzz target in the tree. The pattern exists; the coverage does not. |
| Security property table | `doc/p13-multipath-security-table.md` | 34 rows, a four-value legend (ENFORCED / BY-CONSTRUCTION / PARTIAL / GAP), mutation results. §21.4 uses this form. |
| Deployment gate | `doc/deployment-gate.md` | Evidence carries a sample count, a method, a chain and an age, and the gate is *code* returning an error rather than a number. §21.8 copies the mechanism. |
| Local EVM devnet | `internal/channel/p15_devnet_test.go` | `P15_DEVNET=1 P15_RPC=http://127.0.0.1:8545`, real contracts in Hardhat, production `RPCChainReader` against them, and a test that **skips rather than falls back** when the devnet is absent. |
| Contract harness | `proof-of-facilitation/hardhat.config.ts` + `test/*.test.ts` | Hardhat 2.22, toolbox 5, ethers 6, `defaultNetwork: "hardhat"`, solc 0.8.24. Eleven suites already run here. |
| Release gate | `scripts/check-release.sh` | Credential-free, builds all seven targets and vets each GOOS/GOARCH. Written because a broken release matrix went unnoticed for weeks. |
| Fail-closed build tags | `SECURITY.md`, the `ethbls` tag | The tag *enables* BLS; its absence selects a stub whose every method returns `ErrNoBLSSupport`. A forgotten tag produces the build that refuses, never one that silently claims success. §21.3.2 reuses this exactly. |

**What must be replaced:** nothing. Two things must be *added* with no precedent
in the tree: the multi-node harness (§21.3) and the simulator (§21.7).

**One verified obstacle.** `internal/p2p/node.go:739` generates the node identity
with `crypto.GenerateEd25519Key(nil)` — a `nil` reader means `crypto/rand`. A
deterministic lab cannot re-derive a topology if key generation, path selection
and rebuild jitter read OS entropy directly. Injectable randomness is a
**source-code prerequisite of the test environment**, not a property of it.

### 21.2 The test pyramid

```text
 T6  NETWORK SIMULATION   10^3–10^5 nodes, no real packets. Statistics only.
 T5  LOCAL MULTI-NODE     24–200 real nodes, real packets, injected latency/
     (the lab, §21.3)     loss/NAT, scripted adversary, local EVM chain.
 T4  ADVERSARIAL UNIT     one honest party, one lying party, real stream.
 T3  CONFORMANCE          a frozen transcript reproduced byte for byte.
 T2  PROPERTY             round-trip, monotonicity, length-invariance.
 T1  KNOWN-ANSWER         RFC vectors for every primitive in §5.
```

| Tier | Runs | Clock | Proves | Cannot prove |
|---|---|---|---|---|
| T1 | every commit | < 5 s | The primitive matches its specification | That we call it correctly |
| T2 | every commit | < 60 s | The codec has no input-dependent behaviour | That the protocol above it is sound |
| T3 | every commit | < 10 s | Two implementations would interoperate | That the transcript itself is right |
| T4 | every commit | < 120 s | A named lie is caught by a named check | Anything about a third party |
| T5 | nightly, pre-gate | 5–40 min | End-to-end behaviour under a specific adversary | Behaviour at a scale the lab cannot reach |
| T6 | pre-gate | hours | Statistical anonymity properties over simulated time | Anything about the real implementation |

**T1** `[BUILD NOW]` — one file per primitive, vectors from the defining
document, no generation: Ed25519 (RFC 8032), X25519 (RFC 7748),
ChaCha20-Poly1305 (RFC 8439), HKDF-SHA256 (RFC 5869), BLAKE3 reference vectors.
Ed25519 key blinding has **no published vectors**; its derivation is pinned by a
committed local vector file labelled *self-referential* in its header — proving
we did not change the derivation, not that the derivation is correct.

**T2 — the properties that matter.**

| Property | Statement | Failure it catches |
|---|---|---|
| Cell length invariance | `len(encode(c)) == 1024` for **every** input — empty, maximum, one byte over | The entire traffic-analysis story of §16 rests on this line |
| Cell round-trip | `decode(encode(c)) == c` across all commands and flags | Field-order and endianness drift |
| Header independence | Payload changes never alter header bytes outside `len` | Accidental payload/header correlation |
| Onion commutativity | `peel³(wrap³(m)) == m`; wrong order fails totally | Key-schedule index errors |
| Tag reservation | Capacity is exactly `1024 − 16 − 16·H_max` regardless of actual hop count | A 2-hop circuit distinguishable from a 3-hop one |
| KDF separation | No two labels in the tree collide | Cross-context key reuse |
| Descriptor canonicality | `serialise` is byte-identical for equal inputs | Signature-over-non-canonical-encoding bugs |
| Counter ordering | Record `counter` comparison is a total order with no wraparound window | §21.4 row 13 |

Generated inputs come from a **seeded** generator committed with the test, so a
failure reproduces from the log line alone. `[BUILD NOW]`

**T3 — the conformance transcript** `[BUILD NOW]`. One file,
`testdata/transcript-v1.json`: a complete session (link handshake, CREATE, two
EXTENDs, one data cell each way, DESTROY), every field, intermediate key and
cell hex-encoded, produced by a checked-in generator from fixed seeds and a
fixed clock — never from a live run. A change to the transcript **is** a
protocol version change (§22.4) and the failing test says so. It is what makes a
second implementation possible and the cheapest insurance against wire drift.

**T4.** Direct extension of `recall_lying_holder_test.go`. Its rule transfers
verbatim: the party being asked is the party with the motive to lie, and the test
states which lie it pins and which harder adversary it does **not**.

### 21.3 The local multi-node test environment (`axonlab`)

`[BUILD NOW]` — no research risk, substantial engineering. ~3–5 kLOC plus scenarios.

```text
                    ┌────────────────────────────────────────┐
                    │ axonlab (cmd/axonlab, one process)     │
                    │ topology · seed · clock · adversary    │
                    │ scenario runner · assertion engine     │
                    └────┬──────────────────────────┬────────┘
             controls    │                          │  reads
                         ▼                          ▼
 ┌───────────────────────────────────────┐   ┌──────────────────────┐
 │ netns lab-r00…r23    relays           │   │ event bus            │
 │ netns lab-c00…c05    clients          │   │ unix socket, one     │
 │ netns lab-s00…s02    services         │   │ JSONL line per node  │
 │ netns lab-nat0…nat3  NAT boxes        │   │ event                │
 │ netns lab-chain      anvil            │   └──────────────────────┘
 └───────────────────────────────────────┘
        veth pairs into a bridge, one per link
        tc netem : delay, jitter, loss, reorder, duplicate
        tc tbf   : bandwidth ceiling
        nftables : NAT class per client
```

Two backends behind one interface: `netns` (default — `ip netns` + `veth` + `tc`
+ `nftables`, one `axond` per namespace, real kernel networking and real QUIC,
needs `CAP_NET_ADMIN`, Linux only) and `container` (Podman/Docker, same `tc` and
`nftables` inside, for macOS and the 200-node profile, ~10× the memory).

| Profile | Relays | Clients | Services | Note |
|---|---|---|---|---|
| `smoke` | 8 | 2 | 1 | Laptop-sized. **Not a DHT test** — see below. |
| `default` | 24 | 6 | 3 | The nightly. r=8 replication exercisable. |
| `large` | 200 | 20 | 10 | One 32 GB host. First profile where k=20 lookups behave like the real thing. |

**Stated once, and printed by the tool itself:** with `k=20` and `r=8`, a lab
below roughly 40 nodes cannot exercise Kademlia routing-table depth — every node
sits in every other node's first bucket. `smoke` is a functional test, not a DHT
test.

#### 21.3.1 Determinism

One 32-byte seed governs the run; everything derives from it.

```text
seed  (printed at the top of every run and in every failure message)
  ├─ HKDF(seed, "axonlab:identity:<node>")  → NodeIdentity, RoutingIdentity
  ├─ HKDF(seed, "axonlab:path:<node>")      → path-selection PRNG
  ├─ HKDF(seed, "axonlab:jitter:<node>")    → tunnel rebuild timing
  ├─ HKDF(seed, "axonlab:netem:<link>")     → loss/reorder decisions
  ├─ HKDF(seed, "axonlab:adversary")        → adversary schedule
  └─ HKDF(seed, "axonlab:srv:<epoch>")      → the lab's SRV
```

Three source-code prerequisites:

1. **No data-path package calls `crypto/rand`, `math/rand` or `time.Now()`
   directly.** Randomness and time arrive through injected interfaces. A
   structural test reads every package under `axon/` and fails on a direct
   import — the `refusal_test.go:91` technique. Epochs (24 h), guard rotation
   (45 d), descriptor lifetime (3 h) and the 12 h blinded-key overlap are
   otherwise untestable.
2. **The SRV source is injectable and fails closed.** Production uses the
   verified beacon RANDAO mix (R13); the lab derives it from the seed. Build tag
   `axonlab` selects the lab source; **its absence selects the real one**, and no
   configuration can make an untagged binary accept a seeded SRV. Same shape as
   `ethbls`, for the same reason.
3. `axonlab replay <run-id>` reads the seed and scenario from the run directory
   and reproduces the run. Every failure message ends with that command.

**What determinism does not survive.** Real QUIC timers and kernel scheduling
make two runs at one seed identical at the *protocol-decision* level and
different at the microsecond level. The assertion engine therefore asserts on
events and orderings only, and `axonlab` **refuses a scenario file containing a
bare duration assertion**. Timing budgets are a separate, explicitly
non-deterministic benchmark.

#### 21.3.2 Conditions and NAT injection

Per-link `tc` knobs, cross-producted into the standard matrix: one-way delay
{5, 40, 150, 400} ms; jitter {0, ±10, ±60} ms; loss {0, 0.5, 3, 15} %; reorder
{0, 2} %; duplicate {0, 1} %; bandwidth {100 M, 10 M, 1 M, 256 k}; MTU {1500,
1400, **1200**} — the last being the constitution's QUIC floor, the case that
must not silently fragment a cell.

Each client may sit behind a NAT namespace whose `nftables` ruleset implements
one class:

| Class | Rule | What it must break |
|---|---|---|
| `none` | routed, public | baseline |
| `full-cone` | endpoint-independent mapping and filtering | nothing |
| `restricted-cone` | address-restricted filtering | naive hole punching |
| `port-restricted` | address-and-port-restricted filtering | most hole punching |
| `symmetric` | endpoint-dependent mapping | **all** hole punching; forces relayed transport |
| `cgnat` | symmetric, external address shared with three other clients | port prediction, and any assumption that address ⇒ host |
| `blocked-udp` | outbound UDP dropped | QUIC entirely; forces the L1 TCP+TLS fallback |

`symmetric` and `blocked-udp` are mandatory in the pre-gate matrix. A node behind
`symmetric` must, per R3, end up **not relaying**, and a test asserts it never
advertised the capability.

#### 21.3.3 The scripted adversary

Adversarial nodes are ordinary `axond` builds with a lab-only interposer selected
by the `axonadv` tag, driven by a program:

```yaml
# scenarios/adv/guard-drops-after-establish.yaml
adversary:
  nodes: [r03, r07]                 # 2 of 24 relays = 8.3 %
  program:
    - at: 0s   ; do: honest
    - at: 120s ; do: drop    ; match: {cell: RELAY_DATA, dir: out, p: 0.10}
    - at: 300s ; do: delay   ; match: {cell: "*"} ; by: 800ms
    - at: 420s ; do: reorder ; match: {cell: "*"} ; window: 4
    - at: 540s ; do: replay  ; match: {cell: RELAY_EXTEND} ; count: 3
    - at: 600s ; do: corrupt ; match: {cell: "*", p: 0.02} ; bits: 1
    - at: 660s ; do: lie     ; as: capacity      ; claim: 10Gbit
    - at: 720s ; do: lie     ; as: descriptor    ; sign_with: wrong_key
    - at: 780s ; do: lie     ; as: dht_record    ; counter: lower
    - at: 840s ; do: lie     ; as: extend_target ; to: self
    - at: 900s ; do: eclipse ; target: c00       ; answer_all_lookups: true
```

| Verb | Effect | Attacks (§21.4 rows) |
|---|---|---|
| `drop` / `delay` / `reorder` | discard, hold, or buffer-and-permute matching cells | liveness, failover (R1), correlation resistance, sequence handling |
| `replay` / `corrupt` | re-emit a seen cell; flip bits after the tag was computed | 2, 3 |
| `lie: capacity` | advertise implausible bandwidth | 32; path weighting (R14) |
| `lie: descriptor` | publish a descriptor signed by the wrong key | 10 |
| `lie: dht_record` | serve a lower-counter record, or one not asked for | 13–15 |
| `lie: extend_target` | answer EXTEND with itself or an in-path node | 4, 5 |
| `lie: kadid` | claim a KadID inconsistent with `H(NodeIdentity‖SRV‖prefix)` | 16 |
| `lie: snapshot` | serve a snapshot whose root does not match the chain | 19 |
| `eclipse` | answer every lookup from a target with attacker peers | R14 partitioning; d=3 |
| `withhold` | accept a store, later deny holding it | the existing `recall_lying_holder` case at network scale |
| `sybil` | spawn N identities from one namespace | admission control (§15) |

Two rules, both from the existing culture:

- **An adversary that only misbehaves is a weak adversary.** Every program begins
  with an `honest` prefix, because the interesting attacks start after trust has
  been earned — which is what the scenario's filename records.
- **A scenario asserts what the adversary did NOT achieve.** "The circuit was
  rebuilt" is not the property. "The circuit was rebuilt **and the replacement
  excluded r03**" is.

#### 21.3.4 The local chain

`anvil` is the default (millisecond start, `--block-time`, deterministic accounts
from a seed-derived mnemonic, `anvil_setNextBlockTimestamp` for epoch alignment).
Hardhat remains the contract *test* runner — eleven suites already run there and
there is no reason to port them.

```text
make chain-up →  anvil --port 8545 --block-time 2 --mnemonic-seed <derived>
                 hardhat run deploy/00_phase0.ts       --network localhost
                 hardhat run deploy/10_axon_registry.ts --network localhost
                 → lab/chain/addresses.json, consumed by every node
```

The `P15_DEVNET=1 P15_RPC=http://127.0.0.1:8545` convention is kept verbatim,
including its most important property: `p15_devnet_test.go` **skips** when the
devnet is absent rather than substituting `NewFakeChain()`. Lab scenarios needing
the registry must skip for the same reason — a silent downgrade to a fake is
worse than no test.

The light client is the awkward case: a local anvil has no beacon chain, so
`internal/ethproof`'s sync-committee path cannot run against it. Consequences:
(a) the lab SRV is seed-derived, and the real SRV path is exercised only by the
existing mainnet harness (`live_mainnet_test.go`, `CHAIN_PROBE=1`); (b) chain
outage and stale-snapshot behaviour (R7) **is** lab-testable, by stopping anvil,
because that path needs no beacon chain.

#### 21.3.5 Make targets

```make
# environment
lab-up PROFILE=default SEED=random   # build, create netns, start nodes
lab-down                             # tear down namespaces, veths, nft rules
lab-status                           # per-node peers, tunnels, circuits
lab-shell NODE=r03                   # a shell inside one namespace
chain-up / chain-down                # anvil + contract deployment

# running
lab-scenario S=<name>                # one scenario, default profile
lab-matrix                           # every scenario × the condition matrix
lab-replay RUN=<run-id>              # re-run from the recorded seed
lab-soak HOURS=8                     # churn scenario on the virtual clock

# tiers
test-kat  test-prop  test-conformance  test-adversarial
test-integration                     # lab-matrix on the smoke profile
sim SIM=<name>

# assurance
fuzz TARGET=<name> DURATION=1h
fuzz-ci                              # every target, 60 s, committed corpus
mutate PKG=<pkg>                     # the catalogue; every mutation must die
gate                                 # §21.8; non-zero with the unmet terms
```

`lab-matrix` is the nightly. `gate` is the only target whose exit code may be
read as permission to deploy.

#### 21.3.6 Scenario scripts

The rungs are §24's to fix; these are named for what they exercise.

| Scenario | Nodes | Asserts |
|---|---|---|
| `s01-link` | 2 | QUIC + TLS 1.3 raw-public-key handshake; TCP fallback under `blocked-udp`; cell size constant |
| `s02-peerbook` | 8 | Bootstrap from a seed list; reachability classification; all seven NAT classes detected correctly |
| `s03-dht-store` | 24 | Signed record at r=8 across distinct /24s; the d=3 lookup paths are actually disjoint |
| `s04-circuit` | 24 | 3-hop circuit through 2 pinned guards; no hop repeated; extension refused to an in-path node |
| `s05-tunnel-pool` | 24 | 3+3+1 pools, 10-min lifetime, rebuild at 70 %, every tunnel starting at a pinned guard (R1) |
| `s06-rendezvous` | 24+3 | Descriptor under a blinded key, intro point contacted, RP joins, data flows, RP cannot read |
| `s07-session-survival` | 24 | A stream survives its carrier circuit's death (R9); guard killed mid-transfer |
| `s08-storage` | 24 | Object dispersed, a third of holders killed, repair restores r; holder cannot read plaintext |
| `s09-registry` | 24+chain | Name registered on anvil, snapshot anchored, resolution works; then stop anvil and assert *declared* staleness — not failure, not silent acceptance |
| `s10-adversary-relay` | 24 (2 hostile) | The full verb program; every §21.4 row marked T5 |
| `s11-eclipse` | 24 (8 hostile) | A 33 % adversary eclipsing one client's lookups; d=3 and KadID rotation |
| `s12-churn` | 24→40→16 | Join/leave for 8 virtual hours across an epoch boundary; KadID rotation loses no records |
| `s13-upgrade` | 24 mixed | Half at protocol v1, half at v2; §22.4's dual-stack window |
| `s14-i2p-dual` | 24 | Dual-stack transport (§22.6); both stacks up, one killed, sessions survive |

### 21.4 The security property table

In the form of `doc/p13-multipath-security-table.md`, compressed to one row per
property. **Every status is `PLANNED`.** That is the honest reading: this is a
specification for a test suite, not a report on one, and it should be reprinted
with real statuses as each phase lands. The p13 legend applies unchanged then.

`Class` — **P** must hold before any public deployment (§21.8); **B** best-effort,
measured not guaranteed.

| # | Invariant | Attack it stops | Enforced by | Test that proves it | Tier | Class |
|---|---|---|---|---|---|---|
| 1 | No single relay learns both circuit endpoints | One hostile hop deanonymises a client | Layered AEAD; a hop learns only predecessor and successor | `s04`: over 1000 circuits, each hostile relay's observed peer set excludes the far endpoint | T5 | **P** |
| 2 | A cell replayed at hop 1 is dropped | Replay to probe liveness or force duplicate delivery | Per-direction sequence window inside the AEAD associated data | `replay` at hop 1; the cell never reaches hop 2 and the circuit is not torn down twice | T4+T5 | **P** |
| 3 | A corrupted cell is detected at the first honest hop | Tagging: mark at one end, recognise at the other | Per-hop AEAD tag over the whole cell | `corrupt bits:1`; detection at the next hop and a DESTROY, not silent forwarding | T4+T5 | **P** |
| 4 | A circuit cannot be extended to a node already in the path | Path collapse; one relay seeing both sides | Client path constraint, re-checked at every EXTEND | `lie: extend_target to: in-path` | T4 | **P** |
| 5 | A circuit cannot be extended to a node the responder chooses | A relay steering the path into its own set | EXTEND names the target; the responder cannot substitute | `lie: extend_target to: self`; the client detects the identity mismatch on CREATED | T4 | **P** |
| 6 | No two hops share a /24, /48 or ASN | Same-operator path | Placement-engine diversity levels reused for relay selection | 10,000 sampled paths, zero violations | T2+T5 | **P** |
| 7 | Every tunnel in a pool starts at a pinned guard | I2P-style first-hop churn (R1) | The pool builder takes the guard as a parameter, not a choice | `s05` over 24 virtual hours | T5 | **P** |
| 8 | Guards do not rotate on failure | Guard discovery by induced failure | Rotation is time-driven (45 d) and failure-independent | `s10`: kill a guard repeatedly; the list is unchanged and the node falls to its second primary | T4+T5 | **P** |
| 9 | Cell length is 1024 B for every input | Length-based traffic classification | Fixed-size encoder | T2 property over generated payloads including boundary sizes | T2 | **P** |
| 10 | A descriptor signed by the wrong key is rejected | Service impersonation | Signature check against the period's blinded key | `lie: descriptor sign_with: wrong_key` | T4 | **P** |
| 11 | A descriptor outside its time period is rejected | Replay of an expired descriptor | Validity window with a bounded clock-skew allowance | T4 at the allowance boundary, ± 1 s | T4 | **P** |
| 12 | The storing node learns neither the domain nor the service | DHT operators enumerating services (R4c) | Blinded keys; encrypted descriptor body | `s06`: the storing node's state contains no unblinded identity, checked structurally by field type | T5 | **P** |
| 13 | A record with a lower counter never overwrites a higher one | Rollback of a rotated key or a withdrawn record | Counter comparison before store; total order, no wraparound | `lie: dht_record counter: lower` + the T2 ordering property | T2+T4 | **P** |
| 14 | An unverifiable record is never stored **or served** | Poisoning; and re-serving poison accepted before a fix | Verify on ingress **and** on egress | T4 on both paths — the egress half is the one that gets forgotten | T4 | **P** |
| 15 | The DHT key must derive from the record's own key material | Storing a valid record under an attacker-chosen key | Key/record binding at store time | T4: valid record, wrong key → refused | T4 | **P** |
| 16 | KadID is not freely chosen | Keyspace positioning to eclipse a target | `KadID = H(NodeIdentity‖SRV_epoch‖prefix)`, recomputed by every peer | `lie: kadid`; and `s11` for the eclipse case | T4+T5 | **P** |
| 17 | A resolver never accepts a record not signed by the DomainIdentity the chain names | Name hijack | Chain (or anchored snapshot) → DomainIdentity → record signature | `s09` with a record signed by a different Ed25519 key | T4+T5 | **P** |
| 18 | A stale snapshot is served **as stale**, never silently | A resolver answering confidently from a month-old view (R7) | Freshness bound in the manifest; the API returns the age | `s09` with anvil stopped and the clock advanced past the bound | T5 | **P** |
| 19 | A snapshot whose root does not match the chain anchor is refused | A malicious snapshot server | Root comparison against the anchored value | `lie: snapshot` | T4 | **P** |
| 20 | A chain outage degrades to stale, never to unauthenticated | Availability pressure producing a security downgrade | No code path accepts an unsigned record | `s09` + a structural test that no resolver function returns an unverified record | T4 | **P** |
| 21 | Client DHT lookups always traverse a circuit | Lookups revealing interest (R4b) | The DHT client takes a circuit, not a socket | Structural: the DHT client package must not import the transport dialer | T2 | **P** |
| 22 | No layer above L4 sees an IP address | Accidental leakage through an API type | L5+ APIs take destination handles, never `net.Addr` | Structural test over exported signatures in `axon/l5`…`axon/l8` | T2 | **P** |
| 23 | The rendezvous point cannot read the joined stream | RP as eavesdropper | End-to-end key established through the intro point, not with the RP | `s06`: the RP's observed plaintext is empty | T5 | **P** |
| 24 | The introduction point does not learn the service's tunnel endpoints | IP as a targeting oracle (R10) | The service reaches the IP through its own tunnel | `s06`: the IP's peer set does not intersect the service's node set | T5 | **P** |
| 25 | Intro requests without a valid PoW/token are dropped before reaching the service | The DoS lesson Tor learned (R10) | Puzzle check at the intro point | `s10` flooding at 100× the rate limit; service-side request rate stays bounded | T5 | **P** |
| 26 | A holder cannot read the plaintext it stores | Operator liability; Freenet's caching problem (R5) | The object key never leaves the origin; shards are ciphertext | Extends the existing store tests to the network case | T4 | **P** |
| 27 | No node caches plaintext it did not request | R5 | Opt-in cache holding only encrypted shards | Structural test on the cache write path + `s08` | T4 | **P** |
| 28 | A stream survives its circuit's death | R9; and a correlation signal if it did not | Session layer above circuits | `s07`: kill the guard mid-transfer; byte-exact delivery | T5 | **P** |
| 29 | Version negotiation cannot select below the local floor | Downgrade to a weak version | The floor is compiled in, not configured | T4 with a peer offering only v0 | T4 | **P** |
| 30 | An unknown circuit id is answered identically to a closed one | Circuit-existence oracle | One DESTROY path for both cases | T4 comparing responses byte for byte; timing is **not** asserted (§21.7) | T4 | B |
| 31 | Payment tokens are unlinkable from RoutingIdentity | R11 | Blind signatures; redemption off the data path | T2 unlinkability property over the token scheme | T2 | B |
| 32 | Self-reported capacity is bounded by bonded stake | R14 weighting abuse | The weight function clamps at the stake-derived ceiling | `lie: capacity claim: 10Gbit` at minimum stake; assert the weight used | T4+T5 | **P** |

Rows 30 and 31 are class **B** deliberately. Row 30's real property is timing
indistinguishability, which the lab cannot establish. Row 31's real property is
that a relay operator cannot correlate a redemption with a circuit, which needs
the accounting plane R11 defers out of v1.

### 21.5 Fuzzing

Go's native fuzzer, following `FuzzPeekSNI`. Corpus under `testdata/fuzz/`; every
crash found becomes a permanent seed.

| Target | Input | Oracle |
|---|---|---|
| `FuzzCellDecode` | arbitrary 1024 B | no panic; re-encode is 1024 B where decode succeeded |
| `FuzzCellDecodeShort` | any length ≠ 1024 | always rejected, never partially parsed |
| `FuzzRelayCommand` | decoded payload | no panic; unknown commands rejected with no state change |
| `FuzzDescriptorParse` | arbitrary bytes | no panic; parse→serialise→parse is a fixed point |
| `FuzzDHTRecord` | arbitrary bytes | no panic; nothing accepted without a verified signature |
| `FuzzOnionPeel` | cell + valid key schedule | no panic; failure is total, no partial plaintext emitted |
| `FuzzMultiaddrAxon` | address strings | no panic; nothing parses to a loopback or link-local target |
| `FuzzSnapshotManifest` | arbitrary bytes | no panic; nothing accepted without a matching root |
| `FuzzHandshake` | arbitrary handshake messages | no panic; no key material derived from a malformed message |

`fuzz-ci` runs 60 s per target on the committed corpus every commit — a
regression check, not a search. `make fuzz` is the search, before each gate.
**Coverage-guided fuzzing finds crashes, not protocol flaws.** No fuzz result is
evidence for any row in §21.4.

### 21.6 Mutation testing

The practice and the lesson both come from p13: nine of ten mutations were
caught, and the survivor was the one that mattered — the suite had never tried a
*wrong* preimage, so deleting the check changed nothing it observed.

**The rule: a test for a §21.4 row does not count until a deliberate defect
violating that row has been shown to fail it.** `make mutate` applies the
catalogue one at a time.

| Mutation | Row it must kill |
|---|---|
| Remove the replay window bound; accept a failed AEAD tag and continue | 2, 3 |
| Drop the in-path check from the EXTEND validator; return the responder's identity instead of comparing it | 4, 5 |
| Reduce diversity to /16; let the pool builder pick hop 1 freely | 6, 7 |
| Rotate guards on the third consecutive failure | 8 |
| Pad to `len(payload)` rounded up to 64 B | 9 |
| Compare counters with `>=` instead of `>`; verify records on ingress only | 13, 14 |
| Trust the peer's advertised KadID | 16 |
| Return the stale record without the age field | 18 |
| Fall back to the RPC's own snapshot when the anchor mismatches | 19 |
| Clamp capacity at a constant instead of at the stake ceiling | 32 |

Two disciplines from p13 worth more than the catalogue:

- **A test that recomputes the implementation's arithmetic is worthless.** p13
  discarded one that would have passed with the implementation deleted.
  Assertions must come from an independent source: a transcript, a hand-computed
  vector, or the adversary's own observation.
- **Some attacks need two of something.** p13's survivor needed two payments;
  every mutation written had perturbed one. The analogue here is that many rows
  need **two circuits, two epochs, or two clients** — a single-circuit test will
  pass while the property is absent.

### 21.7 Simulation, and its boundary

`[NEEDS RESEARCH]` — the simulator is straightforward; what it may conclude is not.

A discrete-event simulator, no real packets, no real crypto, a few hundred bytes
per node. 10^4 nodes over 10^3 simulated days is minutes of CPU.

**Measurable, with the model named:**

| Quantity | Model dependence |
|---|---|
| Path diversity (distinct ASN, /24 per path) | AS map snapshot; results move with it |
| Guard compromise over time, by adversary relay fraction | Guard policy only. **The cleanest result the simulator gives**, and the direct justification for 2 guards / 45 days |
| Circuit compromise (guard ∧ terminal hostile) | Path-selection weights |
| Eclipse probability vs. adversary fraction and KadID rotation | Kademlia model, SRV unpredictability |
| Descriptor availability under churn | The churn distribution — our weakest input |
| Repair convergence after losing X % of holders | Bandwidth model |
| Bonded stake required to reach a given relay fraction | The economics of §14, not in v1 |

**Not measurable, and the document must never imply otherwise:**

- **End-to-end correlation success against real traffic.** Correlation works on
  timing and volume signatures produced by real applications. Simulated traffic
  is generated by the model that scores it; a simulated correlation rate is a
  statement about the model.
- **Real churn and user behaviour.** Every published churn distribution comes
  from a different network with different incentives; availability figures
  inherit that uncertainty completely.
- **Actual AS-level path overlap.** Even with a real AS map, relay IP → observed
  Internet path is an approximation that changes daily.
- **Intersection attacks over months.** §7 already declines to defend against
  this; simulating it produces a number with no defensive meaning.
- **Implementation timing side channels** (row 30). The simulator has no
  constant-time behaviour to measure and the lab's timings are dominated by
  netem and scheduling.
- **The epistemic attack (R14).** A simulator has a global truth about the relay
  set; the real system's central difficulty is that no participant does. This is
  the property most likely to be accidentally "verified" by simulation and
  precisely the one it cannot see. `[UNSOLVED]`

Every simulator output prints its adversary fraction, churn model, AS map version
and seed. A number without those four is not a result.

### 21.8 The pre-deployment gate

Modelled on `doc/deployment-gate.md`, a working example of the right mechanism:
the gate is **code that returns an error rather than a number**, and it was
satisfied rather than waived. `make gate` exits non-zero and prints unmet terms.

| # | Term | Evidence | Supplier |
|---|---|---|---|
| 1 | Every class-**P** row has a passing test | Test names in the table resolving to real functions | Tooling |
| 2 | Every class-**P** row has been mutation-killed | `make mutate` output, one kill per row | Tooling |
| 3 | The conformance transcript matches at the released version | `test-conformance` green | Tooling |
| 4 | The full lab matrix passes on `default` | All seven NAT classes, all delay/loss points | Tooling |
| 5 | 8 CPU-hours per fuzz target, zero new crashes | Fuzz logs with corpus hash | Tooling |
| 6 | Independent adversarial review, defaulting to *refuted* | Four reviewers, four lenses, written findings (the p13 practice) | **People** |
| 7 | Every shipped anonymity claim names its adversary class | Audit against §7's vocabulary, plus a human read | **People** |
| 8 | A failing nightly reproduced from its seed | One recorded reproduction | Tooling |
| 9 | Reproducible build confirmed by ≥ 2 independent builders | Matching SHA-256 from different machines | **People** (§22.5) |
| 10 | The update channel's own gate (§22.5) is satisfied | Signature verification present and tested | Tooling |

Two refusals copied verbatim from the existing gate, because they are the ones
that get argued away:

- **An absence of events does not bound the severity of one.** `deployment-gate.md`
  refuses a reorg measurement of zero reorgs. The analogue: a lab matrix in which
  the adversary never succeeded is not evidence that it cannot, unless a
  deliberately weakened build was shown to fail. Hence terms 1 **and** 2 — one
  without the other is a tick in a box.
- **Evidence from another configuration does not validate this one.** A `smoke`
  result does not validate `default`, and no lab result validates a public
  network. Term 4 names the profile.

> **The rule.** No public deployment while any class-**P** row lacks both a
> passing test and a mutation kill. If a row cannot be tested, it is not a
> property this network has, and the claim comes out of the documentation rather
> than the gate being relaxed.

### 21.9 Decisions

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| A deterministic multi-node lab as a first-class deliverable | Anonymity properties are not two-party properties and cannot be unit-tested | Tor's `chutney` and Shadow; I2P has no comparable public harness | Seed-derived everything — identities, path choices, SRV — with `replay` as the primary debugging affordance | A pure simulator (cannot run the real code); testnet-only (not reproducible) | Lab-only code paths in the production tree. Mitigated by an `axonlab` build tag that fails closed, as `ethbls` does |
| Fail-closed lab build tag for the SRV | A build that accepts fake randomness is indistinguishable from one that does not | The project's own `ethbls` pattern | Applied to randomness rather than to a verifier | A config flag (settable in production); an env var (worse) | None identified; the failure mode is a lab that will not start |
| Conformance transcript as the wire's definition | Silent protocol drift; a second implementation being impossible | Tor's spec-plus-vectors practice | Generated from fixed seeds and checked in; changing it *is* a version bump | Prose spec alone; recording a live session (irreproducible) | A wrong transcript becomes authoritative. Only a second implementation catches that |
| Mutation kill required per security row | A green suite proves the tests ran, not that the checks exist | The project's own p13 practice | Made it a gate term rather than an exercise | Coverage percentage (measures execution, not assertion) | Catalogues drift; keeping it beside the table makes drift visible |
| Structural (source-reading) tests for layering rules | "No layer above L4 sees an IP" is an architectural rule no behavioural test enforces | The project's own `refusal_test.go:91` | Extended from one call-site count to import-graph and signature checks | A linter (another tool to keep configured); code review (does not run) | Brittle to refactoring, will produce false failures. Accepted: a false failure is cheap, a missed leak is not |
| Simulation restricted to a published list of quantities | Simulated anonymity numbers are the easiest place in this document to mislead | Tor's research literature, which is careful about this and often misquoted | An explicit "not measurable" list of equal length | Reporting simulator output as a system property | None; the risk is the list being dropped from a summary |

### What this section does NOT establish

- **No test here has been written.** Every §21.4 row is `PLANNED`, every scenario
  is a name, and the lab does not exist. This specifies a suite; it reports on none.
- **It does not establish that the class-P properties are achievable.** Rows 12,
  24, 25 and 32 depend on designs in §8, §9 and §15 that are not built, and a
  test cannot precede the property having an implementation.
- **It does not establish that the scripted adversary resembles a real one.** It
  executes the attacks we thought of. Every attack that mattered historically in
  Tor and I2P was one nobody had scripted.
- **It does not bound timing side channels.** Row 30 is class B for that reason,
  and neither the lab nor the simulator moves it.
- **Reproducibility holds only at the protocol-decision level.** A bug that
  manifests only at a specific microsecond timing will not reproduce from a seed.
- **Simulation results, if ever produced, are model statements.** The boundary
  list in §21.7 is not a caveat; it is the accurate description of those numbers.

---

## 22. Deployment, monitoring, versioning, and migration

**The finding that shapes this section: the migration off I2P has a seam, and it
is one function argument.** `internal/p2p/node.go:369` passes an I2P transport
into `libp2p.New` via `libp2p.Transport(...)`, alongside `libp2p.ListenAddrs`
with a garlic multiaddr. libp2p is already transport-plural: an AXON transport
implementing the same `transport.Transport` interface registers beside the I2P
one, and a node can carry both with no flag day, no fork, and no coordinated
cutover. Nine files import `internal/i2p`; only three do anything structural.

**The second finding is less comfortable.** The update channel —
`scripts/update-from-github.sh`, driven by `syndichan-node-update.timer` every
five minutes — fetches `refs/heads/main` from a GitHub URL over HTTPS, runs
`timeout 15m go test ./...` on whatever it fetched, builds, installs, and health
checks. It runs as `User=root`. **There is no signature verification anywhere in
it**: no `git verify-commit`, no `git verify-tag`, no detached signature, no
pinned key. The boundary is a GitHub account plus TLS. It also replaces itself on
a successful run, so one accepted commit owns every future update. That is the
highest-value target in the system and it defeats every other defence in this
document. §22.5.

### 22.1 What already exists

| Asset | Path | State |
|---|---|---|
| Container image | `storage-client/Dockerfile` | `golang:1.25-alpine` → `alpine:3.20`, `CGO_ENABLED=0`, `-trimpath -ldflags="-s -w"`, non-root UID 10001, `VOLUME /data`, `XDG_CONFIG_HOME=/data`, exposes 9000/9090 |
| systemd units | `packaging/systemd/syndichan-node.service`, `…-gateway-home.service`, `…-update.service`, `…-update.timer` | Hardened: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths=<install>`, `MemoryDenyWriteExecute`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `Restart=on-failure` with a 5-in-60 s burst limit, `TimeoutStopSec=75s` |
| Release build | `scripts/build-release.sh` | Seven targets (linux amd64/arm64/arm-GOARM6, darwin amd64/arm64, windows amd64/arm64), CGO-free, `-trimpath` |
| Release gate | `scripts/check-release.sh` | Builds the matrix, vets every GOOS/GOARCH, and documents that two builds of the *same commit* are byte-identical because Go embeds `vcs.revision`/`vcs.time` |
| Artefacts | `dist/*` with `dist/*.sha256` | Hashes exist. Signatures do not |
| Update channel | `scripts/update-from-github.sh` + timer | Bare mirror, `git archive` to temp, test, build, `-show-config` smoke, install, restart, `/readyz` poll, automatic rollback to `syndichan-node.previous` |
| First-run identity | `internal/p2p/node.go:731` | `loadOrCreateIdentity` creates `<data_dir>/p2p.key` as a libp2p Ed25519 key. The data dir also holds `i2p.destination` and `content.key` |
| Health measurement | `internal/monitor`, `internal/heartbeat` | `monitor.Client` fetches a **target list from a central URL** and POSTs results back; the heartbeat is an HTTPS POST to `syndichan.org` — per the Dockerfile comment, "the ONE deliberate exception to I2P-only networking" |
| Naming today | `internal/gateway/acme.go`, `registry.go`, `snapshot.go` | `autocert` with `HostWhitelist(hostname)`; a registry client that reserves `gw-<id>.syndichan.org` and waits for DNS; a signed snapshot manifest with a freshness state machine |

**What must be replaced:** the I2P transport (§22.6), the centralised measurement
path (§22.3), and the update channel's trust model (§22.5). The naming stack is
**not** replaced — it runs in parallel indefinitely (§22.7).

### 22.2 Node lifecycle and first-run keys

```text
 install ─► first run ─► bootstrap ─► participating ─► draining ─► stopped
                │            │             │              │
                │            │             │              └ withdraw descriptors,
                │            │             │                finish in-flight
                │            │             │                circuits, hand back
                │            │             │                shards
                │            │             └ relay capability advertised only
                │            │               after reachability is confirmed (R3)
                │            └ peers, SRV for the epoch, KadID
                └ generate identities; refuse to start if the data dir is not
                  writable or is world-readable
```

`TimeoutStopSec=75s` exists for the drain step and must grow: an AXON node has a
10-minute tunnel lifetime to respect. Recommend **180 s**, with a withdrawal
published at `SIGTERM` and new circuits refused immediately. `[BUILD NOW]`

| Identity | Generated | Stored | Note |
|---|---|---|---|
| NodeIdentity | first run | `<data>/node.ed25519`, 0600 | The existing `p2p.key` is already a libp2p Ed25519 key and must be **adopted**, not regenerated, or every node changes identity on upgrade |
| RoutingIdentity | per epoch | `<data>/routing/<epoch>.key`, previous retained for overlap | Ed25519 + X25519. Deletion after overlap **is** the forward-secrecy boundary: a real unlink, with no store that journals it elsewhere |
| KadID | derived, never stored | — | `H(NodeIdentity‖SRV_epoch‖prefix)` |
| ServiceIdentity | on `axond service create` | `<data>/services/<name>.ed25519` | Must be generatable **offline** and importable from day one, or nobody will ever do it |
| DomainIdentity | offline, by the operator | not on the node by default | Present only if the node publishes records itself |
| OwnerIdentity | never on the node | — | External wallet (R6) |
| PaymentIdentity | only if accounting is on | `<data>/payment.secp256k1` | Not in v1 (R11) |

Safe defaults, each the conservative choice and each of which will be argued about:

| Setting | Default | Why this way round |
|---|---|---|
| Relay capability | off until reachability is confirmed | R3. A NAT-bound node advertising relaying degrades everyone's paths |
| Exit to clearnet | off, not implemented in v1 | Out of scope, and not a conversation to have by default |
| Traffic class | `BULK` unless the caller declares `INTERACTIVE` | R2. The safer class must be the one you get by forgetting |
| Circuit length | 3 | §5. Length 2 requires an explicit non-anonymous declaration |
| Management UI / metrics | loopback only | Matches the existing `ui_listen` default |
| Opportunistic caching | off | R5 |
| DHT participation | on when reachable, off behind symmetric NAT | R4a |
| Chain RPC | none configured; resolution runs from the anchored snapshot | R7. A node with no RPC still resolves |
| Automatic updates | **off** in v1 | §22.5. Enabling this before the channel is signed would be worse than the status quo |

### 22.3 Monitoring that does not deanonymise

**The finding: current health measurement is a central authority, and R14 forbids
one.** `internal/monitor` fetches its target list from a configured URL and POSTs
results to it; `internal/heartbeat` POSTs presence to `syndichan.org` over
clearnet HTTPS. Both work, both are honest about what they are, and neither
survives into a network whose premise is that no such authority exists.

```text
 LOCAL      anything. Loopback only. The operator's own machine.
    │  quantise · aggregate · delay
    ▼
 PUBLISHED  a small, coarse, epoch-granular set in the signed relay descriptor.
    │  refuse
    ▼
 REPORTED   nothing. No node sends observations to any collector, because there
            is no collector.
```

**Local set** (loopback `/metrics`, unrestricted): `axon_circuits_active`,
`axon_circuit_build_seconds`, `axon_circuit_build_failures_total{reason}`,
`axon_cells_total{direction,command}`, `axon_tunnel_pool_size{role}`,
`axon_guard_state{slot}`, `axon_dht_lookup_seconds`, `axon_dht_records_stored`,
`axon_descriptor_publish_failures_total`, `axon_chain_rpc_failures_total`,
`axon_peer_count{reachable}`, `axon_i2p_*` during migration, and —
the single most important operator metric — `axon_snapshot_age_seconds` (R7).

**Published set** (in the epoch descriptor, signed, quantised):

| Field | Quantisation | Window | Why it is safe enough |
|---|---|---|---|
| `capacity_class` | 8 log-spaced buckets | epoch | R14 needs *some* capacity signal; 8 buckets carry ~3 bits |
| `uptime_class` | 4 buckets (< 1 d, < 1 w, < 1 m, ≥ 1 m) | epoch | Too coarse to fingerprint a restart |
| `capability_flags` | bitmap | epoch | Relay, DHT, storage, intro point |
| `protocol_versions` | set | epoch | §22.4 |
| `overload` | one bit | epoch | Backpressure |

**Forbidden, permanently:** any per-circuit or per-stream identifier in an
exported metric (correlation across vantage points); any timestamp finer than the
publication window (restart fingerprinting); published per-peer byte counters
(the traffic matrix *is* the deanonymisation); request logs of any kind,
including error logs carrying addresses (the commonest real-world leak); any
`.axon` name, service identity or descriptor key in a metric label (L7 data below
L4); client IP addresses in any form, **including hashed** (a hashed IP is an
IP); published per-relay latency percentiles (path fingerprinting); exact uptime
seconds; and any exported counter whose cardinality grows with traffic.

**Network health without a measurement authority.** `[UNSOLVED]` for the
network-wide case; `[BUILD NOW]` for everything local.

| Approach | Mechanism | Verdict |
|---|---|---|
| Stake-bounded self-report | R14: advertised capacity clamped by bonded stake | `[BUILD NOW]` — the v1 answer, and it is a *bound on the lie*, not a measurement. A funded adversary can still buy weight |
| Pairwise delivery receipts | Nodes sign receipts for traffic they forwarded; peers aggregate | `[NEEDS RESEARCH]` — the receipt graph *is* a traffic matrix. Publishing it deanonymises; not publishing makes it unverifiable. Unresolved anywhere |
| SRV-selected measurement committees | The epoch's shared randomness selects a rotating committee | `[NEEDS RESEARCH]` — a smaller authority, still an authority, Sybil-resistant only as far as bonding goes. Better than fixed bwauths on rotation, worse on accountability |
| Client-side noised aggregation | Clients report heavily noised aggregates | `[UNSOLVED]` — reporting needs a recipient, which is the authority we removed; and noise sufficient for privacy appears to destroy the signal at plausible client counts. Not analysed |

**The v1 position:** stake-bounded self-report plus client-local observation that
never leaves the client. A client learns which relays fail *it* and avoids them;
it tells no one. The consequence belongs in the operator documentation rather
than buried here: **the network has no global health view, nobody can tell you
whether it is healthy, and a slow decline would be invisible.** Tor knows its
network is healthy because nine authorities measure it. We refused that, and this
is the price.

### 22.4 Protocol versioning and upgrade

**Negotiation** `[BUILD NOW]`. Three deliberately separate levels:

```text
ALPN          "axon/1"       link level, one string, changes ~never
LINK VERSION  VERSIONS cell  cell format and handshake
SUBPROTOCOLS  per subsystem  Circuit=1-3, DHT=2, Desc=1-2, Reg=1
              version ranges advertised in the relay descriptor
```

Subprotocol versioning follows Tor's practice and is the right shape: a client
picks the highest mutually supported version *per subsystem*, which makes partial
rollout possible. Three rules: the version floor is **compiled in**, not
configured (row 29); the negotiated set is inside the transcript the handshake
authenticates, so a stripped VERSIONS cell breaks the handshake rather than
silently downgrading; and feature flags are **capability bits in the signed
descriptor**, not runtime configuration, so an advertised capability is one the
network can hold a node to.

**The flag-day problem.** A breaking change needs everyone to switch and nobody
can make them. The mechanism, which needs no authority:

```text
 ANNOUNCE   new release understands v_old and v_new, advertises both.  ≥ 30 d
            Nothing changes on the wire.
 ADOPT      nodes upgrade at their own pace. Readiness is observable:   ≥ 60 d
            the fraction of BONDED STAKE advertising v_new, computable
            by anyone from descriptors plus the registry.
 ACTIVATE   at epoch E, nodes prefer v_new. v_old still accepted.       ≥ 90 d
 SUNSET     at epoch E+S, v_old refused.
```

Minimum 180 days end to end, with 90 days between ACTIVATE and SUNSET — chosen as
2× the 45-day guard rotation so no client is carried across the change by a guard
set it never re-selected. That derivation is a choice, not a measurement.

**Chain-anchored protocol parameters — analysed, not adopted wholesale.**

| Design | Gives | Costs |
|---|---|---|
| A. Contract owner sets parameters | Trivial, unambiguous | A multisig that can change the protocol: a directory authority with extra steps. R14 refuses it |
| B. Stake-weighted vote among bonded nodes | Reuses `StakeVault`/`NodeRegistry`, which exist | Plutocracy; makes protocol control purchasable; puts governance on the chain plane's critical path, which R7 forbids |
| C. Chain as an announcement board | The contract records `(param, value, activation_epoch, announcer)` and **commands nothing**. Nodes activate only when their own reading of descriptor-advertised readiness crosses the threshold | Adds no power; adds *agreement about what was announced* |
| D. No chain; readiness from descriptors alone | Purest | Every client computes readiness from its own DHT view, and R14 says views can differ — two clients can disagree about whether activation happened |

**Recommendation: C**, not because the chain is authoritative but because it
closes D's specific hole. Under the partitioning attack (R14) an adversary
controlling a client's DHT view can make it believe an upgrade did or did not
activate. A chain-anchored announcement is the one piece of state every
participant can be shown to see identically. The chain says *what was announced
and when*; descriptors say *whether anyone adopted it*; activation needs both.
The chain never says "activate". **Who may announce is the unsolved part** —
recording an Ed25519 key in the contract records a maintainer, which is smaller
than a directory authority (an announcement without adoption does nothing) but is
not nothing. `[NEEDS RESEARCH]`

### 22.5 The software update channel

**A compromised update channel defeats every other defence in this document.**
Perfect onion routing, a verified light client and a fully tested DHT are worth
nothing to a node running an attacker's binary. This is the shortest path to
compromising the whole network and it deserves more scrutiny than the anonymity
layer.

| Property | Today (read from the source) | Required |
|---|---|---|
| Source authentication | GitHub TLS + branch head | Signed tags verified against a pinned, locally-held key set |
| Artefact authentication | `dist/*.sha256` | Detached signatures over the hashes, plus the hashes |
| Signing key | none | Offline, multi-holder, ≥ 2 of N per release |
| Untrusted code execution | `go test ./...` as root, **before any check** | Verify first; build unprivileged |
| Process privilege | `User=root` for the whole script | Split: unprivileged builder, privileged installer that only moves a verified file |
| Reproducibility | Documented and true per commit; never independently checked | ≥ 2 independent builders, matching hashes, published |
| Transparency | none | An append-only log a node can check for consistency |
| Rollback | Present and good: `.previous` restored on `/readyz` failure | Keep verbatim |
| Downgrade protection | none | Refuse an older version unless explicitly forced, loudly |
| Default | opt-in per install | Keep opt-in until the above lands |

Order of work, all ordinary engineering `[BUILD NOW]`:

```text
 1. Sign release tags; verify with `git verify-tag` against a locally-held key
    set. Refuse unsigned or unknown-key tags.
 2. Move `go test ./...` AFTER verification and out of the root context.
 3. Split the unit: builder (unprivileged) → verified artefact → installer
    (privileged; hash-check, install, restart, roll back, nothing else).
 4. Detached signatures over `dist/*.sha256`; installer verifies signature, then
    hash, then installs.
 5. Two independent builders reproduce each release. `check-release.sh` already
    establishes this is achievable, so it is process, not engineering.
 6. A transparency log of (version, commit, hashes, signatures), mirrored in the
    DHT as immutable content.
 7. Downgrade refusal, with a loud `--force-downgrade`.
```

**Step 6 matters most and is easiest to skip.** Signatures stop a forged release.
They do not stop a *targeted* one: a compromised or coerced signer can sign a
build served to one node. Only a log everyone reads catches that, and the DHT is
already there to hold it.

**What remains after all seven steps.** Maintainers can still push a malicious
release to everyone and it will verify. Reproducible builds let an independent
party confirm that the binary matches the source — not that the source is
honest. That residual is shared with every software distribution channel that
exists and should be stated plainly rather than mitigated in prose.

### 22.6 Migration off I2P

**No flag day is required.** The seam:

```text
internal/p2p/node.go:357-372
    session, _ := syndii2p.Open(ctx, samAddr, <data>/i2p.destination)
    local,   _ := syndii2p.Multiaddr(session.Base32())
    h, _ := libp2p.New(
        libp2p.Transport(func(u, rcmgr) (transport.Transport, error) {
            return syndii2p.NewTransport(u, rcmgr, session)   ◄── one option
        }),
        libp2p.ListenAddrs(local),                            ◄── one address
    )
```

`internal/i2p/transport.go` implements `Dial`, `Listen`, `CanDial`, `Protocols`
(`P_GARLIC32`), `Proxy() == true` and `Close`. An `axon.Transport` implementing
the same interface registers beside it. `IsI2PAddr` (`transport.go:50`) and the
`n.i2pOnly` check (`node.go:1061`) are the two places a transport-class predicate
already drives policy; both become three-valued.

Import sites to touch: `internal/p2p/node.go`, `internal/p2p/compute.go`,
`internal/p2p/storage_capacity.go`, `internal/dcs/transport.go`,
`cmd/syndichan-node/dcs.go`. Three more (`dcs/network.go`,
`dcs/network_attach.go`, `dcs/address.go`) already talk to *interfaces* satisfied
by `i2p.Session` rather than to the package — those are free, and whoever wrote
them made this migration cheaper.

```text
  stage   I2P      AXON     what is true
  ──────────────────────────────────────────────────────────────
  D0      listen   —        today
  D1      listen   listen   both addresses published; I2P preferred for dial
  D2      listen   listen   AXON preferred, I2P the fallback
  D3      listen   listen   AXON only for dial; I2P listen kept for laggards
  D4      —        listen   I2P removed from the build
```

Each stage is a config value — `transport_preference` ∈ {`i2p-only`, `i2p-first`,
`axon-first`, `axon-only`} — not a release. That is what makes rollback real
rather than aspirational: **set the preference back one stage and restart.** Both
listeners stay up through D3, so a rollback costs one restart and loses no state:
no identity changes, no descriptors expire, no shards move. D4 is the only
irreversible step, and only in the sense that reverting needs a release.

Both transports, both listen addresses and both peerbook entries run in parallel
for all of D1–D3. The DHT holds both address types per peer; the existing
multiaddr machinery already supports that. Cost: doubled connection state and a
second SAM session per node — acceptable, and measurable by `s14-i2p-dual`.

**Cutover order**, forced by what each layer needs:

```text
 1. AXON L1 transport works node to node        (s01)
 2. Peerbook carries both address types         (s02)
 3. DHT reachable over AXON                     (s03) ◄ first stage where an
                                                        AXON-only node is useful
 4. Circuits and tunnel pools                   (s04, s05)
 5. Storage disperse/recall over AXON           (s08)
 6. DCS container traffic                       (dcs/transport.go)
 7. Gateway/registry paths                      (§22.7)
 8. Heartbeat and monitor, or their removal     (§22.3)
```

Steps 1–3 ship while every production node is still `i2p-first`. That is what
makes this incremental: **the AXON stack can be running and carrying real traffic
between consenting nodes while remaining completely absent from the critical
path.**

**Criteria for entering D4** — gate terms, not aspirations:

| # | Criterion | Measured how |
|---|---|---|
| 1 | AXON dial success ≥ I2P dial success over 30 days on the same node set | Local counters, aggregated by an operator across their own fleet only |
| 2 | AXON p50 and p95 stream establishment within 2× of I2P's | Local histograms |
| 3 | Zero unexplained transport-attributable data-loss events in 30 days | The existing recall audit machinery |
| 4 | Every class-**P** row passing on the public network's own scenarios | §21.8 |
| 5 | `s14-i2p-dual` passes, including killing either stack mid-transfer | Lab |
| 6 | Fewer than 1 % of reachable peers advertising I2P-only addresses | DHT census — a *published* observation, so it obeys §22.3's quantisation |
| 7 | A D3→D2 rollback has been rehearsed on production, successfully | Operational drill |

Criterion 7 is the one people skip. A rollback path that has never been executed
is a hypothesis.

**What this does not remove.** `internal/i2p/sam.go` is 588 lines of working SAM
code and `transport.go` is 209. Deleting them is cheap; keeping them is also
cheap, and there is an argument for retaining I2P as a permanently supported
alternative transport where AXON is blocked and I2P is not. The constitution
forbids *depending* on I2P, not supporting it. Decide at D3, on evidence.

### 22.7 Migration of naming — DNS/ACME → `.axon`

**These run in parallel indefinitely. There is no cutover and there should not
be one.**

Today a volunteer gateway reserves `gw-<peer-id>.syndichan.org` through
`gateway/registry.go` (`ReserveHostname`, `WaitForReservedDNS`), obtains a
certificate with `autocert` pinned to that exact host
(`NewACMEManager` → `HostWhitelist`), and serves content. The README's warning
that a changed data directory produces "two different identities, two hostnames
and two certificates" is the clearest statement of how tightly identity, name and
certificate are bound today. The target is `<name>.axon` → DomainIdentity →
signed records (§13), with no DNS, no CA and no gateway operator in the trust
path.

```text
 DNS + ACME   "a browser with no AXON software can reach this"
 .axon        "a participant can reach this without trusting a CA, a registrar,
               or a gateway operator"
```

| Step | Change | Breaks anything? |
|---|---|---|
| N1 | Register the `.axon` name; publish records pointing at the same content | No — nothing consumes them yet |
| N2 | The existing gateway serves both: a clearnet request and an AXON request resolve to the same content | No |
| N3 | Publish the `.axon` name in the clearnet site's own metadata, so AXON-capable users discover the native path | No |
| N4 | Optionally retire the clearnet hostname, per site, at the owner's discretion | Only that site |

**The property that makes this safe: the `.axon` name and the DNS name are
different identities pointing at the same content, rather than one being derived
from the other.** No `.axon` name derives from a DNS name and no DNS name is a
claim about a `.axon` name. This avoids the failure every "blockchain DNS bridge"
has — a clearnet resolver becoming a trusted intermediary for a trust-minimised
name, reintroducing exactly the CA that `.axon` exists to remove. If a clearnet
gateway ever resolves `.axon` names *for* users, it must be documented as a
gateway serving *its own view*, never as resolution. `[BUILD NOW]` for N1–N4;
`[UNSOLVED]` for making a clearnet bridge trustworthy, which it cannot be.

### 22.8 Decisions

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Dual-stack transport migration with a config-level stage | Removing a transport dependency without a coordinated flag day | Neither Tor nor I2P has done this; the mechanism is libp2p's | Made the stage a config value, so rollback is a restart rather than a release | A hard cutover release (unrecoverable); a fork (splits the network) | Two transports means twice the attack surface for the whole dual-stack period — including I2P's, which we are trying to shed |
| Three-tier metrics with a hard "published" boundary | Operational visibility that does not become a traffic matrix | Tor publishes coarse relay statistics; I2P publishes almost nothing | Quantised to ~3 bits at epoch granularity, plus a written forbidden list | Prometheus federation (a collector is an authority); no metrics at all (unoperable) | Even 8 capacity buckets plus uptime class fingerprints a node over enough epochs. Not quantified here |
| Stake-bounded self-reported capacity as the v1 weighting input | Path weighting with no measurement authority (R14) | Tor's bandwidth authorities, refused | Replaced measurement with a *bound on the lie* | Bandwidth authorities (centralisation); pure self-report (unbounded lying) | Weight becomes purchasable; a funded adversary buys path probability directly |
| Chain as an announcement board for protocol activation | Two clients disagreeing about whether an upgrade activated, under a partitioning attack | Tor's consensus, refused; Bitcoin's version-bit signalling, adapted | The chain records and never commands; adoption is measured from descriptors | Contract-owner control (a directory authority); stake-weighted vote (purchasable protocol control) | Whoever may announce is a named party — smaller than an authority, not zero |
| Signed, reproducible, transparency-logged releases before automatic updates default on | A compromised update channel defeats everything else | Tor's signed releases are the closest model | Added a DHT-mirrored transparency log to catch *targeted* releases, which signatures alone cannot | Signatures alone (no targeting defence); TUF (correct, and a large dependency — reconsider if the log grows complex) | The signing keys become the highest-value target in the system, and key loss becomes a network-wide event |
| DNS/ACME and `.axon` in permanent parallel, never bridged as a trust path | Reachability for non-participants without contaminating the trust-minimised name | Tor's `.onion`, which coexists with DNS the same way | Stated explicitly that no clearnet resolver may be presented as `.axon` resolution | A clearnet `.axon` resolver (reintroduces the CA); a hard cutover (strands every existing user) | Two names per service is itself a linkage: the DNS name identifies an operator the `.axon` name did not |

### What this section does NOT establish

- **None of the migration has been performed.** The seam is real and was read
  from `node.go`; the AXON transport that plugs into it does not exist, and the
  four dual-stack stages have never been run, in the lab or anywhere else.
- **It does not establish that network health can be measured without an
  authority.** §22.3 offers four candidates and rejects or defers all four. The
  v1 answer is a bound on lying plus client-local observation, and the honest
  consequence — that nobody can tell whether the network is healthy — is a real
  operational regression against today's centralised heartbeat.
- **It does not establish who may announce a protocol parameter.** Option C
  removes the chain's authority but not the announcer's identity.
- **The 180-day upgrade window and 90-day sunset derive from the guard rotation
  period, not from adoption data.** No such data exists for this network; both
  numbers should move when it does.
- **The update-channel findings describe current code, not a hypothetical.**
  `update-from-github.sh` verifies no signature, runs fetched tests as root, and
  replaces itself. That is stated so it gets fixed, and until it is, automatic
  updates must stay opt-in.
- **Reproducible builds prove the binary matches the source, not that the source
  is honest.** No build reproducibility defends against a maintainer who is
  compromised or coerced. The transparency log narrows this to *targeted*
  attacks; it does not close it.

> **Objection to Constitution §5:** the 45-day guard rotation is used in §22.4 to
> derive the 90-day sunset window, which makes a traffic-analysis parameter
> load-bearing for an operational one. The coupling is defensible but accidental.
> If the guard rotation is later tuned for anonymity reasons, the upgrade window
> must not silently follow; the sunset window should be given its own derivation.
