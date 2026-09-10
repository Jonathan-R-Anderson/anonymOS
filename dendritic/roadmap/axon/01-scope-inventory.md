## 1. Scope, Objective, and What Already Exists

**The finding: the anonymity layer is the only large thing missing, and it is
attached to the rest of the system through five files and ten call sites.**

`internal/i2p` is 968 lines across 4 files. Exactly **5 of the 448 Go files** in
the module import it, **no test file imports it at all**, and every import
resolves to one of four exported symbols. Everything that a decentralised
overlay needs *underneath* an anonymity layer — a libp2p host, a Kademlia DHT,
an erasure-coded content store with audited recall and repair, a placement
planner, a mainnet-verified Ethereum light client, payment channels, and a
staking/reward contract suite — is already written, and most of it is already
tested against an adversary.

This is therefore not a design for a new network. It is a design for one new
layer (L4/L5), a hardening pass on three existing ones (L2/L3/L6), a naming
layer (L7) that has no prior art in this codebase at all, and the deletion of
one package.

### What already exists

Read for this section, in the module `github.com/syndichan/maniwani/storage-client`
(Go 1.25.12):

| File read | What it establishes |
|---|---|
| `README.md` | Operator-facing contract: I2P is mandatory, node refuses to start without SAM on `127.0.0.1:7656` and the HTTP proxy on `127.0.0.1:4444`. Gateway mode is ACME + SNI-splicing under `gw-<node-id>.syndichan.org`. |
| `SECURITY.md` | The whole trust-boundary statement, 149 lines. Named residual risks, including `GO-2024-3218`. |
| `go.mod` | 13 direct dependencies. **No I2P library** — SAM is implemented in-tree. |
| `internal/i2p/sam.go` (588 L), `transport.go` (209 L) | The SAM session and the libp2p `transport.Transport` wrapper. The seam. |
| `internal/p2p/node.go` (1775 L) | libp2p host + `go-libp2p-kad-dht` wiring, and the branch between `openI2PNode` and `openNode`. |
| `internal/store/store.go` (1221 L), `types.go` (58 L) | Manifest format, bbolt buckets, shard write path, capacity accounting. |
| `internal/placement/level.go` (240 L), `plan.go` (369 L) | Shard-to-peer assignment and pool levelling. Pure, no I/O. |
| `internal/gateway/protocol.go` (531 L), `identity.go` (61 L), `registry.go` (268 L) | Today's naming/ingress: probe challenge protocol, `p2p.key`-backed signer, credential-free DNS registration client. |
| `proof-of-facilitation/README.md` | Contract inventory and — importantly — the go-live checklist showing nothing is deployed. |
| `doc/trust-anchor.md`, `doc/ethereum-data-layer.md` | The light client, mainnet-verified, and the evidence arithmetic behind it. |

Measured scale, `find . -name '*.go' | xargs cat | wc -l`:

```text
total Go                        126,033 lines    448 files
non-test Go                      68,823 lines
test files                                       210 files

internal/channel                 43,914 lines    135 files
internal/ethproof                13,360 lines     49 files
internal/p2p                     10,230 lines     24 files
internal/dcs                      6,605 lines     35 files
internal/store                    5,893 lines     14 files
internal/gateway                  5,501 lines     27 files
internal/facilitation             4,812 lines     28 files
internal/placement                1,025 lines      4 files
internal/i2p                        968 lines      4 files   ← to be deleted
```

**What must be replaced:** `internal/i2p` in its entirety, and the `syndichan.org`
coordinator's role as lease issuer, bootstrap authority and DNS owner. Both are
addressed below.

---

### 1.1 The objective

The objective is to remove a single external dependency — I2P — without losing
the anonymity property it currently supplies, and to replace the one remaining
centralised control point — DNS and the `syndichan.org` coordinator — with a
chain-anchored namespace the operator does not own. Everything else in the
system is kept and hardened rather than rebuilt. The programme succeeds when a
node can be started with no I2P router installed, no DNS entry provisioned, and
no coordinator reachable, and still publish a service, resolve a name, retrieve
content, and be paid for relaying — with the anonymity claims stated in
quantified, falsifiable terms rather than inherited from somebody else's threat
model.

**Definition of the finished system, one sentence:** AXON is an
Internet-overlay infrastructure layer in which nodes build guard-constrained
onion circuits to reach services identified by self-certifying keys, publish and
retrieve signed records and erasure-coded content through a rotating-keyspace
DHT, and resolve `.axon` names through a locally verified, chain-anchored
registry snapshot — exposing exactly five operations (resolve, publish,
retrieve, tunnel, pay) and no applications.

---

### 1.2 What this project is NOT

| Excluded | Reason |
|---|---|
| **Applications of any kind** | The deliverable ends at the L8 Infrastructure API. No forum, chat, feed, media, market or exchange, notwithstanding that `maniwani` is an imageboard and that `internal/s3api` and `internal/dcs` exist. Those are *consumers* of the infrastructure and appear here only where they define an interface AXON must keep satisfying. |
| **Non-Internet transports** | No radio, LoRa, mesh, sneakernet, Bluetooth. L0 is the Internet. The existing code already assumes this — `internal/i2p/transport.go` is a UDP/TCP-free abstraction only because SAM is a loopback socket, not because the design contemplated other media. |
| **Any dependency on Tor, I2P or Freenet** | Not their code, not their networks, not their infrastructure, not their directory authorities, not their bootstrap. Referencing them as prior art is required throughout this document; linking against them is forbidden. The consequence is concrete: `internal/i2p` is deleted, `/garlic32` multiaddresses stop being minted, and the README's "First install I2P" instruction is removed rather than made optional. |
| **A new cryptographic construction** | Primitives are fixed. Where an existing file has invented one (`internal/channel/onion.go` deliberately builds a fixed-slot packet rather than Sphinx, and says so in its header comment), that choice is inspected in this document but is not extended to the transport plane by default. |
| **A consumer-grade "anonymous internet" claim** | The words *perfect*, *untraceable*, *unbreakable* and *impossible to block* do not appear in this roadmap. `SECURITY.md` already sets this tone — it names traffic timing, shard sizes and ISP-visible I2P usage as things I2P does *not* conceal. That register is preserved. |
| **Retaining the `syndichan.org` coordinator as an authority** | It currently issues store leases, publishes the bootstrap document, holds the Ed25519 key that authenticates leases, receives a direct (non-anonymised) five-minute heartbeat, and — through the now-deleted `gateway-controller` — owned the Name.com credentials. Every one of those is a single point of control. |

One sentence of out-of-scope illustration, marked as such: *an imageboard served
at `research.lab.axon` is what the API is for; how it is built is not this
document's concern.*

---

### 1.3 The inventory

Verified status column: **MAINNET** = exercised against Ethereum mainnet and
documented; **TESTED** = unit/integration tests in-tree; **RUNNING** = deployed
and operated per README; **WRITTEN** = code exists, no deployment evidence
found; **DOC-ONLY** = design document, no code read for this section.

| # | Component | Path | What it does | Verified | Verdict |
|---|---|---|---|---|---|
| 1 | libp2p host + Kademlia DHT | `internal/p2p/node.go:333-504` | `libp2p.New` with `NoTransports` + one injected transport; `dht.New(h, dht.Mode(dht.ModeAutoServer))`; protocol `/syndichan/storage/1.0.0` | RUNNING | **HARDEN** |
| 2 | Clearnet node constructor | `internal/p2p/node.go:405` `openNode` | Same host, TCP listen addrs, NAT port-map, hole punching. Called only from 5 test files over `/ip4/127.0.0.1/tcp/0` | TESTED | **RE-SCOPE** |
| 3 | I2P SAM session | `internal/i2p/sam.go` | `Open`, `Dial`, `Accept`, `AcceptStreamPort`, `DialPort`, `Base32`, session renewal, destination persistence in `i2p.destination` | RUNNING | **RETIRE** |
| 4 | I2P libp2p transport | `internal/i2p/transport.go` | Implements `transport.Transport` over `/garlic32`; `Proxy() == true` | RUNNING | **RETIRE** |
| 5 | Erasure-coded object store | `internal/store/store.go`, `types.go` | bbolt-backed; `Open(dir, dataShards, parityShards, chunkBytes, capacity)`; manifest v1; shard ID = SHA-256 hex | TESTED | **KEEP** |
| 6 | Dispersal / recall / repair / rebalance / drain | `internal/p2p/disperse.go` (26.8 KB), `recall.go` (28.7 KB), `repair.go` (17.2 KB), `rebalance.go` (27.0 KB), `internal/store/drain.go` | Five background loops started in `finishNode` under `storageEnabled` | TESTED | **KEEP** |
| 7 | Lying-holder audit | `internal/p2p/recall_lying_holder_test.go`, `internal/store/recall_failure_test.go` (13.1 KB) | Adversarial recall tests | TESTED | **KEEP** |
| 8 | Placement planner | `internal/placement/plan.go` | `Plan` never assigns two shards of one chunk to one peer; returns *fewer* assignments rather than doubling up; `DistinctHolders`, `SurvivesHolderLosses`, `RemotelyRecoverable` | TESTED | **HARDEN** |
| 9 | Pool levelling | `internal/placement/level.go` | Equal-*bytes* target, `LevelDeadband = 0.10`, `MinLevelMove = 64 MiB`, roles source/sink/balanced | TESTED | **KEEP** |
| 10 | Store-side placement ledger | `internal/store/placement.go` (28.2 KB) | Records intent; levelling reads measured disk instead, deliberately | TESTED | **KEEP** |
| 11 | Admission control | `internal/dcs/admission.go` (10.4 KB), `internal/p2p/challenge.go` (6.8 KB) | Lease-gated remote `STORE`, ≤1 h leases, nonce-replay and per-minute limits | TESTED | **RE-SCOPE** |
| 12 | Clearnet gateway | `internal/gateway/` (27 files) — `protocol.go`, `validator.go` (340 L), `snapshot.go` (598 L) | Probe challenge/response, ACME, SNI-splice forwarding, network-diversity probe quorum | RUNNING | **RE-SCOPE** |
| 13 | Gateway file identity | `internal/gateway/identity.go` | `LoadOrCreateFileIdentity` reads/creates the same `p2p.key` Ed25519 libp2p key without starting storage, I2P or DHT | TESTED | **KEEP** |
| 14 | DNS registry client | `internal/gateway/registry.go` | Signed, nonce-protected, **credential-free** statements to a central controller; `ReserveHostname`, `WaitForReservedDNS`, `PublishGatewayRegistration`, `MultiPublisher` | RUNNING | **REPLACE** |
| 15 | Gateway controller (DNS sync) | *(absent)* — 84 deleted paths under `gateway-controller/` in `dendritic.network` git status | Name.com DNS sync, reservations, SRV, rate limiting | RETIRED ALREADY | **REPLACE** |
| 16 | Ethereum light client | `internal/ethproof/` — `lightclient.go`, `beacon.go`, `bls.go`/`bls_stub.go`, `checkpoint.go`, `chainfollower.go` | BLS12-381 sync-committee verification, SSZ, `execution_branch` | **MAINNET** | **KEEP** |
| 17 | Ethereum state-proof verifier | `internal/ethproof/execution.go`, `headerrlp.go`, `index.go` | Merkle-Patricia account + storage proofs against a `stateRoot` | **MAINNET** | **KEEP** |
| 18 | Payment channels (SCPP/1) | `internal/channel/` (135 files, 43.9 kL); `doc/channel-payment-protocol.md` | HTLCs, multipath, watchtowers, mailbox, delegation | TESTED | **KEEP** |
| 19 | Payment onion | `internal/channel/onion.go` | `MaxHops = 3`, `SlotSize = 1024`, fixed-slot (explicitly *not* Sphinx), per-payment permuted slot order | TESTED | **RE-SCOPE** |
| 20 | Blinded invoices / commitments | `internal/channel/blinded.go`, `pedersen.go`, `atomic.go` | `BlindedInvoice`, `InvoiceLedger`, `Pedersen.Commit(value, blinding)`, `LockChain.BlindingFor(hop)` | TESTED | **RE-SCOPE** |
| 21 | PoF contracts | `proof-of-facilitation/contracts/` | `Treasury`, `AxonToken`, `NodeRegistry`, `StakeVault`, `EpochManager`, `RewardDistributor`, `DisputeManager`, `ServicePolicyRegistry` | WRITTEN (7 EVM tests) | **HARDEN** |
| 22 | PoF Go client | `internal/facilitation/` (28 files, 4.8 kL) | secp256k1 wallet, `nodeId = keccak256(ed25519 p2p key)`, registration digest byte-identical to `abi.encode`, ecrecover-compatible signature | TESTED | **KEEP** |
| 23 | PoF chain-access architecture | `proof-of-facilitation/README.md` §Architecture | Website-run pruned External Node + paymaster + relayer + indexer | DOC-ONLY | **REPLACE** |
| 24 | Traffic meter | `internal/traffic/traffic.go` | `Meter.AddBytes/AddRequest/Serve`, windowed | TESTED | **KEEP** |
| 25 | Container service (DCS) | `internal/dcs/` (35 files), `internal/compute*`, `internal/microvm` | Docker/microVM workloads over the overlay | TESTED | **OUT OF SCOPE** |
| 26 | S3 API | `internal/s3api/` | Local ingress for the store | RUNNING | **OUT OF SCOPE** |
| 27 | Direct heartbeat | `internal/p2p/node.go:392-401`, `heartbeatLoop` | Deliberately bypasses I2P; `Proxy: nil` to defeat `HTTP_PROXY` | RUNNING | **RETIRE** |

#### What "HARDEN" means, per row

Verdicts of KEEP, REPLACE, RETIRE and OUT OF SCOPE are self-explanatory. HARDEN
and RE-SCOPE are not, and vagueness there is how a roadmap becomes unactionable.

| Row | HARDEN / RE-SCOPE means exactly |
|---|---|
| 1 DHT | Replace freely-chosen libp2p peer IDs as keyspace positions with `KadID = H(NodeIdentity ‖ SRV_epoch ‖ network-prefix)`; add S/Kademlia disjoint lookup paths (d=3); split the keyspace into storage-content records and descriptor records with separate record types and validators; route all client lookups over a circuit. `GO-2024-3218` (provider-record hiding, no upstream fix) becomes a design constraint, not an advisory. |
| 2 clearnet ctor | Promote `openNode` from a test-only path to the *supported* substrate for `INTERACTIVE`/`BULK` circuits over QUIC, and delete `i2pOnly` as a boolean in favour of an explicit transport policy. Today it exists only so tests can avoid a SAM bridge; that accident is the migration's foundation. |
| 8 placement | Add real failure-domain diversity. Today `Plan` guarantees *peer distinctness only* — the package header records the bug it was written to fix (`peers[shardNumber % len(peers)]` made 6+3 behave like 6+1). It has no notion of subnet or ASN, and under I2P it structurally cannot: no node ever learns a peer's IP. Adding `/24`, `/48` and ASN levels is **new work**, not reuse. |
| 11 admission | Sever admission from the coordinator. Today a remote `STORE` requires a lease signed by a key learned over a fixed TLS bootstrap origin. Replace the lease issuer with bonded stake + local policy, keeping the lease *format*'s binding of object ID, shard ID, size, recipient and expiry. |
| 12 gateway | Keep the probe protocol (`ChallengeRequest`/`ChallengeResponse`/`ProbeResult`, signed, short-lived, identity-bound, diversity-quorum'd) as the **reachability oracle for relay descriptors**. Discard ACME, hostname reservation and SNI splicing. The anti-SSRF address validation in the prober is reused verbatim. |
| 19 payment onion | Read as prior art and as a source of test vectors; **do not** extend it to carry traffic. It is a per-payment packet with JSON-encoded hop instructions and AES slots, sized 3 × 1024 B; it has no stream semantics, no flow control, and no forward secrecy across a session. |
| 20 blinding | Feed the blind-signature/commitment machinery into the relay-payment token design rather than re-deriving it. |
| 21 PoF contracts | Nothing is deployed. Its own go-live checklist item 1 is *"A funded deployer key on Ethereum Sepolia"*, and item 2 is un-pinning `zksolc 1.5.7`. Treat as designed-and-unit-tested. |

#### Parameters read from the code, not assumed

| Parameter | Value | Source |
|---|---|---|
| Reed-Solomon data shards | **6** | `internal/config/config.go:572` |
| Reed-Solomon parity shards | **3** | `internal/config/config.go:573` |
| RS bounds enforced | `DataShards ≥ 2`, `ParityShards ≥ 1`, sum ≤ 64 | `config.go:817` |
| Chunk size | **1 MiB** (`1 << 20`) | `config.go:574` |
| Chunk size bounds | 64 KiB – 16 MiB | `config.go:820` |
| Manifest format version | 1 | `internal/store/types.go:5` |
| Min / max donated capacity | 64 MiB / 8 PiB | `internal/store/store.go:37-38` |
| Shard fetch timeout | 3 min | `store.go:45` |
| I2P dial timeout | 2 min | `internal/p2p/node.go:69` |
| Accept retry delay | 2 s | `internal/i2p/transport.go:155` |
| Levelling deadband | 0.10 | `internal/placement/level.go:42` |
| Minimum level move | 64 MiB | `level.go:46` |
| Payment onion hops / slot | 3 / 1024 B | `internal/channel/onion.go:45,57` |
| Gateway protocol version | 1 | `internal/gateway/protocol.go:18` |
| Object encryption | XChaCha20-Poly1305, 256-bit key, 192-bit nonce, AD binds bucket ‖ key ‖ index | `SECURITY.md` §Cryptography |
| Shard content ID | SHA-256 | `SECURITY.md`, `internal/placement/plan.go:47` |
| Storage stream protocol | `/syndichan/storage/1.0.0` | `internal/p2p/node.go:54` |

Two of these contradict assumptions in the Constitution; see the objections at
the end of this section.

---

### 1.4 The coupling measurement

`SECURITY.md` states the current position without hedging: *"The libp2p host
registers only the custom I2P transport and advertises only `/garlic32`
multiaddresses… There is no direct-network fallback."* Anonymity is entirely
outsourced. The question the roadmap turns on is how expensive it is to take it
back.

**Measured by grep, not estimated.**

```text
$ grep -rl 'storage-client/internal/i2p' --include=*.go .
cmd/syndichan-node/dcs.go
internal/dcs/transport.go
internal/p2p/compute.go
internal/p2p/node.go
internal/p2p/storage_capacity.go

5 files of 448.   0 of 210 test files.   10 references in total.
```

Every reference, with the symbol it uses:

| Site | Symbol | Role |
|---|---|---|
| `internal/p2p/node.go:357` | `i2p.Open(ctx, samAddr, <dataDir>/i2p.destination)` | Create/restore the session |
| `internal/p2p/node.go:361` | `i2p.Multiaddr(session.Base32())` | Derive the local listen address |
| `internal/p2p/node.go:370` | `i2p.NewTransport(upgrader, rcmgr, session)` | Inject into `libp2p.Transport(...)` |
| `internal/p2p/node.go:509` | `i2p.IsI2PAddr` | `AddrsFactory` filter — advertise nothing else |
| `internal/p2p/node.go:1061` | `i2p.IsI2PAddr` | Bootstrap-peer address filter under `n.i2pOnly` |
| `cmd/syndichan-node/dcs.go:413` | `i2p.Open` | Second session for the container service |
| `internal/dcs/transport.go:44` | `i2p.Multiaddr(worker.Destination)` | Address a DCS worker |
| `internal/p2p/compute.go:334` | `i2p.Multiaddr(destination)` | Address a compute peer |
| `internal/p2p/storage_capacity.go:145` | `i2p.Multiaddr(record.Destination)` | Address a capacity-record peer |
| `cmd/syndichan-node/dcs.go:135` | *(comment only)* | — |

The exported surface consumed by the rest of the tree is therefore **four
functions and one method**:

```go
func Open(ctx context.Context, samAddr, keyPath string) (*Session, error)
func Multiaddr(base32Host string) (ma.Multiaddr, error)
func IsI2PAddr(value ma.Multiaddr) bool
func NewTransport(u transport.Upgrader, r network.ResourceManager, s *Session) (*Transport, error)
func (s *Session) Base32() string
```

`Session.Dial`, `Accept`, `AcceptStreamPort`, `DialPort` and `Close` are used
only *inside* `internal/i2p`, by `transport.go`. They are not part of the seam.

**Why the seam is real and not an artefact of counting.** Three independent
pieces of evidence:

1. **The transport is injected, not assumed.** `node.go:366-375` builds the host
   with `libp2p.NoTransports` and one `libp2p.Transport(func(upgrader, rcmgr)
   (coretransport.Transport, error))` closure. `i2p.Transport` satisfies
   `transport.Transport` — `Dial`, `CanDial`, `Listen`, `Protocols`, `Proxy`,
   `Close` — and nothing above it knows what it is.
2. **A non-I2P constructor already exists and already works.** `openNode`
   (`node.go:405`) builds the same host over TCP, and `finishNode` — the DHT,
   the record validators, the five storage loops, the content key — is shared
   verbatim between the two. Five test files in `internal/p2p` run the complete
   dispersal/recall/repair stack over `/ip4/127.0.0.1/tcp/0`.
3. **No test file imports `internal/i2p`.** The entire 210-file test suite,
   including the adversarial recall tests, is already transport-agnostic. The
   migration cannot break tests that never depended on the thing being removed.

**Therefore: a native anonymity layer slots in behind the same seam.** The AXON
transport implements `transport.Transport`, mints its own multiaddr protocol in
place of `/garlic32`, and is passed to the same closure. `IsI2PAddr` becomes
`IsAxonAddr` in the `AddrsFactory` and the bootstrap filter. `i2p.Multiaddr` at
three call sites becomes the AXON address constructor. The `i2pOnly` boolean
threaded through `finishNode` becomes a transport-policy value.

**What the grep does not measure, and what actually costs.** Four things are
coupled to I2P without importing the package, and each is real work:

| Hidden coupling | Evidence | Consequence |
|---|---|---|
| Timeouts sized for I2P | `store.go:45` — `shardFetchTimeout` is 3 min, with a comment saying it *must* exceed `p2p.i2pDialTimeout` (2 min) because "the previous 20s ceiling expired mid-dial, which is why cross-node object reads failed" | Every latency budget in the storage layer is calibrated to a transport being deleted. They must be re-derived, not merely relaxed. |
| Idle-accept semantics | `transport.go:157-195` — a long comment recording that I2P routers close idle `STREAM ACCEPT` sockets after minutes, returning EOF; returning that to libp2p made "every node go deaf about six minutes after starting" | The AXON listener must define its own liveness contract explicitly rather than inherit a workaround. |
| No IP is ever visible | `SECURITY.md` — bootstrap and provider records containing IP, DNS, TCP, QUIC, WebSocket or relay components are *discarded* | Failure-domain diversity (§1.3 row 8), NAT traversal, and reachability probing have no inputs today. This is why placement is peer-distinct only. |
| Anonymity assumptions in prose | `SECURITY.md` names what I2P does *not* conceal: traffic timing, shard sizes, that the user runs I2P, that two peers advertise the same shard ID | Deleting I2P deletes the justification for every one of those statements. They must be re-derived against the adversary model in §4, not carried over. |

**Honest estimate of the mechanical migration**, distinct from the design work:
roughly 10 call sites, one 968-line package deleted, one `AddrsFactory`, one
boolean, and the re-derivation of two timeout constants. That is days, not
months. **The cost is entirely in the layer being written, not in attaching it.**

---

### 1.5 Gap analysis — what genuinely does not exist

Established by search, and reported as absence of evidence rather than as
certainty:

```text
$ grep -rli 'descriptor' --include=*.go .        →  0 files
$ grep -rliE '\.axon|axonregistry|tld' ...       →  0 files
$ grep -rli 'onion' --include=*.go .             →  internal/channel/onion.go only
                                                    (a per-payment packet, §1.3 row 19)
$ grep -rli 'rendezvous' --include=*.go .        →  4 files, all meaning a libp2p DHT
                                                    provider-record rendezvous CID
                                                    (internal/p2p/storage_capacity.go:33
                                                    storageRendezvousCID), NOT an
                                                    anonymity rendezvous point
```

That last result is a naming hazard, not a component: the word *rendezvous* is
already in use in this codebase for capability discovery. The identity taxonomy's
**rendezvous point (RP)** is a different thing, and the two must not collide in
new package names.

| Gap | Layer | Nothing exists because | Difficulty |
|---|---|---|---|
| **Onion circuit construction** — telescoping extend, per-hop X25519 + HKDF-SHA256 key schedule, ChaCha20-Poly1305 per-hop layers | L4 | Anonymity was outsourced | **[BUILD NOW]** |
| **Fixed-size cell format** — 1024 B, 16 B header, one QUIC stream per circuit | L4 | No cell abstraction of any kind in-tree | **[BUILD NOW]** |
| **Tunnel pools** — inbound/outbound roles, 10-min lifetime, rebuild at 70 %, guard-constrained | L4 | — | **[BUILD NOW]** |
| **Guard selection and persistence** — 2 primary per isolation context, 45-day rotation | L4 | — | **[BUILD NOW]** |
| **Path selection from a local view** — bandwidth-and-diversity weighting with no consensus document | L4 | `internal/placement/plan.go` is the closest analogue and is peer-distinct only | **[NEEDS RESEARCH]** |
| **Relay descriptors** — RoutingIdentity, epoch-scoped, published to the DHT | L3/L4 | Zero occurrences of `descriptor` | **[BUILD NOW]** |
| **Introduction points + rendezvous** — two-stage service contact | L5 | — | **[BUILD NOW]** |
| **Intro-point DoS puzzle** — PoW / token rate limiting | L5 | `internal/p2p/challenge.go` is a reachability challenge, not a client puzzle | **[NEEDS RESEARCH]** |
| **Ed25519 key blinding for descriptors** — 24 h period, 12 h overlap | L6 | `internal/channel/pedersen.go` blinds *values*, not public keys | **[BUILD NOW]** |
| **Blinded DHT records** — storing node learns neither domain nor service | L3 | The DHT stores plaintext-keyed provider records today | **[BUILD NOW]** |
| **KadID derivation and epoch rotation** — `H(NodeIdentity ‖ SRV_epoch ‖ prefix)` | L3 | libp2p peer IDs are the keyspace position and are freely chosen | **[BUILD NOW]** |
| **SRV from a verified RANDAO mix** | L3 | The light client can reach beacon state; nothing consumes it for randomness | **[BUILD NOW]** |
| **Session layer above circuits** — streams survive circuit death | L4/L6 | libp2p streams die with the connection | **[NEEDS RESEARCH]** |
| **Traffic classes** — `INTERACTIVE` vs `BULK`, padding policy | L4 | `internal/traffic` counts bytes; it does not shape them | **[NEEDS RESEARCH]** |
| **`.axon` TLD and name grammar** | L7 | Nothing | **[BUILD NOW]** |
| **`AxonRegistry` / `AxonResolverRegistry` contracts** | Chain | PoF contracts exist; no naming contract does | **[BUILD NOW]** |
| **Registry snapshot** — Merkle root over name → DomainIdentity, anchored on-chain, replicated in the DHT | L7 | `internal/gateway/snapshot.go` (598 L) is a *gateway* snapshot; the name is a collision, the mechanism is not reusable | **[BUILD NOW]** |
| **Resolver with declared freshness bound** | L7 | DNS does this today | **[BUILD NOW]** |
| **Commit–reveal registration** | Chain | — | **[BUILD NOW]** |
| **Relay accounting** — blind-signed unlinkable relay tokens, aggregate off-path redemption | Accounting | `blinded.go` + `pedersen.go` + PoF epochs are the substrate; the relay-specific token is not written | **[NEEDS RESEARCH]** |
| **Failure-domain diversity inputs** — subnet/ASN observation | L2 | Structurally impossible under I2P; `go-libp2p-asn-util v0.4.1` is present only as an indirect DHT dependency | **[BUILD NOW]** |
| **NAT traversal / reachability gating for relays** | L2 | `openNode` has `NATPortMap` + hole punching but is test-only; `internal/gateway` probing works only for public hosts | **[BUILD NOW]** |
| **Decentralised chain access** | Chain | PoF routes through a website-run External Node + paymaster + relayer | **[UNSOLVED]** |
| **Global abuse handling without re-centralisation** | Cross-cutting | Local denial lists exist (`bucketDenied`); a global blocklist is refused by ruling | **[UNSOLVED]** |
| **Partitioned / epistemic view of the relay set** | L3/L4 | No consensus document by ruling; nothing detects a divergent view | **[UNSOLVED]** |
| **Long-term intersection resistance** | L4 | Out of the adversary model by ruling | **[UNSOLVED]** |

Three dependencies already vendored make some of this cheaper than it looks:
`quic-go v0.59.1`, `lukechampine.com/blake3 v1.4.1` and
`go-libp2p-asn-util v0.4.1` are all present in `go.mod` today, all as indirect
dependencies of libp2p. The transport, the content hash and the ASN table needed
for diversity are already on disk.

---

### 1.6 Dependency graph — new work against existing work

```text
 LEGEND    [E] exists, keep         [H] exists, harden        [N] new
           [R] exists, replace      [X] delete

 L0/L1 ─────────────────────────────────────────────────────────────────────
   [X] internal/i2p (SAM + /garlic32) ..................... deleted
   [N] QUIC + TLS1.3 raw-public-key link ....... quic-go v0.59.1 already vendored
        │
        └─▶ implements transport.Transport ─┐
                                            │  (the seam: node.go:366-375)
 L2 ────────────────────────────────────────┼──────────────────────────────
   [N] peerbook / reachability / NAT         │
   [H] internal/gateway probe protocol ──────┤  reused as reachability oracle
   [N] subnet + ASN observation ─────────────┤  go-libp2p-asn-util already vendored
        │                                    │
 L3 ────┼────────────────────────────────────┼──────────────────────────────
   [H] libp2p host + kad-dht (node.go) ◀─────┘
        ├─[N] KadID = H(NodeIdentity ‖ SRV ‖ prefix)     ← needs SRV
        ├─[N] disjoint lookup paths (d=3)
        ├─[N] descriptor keyspace + record type
        └─[N] blinded record keys                        ← needs key blinding
        │
 L4 ────┼──────────────────────────────────────────────────────────────────
   [N] cells ──▶ [N] circuits ──▶ [N] tunnel pools ──▶ [N] guards
                       │                  │
                       │                  └─▶ [N] path selection
                       │                          ▲
                       │        [H] placement ────┘  diversity levels are NEW
                       │
                       └─▶ [N] session layer (streams survive circuit death)
        │
 L5 ────┼──────────────────────────────────────────────────────────────────
   [N] introduction points ──▶ [N] rendezvous ──▶ [N] intro PoW puzzle
        │
 L6 ────┼──────────────────────────────────────────────────────────────────
   [E] internal/store (RS 6+3, 1 MiB chunks, manifest v1)  ── unchanged
   [E] disperse / recall / repair / rebalance / drain      ── unchanged
   [N] service descriptors ──▶ needs Ed25519 key blinding
   [H] admission: coordinator lease ──▶ bonded stake + local policy
        │
 L7 ────┼──────────────────────────────────────────────────────────────────
   [R] DNS + ACME + gateway-controller ──▶ [N] .axon naming
                                             ├─[N] AxonRegistry (chain)
                                             ├─[N] registry snapshot (Merkle)
                                             └─[N] resolver + freshness bound
                                                    ▲
   [E] internal/ethproof light client ──────────────┘  MAINNET-VERIFIED
        │  provides: verified state root, RANDAO mix ──▶ SRV (L3)
        │
 CHAIN / ACCOUNTING PLANE (cross-cutting, off the request path) ───────────
   [H] PoF contracts (written, NOT deployed)
   [E] internal/facilitation (Go client)
   [E] internal/channel SCPP/1 (43.9 kL)
   [H] blinded.go + pedersen.go ──▶ [N] unlinkable relay tokens
   [R] website-run External Node + paymaster + relayer ──▶ [UNSOLVED]
```

**The two critical paths.** Everything at L5, L6-descriptors and L7-blinding
waits on the L4 circuit; the L4 circuit waits only on the QUIC link, which is a
vendored dependency. Separately, KadID rotation waits on SRV, which waits on the
light client — and the light client is finished and mainnet-verified. Those two
chains are independent, so L3 hardening and L4 construction can proceed in
parallel from day one.

**The one thing that blocks nothing.** The accounting plane. Ruling R11 puts the
economic layer outside v1, and the graph shows why that is affordable: no arrow
runs from the accounting plane into L1–L7. Storage admission is the only
consumer, and it can be satisfied by local policy until bonds exist.

---

### 1.7 Success criteria

Stated so that each can be falsified by a specific observation. A criterion that
cannot fail is not on this list.

| # | Criterion | Falsified by |
|---|---|---|
| S1 | `axond` starts, joins, publishes and retrieves with **no I2P router installed, no SAM bridge listening, and `internal/i2p` deleted from the tree** | The binary requiring a loopback SAM socket, or `grep -r internal/i2p` returning any hit |
| S2 | **No node learns another node's IP above L4.** A relay knows its neighbours' addresses; a client's stream layer, the DHT record layer and the resolver never receive one | A packet capture, or an audit of struct fields reachable from L5+, showing an IP or an `/ip4`,`/ip6` multiaddr component |
| S3 | The **existing storage test suite passes unmodified** over the AXON transport — including `recall_lying_holder_test.go` and `recall_failure_test.go` | Any test needing a change beyond its transport constructor |
| S4 | A service reachable **only** through introduction + rendezvous; the descriptor reveals no tunnel endpoint | Extracting a service tunnel endpoint from a published descriptor without contacting an intro point |
| S5 | A DHT node storing a descriptor **cannot name the domain or service** it stores, given the full record and its own keys | Recovering the unblinded ServiceIdentity or the `.axon` name from stored bytes |
| S6 | `alice.lab.axon` resolves from a **locally verified snapshot with no chain RPC reachable**, and the resolver reports its freshness bound | Resolution failing on chain outage, or succeeding without emitting a staleness figure |
| S7 | Registration is **commit–reveal**, and an observer of the mempool cannot predict the name before reveal | Recovering the name from the commit transaction |
| S8 | KadID is **not freely chosen**: a node cannot place itself adjacent to a target key without grinding NodeIdentity, and its position **changes every epoch** | Placing a node at a chosen keyspace position within one epoch at negligible cost |
| S9 | An adversary controlling **20 % of relays** does not deanonymise a `BULK` client above the rate predicted by the stated path-selection model, in simulation with published parameters | Simulation showing a materially higher compromise rate than the model predicts |
| S10 | The network **functions with zero payments**: no relay, storage or DHT operation requires a token to be spendable | Any data-path operation returning a payment-required error in a v1 build |
| S11 | A circuit stall **does not block other circuits on the same link** (one QUIC stream per circuit) | Measuring head-of-line blocking across circuits sharing a link |
| S12 | **Failure-domain diversity is enforced, not hoped for**: no two shards of a chunk, and no two hops of a circuit, share a `/24`, `/48` or ASN when alternatives exist | A placement or path decision violating it with candidates available |
| S13 | Every anonymity claim in the shipped documentation is **quantified and scoped**, and the words *perfect*, *untraceable*, *unbreakable*, *impossible to block* appear nowhere | A grep of the docs finding any of them, or an unquantified claim |
| S14 | The programme's residual risks — funding-graph linkage, epistemic partitioning, global abuse, intersection attacks — are **documented as unsolved**, not silently closed | A release note claiming any of them resolved without a mechanism |

S9 and S12 are the two that will be argued about, because they are the two that
require a model rather than a test. They are stated as falsifiable anyway: a
published parameter set and a published simulator make them falsifiable by a
third party, which is the point.

---

### 1.8 Decision table

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| **Delete `internal/i2p`; implement AXON transport behind the same `transport.Transport` seam** | Anonymity is outsourced to a network we do not control, cannot instrument, and whose threat model we inherit without having chosen it | I2P (the SAM/destination model being removed); Tor (the pluggable-transport idea of a swappable anonymising layer) | The seam already exists and is proven by `openNode`; we reuse it rather than restructure the host | (a) Keep I2P and build only naming — rejected, leaves the core dependency; (b) fork I2P — forbidden by scope; (c) new node from scratch — discards 68.8 kL of tested code | We now own every anonymity bug ourselves. I2P's ~20 years of operational hardening is discarded on day one, and our network will be far smaller, so the anonymity set shrinks before it grows |
| **Keep the erasure-coded store unchanged (RS 6+3, 1 MiB chunks)** | Freenet-role storage that is measurably better than Freenet's: explicit placement, audited recall, contracted repair | Freenet (distributed content) — but with erasure coding and explicit placement, which Freenet does not have | Availability is contracted and measured rather than emergent; holders hold ciphertext they cannot read | (a) Full replication — rejected on cost; (b) re-tune RS during migration — rejected, changes two variables at once | RS 6+3 tolerates 3 shard losses; with peer-distinct-only placement, three correlated losses in one datacentre are one failure, not three. Real until S12 holds |
| **Promote `openNode` from test-only to the supported substrate** | The migration needs a non-I2P host path that is already exercised | Neither — this is an artefact of the existing code | A test convenience becomes a product path, with the review that implies | Writing a fresh constructor — rejected, `finishNode` is already shared and a second constructor is a second place to drift | A path that was only ever run on loopback now faces the Internet. NAT, MTU, address filtering and hole punching are untested at scale |
| **Reuse the gateway probe protocol as the relay reachability oracle** | Relay descriptors must claim reachability; self-reports are worthless | Tor's bandwidth authorities, minus the authority | Probes are peer-run, signed, short-lived, identity-bound and require a network-diversity quorum; no central measurement authority (R14) | (a) Self-reported only — trivially gamed; (b) central measurement — rejected as re-centralisation | Probers see the probed node's IP and its uptime pattern. A large prober coalition builds a relay-availability map, which is exactly the input an eclipse attack wants |
| **Reuse the light client for SRV instead of a directory-authority commit-reveal** | Shared randomness with no central authority | Tor's SRV concept, with Tor's authorities removed | The mix is the beacon-chain RANDAO, verified locally against a sync-committee signature | (a) Directory authorities — refused; (b) node-run commit-reveal — Sybil-prone; (c) unverified RPC — trust-equivalent to no verification | RANDAO's last-revealer bias is real. Also: every AXON node now needs beacon-chain data, which is a liveness dependency on Ethereum for keyspace rotation |
| **Naming from a chain-anchored snapshot, not from live chain reads** | A chain outage, reorg or RPC censorship must not take the namespace down (R7) | None of the three — all three avoid naming or use a hashed key as the name | Resolution runs from a locally verified Merkle snapshot with a declared freshness bound; day-to-day records need no chain access | (a) Live `eth_call` per resolution — latency and censorship exposure; (b) Namecoin-style full chain — storage cost; (c) DNS — the thing being replaced | A stale snapshot serves a revoked or transferred name for up to the freshness bound. Making the bound short reintroduces the chain dependency it was meant to remove |
| **Treat PoF as designed-and-unit-tested, not deployed; keep v1 payment-free** | A roadmap that assumes deployed economics builds a network that cannot start | Freenet and I2P both work with zero payments; Tor works on donated relays | The accounting plane is explicitly off the critical path and off the v1 dependency graph | Making relay payment a v1 requirement — rejected: a network that needs an economy to bootstrap has no bootstrap | Without bonds, Sybil resistance in v1 rests on diversity heuristics alone. That is weaker than the bonded model this document eventually assumes, and the gap must not be narrated away |
| **Replace the website-run chain-access layer** | PoF's current architecture routes every node's chain access through one operator's External Node, paymaster and relayer | Nothing — this is inherited from the existing product, not from prior art | Nodes verify chain data locally with the light client that already exists | Keeping the relayer as the only path — rejected: it observes every registration and can censor any of them | Local verification needs a beacon endpoint, and `doc/trust-anchor.md` records that most checkpoint providers do **not** serve light-client routes. The dependency moves rather than disappearing; it is not yet solved |

---

### What this section does NOT establish

- **That the 10-call-site figure is the migration cost.** It is the *attachment*
  cost. The hidden couplings in §1.4 — timeouts calibrated to a 2-minute I2P
  dial, an accept loop written around I2P router behaviour, and a placement
  engine that has never seen an IP address — are unquantified here, and at least
  the third is a substantial piece of new work.
- **That the anonymity properties survive the swap.** Nothing in this section
  argues that a native layer will match what I2P provides today. The anonymity
  set of a new network is smaller than that of a mature one on day one, and this
  section does not model that cost. The adversary model in §4 and the tunnel
  design are where that must be earned.
- **That the existing code is correct, only that it exists and has tests.**
  "TESTED" in §1.3 means tests are present in-tree; no test was executed for this
  section, no coverage was measured, and no security review of `internal/store`,
  `internal/p2p` or `internal/channel` was performed.
- **That the two contradicting parameters are settled.** RS 6+3 and 1 MiB chunks
  are what the code does; whether they are what AXON should do is a decision for
  the storage and DHT sections, and the objections below flag the conflict rather
  than resolve it.
- **The encryption origin.** `SECURITY.md` says the local S3 gateway is trusted
  with plaintext "because it is the encryption origin"; `internal/store/types.go`
  says "the node no longer encrypts objects: content arrives already encrypted by
  the coordinator". These two statements are not obviously compatible, and the
  correct one determines who can read stored content. It must be resolved by
  reading the write path in `store.go:265-390`, which this section did not do.
- **Any timeline, ordering or effort estimate.** The dependency graph in §1.6
  states what blocks what. It does not state how long anything takes, and the
  "days, not months" figure in §1.4 covers the mechanical re-wiring only.

---

> **Objection to Constitution §5 (content chunk size):** the table gives
> "Content chunk 256 KiB" with the note "Confirm against existing
> `internal/store` before asserting". Confirmed, and it does not match. The
> configured default is **1 MiB** (`internal/config/config.go:574`,
> `ChunkBytes: 1 << 20`), validated to a range of 64 KiB–16 MiB
> (`config.go:820`). `internal/placement/plan.go`'s header comment also
> describes the unit as "every 1 MiB chunk". Either §5 should read 1 MiB, or the
> change from 1 MiB to 256 KiB must be justified as a deliberate re-tune with a
> migration path for existing manifests (`FormatVersion = 1`,
> `internal/store/types.go:5`). Erasure coding, as instructed, was read rather
> than invented: **6 data + 3 parity** (`config.go:572-573`).

> **Objection to Constitution §0 and §5 (placement diversity):** §0 describes
> `internal/placement` as "Diversity-aware shard placement — diversity levels"
> and §5 says DHT replication should "reuse the existing placement engine's
> diversity levels" for distinct /24, /48 and ASN. **Those levels do not
> exist.** `plan.go` guarantees only that no two shards of one chunk go to the
> same *peer*; `level.go` is capacity levelling (source/sink/balanced against a
> byte target), not failure-domain diversity. Neither package contains any
> notion of subnet, prefix or ASN, and under the current I2P-only transport it
> could not: `SECURITY.md` records that records containing IP components are
> discarded, so no node ever observes a peer's address. Subnet/ASN diversity is
> **new work**, and the roadmap should budget for it rather than describe it as
> reuse. `go-libp2p-asn-util v0.4.1` is already vendored (indirect), which helps.

> **Objection to Constitution §0 (Proof of Facilitation status):** §0 states the
> PoF machinery is "already written and unit-tested", which is accurate, but the
> roadmap must not read it as available. `proof-of-facilitation/README.md`'s own
> go-live checklist begins with "A funded deployer key on Ethereum Sepolia" and
> item 2 is un-pinning an unavailable `zksolc 1.5.7`. Nothing is deployed to any
> network. Further, its decided architecture routes node chain access through a
> **website-run** External Node, paymaster and relayer — a single operator who
> observes and can censor every registration. Reusing PoF as the accounting
> substrate therefore imports a centralisation that AXON exists to remove, and
> a ruling is needed on whether the relayer path is permitted in v1.

> **Objection to Constitution §3 (terminology collision):** "rendezvous point"
> is already in use in this codebase with a different meaning —
> `internal/p2p/storage_capacity.go:33` `storageRendezvousCID()` and
> `internal/place.RendezvousSeed` denote a DHT provider-record key for
> capability discovery, not an anonymity rendezvous. New package and symbol
> names must disambiguate, or reviewers will read the wrong mechanism into
> existing code. The same hazard applies to "snapshot":
> `internal/gateway/snapshot.go` (598 lines) is unrelated to the L7 registry
> snapshot of ruling R7.
