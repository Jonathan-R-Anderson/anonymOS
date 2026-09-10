## 2. Where Tor, I2P, Freenet, DHTs and Blockchains Contradict Each Other

### The finding that shapes everything

The four systems AXON draws from are not four halves of one design. Each made a
different bet on the same small set of trade-offs, and several of those bets are
mutually exclusive at the level of arithmetic, not taste. Taking Tor's guards
*and* I2P's tunnel churn does not give the guard property with I2P's failover; it
gives I2P's cumulative first-hop exposure plus the pretence of Tor's guarantee.
Taking Freenet's caching *and* a structured DHT does not give locality with
determinism; it gives a repair loop that cannot tell a missing replica from a
cached copy, and therefore cannot tell a healthy object from a doomed one.

So the useful work here is subtraction. Twenty-one conflicts are enumerated
below — R1–R14 fixed by Constitution §6, plus C15–C21 found while writing. Each
gets: what the conflict is, a concrete failure, the ruling, and what the ruling
costs. A ruling that costs nothing resolved nothing; every entry has a cost line
and several of the costs are severe.

### What already exists

The existing node has already answered several of these, and reading it is how we
know which ones bite.

| Existing artefact | Where | What it already settles |
|---|---|---|
| I2P SAM transport, `/garlic32/`-only multiaddrs | `internal/i2p/sam.go`, `transport.go` | Anonymity is outsourced. The dependency this project exists to remove. |
| `i2pDialTimeout = 2 min` vs `directDialTimeout = 10 s` | `internal/p2p/node.go:69–70` | The latency price of anonymity, already paid, already in the code as a 12× ratio. |
| `manifestFetchTimeout = 3 min`, `challengeTimeout = 90 s` | `internal/p2p/objmanifest.go:26`, `challenge.go:33` | Every control-plane timeout is sized for anonymous transport, not the Internet. |
| Kademlia, `dht.Mode(dht.ModeAutoServer)`, namespaced validators | `internal/p2p/node.go:438`; `gateway/dht.go`, `dcs/dht.go`, `p2p/objmanifest.go` | Structured, deterministic placement was chosen over Freenet-style routing years ago. |
| Reed–Solomon 6+3, 1 MiB chunks | `internal/config/config.go:572–574`, bounds `:817–820` | Availability is contracted arithmetic, not emergent. |
| `DurableRemoteHolders(d,p) = d+1` | `internal/store/placement.go:140–148` | The durability threshold is explicit: 7 distinct holders for 6+3. |
| `placement.Plan` — no two shards of a chunk on one peer | `internal/placement/plan.go` | One failure domain only. **No /24, /48 or ASN awareness exists**; grep returns nothing. |
| Lying-holder audit | `internal/p2p/recall_lying_holder_test.go` | "Unknown must not collapse into the outcome we were hoping for." |
| Signed bootstrap document from one URL | `internal/config/config.go:22`, `internal/bootstrap/bootstrap.go` | The network view is a directory authority with N=1. |
| `EpochManager.randomness` from a privileged aggregator | `proof-of-facilitation/contracts/EpochManager.sol` | Shared randomness today is a trusted input. |
| `NodeRegistry`: wallet ↔ `keccak256(p2pPublicKey)`, `endpointCommitment` | `proof-of-facilitation/contracts/NodeRegistry.sol` | A permanent public payer↔node link — and a precedent for keeping raw endpoints off-chain. |

**What must be replaced:** `internal/i2p` entirely; the single-URL bootstrap as
the source of network view; aggregator-supplied epoch randomness as the source of
SRV; and `SHA-256(bucket ‖ 0x00 ‖ key)` unsigned manifest keys
(`internal/p2p/objmanifest.go:31–34`) as the content naming contract.

### 2.1 The conflict matrix

| # | Conflict | Tor | I2P | Freenet | AXON ruling |
|---|---|---|---|---|---|
| R1 | First hop | Few pinned long-lived guards | Many short-lived tunnels, churn by design | No first-hop concept | Guard-constrained pools: hop 1 pinned to 2 guards, hops 2..n churn on the 10-min schedule |
| R2 | Latency vs. analysis | Low latency, correlation accepted | Low latency, correlation accepted | Store-and-forward, high latency | Two declared classes: `INTERACTIVE` (correlatable, stated) and `BULK` (batched, padded) |
| R3 | Who relays | Dedicated relays | Everyone relays | Everyone stores and routes | Capability-advertised, reachability-gated, opt-in; anonymity never *depends* on relaying |
| R4 | Directory vs. anonymity | Authorities publish; clients fetch directly | Floodfill peers answer queries | Routing table is the network | Membership public via `KadID`; **client lookups always over a circuit**; blinded descriptor keys; separate keyspaces |
| R5 | Caching what you carry | Relays cache nothing | Tunnels cache nothing | Cache along the path | No plaintext cached that was not requested; opt-in encrypted-shard caching; local blocklists only |
| R6 | Ownership vs. anonymity | Address is a key hash, unowned | Destination is a key hash, unowned | Keys are unowned | On-chain ownership, `OwnerIdentity ≠ DomainIdentity`, commit–reveal; funding linkage unsolved |
| R7 | Authority liveness | Consensus must be fresh | Netdb eventually consistent | No authority | Chain on a slow path; resolution from a verified snapshot with a declared freshness bound |
| R8 | Availability | n/a | n/a | Best-effort; forgetting is a feature | Contracted: replication, repair loop, audits, declared tiers, no permanence promise |
| R9 | What an address names | A circuit-reachable service | A destination with lease sets | A content key | Destinations; circuits disposable; a session layer survives circuit death |
| R10 | Contact establishment | Intro points then rendezvous | Lease set contacted directly | n/a | Both stages; intro rate-limited by a PoW/token puzzle |
| R11 | Paying for carriage | Volunteer | Volunteer | Volunteer | No identified payment on the data path; blind tokens redeemed off-path; **no economy in v1** |
| R12 | Link multiplexing | Many circuits per TCP conn; head-of-line blocking | Per-tunnel messages | n/a | One QUIC stream per circuit per link |
| R13 | Shared randomness | Authority commit-reveal | None | None | Beacon RANDAO mix at a fixed slot, verified through the existing light client |
| R14 | Consistent view | 9 authorities sign a consensus | Floodfill netdb, Sybil-prone | Not needed | No consensus document; local weighting from bonded stake and own receipts; partitioning `[UNSOLVED]` |
| C15 | Placement | n/a | n/a | Cache-along-path, probabilistic | Deterministic placement; caching is a read accelerator, never counted as a replica |
| C16 | Packet crypto | Per-hop layered AEAD on fixed cells | Garlic bundling of multiple cloves | n/a | Layered AEAD on 1024 B cells; bundling only end-to-end, never hop-visible |
| C17 | Immutability vs. revocation | Address unrevocable | Destination unrevocable | Content keys immutable | Two record classes — content immutable, naming versioned and revocable — never one keyspace |
| C18 | DHT speed vs. lookup privacy | Directory fetch cheap, non-anonymous | Netdb over tunnels (slow) | Routing is the lookup | Lookups over circuits, budgeted L×RTT, aggressive validity-window caching |
| C19 | Chain consistency vs. partition | n/a | n/a | n/a | Overlay runs indefinitely with no chain; chain authoritative only for ownership *changes*, only eventually |
| C20 | Weighted paths vs. no authority | Bandwidth authorities measure | Self-report + local profiling | n/a | Self-report **bounded** by bonded stake and by receipts the client itself holds |
| C21 | Coding vs. probabilistic availability | n/a | n/a | Availability is a probability | k-of-n with active repair; the threshold is a cliff and the repair budget is sized against the cliff |

---

### 2.2 R1 — Guards vs. tunnel-pool churn

**Conflict.** Tor pins a first hop for months: with hostile fraction *f*, a client
either drew a hostile guard (probability ≈ *f*, compromised for the period) or did
not (safe at position 1 for the period). I2P rebuilds a pool of tunnels every ten
minutes, buying failover and load balance. Churn is precisely what the guard
defends against; both cannot hold.

**Failure.** At *f* = 0.05, an I2P-style pool (3 in + 3 out + spares, 10-minute
lifetime) is ≈1,152 builds/day. P(no build ever starts hostile) = 0.95^1152 ≈
2×10⁻²⁶. The user is not "probably fine"; the user is certainly first-hopped by
the adversary within a day. With 2 pinned guards, P(a hostile first hop at all) =
1 − 0.95² = 9.75 %, decided once per 45-day rotation.
*(Arithmetic under an independence assumption, not a measurement.)*

**Ruling (R1).** Pools are guard-constrained: every tunnel begins at one of that
isolation context's **2 primary guards**; hops 2..n churn on the 10-minute
schedule. 45-day rotation, 90-day list.

**Cost.** Two fixed observation points per context for 45 days, so guard
discovery gets easier the longer a guard is pinned; correlated failure when both
primaries are down, and the fallback (temporarily extending the list) is itself
fingerprintable; worse load balance than I2P, since a popular service concentrates
on its guards. `[BUILD NOW]` mechanism, `[NEEDS RESEARCH]` outage policy — which
is where every guard design leaks.

### 2.3 R2 — Low latency vs. traffic analysis

**Conflict.** Tor and I2P are low-latency and therefore correlatable: an observer
at both ends matches streams by timing and volume, and layered encryption does
not touch either. Freenet destroys the timing relationship and is unusable
interactively. One class must pick, and then lies to half its users.

**Failure.** A single class described as "anonymous" is used to fetch a 4 MB
object from a watched service. The signature — 4 MB, in a burst, at time T —
arrives at both observation points within the circuit RTT. Nothing in the protocol
told the user this would happen.

**Ruling (R2).** Two classes, chosen at the L8 API as a required argument:

| | `INTERACTIVE` | `BULK` |
|---|---|---|
| Cover traffic | none | padding to a schedule |
| Batching | none | at the sender |
| Latency | circuit RTT | seconds to minutes |
| Correlation resistance | **none claimed** | partial, quantified per schedule |
| Used by | request/response streams | dispersal, repair, descriptor publication, token redemption |

**Cost.** Two stacks to test; a user-visible choice users will get wrong; and a
permanent obligation to repeat that `INTERACTIVE` is correlatable (§4.5).

### 2.4 R3 — Everyone relays vs. dedicated relays

**Conflict.** Universal relaying grows capacity with users and offers operators
deniability; a NAT-bound laptop cannot deliver it, a relaying client has a much
larger attack surface, and the deniability argument is weak when the adversary
can distinguish origination from forwarding.

**Failure.** Anonymity is claimed to derive from relaying. The guard sees which
streams originate locally, because an originated circuit begins with a
creation cell the client built and a forwarded one does not. The claimed
protection was never real, and it was load-bearing.

**Ruling (R3).** Relaying is a descriptor-advertised capability gated on measured
reachability: opt-in, defaulted on for reachable nodes, off for NAT-bound
clients. **Anonymity must not depend on relaying.** Relaying is credited by the
accounting plane (`ServiceType` in `internal/facilitation/receipt.go`,
`CAP_*` bits in `NodeRegistry.sol`).

**Cost.** Capacity grows with volunteers, not users — Tor's scaling problem, now
ours. Relays are enumerable and therefore blockable. Deniability is stated as a
side effect for operators, never as protection for clients.

### 2.5 R4 — DHT participation vs. anonymity

**Conflict.** A DHT works because members are enumerable at known keyspace
positions. Anonymity works because interest is unobservable.

**Failure.** A client resolves `alice.lab.axon` by asking nodes near
`H("alice.lab.axon")` from its own IP. The nearest node is the adversary's — one node
covers one name. It now holds every IP that ever looked up that name, with
timestamps. No circuit was compromised and no cryptography was broken.

**Ruling (R4).** Four binding parts: (a) membership is public and keyed by
`KadID = H(NodeIdentity ‖ SRV_epoch ‖ network-prefix)`, not freely chosen;
(b) **client lookups always traverse a circuit** — no direct fast path, not for
first run, not for bootstrap; (c) descriptors sit under **blinded** keys (Ed25519
scalar blinding by a period factor, as in Tor's v3 onion-service design), so a
storing node learns neither name nor service and cannot selectively refuse what it
cannot recognise; (d) content and descriptor DHTs share code but are separate
keyspaces with separate record types and validators — the existing node already
runs three namespaces on one `record.NamespacedValidator`.

**Cost.** Every lookup pays a circuit (C18 has the arithmetic; it is the largest
latency line in the design). Blinding also means a storing node cannot rate-limit
per-service abuse, because it cannot link two periods of the same service.

### 2.6 R5 — Freenet-style caching vs. operator risk

**Conflict.** Path caching makes popular content fast and unpopular content
vanish, and fills an operator's disk with material they never requested and
cannot enumerate. Tor and I2P relays cache nothing and can say so.

**Failure.** A volunteer's node caches plaintext-recoverable content it never
requested. The volunteer cannot list it, cannot selectively remove it, and cannot
explain it. The network loses that volunteer and the ten who read about it.

**Ruling (R5).** No node caches plaintext it did not request. Stored objects are
encrypted so the holder cannot read them without the key carried by the
`ContentIdentity` capability. Path caching is opt-in per node and only of
encrypted shards. Local blocklists by shard/object ID are supported; a global
blocklist is refused as re-centralisation.

**Where the code is.** `internal/store` performs no encryption at all —
`types.go:22–27` says content arrives already encrypted, and there is no
`chacha`/`Seal` call in the package; shards are SHA-256-addressed ciphertext
(`store.go:399`). So holders already hold unreadable bytes, but the encryption
boundary lives *outside* the module (`SECURITY.md` still calls the local S3
gateway "the encryption origin"). AXON must move that boundary into the client and
make it a protocol property. `[BUILD NOW]`

**Cost.** Abuse handling. A network that cannot read what it stores cannot
moderate it, and per-operator blocklists over opaque IDs break when one byte
changes. **`[UNSOLVED]`, and named as unsolved rather than mitigated.**

### 2.7 R6 — Blockchain ownership vs. anonymity

**Conflict.** Ownership, transfer and revocation need a registry with an owner,
and every registration is a transaction from a funded account. Tor and I2P avoid
this by making the address a key hash — unowned, and therefore also
untransferable, unrecoverable and unmemorable.

**Failure.** `alice.lab.axon` is registered from an account funded by an exchange
withdrawal three days earlier. A chain observer joins the two in one query.
Alice's anonymity never depended on the overlay.

**Ruling (R6).** `OwnerIdentity` (secp256k1, on-chain) and `DomainIdentity`
(Ed25519, off-chain) are different keys and the overlay never sees the wallet;
registration uses commit–reveal, which stops front-running *and* separates "I want
this name" in time from "I have this name"; funding-graph linkage is documented as
a residual risk we do not solve, with a recommendation to register from an
unlinked account.

**Cost.** We may never write "anonymous ownership". The honest claim is
pseudonymous ownership with the linkage moved somewhere the user can manage and we
cannot. Note that `NodeRegistry.sol` already publishes wallet ↔
`keccak256(p2pPublicKey)`; reusing it for AXON relays inherits exactly this
problem for relay operators (§4.1, A6).

### 2.8 R7 — Chain finality vs. network liveness

**Conflict.** The chain is authoritative, slow, and blockable. If resolution needs
a chain read, the namespace inherits the chain's availability and the RPC's
politics.

**Failure.** A resolver does one `eth_call` per name; the provider rate-limits and
resolution stops network-wide. Worse, a lying provider is undetectable to a
resolver that cannot verify — `doc/trust-anchor.md` §1 establishes that
post-merge, fabricating a self-consistent chain of execution headers costs nothing
but hashing, so "every execution-layer check is worthless against a lying
provider".

**Ruling (R7).** The chain is consulted on a slow path with a long TTL.
Resolution runs from a locally verified **registry snapshot**: a Merkle root over
the `name → DomainIdentity` map, anchored on-chain and replicated in the DHT. A
resolver may serve from a stale snapshot inside a declared freshness bound and
must report the bound with the answer. Day-to-day records are signed by
`DomainIdentity` and need no chain access.

**Cost.** Revocation is not instant: between an on-chain revocation and the next
snapshot, an old `DomainIdentity` still resolves, for a window set by policy
rather than by the chain. Snapshot production is a new role with new failure modes
(C19). The nearest prior art in-repo is `internal/gateway/snapshot.go`: fetch
while healthy, verify on arrival *and again on serve*, discard rather than
quarantine. That posture carries over unchanged.

### 2.9 R8 — Best-effort retrieval vs. a site that must load

**Conflict.** Freenet treats availability as emergent — popular content survives,
unpopular content is forgotten, "did it work" is a probability. A name that
resolves to a service, or an object a watchtower needs, cannot be a probability.

**Failure.** A watchtower needs a verified header from six months ago to challenge
a fraudulent channel close (`doc/ethereum-data-layer.md` §6 puts ~2.7 GB/year of
append-only headers in the DHT for exactly this). The header was unpopular, so it
was forgotten. The user loses money and the loss is silent.

**Ruling (R8).** Availability is contracted and measured: replication factor,
active repair, audit challenges, declared tiers, no permanence promise. The code
already has the shape — `DurableRemoteHolders(6,3) = 7`, `placement.Plan` refusing
co-location, `internal/p2p/repair.go` rebuilding from `reedsolomon`, and
`recall_lying_holder_test.go` establishing that a holder's word is not evidence.

**Cost.** Storage no longer free-rides on popularity, so it must be bonded or
paid, which drags the accounting plane onto the critical path of *storage* (not of
retrieval — §3.7). An unmet contract must be visible: an under-replicated object
is a deficit (`ObjectPlacement.UnderReplicated()`), never a silent degradation.

### 2.10 R9 — Destination-oriented vs. circuit-oriented addressing

**Conflict.** In Tor the durable object is the circuit and a stream dies with it;
in I2P the durable object is the destination and tunnels churn beneath it. A
10-minute tunnel lifetime (R1) is incompatible with circuit-bound streams unless
applications tolerate being cut off every ten minutes.

**Failure.** A 200 MB retrieval is bound to a circuit. At minute ten the tunnel
expires and the transfer restarts from zero — and the restart is a distinctive
pattern repeating on a fixed schedule, a free timing signal for any observer.

**Ruling (R9).** Addresses name **destinations** (`ServiceIdentity` /
`DomainIdentity`). Circuits are disposable carriers. A **session layer** above the
circuit survives circuit death: streams bind to sessions, and a session migrates
to a fresh circuit with a resumption token and a byte offset.

**Cost.** Session state at both ends, and a resumption token that is by
construction linkable across circuits — it must be single-use per migration and
derived, never reused. The discipline in `internal/channel/blinded.go` ("one
identifier per role, always") is both the model and the warning. `[BUILD NOW]`
for the session layer; `[NEEDS RESEARCH]` for whether migration timing leaks the
session to the new guard.

### 2.11 R10 — Introduction points vs. direct rendezvous

**Conflict.** I2P publishes lease sets — real tunnel endpoints — saving a round
trip; Tor publishes introduction points and meets at a client-chosen rendezvous,
costing one. Publishing endpoints makes them a standing DoS target and lets any
client enumerate the service's tunnel set.

**Failure.** An adversary reads the lease set and (a) floods those gateways,
taking the service down for the price of bandwidth, and (b) records the gateway
set every period, profiling which relays the service selects — which over enough
periods narrows its guard set and then its location.

**Ruling (R10).** Keep both stages, intro then rendezvous, and improve on Tor by
rate-limiting introduction with a proof-of-work / token puzzle whose difficulty
the service publishes in its descriptor. That is the concrete lesson of Tor's
onion-service DoS experience.

**Cost.** One extra round trip on first contact (§3.5 budgets it), client CPU for
the puzzle, and a new asymmetry: a service under attack raises difficulty, which
prices out low-powered clients before it prices out the attacker.
`[NEEDS RESEARCH]` — the puzzle and its difficulty controller are genuinely open.

### 2.12 R11 — Paying relays vs. unlinkability

**Conflict.** A relay that is paid knows who paid. An identifier attached to a
circuit at hop 1 is a de-anonymisation channel with a receipt.

**Failure.** Relays are paid from a channel keyed to the user's settlement
identity. The guard now holds a persistent pseudonym for that client across every
circuit it carries, and a chain observer joins that pseudonym to a funding
transaction. The onion routing is intact and irrelevant.

**Ruling (R11).** No identified payment on the data path. Payment is by
blind-signed, unlinkable tokens (Chaumian / Privacy-Pass style), redeemed in
aggregate off the critical path and settled in batches through the existing PoF
epoch machinery. **No economic layer in v1**, for three reasons: an unpaid network
is testable end to end without a chain; a payment bug must never be able to take
routing down; and a design that needs payment to function has made accounting a
consensus requirement, which R14 refuses.

**Cost.** v1 has no incentive for relay capacity beyond volunteering — Tor's known
constraint. Blind tokens are double-spendable unless redemption is serialised
somewhere, and "somewhere" is a centralisation pressure. `[NEEDS RESEARCH]` for
the redemption topology.

### 2.13 R12 — Fixed-size cells vs. congestion control

**Conflict.** Tor multiplexes many circuits over one TCP connection; TCP delivers
in order, so one circuit's loss stalls every circuit sharing the connection. Fixed
cells are needed for shape uniformity and are not what causes this.

**Failure.** A relay pair carries 500 circuits on one TCP connection. One packet
is lost and all 500 stall for a retransmission they had nothing to do with. Worse:
the stall is observable, and it correlates those 500 circuits as sharing a link.

**Ruling (R12).** **One QUIC stream per circuit per link.** QUIC streams are
independently ordered, so loss on one circuit does not stall its neighbours. This
is the primary justification for QUIC over TCP+TLS.

**Cost.** Per-stream state at relays, scaling with circuit count rather than
connection count; QUIC's own fingerprint (handshake shape, and a connection ID
that must not become a correlator); and the 1200 B datagram floor, which means two
1024 B cells do not fit in one datagram, so the rule is one cell per QUIC STREAM
frame and the per-cell overhead is real.

### 2.14 R13 — Where does shared randomness come from?

**Conflict.** `KadID` rotation and blinded-key periods need a value nobody can
predict far ahead or choose. Tor gets it from authority commit-reveal — a
centralisation we refuse. I2P and Freenet have none, which is part of why I2P
floodfill placement is Sybil-prone.

**Failure.** Without shared randomness a node picks its own `KadID`. An adversary
grinds keys until it owns the eight positions nearest a target descriptor key.
That name is eclipsed permanently, for the price of key generation.

**Ruling (R13).** SRV is the **beacon-chain RANDAO mix at a fixed slot of the
epoch, verified through the light client that already exists** (`internal/ethproof`;
`doc/trust-anchor.md` records 512/512 sync-committee participation verified
against mainnet at attested slot 14994657). RANDAO's last-revealer bias is known:
the final proposer may withhold and choose between two outcomes, and *k* colluding
trailing proposers get 2^k choices. A few bits of bias is tolerable for keyspace
rotation, because the attacker must still win a grinding race against everyone
else's rotation. It is **not** tolerable for anything needing
unpredictable-and-unbiasable randomness, and no such use is permitted.

**Cost.** A hard dependency on Ethereum consensus data for a core routing
parameter. Note also that PoF's `EpochManager` takes `bytes32 randomness` from a
privileged aggregator; that path must not be reused for SRV. A node that cannot
reach beacon data cannot compute the epoch's `KadID`, so a stale-SRV fallback is
required (C19). `[BUILD NOW]` derivation, `[NEEDS RESEARCH]` fallback.

### 2.15 R14 — "Decentralised" vs. needing a consistent view of the relay set

**Conflict.** Path selection needs a relay list, and a list needs an authority or
it is not a list — it is whatever each client happened to learn. Tor uses 9
directory authorities and pays in centralisation; I2P uses floodfill peers and
pays in Sybil exposure. There is no free third option.

**Failure.** A client learns relays only from peers the adversary controls, and is
fed a wholly adversarial relay set. It builds a 3-hop circuit through three
adversarial relays and every property in this document evaporates. It cannot
detect this, because it has nothing to compare against.

**Ruling (R14).** No consensus document. Relay descriptors live in the DHT; path
selection is computed locally from a bandwidth-and-diversity-weighted sample, with
weights from self-reported capacity **bounded** by bonded stake and by delivery
receipts the client itself observed (C20). Never a central measurement authority.

**Residual risk, plainly.** Without a consensus, two clients can be given
different views and neither can tell. This partitioning / epistemic attack is one
of the hardest problems in the design and nothing here solves it. The available
mitigations — diversity constraints, SRV-derived sampling, bonded identities with
withdrawal delay, cross-checking descriptor sets over independent circuits, and a
few pinned bootstrap anchors explicitly *not* trusted for path selection — raise
cost and do not close the hole. Today's code is worse: the view comes from one
signed document at one URL. **`[UNSOLVED]`**

---

### 2.16 C15 — Caching-along-path vs. deterministic placement

**Conflict.** Freenet's caching makes location a function of demand history; a
structured DHT makes it a function of the key. Repair only works in the second
world: to know an object is under-replicated you must know where its replicas are
*supposed* to be.

**Failure.** A repair loop counts cached copies as replicas. Popular content looks
over-replicated and gets shed; caches expire on their own schedule; the object
falls below the coding threshold with no deficit ever recorded. Availability
collapsed and the ledger said all was well. `placement.Plan` names the same error
class: "an unplaced shard is a visible deficit the repair loop can retire later,
whereas a doubled-up shard is a durability claim that is quietly false".

**Ruling (C15).** Placement is deterministic and contracted (r=8 across distinct
/24, /48 and ASN). Caching exists only as a read-side accelerator with its own
TTL, is never counted as a replica by repair, and is never consulted by the audit
challenge. Two structures, never merged.

**Cost.** Popular content gets no locality benefit beyond the cache TTL, and cold
content pays a full DHT lookup every time.

### 2.17 C16 — Garlic bundling vs. per-cell relay crypto

**Conflict.** I2P bundles several messages, possibly for different endpoints, into
one encrypted unit, amortising overhead and hiding message counts. Tor's fixed
cell means a relay sees one uniform object and cannot tell how many logical
messages it carries. Bundling at hop granularity makes the hop-visible size a
function of the sender's queue depth.

**Failure.** A relay observes bundle sizes; size correlates with sender activity
and activity correlates with the sender. Uniformity — the one property that makes
relayed traffic look alike — was traded for a bandwidth saving.

**Ruling (C16).** Hop-visible units are always 1024 B cells with per-hop layered
AEAD. Bundling of logical messages is permitted only inside the end-to-end
payload, where only the endpoints see it, and never as a hop-visible unit. Padding
cells fill the difference.

**Cost.** Bandwidth: a 40-byte acknowledgement occupies a 1024 B cell on every
link it crosses. That is the price of uniformity, paid knowingly.

### 2.18 C17 — Content-addressed immutability vs. revocable mutable records

**Conflict.** Content addressing self-certifies — the name is the hash, so nobody
can lie about the bytes and nobody can change them. Naming needs the opposite:
`alice.lab.axon` must point somewhere new tomorrow and must be revocable when a key is
stolen.

**Failure.** Records are addressed by a hash of their content. Alice's key is
compromised and she publishes a new record; the old one is still valid, still
self-certifying, still served. Revocation is impossible because the old bytes are
as authentic as the new ones. `internal/p2p/objmanifest.go` shows the halfway
house: manifests keyed by `SHA-256(bucket ‖ 0x00 ‖ key)`, unsigned, with the
validator reasoning that "a forged manifest can at worst cause a fetch to fail,
never corruption". True for content; exactly what naming cannot have.

**Ruling (C17).** Two record classes, never in one keyspace:

| | Content records | Naming records |
|---|---|---|
| Address | `ContentIdentity` = BLAKE3 root | blinded `DomainIdentity` for the period |
| Mutability | immutable | versioned, monotonic |
| Authenticity | self-certifying (recompute the root) | Ed25519 signature by `DomainIdentity` |
| Freshness | not applicable | signed validity window; newest valid wins |
| Revocation | not applicable | on-chain revocation + signed tombstone in the DHT |

**Cost.** Naming needs rollback defence that content does not: a node serving
version 4 while version 7 exists is performing a downgrade, and version numbers
alone do not stop it because the client cannot know 7 exists. Signed validity
windows plus d=3 multi-path lookup bound the window without eliminating the
attack. `[NEEDS RESEARCH]`

### 2.19 C18 — A DHT that must be fast vs. lookups that must be anonymous

**Conflict.** R4 requires every client lookup to traverse a circuit. A Kademlia
lookup is iterative: L rounds of α parallel queries, each depending on the last.
Over a 3-hop circuit each round costs a full circuit RTT.

```text
  direct lookup       L × R_direct     L≈4, R≈60 ms   →  ~0.24 s
  over a 3-hop        L × R_circuit    L≈4, R≈450 ms  →  ~1.8 s
  worst case          L≈8, R≈900 ms                   →  ~7.2 s
  plus circuit build  one-time, ≈2×R per hop extension
```

*(Budget figures, not measurements. The only measured anchors in the repo are the
existing anonymous-transport timeouts — `i2pDialTimeout` 2 min against
`directDialTimeout` 10 s, and a 3-minute `manifestFetchTimeout`. They establish
the order of magnitude of the problem, not this design's numbers.)*

**Failure.** A design assumes lookups are cheap and puts one on every request's
critical path; resolution takes seconds and users route around the network by not
using it. Or the designer "optimises" with a direct lookup for the first request
only, reintroducing §2.5's leak in full.

**Ruling (C18).** Lookups run over circuits and the latency is paid, reduced by
three things: an aggressive client-side cache honoured to each record's own
validity window, so a repeat visit costs zero lookups; d=3 disjoint paths run **in
parallel**, so disjointness costs 3× bandwidth and not latency; and descriptor and
snapshot prefetch on a `BULK` schedule, off the request path. The first request to
a cold name is slow, and we say so.

**Cost.** The cache is a per-client record of which names a user cares about,
sitting on disk. It must be encrypted at rest, bounded, and its hit pattern must
not be visible in the timing of later lookups.

### 2.20 C19 — Blockchain global consistency vs. overlay partition tolerance

**Conflict.** A blockchain's product is one globally agreed sequence of events. An
overlay must work while partitioned, because partition is the normal state of the
Internet under an adversary. If the overlay needs the chain's view to progress,
the adversary partitions chain access and the overlay stops.

**Failure.** A censoring network blocks RPC and beacon endpoints. Nodes cannot
fetch a new SRV, so they cannot compute the epoch's `KadID`, so the keyspace
fragments — some rotated, some not — and lookups fail across the split. One
blocked port took down routing.

**Ruling (C19).** The overlay runs indefinitely with no chain access; the chain is
authoritative for ownership *changes* only, and only eventually. Concretely:
(a) SRV falls back to a deterministic function of the last verified SRV and the
epoch number, so partitioned nodes compute the same keyspace as other partitioned
nodes and re-converge on reconnection; (b) resolution serves the last verified
snapshot with its freshness bound reported (R7); (c) **no data-path operation may
block on a chain read** — a rule the transport, DHT and circuit sections inherit.

**Cost.** Divergent keyspaces during a long partition and a re-convergence event
that will look like mass churn. A resolver reporting "as of six days ago" is
telling the truth and still serving a stale ownership record. `[NEEDS RESEARCH]`
for the re-convergence schedule.

### 2.21 C20 — Bandwidth-weighted selection vs. no measurement authority

**Conflict.** Path selection must be bandwidth-weighted or capacity is wasted and
small hostile relays are chosen as often as large honest ones. Weighting needs
measurement, and measurement needs either a trusted authority (Tor's bandwidth
authorities — refused by R14) or self-reporting (inflated for free).

**Failure.** An adversary reports 10 Gbit/s from a 100 Mbit/s VPS, is selected
disproportionately for nothing, and either observes what it can carry and drops
the rest or simply carries slowly. No authority notices, because we abolished it.

**Ruling (C20).**

```text
  weight = min( self_reported_capacity,
                cap_from_bonded_stake,
                observed_delivery_rate_from_receipts )
```

`observed_delivery_rate_from_receipts` derives only from receipts the selecting
client itself holds — its own past circuits, or receipts it signed at the far end
of a completed transfer — never a third party's claim about a relay. The
bonded-stake cap prices Sybil weight, and withdrawal is delayed
(`StakeVault.withdrawDelay`). The minimum bond is **TBD: no minimum exists in
`StakeVault.sol`; it is a policy that must be set.**

**Cost.** A new client with no receipt history has only self-reports and stake —
the weakest weighting, at the moment it is most vulnerable. Weighting diverges
between clients by construction, which is C19's partitioning problem in another
hat. And stake-capped weight means capacity correlates with wealth.
`[NEEDS RESEARCH]`

### 2.22 C21 — Erasure coding vs. probabilistic availability

**Conflict.** Reed–Solomon k-of-n has a cliff: with 6+3, any 6 of 9 shards
reconstruct and any 4 losses destroy the object completely. Freenet-style
availability degrades smoothly with no threshold. A design that mixes the mental
models sizes its repair loop for smooth degradation and gets a cliff.

**Failure.** Nine shards on nine peers. Three peers leave over a month and nobody
notices, because the object still reconstructs perfectly. The fourth leaves and
the object is gone with no warning. The first three losses were free and the
fourth was total — precisely the failure `internal/placement/plan.go` was written
to prevent at placement time ("the arithmetic looked like 6+3 and behaved like
6+1"), applied now to the repair schedule.

**Ruling (C21).** Availability is defined against the cliff, not the average. The
repair loop is sized so expected concurrent losses stay well below the parity
count, with the deficit visible at all times
(`ObjectPlacement.UnderReplicated()`). Audit challenges verify that holders
actually hold, because a claim is not evidence
(`recall_lying_holder_test.go`). Tiers are declared as k-of-n plus a repair
interval, never as a probability.

**Cost.** Repair traffic is continuous, grows with churn, and is `BULK` traffic
over circuits — expensive. The 6+3 defaults were chosen for a friendly volunteer
pool, not a hostile anonymous network, and re-deriving them for AXON's churn model
is open work. Note that the Constitution's 256 KiB chunk does not match the code:
the default is **1 MiB** (`ChunkBytes: 1 << 20`), bounded 64 KiB..16 MiB. Flagged,
not silently reconciled.

### 2.23 Decision table

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Guard-constrained pools (R1) | Cumulative first-hop compromise under churn | Tor guards + I2P pools | Guard pinning applied to hop 1 of every pool member | Pure churn; single guard | Two long-lived observation points; correlated guard outage |
| Two traffic classes (R2) | One class must lie to half its users | Tor/I2P latency; Freenet batching | Class is a required API argument | Single class; adaptive selection | Class label is itself a traffic-analysis feature |
| Reachability-gated relaying (R3) | NAT clients cannot relay; deniability claim is false | Tor role split; I2P universal relay | Relaying credited, never protective | Everyone relays; nobody relays | Relay set enumerable and blockable |
| Lookups over circuits, blinded keys (R4) | Lookup leaks interest to the nearest node | I2P netdb-over-tunnels | Made unconditional; blinding added | Direct lookup with cover; PIR | Latency per lookup; storing nodes cannot rate-limit abuse |
| Encrypted, opt-in caching (R5) | Operators possess what they never requested | Freenet caching, inverted | Encrypted shards only, opt-in | Freenet caching; no caching | Abuse handling impossible — `[UNSOLVED]` |
| Owner/domain key split (R6) | Wallet links a name to a payer | New (chain-side) | Two key classes + commit–reveal | Unowned self-certifying names | Funding-graph linkage remains |
| Snapshot resolution (R7) | Chain outage takes the namespace down | New | Verified snapshot in the DHT | Per-lookup `eth_call`; trusting an RPC | Revocation lag bounded by policy |
| Contracted availability (R8, C21) | Best-effort storage loses money-bearing data | Freenet, refused | k-of-n + repair + audits + tiers | Probabilistic availability; permanence | Continuous repair traffic; cliff if repair lags |
| Session over circuits (R9) | 10-min tunnels vs. long transfers | I2P destinations + Tor circuits | Explicit session with resumption | Circuit-bound streams; long circuits | Resumption token links two circuits |
| Intro + rendezvous + PoW (R10) | Published endpoints are DoS targets | Tor two-stage | Service-set puzzle difficulty | I2P lease sets; unpriced intro | Puzzle prices out weak clients first |
| Blind tokens, off-path (R11) | Payment identifies payer to relay | New | Aggregate redemption; no economy in v1 | Per-circuit channel payments | Double-spend needs serialisation |
| One QUIC stream per circuit (R12) | Cross-circuit head-of-line blocking | Tor's TCP multiplexing, refused | Per-circuit stream isolation | TCP+TLS multiplex; raw UDP | Per-stream relay state; QUIC fingerprint |
| RANDAO SRV via light client (R13) | Self-chosen `KadID` enables eclipse | Tor shared random, decentralised | Verified beacon randomness | Authority commit-reveal; none | Chain dependency for routing; last-revealer bias |
| No consensus document (R14, C20) | Directory authorities are a centralisation | Tor consensus refused; I2P netdb hardened | Weighting bounded by stake and own receipts | Signed consensus; bandwidth authorities | Partitioning attack — `[UNSOLVED]` |
| Placement ≠ cache (C15) | Repair cannot count cached copies | Freenet caching, quarantined | Two structures, never merged | Cache-as-replica | Cold content always pays a lookup |
| Cells never bundled at hops (C16) | Bundle size leaks sender activity | Tor cells over I2P garlic | Bundling only end-to-end | Garlic at hop granularity | Bandwidth waste on small messages |
| Split content/naming keyspaces (C17) | Immutable records cannot be revoked | Freenet keys + DNS semantics | Two classes, two validators | One record type | Downgrade/rollback on naming records |
| Chain-optional operation (C19) | Blocked RPC stops routing | New | Deterministic SRV fallback | Hard chain dependency | Keyspace divergence during partitions |

### What this section does NOT establish

- **No ruling is proved optimal.** Each is a defensible resolution with its cost
  stated. R10's puzzle, R11's redemption topology and C20's weighting are the kind
  of choice settled by deployment data this project does not have.
- **The arithmetic is arithmetic.** §2.2's guard figures assume independent,
  uniform selection, which bandwidth weighting violates; C18's latencies are
  budgets. The only measured numbers cited are the repository's existing timeouts
  and the mainnet figures in `doc/trust-anchor.md` and `doc/ethereum-data-layer.md`.
- **R14 and R5 are bounded, not solved.** The partitioning attack and the abuse
  problem are `[UNSOLVED]`; no combination of the listed mitigations closes either.
- **No wire formats.** Cell layout, descriptor encoding, record schemas and DHT
  record types belong to the transport, circuit, DHT and naming sections; this
  section only constrains what they may contain.
- **Storage parameters are not re-derived for a hostile network.** 6+3 with 1 MiB
  chunks is what the code does in a friendly volunteer pool.

---

## 3. System Architecture

### The finding that shapes everything

The layer boundary that matters is not L1/L2 or L6/L7. It is L4. Everything below
knows IP addresses and nothing about names; everything above knows names,
services and content and must never learn an IP. Every serious de-anonymisation
bug in a system of this shape is a violation of that one rule — a resolver that
leaks a DNS query, a storage client that dials a holder directly because the
circuit was slow, a metrics exporter that logs a peer address next to a name.

The architecture is therefore organised to make that violation *hard to write*,
not merely forbidden in prose. §3.2 states per layer what may and must never be
seen; §3.3 gives the mechanism that enforces it in the type system and in CI.

The existing code does not have this property. `internal/p2p/node.go` is 1,775
lines owning the libp2p host, the DHT, the storage protocol, bootstrap HTTP and
the compute registry at once; `internal/gateway` handles hostnames, IPs, ACME and
content proxying in one package. Reasonable for a non-anonymous storage client;
not a shape that can hold the L4 barrier.

### What already exists

| Layer | Existing implementation | Verdict |
|---|---|---|
| L0/L1 | libp2p transports; `internal/i2p/transport.go` when anonymous | **Replace.** QUIC + TLS 1.3 raw public keys is new work. |
| L2 | libp2p peerstore; `internal/bootstrap` (Ed25519-signed doc from `config.BootstrapURL`) | **Harden.** Keep signed documents, remove the single-URL authority (R14). |
| L3 | `dht.New(h, dht.Mode(dht.ModeAutoServer))` (`node.go:438`); namespaced validators in `gateway/dht.go`, `dcs/dht.go`, `p2p/objmanifest.go` | **Keep and re-scope.** Validator pattern is right; keyspace, `KadID` and record types change. |
| L4 | Nothing — I2P provides it today | **Build.** The genuinely new work. |
| L5 | Nothing native; `internal/channel/blinded.go` has the shape (invoice → introduction node → blinded endpoint) | **Build**, reusing the identifier-per-role discipline. |
| L6 | `internal/store` (RS 6+3, 1 MiB chunks, SHA-256 shard IDs, bbolt), `p2p/disperse.go`, `recall.go`, `repair.go`, `rebalance.go`, `internal/placement` | **Keep.** Re-address to BLAKE3; add the ASN//24//48 diversity that does not exist. |
| L7 | `internal/gateway/registry.go` + `gateway-controller` name.com DNS sync + ACME | **Replace entirely.** Conventional DNS with a central controller. |
| L8 | `internal/s3api`, gateway HTTP surfaces | **Replace** with the AXON infrastructure API. |
| Accounting | `internal/facilitation`, `internal/channel` (SCPP/1), PoF contracts | **Keep**, moved strictly off the data path. |
| Chain | `internal/ethproof` (MPT proofs, BLS light client) | **Keep.** The most valuable existing asset; naming is built on it. |

**What must be replaced:** `internal/i2p`; the single-URL bootstrap authority; the
central registry controller; the `H(bucket ‖ key)` unsigned manifest key.

### 3.1 The stack

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │ L8  INFRASTRUCTURE API   resolve / publish / retrieve / tunnel / pay    │
 │                          the project ends here                         │
 ├────────────────────────────────────────────────────────────────────────┤
 │ L7  NAMING & RESOLUTION  .axon → DomainIdentity → records              │
 ├────────────────────────────────────────────────────────────────────────┤
 │ L6  SERVICE & CONTENT    descriptors, manifests, storage objects       │
 ├────────────────────────────────────────────────────────────────────────┤
 │ L5  RENDEZVOUS           introduction + rendezvous, endpoint hiding    │
 ├════════════════════════════════════════════════════════════════════════┤
 │ L4  TUNNEL / CIRCUIT     onion routing, cells, pools, sessions         │
 │        ══ THE BARRIER ══  names stop here going down                   │
 │                           IP addresses stop here going up              │
 ├════════════════════════════════════════════════════════════════════════┤
 │ L3  DHT                  signed records, discovery, keyspace           │
 ├────────────────────────────────────────────────────────────────────────┤
 │ L2  PEER / MEMBERSHIP    peerbook, reachability, NAT, bootstrap        │
 ├────────────────────────────────────────────────────────────────────────┤
 │ L1  SECURE TRANSPORT     QUIC + TLS 1.3 raw public keys; TCP+TLS fb    │
 ├────────────────────────────────────────────────────────────────────────┤
 │ L0  INTERNET                                                           │
 └────────────────────────────────────────────────────────────────────────┘

 ACCOUNTING PLANE ┄┄ bonds, receipts, blind tokens, settlement.
   Touches L2 (admission), L3 (storage contracts), L4 (relay credit).
   Control plane only. NEVER on the data path's latency budget.

 CHAIN PLANE ┄┄ ownership (AxonRegistry), bonds (StakeVault), settlement
   anchors (EpochManager), SRV source (beacon RANDAO via internal/ethproof).
   Slow, expensive, authoritative, and OFF the request path (C19).
```

### 3.2 Layer contract table

| Layer | Responsibility | May see | Must never see | Module (proposed) | Interface upward |
|---|---|---|---|---|---|
| L8 | Public API; forces the class choice; holds the "no applications" line | Names, CIDs, class labels, session handles | Circuit ids, relay identities, IPs | `axon/api` | `Resolve`, `Publish`, `Retrieve`, `Dial`, `Listen`, `Pay` |
| L7 | `.axon` → `DomainIdentity` → records; snapshot verification; freshness | Names, `DomainIdentity`, snapshot root, freshness bound | IPs, relay identities, circuit ids | `axon/naming` | `Resolve(name) → (DomainIdentity, records, freshness)` |
| L6 | Descriptors, manifests, chunk trees, storage contracts | `ServiceIdentity`, `ContentIdentity`, blinded keys, shard ids | IPs; holder `NodeIdentity` (holders are opaque handles) | `axon/service`, `axon/store` | `FetchDescriptor(blinded)`, `Get(cid)`, `Put(bytes) → cid` |
| L5 | Introduction, rendezvous, PoW gating, endpoint hiding | Intro/RP handles, rendezvous cookies | Either party's real IP | `axon/rendezvous` | `Connect(descriptor) → Session` |
| **L4** | **Onion routing, cells, pools, guards, sessions. The barrier.** | Both sides: `RoutingIdentity`, IPs via L2 handles, opaque payloads | **Payload semantics** — it must not parse what it carries | `axon/circuit`, `axon/pool`, `axon/session` | `BuildCircuit(class, len)`, `OpenStream(session)` |
| L3 | Signed records, keyspace, `KadID`, lookup routing | `KadID`, record keys and bytes, peer handles | Names, plaintext, which client asked | `axon/dht` | `Get(key)`, `Put(key, record)`, `FindNode(id)` |
| L2 | Peerbook, reachability, NAT class, bootstrap, admission | IPs, ASNs, `NodeIdentity`, reachability results | Names, CIDs, circuit contents | `axon/peer` | `Peers(filter)`, `Reachability()`, `Dial(PeerRef)` |
| L1 | QUIC + TLS 1.3 raw public keys; one stream per circuit (R12) | IPs, ports, `NodeIdentity` as raw public key | Anything above; cells are opaque bytes | `axon/transport` | `Open(PeerRef) → Link`, `Link.NewStream()` |

The "must never see" column is the specification. A field appearing where the
table forbids it is a bug of the same severity as a key leak.

### 3.3 How the L4 barrier is enforced

**1. Types that never meet.**

```text
  // L1–L4 only
  type PeerRef  struct { node NodeIdentity; addr netip.AddrPort }
  type RelayRef struct { routing RoutingIdentity; peer PeerRef }  // L4-private

  // L5–L8 only
  type Dest struct { service ServiceIdentity }
  type Name struct { labels []string }   // ends in TLD
  type CID  struct { root [32]byte }     // BLAKE3

  // The ONLY legal downward conversion, and it lives inside L4:
  func (c *circuitBuilder) resolveHop(RelayRef) (*link, error)
```

`RelayRef` is unexported outside `axon/circuit`. Layers above receive opaque
`HopHandle` values — an index into the builder's private table — so an L6 storage
client can say "fetch from holder #3" and cannot say "fetch from 198.51.100.7".

**2. A CI import check.** `axon/internal/lint/noaddr` fails the build if any
package under `axon/{rendezvous,service,store,naming,api}` imports `net`, `netip`,
`crypto/tls` or `axon/transport`. Crude, and it catches the real mistake, which is
someone reaching for `net.Dial` at 2 a.m. to work around a slow circuit.

**3. Logging discipline.** No structured-log field above L4 may carry a type
containing an address; same lint rule, plus a `Redacted` wrapper on
`PeerRef.String()`.

Upward is enforced identically: nothing below L4 has a type that can hold a `Name`
or a `CID`, and the DHT never learns that `0x9f3c…` is `alice.lab.axon` because
blinding (R4) makes the key non-invertible to the name.

### 3.4 The dependency stack is not the call stack

L3 sits below L4 in the diagram, but R4 requires client lookups to run **over** a
circuit. Both hold, because the DHT has two modes:

```text
  DHT server mode (we answer)  L3 → L2 → L1    direct, public, fine
  DHT client mode (we ask)     L3 → L4 → L1    over a circuit, always
```

The diagram is a *dependency and visibility* stack: L3's record semantics do not
depend on L4, and L3 never sees a name. The client lookup transport is injected as
an interface (`type LookupTransport interface { RoundTrip(HopHandle, []byte)
([]byte, error) }`), satisfied by `axon/circuit` in client mode and `axon/peer` in
server mode. `axon/dht` never imports `axon/circuit`; wiring happens at `axond`
startup. That inversion is what keeps the barrier intact.

### 3.5 Trace A — `https://alice.lab.axon/`, resolver call to bytes returned

```text
 A1  L8   api.Dial(Name("alice.lab.axon"), Class=INTERACTIVE)
          class is mandatory (R2); no default exists.

 A2  L7   naming.Resolve("alice.lab.axon"); snapshot cache hit → A6, else A3.

 A3  CHAIN PLANE (slow path; off the request path when warm)
          BLS12-381 sync-committee signature over a beacon header
            (internal/ethproof; 512/512 verified on mainnet, doc/trust-anchor.md)
          → execution_branch SSZ proof → execution payload header → stateRoot
          → MPT storage proof of AxonRegistry.snapshotRoot
          KEYS: BLS12-381 committee pubkeys, keccak256 (slots), SHA-256 (SSZ)

 A4  L7   snapshot Merkle inclusion proof for label "alice"
          → DomainIdentity_alice (Ed25519, 32 B)
          → freshness = now − snapshot_timestamp, reported upward with the answer

 A5  L7   cache (name → DomainIdentity, validity window), encrypted at rest

 A6  L7→L6  descriptor key, computed locally, no network:
            period  = floor(now / 24h), 12 h overlap
            B       = BlindEd25519(DomainIdentity_alice, period)   [Tor v3 style]
            dht_key = SHA-256("axon:desc:v1" ‖ B ‖ SRV_epoch)

 A7  L6→L3  dht.Get(dht_key): d=3 disjoint paths, α=3, k=20

 A8  L3→L4  every lookup round travels a circuit (R4). If none exists, L4 builds:
            guard (1 of 2 pinned) → middle → terminal
            per hop: X25519 ephemeral ↔ hop RoutingIdentity X25519
                     → HKDF-SHA256(label "axon/circuit/hop/v1")
                     → ChaCha20-Poly1305, one key per direction
            cell 1024 B; header 16 B; 16 B tag reserved per hop POSITION:
              payload = 1024 − 16 − 16×H_max(4) = 944 B
              a 3-hop circuit leaves one tag slot reserved-but-unused, so cell
              geometry never reveals hop count

 A9  L4→L1  one QUIC stream per circuit per link (R12); TLS 1.3 raw public keys
            authenticate NodeIdentity at the link layer only.

A10  L3    descriptor returned. Verify the signature by B. Decrypt the inner layer
           with the subcredential from DomainIdentity_alice and the period
           (HKDF-SHA256, "axon/desc/subcred/v1"); optional client-auth layer above.
           Yields IP1..IP3 as (RelayRef, intro auth key, intro X25519 onion key)
           and the PoW parameters (R10).

A11  L5    pick RP from the locally weighted sample (C20); build a 3-hop circuit to
           it; ESTABLISH_RENDEZVOUS with a 20 B random cookie. RP learns the cookie
           and nothing else.

A12  L5    solve the descriptor's puzzle; build a 3-hop circuit to IP1; INTRODUCE1
           encrypted to IP1's intro key: { RP RelayRef, cookie, client ephemeral
           X25519 pubkey, PoW solution, class }. IP1 forwards over the service's own
           circuit. IP1 learns that a request arrived — not who, not for what.

A13  L5    service builds a 3-hop circuit to RP; RENDEZVOUS1 carries the cookie and
           its ephemeral X25519 pubkey. RP joins the two circuits by cookie and
           learns two circuit ids.

A14  L5    ntor-style handshake end to end:
             shared = X25519(client_eph, service_eph)
                    ‖ X25519(client_eph, ServiceIdentity_x)
             keys   = HKDF-SHA256(shared, "axon/rend/v1")
                    → ChaCha20-Poly1305, one key per direction
           Total path: 3 client hops + RP + 3 service hops = 6 relays + RP.

A15  L4    session established (R9). The session, not the circuit, is durable;
           either side may migrate with a single-use resumption token and offset.

A16  L8    a Stream is returned; bytes flow. "https://" is an APPLICATION
           convention and out of scope (Constitution §8). Two notes belong here:
           the .axon name is already self-authenticating through A4+A10, so
           TLS-to-a-CA adds nothing and reintroduces a centralised trust root;
           TLS inside the tunnel is permitted, costs a second handshake, and is
           useful only when the endpoint also exists on the clearnet.
```

| Step | Key / value | Identity class | Who learns it |
|---|---|---|---|
| A3 | BLS12-381 committee pubkeys | chain plane only | public |
| A4 | `DomainIdentity_alice` | DomainIdentity | anyone who resolves the name |
| A6 | blinded key `B`; `SRV_epoch` | derived / shared | the storing DHT nodes (cannot invert `B`) |
| A8 | per-hop X25519 ephemeral + `RoutingIdentity` | RoutingIdentity | that hop only |
| A9 | raw-public-key `NodeIdentity` | NodeIdentity | the directly connected peer only |
| A10 | intro auth key, intro onion key | ServiceIdentity-derived | client and intro point |
| A11 | rendezvous cookie (20 B) | ephemeral | client, RP, service |
| A14 | end-to-end AEAD keys | ephemeral | client and service only |

**Latency budget (target, not measurement).** A3 is off-path when warm and
hundreds of milliseconds when not (`doc/ethereum-data-layer.md` measured ~210–290
ms for a verified 11-slot read, 41 ms for a header fetch, against mainnet). A7–A9
is C18's budget (~1.8 s at L≈4). A11–A14 costs three circuit builds and two extra
round trips. Cold first contact in the low single-digit seconds is the target; a
warm repeat should be one circuit RTT plus the service's own latency.

### 3.6 Trace B — content retrieval from distributed storage

```text
 B1  L8   api.Retrieve(CID, Class=BULK). BULK is correct for storage; a caller may
          demand INTERACTIVE and is told in the returned metadata that correlation
          resistance was waived.

 B2  L6   manifest key = SHA-256("axon:obj:v1" ‖ CID.root). This REPLACES
          internal/p2p/objmanifest.go's SHA-256(bucket ‖ 0x00 ‖ key), which is
          unsigned and names a mutable location rather than immutable content (C17).

 B3  L6→L3  dht.Get(manifest key) over BULK circuits. Verification is
          self-certifying: recompute the BLAKE3 chunk-tree root, compare to
          CID.root. No signature is needed or accepted.

 B4  L6   per chunk: k=6 data + 3 parity shard ids, shard size, cipher length
          (the existing store.ChunkManifest fields, re-addressed).

 B5  L3   provider lookup → r=8 holder records, constrained to distinct /24 (v4),
          /48 (v6) and distinct ASNs. **This constraint does not exist in the
          current code:** internal/placement guarantees distinct PEERS only, and
          grep finds no ASN or prefix logic in internal/placement or
          internal/store/placement.go.

 B6  L4   open BULK circuits to 6 holders in parallel, exposed upward as
          HopHandles. L6 never sees a holder's address (§3.3).

 B7  L6   verify each shard against its content id BEFORE decoding — "Kademlia
          records and peer responses are untrusted hints" (SECURITY.md), unchanged.

 B8  L6   Reed–Solomon reconstruct (existing internal/store + klauspost/reedsolomon;
          defaults 6+3, internal/config/config.go:572–573).

 B9  L6   decrypt with the content key carried by the CID capability. The holder
          never had it (R5). ChaCha20-Poly1305, per-chunk nonce.

B10  L6   verify the BLAKE3 root over the reassembled plaintext. A mismatch is a
          hard failure, never a warning.

B11  ACCOUNTING PLANE, off-path, after delivery: the client signs a delivery
          receipt per holder, modelled on the existing ServiceReceipt encoding
          (keccak256 over fixed-order fields, witness co-signatures). Receipts feed
          C20's weighting and PoF settlement. Nothing in B1..B10 waits for this.

B12  L8   bytes returned, with the k-of-n tier the object was stored under and how
          many holders answered.
```

**Convergent-encryption note.** Deriving the content key from the plaintext would
deduplicate identical files and would enable a confirmation-of-file attack: an
adversary who guesses the plaintext computes the CID and tests whether the network
holds it. The default is a random per-object key carried in the capability;
convergent encryption is a per-object opt-in the API labels as such.
`[BUILD NOW]` for the default, `[NEEDS RESEARCH]` for whether dedup is ever worth
the attack.

### 3.7 The accounting plane

Cross-cutting, not a layer. Three rules; the third is the one that gets broken.

1. It touches L2 (admission — bond required to be a relay or holder), L3 (storage
   contracts — who agreed to hold what), L4 (relay credit — receipts for carriage).
2. Layers may read its **policy** (a boolean: "bonded above threshold?"; a weight
   cap) and never its **state machine** (channel states, receipt queues, epochs).
3. **No data-path operation blocks on it.** Receipts are generated after delivery,
   queued, and redeemed on a `BULK` schedule. If the whole plane is down, routing,
   resolution and retrieval continue and only credit accrual stops. This is why
   R11 puts the economy outside v1: a network that must be paid to route is a
   network whose payment bug is an outage.

Existing: `internal/facilitation` (receipts, witnesses, epoch loop, `ServiceType`),
`internal/channel` (SCPP/1, HTLCs, multipath, watchtowers), PoF contracts
(`StakeVault`, `EpochManager`, `DisputeManager`, `RewardDistributor`). The gap is
R11's blind-token layer: `internal/channel/blinded.go` blinds the *recipient*, and
payer-side unlinkability is new work.

### 3.8 The chain plane

Authoritative for exactly four things:

| Concern | Source | Read frequency | Data-path dependency |
|---|---|---|---|
| Name ownership, `DomainIdentity` commitment | `AxonRegistry` (new) | snapshot refresh | none (R7) |
| Registry snapshot root | `AxonRegistry.snapshotRoot` | snapshot refresh | none |
| Bonds and slashing | `StakeVault`, `DisputeManager` | epoch-scale | none |
| Settlement anchors | `EpochManager` | epoch-scale | none |
| SRV source | beacon RANDAO via `internal/ethproof` | once per epoch | **soft** — stale-SRV fallback required (C19) |

Everything read is verified locally against the light client's anchor.
`doc/trust-anchor.md` §1 is the standing reason: post-merge an execution header
carries no proof of work, so a provider can fabricate an internally consistent
chain and our own MPT verifier will confirm it, correctly. Only sync-committee
signatures make a header canonical. The naming layer inherits both the verifier
and its boundary — the initial checkpoint is a subjective input a human supplies
from independent sources.

### 3.9 Decision table

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| L4 barrier as a typed boundary | Address leaks above L4 are the whole bug class | Implicit in Tor's SOCKS/DNS separation | Made it a type-system and CI property | Documentation-only rule; runtime assertions | `HopHandle` indirection can be misused if a table index is reused across circuits |
| DHT transport injected, not imported | R4 without a layer inversion | I2P netdb-over-tunnels | Interface injection at startup | DHT above L4; direct lookups | Startup wiring becomes security-critical |
| Session above circuit (R9) | 10-min tunnels vs. long transfers | I2P destinations | Explicit sessions with resumption | Circuit-bound streams | Resumption token links two circuits |
| Two-stage rendezvous with PoW (R10) | Published endpoints are DoS targets | Tor intro+RP | Service-set difficulty in the descriptor | I2P lease sets | Extra RTT; puzzle penalises weak clients |
| Self-certifying manifests keyed by CID | Unsigned `H(bucket‖key)` names a location, not content | Freenet content keys | BLAKE3 chunk tree; no signature accepted | Signed mutable manifests | A bad CID is permanent — by design (C17) |
| Accounting strictly off the data path | Payment failure must not be an outage | New | Policy readable, state machine not | Per-hop payment; payment-gated routing | Credit can be silently lost; needs its own monitoring |
| Chain read only on snapshot refresh | Chain outage must not stop resolution | New | Verified snapshot + declared freshness | Per-lookup chain reads | Revocation lag; stale-but-valid answers |
| Random content key by default | Confirmation-of-file attack | Freenet CHKs | Default flipped away from convergent | Convergent-by-default | Loss of deduplication; larger footprint |

### What this section does NOT establish

- **No wire formats.** Cell layout, descriptor encoding, DHT record schemas and
  the exact L8 signatures belong to the transport, circuit, DHT, service and API
  sections. This fixes only what each layer may see.
- **The module decomposition is proposed, not built.** `axon/circuit`, `axon/dht`,
  `axon/naming` and the rest name work that does not exist, and the existing
  `internal/p2p/node.go` does not decompose along these lines. The restructure is
  unbudgeted here.
- **The latency budget is a target.** §3.5's figures are arithmetic plus the two
  measured anchors in `doc/ethereum-data-layer.md`. No AXON circuit has been built,
  so no AXON RTT has been measured.
- **The ASN/prefix diversity constraint has no implementation.** B5 requires it;
  `internal/placement` gives distinct-peer only. Where ASN data comes from, and how
  a node verifies another's claimed prefix, is open.
- **The CI import check does not stop semantic leaks.** A package can leak an
  address through a string, an error message or a timing side channel without
  importing `net`. It catches the common mistake, not the clever one.

---

## 4. Adversary Model and Anonymity Assumptions

### The finding that shapes everything

AXON's `INTERACTIVE` traffic class is vulnerable to end-to-end correlation by any
adversary that observes both ends of a connection. This is not a gap to be closed
later. It follows directly from choosing low latency, it is true of Tor and I2P
for the same reason, and the only known defences — constant-rate cover traffic,
batching, deliberate delay — are exactly what `BULK` provides and exactly what
makes `BULK` unusable for interactive work.

Every anonymity statement in this document is therefore scoped to an adversary
class. A claim with no class attached is not a weak claim; it is a false one.

### What already exists

`SECURITY.md` already states trust boundaries in the right register: the local S3
gateway is trusted with plaintext, volunteer peers get only content-addressed
ciphertext, and "Kademlia records and peer responses are untrusted hints". The
adversarial test culture exists — `recall_lying_holder_test.go` pins the case
where the party asked to delete is the party with the motive to lie, and its
sibling pins that an unverifiable claim must not collapse into the hoped-for
outcome. What does not exist is a network-level adversary model, because the
network layer is I2P's and its model was inherited rather than stated.

### 4.1 Adversary classes

| Class | Capabilities | Cost to become | AXON countermeasure | Residual |
|---|---|---|---|---|
| **A1 Curious relay** | Sees one hop: predecessor, successor, timing, volume. Cannot read payload | One VPS + a bond (minimum **TBD — none exists in `StakeVault.sol`**) | Layered AEAD; fixed 1024 B cells; `RoutingIdentity` rotation | Position inference: a relay can often tell whether its predecessor is a client |
| **A2 Colluding relay set, fraction *f*** | Correlates across hops it owns; end-to-end when it holds first and last | Linear in *f*: nodes, bonds, and bandwidth enough to be selected (C20) | Guards fix the first-hop draw (R1); /24, /48 and ASN diversity; stake-capped weighting | ≈1−(1−*f*)² chance of a hostile guard **for a whole 45-day period**, then ≈*f* per circuit at the far end |
| **A3 AS-level observer** | Sees all traffic crossing its network; correlates client→guard with terminal→service if both cross it | A national ISP or large transit provider | ASN diversity; avoid the client's own AS for guards where determinable | We see endpoints, not AS paths; asymmetric routing means a path we believe diverse may not be. `[UNSOLVED]` |
| **A4 IXP observer** | Sees traffic at an exchange; few IXPs carry many paths | A large exchange operator, or a warrant to one | Same as A3 | Same as A3, with better adversary coverage per site |
| **A5 The service itself** | Sees everything the client sends it; sets PoW difficulty; controls its descriptor | Run a service | None. **Explicitly not defended** | A full participant in the client's session by construction |
| **A6 Chain observer** | Reads the whole chain forever with perfect recall: registrations, bonds, settlements, timing | Free | `OwnerIdentity ≠ DomainIdentity`; commit–reveal; `endpointCommitment` not raw endpoints; blind tokens (R11) | **Funding-graph linkage unsolved.** `NodeRegistry` already publishes wallet ↔ `keccak256(p2pPublicKey)` for relay operators |
| **A7 Local network** | Sees that AXON is in use, when, and how much; can block | Wi-Fi operator, ISP, campus, censor | None in v1; obfuscated transports are out of scope and named as such | Using AXON is **observable**; a QUIC handshake to a bonded relay is recognisable |
| **A8 The endpoint** | Reads memory, keys, plaintext, history | Malware, physical access, a malicious build | None. **Explicitly not defended** | Complete compromise |
| **A9 Bootstrap / view adversary** | Controls which relay descriptors a target can learn | Own the client's bootstrap contacts, or eclipse its DHT neighbourhood | Unchoosable `KadID`; d=3 disjoint lookups; bonded identities; diverse anchors | **`[UNSOLVED]`** — without a consensus, two clients hold different views and neither can tell |
| **A10 Storage adversary** | Runs many holders; refuses, lies about holding, or selectively withholds | Bonds + disks | Audit challenges (`p2p/challenge.go` transport, `internal/facilitation` proofs); k-of-n over diverse holders; deficit accounting | Selective withholding against a specific CID is cheap once the adversary can identify its shards |

The bond is the only thing that makes *f* expensive, and the bond minimum is a
policy that has not been set: `StakeVault.sol` has `bond`, `slash`,
`requestWithdraw` and a constructor-set `withdrawDelay`, and no minimum anywhere.
Until that number exists, *f* is limited by an adversary's willingness to run
machines — the same position Tor is in.

### 4.2 Properties AXON aims to provide, stated precisely

Each is an adversary's inability to distinguish two worlds, scoped to a class from
§4.1 and a traffic class from R2.

| Property | Precise statement | Holds against | Fails against | Basis |
|---|---|---|---|---|
| **Sender anonymity** | Given a stream arriving at a service, the adversary cannot say which `NodeIdentity`/IP originated it better than its prior over the client set | A1, A5 alone, A6, A10 | A2 holding guard + far end; A3/A4 seeing both ends; A8 | 3-hop circuits, layered AEAD, guards |
| **Recipient anonymity** | Given a service reachable by name, the adversary cannot determine the IP hosting it | A1, A2 below the guard threshold, A7, A9 partially | A2 holding the service's guard and a rendezvous-adjacent position; A8 | Intro + rendezvous (R10); no endpoint is ever published |
| **Session unlinkability** | Two sessions by one client to different services cannot be linked | A1, A5 across services, A6 with blind tokens | A2 at the shared guard over time; A3 | Per-context guard isolation; separate circuits; one identifier per role |
| **Interest privacy at the DHT** | A node storing a descriptor cannot tell which name it stores or which client asked | A1, A9 for content, A10 | Nobody if blinding is correct — but a *global* view of blinded keys across periods may permit linkage `[NEEDS RESEARCH]` | Blinded keys (R4c); lookups over circuits (R4b) |
| **Content confidentiality from holders** | A holder cannot read a shard it stores | A1, A10 | Anyone holding the CID capability | R5; existing content-addressed ciphertext |
| **Payment unlinkability** | A relay paid for carriage cannot link the payment to the circuit's client | A1, A6 | Nobody in v1 — **there are no payments in v1** | R11, design only |
| **`BULK` correlation resistance** | An adversary seeing both ends needs materially more observation than for `INTERACTIVE` | A3, A4, *partially and quantifiably per padding schedule* | A global adversary with unlimited time | R2 |
| **Ownership integrity** | Only `OwnerIdentity` can change what `alice.lab.axon` resolves to, and a stale resolver reports its staleness | A6, A9, a lying RPC provider | Whoever holds `OwnerIdentity`'s private key | R7 + `internal/ethproof` |

### 4.3 Properties AXON explicitly does not provide

Refusals, not omissions:

- **Correlation resistance for `INTERACTIVE`** against an adversary seeing both
  ends (§4.5).
- **Membership concealment.** Whether you use AXON is visible to A7. Relays are
  public by design and therefore enumerable and blockable. No v1 bridge or
  obfuscated-transport story exists.
- **Anonymous name ownership.** R6 gives pseudonymity with an unsolved
  funding-graph linkage. Registering a name is a chain transaction, always.
- **Protection from the service** (A5). Nothing at the infrastructure layer stops
  a service identifying its users from what they send it.
- **Endpoint security** (A8). No overlay fixes a compromised machine.
- **Resistance to long-term intersection attacks** against a persistently online,
  low-churn user.
- **Resistance to targeted state-level active attack** on a specific known user.
- **Permanence of stored content.** R8 declares tiers, not forever.
- **A consistent network view** (R14 / A9). `[UNSOLVED]`

### 4.4 The anonymity trilemma, and AXON's position

The formal result in the anonymous-communication literature: no protocol has all
three of **strong anonymity**, **low latency** and **low bandwidth overhead**.
Strong anonymity means an adversary observing the network has negligible advantage
in deciding which of two senders sent a message. It is a lower bound — to defeat an
observer who sees both ends, either messages are delayed or noise is sent when
there is nothing to send, and the required amount of each is bounded below by user
count and message rate. AXON refuses to pick once, and makes the choice explicit:

```text
                    strong anonymity
                           ▲        ┌────────────┐
                           │        │    BULK    │  anonymity, paid in
                           │        │  padded,   │  bandwidth and latency
                           │        │  batched   │
   low bandwidth ◄─────────┼────────└────────────┘──► low latency
     overhead      ┌───────┴───────┐
                   │  INTERACTIVE  │  latency + low overhead; correlation
                   │   no cover    │  by a both-ends adversary is EXPECTED
                   └───────────────┘
```

- `INTERACTIVE` takes low latency and low overhead and therefore does **not** have
  strong anonymity. It has anonymity against A1, A5, A10 and against A2 below the
  guard threshold — real and useful, and not the strong property.
- `BULK` pays in bandwidth and latency; its resistance is quantified **per padding
  schedule**, and the section specifying that schedule owes the quantification.
- No third class exists, because a class claiming all three would be the lie the
  trilemma forbids.

### 4.5 End-to-end correlation: a design acceptance

> **`INTERACTIVE` traffic in AXON is vulnerable to end-to-end correlation by an
> adversary who observes both ends of the connection. This is a design
> acceptance, not an oversight.**

Layered encryption changes a cell's bytes at each hop; it does not change *when*
the cell moves or *how many* cells there are. An observer at the client's link and
one at the service's link see two streams whose inter-packet timing and volume
envelopes match, offset by the circuit RTT. Published traffic-correlation work
against low-latency onion routing reports high true-positive rates at low
false-positive rates given minutes of observation; we do not restate figures we
have not measured, and the direction of the result is not in dispute.

What follows:

1. **No section may claim correlation resistance for `INTERACTIVE`** — not "makes
   it harder", not "raises the cost". The honest claim is that the adversary must
   *hold both ends*.
2. **Our defences are probability defences.** Guards (R1) fix the first-hop draw;
   diversity constraints reduce the chance one AS or ASN sees both ends;
   stake-capped weighting (C20) prices up a large *f*. Each reduces P(adversary
   holds both ends). None reduces P(correlation succeeds | adversary holds both
   ends), which is close to 1.
3. **`BULK` exists so the operations that can tolerate delay do.** Dispersal,
   repair, descriptor publication and token redemption are all `BULK`, so the most
   voluminous and most schedulable traffic is also the padded traffic.
4. **The API makes the acceptance visible.** `Class=INTERACTIVE` is a required
   argument precisely so the choice appears in the caller's code and in review.

### 4.6 Guard arithmetic, and what it does and does not buy

```text
  P(at least one of 2 guards hostile) = 1 − (1−f)²
      f = 0.01 → 1.99 %     f = 0.05 → 9.75 %     f = 0.10 → 19.0 %

  P(adversary holds both ends of a circuit) ≈ P(guard hostile) × f
      f = 0.05 → 0.49 % averaged over clients, but 5 % per circuit for a
                 client whose one-time guard draw was unlucky
  (§2.2 has the churn comparison: without guards, compromise is certain daily.)
```

*(Arithmetic under independence and uniform selection. Real selection is
bandwidth-weighted, so an adversary buying weight — bounded by C20 — gets more
than its node-count share. This shows the shape of the guard argument, not AXON's
exposure.)*

What it buys: the compromise decision is made once per 45-day rotation rather than
continuously, so most clients are never first-hopped and the unlucky minority are
compromised stably and therefore in principle detectably. What it does not buy:
anything for that minority, and nothing at all against A3/A4, who need not own a
relay.

### 4.7 Decision table

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Classes A1–A10 as the unit of every claim | Unscoped anonymity claims are false claims | Tor's threat-model discipline | Added A6 (chain) and A9 (view), neither in Tor's model | A single "the adversary"; global-passive-only | A taxonomy invites gaps; a real adversary is several classes at once |
| Declare `INTERACTIVE` correlatable (R2, §4.5) | Users cannot reason about a property nobody states | Tor states this; I2P less clearly | Made it an API-visible required choice | Claiming mixnet properties; one class | Users may pick `INTERACTIVE` for everything because it is faster |
| Two classes, no tunable knob | A single class must lie about one axis | The formal trilemma result | Two named classes | A continuous latency/padding knob | The class label is observable and partitions the anonymity set |
| Guards as a probability defence only | Guards are routinely oversold as correlation defence | Tor guards | Stated as P(both ends), never as correlation resistance | Claiming guards defeat correlation | The unlucky ~10 % at f=0.05 gain nothing |
| Membership concealment out of scope in v1 | A half-built obfuscation layer is worse than none | Tor pluggable transports, deferred | Explicit refusal with a reason | Shipping weak obfuscation | AXON is blockable, and blocking is how most users lose access |
| Chain observer as first-class (A6) | Ownership and bonding are permanently public | New — blockchains post-date Tor's model | Named the linkages we cannot fix | Treating the chain as neutral | Naming a risk does not reduce it |

### What this section does NOT establish

- **`BULK`'s correlation resistance is unquantified.** The bound depends on a
  padding schedule this section does not specify; until then the advantage is a
  design intention.
- **No AS-level or IXP-level path analysis.** A3 and A4 are stated as capabilities
  without a model of which paths they see. Doing it properly needs BGP data and a
  path-prediction model; without it, "ASN diversity" is a heuristic.
- **No cost figure for A2.** *f* is limited by bonding and the minimum bond does
  not exist in `StakeVault.sol`.
- **Nothing here is measured.** Every probability is arithmetic on assumptions.
  AXON has no deployed network, no measured anonymity set, no churn model and no
  observed relay distribution.
- **A9 is not defended against**, only made more expensive — the same `[UNSOLVED]`
  as R14, and the most likely place for this design to fail in practice.
- **Intersection attacks are acknowledged and unaddressed.** A user online on a
  regular schedule, with a persistent service, over months, is identifiable by
  nothing more sophisticated than a calendar.

> **Objection to Constitution §5:** the parameter table gives "Content chunk:
> 256 KiB — confirm against existing `internal/store`". The existing default is
> **1 MiB** (`ChunkBytes: 1 << 20`, `internal/config/config.go:574`), validated to
> 64 KiB..16 MiB (`:820`). Sections 2 and 3 quote the code and flag the gap rather
> than asserting 256 KiB. If 256 KiB is intended as a *change* it needs a reason,
> because it quadruples shard count per object and therefore placement and repair
> work per byte.

> **Objection to Constitution §5 (second):** "DHT replication r=8 across distinct
> /24 (v4), /48 (v6) and distinct ASNs — reuse the existing placement engine's
> diversity levels." The existing engine has **no** prefix or ASN awareness.
> `internal/placement/plan.go` guarantees only that no two shards of one chunk go
> to the same peer, and a grep for `asn`, `/24`, `subnet` or `prefix` across
> `internal/placement` and `internal/store/placement.go` returns nothing. The
> diversity levels are new work, not reuse, and dependent sections should budget
> accordingly.
