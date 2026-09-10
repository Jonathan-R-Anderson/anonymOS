## 18. Threat Model

**The finding that shapes this section: the highest-leverage attack on AXON is
not on the overlay at all. It is the software update channel, and today it is
unauthenticated.** `scripts/update-from-github.sh` fetches
`refs/heads/main` from a GitHub URL over TLS, builds it, and installs the
result as the running node. There is no commit signature check, no release
signature, no reproducible-build attestation, and — as `scripts/check-release.sh`
says in its own comments — "this repository has no CI, no hooks and no cron".
The `.sha256` files in `dist/` are hashes with nothing signing them. An adversary
who obtains write access to one branch of one repository owns every node that
runs the updater, at every layer simultaneously, and no amount of onion routing
below that matters. Everything else in this section is a smaller attack than
that one.

The second finding is structural: **AXON's threat surface is not the union of
Tor's, I2P's and Freenet's — it is their union plus a chain plane and an
accounting plane that neither Tor nor I2P has.** Domain hijacking, RPC lies,
reorg exploitation, contract owner-key compromise and receipt forgery are new
threat classes that anonymity-network prior art has no answers for, because
those networks have no on-chain authority to attack.

The third: several of the attacks below are **not mitigated**, and a few are
not mitigable within this design. They are gathered in §18.18 so a reader
cannot skim past them.

---

### 18.1 What already exists

| Existing artefact | Path | What it contributes to this threat model |
|---|---|---|
| A written security model | `storage-client/SECURITY.md` | Trust boundaries, admission rules, the `GO-2024-3218` Kademlia availability advisory, and an explicit statement that I2P hides IPs but not timing, sizes or the fact of I2P use. This section extends its register rather than replacing it. |
| Adversarial tests, not just unit tests | `internal/p2p/recall_lying_holder_test.go`, `refusal_test.go`, `recall_failure_test.go` | A holder that claims deletion and keeps the bytes is caught by a follow-up `have`; an unverifiable claim is *not* credited as a deletion. The culture of "test the lying peer" is already here. |
| DHT record validation | `internal/dcs/dht.go` (`WorkerDHTValidator`) | Records must be ≤64 KiB, stored under their own node's key, signed by that key, and live ≤3600 s; `Select` prefers the highest `Sequence`. This is the shape L3 record validation must keep. |
| Replay guard | `internal/dcs/replay.go` (`MemReplayGuard`) | Nonce table bounded by envelope expiry, pruned lazily. Correct pattern; wrong scale for L4. |
| Bootstrap corroboration | `internal/bootstrap/discover.go`, `bootstrap.go` | `maxSources = 5`, `DefaultAgreement = 2`. With a pinned `CoordinatorKey` a document is *verified*; without one it is explicitly logged as "corroborated rather than verified". That distinction is exactly right and must survive into AXON. |
| Audit / challenge transport | `internal/p2p/challenge.go` | Opaque-payload PoF challenges riding the storage protocol, `challengeTimeout = 90s`; `PeerForNodeID` documents that unreachable must mean "could not audit", never "failed the audit". |
| Chain verification | `internal/ethproof`, `doc/trust-anchor.md` | A real light client: 512/512 mainnet sync-committee signature verified, and the harness *refuses to run* if the beacon endpoint and the execution RPC share a provider. This is the only defence that exists today against an RPC that lies. |
| Reorg observation | `doc/p12-8-reorg-observation.md`, `internal/channel.ObserveReorgs` | Chain-linkage verification, and an explicit refusal (`ReorgObservation.AsEvidence`) to convert "no reorgs seen" into evidence. Reorg depth is budgeted, **not measured**. |
| Accounting contracts | `proof-of-facilitation/contracts/` | `NodeRegistry`, `StakeVault`, `EpochManager`, `RewardDistributor`, `DisputeManager`, `ServicePolicyRegistry` — all OpenZeppelin `Ownable`, **no proxy pattern anywhere** (no UUPS, no `Initializable`, no `delegatecall`). Read for §18.13. |
| Release build | `scripts/build-release.sh`, `check-release.sh`, `dist/` | Seven targets, `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`. Reproducible per-commit; unsigned. Read for §18.14. |

**What must be replaced.** The current model's anonymity threat surface is
I2P's, because anonymity is outsourced to `internal/i2p`. Every row in §18.5–§18.9
below is therefore a threat against code that does not exist yet, and is written
as a requirement on it. The rows in §18.10–§18.14 are threats against code that
does exist and were checked against it.

---

### 18.2 How to read the tables

Every threat carries four fields, per the brief: the attack, the vulnerable
component, the mitigation, the residual risk. IDs are stable
(`T-<layer>-<nn>`) so other sections and reviewers can cite a row.

The residual column uses four words with fixed meanings:

| Word | Meaning |
|---|---|
| **bounded** | The attack still works but its yield is capped by a stated quantity. |
| **detectable** | The attack succeeds once, then is attributable and punishable. |
| **unmitigated** | We have no defence. Named here and gathered in §18.18. |
| **out of scope** | Outside the adversary model of §4; stated so it is not mistaken for a gap we failed to notice. |

Component markers follow the house convention: `[BUILD NOW]`, `[NEEDS RESEARCH]`,
`[UNSOLVED]`.

---

### 18.3 Threat-model decisions

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| **Declared traffic classes** — `INTERACTIVE` is documented as correlatable end-to-end; `BULK` gets batching and padding (R2) | Users and integrators cannot reason about a property the protocol does not name | Tor's honest "we do not defend against a global adversary"; I2P's per-tunnel padding | The class is a **caller-visible API parameter**, not a footnote, so the weaker property is chosen explicitly | A single uniform class with cover traffic (unaffordable at interactive latency); silently claiming mixnet properties | The class label is itself an observable: choosing `BULK` marks a flow as high-value to an observer |
| **No clearnet exit role in v1** | Exit sniffing, exit-side abuse liability, and exit-node deanonymisation are Tor's largest operational costs | Tor (which has exits); I2P (which largely does not) | Delete the role. All terminal hops end at an RP, an IP, or a storage peer inside the overlay | An exit capability behind a flag — rejected because a flag that exists gets turned on | The overlay is now unusable for clearnet fetch, so users will run their own bridges and get *worse* isolation than a designed exit would give |
| **Position-power model for relays** (§18.16) rather than a single "malicious relay" row | "Malicious relay" hides that the three positions have entirely different powers | Tor's guard/middle/exit analysis | Made it a normative table that path selection and padding decisions must cite | One aggregate relay-trust score | Encourages treating middle relays as harmless; they are not (they can partition and fingerprint) |
| **Per-layer DoS budget with named exhaustible tables** (§18.15) | DoS is written as "rate limit it" and then nobody knows which table overflowed | Tor's DoS lessons at introduction points (R10) | Each layer must name its bounded resource and the eviction policy | A global connection rate limit only | Eviction policies are themselves an attack: an attacker who can force eviction can evict *chosen* state |
| **Explicit non-mitigation register** (§18.18) | Hopeful mitigations are worse than none because they stop people looking | Tor's design docs, which do this | Gathered in one subsection with no softening language | Distributing the caveats through the text | A reviewer may read §18.18 alone and conclude the system is weaker than it is |
| **Release signing made a v1 blocker** (§18.14) | The update channel is the highest-leverage attack and is currently unauthenticated | None — this is not an overlay-network idea, it is a supply-chain one | Elevated from "ops hygiene" to a protocol-level requirement with a fail-closed verifier in the node | Continuing with TLS-only trust in a Git branch; hashes without signatures | A signing key is a new single point of compromise, and a threshold scheme is a new consensus problem |
| **Isolation contexts are the anonymity unit, not circuits** | Cross-role correlation on a multi-role machine (§18.12) | Tor's stream isolation; I2P's per-destination tunnel pools | Contexts span guards, tunnel pools, DHT lookups, payment tokens and descriptor fetches — one boundary, not five | Per-stream isolation only (leaks via shared guards); per-process isolation (unenforceable) | More contexts means more guards and a larger total exposure to guard selection (§18.16) |

---

### 18.4 Adversary classes

§4 is authoritative. Restated here only as the axis the tables are scored
against; do not re-derive it.

```text
A1  LOCAL OBSERVER      the user's ISP / LAN / a wiretap on one access link
A2  RELAY ADVERSARY     runs a large but minority fraction of relays, storage
                        and DHT nodes; bounded by bonding cost
A3  NETWORK ADVERSARY   observes a substantial fraction of Internet paths but
                        NOT all; can AS-level or IX-level correlate
A4  CHAIN ADVERSARY     observes the blockchain completely; may control an RPC
                        provider; may propose/reorg at the margin
A5  SERVICE ADVERSARY   is the service the user talks to, or is the client
                        talking to the service
A6  SUPPLY ADVERSARY    controls the software the user runs, or its update path
A7  GLOBAL PASSIVE      sees every link. EXPLICITLY NOT DEFENDED AGAINST.
```

A6 is not in the Constitution's list. It is added here because §18.14 shows it
is the strongest adversary that a real deployment actually faces, and because
omitting it would make this document misleading in exactly the way §18.21
warns about.

---

### 18.5 L1 — Secure transport

| ID | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| T-L1-01 | MITM on a link, substituting a relay's transport key | QUIC + TLS 1.3 raw-public-key handshake `[BUILD NOW]` | Peer authenticated against the `RoutingIdentity` X25519/Ed25519 pair carried in the signed relay descriptor; no PKI, no CA to compromise | An adversary who controls descriptor delivery (T-L3-04) controls the key you authenticate against. Transport security is **only as good as descriptor integrity** |
| T-L1-02 | Passive recording of ciphertext for later decryption ("harvest now, decrypt later") | X25519 key exchange | Hybrid slot (`X25519 + ML-KEM-768`) reserved in the wire format and selected by version negotiation; v1 ships X25519 | **Unmitigated in v1 by construction.** Traffic recorded in v1 is decryptable by a future CRQC. Long-lived `ServiceIdentity`/`DomainIdentity` signatures are Ed25519 and equally exposed |
| T-L1-03 | Downgrade of the negotiated suite | Version negotiation | Negotiated parameters are bound into the transcript hash and into the HKDF-SHA256 label; a downgrade changes the derived key and the handshake fails | A version-rollback attack against a client that *has no* hybrid support is indistinguishable from an honest old client. Rollback protection needs a floor policy, which is `[NEEDS RESEARCH]` |
| T-L1-04 | QUIC fingerprinting — identifying `axond` by its handshake, transport parameters, initial packet shape and version | QUIC stack, `[NEEDS RESEARCH]` | Fixed transport parameter set across all nodes; single QUIC version; no client-tunable knobs on the wire | **Bounded, not removed.** A distinctive stack identifies AXON traffic to A1/A3 even when contents are hidden. R12's one-stream-per-circuit is itself a fingerprint: stream-count-versus-bytes is unlike any browser |
| T-L1-05 | Traffic-shape identification of AXON without decryption | Cell layer | 1024 B fixed cells on every link regardless of hop count | Cells are fixed; **packet timing and stream counts are not**. A censor can block AXON without breaking it (see T-L1-06) |
| T-L1-06 | Blocking / censoring AXON at the network edge | L1 as a whole | None in v1. Pluggable-transport-style obfuscation is out of scope for v1 | **Unmitigated.** AXON is designed to be anonymous, not unblockable. Do not describe it as censorship-resistant at the transport layer |

---

### 18.6 L2 — Peer and membership

| ID | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| T-L2-01 | **Sybil** — flooding the relay/storage/DHT population with cheap identities | Peerbook, path selection, DHT routing table `[BUILD NOW]` | Bonded stake via the existing `StakeVault`/`NodeRegistry`; path-selection weight bounded by bond *and* by measured delivery receipts (R14); placement diversity over distinct /24, /48 and ASN reusing `internal/placement` | Bonding raises the price of a Sybil, it does not prevent one. A funded adversary buys exactly the fraction of the network they are willing to pay for, and the *price* is a governance parameter nobody has set. `[UNSOLVED]` at the level of "what bond makes 20 % infeasible" |
| T-L2-02 | **Eclipse of a node** — surrounding a target so every peer it knows is hostile | Peerbook, bootstrap | Peerbook diversity requirement across ASN and prefix; guards pinned for 45 days so an eclipse must survive guard rotation to matter; multiple bootstrap sources (`maxSources = 5`) | A node eclipsed *at first start*, before it has any peerbook, is eclipsed permanently, because everything it learns afterwards comes from the eclipsing set. First-start is the weak moment and it always will be |
| T-L2-03 | **Compromised bootstrap seed set** | `internal/bootstrap` `[BUILD NOW]` | Pinned coordinator key makes a document *verified*; without a pin, `DefaultAgreement = 2` of up to 5 sources must agree, and the code logs that this is "corroborated rather than verified" | Corroboration is not verification and the existing code says so. An adversary who controls the SRV record and 2 of 5 gateways defeats the unpinned path outright. For AXON the pin must become **mandatory**, which pushes the problem into §18.14: the pin ships in the binary |
| T-L2-04 | Reachability lying — claiming relay capability without providing it | Capability advertisement (R3) | Reachability-gated advertisement plus delivery receipts; a relay that does not forward earns nothing | Between advertisement and the first audit, a lying relay is selected. The window is the audit interval, and the audit interval is `TBD — must be set by the accounting-plane section` |
| T-L2-05 | NAT / hole-punch abuse: using the punch protocol to make a victim connect somewhere | NAT traversal `[NEEDS RESEARCH]` | Punch targets restricted to peers already authenticated at L1; no address supplied by a third party is dialled unvalidated (the existing `internal/gateway/probe.go` SSRF hardening is the pattern: reject local, private, link-local, CGNAT, documentation, multicast and unspecified targets) | A relay can still cause a *bounded* number of dials to addresses it names, which is a low-rate amplification and scanning primitive |
| T-L2-06 | Membership enumeration — building a full list of AXON nodes | DHT membership (R4a) | **None, and deliberately none.** Relays are public by design | Every relay operator is publicly identifiable as an AXON relay operator. In jurisdictions where that is dangerous, running a relay is dangerous. Say so to operators; do not imply otherwise |

---

### 18.7 L3 — DHT

| ID | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| T-L3-01 | **Malicious DHT node** returns wrong values, empty results, or "not found" for records it holds | Lookup path `[BUILD NOW]` | All records are signed; a wrong value is rejected on signature. `d = 3` disjoint lookup paths, `α = 3`, `k = 20` (S/Kademlia-style) so a single hostile path does not decide the answer | A hostile node can still **withhold**. `GO-2024-3218`, named in the existing `SECURITY.md`, is exactly this: hostile peers can attempt to hide provider records, with no upstream fix. Withholding is an availability attack that signatures cannot touch |
| T-L3-02 | **DHT poisoning** — storing forged or over-large records | Record validator | Port the `WorkerDHTValidator` shape: record ≤64 KiB, must be stored under its own derived key, must be signed by the key that key is derived from, must carry `IssuedAt`/`ExpiresAt` with a bounded lifetime, `Select` takes the highest sequence number | Highest-sequence-wins is a **rollforward** primitive: an adversary who obtains a signing key once can publish sequence `2^63` and permanently pin a record until the key is revoked on-chain. Sequence ceilings are `[NEEDS RESEARCH]` |
| T-L3-03 | **Eclipse of a key** — placing chosen identities around a target keyspace position to own every replica of one record | Keyspace assignment `[BUILD NOW]` | `KadID = H(NodeIdentity ‖ SRV_epoch ‖ network-prefix)`, so a node cannot choose its position; it rotates every 24 h epoch; replication `r = 8` across distinct /24, /48 and ASN | Grinding: an adversary generates many `NodeIdentity` values offline and keeps those whose `KadID` lands near a target. Rotation means they must grind for *each* epoch, but the SRV is known at epoch start, so they have the whole epoch. **Cost of grinding is bounded only by bond cost per identity**, which returns to T-L2-01 |
| T-L3-04 | Partitioned view — different clients shown different relay descriptor sets (the epistemic attack of R14) | Absence of a consensus document | Diversity requirements, disjoint lookups, and cross-checking descriptors seen through different circuits | **Unmitigated, and named as such in R14.** Without a consensus there is no ground truth to compare against. This is the single largest unsolved problem in the design `[UNSOLVED]` |
| T-L3-05 | Lookup-interest leakage — the storing node learning what a client is looking for | Lookup path (R4b, R4c) | Client lookups always traverse a circuit, so the storing node sees a relay; descriptors are stored under **blinded** keys derived per time period, so the storing node learns neither the domain nor the service | The storing node learns *that a blinded key was requested*, and how often. Popularity of a service is measurable even when its identity is not, and popularity plus a candidate list is a confirmation oracle |
| T-L3-06 | **Descriptor enumeration** — walking the DHT to harvest every service that exists | Descriptor keyspace | Blinded keys rotate every 24 h time period with 12 h overlap; a harvested key is useless after the period and does not reveal the `ServiceIdentity` | Enumeration of *how many* services exist, and of their publication timing, remains possible. A service that publishes at a fixed offset from midnight UTC is fingerprintable across periods, which partially defeats blinding. Publication jitter is `[BUILD NOW]` and must not be forgotten |
| T-L3-07 | Storage-node crawling to build a shard-holder map | Content keyspace (R4d) | Content and descriptor keyspaces are separate record types; shards are encrypted and content-addressed | Two peers advertising the same encrypted shard ID are linkable — the existing `SECURITY.md` already names this. Shard IDs are a global correlation index across the whole network |
| T-L3-08 | Record replay — re-publishing an old, still-signed record after it was superseded | Record validation | `ExpiresAt` bounded (≤1 h in the existing worker records; ≤3 h for AXON descriptors), monotonic `Sequence`, and the time period baked into the blinded key | Within the freshness window a superseded record is replayable, so revocation is not instant. Revocation latency = descriptor lifetime = **3 h worst case** |

---

### 18.8 L4 — Tunnel / circuit

| ID | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| T-L4-01 | **Malicious first hop (guard)** learns the client's IP and every timing/volume pattern of everything that client does | Guard selection `[BUILD NOW]` | 2 primary guards per isolation context, 45-day rotation, 90-day list (R1). Every tunnel in a pool starts at one of that context's pinned guards, so I2P-style churn never re-rolls the first-hop dice | If a guard is hostile, it is hostile for 45 days and sees **everything in that context**. Guards convert "eventually certain compromise" into "one weighted coin flip, held for 45 days". That is the trade, and it is not free |
| T-L4-02 | **Malicious middle hop** | Path selection | Learns only its predecessor and successor; layered AEAD prevents reading or modifying payload undetected | Middles can **drop, delay and reorder**, which is a fingerprinting primitive (T-L4-06) and a partitioning primitive: a middle that fails only for chosen circuits shapes which relays a client believes are working |
| T-L4-03 | **Malicious terminal hop / RP** | Rendezvous joining | Terminal hops never reach clearnet (no exit role, §18.3); an RP joins two 3-hop legs and sees neither endpoint's location | An RP is **by construction a correlation point between the two legs**: it sees both halves' volume and timing at zero cost. It cannot locate either endpoint, but it can confirm that this client-side circuit and that service-side circuit are one conversation |
| T-L4-04 | **Colluding relay sets — end-to-end correlation** | The whole L4 design | Guard pinning (R1), path diversity across ASN/prefix, `BULK` padding for the storage plane | **The primary unmitigated attack against `INTERACTIVE`.** See the arithmetic below. Correlation does not require breaking anything |
| T-L4-05 | Timing attack: injecting a recognisable pattern at one end and looking for it at the other | Cell scheduling | `BULK` batching; best-effort padding on `INTERACTIVE` | Active timing watermarks defeat best-effort padding. `INTERACTIVE` is explicitly vulnerable (R2), and padding that would stop it costs more bandwidth than the network has |
| T-L4-06 | Circuit fingerprinting — identifying a circuit by its build latency, extend pattern, or per-hop RTT | Circuit construction | Fixed cell size; uniform extend cell shape | Build-time RTT reveals approximate geography of the next hop to the previous hop. Not removable without padding the handshake, which is `[NEEDS RESEARCH]` |
| T-L4-07 | Cell tagging / bit-flipping to mark a stream for downstream recognition | Onion layer crypto | Per-hop AEAD with a 16 B tag reserved for **every** hop position; a modified cell fails authentication at the next hop and the circuit is torn down | Tearing down on failure is itself a signal. An adversary who can flip a bit and observe teardown has a 1-bit confirmation channel with a cost of one circuit |
| T-L4-08 | **Replay** of a captured cell into a live circuit | Circuit state | AEAD nonces are derived from a per-direction counter; a repeated counter is rejected without decryption | A replay against a *torn-down* circuit produces a distinguishable error, giving a liveness oracle for a circuit ID |
| T-L4-09 | **Routing manipulation** — steering a client onto attacker-controlled paths by lying about descriptors, capacity, or availability | Path selection (R14) | Weights derived from self-reported capacity **bounded by** bonded stake and by measured delivery receipts, never from a central measurement authority | Self-report bounded by bond still lets a well-funded adversary buy weight. Combined with T-L3-04 (partitioned views) this is the compound attack that worries us most, and neither half is solved |
| T-L4-10 | **Guard discovery** — locating a hidden service's guards by injecting traffic and observing which relays react | Service-side guards | Guard pinning; rate limiting at introduction points via a proof-of-work / token puzzle (R10) | Guard discovery against a service that answers requests is a **known, working attack class in Tor and it works here too**. Rate limiting raises its cost; it does not close it. `[UNSOLVED]` |
| T-L4-11 | Circuit-building oracle: forcing rebuilds to sample a client's guard set | Tunnel pool rebuild (10 min, rebuild at 70 %) | Guards are pinned across rebuilds, so rebuilds never re-sample the first hop | Hops 2..n *are* re-sampled every 10 minutes, so an adversary observing many rebuilds learns the client's middle-relay preference distribution, which is a weak but persistent behavioural fingerprint |

#### The correlation arithmetic, stated with its assumptions

This is arithmetic, not measurement. It assumes uniform independent selection,
which bandwidth weighting violates, and independent relay compromise, which
shared hosting violates. Both violations move the answer the wrong way.

```text
Let g = bandwidth-weighted fraction of guard-capable relays under one adversary.
Let f = bandwidth-weighted fraction of all relays under that adversary.

Naive Tor-style path, no guards, per circuit:
    P(first AND last hostile) = f²         and over n circuits it tends to 1.

Guard-constrained pool (R1), 2 primary guards per isolation context:
    P(at least one of the context's guards is hostile) = 1 - (1-g)²
    Once that is FALSE, no circuit in the context can be end-to-end correlated
    by that adversary via relay position alone, for the whole 45-day period.
    Once it is TRUE, every circuit in that context is a candidate, and only the
    terminal side still has to land, which it does with probability ~f per
    circuit and therefore ~1 over the period.

So the design converts a per-circuit risk that accumulates to certainty into a
per-CONTEXT risk that is decided once. It does not reduce the adversary's yield
when the coin lands their way; it reduces how often it lands their way.

Worked, for intuition only (g = 0.05):   1 - 0.95² = 0.0975
Worked, for intuition only (g = 0.20):   1 - 0.80² = 0.36
```

Two honest consequences. First, more isolation contexts (§18.12) means more
independent coin flips, so **isolation and guard exposure trade against each
other**; the optimum is not known and is `[NEEDS RESEARCH]`. Second, an
adversary at A3 (network observer) does not need relays at all — see T-L4-04
and §18.19.

---

### 18.9 L5 — Rendezvous, and the service/client relationship

| ID | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| T-L5-01 | Malicious introduction point drops rendezvous requests, censoring a service | IP selection `[BUILD NOW]` | A service publishes several IPs in its descriptor and rotates on failure | An IP that drops *selectively* (some clients, not all) is hard to distinguish from network loss. Selective censorship is **detectable only statistically** and no detector is specified |
| T-L5-02 | Introduction-point flooding (Tor's real DoS lesson) | IP request handling | Proof-of-work / token puzzle at the IP (R10), rate limited per requester | A puzzle taxes honest mobile clients most and the attacker least, because the attacker has more CPU than a phone. Puzzle difficulty is a **denial-of-service knob that can itself deny service** |
| T-L5-03 | Enumerating a service's tunnel endpoints | Descriptor contents | Two-stage intro+rendezvous is kept precisely so the published endpoint is not the service's tunnel endpoint (R10) | The client learns the RP it chose and the IPs it used. A **malicious client** therefore learns a rolling sample of the service's IP set, and many malicious clients learn most of it |
| T-L5-04 | **Malicious service host** deanonymising its clients | The service itself | None at the protocol layer. Circuits hide network location; they do not hide anything the client sends | **Out of scope by §4, and the largest practical risk to users.** A service that asks for an email address gets one. See §18.21 |
| T-L5-05 | **Malicious client** attacking a service: resource exhaustion, application exploits, or forcing distinguishable behaviour to confirm a hypothesis about the host | Service-side rendezvous handling | Per-client rate limits keyed on rendezvous cookie; connection caps; puzzles | A client that costs the service more than it costs itself always wins eventually. Asymmetric-cost analysis per service is `[NEEDS RESEARCH]` |
| T-L5-06 | Rendezvous cookie replay or prediction | RP protocol | Cookies are 128-bit random, single-use, bound to the circuit that presented them | An RP can replay a cookie to itself to keep a dead rendezvous slot alive — a small state-holding DoS, bounded by the RP's own slot table |
| T-L5-07 | Confirmation attack: an adversary who suspects host X runs service S takes S offline and watches X | Service availability | None | **Unmitigated.** Availability is observable and correlating it with a suspect host's uptime is trivial. This is the attack that catches real services |

---

### 18.10 L6 — Service and content

| ID | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| T-L6-01 | Content substitution — a holder returns different bytes | Retrieval path | BLAKE3 Bao-style verified streaming: every chunk is verified against the root before use. The existing store already does the SHA-256 analogue (`SECURITY.md`: "Every returned shard must match its SHA-256 ID before Reed-Solomon reconstruction") | Substitution becomes a **denial** attack rather than an integrity attack. That is the correct trade and it is not free: a holder can deny cheaply and repeatedly |
| T-L6-02 | Lying holder — claims to hold a shard it does not, or claims deletion while retaining | Storage accounting | Audit challenges over the existing `internal/p2p/challenge.go` transport; the `recall_lying_holder_test.go` pattern — a delete claim is confirmed by a follow-up `have`, and an unverifiable claim is **not** credited | A holder that keeps the shard and also lies to `have` is a different and harder adversary; the existing test comments say so explicitly. Only a possession proof catches it, and possession proofs at scale are `[NEEDS RESEARCH]` |
| T-L6-03 | **Storage abuse** — using the network to store illegal or infringing content | Every storing node `[UNSOLVED]` | No node caches plaintext it did not request; stored objects are encrypted such that the holder cannot read them without the CID/key (R5); path caching is opt-in and only of encrypted shards; local operator blocklists supported | **Not solved and cannot be solved here.** A global blocklist is refused as re-centralisation (R5). An operator holds encrypted shards of content they cannot inspect, and "I could not read it" is a technical fact, not a legal defence in every jurisdiction. This must be stated to operators before they run a node |
| T-L6-04 | Operator liability from *retrieval* traffic they relayed | Relay operators | No exit role, so no clearnet-attributable fetches originate from a relay's address | Relay operators remain publicly enumerable (T-L2-06) and are the first people a plaintiff or prosecutor can find |
| T-L6-05 | Malicious content — content that exploits the retrieving client | L8 API consumers | AXON delivers verified bytes and makes no claim about their safety; no rendering, no execution, no scripting anywhere in the infrastructure | The API's callers will render what we hand them. The infrastructure boundary protects *us*, not the user |
| T-L6-06 | Erasure-coding parameter attack: pushing objects to layouts that maximise repair cost | Store configuration | `internal/config/config.go` bounds the layout: `DataShards ≥ 2`, `ParityShards ≥ 1`, `DataShards+ParityShards ≤ 64`, `ChunkBytes` in [64 KiB, 16 MiB]; defaults are 6/3 and 1 MiB | The bounds are wide. 62/2 is legal and catastrophic for durability. AXON must narrow this, and the narrowing is a `[BUILD NOW]` config change, not new code |
| T-L6-07 | Repair-loop amplification — inducing repeated rebalancing to burn network capacity | `internal/store/rebalance.go`, `internal/placement/level.go` | `LevelDeadband = 0.10` and `MinLevelMove = 64 MiB` exist precisely to stop two nodes trading bytes forever; shard moves are rate limited | The deadband is a *stability* control, not an *adversarial* control. A peer that misreports `Used` can still steer placement; measured-usage-only is documented in `level.go` but a peer's self-report of its own free space is still a self-report |

---

### 18.11 L7 — Naming, and the chain plane

Domain hijacking is two different attacks with different attackers, different
costs, and different blast radii. Collapsing them is the most common error in
this area.

```text
CHAIN-LEVEL HIJACK              RECORD-LEVEL HIJACK
attacker: holds/steals the      attacker: holds/steals DomainIdentity
  OwnerIdentity secp256k1 key     Ed25519 key, or gets a forged record
                                  accepted
effect:   transfers the name    effect:   redirects the name's records
  permanently, on-chain, in       until the key is rotated on-chain
  public
recovery: none — the chain      recovery: rotate DomainIdentity via the
  says they own it                OwnerIdentity, publish revocation
blast radius: the name itself   blast radius: everything under the name
  and all future records          for up to the descriptor lifetime (3 h)
```

| ID | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| T-L7-01 | **Chain-level domain hijack** — theft or coercion of `OwnerIdentity` | `AxonRegistry` ownership record | `OwnerIdentity` never touches the overlay (§3) and may be a multisig or hardware key; commit–reveal registration blocks front-running (R6) | Key theft is unrecoverable by design. There is no social recovery, no arbitration, and adding one would create the authority this design refuses. **State this to users: losing the owner key loses the name permanently** |
| T-L7-02 | **Record-level hijack** — compromise of `DomainIdentity` | Signed records, resolver | `DomainIdentity` is rotatable without a transfer and revocable on-chain; resolution prefers the highest-sequence record signed by the *currently committed* key | The revocation is only as fast as the resolver's chain freshness bound (R7). A resolver operating on a stale snapshot honours a revoked key for the length of its declared staleness window. **Revocation latency is a resolver policy parameter, and a resolver may lawfully be hours stale** |
| T-L7-03 | Front-running a registration | Registration flow | Commit–reveal (R6) | Commit–reveal breaks the *ordering* attack and partially breaks the timing link; it does not break the funding-graph link (T-L7-08) |
| T-L7-04 | **Registry contract bug** | `AxonRegistry` solidity | The existing PoF contracts show the pattern to follow: **no proxies anywhere** — no UUPS, no `Initializable`, no `delegatecall` in `proof-of-facilitation/contracts/`. A non-upgradeable contract cannot be silently rewritten | Non-upgradeable also means **unfixable**. A bug is migrated out of, not patched, and migration needs every name-holder to act. There is no good answer here; there is only choosing which bad one |
| T-L7-05 | **Upgrade-key compromise** | Not applicable in the current contract set; applicable to any future proxy | Do not introduce a proxy. If one is ever introduced it must be behind a timelock plus multisig, and the timelock must exceed the resolver freshness bound | If a future author adds a proxy, every row in this table becomes decorative. Flag this loudly in the contract review checklist |
| T-L7-06 | **Privileged-role compromise on the accounting contracts** | `proof-of-facilitation/contracts/` | Read from source: `DisputeManager.resolve(id, upheld, slashAmount)` is `onlyOwner`; `RewardDistributor.sweep(to, amount)` and `DisputeManager.sweep` are `onlyOwner`; `StakeVault.setSlasher` and `setWithdrawDelay` are `onlyOwner`; `EpochManager.setAggregator`, `setDisputeManager` and `setChallengeWindow` are `onlyOwner` | **A single compromised owner key can slash arbitrary stake, resolve any dispute either way, appoint itself slasher and aggregator, and sweep contract balances.** This is the largest concentrated risk in the existing code and it is a key-management problem, not a code problem. Multisig + timelock is `[BUILD NOW]` |
| T-L7-07 | **RPC provider lies** — fabricated headers, state roots and storage proofs | Resolver's chain access | Solved, and already built: `doc/trust-anchor.md` §1 shows that post-merge execution headers cost nothing to fabricate, and `internal/ethproof` verifies BLS12-381 sync-committee signatures — 512/512 verified against mainnet. The harness refuses to run if the beacon endpoint and the execution RPC share a provider | The **initial weak-subjectivity checkpoint is a subjective input**, taken from outside the RPC. It must come from a client release, several explorers, or a trusted peer — which is §18.14 again. Also: a light-client-capable beacon endpoint is rare (the table in `trust-anchor.md` §5b shows 1 of 8 probed endpoints served the light-client routes), so endpoint diversity is thin |
| T-L7-08 | Funding-graph linkage — the wallet that paid for `alice.lab.axon` is publicly linked to it | Chain plane, by construction | Registration through an unlinked account is *recommended*; `OwnerIdentity ≠ DomainIdentity` keeps the wallet off the overlay (R6) | **Unmitigated, and R6 says so: do not claim anonymous ownership.** A chain adversary (A4) sees the funding path. Mixing is out of scope and legally fraught |
| T-L7-09 | **Reorg exploitation** — acting on a registration or revocation that is later rewritten | Resolver, registry watchers | R7 puts the chain on a slow path with a long TTL and resolves from a signed snapshot. `doc/p12-8-reorg-observation.md` gives the detector: every new head must name the recorded hash for the previous height as its `parentHash`, so a single-slot rewrite breaks the link on the next poll; gaps are backfilled, not assumed good | **Reorg depth is budgeted at 30m and explicitly NOT MEASURED**, and `ReorgObservation.AsEvidence` refuses to turn "no reorgs seen" into evidence. The confirmation depth for a name transfer is therefore an unvalidated parameter |
| T-L7-10 | Chain outage or RPC censorship taking the namespace down | Resolution | R7: resolution runs from a locally verified signed snapshot replicated in the DHT; day-to-day records need no chain access at all; a resolver on a stale snapshot **must say so** | A snapshot that is never refreshed is a fork of the namespace. Freshness bounds must be enforced, not advertised, and an enforcement policy is `[BUILD NOW]` |
| T-L7-11 | **Resolver-cache-as-history** — the local `.axon` cache is a browsing history in a file | Resolver cache `[BUILD NOW]` | Cache entries encrypted at rest under a key that is not persisted across an explicit "forget" operation; TTL-bounded; per-isolation-context caches so one role's lookups never appear in another's cache | Encryption at rest does not help against a live endpoint compromise, and TTLs long enough to be useful are long enough to be evidence. **A cache is a history; the only real mitigation is not keeping one, and that costs resolution latency on every lookup** |
| T-L7-12 | **DNS leak of `.axon` queries** — the OS resolver sends `alice.lab.axon` to a recursive resolver, publishing the user's interest to their ISP and to the root servers | Host integration `[BUILD NOW]` | `.axon` must be intercepted before any system resolver call. The pattern already exists in this codebase: the libp2p host "registers only the custom I2P transport and advertises only `/garlic32` multiaddresses" and discards bootstrap records containing IP, DNS, TCP, QUIC, WebSocket or relay components (`SECURITY.md`). AXON needs the equivalent: a resolver that **has no DNS fallback path at all**, so a leak requires code that does not exist | Applications that bypass the AXON resolver (a browser with its own DoH, a library calling `getaddrinfo`) leak regardless. This is an integration failure mode, not a protocol one, and it is the single most likely real-world leak — the `.onion` special-use registration exists precisely because this happens constantly |

---

### 18.12 L8 — API surface, and the multi-role machine

| ID | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| T-L8-01 | **Cross-role correlation on a multi-role machine** — one host is a relay, a storage node, a service host and a client, and the roles are linkable | Node process, `[BUILD NOW]` | Separate identities by construction (§3: eight classes, no two ever the same key); separate isolation contexts with separate guards, tunnel pools, DHT lookups and payment tokens | **Timing links what keys do not.** A relay that is also a service host stops relaying when its service is busy. Shared CPU, shared NIC, shared bandwidth ceiling, and one uptime pattern. Only separate hardware truly separates roles, and the design cannot require that |
| T-L8-02 | Local API exposure — the L8 API bound to a reachable address | `axond` control surface | Follow the existing pattern exactly (`SECURITY.md`): loopback by default; a private-range bind requires a password of ≥12 characters compared in constant time; `0.0.0.0` and `::` refused with or without a password; Host header validated | An API on loopback is still reachable by every process on the machine. Process-level authorisation is `[NEEDS RESEARCH]` |
| T-L8-03 | Direct non-overlay traffic from the node revealing its address | Any component that speaks clearnet | The existing code has exactly this defect and documents it: the five-minute frontend heartbeat "is intentionally direct rather than I2P, per product requirements. It therefore exposes the node's public egress IP to `syndichan.org`" | **AXON must have no such exception.** If one is added for telemetry, updates or metrics, it deanonymises the node completely. This is a policy that must be enforced by the absence of a clearnet HTTP client in the binary, not by a code review |
| T-L8-04 | Configuration and identity file exposure | On-disk state | Owner-only permissions on configuration, identity, metadata and key files (existing practice) | A backup, a container image, or a support bundle exports the identity. Key material in a snapshotted VM is a common real-world compromise |
| T-L8-05 | **Node fingerprinting** — identifying a specific node across identity rotations by version, capability set, capacity claim, uptime and latency profile | Descriptors, capability advertisement | `RoutingIdentity` rotates per epoch while `NodeIdentity` persists for reputation — but the descriptor's *contents* are the fingerprint, not the key | Rotating a key while advertising 4.7 TB of capacity and the same 43-day uptime rotates nothing. **Descriptor contents must be bucketed** (capacity, uptime, version) or rotation is theatre. `[BUILD NOW]` and easy to forget |

---

### 18.13 Accounting plane

| ID | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| T-AC-01 | **Receipt forgery** — claiming service that was never provided | `internal/facilitation/receipt.go` | `CanonicalReceiptHash` covers the whole receipt including a `Nonce`; `SignReceipt`/`VerifyReceiptSignature` bind it to the Ed25519 key whose keccak256 *is* the node id (`p2p.NodeIDFromPeer`), so a node cannot claim another's identity; settlement requires witness attestations against a threshold ("Need of Of" in `witness.go`) | A receipt signed by two colluding parties for service between themselves is **valid and false**. Witness selection is the only defence, and `witness.go` warns that its own duplicate implementation in the aggregator must not diverge by one candidate, or honest receipts are scored as fraud |
| T-AC-02 | Receipt replay / double-spend of the same work | Receipt store | `Nonce` in the canonical hash; the `MemReplayGuard` pattern (nonce table bounded by expiry) | Replay across *epochs* is bounded only by however long receipt history is retained. Retention policy is `TBD — read from internal/facilitation/receipt_store.go` |
| T-AC-03 | **Payment fraud** — paying with tokens that are not honoured, or being paid and not delivering | Payment channels, SCPP/1 | The existing channel machinery with HTLCs and watchtowers (`doc/channel-payment-protocol.md`) | A watchtower that is shown a fabricated chain fails to defend — which is exactly why the trust anchor exists (`doc/trust-anchor.md` §5: "the loss is a user's money"). Chain verification is a prerequisite for payment safety, not an optional extra |
| T-AC-04 | **Payment as a deanonymisation channel** | Relay payment (R11) | Relays are never paid with an identified transaction on the data path; blind-signed unlinkable tokens redeemed in aggregate off the critical path | Blind tokens unlink the *payment*; they do not unlink the *timing* of issuance and redemption. A user who buys tokens and spends them minutes later against one relay is linkable by timing. Batching windows are `[NEEDS RESEARCH]` |
| T-AC-05 | Economic denial: bidding relay prices to make the network unusable, or paying for capacity to increase selection weight | Path-selection weights (R14) | **The economic layer is not in v1** (R11), and the network must work with zero payments before any payment exists | When payment does arrive, it will become a Sybil-weight purchase mechanism unless weight and payment are firmly separated. This is a design constraint on a future section, recorded here |
| T-AC-06 | Selective slashing via compromised dispute resolution | `DisputeManager` | See T-L7-06 | Same residual: `resolve` is `onlyOwner` |

---

### 18.14 Supply chain and the update channel

> **PARTLY CLOSED (2026-08-16).** `scripts/update-from-github.sh` now verifies
> the commit it is about to build, fail-closed, with 4 tests against real git and
> real `ssh-keygen` signatures (`scripts/verify-commit-signing.test.sh`).
>
> **The finding that shaped it: this network has TWO distribution paths and they
> need DIFFERENT mechanisms.** `internal/axon/release` — which refuses 13
> distinct tampering attacks — was built for a signed manifest over built
> artifacts, and was filed as "the updater must call it". That was wrong:
>
> | Path | What it ships | What authenticates it |
> |---|---|---|
> | `update-from-github.sh` | a **commit**, built locally as root | the **commit signature** — a manifest signs artifacts this path never downloads |
> | backend `node_release.py` | a **binary**, content-addressed | the **manifest signature** — and today it has none |
>
> **The backend path's sha256 is not a signature.** It proves the object store
> returned the bytes matching a digest **the server itself recorded** in
> `site_setting`. Whoever compromises the server publishes any binary and its
> matching digest, and every check passes. Content addressing makes corruption
> detectable; it does nothing about authorship. That is now item 2.2b.
>
> **What the commit check does and does not do.** With
> `SYNDICHAN_ALLOWED_SIGNERS` set, an unsigned or wrongly-signed head is refused
> and **nothing is built** — the check runs before the "already current" exit and
> before compilation, so a candidate is never compiled, let alone run, on the
> strength of having been fetched. The verification policy is passed
> per-invocation with `-c`, because `gpg.ssh.allowedSignersFile` can be set in a
> repository's own config and **a mirror allowed to supply its own policy would
> be verifying itself** — that is the fourth test.
>
> **It is not enforced yet.** No commit on `main` is signed and no key is pinned,
> so every node currently takes the unpinned branch, which prints a warning
> naming what is unprotected on every run. That is deliberate — failing closed by
> default would brick every volunteer node on the next update — and it means the
> trust root is still "whoever can push to `main`". Items 2.2 and 2.2b.

This subsection is prose because the tables understate it.

An adversary at A6 does not attack circuits, DHT records, descriptors or
contracts. They ship a binary. Every mitigation elsewhere in this document
assumes the code running on the user's machine is the code we wrote, and
nothing currently establishes that.

**What the code does today, read from the scripts:**

```text
scripts/update-from-github.sh
  git fetch  +refs/heads/<branch>:refs/remotes/origin/<branch>
  candidate_sha = rev-parse refs/remotes/origin/<branch>     <- branch HEAD
  git archive <sha> | tar -x                                 <- no signature check
  go test ./...  &&  go build -trimpath -ldflags="-s -w"     <- attacker's tests
  install -m 0755 ... "$PROGRAM"                             <- becomes the node
  systemctl restart; curl "$HEALTH_URL/readyz" or roll back
  install .../update-from-github.sh -> $BIN_DIR              <- updater replaces
                                                                ITSELF from the
                                                                same source
```

Four observations, in increasing severity:

1. **Trust is "whatever is at the head of that branch"**, authenticated only by
   TLS to GitHub. A force-push, a compromised account, a malicious commit merged
   in good faith, or GitHub itself, are all sufficient.
2. **The candidate's own tests decide whether it is installed.** An attacker
   controlling the source controls the test suite. The health gate is
   `curl .../readyz` — a backdoored node passes it trivially.
3. **The updater rewrites itself** from the same unverified source, so a single
   successful compromise removes any future opportunity to add verification.
4. **The rollback binary is the previous unverified binary.** Rollback restores
   availability, never integrity.

`scripts/build-release.sh` is CGO-free, `-trimpath`, seven targets, and
`check-release.sh` correctly notes that two builds of the *same commit* produce
identical bytes because Go embeds `vcs.revision` — so the hash proves
provenance. But nothing signs the hash, and `dist/*.sha256` served from the same
place as the binary proves nothing at all.

| ID | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| T-SC-01 | Malicious release binary | `dist/`, install path `[BUILD NOW]` | **Required for v1:** detached signatures over release artefacts by an offline key; the verifying public key compiled into the previous binary and into the installer; installation fails closed on a bad or missing signature | The first install is unverifiable (trust-on-first-use). The bootstrap of trust is a human decision, exactly as the weak-subjectivity checkpoint is (`trust-anchor.md` §3) |
| T-SC-02 | Malicious commit reaching the update path | `update-from-github.sh` `[BUILD NOW]` | Verify a **signed tag**, not a branch head; refuse unsigned; refuse a tag that does not descend from the currently deployed commit | Signing key compromise collapses this. A threshold of signers is `[NEEDS RESEARCH]` and is a new consensus problem |
| T-SC-03 | Targeted update — serving a backdoored build only to one node | Update fetch | Binary transparency: an append-only log of release hashes, published in the DHT and cross-checked between nodes, so a build served to one node is visible to all | Requires the transparency log to be gossiped over paths the adversary does not also control. Partial `[UNSOLVED]`, related to T-L3-04 |
| T-SC-04 | Dependency compromise | Go module graph | `go.sum`, vendored review, and a policy that the security path (BLS, QUIC, AEAD) gets human review on every bump | A transitive dependency of a dependency is not reviewed by anyone. This is the industry's unsolved problem, not ours |
| T-SC-05 | Build-host compromise | Whoever runs `build-release.sh` | Reproducible builds are *already achievable* per-commit; a second independent builder confirming the same hash converts that into evidence | Two builders can both be compromised; and `check-release.sh` records that automatic invocation is "deliberately undefined" — there is no CI, so today there is one builder, on one machine |
| T-SC-06 | Compromised pinned constants — bootstrap coordinator key, weak-subjectivity checkpoint, registry contract address, seed list | The binary itself | All four are compiled-in trust roots and inherit T-SC-01 exactly | **Every trust root in AXON reduces to "the binary is genuine".** This is the sentence that justifies making release signing a v1 blocker rather than a later hardening task |

---

### 18.15 Denial of service, by layer, and resource exhaustion

| Layer | DoS attack | Bounded resource | Mitigation | Residual risk |
|---|---|---|---|---|
| L1 | Handshake flood (CPU on X25519 / signature verification) | CPU, half-open handshakes | QUIC retry/address-validation token before any key agreement; per-source rate limit | Address validation costs a round trip and is defeated by an on-path spoofer; a distributed flood is unbounded |
| L2 | Peerbook pollution — flooding a node with junk peer records | Peerbook entries | Fixed-size peerbook with diversity-preserving eviction | Eviction policy is an attack surface: an adversary who can force eviction chooses **which** honest peers are forgotten |
| L3 | Lookup amplification — cheap query, expensive `k=20` fan-out | Outbound lookups, socket table | Per-requester lookup budget; queries that arrive over a circuit are charged to that circuit | Charging per circuit means an adversary buys more circuits. Circuits are cheap until they are paid for, and payment is not in v1 |
| L4 | **Circuit-table exhaustion** — build circuits and never use them | Circuit table (per relay) | Hard cap on circuits per link and per node; idle circuits reaped; extend requests rate limited per predecessor | Under R12 one QUIC stream per circuit per link means the circuit table **is** the stream table: circuit caps and QUIC stream limits must be set together, or one silently overrides the other. This coupling is new with R12 and is easy to get wrong |
| L5 | Introduction flooding | IP request queue, service-side rendezvous slots | Proof-of-work / token puzzle (R10); per-IP request budgets | See T-L5-02: the puzzle penalises weak honest clients more than strong attackers |
| L6 | Storage fill — pushing junk to consume donated disk | Disk capacity | The existing `Store.ensureCapacityLocked` / `Capacity()` cap, plus admission: a remote `STORE` requires a signed lease binding object ID, shard ID, size, recipient and expiry, ≤1 h, matching bytes (`SECURITY.md`) | A lease authority is a **central bottleneck and a censorship point**. AXON must replace the coordinator-issued lease with a bond-backed or payment-backed admission, and that design does not exist yet `[NEEDS RESEARCH]` |
| L7 | Resolution flood — forcing chain access or snapshot refresh | Chain RPC quota, snapshot bandwidth | R7's slow path with long TTL means resolution normally makes **no** chain call; snapshots are cached and shared | An adversary who forces cache misses (querying random non-existent names) turns a resolver into an RPC amplifier. Negative caching is `[BUILD NOW]` and is usually forgotten |
| L8 | API flood from a local application | API worker pool | Per-caller concurrency limits and backpressure to the caller, never silent queueing | A local application can always outcompete a remote one for local resources |

**Resource exhaustion, by resource:**

| Resource | Attack | Existing bound | Required AXON bound |
|---|---|---|---|
| Memory | Oversized frames | `maxHeaderBytes = 64 << 10` in `internal/p2p/node.go`; DHT records ≤64 KiB in `internal/dcs/dht.go`; response bodies read through `io.LimitReader(..., 1<<20)` | Cells are 1024 B fixed, so L4 memory is `circuits × window`, not attacker-chosen. Windows must be capped per circuit `[BUILD NOW]` |
| Circuit table | Build-and-abandon | none (does not exist yet) | Hard cap + idle reap + per-predecessor extend budget |
| Stream table | One stream per circuit per link (R12) | none | Must be derived from the circuit cap, not set independently |
| Disk | Storage fill | `Capacity()` / `ensureCapacityLocked`, denial lists (`IsRejected`, `Reject`, `RejectAndRemove`) | Bond-backed admission to replace the coordinator lease |
| Nonce/replay tables | Nonce flooding to grow a replay table | `MemReplayGuard` is bounded by envelope expiry and pruned lazily | Same pattern; the window must be short enough that the table cannot be grown faster than it drains |
| File descriptors / sockets | Connection flood | libp2p `ConnManager`/`ResourceManager` are wired in `node.go` | Explicit limits must be set, not defaulted |

---

### 18.16 Relay position powers — the normative table

Path selection, padding and isolation decisions must cite this table rather
than reasoning about "a malicious relay".

| Position | Learns | Cannot learn | Unique power | Bounded by |
|---|---|---|---|---|
| **Guard (hop 1)** | Client IP; that the client runs AXON; exact timing and volume of everything in that isolation context; how many circuits and when | Destination, service, domain, content | The **only** relay that ever learns the client's network location. Can correlate all of that client's contexts that share it | 2 guards per context, 45-day rotation; guard-constrained pools (R1) so churn never re-rolls it |
| **Middle (hop 2)** | Predecessor and successor `RoutingIdentity`; cell timing | Client, destination, content | **Partitioning:** by failing selectively it shapes which relays a client believes work. **Fingerprinting:** by delaying it can watermark | Path diversity across ASN/prefix; the middle is re-chosen every 10 min, which limits duration but increases the number of adversaries who get a look |
| **Terminal (hop 3)** | The RP or IP it connects to; cell timing and volume | Client, service, content | Sees the meeting point identity, which is a join key with anyone watching the other leg | No exit role, so it never sees plaintext or a clearnet destination |
| **Rendezvous point** | That two circuit legs are one conversation; both legs' volume and timing | Either endpoint's location or identity | A **free correlation point by construction** — the two legs are correlated at the RP with no work at all | Each leg is still 3 hops, so the RP learns "these two anonymous parties are talking", not who they are |
| **Introduction point** | That a blinded service key is reachable through it; rendezvous request rate | The service's location, its tunnels, its clients | Selective censorship (T-L5-01); popularity measurement | Multiple IPs per service, rotation, PoW gating (R10) |
| **DHT storing node** | That a blinded key was published and how often it is fetched | The domain, the service, the content | Withholding (T-L3-01); popularity measurement | `r = 8` replication across distinct /24, /48 and ASN; `d = 3` disjoint lookup paths |
| **Storage holder** | Encrypted shard bytes; who asked for them (a circuit, not a client) | Plaintext, object identity, requester | Denial by refusal; correlation via shared shard IDs across peers | Content addressing + AEAD; audits (T-L6-02) |

---

### 18.17 Long-term attacks

These are the attacks that succeed by patience rather than by capability, and
they are the ones a per-session threat model misses.

| ID | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| T-LT-01 | **Intersection attack** — repeatedly intersect the set of users online whenever a service is active | The user's availability pattern | None that works. Guard pinning does not help; padding does not help | **Unmitigated, and §4 explicitly does not defend against it** for a persistently-online, low-churn user. A user who is online exactly when their service is is identifiable given enough observations |
| T-LT-02 | **Statistical disclosure** — repeated observation of who sends when, narrowing a suspect set | Traffic patterns on `INTERACTIVE` | `BULK` batching helps for storage traffic only | Unmitigated for `INTERACTIVE` (R2 concedes this). The number of observations required is a function of user population size and churn — both unknown for AXON, so **we cannot state how long a user is safe** |
| T-LT-03 | **Long-term identity correlation** — linking `RoutingIdentity` epochs, or linking a service across time periods | Epoch and time-period rotation | `RoutingIdentity` rotates per epoch; `KadID` rotates per epoch; descriptor keys are blinded per 24 h time period with 12 h overlap | Rotation only unlinks what the *key* reveals. Capacity claims, uptime, version strings, latency profile and publication offsets survive rotation (T-L8-05). **Bucketing descriptor contents is as important as rotating keys, and is more likely to be skipped** |
| T-LT-04 | Guard-set fingerprinting — identifying a client by which guards it uses | Guard selection | Guards are pinned, so the set is stable — which is exactly what makes it a fingerprint | A relay that sees a client's guard set can recognise that client across contexts *if* contexts share guards. **This is the reason isolation contexts must not share guards**, and the reason more contexts costs more guard exposure (§18.8) |
| T-LT-05 | Descriptor archival — storing every blinded descriptor forever and correlating publication behaviour across periods | Descriptor DHT | Blinding prevents linking keys across periods | Blinding does not prevent linking *behaviour* across periods: publication time, descriptor size, IP-set size and rotation cadence are all stable across a blinding boundary. `[NEEDS RESEARCH]` |
| T-LT-06 | Chain archaeology — the chain is permanent, so every registration, transfer, bond and slash is analysable forever, with hindsight and with tools that do not exist yet | Chain plane | None. This is what a blockchain is | **Unmitigated by construction.** A linkage that is not findable today is findable in ten years. This argues for keeping as little as possible on-chain, which R7 already does for other reasons |

---

### 18.17a Governance and the multi-namespace root

The governed root (§12.0a) buys a namespace users can extend and pays for it with
an attack surface a hardcoded TLD does not have. Every row here is new since the
single-namespace design.

| # | Attack | Vulnerable component | Mitigation | Residual risk |
|---|---|---|---|---|
| G1 | **Governance capture** — acquire enough weight to approve a namespace, freeze a rival's registrar, or rewrite root parameters | Governor, `TLDRegistry` | Enumerated powers only; supermajority + quorum; 14–90 day timelocks; contribution-weighted rather than purely stake-weighted voting (§12.0a) | **High and unresolved.** Low turnout makes quorum cheap; contribution can be bought by renting servers. The timelock makes capture *visible*, not impossible. The real backstop is the fork right, which is reactive and requires resolver operators to act |
| G2 | **Governance cannot reach a name** — attacker captures the governor to seize `alice.lab.axon` | — | No such function exists on `ITLDRegistry` (§12.0a invariant). Tested as a property in §21, not assumed | Capture can retire the whole namespace on 90 days' notice, which denies the *name*. The service stays reachable at Layer 1 (§11.9) |
| G3 | **Malicious or captured registrar** — a namespace whose registrar can seize, redirect, or mint names | Per-namespace `IRegistrar` | `registrarClass` is surfaced before registration (§12.0, §13.3a); root can FREEZE new registrations; `IMMUTABLE` registrars have no such path | A holder who registered under an `UPGRADEABLE` or `STEWARDED` registrar accepted this risk. Freezing does not undo damage already done to existing names |
| G4 | **ICANN collision** — a namespace label is delegated in the public DNS root after activation | Resolver, every user's ordinary browsing | Root suffix is not votable, so the surface is one label wide (§11.0.2); eligibility predicate at proposal; resolver re-checks an anchored IANA snapshot; public DNS always wins in flat mode | The anchored snapshot goes stale between updates. A newly delegated label produces a window in which flat-mode users see AXON for a name that now exists publicly. Canonical form is unaffected |
| G5 | **Namespace squatting** — register `bank`, `mail`, `corp` to rent-seek | Governor | Bond, proposal deposit, charter review, supermajority | Not solved, and not solvable by a vote that can be lobbied. Squatting at the *namespace* level is more damaging than at the name level because it is permanent and wholesale |
| G6 | **Proposal spam / griefing** | Governor | Slashable deposit; eligibility check before the discussion window | A well-funded adversary can still exhaust reviewer attention, which is the scarce resource |
| G7 | **Cross-namespace impersonation** — `alice.corp.axon` targeting users of `alice.lab.axon` | Human reading the name | Full canonical name always rendered; no abbreviation (§13.3a) | `[UNSOLVED]`. No registrar can police another namespace. This is the strongest argument for keeping namespaces few |
| G8 | **Unauthorised name pointing at your service** — register `free-money.corp.axon → S` to defame or phish | Resolver attribution | Mutual binding: `NameAcceptance` signed by the service must contain the name (§11.0.3 rule 4, R8a) | An attacker can still *route* traffic to the service; they cannot make the resolver attribute the name to it. A service that accepts all names disables this defence |
| G9 | **Guardian abuse** — the veto council blocks a legitimate proposal, or is compromised | Governor | Veto-only (may block, never enact); expires and must be re-authorised | A standing centralisation point and a standing target. Named as such in §12.0a rather than defended |
| G10 | **Root-registry pin poisoning** — push a client at an attacker's `TLDRegistry` | Resolver configuration | Pin is explicit configuration, never auto-updated; displayed in status; multiple roots may be held and disagreement fails loudly (§13.3a) | Anyone who controls the software update channel controls the pin. See §18.14 — that attack dominates this one |
| G11 | **Vanity-prefix collision phishing** — grind the same 8-character prefix (≈ a machine-day, §11.9.1) | Human comparing addresses | Never abbreviate; fingerprint rendering; prefer verified names for display (§13.3a) | **Real and only partly mitigated.** Users compare prefixes regardless of what the UI does. The defence is to move humans off Layer 1 identifiers, not to make Layer 1 safe to eyeball |
| G12 | **Weak vanity grinder entropy** — a grinder seeded from a timestamp or counter | `ServiceIdentity` | Full-entropy seed per candidate, or destroy the base and all non-selected offsets (§11.9.1) | Entirely dependent on the grinder implementation. A third-party grinder is a supply-chain dependency on the service's own identity key, and should be treated as one |

### 18.18 Attacks for which AXON has no adequate mitigation

Gathered so they cannot be missed. Each is stated at full strength.

1. **End-to-end traffic correlation against `INTERACTIVE` traffic** (T-L4-04,
   T-L4-05). An adversary who observes both ends — as a guard plus a terminal
   hop, or as a network observer at two points — confirms a flow by timing and
   volume. Fixed cells do not stop it. Guards reduce how often the adversary is
   in position; they do nothing once the adversary *is*. `[UNSOLVED]`

2. **The global passive adversary** (A7). Explicitly outside §4. Every claim in
   this document is void against an adversary who sees every link.

3. **Partitioned network views / the epistemic attack** (T-L3-04). Without a
   consensus document there is no ground truth about the relay set, so clients
   can be given different views. R14 names this as one of the hardest unsolved
   problems and does not solve it. `[UNSOLVED]`

4. **Long-term intersection and statistical disclosure** (T-LT-01, T-LT-02)
   against a persistently-online user. We cannot say how many observations are
   required because we do not know the population.

5. **Guard discovery against an online service** (T-L4-10). Rate limiting and
   PoW raise the cost. The attack class works.

6. **Storage abuse and the operator-liability problem** (T-L6-03). Encryption
   means an operator cannot inspect what they hold. A global blocklist is
   refused as re-centralisation (R5). There is no answer here, only a
   disclosure obligation to operators.

7. **Funding-graph linkage of domain ownership** (T-L7-08). R6 states it: do not
   claim anonymous ownership.

8. **Compromise of a contract owner key** (T-L7-06). Today one key can slash
   arbitrary stake, resolve any dispute, and sweep balances. Multisig and
   timelocks reduce it to a governance problem; they do not remove it.

9. **Post-quantum exposure of v1 traffic** (T-L1-02). Traffic recorded today
   under X25519 is decryptable later. The hybrid slot is reserved, not shipped.

10. **The endpoint** — a compromised client or service host (T-L5-04). Outside
    §4 and outside anything a network protocol can address.

11. **Transport-level blocking** (T-L1-06). AXON can be blocked. It is not
    designed to be unblockable.

12. **First-start eclipse** (T-L2-02) and **first-install trust** (T-SC-01).
    Both are trust-on-first-use and both are irreducible; the honest response is
    to make the first moment explicit to the user rather than to hide it.

---

### 18.19 What survives, per adversary class

Read as: given this adversary, what does AXON still guarantee?

| Adversary | Survives | Does not survive |
|---|---|---|
| **A1 local observer** (ISP, LAN) | Destination, service, domain, content, and which `.axon` names were resolved — provided the resolver has no DNS fallback (T-L7-12) | The fact that you use AXON, when, and how much. Volume and timing at your access link are fully visible |
| **A2 relay adversary** (minority of relays) | Location privacy for any context whose guards are honest — a per-context property decided once per 45 days, not per circuit. Content confidentiality and integrity always. Domain and service identity at the DHT layer (blinded keys) | Any context whose guard is hostile: for that context, expect correlation of `INTERACTIVE` traffic. Availability: a relay adversary can always degrade |
| **A3 network adversary** (many paths, not all) | Cryptographic confidentiality and integrity. Anonymity **only** for flows whose entry and exit paths they do not both observe | `INTERACTIVE` anonymity on any flow they straddle. They need no relays at all, which is why relay-fraction arguments understate this adversary |
| **A4 chain adversary** (full chain view, possibly the RPC) | Correctness of resolution — `internal/ethproof` means a lying RPC produces proofs that fail to verify, which is a detectable failure not a silent one. Namespace liveness during an outage (R7 snapshots) | Ownership privacy: registration, transfer, bonding and slashing are public forever (T-L7-08, T-LT-06). Freshness: they can stall you into a stale snapshot |
| **A5 service adversary** (is the service, or is the client) | Network location of the other party — the two-stage intro+rendezvous means neither endpoint learns the other's address | Everything the other party says or does at the application layer. Behavioural fingerprinting. Confirmation by selective service behaviour (T-L5-07) |
| **A6 supply adversary** (owns the software or its updates) | **Nothing.** No property in this document holds | Everything, at every layer, simultaneously. This is why §18.14 is a v1 blocker |
| **A7 global passive** | Cryptographic confidentiality and integrity of content | Anonymity, per §4. Not defended against, by design and by declaration |

---

### 18.20 On the strength of the anonymity claim

Stated once, precisely, and not softened elsewhere:

> **AXON does not provide perfect anonymity, and no configuration of it does.**
> It provides *unlinkability of network location from destination against an
> adversary who does not observe both ends of a flow and does not control both
> the first hop and a point past the last*, for the duration and under the
> traffic class the caller selected. Against an adversary who does observe both
> ends, `INTERACTIVE` traffic is correlatable, and this is a property of the
> design, not a defect in its implementation.

Every other anonymity statement in this document is scoped to an adversary
class in §18.19 or it is a mistake.

---

### 18.21 Operational security: what actually deanonymises people

A protocol document that stops at the protocol misleads its reader. In
practice, most real deanonymisations of anonymity-network users have nothing to
do with the anonymity network. The four categories below are not speculative;
they are the recurring pattern.

**1. Application-layer leaks.** The protocol carries what it is given. An
application that includes a hostname, a local file path, an EXIF GPS tag, a
document's author field, a client-side timezone, a WebRTC candidate list or a
`Referer` header has deanonymised its user through a perfectly anonymous
circuit. AXON's L8 API cannot inspect payloads and will not try. **The
infrastructure boundary is real: past L8, we protect nothing.**

**2. Uniquely identifying behaviour.** Writing style, activity schedule,
vocabulary, timezone-correlated posting times, and the specific set of things a
person is interested in are all identifiers. An adversary with a candidate list
does not need to break a circuit; they need to confirm a hypothesis, and
behaviour confirms it. This is why T-L5-07 and T-LT-01 are unmitigated: they
are the *cheap* attacks.

**3. Correlated login identities.** Using the same handle, the same email
address, the same password, the same payment method, or the same PGP key inside
and outside the overlay collapses the two identities into one. The eight-class
identity taxonomy of §3 exists to make key reuse *structurally* impossible
inside AXON; it can do nothing about a user who reuses an identity above it.

**4. Service misconfiguration leaking its own address.** The classic and still
the most common: a service that also listens on a public interface; a web
server whose default vhost or error page reveals its clearnet hostname; a
certificate that names the host; an SSH banner; an NTP or DNS query from the
service host; a monitoring agent phoning home; a status page that reports the
machine's public IP. The existing codebase contains a live example of exactly
this shape, disclosed in its own `SECURITY.md`: the five-minute frontend
heartbeat is deliberately direct rather than over I2P and therefore "exposes the
node's public egress IP". Every such exception must be treated as a
deanonymisation, not as a convenience.

The engineering consequence for AXON: the node binary must contain **no
clearnet HTTP client on any path a service host can reach**. Enforcement by
absence, not by policy (T-L8-03).

---

### 18.22 Component difficulty index

| Component | Marker | Note |
|---|---|---|
| Release signing + fail-closed verifier | `[BUILD NOW]` | v1 blocker (§18.14). Everything else depends on it |
| Contract owner multisig + timelock | `[BUILD NOW]` | Reduces T-L7-06 from "one key" to "a governance problem" |
| DHT record validator (port of `WorkerDHTValidator`) | `[BUILD NOW]` | Shape already proven in `internal/dcs/dht.go` |
| Circuit/stream table caps set together under R12 | `[BUILD NOW]` | Easy to get wrong; the coupling is new |
| Descriptor content bucketing (capacity/uptime/version) | `[BUILD NOW]` | Without it, key rotation is theatre (T-L8-05, T-LT-03) |
| Resolver with no DNS fallback path | `[BUILD NOW]` | T-L7-12 |
| Negative caching + resolver freshness enforcement | `[BUILD NOW]` | T-L7-10, L7 DoS row |
| Narrowed erasure-coding bounds | `[BUILD NOW]` | Config change only (T-L6-06) |
| Bond-backed storage admission (replacing coordinator leases) | `[NEEDS RESEARCH]` | Removes a censorship point (L6 DoS row) |
| Possession proofs at scale | `[NEEDS RESEARCH]` | Catches the holder that lies to `have` (T-L6-02) |
| Isolation-context count vs. guard exposure optimum | `[NEEDS RESEARCH]` | §18.8 |
| Blind-token issuance/redemption batching windows | `[NEEDS RESEARCH]` | T-AC-04 |
| Binary transparency log | `[NEEDS RESEARCH]` | T-SC-03; depends on gossip the adversary does not control |
| Behavioural unlinkability across blinding periods | `[NEEDS RESEARCH]` | T-LT-05 |
| Defence against partitioned relay views | `[UNSOLVED]` | T-L3-04, R14 |
| End-to-end correlation on `INTERACTIVE` | `[UNSOLVED]` | T-L4-04 |
| Guard discovery against an online service | `[UNSOLVED]` | T-L4-10 |
| Long-term intersection resistance | `[UNSOLVED]` | T-LT-01 |
| Storage abuse / operator liability | `[UNSOLVED]` | T-L6-03, R5 |
| Sybil cost calibration ("what bond makes 20 % infeasible") | `[UNSOLVED]` | T-L2-01 |

---

### What this section does NOT establish

- **No probability in this section is measured.** The correlation arithmetic in
  §18.8 is algebra under stated assumptions (uniform selection, independent
  compromise) that the real network violates in both directions. No simulation
  has been run, and no relay-fraction, bandwidth-weight or population figure
  here comes from an experiment.

- **The unbuilt layers are assessed against a specification, not against code.**
  Everything in §18.5–§18.9 concerns L1–L5 components that do not exist yet.
  Those rows are requirements on future code; only §18.10–§18.14 were checked
  against files that exist, and only the claims attributed to a path were read.

- **No adversarial cost model exists.** We do not know what a Sybil, an eclipse,
  a guard-discovery campaign or a correlation attack costs in dollars against
  AXON's parameters, so "a large but minority fraction" (§4) is unquantified and
  the bonding parameters that would quantify it are unset.

- **Attack composition is not analysed.** Each row is scored in isolation. The
  dangerous adversary combines T-L3-04 (partitioned views) with T-L4-09 (routing
  manipulation) and T-L2-01 (Sybil), and compound attacks are strictly stronger
  than the sum of these rows suggests. No composition analysis has been done.

- **Detection and response are absent.** This section says what can be attacked;
  it does not specify what a node logs, how misbehaviour is attributed, who
  publishes evidence, or how the network reacts. "Detectable" in the residual
  column means *detectable in principle*, not *detected by shipped code*.

- **This is not a security review of the existing codebase.** Files were read to
  ground specific claims. No audit was performed, and the absence of a finding
  here is not evidence that a file is sound.

> **Objection to Constitution §7:** the canonical adversary model omits the
> supply-chain adversary. §18.14 shows, from the existing update script, that it
> is the strongest adversary a real deployment faces and that it voids every
> other property in the document. This section adds it as A6 and asks the
> synthesis pass to promote it into §4 rather than leave it as a local
> extension.

> **Objection to Constitution §5:** the parameter table gives a 256 KiB content
> chunk with the instruction to confirm it against `internal/store`. The
> existing default, read from `internal/config/config.go`, is `ChunkBytes = 1 << 20`
> with 6 data / 3 parity shards, and validation accepts 64 KiB–16 MiB and any
> layout up to 64 total shards. The threat-model consequence (T-L6-06) is that
> the *bounds*, not the default, are what an adversary picks from; whichever
> default is chosen, the bounds need narrowing.
