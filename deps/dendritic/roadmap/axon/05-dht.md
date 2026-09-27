## 7. The DHT

> **AS BUILT (2026-08-16).** `internal/axon/dht`, 52 tests. **P4 complete** —
> KadID + SRV rotation with a declared-staleness fallback, six record classes over
> canonical CBOR with per-class validators, bucket caps 2/24 + 8/ASN and sibling
> caps 1/1, d=3 node-disjoint lookup, `seq_floor`. T4.1's grind measured at
> 162 / 263 086 / 27 192 507 derivations for 8/16/24 bits. E4.3 = 1000/1000 at
> 20 % adversarial.
>
> **R4(b) — the circuit binding now exists (2026-08-17).** `dht.CircuitRPC`,
> 9 tests. Lookups are still direct, and the reason is stated below, but the
> layer that decides *which circuit a query may use* is built and enforces the
> refusals that make the property meaningful.
>
> **The finding that shaped it: `RPC` had no path index.** A lookup runs d
> node-disjoint paths, and the RPC could not tell which path it was serving — so
> it could not bind a path to its own circuit, and all d would have shared one.
> **That is disjointness at the DHT layer with convergence at the circuit
> layer**, which is not disjointness: one terminal relay would see every path,
> its progress and its result. `RPC` now takes the path, which is what makes the
> property expressible at all.
>
> Three refusals, none of them warnings:
>
> - **two paths may not share a circuit** — the failure is silent by nature,
>   since a lookup over one circuit returns the same answer as one over d;
> - **two paths may not share a TERMINAL RELAY** — distinct circuits that
>   converge give that relay exactly the view a shared circuit would;
> - **no circuit is a FAILURE, never a fallback to a direct query.** A silent
>   fallback is precisely how R4(b) comes to look met while being unmet, and the
>   caller who wanted anonymity would never learn it did not get it.
>
> `CircuitConfig` is the only way to set `OverCircuit`, so the flag that
> suppresses `UnsafeDirectLookup` from the evidence cannot be set independently
> of the RPC that earns it.
>
> **Still NOT claimed, and R4(b) remains unmet.** There is no wire protocol:
> sending a FIND_NODE over a circuit and reading the reply needs the session
> layer, which is **P23 and `[NEEDS RESEARCH]`**. Every lookup issued today
> supplies no Dispatcher and therefore still records `UnsafeDirectLookup`, which
> is the honest state. What changed is that the remaining work is a transport,
> not a design.
>
> **Deliberately NOT claimed:** **E4.1 was discharged IN SIMULATION ONLY** — 30
> nodes in one process, 1000/1000 across the epoch boundary. The `axon-lab` fleet
> run has not happened. And **lookups are direct, not circuit-borne**: R4(b) is
> unmet until P5's circuits carry them, so every `LookupResult` carries
> `UnsafeDirectLookup` rather than pretending otherwise.

**The finding that shapes this section: hash-grinding an identity into a target
region of the keyspace is free, and always will be.** At N = 10,000 nodes the
ball around a key containing the eight nearest honest nodes has measure
8/N = 8×10⁻⁴, so a random identity lands inside after ~1,250 SHA-256 trials —
under a microsecond. Eight of them cost ~10⁴ trials. No plausible hardening
makes that arithmetic expensive.

§7.2 therefore does **not** try to make grinding expensive. It makes ground
positions *perishable* and *paid for*: `KadID` is rebound to a per-epoch shared
random value, so today's ground position is worthless tomorrow, and to the
node's network prefix and a bonded identity, so re-grinding costs a fresh bond
and fresh address space rather than fresh CPU. The attacker's budget line moves
from hashes to bonds × ASNs × epochs. That raises cost; it does not make eclipse
impossible.

The second finding, which is uncomfortable: **epoch rotation converts a targeted
eclipse into a random one, and a random one still lands on somebody.** An
adversary holding half the bonded identities cannot reliably eclipse *your* key,
but eclipses 1/256 of all keys in every epoch (§7.2).

---

### What already exists

The node in `/home/bruns/Documents/maniwani/storage-client` already runs a
Kademlia DHT. Read from the source, this is exactly what it is and does today:

| Fact | Where | Value |
|---|---|---|
| DHT construction | `internal/p2p/node.go:438` | `dht.New(h, dht.Mode(dht.ModeAutoServer))` — **one call, one option** |
| Library | `go.mod:14` | `github.com/libp2p/go-libp2p-kad-dht v0.42.1` |
| Protocol prefix | not set | Library default (`/ipfs/kad/…`). Not namespaced to this network. |
| k, α, sibling list | not set | Library defaults. **TBD — the effective values are the library's, not the project's** |
| Transport underneath | `internal/p2p/node.go:366-379` | libp2p host with `NoTransports` + the I2P SAM transport only; `AddrsFactory(i2pAddressesOnly)` |
| Record validation | `record.NamespacedValidator` | Three namespaces registered, below |
| Namespace `syndichan-object-manifest` | `internal/p2p/objmanifest.go:22,50` | 512 KiB cap, key = SHA-256(bucket ‖ 0x00 ‖ key), **no signature at all** — integrity comes from content-addressing downstream |
| Namespace `syndichan-gateway` | `internal/gateway/dht.go:10,25,38` | 256 KiB cap, key = `/syndichan-gateway/<nodeID>`, `Select` prefers highest `Sequence`, validated against a probe quorum |
| Namespace `dcs_worker` | `internal/dcs/dht.go:23-60` | 64 KiB cap, record must be stored under its own node id, signed by that node's libp2p key, `ExpiresAt−IssuedAt ≤ 3600 s`, `Select` prefers highest `Sequence` |
| Provider records | `internal/p2p/node.go:1254-1265` | `dht.Provide` per shard; `advertiseInterval = 10 * time.Minute` |
| Rendezvous discovery | `internal/p2p/node.go:663-670`, `internal/place/place.go:59` | Well-known CIDs (`…dcs-worker-rendezvous/1`, `…storage-capacity-rendezvous/1`) that every worker/holder provides, because "Kademlia cannot list a namespace by itself" |
| Capacity records | `internal/place/place.go:69-80` | `RecordTTL = 10 * time.Minute`, **deliberately unsigned** — a lying peer costs one wasted attempt |
| Placement diversity | `internal/placement/plan.go:73-137` | Distinct **peer id** only. No /24, no /48, no ASN, no operator awareness anywhere in the package |
| Durability rule | `internal/store/placement.go:140-148` | `DurableRemoteHolders = dataShards + 1` (7 of 9 at the 6+3 default) |
| RS / chunk defaults | `internal/config/config.go:572-574` | `DataShards: 6`, `ParityShards: 3`, `ChunkBytes: 1 << 20` |
| Known DHT risk, already documented | `SECURITY.md:138-149` | `GO-2024-3218`, availability advisory, **no upstream fixed version**: hostile peers can hide provider records. The client's stated mitigation is to ask trusted bootstrap and already-connected swarm peers *before* using Kademlia hints |

The existing threat posture is already the right one and is worth quoting rather
than re-deriving: *"Kademlia records and peer responses are untrusted hints"*
(`SECURITY.md:12`). Nothing below weakens that. What changes is that AXON has
record classes where content-addressing cannot save us — a descriptor is not
self-certifying against *absence*, and a name binding is not self-certifying at
all — so the DHT stops being a pure hint layer and acquires real integrity and
availability obligations.

### What must be replaced

1. **The coordinator.** `syndichan.org` signs leases and is the discovery root
   (`internal/p2p/node.go:103`, `:1099-1131`). Write authorisation moves to
   per-record signatures plus a bond reference (§7.6, §7.9).
2. **The I2P substrate.** The DHT runs *inside* I2P today, which is why
   `i2pDialTimeout = 2 * time.Minute` (`node.go:69`). Lookup anonymity becomes a
   property of our circuit layer (L4), not of the transport (R4b).
3. **Freely chosen keyspace position.** A node's position is its libp2p peer id,
   chosen by whoever generates the key. §7.2 replaces it.
4. **Unsigned record classes.** `objectManifestValidator` carries no signature;
   `place.Record` is unsigned by design. Both reasonings are correct for their
   current uses and inadequate for descriptors and name bindings.
5. **Distinct-peer-only placement.** `placement.Plan` must gain the §7.5
   diversity ladder; nothing in the tree does IP-prefix diversity today.
6. **The default protocol prefix.** A distinct prefix is one line and prevents
   accidental keyspace union with an unrelated network.

---

### 7.0 Why Kademlia, argued rather than assumed

Kademlia is the incumbent here — it is already running — but incumbency is not a
justification, and the anonymity requirement changes the trade-offs enough that
the choice deserves re-derivation.

| Overlay | What it gives | Why it loses here |
|---|---|---|
| **Kademlia (XOR metric)** | Symmetric metric (d(a,b) = d(b,a)), so routing information is learned free from incoming traffic and a claimed position is verifiable. Parallel lookups are natural. k-buckets tolerate churn without a repair protocol. | Nothing structural. Its weaknesses — free position choice, no verifiable routing — are exactly what §7.2 and §7.3 address. |
| **Chord / Pastry** | Tighter routing-table bounds; Pastry's proximity-neighbour selection lowers latency. | Asymmetric successor/predecessor structure: an attacked ring produces silently *wrong* successors rather than an unavailable lookup, and repairing it under 50 % churn is a stabilisation protocol where k-bucket repair is a no-op. There is essentially one route to a successor, so d disjoint paths cannot be expressed. **Rejected: disjoint paths are our primary lookup defence.** |
| **Structured overlay with verifiable routing** | Each hop can prove it forwarded toward the target, so a hop cannot silently misroute — genuinely stronger than §7.3. | Needs an authority certifying which nodes exist and where, or a membership consensus: precisely what R14 refuses. Also needs per-hop proof verification on the request path. **`[NEEDS RESEARCH]` rather than rejected** — a construction that works without membership consensus would dominate §7.3. |
| **Freenet-style small-world routing** (greedy routing over a location-swapped small-world graph — what Freenet actually uses) | Plausible deniability for the routing node; no explicit who-stores-what table to enumerate; the request path is itself the anonymity mechanism. | (a) Retrieval is best-effort by construction and R8 requires availability to be contracted and measured. (b) Location swapping is the attack surface — an adversary in the swap protocol walks toward a target location, and the defence is a trusted friend graph we do not have. No bounded lookup depth, so censorship shows up as latency you cannot distinguish from load. **Rejected: we need a lookup that returns or provably failed.** |

**Kademlia wins because of the symmetric metric.** That single property is what
makes §7.2 possible: because `d(a,b) = d(b,a)`, a node verifies for itself
whether a peer claiming to be near a key actually is, using only that peer's
signed descriptor and the current epoch's SRV — no third party, no consensus, no
membership authority. In an asymmetric overlay the same check requires knowing
the ring, which requires knowing the membership, which is R14's forbidden
object. What we borrow from the others anyway: sibling lists (§7.3) are Chord's
successor list imported via S/Kademlia; independent replica positions (§7.1) are
Tor's, not Kademlia's; and "best effort is not availability" is Freenet's lesson
learned in the negative.

---

### 7.1 Record types and keyspaces

**Rule: one routing substrate, six domain-separated keyspaces.** Every key is a
256-bit SHA-256 digest whose first pre-image byte-string begins with an ASCII
class label. Two record classes can therefore never collide, and a write for
class X can never overwrite a record of class Y even if an attacker finds the
input that would produce the same digest — because the storing node recomputes
the key from the record's own fields and rejects a mismatch (the rule
`internal/dcs/dht.go:32` already enforces for worker records, generalised).

*Alternative rejected:* two physically separate overlays (a descriptor DHT and a
content DHT), which is the naive reading of R4d. It halves the honest node count
in each overlay while leaving the attacker's identity budget whole, so it
*lowers* the Sybil bar in both. R4d is satisfied by separate keyspaces, separate
record types, separate quotas and separate validators over one routing table.

```text
key(class, input)  =  SHA-256( "axon:" ‖ class ‖ ":v1" ‖ 0x00 ‖ input )
```

| Record | Key derivation (input to the hash above) | Value schema (canonical CBOR, deterministic encoding) | Size bound | TTL / republish | Signing key | Who may write | Replica layout |
|---|---|---|---|---|---|---|---|
| **RelayDescriptor** `[BUILD NOW]` | class `relay`, input = `NodeIdentity_pub ‖ SRV_epoch` | `{ver, node_id_pub[32], routing_ed25519[32], routing_x25519[32], addrs[], caps_bitmap, claimed_bw, prefix_v4/v6, asn, bond_ref, epoch, seq:u64, exp, sig}` | 2 KiB | 3 h / 1 h | `NodeIdentity` (Ed25519), which certifies the epoch's `RoutingIdentity` inside the value | Only the holder of the `NodeIdentity` whose pubkey appears in the key pre-image | r=8 closest to one key |
| **ServiceDescriptor (blinded)** `[BUILD NOW]` | class `desc`, input = `BlindedPub[32] ‖ time_period ‖ replica_index(0..7)` | Tor-v3-shaped: outer plaintext `{ver, blinded_pub, desc_signing_cert, revision:u64, lifetime}` + `sig` by blinded key; inner layer encrypted to the subcredential and containing ≤3 intro-point entries with their `RoutingIdentity` and auth keys | 8 KiB | 3 h / 1 h (Constitution §5) | Blinded `ServiceIdentity` — scalar-blinded per Tor rend-spec-v3 | Anyone holding the blinded private key. The storing node verifies the signature *against the pubkey embedded in its own key derivation*, so it authorises without learning who | **8 independent positions**, one per `replica_index` |
| **DomainRecord** `[BUILD NOW]` | class `domain`, input = `SHA-256(name_normalised) ‖ SRV_epoch` | `{ver, name_hash[32], domain_identity_pub[32], records[] (service delegations, CID pointers), snapshot_root[32], inclusion_proof, seq:u64, exp, sig}` | 16 KiB | 6 h / 1 h | `DomainIdentity` (Ed25519) | The `DomainIdentity` whose binding to `name_hash` verifies against the registry snapshot root carried in the record | 8 independent positions |
| **StorageLocation** `[BUILD NOW]` | class `loc`, input = `CID` (BLAKE3 root, Constitution §2) | **Multi-writer set record.** `{ver, cid, entries[≤64]}` where each entry is `{holder_node_id[32], bond_ref, exp, sig_by_holder}` | 8 KiB | entry 2 h / holder republishes 30 min | Each *entry* signed by its own holder; the record as a whole is unsigned | Any bonded node, for its own entry only | r=8 closest to one key; entries merged, not replaced |
| **RegistrySnapshot anchor** `[BUILD NOW]` | class `snap`, input = `chain_id ‖ snapshot_epoch` | `{ver, snapshot_root[32], eth_block_number, eth_state_root[32], anchor_tx_proof, body_cid (BLAKE3), publisher_pub, sig}` | 4 KiB (anchor only — the snapshot *body* lives in the content layer under `body_cid`) | 48 h / 6 h | Publisher's Ed25519 — **but the signature is not the authorisation** | **Anyone.** The record proves itself against the chain through the existing light client; a wrong one fails verification and is dropped | r=8 closest to one key |
| **IntroPointRecord** `[BUILD NOW]` | class `intro`, input = `IntroPoint_RoutingID[32] ‖ SRV_epoch` | `{ver, routing_id[32], pow_seed[32], pow_difficulty:u8, token_issuer_pub[32], capacity_hint, seq:u64, exp, sig}` | 512 B | 30 min / 10 min | The intro point's `RoutingIdentity` | The intro point relay itself | r=8 closest to one key |

Notes that are load-bearing:

- **Why `IntroPointRecord` exists at all,** given Tor keeps intro points inside
  the descriptor: R10 requires them to be rate-limited by a PoW/token puzzle,
  and the difficulty has to move faster than a 3 h descriptor lifetime or it is
  useless against a live flood. Cost: intro-point *relays* become enumerable
  (§7.7); the service they front does not, because that binding is only in the
  descriptor's encrypted inner layer.
- **Why descriptors get 8 independent positions and the others do not.** With
  `replica_index` in the pre-image the 8 replicas sit at 8 unrelated keyspace
  points, so eclipsing a descriptor means eclipsing eight unrelated regions.
  Publishing costs 8 lookups; **fetching costs one**, because the client picks
  an index at random. `StorageLocation` is excluded: its replica set is already
  governed by the diversity ladder (§7.5) and 8× publish cost per CID is
  unaffordable at content scale.
- **`RegistrySnapshot` has no authorised writer.** It is self-verifying, so
  restricting publication would only create a censorship point. Merge rule:
  highest `snapshot_epoch` whose chain proof verifies. This serves R7 directly.
- **Size vs. the cell budget.** At 1024 B cells, a 16 B header and a 16 B tag
  per hop position, a 3-hop circuit carries 960 B per cell — an 8 KiB descriptor
  is 9 cells. Stated once; the L4 section owns the framing.

---

### 7.2 KadID derivation and epoch rotation

```text
KadID = SHA-256( "axon:kadid:v1" ‖ 0x00 ‖ NodeIdentity_pub[32]
                                 ‖ SRV_epoch[32]
                                 ‖ network_prefix )        → 256 bits

network_prefix = 0x04 ‖ <IPv4 /24, 3 bytes>   for an IPv4-reachable node
               = 0x06 ‖ <IPv6 /48, 6 bytes>   for an IPv6-reachable node
SRV_epoch      = the verified beacon-chain RANDAO mix for the epoch
                 (Constitution R13; obtained through the existing light client)
```

Each term is doing one job and only one:

| Term | Job | What breaks for the attacker |
|---|---|---|
| `NodeIdentity_pub` | Binds position to the identity that carries the bond and the reputation | A new position requires a new identity, which requires a new bond |
| `SRV_epoch` | Makes the position **perishable** | A position ground for today's SRV is uncorrelated with tomorrow's. Pre-positioning is impossible because the SRV is unknown until the epoch's sampling slot passes |
| `network_prefix` | Makes the position **self-checkable and address-bound** | Any peer with a live connection recomputes `KadID` from the observed source prefix and rejects a mismatch. Moving a node changes its position, so an attacker cannot hold a ground position while rotating addresses through a proxy pool |

`network_prefix` alone does not cap identities per location — a /24 can still
mint unlimited keypairs. The cap is an explicit admission rule enforced by every
node maintaining a routing table, and it is the term that makes the arithmetic
below hold:

```text
ADMISSION (routing table and sibling list)
  ≤ 2 entries per /24 (v4) or /48 (v6) per k-bucket
  ≤ 8 entries per ASN per k-bucket
  ≤ 1 replica-set slot per /24 and ≤ 1 per ASN     (see §7.5)
```

#### The arithmetic

Let N = honest identities in the DHT, A = attacker identities, and
f = A/(N+A) the attacker's share of the population. All identities land
uniformly in the keyspace because `SRV_epoch` is not chosen by them. The
attacker owns all r = 8 replica slots of a *specific* key in a *specific* epoch
with probability

```text
P_full  =  ∏(i=0..7) (A − i)/(N + A − i)   ≈   f⁸
```

| f (attacker share of identities) | P_full per key per epoch | Expected epochs to eclipse one chosen key | Fraction of *all* keys eclipsed in every epoch |
|---|---|---|---|
| 0.05 | 3.9 × 10⁻¹¹ | 2.6 × 10¹⁰ (7×10⁷ years) | 1 in 2.6 × 10¹⁰ |
| 0.10 | 1.0 × 10⁻⁸ | 1.0 × 10⁸ (274,000 years) | 1 in 10⁸ |
| 0.20 | 2.6 × 10⁻⁶ | 3.9 × 10⁵ (1,070 years) | 1 in 390,000 |
| 0.33 | 1.5 × 10⁻⁴ | 6.6 × 10³ (18 years) | 1 in 6,600 |
| 0.50 | 3.9 × 10⁻³ | 256 (256 days) | **1 in 256** |
| 0.70 | 5.8 × 10⁻² | 17 (17 days) | 1 in 17 |
| 0.90 | 4.3 × 10⁻¹ | 2.3 | 1 in 2.3 |

Read the last column, not the third. **At f = 0.5 no chosen key is reliably
eclipsed, but 0.39 % of the whole namespace is eclipsed at any instant, and it
is a different 0.39 % every day.** Whoever owns those keys that day is censored,
without having been targeted. That is the honest characterisation of what epoch
rotation buys: it turns a persistent targeted attack into a rotating untargeted
one. It does not eliminate the harm.

#### The diversity constraint is the hard bound

Because a replica set admits at most one member per /24 and one per ASN (§7.5),
an attacker present in g distinct ASNs holds **at most min(g, 8)** slots
regardless of A:

```text
g < 8   →   P_full = 0, exactly. Full eclipse is structurally impossible.
g ≥ 8   →   P_full ≈ (f_asn)⁸ where f_asn weights ASNs by the identities in them
```

This is the term that converts the attack from "buy identities" to "buy presence
in eight independent autonomous systems, each with its own /24, and keep all
eight bonded across every epoch you want the eclipse to persist". For a
well-resourced adversary that is a purchase order, not a barrier — a large cloud
provider spans many ASNs, and ASN diversity is not operator diversity. Which is
why the ladder has a fourth rung (operator, from `NodeRegistry.Node.owner`) in
§7.5, and why we do not claim this makes eclipse impossible.

#### What re-grinding actually costs

| Step | Cost | Comment |
|---|---|---|
| Find one identity landing inside the 8-nearest ball at N = 10⁴ | ~1,250 SHA-256 | Free |
| Find eight | ~10⁴ SHA-256 | Free |
| Make those eight *usable* | 8 bonds in `StakeVault` | The actual price |
| Keep them usable next epoch | The ground positions are gone; the same eight bonded identities land uniformly at random | **You cannot re-grind without new identities, and new identities need new bonds** |
| Recycle capital from a discarded identity | Blocked for `withdrawDelay` | `StakeVault.requestWithdraw` / `withdrawableAt` (`StakeVault.sol:19-20,54-61`) — capital is locked through the delay window and remains slashable in it |

**The attack cost per persistently-eclipsed key per epoch is therefore eight
fresh bonds in eight distinct ASNs, with the previous eight bonds still locked.**
That is the sentence the whole mechanism exists to be able to write.

#### The RANDAO caveat, made concrete

R13 requires SRV to be the beacon-chain RANDAO mix and requires us to document
its last-revealer bias. The bias matters here in a specific, quantifiable way:
an attacker who controls the last k block proposers before the sampling slot can
withhold blocks and thereby choose among up to 2ᵏ candidate SRVs — and can pick
the one that best positions the bonded identities they *already hold*.

```text
P_full(with k withheld slots)  ≈  1 − (1 − f⁸)^(2^k)  ≈  2^k · f⁸   (for small f⁸)
```

| f | k = 0 | k = 2 (4 choices) | k = 4 (16 choices) | k = 8 (256 choices) |
|---|---|---|---|---|
| 0.20 | 2.6 × 10⁻⁶ | 1.0 × 10⁻⁵ | 4.2 × 10⁻⁵ | 6.7 × 10⁻⁴ |
| 0.33 | 1.5 × 10⁻⁴ | 6.1 × 10⁻⁴ | 2.4 × 10⁻³ | 3.8 × 10⁻² |
| 0.50 | 3.9 × 10⁻³ | 1.6 × 10⁻² | 6.0 × 10⁻² | 6.3 × 10⁻¹ |

An adversary who is simultaneously a large staker *and* holds half the DHT
identities gets a materially better attack. This is exactly the case R13 says
is tolerable "for keyspace rotation but NOT for anything requiring
unpredictable-and-unbiasable randomness" — we accept it for KadID and flag it
here so the naming layer does not accidentally reuse SRV for something where a
few bits of adversarial choice would be fatal. `[NEEDS RESEARCH]` — whether to
mix a VDF or a second, independent beacon into SRV to kill the last-revealer
choice is a real open question and it is not resolved in v1.

---

### 7.3 S/Kademlia-style hardening

Four mechanisms, all from the S/Kademlia line of work, all adapted:

| Mechanism | Parameter | What it defends |
|---|---|---|
| Disjoint lookup paths | d = 3 (Constitution §5) | A hostile node on one path cannot poison the others' candidate sets |
| Sibling list | s = 2r = 16 | Replica-set membership is agreed by the nodes closest to the key, not inferred per-lookup |
| Signed routing entries | every entry | A peer cannot be advertised at a position it does not occupy |
| KadID verification | every contact | The recipient recomputes `KadID` and checks it against the observed prefix |

**Signed routing table entry.** Every entry is the peer's own `RelayDescriptor`
(§7.1) or a compact projection of it. Admission requires: (a) the signature
verifies under `NodeIdentity`; (b) `KadID` recomputes from
`NodeIdentity_pub ‖ SRV_epoch ‖ prefix`; (c) for entries learned from a live
connection, the prefix matches the connection's observed source; (d) the §7.2
caps are not exceeded. Entries learned indirectly (returned in a `FIND_NODE`)
satisfy (a), (b), (d) but not (c) and are marked `unverified`. **An `unverified`
entry may be used to make routing progress but may never be counted toward a
replica set.** That distinction is the whole value of the signature.

#### The lookup algorithm

```text
LOOKUP(K, d=3, α=3, k=20, r=8) → (records, evidence)

  # Global disjointness state, shared across the d paths.
  claimed ← ∅                       # every node id ever admitted to any path

  # Seed. Take the 3d closest verified entries to K from the local routing
  # table and deal them round-robin, so no two paths begin in the same
  # bucket-neighbourhood and one poisoned bucket cannot seed all three.
  seeds ← closest_verified(local_table, K, 3d)
  for i in 0..d-1:
      P[i].frontier ← ∅
      for node in seeds[i::d]:
          if claim(node):  P[i].frontier.add(node)
      P[i].queried  ← ∅
      P[i].best     ← ∞

  # Each path runs an ordinary Kademlia iterative lookup, but draws only from
  # nodes it has exclusively claimed.
  parallel for i in 0..d-1:
      while P[i].frontier ≠ ∅ and not P[i].converged():
          batch ← α closest unqueried nodes in P[i].frontier
          responses ← rpc_parallel(batch, FIND_VALUE(K))
          for (node, resp) in responses:
              P[i].queried.add(node)
              for cand in resp.closer_nodes:
                  if not verify_entry(cand):      continue   # sig + KadID + caps
                  if not claim(cand):             continue   # DISJOINTNESS
                  P[i].frontier.add(cand)
              if resp.record ≠ ⊥ and validate(K, resp.record):
                  P[i].result ← merge(P[i].result, resp.record)
          P[i].converged() ⟺ the k closest known nodes have all been queried
                              and no response improved P[i].best this round

  records  ← merge_by_class(P[0].result, …, P[d-1].result)   # §7.6 merge rules
  evidence ← { per-path: hops, timeouts, refusals, closest_reached }
  return (records, evidence)

  # claim() is a test-and-set on `claimed`, executed at the moment a candidate
  # is admitted to any frontier.
  claim(n) ≜ atomically: if n ∈ claimed then false else (claimed ← claimed ∪ {n}; true)
```

**The disjointness invariant, stated exactly:**

```text
∀ i ≠ j :  P[i].queried  ∩  P[j].queried  =  ∅
```

It is enforced by construction: a node enters `P[i].frontier` only via `claim`,
which succeeds at most once across all paths, and a node is queried only from
the frontier it entered. The invariant is over *queried nodes*, not over the
records returned; two paths reaching the same record through disjoint node sets
is the success case, not a violation.

**What disjoint paths do and do not buy.** They buy *availability against
refusal*: an adversary must control at least one node on **every** path, and the
paths share no nodes. They buy almost nothing against forgery, because every
record class in §7.1 is signed and self-validating — a lying node can refuse or
delay, not substitute. d = 3 is a censorship-resistance parameter, not an
integrity parameter, and raising it does not make records more trustworthy.

**Cost.** d = 3 with α = 3 is up to 9 concurrent RPCs and ~3× the message volume
of a plain lookup, each RPC crossing a 3-hop circuit (§7.4). This is the
dominant latency term in resolution and the reason the naming layer must cache.

**Sibling lists.** Each node maintains the s = 16 nodes closest to its own
`KadID`, refreshed each epoch and on membership change, under the §7.2 caps.
This makes "who are the r = 8 replicas for key K" a question the nodes near K
agree on rather than one each publisher answers alone: a write is accepted only
by a node that believes itself within the r closest, and that belief is
checkable by anyone against the same SRV and the same signed descriptors.
`s = 2r` gives one full replica set of headroom for churn between refreshes.

---

### 7.4 Blinded and privacy-preserving lookups

Three separate protections, which are often conflated and should not be:

```text
WHAT THE STORING NODE LEARNS
  neither defence   "203.0.113.9 asked for alice.lab.axon's descriptor at 14:02"
  blinding only     "203.0.113.9 asked for key 7f3a… at 14:02"
  blinding+circuit  "relay R (a terminal hop) asked for key 7f3a… at 14:02"
                    ...which is where we stop. See the residual below.
```

**Blinding (Constitution §2: Ed25519 key blinding per Tor rend-spec-v3).** For
time period T the service blinds `ServiceIdentity` to `BlindedPub` and publishes
at `key("desc", BlindedPub ‖ T ‖ replica_index)`. The storing node verifies the
signature under `BlindedPub` extracted from its *own key pre-image* — so
**authorisation is checkable without identity being learnable** — and the inner
layer is encrypted to a subcredential derived from the unblinded identity, so
the holder cannot read the intro-point set either. This is Tor's design
reimplemented, not improved on.

**Lookups over a circuit (R4b).** Every client-issued `GET` is emitted by an L4
circuit's terminal hop, one circuit per *isolation context* rather than per
lookup: a fresh circuit per lookup is both unaffordable and counterproductive,
since it maximises the number of distinct relays that see any of your lookups.
Circuits rotate on the 10-minute tunnel lifetime (Constitution §5).

**Nodes in the DHT do not get this protection and are not supposed to.** R4a
makes membership public, so a relay's own maintenance traffic (bucket, sibling
and replica refresh) goes direct; only *client interest* is circuit-borne.
Routing maintenance through circuits would double DHT maintenance cost and make
the DHT depend on the circuit layer that depends on the DHT for relay discovery
— a bootstrap cycle.

#### The residual leak, stated without hedging

| Leak | Who sees it | Why we cannot close it |
|---|---|---|
| Request **timing and volume** for a keyspace region | The r = 8 storing nodes for that region | The record has to be fetchable, so somebody has to be asked. Popularity of a blinded key is visible even though the key is meaningless |
| The **blinded key itself**, to the terminal relay | The circuit's last hop | It has to send the query somewhere. The key is meaningless without the identity — *unless* the relay knows the identity, which for an on-chain-registered domain it does (§7.7) |
| **Repeated** lookups of the same key over the same circuit | The terminal relay | Correlates a client's interest set within one 10-minute circuit lifetime. Mitigation is circuit rotation, which bounds but does not remove it |
| The **fact that a key exists** in a region | Anyone who probes | Kademlia answers "not found" distinguishably from "found"; a probing adversary maps which regions hold live descriptors |

Padding the region-level request pattern is `[UNSOLVED]` and we do not attempt
it in v1. Fetching decoy keys alongside real ones is the obvious idea and is
`[NEEDS RESEARCH]`: it costs bandwidth linearly in the decoy ratio and its
effectiveness against a storing node that sees the whole region's traffic is not
established.

---

### 7.5 Replication, repair, and churn

#### The diversity ladder `[BUILD NOW]`

The Constitution instructs reuse of "the existing placement engine's diversity
levels". **They do not exist.** `internal/placement/plan.go` guarantees distinct
*peer ids* and nothing else, and its own package doc says so. The ladder below
is new code, shaped to slot into `placement.Plan` as an additional filter so the
existing durability tests keep meaning what they mean:

```text
D0  distinct NodeIdentity     ← exists today (placement.Plan)
D1  distinct /24 (v4) or /48 (v6)
D2  distinct ASN
D3  distinct operator         ← NodeRegistry.Node.owner, on-chain
                                (proof-of-facilitation/contracts/NodeRegistry.sol:24-34)
```

D3 is available for free and is the strongest rung: `NodeRegistry` already maps
`nodeId = keccak256(p2pPublicKey)` to an owner address, so "two nodes with the
same operator" is a public, checkable fact. It costs nothing in privacy that the
chain does not already cost (R6), and it catches the case D2 misses — one
operator renting capacity in eight ASNs.

**Replica selection:** walk the candidates in ascending XOR distance from the
key; admit a candidate only if it introduces a new D1 *and* a new D2 *and* a new
D3 value; stop at r = 8. If the network cannot supply 8 at full diversity,
**relax one rung at a time, record which rung was relaxed in the record's local
metadata, and report it** — the same discipline `internal/store/placement.go`
already applies by counting `DistinctHolders` rather than placements, and by
refusing to call a co-located object durable.

#### The repair loop

Modelled directly on the existing audit machinery, which is the right shape and
should not be redesigned:

```text
every REPAIR_INTERVAL (10 min, jittered ±25 %):
  for each key this node is within the r closest to, oldest-audited first:
    live ← 0
    for each of the other r-1 expected replicas:
      probe HAVE(key, seq)
      if answered and seq ≥ ours:   live++;  clear_silence(peer)
      if answered and seq <  ours:  push our record (a rollback candidate, §7.6)
      if silent:                    n ← note_silence(peer)
                                    if n ≥ 3 consecutive: drop from replica set
    if live + 1 < r:  re-place the deficit at the next-closest diverse candidates
```

`note_silence` / `clear_silence` are `Store.NoteHolderSilence` and
`NoteHolderAnswered` (`internal/store/placement.go:483-532`) generalised from
shards to records, including the property that made them correct: silences are
**consecutive** and persisted, so a reboot does not evict a node and a node
silent for two days does not get a clean slate from a process restart.

#### Join and leave

```text
JOIN   1. Acquire NodeIdentity, bond it (StakeVault.bond).
       2. Fetch SRV_epoch via the light client; compute KadID.
       3. Bootstrap the routing table (L2).
       4. Publish RelayDescriptor.
       5. Ask each sibling for records in the range this node is now within the
          r closest to. Records are signed, so a lying sibling withholds but
          cannot forge. Accept only records that validate AND whose key really
          places this node in the r closest under the current SRV.
       6. Serve reads only after 5 completes, or after a bounded timeout with a
          `partial` flag — never silently answer NOT_FOUND from an empty range.

LEAVE  graceful:  stop writes, keep serving; push held records to the
       (graceful) next-closest diverse candidate; publish RelayDescriptor with
                  exp = now; StakeVault.requestWithdraw (still slashable).
       ungraceful: nothing. Repair notices in ≤3 audit intervals (≤30 min) and
                  the publisher's hourly republish usually beats it there.
```

Step 6 matters more than it looks: a joining node answering `NOT_FOUND` for a
range it has not yet received is indistinguishable from an eclipse, and at scale
a steady stream of joins is a background of false negatives that masks a real
attack.

#### The scheduled 100 % churn event nobody else has

**Every epoch boundary reshuffles the entire keyspace.** This is the cost of
§7.2 and it is not small: at the boundary, every node's `KadID` changes, so
every record's replica set changes, so in principle every record must be
re-placed. The arithmetic:

```text
10⁶ records × r=8 × 1 KiB mean          =  8 GiB per epoch, network-wide
8 GiB / 86,400 s                        =  ~97 KB/s aggregate
at N = 10⁴ nodes                        =  ~10 B/s per node
```

Negligible in bandwidth; not negligible in correctness, so: records are stored
and served under **both** the epoch-e and epoch-e+1 assignments for a 2 h window
straddling the boundary, and **publishers, not holders, own re-placement** — a
holder pushes to the new set as a courtesy, the guarantee comes from the next
hourly republish. Requiring holders to hand off would make every epoch boundary
a synchronised network-wide transfer storm. The overlap window is also an attack
window: 16 nodes can answer for a key instead of 8, halving the share of the
replica set an attacker needs to be *present* in — though not to eclipse.

#### A 50 % churn event

Independent uniform loss of half the nodes, with r = 8 and diversity satisfied:

| Quantity | Value | Reasoning |
|---|---|---|
| Records losing **all** replicas | 2⁻⁸ = **0.39 %** | Each replica survives with p = 0.5, independently |
| Records losing ≥ 4 replicas | ~63 % | Binomial(8, 0.5) ≥ 4 |
| Time for a record with ≥1 live replica to return to r = 8 | ≤ 1 repair interval + placement time (~10–20 min) | Repair loop above |
| Time for a record with 0 live replicas to return | ≤ publisher's republish interval (1 h for descriptors/domains) | Only the publisher can regenerate a signed record |
| Records **permanently** lost | those whose publisher is also gone | A `DomainRecord` whose `DomainIdentity` is offline is gone until it comes back. The registry snapshot still proves the name exists and who owns it — R7's point exactly |
| Routing table health | k = 20 buckets retain ~10 live entries | Lookups slow; they do not fail |
| `StorageLocation` entries | lost entries repopulate as surviving holders republish (30 min) | The 6+3 erasure layer's own durability is the storage section's problem, not this one's |

Independence is the assumption that will not hold in the real failure that
matters (a cloud region, an ASN, a jurisdiction). The diversity ladder is
precisely the defence against correlated loss, and D3 is the rung that addresses
the correlation nobody else catches.

---

### 7.6 Write authorisation and anti-poisoning

**Every record carries a signature and a monotonic `seq:u64`.** This is not new
— `gateway.Registration` and `dcs.WorkerRecord` both have `Sequence` and both
`Select` on it (`internal/gateway/dht.go:38-55`, `internal/dcs/dht.go:45-60`).
What is new is that the rule has to survive an adversary rather than merely a
stale cache.

**Conflict resolution, exactly:**

```text
BETTER(a, b) for single-writer classes:
  1. drop any record failing validate() outright
  2. higher seq wins
  3. tie → lower SHA-256(canonical_encoding(record)) wins    # deterministic
  4. never: "newer wall-clock", "the one I heard first", "the larger one"
```

Rule 3 is not decoration. Two honest replicas that disagree must converge on the
same answer without talking to each other, or the record oscillates forever and
every client sees a coin flip. A wall-clock tiebreak reintroduces the clock as a
trust input.

**`StorageLocation` is the exception and needs its own rule** because it is
multi-writer:

```text
MERGE(a, b) for StorageLocation:
  entries ← a.entries ∪ b.entries, keyed by holder_node_id
  per holder: keep the entry with the higher exp and a valid sig
  drop entries whose exp has passed
  drop entries whose bond_ref does not verify (§7.9)
  if |entries| > 64: keep the 64 with the highest bond, ties by lowest node id
```

The bond-ordered eviction is what stops an index-poisoning flood: an attacker
can add entries, but displacing an honest holder from a full record costs more
bond than the honest holder posted.

**Rollback resistance for mutable records `[BUILD NOW]`.** A storing node keeps
a `seq_floor` table: `key → highest seq ever validated`, retained for
**2 × max_TTL** past the record's own expiry, and refuses any write with
`seq < seq_floor[key]`. Costs 40 bytes per key.

The honest residual: **a node that has never seen the key has no floor**, so
rollback succeeds against freshly joined nodes and nodes whose floor aged out.
Three partial defences, none complete: (1) **quorum read** — the client takes
the highest `seq` any replica returns, so rollback needs all 8 floor-ignorant at
once, which is exactly what a 50 % churn event or a successful eclipse produces;
(2) **floor transfer on join** (JOIN step 5), which moves the problem to
siblings lying about the floor — possible only downward, and only for keys they
also withhold; (3) **chain anchoring for `DomainRecord` only**, where the
registry snapshot commits to a per-domain minimum `seq`, at one on-chain write
per snapshot rather than per record — the naming layer's call.

Rollback is `[NEEDS RESEARCH]` in the general case. A DHT without a consensus
cannot make "this is the newest version" decidable; it can only make old
versions expensive to present.

---

### 7.7 Attack analysis

| Attack | Mechanism | Mitigation | Residual risk |
|---|---|---|---|
| **Sybil** | Mint unlimited identities to inflate f | Bond per identity (`StakeVault`), verified via §7.9. Per-prefix and per-ASN admission caps (§7.2) | Bonds are a *price*, not a barrier. A funded adversary buys f. The caps bound identities per *location*, not per *wallet*, and D3 only helps where the operator is honestly registered |
| **Eclipse of a specific key** | Occupy all r = 8 replica slots | KadID = H(id ‖ SRV ‖ prefix); r = 8 with D1/D2/D3 diversity; d = 3 disjoint paths; independent replica positions for descriptors | Quantified in §7.2. At f = 0.5 targeted eclipse needs 256 epochs, but 1/256 of the namespace is eclipsed *every* epoch. RANDAO bias multiplies this by up to 2ᵏ |
| **Targeted-key placement** (pre-position near a key you will later censor) | Grind identities toward a known key | SRV rotation makes the grind expire in ≤24 h; the grind itself is free but the bond is not | An adversary who wants a key eclipsed *on a known future date* still cannot pre-position, because SRV for that date is unknown. An adversary who wants it eclipsed *eventually* just waits |
| **Eclipse of a node** (feed one node a false view) | Fill its routing table with your identities | Signed routing entries; per-prefix/per-ASN caps per bucket; `unverified` entries barred from replica sets; bootstrap diversity (L2) | A node whose *first* view of the network is adversarial is adversarially bootstrapped, and no amount of later hardening fixes it. This is R14's epistemic-partition problem in its DHT form and it is **`[UNSOLVED]`** |
| **Routing manipulation** (return wrong "closer" nodes) | Steer lookups into a controlled region | Every returned entry must verify (sig + KadID + prefix) before entering a frontier; d = 3 disjoint paths; lookup returns per-path `evidence` so a client can see one path diverging | A hostile node can still return *fewer* or *slower* valid entries. Degradation is cheap; the client sees a slow lookup, not an attack |
| **Storage refusal** (accept a write, serve nothing) | Silent censorship of a record you hold | Repair-loop `HAVE` probes with consecutive-silence counting; publisher republish; the audit-challenge machinery already proven in `recall_lying_holder_test.go` | A node that answers probes honestly and refuses only *specific requesters* is invisible to the repair loop. Detecting selective refusal requires probing as the victim, which requires the victim's circuit |
| **Index poisoning** (`StorageLocation`) | Flood a CID's entry list with fake holders | Per-entry signature; bond-ordered eviction; 64-entry cap; a bad entry costs the fetcher one wasted dial, which is already the existing model (`internal/place/place.go` package doc) | An attacker with enough bond can occupy the list and turn every fetch into 64 wasted dials. Fetch cost, not correctness — but a real DoS on retrieval latency |
| **Lookup correlation** | Learn who is interested in what | Lookups over circuits (R4b); blinded keys; per-context circuits | The storing node sees timing and volume per keyspace region; the terminal relay sees the key. Correlating a client's interest set across circuit rotations is not defended against |
| **Enumeration of the namespace** | List every registered name | See below — this one deserves its own treatment | See below |

#### Enumeration, honestly

**Can an adversary enumerate all registered `.axon` domains? Yes, and nothing the
DHT does changes that.** Registration is on-chain (R6), the chain is public, and
the Constitution's adversary model explicitly grants the adversary complete
observation of the blockchain. `AxonRegistry` events are the domain list. Any
claim that the DHT hides the set of registered names is false, and this document
does not make it.

What the DHT layer *can* and *cannot* hide, separated:

| Question | Hidden? | Why |
|---|---|---|
| Which names exist | **No** | On-chain registration. Structural, not a DHT property |
| Who owns a name | **No** | `OwnerIdentity` is an Ethereum account and its transactions are public. R6 refuses to claim otherwise |
| Which names have a **live service right now** | **No, against a chain observer** | `DomainIdentity` is committed on-chain, so an adversary computes `BlindedPub` for each period and probes each name's descriptor key. This is the same property Tor has: knowing the address lets you compute the HSDir key |
| Which names have a live service, against someone who does **not** know the identity | **Yes** | The keyspace is 256 bits of SHA-256 over an Ed25519 point; brute-force enumeration is not a thing |
| Which relays run an intro point | **No** | `IntroPointRecord` is published under the intro point's own routing id (§7.1). Deliberate trade for R10's rate limiting |
| **Which intro point serves which service** | **Yes** | The binding lives only in the descriptor's encrypted inner layer |
| Which nodes are in the DHT | **No, by design** | R4a: DHT membership is public, relays are public |
| Which CIDs exist | **Partially** | `StorageLocation` keys are BLAKE3 roots; not enumerable by brute force, but a holder knows every CID it holds an entry for, and the r = 8 nearest nodes to a CID learn of its existence |

**The load-bearing conclusion: descriptor blinding buys privacy against parties
who do not already know the service identity, and for an on-chain-registered
`.axon` domain the adversary in our model always knows it.** Blinding does real
work only for `ServiceIdentity` values never registered on-chain — unlisted
services reached by out-of-band address exchange. The naming layer must say this
too: a user choosing between a registered name and an unlisted service is
choosing between two different privacy properties.

---

### 7.8 Rate limiting and DoS

**The structural problem first:** because client lookups arrive over circuits
(R4b), the "source" a storing node sees is a *terminal relay*, which aggregates
many unrelated clients. Per-source rate limiting therefore punishes popular
relays and is useless against an attacker who spreads across many circuits.
**Per-source limits are a coarse backstop; the per-key budget is the real read
control, and the write side is where the actual defence lives.**

| Budget | Scope | Value (v1, tunable) | Rationale |
|---|---|---|---|
| Read, per source | Per connected peer / circuit terminal | 50 req/s sustained, burst 200, token bucket | Generous because sources are aggregators |
| Read, per key | Per key, all sources | 20 req/s sustained, burst 100 | A single key being hammered is the actual abuse signal |
| Read, per keyspace region | Per bucket-prefix, all sources | 500 req/s | Catches an enumeration sweep that spreads across keys |
| Write, per key | Per key | 1 accepted write per 60 s | Republish cadence is hourly (§7.1); 60 s is 60× headroom |
| Write, per source | Per bonded `NodeIdentity` | 20 writes/s | Bond-gated, so it is a fairness control not a security one |
| Value size | Per class | §7.1 table | Enforced by the validator before signature check — cheap check first, matching `internal/dcs/rpc.go:125`'s existing discipline |

**Proof-of-work for writes `[BUILD NOW]`.** A write that does not carry a valid
bond reference must carry a puzzle solution:

```text
H( "axon:dht:pow:v1" ‖ 0x00 ‖ KadID_of_target_node ‖ SRV_epoch
                             ‖ SHA-256(record_canonical) ‖ nonce )  <  2^(256−w)
```

Binding to `KadID_of_target_node` stops one solution being replayed across the
r = 8 replicas; binding to `SRV_epoch` stops precomputation more than one epoch
ahead; binding to the record hash stops a solution being reused for different
content.

| w | Expected hashes | ~Time, one modern core | Intended for |
|---|---|---|---|
| 18 | 2.6 × 10⁵ | ~3 ms | Idle node, unbonded write |
| 22 | 4.2 × 10⁶ | ~40 ms | Normal load |
| 26 | 6.7 × 10⁷ | ~0.7 s | Under pressure |
| 30 | 1.1 × 10⁹ | ~11 s | Under attack; effectively write-closed to casual clients |

`w` is chosen per-node from its own accept queue depth and published in the
node's `RelayDescriptor` so a client sizes the puzzle before spending it.

**The honest problem with PoW:** it disadvantages exactly the clients we care
about (battery-powered, low-power, single-device) and barely inconveniences the
attacker we fear (a botnet has more aggregate hash rate than the honest
publisher set). This is why PoW is the **fallback path and not the primary**:

```text
WRITE ADMISSION
  bond reference present and verifies (§7.9)  →  full budget, no puzzle
  no bond reference                           →  puzzle at current w, 1/10 budget
  neither                                     →  refused
```

A legitimate node publishing its own descriptors is bonded and pays nothing. A
spammer either bonds (and is slashable, and is rate-limited by bond) or grinds
(and is throttled to a tenth of the budget). Memory-hard puzzles are
`[NEEDS RESEARCH]` — they narrow the botnet/mobile gap but add a dependency and
a verification cost we have not measured.

**What none of this stops:** an adversary with bonded identities issuing
perfectly legitimate-looking reads at exactly the budget, from many circuits, is
indistinguishable from popularity. `[UNSOLVED]`.

---

### 7.9 Interaction with the accounting plane

**Requirement: verifying a bond reference must cost no chain call and no network
round trip on the write path.** The machinery to do this already exists on-chain
and is worth naming precisely, because it is the difference between a design and
a wish.

`EpochManager.Epoch` (`proof-of-facilitation/contracts/EpochManager.sol:14-24`)
already carries, per epoch:

```text
bytes32 receiptRoot
bytes32 rewardRoot
bytes32 nodeStateRoot      ← this is the hook
bytes32 randomness
uint64  challengeDeadline
bool    finalized
```

**The design:**

```text
ONCE PER EPOCH (control plane, off the request path)
  1. The aggregator submits nodeStateRoot: a Merkle root over the sorted map
       nodeId(32) → { bondedAmount:u256, capabilities:u256, activeEpoch:u64 }
     built from NodeRegistry + StakeVault state at the epoch boundary.
  2. Every AXON node fetches the root and verifies the block containing it
     through the EXISTING light client (doc/trust-anchor.md): sync-committee
     signature → beacon header → execution_branch → stateRoot →
     eth_getProof for the EpochManager storage slot.
  3. The node caches   epoch → nodeStateRoot   (32 bytes per epoch).

ON EVERY WRITE (hot path)
  4. The write carries  bond_ref = { epoch, bondedAmount, merkle_path[] }.
  5. The node recomputes the leaf and walks the path against the cached root.
     Cost: ceil(log2(N)) SHA-256 = 14 hashes at N = 10^4.  Sub-microsecond.
     No chain call. No network I/O. No RPC provider in the picture at all.
```

The verification path is a re-use, not new work: `internal/ethproof` already
verifies Merkle-Patricia storage proofs against a state root and was measured
against mainnet block 25,737,778, and the light client already establishes
finality (`doc/trust-anchor.md` §5b, 512/512 sync-committee signature verified).
What is new is one storage slot to prove and one Merkle tree to build.

| Property | Value |
|---|---|
| Hot-path cost per write | ~14 SHA-256 |
| Hot-path chain calls | **zero** |
| Cached state per node | 32 B per epoch root + the epochs retained |
| Bond-state staleness | ≤ 1 epoch, plus `EpochManager.challengeWindow` |
| Proof size in the write | 32 × ceil(log2 N) ≈ 448 B at N = 10⁴ |

**Three residuals, none of which should be buried:**

1. **A slashed node keeps write authority for up to one epoch**, because its
   proof against the previous root still verifies. Mitigation is a bounded,
   signed revocation list gossiped between siblings — `[NEEDS RESEARCH]`, since
   an unbounded revocation channel is itself a DoS vector.
2. **`nodeStateRoot` is aggregator-submitted, not consensus.**
   `EpochManager.submitEpoch` is gated on `isAggregator`
   (`EpochManager.sol:68`) with a challenge window and a dispute manager — a
   fraud-proof shape. **The DHT therefore inherits the accounting plane's trust
   assumption and its challenge window as the bond-freshness bound.** A
   dishonest aggregator can mint bond references for identities that posted
   nothing, for one challenge window. That belongs in the risk register.
3. **`Epoch.randomness` is *not* SRV.** The field exists and is tempting, but it
   is aggregator-submitted — putting the keyspace shuffle and the bond-reference
   mint in one hand. R13's beacon RANDAO mix, verified independently through the
   light client, is used precisely because it is not in the aggregator's gift.

**The zero-payment requirement (R11).** Nothing here requires a payment. A bond
is a *deposit* checked as a Merkle inclusion; no token moves on any DHT
operation and no receipt is generated on the read path. Unbonded writes still
work via the PoW path at a tenth budget (§7.8), so a network with no accounting
plane at all degrades to a PoW-gated DHT rather than a dead one.

---

### Decision table

| Decision | Problem it solves | Derived from Tor / I2P / Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Keep XOR-metric Kademlia | Need a lookup that is either answered or provably failed, without a membership consensus | Neither — Tor uses directory authorities, I2P uses floodfills, Freenet uses small-world greedy routing | The symmetric metric lets any node verify a peer's claimed position unaided; this is what makes KadID checkable without an authority | Chord/Pastry (asymmetric, cannot express disjoint paths); verifiable-routing overlays (need a membership authority); Freenet small-world (best-effort retrieval violates R8) | Kademlia's routing table is publicly enumerable, so the relay set is a public list |
| `KadID = H(NodeIdentity ‖ SRV ‖ prefix)` | Free choice of keyspace position enables targeted eclipse | Tor's HSDir ring rotated by the daily shared random value | We add the network-prefix term, making the position self-checkable against the observed source address, and bind to a bonded identity | Free peer-id position (status quo, `internal/p2p/node.go`); PoW-derived id (a one-off cost, then permanent position); certificate-authority-assigned id (a central authority) | Whole-keyspace reshuffle every 24 h; a node behind a changing address changes position; SRV's last-revealer bias becomes a keyspace-level attack surface |
| d = 3 disjoint lookup paths | One hostile node on the path can suppress a record | S/Kademlia (research), not from the three named systems | Disjointness enforced by a shared claim set at frontier-admission time, and per-path evidence returned to the caller | Single path with retry (retries follow the same poisoned table); more paths (linear cost, sublinear benefit) | ~3× lookup message volume, each RPC crossing a 3-hop circuit — the dominant resolution latency term |
| r = 8 with a D1/D2/D3 diversity ladder | Eight nearest nodes in one rack is not eight replicas | Freenet's honest lesson that emergent availability is not availability (R8); the existing `placement.Plan` distinct-holder rule | New code: /24-/48, ASN, and on-chain operator rungs. `placement.Plan` has *no* network diversity today | Distinct-peer only (status quo); geographic diversity (unverifiable claims); random selection (correlated failure) | ASN and operator lookups are new external data dependencies; a wrong ASN table silently weakens the guarantee |
| Descriptors at 8 independent replica positions | A single-region eclipse takes out a whole descriptor | Tor v3 descriptor replicas | Extended from Tor's 2 replicas to 8 positions, matching r; fetch still costs one lookup | r closest to one key (one region to eclipse) | Publishing costs 8 lookups instead of 1 |
| Blinded descriptor keys | The storing node must not learn what it stores | Tor rend-spec-v3 key blinding | Reimplemented per Constitution §2; extended to `DomainRecord` even though domains are public, so the DHT alone leaks nothing | Plaintext keys (I2P lease-set style); encrypted-only-value (the key still names the service) | Blinding gives nothing against an adversary who knows the identity — which for an on-chain domain is everyone (§7.7) |
| Client lookups over a circuit | A lookup names your interest | Tor (client fetches descriptors over a circuit); R4b | One circuit per isolation context rather than per lookup; node maintenance traffic deliberately stays direct | Direct lookups (leaks interest); circuit per lookup (unaffordable and leaks to more relays) | The terminal relay sees every key you fetch within a 10-minute window |
| Signed, seq-numbered records with a `seq_floor` | Rollback and cache-poisoning | Neither; the existing `Sequence`+`Select` pattern in `gateway/dht.go` and `dcs/dht.go` | Persist the floor for 2× TTL past expiry, transfer floors on join, quorum-read the max | Timestamp-based freshness (clock as a trust input); newest-wins (trivially attacked) | Fresh nodes have no floor and are rollback-vulnerable; floor state is unbounded-ish per key |
| Bond reference verified by Merkle proof against `nodeStateRoot` | Write authorisation without a chain call on the hot path | Neither; PoF `EpochManager`/`StakeVault` already exist | Use the already-present `nodeStateRoot` field; verify the root once per epoch via the existing light client | Chain call per write (latency, RPC dependency, censorship point); trusting a coordinator (what we are removing) | Bond state is up to one epoch + one challenge window stale; the aggregator role is a real centralisation term |
| PoW as the *fallback*, bond as the primary | Spam writes from unbonded parties | Tor's DoS lesson at intro points (R10) | PoW binds target KadID, epoch and record hash; difficulty published in the relay descriptor | PoW as the primary control (botnets beat phones); no unbonded writes at all (kills bootstrapping) | Low-power clients pay disproportionately; adaptive difficulty is itself a signal an attacker can drive |

### Component status

**`[BUILD NOW]`** — domain-separated keyspaces with per-class validators and size
bounds (the namespaced-validator pattern already works); `KadID` derivation,
epoch rotation, prefix binding and admission caps; signed routing entries with
the `verified`/`unverified` distinction; d = 3 disjoint lookup over a shared
claim set; sibling lists (s = 16); blinded descriptor publish/fetch; the
D1/D2/D3 diversity ladder inside `placement.Plan` (new code, existing home); the
repair loop generalised from `store/placement.go`; `seq_floor` as a mechanism;
bond Merkle-proof verification against a cached `nodeStateRoot`.

**`[NEEDS RESEARCH]`** — rollback resistance for fresh and aged-out nodes;
mid-epoch bond revocation without an unbounded gossip channel; removing SRV's
last-revealer bias (VDF or a second beacon); memory-hard write puzzles;
region-level request padding or decoy lookups; verifiable-routing constructions
that need no membership consensus (they would dominate §7.3).

**`[UNSOLVED]`** — adversarial bootstrap, where a node's first view of the
network is hostile (R14's partition problem in DHT form); selective storage
refusal that is honest to probes and hostile to one victim; reads issued at
exactly the budget from many circuits, which is indistinguishable from
popularity; making blinding meaningful for on-chain-registered names, which is
structural rather than a matter of effort.

---

### What this section does NOT establish

- **Eclipse is not prevented.** §7.2 gives probabilities, not impossibilities. At
  f = 0.5 a persistent targeted eclipse costs 256 epochs of eight fresh bonds in
  eight ASNs — and 0.39 % of all keys are eclipsed in every epoch as a side
  effect, belonging to nobody in particular.
- **No parameter here is measured.** k = 20, α = 3, d = 3, r = 8 and s = 16 come
  from the Constitution and S/Kademlia's published reasoning, not from a
  simulation of this network; §7.8's rate limits and PoW figures are engineering
  guesses with stated units, and the `w` table's "one modern core" is nominal.
- **It does not establish that the existing DHT can be hardened in place.** The
  design needs a custom keyspace derivation, a custom routing-table admission
  policy, disjoint-path lookup and sibling lists. Whether those are
  configuration, a fork of `go-libp2p-kad-dht v0.42.1`, or a rewrite against the
  same wire protocol is **not determined here**, and it is the single largest
  unknown in this section's cost estimate.
- **`GO-2024-3218` is not resolved.** `SECURITY.md:138-149` records an
  availability advisory with no upstream fixed version. Disjoint paths and r = 8
  reduce its impact; a large eclipse can still delay availability.
- **Write authorisation is exactly as trustworthy as the PoF aggregator**, for
  at most one challenge window at a time (§7.9). Not a DHT-layer problem, and
  not a DHT-layer fix.
- **Descriptor privacy is much weaker than blinding suggests for the primary use
  case.** A chain-observing adversary computes a registered domain's blinded key
  themselves; blinding protects unlisted services and non-chain-observing
  storing nodes, and nothing else.

> **Objection to Constitution §5 (parameter table):** the Constitution instructs
> sections to "reuse the existing placement engine's diversity levels" for the
> r = 8 /24, /48 and ASN spread. **Those levels do not exist.**
> `internal/placement/plan.go` guarantees distinct *peer ids* only and says so in
> its own package doc; the only network-diversity code in the tree is the gateway
> probe quorum's `DistinctNetworks` counter
> (`internal/gateway/protocol.go:233-258`), over opaque probe-network strings,
> and `compute.faultDomain` (`internal/compute/schedule.go:75-108`), which is
> (GPU vendor+model, CPU vendor, region). §7.5 specifies the ladder as new code
> with an existing home; the roadmap's effort estimate should say build, not
> reuse.

> **Objection to Constitution §5 (content chunk = 256 KiB):** the shipped default
> is `ChunkBytes: 1 << 20` with `DataShards: 6` / `ParityShards: 3`
> (`internal/config/config.go:572-574`). Section 7 does not depend on it, but the
> storage section will, and 256 KiB contradicts the default rather than
> confirming it.
