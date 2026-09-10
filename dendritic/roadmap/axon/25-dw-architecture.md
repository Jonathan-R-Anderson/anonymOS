# Part VII — Distributed Website State and Self-Replicating Hosting

**Turning a website from something a server *hosts* into something the network
*is*.**

---

## 52. The Finding That Shapes Part VII

**Most of this is already built, and the part that isn't is the part that
sounds easy.** The node in `internal/store` already does content-addressed,
erasure-coded, DHT-placed, self-repairing storage with audited recall
(§10) — which is four of the eleven phases the brief lists. What does not exist
is three things, and only one of them is straightforward:

```text
  ALREADY BUILT (§10)              NEW, EASY [BUILD NOW]         NEW, HARD
  ─────────────────────            ─────────────────────        ─────────────
  content addressing               the Website Manifest         mutable state
  erasure coding (6+3)             cache-on-read replication     (§57) [NEEDS
  DHT placement + diversity        publisher-offline serving          RESEARCH]
  recall + repair + audit          version pointers             /[UNSOLVED]
```

The brief's framing — "the network becomes the host" — is correct and is a
genuine architectural shift, but the shift is small in code and large in
consequence. A website today is fetched from an origin and proxied. Under Part
VII a website is a **signed manifest naming a set of content-addressed objects**,
and any node that fetches those objects can verify them against the manifest and
re-serve them. The origin becomes a *publisher*, needed to sign new versions and
nothing else.

Three consequences bind the rest of Part VII:

1. **The publisher/host split is the identity taxonomy, unchanged.** The brief's
   `Publisher ≠ Storage Node ≠ Relay ≠ Client` is exactly Constitution §3:
   `DomainIdentity`/`ServiceIdentity` publish; `NodeIdentity` stores; they are
   different keys and were always meant to be. No new identity class is needed.

2. **Self-replication is safe *because* content is addressed, not despite it.**
   A node serving content it fetched from an untrusted peer is only safe if the
   client verifies the bytes against a hash the publisher signed. That
   verification chain (§26 of the brief) is the §10.2 Bao-tree CID plus the
   §11 signed records. Cache-on-read without it is a content-forgery machine.

3. **This deployment is Phase 1.** The live work of importing the existing site
   into the node's DHT S3 (§10, and the deployment in progress) *is* the brief's
   §23 "origin server compatibility" path. Part VII does not start from zero; it
   starts from a site already being pushed into the store.

---

## 53. Website as a Distributed Object

### 53.1 The object model, grounded in what exists

A website is a DAG of content-addressed objects with one signed root. Every leaf
is already exactly what `internal/store` stores; the new types are the manifest
and the interior nodes.

```text
   WebsiteManifest            signed by DomainIdentity (§11), the ONLY signed part
        │  names ↓
   RootObject (a directory)   content-addressed; maps paths → child CIDs
        ├── index.html   → CID
        ├── styles.css   → CID
        ├── app.js       → CID
        └── images/      → CID of a sub-directory object
                              └── hero.jpg → CID
```

Each CID is a BLAKE3 Bao-tree root (§10.2), so a 4 KB HTML file and a 40 MB
video are the same kind of identifier and both verify chunk-by-chunk. A node
retrieving `hero.jpg` can verify each 256 KiB chunk as it arrives and reject a
lying holder at the first bad chunk (§10.2's whole point), which is what makes
retrieval from untrusted providers sound.

**Directory objects are the new interior type**, and they are deliberately
boring: a canonical, length-prefixed list of `(name, CID, mode)` entries, hashed
the same way as any other object so a directory is itself content-addressed. A
change to any file changes its CID, which changes its parent directory's CID, up
to the root — a Merkle DAG, so two websites sharing an unchanged `images/`
subtree share its storage automatically (structural dedup for free).

### 53.2 The Website Manifest

The manifest is the authoritative entry point and the only object a publisher
signs. Byte layout, in the canonical-encoding discipline of §5.2 (fixed offsets,
length-prefixed variable fields, no maps — a signed record with two encodings is
a forgery vector):

```text
  WebsiteManifest
    version_tag        u8    format version
    domain_identity    32    Ed25519 pubkey that signs this (§11), NOT the owner wallet
    service_identity   32    the ServiceIdentity for the live half, if any (§53.4); 0 if pure-static
    site_version       u64   monotonic; anti-rollback (§57.3, §7.6)
    root_cid           32    BLAKE3 root of the RootObject directory
    created_at         u64   unix seconds
    expires_at         u64   0 = no publisher-declared expiry
    replication        ReplicationPolicy   (§56)
    pinset_cid         32    optional: CID of a list of pinned CIDs (§56.4); 0 if none
    state_ref          32    optional: mutable-state channel id (§57); 0 if none
    prev_manifest_cid  32    the previous version's manifest CID; 0 for v1 (§57.2 history chain)
    signature          64    Ed25519 over all preceding bytes, label "AXON-manifest-v1"
```

The manifest is itself a content-addressed object (its CID is the BLAKE3 root of
its bytes), so "which manifest is current" is a *pointer* question answered by
the naming layer (§53.3), and "is this manifest authentic" is answered by the
signature — two separate checks, and conflating them is the classic naming bug.

### 53.3 Resolution: from name to manifest to bytes

The full path, composing the naming layer (§11–§13), the DHT (§7), and the store
(§10). Every arrow states what is verified:

```text
   alice.lab.axon
        │  §12 registry (verified via light client) → DomainIdentity        [T2]
        ▼
   DomainIdentity
        │  §11 DomainRecord under a blinded DHT key → current manifest CID  [T4]
        ▼
   manifest_cid
        │  §7 DHT: who holds this CID?  → provider set                      [T0→T5]
        ▼
   WebsiteManifest bytes
        │  verify signature under DomainIdentity, verify site_version       [T4]
        │  monotonic against cache (anti-rollback, §57.3)
        ▼
   root_cid → directory → path → leaf CID
        │  §10.2 Bao-tree verification, chunk by chunk                      [T5]
        ▼
   verified bytes, from any provider, trusted or not
```

The trust states are §13's lattice. The point the brief makes in its §26 — "if
the retrieved object does not match, REJECT" — is the `[T5]` step: self-
certifying, and *not weakened by anything above it*, so a hostile storage node
cannot substitute content.

### 53.4 The hybrid site, resolved

§10.10 left a site as "live service for dynamic paths, distributed content for
static paths". Part VII makes the *whole site a manifest* and the live service
one entry within it:

```text
   Manifest
     ├── static paths  → content DAG (this Part), served by any replica
     └── /api, /live   → service_identity → rendezvous (§9), served by the origin
```

The resolution rule (§10.10, made concrete): a path present in the RootObject
directory is served from the DAG by any replica; a path not present falls through
to the ServiceIdentity's live service if `service_identity ≠ 0`, else 404. So a
blog's posts survive the publisher going offline (they are in the DAG) while its
comment-submission endpoint does not (it is live) — and the failure is
per-path and legible, not a whole-site outage.

---

## 54. Publisher Identity and the Chain Binding

Nothing new here, and that is the finding: the brief's publisher model is the
identity taxonomy already fixed in Constitution §3 and the naming design in
§11–§12. Stated as the mapping, so no second identity system is invented:

| Brief's term | AXON identity (§3) | On-chain? | Role |
|---|---|---|---|
| Domain / name | name in a namespace (§11) | ownership only (§12) | human entry point |
| Publisher public key | `DomainIdentity` (Ed25519) | committed (§12) | signs the manifest |
| Website live identity | `ServiceIdentity` (Ed25519) | no | the live half (§9) |
| Storage node | `NodeIdentity` (Ed25519) | bonded (§14) | holds shards |
| Owner (wallet) | `OwnerIdentity` (secp256k1) | yes (§12) | holds the name; never touches the overlay |

The one on-chain addition Part VII wants is a **manifest commitment**, and §12
already has the slot for it: the registry's `resolver` / record fields can carry
the current `manifest_cid` (or, cheaper, the manifest is published off-chain
under the DomainIdentity's blinded DHT key and the chain carries only the
DomainIdentity, per R7's "day-to-day records are off chain"). The brief's own
rule — "do not store the website itself on-chain, only ownership + publisher key
+ manifest commitment" — is R7 restated, and the roadmap keeps the commitment
*off* chain by default and *anchored* on chain only when a publisher pays for the
stronger guarantee (§57.4).

---

## 55. Self-Replicating Cache-on-Read

### 55.1 The mechanism, and why it is the genuinely new work

Today `internal/store` places shards deliberately, by the publisher's dispersal.
Cache-on-read adds a second, *demand-driven* replication path: a node that
retrieves and verifies an object MAY retain it and advertise itself as a provider
for its CID.

```text
   Client → (retrieval, §58) → Provider P → verified bytes
                                   │
                                   ▼
                            requesting node R keeps the verified object,
                            publishes a provider record for its CID to the DHT
                                   │
                            later: Client' asks the DHT for that CID → R answers
```

R is now a replica. It became one by *using* the content, so popular content
accretes replicas exactly where demand is — the brief's "popularity increases
availability", which is Freenet's central idea (§2, C15) kept and made safe by
content addressing.

### 55.2 The three rules that keep it from being an attack

Freenet's opportunistic caching is also its operator-liability and
cache-poisoning problem (R5, C15). Cache-on-read is safe only under all three:

| Rule | Defends against | Grounded in |
|---|---|---|
| A node caches only objects it *verified* against a CID it was seeking | Cache poisoning: a peer cannot push unrequested or altered bytes into R's cache | §10.2 Bao verification |
| A node caches only *encrypted* shards it cannot itself read (opt-in), OR whole objects it fetched for its own use | Operator liability for content the node never chose to hold (R5) | §10.4 encryption-at-rest |
| A provider record is a *claim*, checked by re-verification on fetch, never trusted on assertion | A lying node advertising CIDs it does not hold, or holding corrupt copies | §7.6 signed records + §10.9 audit |

The second rule is the sharp one and it forks the design: a **relay/storage
node** caches encrypted shards it cannot read (opt-in, R5) and is a
content-neutral carrier; a **client** that fetched `alice.lab.axon` for its user
holds the plaintext it already chose to see, and re-serving it is closer to a
browser cache than to hosting. Part VII keeps both and never blurs them — §60
carries the residual, which is that neither fully escapes the abuse problem
(§29's unsolved territory).

### 55.3 Demand-driven, but bounded

Uncontrolled cache-on-read is the multipath commons problem again (R20): the
popular site evicts everything else. The policy, reusing the store's existing
capacity accounting:

```text
   cache-on-read admits an object when:
     popularity(cid) rising          (recent distinct requesters via this node)
     AND local_pressure < high_watermark
     AND object_size < per-object cap
   evicts (§56.3) when:
     replica_count(cid) > TARGET_REPLICAS     (someone else holds it)
     AND local_pressure > low_watermark
     AND demand(cid) falling
   NEVER evicts when:
     replica_count(cid) <= MIN_REPLICAS       (§56, last-copy protection)
     OR cid ∈ pinset                          (§56.4)
```

---

## 56. Replication Factor, Diversity, and Self-Healing

### 56.1 What already exists versus what is added

The store already has replication and repair (§10.6, `internal/p2p/repair.go`,
`rebalance.go`) and a placement engine with distinctness constraints
(`internal/placement`). Part VII adds a *policy object* the publisher signs into
the manifest, and the failure-domain diversity that §10 flagged as not-yet-built.

```text
  ReplicationPolicy (in the manifest, signed)
    min_replicas       u16   below this, self-heal is urgent; never evict (default 3)
    target_replicas    u16   steady-state goal (default 10)
    max_replicas       u16   cap; cache-on-read stops admitting above this (default 100)
    erasure            u8    0 = whole-object replication; 1 = 6+3 shards (§10.1)
    diversity_class     u8    NONE | PREFIX | ASN | OPERATOR (§56.2)
```

Erasure vs whole-object is a real choice the brief asks for (§18): whole-object
replication makes cache-on-read trivial (a replica is a copy) but costs
`target_replicas ×` storage; 6+3 erasure costs `1.5 ×` for the same fault
tolerance but a "replica" is now a shard-holder and serving requires
reconstruction (§58.3). **Default: small objects (< 1 MiB, one chunk) replicate
whole; large objects erasure-code.** The crossover is the §5 chunk size and is a
measured parameter, not a guess (DW8, §61).

### 56.2 Diversity is the number that matters, and it is [NEEDS RESEARCH] here

"Ten replicas on one operator's machines are not ten replicas" — the brief is
right, and §10 already conceded the store has *no* failure-domain awareness
because under I2P no node sees a peer's IP. Part VII inherits that gap and it is
the hardest storage problem: **without observable network location, PREFIX/ASN
diversity is unenforceable.** The partial answers, none complete:

- `OPERATOR` diversity via the bonded `NodeIdentity` (§14): distinct bonds are
  distinct operators *only* to the extent Sybil resistance holds (§15,
  `[UNSOLVED]`), so this bounds cheap self-collusion, not a funded adversary.
- `PREFIX`/`ASN` diversity becomes measurable only once the native transport
  (§6) replaces I2P and nodes observe each other's addresses — which is why the
  whole AXON programme exists. Under the current I2P transport, it is unavailable
  and the roadmap says so rather than pretending.

### 56.3 Self-healing

The existing repair loop (§10.6) already regenerates lost shards from survivors.
Part VII points it at the manifest's `min_replicas`:

```text
   ReplicationMonitor (per CID a node holds or tracks)
     observe replica_count via DHT provider records (§54)
     if replica_count < min_replicas:
         become a provider if capacity allows (self-heal by pull)
         else nudge a diverse healthy provider to replicate (§10.6 rebalance)
     bound the repair rate so a mass-eviction event does not become a storm
```

The honest limit (§10.8): this maintains availability *while enough independent
holders remain*. It cannot resurrect an object whose every holder left and whose
publisher is offline — permanence is not offered, only contracted redundancy.

### 56.4 Publisher pinning

The manifest's `pinset_cid` names objects that must stay at `max_replicas` and
must never be evicted regardless of demand — the brief's §22. Pinning is how a
publisher keeps the manifest and critical assets hot even when cold; it costs the
publisher storage payments (§59), which is what stops "pin everything" being free.

---

## 57. Immutable versus Mutable — the Distributed State Layer

### 57.1 The finding: immutable is done, mutable is the research frontier

Everything in §53–§56 is *immutable* content, which is what content addressing is
for and what the store already does. Mutable state — counters, per-user records,
anything that changes without a full republish — is a different problem and the
brief is right to demand it be treated separately (§13). It is `[NEEDS
RESEARCH]` bleeding into `[UNSOLVED]`, and Part VII scopes it honestly rather
than promising a distributed database.

### 57.2 The two mutable mechanisms that already exist, and their ceiling

AXON already has two mutable primitives, and a great deal of "mutable" website
state needs nothing more:

1. **The manifest pointer itself** (§53.2, §11): a signed record with a
   monotonic `site_version`, republished under the DomainIdentity's blinded DHT
   key. This is *publisher-mutable* state — the site changes when the publisher
   signs a new manifest. Versioning (the brief's §12) is exactly the
   `prev_manifest_cid` chain, giving an auditable history and rollback resistance
   (§7.6, highest counter wins).

2. **Signed mutable references** (§10.3): a named pointer, signed, monotonic,
   pointing at a current CID. Good for low-frequency, single-writer state.

Their shared ceiling: **single-writer.** Both assume one key authorises the
change. That covers a huge fraction of real sites (a blog, a docs site, a
release page — all single-publisher). It does *not* cover multi-writer
application state (a shared counter, a guestbook, collaborative data), and
pretending it does is the trap §13 of the brief warns against.

### 57.3 Multi-writer state: the options, scored

For genuine multi-writer state the roadmap evaluates rather than commits, because
each option buys different things and none is free:

| Mechanism | Consistency | Writers | Cost / when it fits | Verdict |
|---|---|---|---|---|
| Signed append-only log per writer, merged by readers | eventual, causal | many, each owns their log | cheap; readers reconcile; conflicts surface, not resolved | **DW9 start here** |
| CRDTs over the logs | eventual, conflict-free | many | convergence without coordination; only for data with a lawful merge (counters, sets, LWW-registers) | **DW9 for suitable types** |
| Consensus (Raft/BFT) among a state-node quorum | strong | many | coordination cost, a quorum that must stay live, a Sybil surface | rejected as a default; a website is not a bank |
| Blockchain anchoring of state roots | strong, slow, expensive | many | only for state that must be globally, contentiously agreed | §57.4, rare |

The through-line: **signed causal logs first (they compose with everything AXON
already signs), CRDTs where the data type permits lawful merge, consensus never
by default, chain only where disagreement is adversarial and value-bearing.**
This is deliberately the weakest consistency that works, because stronger
consistency on an anonymous, churning, Sybil-exposed overlay is either a
liveness liability or a centralisation.

### 57.4 State authenticity and the chain anchor

Every state transition is signed (the brief's §15), so a replica cannot fabricate
state — the same signed-record discipline as everywhere else. The residual is
*ordering*: signatures prove authorship, not sequence, and two honest replicas
can hold different-but-valid tips. Version vectors / causal metadata bound this
to "concurrent", not "forged". Where even that is insufficient — state whose
order is adversarially contested and financially material — a Merkle root of the
state is anchored on chain (§12) at a cadence the application pays for, buying
total order at settlement latency. This is the brief's §14 "blockchain
anchoring" scoped to where it is actually worth its cost, and nowhere else.

---

## 58. Retrieval: Privacy Routing and Multipath, Composed

### 58.1 Nothing new, by design

Retrieval rides the layers already specified: the request travels a circuit
(§8) or tunnel pool (§9) so the storage node does not learn the client's network
identity (the brief's §16), and large objects are pulled from multiple providers
in parallel and reassembled by the multipath substrate (Part VI, the brief's
§17). Part VII adds no transport; it *uses* L4/L4.5.

### 58.2 Multi-provider retrieval is the multipath substrate with a different source

Part VI aggregates one logical stream across N *paths*. Distributed retrieval
aggregates one object across N *providers*, and the two compose exactly:

```text
   object = chunk 0 ‖ chunk 1 ‖ chunk 2 ‖ chunk 3 ‖ …
              │         │         │         │
           Provider A  Prov. B  Prov. C  Prov. A     ← DHT provider records (§54)
              │         │         │         │
           circuit    circuit   circuit   circuit    ← each over L4 (§8), diverse paths
              └─────────┴────┬────┴─────────┘
                        L4.5 reassembly (§43): global sequence = chunk index
                             │  each chunk verified by its Bao path (§10.2)
                             ▼
                        verified object
```

The scheduler (§44) picks providers by observed throughput exactly as it picks
paths, the reassembly buffer arithmetic (§43.3) is unchanged, and a stalled
provider is dropped and its chunks re-requested elsewhere (§44.2's HoL guard).
The one addition: a chunk that *fails Bao verification* is not a stall but a
**detected lying provider** — re-request elsewhere and drop that provider's
records from consideration (§10.9 audit, in the fast path).

### 58.3 Erasure-coded retrieval

When the object is 6+3 sharded (§56.1), retrieval fetches any 6 of 9 shards from
6 distinct holders and reconstructs — strictly better for multi-provider
retrieval than whole-object, because any 6 will do and slow holders are simply
not among the 6 chosen. The cost is reconstruction CPU and that a single-chunk
small object should *not* be coded (§56.1's crossover). This is the store's
existing recall path (`internal/p2p/recall.go`) over AXON circuits instead of I2P
streams.

---

## 59. Storage Economics

### 59.1 Grounded entirely in the existing accounting plane

The brief's §20 — compensate storage and bandwidth, discourage false claims — is
§14 (payments) and §15 (Sybil) and the deployed Proof of Facilitation
contracts, not a new economy. The mapping:

| Brief's ask | Existing mechanism (§14, PoF) |
|---|---|
| Storage compensation | PoF epoch rewards weighted by verified stored bytes |
| Bandwidth compensation | relay/serve receipts, blind-tokenised (§14 R11, §35) |
| Deposits | `StakeVault` bonds per storage `NodeIdentity` |
| Proof of storage | the existing audit-challenge machinery (§10.9, `recall_lying_holder_test.go`) |
| Proof of retrieval | client-attested delivery, unlinkable (§35.1) |
| Reputation | measured contribution in the PoF epoch record (§14) |

### 59.2 The one honest gap

Proof of *storage over time* — that a node kept an object between audits, not
just that it can produce it when asked — is a real proof-of-retrievability
problem the store's current challenge does not fully close (§10.9 marked it
`[NEEDS RESEARCH]`). Part VII inherits that gap; it does not solve it, and the
economic layer must not pay for storage it cannot verify was actually held.
Until a real PoR scheme exists, storage payment is bounded to what audits can
confirm, and the roadmap says so rather than paying on a claim.

---

## 60. Security Model for Distributed Websites

The brief's §25 threat list, each mapped to a mitigation and an honest residual,
in §18's four-column discipline. Most reduce to the integrity chain (§53.3) and
the existing DHT/Sybil analysis; the new rows are manifest substitution, version
rollback, and cache poisoning.

| Attack | Component | Mitigation | Residual risk |
|---|---|---|---|
| Corrupted / lying replica | retrieval | Bao chunk verification (§10.2); the object is self-certifying | None to integrity; a lying provider wastes a round trip (§58.2) |
| Manifest substitution | resolver | manifest signed by DomainIdentity, which the chain names (§12, §53.3) | Only the DomainIdentity holder can sign; compromise of that key is §18's domain-hijack row |
| Version rollback | resolver | monotonic `site_version`, highest wins, cached floor (§57.3, §7.6) | A client offline across a rotation can be shown a stale-but-valid old version up to its cache TTL (§13.5) |
| Cache poisoning | cache-on-read | cache only verified, sought objects (§55.2 rule 1) | None to integrity; a node can still waste its own cache on low-value objects |
| Sybil-controlled replicas | replication/diversity | OPERATOR diversity via bonded identity (§56.2) | **High and inherited** — real failure-domain diversity is unavailable under I2P (§56.2); a funded Sybil defeats it (§15 `[UNSOLVED]`) |
| Eclipse of a CID's providers | DHT | S/Kademlia disjoint lookups, KadID rotation (§7.2–7.3) | §30's eclipse residual, unchanged; a fully eclipsed client cannot find honest providers |
| Fake storage provider | DHT provider records | records are claims, re-verified on fetch (§55.2 rule 3) | Wastes lookups; mitigated by dropping providers that fail Bao (§58.2) |
| Malicious state transition | state layer (§57) | every transition signed; version vectors bound concurrency (§57.4) | Ordering of concurrent honest writes is not total without the chain anchor (§57.4) |
| Unauthorised website modification | manifest | only DomainIdentity signs; delegation is explicit (§5.2) | Reduces to key management; a leaked DomainIdentity key modifies the site until revoked (§13.5 revocation latency) |
| Publisher-key compromise | naming | on-chain revocation + rotation (§12, §13.5) | The fundamental limit: a client that never re-checks the chain cannot learn of a revocation (§13.5), bounded by mode |
| Malicious content / abuse | storage operators | §29's subscribable local policy; encrypted-shard neutrality (§55.2 rule 2) | **Unsolved** (§29.6): no global takedown, and self-replication *widens* distribution of whatever is popular, including abuse |

Two residuals deserve to be stated plainly rather than left in a table cell.
**Cache-on-read amplifies abuse as readily as it amplifies legitimate content** —
popularity increases availability for anything, and §29's "no global blocklist"
means the network has no mechanism to preferentially starve abusive content of
replicas. And **diversity is the load-bearing assumption Part VII cannot
currently satisfy**: every availability and integrity-under-collusion claim rests
on replicas being independent, which the I2P transport makes unmeasurable — so
the strongest honest claim today is redundancy against *random* failure, not
against a *targeted* adversary.

---

## 60a. What This Part Does NOT Establish

- **That the storage layer is new.** It is not; §53–§56 are a website object
  model over the existing `internal/store`. The new code is the manifest, the
  directory object, cache-on-read policy, and the state layer.
- **That mutable multi-writer state works.** §57 scopes it, scores the options,
  and starts at signed causal logs; it does not deliver a distributed database
  and explicitly declines to promise one.
- **That replicas are diverse.** Under I2P they are not measurably so (§56.2),
  and every collusion-resistance claim is therefore provisional on the native
  transport (§6) existing.
- **That permanence is offered.** Availability is contracted redundancy plus
  demand-driven caching, both of which decay to nothing if every holder leaves
  and the publisher is offline (§56.3).
- **That self-replication is free of abuse cost.** It amplifies distribution
  without regard to content, and §29's takedown problem is unsolved and made
  larger, not smaller, by this Part.
- **That proof-of-storage-over-time exists.** §59.2 — payment is bounded to what
  audits confirm until a real PoR scheme is built.
