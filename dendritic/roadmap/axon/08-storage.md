## 10. Distributed Content Storage

> **AS BUILT (2026-08-16).** The erasure-coded store is **live in production**
> (RS 6+3, 1 MiB chunks) and holds the site's assets. P11's audits are done:
> `internal/axon/storage`, 4 tests.
>
> **T11.5 resolved a real contradiction.** `SECURITY.md` said the local gateway
> was "trusted with plaintext because it is the encryption origin"; `types.go`
> said "the node no longer encrypts objects". The **code was right** — there is no
> AEAD anywhere in `internal/store` — so the coordinator holds plaintext and the
> node never does. `SECURITY.md` now says so. T11.2 re-derived
> `shardFetchTimeout` from 3 min to 90 s against §8.4's budgets, and E11.3 is
> clean.
>
> **T12.2 — THE DOMAINS NOW REACH THE PLANNER (2026-08-17).**
> `internal/p2p/domains.go`, 4 tests. The planner has refused to co-locate two
> shards of a chunk in one failure domain since P12b, and **nothing supplied it
> any domains**, so what it actually delivered was distinct-PEER — precisely
> where §1.4 found the storage layer. Both candidate branches now populate
> `Candidate.Domains`.
>
> **The address comes from the live connection, never from the DHT record.**
> `place.Record.Destination` is a `<b32>.i2p` — a public key, deliberately
> unrelated to where the machine is, which is §1.4's finding in one field. A
> libp2p connection over TCP or QUIC exposes the peer's IP **as observed by this
> node rather than asserted by the peer**, which is the distinction §7.3 rule (c)
> turns on and the only kind of address a diversity claim may rest on.
>
> **Loopback and unspecified addresses yield NO domain, deliberately.** On a
> single-host fleet every peer is 127.0.0.1; annotating those puts every
> candidate in one /24 and the planner then refuses to place more than one shard
> of a chunk. A diversity mechanism would become an outage on exactly the setup
> people develop against, and it would present as a storage bug rather than an
> address bug.
>
> **So the guarantee is now conditional and the condition is visible.** Peers
> reached over an IP transport get real failure domains; peers reached over I2P
> get none and fall back to distinct-peer, with `placement.DomainsUnavailable`
> counting them. Given the network still runs on I2P (§22), **most candidates
> today will have no domains** — the mechanism is live, its inputs largely are
> not, and that is what the counter is for.
>
> **Deliberately NOT claimed:** **the transport swap has not happened.** The store
> still runs over the existing transport, so T11.1's "over AXON" is unmet and
> T11.3, T11.4 and E11.2/M4 are not claimed. **T11.2's figure is derived from
> SPECIFIED budgets, not measured** — no AXON circuit has been built on a real
> network, and the source says `NOT A MEASUREMENT` in as many words.

**The finding that shapes this section: the Freenet-role layer is already built,
already deployed, and is measurably stronger than Freenet's design. It does not
need replacing. It needs four things it does not have — an authenticated
content identity, an authenticated name→content binding, an encryption story
that does not end at a central master key, and a transport that is not I2P.**

Everything below is read from the source. Where a number could not be read it
says so.

---

### 10.1 What already exists

Read from `github.com/syndichan/maniwani/storage-client` at the paths given.

| File | What it provides |
|---|---|
| `internal/store/store.go` | Content-addressed shard store on bbolt + a shard tree; Reed–Solomon split/encode on write; `gatherChunk` parallel read with early quorum cancel; capacity accounting; `IsContentID` path-traversal gate |
| `internal/store/types.go` | `Manifest`, `ChunkManifest`, `ShardRef`, `RemoteShard`, `StoredItem`; `FormatVersion = 1` |
| `internal/store/placement.go` | The placement ledger: `ObjectPlacement`, `ShardPlacement`, confirmed-holder lists, silence counters, `DurableRemoteHolders`, `WeakestChunk`, `ChunkIsDurable`, `ChunkIsSpread`, `FullyDispersed` |
| `internal/store/recall.go` | Recall tombstones, five holder states, `recallRefusalTTL = 6h`, revocation-nonce replay cache (`maxRevocationNonces = 4096`) |
| `internal/store/rebalance.go` | Levelling queue, `ChunkHasDurabilityMargin`, `SurvivesLosingHolder`, moved-away memory |
| `internal/store/drain.go` | Drain queue with its own clock, `ShardsRecordedOn`, `HeldForOthers` |
| `internal/placement/plan.go` | Pure planner: no two shards of one chunk on one peer; `SurvivingIndexes` exact subset search with a pessimistic fallback |
| `internal/placement/level.go` | Pure levelling arithmetic: equal **bytes** not equal percentage, `LevelDeadband = 0.10`, `MinLevelMove = 64 MiB` |
| `internal/p2p/disperse.go` | Dispersal pass, candidate discovery, refusal classification (`refusalsBeforeSkipping = 3`, `refusalCooldown = 30m`), `PeerHasShard` |
| `internal/p2p/repair.go` | Audit + rebuild: `repairInterval = 30m`, `repairCooldown = 6h`, `repairShardsPerPass = 48`, `repairSilentAuditsBeforeDrop = 3`, isolation test |
| `internal/p2p/recall.go` | Authenticated delete verb; revocation token bound to **both** recipient and requester; deletion claims verified by a follow-up `have` |
| `internal/p2p/objmanifest.go` | Manifest DHT record, namespace `syndichan-object-manifest`, 512 KiB cap, key = `sha256(bucket‖0x00‖key)` |
| `internal/p2p/storage_capacity.go` | Capacity advertisement at a rendezvous CID; `place.RecordTTL = 10m` |
| `internal/p2p/node.go` | `/syndichan/storage/1.0.0` with verbs `have`/`get`/`store`/`delete`/`pof-challenge`; `maxNetworkShard = 32 MiB`; `FetchShard` hint-ordered lookup; `advertiseInterval = 10m` |
| `internal/p2p/recall_lying_holder_test.go` | The adversarial test that pins "a holder claiming deletion while keeping the bytes is not recorded deleted" |
| `internal/gateway/contentproxy.go`, `snapshot.go`, `originhealth.go` | A working hybrid-site prototype: signed route manifest, offloadable routes, emergency fallback state machine |
| `backend/services/content_keys.py` | Coordinator-rooted encryption: BIP32-hardened secp256k1 child per object, AES-256-GCM, ECIES-wrapped key |
| `go.mod` | `klauspost/reedsolomon v1.14.1`, `ipfs/go-cid v0.6.2`, `multiformats/go-multihash v0.2.3`, `go.etcd.io/bbolt v1.4.3`, and **`lukechampine.com/blake3 v1.4.1` already present as an indirect dependency** |

**The real parameters, read from `internal/config/config.go`:**

```text
DataShards    6          default (config.go:572)
ParityShards  3          default (config.go:573)
ChunkBytes    1 << 20    1 MiB default (config.go:574)
validation    DataShards >= 2, ParityShards >= 1, k+m <= 64   (config.go:817)
              64 KiB <= ChunkBytes <= 16 MiB                  (config.go:820)
shard size    ceil(1048576/6) = 174,763 B   (reedsolomon.Split, 2 B zero pad)
stored/chunk  9 x 174,763 = 1,572,867 B = 1.500x
content addr  shard id = lowercase hex sha256(shard bytes), 64 chars
object id     sha256(canonical manifest JSON with ObjectID blanked)
durable at    DurableRemoteHolders(6,3) = 7 distinct confirmed holders
full spread   9 shards on 9 distinct holders, survives 3 simultaneous losses
```

> The Constitution (§5) lists a 256 KiB chunk with an instruction to confirm it.
> **Confirmed different: the deployed value is 1 MiB.** This section uses 1 MiB
> and flags it. The unit that actually crosses the wire is the *shard*, at
> 174,763 B, which is within 1.5x of the Constitution's figure; the discrepancy
> is chunk-versus-shard, not a disagreement about transfer sizing.

#### What must be replaced

| Replace | Why |
|---|---|
| I2P SAM transport under every fetch, push, probe and recall | The dependency the project exists to remove. Every timeout in this layer (`shardFetchTimeout = 3m`, `manifestFetchTimeout = 3m`, `challengeTimeout = 90s`, `i2pDialTimeout = 2m`) is sized for a cold I2P dial |
| Coordinator-signed leases and revocations minted over HTTPS to `syndichan.org` | A single authority that can authorise a write and a delete anywhere on the network |
| The coordinator content master (`content_keys.py`) | One BIP32 master that can decrypt every object ever stored. Deliberate for their moderation model; disqualifying for AXON |
| Unsigned, name-keyed manifest DHT records | Anyone may publish a manifest under any `(bucket, key)`; the validator checks only key derivation. First-writer-wins with no authority |
| SHA-256 as the content address | Replaced by BLAKE3 for chunk-level verification (§10.2). SHA-256 stays as the protocol hash per Constitution §2 |
| S3 vocabulary (`bucket`, `key`, ETag) in the content identity | `Manifest` carries `Bucket`, `Key`, `ContentType`, `CreatedAt`, so identical bytes under two names get two object ids and object-level dedup is defeated |

#### What supersedes what in Freenet

| Freenet concept | AXON equivalent that already exists | Why it is stronger |
|---|---|---|
| CHK — content hash key, convergently encrypted | `sha256(shard)` content address + coordinator AES-GCM ciphertext | Same self-certification; encryption mode is a *choice* rather than always-convergent (§10.4) |
| SSK / USK — signed, versioned mutable key | **Nothing.** `objectManifestKey` is name-keyed and unsigned | This is a genuine gap. §10.3 specifies `MutableRef` |
| KSK — keyword signed key | Refused | Squattable by construction; naming belongs in §11 |
| Full block replication along the insert path | Reed–Solomon 6+3 with `placement.Plan` | 1.5x storage for ~3-copy durability at high node availability (arithmetic below) |
| Store/cache merged, LRU by key distance | `bucketObjects` + `bucketRemote` + placement ledger | Placement is recorded, so repair is possible at all. Freenet cannot repair what it never recorded |
| Best-effort retrieval, HTL, data decays if unrequested | `AuditCandidates` + `repairObject` + silence counting | R8: availability is contracted and measured, not emergent |
| Nothing proves a node kept a block | `have` probe, follow-up `have` after a delete claim, `pof-challenge` transport | Weak (§10.9), but non-zero, and adversarially tested |
| Opportunistic caching of everything on the path | Fetched shards written back in `gatherChunk` | Same idea; needs the pool split and eviction it does not have (§10.7) |

#### Erasure coding versus full replication, with the arithmetic

Storage overhead is exact: `(k+m)/k = 9/6 = 1.500x`. Availability is not, so it
is computed rather than asserted. Let `p` be the probability that an
independently-chosen holder is reachable at fetch time. A 6+3 chunk is
retrievable iff at least 6 of its 9 holders answer:

```text
P_ec(p) = sum_{i=6..9} C(9,i) p^i (1-p)^(9-i)
P_rep(p, r) = 1 - (1-p)^r
```

| p | EC 6+3 @ 1.500x | 2 copies @ 2x | 3 copies @ 3x | 4 copies @ 4x |
|---|---|---|---|---|
| 0.50 | 0.2539 | 0.7500 | 0.8750 | 0.9375 |
| 0.85 | 0.9661 | 0.9775 | 0.9966 | 0.99949 |
| 0.90 | **0.99167** | 0.9900 | 0.9990 | 0.99990 |
| 0.95 | **0.99936** | 0.99750 | 0.999875 | 0.9999938 |
| 0.99 | **0.9999988** | 0.9999 | 0.999999 | 0.99999999 |

Three honest readings. **At p = 0.99 the code buys 3-copy durability for half
the bytes** — failure 1.2e-6 at 1.500x against 1.0e-6 at 3.000x. **At p = 0.90
it is worth about two copies** at three quarters of their cost. **Below
p ≈ 0.88 it is WORSE than two plain copies**, and by p = 0.5 catastrophically so
(0.25 against 0.75): a 6+3 code needs 6 of 9, and churny volunteers do not
supply that.

The consequence is not "use replication". It is that **the repair loop is not a
nicety, it is what makes the arithmetic true.** Freenet has no repair and
therefore lives permanently in the left-hand column. The existing repair pass,
the 7-distinct-holder threshold and the audit cadence are what hold `p` high
enough for 1.5x to beat 3x. If measured `p` turns out below 0.9 the correct
response is to raise `m` (6+4, 6+6 — still 1.67x and 2.0x, cheaper than three
copies), which `config.go` already permits at `k+m <= 64`: a configuration
change, not a redesign. **Measuring `p` is unfinished work.**

---

### 10.2 Content addressing

**Decision: `ContentIdentity` is a CIDv1, codec `raw` (0x55), multihash BLAKE3
(0x1E), 32-byte digest. 36 bytes binary. [BUILD NOW]**

Exact byte layout, and it is deliberately the same shape as the CID the code
already builds in `cidForShard` and `storageRendezvousCID`:

```text
byte  0   0x01        CID version 1 (varint)
byte  1   0x55        multicodec "raw" (varint)
byte  2   0x1E        multihash code, BLAKE3 (varint)
byte  3   0x20        digest length, 32 (varint)
bytes 4..35           BLAKE3-256 root, 32 bytes
                      ------------------------------
                      36 bytes binary; base32 multibase 'b' for text
```

Today's shard CID is byte-identical in shape with `0x12 0x20` (sha2-256) in
bytes 2–3. **The change is two bytes and a hash call.** `go-multihash v0.2.3`
already defines `BLAKE3 = 0x1E` and ships `register/blake3`, and
`lukechampine.com/blake3 v1.4.1` is already in the module graph as an indirect
dependency (`go.mod`, indirect block). Adopting BLAKE3 costs one direct
`require` and one blank import; it is not a new dependency on the security path.

#### Why a tree hash, precisely

BLAKE3 is a Merkle tree over 1024-byte chunks. Bao-style verified streaming
exposes that tree: a receiver holding only the 32-byte root can verify any byte
range by being sent the range plus the sibling chaining values on its path.

```text
BLAKE3 chunk        1024 B   (fixed by the hash construction, not by us)
parent node           64 B   (two 32-byte chaining values)
full outboard tree    64 x (chunks - 1) + 8 B length header
  for a 1 MiB chunk:  64 x 1023 + 8 = 65,480 B  (6.24 % of the data)
slice proof for one 1024 B leaf: 64 x ceil(log2(chunks)) B
  for a 1 MiB chunk:  64 x 10 = 640 B
  for a 174,763 B shard (171 leaves): 64 x 8 = 512 B
```

So verifying one kilobyte of a shard costs 1024 B of data and 512 B of proof,
against a root the verifier already holds. That is the property the audit in
§10.9 is built on and it arrives free with the hash choice.

#### What this changes about retrieval, stated without overclaiming

The existing code is **not** naive here, and the improvement must be described
honestly:

| Integrity property | Today | With BLAKE3/Bao |
|---|---|---|
| A corrupt shard is rejected | Yes — `gatherChunk` and `fetchFromPeer` both check `sha256(bytes) == shardID` | Yes, same, BLAKE3 |
| Detection granularity within a shard | 174,763 B — you must receive the whole shard to know | 1024 B — a lying holder is caught on the first bad kilobyte |
| A corrupt *reassembly* is rejected | Only at end of object, against `PlainSHA256` | Per chunk, against the chunk's subtree root |
| A **forged manifest** is rejected | **No.** `objectManifestValidator` checks version, non-empty chunks and key derivation. The comment concedes a forged manifest "can at worst cause a fetch to fail" — after the full transfer | Yes, before the first shard is requested: the manifest *is* the object CID's preimage |

The last row is the one that matters. Today an adversary publishing a well-formed
manifest under someone's `(bucket, key)` costs every reader a complete failed
transfer; under AXON the reader resolves a CID, fetches the manifest, hashes it,
and discards a forgery in one round trip.

**Compatibility with existing `go-cid` usage.** Shard and rendezvous CIDs keep
the `NewCidV1(cid.Raw, mh)` construction; only the multihash code changes.
Existing sha2-256 shard ids remain valid CIDs and stay resolvable — the DHT
provider key is derived from the CID bytes, so old and new coexist in one
keyspace without a flag day. Migration rule: **new writes are BLAKE3; existing
shards are never rehashed**, since rehashing would change every id in the
placement ledger, every recall tombstone and every provider record at once.

---

### 10.3 The object model

Four types. Chunk and shard carry **no header at all** — that is deliberate and
preserves the existing property that a shard's bytes are exactly what its
content address covers, so two objects sharing a shard share it on disk and on
the wire.

```text
   Object (logical)
     └── ciphertext stream, BLAKE3 root = content_root
           └── Chunk[i]  : 1 MiB slice of the ciphertext, subtree root committed
                 └── Shard[i][j] : RS piece, 174,763 B, addressed by BLAKE3(bytes)

   ObjectManifest : canonical binary, addressed by BLAKE3(manifest bytes) = ObjectCID
   MutableRef     : signed, versioned pointer to an ObjectCID
```

#### ObjectManifest [BUILD NOW]

Canonical, fixed-width, big-endian. No names, no timestamps, no content type —
**those are metadata about a naming, not about content**, and including them (as
`store.Manifest` does today) is what defeats object-level dedup.

```text
off  len  field
  0    4  magic "AXOM"
  4    1  version = 1
  5    1  hash_alg      0x1E BLAKE3-256
  6    1  enc_mode      0 = none | 1 = random-key | 2 = convergent | 3 = keyed-convergent
  7    1  flags         bit0 = manifest is a segment index (see below)
  8    2  k             data shards      (uint16)
 10    2  m             parity shards    (uint16)
 12    4  chunk_bytes                    (uint32)
 16    8  cipher_len    total ciphertext bytes            (uint64)
 24    8  plain_len     plaintext bytes before encryption (uint64)
 32   32  content_root  BLAKE3 root over the ciphertext stream
 64    4  chunk_count n                                    (uint32)
 68  ...  n x ChunkRecord

ChunkRecord (40 + 32*(k+m) bytes)
off  len  field
  0    4  cipher_len_of_chunk            (uint32)
  4    4  shard_size                     (uint32)
  8   32  chunk_root   BLAKE3 subtree root of this chunk's ciphertext
 40  ...  (k+m) x 32-byte shard digests, in shard-index order
```

At k+m = 9 a ChunkRecord is 40 + 288 = **328 bytes**. Size arithmetic, and the
finding it produces:

```text
1 MiB object   1 chunk     396 B manifest
1 GiB object   1024 chunks 336 KB manifest
existing JSON manifest, same object: ~960 B/chunk -> ~983 KB
existing DHT record cap (objmanifest.go): 512 KiB
  => today a single object is capped near 550 MiB by the manifest record alone
  => binary encoding raises that to roughly 1.5 GiB
```

That is still a ceiling, so: `flags` bit0 marks a **segment index** — a manifest
whose ChunkRecords are replaced by 32-byte child-manifest CIDs, giving a
two-level tree and removing the ceiling. [BUILD NOW] for the leaf form,
[NEEDS RESEARCH] for the fan-out and the retrieval scheduler over it.

#### MutableRef [BUILD NOW]

The type Freenet has (USK) and this codebase does not. It is what a domain
points at when the content changes.

```text
off  len  field
  0    4  magic "AXMR"
  4    1  version = 1
  5    1  flags     bit0 = final (no successor will ever be published)
  6    2  label_len L                        (uint16)
  8   32  signer    Ed25519 public key (DomainIdentity or a delegated key)
 40    8  seq       monotonic, uint64, strictly increasing per (signer,label)
 48    8  valid_from   unix seconds          (uint64)
 56    8  valid_until  unix seconds          (uint64)
 64   36  target    CIDv1 of the ObjectManifest
100    L  label     UTF-8, the path or name under the domain
100+L 64  sig       Ed25519 over "axon-mutable-ref-v1" || bytes[0 .. 100+L)
```

Rules, all of which must hold or the record is discarded:

| Rule | Value |
|---|---|
| DHT key | blinded per R4(c): `H("axon-mref" ‖ blind(signer, period) ‖ label ‖ period)`. The storing node learns neither signer nor label |
| Selection among candidates | highest `seq` wins; tie → later `valid_from`; tie → lexicographically smaller `sig`. Deterministic, so two clients converge |
| Rollback resistance | a client persists the highest `seq` it has ever accepted for a `(signer, label)` and **refuses any lower one, permanently**. A hostile DHT node can withhold, never rewind |
| Freshness bound | `valid_until - now` is reported to the caller. Default lifetime 7 days, republish hourly. A resolver serving an expired ref must fail, not serve |
| Replay across labels | `label` is inside the signature, so a ref for `/a` is inert at `/b` |
| Relationship to §11 | A `DomainRecord` of type `CONTENT` carries either a bare `ObjectCID` (immutable) or a `MutableRef` signer+label pair. **A domain may point at a mutable head.** The chain of authority is OwnerIdentity → DomainIdentity (on-chain, §11) → MutableRef signer (signed delegation) → ObjectCID → content_root |

The one thing rollback resistance does **not** give: a client that has never
seen a `(signer, label)` before has no floor and will accept whatever the DHT
serves it, including an old-but-validly-signed ref. Trust-on-first-use, and it
is a real limit, named here rather than hidden. A client can narrow it by
requiring `d = 3` disjoint DHT lookups (Constitution §5) to agree, which raises
the cost of the attack to controlling all three paths.

---

### 10.4 Encryption at rest, and the operator-risk ruling

**What a storage node can learn today, read from the code:**

| The holder learns | From |
|---|---|
| The shard's ciphertext bytes | It holds them |
| The shard's content address | `RemoteShard.ID` |
| **The object id the shard belongs to** | `RemoteShard.ObjectID`, sent in the `store` frame header |
| The shard's size and arrival time | `RemoteShard.Size`, `CreatedAt` |
| Which shards are asked for, how often, by whom | The `get` verb, over a clear libp2p stream today |
| Nothing about the plaintext | Content arrives already AES-256-GCM encrypted |

The third row is a leak worth closing. Carrying `ObjectID` lets a holder group
shards of one object, count how many it has, and correlate with any other holder
it colludes with. It exists because recall is scoped per object
(`RecallRefused(objectID, shardID)`).

**Change [BUILD NOW]:** the wire carries an opaque per-holder tag instead:

```text
obj_tag = BLAKE3("axon-objtag-v1" || ObjectCID || holder_NodeIdentity)[0..16]
```

The owner recomputes it for any holder; the holder can scope its recall refusal
by it; **two holders cannot link their tags to each other or back to the CID.**
Cost: the owner must know the holder identity at push time, which it does.

**What the holder still learns, and we do not fix:** shard size, request timing,
and its own request-rate statistics. Popularity is visible to whoever holds the
bytes. Traffic-analysis defence for BULK is the transport's problem (R2), not
this layer's.

#### Convergent versus randomly-keyed

| | Convergent | Randomly keyed |
|---|---|---|
| Key derivation | `K = HKDF-SHA256(BLAKE3(plaintext), "axon-convergent-v1")` | `K = 32 random bytes` |
| Cross-publisher dedup | Yes — identical plaintext gives identical CID | No |
| Read capability | The CID alone (anyone who can name it can read it) | CID + K, distributed separately |
| Confirmation-of-file attack | **Yes** | No |

**The confirmation-of-file attack, stated exactly.** An adversary who has a
candidate plaintext — a leaked document, a photograph, a specific build of a
binary — derives `K`, encrypts, computes the ObjectCID, and asks the DHT for
providers. A hit proves the file is stored on the network and names the holders.
No key material is needed and no decryption occurs. Against low-entropy content
(a form with three unknown fields) the attacker can enumerate the unknowns and
confirm which variant exists — a *learn-the-remaining-information* attack. Both
are inherent to convergence and cannot be patched away.

**Ruling, consistent with Constitution R5:**

```text
DEFAULT           enc_mode = 1, randomly keyed. Every publish API path that
                  does not explicitly ask for convergence gets this.
OPT-IN, PER OBJECT enc_mode = 2, convergent. Never a node-wide setting, never
                  a default, and refused outright for any object the publisher
                  marks private.
RECOMMENDED       enc_mode = 3, keyed-convergent:
                    K = HKDF-SHA256(BLAKE3(plaintext) || S_ns, "axon-conv-v1")
                  with S_ns a per-publisher convergence secret. Dedups within
                  one publisher's corpus, which is where nearly all real
                  duplication lives, and makes the confirmation attack require
                  S_ns. This is the construction Tahoe-LAFS calls an added
                  convergence secret.
NEVER             enc_mode = 0 for anything a publisher did not explicitly mark
                  public. A holder must be able to say truthfully that it cannot
                  read what it holds.
```

**Shard-level dedup is unaffected by any of this** and stays as it is today:
shards are content-addressed, `writeShard` early-returns on a hit, and two
objects sharing a shard share it on disk. The existing code already documents
the subtlety that a chunk of uniform bytes produces several indexes with the
same shard id.

**What is removed:** the coordinator master. Under AXON no key exists from which
every object's key can be derived, and the consequence is that **a lost
publisher key is lost content** with no recovery path. That is the price of
removing the escrow, and it is the correct price.

---

### 10.5 Retrieval routing, and the honest latency

Retrieval has two modes, and choosing between them is the main routing decision
in this section.

```text
MODE A  PUBLIC HOLDER  (default)
  client --[3-hop circuit: guard, middle, terminal]--> holder (public relay)
  4 links. Client anonymous; holder's address public. Holder learns a shard was
  requested, never by whom.

MODE B  HIDDEN HOLDER  (opt-in, for holders needing location privacy)
  client --[3 hops]--> RP <--[3 hops]-- holder-as-service
  7 forwarding elements + descriptor lookup + intro round trip (R10).
```

**Ruling: Mode A is the default.** R4(a) already establishes that DHT membership
is public and that relays are public; a storage holder is a relay with a disk.
Making every holder a hidden service would add a descriptor lookup and a
two-stage rendezvous *per holder*, and a 6+3 chunk needs six of them. Mode B
exists for the operator who needs it and is priced accordingly.

**Traffic class is BULK (R2), always.** The API does not offer INTERACTIVE for
shard transfer. Storage reads are exactly the batched, padded, latency-tolerant
traffic the class was defined for, and a storage read is also the easiest thing
on the network to correlate end-to-end if it is not batched — the sizes are
fixed and known (174,763 B), which is a fingerprint.

#### The fetch, step by step

```text
1. resolve name -> DomainRecord -> ObjectCID or MutableRef      (§11)
2. DHT GET manifest by ObjectCID          over a circuit, d=3 disjoint paths
3. verify BLAKE3(manifest) == ObjectCID   -- forged manifests die here
4. for each chunk: DHT FINDPROVIDERS on k+m shard CIDs, or use the
   publisher-supplied holder hints from the placement ledger
5. open BULK streams to k+2 holders in parallel (2 hedges), one circuit each
6. verify each shard against its manifest digest as it arrives
7. RS-reconstruct at k, cancel the stragglers  (this logic exists: gatherChunk)
8. verify the chunk against chunk_root by Bao path
```

Steps 5 and 7 already exist: `gatherChunk` fetches concurrently with a shared
context cancelled the instant `dataShards` distinct indexes are in hand, because
"fetching 9 when 6 decode is 50% wasted network on every read."

#### Latency arithmetic — assumptions, not measurements

**None of the following is measured.** Every input is a declared assumption and
the output is an estimate.

```text
ASSUMED   L    = 50 ms one-way per relay link
          RTT  = 4 links x 2 x 50 ms = 400 ms for a 3-hop circuit to a holder
          q    = 100 ms BULK batching quantum, each direction
          B    = 1 Mbit/s usable goodput per circuit
          DHT  = 4 sequential lookup rounds (k=20, alpha=3)
          cells: 1024 B on the link, payload 1024 - 16 - 16*3 = 960 B
```

| Step | Formula | Estimate |
|---|---|---|
| Circuit from the pool | pooled | 0 ms (cold build ≈ 1.2 s) |
| Manifest lookup | 4 x (RTT + 2q) | 2.4 s |
| Manifest fetch | RTT + 2q + small | 0.7 s |
| Shard request → first byte | RTT + 2q | 0.6 s |
| One shard, 174,763 B = 183 cells | 174763 x 8 / B | 1.4 s |
| One 1 MiB chunk, 6 circuits in parallel | 0.6 + 1.4 | 2.0 s |
| **1 MiB object, cold** | 2.4 + 0.7 + 2.0 | **≈ 5.1 s** |
| **10 MiB object, 6 circuits pipelined** | 3.1 + 10 MiB / (6 x 1 Mbit/s) | **≈ 17 s** |
| Steady-state throughput | 6 x 1 Mbit/s | **≈ 750 KB/s** |

**This is slow and it should be said plainly: a 10 MiB object takes about 17
seconds and first byte takes about 3 seconds.** Fetching erasure-coded shards
over anonymous circuits pays the circuit latency once per holder and the DHT
latency once per object, and neither is avoidable at this layer.

Two mitigations that are real and one that is not. **Real:** hint-ordered
fetch — `FetchShard` already tries recorded holders first and its comment
explains why (every stale fallback entry was a cold dial charged against the
caller's budget); carrying holder hints in the manifest removes step 4 for the
common case. **Real:** client-side manifest and ref caching, which skips 2.4 s
on a repeat visit. **Not real:** shortening circuits — 2-hop is permitted by
Constitution §5 only for explicitly non-anonymous contexts and must never
become the storage default to make a benchmark look better.

For calibration against the status quo: the existing code budgets
`shardFetchTimeout = 3 minutes` per shard and its own comment computes that a
40 MB object over I2P is "39 chunks x 9 = 351 acquisitions, and at an optimistic
2s per I2P fetch that is 11.7 minutes". **AXON is not slower than what is
deployed. It is roughly an order of magnitude faster, and still slow.**

---

### 10.6 Replication, repair, rebalancing, drain

All four passes exist. The table gives what they are today and what the
transport change forces.

| Pass | Today | Constants | Change under AXON circuits |
|---|---|---|---|
| Dispersal | `DisperseObject` → `placeShards` → `placeOne`; ack-then-confirm; refusal classification | `disperseConcurrency = 4`, `candidateLimit = 32`, `candidateCacheTTL = 2m` | Concurrency 4 exists to avoid burying the coordinator's lease service. With no coordinator, the bound becomes circuit-pool size. Raise to the number of BULK circuits available, typically 6–8 |
| Repair | `RepairStored` → `auditHolders` → `restoreChunkBytes` → `placeShards` | `repairInterval = 30m`, `repairCooldown = 6h`, `repairObjectsPerPass = 8`, `repairShardsPerPass = 48`, `repairSilentAuditsBeforeDrop = 3`, `repairMinHolderChecks = 1` | The isolation test (`silent > answered` → record nothing) must become **circuit-aware**: three silences over three dead circuits is a circuit fault, not three dead holders. Add "at least two distinct guards were used" to the isolation predicate |
| Levelling | `rebalanceChunk` → `moveShard`: copy, verify by `have`, then recall | `rebalanceInterval = 1h`, `rebalanceCooldown = 24h`, `rebalanceShardsPerPass = 8`, `moveWindow = 30m`, `movesPerWindow = 64`, `LevelDeadband = 0.10`, `MinLevelMove = 64 MiB` | Unchanged in logic. The recall half needs a new authority (below) |
| Drain | `DrainCandidates` with its own clock; includes under-replicated rows so they are *reported* even when unmovable | `drainInterval = 10m`, `drainCooldown = 15m`, `drainObjectsPerPass = 16`, `drainShardsPerPass = 16` | Unchanged. The draining flag rides the capacity record, which becomes a signed DHT record instead of an unsigned one |

**The one structural change: authority for the delete verb.** Today a delete is
authorised by a coordinator-signed `Revocation` bound to `(object, shard,
recipient, requester, nonce, expiry)`, fetched over HTTPS from
`syndichan.org/api/v1/storage/revocations`. The construction is good and the
binding of *both* ends is the part worth keeping. What must change is who signs:

```text
today   coordinator Ed25519 key, pinned via the bootstrap document
AXON    the object's own publisher key. The holder learns that Ed25519 public
        key at store time, inside the placement offer, and pins it against
        obj_tag. Revocations are signed by it under the domain prefix
        "axon-storage-revocation-v1", over the same field set; recipient and
        requester bindings and the nonce replay cache (maxRevocationNonces =
        4096) are retained verbatim.
```

This is strictly less trust than today: a revocation authorises deletion of one
shard of one object on one holder by one requester, and no key can delete
anything else. The write lease disappears entirely — a holder under AXON accepts
a shard because it chose to, subject to its own capacity and policy, not because
a central party said so. **That removes the last hard dependency on
`syndichan.org` from the storage data path.**

Losing the lease also loses its Sybil brake on who may fill a holder's disk.
Replacement: per-source admission by bonded stake, reusing Proof-of-Facilitation
as the accounting plane (Constitution §0, R11), plus the holder's existing local
refusal path. [NEEDS RESEARCH] — the same problem `internal/dcs/admission.go`
solves for compute, and the two should share a design rather than diverge.

---

### 10.7 Caching

**Keep from Freenet:** popularity-driven caching on the retrieval path is
correct and is why Freenet's popular content is fast. **Drop from Freenet:**
that a node caches everything it forwards, in plaintext, into the same pool as
its contracted data, evicted by one LRU.

Three rules, and the reasoning for each.

| Rule | Reasoning |
|---|---|
| **Opt-in per node.** Default off | R5. Caching is an operator's risk decision about what sits on their disk, and it is not the network's to make for them |
| **Encrypted shards only, never plaintext, never a whole object** | R5 again. A cache entry is an RS shard of ciphertext: 174,763 B that decode to nothing without k−1 siblings and a key the holder does not have |
| **Two disjoint pools with separate budgets** | The bug this fixes exists today and the code says so |

The existing defect, quoted from `gatherChunk`:

> "Keep a copy so the next read of this object is local. This is a cache, and it
> is why the origin refills itself on read: there is no eviction anywhere in
> this package, so a node that reads foreign objects grows forever. Left as-is
> deliberately — adding eviction here without a reference model would delete
> shards this node is the only holder of."

That comment identifies the exact reason the fix needs a pool split rather than
an eviction policy. [BUILD NOW]:

```text
CONTRACT pool   shards this node accepted via a placement offer.
                Recorded in bucketRemote. NEVER evicted by cache pressure.
                Removable only by an authenticated revocation, a drain, or the
                operator.

CACHE pool      shards this node fetched for its own reads or forwarded.
                Separate bolt bucket, separate byte counter.
                Capped at cacheFraction of capacity  [proposed 0.25]
                Evicted by LFU with an age decay; ties broken by size.
                A shard promoted from CACHE to CONTRACT (the node later accepts
                a placement for it) is moved, not copied.
```

`removeUnreferenced` must consult both pools, and `UsedBytes` must report them
separately so the capacity advertisement and the levelling arithmetic — which
is defined over *contracted* bytes — are not distorted by cache.

**What caching does not do:** it does not help content nobody else wants, it
repairs nothing, and it must never count toward a chunk's holder count.
`DistinctHolders` counts confirmed contract holders. A cached copy is a
performance accident, not durability, and treating it as durability is exactly
the mistake `WeakestChunk` was written to prevent.

---

### 10.8 Garbage collection and storage accounting

**Today's mechanism, read from the code:** reference counting by exhaustive
scan. `removeUnreferenced` calls `shardReferenced`, which checks `bucketRemote`
and then iterates **every object manifest** looking for the shard id.

```text
cost = O(candidates x objects x chunks x shards)
a node with 11k objects deleting one 40 MB object:
  351 candidate shards x 11,000 manifests unmarshalled from JSON each time
```

That is a real scaling defect and it is on the delete path. [BUILD NOW]:

```text
bucketShardRefs :  shard_id -> varint count + list of referencing manifest CIDs
  incremented in the same bolt transaction that writes the manifest
  decremented in the same transaction that deletes it
  a shard is removable iff count == 0 AND it is not in the CACHE pool
  reconciled by a full scan on the same cadence as reconcileUsedBytes (hourly),
  because an incremental counter that drifts must drift DOWN, and a full scan
  is the only thing that proves it
```

The existing usage counter already establishes this pattern — measure at
startup, maintain incrementally, reconcile hourly, drift only ever downward.
Reference counting should copy it.

**Reference counting versus lease expiry.** Both, for different objects:

| Mechanism | Applies to | Expiry |
|---|---|---|
| Reference count | Shards referenced by a manifest this node owns | None. Lives while the object does |
| Storage contract | Shards this node holds **for someone else** | `expires_at`, renewed by the owner's repair pass. Default 30 days, refused above 365 |
| Cache entry | CACHE pool | Evicted under pressure, no guarantee at all |

A contract that is not renewed expires and the shard becomes evictable. That is
what stops a holder accumulating the shards of publishers who vanished, without
anyone having to detect that they vanished. The repair pass already visits every
object on a 6-hour cooldown, so renewal is a field on a probe that happens
anyway.

**Who pays for persistence.** In v1: **nobody.** R11 fixes the economic layer
outside v1, so what holds an object alive is (1) the publisher's own node
keeping the manifest and re-running dispersal, (2) volunteers who accepted
contracts because they chose to, (3) the repair loop converting a holder's
departure into a re-placement, and (4) the accounting plane crediting storage
without settling it (PoF epochs already record this).

**What happens when nobody pays and nobody volunteers.** The object degrades in
a defined, observable order, and the node reports each state rather than
smoothing them:

```text
FullyDispersed   9 shards on 9 distinct holders   survives 3 losses
     v
durable          >= 7 distinct holders + survives any 1  (DurableRemoteHolders)
     v
UnderReplicated  fewer, still decodable            reported, queued, retried
     v
LocalOnly        WeakestChunk() == 0               one disk from gone
     v
LOST             fewer than 6 distinct indexes anywhere
                 restoreChunkBytes returns "fewer than dataShards survivors;
                 this chunk is lost"
```

**Permanence is not offered**, and the API must say so. AXON offers
*contracted, measured, repairable availability with a declared tier* (R8) plus
an honest report of the current tier. It does not offer that an object will
exist tomorrow. A system promising permanence without an endowment would be
lying; Freenet's "data you do not request decays" is at least honest about the
same limit. Proposed tiers, declared per object and reported by the API:

| Tier | Target | Enforcement |
|---|---|---|
| `EPHEMERAL` | best effort, no contract | none |
| `REPLICATED` | >= `DurableRemoteHolders(k,m)` distinct holders | repair pass |
| `SPREAD` | full `FullyDispersed` | repair pass + levelling |
| `PINNED` | `SPREAD` + contracts renewed by a bonded party | accounting plane, **not in v1** |

---

### 10.9 Audit and proof of storage

**What exists:**

| Mechanism | Where | What it proves |
|---|---|---|
| `have` probe | `PeerHasShard`, `disperse.go` | The holder **says** it has the shard. That is all |
| Follow-up `have` after a delete claim | `recallFromPeer` | A holder that claims deletion and did not delete is caught |
| Consecutive-silence counting | `NoteHolderSilence`, threshold 3, with an isolation test | A holder that is gone is eventually dropped; a rebooting holder is not |
| `get` and verify | `fetchFromPeer` | Full possession at one instant, at the cost of the full shard |
| `pof-challenge` transport | `challenge.go`, `challengeTimeout = 90s` | Nothing by itself — it carries opaque bytes for `internal/facilitation`. The p2p layer deliberately has no opinion about the proof |

**What it does not prove, stated exactly.** The lying-holder test file says it
itself: the fake handler "answers `have` honestly, because a holder that keeps
the shard and hides it from `have` is a different (and harder) adversary that
only `pof-challenge` would catch." The mirror case is worse and is the real gap:
**a holder that answers `have` with `true` while holding nothing is not caught
by any probe in this codebase.** It costs the liar one JSON frame per audit and
it silently inflates `DistinctHolders`, which is the number every durability
decision in `placement.go` and `rebalance.go` is built on.

#### The cheap fix the hash choice already paid for [BUILD NOW]

Replace `have` with a **Bao slice spot-check**. The verifier holds the shard's
BLAKE3 root (it is in the manifest). It asks for a randomly chosen 1024-byte
leaf and its proof path:

```text
challenge   nonce, leaf_index (derived: leaf = BLAKE3(nonce || shard_cid) mod L)
response    1024 B of shard data + 64 x ceil(log2 L) B of sibling CVs
            for a 174,763 B shard, L = 171 leaves: 1024 + 512 = 1536 B
verify      recompute the root; compare with the manifest digest
```

Properties, and the arithmetic that makes them worth having:

| Property | Value |
|---|---|
| Cost per challenge | 1536 B, one round trip |
| A holder storing a fraction `(1-f)` of the shard is caught with probability | `1 - (1-f)^t` over `t` challenges |
| To catch a holder missing 1 % with 99 % confidence | `t = 459` challenges = 705 KB, versus 174,763 B for one `get` |
| To catch a holder missing 10 % with 99 % confidence | `t = 44` = 68 KB |
| To catch a holder missing **everything** | `t = 1` |
| Secret required | none — this is a public-coin check |
| Precomputation defeat | the nonce must be fresh and unpredictable per challenge; derive it from the SRV (R13) plus a local nonce |

So: one 1536-byte challenge per audit catches the total liar immediately, which
is the realistic adversary and the one `have` currently misses entirely. Partial
withholding needs many challenges and stays cheap because they are 1.5 KB each.

#### What a real proof of retrievability would add [NEEDS RESEARCH]

The spot-check has two limits it cannot cross. **Outsourcing:** it proves the
holder had that leaf at that moment, and a holder can fetch the challenged leaf
from another holder on demand and pass every challenge while storing nothing.
Defence needs a response-time bound, which is nearly meaningless over anonymous
circuits. **Sampling:** a holder that deliberately drops the 5 % of leaves
nobody has ever challenged survives indefinitely.

The literature answer is a compact proof of retrievability with homomorphic
authenticators (the Shacham–Waters construction) or a provable-data-possession
scheme (the Ateniese line): constant-size proofs over the whole file with an
extraction guarantee rather than a sampling bound. Both need per-shard tags
computed at publish time and both put a public-key operation on the audit path.

**Whether that is warranted here is genuinely open.** Against: with no payment
layer in v1 (R11) a holder gains nothing by lying, and repair already treats an
unanswered probe as loss. For: the moment the accounting plane pays for storage
a holder gains *exactly* by lying, and retrofitting tags means rewriting every
manifest in existence. Recommendation: **reserve the tag field in `ChunkRecord`
now** (32-byte optional extension keyed by `flags`), build the Bao spot-check
now, and do not build the PoR until the accounting plane exists. Do not ship a
scheme that *looks* like a proof of storage without an extraction argument —
the same reasoning `doc/trust-anchor.md` §5 gives for refusing multi-provider
corroboration as verification.

**[UNSOLVED]:** an audit performed over anonymous circuits cannot distinguish a
holder that is slow from a holder that is outsourcing, and cannot bound response
time. Every proof-of-storage scheme in the literature assumes a network where
latency means something.

---

### 10.10 The hybrid site model

**The goal: a domain serves dynamic paths from a live anonymous service and
static paths from distributed content, so the site survives its publisher going
offline.** A prototype already runs in `internal/gateway/contentproxy.go` with
`SnapshotCache` and `OriginHealth`; the AXON version replaces "fetch from origin
over HTTPS" with "resolve through §11 and fetch over circuits", and replaces the
publisher-signed snapshot manifest with a `MutableRef` → `ObjectManifest`.

#### The record set

Under §11, a domain publishes (all signed by DomainIdentity):

```text
SERVICE   -> ServiceIdentity          the live anonymous service, if any
CONTENT   -> MutableRef(signer,label) or a bare ObjectCID
ROUTES    -> RouteTable               signed, versioned, monotonic like MutableRef
```

`RouteTable` is a list of `(prefix, disposition)` with a header default:

```text
off  len  field
  0    4  magic "AXRT"
  4    1  version = 1
  5    1  default_disposition
  6    2  entry_count            (uint16)
  8  ...  entries: 1 B disposition, 2 B prefix_len, prefix bytes
```

| Disposition | Meaning |
|---|---|
| `LIVE_ONLY` | Never served from content. A path that must not be answered by a stale copy |
| `CONTENT_ONLY` | Never contacts the service. The service never learns these requests were made |
| `LIVE_PREFERRED` | Service first; content on failure |
| `CONTENT_PREFERRED` | Content first; service only on a content miss |

#### The resolution rule, exactly

```text
resolve(domain, path, method):
  1. R  <- DomainRecords(domain)                              (§11)
     if R absent or expired beyond the resolver's declared
     freshness bound          -> FAIL "name unresolvable"
  2. T  <- R.ROUTES ; verify signature and seq ratchet
     if T absent               -> synthesise:
        default = LIVE_PREFERRED if R.SERVICE else CONTENT_ONLY
  3. d  <- longest-prefix match of path in T, else T.default
  4. if method is not safe (anything other than a read):
        if d in {CONTENT_ONLY, CONTENT_PREFERRED} -> FAIL 405, hard.
        else                                      -> d := LIVE_ONLY
  5. dispatch by d:
        LIVE_ONLY          -> service, or FAIL
        CONTENT_ONLY       -> content, or FAIL
        LIVE_PREFERRED     -> service; on failure (per the health rule
                              below) -> content; on content miss -> FAIL
        CONTENT_PREFERRED  -> content; on miss -> service
```

Two rules there are load-bearing, both inherited from the existing proxy.
**Longest prefix, not first match**, so a publisher can carve `/api/` out of a
`/` default without ordering games. **Unsafe methods never touch content** —
`ContentProxy` already refuses anything but GET and HEAD, for the reason its
comment gives: a forged write "could never be detected after the fact". A write
served from a static copy is not a stale answer, it is a lost one.

#### Failure semantics

`OriginHealth`'s state machine transfers directly and its reasoning survives the
change of transport: one timeout is not an outage; entering degraded mode needs
a threshold of failures within a window **and more than one kind** of failure;
leaving it needs consecutive successes over a minimum span plus random jitter so
a fleet does not stampede a service that has just come back.

| Service | Content | Result |
|---|---|---|
| up | any | serve live. `X-Axon-Source: service` |
| down, below threshold | available | serve live attempt; on this reader's failure serve content immediately rather than making them wait for the threshold |
| down, degraded | available | serve content. `X-Axon-Source: content`, `X-Axon-Degraded: 1`, `X-Axon-Content-Age: <now - ref.valid_from>` |
| down, degraded | path not in manifest | **known-unknown**: 404, not 503. The content tree exists and does not contain this path |
| down, degraded | no manifest at all | 503 + maintenance response |
| up | ref expired | serve live. An expired ref is never served |
| down | ref expired | **FAIL.** Do not serve expired content. This is the boundary of the survival claim |

The last row is the honest limit of "the site survives the publisher going
offline". It survives for `valid_until − now`, default **7 days**, because a
`MutableRef` that nobody republishes must eventually stop being authoritative —
otherwise a captured DHT record is a permanent site takeover. Extending survival
past the ref lifetime requires either a longer `valid_until` (which lengthens
the rollback window a withholding adversary can exploit) or a delegated
republisher holding pre-signed refs (which is a key-delegation problem, and is
[NEEDS RESEARCH]). **A site whose publisher never returns goes dark. That is the
design, not a defect, and it should be stated to publishers.**

---

### Decision table

| Decision | Problem it solves | Derived from | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| RS 6+3 erasure coding, 1 MiB chunks | 1.5x storage for ~3-copy durability at high `p` | Freenet's replicated blocks | Coding instead of copies; explicit diversity-aware placement | Plain 3x replication (2x the bytes); RaptorQ (no mature audited Go implementation in this module) | A sharp availability cliff below p≈0.88; loss of *any* 4 of 9 holders is total loss |
| `placement.Plan`: no two shards of one chunk on one peer | `peers[n % len(peers)]` made 6+3 behave like 6+1 | Nothing — original | Placement is planned and recorded, never emergent | Random placement; consistent hashing (neither can express "not this peer") | Fewer usable peers than shards leaves shards unplaced; a visible deficit rather than a hidden one |
| 7 distinct holders = durable, 9 = fully dispersed | "Placed" was being counted instead of "survivable" | Nothing — original | Durability measured in machines, not in shard indexes | Counting placed indexes (accepts 9 shards on 1 host) | A holder that lies about `have` inflates the count (§10.9) |
| BLAKE3 CIDv1 as ContentIdentity | Forged manifests cost a full failed transfer; no sub-shard verification | Freenet CHK; IPFS CID encoding | Tree hash, so any leaf verifies against the root | SHA-256 (no tree); BLAKE2b (no standard Bao streaming) | New hash on the security path; two coexisting multihash codes during migration |
| `MutableRef`, signed + monotonic `seq` | The name→content binding is unsigned and squattable today | Freenet USK; Tor descriptor republication | Blinded DHT key (R4c); permanent local `seq` ratchet | Bare CIDs (immutable sites); on-chain pointers (R7 forbids chain on the request path) | Trust-on-first-use: a client with no prior `seq` accepts whatever it is served |
| Randomly-keyed encryption by default | Convergent encryption enables confirmation-of-file | Freenet CHK (convergent); Tahoe-LAFS convergence secret | Convergence is opt-in per object; keyed convergence recommended | Convergent-always (dedup at the cost of confirmation attacks); no encryption (violates R5) | Lost publisher key = lost content; no recovery, by design |
| `obj_tag` instead of `ObjectID` on the wire | A holder can group and correlate shards of one object | Nothing — original | Per-holder blinded tag, recomputable by the owner | Sending nothing (breaks per-object recall scoping) | Owner must know holder identity at push time; a colluding owner still links everything |
| Mode A public holders, BULK class | 6 hidden-service rendezvous per chunk is unaffordable | Tor onion services (Mode B); I2P lease sets | Holders are public relays; only the client is anonymous | All-hidden holders (2 extra RTT + a descriptor lookup per shard) | The holder's address and the fact it holds shard X are public |
| Publisher-signed revocations | A coordinator that can delete anything, anywhere | Nothing — original construction, retained | Signer becomes the publisher; recipient+requester binding kept verbatim | Unauthenticated delete (any peer wipes any disk); capability-only (bearer token) | No central authority can remove content; abuse handling falls entirely to local blocklists (R5, unsolved) |
| Two disjoint pools, CONTRACT and CACHE | Today's cache has no eviction and grows forever | Freenet path caching | Cache never counts as durability; contracts never evicted by cache pressure | One pool with LRU (would evict shards this node uniquely holds) | Cache occupancy leaks what this node has read |
| Bao slice spot-check replacing `have` | A holder answering `have=true` while holding nothing is uncaught | Nothing — enabled by the hash choice | Public-coin sampled proof, 1536 B per challenge | Full `get` (174 KB per audit); PoR (needs tags and an economy) | Outsourcing: a holder can fetch the challenged leaf on demand |
| Route table with longest-prefix disposition | Static paths must survive the publisher; dynamic paths must not be staled | The deployed `SnapshotCache` + `OriginHealth` | Signed route table; content plane is the storage layer, not an HTTP cache | Serving everything from content (breaks writes); serving nothing (site dies with publisher) | A publisher who mis-marks a path serves stale data indefinitely under `CONTENT_ONLY` |

### Build status

| Status | Components |
|---|---|
| **Exists**, but **still on the OLD transport** — the retarget onto AXON has NOT happened (T11.1 unmet, T11.3/T11.4/E11.2/M4 unclaimed) | RS coding, shard store, placement ledger, dispersal, repair, levelling, drain, recall, refusal classification, the lying-holder test harness |
| [BUILD NOW] | BLAKE3 CID + Bao verified streaming (two bytes of CID, one blank import, one direct require); binary content-only `ObjectManifest`; `MutableRef` + blinded key + `seq` ratchet; encryption-mode selector and keyed convergence; `obj_tag` replacing `ObjectID` on the wire; shard reference-count bucket; CONTRACT/CACHE pool split with eviction; Bao slice spot-check audit; route table + hybrid resolution (the gateway prototype is the template) |
| [NEEDS RESEARCH] | Segmented manifests above ~1.5 GiB; admission control replacing the write lease; storage contracts with expiry and renewal; proof of retrievability with an extraction argument; delegated republication so a site outlives its ref lifetime; **measuring real per-holder availability `p`**, on which the whole EC-versus-replication argument rests |
| [UNSOLVED] | Abuse handling without a global blocklist (R5); distinguishing a slow holder from an outsourcing one over circuits; timing and size correlation of BULK shard transfers by a partial observer, since shard sizes are fixed and known |

---

### What this section does NOT establish

- **No measurement of per-holder availability `p` on any real deployment.** The
  entire case for erasure coding over replication is a function of `p`, and the
  table in §10.1 shows the sign of that comparison flips below p≈0.88. Until `p`
  is measured, "1.5x for 3-copy durability" is arithmetic conditioned on an
  assumption, not a result.
- **No measured latency.** Every figure in §10.5 is derived from declared
  assumptions (50 ms/link, 1 Mbit/s per circuit, 4 DHT rounds). Nothing in this
  layer has ever run over an AXON circuit, because AXON circuits do not exist
  yet. The comparison against the deployed I2P path uses that code's own stated
  estimate, not a benchmark either.
- **It does not establish that `have` can be made trustworthy.** The Bao
  spot-check catches the total liar cheaply and bounds the partial liar
  statistically, and that is all it does. Outsourcing defeats it, and no
  proof-of-storage scheme in the literature survives an adversary who can hide
  behind unbounded circuit latency.
- **It does not solve abuse.** R5 refuses a global blocklist as
  re-centralisation. Removing the coordinator's revocation key removes the only
  party who could currently take content down network-wide. What replaces it is
  local operator blocklists (`bucketDenied`, which exists) and nothing else.
  This is a deliberate, named, unsolved problem, and it gets worse the better
  the rest of this section works.
- **It does not offer permanence, and the tiers are proposals.** `EPHEMERAL`,
  `REPLICATED`, `SPREAD` and `PINNED` are named here for the first time; only
  the first three are implementable without the accounting plane, and `PINNED`
  depends on machinery R11 puts outside v1.
- **The hybrid site survives the publisher for a bounded time only.** Seven
  days by default, set by `MutableRef.valid_until`. Extending it trades against
  the rollback window. A delegated republisher would fix it and does not exist.
