## 19. Implementation Architecture

**The finding: the language question is smaller than it looks, and the release
architecture already answers it.** The existing node is Go, and its release build
is deliberately CGO-free — seven platforms cross-compiled from one host, static,
`-trimpath` (`SECURITY.md`, "Ethereum BLS verification is an opt-in build
capability"). That property is why `blst` sits behind an `ethbls` build tag and
is absent from every shipped binary. Any plan that puts a Rust crate on the
forwarding path hits the same wall from the other side: it needs cgo, cgo
forfeits the cross-compiled static release, and this project has already paid
that price once and chosen not to pay it again. The recommendation is Go, and
the argument is not "Go is better" — it is that Rust's win is narrow, sits where
the *composition* rather than the primitive will be wrong, and the build system
says no.

Cross-references are by layer name (L1–L8) and Constitution ruling (R1–R14)
rather than by neighbouring section number, since numbering is fixed at
assembly. Parameters come from Constitution §5 unless attributed to a file.

### 19.1 What already exists

| Thing | Path | What §19 does with it |
|---|---|---|
| Go module, `go 1.25.12` | `go.mod` | Kept. Sets the toolchain floor for the stdlib-crypto argument in §19.7. |
| libp2p host + Kademlia | `internal/p2p/node.go` (1775 lines), `internal/dcs/dht.go` | L2/L3 substrate. `ProtocolID = "/syndichan/storage/1.0.0"`, `maxHeaderBytes = 64<<10`, `maxNetworkShard = 32<<20`. |
| bbolt metadata store | `internal/store/store.go:84-137`, `internal/facilitation/receipt_store.go:42` | Kept for the state classes in §19.6. Both files document bbolt's single-process file lock and translate `bolt.ErrTimeout` into a human sentence. |
| Erasure defaults | `internal/config/config.go:572-574`, `:817-821` | **RS 6+3, `ChunkBytes = 1<<20` (1 MiB)**, validated 64 KiB–16 MiB. Constitution §5 says 256 KiB and asks for confirmation; the code says 1 MiB. Flagged, not silently changed. |
| A working fixed-slot onion | `internal/channel/onion.go` (318 lines) | In-repo prior art for L4. `MaxHops = 3`, `SlotSize = 1024`, per-hop AES-256-GCM, key-derived slot permutation. Its header records why the slot had to be 1 KiB: `encoding/json` renders `[32]byte` as a decimal array. |
| Canonical-hash discipline | `internal/facilitation/receipt.go:60-95` | `CanonicalReceiptHash`: flat big-endian concatenation, fixed field order, keccak256, Ed25519-signed. §19.4 generalises it. |
| Sign-over-re-marshalled-JSON | `internal/dcs/dht.go:105-115` | The anti-pattern §19.4 replaces: verification blanks `Signature`, re-marshals with `encoding/json`, and checks the signature over *that*, not over the received bytes. |
| Config loader | `internal/config/config.go` (1456 lines) | Kept: `ListenIsLoopback` (:739), refusal of `0.0.0.0`/`::` for the dashboard (:778-794), "every default is the refusing one" (:249). |
| Traffic meter | `internal/traffic/traffic.go` | Kept. Drain-once semantics with exactly one legitimate caller — the model for §19.8. |
| Monitor / heartbeat | `internal/monitor/monitor.go`, `internal/heartbeat` | **Not ported.** `DirectHTTPClient()` bypasses the anonymity transport by design, and `SECURITY.md` records that the heartbeat exposes the node's egress IP to `syndichan.org`. On a relay this is a deanonymisation channel. |
| Logging | `cmd/syndichan-node/main.go:54` | `log.New(os.Stderr, "syndichan-node ", log.LstdFlags\|log.LUTC)` — one stdlib logger, no levels, no redaction. Replaced in §19.8. |
| I2P transport | `internal/i2p/sam.go`, `transport.go` | Removed (Constitution §8). Its shape — a custom transport registered exclusively, every IP-bearing multiaddr discarded — is what L1 inherits. |

**What must be replaced:** the logger, the metrics/heartbeat surface, JSON as a
signed-record encoding, and the I2P transport. Everything else is kept.

### 19.2 The language decision

**What Go actually costs, without flattery.** Memory safety at the parser
boundary is *not* the differentiator: Go bounds-checks slices, has no pointer
arithmetic, and panics rather than reads out of range. The residual unsafety is
`unsafe`, cgo, and **data races**, which in Go are genuinely unsound — a
concurrently-written slice header or interface can tear — and that lands exactly
where a relay lives, on shared circuit tables under concurrent readers. It is
answered architecturally in §19.9 plus `-race` in CI. The **GC pause** is a real
timing channel: forwarding latency correlates with allocation rate, which
correlates with traffic, so a circuit through a relay can in principle measure
that relay's load. It is unmeasured and strictly weaker than the end-to-end
correlation Constitution §7 already concedes for `INTERACTIVE`; the mitigation
is to allocate nothing per cell, which throughput requires anyway.
**Constant-time discipline** is a review property, not a language property: the
Go stdlib gives assembly-backed constant-time Ed25519, X25519 and AES-GCM plus
`crypto/subtle`, but nothing stops `if secret == x` compiling, where Rust's
`subtle::Choice` makes the variable-time version awkward to write by accident.
**Zeroisation** is genuinely worse in Go — values are copied into stack frames,
interfaces and grown slices, so `clear()` is best-effort where `zeroize`+`Drop`
is not. Neither survives a core dump or swap; those mitigations are OS-level.

**What Rust actually buys, and where.** Exactly one place: a cell-processing
inner loop that is allocation-free, panic-free, constant-time by type and
zeroising — roughly 2,000–4,000 lines of AEAD layering, handshake and cell
codec. It does not win in the circuit state machine, path selector, DHT, pool
manager, descriptor logic, resolver or chain plane, which is where the
interesting bugs will be, because those are logic bugs.

**The hybrid — Go node, Rust crypto core behind FFI — is rejected**, on four
grounds in order of weight:

1. **It breaks the release build.** Linking Rust means cgo, which ends
   `CGO_ENABLED=0` cross-compilation for every target. `SECURITY.md` records
   that this is precisely why BLS is build-tagged and absent from shipped
   binaries. A build-tagged *anonymity core* is not an option: the tagless build
   would have to refuse to route or route with a second implementation, and a
   second implementation of cell crypto is worse than either.
2. **The boundary is the wrong shape.** Keeping the circuit table in Go means
   keys cross the FFI or are duplicated; keeping it in Rust makes the boundary
   per-cell (~122,000 calls/s per gigabit). The first forfeits the zeroisation
   argument that motivated Rust at all.
3. **Two toolchains, two sanitiser stories, two supply chains,** plus a
   marshalling layer that is new attack surface in neither language's safe
   subset.
4. **Team continuity.** `internal/ethproof` — BLS12-381 sync-committee
   verification, SSZ, `execution_branch`, 512/512 mainnet signature verified
   (`doc/trust-anchor.md`) — is the most valuable existing asset, the naming
   layer depends on it, and it is Go.

**Recommendation: Go, one language, for v1.** `[BUILD NOW]` The other choice
becomes right under any one of these, and the decision should be reopened when
one occurs:

| Condition | Why it flips |
|---|---|
| The CGO-free 7-platform static release stops being required | Removes objection 1; the hybrid becomes merely expensive |
| A wasm/browser client enters scope | Go's wasm output is large and its GC hostile to a tab; Rust's is not |
| GC-pause leakage is *measured* to be exploitable at a relay | The one unquantified Go objection becomes quantified |
| An audit requires constant-time verification of the cell core (dudect/ctgrind-class tooling) | That tooling is materially better developed against Rust |
| A greenfield restart with no Go assets | Discount the light client, storage, placement engine and PoF client to zero and Rust is the better default |

Instead of switching, buy the Rust advantages cheaply: one `axon/crypto` package
that is the only code permitted to touch key material; a lint forbidding `==` on
its `Secret` family; `-race` and a cell-parser fuzz target in CI; and an
allocation-budget test that fails the build if the forwarding path allocates
(§19.9).

### 19.3 Repository layout and the migration map

```text
EXISTING                              TARGET  axon/
storage-client/                         cmd/axond/    daemon        cmd/axon/    CLI (§20.7)
  cmd/syndichan-node/                   crypto/       sole holder of key material
  internal/                             identity/     8 identity classes, keystore, blinding
    p2p/       host, DHT, disperse      transport/    L1 QUIC+TLS1.3 raw keys, TCP fallback
    dcs/       containers, records      peers/  nat/  L2 peerbook, reachability, traversal
    store/     shards, bbolt meta       routing/      L4 path selection, guards, weighting
    placement/ place/  diversity        tunnels/      L4 circuits, cells, pools, flow control
    i2p/       SAM + transport  ←DEL    rendezvous/   L5 intro, rendezvous, PoW puzzles
    gateway/   ACME, registry   ←REPL   dht/          L3 two keyspaces, disjoint lookup
    channel/   SCPP/1, onion.go         resolver/ domains/  L7 resolution, registry records
    facilitation/ PoF, receipts         blockchain/   chain plane: light client, SRV
    ethproof/  light client, MPT        storage/ services/  L6 shards, manifests, descriptors
    config/ traffic/ monitor/           payments/ accounting/  accounting plane (OFF in v1)
    heartbeat/ bootstrap/ ui/ s3api/    protocol/ metrics/ api/   wire, export policy, L8
```

| Existing | Target | Kind of move |
|---|---|---|
| `internal/p2p/node.go` | `transport/` + `peers/` | Split: host construction and dial policy to `transport`, peerbook and bootstrap to `peers` |
| `internal/p2p/{disperse,recall,repair,rebalance,objmanifest,contentkey}.go` | `storage/` | Lift and shift; retarget from libp2p streams onto `tunnels` |
| `internal/store/` | `storage/local/` | Unchanged except the encryption gap in §19.7 |
| `internal/placement/`, `internal/place/` | `storage/placement/` **and** `routing/diversity/` | **Forked deliberately.** The same diversity levels serve shard placement and relay path selection (R14); one package with two callers would couple L3 and L4 |
| `internal/dcs/{dht,record}.go` | `dht/` | Records re-encoded per §19.4; keyspace split into descriptor and content (R4d) |
| `internal/gateway/` | `resolver/` + `domains/` | Replaced, not ported. ACME/DNS has no analogue; `snapshot.go`'s signed-snapshot idea survives as the R7 registry snapshot |
| `internal/ethproof/` | `blockchain/` | Move, no rewrite. Also becomes the SRV source (R13) |
| `internal/channel/` | `payments/` | Move. `onion.go` **stays there** as the payment-route onion; it is not the L4 cell onion and merging them would put a payment format on the data path |
| `internal/facilitation/` | `accounting/` | Move; `CanonicalReceiptHash` generalises into `protocol/` |
| `internal/config/`, `internal/traffic/` | `axond/config/`, `metrics/` | Move; conventions retained verbatim |
| `internal/{monitor,heartbeat,i2p}` | — | Not ported / deleted |
| `internal/{compute,computeworker,computeimage,microvm,s3api,ui,directive}` | out of scope | Constitution §8 — Syndichan product, not AXON infrastructure |

One hard ordering constraint: `transport/` and `tunnels/` must be complete
before `internal/i2p` is deleted, because the store's cross-node fetch budgets
three minutes specifically to survive a cold I2P dial
(`internal/store/store.go:41-45`).

### 19.4 Wire protocol and serialization

**Cells: fixed binary, hand-written, no schema.** Cells are 1024 B constant. A
schema-driven encoder cannot produce a fixed size without padding rules that are
themselves a hand-written layout, so the schema buys nothing and costs a parser.
The layout belongs to the L4 section; `protocol/` holds the codec and fuzz corpus.

**Records: a strict deterministic binary TLV profile, hand-written codec,
schema-described.** Records are signed, so a non-canonical encoding is a
signature-forgery vector: if two byte strings decode to the same object and the
verifier signs a re-encoding, an attacker substitutes one for the other and the
signature carries across. `internal/dcs/dht.go:105-115` has exactly that shape
today; it is safe only because Go's `encoding/json` happens to be deterministic
for that struct — a security property resting on a library implementation detail.

| Candidate | Canonical? | Size | Parser surface | Cross-language | Verdict |
|---|---|---|---|---|---|
| Protobuf | **No** — unspecified field order, non-minimal varints accepted, unknown fields preserved and re-emitted, default elision, repeated-merge semantics | Small | Generated, well fuzzed | Excellent | **Rejected for signed data.** The unknown-field rule alone is fatal: a verifier ignoring a field a peer honours is a split-brain forgery |
| CBOR | Deterministic profile exists, but decoders accept non-deterministic input by default; indefinite lengths, tags, floats, bignums, duplicate keys | Small | Large type system; strict mode opt-in and often partial | Excellent | **Second choice, restricted** to *unsigned* local and diagnostic payloads |
| Hand-rolled deterministic TLV | Canonical by construction when the decoder rejects anything it would not re-emit identically | Smallest | Smallest; one codec per record type, all fuzzed | One codec per language, ~15 record types | **Chosen for every signed record** |
| JSON | No — key order, whitespace, number and escape forms, duplicate keys | Largest; a `[32]byte` renders as ~160 characters (`onion.go:47-57`) | Large | Universal | **Rejected.** Already measured to cost 512 B of slot in this repo |

**The rule that does most of the work:** *the signature is computed over the
exact octets received, never over a re-encoding.* Decoders return
`(value, signedBytes)` and the verifier is handed `signedBytes`. Canonicality is
then defence in depth rather than the sole guarantee.

**Canonicalization rules for signed records.** A decoder MUST reject on any
violation; there is no lenient mode.

```text
R-1  Integers are fixed-width big-endian. No varints in signed records.
R-2  Fields appear in ascending tag order. Out-of-order or duplicate tag = error.
R-3  Every field is length-prefixed u16 big-endian; declared length must equal
     actual; trailing bytes after the last field = error.
R-4  Optional fields are declared by a presence bitmap in the header. Absent
     means absent — there is no "absent means default".
R-5  No floating point. No maps. Sets are sorted byte-ascending; a duplicate is
     an error.
R-6  Strings are UTF-8, NFC, length-prefixed. Domain labels are lowercased and
     IDNA-processed at the L7 boundary BEFORE hashing; the codec sees bytes.
R-7  Unknown tags in a signed record are an error. Forward compatibility comes
     from version negotiation (§19.5), never from ignore-unknown-fields.
R-8  Keys, hashes and identifiers are fixed-width raw bytes. No base64, hex or
     multibase inside the signed region.
R-9  Timestamps are u64 seconds since the Unix epoch, UTC. No sub-second field:
     microsecond timestamps in a published descriptor are an analysis dataset.
R-10 The codec is property-tested both ways: decode(encode(x)) == x for all x,
     and encode(decode(b)) == b for every b accepted. The second is the
     canonicality test and the one that catches real bugs.
```

Every signed byte string is prefixed with an ASCII domain-separation label
(`"axon/desc/v1"`, `"axon/relaydesc/v1"`, …), matching the convention already in
`internal/channel/onion.go:61-66`. `[BUILD NOW]`

### 19.5 Version negotiation and the downgrade rule

`LinkVersion` is negotiated per QUIC connection; `RecordVersion` is a u16 in each
record header. The initiator sends `VERSIONS` listing every supported
`LinkVersion`, ascending, no duplicates; the responder replies with its own set
and selects the highest common value. An empty intersection closes with
`NO_COMMON_VERSION` before any key material is derived.

**The rule that prevents a downgrade attack** — the handshake KDF input includes
both complete offered lists and the selection:

```text
transcript = "axon/link/v1"
           ‖ len(initiator_list) ‖ initiator_list
           ‖ len(responder_list) ‖ responder_list
           ‖ selected_version
           ‖ initiator_ephemeral_pub ‖ responder_ephemeral_pub

k_link = HKDF-SHA256(shared_secret, salt = H(transcript), info = "axon/link/keys/v1")
```

Stripping entries from either list changes `transcript` on one side only, so the
two sides derive different keys and the first authenticated cell fails to open.
The downgrade surfaces as a decryption failure, not as a policy check that can
be forgotten. This is TLS 1.3's transcript binding restated for a two-message
handshake — no new construction.

**Version floors.** A node MUST NOT negotiate below `MinLinkVersion` even when
offered nothing else. With no consensus document (R14) the floor cannot be
raised by network vote: it is compiled into a release *and* published in the
registry snapshot's parameter block (R7), and the two must agree. **Residual
risk, named:** without a flag day, retiring a broken link version needs either a
release cadence the network follows or a snapshot publisher who becomes a trust
point. `[UNSOLVED]` in general; v1 ships the compiled floor and accepts slow
retirement.

| Situation | Handling |
|---|---|
| Unknown field in a signed record | Reject the record (R-7) |
| Unknown cell command during the handshake | Fatal; close with `PROTOCOL_ERROR` |
| Unknown cell command on an established circuit | Drop, count, continue. Tearing down turns a version probe into cheap DoS and makes the supported-command set remotely enumerable |
| Unknown record type arriving from the DHT | A storage host may store what it cannot parse; a client refuses to act on it |
| `RecordVersion` above what we know | `ErrUnsupportedRecordVersion`, never `ErrBadSignature` — conflating them makes version skew look like an attack |

### 19.6 Node-local storage, and what may never touch disk

| State | Where | Engine | Why |
|---|---|---|---|
| Circuit table (circuit id ↔ hop keys ↔ predecessor/successor) | **Memory only** | — | It is the exact record a seizure wants, and there is no meaningful encrypted-at-rest version: the key is on the same disk |
| Session and stream table (R9) | **Memory only** | — | Sessions outlive circuits, not processes |
| Handshake replay cache | **Memory only** | bounded rotating set, per epoch | Persisting it creates a log of who handshook with you — see the caveat below |
| Client descriptor cache and resolution cache | **Memory only** | — | A record of which services and names a user visited |
| Guard set and guard health | **Disk, required** | bbolt or 0600 file | A guard set that resets on restart destroys the guard property (R1). The second most sensitive file after the identity key |
| Peerbook / relay descriptor cache | Disk | bbolt | Public information about public relays |
| Descriptor host store (descriptors stored *for* the DHT) | Disk | bbolt | Blinded keys, public by role (R4c) |
| Shard metadata / shard bytes | Disk | bbolt `metadata.db` / flat files | Unchanged from `internal/store` |
| Accounting receipts | Disk | separate bbolt file | `receipt_store.go:19-21` already explains why it is separate: one process may hold one bbolt file |
| Identity keys | Disk, 0600 | flat files | Existing convention |

**Is bbolt right?** For the rows above, yes: a single-writer mmap'd B+tree with
full ACID semantics, no compaction and no background threads suits append-mostly
small-key metadata, and the codebase already knows its failure modes well enough
to translate `bolt.ErrTimeout` into a human sentence (`store.go:91-97`). It is
the wrong engine for a high small-write rate, because every write copies pages
and a commit fsyncs — which is why nothing on the per-cell path touches it.
**The rule: no fsync on the data path.** A relay that fsyncs per circuit is a
relay whose latency is a disk; circuit creation, extension and teardown write
nothing. If the descriptor host store outgrows bbolt's write amplification under
a 3 h lifetime with hourly republication, the answer is an append-only log plus
an in-memory index, not another embedded engine. `[NEEDS RESEARCH]` — the write
rate depends on how many descriptors a node hosts at `r=8`, which is a function
of network size and not knowable yet.

**Honest caveat.** Clearing the replay cache on restart opens a replay window
bounded by the handshake timestamp tolerance (±5 min): a captured `CREATE` can
be replayed inside it, making the relay derive the same keys twice — a
confirmation primitive. The alternatives are persisting a salted epoch-scoped
digest set (the contact log we were avoiding) or refusing all handshakes for the
tolerance window after boot (a self-inflicted outage on every restart). v1
accepts the window and says so. `[NEEDS RESEARCH]`

### 19.7 Cryptographic libraries

**Rule 1: no primitive is implemented in-house.** The three exceptions below are
*compositions* of audited primitives, not new primitives. **Rule 2:
`axon/crypto` is the only package permitted to hold key material;** everything
else gets handles.

| Purpose | Library | Constant-time | In-house? |
|---|---|---|---|
| Ed25519 sign / verify | `crypto/ed25519` (stdlib) | Required on the secret scalar; not required for verify (public inputs) | No |
| Ed25519 key blinding (rend-spec-v3 style) | `filippo.io/edwards25519` `Scalar`/`Point` | Required on the blinding factor and resulting scalar | **Exception 1**: we write the blinding *schedule*, the library does group and field arithmetic. `[BUILD NOW]` behind an audit gate |
| X25519 | `crypto/ecdh` (stdlib) — **not** `x/crypto/curve25519` | Required; `crypto/ecdh` also rejects all-zero shared secrets, which the raw function does not | No. Migrate the two existing `curve25519` call sites |
| ML-KEM-768 (hybrid slot) | `crypto/mlkem` (Go 1.24+) | Required, including the implicit-rejection path, which must not branch | No. Confirm with `go doc crypto/mlkem`; the module declares `go 1.25.12` |
| ChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` | Required | No. **Not currently a dependency — see below** |
| AES-256-GCM (negotiable alternative) | `crypto/aes` + `crypto/cipher` | Required; AES-NI where present | No |
| HKDF-SHA256 | `crypto/hkdf` (Go 1.24+) or `x/crypto/hkdf` | Required | No |
| SHA-256 | `crypto/sha256` | Not required | No |
| keccak256 | `x/crypto/sha3` `NewLegacyKeccak256` | Not required | No. Already used in 8 files; stdlib `crypto/sha3` does not provide legacy Keccak padding, so this dependency stays |
| BLAKE3 / Bao verified streaming | `lukechampine.com/blake3` (already indirect) | Not for hashing; required for any KDF over it | **Exception 2** for the Bao tree walk — a data-structure traversal over an audited hash |
| BLS12-381 | `blst` behind `ethbls` | Required | No. **Chain plane only** (Constitution §2); `SECURITY.md` documents the tag and the fail-closed stub |
| Secret comparison | `crypto/subtle` | Required, always | No |
| Randomness | `crypto/rand` only; `math/rand` banned | — | No. `monitor.go:327-341` already sets the precedent |
| Onion layering | `axon/crypto/onion` | Nonces derived, never random; per-direction counter; circuit torn down at exhaustion, never wrapped | **Exception 3**: a composition of AEAD invocations, as `internal/channel/onion.go` already is |

**A discrepancy that must be reconciled before either document is cited.**
`SECURITY.md` ("Cryptography") states each object receives an
XChaCha20-Poly1305 key with a 192-bit nonce per chunk. No ChaCha20
implementation is imported anywhere in the module, `go.sum` contains no ChaCha
entry, and `internal/store` and `internal/s3api` contain no `crypto/cipher` use
at all. The AEAD actually constructed in this tree is AES-256-GCM
(`internal/channel/onion.go:144`, `internal/channel/vaultstore.go:137`,
`internal/dcs/content.go:85`). Either the object-encryption path lives outside
this module or the document describes an intent. This must be resolved before
the AEAD story is treated as settled — R5 ("no node ever caches plaintext it did
not request") depends on it.

### 19.8 Configuration, logging, metrics

**Configuration.** One JSON file, mode 0600, at the OS config location, with a
single `-config` flag — the existing design (`cmd/syndichan-node/main.go:41-49`),
worth keeping verbatim because posture in the file rather than in flags makes a
node's behaviour auditable by reading one file. Carried forward: every default is
the refusing one (`config.go:249`); an absent section means off, never
on-with-defaults; **no secret in an environment variable**
(`/proc/<pid>/environ` and container inspection both read it); and any setting
that weakens anonymity needs an explicitly-named key (`unsafe_log_addresses`,
`allow_two_hop_tunnels`, `api_listen_tcp`), each raising a `Status.Warning`
(§20.3) for as long as it is set.

**Logging.** The current logger is one stdlib `log.Logger` to stderr with no
levels and no redaction. It is replaced. *The pairing rule, which is the whole
point:* a relay knows the predecessor and
successor of every circuit it carries, and that pairing **is** the
deanonymisation. It lives in memory because it must. It must never appear in a
log line, a metric, an event, or a crash dump. Enforcement is typed, not
conventional: the logging API accepts a `CircuitHandle` —
`H(process_salt ‖ real_circuit_id)[:8]` with a random per-process salt — and
there is no method taking a peer identity and a circuit handle in the same call.

| Category | Never | Redacted | Plainly |
|---|---|---|---|
| Client IP / peer address | At INFO and above | `/24` (v4) or `/48` (v6) at DEBUG | Only under `unsafe_log_addresses`, which prints a startup WARN and sets a persistent `Status.Warning` |
| Node/Routing identities | Predecessor and successor of the same circuit, in any line | `H(salt‖id)[:8]` | Own identity, once, at startup |
| Circuit / stream ids | Real wire ids | Salted handle | — |
| `.axon` names resolved (client side) | Always | — | Only on the domain's own publisher |
| Blinded descriptor keys requested | Always | — | On a DHT storage host, the key it was asked for is its job |
| Content IDs requested | Always | — | On a holder, the shard it holds |
| Payment tokens with circuit context | Always (R11) | — | — |
| Timestamps | Sub-second in relay logs | Second granularity | Sub-second under `-tags axondebug` |

Levels ERROR/WARN/INFO/DEBUG/TRACE, default INFO; TRACE compiled out unless
built with `-tags axondebug`, mirroring `ethbls` so a forgotten tag yields the
safe build. **No remote log shipping by default** — a relay that ships logs to a
collector has appointed that collector a global passive observer of its own
traffic.

**Metrics.** A metrics endpoint is a per-node oracle: anything a metric
distinguishes, whoever scrapes it can distinguish. Loopback-only, **off by
default**, OpenMetrics text, no push, no remote write. A non-loopback bind is
refused outright rather than password-gated — stricter than the dashboard rule at
`config.go:778-794`, deliberately. Drain-once semantics follow
`internal/traffic.Meter` and its "exactly one legitimate caller" comment.

| May be exported | Must NOT be exported |
|---|---|
| Build version; uptime rounded to the minute | Uptime at second resolution (a restart fingerprint) |
| Cumulative cells and bytes relayed | Any per-peer counter — a "who am I connected to" oracle by label cardinality |
| Aggregate circuit build success rate | Per-circuit anything |
| Circuit count **bucketed** (0, 1–2, 3–5, 6–10, 11–25, 26–50, 51+), refreshed at most every 30 s | Exact live circuit count at scrape resolution. An observer polling at 1 Hz watches circuits being built — an end-to-end confirmation oracle given away for free |
| DHT lookup latency histogram, aggregate | Per-key or per-namespace lookup counters |
| Bytes held, shard count, repair backlog | Per-object or per-holder counters |
| Goroutines, heap, GC pause histogram | — |
| Guard count and health summary | Guard identities |

**The existing monitor and heartbeat must not run on a relay under the relay's
identity.** `internal/monitor` probes over a direct HTTP client by design
("Probing through I2P would measure I2P") and `SECURITY.md` records that the
five-minute heartbeat exposes the node's egress IP to `syndichan.org`. Correct
for a Syndichan storage node; a deanonymisation channel for an AXON relay. They
are not ported. If the product wants them co-resident, they run as a separate
process under a separate identity and the AXON node records a `Status.Warning`
that a clearnet beacon is present.

### 19.9 Concurrency and resource model

**Circuits are data, not goroutines.** One goroutine per circuit at 16,000
circuits is 128 MiB of stacks before any payload, plus scheduler pressure.

```text
per QUIC connection:  1 reader goroutine
                      1 writer goroutine  (single writer owns the connection, so
                                           cell interleaving is serialised and no
                                           lock sits on the send path)
per node:             1 pool manager, a bounded DHT worker set (α=3 per lookup),
                      1 timer wheel, 1 accounting drain
per circuit:          0
```

A circuit is a struct owned by exactly one connection reader at a time; ownership
moves through a channel, never a shared mutable pointer. That is also the
mitigation for Go's data-race unsoundness (§19.2).

**Per-circuit memory at a relay.**

| Item | Bytes | Note |
|---|---|---|
| Circuit state (ids, link refs, timers, counters) | ~256 | |
| Hop key material, 2 directions | 128 | 2 × (32 B key + 32 B nonce base) |
| AEAD contexts, 2 directions | ~1,024 | Implementation-dependent; measure |
| Relay queue, 4 cells × 1024 B × 2 directions | 8,192 | Small on purpose — QUIC stream flow control does the buffering (R12) |
| QUIC per-stream state and windows | **TBD — measure against `quic-go` v0.59.1** | The dominant term, and the one number that must not be guessed |
| **Planning budget** | **64 KiB per circuit, end to end** | Used below until the QUIC term is measured |

Per stream (multiplexed inside a session, R9): 8 KiB reassembly + 4 KiB send +
~128 B state ≈ **12 KiB**, default 16 streams per session.

| Relay class | Hardware | `MaxCircuits` | `MaxLinks` | Circuit memory |
|---|---|---|---|---|
| A | 1 vCPU, 1 GiB, 100 Mbps | 2,000 | 512 | 128 MiB |
| B | 2 vCPU, 4 GiB, 1 Gbps | 16,000 | 4,096 | 1 GiB |
| C | 8 vCPU, 16 GiB, 10 Gbps | 65,536 | 16,384 | 4 GiB |

**Throughput arithmetic.** At 1024 B cells, 1 Gbps is ~122,000 cells/s, one AEAD
operation each over ~1008 B. Taking a published-typical 1–2 GB/s/core figure for
ChaCha20-Poly1305, 125 MB/s of forwarding is roughly one tenth of a core.
**Crypto is not the bottleneck; packet handling is** — plan for `sendmmsg`/GSO
batching and expect the QUIC per-packet path to dominate. These are arithmetic
from a generic rate, not measurements of this code, and must be re-derived on
real hardware before anyone quotes them.

**Allocation budget.** The forwarding path allocates zero: cells come from a
per-connection ring of pooled 1024 B buffers, AEAD is in place, the codec returns
sub-slices. CI asserts `AllocsPerOp == 0` on `RelayCell` as a build-breaking
test. This is what keeps the GC-pause channel small.

**Runtime settings.** `GOMEMLIMIT` set explicitly to 75 % of the cgroup or
configured budget — a Go relay without it is an OOM waiting for a traffic spike.
`GOGC` stays at 100. `GOMAXPROCS` pinned to the cgroup CPU quota, not host cores.

**Backpressure, four layers, innermost first:**

```text
1. QUIC stream flow control   one stream per circuit per link (R12); a slow next
                              hop stops its predecessor by not opening the
                              window. Hop-by-hop only. PRIMARY mechanism.
2. End-to-end cell credit     window of 1000 cells, acknowledged every 100, so an
                              intermediate relay's memory is not the only limit
                              on a fast sender. Tor's SENDME idea; our numbers.
3. Admission control          refuse CREATE above 90 % of MaxCircuits, DESTROY
                              reason RESOURCE.
4. Memory watermark           above 90 % of GOMEMLIMIT tear down the NEWEST
                              circuits. Never the oldest: killing established
                              circuits is what an attacker wants.
```

Layer 3 has an honest cost — a refusal is itself a load signal, and an adversary
who can provoke one can distinguish a loaded relay from an idle one. Refusals are
rate-limited and jittered, which reduces the signal without removing it.
`[NEEDS RESEARCH]`

### 19.10 Decision table

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Single language: Go | Team continuity; keeps the light client, storage and PoF assets usable | Neither (Tor is C, I2P and Freenet Java) | Let the CGO-free static cross-compiled release constraint decide | Rust rewrite; Go+Rust hybrid via cgo | Unmeasured GC-pause timing channel; Go data-race unsoundness under concurrent circuit access |
| Circuits are data, not goroutines | 16k circuits × 8 KiB stacks is 128 MiB before payload | Tor's per-circuit state in one event loop | Per-link goroutines, single-writer sends | Goroutine per circuit or per stream | One slow connection reader stalls every circuit on that link until the QUIC window closes |
| Fixed binary cells, no schema | Cells are 1024 B fixed; a schema needs hand-written padding rules anyway | Tor's fixed cell | 1024 B; one QUIC stream per circuit (R12) | Protobuf or CBOR cells | A hand-written parser on the hostile boundary, mitigated only by fuzzing |
| Deterministic TLV; signature over received bytes | Non-canonical encoding is a signature-forgery vector | Neither (Tor signs text documents, I2P a binary format) | Sign received octets rather than a re-encoding, fixing the `internal/dcs/dht.go` pattern | Protobuf (unknown fields, non-minimal varints); CBOR (strict mode opt-in); JSON (measured 512 B slot cost) | A codec per language is a porting burden and a place for two implementations to disagree |
| Transcript-bound version negotiation | Link-version downgrade | TLS 1.3's transcript binding | Both offered lists plus the selection enter the KDF, so a strip is a decryption failure | Post-handshake policy check on the negotiated version | Version-skewed peers fail with an opaque crypto error that reads like an attack |
| Circuit table, replay cache and client caches memory-only | Seizure of a running relay must not yield a contact log | Tor keeps circuit state in memory | Extended to the resolver and client descriptor caches | Encrypted-at-rest circuit table (key is on the same disk) | ±5 min replay window after restart |
| Guard set persisted | A guard set that resets destroys the guard property | Tor's persistent guard file | Two guards per isolation context (R1) | Ephemeral guards | The most sensitive file after the identity key; disk compromise yields the guard set |
| bbolt for metadata, nothing on the cell path | Reuse a store the team understands without a disk in the latency budget | Neither | Explicit per-state-class disk/memory ruling | SQLite; a new engine; one unified DB | Single-writer file lock means one process per data dir; write amplification if the descriptor store grows |
| Metrics loopback-only, gauges bucketed, no per-peer labels | A metrics endpoint is a per-node oracle | Neither (Tor's MetricsPort is a similar admission) | Bucketed circuit gauge with a 30 s refresh floor | Prometheus with per-peer labels; remote write | Bucketing degrades visibility exactly when a node is under attack |
| Typed logging, salted handles, the pairing rule | Predecessor+successor in one line is the deanonymisation | Tor's safe-logging convention | Type-level enforcement instead of convention | Free-form logging with a redaction filter | Salted handles are useless across restarts, so cross-restart debugging is genuinely harder |

`[BUILD NOW]`: codec and fuzz targets, version negotiation, storage
classification, the crypto package boundary, the logging API, the metrics policy,
resource limits. `[NEEDS RESEARCH]`: GC-pause measurement, QUIC per-stream
memory, descriptor-host write rate, refusal jitter, replay-cache persistence.
`[UNSOLVED]`: retiring a broken link version without a consensus document.

### What this section does NOT establish

- **No number here was measured on this system.** The 64 KiB circuit budget, the
  relay sizing table and the AEAD throughput arithmetic are planning figures from
  generic rates. The QUIC per-stream term is marked TBD precisely because
  guessing it would make the whole table wrong.
- **The language recommendation rests on a build constraint, not a benchmark.**
  If the CGO-free 7-platform release stops being required, the strongest argument
  against Rust disappears and the decision should be reopened, not defended.
- **The GC-pause timing channel is unquantified.** The allocation budget reduces
  it; nobody has shown by how much.
- **R-10 is a property test, not a proof of canonicality.** It finds bugs its
  generators reach. No formal round-trip proof is attempted.
- **The `SECURITY.md`/code AEAD discrepancy is reported, not resolved.**
- **Nothing here validates that the storage layer survives the transport swap.**
  The three-minute shard fetch budget is sized for a cold I2P dial; what it
  should be over native QUIC is unknown until the transport exists.

---

## 20. Infrastructure APIs and CLI

**The finding: the API is where the anonymity contract is enforced or silently
lost, and two rules carry most of that weight.** First, the traffic class is a
required argument with no usable zero value on every call that creates traffic
(R2), so the latency/analysis trade is never made by a default. Second, no L8
call accepts or returns an IP address, a relay identity on a live path, or a wire
circuit id — the Constitution's layering rule ("no layer above L4 may see an IP
address") is enforced by the type signatures rather than by discipline. A caller
that cannot name a hop cannot leak one.

Signatures are Go, per §19.2. The wire form is the deterministic record encoding
of §19.4 over a length-prefixed framing on the socket of §20.4.

### 20.1 What already exists

| Thing | Path | Relevance |
|---|---|---|
| A loopback operator API with a bearer token | `internal/channel/api.go` | The closest analogue. `NewAPI` refuses to exist without a token (`ErrNoAPIToken`), and its own comments call a single shared token a **placeholder** for an undecided design ("roadmap D2"), with no read/write split. §20.4 decides it. |
| Intent-not-state discipline | `internal/channel/api.go:18-34` | "A caller states an intent, never a state." Carried forward: no L8 call accepts a circuit, a path, a hop or a key. |
| Three-outcome result | `internal/channel/api.go:35-42` | `completed` / `rejected` / `unknown`, with `unknown` an honest answer rather than an error to smooth over. Adopted in §20.6. |
| Error-to-status mapping | `internal/channel/api.go:141-165` | Existing taxonomy shape, including the note that a correctly-refused replay reported as a server error pushes operators to investigate an outage that never happened. |
| Loopback-default binding | `internal/config/config.go:549`, `:735-739`, `:778-794`, `:1087` | `S3Listen: "127.0.0.1:9000"`; `ListenIsLoopback`; a non-loopback dashboard needs a ≥12-character password and `0.0.0.0`/`::` are refused with or without one. |
| CLI shape | `cmd/syndichan-node/main.go`, `headless.go` | One `-config` flag plus a small headless set. There is no subcommand tree today; §20.7 is new. |
| S3 and DCS HTTP surfaces | `internal/s3api/`, `cmd/syndichan-node/dcsapi.go` | Product APIs, out of scope (Constitution §8). Listed so nobody ports them by accident. |

**What must be replaced:** the bearer-token-only authorization model, and the
HTTP/TCP transport.

### 20.2 Shared types and the two invariants

```go
package axon

// Class is the R2 traffic class. There is deliberately no zero value meaning
// "default": ClassUnset on a traffic-creating call returns ErrClassRequired.
type Class uint8
const (
    ClassUnset       Class = 0
    ClassInteractive Class = 1 // no cover traffic, best-effort padding, explicitly
                               // vulnerable to end-to-end correlation
    ClassBulk        Class = 2 // batched, padded, higher latency
)

type (
    Name      string   // "alice.lab.axon"; IDNA-processed at L7
    DomainID  [32]byte // Ed25519 public key of a DomainIdentity
    ServiceID [32]byte // Ed25519 public key of a ServiceIdentity
    NodeID    [32]byte // Ed25519 public key of a NodeIdentity
    RoutingID [32]byte // epoch-scoped RoutingIdentity
    SessionID uint64   // process-local handles, unrelated to any wire identifier
    StreamID  uint64
    TunnelID  uint64
    KeyRef    string   // names a key the daemon holds; private keys never cross the API
    IsolationKey string // streams from different contexts never share a tunnel
)
type ContentID struct { Root [32]byte; Size uint64 } // BLAKE3 root of the chunk tree
```

**Invariant 1 — no path information crosses L8.** No type here can hold an IP
address, a `RoutingID` on a live path, or a wire circuit id. This is why
`ResolveService` returns an intro-point *count* and never intro-point
identities: an API client has no use for them, and returning them makes every
API client a place where a service's intro points can be enumerated and logged.

**Invariant 2 — the daemon holds the keys.** `PublishService` takes a `KeyRef`;
`RegisterDomain` takes an `OwnerRef` that may name an external or offline signer.
A compromised API client can misuse a key; it cannot copy one.

### 20.3 The L8 call surface

```go
// ---- Naming (L7) ----------------------------------------------------------
func (c *Client) Resolve(ctx context.Context, r ResolveRequest) (ResolveResult, error)
type ResolveRequest struct {
    Name         Name
    RecordType   RecordType    // Service | Content | Delegate | Text
    Class        Class         // REQUIRED: a client lookup always traverses a circuit (R4b)
    MaxStaleness time.Duration // R7 freshness bound; 0 = daemon policy (default 6h)
}
type ResolveResult struct {
    Name Name; Domain DomainID; Records []Record
    SnapshotRoot [32]byte
    SnapshotAge  time.Duration     // R7: the resolver MUST say how stale it is
    ChainBlock   uint64
    Verified     VerificationLevel // SnapshotVerified | ChainVerified
    ValidUntil   time.Time
}

func (c *Client) ResolveService(ctx context.Context, r ResolveServiceRequest) (ServiceEndpoint, error)
type ResolveServiceRequest struct {
    Name Name; Service ServiceID // exactly one
    Class Class                  // REQUIRED
    MaxStaleness time.Duration
}
type ServiceEndpoint struct {
    Service ServiceID; Revision uint64
    PublishedAt, ValidUntil time.Time
    IntroPoints  int        // COUNT ONLY — never identities (Invariant 1)
    AuthRequired bool
    PoWRequired  *PoWParams // R10: the puzzle a client must solve
}

// ---- Services (L5/L6) -----------------------------------------------------
func (c *Client) PublishService(ctx context.Context, r PublishServiceRequest) (PublishServiceResult, error)
type PublishServiceRequest struct {
    Service     KeyRef           // ServiceIdentity held by the daemon
    Class       Class            // REQUIRED; ClassBulk expected
    IntroPoints int              // 0 = daemon default (3)
    Ports       []PortMap        // virtual port -> local unix path or 127.0.0.1:port
    Auth        ClientAuthPolicy // AuthOpen | AuthAllowlist([]ed25519.PublicKey) | AuthToken
    PoW         PoWPolicy        // PoWOff | PoWFixed(difficulty) | PoWAdaptive
    TTL         time.Duration    // 0 = descriptor lifetime 3h, republished hourly
}
type PublishServiceResult struct {
    Service ServiceID
    Address string // base32(pubkey) + "." + TLD — self-certifying
    Revision uint64
    PublishedAt, NextRepublish time.Time
}
func (c *Client) UnpublishService(ctx context.Context, s ServiceID, reason string) error

// ---- Tunnels (L4) ---------------------------------------------------------
func (c *Client) CreateTunnel(ctx context.Context, r CreateTunnelRequest) (TunnelInfo, error)
type CreateTunnelRequest struct {
    Direction TunnelDirection // Inbound | Outbound
    Class     Class           // REQUIRED
    Hops      int             // 0 = default 3; 2..4 permitted
    AllowWeak bool            // MUST be true for Hops == 2, else ErrHopsOutOfRange
    Isolation IsolationKey    // zero value derives from the caller's credential
    Purpose   TunnelPurpose   // General | Descriptor | Rendezvous | Storage
}
type TunnelInfo struct {
    Tunnel TunnelID; Direction TunnelDirection; Hops int
    Class Class; Purpose TunnelPurpose
    State TunnelState            // Building | Ready | Degraded | Closing | Dead
    BuiltAt, ExpiresAt time.Time // 10 min lifetime, rebuild at 70 %
    Isolation IsolationKey
}
func (c *Client) DestroyTunnel(ctx context.Context, t TunnelID, reason string) error
func (c *Client) ListTunnels(ctx context.Context, f TunnelFilter) ([]TunnelInfo, error)

// ---- Sessions and streams (R9) --------------------------------------------
func (c *Client) OpenSession(ctx context.Context, r OpenSessionRequest) (SessionInfo, error)
type OpenSessionRequest struct {
    Name Name; Service ServiceID // exactly one
    Class     Class              // REQUIRED; every stream inherits it
    Isolation IsolationKey
    Auth      *ClientCredential
    Keepalive time.Duration
}
type SessionInfo struct {
    Session SessionID; Target ServiceID; Class Class
    State SessionState // Connecting | Established | Reconnecting | Closed
    OpenedAt time.Time; Streams int
    Migrations uint32 // how many times the underlying circuit was replaced
}
func (c *Client) CloseSession(ctx context.Context, s SessionID, reason string) error
func (c *Client) OpenStream(ctx context.Context, r OpenStreamRequest) (Stream, error)
type OpenStreamRequest struct { Session SessionID; Port uint16; Deadline time.Time }
type Stream interface {
    io.ReadWriteCloser
    ID() StreamID; Session() SessionID
    CloseWrite() error; Stats() StreamStats
}
func (c *Client) CloseStream(ctx context.Context, s StreamID, reason string) error
```

A stream has no `Class` field, deliberately: it inherits the session's. Mixing
`INTERACTIVE` timing and `BULK` padding on one session forfeits both properties
and leaves no honest way to describe what the caller got.

```go
// ---- Content (L6) ---------------------------------------------------------
func (c *Client) PublishContent(ctx context.Context, r PublishContentRequest) (PublishContentResult, error)
type PublishContentRequest struct {
    Data        io.Reader
    Size        uint64           // required when Data is not seekable
    Class       Class            // REQUIRED; ClassInteractive returns ErrClassRefused
    Replication int              // 0 = policy default r=8 across distinct /24, /48, ASN
    Tier        AvailabilityTier // TierBestEffort | TierContracted (R8)
    TTL         time.Duration
}
type PublishContentResult struct {
    Content ContentID
    Key     [32]byte         // the caller MUST store this; the daemon does not (R5)
    Shards, Holders int
    Contract *StorageContract // nil for TierBestEffort
}

func (c *Client) RetrieveContent(ctx context.Context, r RetrieveContentRequest) (io.ReadCloser, ContentMeta, error)
type RetrieveContentRequest struct {
    Content ContentID
    Key     *[32]byte  // nil returns ciphertext
    Class   Class      // REQUIRED
    Range   *ByteRange
}
```

There is no `Verify bool`. Verification against the BLAKE3 tree is
unconditional and there is no API to retrieve unverified content: the Bao
structure makes chunk-level verification free, so an opt-out is a footgun with
no upside.

```go
// ---- Domains (L7 + chain plane) -------------------------------------------
func (c *Client) RegisterDomain(ctx context.Context, r RegisterDomainRequest) (RegistrationHandle, error)
type RegisterDomainRequest struct {
    Name     Name
    Owner    OwnerRef      // OwnerLocal(KeyRef) | OwnerExternal(signer) | OwnerOffline
    Domain   KeyRef        // the DomainIdentity to bind
    Duration time.Duration // rounded up to the registry period
    Commit   CommitPolicy  // CommitReveal (default) | Immediate (explicit only)
    MaxFee   *big.Int      // wei ceiling; the call fails rather than overpay
    Class    Class         // REQUIRED for the overlay-side announcement
    // AcknowledgeChainLinkage must be true. R6: registration links the name to a
    // funded account and the roadmap does not solve funding-graph linkage. The API
    // refuses to let a caller acquire a name without recording that they were told.
    AcknowledgeChainLinkage bool // else ErrChainLinkageNotAcknowledged
}
type RegistrationHandle struct {
    Name Name
    Phase RegistrationPhase // Committed | RevealPending | Confirmed | Failed
    CommitTx, RevealTx *TxRef
    RevealAfter, ExpiresAt time.Time
}
func (c *Client) RenewDomain(ctx context.Context, r RenewDomainRequest) (RegistrationHandle, error)
func (c *Client) TransferDomain(ctx context.Context, r TransferDomainRequest) (RegistrationHandle, error)
func (c *Client) GetDomainOwner(ctx context.Context, r GetDomainOwnerRequest) (DomainOwner, error)
type DomainOwner struct {
    Name Name; Owner [20]byte // Ethereum address — public on-chain data
    Domain DomainID; ExpiresAt time.Time
    Source OwnerSource // SnapshotVerified | ChainVerified
    SnapshotAge time.Duration; ChainBlock uint64
}

// ---- Payments (accounting plane; OFF in v1 per R11) -----------------------
func (c *Client) CreatePayment(ctx context.Context, r CreatePaymentRequest) (PaymentHandle, error)
type CreatePaymentRequest struct {
    Counterparty PaymentPeer
    Amount       Amount         // integer units of a named asset; never a float
    Purpose      PaymentPurpose // RelayCredit | StorageContract | ServiceFee
    Class        Class          // REQUIRED; control plane, ClassBulk expected
    Tokens       *TokenRequest  // R11: blind-signed unlinkable token issuance
    Deadline     time.Time
}
type PaymentHandle struct {
    Payment PaymentID
    Outcome PaymentOutcome // Completed | Rejected | Unknown — the three-outcome
                           // model already in internal/channel/api.go
    Reason string          // set only for Rejected
    SettledAt *time.Time
}
func (c *Client) SettlePayment(ctx context.Context, r SettlePaymentRequest) (SettlementResult, error)
```

Both payment calls exist and return `ErrNotEnabled` unless the accounting plane
is compiled in and configured on. The network must work with zero payments (R11),
so "payments are off" has to be an ordinary typed answer rather than a missing
method.

```go
// ---- Nodes, status, events, capabilities ----------------------------------
func (c *Client) QueryNode(ctx context.Context, r QueryNodeRequest) (NodeInfo, error)
type QueryNodeRequest struct {
    Node   NodeID // zero value = this node
    Class  Class  // REQUIRED when Node is not this node
    Fields NodeFieldMask
}
type NodeInfo struct {
    Node NodeID; Routing RoutingID // current epoch only
    Capabilities Capability        // Relay | DHTStore | IntroPoint | Rendezvous | StorageHolder
    Bandwidth BandwidthClaim       // self-reported, bounded by bonded stake (R14)
    Bond *BondInfo; Descriptor DescriptorMeta; LastSeen time.Time
    // Addresses is populated ONLY for a self-query by a caller holding CapAdmin.
    // A CapClient caller never learns any node's address, including this one's.
    Addresses []string
}

func (c *Client) Status(ctx context.Context) (Status, error)
type Status struct {
    Version string; Roles Capability
    Uptime time.Duration      // rounded to the minute
    Reachability Reachability // Unknown | Unreachable | ReachableV4 | ReachableV6 | Both
    Guards GuardSummary       // counts and health; identities only under CapAdmin
    Tunnels TunnelSummary     // counts by state, bucketed as in §19.8
    DHT DHTSummary; Storage StorageSummary; Accounting AccountingSummary
    Chain ChainSummary        // snapshot root, snapshot age, light-client head
    Warnings []Warning        // every unsafe setting currently in force
}

func (c *Client) Subscribe(ctx context.Context, r SubscribeRequest) (<-chan Event, func(), error)
type SubscribeRequest struct {
    Topics []Topic // Tunnel | Session | Descriptor | Domain | Storage | Accounting | Health
    Since  uint64  // resume from a sequence number; 0 = now
}
type Event struct { Seq uint64; At time.Time; Topic Topic; Body any }

func (c *Client) Capabilities(ctx context.Context) (CapabilitySet, error)
func (c *Client) SetCapabilities(ctx context.Context, r SetCapabilitiesRequest) error // R3
```

Events never carry hop information: a `TopicTunnel` event reports
`(TunnelID, State)` and nothing else. An event saying "extended to relay X"
would hand a compromised API client a complete path oracle — the same disclosure
§19.8 forbids in logs. Under `CapDebug` the daemon emits richer tunnel events and
simultaneously raises a `Status.Warning` for as long as a debug subscriber is
attached.

### 20.4 API transport and authorization

**Decision: a Unix domain socket, peer-credential authenticated, with a
capability granted per connection. Not a TCP port, not by default, not with a
token.** `[BUILD NOW]`

```text
/run/axond/axond.sock        system service, owner axond:axon, mode 0660
$XDG_RUNTIME_DIR/axon/sock   user instance, mode 0600
Windows                      named pipe with an explicit DACL
```

**Why it must not be a network-listening port**, in order of weight:

1. **A browser can reach `127.0.0.1`; it cannot reach a Unix socket.** A hostile
   page can issue cross-origin requests to a loopback port, and DNS rebinding
   defeats origin checks resting on the `Host` header. On a TCP L8 API a visited
   page could attempt "open a stream to `X.axon`" or "publish this content" from
   the victim's own daemon. This is decisive and not hypothetical.
2. **Peer credentials beat tokens.** `SO_PEERCRED` (Linux) and `LOCAL_PEERCRED`
   (BSD/macOS) give the kernel's own answer for the caller's uid, gid and pid. A
   token can be read from a file, an environment variable, a process listing or a
   backup; a uid cannot be presented by a process that lacks it. The existing
   `internal/channel/api.go` uses a shared bearer token and its own comment calls
   that a placeholder for an undecided design — this is the decision.
3. **Filesystem permissions are an authorization model the OS already enforces**
   and auditors already understand: group `axon` grants client access, ownership
   grants admin.
4. **A listening port is a fingerprint.** On shared hosting, scanning loopback
   enumerates AXON nodes and versions.
5. **The repository already learned this.** `config.go:778-794` refuses
   `0.0.0.0` and `::` for the dashboard with or without a password, because such
   a bind also captures whatever public interface the machine acquires later.

| Capability | Granted to | May do |
|---|---|---|
| `CapClient` | Any process in group `axon` | resolve, resolve_service, sessions, streams, retrieve_content, get_domain_owner, redacted status and events |
| `CapPublish` | Same uid as the daemon, or an explicit allowlist entry | publish_service, publish_content, create/destroy_tunnel |
| `CapWallet` | Same uid **and** the cookie | register/renew/transfer_domain, create/settle_payment |
| `CapAdmin` | Daemon owner uid **and** the cookie | set_capabilities, full status including guard identities and self addresses, detailed error reasons (§20.6) |
| `CapDebug` | `CapAdmin` plus an explicit config key | per-hop tunnel events; raises a persistent `Status.Warning` |

The cookie is 32 random bytes regenerated at each start, mode 0600, used **in
addition to** peer credentials and never instead: a leaked cookie without the uid
gets nothing, and the uid without the cookie gets nothing above `CapPublish`.

**The escape hatch and its price.** A container that genuinely cannot share a
socket may set `api_listen_tcp`. It then requires mutual TLS with a pinned client
certificate, is refused on any publicly routable address (reusing
`config.ListenIsLoopback` and the private-address predicate at `config.go:1087`),
and raises a permanent `Status.Warning`. There is no configuration in which it is
quieter than the socket.

### 20.5 The traffic class is a required argument

| Call | Class required | Refused classes | Note |
|---|---|---|---|
| `Resolve`, `ResolveService` | Yes | — | Lookups traverse a circuit (R4b) |
| `PublishService` | Yes | — | `ClassInteractive` permitted and warned |
| `CreateTunnel`, `OpenSession` | Yes | — | Binds every session/stream placed on it |
| `OpenStream` | No | — | Inherits the session's; overriding is not expressible |
| `PublishContent` | Yes | `ClassInteractive` → `ErrClassRefused` | Storage is BULK by construction |
| `RetrieveContent` | Yes | — | `ClassInteractive` allowed for small ranges, warned |
| `RegisterDomain`, `RenewDomain`, `TransferDomain`, `GetDomainOwner` | Yes | — | A local snapshot hit produces no traffic; the argument is still required so a cache miss is not a silent class choice |
| `CreatePayment`, `SettlePayment` | Yes | — | Control plane, off the critical latency path |
| `QueryNode` | Yes when `Node != self` | — | Self-query is local |
| `Status`, `Capabilities`, `Subscribe` | No | — | Local only |

`ClassUnset` on a required row returns `ErrClassRequired` before anything else is
validated, before any name is parsed, and before any traffic is generated. The
CLI mirrors this: `--class` has no default (§20.7).

### 20.6 Error model

Errors are `(Code, Message, Retryable, RetryAfter, Detail)`. `Code` is stable and
machine-readable; `Message` is a fixed compile-time string; `Detail` is populated
only for `CapAdmin`.

| Family | Codes |
|---|---|
| Argument | `ErrClassRequired`, `ErrClassRefused`, `ErrBadName`, `ErrBadContentID`, `ErrRangeInvalid`, `ErrHopsOutOfRange`, `ErrChainLinkageNotAcknowledged`, `ErrUnknownKeyRef` |
| Authorization | `ErrUnauthorized`, `ErrCapabilityRequired`, `ErrNotEnabled` |
| Resource | `ErrNoTunnel`, `ErrCircuitLimit`, `ErrBackpressure`, `ErrStorageFull`, `ErrRateLimited` |
| Liveness | `ErrTimeout`, `ErrDegraded`, `ErrSnapshotStale`, `ErrChainUnavailable` |
| Naming | `ErrNameNotFound`, `ErrNameExpired`, `ErrNoRecord`, `ErrUnsupportedRecordVersion` |
| Service | **`ErrServiceUnavailable`** (collapsed), `ErrServiceAuthRequired`, `ErrPoWRequired` |
| Content | `ErrContentNotFound`, `ErrInsufficientShards`, `ErrContentUnverifiable` |
| Session | `ErrSessionClosed`, `ErrStreamReset`, `ErrPortRefused` |
| Payment | `ErrNoFunds`, `ErrPaymentRefused`, `ErrPaymentUnknown` |
| Internal | `ErrInternal` |

**The non-distinguishing rule.** For a caller without `CapAdmin` these four are
one error, `ErrServiceUnavailable`:

```text
1. no descriptor published for this ServiceID
2. a descriptor exists, but the service refused this client's credential
3. a descriptor exists, but the intro point rate-limited this client
4. a descriptor exists, but the service is at capacity
```

If (2) were distinguishable from (1), a client-authorised service becomes
enumerable by anyone — an attacker learns "this exists and I am not on its list",
which is exactly what client authorisation exists to hide, and it turns the
descriptor DHT into a service directory. `ErrServiceAuthRequired` is returned
only when the descriptor itself advertises `AuthRequired` in the open: an
explicit operator choice to be discoverable-but-closed.

**Timing is part of the answer.** Collapsing four codes buys nothing if they take
visibly different times, so the four share a floor: the daemon computes the
outcome and waits until a fixed budget (default 750 ms, configurable, never zero)
has elapsed. This is genuinely partial — case (1) is also reachable by network
timeout, and a client timing many attempts can still separate the distributions;
raising the floor above the network timeout would make every failure slow.
`[NEEDS RESEARCH]` on the floor; `[UNSOLVED]` for full indistinguishability.

| Distinction kept | Why it is safe |
|---|---|
| `ErrNameNotFound` vs found | Registrations are on a public chain; hiding them buys nothing and costs every diagnostic |
| `ErrContentNotFound` vs `ErrContentUnverifiable` | The second is a fault report the repair loop needs (R8), and content is self-certifying, so there is no secret to protect |
| `ErrInsufficientShards` vs `ErrContentNotFound` | Separates "the network lost it" from "it never existed" — an availability measurement, not a privacy leak |
| `ErrPaymentUnknown` vs failed | The exchange may have completed; reporting it as failure invites a double payment. `internal/channel/api.go` already takes this position |

**Message rules.** No filesystem paths, no IP addresses, no peer identities, no
key material, no internal state, no stack traces, no wrapped library error
strings. `ErrInternal`'s message is the constant `"internal error"`; specifics go
to the log under §19.8's redaction rules and to `Detail` under `CapAdmin`.

### 20.7 The CLI

Binary `axon` (client), daemon `axond`. Global flags `--socket`, `--json`,
`--timeout`, `--quiet`, `--class` (no default; required by commands marked `†`).

```text
axon node
  status              roles, reachability, tunnel and DHT summaries, active warnings
  version             build version, protocol versions supported, link-version floor
  reachability        run the L2 reachability probe and report the verdict
  shutdown            stop gracefully, draining circuits rather than cutting them
  warnings            every unsafe setting in force, with the config key that set it

axon id
  new                 generate an identity (--kind node|service|domain|payment)
  list                identities held by the daemon, by kind and label
  show <ref>          public key, fingerprint, creation time, current blinding period
  export <ref>        export a PUBLIC key; private material is never exportable
  import              import an identity from a file (--kind; mode 0600 enforced)
  rotate <ref>        rotate a RoutingIdentity or DomainIdentity without losing reputation
  delegate            sign a delegation from a DomainIdentity to a ServiceIdentity
  revoke <ref>        publish a revocation for a delegated identity

axon relay
  enable              advertise the relay capability (R3); refuses if unreachable
  disable             stop advertising; existing circuits drain rather than break
  status              circuits carried (bucketed), bytes served, refusal counters
  bandwidth           show or set the advertised capacity bound
  bond                show or adjust the PoF stake backing that claim
  guards              guard set health; identities only with admin capability

axon service
  publish †           publish a descriptor and bind local ports
  unpublish           withdraw a descriptor and stop answering introductions
  list                services published here, with revision and next republish
  show <id>           descriptor metadata, auth policy, PoW policy, intro-point count
  republish †         force an immediate republication
  auth add|rm|list    manage the client authorisation allowlist
  open †              open a session to a service and forward it to a local address

axon domain
  register †          commit-reveal registration; needs --acknowledge-chain-linkage
  renew †             extend a registration before expiry
  transfer †          transfer ownership to another OwnerIdentity
  owner †             current owner, source of truth, and snapshot age
  records set|get|rm †  manage records signed by the DomainIdentity
  snapshot            registry snapshot root, age, and verification level

axon content
  put †               erasure-code, encrypt and disperse; prints the object key ONCE
  get †               retrieve and verify; verification is not optional
  info †              manifest, shard count, holder count, availability tier
  contract †          show or renew a storage contract (R8)
  repair †            trigger a repair pass for an under-replicated object
  holders †           holder count and diversity levels; never holder identities

axon tunnel
  list                tunnels by direction, purpose, class and state
  show <id>           hop count, class, age, expiry; never hop identities
  build †             build a tunnel eagerly into the pool
  destroy <id>        tear a tunnel down
  pool                pool occupancy per destination against the 3+3+1 target

axon dht
  get †               fetch a record by key and report its verification result
  providers †         provider-set size for a content key; counts, not identities
  routing-table       local routing table occupancy per bucket
  probe †             lookup latency and disjoint-path agreement

axon pay
  balance             accounting-plane balances; ErrNotEnabled in v1
  tokens              blind-signed token stock and issuance status (R11)
  create †            create a payment
  settle †            settle a batch off the critical path
  channels            payment channel states, from the existing SCPP/1 machinery

axon diag
  selftest            local checks: keys, clock skew, storage, socket permissions
  path †              which pool and class a target would use; no hop identities
  metrics             the local metrics snapshot, subject to the §19.8 policy
  logs                tail the daemon log with redaction already applied
  bugreport           bundle diagnostics with a redaction manifest

axon config
  show                effective configuration, secrets elided
  set <key> <value>   change a setting; unsafe keys require --i-understand
  validate            validate a config file without starting anything
```

Commands marked `†` require `--class INTERACTIVE|BULK`. There is no default and
no config key supplying one: a default would make the R2 trade implicit, which is
what R2 forbids.

### 20.8 Worked example

```console
# ---- on the service operator's node ---------------------------------------
$ axond --config /etc/axon/node.json
axond 0.1.0-dev  link versions 1  record versions 1
identity  node  9f3c1a2e…  (NodeIdentity)
socket    /run/axond/axond.sock  mode 0660 owner axond:axon
warning   accounting plane is disabled; relay credit will not accrue

$ axon node status
roles client,relay,dht-store   reachability reachable-v4   uptime 2m
guards   2 primary, 2 healthy, 0 probation
tunnels  outbound 3 ready / 1 spare, inbound 3 ready / 1 spare
chain    snapshot 0x7c4e…, age 41m, light-client head verified
warnings accounting disabled

$ axon id new --kind service --label wiki
created service wiki
pubkey  4d8a7f31c0be59a2d17e6b04c9f2a8531e7d0c46b98f2a10d3e5c7b91f60a284
address jwuh6mo…q5be.axon

$ axon service publish --key wiki --port 80=127.0.0.1:8080 \
      --intro 3 --pow adaptive --auth open --class BULK
publishing under blinded key for time period 20260815/00
descriptor revision 1  intro points 3  valid until 2026-08-15T18:42:00Z
address jwuh6mo…q5be.axon   next republish 2026-08-15T16:42:00Z

$ axon domain records set research.lab.axon SERVICE 4d8a…a284 --class BULK
signed by DomainIdentity c1f0…9ab2, ttl 3h, published to 8 replicas

# ---- on a client machine --------------------------------------------------
$ axon resolve research.lab.axon --class INTERACTIVE --json
{"name":"research.lab.axon","domain":"c1f0...9ab2",
 "records":[{"type":"SERVICE","value":"4d8a...a284"}],
 "snapshot_root":"0x7c4e...","snapshot_age":"38m","chain_block":25757314,
 "verified":"SnapshotVerified","valid_until":"2026-08-15T18:42:00Z"}

$ axon service open research.lab.axon:80 --forward 127.0.0.1:9080 --class INTERACTIVE
session 0x00000017 established, class INTERACTIVE
tunnels outbound 3 hops, inbound 3 hops, rendezvous joined
forwarding 127.0.0.1:9080 -> research.lab.axon:80
note: INTERACTIVE carries no cover traffic and is vulnerable to end-to-end
      correlation by an observer of both ends.

$ axon tunnel list
ID     DIR       PURPOSE     HOPS  CLASS        STATE  AGE    EXPIRES
0x0a1  outbound  rendezvous     3  INTERACTIVE  ready  0m12s  9m48s
0x0a2  inbound   rendezvous     3  INTERACTIVE  ready  0m12s  9m48s
0x0a3  outbound  general        3  BULK         ready  4m01s  5m59s

# the failure that may be specific, and the one that must not be:
$ axon resolve absent.axon --class INTERACTIVE
error: name-not-found: no registration for that name

$ axon service open jwuh6mo…q5be.axon:80 --class INTERACTIVE   # wrong credential
error: service-unavailable: the service could not be reached (retry after 60s)
```

A name that does not exist says so, because the registry is public. A service
that exists but refused you is indistinguishable from one never published.

### 20.9 Decision table

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Unix socket + peer credentials + cookie | A loopback TCP API is reachable by a hostile web page; a shared token is copyable | Tor's control port with cookie auth; I2P's I2CP | Peer credentials are primary, the cookie additive rather than alternative | TCP + bearer token (today's `internal/channel/api.go`); TCP + Basic auth | Any process running as the daemon's uid has full control; containers need extra plumbing |
| Class required on every traffic-creating call | The anonymity/latency trade must never be implicit (R2) | Neither exposes this to callers | Made un-defaultable at both API and CLI | A config default; a per-session default | Callers will pick `INTERACTIVE` reflexively; only the warning pushes back |
| No IPs, hop identities or wire circuit ids in any L8 type | A compromised API client must not become a path oracle | Tor's control port leaks far more by design | Enforced by the type system rather than policy | Full circuit introspection behind an admin flag | Debugging a path problem needs `CapDebug`, which itself raises a warning |
| Keys stay in the daemon; the API takes `KeyRef` | A copied key is permanent; a misused handle is revocable | Tor's `ADD_ONION` can accept a key; we do not | Handles only, in both directions | Passing private keys for ephemeral services | The daemon becomes the single point of key compromise |
| Collapse four service failures into one error | Distinguishable auth failure makes authorised services enumerable | Tor's onion-service errors are more granular | Added a shared timing floor so the cases are not separable by latency | Distinct codes; distinct codes for authorised callers | Operators lose diagnostics without `CapAdmin`; the timing floor is partial |
| `ErrPaymentUnknown` kept distinct | An exchange that may have completed must not be reported as failed | Neither | Adopted from `internal/channel/api.go` | Mapping unknown to failed | Callers must implement recovery, and some will not |
| Payment calls present but `ErrNotEnabled` in v1 | The network must work with zero payments (R11) | Neither | A typed "off" rather than a missing method | Omitting the calls until v2 | Invites callers to assume payments arrive on a schedule nobody committed to |
| `AcknowledgeChainLinkage` required to register | R6: funding-graph linkage is a residual risk we do not solve | Neither | An API-level acknowledgement instead of a documentation footnote | A config-wide acknowledgement; a warning only | Ritual compliance — callers will set it true without reading it |
| Stream class inherited, never overridden | Mixing classes on one session forfeits both properties | I2P pools have per-pool properties | Made inexpressible rather than discouraged | A per-stream class field | A caller needing both must open two sessions, costing two tunnel sets |
| `resolve_service` returns counts, not intro-point identities | An API client must not be able to enumerate a service's intro points | Tor descriptors carry intro points to the client's daemon | The daemon keeps them; the caller never sees them | Returning the full descriptor | A third-party resolver cannot be built on top of the API |

`[BUILD NOW]`: socket transport, capability model, the call surface, the error
taxonomy, the CLI tree. `[NEEDS RESEARCH]`: the timing floor for collapsed
errors; the right `IsolationKey` default on multi-user hosts. `[UNSOLVED]`:
making service existence genuinely unobservable under repeated timed probing.

### What this section does NOT establish

- **These are a surface, not a specification.** `Record`, `PoWParams`,
  `StorageContract` and `ClientCredential` are named here and defined by the L5,
  L6 and L7 sections that own them; their fields are not fixed here.
- **The timing-floor defence is partial and known to be so.** A client timing
  many attempts can still separate "not published" from "refused"; the floor
  raises the cost, it does not close the channel.
- **The capability model is not a sandbox.** Any process running as the daemon's
  uid can read the cookie and hold `CapAdmin`. Isolating a compromised publishing
  client needs OS-level separation this section does not design.
- **No wire encoding for the API is specified.** §19.4 fixes the record encoding;
  the request/response framing and its relation to the link version belong to the
  protocol package.
- **The CLI tree is not costed.** `content repair`, `dht probe` and `diag path`
  depend on subsystems other sections own and may not be buildable in the phase
  where the CLI first ships.
- **Nothing here has been run.** The transcript is illustrative; no output shown
  was produced by executing code.

> **Objection to Constitution §5 (content chunk size):** the table gives 256 KiB
> and asks for confirmation against the existing store. The existing default is
> `ChunkBytes = 1 << 20` (1 MiB), validated over a 64 KiB–16 MiB range, with
> RS 6+3 (`internal/config/config.go:572-574`, `:817-821`). Moving to 256 KiB
> quadruples shards per object and therefore the placement-ledger and DHT
> provider-record load, which the storage section should cost before the number
> is fixed. §19 reports both values rather than silently adopting either.
