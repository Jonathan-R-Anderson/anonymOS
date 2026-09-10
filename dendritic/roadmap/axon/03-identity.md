## 5. Cryptographic Identity System

> **AS BUILT (2026-08-16).** `internal/axon/identity` + `internal/axon/params`,
> 23 tests. **P1 complete** — T1.1–T1.5, E1.1, E1.2 all discharged, including
> scalar-arithmetic verification of the Ed25519 blinding. Nothing in this section
> is outstanding.

**The finding that shapes this section: the existing node has one key doing six
jobs.** `p2p.key` is simultaneously the libp2p transport identity, the DHT
routing identity, the Proof-of-Facilitation node id
(`keccak256(raw ed25519 pubkey)`, `internal/p2p/challenge.go:125`), the receipt
signer (`internal/facilitation/receipt.go`), the payout-declaration signer
(`internal/facilitation/payout.go`), and the input the controller uses to assign
a gateway its `gw-<node-id>` hostname. On the clearnet that is convenient; on an
anonymity overlay it is a free correlation. Anyone who sees a relay forward a
cell, a receipt get settled and a bond get posted learns they are one machine,
and the anonymity of a service hosted there is gone before traffic analysis
begins.

The identity system's job is therefore not secrecy — Ed25519 and X25519 supply
that — but **unlinkability by construction**: eight key classes, no two ever the
same key, every relationship between them either a one-way hash or an explicitly
signed, scoped, expiring delegation (Constitution §3). One invariant governs the
rest:

> **R-ID1 — every binding edge is signed at both ends.** The issuer signs to
> authorise the binding, the subject countersigns to prove the key exists and
> consented. A one-sided binding lets an attacker graft someone else's key — and
> with it their reputation, bond or descriptor history — under their own identity.

### What already exists

| Existing | File | What it establishes |
|---|---|---|
| Ed25519 node key, protobuf-marshalled, `p2p.key`, mode 0600 | `internal/p2p/node.go:731` (`loadOrCreateIdentity`) | The persistence convention: create-on-first-run, 0600, beside the data dir. |
| Same format, no networking | `internal/gateway/identity.go` (`LoadOrCreateFileIdentity`) | `dataDir` 0700, `p2p.key` 0600, `Sign`/`PublicKey` surface. |
| X25519 key, raw 32 bytes, `content.key`, mode 0600 | `internal/p2p/contentkey.go` | The codebase **already separates signing from key agreement** — the comment says the Ed25519 identity "cannot be used for that because it is a signing key, not an ECDH key". That is R-ID1's smaller cousin, already accepted. |
| I2P destination private key, `i2p.destination`, `O_EXCL` create, chmod 0600 on load | `internal/i2p/sam.go:187` (`loadOrCreateDestination`) | The strongest file-handling precedent in the tree: refuse to silently mint a new identity, force the mode on every load. |
| Raw Ed25519 escape hatch with a warning | `internal/p2p/node.go` (`SigningKey`) | "must never be logged, written outside `p2p.key`, or sent anywhere". The libp2p protobuf form hashes to a *different* value than the raw form, which is why the raw accessor exists. |
| Canonical record hashing | `internal/facilitation/receipt.go` (`CanonicalReceiptHash`) | Flat big-endian concatenation, fixed field order, no length prefixes, no padding, keccak256, pinned by a golden vector across two repositories. §5.2 copies this discipline. |
| ASCII domain-separated signed records | `internal/facilitation/register.go` (`syndichan-pof-register:v1`), `internal/gateway/snapshot.go` (`syndichan-revocation:v1`, `syndichan-defensive:v1`) | The house label convention: `syndichan-<purpose>:v1`, newline-joined fields. AXON keeps the shape and changes the prefix. |
| Data-dir layout | `README.md`, systemd section | "The node writes `i2p.destination`, `p2p.key` and `content.key` beside `storage/`" — the paths are load-bearing enough that a wrong `ReadWritePaths=` is documented as a startup failure. |

**There is no key-derivation hierarchy in the existing code at all** — a grep for
HKDF returns only Ethereum's BLS domain-separation tag (`internal/ethproof/bls.go`).
Every key is independently generated and persisted. §5.3 introduces the first
derivation tree in this codebase.

### What must be replaced

1. **The one-key-many-jobs consolidation** → NodeIdentity, RoutingIdentity,
   KadID (derived), PaymentIdentity.
2. **The libp2p protobuf key file** → raw 32-byte seeds (§5.7). A one-shot
   migration reads `p2p.key`, unmarshals, writes the same seed to `node.key`, so
   the PoF node id, bond and reputation survive unchanged.
3. **`i2p.destination` as the anonymous address** → ServiceIdentity plus the
   self-certifying `.axon` address (§5.8). The 52-character `.b32.i2p` host is
   prior art for that encoding and nothing more.
4. **`content.key`'s absent rotation** — a long-term X25519 key with no forward
   secrecy and no rotation path; see the row in §5.5.

### 5.0 The eight classes

Table A — key material and encoding.

| Class | Primitive | Generation | Public serialization (exact) | Human encoding |
|---|---|---|---|---|
| **OwnerIdentity** | secp256k1 | Wallet/HSM, outside AXON | 20 B Ethereum address = `keccak256(uncompressed_pub[1:])[12:]` | EIP-55 checksummed hex, `0x…` (40 hex chars) |
| **DomainIdentity** | Ed25519 | `csprng → 32 B seed`; `A = a·B` per RFC 8032 | 32 B raw compressed point, little-endian y with sign bit | `axondom:` + 56-char base32 (§5.8, version `0x02`); normally shown as the name itself |
| **ServiceIdentity** | Ed25519 | as above | 32 B raw | `<56-char base32>.axon` (§5.8, version `0x01`) |
| **NodeIdentity** | Ed25519 | as above; migrated from `p2p.key` | 32 B raw | `axonnode:` + 56-char base32 (version `0x03`) |
| **RoutingIdentity** | Ed25519 **+** X25519 | both derived from the node master seed per epoch (§5.3) | 32 B Ed25519 ‖ 32 B X25519, in that order, inside the RelayDescriptor | not shown to humans; it is an internal, epoch-scoped handle |
| **KadID** | none — a hash | `SHA-256("AXON-kadid-v1" ‖ 0x00 ‖ node_pub ‖ SRV_epoch ‖ net_prefix)` | 32 B | first 8 hex chars in logs, matching existing node-id logging |
| **ContentIdentity** | none — a hash | BLAKE3 root of the Bao chunk tree | 32 B root, exposed as a CIDv1 multihash | standard CID text form (§10) |
| **PaymentIdentity** | secp256k1 (settlement) + blinded token keys | wallet for settlement; tokens minted per §14 | 20 B address; tokens are opaque | `0x…` for settlement; tokens never displayed |

Table B — lifecycle.

| Class | At rest | Lifetime | Rotation | Revocation | Compromise recovery |
|---|---|---|---|---|---|
| **OwnerIdentity** | Hardware wallet / multisig; never in the data dir | Indefinite | Chain transfer of the name to a new owner | None — the chain *is* the revocation | Recover only if a multisig quorum survives. Single-key loss is terminal for that name. |
| **DomainIdentity** | `domain.key`, 0600 — preferably on an air-gapped host (§5.7) | 1–2 years | IdentityRotation record (§5.2), anchored on-chain, overlap ≥ max snapshot staleness | Revocation record; authoritative form is an on-chain event | OwnerIdentity commits a new DomainIdentity on-chain; resolvers converge at snapshot TTL (R7) |
| **ServiceIdentity** | `service/<label>.key`, 0600 | Indefinite — it *is* the address | Not rotatable in place: rotation changes the address. A DelegationCertificate from DomainIdentity to a new ServiceIdentity is how a *name* moves | Revocation by the delegating DomainIdentity, or self-revocation | If the name is registered: re-delegate, minutes. If the fallback address was published: the address is lost, permanently. |
| **NodeIdentity** | `node.key`, 0600 | Years | IdentityRotation, countersigned; bond and reputation follow the chain of rotations | Self-revocation or bond-slash event | Rotate, re-bond. Reputation transfer across a compromise rotation is `[NEEDS RESEARCH]` — see §15. |
| **RoutingIdentity** | `routing/<epoch>.key`, 0700 dir; derived, so re-derivable from `node.key` | 1 epoch (24 h) + 2 h publish lead | Automatic, per epoch, no record needed beyond the new RelayDescriptor | Implicit at epoch end; explicit Revocation for early kill | Wait one epoch, or publish a Revocation and a fresh descriptor. Cheapest recovery in the system. |
| **KadID** | Not stored | 1 epoch | Automatic with SRV | N/A | N/A |
| **ContentIdentity** | Not stored as a key | Immutable | N/A — a new object is a new identity | N/A | N/A (a compromised *content key* is §10's problem, not an identity problem) |
| **PaymentIdentity** | `payment.key`, 0600, or external wallet | Per §14 | Per §14 | Per §14 | Per §14 |

Three of the eight are not keypairs, and treating them as keys is the commonest
way this taxonomy gets built wrong: KadID is a *position*, ContentIdentity a
*hash of data*, PaymentIdentity a *pair* of unrelated mechanisms. Only five
classes have a private key that can be stolen.

### 5.1 The identity graph

```text
CHAIN PLANE   OwnerIdentity   secp256k1. Never appears on the overlay.
                     │ E1  on-chain tx carries the DomainIdentity pubkey;
                     │     DomainIdentity countersigns off-chain (R-ID1
                     ▼     holds on-chain too)
NAMING        DomainIdentity   Ed25519, offline root
                     │
        ┌────────────┼──────────────────────┐
        │ E2 signs   │ E3 DelegationCert     │ E3'  (scoped, expiring)
        ▼            ▼                       ▼
  name record   ServiceIdentity          OnlineSigner  sub_delegate = 0
  set (offline)       │
                      │ H1  A' = h·A , h = HKDF-SHA256(A ‖ period)
                      │     forward-computable by anyone who KNOWS A;
                      ▼     not invertible by anyone who does not
              BlindedDescriptorKey   one per 24 h time period
                      │ E4  certifies, ≤3 h
                      ▼
              DescriptorSigningKey ─► descriptor in the DHT at
                      H2  index = SHA-256(label ‖ A' ‖ SRV ‖ period_number)

DATA PLANE    (must never be linkable to anything above this line)
        NodeIdentity   Ed25519, long-lived, deliberately PUBLIC
              │ │ └── H3  nodeId = keccak256(pub)   [existing, PoF + bond]
              │ └──── H4  KadID  = SHA-256(label ‖ pub ‖ SRV ‖ prefix)
              │ E5  RelayDescriptor: NodeIdentity signs the binding to this
              ▼     epoch's RoutingIdentity, which countersigns
        RoutingIdentity   Ed25519 (auth) + X25519 (agreement), epoch-scoped
              │ H5  per-hop keys = HKDF-SHA256(ntor-style shared secret)
              ▼
        circuit hop keys   ephemeral, zeroized at teardown (≤10 min)

CONTENT   ContentIdentity = BLAKE3 root of the chunk tree. A hash of DATA, with
          no edge to any key; it enters this graph only as a field inside a
          manifest that a DomainIdentity or ServiceIdentity signs.

ACCOUNT   PaymentIdentity — NO EDGE to RoutingIdentity or NodeIdentity, by
          construction (R11). An edge here is a de-anonymisation channel, and
          adding one is a design error rather than a trade-off.
```

Edge table. "Both ends" is R-ID1.

| Edge | From → To | Mechanism | Verified by | If forged |
|---|---|---|---|---|
| E1 | Owner → Domain | On-chain registry entry + off-chain Ed25519 possession proof | Light client + snapshot (§12, §13) | Attacker owns the name; only the chain can undo it |
| E2 | Domain → records | Ed25519 signature, label `AXON-record-v1` | Any resolver, offline | Wrong records served for a real name |
| E3 | Domain → Service | DelegationCertificate, both ends sign | Any client with the domain's key | Attacker's service answers for a real name |
| E4 | Blinded → DescSigning | Ed25519 certificate, ≤3 h | Client that computed A' | Descriptor substitution within the period |
| E5 | Node → Routing | RelayDescriptor, both ends sign | Any peer, from the DHT | Attacker attracts circuits under a bonded node's reputation |
| H1 | Service → Blinded | Scalar blinding (§5.4) | Recomputable by anyone holding A | Not forgeable without `a`; see §5.4's honest limit |
| H2 | Blinded → DHT index | SHA-256 | Every DHT node | Descriptor stored where clients will not look (DoS, not impersonation) |
| H3 | Node → nodeId | keccak256 (existing) | On-chain `NodeRegistry` | Preimage resistance of keccak256 |
| H4 | Node → KadID | SHA-256 with SRV | Every peer | Eclipse; this hash is the anti-eclipse mechanism (R4, §7) |
| H5 | shared secret → hop keys | HKDF-SHA256 | Both circuit endpoints | Circuit compromise, bounded to that circuit |

The three edges that are deliberately **absent** are as important as the ten that
exist: Service ↮ Node (a service must not reveal which machine hosts it),
Payment ↮ Routing (R11), and Owner ↮ anything on the overlay (R6).

### 5.2 Record formats

Encoding rules, borrowed wholesale from `CanonicalReceiptHash`:

- All integers big-endian, times `u64` Unix seconds, no padding or alignment.
- **Exactly one valid encoding per record.** A verifier re-serialises what it
  parsed and rejects it if the bytes differ — this kills signature malleability
  and parser-differential attacks in one rule.
- Signature input is `label_ascii ‖ 0x00 ‖ record_bytes_so_far`; no label
  contains a NUL. Labels are in §5.3.

```text
off len field       — the 8-byte header every record starts with
0   4   magic      "AXN1"
4   1   rtype      0x01 RelayDescriptor · 0x02 IdentityRotation
                   0x03 Revocation      · 0x04 DelegationCertificate
5   1   version    0x01
6   2   body_len   u16, bytes of body after this header, signatures excluded
```

#### RelayDescriptor (rtype 0x01)

```text
off  len  field                   notes
  0    8  header                  rtype 0x01
--- body, body_len counts from here ---
  0   32  node_identity_pub       Ed25519, raw
 32   32  routing_identity_pub    Ed25519, raw, epoch-scoped
 64   32  routing_x25519_pub      X25519, raw
 96    1  pq_suites               bit0 X25519 · bit1 X25519+ML-KEM-768 (§5.6)
 97    1  link_versions           bitmap, §6 owns the assignment
 98    4  capabilities            u32: bit0 relay · 1 guard-eligible · 2 intro
                                  3 rendezvous · 4 dht-server · 5 storage
                                  6 exit-to-service-only · 7..31 reserved zero
102    4  bw_claim_kibps          u32, self-reported ceiling
106    4  bw_receipted_kibps      u32, backed by delivery receipts; 0 if none
110    8  epoch                   u64, epochs since UTC 1970-01-01
118    8  valid_after             u64 unix
126    8  valid_until             u64 unix; valid_until − valid_after ≤ 93 600 s
134    8  bond_chain_id           u64 (EIP-155)
142   20  bond_contract           Ethereum address of the StakeVault
162   16  bond_amount_wei         u128
178    8  bond_valid_until        u64 unix
186    4  as_number               u32, self-declared; §7 cross-checks it against
                                  observed addresses for diversity (R14)
190    1  addr_count              u8, ≤ 8
191   ..  addresses[]             kind u8 · len u8 · value; kind 1 = IPv4 len 6,
                                  2 = IPv6 len 18 (addr ‖ u16 port BE),
                                  3 = DNS len 3..255 (u8 hostlen ‖ host ‖ port)
  ..   1  ext_count               u8
  ..  ..  extensions[]            type u16 · len u16 · value; type high bit set
                                  = critical, reject if unknown
--- signatures, not counted in body_len ---
  ..  64  sig_node                by node_identity_pub, label
                                  "AXON-relaydesc-node-v1", over header ‖ body
  ..  64  sig_routing             by routing_identity_pub, label
                                  "AXON-relaydesc-routing-v1", over
                                  header ‖ body ‖ sig_node
```

Body fixed prefix is 191 bytes. A descriptor with one IPv4 (8 B) and one IPv6
(20 B) address and no extensions has `body_len = 220` and a **total wire size of
356 bytes**. The PoF node id is not carried: it is `keccak256(node_identity_pub)`,
and a derivable field that is also transmitted is a field that can disagree.

Validation, in order: magic and version; re-serialise check;
`valid_until > valid_after` within the ≤26 h window; `epoch` consistent with
`valid_after`; both signatures; `bw_claim_kibps` within the cap
`bond_amount_wei` supports (§15 owns the curve); `bond_valid_until ≥ valid_until`;
no cached revocation for either key. Failure drops the record without a reply —
a distinguishing error message is a probe oracle.

#### IdentityRotation (rtype 0x02)

```text
off  len  field
  0    1  class            1 Domain · 2 Service · 3 Node · 4 Routing
  1   32  old_pub
 33   32  new_pub
 65    8  sequence         u64, strictly increasing per old_pub
 73    8  effective_at     u64 unix
 81    8  old_valid_until  u64 unix; old_pub still verifies until this
 89    1  reason           0 scheduled · 1 suspected compromise
                           2 hardware change · 3 policy
 90    2  anchor_len       u16
 92   ..  anchor           chain reference: chain_id u64 ‖ block_number u64 ‖
                           log_index u32 ‖ topic0 32 B  (52 B), or empty
--- signatures ---
      64  sig_old          by old_pub, label "AXON-rotation-old-v1"
      64  sig_new          by new_pub, label "AXON-rotation-new-v1", over
                           header ‖ body ‖ sig_old
```

With a 52-byte anchor: `body_len = 144`, total 280 bytes. `sig_new` is what stops
an attacker binding a victim's key as the successor of their own worthless
identity to inherit its standing.

Two hard rules. A `class = 1` rotation is **invalid with an empty anchor** — the
naming layer accepts only a domain rotation the chain witnessed, since an
off-chain one would let a stolen key permanently capture a name. And `reason = 1`
is retroactive: it invalidates every DelegationCertificate `old_pub` issued
before `effective_at`, whereas `reason = 0` leaves them valid to their own
`not_after`.

#### Revocation (rtype 0x03)

```text
off  len  field
  0    1  class
  1   32  subject_pub      the key being revoked
 33    1  scope            0 this key only
                           1 this key and every certificate it issued
                           2 this key and everything beneath it, transitively
 34    8  sequence
 42    8  issued_at
 50    1  reason           0 unspecified · 1 compromise · 2 superseded
                           3 retired · 4 bond slashed
 51    1  revoker_class    0 self · 1 on-chain · 2 parent DomainIdentity
 52   32  revoker_pub      zero when revoker_class = 1
 84    2  anchor_len
 86   ..  anchor           required non-empty when revoker_class = 1
--- signature ---
      64  sig_revoker      by revoker_pub, label "AXON-revocation-v1";
                           MUST be 64 zero bytes when revoker_class = 1, and the
                           verifier resolves the anchor through the light client
```

Revocations are **monotone**: they only remove trust, never confer it. Three
consequences follow, and they are the whole design.

1. A thief holding the key can revoke it. Acceptable — that is denial of service
   against the victim, not impersonation, and the victim can rotate.
2. They **never expire and are never garbage-collected**. Stored in a local bbolt
   bucket beside the shard store, gossiped on peer contact, replicated in the DHT
   under the subject key. A revocation always beats a valid-looking descriptor.
3. Being monotone, one may be accepted from *any* source whose signature or
   anchor verifies. No freshness requirement, no authority to ask.

Propagation has no completeness guarantee — a partitioned client may never see
one. That is OCSP's problem and we do not solve it either; the mitigation is
short certificate and descriptor lifetimes, which is why both are hours. `[UNSOLVED]`

#### DelegationCertificate (rtype 0x04)

```text
off  len  field
  0   32  issuer_pub       DomainIdentity
 32   32  subject_pub      ServiceIdentity (or an OnlineSigner)
 64    8  sequence
 72    8  not_before
 80    8  not_after        not_after − not_before ≤ 90 days (7 776 000 s)
 88    4  scope_flags      bit0 publish_descriptors · bit1 publish_records
                           bit2 publish_content_manifests · bit3 accept_payments
                           bit4 sub_delegate · bits 5..31 reserved zero
 92    1  max_depth        0 = subject may not sub-delegate; ignored unless bit4
 93    1  name_len         u8
 94   ..  name             lowercase ASCII FQDN under the issuer's domain, ≤253 B
  ..   1  ext_count
  ..  ..  extensions[]
--- signatures ---
      64  sig_issuer       label "AXON-delegation-issuer-v1"
      64  sig_subject      label "AXON-delegation-subject-v1", over
                           header ‖ body ‖ sig_issuer
```

For `name = "chat.alice.lab.axon"` (15 B): `body_len = 110`, total 246 bytes.

Chain-of-time rule: a certificate is invalid outside its own window, invalid if
`not_after` outlives the issuer's `old_valid_until` after a rotation, and invalid
if any key on the path from OwnerIdentity down to `subject_pub` carries a cached
Revocation with `scope ≥ 1`. Validation walks the chain root-down and stops at
the first failure, so a client with no chain access can still reject a
certificate on a locally cached revocation.

### 5.3 Key derivation and the full label table

Form: `HKDF-SHA256(salt, ikm, info, L)` per RFC 5869. Unless a row says
otherwise `salt` is 32 zero bytes and `info = label_ascii ‖ 0x00 ‖ context`.
Labels are ASCII, contain no NUL, carry a mandatory `-vN` suffix, and are **never
reused across layers**; adding a field to a context without bumping the version
is a protocol break. The node master seed (32 B, OS CSPRNG, stored as `node.key`)
roots the node-side tree; service and domain seeds are independent roots, so that
a node compromise does not reach a service key hosted on the same box.

Table 1 — HKDF-SHA256 invocations.

| `info` label | IKM | Context appended | L | Consumer |
|---|---|---|---|---|
| `AXON-node-seed-v1` | node master seed | — | 32 | NodeIdentity Ed25519 seed |
| `AXON-routing-ed-v1` | node master seed | `u64be(epoch)` | 32 | RoutingIdentity Ed25519 seed for the epoch |
| `AXON-routing-x-v1` | node master seed | `u64be(epoch)` | 32 | RoutingIdentity X25519 scalar (clamped) |
| `AXON-link-handshake-v1` | TLS 1.3 exporter secret | connection transcript hash | 64 | L1 link keys — §6 owns the split |
| `AXON-ntor-verify-v1` | circuit-extend ECDH secrets | node_pub ‖ B ‖ X ‖ Y | 32 | handshake verification value |
| `AXON-ntor-auth-v1` | as above | as above | 32 | handshake auth tag |
| `AXON-circuit-hop-v1` | ntor shared secret | hop index u8 | 96 | per-hop forward/backward AEAD keys and nonce salts — §8 owns the split |
| `AXON-pq-hybrid-v1` | `x25519_ss ‖ mlkem_ss` | `mlkem_ct ‖ mlkem_ek ‖ x25519_pub` | 32 | hybrid combined secret (§5.6) |
| `AXON-descriptor-blind-v1` | ServiceIdentity pub `A` | `u64be(period_number) ‖ u64be(period_length) ‖ optional_secret` | 32 | blinding factor `h` before clamping (§5.4) |
| `AXON-desc-outer-v1` | subcredential | `u64be(period_number)` | 64 | outer descriptor layer key ‖ nonce |
| `AXON-desc-inner-v1` | subcredential ‖ client-auth secret | descriptor salt (16 B) | 64 | inner descriptor layer key ‖ nonce |
| `AXON-intro-cookie-v1` | rendezvous cookie | intro point pub | 32 | §9 |
| `AXON-content-key-v1` | object root key | ContentIdentity | 32 | §10 object encryption |
| `AXON-shard-key-v1` | object content key | shard index u32 | 32 | §10 per-shard key |
| `AXON-token-blind-v1` | token seed | epoch, denomination | 32 | §14 blind-signed tokens |
| `AXON-keyfile-v1` | password-derived key (§5.7) | file class byte | 32 | at-rest wrapping key |

Table 2 — SHA-256 and signature domain-separation prefixes (not HKDF; the label
is prefixed to the hashed or signed bytes with a `0x00` separator).

| Label | Applied to | Produces |
|---|---|---|
| `AXON-kadid-v1` | `node_pub ‖ SRV_epoch ‖ network_prefix` | KadID, 32 B |
| `AXON-hsdir-index-v1` | `A' ‖ SRV_epoch ‖ u64be(period_number)` | descriptor DHT index, 32 B |
| `AXON-credential-v1` | ServiceIdentity pub `A` | credential, 32 B |
| `AXON-subcredential-v1` | `credential ‖ A'` | subcredential, 32 B |
| `AXON-address-checksum-v1` | `pubkey ‖ version` | 2-byte address checksum (§5.8) |
| `AXON-relaydesc-node-v1` | RelayDescriptor header ‖ body | Ed25519 signature |
| `AXON-relaydesc-routing-v1` | ‖ sig_node | Ed25519 signature |
| `AXON-rotation-old-v1` / `-new-v1` | IdentityRotation | Ed25519 signatures |
| `AXON-revocation-v1` | Revocation | Ed25519 signature |
| `AXON-delegation-issuer-v1` / `-subject-v1` | DelegationCertificate | Ed25519 signatures |
| `AXON-record-v1` | name record set | Ed25519 signature by DomainIdentity |
| `AXON-descsign-cert-v1` | DescriptorSigningKey certificate | Ed25519 signature by the blinded key |
| `AXON-ownerproof-v1` | `owner_address ‖ name ‖ u64be(nonce)` | Ed25519 possession proof for edge E1 |

A test file pins one vector per label, on the precedent of
`TestCanonicalReceiptHashGoldenVector` — which exists because two implementations
of one encoding in different repositories drift, and a drifted domain separator
fails silently rather than loudly.

### 5.4 Ed25519 key blinding for descriptor keys

**What it buys.** A DHT node holding a descriptor learns the blinded key `A'`, an
index derived from it, and an encrypted blob. It does not learn which service the
descriptor belongs to, cannot link this period's descriptor to last period's, and
cannot serve it to a client who does not already know the service — exactly
R4(c). This is a reimplementation of Tor's v3 onion-service construction, not a
port of its code.

**Construction.** An Ed25519 private key is a 32-byte seed. `SHA-512(seed)` gives
`(a_pre ‖ prefix)`; `a = clamp(a_pre)` is the scalar and `A = a·B` the public key.

```text
period_length  = 86 400 s          (Constitution §5)
period_number  = floor((unix_time − period_offset) / period_length)

h_raw = HKDF-SHA256(salt = 32 zero bytes,
                    ikm  = A,
                    info = "AXON-descriptor-blind-v1" ‖ 0x00 ‖
                           u64be(period_number) ‖ u64be(period_length) ‖ s,
                    L    = 32)
                                    s = optional client-auth secret; empty in v1

h = clamp(h_raw):  h[0]  &= 248
                   h[31] &= 63
                   h[31] |= 64
   interpreted little-endian, then reduced mod L (the group order)

private:  a' = (h · a) mod L        prefix' = SHA-512("AXON-descriptor-blind-
                                              nonce-v1" ‖ 0x00 ‖ prefix)[0:32]
public:   A' = h · A                (point scalar multiplication)
```

**Why verification works, precisely.** `A = a·B`, so
`h·A = h·(a·B) = (h·a)·B = a'·B`. `A'` is therefore exactly the public key of the
blinded scalar `a'`, and a signature made with `a'` verifies under `A'` with an
unmodified Ed25519 verifier. Verification does not change; only key *generation*
does.

**The implementation hazard, and it is the part that gets built wrong.** `a'` is
a product of two scalars reduced mod `L`: **not** a clamped scalar — generally
not a multiple of 8, high bit not set — and it has no corresponding 32-byte seed.
Every seed-based Ed25519 API is therefore unusable, including Go's
`crypto/ed25519`, whose `NewKeyFromSeed` and `Sign` both assume seed derivation.
The signer must be written against a scalar-level library
(`filippo.io/edwards25519` or equivalent):

```text
r = SHA-512(prefix' ‖ M) mod L         R = r·B
k = SHA-512(R ‖ A' ‖ M) mod L
S = (r + k·a') mod L                   signature = R ‖ S       (64 B)
```

`prefix'` must be derived rather than reused, so that period keys do not share
nonce derivation. It costs one SHA-512.

**Client-side derivation, with no secret at all.** A client knowing only the
ServiceIdentity public key `A` — from a name resolution (§13) or from the 56
characters of a fallback address (§5.8) — computes `period_number` from its
clock, `h` from public inputs, `A' = h·A`, then the DHT index
`SHA-256("AXON-hsdir-index-v1" ‖ 0x00 ‖ A' ‖ SRV_epoch ‖ u64be(period_number))`,
fetches, and verifies the descriptor's signature chain against `A'`. No secret,
no round trip to the service, no state.

**Why the DHT node cannot invert it.** `h` is a function of `A`. Recovering `A`
from `A'` needs `h`; computing `h` needs `A`. The storing node has neither, and
the map is circular by design.

**The limit, stated honestly.** Blinding hides the service only from a party
without a candidate `A`. An adversary holding a list of known service keys can
compute `h` and `A'` for each and check the DHT; descriptor contents are also
encrypted under the subcredential, but that too derives from `A`. So blinding
provides **unlinkability across periods and non-enumerability, not
confidentiality against a targeted guess**. A service whose public key the
adversary already has gets nothing from blinding.

Validation: `A` must be canonical and torsion-free (`[L]·A` is the identity)
before blinding, or an attacker-supplied address carries a small-order component
into `A'`. Verification must reject non-canonical point and scalar encodings and
small-order public keys, byte-identically across implementations and pinned by a
test vector file, because Ed25519 libraries genuinely disagree here.

Overlap: descriptors are published under both `period_number` and
`period_number + 1` during the final 12 h of a period; a client tries the current
period then the previous, covering ±12 h of clock skew.

### 5.5 Forward secrecy

Only key-agreement keys raise a forward-secrecy question. Signing keys do not
encrypt anything, so their compromise exposes no past traffic — it grants future
impersonation. That distinction drives §5.6 as well.

| Key | Ephemeral? | Compromise window |
|---|---|---|
| L1 link key (QUIC/TLS 1.3) | Yes, per connection | Connection lifetime; TLS 1.3 gives FS against static key compromise immediately |
| Client circuit-handshake key | Yes, per circuit | Discarded after the handshake |
| Per-hop AEAD keys | Yes | ≤10 min (tunnel lifetime), zeroized at teardown |
| RoutingIdentity X25519 | Epoch-scoped | 24 h + 2 h publish lead = **≤26 h** |
| RoutingIdentity Ed25519 | Epoch-scoped | 26 h of forgeable descriptors |
| NodeIdentity | No | Indefinite, until rotation propagates |
| ServiceIdentity | No | Indefinite |
| DomainIdentity | No | Until an on-chain rotation reaches resolvers (snapshot TTL, §13) |
| `content.key` (existing) | **No, and never rotated** | The lifetime of the node |

| Adversary compromises… at time T | What past traffic is exposed |
|---|---|
| A relay's **RoutingIdentity X25519** for epoch e | Every circuit-extend handshake to that relay in epoch e that the adversary recorded, and therefore the cell contents of those circuits at that hop. Bounded to ≤26 h. This is the single largest forward-secrecy exposure in the design and it is the price of a one-round-trip, ntor-style extend. |
| A relay's **NodeIdentity** | Nothing past. Future: it can sign descriptors binding attacker-controlled routing keys until revocation propagates, so it converts to the row above going forward. |
| A relay's **L1 TLS key** | Nothing. Ephemeral ECDHE per connection. |
| A client's **guard connection state** at time T | The circuits currently live on it, not past ones. |
| A **ServiceIdentity** | All recorded descriptors for that service become readable and linkable across every period, past and future — the adversary derives every historical `h`, `A'`, credential and subcredential. That reveals the historical set of introduction points, which is a real deanonymisation aid, not merely a privacy loss. It does **not** reveal past circuit payloads. |
| A **DomainIdentity** | Nothing past — the records it signed were public. Future: it can re-delegate the name until the on-chain rotation lands. |
| An **OwnerIdentity** | Nothing on the overlay. Full future control of the name. |
| The node's **`content.key`** | Every per-object content key ever sealed to it, for the life of the node. `internal/p2p/contentkey.go` generates it once and never rotates it. |

The `content.key` row is a finding, not a hypothetical: the file is created on
first run and there is no rotation path anywhere in the tree. Fixing it needs
epoch-scoped content keys with an overlap and a re-sealing procedure that
requires the sealing party online at rotation — `[NEEDS RESEARCH]`, owned by §10,
named here because this is where the absence is visible.

### 5.6 Post-quantum posture

**Signatures can wait; key exchange cannot.** Forging a recorded signature needs
the quantum machine *at the moment the signature is checked*, so that migration
can be reactive. A recorded X25519 handshake plus a machine in 2035 decrypts that
traffic retroactively. Harvest-now-decrypt-later makes key exchange the only
urgent item, which is why Constitution §2 defers ML-DSA-65 and reserves the
ML-KEM-768 slot. The one signature-side exception is long-lived commitments: an
on-chain `name → DomainIdentity` binding meant to hold a decade is relied on in
the future, so §12 needs an upgrade path even though the data plane does not.

**Why v1 reserves rather than ships.** ML-KEM-768's published FIPS 203 sizes are
1184 B encapsulation key, 1088 B ciphertext, 32 B shared secret, against X25519's
32/32/32. The link cell is **1024 B fixed** (Constitution §5), so a 1088-byte
ciphertext does not fit in one: a hybrid circuit-extend needs the handshake
fragmented across cells plus a matching `CREATE`/`EXTEND` state machine — a
change to §8's cell format and reassembly, not a cipher swap, and a new DoS
surface in the partial-handshake state a relay must hold. Reserving the slot
costs one byte; shipping it costs that redesign.

**What is reserved.** `pq_suites` in the RelayDescriptor (§5.2, offset 96),
`suite_id` negotiation in §6's handshake, and the combiner label
`AXON-pq-hybrid-v1` (§5.3). The combiner is fixed now so it cannot be got wrong
later: its KDF input is **both** shared secrets **and** the ML-KEM ciphertext and
both public keys — the shape current hybrid-KEM proposals converge on. A combiner
over the two secrets alone is not robust if one KEM is malleable.

**Migration trigger**, not a date: at ≥60 % of bandwidth-weighted descriptors
advertising bit1, clients require the hybrid for `BULK` circuits (the most
valuable to harvest); `INTERACTIVE` follows at ≥90 %. Requiring it earlier
partitions the network, a worse anonymity outcome than a pre-quantum handshake.

**What has no answer.** Key blinding (§5.4) is an algebraic property of Ed25519's
scalar group and no standardised PQ signature scheme has an equivalent, so
descriptor privacy is pre-quantum by design: an adversary with a CRQC and a
recorded DHT can in principle recover service identities from blinded keys.
Lattice blinding, or a hash-based per-period index from a shared secret, are open
work. `[UNSOLVED]`

### 5.7 Key storage, hardware, and the offline/online split

Data directory layout, extending the existing convention (`p2p.key`,
`content.key`, `i2p.destination` beside `storage/`):

```text
<data_dir>/
  node.key             NodeIdentity seed, 32 B raw           0600
  content.key          existing X25519 content key           0600  (unchanged)
  routing/             epoch keys, derived and re-derivable  0700 dir
  service/<label>.key  ServiceIdentity seed                  0600
  domain.key           DomainIdentity seed — ONLY if the operator declined
                       the offline split below               0600
  payment.key          settlement key, absent if external    0600
  revocations.db       monotone revocation cache (bbolt)     0600
  storage/             existing shard store
```

Files are created `O_EXCL` and the mode re-asserted on every load, both copied
from `internal/i2p/sam.go:187`. `axond` refuses to start on a group- or
world-readable key file rather than warning — a warning in a log nobody reads is
not a control. Optional at-rest wrapping, `[BUILD NOW]`:

```text
off len field
0   4   magic    "AXK1"
4   1   class    1 node · 2 domain · 3 service · 4 payment
5   1   version  0x01
6   1   wrap     0 = raw seed follows · 1 = Argon2id + ChaCha20-Poly1305
7   1   reserved 0x00
8   16  salt     (wrap = 1 only)
24  12  nonce    (wrap = 1 only)
36  ..  payload  32 B raw seed, or 48 B ciphertext ‖ tag
```

Constitution §2 fixes no password-based KDF; Argon2id is an addition, flagged in
the objection below.

Hardware options. `[NEEDS RESEARCH]` on the exact device matrix — verify against
firmware before depending on any row; this is not a purchasing guide.

| Class | Hardware story |
|---|---|
| OwnerIdentity (secp256k1) | Good. Hardware wallets, multisig, and air-gapped signing are mature for Ethereum accounts. This is the class that most needs hardware and the one best served. |
| DomainIdentity (Ed25519) | Patchy. Ed25519 signing is available on some smartcard applets and security keys but is not the universal capability that P-256 ECDSA is. The dependable fallback is an air-gapped machine with the seed on removable media. |
| ServiceIdentity (Ed25519) | **Cannot be done in hardware at all for the descriptor path.** Blinding needs arithmetic on the private *scalar* (§5.4), and no signing token exposes that. A token that only signs messages cannot produce `a'`. |
| NodeIdentity / RoutingIdentity | Hardware is not useful. The routing key must be online continuously; the node key is re-derivable from the master seed. |

The ServiceIdentity constraint has one escape worth building: `(a', prefix')`
pairs for future periods can be computed on an offline machine and shipped to the
online host, which then signs descriptors for N periods without ever holding `a`.
Compromise costs the pre-shipped periods and no more. `[BUILD NOW]`

**DomainIdentity offline/online split.** The default posture:

```text
  air-gapped host                        online host (axond)
  domain.key (DomainIdentity)  ── DelegationCert, 30 days ──►  online.key
  never networked                 sub_delegate = 0             scope: publish_
  issues Revocations              max_depth = 0                records + desc
```

| Level lost | Blast radius | Recovery | Cost |
|---|---|---|---|
| Online signer | Attacker publishes records for ≤ the certificate's remaining life | Air-gapped host issues a Revocation for `online.key` and a new certificate | Minutes, no chain access |
| DomainIdentity | Attacker re-delegates the whole name until the chain rotation propagates | OwnerIdentity submits an on-chain rotation; resolvers converge at snapshot TTL | Gas plus the resolver freshness bound (R7, §13) |
| OwnerIdentity | Attacker owns the name outright | Only a surviving multisig quorum helps | Terminal for a single-key owner |

Two rules make the split hold rather than look tidy. `sub_delegate` **must** be 0
for an online signer, or the online key mints its own successors and the offline
root is decorative. And a DomainIdentity rotation is invalid without a chain
anchor (§5.2), so a stolen online key cannot rotate the domain away from its
owner. A rotation's overlap must also be at least the maximum snapshot staleness
a resolver may operate under, or a resolver on a stale snapshot rejects both the
new key's records and the old key's. §13 owns that bound; this section owns the
constraint.

### 5.8 The self-certifying fallback address

Used before a name is registered, when the owner wants no name at all, and as the
ground truth a name resolution is checked against. The address **is** the key: an
encoding, not a hash, and reversible.

```text
version  = 0x01                       (ServiceIdentity, routable)
checksum = SHA-256("AXON-address-checksum-v1" ‖ 0x00 ‖ pubkey ‖ version)[0:2]
payload  = pubkey(32) ‖ checksum(2) ‖ version(1)          = 35 bytes
address  = base32(payload) ‖ ".axon"
```

Base32 is RFC 4648, lowercase, **no padding**: 35 bytes is 280 bits, exactly 56
base32 characters with nothing left over, so no padding character can ever
appear.

```text
label   56 chars [a-z2-7]   suffix  ".axon" (5)   total  61 characters
shape   p3qk7f2mzv4t6y8bnd5rjw9xh3cs4gl2ea7uv6mk9pt3zr8qwsdy.axon
        (illustrative shape only — not a real key)
```

The 56-character label is inside the 63-octet DNS label limit, so the address
survives any DNS-shaped interface without truncation. That is not an endorsement
of resolving `.axon` in DNS (§11 rules on that) — it is a constraint the encoding
satisfies for free and would be painful to retrofit.

Version bytes separate the classes, and since the version is inside the checksum,
an altered version fails it:

| Version | Class | Text form | Routable |
|---|---|---|---|
| `0x01` | ServiceIdentity | `<56>.axon` | Yes |
| `0x02` | DomainIdentity | `axondom:<56>` | No — display only |
| `0x03` | NodeIdentity | `axonnode:<56>` | No — display only |
| `0x04`–`0xFF` | reserved | — | — |

Parsing is strict: exact length, alphabet, checksum, version, and the decoded key
must be canonical and torsion-free (§5.4). A mistyped character fails the
checksum with probability ≈ 1 − 2⁻¹⁶; the checksum is a typo guard, not a
security control — the security is that the address *contains* the key.

Prior art: I2P's 52-character `.b32.i2p` host is a SHA-256 of the destination
(`internal/i2p/sam.go:560`); Tor's v3 onion address is 56 characters and carries
the key. We match Tor's length because we match its content, and carrying the key
rather than a hash is what makes descriptor verification possible from the
address alone.

### Decision table

| Decision | Problem it solves | Derived from | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Eight disjoint key classes | One key linking relay, bond, service and payment | Tor (identity/onion/service keys), I2P (destinations) | More classes than either, and a written rule that no two are ever equal | Reusing `p2p.key`; a two-key node/service split | Eight lifecycles to get right; a rotation bug in any one is a partition |
| R-ID1: both ends sign every binding | Reputation and bond grafting | Neither — Tor certs are one-sided | Mandatory countersignature on every binding record | Issuer-only signing (smaller records) | +64 B per record; a subject that is offline cannot be delegated to |
| Ed25519 key blinding for descriptors | DHT node learning what it stores (R4c) | Tor v3 onion services | HKDF-SHA256 instead of SHA3, own labels, reimplemented | Storing under `H(A)` (enumerable, linkable across periods) | Needs a scalar-level Ed25519 API; no hardware path; no PQ analogue |
| `KadID = H(NodeIdentity ‖ SRV ‖ prefix)` | Eclipse via chosen keyspace position | S/Kademlia; Tor's HSDir ring | SRV from a verified beacon RANDAO (R13), not an authority | Free choice of node id; PoW-derived ids | All positions shift each epoch: routing tables churn completely every 24 h (§7's cost) |
| Epoch-scoped RoutingIdentity | Forward secrecy without losing reputation | Tor's onion key, I2P's per-tunnel keys | 24 h rotation vs Tor's weeks; bond stays on NodeIdentity | One long-term key (no FS); per-circuit static keys (no reputation) | Descriptor churn every epoch; a clock-skewed relay is unreachable |
| Versioned ASCII labels on every KDF and signature | Cross-protocol signature reuse | TLS 1.3 / HKDF practice; existing `syndichan-*:v1` labels | One table, one format, mandatory version suffix | Implicit separation by key type | A missed version bump fails silently — hence the golden vectors |
| Self-certifying `.axon` address | Names before a registry exists; a ground truth for resolution | Tor v3 onion address; I2P `.b32.i2p` | SHA-256 checksum, own label, version byte per class | Hash-of-key addresses (cannot verify descriptors); shorter human names | 61 characters is unusable by humans without a name layer |
| Monotone, never-expiring revocations | Stolen keys outliving discovery | X.509 CRL/OCSP, minus the responder | No authority, no freshness requirement, gossip + DHT | Short-lived positive attestations only; a global CRL authority | Unbounded storage growth; no completeness guarantee (`[UNSOLVED]`) |
| Offline domain root, scoped online signer | A web-facing box holding the name | TLS delegated credentials; Tor's offline master key | Scope bits and `sub_delegate = 0` enforced at verification | Domain key on the online host; hardware-only root | Certificate re-issue is a recurring manual operation; a forgotten renewal is an outage |
| PQ hybrid slot reserved, not shipped | Harvest-now-decrypt-later | Neither — none of the three has an answer | One `pq_suites` byte and a fixed combiner label now | Shipping ML-KEM in v1 (breaks the 1024 B cell); ignoring PQ entirely | Everything recorded before the switch stays recoverable by a future CRQC |
| Raw seeds replace libp2p protobuf key files | Two hash-incompatible encodings of one key | Existing code's own `SigningKey` warning | One canonical on-disk form, migration preserves the node id | Keeping the protobuf form | A migration bug loses a bonded identity — needs a dry-run mode and a backup |

### Component status

`[BUILD NOW]` — eight-class key generation, storage and serialization; record
encoding, canonicalisation and golden vectors; the KDF label table and its
vectors; Ed25519 blinding with a scalar-level signer and the address codec (small,
delicate, fully specified above); the offline/online split with pre-shipped
period scalars; migration from `p2p.key` preserving the PoF node id and bond.

`[NEEDS RESEARCH]` — reputation continuity across a compromise rotation (§15);
`content.key` rotation and re-sealing (§10); the hardware Ed25519 device matrix.

`[UNSOLVED]` — revocation propagation with any completeness property;
post-quantum descriptor blinding.

### What this section does NOT establish

- **It does not make revocation reliable.** A partitioned or freshly bootstrapped
  client may never learn a key was revoked. Short lifetimes bound the damage;
  nothing here eliminates it. Same gap OCSP has.
- **It does not prove blinding hides a service from a targeted adversary.** It
  stops enumeration and cross-period linkage. An adversary already holding a
  candidate ServiceIdentity computes every blinded key it will ever have.
- **It does not solve identity for a service that loses its key.** A
  ServiceIdentity published as a fallback address and then lost is unrecoverable
  — the address is the key. Only a registered name is portable.
- **It does not establish that the PoF node id, bond and reputation survive the
  key-file migration.** That needs the migration written and tested against a
  real bonded node; today it is design intent.
- **It does not specify the handshake, the cell format, the DHT record validator
  or the on-chain registry.** This section fixes the keys, records and labels
  those subsystems consume; §6, §7, §8 and §12 own their use of them.
- **It does not measure anything.** Record sizes are arithmetic over the layouts
  as written, and the ML-KEM-768 figures are the published FIPS 203 parameters,
  not values we observed.

> **Objection to Constitution §2 (a):** the primitive table fixes no
> password-based KDF, but an encrypted key file needs one. §5.7 names Argon2id
> with parameters open. Synthesis should add a row to §2 or rule that key files
> rely on filesystem permissions only, which is the existing node's posture.

> **Objection to Constitution §2 (b):** the table specifies blinding "as in Tor
> rend-spec-v3", whose blinding factor is SHA3-based, while the same table fixes
> SHA-256/HKDF-SHA256. §5.4 resolves this for one hash discipline across the
> document, since we are forbidden to interoperate with Tor anyway. If exact
> rend-spec-v3 compatibility is preferred, §5.4's `h_raw` line is the only change.

> **Objection to Constitution §2 (c):** deferring PQ signatures "only for
> long-lived domain records" is coherent for DomainIdentity but can never apply
> to ServiceIdentity: ML-DSA-65 has no known blinding construction, and blinding
> is load-bearing for descriptor privacy (§5.4, §5.6). The document should state
> that descriptor privacy is pre-quantum by design rather than imply an upgrade
> path exists.
