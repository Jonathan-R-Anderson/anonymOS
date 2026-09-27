## 8. Anonymous Routing — Circuits, Cells, and Onion Cryptography

> **AS BUILT (2026-08-16).** `internal/axon/circuit`, 68 tests. **M1 passes** — a
> 3-hop telescoped circuit forwards a cell, all three link ids distinct, plaintext
> invisible at every intermediate hop.
>
> **§8.3's tag stack is WITHDRAWN.** PAR-01 found it to be a cross-hop tagging
> channel — 16 unauthenticated hop-chosen bytes per cell, carried downstream
> unchanged. It is replaced by a LIONESS wide-block PRP (P5a): 0 channel hits over
> 10⁶ cells, relay data 936 → 984 B, goodput 91.4 % → 96.9 %. **Two claims in this
> section are retracted as a result** — §8.3's "hop i+1 finds out immediately" and
> §8.9's corruption localisation. See §81.1.1 for the ruling and the reasoning.
>
> **Deliberately NOT claimed:** **flow control** is P5b and `[NEEDS RESEARCH]` —
> §8.6's window figures are unmeasured and none is claimed. **E5.2's throughput
> half** was measured at 129 Mbit/s over 5 min with zero loss across 4.9 M cells,
> but the criterion is 10 min, so it is not discharged. **M1 is in-process**; a
> live-link run over libp2p hosts has not happened.

**The finding that shapes this section: there is no anonymity code in this
project.** There is an *interface* to somebody else's anonymity code. The node
builds a libp2p host with `libp2p.NoTransports` and exactly one transport, the
I2P SAM bridge (`internal/p2p/node.go:366-371`), so the anonymous configuration
has no fallback: remove I2P and the node cannot dial or be dialled at all.
Everything in §8 is new construction, not hardening. It is the largest single
piece of work in the roadmap and the piece with the least existing code to lean
on.

The second finding is smaller and useful: the project has already written an
onion, already worried about hop-position leakage, and already built a
diversity-constrained path selector — for payments, not for traffic. Those files
are the right starting shape and are cited throughout.

---

### 8.0 What already exists

| Path | Lines | What it is | Fate |
|---|---|---|---|
| `internal/i2p/sam.go` | 588 | SAM v3 control protocol: `SESSION CREATE STYLE=STREAM`, destination persistence, session renewal on control-socket death, `STREAM CONNECT`/`ACCEPT` | **Replaced entirely** |
| `internal/i2p/transport.go` | 209 | libp2p transport over SAM streams; `/garlic32/` multiaddrs only | **Replaced entirely** |
| `internal/p2p/node.go:366-371` | — | `libp2p.New(libp2p.NoTransports, libp2p.Transport(syndii2p.NewTransport…))` | Rewired to §6's QUIC transport |
| `internal/channel/onion.go` | 319 | Fixed-slot 3-hop onion for **payment** routing | Prior art, not reusable as-is |
| `internal/channel/route.go` | 217 | Diversity-constrained, seeded router selection with a typed `RouteRefusal` | Direct ancestor of §8.7 |
| `internal/facilitation/witness.go` | 181 | Deterministic weighted sampling without replacement, group-diversity first pass | Structural ancestor of §8.7 |
| `internal/facilitation/receipt.go` | 146 | `ServiceReceipt` + `CanonicalReceiptHash` (keccak256, fixed field order) + Ed25519 signature + witness attestations | Receipt shape for §8.7 |
| `internal/p2p/contentkey.go` | 58 | X25519 via `golang.org/x/crypto/curve25519`, already a dependency | Reused |

Four facts read out of those files rather than assumed:

1. **The I2P session parameters already match the Constitution's pool figures.**
   `sam.go:84-87` and `sam.go:142-145` send `inbound.length=3 outbound.length=3
   inbound.quantity=3 outbound.quantity=3 inbound.backupQuantity=1
   outbound.backupQuantity=1` — 3 hops, 3+3 tunnels, 1 spare each, exactly
   Constitution §5. Those figures describe what this node *asks a foreign router
   for*. They have never been measured against our own code and §8 must not
   present them as validated.

2. **`internal/channel/onion.go` is not a circuit and cannot become one.** No key
   exchange (`Build(ephemeral, hops, sharedSecrets)` takes secrets from
   outside), no direction, no streams, no sequence numbers, single-shot per
   payment. What §8 keeps from it: constant wire size independent of route
   length; unused slots filled with random bytes of identical length ("a short
   route must be indistinguishable from a full one"); a per-hop per-payment
   `ReplayGuard`; and position hiding, which it buys with a Fisher-Yates slot
   permutation (`permutation`, lines 122-137) and §8.3 buys more cheaply.

3. **The existing key derivation is not HKDF.** `internal/channel/note.go:111`
   defines `derive(domain string, parts ...[]byte)` as a length-prefixed
   HMAC-SHA256 keyed by the domain string. Sound, and not what Constitution §2
   mandates. §8 uses HKDF-SHA256 with ASCII labels; the divergence should be
   recorded, not silently resolved.

4. **`internal/channel/onion.go` seals with AES-256-GCM and a fresh random nonce
   per slot** (`seal`, lines 139-153). §8 uses ChaCha20-Poly1305 with a counter
   nonce, because a per-cell random nonce would cost 12 bytes of every cell on
   top of the tag.

**What must be replaced:** all of `internal/i2p`, and the transport wiring in
`internal/p2p/node.go`.

**What does not exist at all:** cells, circuit identifiers, the extension
handshake, per-hop onion cryptography, telescoping, guards, stream
multiplexing, circuit flow control, replay caches. No partial implementation of
any of them.

---

### 8.1 The cell

Every cell on every link is exactly **1024 bytes**, regardless of circuit
length, hop position, command, or payload. One cell per QUIC STREAM frame
(Constitution §5: two do not fit the 1200 B datagram floor).

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       CIRCID  (8 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      CMD      |     FLAGS     |            LENGTH             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         RESERVED (4)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          TAG STACK (64 B) = TAG[0] TAG[1] TAG[2] TAG[3]        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    ONION PAYLOAD (944 B)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Off | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `CIRCID` | **Link-local.** Different on every link the circuit crosses. Zero reserved for link-level cells. |
| 8 | 1 | `CMD` | Link command. Not onion-encrypted. |
| 9 | 1 | `FLAGS` | bit0 `EARLY_OK`, bit1 `PRIORITY` (INTERACTIVE), bits 2-7 reserved, MUST be zero. |
| 10 | 2 | `LENGTH` | Meaningful only for non-onioned cells. For `RELAY`/`RELAY_BUILD` it MUST be zero — the real length lives inside the onion where an observer cannot read it. |
| 12 | 4 | `RESERVED` | MUST be zero and MUST be checked. A non-zero value is a covert channel between adjacent relays. |
| 16 | 64 | `TAG STACK` | Four 16-byte Poly1305 slots, `H_max = 4`. §8.3. |
| 80 | 944 | `ONION PAYLOAD` | Layered ciphertext, or cleartext handshake material. |

The header is **not** authenticated by the onion, and does not need to be: the
link between adjacent relays is TLS 1.3 inside QUIC (§6), and a neighbour that
wanted to corrupt a cell can drop it instead. Putting `CIRCID` in the AEAD
associated data would break the per-link rewriting the design depends on.

#### Payload capacity arithmetic

```text
link cell                                          1024 B
  − cell header                                      16 B
= body                                             1008 B
  − tag stack, H_max = 4 slots × 16 B                64 B
= onion payload region                              944 B
  − relay header (§8.6)                               8 B
= relay data per cell                               936 B

goodput          936 / 1024 = 91.4 %
tag overhead      64 / 1024 =  6.25 %
header overhead   16 / 1024 =  1.56 %
```

At the default H = 3 one tag slot is never verified; it carries random filler
for the life of the circuit. That is **16 bytes wasted on every cell of every
default circuit, 1.6 %**, and it is the price of a cell layout independent of
circuit length. Shrinking the stack for shorter circuits would announce circuit
length to every relay and every link observer. For comparison a Tor cell carries
498 bytes of relay payload in 514 (~96.9 %); AXON gives up roughly 5.5 points of
goodput to get per-hop authentication.

#### Link commands (`CMD`)

| Code | Name | Direction | Onioned | Body |
|---|---|---|---|---|
| `0x00` | `PADDING` | either | no | Link-local filler/keepalive. Ignored, never forwarded, never counted against a window. |
| `0x01` | `CREATE` | initiator → relay | no | `HTYPE(2) ‖ HLEN(2) ‖ handshake` (§8.2) |
| `0x02` | `CREATED` | relay → initiator | no | `HLEN(2) ‖ reply` |
| `0x03` | `RELAY` | either | yes | Onion-layered relay message. `EXTEND`/`EXTENDED` inside a `RELAY` MUST be rejected. |
| `0x04` | `RELAY_BUILD` | either | yes | As `RELAY`, but `EXTEND`/`EXTENDED` permitted. Budget-limited; the `RELAY_EARLY` equivalent. |
| `0x05` | `CREATE_FRAG` | initiator → relay | no | `FRAGIDX(1) ‖ FRAGCNT(1) ‖ bytes`. Continuation of an oversized `CREATE` (hybrid). Max 2 fragments. |
| `0x06` | `DESTROY` | either | no | `REASON(1) ‖ reserved(15)`. Never onioned, never forwarded verbatim — each relay emits its own. |
| `0x07` | `VERSIONS` | either | no | Link protocol version list. First cell on a link, `CIRCID = 0`. |
| `0x08` | `NETINFO` | either | no | Clock and observed-address exchange, `CIRCID = 0`. Consumed by L2. |
| `0x09` | `LINK_PAD_NEG` | either | no | **Reserved, not implemented in v1** (§8.10). Code allocated so v2 needs no wire break. |
| `0x0A`–`0xFF` | — | — | — | Unknown `CMD` on a circuit → `DESTROY` it. Unknown with `CIRCID = 0` → close the link. |

#### Relay commands (`RCMD`, inside the onion)

Scope: **S** = stream-scoped (`STREAMID ≠ 0`), **C** = circuit-scoped
(`STREAMID = 0`).

| Code | Name | Scope | Direction | Purpose |
|---|---|---|---|---|
| `0x01` | `BEGIN` | S | client → terminal | Open a stream. `DSTTYPE(1) ‖ PORT(2) ‖ DSTLEN(2) ‖ DST ‖ FLAGS(1)`. `DSTTYPE` semantics belong to L5/L7. |
| `0x02` | `DATA` | S | either | Stream payload ≤ 936 B. Counts against both windows (§8.8). |
| `0x03` | `END` | S | either | Close one stream, `REASON(1)`. Does not affect the circuit. |
| `0x04` | `CONNECTED` | S | terminal → client | `BEGIN` succeeded. |
| `0x05` | `SENDME` | S or C | either | Window opening. Authenticated (§8.8). |
| `0x06` | `EXTEND` | C | client → hop k | `NEXTID(32) ‖ LSLEN(2) ‖ LINKSPECS ‖ HTYPE(2) ‖ HLEN(2) ‖ handshake`. `RELAY_BUILD` only. |
| `0x07` | `EXTENDED` | C | hop k → client | `HLEN(2) ‖ reply`. `RELAY_BUILD` only. |
| `0x08` | `TRUNCATE` | C | client → hop k | Drop everything beyond hop k. |
| `0x09` | `TRUNCATED` | C | hop k → client | Confirmation, or unsolicited report that the downstream hop died. `REASON(1)`. |
| `0x0A` | `DROP` | C | either | Onion-level padding, consumed at the terminal. The only padding crossing more than one link. |
| `0x0B` | `RESOLVE` | S | client → terminal | Resolve a `.axon` name. Semantics: L7 naming section. |
| `0x0C` | `RESOLVED` | S | terminal → client | Signed answer or typed failure. |
| `0x0D` | `LOOKUP` | S | client → terminal | DHT lookup on the client's behalf. Required by R4(b). Body: L3 DHT section. |
| `0x0E` | `LOOKUP_REPLY` | S | terminal → client | Signed records; fragmented via `FRAG_MORE` when > 936 B. |
| `0x0F` | `ERROR` | S or C | either | `CODE(2) ‖ detail`. Never free-form text — an error string is an operator fingerprint. |
| `0x10` | `ESTABLISH_INTRO` | C | service → IP | L5 |
| `0x11` | `INTRO_ESTABLISHED` | C | IP → service | L5 |
| `0x12` | `INTRODUCE1` | C | client → IP | L5; carries the rate-limit token (R10) |
| `0x13` | `INTRODUCE2` | C | IP → service | L5 |
| `0x14` | `INTRODUCE_ACK` | C | IP → client | L5 |
| `0x18` | `ESTABLISH_RENDEZVOUS` | C | client → RP | L5 |
| `0x19` | `RENDEZVOUS_ESTABLISHED` | C | RP → client | L5 |
| `0x1A` | `RENDEZVOUS1` | C | service → RP | L5 |
| `0x1B` | `RENDEZVOUS2` | C | RP → client | L5 |
| `0x20`/`0x21` | `PADDING_NEGOTIATE(D)` | C | either | **Reserved, v2** (§8.10) |
| `0x30`/`0x31` | `RECEIPT_REQUEST` / `RECEIPT` | C | either | Accounting plane, off the latency path (§8.7) |

The `INTRODUCE_*`/`RENDEZVOUS_*` bodies belong to the L5 rendezvous section. §8
owns only their codes, their circuit scope, and the rule that circuit scope is
what stops them being confused with stream traffic.

---

### 8.2 The circuit-extension handshake

One round trip, ntor-style, against the **RoutingIdentity** — never
NodeIdentity. RoutingIdentity is epoch-scoped (Constitution §3), which is what
makes the forward-secrecy boundary meaningful and lets a relay rotate circuit
keys without losing its bond or reputation.

Each relay publishes in its descriptor (L3 DHT), signed by NodeIdentity:

```text
RID     Ed25519 public key    32 B    RoutingIdentity signing key
B       X25519 public key     32 B    RoutingIdentity static DH key
EPOCH   uint64                 8 B
EK      ML-KEM-768 enc key  1184 B    only if HTYPE 0x0002 is offered

ID = SHA-256(RID)                     the 32-byte relay identifier in EXTEND
```

#### HTYPE 0x0001 — `axon-ntor-v1` (X25519)

```text
PROTOID  = "axon-ntor-v1"
t_key    = PROTOID ‖ ":key_extract"      t_verify = PROTOID ‖ ":verify"
t_mac    = PROTOID ‖ ":mac"              m_expand = PROTOID ‖ ":key_expand"

CREATE handshake body, 96 B      ID(32) ‖ B(32) ‖ X(32)
CREATED handshake body, 64 B     Y(32)  ‖ AUTH(32)
```

A relay that does not recognise `ID`, or whose current static key is not `B`,
answers `DESTROY(REASON_WRONG_KEY)` and does no cryptography. A client with a
stale descriptor then costs the relay one comparison, not one scalar
multiplication — the first line of handshake DoS defence.

```text
secret_input = EXP(X,y) ‖ EXP(X,b) ‖ ID ‖ B ‖ X ‖ Y ‖ PROTOID

  client: EXP(X,y) = X25519(x, Y),  EXP(X,b) = X25519(x, B)
  relay : EXP(X,y) = X25519(y, X),  EXP(X,b) = X25519(b, X)
  Both MUST reject an all-zero X25519 output (low-order point).
  Every input is fixed-length, so no length prefixes are needed or used.

verify     = HMAC-SHA256(key = t_verify, msg = secret_input)
auth_input = verify ‖ ID ‖ B ‖ Y ‖ X ‖ PROTOID ‖ "Server"
AUTH       = HMAC-SHA256(key = t_mac, msg = auth_input)

KEY_SEED   = HKDF-Extract(salt = t_key, IKM = secret_input)
K          = HKDF-Expand(PRK = KEY_SEED, info = m_expand, L = 136)
```

| Off | Size | Name | Use |
|---|---|---|---|
| 0 | 32 | `Kf` | Forward AEAD key (client → relay), ChaCha20-Poly1305 |
| 32 | 32 | `Kb` | Backward AEAD key |
| 64 | 32 | `Af` | Forward authentication key |
| 96 | 32 | `Ab` | Backward authentication key |
| 128 | 4 | `NPf` | Forward nonce prefix |
| 132 | 4 | `NPb` | Backward nonce prefix |

`Af`/`Ab` do **not** authenticate the data path — the AEAD tags do. Tor needs
separate digest keys because a stream cipher has no authenticator; we do not.
They serve the control plane: authenticated `SENDME` proof-of-delivery (§8.8)
and hop receipts (§8.7). Deriving them here costs 64 bytes of KDF output and
avoids a second key exchange later.

**The auth check.** On `CREATED`, the client recomputes `AUTH` from its own `x`,
the received `Y`, and the `ID`/`B` from the descriptor, and compares in constant
time. On mismatch it sends `DESTROY` and marks **the hop it extended through**,
not only the target, because a bad `AUTH` in an `EXTENDED` means either the
target is not who the descriptor said or the carrying relay altered the reply.

What the check gives, precisely:

- **The relay cannot be impersonated without `b`.** `AUTH` is a MAC keyed by
  material derived from `EXP(X,b)`, which requires the static private key. An
  intermediate hop forwarding an `EXTEND` sees `X` and `Y` in the clear and
  still cannot produce a valid `AUTH`. This is the entire security of
  telescoping.
- **Later compromise of `b` does not open past circuits.** `KEY_SEED` depends on
  `EXP(X,y)`; `x` and `y` are discarded once `K` is derived. An adversary who
  recorded a handshake and later obtains `b` recovers `EXP(X,b)` and nothing
  else.
- **What it does not give.** Possession of `b` allows impersonation *going
  forward*, until the epoch rolls (24 h), and allows an active
  man-in-the-middle on *future* handshakes. Forward secrecy is a claim about
  recorded traffic, not about a live adversary. And `B` is bound to `RID` only
  by the descriptor signature, so a client that accepts an unverified descriptor
  has no authentication at all — the L3 DHT section owns that check and §8
  depends on it absolutely.

#### HTYPE 0x0002 — `axon-ntor-hybrid-v1` (X25519 + ML-KEM-768)

Negotiated. Purpose is harvest-now-decrypt-later defence. Sizes are fixed by
FIPS 203: encapsulation key 1184 B, ciphertext 1088 B, shared secret 32 B. `EK`
is **published in the descriptor, not sent on the wire**, so only the ciphertext
travels.

```text
CREATE body, hybrid:  ID(32) ‖ B(32) ‖ X(32) ‖ CT(1088)  = 1184 B

secret_input = EXP(X,y) ‖ EXP(X,b) ‖ SS_KEM
             ‖ ID ‖ B ‖ SHA-256(EK) ‖ X ‖ Y ‖ SHA-256(CT)
             ‖ "axon-ntor-hybrid-v1"
```

1184 bytes does not fit a 944-byte onion payload:

- On the **first** hop the `CREATE` splits across two cells via `CREATE_FRAG`.
  The relay buffers at most one partial `CREATE` per link, 5 s reassembly
  timeout, at most 2 fragments.
- On **later** hops the `EXTEND` relay message splits via the `FRAG_MORE` bit
  (§8.6), bounded at 4 cells / 3744 bytes per relay message.
- `CREATED` is unchanged — ML-KEM encapsulation is one-directional — so the
  reply still fits one cell.

Labels, `AUTH`, `KEY_SEED` and the 136-byte expansion are identical with
`PROTOID` replaced throughout. Concatenating both shared secrets and both
transcripts into one `HKDF-Extract` means the derived keys are no weaker than
the stronger component, under the standard argument that HKDF-Extract behaves as
a dual-PRF over the concatenation. **We are not inventing a combiner**; we use
concatenate-then-KDF and include the full transcript so neither component's
ciphertext can be mauled independently.

Cost per hop: 1184 B instead of 96 B outbound, one extra forward cell, one
ML-KEM decapsulation at the relay. Roughly 3 extra cells and 3.3 KB per 3-hop
circuit. That is why it is negotiated rather than default in v1.

---

### 8.3 The onion cryptography ruling

**AXON uses per-hop AEAD on fixed-size cells with tag space pre-reserved at
every hop position.** This is a deliberate divergence from Tor.

Tor's long-standing relay cryptography is in the class of *unauthenticated
stream cipher plus an end-to-end running digest*: each hop applies a keyed
stream-cipher layer and integrity is checked only by the endpoints against a
rolling hash. That construction is **malleable at every intermediate hop** — a
relay can flip bits and the flip propagates predictably to the far end. This is
the basis of the tagging-attack family: an adversary at the entry marks a cell,
a confederate at the exit recognises the mark, and the two confirm they are on
the same circuit without any timing analysis. Tor has published proposals to
replace this class of construction; their current parameters are not restated
here, because a misdescription would be worse than an omission.

```text
Every relay layer is ChaCha20-Poly1305 (RFC 8439) over the 944-byte onion
payload region, producing a 16-byte tag placed in the tag stack. Ciphertext
length equals plaintext length, so the cell does not grow. The tag stack is a
fixed 64 bytes: H_max = 4 slots, always present, always the same size.
```

#### Forward direction (client → terminal)

```text
BUILD, circuit of length H ≤ 4, layers applied innermost-first:
  P ← relay message padded to 944 B
  for i = H down to 1:
      nonce  = NPf_i ‖ ctr_f_i          (4 B prefix ‖ 8 B big-endian counter)
      P, tag = Seal(Kf_i, nonce, aad = "", P)
      TAG[i-1] = tag ;  ctr_f_i += 1
  for j = H .. H_max-1:  TAG[j] = 16 random bytes

FORWARD, at hop i:
  1. tag = TAG[0]
  2. P   = Open(Kf_i, NPf_i ‖ ctr_f_i, aad = "", P, tag)
           on failure → DESTROY(REASON_INTEGRITY); do not forward
  3. ctr_f_i += 1
  4. shift the tag stack LEFT one slot; TAG[H_max-1] = 16 random bytes
  5. terminal → parse P as a relay message
     otherwise → rewrite CIRCID for the next link and forward
```

#### Backward direction (terminal → client)

```text
AT HOP i, on a cell travelling toward the client:
  1. shift the tag stack RIGHT one slot (the discarded last slot held filler)
  2. P, tag = Seal(Kb_i, NPb_i ‖ ctr_b_i, aad = "", P)
  3. TAG[0] = tag ;  ctr_b_i += 1

AT THE CLIENT:
  for i = 1 .. H:
      P = Open(Kb_i, NPb_i ‖ ctr_b_i, aad = "", P, TAG[0])
          on failure → the chain broke at or before hop i  (§8.9)
      shift the tag stack LEFT one ;  ctr_b_i += 1
```

**Why the stack rotates instead of being indexed.** If hop i always read
`TAG[i-1]`, a relay would learn its position from the slot index that verified.
Rotation makes every hop read `TAG[0]`, so the cell format carries no position
information. This is the property `internal/channel/onion.go` buys with a
per-packet Fisher-Yates shuffle and an `H_max`-way trial decryption; we get it
for a 64-byte `memmove`. Telescoping leaks position by other means (§8.4), so
this is defence-in-depth rather than a complete answer — but it still matters,
because after the build completes a relay handling *data* cells has no
format-level evidence of circuit length or its own position, and that is the
window in which most of a circuit's cells travel.

#### Nonce discipline

```text
nonce = NP (4 B, from the KDF) ‖ counter (8 B, big-endian)
```

| Rule | Enforcement |
|---|---|
| One counter per **(circuit, hop, direction)** — four independent counters per hop | State lives in the per-hop circuit context; no counter is shared |
| Counters start at 0 and are **never** reset, rewound, or reused | Incremented only after a successful `Seal`/`Open` |
| Keys are already unique per (circuit, hop, direction), so even a bug reusing a counter across hops would not reuse a (key, nonce) pair | Belt and braces, deliberately |
| Hard limit 2³² cells per direction per hop (≈ 4 TB); at the limit the circuit is torn down | Checked at increment. The 10-minute lifetime makes it unreachable; the check exists so a bug cannot make it reachable |
| Cells arrive in order (one QUIC stream per circuit, R12), so the receiver requires `counter == expected`; anything else is a protocol violation, not a reorder | §8.9 |

`NP` adds no security beyond the counter — the key is already unique. It is
derived anyway so a future construction sharing a key across directions cannot
silently collide.

#### Overhead and the honest trade

```text
per cell             64 B tag stack                 6.25 % of the link cell
per cell, wasted     16 B (unused slot at H = 3)    1.56 %
per relay per cell   1 ChaCha20-Poly1305 op over 944 B
per circuit          136 B of key material per hop
```

At 100 Mbit/s a relay handles ~12,200 cells/s per direction, ~24,400 AEAD
operations per second over 944 bytes each, ≈ 23 MB/s of AEAD throughput. *This
is arithmetic from the cell size. No AXON relay has been benchmarked.*

**An intermediate relay learns that a cell was corrupted upstream.** With an
end-to-end digest only the client finds out; here hop i+1 finds out immediately
and tears the circuit down. This is fine, and useful:

- The tagging channel collapses. A bit flip at hop 1 does not deliver a mark to
  a confederate at hop 3; it produces a dead circuit at hop 2. The confederate
  learns "some circuit died", which it could have caused by dropping the cell.
- The next hop can attribute corruption to its immediate predecessor and feed
  the accounting plane. A corrupting relay becomes visible to the relays around
  it, not only to clients who cannot say anything credible about it (§8.7).
- What leaks to hop i+1 is information about *an attack in progress*, not about
  the user.

What it does **not** buy, and must not be claimed to buy: per-hop AEAD stops
bit-level tagging. It does nothing about dropping, delaying, or volume
correlation. An adversary holding both ends still confirms a circuit by traffic
pattern, and Constitution §7 already places that adversary outside scope for
`INTERACTIVE`.

| Alternative | What it gives | Why not v1 |
|---|---|---|
| Stream cipher + end-to-end running digest (Tor's historical class) | Zero per-hop expansion, ~96.9 % goodput | Malleable at every hop — the tagging channel is exactly what we are removing. Rejected. |
| **Wide-block / tweakable-cipher construction** — a strong PRP over the whole relay payload, so any bit flip randomises the block | Zero expansion **and** non-malleability. The right long-term answer; Tor has proposed constructions in this class | Needs a wide-block cipher not in the Go standard library, needs its own security argument, and rests on a PRP property harder to argue informally than "this is an AEAD". **[NEEDS RESEARCH]** for v2, with the cell layout unchanged (the tag stack becomes reserved-and-random) |
| Sphinx-style single-pass packet with per-hop MACs | Constant size, position hiding, one-pass build | Solves a different problem (§8.4); its MAC layout is the "filler must be computable at build time" hazard `internal/channel/onion.go` explicitly declined |
| AES-256-GCM per layer | Hardware acceleration on most server CPUs | Kept as a negotiable AEAD (Constitution §2). ChaCha20-Poly1305 is default because relay operators include low-power ARM hardware and a constant-time software implementation is the safe default |

**Ruling: per-hop AEAD, ChaCha20-Poly1305, 16 B per hop position, rotating tag
stack.** Not because it is optimal — it costs 5.5 points of goodput — but
because its security property is one sentence and an implementer can check it:
*each hop's layer is an AEAD under a key shared only with the client, so forging
a layer is forging an AEAD.*

---

### 8.4 Circuit lifecycle

#### Why telescoping, not a single-pass construction

| | Telescoping (chosen) | Single-pass (Sphinx-style / one-shot KEM to all hops) |
|---|---|---|
| Build cost | H round trips (3 RTT default) | 1 round trip |
| Failure attribution | **Exact** — the client knows which hop refused | None; the circuit comes up or does not |
| Live repair | `TRUNCATE` + re-`EXTEND` replaces one bad hop | Full rebuild |
| Position leakage to relays | **Leaks** (see below) | Hides position much better |
| Key freshness | Fresh ephemeral per hop, negotiated live | Needs current descriptor keys for every hop up front |
| Implementation risk | Low — three sequential handshakes | The build-time/forward-time filler asymmetry `internal/channel/onion.go` declined to take on |

**Ruling: telescoping in v1.** The deciding argument is failure attribution. R14
removes the consensus document, so relay quality must be learned locally from
observed behaviour (§8.7); a build mechanism that cannot say *which hop failed*
leaves the weighting function nothing to learn from. The 3-RTT cost is absorbed
by pre-building — the pool holds 3+3 tunnels with 1 spare each and rebuilds at
70 % of the 10-minute lifetime (Constitution §5) — so a request is served by a
circuit that already exists.

The cost is named rather than buried: **telescoping tells each relay roughly
where it sits.** Hop 1 forwards H−1 `RELAY_BUILD` cells, hop 2 forwards H−2,
hop 3 forwards H−3, so a relay counting its own forwards learns its distance
from the terminal. Because lengths 2-4 are allowed the count is ambiguous by a
position or two, which is a mitigation and not a fix. Single-pass construction
is **[NEEDS RESEARCH]** for v2 and would be a wire-format break.

**The `RELAY_BUILD` budget.** `EXTEND`/`EXTENDED` are accepted only inside
`RELAY_BUILD`. Each relay keeps a **private** per-circuit counter of
`RELAY_BUILD` cells it has forwarded and refuses beyond `H_max = 4`, answering
`DESTROY(REASON_BUILD_BUDGET)`. The counter is deliberately not on the wire:
Tor's equivalent carries a decrementing count in the cell, which leaks position
directly and has been usable as a signalling channel. A local counter bounds
path length identically and adds no field an adversary can modulate.

#### State machine

| State | Meaning | Entered by | Budget (specified default, **not measured**) | On expiry | Next |
|---|---|---|---|---|---|
| `C_NEW` | Allocated, no link | `Open()` | — | — | `C_LINK` |
| `C_LINK` | QUIC link to the guard establishing | Dial | 5 s | Guard `DOWN`; try the other primary | `C_CREATING` |
| `C_CREATING` | `CREATE` sent | Link up | 10 s | Guard `DOWN`; one retry on the other primary; **no new guard is added** (§8.5) | `C_EXT(2)` |
| `C_EXT(k)` | `EXTEND` to hop k sent | Previous `EXTENDED` | 10 s | `TRUNCATE` to k−1, redraw hop k, ≤ 2 redraws per circuit | `C_EXT(k+1)` / `C_OPEN` |
| `C_OPEN` | All hops up, no stream | Final `EXTENDED` | 60 s idle | Close, unless designated pool spare | `C_ACTIVE` |
| `C_ACTIVE` | ≥ 1 stream | First `BEGIN` | — | — | `C_ROTATE` |
| `C_ROTATE` | Past 70 % of lifetime (7 of 10 min) | Timer | 3 min drain | Force-`END` remaining streams | `C_CLOSING` |
| `C_CLOSING` | `DESTROY` sent both ways | Any teardown | 5 s | Free state regardless of acknowledgement | `C_DEAD` |
| `C_DEAD` | Freed; `CIRCID` quarantined | — | 60 s | `CIRCID` returns to the pool | — |

Worst-case 3-hop build: 5 + 10 + 10 + 10 = **35 s** hard ceiling. The client also
runs an **adaptive soft timeout** at the 80th percentile of its own recent
successful builds, floor 1.5 s, ceiling 30 s; a build exceeding it is abandoned
and retried on a different path while the original completes in the background
(a late build is still a usable circuit and still teaches the weighting
function). The estimator's window and percentile are **[NEEDS RESEARCH]**; the
floor and ceiling are specified defaults, not measurements.

#### Failure handling by hop position

| Position | Failure | What the client can conclude | Action | Local weight effect |
|---|---|---|---|---|
| Guard | Link refused / times out | Guard unreachable *from here* — may be a local network problem | Mark `DOWN` with backoff; use the other primary | Down-count only; **never** an immediate replacement |
| Guard | No `CREATED`, or `AUTH` fails | Stale descriptor, or the guard is not who it claims | Refetch descriptor once; on a second `AUTH` failure remove from the primary set | Hard negative — the one failure that removes a guard quickly |
| Middle | `EXTENDED` times out | Hop k is down, refusing, or hop k−1 dropped the cell — **ambiguous** | `TRUNCATE` to k−1, redraw hop k excluding it | Small negative for hop k, smaller for hop k−1; the ambiguity is real |
| Middle | `EXTENDED` with bad `AUTH` | Either hop k is not the advertised relay, or hop k−1 tampered | Destroy the circuit; do not repair — one of the two is hostile | Hard negative for **both** |
| Terminal | `BEGIN` with no `CONNECTED` in 15 s | Destination unreachable, or terminal refuses the role | `END` the stream; `TRUNCATE` to H−1 and re-extend, preserving the guard leg | Negative for the terminal; none for the destination unless it fails on ≥ 2 distinct terminals |
| Terminal | Integrity failure on the innermost layer | Only the terminal could produce a valid inner layer, so this is tampering between it and us | Destroy; record every hop | Negative across the path, weighted toward hops nearest the failure |
| Any | `DESTROY` received | Explicit teardown with a reason code | Do not retry the same path | Depends on the reason code |

Two rules that are easy to get wrong:

1. **Preserve the guard leg on downstream failures.** A full rebuild after a
   terminal failure means a new `CREATE` at the guard, and repeated rebuilds
   give the guard a circuit-count signal tracking the user's difficulty reaching
   one destination. `TRUNCATE` + re-extend creates no new circuit at the guard.
2. **Never let failure drive guard selection.** An adversary who can make a
   client's guards fail can walk it onto a guard of the adversary's choosing.

---

### 8.5 Guards

#### Why guards exist at all

Let `f` be the fraction of the relay set, by selection weight, an adversary
controls. Take `f = 0.05`.

```text
No guards, I2P-style churn
  pool = 3 inbound + 3 outbound = 6 tunnels
  10-min lifetime → 144 rebuilds/slot/day → 864 builds/day
  P(no hostile first hop in one day) = 0.95^864 ≈ e^-44.3 ≈ 6 × 10^-20
  Distinct relays serving as first hop over 90 days:
      min(864 × 90, |relay set|) ≈ the whole relay set

Guards, as specified
  Distinct relays serving as first hop over 90 days: at most N_sample = 20,
  at most 2 live at any moment.
```

Guards do not reduce the probability that a single draw is hostile. They reduce
the **number of draws**, which is what turns a near-certainty into a bounded
risk. That is the whole argument, and it is why R1 makes the pool
guard-constrained rather than choosing between the two designs.

#### Structure

```text
RELAY SET  (from §8.7)
    │  weighted draw under diversity constraints, then refilled slowly
    ▼
GUARD SAMPLE   N_sample = 20, ORDERED by insertion, persisted per context,
               entries expire after 90 days
    │  earliest usable entries
    ▼
PRIMARY GUARDS  2, rotated every 45 days
```

| Parameter | Value | Source |
|---|---|---|
| Primary guards per isolation context | 2 | Constitution §5 |
| Primary rotation | 45 days | Constitution §5 |
| Sample size `N_sample` | 20 | This section |
| Sample entry lifetime | 90 days | Constitution §5 ("90-day list") |
| Minimum bond for the guard role | `BondFloor(GUARD)` | Accounting plane; a guard sees more than any other hop and should cost more to be |
| Down-backoff | 1 min doubling to 4 h | This section |

```text
SelectPrimaries(ctx):
  S ← LoadGuardSample(ctx)                        # ordered, persisted

  # 1. Expire — never on failure
  for e in S:
      if now - e.added > 90d
         or e.relay.bond < BondFloor(GUARD)
         or e.relay.descriptor unresolvable for > 7d:   mark e RETIRED
  # A relay that is merely DOWN is NOT retired. Down is a state; retired is
  # a decision, and an adversary must not be able to force decisions.

  # 2. Refill to N_sample, preserving insertion order
  while count(S, not RETIRED) < 20:
      r ← WeightedDraw(relay set, weights from §8.7, role = GUARD)
      reject r if it shares /16 (v4) or /32 (v6), ASN, or operator label
             with any non-RETIRED entry of S
      append r to S with added = now

  # 3. Primaries are the EARLIEST usable entries
  P ← []
  for e in S in insertion order:
      if e RETIRED or e DOWN: continue
      if e shares /16, ASN or operator with anything in P: continue
      P.append(e); if len(P) == 2: break

  # 4. Scheduled rotation, independent of failure
  if now - ctx.last_rotation > 45d:
      demote the older primary to the sample tail; ctx.last_rotation = now
```

Insertion order is load-bearing. Because primaries are always the *earliest*
usable entries, a transient failure demotes a guard only while it is down and it
is used again on recovery. Without the ordering, every failure would be an
opportunity for the next relay in the list — the guard-discovery attack.

#### The arithmetic this design does not escape

```text
Guard-selection events per context per year
  Tor-style, 1 guard × ~1 year        ≈ 1-2
  AXON, 2 guards × 45 days            = 2 × (365/45) ≈ 16.2

P(≥1 hostile relay enters the sample), f = 0.05, 20 entries   1 − 0.95^20 = 0.64
P(a given live primary is hostile)                            f = 0.05
Fraction of wall-clock time with ≥1 hostile primary           1 − 0.95² = 0.0975
```

Two guards on a 45-day cycle is roughly an order of magnitude more selection
events than Tor's design. The sample bounds total exposure (20 relays over 90
days, not 77,760), which is what makes it defensible; it does not make it as
good. An objection is filed at the end of this section.

#### Isolation contexts, specified

```text
GuardContext = (identity_scope, purpose_group)
  identity_scope ∈ { CLIENT_PERSONA(p), SERVICE(sid) }
  purpose_group  ∈ { CLIENT, SERVICE }
```

| Shares a guard set | Never shares a guard set |
|---|---|
| `INTERACTIVE` and `BULK` for the same persona | Two `ServiceIdentity` values — always, without exception |
| DHT lookups made *on behalf of* a persona (R4b) and that persona's ordinary traffic | A hosted service and its operator's client traffic |
| Storage retrieval and publication for one persona | Two `CLIENT_PERSONA` values |
| All destinations reached by one persona (destination isolation happens at the *circuit* level, §8.6) | A relay's own public DHT participation (R4a), which uses no circuit at all |

**Why traffic class does not create a context.** Splitting `INTERACTIVE` from
`BULK` at the guard doubles every user's guard count to hide from a guard that
one user does both. That is a weak signal; a client holding four guards instead
of two is a stronger one. The class selects the tunnel pool and padding regime,
not the guard set.

**Why two services must never share.** A guard sees the uptime and circuit
cadence of everything starting at it. Two services on one guard are correlated
by construction: they go down together, rebuild together, and vanish together on
reboot. That single fact links two identities the whole L5 design exists to keep
separate.

**The cost, named.** Each context costs 2 guards and a pool of 3+3+1+1 = 8
circuits × 3 hops. A node hosting 10 services holds 20 guards and 80 circuits —
in a small relay set, a large fraction of the network observing one machine —
and the *number* of guards a node holds is itself a fingerprint of how many
services it runs. **Guard-set inflation under many isolation contexts is
[UNSOLVED].** Capping contexts and sharing guards among low-value services
destroys the property above; running services on separate nodes moves the cost
rather than removing it.

---

### 8.6 Stream multiplexing over a circuit

Inside the fully-peeled 944-byte onion payload:

| Off | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | `STREAMID` | 0 = circuit-scoped. The circuit's initiator uses odd ids, the other end even, so the two cannot collide on a rendezvous-joined circuit. |
| 2 | 1 | `RCMD` | Relay command (§8.1) |
| 3 | 1 | `RFLAGS` | bit0 `FRAG_MORE`, bit1 `ACK_REQ`, bits 2-7 reserved, MUST be zero |
| 4 | 2 | `RLEN` | 0..936; above 936 is a protocol violation |
| 6 | 2 | `RESERVED` | MUST be zero; aligns `RDATA` to 8 bytes |
| 8 | 936 | `RDATA` | `RLEN` bytes; the remainder MUST be zero-filled before encryption and MUST NOT be checked on receipt (it is inside the AEAD, so it cannot be a channel, and checking costs a pass) |

`FRAG_MORE` allows a relay message up to 4 cells / 3744 bytes, for the hybrid
`EXTEND` (§8.2) and oversized `LOOKUP_REPLY` records. Reassembly buffers are
per-circuit, capped at one in-progress message, 10 s timeout.

```text
AXON stream          end-to-end, client ↔ terminal, keyed by STREAMID
  └ circuit          end-to-end, 3 hops, keyed by the per-hop key sets
     └ QUIC stream   one per circuit PER LINK  (ruling R12)
        └ QUIC conn  one per pair of adjacent relays
```

R12 buys three things and costs two. Buys: a stalled circuit cannot
head-of-line-block its neighbours (Tor's oldest performance complaint); ordered
reliable per-circuit delivery, which allows the strict `counter == expected`
check in §8.3 instead of a replay window; and circuit teardown as a stream
reset rather than a bookkeeping problem. Costs: a relay with 10,000 circuits to
one neighbour holds 10,000 QUIC stream states, so `MAX_STREAMS` becomes the
circuit-admission knob and must be set deliberately rather than left at a
library default; and the rate and pattern of stream opens on a link is metadata
that tracks circuit-build activity fairly directly. Both belong to §6; §8
records the dependency.

| Parameter | `INTERACTIVE` | `BULK` |
|---|---|---|
| `STREAM_WINDOW_INIT` / increment | 500 / 50 cells | 2000 / 200 cells |
| `CIRC_WINDOW_INIT` / increment | 1000 / 100 cells | 4000 / 400 cells |
| Link scheduling | `PRIORITY` set, served ahead of BULK | Best effort |
| Batching | None | Cells may be held ≤ 50 ms to fill a QUIC packet |
| Max concurrent streams per circuit | 64 | 64 |

> **EVALUATED (2026-08-19) — 5.1.** The figures above were carried as unmeasured
> and none was claimed. They can now be *evaluated*, because E5.2's soak measured
> the data path at **135.0 Mbit/s** (10 min, 3 hops, zero loss over 10,292,480
> cells, single-threaded, in-process) — so window and crypto can be compared on
> the same axis. A window of `n` cells permits at most `n × 936 B / RTT`:
>
> | Class | Window | 50 ms | 100 ms | 200 ms | 400 ms |
> |---|---|---|---|---|---|
> | INTERACTIVE | stream 500 | 74.9 | 37.4 | 18.7 | 9.4 |
> | INTERACTIVE | circuit 1000 | 149.8 | 74.9 | 37.4 | 18.7 |
> | BULK | stream 2000 | 299.5 | 149.8 | 74.9 | 37.4 |
> | BULK | circuit 4000 | 599.0 | 299.5 | 149.8 | 74.9 |
>
> (Mbit/s of relay payload.)
>
> **Two things fall out, and neither was previously written down.**
>
> **The circuit window is exactly 2× the stream window in both classes.** So a
> single stream can never use more than half its circuit, and saturating a
> circuit takes at least two concurrent streams. That is a deliberate ratio
> rather than a coincidence of two hand-picked pairs, and it is the kind of
> relationship that gets broken by tuning one number in isolation.
>
> **The window binds before the crypto does, at any RTT an anonymity network
> actually sees.** Against the measured 135.0 Mbit/s, BULK's *stream* window
> becomes the bottleneck above roughly **110 ms RTT**, and INTERACTIVE's above
> roughly **10 ms**. A 3-hop circuit is not going to be under 110 ms. So on this
> hardware the limit on a bulk transfer is §8.6's window, not §8.3's crypto —
> which means these figures, not the cipher, are what a throughput complaint
> would be about.
>
> **This does not discharge P5b.** The windows exist in prose only; no constant
> in `internal/axon` declares them and no flow-control loop consumes them, so
> there is nothing implemented to measure. What has changed is that choosing
> them is now an arithmetic question against a measured ceiling rather than an
> open one.

| Claimed property | None beyond onion routing; Constitution §7 applies | Timing deliberately coarsened; **still not a mixnet** |

A `DATA` cell decrements both windows and a sender stops when either reaches
zero. `DROP`, `SENDME` and every control command are exempt — otherwise flow
control would throttle the mechanism that opens flow control. These are
specified defaults with the right shape; **none has been measured on AXON.**

#### Isolation rules — which streams may share a circuit

```text
Open(dest, class, isolation_tag = dest) → stream

streams share a circuit  ⟺  equal identity_scope
                         ∧  equal isolation_tag
                         ∧  equal destination
                         ∧  equal traffic_class
```

**The linkability reason, stated exactly.** The terminal hop, and the rendezvous
point of a joined circuit, see every stream on that circuit. If streams to D₁
and D₂ share a circuit, whoever is or observes that terminal learns a single
user contacts both. The adversary does not learn who the user is; it learns that
the D₁ visitor and the D₂ visitor are the same person. Constitution §7 assumes
the adversary runs a minority of relays, so it will be the terminal for some
fraction of circuits, and every shared circuit is a free correlation for it.
Isolation makes that fraction yield one destination each instead of a set.

**The counter-argument, which is also real.** Per-destination isolation
multiplies circuit count, and circuit count is a fingerprint: 40 live circuits
is distinguishable from 4. Each extra circuit is another draw against the
hostile fraction at the middle and terminal. The design accepts this because the
linkage above is a *certain* leak to a *specific* adversary, while
circuit-count fingerprinting is a statistical leak to an adversary who must
already be watching the guard — and the guard is pinned and bonded.

| Hard rule | Reason |
|---|---|
| `INTERACTIVE` and `BULK` never share a circuit | Different windows and (in v2) different padding regimes; mixing makes padding meaningless and windows wrong |
| Different `identity_scope` never share a circuit | §8.5's guard rule, one level down |
| A circuit that has carried a stream for D is never used for D′ | "Once bound, always bound". Reusing a drained circuit re-creates the linkage isolation prevents, one destination at a time |
| A circuit past `C_ROTATE` accepts no new streams | Otherwise a long stream keeps a circuit alive past rotation and defeats the 10-minute lifetime |
| Streams are bound to **sessions**, not circuits (R9) | Circuit death migrates the session's streams to a fresh circuit in the same pool; the session layer above L4 owns resumption |

---

### 8.7 Path selection

> **AS BUILT (2026-08-16) — P12, P12a, P12b.** `internal/axon/path` and
> `internal/axon/profile`, 100 tests across path/profile/peer/placement.
> **Two statements in this subsection were found to be in conflict with other
> sections while it was being built, and both are now resolved in code:**
>
> **1. The prefix width.** This subsection says "no two hops in the same IPv4
> /16 or IPv6 /32". §7.5 says /24 and /48. They had been read as one number, and
> `peer.PrefixLenV4`'s comment cited BOTH sections for /24 — which made every
> path constraint **256× weaker than this table asks for**. They are now
> separate constants: `params.PathPrefixBitsV4/V6` = /16 and /32 for paths,
> `peer.PrefixLenV4/V6` = /24 and /48 for replication. The asymmetry is correct
> and is now written down: placement defends against *correlated outage* (a
> rack, a /24), a path defends against a *vantage point* (an ISP sees a /16).
>
> **2. The unlabelled operator.** This table says all unlabelled relays count as
> ONE operator; P12b's card says two unknown operators are never equal. Both are
> right about a different input — this section assumes a **self-declared label**,
> where omitting it buys diversity, and P12b reads the **bonded on-chain owner**,
> where there is nothing to omit. Implemented as
> `UnknownOperatorPolicy{Distinct|Collapse}`, defaulting to P12b's reading,
> because Collapse cannot build a 3-hop path at all on a network where nothing
> is registered. **The exposure the default carries is real and open**: this
> subsection's own `bond >= BondFloor(role)` filter is what would exclude an
> unregistered relay, and that filter is P14/P15's and **is not built**.
>
> **Also not as specified:** §8.7's `probation(r) = 0.25` for a relay with fewer
> than 5 observations is **not implemented**, because P12a's T12a.2 requires a
> fresh node to fall back to **uniform** selection — 0.25 is a penalty on being
> unknown, and this section itself calls it "a weak substitute for knowledge".
> `pos_mult` (position-dependent weights) is not implemented; guard position is
> P7's and is already pinned.
>
> **Deliberately NOT claimed:** **E12.3 is discharged against a published model
> in `path/model.go`, not against a live network** — 10⁵ selections over 60
> synthetic relays, measured 0.03923 vs model 0.03860, inside a 5σ tolerance of
> 0.00305. **E12.4** is satisfied by that model being code rather than prose.
> **T12.2's production wiring is NOT done**: `placement.Candidate.Domains`
> exists and is enforced, but no caller populates it yet, so live shard
> placement still guarantees distinct-PEER only. **T12.5 catches a crude
> partition and not a careful one** — two large, diverse, disjoint halves trip
> neither floor, and R14's residual is untouched.

R14 removes the consensus document. This subsection is where that ruling is paid
for, and it is the least solid part of §8.

| Attribute | Source | Trustworthiness |
|---|---|---|
| `RID`, `B`, `EK`, epoch | Signed relay descriptor in the DHT | Authentic if the descriptor verifies (L3) |
| `adv_bw` advertised capacity | Self-declared | **Free to inflate** |
| `bond` bonded stake | On-chain `StakeVault`/`NodeRegistry`, read through the existing light client (`internal/ethproof`) | Authentic and expensive to fake |
| Role flags | Self-declared | Free to declare, constrained by per-role bond floors |
| `/16`, ASN | Derived by the client from the descriptor's address | Verifiable by connecting; an address the relay does not answer on is useless to it |
| Operator label, jurisdiction | Self-declared | **Hints only.** `internal/channel/route.go` already states the rule: used to EXCLUDE, never to prove independence |
| `succ`/`fail`, observed throughput | This client's own history | Trustworthy for this client, and nobody else's business |

```text
w(r, position) = bw_eff(r) · rep(r) · probation(r) · pos_mult(r, position)

bw_eff(r)    = min( adv_bw(r),
                    BW_PER_BOND · bond(r),
                    obs_p90(r) if this client has ≥ K_min = 5 observations )
rep(r)       = clamp( succ / (succ + fail + 2), 0.05, 1.0 )   # Laplace-smoothed
probation(r) = 0.25 if fewer than K_min observations, else 1.0
pos_mult     = 1.0 (GUARD, if role offered and bond ≥ BondFloor(GUARD))
             = 1.0 (MIDDLE)
             = TerminalWeightFactor (TERMINAL, if role offered)
             = 0   if the relay's declared policy forbids the role
```

Three deliberate choices inside that formula:

1. **Bandwidth is bounded, not trusted.** `BW_PER_BOND · bond` means a relay may
   only claim capacity it has bonded for. Inflating `adv_bw` past the ceiling
   buys nothing; reaching the ceiling costs capital that is slashable by the
   existing `DisputeManager`. This replaces a measurement authority with "you
   may claim what you have staked against".

2. **Weight is LINEAR in bond, and this is a deliberate divergence from the
   existing code.** `internal/facilitation/witness.go:76-85` computes
   `selectionWeight = sqrt(stake) × reputationBps`. Sublinear weighting is right
   *there* — witness selection wants to stop one large staker dominating every
   draw, and the group pass plus a per-identity registration cost does the
   anti-Sybil work. It is **wrong here**: split a bond `S` across `k` identities
   and sublinear weighting gives total `k · √(S/k) = √(kS)`, which is `√k` times
   *more* path share than keeping it whole. Sublinear weighting pays an
   adversary to Sybil. Linear is Sybil-neutral — splitting leaves total weight
   unchanged. Superlinear would punish splitting but concentrate paths on the
   largest stakers, which costs more diversity than it buys.

3. **Observations never leave the client.** `obs_p90` and `succ`/`fail` are
   local. No reputation gossip, no published blacklist. This kills the slander
   vector completely: a client cannot damage a relay it dislikes, because nobody
   ever asks it. The price is slow learning and a fresh client with no history;
   `probation = 0.25` is a weak substitute for knowledge.

| Diversity constraint (hard filter, not a weight) | Rule |
|---|---|
| Network | No two hops in the same IPv4 /16 or IPv6 /32 |
| Autonomous system | No two hops in the same ASN |
| Operator | No two hops with the same declared operator label |
| Unlabelled operator | **All** unlabelled relays count as one operator, so at most one per path |
| Family | A mutually-signed family declaration counts as one operator |

The unlabelled rule resolves a conflict inside the existing tree that should be
recorded: `internal/channel/route.go:99-105` *excludes* unlabelled candidates
entirely, while `internal/facilitation/witness.go:36-39` treats an empty `Group`
as its own unique group. The first is too strict for path selection (it would
exclude most of a young network); the second is exploitable (omitting the field
buys diversity). Collapsing all unlabelled relays into one operator is the
conservative reading of both.

**Refuse rather than degrade.** If the constraints cannot be met, selection
returns a typed refusal naming what was missing — the `RouteRefusal` shape from
`internal/channel/route.go:71-84`. There is no best-effort mode: a three-hop path
through one operator provides no anonymity while reporting success, and a system
that looks private invites people to behave as though it is.

```text
SelectPath(ctx, class, dest, H = 3):
  1. hop[1] ← the healthier primary guard for ctx                    (§8.5)
  2. C ← relay descriptors from the local cache, filtered:
           descriptor signature valid AND RoutingIdentity epoch current
           bond ≥ BondFloor(role)
           not in ctx.AvoidSet (used by this context within RotationWindow)
           not diversity-conflicting with hops already chosen
  3. hop[H] ← WeightedDrawWithoutReplacement(C, w(·, TERMINAL))
       # Terminal FIRST: its role/policy constraints are tightest, and
       # drawing it last repeatedly produces paths with no legal exit.
  4. for k = 2 .. H-1:
         hop[k] ← WeightedDrawWithoutReplacement(C, w(·, MIDDLE)),
                  re-filtering diversity against the partial path each time
  5. any empty candidate set → RouteRefusal{reason, counts}
  6. The draw is seeded per circuit, NOT per client.
```

The weighted-draw-without-replacement primitive with a diversity first pass
already exists in `internal/facilitation/witness.go:103-167`. The structure is
reusable; the weight function is not (point 2). Note also that path selection
must **not** be deterministic given the same inputs — the witness selector is
deliberately reproducible so a dispute can re-derive it, and reproducibility
here would let anyone who learned the seed replay a client's path choices.

#### The residual risk — [UNSOLVED]

Without a consensus, two clients can hold different views of the relay set, and
an adversary who controls what a client can find has controlled its paths. This
is the hardest problem in §8 and it is not solved. What can be said:

**The chain narrows it from fabrication to suppression.** Relay *membership* —
which NodeIdentities are bonded, at what level, under which roles — is on-chain
state, verified through the light client that already exists and has already
verified a 512/512 mainnet sync-committee signature (`doc/trust-anchor.md`).
Relay *descriptors* come from the DHT.

| Attack | DHT only | With chain-anchored membership |
|---|---|---|
| Invent 10,000 relays for one client | Cheap | Impossible without 10,000 bonds |
| Hide the honest relays from one client | Possible | **Still possible** |
| Show a real but adversary-chosen subset | Possible | **Still possible**, but the client can compare the descriptor count it can find against the on-chain bonded count and refuse to build when the ratio collapses |

That last row converts an invisible partition into a visible one. It does not
stop the partition. Other partial mitigations, none sufficient: `KadID =
H(NodeIdentity ‖ SRV_epoch ‖ network-prefix)` makes keyspace eclipse expensive;
d = 3 disjoint lookup paths raise the cost of controlling a lookup; a persisted
relay cache means a client notices when the set changes wholesale.

Costs of the chain anchor, honestly: an on-chain registration per relay is a
real barrier to casual relaying and pulls against R3; and it makes the relay set
as available as the chain, which R7 puts on a slow path with a long TTL. Both
are tolerable because the bonded set changes slowly. Neither is free.

---

### 8.8 Congestion and flow control

**Why circuit-level flow control is still needed on top of QUIC.** Three
independent reasons, each sufficient alone:

1. **QUIC's flow control is per link, not end to end.** A 3-hop circuit crosses
   three separate QUIC connections. When the terminal's onward link stalls,
   backpressure reaches hop 2 and stops there; the client, three links away,
   sees nothing. Without an end-to-end window a fast client fills the queues at
   hops 2 and 3 with cells that cannot leave.
2. **Relay memory is the scarce resource, and queue length is an anonymity
   problem.** Queued cells have their timing reshaped by the backlog; a long
   queue is observable through latency and is a correlation signal available to
   anyone who can probe the relay. Bounded windows bound queue depth to
   `window × 1024 B × 2 × circuits`, a number an operator can plan against.
3. **The congestion signal is on the wrong link.** QUIC's controller reacts to
   loss and delay on the link it owns; the circuit's bottleneck is whichever
   link is slowest, usually not the client's link to its guard. Per-link
   congestion control cannot converge on an end-to-end rate.

Windows are per stream and per circuit, values in §8.6. A receiver emits a
`SENDME` after consuming `INC` cells since its last one.

#### Authenticated SENDME

An unauthenticated window-opening cell is two vulnerabilities at once: an
intermediate relay can open the window without anything having been delivered (a
memory attack on the peer, and a way to make a sender emit traffic on demand),
and the timing of forged `SENDME`s is a side channel one end can modulate for
the other to read. Tor learned this and added a proof of delivery; we do the
same from the start.

```text
SENDME body
   off  size  field
    0     1   VERSION (0x01)
    1     4   WINDOW_SEQ    monotonic per direction
    5    32   PROOF

PROOF = HMAC-SHA256( key = Ab (backward; Af for forward),
                     msg = "axon/sendme/v1" ‖ CIRC_EPOCH(8) ‖ WINDOW_SEQ(4)
                         ‖ SHA-256( concatenated AEAD tags of the last INC
                                    cells actually authenticated in this
                                    direction ) )
```

`Af`/`Ab` come from the handshake KDF and are shared only between the client and
the hop that issued the `SENDME`. A middle relay does not hold them and has not
seen the tags in question — it saw *its own* layer's tags, not the terminal's —
so it cannot forge the proof. A `SENDME` whose proof fails closes the circuit.

Fixed windows are known-poor congestion control: they cannot adapt to path
capacity, interact badly with the underlying QUIC controller, and underuse fast
paths while overrunning slow ones. An RTT-driven scheme — the class Tor moved to
when fixed windows proved to be the throughput ceiling — is **[NEEDS RESEARCH]**
for v2. The `VERSION` byte exists so that upgrade needs no new command code.

---

### 8.9 Replay and injection defence

#### Within a circuit: replay is structurally impossible

Because each circuit occupies one QUIC stream per link (R12), cells arrive
reliably and **in order**. The receiver keeps no replay window, only an expected
counter — which *is* the nonce, so a mismatched counter is an `Open` failure by
construction.

```text
Open failure → DESTROY(REASON_INTEGRITY), tear down, do not forward
Open success → counter += 1
```

A replayed cell fails because its nonce is consumed and the counter has moved
on. A cell from another circuit, or from the other direction, fails because the
key differs. **Choosing an ordered reliable per-circuit stream converts replay
defence from a data structure into an assertion** — worth naming as one of
R12's benefits alongside head-of-line blocking.

#### Injection, and how far the client can localise it

A relay can always drop or delay. It cannot inject content that survives.

```text
Forward, hop k substitutes bytes
    hop k+1's Open fails immediately — detected one hop downstream.

Backward, hop k fabricates a cell
    hop k does not hold Kb_{k+1..H}, so it cannot produce valid tags for the
    layers that should sit beneath its own. The client peels layers 1..k
    successfully and FAILS at layer k+1.
    ⇒ the client learns the deepest layer index at which the chain broke,
      which UPPER-BOUNDS the position of the forger.
```

Tor's single end-to-end digest tells the client only that something went wrong.
Here the client learns *how far down the path* the corruption entered, which
feeds §8.7's local weighting with an attributable observation rather than a
circuit-wide penalty.

One subtlety worth spelling out: hop k could replay an *earlier, genuine* inner
payload from the terminal, wrapped in a fresh layer of its own, so that all tags
are genuine. It fails anyway, because the client's backward counter for hop H
has advanced and the replayed inner layer was sealed under an older nonce. **The
per-hop, per-direction, never-reset counter is what closes this hole**, and it
is why §8.3 states the counter rules as rules rather than as implementation
detail.

#### Across circuits: the CREATE replay cache

`CREATE` is the only cell an adversary can usefully replay, because it is the
one cell not yet protected by circuit state.

```text
Cache key   first 16 bytes of SHA-256(X)         HTYPE 0x0001
            first 16 bytes of SHA-256(X ‖ CT)    HTYPE 0x0002
Scope       per relay, per RoutingIdentity epoch
Structure   2 generations of a flat open-addressed set, rotated hourly;
            a lookup checks both, an insert goes into the current one

entry            16 B key + 16 B table overhead    =  32 B
design rate      200 CREATE/s sustained  (a POLICY limit enforced by the
                 handshake rate limiter, not an observation)
per generation   200 × 3600 × 32 B                 =  23.0 MB
two generations                                    =  46.1 MB
```

**46 MB is a policy choice, not a natural constant.** A relay accepting more
handshakes per second must raise the memory or shorten the generation. The
retention window is 1-2 hours, not the 24-hour epoch, so a `CREATE` older than
the window can be replayed. That is acceptable, for the reason below.

#### Why a replayed CREATE cannot fingerprint a service

A `CREATE` cell contains exactly three things: `ID`, the SHA-256 of the target
relay's *own* RoutingIdentity key; `B`, that relay's *own* advertised static
key; and `X`, a fresh client ephemeral. **Nothing in it is a function of any
service, domain, destination, or client identity.** It is addressed *to* the
relay, not *through* it.

Replaying it achieves this and nothing else: the relay performs two scalar
multiplications and emits a `CREATED` containing a fresh `Y` and an `AUTH`. The
replayer cannot derive `KEY_SEED`, which needs `x`, which never left the
original client. It cannot decrypt any later cell. It cannot learn what the
circuit was for, because that appears only in `RELAY` cells — onion-encrypted
under keys it does not hold and counter-bound to the original circuit, so a
recorded `RELAY` cell replayed into the new circuit fails its AEAD (wrong key)
and replayed into the old circuit fails its counter.

The service-fingerprinting worry is real but belongs one layer up. An
`INTRODUCE1` cell **is** a function of a specific `ServiceIdentity`: replaying it
to a suspected introduction point and observing whether the service responds is
a genuine confirmation attack. The mechanism there is the same — a cache keyed
on the introduction handshake's ephemeral, plus R10's rate-limiting token — and
the reason it is *needed* there and not here is precisely that a `CREATE`
carries no service-dependent bits and an `INTRODUCE` carries several. The L5
rendezvous section owns that cache; §8 owns this one.

So what is this cache actually for? Two narrower things: it stops an adversary
burning relay CPU by replaying one handshake in a loop (a rate limiter does this
too, less precisely), and it removes the distinguisher in which a relay behaves
differently on a first-seen versus a repeated handshake. Both are real; neither
is service fingerprinting, and the document should not imply otherwise.

---

### 8.10 What is deliberately not in v1

| Deferred | Why not now | When it becomes relevant | Status |
|---|---|---|---|
| **Cover traffic** (constant-rate, end-to-end) | Bandwidth is the scarcest resource a young volunteer network has, and cover traffic costs are linear in idle time — most expensive exactly when the network is least used. It only helps if both endpoints cooperate, so the service side must implement it too. | When `BULK` volume is large enough to hide `INTERACTIVE` inside it, or when Constitution §7's adversary is upgraded to one that sees both ends. | **[NEEDS RESEARCH]** |
| **Adaptive padding** (the website-fingerprinting defence class) | The defence is evaluated against a corpus of traffic shapes; Constitution §8 forbids building applications, so there is no corpus and no way to tell a working defence from a placebo. An unevaluated padding machine costs bandwidth and produces a claim nobody can check. | When a first gateway exists and an evaluation set can be built. Codes `0x20`/`0x21` and link `CMD 0x09` are reserved now so this is not a wire-format break. | **[NEEDS RESEARCH]** |
| **Mixing / batching for `INTERACTIVE`** | R2 declares `INTERACTIVE` explicitly non-mixed and explicitly vulnerable to end-to-end correlation. Batching would make it neither low-latency nor a mixnet — the worst of both, plus a claim we would have to defend. | Never for `INTERACTIVE`. Batching is already in scope for `BULK` in v1 (§8.6), the class where latency is not binding. | Ruling, not deferral |
| **Multipath circuits** | Splitting a session across two circuits doubles the relay set observing it, doubling the chance of drawing a hostile middle or terminal, in exchange for throughput; and the merge point is a new correlation surface. | When measured single-circuit throughput is the binding constraint on the storage layer — and not before §8.7's receipt and weighting machinery can attribute a slow leg to the right relay. | **[NEEDS RESEARCH]** |
| **Conflux-style circuit merging** | Same objection, plus a specific one: the shared terminal sees both legs and can tell they are one session, so the whole anonymity cost lands on the position we most want ignorant. | After multipath, if at all. Needs a resequencing buffer and an ordering field the relay header does not reserve, so this **is** a wire-format break and should be planned as one. | **[NEEDS RESEARCH]** |
| **Wide-block relay cipher** (§8.3) | Recovers the 6.25 % tag overhead and keeps non-malleability, but needs a primitive not in the standard library and an argument that is not one sentence. | v2, once the cell format has stabilised. The tag stack becomes reserved-and-random, so the layout does not change. | **[NEEDS RESEARCH]** |
| **Single-pass circuit construction** (§8.4) | Cuts build latency from 3 RTT to 1 and hides hop position, but destroys the failure attribution §8.7 depends on. | When relay quality can be learned from something other than the client's own build failures — in practice, when the receipt machinery works. | **[NEEDS RESEARCH]** |
| **Relay payment on the data path** | R11: the economic layer is not in v1, and the network must work with zero payments before any payment exists. `0x30`/`0x31` are reserved so the accounting plane can be added without touching the data path. | After the network runs unpaid. | Ruling |

---

### 8.11 Decision table

| Decision | Problem it solves | Derived from | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| 1024 B fixed cell, constant on every link | Cell size must not reveal hop count, position, or payload length | Tor (fixed cells); I2P (fixed 1 KB tunnel messages) | 1024 B rather than 514 B, sized for one cell per QUIC STREAM frame under the 1200 B datagram floor | Variable-length records; Tor's 514 B | Larger padding waste on small payloads; a distinctive 1024 B shape on the wire (§ NOT-established) |
| Per-hop AEAD with tag space reserved at every hop position | Per-hop malleability is the basis of tagging attacks | Tor's relay crypto, inverted | Replaced stream-cipher-plus-end-to-end-digest with an AEAD per layer | Wide-block tweakable cipher (deferred, v2); AES-GCM as default | 6.25 % overhead; an intermediate relay learns a cell was corrupted upstream |
| Rotating tag stack, every hop reads `TAG[0]` | A fixed tag index would tell each relay its position | I2P's position-hiding instinct; `internal/channel/onion.go`'s slot permutation | A 64 B `memmove` instead of a per-packet Fisher-Yates and H_max trial decryptions | Indexed slots; per-packet permutation | Does not close the position leak from telescoping (§8.4) |
| ntor-style 1-RTT handshake against RoutingIdentity | Authenticate a relay without a signature per circuit, with forward secrecy | Tor's ntor | Bound to an epoch-scoped RoutingIdentity, not a long-term identity; HKDF-SHA256 labels per Constitution §2 | Signed handshake (a signature per circuit, no FS); TLS to each hop | Compromise of `b` allows impersonation until the epoch rolls |
| Hybrid X25519 + ML-KEM-768 as a negotiated HTYPE | Harvest-now-decrypt-later | New; not present in Tor/I2P/Freenet | `EK` published in the descriptor so only the 1088 B ciphertext travels; `CREATE_FRAG` + `FRAG_MORE` carry it | Sending `EK` on the wire; deferring PQ entirely | Fragmentation state at relays is new DoS surface (bounded at 2 and 4 cells) |
| Telescoping build | Path must be repairable and failures must be attributable | Tor | `RELAY_BUILD` budget held privately per relay instead of an on-wire counter | Sphinx-style single pass (deferred, v2) | 3 RTT build cost; each relay learns roughly where it sits |
| 2 primary guards from a 20-entry ordered 90-day sample, 45-day rotation | Bound the number of distinct first hops a client ever exposes itself to | Tor's guards + guard sample; I2P's failover | Two primaries instead of one, drawn from a sample rather than the whole relay set (R1) | I2P per-tunnel churn; Tor's single guard | ~16 selection events/year vs Tor's 1-2; guard-set inflation with many services **[UNSOLVED]** |
| Per-destination stream isolation by default | A shared circuit lets the terminal link two destinations to one user | Tor's stream isolation | Isolation tuple is explicit in the API rather than inferred from SOCKS credentials | One circuit per client; isolation only on request | Circuit count becomes a client fingerprint; more draws against the hostile fraction |
| One QUIC stream per circuit per link (R12) | Cross-circuit head-of-line blocking | New; Tor multiplexes circuits on one TCP connection | QUIC instead of TCP, one stream per circuit | Tor's shared-connection model | 10,000 stream states per busy neighbour; stream-open pattern is link metadata |
| In-order counter check instead of a replay window | Replay within a circuit | Tor's sequence discipline | Made structural by relying on R12's ordered delivery | Sliding replay window; per-cell random nonces | A transport that ever reorders silently breaks the assumption |
| Bounded self-report: `bw_eff = min(adv_bw, BW_PER_BOND·bond, obs_p90)` | R14 — no consensus, no measurement authority, and self-reported bandwidth is free to inflate | Tor's bandwidth authorities, removed; `internal/channel/route.go` (capacity used to exclude, never to reward) | Capacity claims are capped by bonded stake, which is slashable | Central bandwidth measurement; trusting `adv_bw`; ignoring bandwidth entirely | A well-funded adversary can buy legitimate weight; bond floors gate casual relaying (against R3) |
| Weight linear in bond, **not** `sqrt` | Sublinear weighting pays an adversary to split a bond across Sybils | Diverges from `internal/facilitation/witness.go:76-85` | Linear instead of `sqrt(stake) × reputation` | Sublinear (Sybil-positive); superlinear (concentrates paths) | Path share is proportional to capital |
| Client observations never leave the client | A published reputation signal is a slander channel | Neither Tor nor I2P; a deliberate refusal | No gossip, no shared blacklist | Reputation gossip; signed client complaints | Slow learning; cold-start clients have no history **[UNSOLVED]** |
| Chain-anchored relay membership, DHT-served descriptors | R14's partitioning attack | New; uses the existing light client (`doc/trust-anchor.md`) | Membership from verified chain state, descriptors from the DHT | A consensus document; floodfill-style directory peers | Relay set is as fresh as the chain (R7); on-chain registration per relay |
| Authenticated `SENDME` with a delivery digest | A forged window-opener is both a memory attack and a side channel | Tor, which added proof-of-delivery after the fact | Built in from the start, keyed by `Af`/`Ab` from the handshake KDF | Unauthenticated `SENDME` | Fixed windows are poor congestion control (v2 problem) |
| `CREATE` replay cache, 2 hourly generations, 46 MB | Repeated-handshake CPU burn and a first-seen/repeat distinguisher | Tor's replay caches; `internal/channel/onion.go`'s `ReplayGuard` | Explicit memory bound derived from a declared handshake rate policy | Unbounded cache; no cache at all | A `CREATE` older than the 1-2 h window can be replayed (harmless, §8.9) |
| No cover traffic, no adaptive padding in v1 | Cost without a way to evaluate the benefit | Tor's and I2P's padding, deliberately not adopted yet | Command codes reserved so v2 is not a wire break | Shipping unevaluated padding | `INTERACTIVE` remains explicitly correlatable end-to-end (Constitution §7) |

### 8.12 Component status

| Component | Status |
|---|---|
| Cell format, command dispatch, `CIRCID` management | **[BUILD NOW]** |
| `axon-ntor-v1`, constant-time `AUTH`, low-order point rejection | **[BUILD NOW]** |
| `axon-ntor-hybrid-v1` wire format, `CREATE_FRAG` / `FRAG_MORE` with bounds | **[BUILD NOW]** — enabling by default is a later measurement decision |
| Per-hop AEAD, rotating tag stack, counter discipline | **[BUILD NOW]** |
| Telescoping build, state machine, `RELAY_BUILD` budget | **[BUILD NOW]** |
| Guard sample/primary structure, insertion ordering, down-vs-retire | **[BUILD NOW]** |
| Stream multiplexing, per-destination isolation, both window levels | **[BUILD NOW]** |
| Bounded self-report, linear-in-bond weighting, diversity filters, typed refusal | **[BUILD NOW]** (port the shape from `internal/channel/route.go`) |
| Authenticated `SENDME`; in-order counter check; `CREATE` cache | **[BUILD NOW]** |
| Mutual hop receipts as relay-side work evidence | **[BUILD NOW]** — receipt shape from `internal/facilitation/receipt.go`. Note `ServiceType` (0..6) has **no relay/circuit index**, and adding one is a coordinated change across two repositories, as that file's own header warns |
| Adaptive circuit-build timeout estimator (window, percentile) | **[NEEDS RESEARCH]** |
| Relay-side handshake CPU budget; whether 200 CREATE/s is realistic | **[NEEDS RESEARCH]** |
| Detecting a guard that fails selectively rather than genuinely | **[NEEDS RESEARCH]** |
| RTT-driven congestion control replacing fixed windows | **[NEEDS RESEARCH]** |
| Wide-block relay cipher; single-pass construction; multipath | **[NEEDS RESEARCH]** |
| Guard-set inflation under many isolation contexts | **[UNSOLVED]** |
| Cold-start clients with no observation history | **[UNSOLVED]** |
| Epistemic partitioning / differing views of the relay set | **[UNSOLVED]** |

---

### What this section does NOT establish

- **No number here has been measured.** Every timeout, window, memory bound and
  rate limit is a specified default chosen for its shape. The only figures with
  operational history — `inbound.length=3 outbound.length=3 inbound.quantity=3
  outbound.quantity=3 inbound.backupQuantity=1` in `internal/i2p/sam.go:84-87` —
  describe what this node asks a *foreign* I2P router for and say nothing about
  our own code. The 46 MB replay cache, the 200 CREATE/s design rate, the 35 s
  build ceiling and the 23 MB/s AEAD throughput are arithmetic or assertion.

- **The onion construction has not been reviewed or proved.** §8.3's argument —
  "each hop's layer is an AEAD under a key shared only with the client, so
  forging a layer is forging an AEAD" — is informal. The rotating tag stack, its
  interaction with the backward direction, and the claim that the discarded
  filler slot leaks nothing all want a written proof sketch and a differential
  test suite before anyone relies on them.

- **Nothing here defends against traffic confirmation.** Per-hop AEAD removes
  bit-level tagging. It does not touch dropping, delaying, or volume
  correlation, and Constitution §7 already places the adversary holding both
  ends of an `INTERACTIVE` circuit outside the threat model. No claim in §8
  narrows that exclusion.

- **No fingerprinting analysis exists.** 1024-byte cells, one QUIC stream per
  circuit, a 3-RTT telescoping build and per-destination isolation together
  produce a distinctive wire shape and a distinctive stream-open pattern on
  every link. Nothing here measures how distinguishable an AXON link is from
  ordinary QUIC, or how much a client's circuit count reveals about the number
  of destinations and services it has.

- **The epistemic problem is narrowed, not solved.** Chain-anchored membership
  converts fabrication into suppression and gives a client a countable
  discrepancy to notice. It does not stop an adversary who controls a client's
  view from showing it a real but adversary-chosen subset, and it does nothing
  for a client with no observation history.

- **The guard arithmetic is worse than Tor's and this section says so rather
  than solving it.** Two primaries on a 45-day cycle is roughly 16
  guard-selection events per context per year against Tor's one or two. The
  20-relay sample bounds total exposure, which is what makes the design
  defensible; it does not make it as good.

---

> **Objection to Constitution §5 (guards: 2 primary, 45-day rotation):** The
> arithmetic in §8.5 is uncomfortable. Two primaries rotating every 45 days
> gives ≈ 16.2 guard-selection events per isolation context per year against
> ≈ 1-2 for a single long-lived guard, and the fraction of wall-clock time with
> at least one hostile primary rises from `f` to `1 − (1−f)²` — 5 % to 9.75 % at
> `f = 0.05`. The 20-entry sample bounds the *total* set of relays that ever see
> the client as a first hop, which is what makes the design defensible, but
> rotation frequency is where the exposure lives. Two suggestions, in order of
> preference: (a) keep 2 primaries and extend rotation to 90 days so primary
> rotation and sample expiry coincide, halving the selection events at no cost
> to failover; or (b) keep 45 days but make the second primary a *standby* that
> carries traffic only when the first is down, so steady-state exposure is `f`
> rather than `1 − (1−f)²`. Option (b) preserves R1's failover property exactly
> and is the cheaper change. §8 is written to conform to the Constitution as
> given.

> **Objection to Constitution §5 (per-hop tag reservation at `H_max`):** With
> `H_max = 4` and a 3-hop default, every cell of every default circuit carries
> 16 bytes of tag that is never verified — 1.6 % of all network traffic,
> permanently, so that circuit length is not readable from the cell layout. This
> is the correct trade and should stay, but the document should state explicitly
> that `H_max` is a **network-wide constant that can never be raised without a
> flag day**, because raising it changes the size of the onion payload region and
> therefore every relay's parser. If 5- or 6-hop circuits are ever wanted,
> `H_max` should be set to that value now and the extra 32 bytes paid from the
> start.
