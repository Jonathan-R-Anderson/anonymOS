## 6. Secure Transport and NAT Traversal

> **AS BUILT (2026-08-16).** `internal/axon/link` (P2) and `internal/axon/peer`
> (P3), 44 peer tests. The `Build status` table below still reads `[BUILD NOW]`
> for items that are done; treat this note as current and that table as the
> original plan.
>
> **Done:** QUIC + TCP link with byte-identical framing, cell codec, §6.5
> classification (PUBLIC/MAPPED/EIM/EDM/CGNAT/UDP_BLOCKED/OFFLINE), role gating,
> address quorum ≥ 3, prober-refusal handling, bootstrap partition audit, UPnP +
> NAT-PMP mapping off by default. E2.1 = 10⁶ cells per transport, identical digest.
>
> **Deliberately NOT claimed:** **E2.2** ("within 10 %") needs a controlled link
> with stable RTT, not a loopback pair — the test asserts the qualitative R12
> property instead. **T2.6** (two independent builds emit identical QUIC Initials)
> needs a reproducible-build harness that does not exist. **Hole punching** and
> **link padding** remain unbuilt as the table says.
>
> **A limit that is not in the table:** `go-libp2p-asn-util` resolves ASNs for
> **IPv6 only**, so IPv4 peers get `ASNUnknown` and any ASN-diversity constraint
> degrades to prefix-only. This is reported through `ConstraintReport`, never
> silently substituted.

**The finding that shapes this section: NAT traversal and anonymity are in
direct conflict, and the conflict is not resolvable at L1.** Every technique
that turns an unreachable node into a directly-dialable one — hole punching,
port mapping, relayed link setup — works by telling two endpoints each other's
IP address, which is what L4 exists to prevent. So AXON gives inbound
reachability only to nodes whose address is *already public by role* (relays,
introduction points, rendezvous points, DHT servers), and gives everyone else
inbound service through an L4 tunnel, where address hiding is the point. **There
is no link-level relay in AXON.** Circuit Relay v2's job is done by the
anonymity layer, once, instead of by two mechanisms with different security
properties.

The second finding decides more code: **libp2p is not AXON's L1 or L2** — not
from "not invented here", but because libp2p's NAT machinery is built on address
gossip AXON must suppress, and a libp2p peer ID is a mandatory second name for
NodeIdentity.

### What already exists

Read from `/home/bruns/Documents/maniwani/storage-client`:

| Existing | Path | State |
|---|---|---|
| libp2p host construction, two variants | `internal/p2p/node.go:346` (`openI2PNode`), `:405` (`openNode`) | Production is the I2P variant. |
| I2P SAM transport implementing `transport.Transport` | `internal/i2p/transport.go`, `internal/i2p/sam.go` | The dependency being removed. |
| Node identity key | `internal/p2p/node.go:731` `loadOrCreateIdentity`, file `<dataDir>/p2p.key`, `crypto.GenerateEd25519Key` | Ed25519, stored in libp2p's marshalled form. |
| Signing surface | `internal/p2p/node.go:525` `Sign`, `:533` `PublicKey` | Private key never leaves libp2p's peerstore. |
| Storage stream protocol | `ProtocolID = "/syndichan/storage/1.0.0"`, `internal/p2p/node.go:54`, handler `:1133` | JSON frames, 30 s stream deadline. |
| DHT mode | `internal/p2p/node.go:438` `dht.New(h, dht.Mode(dht.ModeAutoServer))` | See below. |
| Dial timeouts | `internal/p2p/node.go:69` `i2pDialTimeout = 2m`, `:70` `directDialTimeout = 10s` | Measured against real I2P LeaseSet lookup latency. |
| Dependency set | `go.mod` | 126 module requirements; 156 unique modules in `go.sum`; 14 libp2p modules; 17 pion modules. |

Three things in that inventory matter more than the rest.

**The production node uses none of libp2p's connectivity machinery.**
`openI2PNode` passes `libp2p.NoTransports`, installs only the I2P transport,
passes `libp2p.DisableRelay()`, and passes
`libp2p.AddrsFactory(i2pAddressesOnly)`, which strips every non-`/garlic32`
address (`internal/p2p/node.go:366-375`, `:506`). QUIC, Circuit Relay v2 and
hole punching are compiled in and switched off. The only path that enables
`libp2p.NATPortMap()` and `libp2p.EnableHolePunching()` is `openNode`
(`:410-415`), and every caller of it in the tree is a `_test.go` file listening
on `/ip4/127.0.0.1/tcp/0`. **This project has never operated libp2p's QUIC
transport, AutoNAT, relay or DCUtR in production**, so "reuse the battle-tested
thing" is weaker here than it looks: either way this deployment is bringing up
transport code it has not run.

**Reachability is assumed, not measured.** `dht.ModeAutoServer` defaults to DHT
server mode while reachability is unknown and demotes only on a reachability
event; over an address set of nothing but `/garlic32` there is no IP for a
dial-back, so no verdict is available to demote it. In practice the node is a
DHT server unconditionally. §6.5 makes reachability an explicit, probed,
demotable input.

**There are already two names for one key.** `n.ID()` returns
`host.ID().String()` — a multihash over the protobuf-wrapped public key — while
Proof of Facilitation names the same node `keccak256(ed25519 pubkey)`
(Constitution §0). One private key, two identifiers, and the one the transport
authenticates is libp2p's.

**What must be replaced:** the libp2p host, its security and stream negotiation,
its NAT and relay protocols, and `internal/i2p` entirely. **What is kept:** the
Ed25519 key material and the `p2p.key` file (re-encoded — see §5), the storage
protocol's *semantics* (not its framing), and the diversity levels in
`internal/placement/level.go`, reused for the address quorum in §6.5.

### The ruling on libp2p, and what it costs

**AXON implements L1 and L2 natively on `quic-go`. go-libp2p is not linked into
`axond`.**

This is not a rejection of the underlying libraries. The distinction that makes
the decision cheap:

| Component | Verdict | Reason |
|---|---|---|
| `quic-go` (RFC 9000 implementation) | **REUSE** | Already an indirect dependency at v0.59.1. We are not writing a QUIC stack. It exposes `crypto/tls` configuration directly, which is what we need for §6.1. |
| Go `crypto/tls` TLS 1.3 | **REUSE** | Standard library, on the security path, already trusted by the existing HTTP clients. |
| `huin/goupnp`, `jackpal/go-nat-pmp` | **REUSE (direct)** | Standalone port-mapping libraries. Usable without a libp2p host; already in `go.mod` as indirect deps. |
| `pion/stun` | **REUSE, optional** | Only for the operator-supplied external STUN case in §6.5. AXON's primary address discovery is peer-mutual, not STUN. |
| libp2p security (Noise, libp2p-TLS) | **REPLACE** | libp2p-TLS carries a libp2p-specific X.509 extension holding the host key; the certificate exists only to smuggle a key TLS 1.3 can carry natively. §6.1 does it directly. |
| multistream-select | **REPLACE** | A plaintext protocol-name negotiation and an extra round trip **per stream**. With one stream per circuit (R12) and 10-minute tunnel lifetimes, that is a per-circuit RTT and a fixed identifiable string, repeatedly. |
| yamux | **DROP** | Only needed over TCP. §6.3 frames cells directly; fixed-size cells need no length-prefixed muxer. |
| Identify | **REPLACE (reduced)** | Identify hands any dialer the peer's full listen-address set, protocol list, and agent version, and it is the substrate AutoNAT/relay/DCUtR consume. AXON publishes addresses in a signed descriptor (§7) and tells a peer only the address it was observed at. |
| AutoNAT v1/v2 | **REPLACE** | Depends on Identify's address gossip. §6.5 specifies the reduced form. |
| Circuit Relay v2 | **DROP** | Superseded by L4. See the section opening. |
| DCUtR | **REPLACE (narrowed)** | The coordination idea is right; §6.5 restricts it to links where both endpoints are already publicly identified. |
| peerstore / connection manager / resource manager | **REPLACE** | Small, and they are where our own admission and accounting policy has to live (§15). |
| `peer.ID` | **DELETE** | See below. |
| `go-libp2p-kad-dht` | **§7's call, but it cannot be linked** | Kademlia logic runs on a `host.Host`. With a native L1 the implementation is design lineage, not a linked library. Flagged as a cross-section consequence. |

**The four arguments that decide it.**

1. **libp2p's NAT machinery cannot be kept without the address gossip AXON must
   suppress.** AutoNAT, DCUtR and relay discovery all consume Identify. Disable
   Identify and you keep libp2p's QUIC wrapper and lose the connectivity stack
   you kept libp2p for; keep it and every dialer learns the node's full address
   set and protocol list on connect. There is no configuration of libp2p that is
   both quiet and NAT-capable.

2. **`peer.ID` is a structural second identity.** Constitution §3 forbids two
   identity classes sharing a key; this is the mirror failure — one key with two
   names, where the transport authenticates the name AXON does not use and every
   layer above carries a mapping table that is a substitution-attack surface.
   Worse: a libp2p connection authenticates NodeIdentity, while circuits are
   extended to **RoutingIdentity** (§5, §8). Riding circuits on libp2p streams
   puts the forward-secrecy boundary in libp2p's hands, on the wrong key.

3. **The wire format is the product.** R12 requires one stream per circuit with
   1024-byte cells; §16 requires link padding on a schedule the application does
   not control; §6.4 requires link-local circuit IDs a relay rewrites. All three
   are wire-format decisions, and owning them through an abstraction whose
   contract is "a reliable byte stream, protocol negotiated by name" is possible
   but adversarial to the library.

4. **Dependency weight on the security path.** 156 modules today, 17 of them the
   pion WebRTC stack pulled in for a transport AXON will never offer — a large
   volume of network-facing parsing in a binary whose failure mode is
   de-anonymisation. `doc/trust-anchor.md` §5 settled this question for this
   project already, and gave the reason: *"a third party on the security path
   needs the same scrutiny as writing it would."* A native L1 linking `quic-go`
   and `crypto/tls` and nothing else is a smaller audit than
   libp2p-with-most-of-it-disabled.

**The honest cost.** We give up years of hardening in libp2p's connection
handling, resource limits and dial orchestration, and will reimplement some of
its fixed bugs. Hole punching is genuinely hard, and libp2p's published DCUtR
measurements report success well below 100 % — AXON must measure its own
population (§23), not inherit a figure. Ecosystem interoperability is gone,
which for an anonymity overlay is close to a feature but means no free bootstrap
infrastructure and no third-party tooling. And the migration is not incremental:
the existing storage node keeps running on libp2p over I2P while `axond` is
built beside it, with no half-state where one host speaks both. §23 owns the
cutover.

**Marker:** native L1 link layer `[BUILD NOW]`; native L2 reachability
`[BUILD NOW]`; hole punching `[NEEDS RESEARCH]`.

### 6.1 Link protocol: QUIC with TLS 1.3 raw public keys

A **link** is a QUIC connection between two nodes, authenticated to
NodeIdentity, carrying cells for zero or more circuits. One UDP socket per node
serves every link.

```text
LINK HANDSHAKE  (TLS 1.3 inside QUIC, RFC 9000 + RFC 9001)

  initiator ─► ClientHello
                 supported_versions      = TLS 1.3 only
                 key_share               = X25519   (hybrid slot reserved, §5)
                 alpn                    = LinkALPN (one constant, §6.8)
                 server_name             = ABSENT   (not a web server)
                 server_certificate_type = RawPublicKey  (RFC 7250)
                 client_certificate_type = RawPublicKey
                 psk_key_exchange_modes  = ABSENT   (no resumption, no 0-RTT)
                 early_data              = NEVER SENT

  responder ─► ServerHello (X25519) · {EncryptedExtensions}
               {CertificateRequest}†
               {Certificate}        SPKI = NodeIdentity Ed25519 public key
               {CertificateVerify}  Ed25519 over the handshake transcript
               {Finished}

  initiator ─► {Certificate}† {CertificateVerify}† {Finished}

  ── established; LINK_INFO exchanged as cells on stream 0 ──
  † relay↔relay links only; see "who authenticates" below.
```

**What is authenticated.** The responder proves possession of the NodeIdentity
private key over a transcript covering both randoms and both key shares. That
binding is the anti-replay story at this layer: a captured flight cannot be
replayed into a different session, because the signature covers a transcript the
attacker cannot reproduce.

**What is *not* authenticated, and is the usual way to get this wrong.** A
successful handshake proves *someone holding a NodeIdentity key* answered — not
that it is the node you selected. Therefore:

> **INVARIANT L1-1.** The dialer MUST know the expected NodeIdentity before
> sending its ClientHello, MUST compare the peer's raw public key to it byte for
> byte, and MUST abort before any cell is written on mismatch. A link with no
> pinned expectation is refused, not opened.

Also not authenticated: the address (§6.5), the epoch, and anything about
RoutingIdentity — circuit extension keys live at L4 (§8) and are deliberately
not derived from the link.

**Who authenticates.**

| Link kind | Server auth | Client auth | Reason |
|---|---|---|---|
| client → guard | required | **none** | A client presenting a long-term identity to its guard would bind its traffic to a public key. Tor does not do it and neither do we. Rate limiting is per-source-address plus the L4 puzzles in §15. |
| relay → relay | required | required | Both are public by role; accounting (§14) and admission (§15) need the peer's NodeIdentity. |
| client → storage holder (BULK) | required | optional, ephemeral | If a client key is presented it MUST be a per-isolation-context ephemeral key, never NodeIdentity. |

> **TRAP.** A node that is both a relay and a client must not present its relay
> NodeIdentity when acting as a client: that links its own anonymous traffic to
> its public relay identity at the first hop. The two roles get separate TLS
> configurations and separate source-port pools; they cannot share a
> `tls.Config`.

**0-RTT: disabled. Session resumption: disabled in v1.** Four reasons, most
important first:

1. **A session ticket is a linkability primitive.** A client that resumes to the
   same relay from a new IP hands that relay a proof that two addresses are the
   same client — a de-anonymisation channel sold for one round trip.
2. **0-RTT data is replayable by construction** (RFC 8446 §8, RFC 9001 §9.2).
   Replaying an early-data flight carrying circuit setup is a tagging primitive:
   replay, then watch where the duplicate goes.
3. **0-RTT has no fresh ECDHE**, so early data is not forward secret. Circuit
   setup is the last thing that belongs in that bucket.
4. **The benefit is small in our topology.** Guards are pinned for 45 days
   (Constitution §5) and links are long-lived, so a handshake amortises over
   hours or days. 0-RTT optimises a case we deliberately do not have.

If resumption is ever re-enabled it is permitted only on a guard link, only
within one isolation context, only with single-use tickets, and still off by
default. `[BUILD NOW: the off switch]`

**Fixed QUIC transport parameters.** Transport parameters are a
per-implementation fingerprint. AXON fixes them network-wide so nodes are not
distinguishable *from each other*; the cost is that the set as a whole becomes
an AXON signature. Taken deliberately; revisited in §6.8.

| Parameter | Value | Reason |
|---|---|---|
| `max_idle_timeout` | 60 s | Longer than the keepalive floor in §6.6, short enough to reap dead links. |
| `max_udp_payload_size` | 1200 | The Constitution's floor; no PMTU-dependent behaviour, no per-path variation to observe. |
| `initial_max_data` | 4 MiB | Connection-level credit. |
| `initial_max_stream_data_bidi_*` | 64 KiB | 64 cells in flight per circuit. See the arithmetic in §6.2. |
| `initial_max_streams_bidi` | 512 | Circuits per link, per direction. Raised only by explicit config on a relay. |
| `initial_max_streams_uni` | 0 | Unidirectional streams are unused; a node offering them is not speaking AXON. |
| `active_connection_id_limit` | 8 | A pool for migration (§6.6). |
| `disable_active_migration` | absent | Migration is required. |
| `ack_delay_exponent`, `max_ack_delay` | RFC 9000 defaults | Nothing gained by varying them. |

**Default listen port:** a high port chosen at first start and persisted, never
a well-known one — a fixed network-wide port is a one-line blocklist rule.
UDP/443 is an operator option for blending with web traffic; it needs privilege
or a capability on Unix and is not the default.

### 6.2 Why QUIC and not TCP+TLS as the primary link

**The reason is R12 and it is worth the rest of the costs.** Tor multiplexes
every circuit on a link over one TCP connection, so one stalled circuit's
retransmission stalls every other circuit sharing that link — cross-circuit
head-of-line blocking that a client cannot detect, cannot route around, and does
not deserve. QUIC gives each circuit its own stream with its own flow control
and its own loss recovery ordering. A lost packet belonging to circuit A delays
circuit A only.

Three further properties earn their place: **connection migration**, so an
address change or NAT rebinding costs one path validation instead of a circuit
rebuild (§6.6); **one UDP port for every link**, so a node has one socket, one
firewall rule and one NAT mapping to keep alive rather than a TCP listener plus
outbound connections; and a **userspace implementation**, so padding and pacing
(§16) need no kernel cooperation.

**The honest costs.**

- **UDP is blocked or throttled on a real fraction of networks** — enterprise
  egress filters, captive portals, some mobile management planes. Published
  figures vary widely and none describe AXON's population; the number is
  **TBD — measure in the phase named in §23**, not inherited. §6.3 exists
  because it is not zero.
- **QUIC Initial packets are not confidential.** Initial protection uses keys
  derived from the publicly known Destination Connection ID and a published
  salt, so any on-path observer decrypts the first flight and reads the
  ClientHello, `LinkALPN` included. With the fixed transport parameters above,
  **AXON link traffic is trivially identifiable on the wire in v1.** Stated
  flatly rather than mitigated; it is the content of §6.8.
- **Per-stream state at relays is the price of R12.** Arithmetic from §6.1's
  parameters: 64 KiB of receive credit per circuit per direction means 64 MiB of
  window commitment at 1 000 concurrent circuits and 640 MiB at 10 000. That is
  a credit commitment, not steady-state RSS — a relay that never fills the
  windows never allocates — but it is the number an attacker aims at by opening
  circuits and stalling them. Bounded by `initial_max_streams_bidi`, by
  connection-level `initial_max_data` regardless of stream count, and by the L4
  circuit-creation puzzles in §15. Tor's equivalent is one TCP receive buffer
  per link: cheaper, and precisely why it head-of-line blocks.
- **Anti-amplification.** RFC 9000 §8.1 forbids sending more than three times
  the bytes received from an unvalidated address. This constrains hole punching
  (§6.5) and means link padding cannot begin until path validation completes —
  §16's schedules start after the handshake, not during it.
- **CPU.** Per-packet AEAD and packet handling in userspace cost more per byte
  than kernel TCP with kernel TLS; GSO/GRO and batched syscalls recover much of
  it. The relay-class figure is **TBD — measure; do not publish an assumed
  throughput number.**
- **One cell per datagram, and the arithmetic that forces it.** Against the
  1200-byte datagram floor: a short-header packet costs ~1 B header + up to 8 B
  connection ID + 1–4 B packet number, a STREAM frame header costs 1 B plus
  three varints, and the AEAD tag costs 16 B. One 1024-byte cell fits
  comfortably; two (≥ 2048 B) do not. So the mapping is one cell per STREAM
  frame, and a relay never coalesces two circuits' cells into one datagram —
  which is also §16's answer, since coalescing leaks circuit co-residency.

### 6.3 TCP+TLS 1.3 fallback

**Fallback is a degraded mode and the design says so out loud: over TCP,
cross-circuit head-of-line blocking comes back.** R12's benefit is a property of
QUIC streams, not of the cell format. A TCP link is still correct, still
authenticated identically, and still carries the same bytes — it is simply
subject to the failure mode we chose QUIC to escape.

**Engagement rules.**

```text
1. QUIC endpoint advertised and UDP not known-blocked
     → attempt QUIC, deadline 3 s, 2 retries with jitter.
2. Third consecutive failure to complete ANY QUIC handshake to ANY peer within
   one probe window → set local UDP_BLOCKED, log it, re-probe every 15 min.
   Never latch permanently.
3. UDP_BLOCKED, or no QUIC endpoint advertised, or operator set tcp_only
     → attempt TCP+TLS 1.3 on the peer's TCP endpoint.
4. Racing QUIC and TCP simultaneously is NOT done: it doubles the observable
   footprint and the connection state for a saving that matters once per link.
```

**The framing is byte-identical over both.** A deliberate constraint on §8's
cell format, not an accident:

```text
QUIC link   one bidirectional QUIC stream per circuit — client-initiated
            streams 0, 4, 8, …; server-initiated 1, 5, 9, … — each carrying a
            whole number of 1024 B cells, one cell per STREAM frame.

TCP link    one TLS 1.3 record stream carrying 1024 B cells back to back,
            demultiplexed by the 8-byte circuit_id already in the cell header.

            ┌──────────────── 1024 B ────────────────┐
            │ circuit_id(8) cmd(1) flags(1) len(2)   │  header 16 B
            │ reserved(4) │ payload …                │  (§5, §8)
            └────────────────────────────────────────┘
```

No length prefix is needed because cells are fixed size; no stream muxer is
needed because the circuit ID is already in the header. The circuit ID is
therefore redundant on a QUIC link and kept anyway: identical framing means one
parser, one fuzz target, one padding implementation, and a relay bridging a QUIC
link to a TCP link forwards cells without re-framing.

**What differs, and must be visible to path selection (§8):**

| | QUIC link | TCP link |
|---|---|---|
| Cross-circuit HoL blocking | no | **yes** |
| Circuit ↔ transport mapping | one stream each | interleaved on one byte stream |
| Address change | migration (§6.6) | connection dies, circuits die |
| Congestion control | per connection, streams share | per connection |
| Link class advertised in descriptor | `quic` | `tcp` |

Path selection MUST prefer QUIC links for `INTERACTIVE` circuits (R2) and MAY
use TCP links freely for `BULK`. A node reachable only over TCP is still a
usable relay; it is a worse guard.

### 6.4 The link layer versus the circuit layer

The common way to get this wrong is to let a circuit's lifetime, keys or
identity depend on the link carrying it. They are independent by design (R9).

| | Link (L1) | Circuit (L4) |
|---|---|---|
| Endpoints | two adjacent nodes | client → guard → middle → terminal |
| Authenticated to | NodeIdentity | RoutingIdentity, per hop (§8) |
| Key lifetime | connection lifetime | circuit lifetime, forward-secret per hop |
| Address-bound | yes | never — no layer above L4 sees an IP (Constitution §4) |
| Identifier | connection ID, path | `circuit_id`, **link-local and directional** |
| Survives peer address change | yes, by migration | only if its links do |
| Survives link death | n/a | no — but the *session* does (R9, §9) |

**Circuit IDs are link-local.** A relay terminates `circuit_id = A` on the
inbound link and originates an independently chosen `circuit_id = B` on the
outbound link, so an observer of one link cannot match IDs across the relay —
doubly so on QUIC, where the stream IDs belong to unrelated connections. Tor's
design, kept unchanged.

> **INVARIANT L1-2.** Circuit key material MUST NOT be derived from the link's
> TLS exporter. Binding them would stop a circuit outliving its link and would
> give the link peer input into circuit keys. The exporter is used only for
> link-scoped control: accounting receipts (§14) and the address-observation
> attestation in §6.5.

**Link lifetime.**

```text
  IDLE ──dial + INVARIANT L1-1──► OPEN ──no circuits AND no padding──► DRAINING
                                   ▲       contract for 3 min             │
                                   │                                      │
                                   └────── a circuit attaches ────────────┘
                                                                          │
  peer address change (initiator) ──► path validation, link SURVIVES      ▼
  CONNECTION_CLOSE | idle timeout | auth failure ──────────────────► CLOSED
```

A guard link is exempt from idle reaping: it is held open with padding for as
long as the client wants that guard, because letting it close and reopen
publishes the client's activity pattern to anyone watching its access network.

**Link padding is not circuit padding.** They defend different observers and
neither substitutes for the other:

| | Link padding | Circuit padding |
|---|---|---|
| Scope | one hop, node ↔ node | end-to-end, or client ↔ a chosen hop |
| Consumed by | the next node, which discards it | the terminating hop |
| Hides from | an observer of *this link* | a relay on the path |
| Hides *what* | the number and timing of real cells on this link | the presence and shape of one circuit's traffic |
| Cannot hide | a circuit's existence from the relay itself | the total volume on a link |
| Cost | wasted bandwidth on one hop | wasted bandwidth on every hop it crosses |
| Owned by | this section: the mechanism | §16: the schedules and the analysis |

Mechanically: a link padding cell carries `circuit_id = 0` and the drop command;
it is never forwarded and never counted as delivered traffic for accounting
(§14), or padding becomes a way to mint credit. It must be paced by the sender's
own timer, never emitted in response to a received cell, or it echoes the
traffic it exists to hide.

### 6.5 NAT, reachability, and address discovery

**The opening finding, in operational terms: AXON needs inbound reachability
only for roles whose address is already public, and a client never needs to be
dialable because a client always initiates.** That collapses most of the NAT
problem. What remains is (a) deciding honestly whether a node is reachable,
(b) discovering a node's external address without a central service, and (c) the
narrow case of two non-anonymous peers who both want a direct link.

**Classification.** Determined by probing, never by asking the operating system.

| Class | Test result | Inbound? |
|---|---|---|
| `PUBLIC` | dial-back to the observed address succeeds from ≥2 unrelated peers | yes |
| `MAPPED` | as `PUBLIC`, but only after a UPnP-IGD or NAT-PMP/PCP mapping was created | yes, while the lease holds |
| `EIM` (endpoint-independent mapping, "full/restricted cone") | two probes from different peers observe the **same** external port | punchable |
| `EDM` (endpoint-dependent mapping, "symmetric") | two probes from different peers observe **different** external ports | not punchable by port reuse |
| `CGNAT` | external address is in 100.64.0.0/10, or the observed address differs from every local interface address and no mapping protocol responds | not punchable, not mappable |
| `UDP_BLOCKED` | no QUIC handshake completes to any peer in a probe window | TCP only |
| `OFFLINE` | nothing completes | none |

CGNAT is separated from EDM because the operator-facing advice differs: an EDM
node may be fixable with a router setting, a CGNAT node cannot be fixed by the
subscriber at all, and telling them to forward a port wastes their time.

**IPv6 removes the NAT problem and introduces an identity problem.** A globally
routable address stable across time is a per-host identifier visible to every
peer and every observer, and the /64 prefix identifies the subscriber line even
when the interface identifier rotates.

> **RULING.** For a **relay** this is expected: relays are public (R3, R4). For
> a **client** it is not. A client MUST use temporary addresses (RFC 8981) for
> outbound links, MUST NOT accept inbound IPv6 unless it has declared a public
> role, and MUST re-source on rotation.
>
> **What this does not fix:** a node that is a relay on IPv6 and an anonymous
> client on the same interface sources both from the same /64, and rotating the
> interface identifier does not help. **Running a public relay and being an
> anonymous client on one machine and prefix is linkable, and AXON does not
> solve it.** The mitigation is operational — a different machine, a different
> prefix, or knowing acceptance. Tor has the same problem and the same answer.

**Address discovery without a STUN server.** A central STUN service is a
metadata chokepoint and a single point of failure; we need none, because every
peer already sees our source address.

```text
1. OBSERVE   Each peer sends LINK_INFO carrying the source address it observed
             for us, signed under the link's TLS exporter so the statement
             cannot be replayed onto another link.
2. QUORUM    Candidate = the value reported by ≥3 peers in DISTINCT /24 (v4) or
             /48 (v6) AND DISTINCT ASNs. Diversity predicate reused from
             internal/placement/level.go, not rewritten.
3. REFUSE    Below quorum the address is UNCONFIRMED and nothing is advertised.
             A node that believes one peer can be induced to advertise an
             address that is not its own — a redirection and DoS primitive.
4. VERIFY    Reachability is proved, not inferred: request a dial-back at the
             candidate. It MUST arrive from an address other than the one the
             request went over, or a lying peer "verifies" us by answering
             itself.
5. BOUND     A dial-back is answered only once the requester has sent at least
             as many bytes as the fixed-size probe costs, or the mechanism is a
             reflector. The concern libp2p's AutoNAT v2 redesign addresses; we
             adopt the requirement, not the code.
```

An operator-supplied external STUN server (`pion/stun`) is permitted as a
bootstrap convenience for a node with zero peers; its answer is a hint that
still requires the quorum above before anything is advertised.

**Port mapping.** UPnP-IGD and NAT-PMP/PCP are attempted, in that order of
decreasing awfulness, only on operator opt-in. Off by default: a node that
silently reconfigures the user's router is not a node an operator can reason
about. Success yields `MAPPED`, refreshed at half the lease, demoted the moment
a refresh fails.


> **BUILT (2026-08-17) — F3, PCP.** `internal/axon/peer/pcp.go`, 10 tests, five
> injections verified.
>
> **The enum was lying.** §5's table correctly said "PCP is not implemented" —
> but a single `MappingNATPMP` constant was commented `// NAT-PMP / PCP` and
> stringified `"nat-pmp"`. Those are two protocols: RFC 6886 and RFC 6887, which
> share UDP port 5351 and a lineage and nothing else, and a gateway answering one
> need not answer the other. An operator reading a log could not tell which had
> been spoken, and the roadmap could describe PCP as covered by a constant that
> never implemented it. `MappingPCP` is now distinct.
>
> **Why PCP and not just NAT-PMP.** NAT-PMP has no IPv6, no way to request a
> specific external address, and **no mapping nonce** — so it cannot distinguish
> its own response from an off-path forgery, and it cannot survive the CGNAT that
> a large share of residential and every mobile network now runs.
>
> **The nonce is a security property, not a formality.** RFC 6887 §11.1 requires
> a random 96-bit nonce echoed in the response. Without it, an off-path attacker
> spraying UDP at 5351 convinces this node it holds a mapping on an external
> address *the attacker chose* — and §5's reachability machine then advertises
> it. Checked on every response; a mismatch is a hard error, not a retry. The
> nonce is drawn **once per mapper**, because it identifies the *mapping*: a
> refresh with a fresh nonce creates a second mapping instead of extending the
> first, leaking one per cycle until the gateway is full.
>
> **The granted lease is the gateway's, not the one asked for** (RFC 6887 §11.2).
> Refreshing on the requested figure refreshes after the mapping has already
> expired — which looks exactly like a working mapping right up until it isn't.
>
> **Gateway-restart detection** (RFC 6887 §8.5): a restarted gateway has lost
> every mapping but keeps answering, because the response is generated from the
> request. §5 demotes on a *failed* refresh, and a refresh against a restarted
> gateway never fails — so a backwards epoch is an error.
>
> **`ADDRESS_MISMATCH` (code 12) is named loudly**: it means a second layer of
> NAT, so no mapping here can make the node reachable. That is not a retry.
>
> **PCP is tried before NAT-PMP**, inserted into §5's "order of decreasing
> awfulness" — they share a port, PCP is the successor, and RFC 6887 §16
> specifies this fallback direction.
>
> **Two things found on the way.** (1) `MappingConfig.protocols()` was **dead
> config**: it returned a preference order and nothing turned it into mappers, so
> adding PCP to the list would have implemented a protocol nothing could reach.
> `NewMappersFor` now does, and re-checks the opt-in because UPnP discovery
> broadcasts on the local network. (2) `defaultGateway` did not exist —
> `NewNATPMPMapper` took a gateway nobody supplied. It now reads
> `/proc/net/route` rather than assuming the `.1` of the local /24; **on the
> machine this was written on the gateway is `192.168.1.254`**, so the guess
> would have been wrong here, and a wrong guess sends mapping requests to an
> unrelated host that never consented to one.
>
> **STILL OPEN, and not F3's:** nothing in `cmd/` calls `NewMappersFor` or
> `NewMappingManager`. Port mapping is now *constructible*; it is not *wired*.

**Hole punching is restricted because a successful punch tells both endpoints
each other's IP address.** Fatal for anonymous traffic; fine between parties who
are already publicly identified.

> **RULING.** Hole punching is permitted **only** between endpoints that are
> both public by role, or between a storage owner and a holder where the owner
> has explicitly accepted address exposure for a `BULK` transfer (R2). It is
> **forbidden** for any link carrying `INTERACTIVE` circuits, and forbidden for
> a client's guard link under all circumstances. `[NEEDS RESEARCH]` — whether
> the `BULK` exception is worth its exposure at all is an open question; the
> conservative default is off.

Mechanism, from DCUtR and narrowed: the two peers already share an L4 circuit,
which is the only coordination channel — there is no libp2p-style relayed
*connection* to negotiate over. Each measures RTT over that circuit, they agree
a firing instant, and both send QUIC Initial packets simultaneously so each
side's NAT sees an outbound packet before the other's inbound arrives. EIM↔EIM
and EIM↔EDM succeed often; EDM↔EDM does not, and port prediction against
symmetric NAT is noisy, detectable, and **rejected for v1**.

**Relay-assisted connectivity for the cases that remain.** There is no
link-level relay. An `EDM`, `CGNAT`, `UDP_BLOCKED` or `OFFLINE` node that must
be *reachable* for a role publishes a descriptor and is reached through an L4
tunnel exactly as an anonymous service is (§9) — one relaying mechanism, already
required and already analysed for anonymity, instead of a second at L1 with
different properties. The cost is honest: reaching a NAT-bound storage holder
costs a full circuit rather than one relayed hop, and the holder must maintain a
tunnel pool to be reachable at all. It buys the deletion of Circuit Relay v2 and
of everything that would have had to be said about what a link relay observes.

**Reachability state machine.**

```text
   start ─► UNKNOWN ──≥3 diverse peers agree on an address──► PROBING
            (advertise nothing, take no public role)             │
                                                dial-back fails  │  dial-back OK
                        ┌────────────────────────◄───────────────┤
                        ▼                                        ▼
                  UNREACHABLE ──re-probe 15 min, jittered──► REACHABLE
                                                            {PUBLIC | MAPPED}
                                                                 │
              3 consecutive dial-back failures, or lease lost ───┤──► UNREACHABLE
              no UDP handshake completes ───────────────────────┘──► UDP_BLOCKED
                                                                     (TCP roles)

   Demotion is immediate. Promotion needs a fresh quorum AND a fresh dial-back.
   Re-verified every 30 min and on every observed local address change: a node
   that was reachable an hour ago and advertises now is worse than one that
   never advertised.
```

**Role gating.** §17 owns the role taxonomy; this table owns the transport
precondition for each. A node MUST NOT advertise a role its class does not
permit, and MUST withdraw within one descriptor period of demotion.

| Role | PUBLIC | MAPPED | EIM | EDM / CGNAT | UDP_BLOCKED | OFFLINE |
|---|---|---|---|---|---|---|
| Client (initiator) | yes | yes | yes | yes | yes (TCP) | no |
| Guard | yes | yes | no | no | yes (TCP, deprioritised) | no |
| Middle relay | yes | yes | no | no | yes (TCP) | no |
| Terminal relay | yes | yes | no | no | yes (TCP) | no |
| Introduction point | yes | yes | no | no | yes (TCP) | no |
| Rendezvous point | yes | yes | no | no | no | no |
| DHT server (L3) | yes | yes | no | no | yes (TCP) | no |
| Storage holder, dialed directly | yes | yes | opportunistic (BULK only) | no | yes (TCP) | no |
| Storage holder, via own tunnel | yes | yes | yes | yes | yes | no |
| Anonymous service (L5) | yes | yes | yes | yes | yes | no |

`MAPPED` is allowed for relay roles and deliberately **not** preferred: a lapsed
mapping lease turns a relay into a black hole for every circuit through it, so
guard selection (§8) weights `PUBLIC` above `MAPPED`. Rendezvous points are
denied to `UDP_BLOCKED` nodes because an RP joins two circuits and is the worst
possible place for cross-circuit head-of-line blocking (R12) — the one role
where the TCP fallback's failure mode is unacceptable.

### 6.6 Dynamic IP and address churn

> **BUILT (2026-08-17) — F4.** `internal/axon/link/migration.go`, 9 tests, run
> against **real quic-go connections on loopback** rather than mocks — F4's whole
> content is whether the library does what this section assumes.
>
> **CASE 1 verified**: a link survived an initiator address change onto a new UDP
> socket. **CASE 2 verified as a refusal**: `AddPath` returns *"server cannot
> initiate connection migration"*, so the analysis that inbound links die and the
> relay absorbs a reconnection storm rests on a property of the library, not on
> prose.
>
> **L1-3's hard half is already kept by quic-go.** Reading v0.59.1: the outgoing
> path manager asks for a connection ID before sending `PATH_CHALLENGE`, and when
> the pool is empty it sends **nothing** rather than falling back to the current
> ID. Re-enforcing "never reuse" from outside would be a second copy of a rule
> the library keeps.
>
> **§6.6's "detectable" is NOT earned, and cannot be from outside the library.**
> The signal separating CID starvation from an unreachable path — whether a
> `PATH_CHALLENGE` was actually sent — lives on quic-go's unexported
> `pathOutgoing`, and `Path.Probe` returns `context.Cause(ctx)` either way. A
> classifier was written and **abandoned rather than approximated**: one that
> guessed would report an honest peer as hostile on an ordinary dead path.
> What is enforceable is the predictable half — `MigrationGuard` counts
> outstanding probes and refuses the one that would exhaust the pool, which is
> L1-3's prescribed outcome, "a link that cannot be migrated, not one that may be
> migrated unsafely". One entry is always held back for the **active** path,
> since spending the last ID on a probe leaves nothing to migrate to if the
> current path dies mid-probe.
>
> **§6.2's `active_connection_id_limit = 8` IS NOT ACHIEVABLE.** quic-go
> hardcodes `protocol.MaxActiveConnectionIDs = 4` and exposes no way to set it.
> Worse, **measured against a real connection only TWO extra paths validate
> concurrently** — not the three that 4-minus-the-active-path predicts. The
> constant and the behaviour disagree, and the guard is built on the
> **measurement**: trusting the constant is how a guard green-lights a probe the
> library cannot back, the one thing it exists to prevent. §6.2 asked for a
> margin of seven; the deployment gets two.
>
> **A silent trap, found by bisect.** Migration works **only when both sides use
> an explicit `quic.Transport`**. Built with `quic.ListenAddr`/`quic.DialAddr`,
> `AddPath` succeeds, `Probe` sends nothing, and the migration times out with
> `context deadline exceeded` — indistinguishable from an unreachable network. A
> link layer built on the convenience helpers would have **no working migration
> and no error saying so**. A test now asserts the trap still exists, so it
> cannot be reintroduced by a simplification.
>
> **The transport profile has no knobs**, per §12: `TransportProfile()` takes no
> arguments and a test asserts the signature. Windows are pinned initial-equals-
> max so they never auto-tune — a growing window is a per-connection behaviour an
> observer can watch, the same leak class as a configurable parameter — and PMTU
> discovery is off, because §6.2 fixes 1200 precisely to remove per-path size
> variation.
>
> **Two existing audits caught the new file, and both were right.** E13.4
> refused a literal `1200` for `max_udp_payload_size` — §6.2's figure and §16's
> `DatagramSize` are the same number for the same reason, and two copies drift
> the moment either is retuned; it now takes the value from `params`. T2.5's
> `Allow0RTT` audit then refused the file for *naming* the field in a comment
> explaining why it is deliberately left alone. That one was over-broad in the
> §87 way, so the audit was fixed to read code rather than prose — and
> re-verified by injection: setting `Allow0RTT: true` is still caught. The
> explicit `Allow0RTT: false` was removed, because a harmless line naming the
> field is one an audit cannot tell from a harmful one.
>
> **STILL OPEN:** this is the profile and the guard, not a link layer. §4's
> native L1 on `quic-go` does not exist — today's transport is still libp2p — so
> nothing in the running node uses either yet.


**A relay's identity is a key, not an address, so an address change is a
descriptor republish — and for links where the changing node was the initiator,
not even a reconnection.**

```text
CASE 1  the mover is the QUIC INITIATOR (client whose home IP changed; a relay
        dialling out)
          new path ──► PATH_CHALLENGE, with a new CID from the peer's pool
                   ◄── PATH_RESPONSE
          Link survives; every circuit on it survives. Cost: 1 RTT, plus the
          anti-amplification limit until validation completes.

CASE 2  the mover is the RESPONDER (a relay's own public address changed)
          RFC 9000 has no server-initiated migration, so inbound links die. The
          relay serves on the old socket until it is actually gone, publishes a
          new signed descriptor (§7) with a higher sequence, and absorbs the
          reconnection storm, staggered by peers' jittered redial backoff.
          Circuits through it die. Sessions above them do not (R9, §9).
```

**Connection IDs are the linkability object.** Migrating while reusing a
connection ID lets any observer of both paths link the old address to the new.
RFC 9000 requires a fresh connection ID per path for exactly this reason; AXON
hard-enforces it:

> **INVARIANT L1-3.** A node migrating to a new path MUST consume an unused
> connection ID from the peer's issued pool and MUST NOT reuse a connection ID
> observed on any previous path. `active_connection_id_limit = 8` exists to
> guarantee the pool is never empty at the moment of migration. A peer that
> fails to issue replacement IDs is treated as a link that cannot be migrated,
> not as one that may be migrated unsafely.

What migration does **not** hide: the peer at the far end learns both addresses,
because it is the same connection. That is inherent, it is why guards are pinned
and few (Constitution §5), and it is not a bug to be mitigated at L1.

**NAT rebinding.** When a NAT silently changes the external port, packets arrive
from a new 4-tuple with a valid connection ID and QUIC validates the new path.
TCP simply breaks. One of the concrete reasons QUIC is primary.

**Keepalive.** RFC 4787 requires NAT UDP mappings not to expire in under two
minutes; deployed NATs frequently ignore that, and 30 s or less is common.

| Link kind | Keepalive | Mechanism |
|---|---|---|
| Guard link (client side) | 15 s floor | Link padding cell — it doubles as the §16 cover schedule, so it is not extra traffic. **P13 satisfies this by construction**: M6a's longest possible interval is 9.5 s and M6b's floor is 2 s, both under 15 s. The invariant is now a test (`TestPaddingSatisfiesTheNATKeepaliveFloor`), because raising `KeepaliveMax` past 15 s would expire NAT mappings and present as random client-link loss rather than as a padding bug — measured worst idle gap 4.4 s over 30 min. |
| Relay ↔ relay | 20 s | QUIC PING when no cell has been sent. |
| Idle link with no circuits | none | It is being reaped anyway (§6.4). |

**Rate limits on address change.** A descriptor republish is a DHT write and an
invitation to every peer to redial — uncontrolled, a flooding primitive. A
minimum republish interval, a monotonic sequence number to prevent rollback to a
stale address, and a per-epoch republish cap are all required; the values belong
to §7 with the rest of the descriptor rules.

**What survives what:**

| Event | Link | Circuits on it | Session (§9) |
|---|---|---|---|
| Initiator address change | survives (migration) | survive | survives |
| Responder address change | dies | die | survives |
| NAT rebinding | survives | survive | survives |
| Idle timeout | dies | none by definition | survives |
| Peer restart | dies | die | survives |
| Guard rotation (45 d) | closed deliberately | rebuilt | survives |

### 6.7 Deployment matrix

What an operator actually has, and what it means. §17 owns the full role model;
this is the transport view.

| Deployment | Likely class | Roles available | Must configure | Notes |
|---|---|---|---|---|
| **Residential IPv4 behind consumer NAT** | `EIM` typical, `EDM` on some routers | client; storage holder via own tunnel; anonymous service | nothing | The default install. Forward one UDP port to get relay roles; the node reports the port it wants. |
| **Residential IPv4, port forwarded** | `PUBLIC` | all | one UDP port (+ same TCP port for fallback), static LAN address or DHCP reservation | The cheapest way to become a real relay. |
| **Residential with IPv6** | `PUBLIC` on v6, `EIM`/`EDM` on v4 | all, on v6 | firewall rule permitting inbound UDP to the node's address; **RFC 8981 temporary addresses for client traffic** | Read the §6.5 ruling first: relay + anonymous client on one prefix is linkable at the /64. Dual-stack nodes advertise both and must keep the v6 relay address separate from the v4 client path. |
| **CGNAT (mobile, some fibre/cable)** | `CGNAT` | client; storage holder via own tunnel; anonymous service | nothing; port forwarding is impossible | Do not tell the operator to forward a port. The node should say "your ISP does not give you an address; you can use the network and host services through it, but you cannot relay." |
| **VPS** | `PUBLIC` | all | UDP + TCP port open; egress unrestricted | The relay case the network needs most. Diversity weighting (§8, R14) must actively resist everything ending up in three hosting ASNs. |
| **Cloud with a restrictive firewall / security group** | `PUBLIC` once opened, `UDP_BLOCKED` if only TCP is permitted | all if UDP opened; no rendezvous role if TCP-only | inbound UDP allow rule on the chosen port; inbound TCP for fallback | A very common misconfiguration is opening TCP only, which silently produces a TCP-only relay. The node must log the class it detected, loudly, at start. |
| **Enterprise LAN / managed desktop** | `UDP_BLOCKED` or `OFFLINE` | client over TCP, at best | proxy exception, usually unobtainable | Honest advice: this is a network that does not want AXON on it, and §6.8 is not going to help in v1. |

### 6.8 Censorship and blocking posture

**Stated without hedging: AXON v1 is blockable, and pluggable-transport-style
obfuscation is out of scope for v1.** From §6.2: QUIC Initial packets are
readable by any on-path observer, `LinkALPN` is a constant in that plaintext,
the transport parameter set is fixed network-wide, and relay addresses are
published in a DHT that an adversary is assumed to be able to read (Constitution
§7). A censor with those facts writes a filter in an afternoon. The Constitution
forbids the phrase "impossible to block" and there would be no basis for it
here.

Building obfuscation badly is worse than not building it: a transport that
*looks* obfuscated but carries a distinguishable timing or length signature
gives users a false belief about which networks they can safely use AXON on.
**Future work `[NEEDS RESEARCH]`**: obfuscated link transports, unlisted relays,
and a distribution mechanism for them.

**Design hooks kept now, because they are free now and expensive later.**

| Hook | Cost today | What it enables |
|---|---|---|
| `LinkALPN` is a single named constant, in one file | zero | An obfuscated variant changes a constant, not a protocol. |
| L1 is an interface — `Dial`, `Listen`, `Framing` — with QUIC and TCP as its two implementations | small | A third implementation (obfuscated, tunnelled, or a future non-QUIC link) is a new file, not a fork. This is the one structural thing libp2p got right and we are keeping the shape of it. |
| Cells are fixed-size and already padded | zero | An obfuscating layer inherits a flat length distribution instead of having to manufacture one. |
| Descriptors do not *require* DHT publication (§7) | zero | An unlisted, out-of-band-distributed relay is a descriptor that was never published — no new record type, no new format. |
| Link version negotiation exists from v1 | small | A future link protocol is a version, not a network split. |
| Default port is per-node and configurable, not well-known | zero | No single-line port blocklist; UDP/443 available for operators who want to blend. |

**Explicitly not attempted in v1:** domain fronting, decoy routing, polymorphic
encoding, protocol mimicry, or any claim that AXON resists a
nation-scale blocking effort.

### Decisions, and what each one costs

| Decision | Problem it solves | Derived from | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Native L1/L2 on `quic-go`; no go-libp2p | Second node identity; unsuppressable address gossip; no control of the wire | none (libp2p) | Keep the QUIC and TLS libraries, drop the libp2p protocols | Keep libp2p whole; keep libp2p with Identify disabled (loses AutoNAT/relay/DCUtR, which is what libp2p was for) | We reimplement dial orchestration, resource limits and connection lifecycle, and will reproduce some of libp2p's fixed bugs |
| QUIC as the primary link | Cross-circuit head-of-line blocking (R12) | Tor's TCP link, inverted | One stream per circuit instead of one TCP connection per link | TCP+TLS primary (keeps HoL blocking); SCTP/DTLS (no deployment) | Per-stream memory at relays; QUIC is fingerprintable; UDP is blockable |
| TLS 1.3 with RFC 7250 raw public keys bound to NodeIdentity | Authenticate the node without a PKI or a certificate parser | Tor's link handshake; libp2p-TLS | No X.509, no custom extension, no CA | libp2p-TLS (custom extension, libp2p-shaped); Noise (a second handshake to audit, no gain over TLS 1.3) | Raw-public-key support is not universal in TLS stacks — see the build table |
| 0-RTT disabled; resumption disabled in v1 | Ticket-based cross-address linkage; replayable early data | Tor has no analogue | Refuse a QUIC feature the ecosystem treats as a headline | Allow 0-RTT for non-circuit control cells (still replayable, still a ticket) | One extra RTT per new link; a modest fingerprint (AXON never offers PSK modes) |
| Identical 1024 B cell framing over QUIC and TCP | One parser, one padding implementation, bridgeable links | Tor's fixed cells | Circuit ID kept even where QUIC makes it redundant | Per-transport framing; length-prefixed muxing over TCP | Redundant 8 bytes per cell on QUIC links |
| Server-only authentication on client links | A client identifying itself to its guard | Tor | Made explicit and enforced by separate `tls.Config`s per role | Mutual auth everywhere (links client traffic to a public key) | Relays cannot rate-limit per client identity; must rate-limit per address plus L4 puzzles (§15) |
| Circuit IDs link-local, rewritten per hop | Cross-link correlation at a relay | Tor | unchanged | Global circuit IDs (I2P tunnel IDs are per-hop too, for the same reason) | none new |
| No link-level relay; inbound via L4 tunnel | Two relaying mechanisms with different anonymity properties | I2P: every destination is reached through its own tunnels | Deleted Circuit Relay v2 rather than reimplementing it | libp2p Circuit Relay v2 (a relay that sees both endpoints' addresses and needs its own trust story) | Reaching a NAT-bound holder costs a full circuit; NAT-bound holders must maintain tunnel pools |
| Peer-mutual address observation with a 3-peer, ASN-and-prefix-diverse quorum | Central STUN as chokepoint; a single peer lying about your address | libp2p AutoNAT, reduced | Quorum + diversity predicate reused from `internal/placement/level.go`; dial-back must come from a different address | Central STUN; trusting one peer's report; OS interface enumeration | A colluding minority that dominates a new node's peer set can still delay or deny promotion (a targeted eclipse; §7, R14) |
| Reachability-gated roles with immediate demotion | Nodes advertising capacity they do not have (R3) | Tor's reachability self-test | Demotion is immediate; promotion needs a fresh quorum *and* a fresh dial-back | `dht.ModeAutoServer`'s "assume server until told otherwise", which is what the existing code does | Probing is itself a signal: a node's promotion is visible to the peers it probed |
| Hole punching restricted to already-public endpoints | Hole punching reveals both IPs | libp2p DCUtR, narrowed | Coordinated over an existing L4 circuit; forbidden for `INTERACTIVE` and for guard links | General-purpose hole punching for all peers; symmetric-NAT port prediction | The `BULK` exception still exposes two storage peers to each other; default off |
| Connection migration with mandatory fresh CIDs | NAT rebinding and address change killing circuits | none (QUIC) | Hard-enforced CID rotation; refuse to migrate rather than reuse | Reconnect-and-rebuild (loses every circuit); reusing CIDs (links old and new address) | A peer that withholds new CIDs can force link death at an address change — a targeted, detectable DoS |
| Fixed transport parameters network-wide | Per-implementation fingerprinting inside AXON | none | Every AXON node presents an identical parameter set | Per-node randomisation (distinguishes nodes from each other) | Makes AXON as a whole easier to classify — accepted, see §6.8 |

### Build status

| Component | Marker | Note |
|---|---|---|
| QUIC link with TLS 1.3, NodeIdentity pinning, 0-RTT off | `[BUILT]` P2 | `internal/axon/link`. |

> **T2.6 — REPRODUCIBLE BUILDS MEASURED (2026-08-17).** The apparatus exists:
> `scripts/reproducible-build.sh`, and **all seven release targets build
> byte-identically from two independent trees**.
>
> **The build was NOT reproducible before this.** `-trimpath -ldflags="-s -w"`,
> the flags `build-release.sh` had always used, are not enough — Go stamps
> `vcs=git`, `vcs.revision`, `vcs.time`, `vcs.modified` and a commit-derived
> module version into every binary, so the same source built inside the repo and
> from a tarball produced **different bytes**. `-buildvcs=false` removes all
> five and the two agree.
>
> It was easy to miss because `vcs.time` is the **commit** time, not the build
> time: two builds of one commit at different moments already matched. The
> divergence appears only when a `.git` directory does — which is exactly the
> case that matters, a release built in CI from a checkout and verified by a
> user from a tarball.
>
> All three build sites now use identical flags (`build-release.sh`,
> `update-from-github.sh`, `reproducible-build.sh`), so **a node that builds
> from source gets byte-identical output to the published release** and an
> operator can check that a release matches its source. An audit fails the build
> if any of the three drifts — and that audit was itself found vacuous first, as
> it matched the flag inside the comment explaining why the flag matters.
>
> **T2.6 and T13.1 are still NOT claimed.** Both ask for two *independently*
> built binaries; this is one machine, one Go toolchain, one libc, one GOAMD64
> level, and a copy at a different path is the closest a single machine gets to
> "another machine". **E13.1's three-platform requirement needs CI.** What has
> changed is that the causes within the build's control are removed, so a real
> cross-machine difference would now be a signal rather than noise.

| RFC 7250 raw public keys | `[NEEDS RESEARCH]` | **TBD — verify raw-public-key support in the target TLS stack before committing.** If unavailable, use a minimal self-signed Ed25519 certificate whose subject public key *is* the NodeIdentity, with constant subject and validity fields so it carries no distinguishing content. This authenticates the same key and costs roughly a hundred extra encrypted bytes; it is a fallback, not a redesign. |
| Cell framing identical over QUIC and TCP; TCP+TLS 1.3 fallback | `[BUILT]` P2 | Format owned by §8; this section owns the invariant that it is transport-independent, which makes the fallback small. |
| Peer-mutual address discovery, quorum, reachability state machine, role gating | `[BUILT]` P3 | `internal/axon/peer`. ASN diversity degrades to prefix-only for IPv4 — reported, not hidden. |
| UPnP / NAT-PMP / PCP mapping | `[BUILT]` P3 | UPnP + NAT-PMP + **PCP (RFC 6887)**, off by default. See the F3 note at §5. **Not wired into `cmd/`.** |
| Connection migration with CID rotation | `[BUILT]` F4 — see the note at §6.6 | `internal/axon/link/migration.go`. **§6.2's pool of 8 is not achievable**; measured depth is 2. |
| Link padding mechanism | `[BUILT]` P13 | `internal/axon/padding`: §16.3's M6a keepalive and M6b floor. The schedules are §16.3's and the ruling that resolved its self-contradiction about M6b is recorded there. |
| Coordinated hole punching | `[NEEDS RESEARCH]` | Success rate unknown for this population; the anonymity restriction may make it not worth building. |
| Symmetric-NAT traversal without a relay | `[UNSOLVED]` | Port prediction is noisy and detectable. AXON's answer is "use a tunnel", which is a real answer with a real latency cost, not a solution to the NAT problem. |
| Blocking resistance | `[UNSOLVED]` for v1 | §6.8. |
| Relay + anonymous client on one IPv6 prefix | `[UNSOLVED]` | Linkable at the /64. Operational mitigation only. |

### What this section does NOT establish

- **That replacing libp2p is the right call at the schedule level.** The
  argument is a security and architecture argument. No line count or
  engineer-month figure appears here because none has been measured. If §23's
  phasing shows the native L1 delaying the anonymity layer — the only genuinely
  novel work in the project — that is an argument for a temporary libp2p-based
  prototype which this section has not made.
- **That QUIC's costs are affordable on relay-class hardware.** Every CPU and
  memory figure in §6.2 is arithmetic from declared parameters, not measurement.
  Userspace QUIC's per-byte cost against kernel TCP on a real relay is
  unmeasured, and the flow-control figure bounds what an attacker can ask for,
  not what a relay uses.
- **That the reachability classification is correct in the field.** The EIM/EDM
  test is inferred from two observed port mappings — the standard test, known to
  misclassify NATs that preserve ports until they conflict and NATs that vary by
  destination port. AXON's real NAT distribution is unknown and must be measured
  before the role-gating table is trusted.
- **That hole punching will work often enough to matter.** No success rate is
  claimed, and the anonymity restriction confining it to already-public peers
  may leave it with no worthwhile use case at all.
- **That the fallback path is safe against downgrade.** An adversary who blocks
  UDP to a specific node forces it onto TCP links and their head-of-line
  blocking, and denies it the rendezvous-point role. §6.3 reports the block
  honestly; nothing here prevents it being caused. Whether a forced downgrade is
  exploitable beyond degradation is open, for §16 and §18.
- **Anything about what travels over the link.** Cell commands, onion layers,
  circuit construction, padding schedules and path selection are §8, §9 and §16.
  This section establishes only that the pipe exists, is authenticated to the
  right key, does not head-of-line block, and that a node is honest about
  whether it can be dialed.
