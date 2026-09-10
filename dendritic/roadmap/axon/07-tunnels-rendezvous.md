## 9. Tunnel Pools, Rendezvous, and Anonymous Services

> **AS BUILT (2026-08-16).** `internal/axon/rendez` (P6, 19 tests) and
> `internal/axon/tunnel` (P7, 12 tests). **M2 passes** — client and service agree
> a session key across six real relay hops joined at a rendezvous point that
> retains nothing.
>
> **Done:** INTRODUCE1 with a fixed 512 B plaintext so the intro point cannot
> size-distinguish a resumption from a fresh introduction; intro encryption bound
> to the header as AAD; ntor-shaped rendezvous handshake; RP cookie splice with a
> single-use replay guard; guard-constrained pools with the PAR-05 bounded sampled
> set and PAR-10 pre-built spares. E7.2 = 1000/1000 builds at a pinned guard;
> E7.4 = both guards down is a hard failure with no tunnel built.
>
> **Deliberately NOT claimed:** **the intro puzzle does not exist.** R10 requires
> it, `IntroPointRecord` already carries `pow_seed` and `pow_difficulty` for it,
> and §9.6's parameters are `[NEEDS RESEARCH]`. It is **P6a / PAR-16**, one of two
> `critical` parity gaps, and until it lands `IntroPoint.UnsafeModes()` declares
> `no-intro-puzzle` and admission is rate-limited only. **The session layer** is
> `[NEEDS RESEARCH]` (P23), so **T7.2** and **E7.1** are not claimed. **T7.5/E7.3**
> need descriptor publication at 8 replica positions, which is unbuilt.
> **E6.2, E6.3 and T6.6** are multi-node and have not been run.

**The finding that shapes this section: tunnel-build load is scale-invariant.** At
the Constitution's parameters a node offers 48 builds per hour per destination,
and the per-relay share is `144 / (3600·f)` hop-creations per second — a function
of the *relaying fraction* `f`, not of network size. It is 0.147/s at f=0.3 and
stays 0.147/s at 1,000 nodes and at 100,000. The pool model does not get more
expensive as the network grows. What does get expensive (§9.3) is running many
destinations on one node; what stays scarce is guards.

Second: **the service side needs no inbound reachability of any kind.** Every
circuit a service holds — including the ones third parties connect *into* — is
built outward by the service. That is already true of the deployed node, which
runs over I2P behind whatever NAT the operator has, and the native layer must
preserve it exactly.

§8 owns circuits: cell format, telescoped handshake, per-hop key schedule, path
selection. This section owns everything above — pools, rendezvous, descriptors,
sessions, the service side. Nothing here re-specifies a cell or a handshake.

---

### What already exists

All of this area is currently outsourced to I2P. Files are in
`/home/bruns/Documents/maniwani/storage-client`.

| File | What it gives us | Status |
|---|---|---|
| `internal/i2p/sam.go:84-87, 142-145` | The live pool parameters the node already asks I2P for: `inbound.length=3 outbound.length=3 inbound.quantity=3 outbound.quantity=3 inbound.backupQuantity=1 outbound.backupQuantity=1 i2cp.leaseSetEncType=6,4`. The Constitution's 3+3+1-spare pool is not a new number — it is what this node has been running. | **Replace** |
| `internal/i2p/sam.go:62-112` (`renew()`) | Prior art for R9. A SAM session dies with its TCP control socket; `renew()` re-creates it **from the persisted destination key**, so the address survives the carrier's death. The comment is explicit that reusing the key is what makes recovery safe rather than a silent identity change. | **Replace, keep the lesson** |
| `internal/i2p/transport.go:157-195` | The operational finding in the comment: routers close an idle `STREAM ACCEPT` socket, libp2p treated the EOF as terminal, and *"every node went deaf about six minutes after starting"*. Any endpoint-holding loop must treat carrier loss as routine. Feeds §9.9. | **Replace, keep the lesson** |
| `internal/dcs/dht.go` (`WorkerDHTValidator`), `internal/gateway/dht.go` (`DHTValidator`) | The signed-DHT-record pattern the descriptor validator reuses, written twice already: well-formed, unexpired, stored under its own key, signed by the right key; `Select` prefers the highest `Sequence`; lifetime capped (`ExpiresAt-IssuedAt > 3600` rejected); record capped at 64 KiB and 256 KiB respectively. The descriptor validator should be the one these converge on. | **Reuse the shape** |
| `internal/p2p/challenge.go` | An opaque challenge/response carried as one more operation on the existing storage protocol (`challengeOperation = "pof-challenge"`, 90 s timeout), deliberately holding no opinion about proof format. §9.6's puzzle is this shape and must not open a second protocol. | **Reuse the shape** |
| `internal/dcs/admission.go` | Slot cap, per-owner cap, a FIFO **queue with ticket / position / ETA** instead of a bare rejection, and a `ReservationTTL` (2 min) reclaiming slots from clients that never start. §9.6's "never reject, reorder" rule is this controller applied to introductions. | **Reuse the shape** |
| `internal/p2p/drain.go`, `internal/store/drain.go` | An existing graceful-shutdown discipline. §9.9's service drain is the same discipline at L5. | **Reuse the shape** |
| `internal/placement/plan.go` | The diversity primitive that actually exists is holder-distinctness (`DistinctHolders`, `WithoutCrowdedHolders`, `SurvivesHolderLosses`); `internal/gateway/protocol.go` has a separate `DistinctNetworks` probe quorum. Neither is a /24-or-ASN relay-diversity function. That is new work and belongs to §8. | **Extend** |

Nothing implements introduction points, rendezvous, descriptors, key blinding,
client authorization, or a proof of work. A grep for `pow|PoW|puzzle|difficulty`
across `internal/` returns only Ethereum header fields and unrelated prose.

---

### 9.1 Tunnels versus circuits

The two words are not synonyms and the distinction is load-bearing. The stack is
`stream ⊂ session`, carried over time by many `tunnel`s, each holding one
`circuit` at a time, each circuit occupying one QUIC stream per link (R12).

| | circuit | tunnel | session | stream |
|---|---|---|---|---|
| Owned by | §8 | §9.2 | §9.8 | §9.8 |
| Identified by | circuit id, per link | (pool, role, slot) | SessionID, 16 B | (SessionID, StreamID) |
| Nominal lifetime | until DESTROY | 10 min | ≤ 12 h | application |
| Dies when | any hop tears down | its circuit dies **and** replacement fails | idle timeout or explicit close | FIN/RST |
| Survives circuit death | — | yes | yes | yes |

**Inbound versus outbound, precisely.** Both are built *outward* by their owner;
the difference is what the far end does afterwards. An **outbound** tunnel's
terminal hop reaches a target the owner chose (an HSDir, an intro point, a
rendezvous point), and no third party learns it exists. An **inbound** tunnel's
terminal hop has been asked to *hold state on the owner's behalf and accept a
splice from a third party* — an established intro circuit and an established
rendezvous circuit are both inbound tunnels. "Inbound" never means an inbound TCP
connection. That is the whole NAT-traversal property (§9.9).

**Why both concepts.** Tor has only circuits — workable because a Tor client always
initiates, but it forces per-purpose circuit types (intro, rend, directory) each
with bespoke lifetime rules; the pool exists in Tor's implementation but not in
its vocabulary. I2P has only tunnels: a connection is the pairing of my outbound
with your inbound, which gives reachability without inbound TCP and real load
balancing, but the two directions traverse *different* paths, so a 3+3 exchange
crosses six relays per round trip in each direction — double the relay exposure
and RTT. AXON takes the bidirectional circuit from Tor and the pool from I2P, so a
tunnel is a pool-managed circuit with a role: I2P's failover, load balancing and
endpoint semantics without the doubled path, plus Tor's guard property (R1). The
cost is that client and service each contribute a 3-hop circuit to a rendezvous,
so the joined path is 6 relays plus the RP — the same total as I2P, reached with
half as many distinct tunnels.

---

### 9.2 Tunnel pools `[BUILD NOW]`

One pool per destination, with an inbound and an outbound half:

```text
POOL(destination D, isolation context C)
  guards      G = {g1, g2}          pinned, 45-day rotation, 90-day list (§5)
  outbound    slots o0 o1 o2 + oS   3 active + 1 spare
  inbound     slots i0 i1 i2 + iS   3 active + 1 spare
```

For a service destination the inbound half **is** the introduction-point set: the
three active slots hold the three established intro circuits and the spare holds a
warm fourth, ready for instant promotion when an intro point fails or is attacked
(§9.10). The 3+1 figure is not an approximation of the intro count; it is exactly
it, at the default. A service under attack widens its inbound half to a declared
bucket `N_intro ∈ {3, 6, 12, 20}`, which changes the arithmetic in §9.3.

Every tunnel starts at `g1` or `g2` (R1). Hops 2..n are sampled fresh per build by
§8's path selector under §8's diversity constraints. Slots alternate guards by
index `mod 2`, so the two guards carry equal load.

#### The pool state machine

```text
            select_path(): guard fixed, hops 2..n sampled
  ┌─────────┐        ┌──────────┐  timeout 10 s, EXTEND fail,  ┌────────┐
  │ PLANNED │───────►│ BUILDING │─────────or guard loss───────►│ FAILED │
  └─────────┘        └────┬─────┘                              └───┬────┘
    ▲      ▲              │ handshake complete                     │
    │      │              ▼                                        │
    │      │         ┌─────────┐                     backoff 1,2,4,│8,16 s;
    │      │         │  READY  │  counts toward       ≤5 tries, then│guard
    │      │         └────┬────┘  min_ready           → SUSPECT     │
    │      └──────────────┼─────────────────────────────────────────┘
    │                     │ first message assigned
    │                     ▼           3 probes missed
    │           ┌────────────────┐ ──────────────► ┌─────────┐
    │           │     ACTIVE     │ ◄────────────── │ SUSPECT │
    │           └────────┬───────┘  probe answered └────┬────┘
    │                    │ age ≥ 420 s (70 %):          │ probe deadline
    │                    │ replacement slot → PLANNED   │ missed
    │                    ▼                              │
    │           ┌────────────────┐  no NEW streams;     │
    │           │    EXPIRING    │  in-flight continue  │
    │           └────────┬───────┘                      │
    │                    │ age ≥ 600 s OR replacement ACTIVE
    │                    ▼                              │
    │           ┌───────────────────────────────────┐   │
    └───────────│ DEAD — DESTROY sent, state freed, │◄──┘
                │        slot returns to PLANNED    │
                └───────────────────────────────────┘
```

`ACTIVE → SUSPECT` fires on 3 consecutive unacknowledged L4 probes (30 s cadence,
idle tunnels only) or a late `DESTROY` from a middle hop; `SUSPECT → ACTIVE` needs
one probe answered inside 2× the tunnel's EWMA RTT; `SUSPECT → DEAD` triggers an
**immediate** replacement build, not one deferred to the 70 % trigger. An EXPIRING
tunnel is never extended past its lifetime, even mid-stream — §9.8 moves the
stream.

**Build-ahead.** The 70 % trigger gives 180 s to produce a replacement. That is
not about build latency (§9.3 shows a build is sub-second); it absorbs *failures*.
With per-build success probability `p` and the 1-2-4-8-16 s backoff the window
permits five attempts, so the probability a slot is empty at expiry is `(1−p)^5` —
3.2 × 10⁻⁴ at p=0.8, 3.1 % at a badly degraded p=0.5. It is sized for the degraded
case.

**`min_ready` and the degraded signal.** Each half keeps ≥ 2 tunnels in READY or
ACTIVE. Below that the pool builds at elevated priority and raises `DEGRADED` to
the session layer, which **stops opening new streams** rather than opening them
all onto the single survivor. Concentrating a destination's whole traffic on one
path while the pool is failing is exactly the moment an adversary who caused the
failures gets to observe everything.

#### Selection: which tunnel carries the next message

| Traffic class (R2) | Policy | Reason |
|---|---|---|
| `INTERACTIVE` | **Sticky per stream.** At stream open, weighted-random over READY/ACTIVE tunnels, weight `1 / EWMA_RTT`, EXPIRING excluded; the stream stays there until the tunnel dies. | Reordering and RTT variance are visible to the peer and to observers. Sticky keeps a stream's timing signature on one path. |
| `BULK` | **Stripe** per message across READY/ACTIVE tunnels, same weighting. | Batched and padded, so per-message timing leaks little, and striping is what makes the erasure-coded storage layer's parallelism usable. |
| Control (publish, fetch, intro upkeep) | Least-recently-used, and never the tunnel currently carrying data for the same destination. | Keeps a descriptor publish from sharing a terminal hop with the traffic it advertises. |

Striping is cheaper here than in I2P: hop 1 is pinned (R1), so striping varies hops
2..n only and exposes no additional first hops. It does expose more middle and
terminal relays per unit time, raising the chance that *some* relay on *some*
tunnel is hostile and sees terminal traffic. That is the price, and it is why
`INTERACTIVE` does not pay it.

#### Guard failure, and why replacement is deliberately slow

Five consecutive build failures on one guard mark it SUSPECT; builds continue on
the other. When both are SUSPECT the context **stalls** — it does not silently
re-guard. A guard is replaced only after **12 hours** of continuous
unreachability *and* confirmation of general network reachability through another
isolation context. Anything faster converts a targeted DoS on a client's guard
into a forced re-guard, which is how guard pinning is defeated in practice. The
cost is honest: a node whose two guards are genuinely dead is offline for that
context for up to 12 hours. `[BUILD NOW]` for the mechanism; the 12 h constant is
a policy number wanting measurement.

---

### 9.3 Why pools are per-destination, and what that costs

**Per-node pooling is cheaper and leaks co-hosting.** If one pool served every
destination on a node, a relay in that pool would see traffic for service A and
service B leaving through the same tunnel and could infer they are co-hosted;
worse, an operator's own browsing would share paths with the service they run.
Per-node pooling makes the pool a *join key*. Per-destination pooling removes the
shared object: each destination is its own isolation context (§5), gets its own
two pinned guards, and shares no tunnel with any other destination on the machine.

#### The arithmetic

Fixed inputs from the Constitution: lifetime 600 s; 3+1 inbound and 3+1 outbound
per destination; default circuit length 3 hops. Therefore
`(3+1)+(3+1) = 8` tunnels per destination, `3600/600 = 6` builds per slot per
hour, `8 × 6 = 48` builds and `48 × 3 = 144` hop-creations per destination-hour.

| Node shape | Destinations | Tunnels | Builds/hour | Hop-creations/hour |
|---|---:|---:|---:|---:|
| Pure client | 1 | 8 | 48 | 144 |
| Client + 1 service | 2 | 16 | 96 | 288 |
| Client + 5 services | 6 | 48 | 288 | 864 |
| Client + 1 service, widened to 12 intro points | 2 | 8 + (4+12) = 24 | 144 | 432 |

Load is linear in destination count: a node hosting five services does six times a
client's build work — 288 builds/hour, one every 12.5 seconds. That is the price
of not leaking co-hosting, and it is affordable.

#### Aggregate network load

Assume `N` nodes, each with one client destination, a fraction `s = 0.1` hosting
one service each, and a fraction `f = 0.3` relaying (R3 gates relaying on
reachability, so `f` is well below 1). The network offers `48·N·(1+s) = 52.8·N`
builds/hour and three times that in hop-creations, spread over `f·N` relays:
`158.4/(3600·f) = 0.147` hop-creations per second per relay, **independent of N**.

| N | Builds/h, network | Builds/s | Hop-creations/s | Relays (f=0.3) | Hop-creations/s **per relay** |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 52,800 | 14.7 | 44 | 300 | **0.147** |
| 10,000 | 528,000 | 147 | 440 | 3,000 | **0.147** |
| 100,000 | 5,280,000 | 1,467 | 4,400 | 30,000 | **0.147** |

**The per-relay column is constant.** Offered load and relay capacity both scale
with `N`, so the build economy is self-scaling. The parameter that moves it is `f`:

| `f` | Per-relay hop-creations/s | Per-relay concurrent circuits `= 3·8·(1+s)/f` |
|---|---:|---:|
| 1.0 (everyone relays — I2P/Freenet model) | 0.044 | 26 |
| 0.3 (assumed) | 0.147 | 88 |
| 0.1 (pessimistic; most nodes CGNAT-bound) | 0.44 | 264 |
| 0.03 (Tor-like relay:client ratio) | 1.47 | 880 |

Both columns are independent of `N`. Each circuit carries two AEAD key schedules,
a replay window and one QUIC stream's buffers; even 880 concurrent circuits is a
few megabytes and under two X25519 operations per second. **CPU and memory are not
the binding constraint at any of these figures.** What binds is build latency
under failure — absorbed by the 180 s window — and guard capacity.

#### Guard concentration is the real scarcity

Every build's first hop is a guard, so all `52.8·N` builds/hour land on the
guard-eligible subset. With guard-eligible fraction `g` of relays there are
`f·g·N` guards, taking `52.8/(f·g)` CREATEs per hour each, with
`2·N·(1+s)/(f·g·N) = 2.2/(f·g)` destinations pinned to each.

| `f` | `g` | CREATEs/hour per guard | Destinations pinned per guard |
|---|---|---:|---:|
| 0.3 | 0.5 | 352 | 14.7 |
| 0.3 | 0.2 | 880 | 36.7 |
| 0.1 | 0.2 | 2,640 | 110 |

352 CREATEs/hour is 0.1/s — trivial. The number that matters is the right-hand
column: a guard carries the **entire traffic** of every destination pinned to it.
At f=0.1, g=0.2 that is 110 destinations' full bandwidth through one node. Guard
eligibility must be generous, or guards become the bandwidth bottleneck long
before they become the CPU bottleneck. `[NEEDS RESEARCH]`: the eligibility
threshold is a bandwidth-and-stake policy question §8 and the accounting plane
jointly own.

#### What the guard constraint buys

Over 45 days one destination performs `8 × 6 × 24 × 45 = 51,840` builds. Sampling
first hops fresh (I2P-style) gives `P(≥1 hostile first hop) = 1 − (1−h)^51840 ≈ 1`
for any hostile fraction `h > 10⁻⁴`; two pinned guards give `1 − (1−h)²` — 1.99 %
at h=0.01, 9.75 % at h=0.05, 19.0 % at h=0.10. The comparison is unfair to I2P in
one respect (a hostile first hop on one of 51,840 short-lived tunnels sees far
less than a guard sees over 45 days) but the shape is the point: churn makes
compromise near-certain and shallow, pinning makes it unlikely and deep. R1 chooses
unlikely-and-deep; the 45-day rotation bounds how deep.

---

### 9.4 The service descriptor `[BUILD NOW]`

A signed record published to the DHT under a **blinded** key, so the storing node
learns neither the service identity nor the name (R4c), encrypted in two layers so
that only a party who knows the `.axon` name or the raw ServiceIdentity can read
the outer one, and only an authorized client the inner one.

#### Key derivation

```text
K_svc       ServiceIdentity Ed25519 public key (32 B), never on the wire
period_len  86400 s; overlap 43200 s  →  two periods valid at once
period_num  floor((unix_now − period_offset) / period_len)
SRV         the epoch's shared random value (R13: verified RANDAO mix)

h        = SHA256("axon:blind:v1" ‖ K_svc ‖ LE64(period_num) ‖ LE64(period_len)
                  ‖ SRV ‖ auth_secret)     -- auth_secret = 0^32 unless §9.7 L2
K_blind  = Ed25519-blind(K_svc, h)         -- scalar blinding, rend-spec-v3 style
k_blind  = Ed25519-blind-priv(k_svc, h)

credential     = SHA256("axon:cred:v1"    ‖ K_svc)
subcredential  = SHA256("axon:subcred:v1" ‖ credential ‖ K_blind)
hsdir_index(j) = SHA256("axon:hsdir-index:v1" ‖ K_blind ‖ u8(j)
                        ‖ LE64(period_num) ‖ SRV)         for j ∈ {0,1}
```

Two replica indices, each written to the DHT's `r=8` closest holders (§5) → 16
holders per period, up to 32 during the 12 h overlap. At a typical 8 KiB descriptor
republished hourly that is 256 KiB/hour per service — negligible, and stated so the
number is on the record rather than assumed.

#### Outer record — plaintext, signed; what an HSDir stores and validates

| Off | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 1 | `version` | = 1 |
| 1 | 1 | `flags` | bit0 `restricted_discovery`, bit1 `pow_required`, rest 0 |
| 2 | 2 | `intro_bucket` | one of 3, 6, 12, 20 — the *declared* intro count |
| 4 | 32 | `blinded_pubkey` | `K_blind`; the DHT key derives from it and the HSDir checks that |
| 36 | 8 | `revision` | monotonic per (K_svc, period); ties broken first-seen |
| 44 | 4 | `lifetime_s` | 10800 (3 h). HSDir rejects > 10800 |
| 48 | 8 | `published_at` | unix seconds **rounded down to the hour** — do not leak publish jitter |
| 56 | 32 | `desc_signing_key` | `K_desc`, short-term Ed25519 |
| 88 | 64 | `desc_signing_cert` | `K_blind` signs `("axon:desc-sign:v1" ‖ K_desc ‖ expiry)` |
| 152 | 8 | `cert_expiry` | |
| 160 | 16 | `salt_1` | random per revision |
| 176 | 4 | `superenc_len` | |
| 180 | var | `superencrypted` | layer-1 ciphertext + 16 B Poly1305 tag |
| … | var | `padding` | to the next bucket in {4, 8, 16, 32, 64} KiB |
| … | 64 | `signature` | `K_desc` over all preceding bytes, prefixed `"axon:desc:v1"` |

Record capped at **64 KiB**, matching the existing `WorkerDHTValidator` cap. An
HSDir validates exactly this much and no more: parses, `blinded_pubkey` matches
the storage key, `lifetime_s ≤ 10800`, `published_at` not in the future, cert
chain `K_blind → K_desc` verifies, signature verifies, `revision` exceeds the
stored one. It cannot learn the service. This is `WorkerDHTValidator.Validate`
with a blinded key in place of a node id and `Select` on `revision` instead of
`Sequence` — the same two functions the codebase has written twice already.

#### Layer 1 — "superencrypted": decryptable by anyone who knows the name

```text
secret_1  = K_blind ‖ subcredential ‖ LE64(revision)
K_1 ‖ N_1 = HKDF-SHA256(salt=salt_1, ikm=secret_1,
                        info="axon:desc:outer:v1", L=32+12)
superencrypted = ChaCha20-Poly1305(K_1, N_1, layer1_body,
                                   AAD = outer bytes [0..180))
```

| Size | `layer1_body` field |
|---:|---|
| 1 | `auth_type` — 0 = public, 1 = X25519 client auth |
| 32 | `desc_eph_pub` — ephemeral X25519 public key, one per revision |
| 2 | `n_auth_clients` — always a multiple of 16; unused entries are random bytes |
| 56×n | `auth_client[]` — §9.7 |
| 16 | `salt_2` |
| 4 | `enc_len` |
| var | `encrypted` — layer-2 ciphertext + tag |

#### Layer 2 — "encrypted": decryptable only by an authorized client

```text
descriptor_cookie = 0^32                     for a public service
                  = random 32 B per revision for a restricted service
secret_2  = K_blind ‖ subcredential ‖ descriptor_cookie
K_2 ‖ N_2 = HKDF-SHA256(salt=salt_2, ikm=secret_2,
                        info="axon:desc:inner:v1", L=32+12)
encrypted = ChaCha20-Poly1305(K_2, N_2, layer2_body, AAD = layer-1 header)
```

| Size | `layer2_body` field | Notes |
|---:|---|---|
| 1 | `n_intro` | equals `intro_bucket` |
| 368×n | `intro_point[]` | below |
| 1 | `pow_scheme` | 0 = none, 1 = memory-hard puzzle (§9.6) |
| 32 | `pow_seed` | rotates with the descriptor and on any effort raise |
| 4 | `pow_suggested_effort` | |
| 4 | `pow_reference_ms` | **measured** solve time at that effort on the declared reference profile |
| 8 | `pow_expiry` | |
| 2 | `flow_control` | initial session window, in cells |
| var | `padding` | to a fixed multiple of 512 B |

| Size | `intro_point[i]` field (368 B) | Notes |
|---:|---|---|
| 32 | `ip_routing_id` | the IP relay's RoutingIdentity Ed25519 (§3) |
| 32 | `ip_onion_key` | its X25519, for §8's handshake when extending to it |
| 32 | `auth_key` | per-intro Ed25519; names *which* established intro circuit at the IP |
| 32 | `enc_key` | per-intro X25519 `B_enc`; the client encrypts INTRODUCE to **the service** under it, and the IP cannot read it |
| 64 | `auth_key_cert` | `K_desc` signs `("axon:intro-auth:v1" ‖ auth_key)` |
| 64 | `enc_key_cert` | `K_desc` signs `("axon:intro-enc:v1" ‖ enc_key)` |
| 80 | `link_hints` | opaque, forwarded to §8's path selector |
| 32 | `instance_tag` | `HMAC(K_desc, "axon:instance:v1" ‖ index)` — §9.9 |

**Why two layers.** One layer forces a choice: either the intro list is readable by
anyone who knows the name (so client authorization cannot hide it), or the whole
descriptor is readable only by authorized clients (so a public service cannot be
public). Two layers separate *knowing the name* from *being authorized* — genuinely
different facts. **What we changed from Tor v3:** its layers use a stream cipher
plus a separately-computed SHA3-256 MAC over a length-prefixed encoding; we use
ChaCha20-Poly1305 with the preceding header as AAD in both. That removes a
hand-rolled encrypt-then-MAC construction and its canonicalization rules — one
fewer place to get a decryption-oracle bug — with the security argument unchanged.

---

### 9.5 The rendezvous protocol `[BUILD NOW]`

#### L5 command set

These are relay commands carried in §8's cells. §8 owns the cell; this table owns
the commands.

| Command | From → To | Carried on | Body |
|---|---|---|---|
| `ESTABLISH_INTRO` | service → IP | service inbound tunnel | `auth_key`, `auth_key_cert`, handshake-bound signature, extensions |
| `INTRO_ESTABLISHED` | IP → service | same circuit | status, IP's advertised rate-limit state |
| `INTRODUCE1` | client → IP | client outbound tunnel | layout below |
| `INTRODUCE_ACK` | IP → client | same circuit | status ∈ {OK, RATE_LIMITED, PUZZLE_REQUIRED, UNKNOWN_AUTH_KEY, REPLAY} + puzzle params |
| `INTRODUCE2` | IP → service | service's intro circuit | the `INTRODUCE1` body verbatim + the IP's admission verdict |
| `ESTABLISH_RENDEZVOUS` | client → RP | client inbound tunnel | `rend_cookie` (20 B), optional token/puzzle |
| `RENDEZVOUS_ESTABLISHED` | RP → client | same circuit | status |
| `RENDEZVOUS1` | service → RP | service outbound tunnel | `rend_cookie`, `Y` (32 B), `AUTH` (32 B) |
| `RENDEZVOUS2` | RP → client | client's rend circuit | `Y`, `AUTH` |
| `RESUME_REGISTER` | client → RP | spliced circuit | `commit` (32 B), `counter` (u32) — §9.8 |
| `RESUME_RENDEZVOUS` | client → RP | fresh circuit | `preimage` (32 B), `counter` (u32) — §9.8 |
| `INTRO_TEARDOWN` | service → IP | intro circuit | reason — §9.9 |

#### Sequence

```text
CLIENT                                                              SERVICE
  │  ═══ phase 0: descriptor, over a client outbound tunnel ═══        │
  │  K_blind from the .axon name → K_svc, or from K_svc directly       │
  │  FETCH hsdir_index(0), hsdir_index(1) via a 3-hop tunnel           │
  │◄──── descriptor (~8 KiB) ──── HSDir                                │
  │  decrypt layer 1 (subcredential) → layer 2 (descriptor_cookie)     │
  │      → intro_point[], pow params                                   │
  │  ═══ phase 1: rendezvous — RUNS IN PARALLEL WITH PHASE 0 ═══       │
  │  pick RP from the local relay view (§8); rend_cookie ← random 20 B │
  │  ESTABLISH_RENDEZVOUS{rend_cookie} ──► RP                          │
  │◄── RENDEZVOUS_ESTABLISHED ──────────── RP  (this circuit is now an │
  │                                             INBOUND tunnel)        │
  │  ═══ phase 2: introduction ═══                                     │
  │  x ← random;  X = x·G;  solve puzzle or spend token (§9.6)         │
  │  INTRODUCE1{auth_key_id, X, pow_ext, ENCRYPTED} ──► IP             │
  │                             IP checks: auth_key_id known? proof    │
  │◄── INTRODUCE_ACK{OK} ─────  valid? replay? rate ok?                │
  │                                 INTRODUCE2 ──────────────────────► │
  │                                        service decrypts ENCRYPTED: │
  │                                        rend_cookie, RP identity, X │
  │                                        y ← random; Y = y·G         │
  │                                        derive KEY_SEED, AUTH       │
  │                  ◄──── RENDEZVOUS1{rend_cookie, Y, AUTH} ───────── │
  │                  RP    (service outbound tunnel, 3 hops)           │
  │  RP matches rend_cookie to the client's established circuit,       │
  │  drops the cookie, and SPLICES the two circuits.                   │
  │◄── RENDEZVOUS2{Y, AUTH} ─── RP ;  recompute KEY_SEED, verify AUTH  │
  │  ═══ phase 3 ═══                                                   │
  │  ◄═══════════ end-to-end session, 6 relays + RP ═══════════════►   │
  │       client 3 hops │ RP │ 3 hops service                          │
```

#### INTRODUCE1 layout

| Size | Field | Visible to IP? |
|---:|---|---|
| 1 | `version` = 1 | yes |
| 32 | `auth_key_id` — the `auth_key` from the descriptor entry | yes; it is how the IP finds the circuit |
| 1 | `ext_count` | yes |
| var | `extensions[]` — `pow_proof` or `token`, `client_auth_present` flag | yes; the IP must check them |
| 32 | `X` — client ephemeral X25519 | yes |
| 2 | `enc_len` | yes |
| var | `ENCRYPTED` + 16 B tag — **fixed 512 B plaintext** | **no** |

`ENCRYPTED` plaintext: `rend_cookie` (20) ‖ `rp_routing_id` (32) ‖ `rp_onion_key`
(32) ‖ `rp_link_hints` (80) ‖ `resume_present` (1) ‖ `session_resume{session_id 16,
counter 4, proof 32}` (52, zeroed if absent) ‖ `client_auth_proof` (32, zeroed if
absent) ‖ `flow_control` (2) ‖ padding to 512 B. The fixed length means the IP
cannot tell a fresh introduction from a resumption, or an authorized client from a
public one, by size.

#### Every key, in order

```text
INTRO ENCRYPTION  (client → service, one-way authenticated; the IP cannot read it)
  B_enc  = intro_point[i].enc_key          (from the descriptor)
  x, X   = client ephemeral X25519 pair
  ikm    = X25519(x, B_enc) ‖ K_svc ‖ X ‖ B_enc
  K_i ‖ N_i = HKDF-SHA256(salt=auth_key, ikm,
                          info="axon:intro:v1" ‖ subcredential, L=32+12)
  ENCRYPTED = ChaCha20-Poly1305(K_i, N_i, plaintext, AAD = INTRODUCE1 header)

RENDEZVOUS HANDSHAKE  (ntor-shaped: service authenticates, both get forward secrecy)
  b_enc, B_enc = the service's per-intro X25519 pair
  y, Y         = service ephemeral X25519 pair
  ntor_input = X25519(y, X) ‖ X25519(b_enc, X) ‖ K_svc ‖ B_enc ‖ X ‖ Y
               ‖ "axon-rend-v1"
  KEY_SEED   = HMAC-SHA256(key="axon:rend:keyseed:v1", msg=ntor_input)
  AUTH       = HMAC-SHA256(key="axon:rend:auth:v1", msg=ntor_input ‖ "server")
  client recomputes with X25519(x, Y) ‖ X25519(x, B_enc) ‖ … and checks AUTH

SESSION KEYS  (above the circuit crypto — §9.8)
  session_root      = HKDF-SHA256(0, KEY_SEED,
                                  "axon:sess:root:v1" ‖ session_id, 32)
  K_f ‖ K_b ‖ resume_secret
                    = HKDF-SHA256(0, session_root, "axon:sess:keys:v1", 96)
```

The first DH (`x·Y`) gives forward secrecy; the second (`x·B_enc`) authenticates
the service, because only the holder of `b_enc` — certified by `K_desc`, certified
by `K_blind`, derived from `K_svc` — produces a matching `AUTH`. This is the ntor
pattern unmodified; the only AXON-specific parts are the domain-separation labels
and the inclusion of `K_svc`.

#### Hop count and latency budget

```text
client ── g ── m ── t ──►  RP  ◄── t ── m ── g ── service
         1    2    3            3    2    1     = 6 relay hops + RP  (§5)
```

Let `L` be mean one-way relay-to-relay latency; a round trip over a 3-hop circuit
costs `6L`.

| Phase | Cost | @25 ms | @50 ms | @100 ms | Note |
|---|---|---:|---:|---:|---|
| Descriptor fetch, cold | `24L` | | | | iterative DHT lookup, ~4 iterations at α=3, each one circuit RTT |
| Descriptor fetch, cached | `0` | | | | 3 h lifetime; a repeat visit skips it entirely |
| RP establishment | `6L` | | | | **concurrent with the descriptor fetch** — it does not depend on it |
| Puzzle solve | 0–`pow_reference_ms` | | | | client CPU; also concurrent with RP establishment |
| `INTRODUCE1` → service | `3L+3L` | | | | client→IP, then IP→service down the intro circuit |
| `RENDEZVOUS1` → RP → client | `3L+3L` | | | | |
| **Total, cold** | **`max(24L,6L)+12L = 36L`** | **0.90 s** | **1.80 s** | **3.60 s** | |
| **Total, warm descriptor** | **`max(0,6L)+12L = 18L`** | **0.45 s** | **0.90 s** | **1.80 s** | |
| **Resume at the same RP (§9.8)** | **`6L`** | **0.15 s** | **0.30 s** | **0.60 s** | no descriptor, no intro, no rendezvous |
| First data round trip after connect | `+6L` | | | | |

Two caveats. These are budgets from hop counts, not measurements — no AXON code
exists. And `L` is not a constant: relay-to-relay latency has a long tail and a
3-hop circuit's RTT is dominated by its worst link, so the mean understates the
95th percentile. The term to optimise is the descriptor fetch, and the lever is
the cache, not the protocol.

---

### 9.6 Introduction points, and pricing access to them

**Why intro points exist (R10).** I2P publishes the lease set — the actual tunnel
gateways — directly, so anyone who reads it can flood the service's inbound
gateways and can enumerate its tunnels and watch them rotate, which is a
fingerprint. Tor interposes an introduction point: the published endpoint is a
*third party's* address and the service's own tunnel endpoints are never
published. The cost is one extra round trip — `6L` of `36L` cold, overlapped with
the descriptor fetch — and R10 rules it worth paying.

**Where Tor's version fails.** An `INTRODUCE1` is a few hundred bytes and costs the
service a circuit build to an attacker-chosen rendezvous point: three relay
handshakes and ten minutes of circuit state. That asymmetry has hurt real onion
services more than anything else. R10's improvement is to price the introduction.

#### Two accepted proofs `[BUILD NOW]` (interface) / `[NEEDS RESEARCH]` (parameters)

| Proof | Client cost | Verify cost | Preferred when |
|---|---|---|---|
| **Token** — blind-signed, unlinkable, Privacy-Pass shaped | one VOPRF evaluation at issuance; ~0 at spend | one HMAC + a double-spend lookup | The client has one. Same machinery R11 specifies for relay payment: issued once, spent anywhere. |
| **Puzzle** — memory-hard, asymmetric-verification proof of work | `pow_reference_ms` of CPU | microseconds | The client has no token. Always available, never needs an issuer. |

Both ride the opaque challenge/response shape in `internal/p2p/challenge.go`
rather than opening a second protocol.

Puzzle requirements, in priority order: (1) **verification must be orders of
magnitude cheaper than solving**, or the puzzle is itself the DoS — this rules out
Argon2id and every symmetric memory-hard KDF, which cost the verifier exactly what
they cost the solver; (2) **solving must be memory-hard**, because plain hashcash
over BLAKE3 satisfies (1) but hands a GPU or ASIC adversary a two-to-three
order-of-magnitude advantage over a phone, converting the puzzle into targeted
exclusion of exactly the users who most need the service; (3) **parameters must be
runtime-adjustable**, because the load is adversarial. The family satisfying all
three is Equihash-style — asymmetric, memory-bound, cheap to verify — and Tor's
deployed onion-service proof of work uses a scheme of this family for these
reasons. The parameterisation is `[NEEDS RESEARCH]`: Equihash `(n,k)` selection has
a history of parameter breaks and this document must not pick numbers it cannot
defend. What v1 fixes is the interface:

```text
challenge = SHA256("axon:pow:v1" ‖ pow_seed ‖ K_blind ‖ LE32(effort) ‖ nonce)
solution  = the scheme's proof over `challenge`
valid iff scheme_verify(challenge, solution) AND
          SHA256("axon:pow:check:v1" ‖ challenge ‖ solution) < 2^256 / effort
```

The second condition is the effort dial: a cheap post-filter on an already
memory-hard solution, so effort scales linearly while the memory floor stays fixed.
`pow_seed` rotates with the descriptor, bounding pre-computation to one period.

#### Difficulty adjustment

The service, not the intro point, sets effort — only the service knows whether it
is overloaded. The IP reports load; the service decides.

```text
every 10 s at the service, with q = INTRODUCE2 queue depth, q_target = 6:
  q > q_target    → effort ← min(effort × 1.5 + 1, effort_ceiling)
  q < q_target/4  → effort ← max(effort × 0.75, 0)
  otherwise       → unchanged
effort_ceiling = largest effort whose MEASURED solve time on the declared
                 reference profile is ≤ 5 s              ← a POLICY number
```

New effort reaches clients only at the next republish (up to 1 h later), so the IP
also carries the current value in `INTRODUCE_ACK{PUZZLE_REQUIRED, effort, seed}`,
letting a client retry immediately. That is the fast path; the descriptor is the
slow path.

#### Failure modes, including the one that matters

| Failure mode | Effect | Response |
|---|---|---|
| Effort too low | attack succeeds, queue grows | the 10 s loop raises it |
| Effort too high | slow clients time out | the ceiling, plus reference-time disclosure |
| Seed rotation too slow | pre-computed solutions | 3 h lifetime bounds it; seed also rotates on any effort raise |
| Solution replay | one solve serves many introductions | IP replay cache on `SHA256(challenge ‖ solution)`, window = `pow_expiry` |
| Attacker holds valid tokens | tokens spent instead of CPU | double-spend set; per-issuance-epoch spend caps |

**A puzzle that prices out slow clients is a censorship mechanism.** The design
answers this rather than noting it.

1. **Effort is never a gate. It is a queue position.** An `INTRODUCE1` with a weak
   proof, or none, is **not rejected** — it is placed in a lower-priority queue.
   Under no attack that queue drains immediately; under attack it drains slowly;
   it never drains never. This is the shape of `AdmissionController.Admit` in
   `internal/dcs/admission.go`, which already returns a ticket, a position and an
   ETA rather than a bare rejection, and it is the most important rule here.
2. **The token path costs a slow client nothing.** Tokens are unlinkable and
   transferable before spend, so they can be issued out of band to people whose
   hardware cannot solve puzzles. The cost is an issuer — a centralisation risk
   named in R11 and not solved here.
3. **The ceiling is enforced client-side, not merely advertised.** A client refuses
   an effort whose `pow_reference_ms` exceeds its own budget and reports
   `PUZZLE_TOO_EXPENSIVE`, so a service that prices its users out loses them
   visibly rather than appearing merely slow.
4. **The descriptor discloses the price.** `pow_reference_ms` is a *measured* solve
   time on a declared reference profile. A service that fills this field with an
   estimate is publishing a fiction.

**Residual `[UNSOLVED]`.** An adversary with more aggregate CPU than the honest
client population will push effort to the ceiling and hold it there, and at the
ceiling the low-priority queue is where slow clients live — the service is degraded
for exactly the population least able to pay. The puzzle converts a hard outage
into a graded slowdown; it does not eliminate the attack. The only mechanism that
does is the token, and the token needs an issuer. No decentralised,
Sybil-resistant, privacy-preserving token issuer exists — here or anywhere.

---

### 9.7 Client authorization

Two levels, defending against different observers.

#### Level 1 — descriptor authorization `[BUILD NOW]`

The `descriptor_cookie` gates layer 2 (§9.4). Per revision the service generates an
ephemeral X25519 pair `e, E` and publishes `E` as `desc_eph_pub`; for each
authorized client with X25519 public `Kx_i`:

```text
s_i        = X25519(e, Kx_i)
client_id  = first 8 B of SHA256("axon:auth:clientid:v1" ‖ subcredential ‖ s_i)
K_i ‖ N_i  = HKDF-SHA256(salt=subcredential, ikm=s_i,
                         info="axon:auth:cookie:v1", L=32+12)
cookie_ct  = ChaCha20-Poly1305(K_i, N_i, descriptor_cookie)   -- 32 + 16 B
auth_client[i] = client_id ‖ cookie_ct                        -- 8 + 48 = 56 B
```

The list is padded to a multiple of 16 with uniformly random bytes, so the
authorized-client count is disclosed only to the nearest 16, and `client_id`
derives from `subcredential`, which rotates each period, so client identifiers are
unlinkable across periods. A client not in the list can still fetch the record,
decrypt layer 1, and find no matching `client_id` — **it therefore learns the
service exists and is restricted.** That is the honest limit of level 1.

#### Level 2 — restricted discovery `[NEEDS RESEARCH]`

To deny even existence, the DHT location must be secret. A shared `auth_secret`
(32 B) is folded into the blinding factor `h` (§9.4). Someone who knows the name
but not `auth_secret` computes a different `K_blind`, looks where nothing was ever
published, and gets the same answer as for a name that does not exist: nothing.
Existence is not confirmable. The `restricted_discovery` flag is set only on the
descriptor that *is* published, where only authorized clients see it.

Costs, plainly: rotating `auth_secret` needs out-of-band redistribution to every
client, with no in-band revocation channel — that is the point of the design; any
single authorized client that leaks it restores discoverability for everyone until
rotation; and it interacts badly with multi-instance publication (§9.9), because
the publisher must hold it, making it a second secret with `K_svc`'s blast radius.
That last interaction is what the `[NEEDS RESEARCH]` marks.

#### Credential format

```text
axoncred1<base32( body ‖ checksum )>
body     = version u8 = 1 ‖ flags u8 (bit0: auth_secret present)
         ‖ K_svc 32 B ‖ client_auth_priv 32 B (X25519)
         ‖ auth_secret 32 B  (present iff flags bit0)
checksum = first 4 B of SHA256("axon:cred:checksum:v1" ‖ body)
```

The label a user attaches is stored locally and never encoded: a credential file
naming the service it belongs to is a plaintext record of which restricted
services a person has access to.

---

### 9.8 The session layer `[BUILD NOW]`

R9: addresses name destinations, circuits are disposable carriers, **streams bind
to sessions, not circuits.**

```text
SESSION
  session_id      16 B, chosen by the client, never reused
  session_root    32 B from KEY_SEED (§9.5)
  K_f, K_b        32 B each, ChaCha20-Poly1305, ABOVE the circuit crypto
  resume_secret   32 B
  seq_f, seq_b    u64, monotonic per direction, NEVER reset across carriers
  ack_f, ack_b    u64, highest contiguous received
  streams         map[StreamID] → {window, send buffer, recv reorder buffer}
  carrier         the current (client tunnel, RP, service tunnel) triple, or none
  state           ATTACHED | ORPHANED | CLOSED
```

The session AEAD is a second, independent layer over the circuit's. That is the
whole mechanism: because session keys and sequence numbers are independent of the
carrier, replacing the carrier is a routing change, not a cryptographic one. It
also means a hostile RP cannot inject — it can splice a new circuit in, but every
cell it injects fails `K_f`/`K_b` authentication.

**Case A — the client's circuit to the RP died; RP and service side are alive.**
The common case, since rotation kills a circuit every 10 minutes by design.

```text
at splice time, and after every successful resume, on the live circuit:
  client → RP: RESUME_REGISTER{ counter = n,
                 commit = SHA256("axon:rp:resume:v1" ‖ rp_resume_id ‖ LE32(n)) }
  where rp_resume_id = HKDF(session_root, "axon:sess:rpid:v1", 32)

the RP holds the SERVICE-side circuit for a 60 s grace window after the client
side drops, indexed by `commit`.

on resume, over a FRESH client circuit to the SAME RP:
  client → RP: RESUME_RENDEZVOUS{ counter = n, preimage = rp_resume_id }
  RP checks the hash, splices, BURNS the commitment;
  client immediately registers commit for counter = n+1.
```

Cost: `6L`. No descriptor fetch, no introduction, no puzzle, no new rendezvous.

| Attack on resumption | Defence |
|---|---|
| Replay of a captured `RESUME_RENDEZVOUS`, in order or out | one-shot burn (the commitment is deleted on first successful use); the RP stores only the newest commitment and `counter` must equal it |
| Third party guessing `rp_resume_id` | 256-bit, derived from `session_root`, which requires the rendezvous handshake |
| Hostile RP splices an attacker's circuit to the service, or replays the service side to a second client | session AEAD rejects every injected cell (`CARRIER_HOSTILE`); the second client cannot produce `K_f` and sees only authentication failures |
| RP state exhaustion via registered commitments | one 32 B commitment per spliced circuit, freed with the circuit |

**Case B — the RP itself died.** A new rendezvous is required but not a new
*session*. The client fetches nothing (descriptor cached), picks a new RP, and
sends an `INTRODUCE1` whose encrypted payload carries:

```text
session_resume { session_id 16 B, counter u32 (strictly increasing),
  proof = HMAC-SHA256(resume_secret, "axon:sess:resume-svc:v1" ‖ session_id
                      ‖ LE32(counter) ‖ new_rend_cookie ‖ rp_routing_id) }
```

The service verifies `proof`, checks `counter` exceeds the stored one, and
**reattaches the existing stream state** instead of creating a new session. The new
cookie and RP identity are bound into the proof, so a replayed introduction names
an RP the replayer does not control and cannot complete the ntor (it lacks `x`).
The residual belongs here, not in §9.10: a replayed `INTRODUCE1` still costs the
service one circuit build before it fails, and the defence is the intro-level
replay cache on `(auth_key_id, X)` windowed to the descriptor lifetime — the same
cache §9.10 needs for other reasons.

**Ratchet.** Case-B resumption already performs a fresh DH, so mix it in:
`session_root ← HKDF(salt=session_root, ikm=new KEY_SEED,
info="axon:sess:ratchet:v1", 32)`, re-deriving `K_f`, `K_b`, `resume_secret`
without resetting `seq_*`. That gives post-compromise security at every new
rendezvous, free. **Case-A resumption contributes no new DH and therefore gives no
post-compromise security** — an adversary holding session keys keeps them across a
case-A resume. Say so; do not imply otherwise. A symmetric rekey
(`K ← HKDF(K, "axon:sess:rekey:v1" ‖ n)`) every 2²⁰ cells or 1 hour bounds nonce
reuse risk and provides no post-compromise security either.

Timers: carrier grace at the RP 60 s, after which it frees the service-side
circuit; ORPHANED retention 5 min at both ends, then `CLOSED`; idle timeout
15 min; hard session lifetime 12 h, forcing re-rendezvous with a new `session_id`.
The hard cap exists because a long-lived session is a long-lived correlation
handle. A 12-hour session is a persistently-online user, which §7 explicitly does
not defend; the cap does not fix that, it declines to make it worse.

---

### 9.9 Service-side operations

#### No inbound reachability, at all `[BUILD NOW]`

Every circuit a service holds is built outward by it: to an HSDir to publish, to
each intro point (`ESTABLISH_INTRO`), and to a rendezvous point (`RENDEZVOUS1`). A
service therefore works behind NAT, behind CGNAT, behind a firewall permitting only
outbound 443, with zero port forwarding and zero UPnP. Not an aspiration — the
deployed node already operates this way, with its entire transport in
`internal/i2p/transport.go` and no inbound listener of any kind.

The consequence, stated honestly: R3 gates relaying on reachability, so a
CGNAT-bound service node **cannot relay**, earns nothing from the accounting plane
for forwarding, and consumes guard and relay capacity it does not replenish. A
network of unreachable services and few relays is the `f = 0.1` or `f = 0.03` row
of §9.3, where guard concentration becomes the bottleneck. The incentive design
that would fix this is not in this section and not in v1 (R11).

One rule inherited directly from `internal/i2p/transport.go`: an endpoint-holding
loop **must treat carrier loss as routine**. That file records what happens
otherwise — every node went deaf about six minutes after starting, because an idle
accept socket's EOF was treated as terminal. The intro-circuit maintainer, the RP
grace-window holder and the descriptor publisher all hold long-lived idle state
and all have this failure mode.

#### Multiple instances behind one ServiceIdentity `[BUILD NOW]`

Two instances cannot both publish under one `K_blind`: `Select` takes the highest
`revision`, so one wins, the other's intro points vanish, and the instances
alternate which half of the service is reachable. The design is a **front-end
publisher**:

```text
   instance 0 ──┐  each instance establishes its OWN intro points and reports
   instance 1 ──┤  (auth_key, enc_key, ip_routing_id, certs) to the publisher
   instance 2 ──┘  over an authenticated overlay session
                       │
                  PUBLISHER  holds K_svc (and auth_secret, if any); merges all
                       │     instances' intro points into ONE descriptor,
                       ▼     revision++, publishes to 16 HSDirs
                   the DHT
```

| Property | Consequence |
|---|---|
| Only the publisher holds `K_svc` | Instances hold no long-term secret; a compromised instance costs its intro points, not the identity. |
| Intro points pinned to instances | A client's choice of intro point *is* its choice of instance; load balance by intro-point count per instance. |
| `instance_tag` per intro entry | Lets the publisher, and only the publisher, attribute a failing intro point to an instance. An HMAC under `K_desc`, so a client learns nothing. |
| Instance failure | Its intro points stop answering; `INTRODUCE_ACK` times out and the client retries another entry — recovery is client-side and immediate. |
| Publisher failure | **Publication** stops; **service** does not. The existing descriptor stays valid for 3 h, so the publisher has a 3 h outage budget. |
| `intro_bucket` | The intro count is a bucket, not the true count, so instance count is disclosed only to the nearest bucket: a 20-entry descriptor is one instance under attack or five at rest. |

The publisher is a single point of compromise for `K_svc` and a 3 h single point of
failure for publication — real centralisation inside the service. It should run on
the most protected machine the operator has, ideally offline between republishes
with the 3 h lifetime as the batching window.

#### Graceful shutdown `[BUILD NOW]`

Vanishing is the worst exit: a service that disappears is indistinguishable from
one being censored, and clients respond by retrying hard against intro points —
generating exactly the load pattern §9.10 exists to prevent. Follow the discipline
in `internal/p2p/drain.go` and `internal/store/drain.go`.

```text
T+0     stop publishing; leave the current descriptor to expire naturally
T+0     SESSION_CLOSE{GOING_AWAY, retry_after} on every session — `retry_after`
        is what stops the retry storm
T+0     INTRO_TEARDOWN{reason} to every intro point, so the IP frees state and
        answers new INTRODUCE1 with UNKNOWN_AUTH_KEY rather than timing out
T+0..30 drain window: existing streams finish; no new streams
T+30    close rendezvous circuits; DESTROY every tunnel in the service pool;
        zeroise K_desc, per-intro enc_keys, every session key
        (the descriptor stays in the DHT until T+10800; accept it — a stale
         descriptor yields a clean UNKNOWN_AUTH_KEY, not a hang)
```

#### Key compromise recovery

| Key | Blast radius | Recovery |
|---|---|---|
| `K_desc` | until `cert_expiry` | mint a new one under `K_blind`, republish with `revision++`. Cheap. |
| per-intro `enc_key`, `auth_key` | that intro point | drop it, promote the spare, republish. Cheap. |
| `session_root`, one session | that session | `SESSION_CLOSE`; the case-B ratchet recovers future sessions. |
| `auth_secret` | discoverability, permanently | rotate, redistribute out of band. No in-band channel exists. `[NEEDS RESEARCH]` |
| **`K_svc`** | **total** — the holder can publish descriptors and impersonate the service to every client | Clients that resolve **by name** recover: DomainIdentity signs a new ServiceIdentity delegation (cross-reference §11) and a DomainIdentity-signed revocation is published under the *old* `K_blind` for the remaining overlap. Clients holding the **raw ServiceIdentity** do not: they trust `K_svc` and nothing above it, so no key exists that they would accept a revocation from. `[UNSOLVED]` |

**A self-certifying address cannot be revoked to a party who trusts only the
address.** That is not a gap in the design — it is what self-certifying means. The
only mitigation is to make name-based addressing the documented default and
discourage raw-ServiceIdentity addressing.

---

### 9.10 Denial of service against a service

Treat this as the primary failure mode, because in the deployed prior art it is.

| Surface | Attack | Defence | Residual |
|---|---|---|---|
| **Intro point** | `INTRODUCE1` flood | Puzzle/token (§9.6); the IP verifies *before* forwarding, so bad proofs never reach the service | At the effort ceiling, slow clients queue behind the attack `[UNSOLVED]` |
| **Intro point** | replayed `INTRODUCE1` | IP replay cache on `(auth_key_id, X)`, window = descriptor lifetime, ~48 B/entry | Cache size is attacker-driven; bound it and evict oldest, accepting a replay window under flood |
| **Intro point** | volumetric DDoS on the IP relay itself | 3 active + 1 warm spare (§9.2): the spare promotes with no build; republish moves the service off the dead IP | 3 h descriptor lifetime bounds propagation. Emergency republish at 5 min costs 16 DHT writes each `[NEEDS RESEARCH]` |
| **Intro point** | every listed intro point knocked out at once | widen to 20 under §8 diversity constraints so no two share a /24 or an ASN | An adversary with enough bandwidth wins for the duration. **`[UNSOLVED]`** |
| **Intro point** | hostile IP silently drops introductions | **Canary introductions**: the service introduces to *itself* through each of its own intro points over a fresh client circuit and drops any that fails twice | A selective IP cannot distinguish canaries — `INTRODUCE1` is fixed-length and encrypted — so it must drop all or none. This defence is strong. |
| **Rendezvous point** | establish many, never complete | unmatched `rend_cookie` expires in 30 s; one rendezvous per circuit; `ESTABLISH_RENDEZVOUS` also takes a token/puzzle when the RP is loaded | An attacker with many circuits still holds RP state 30 s each |
| **Rendezvous point** | hostile RP injects or drops | session AEAD rejects injection (§9.8); dropping triggers case-B resumption to a *different* RP | The RP is by construction a perfect timing correlator for that one flow. It does not learn either party's identity. Accepted, not defended. |
| **Service tunnels** | flood data on an established session | per-session token bucket; the service is an endpoint and closes for the cost of one cell | Attacker cost equals defender cost — the least asymmetric and least dangerous surface |
| **Service tunnels** | force repeated case-B resumption to burn builds | `(auth_key_id, X)` replay cache; `counter` monotonicity | A *fresh* introduction per attempt still costs one build, which is what the puzzle prices |
| **DHT / HSDir** | flood writes under the blinded key | HSDir verifies the `K_blind` signature before storing and keeps only the highest `revision` | Verify cost becomes the flood target; per-key write rate limit |
| **DHT / HSDir** | flood *reads* to burn HSDir bandwidth | per-key read rate limit; 8 KiB records; `r=8` × 2 replicas spreads it | Cheap for the attacker. Bounded by record size, not eliminated. |
| **Whole service** | Sybil the HSDir positions for this period | `KadID = H(NodeIdentity ‖ SRV_epoch ‖ prefix)` is not freely chosen (§3) and rotates each epoch | RANDAO's last-revealer bias (R13) gives a few bits of grind on `SRV`. Few bits cannot target a specific `K_blind`, but it is not zero. |

#### The asymmetry table, which is the actual point

| Message | Attacker cost | Defender cost, undefended | Defender cost, defended |
|---|---|---|---|
| `INTRODUCE1` | ~600 B sent | 1 circuit build (3 handshakes) + 10 min state | 1 puzzle verify (µs), or 1 HMAC + a set lookup |
| `ESTABLISH_RENDEZVOUS` | 1 circuit | 30 s × 20 B of RP state | same, plus a puzzle when loaded |
| descriptor fetch | 1 lookup | 8 KiB from 1 HSDir | same, rate-limited per key |
| session data | 1 cell | 1 cell forwarded ×7 | 1 cell, token-bucketed |

The defence works by moving the first row from "three handshakes" to
"microseconds". Every other row was already roughly symmetric. The introduction was
the one place where a few hundred bytes bought a few hundred milliseconds of
someone else's CPU, and that row is what R10 exists to fix.

---

### Decision table

| Decision | Problem it solves | Derived from | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Tunnel = pool-managed circuit with a role; circuit = mechanism | Tor scatters lifetime rules across circuit *types*; I2P's tunnels double the path | I2P (pool, role) + Tor (bidirectional circuit) | Bidirectional circuits under an I2P-style pool, so one tunnel serves both directions | I2P's separate in/out paths (doubles exposure and RTT); Tor's per-purpose circuit types (no shared lifetime discipline) | One circuit failure now costs both directions at once, where I2P would lose one |
| Guard-constrained pools (R1) | Churn makes a hostile first hop near-certain; pinning makes failover hard | Tor (guards) + I2P (pools) | Pool churns hops 2..n on the 10-min schedule; hop 1 pinned 45 days | I2P's full churn (P → 1); Tor's single guard (no failover) | A hostile guard sees 100 % of a destination's traffic for up to 45 days, not a sliver of it |
| One pool per destination, not per node | A shared pool is a join key linking co-hosted services and the operator's own client traffic | Neither — Tor and I2P both pool per client instance | Isolation context is the destination | Per-node pooling (leaks co-hosting); per-stream pooling (unaffordable) | Build load linear in destination count; a relay chosen as guard for two of a node's destinations sees the same IP and infers co-hosting `[NEEDS RESEARCH]` |
| Inbound pool ≡ intro-point set (3 active + 1 warm spare) | Intro-point replacement otherwise needs a build at the worst moment | Tor (intro points) + I2P (`backupQuantity`) | The 3+1 inbound pool *is* the intro set; the spare is a pre-built intro circuit | A separate intro pool (double-counts the same tunnels); lazy spare (build latency mid-attack) | Widening to 20 under attack triples the service's build load exactly when it is already loaded |
| Never re-guard on transient failure (12 h rule) | An adversary who can DoS a guard can force re-guarding until chosen | Tor | Made the timer explicit, long, and gated on independently confirmed reachability | Fast re-guard (defeats pinning); never re-guard (permanent outage) | A node with two genuinely dead guards is offline for that context up to 12 h |
| Two-layer descriptor encryption | "Knows the name" and "is authorized" are different facts | Tor v3 | ChaCha20-Poly1305 with header-as-AAD replaces the stream cipher + separate SHA3 MAC | Single layer (cannot be both public and restricted); per-client descriptors (N× DHT load, leaks N) | AAD must cover exactly the right bytes; a canonicalization bug here is a decryption oracle |
| Intro + rendezvous, both stages (R10) | A published lease set is a DoS target and lets a client enumerate service tunnels | Tor, against I2P | Kept both stages; priced the intro | I2P's direct lease-set contact (endpoint is a target, tunnels enumerable) | One extra round trip, and the IP is a new party that learns the service has *an* intro circuit |
| Intro access priced by token-or-puzzle | 600 B costing three handshakes is the observed onion-service killer | Tor's deployed onion PoW + Privacy-Pass tokens | Two accepted proofs; effort is a **queue position, never a gate**; measured solve time disclosed | Hashcash (GPU asymmetry excludes phones); Argon2id (verify = solve); CAPTCHA (needs a human, breaks the infrastructure-only boundary) | At the ceiling the puzzle *is* a slow-client exclusion mechanism `[UNSOLVED]` |
| Restricted discovery via `auth_secret` in the blinding factor | Level-1 auth still confirms existence to anyone with the name | Extension of Tor's blinding | Fold a shared secret into the blinding factor so the DHT location itself is secret | Per-client publication (N× load, leaks N); accepting existence disclosure | `auth_secret` has `K_svc`'s blast radius, no in-band revocation, one leaker deanonymises the set |
| Session above the circuit, surviving carrier death (R9) | Tunnel rotation kills a circuit every 10 min by design | I2P (destination-oriented) + Tor (rendezvous) | Independent session AEAD and sequence space; commit/preimage resume at the RP | Rebuilding the rendezvous each rotation (12L + an introduction + a puzzle, every 10 min) | The RP holds 60 s of grace state per session, and a long session is a long correlation handle |
| Front-end publisher for multi-instance | Two publishers under one `K_blind` fight over `revision` | Neither, in-protocol | Instances hold only per-intro keys; one publisher holds `K_svc` and merges | Per-instance descriptors (impossible under one blinded key); round-robin publication (visible flapping) | Single point of compromise for `K_svc`; 3 h single point of failure for publication |
| Canary self-introductions | A hostile intro point can drop introductions invisibly | Neither | The service introduces to itself through each of its own intro points | Client-side reporting (unauthenticated, itself a DoS vector) | Each canary costs a full rendezvous; a service that canaries aggressively DoSes itself |

**Status beyond the per-heading markers.** `[NEEDS RESEARCH]`: Equihash-family
`(n,k)`; the policy constants (`q_target`, effort ceiling, 5 s reference, 12 h
guard timer); restricted discovery × multi-instance; emergency republish cadence;
guard co-selection across one node's own destinations. `[UNSOLVED]`: sustained DoS
by an adversary with more CPU than the honest client population; simultaneous
volumetric takedown of every listed intro point; revoking a compromised `K_svc` to
a client that addresses by raw ServiceIdentity. Everything else in this section is
`[BUILD NOW]`.

---

### What this section does NOT establish

- **No number here is measured.** The build arithmetic derives from the
  Constitution's parameters and stated assumptions (`f`, `s`, `g`, `L`); the
  latency budget is a hop count times an assumed link latency. No AXON code exists.
  Every figure in §9.3 and §9.5 is a budget to be checked against an
  implementation, and `f`, `s`, `g` are guesses about deployment, not observations.
- **The puzzle is specified as an interface, not as a scheme, and the
  queue-not-gate rule bounds its harm without removing it.** The memory-hard,
  asymmetric-verification family is chosen and argued; the parameters are deferred,
  and choosing them badly makes the puzzle useless or a censorship mechanism.
  Against an adversary with more aggregate CPU than the honest client population,
  slow clients are queued behind the attack, and the only answer needs a token
  issuer that does not exist. This is the largest open item in the section.
- **Intro-point availability under volumetric attack is unsolved.** Diversity and
  a warm spare raise the cost; they do not defeat an adversary with more bandwidth
  than the intro points have. The 3 h descriptor lifetime is a floor on how fast a
  service can route around a takedown.
- **The rendezvous point is an accepted correlation point.** It sees both
  circuits' cell timings by construction. It learns neither party's identity, but
  the design does not pretend the correlation is absent, and §7 already declines to
  defend `INTERACTIVE` traffic against end-to-end correlation.
- **Path selection, cell format and the circuit handshake are §8's.** This
  section assumes a selector honouring guard pinning and /24-and-ASN diversity, and
  a handshake completing in one telescoped round trip per hop. Neither exists yet,
  and §9.3's arithmetic assumes the second.

> **Objection to Constitution §5 (tunnel pool):** "3 inbound + 3 outbound + 1 spare
> each, per destination" does not say whether a service's introduction circuits are
> drawn from the inbound pool or held in addition to it. This section reads it as
> *drawn from* — the 3 active inbound slots are the 3 intro circuits, the spare a
> warm fourth — because that makes the parameter self-consistent and matches the
> `inbound.quantity=3 inbound.backupQuantity=1` configuration the deployed node
> already runs (`internal/i2p/sam.go:85`). Under the other reading a service node's
> tunnel count rises from 16 to 22 and its build rate from 96 to 132 per hour, and
> the "widen the inbound pool under attack" mechanism in §9.2 and §9.10 must be
> restated as a separate intro-circuit allocator.
