## 16. Traffic Analysis Resistance

**The finding that shapes this section: every defence AXON can ship in v1 protects
against an observer of *one link*, and none of them protects against an observer
of *both ends*.** That is not a gap we intend to close. No deployed low-latency
anonymity system closes it, and a roadmap that implies otherwise is lying. The
work therefore splits cleanly into an MVP set that is cheap, well-understood, and
buys real protection against the single-vantage adversary of §4, and a research
set that is expensive, contested in the literature, and only ever bought for the
`BULK` class (R2).

The second finding, which follows from the first: **the traffic class is a
user-visible API decision, not an internal optimisation.** `INTERACTIVE` is fast
and correlatable. `BULK` is slow and defended. The L8 API (§20) forces the caller
to name one. A system that silently picks for the caller will pick `INTERACTIVE`
every time, and then the anonymity claim in the marketing does not match the
anonymity in the wire.

### What already exists

Nothing in this problem domain is implemented. The existing node outsources all
of it to I2P: `internal/i2p/sam.go` opens a SAM session with the literal options

```text
inbound.length=3 outbound.length=3 inbound.quantity=3 outbound.quantity=3
inbound.backupQuantity=1 outbound.backupQuantity=1 i2cp.leaseSetEncType=6,4
```

so today's tunnel length, pool size and spare count are *requests to somebody
else's router*, and every padding, batching and cell-size decision below the SAM
socket belongs to the I2P router process. The Go module contains no cell type, no
padding scheduler, no traffic-class enum, and no link-level flow accounting.
`internal/p2p/node.go` builds the libp2p host with `libp2p.NoTransports` plus the
I2P transport only, and `i2pAddressesOnly` strips clearnet addresses from the
peerstore — which is the one existing behaviour in the right spirit: it prevents
an accidental clearnet leak of an address that is supposed to be hidden.

**What must be replaced:** all of it. The SAM session is the dependency this
project exists to remove. Its parameters are useful as evidence that the
Constitution's §5 pool figures (3 in + 3 out + 1 spare, 3 hops) are the numbers a
production I2P deployment actually chose, not invented ones.

### 16.1 The threat, stated per observation point

Five observable quantities, in increasing order of how hard they are to suppress,
and what the MVP set (§16.3) does to each:

```text
1  per-message length      REMOVED by fixed cells
2  packet timing           blurred at the link only; unchanged at a relay
3  flow volume             NOT ADDRESSED
4  flow duration           NOT ADDRESSED
5  start / stop instants   blurred by the padding tail, not removed
```

| Vantage | Sees | Does not see | Strongest inference available |
|---|---|---|---|
| **Client access link** (ISP, home router, campus NAT, hostile Wi-Fi) | That this IP speaks AXON at all; every byte to/from the 2 guards; exact timing and volume | Circuit count, destination, service identity, content | *You are an AXON user*, plus a full activity trace. This is the vantage most users actually face and the one the MVP set is aimed at. |
| **Guard** | Client IP, per-circuit cell counts and timing, circuit build/teardown events, isolation-context count | Anything past hop 2; destination; whether the client is origin or is relaying (unless co-residency rules in §17.4 are broken) | Client fingerprint over time; correlation input if the other end is also observed |
| **Middle hop** | Two relay IPs, per-circuit cell counts, timing | Client, destination, position confirmation (it cannot prove it is the middle) | Little alone. Valuable only in aggregate or as one end of a two-hop compromise |
| **Terminal hop / RP** | Cell counts and timing on both legs it joins; the *shape* of the session | Client IP, service IP, service identity (RP sees only the rendezvous cookie) | Correlation input; RP is the cheapest place to sit for the service-side half |
| **Service link** | That this IP speaks AXON; volume and timing of everything the service does | Which service, which clients | *This host runs something*. Combined with a known service's request pattern, a confirmation oracle |
| **AS / IXP level** | Any subset of the above simultaneously, and crucially both a client link and a service link if they traverse the same AS | Contents | End-to-end correlation. This is the adversary §4 declines to defend `INTERACTIVE` against |
| **Storage holder link** (§10) | Shard fetch pattern, sizes, timing | Which object, which requester (fetches arrive over circuits) | Object reconstruction from shard-request co-occurrence, if shard placement is predictable |

Two asymmetries worth stating because they change where the defences go:

- **A relay is not a link observer and a link observer is not a relay.** Link
  padding defends against the second and does nothing against the first, because
  a relay strips padding at the hop boundary and counts only real cells. Any
  claim that "we pad, therefore relays learn less" is false.
- **The client's link is the only vantage where the adversary is *guaranteed* to
  be present.** The ISP always sees it. Every other vantage requires the
  adversary to have won a placement lottery. Spend the MVP budget there.

### 16.2 What fixed-size cells actually buy

They remove exactly one thing: **per-message length leakage on a link**. A
1024-byte cell carrying a 12-byte DHT keepalive is indistinguishable on the wire
from a 1024-byte cell carrying 944 bytes of a file. That is worth having and it
is not much.

They do not remove:

| Leak | Why cells do not help |
|---|---|
| Flow volume | 10 MB is 10,873 cells; the count is the volume |
| Flow duration | Cells arrive over the same interval the data did |
| Burst structure | A request/response pattern is still a request/response pattern in cell counts |
| Start/stop | The first and last cell are still first and last |
| Direction ratio | Download-heavy still looks download-heavy |

The Constitution's layout (§5) gives, with `H_max = 4` reserved unconditionally
so that hop count does not leak from payload capacity:

```text
cell                    1024 B
  header                  16 B   (circuit id 8, cmd 1, flags 1, len 2, rsvd 4)
  AEAD tags               64 B   (16 B × 4 hop positions, always reserved)
  payload                944 B

QUIC datagram floor     1200 B   (§5 MTU assumption)
  one cell per STREAM frame, packet padded to the floor
  + IPv4/UDP header       28 B
  on-wire per cell      1228 B

payload efficiency      944 / 1228 = 76.9 %
link overhead vs payload            +30.1 %
```

**Derived, not measured.** The 30.1 % is arithmetic from the §5 parameters and
the decision to pad every overlay-carrying QUIC packet to a constant datagram
size. Padding to the floor is what makes the *datagram* length distribution
degenerate; without it, cell boundaries would be visible in packet sizes and the
fixed cell would have bought nothing at the IP layer. If `H_max` is fixed at 3
instead of 4 the figure improves to +27.9 %, at the cost of leaking that this
network never builds 4-hop paths.

### 16.3 The MVP set [BUILD NOW]

> **AS BUILT (2026-08-16) — P13.** `internal/axon/padding`, 17 tests, plus M5 in
> `internal/axon/tunnel` and `roadmap/check-claims.py` for S13.
>
> **§16.3 CONTRADICTS ITSELF ABOUT M6b AND THE CODE RULES ON IT.** The table
> above says the floor "continue[s] at the floor for U(5 s, 30 s)" after the last
> real cell, which reads as an on/off switch driven by activity. The prose three
> paragraphs down says the mechanism makes the link "carry a constant floor of
> traffic **whether or not the user is doing anything**", and lists "hides
> daemon-running-but-idle from daemon-running-and-trickling" as the property
> bought. Those are different mechanisms, and the switch reading **does not
> deliver that property** — E13.2 measured an idle link at 0.18 cells/s (M6a's
> rate) against a trickling one at 0.50 and separated them by counting.
> **§16.3's own cost figure settles it**: 6.4 GB/month at R_floor = 0.5 is
> 0.5 × 1228 B × 2 directions × 2 guards × 30 days, arithmetic for a floor that
> never stops. **Ruling: the floor runs for the life of a client↔guard link, and
> the U(5 s, 30 s) draw rolls the deficit epoch** — its job is to randomise the
> phase at which post-activity padding resumes, so the instant activity stopped
> is not marked by a deterministic offset. Both readings are then satisfied.
>
> **A second, separate defect, in the mechanism as first built.** Scheduling the
> floor as a *minimum gap since the last cell* is not the same as *a rate*: real
> traffic at 0.4 cells/s against a 0.5 floor produced **0.8 cells/s total**,
> because each real cell reset the gap and padding fired in between. The total
> rate was therefore a function of the real rate — the exact leak the floor
> removes. It is now deficit accounting over an epoch, and E13.2 measures 0.4733
> idle against 0.4983 lightly-loaded, inside a stated bound of 25 % of the floor.
>
> **M5's jitter was missing and the phase lock was live.** `pool.go` triggered
> rebuild at a fixed 70 % of lifetime, and a test *asserted* that fixed value —
> so every client emitted CREATE cells on a phase-locked 420 s cadence, and the
> phase offset was a stable per-client identifier at the guard. Jitter is drawn
> **once per tunnel, downward only** (jittering upward would eat the 180 s the
> schedule reserves for rebuild failures).
>
> **Done:** M6a, M6b, M5, M2's framing, and audits for T13.2, T13.3 and E13.4.
> **T13.4 is discharged as a negative**: the padding schedule is byte- and
> timing-identical under both traffic classes, enforced by an audit that forbids
> this package from referencing a class at all — a class-dependent padding rate
> would let a link observer read the class off an idle link. **S13 (T13.5,
> E13.3)** is `roadmap/check-claims.py`; it found and fixed **two unscoped
> anonymity claims in shipped website copy**.
>
> **Deliberately NOT claimed:** **M2 is not in force on the deployed transport.**
> Cells run over libp2p streams over QUIC, where quic-go owns packetisation, so a
> capture still shows quic-go's length distribution. The framing is built and
> tested and takes effect only in QUIC datagram mode, which is P11's transport
> work and has not happened. **T13.1 and E13.1 are NOT discharged** — two
> independently built binaries emitting byte-identical QUIC Initials needs the
> same reproducible-build harness **T2.6** has been blocked on since P2, and
> neither exists. **E13.2's bound is a rate threshold**, the weakest useful
> classifier; a burst-structure classifier is a different question that §16.4
> defers with a named criterion. **No overhead figure here is measured** — §16's
> own closing note already says so and P13 did not change it.

Six mechanisms. All are well-understood engineering; none requires research.

| # | Mechanism | Parameter | Applies to | Derived bandwidth cost |
|---|---|---|---|---|
| M1 | Fixed cells | 1024 B, 944 B payload | every link | +8.6 % over payload at the cell layer |
| M2 | Fixed datagrams | pad every overlay QUIC packet to 1200 B | every link | +30.1 % over payload including IPv4/UDP |
| M3 | Stream multiplexing | many application streams per circuit; stream id in the cell payload (§8 owns the layout) | client ↔ terminal | reduces circuit count; saves ~12 KiB of handshake per avoided circuit |
| M4 | Per-destination circuit isolation | isolation key `H(dest ‖ credential ‖ port-class)`; a separate circuit set per key; **never** reuse a circuit across keys | client | +1 circuit build per new key ≈ 12 KiB of link traffic |
| M5 | Circuit rotation | lifetime 600 s, rebuild at 70 % **± U(0, 15 %)** jitter | client | 8 tunnels × 12 KiB / 600 s ≈ 160 B/s |
| M6a | Link keepalive padding | on an idle link, send 1 PADDING cell after `U(1.5 s, 9.5 s)`; reset on any real cell | relay↔relay, client↔guard | 1228 B / 5.5 s ≈ 223 B/s ≈ 1.8 kbit/s per link per direction |
| M6b | Connection floor padding | maintain ≥ `R_floor` cells/s per direction; real cells count toward the floor; after the last real cell continue at the floor for `U(5 s, 30 s)` | **client↔guard only** | at `R_floor = 0.5`: 6.4 GB/month across 2 guards, both directions |

Circuit-build cost, derived: a 3-hop build is one CREATE/CREATED pair plus two
EXTEND/EXTENDED pairs, six cells, each traversing 1–3 links, ≈ 12 cell
transmissions ≈ 12 KiB of link traffic. §8 owns the exact handshake.

Floor padding cost at three settings, per client, across 2 guard links in both
directions:

| `R_floor` (cells/s/direction) | per link/direction | per client total |
|---|---|---|
| 0.25 | 307 B/s | 3.2 GB/month |
| **0.5 (default)** | 614 B/s | **6.4 GB/month** |
| 1.0 | 1228 B/s | 12.7 GB/month |

**What M6b does and does not do, exactly.** It makes the link between a client
and its guard carry a constant floor of traffic whether or not the user is doing
anything, and it extends that floor past the end of real activity by a random
tail. So it hides:

- daemon-running-but-idle from daemon-running-and-trickling;
- the precise instant a flow started and the precise instant it stopped;
- flows whose entire rate is below `R_floor` (512 B/s at the default).

It does **not** hide:

- any activity above `R_floor` — a 2 Mbit/s download is 2 Mbit/s of visible
  cells with a 4 kbit/s floor underneath it;
- the fact that the host speaks AXON at all (that is §6's problem — pluggable
  transports and traffic obfuscation are a censorship-resistance concern, not an
  anonymity one, and the two must not be conflated);
- anything from the guard's point of view. The guard counts real cells.

**Jitter on M5 is not decoration.** Rotation at exactly 70 % of a 600 s lifetime
means every client in the network emits a burst of CREATE cells on a
phase-locked 420 s cadence. The phase offset is then a per-client identifier
visible to any link observer and stable across the client's whole session. The
`± U(0, 15 %)` jitter removes the phase lock; without it, M5 *adds* a
fingerprint while claiming to reduce one.

**M4's honest cost is not bandwidth, it is fingerprint richness at the guard.** A
client with 30 isolation contexts holds 30 circuit sets, all beginning at the
same 2 guards (R1), and 30 concurrent circuits from one IP is itself a profile.
M4 trades cross-destination linkability — easy for any destination to exploit —
for a richer client profile visible only to a hostile guard. We take that trade
and say so.

### 16.4 The deferred set [NEEDS RESEARCH]

Six mechanisms deliberately not in v1. For each: the problem, the overhead, the
position of the published literature *described rather than cited*, and the
criterion under which AXON would adopt it.

| Mechanism | Problem it solves | Overhead | Where the literature stands (described) | Adoption criterion |
|---|---|---|---|---|
| **Adaptive padding / defended shaping** | Burst structure at the link — the input to website fingerprinting | Reported in the single-digit to ~50 % bandwidth range for the low-overhead designs | The adaptive-padding family (Shmatikov–Wang style adaptive padding, and the WTF-PAD lineage adopted into Tor's circuit-padding framework) fills inter-burst gaps to destroy the burst signature. Later deep-learning attacks substantially degraded the reported protection, and the padding *machine parameters* became a fingerprint of their own. | Adopt only when we can run our own attack on our own testbed traffic and show a drop in attacker accuracy that survives retraining on padded traffic. A paper number is not a criterion. |
| **End-to-end cover traffic (loops)** | Idle-vs-active above the floor; whether an endpoint is a source or a forwarder | Proportional to the rate you want to hide — to hide 1 Mbit/s of real traffic you send 1 Mbit/s of cover | Loop cover traffic (client→self through the network) is the mechanism that makes continuous-time mix designs analysable; it is why such designs can state a quantitative unlinkability bound at all. It is also why they are unusable at interactive rates. | `BULK` only, and only once §14's accounting can charge for cover traffic — otherwise cover is a free DoS on volunteer relays. |
| **Batching / mixing for `BULK`** | End-to-end correlation, genuinely — the only thing on this list that attacks it | Latency, not bandwidth: seconds to minutes per hop | Continuous-time (Poisson / exponential-delay) mixing at each hop, with loop cover, is the construction with an actual argument behind it. Threshold-and-pool batching is the older form. Both trade latency for an anonymity set that grows with the batch. | A measured `BULK` latency budget from §10's repair and audit loops. If the storage layer cannot tolerate a 30 s per-hop delay, mixing is not adoptable and we should say so rather than ship a token version. |
| **Dummy circuits** | Circuit *count* and build-pattern leakage at the guard | ~12 KiB per dummy build, plus its floor padding | Rarely deployed. Tor builds pre-emptive circuits for latency, which incidentally muddies the count; that is not the same as a designed defence. | Only after M4's fragmentation cost is measured. Dummy circuits are the natural answer to it, and the natural answer may cost more than the leak. |
| **Traffic splitting across disjoint paths** | Single-vantage correlation: no one entry path sees the whole flow | Path multiplication; congestion control across paths with different RTTs is the hard part | The published approach (splitting one logical circuit's cells across several entry paths at the client) reports meaningful reductions in website-fingerprinting accuracy. It does **not** defeat an adversary who observes the client's access link, because all paths leave through that one link. | Adopt only for the *service* side, where multiple inbound tunnels already exist (§9), and only after §8's flow control can reassemble across paths without a head-of-line stall. |
| **Website-fingerprinting defences** (as a class) | Which resource was fetched, given only encrypted, fixed-size traffic | The constant-rate family (BuFLO / Tamaraw lineage) reports overheads on the order of 100 % bandwidth and comparable latency inflation. The lightweight family is cheaper and weaker. | Closed-world results are consistently high. Open-world results are contested on base rates, dataset drift and the realism of the training set. The honest summary is that the attack works well when the attacker knows the candidate set and degrades sharply when it does not. | This is an *application-layer* threat and AXON is infrastructure. We provide the primitive (constant-rate shaping on a session) and refuse to claim a WF defence. Adopting a specific defence requires an application threat model we are explicitly not writing (§8 of the Constitution). |

None of the above is scheduled for v1. Each is a `[NEEDS RESEARCH]` item with a
named criterion, and the criteria are deliberately measurement-shaped so that
"we read a paper" cannot satisfy them.

### 16.5 End-to-end correlation [UNSOLVED]

Stated plainly, because it is the single most misrepresented property in this
class of system:

> **If the adversary observes the client's link and the service's link, the
> adversary wins.** Correlating the two observations is a statistics problem, not
> a cryptography problem, and the statistics are easy. Published flow-correlation
> work — including deep-learning correlators trained on packet-count and
> inter-arrival features — reports high true-positive rates at low false-positive
> rates using tens of seconds of a flow. The direction of that result is not in
> dispute and it is not sensitive to the details of the encryption. Fixed cells
> do not prevent it. Link padding does not prevent it. Nothing in §16.3 prevents
> it.

What changes the result is delay and cover — the mixing mechanisms in §16.4 —
and those are incompatible with an interactive latency budget. Hence R2 and hence
the API split, in which `TrafficClass` is a **required argument with no default**:

```text
axon.Open(dest, TrafficClass) error

  INTERACTIVE   3 hops each side, no batching, best-effort padding.
                Correlation-vulnerable BY CONSTRUCTION. Latency ~6 hop RTTs.
                Every anonymity claim is against a SINGLE-vantage adversary.

  BULK          batching, cover, higher hop delay. Used by the storage
                layer (§10). Latency budget in seconds, not milliseconds.
                Claims are stronger and still not absolute.
```

A caller that does not choose gets an error, because the alternative is that
every caller gets `INTERACTIVE` and the network ships with a documented property
nobody uses.

**The guard arithmetic, since it is the part users can actually reason about.**
With 2 primary guards per isolation context and 45-day rotation (§5), and a
hostile fraction `f` of guard-eligible weight:

| `f` | P(≥1 hostile guard) per 45-day period | over 1 year (8 periods) |
|---|---|---|
| 1 % | 1.99 % | 14.9 % |
| 5 % | 9.75 % | 56.0 % |
| 10 % | 19.0 % | 81.5 % |

Derived as `1 − (1−f)²` per period, compounded over 8 periods. A hostile guard is
not deanonymisation — the adversary still needs the other end — but it is one
half of the pair, held for 45 days, and for a service it is the half that has the
IP address attached. What the guard mechanism is actually doing is converting a
per-circuit `f²` risk into an all-or-nothing `f` risk that persists for the guard
lifetime: the correct trade for a long-lived user, and a *worse* trade for one
who connects once and never returns.

### 16.6 Intersection and long-term observation

**A persistent service is inherently more exposed than an intermittent one, and
no protocol change fixes this.** The reason is structural: every attack whose
success probability grows with observation time succeeds against a target that
can be observed indefinitely.

```text
                observation window
                ├──────────────────────────────────────────────► t

candidate set   ████████████████████████████████████████  all hosts
                     ↓ service answers at t1
                     ███████████████████████████████      hosts up at t1
                          ↓ service answers at t2
                          ██████████████████████          ∩ hosts up at t2
                               ↓ ... t3, t4, ... tn
                                    ███                   ∩ ... → 1
```

Three distinct attacks, often conflated:

| Attack | Mechanism | Why persistence makes it worse |
|---|---|---|
| **Intersection** | Repeatedly intersect "hosts reachable now" with "service reachable now" | An always-up service never leaves the set, so the intersection is driven entirely by *other* hosts' churn — and every host that goes down once is eliminated. The set shrinks monotonically and never recovers. |
| **Statistical disclosure** | Same, but probabilistic, over aggregate volume rather than binary up/down | Works even when the service is not perfectly up. More observation time is strictly more evidence. |
| **Guard rotation exposure** | 16.5's table | An always-online service accumulates guard selections at the full 45-day rate for its entire life. A service that exists for a week draws two guards, once. |

Consequences AXON accepts and states:

1. **An always-online service on a stable IP with a stable guard set is findable
   given enough time and vantage points.** We do not claim otherwise. The
   mitigation is not a protocol feature; it is running the service where its
   uptime is uncorrelated with anything else about the operator.
2. **Descriptor publication is the clock the attacker uses.** Republishing hourly
   on the hour (§5) hands the attacker a synchronised sampling schedule.
   Publication must be jittered within the period and lifetime must not be
   inferable from publication timing — a concrete §9 requirement arising here.
3. **Service-side guard sets are the highest-value long-lived secret in the
   system.** Layered guards at the intro and rendezvous positions (extra pinned
   hops at positions 2 and 3 with staggered lifetimes, so no single rotation
   exposes a whole path) are the known mitigation. `[NEEDS RESEARCH]` only
   because the schedule must be chosen against our own churn data. §9 owns it.
4. **[UNSOLVED]** There is no defence against intersection for a service that must
   be continuously available. The trade is availability against exposure and it is
   the operator's to make; §17.6 gives the shapes, not the choice.

### 16.7 Node fingerprinting

Distinct from traffic analysis and frequently forgotten: an adversary who cannot
correlate flows may still be able to say *that host is the same host* across
addresses, or *that host is running our software*, or *that relay and that
service are the same machine*.

| Surface | What it leaks | Mitigation | Status |
|---|---|---|---|
| **QUIC Initial fingerprint** | Version list, transport-parameter set and ordering, connection-ID lengths, GREASE presence, token behaviour — all of which vary by library and by build | One canonical wire profile for the whole network. Transport parameters fixed by spec, not by config. No knob may change a byte that is visible before the handshake completes. | `[BUILD NOW]` |
| **TLS 1.3 fingerprint** | Cipher-suite order, extension order, ALPN string, key-share group, certificate-compression support | Raw public keys only (§5 layer stack, L1), single fixed ALPN, single named group per version. The ALPN string identifies the network to any observer — a censorship problem (§6), not an anonymity one. | `[BUILD NOW]` |
| **Congestion control** | BBR vs CUBIC pacing is visible in the send pattern and differs by build and tuning | Specify one CC algorithm and one pacing configuration normatively. Divergence is a fingerprint even when it is a performance win. | `[BUILD NOW]` |
| **Version strings** | A descriptor field like `axond/0.4.2-rc1+git` partitions the network into small, trackable cohorts | Descriptors carry a single integer protocol version, never a build string. Build identity goes in local logs. | `[BUILD NOW]` |
| **Padding-machine parameters** | If `R_floor`, jitter bounds or a padding state machine are operator-configurable and observable, the configuration is an identifier | Padding parameters are protocol constants. An operator may disable padding entirely (one bit, and it is visible that they did) but may not tune it. | `[BUILD NOW]` |
| **Clock skew** | Timestamps in the handshake, QUIC ACK delay, and TCP timestamps expose a per-machine crystal offset that survives IP change and NAT | Coarse timestamp granularity, and no application-layer timestamp with better than second resolution on the wire. Skew via ACK-delay statistics is **not** fully mitigable at the protocol layer. | `[NEEDS RESEARCH]` |
| **Uptime pattern** | The set of epochs in which a descriptor was published is a fingerprint that identifies a node across key rotations — which defeats the point of RoutingIdentity rotation (§3 taxonomy) | Rotation must be accompanied by a plausible gap, or the rotation is cosmetic. Honest statement: a relay that rotates its RoutingIdentity every epoch but is up continuously is trivially re-linked by uptime. | `[UNSOLVED]` |
| **Cell size itself** | 1024 B is not Tor's 514 B; the constant identifies the network | Accepted. Network identification is §6's problem. Do not attempt to imitate another network's cell size; a half-imitation is a worse fingerprint than an honest one. | accepted |

The last row is the general rule for this table: **an identifiable network is not
the same problem as an identifiable user, and solving the first badly makes the
second worse.**

### 16.8 Decisions

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Fixed 1024 B cell + fixed 1200 B datagram | Per-message length leakage at both the cell and IP layers | Tor's fixed cell | Larger cell sized to one QUIC datagram; datagram padded to a constant so the cell boundary is not visible in packet lengths | Variable-length records with per-record padding (leaks a length distribution); Tor's 514 B (two per datagram do not fit, §5) | +30.1 % link overhead; small messages pay 21× on a 44-byte payload |
| Two declared traffic classes, no default | Users silently getting the fast, correlatable path while believing the strong claim | R2; Tor has one class, I2P has none, mixnets have only the slow one | Made it an API-level required argument | A single adaptive class that "does its best" — unanalysable and unclaimed | Callers will pick `INTERACTIVE` and blame the network; the documentation burden is now permanent |
| Link padding is hop-by-hop only | Access-link observers (the guaranteed adversary) | Tor's connection-level padding, which exists to keep NetFlow records from being written | Fixed the parameters in the protocol rather than in a consensus document (R14: we have no consensus) | End-to-end padding in v1 (cost scales with the rate you want to hide) | Padding is a free DoS vector until §14 can charge for it; a relay must rate-limit padding it did not ask for |
| Floor padding on the client↔guard link only | Idle-vs-active at the access link | Neither Tor nor I2P does this by default | Bounded, constant, low; explicitly does not scale with activity | Constant-rate full-link padding at the client's peak rate (unusable on metered links) | 6.4 GB/month at default is a real cost and will be turned off; a network where only the careful pad has a smaller anonymity set for the careful |
| Rotation jitter `± U(0,15 %)` | Phase-locked rebuild bursts becoming a stable per-client identifier | I2P's 10-minute tunnel lifetime | Added jitter; I2P's fixed schedule has the same phase-lock issue | Fixed schedule (simpler, leaks phase); fully random lifetime (breaks the pool's spare-provisioning logic) | Jitter widens the window in which a tunnel is near expiry, slightly raising failure rate at rebuild |
| Per-destination circuit isolation | Cross-destination linkability by a hostile destination or terminal hop | Tor's stream isolation | Isolation key is explicit in the API rather than inferred from SOCKS credentials | One circuit set per client (cheap, links everything) | Concurrent circuit count at the guard becomes a client fingerprint (§16.3) |
| No cover traffic, no mixing, in v1 | — (this is a deferral, not a defence) | Mixnet literature | Deferred with named measurement criteria rather than "future work" | Shipping a token version of mixing to be able to claim it | The network ships with a known, stated, unmitigated correlation exposure for `INTERACTIVE` |
| One canonical wire profile, no tunable knobs on the wire | Node fingerprinting via configuration diversity | Tor's uniform client behaviour | Made it normative for QUIC transport parameters and CC, which Tor did not have to face | Operator-tunable performance parameters | Removes a legitimate operator tuning surface; a relay on an unusual network path cannot optimise |

### What this section does NOT establish

- **No overhead figure here is measured.** Every percentage and byte rate is
  arithmetic from the §5 parameters plus the datagram-padding decision. The real
  figures depend on the cell-payload framing §8 defines and on QUIC's own
  per-packet overhead, and both must be measured on a testbed before any of these
  numbers appears in operator-facing documentation.
- **It does not establish that the MVP set resists website fingerprinting**, and
  it makes no claim in that direction. Fixed cells and link padding are known to
  be insufficient against modern classifiers. AXON's position is that this is an
  application-layer threat outside the infrastructure scope.
- **It does not quantify the anonymity set for any mechanism.** There is no
  entropy calculation here, because an honest one requires a population model of
  the deployed network that does not exist yet. Quantified claims wait for
  measurement (§21).
- **It does not resolve whether floor padding is affordable.** 6.4 GB/month is a
  design decision made without any data on the target user's connection. If it is
  widely disabled, the mechanism is worse than useless because it partitions users
  into padded and unpadded populations.
- **It does not address censorship or blocking.** Making AXON traffic
  unrecognisable to a censor is a different problem with a different threat model
  and belongs to §6. Nothing in §16 helps a user in a country that blocks the
  protocol.
- **It does not defend `INTERACTIVE` against a global passive adversary, and no
  future version will.** This is a stated limit of the architecture, consistent
  with §4, not a gap awaiting engineering.

---

## 17. Node Roles, Gateways, and Deployment Topologies

**The finding that shapes this section: the existing `NodeRegistry` contract
cannot accept a single new capability bit without being redeployed.**
`NodeRegistry.sol` declares `uint256 public constant CAP_ALL = (1 << 7) - 1` and
both `_register` and `updateNode` execute `if (capabilities == 0 || (capabilities
& ~CAP_ALL) != 0) revert BadCapabilities();`. Every AXON role bit lives at `1<<7`
or above, so every one of them reverts against the deployed contract. The bitmap
field itself is `uint256` and has ample room; the *validator* is a compile-time
constant. This is a small change and a hard blocker, and it must be sequenced
into §23 before any relay advertises an AXON capability on-chain.

The second finding: **"RELAY" and "ROUTER" are the same thing and the roadmap
should stop using two names for it.** The distinction those two words were
reaching for is real, but it is not a role — it is *position within a circuit*,
which is chosen per-circuit by the client and never configured by an operator.

### What already exists

| Existing | Path | What it gives §17 |
|---|---|---|
| Capability bitmap, on-chain | `proof-of-facilitation/contracts/NodeRegistry.sol` | `CAP_DHT=1<<0`, `CAP_GATEWAY=1<<1`, `CAP_STORAGE=1<<2`, `CAP_LOADBALANCE=1<<3`, `CAP_DOCKER_WORKER=1<<4`, `CAP_DOCKER_CONTROLLER=1<<5`, `CAP_WITNESS=1<<6`, `CAP_ALL=(1<<7)-1`. Also `endpointCommitment = hash(endpoint ‖ nodeSecret ‖ epoch)` — **no raw endpoint on-chain**, which is exactly the property AXON needs. |
| Capability bitmap, client side | `internal/facilitation/facilitation.go:32-39` | Go mirror of the same bits, `uint64`, commented "MUST match NodeRegistry.sol". |
| Service index vs capability bit | `internal/facilitation/receipt.go` | `ServiceType` is the *index* (0..6); `CapabilityBit()` maps index → `1<<n`. The file already warns that confusing the two attributes work to the wrong service. AXON must preserve this distinction. |
| Runtime roles | `internal/config/config.go:24-56, 233-240, 694-700` | `Role` is resolved from the command line *before configuration is read*: `RoleStorage`, `RoleGatewayOnly`, `RoleProbeOnly`, `RoleManagement`, with `ValidateForRole` checking only the config that role consumes. This is the right shape and AXON keeps it. |
| Bootstrap | `internal/bootstrap/bootstrap.go`, `discover.go` | Signed bootstrap document, pinned-key verification, multi-source agreement fallback, truncation-resistant signed message, fingerprint-based disagreement detection. Detailed in §17.5. |
| Gateway | `internal/gateway/` (`registry.go`, `probe.go`, `protocol.go`, `validator.go`, `acme.go`, `contentproxy.go`, `snapshot.go`), `GATEWAY.md` | A *content* gateway: clearnet browsers → overlay-stored content over WebPKI HTTPS. Probe quorum, connect-back verification, CGNAT rejection (`PublicAddress` in `protocol.go:472` blocks `100.64.0.0/10`, TEST-NET ranges and Teredo). Detailed in §17.6. |
| Eligibility thresholds | `internal/config/config.go:592-596` | `MinimumUploadMbps: 10`, `MinimumFreeMemoryMB: 512`, `MinimumFreeDiskMB: 1024`, `MaximumCPUPercent: 90`, `RequirePublicAddress: true`, `RejectCGNAT: true`. Real numbers a real operator already runs; §17.7 anchors on them. |
| Store defaults | `internal/config/config.go:572-574` | `CapacityBytes: 20 GiB`, `DataShards: 6`, `ParityShards: 3`, `ChunkBytes: 1 MiB`. Note: **1 MiB, not the 256 KiB in Constitution §5** — flagged as an objection below. |
| Bond | `proof-of-facilitation/contracts/StakeVault.sol` | Bonds, delayed withdrawal, slashing by `DisputeManager`. **There is no minimum-bond constant in the contract** — the threshold is a policy value, and `ServicePolicyRegistry` is where versioned policy lives. Any bond amount in this document would be invented; it is not stated here. |

**What must be replaced:** the gateway's dependence on a central controller
(Name.com DNS sync, `https://syndichan.org/api/v1/gateways`), the bootstrap
document's single coordinator key, and every I2P-shaped assumption in role
resolution. The *shapes* — signed statements, probe quorum, role-before-config,
capability bitmap — all survive.

### 17.1 The roles, and the RELAY/ROUTER ruling

> **Ruling R-17.1.** RELAY and ROUTER name one thing. AXON says **RELAY**.
> "ROUTER" is retired as a role name and reserved for the local routing engine
> inside `axond` (a software component, never a network role). What the two names
> were reaching for is the difference between *being willing to forward cells*
> (a configured, advertised capability) and *the position a particular circuit
> puts you in* (guard / middle / terminal, chosen per-circuit by the client).
> Position is never configured, never advertised as a role, and never stable.

Eight configured roles, plus three dynamically assigned functions:

| Role | Definition | Advertised? | Requires inbound reachability? | Key it uses |
|---|---|---|---|---|
| **CLIENT** | Originates circuits; consumes the L8 API. Never forwards for others. | **No — clients are never in any registry** | No | RoutingIdentity for circuit building only; no NodeIdentity registration |
| **RELAY** | Forwards cells at L4 between links. The only forwarding role. | Yes (`CAP_RELAY`) | Yes — measured, not asserted | NodeIdentity (public, bonded) + epoch RoutingIdentity |
| **DHT NODE** | Serves DHT lookups and stores signed records; occupies a KadID. | Yes (`CAP_DHT`, exists) | Yes | NodeIdentity; KadID = `H(NodeIdentity ‖ SRV_epoch ‖ prefix)` |
| **STORAGE NODE** | Holds encrypted shards, answers recall, participates in repair and audit. | Yes (`CAP_STORAGE`, exists) | Yes | NodeIdentity + storage contract keys |
| **BOOTSTRAP NODE** | Serves a signed, chain-anchored peer sample to joining nodes. | Yes (`CAP_BOOTSTRAP`) — and published out-of-band | Yes, on a stable address | NodeIdentity; seed-set signer key is separate and offline |
| **GATEWAY (inbound)** | Clearnet → overlay. What `internal/gateway` already is. | Yes (`CAP_GATEWAY`, exists) | Yes, on 443, with a WebPKI name | NodeIdentity + a TLS certificate identifying a *public* operator |
| **EXIT (outbound gateway)** | Overlay → clearnet. Off by default, opt-in, policy-bounded. | Yes (`CAP_EXIT`) | Yes, plus permissive egress | NodeIdentity; **never** co-resident with a SERVICE |
| **SERVICE NODE** | Hosts an anonymous service reachable only via rendezvous. | **No — deliberately never advertised anywhere** | **No** | ServiceIdentity (blinded per time period), which never appears on the wire in the clear |

Dynamically assigned functions — a relay is *used as* these; it does not
configure them:

| Function | Assigned by | Duration | Eligibility |
|---|---|---|---|
| **guard** | the client, pinned | 45 days (§5) | client-computed from measured uptime/stability; a relay may only *decline* via `CAP_GUARD` being unset |
| **introduction point** | the service, from its descriptor | descriptor period | relay must accept intro duty and enforce the §9 PoW/token rate limit (R10) |
| **rendezvous point** | the client, per session | one session | any relay accepting rendezvous |

Two consequences worth stating explicitly:

1. **CLIENT is not in any registry and has no capability bits.** A client that
   registers on-chain has published "this wallet operates a node", which is a
   linkage the taxonomy (§3) exists to prevent.
2. **There is no `CAP_SERVICE` bit and there never will be.** An on-chain or
   in-DHT advertisement that a node hosts a service is a deanonymisation vector
   with no compensating benefit. If a service node also relays, it advertises
   `CAP_RELAY` and nothing else, and §17.4 governs what that costs.

### 17.2 Capability advertisement: the ruling and the bitmap

> **RESOLVED (2026-08-16) — P14.** `CAP_ALL` is now `(1 << 13) - 1` in
> `NodeRegistry.sol`, and `CAP_RELAY`, `CAP_GUARD`, `CAP_RENDEZVOUS`,
> `CAP_INTRO`, `CAP_BOOTSTRAP` and `CAP_EXIT` are declared at the bit positions
> this section specifies. 4 contract tests: every AXON bit survives
> registration, every pre-existing bit is unmoved (a renumber would silently
> misattribute every receipt through `internal/facilitation/receipt.go`), bit 13
> is still refused so the ceiling remains a ceiling, and **there is no
> `CAP_SERVICE`** — asserted by absence, because a later completeness pass
> adding one would look like tidying up.
>
> **Still true: this is a REDEPLOY.** `NodeRegistry` is written and deployed
> nowhere, so nothing has to be migrated yet — but the moment it is deployed,
> widening `CAP_ALL` again would mean re-registering every node.

> **Ruling R-17.2.** A capability is advertised in the relay descriptor and is
> **valid only when all three of the following hold**: (a) the operator enabled it
> in configuration; (b) the node's reachability for that capability has been
> *measured by other nodes*, not asserted by itself; (c) the node's bond covers
> the capability's policy threshold (§15). Any capability failing (b) or (c) is
> ignored by path selection regardless of what the descriptor says.

Rule (b) is already the existing gateway's discipline and it is the right one:
`GATEWAY.md` requires three distinct admitted probe identities across two
configured network trust domains, each probe connecting to the *literal claimed
IP* while validating TLS against the hostname, with redirects forbidden and the
probe's own result excluded when candidate and probe are the same process. AXON
generalises this to every capability. A listening socket is not reachability.

The bitmap, preserving the existing seven bits exactly:

```text
  bit   value    name                     status
  ---   -----    ----                     ------
    0   1<<0     CAP_DHT                  EXISTS — NodeRegistry.sol
    1   1<<1     CAP_GATEWAY              EXISTS — inbound clearnet gateway
    2   1<<2     CAP_STORAGE              EXISTS
    3   1<<3     CAP_LOADBALANCE          EXISTS
    4   1<<4     CAP_DOCKER_WORKER        EXISTS
    5   1<<5     CAP_DOCKER_CONTROLLER    EXISTS
    6   1<<6     CAP_WITNESS              EXISTS
  --- AXON additions ---
    7   1<<7     CAP_RELAY                forwards cells at L4
    8   1<<8     CAP_GUARD                willing to be pinned as a guard (a VETO
                                          bit: unset means "never"; set does not
                                          make the node eligible — the client
                                          computes eligibility from measurement)
    9   1<<9     CAP_RENDEZVOUS           willing to serve as an RP
   10   1<<10    CAP_INTRO                willing to serve as an intro point
   11   1<<11    CAP_BOOTSTRAP            serves the joining-node sample
   12   1<<12    CAP_EXIT                 outbound clearnet. Opt-in. See §17.6

  CAP_ALL must become (1 << 13) - 1        ← CONTRACT CHANGE REQUIRED
```

Compatibility rules, binding:

- **Never renumber an existing bit.** `internal/facilitation/receipt.go` derives
  the receipt `ServiceType` index from the bit position; a renumber silently
  misattributes every receipt and the node earns nothing while appearing healthy.
  The golden-vector test in that package is the tripwire.
- **`CAP_ALL` is the only line that changes in the contract.** The bitmap field is
  already `uint256`. Widening `CAP_ALL` is a redeploy of `NodeRegistry`, with
  re-registration of existing nodes, and it belongs in the phase plan (§23).
- **The chain never learns where a node is.** `endpointCommitment` stays as it is:
  `hash(endpoint ‖ nodeSecret ‖ epoch)`. The DHT descriptor carries the endpoint,
  signed by RoutingIdentity, and anyone can check it against the commitment. The
  chain says *bonded, and claims these capabilities*; the DHT says *here, now*.
  A SERVICE node writes no commitment at all.

### 17.3 Co-residency: what must not be shared

Multiple roles on one machine is the normal case for a volunteer, and it is where
anonymity is most often lost to an implementation detail rather than to an
attack. The two classic failures:

```text
FAILURE 1 — the relay reveals the service
  host H runs RELAY (public IP, in every descriptor) and SERVICE (hidden).
  adversary: DoS H's relay port, watch service S's latency rise.
             or: note that S is unreachable in exactly the minutes H is down.
  cost to adversary: near zero. Confirmation, not search.

FAILURE 2 — the client's own traffic is distinguishable from what it relays
  host H relays for others AND originates its own circuits on the same links.
  if the two have different padding behaviour, different flow control, different
  scheduling, or different queue depth, the guard can separate them — and
  originated traffic is H's own.
```

Binding rules:

| # | Rule | Enforced by |
|---|---|---|
| C1 | SERVICE and RELAY in one process is **refused**. Co-residency on one *host* is allowed only with an explicit `--i-understand-corelation-risk`-class acknowledgement recorded in the config, and is off by default. | config validation, role-before-config as in `config.go:694` |
| C2 | SERVICE and EXIT never co-reside, on one host, at all. No override. An exit attracts law-enforcement attention to a specific machine; hosting a hidden service there is the worst available combination. | config validation |
| C3 | A node **never uses itself as the first hop** of its own circuits. A service that does so gives hop 2 its own address as predecessor and has silently built a 2-hop path. | path selection (§8) |
| C4 | Originated and relayed traffic use **the same padding profile, the same scheduler, and the same queue discipline** on any shared link. If they cannot, they must not share a link: the client role opens its own guard links and the relay role uses its own. | L1/L4 implementation, tested by a distinguishability test in §21 |
| C5 | Separate keystores, separate file ownership, separate processes: ServiceIdentity is never in the relay process's address space, and NodeIdentity is never in the service process's. | process split below |
| C6 | Separate metrics. A `/metrics` endpoint that reports both relayed cell counts and locally originated cell counts is a correlation oracle for anyone who can read it. Local-only bind, and originated counters are not exported at all. | metrics config, default deny |
| C7 | Separate logs, separate log rotation, separate retention. Default: no per-circuit logging on any public role. | logging config |
| C8 | An EXIT's DNS resolver is never the resolver the local CLIENT uses. Shared cache = shared timing side channel between exit users and the operator. | exit subsystem |
| C9 | A SERVICE's own content is not pinned in the locally-audited store as its sole holder. Being the only holder of an object that a service serves is a proof of hosting. | storage placement (§10) |
| C10 | Distinct on-disk state. Separate bbolt files, separate data directories, separate UIDs. One database file that contains both the relay's peer table and the service's descriptor state loses both to one disk seizure. | packaging |

The process/keying separation that enforces C4–C7:

```text
  ┌────────────────────────────────────────────────────────────────┐
  │ HOST                                                            │
  │                                                                 │
  │  uid axon-relay          uid axon-client        uid axon-svc    │
  │  ┌───────────────┐       ┌──────────────┐      ┌─────────────┐  │
  │  │ axond-relay   │       │ axond-client │      │ axond-svc   │  │
  │  │ NodeIdentity  │       │ (no public   │      │ Service     │  │
  │  │ RoutingIdent. │       │  identity)   │      │ Identity    │  │
  │  │ forwarding    │       │ own circuits │      │ descriptors │  │
  │  │ table         │       │ guard set A  │      │ guard set B │  │
  │  └───────┬───────┘       └──────┬───────┘      └──────┬──────┘  │
  │          │ public links         │ own guard links     │         │
  │          │                      │                     │         │
  │     ═════╧══════════════════════╧═════════════════════╧═════    │
  │            L1 transport — SAME padding profile on all           │
  └────────────────────────────────────────────────────────────────┘

   guard set A ∩ guard set B = ∅       (a shared guard sees both roles)
   IPC: local unix socket, capability-scoped API, no key material crosses
```

Guard-set disjointness (`A ∩ B = ∅`) is the non-obvious one. If the client role
and the service role share a guard, that guard sees both the client's originated
traffic and the service's tunnels from one IP, and the co-residency it was
supposed to not know about is the first thing it learns.

### 17.4 Bootstrap

**The problem in one line: a joining node must learn a peer set from someone, and
whoever it learns from chooses its entire initial view of the network.**

The existing implementation reasons about this correctly — its package comment
is the standard to preserve: *"A bad peer costs a failed dial. A bad coordinator
key means accepting forged storage leases indefinitely, with nothing to notice
it."* What it does today:

| Mechanism | Detail | Source |
|---|---|---|
| Discovery | SRV lookup, priority/weight honoured, capped at `maxSources = 5`; document at `/.well-known/syndichan/storage-node.json` | `discover.go:14-22, 44-85` |
| Verification | Ed25519 signature over a canonical message, checked against a **key pinned at install**, and the document must *announce* the pinned key | `bootstrap.go:245-276` |
| Truncation resistance | The peer **count** is signed before the peers, so a shortened list cannot pass as complete | `bootstrap.go:192-201` |
| No-pin fallback | Require agreement across `DefaultAgreement = 2` independent sources; refuse to act otherwise | `discover.go:203-222` |
| Disagreement | Fingerprint = `sha256(coordinatorKey ‖ sorted peers)[:8]`; a source that differs from a signature-verified document is logged as **attributable misbehaviour**, not skipped | `bootstrap.go:312-321`, `discover.go:224-231` |
| Expiry | Signed, and a stale document is refused with the source named | `discover.go:144-152` |
| Limits | 15 s timeout, 1 MiB body cap | `discover.go:18`, `discover.go:249` |

**What is wrong with it for AXON, precisely:**

1. **One coordinator key is a central directory wearing a different hat.** The
   package comment itself concedes that consensus cannot replace the signature
   because the participant list comes from DNS, which one party controls. True —
   and it means the signature is a single point of authority, not a solution.
2. **The SRV name is DNS.** A censor blocks it; the domain owner is a legal target
   and an eclipse operator.
3. **Fetching over WebPKI HTTPS identifies the joiner** to the network observer
   and to the gateway, before any anonymity exists.

**The AXON bootstrap design:**

```text
 tier 0  cached peerbook from the previous run          ← always tried first
         (no network exposure; a returning node needs no seed at all)
              │ empty or all stale
              ▼
 tier 1  user-supplied peers  --peer <addr>/<nodeid>    ← always honoured
              │ none given
              ▼
 tier 2  CHAIN-ANCHORED SEED ROOT                       ← the authority
         a Merkle root over the seed set, published on-chain, verified
         through the light client that already exists (doc/trust-anchor.md)
              │
              ▼
 tier 3  k independent seed sets, each signed by a different signer,
         shipped in the binary; m-of-k must agree with the chain root
              │
              ▼
 tier 4  seeds return  { sample of relay descriptors,
                         Merkle inclusion proof against the anchored root }
         → a seed can WITHHOLD. It cannot INVENT.
```

Design rules, with what each buys:

| Rule | Buys | Residual |
|---|---|---|
| The seed's answer carries an inclusion proof against a chain-anchored root | A seed cannot fabricate a peer | It can still withhold and serve only its own subset |
| Sample from ≥ 3 independent seeds; require the union to cover ≥ *N* distinct ASNs before proceeding | Withholding requires collusion across operators and networks | Small networks may not *have* N ASNs; the check must degrade loudly, not silently |
| Seed sets are signed by **different, independent signers**, and disagreement between them is a reportable event, following the existing fingerprint/disagreement pattern | One compromised signer is detected, not obeyed | Detection requires someone reading the report |
| Do not build an anonymity-bearing circuit until the peerbook holds peers from ≥ 2 independent sources | Eclipse during the first minutes | The threshold is a guess; the vulnerable window is narrowed, not closed |
| Seeds serve a *sample*, never the relay set | Seeds are not a consensus authority (R14) | Different clients get different views — the epistemic-partition risk R14 names as unsolved |
| The chain anchor is read through the existing light client | Trust-minimised authority without a directory authority | **Weak subjectivity**: the light client's initial checkpoint is a subjective input, exactly as `doc/trust-anchor.md` §3 states. That trust does not disappear; it moves to a place where it can be checked against several independent providers. |

**The hardcoded-seed problem, stated without softening.** Seeds are:

- a **censorship** target — block the addresses and no new node joins;
- an **eclipse** target — control the seeds a specific node reaches and you choose
  its entire initial view, its first guards, and therefore its anonymity;
- a **surveillance** target — contacting a seed identifies the contacting host as
  a new AXON node to the seed operator and to any observer of that link, before
  any circuit exists to hide behind.

None of the mitigations removes any of these three. They raise cost, spread
trust, and make misbehaviour attributable. **Bootstrap is `[UNSOLVED]` in the
strong sense** and the roadmap says so rather than treating a signed list as an
answer.

### 17.5 Gateways to the ordinary Internet

> **Ruling R-17.3.** No node is an exit by default. Exit is opt-in via
> `CAP_EXIT`, an explicit configuration block, and a recorded operator
> acknowledgement. A node with no exit configuration refuses exit requests at the
> protocol level, not by policy evaluation. **The network must function with zero
> exits**; the exit is a compatibility bridge, not infrastructure.

**Two directions, routinely confused.** The existing code implements only one of
them, and it is the safe one.

| | Existing gateway (`internal/gateway`) | AXON inbound gateway | AXON exit (outbound) |
|---|---|---|---|
| Direction | clearnet browser → overlay-stored content | clearnet browser → `.axon` service | overlay client → arbitrary clearnet host |
| What it proxies | Content the network already holds (`contentproxy.go`) | A named service's HTTP | **Anything the client asks for** |
| Naming | `gw-<identity-hash>.syndichan.org`, derived by the controller | a WebPKI name chosen by the operator | none needed |
| Certificate | ACME, exact-host (`acme.go`) | ACME | none |
| Central authority | **Yes** — `gateway-controller` owns Name.com DNS; registration at `https://syndichan.org/api/v1/gateways` | None. Descriptor in the DHT | None |
| Reachability proof | 3 admitted probes across 2 network trust domains, connect-back to the literal source IP, redirects forbidden, `/readyz` 200 with `X-Gateway-Version` (`GATEWAY.md`, `probe.go`) | Same discipline, peer-measured (R-17.2) | Same, plus egress verification |
| CGNAT | rejected — `PublicAddress` blocks `100.64.0.0/10` (`protocol.go:472-491`) | rejected | rejected |
| Abuse surface | Bounded: it can only serve objects the network stores | Bounded: one named service | **Unbounded** |
| Legal exposure | Operator is publicly identified by DNS and certificate, serving content they did not choose | Same | The operator's IP is the apparent source of every connection |

**Exit policy format** — a line-oriented, ordered, first-match grammar, published
verbatim in the relay descriptor and evaluated identically by client and exit:

```text
exit-policy-version 1
accept   0.0.0.0/0:443
accept   0.0.0.0/0:80
reject   0.0.0.0/0:25            # SMTP: spam complaints end an exit fastest
reject   10.0.0.0/8:*  172.16.0.0/12:*  192.168.0.0/16:*  127.0.0.0/8:*
reject   169.254.0.0/16:*  [::1]:*  [fc00::/7]:*
reject   100.64.0.0/10:*         # CGNAT — reuse gateway.PublicAddress
reject   *:*                     # IMPLICIT and MANDATORY final line
```

Binding properties of the format:

- **The final `reject *:*` is implicit and cannot be overridden.** A policy is an
  allowlist with exceptions, never a denylist. An operator who wants a permissive
  exit writes the permissive lines explicitly.
- **The private/loopback/link-local/CGNAT rejections are not operator-editable.**
  They exist to stop SSRF against the operator's own LAN and cloud metadata
  service. Reuse `gateway.PublicAddress` (`protocol.go:472`) as the single
  implementation of "is this address allowed to be a destination" so the exit and
  the probe subsystem cannot drift.
- **Policy is descriptor state, evaluated client-side before the terminal hop is
  chosen.** A client must not learn a destination is refused by being refused; it
  reveals the destination to a relay that will not serve it.
- **Policy changes are not retroactive.** Existing streams run to completion under
  the policy in force when they were opened; the new policy applies at the next
  descriptor publication.
- **DNS is a separate sub-capability from TCP exit.** An exit that resolves names
  is a different risk profile from one that only connects to literal addresses,
  and the two must be independently declinable.

**The legal and abuse exposure, plainly.** This is the part no protocol change
touches:

- Every connection the exit makes appears to originate from the operator's IP
  address. Abuse complaints, DMCA notices and law-enforcement requests arrive at
  the operator or their ISP.
- Residential and most consumer VPS terms of service prohibit this. Account
  termination is the common outcome and is not appealable.
- The exit's address will be listed on spam and abuse blocklists, which degrades
  every other service on that address and often on the whole subnet.
- Hardware seizure is a realistic outcome in some jurisdictions. Intermediary
  liability protections were written for hosting and access providers and their
  application to an anonymising relay is unsettled in most places and unfavourable
  in some.
- No configuration makes this safe. A narrow policy reduces the volume of
  complaints and does not change the category.

AXON's position: **the exit is optional, narrow by default, and outside the
critical path.** Nothing in §§7–13 requires an exit to exist. A network with zero
exits is a fully functional AXON network that cannot reach the clearnet, which is
the correct default posture for infrastructure whose purpose is the overlay.

### 17.6 Deployment topologies

Resource figures are **estimates derived from the arithmetic below**, except where
a cell cites an existing configured value. None is measured. §21 owns measurement.

Derivations used:

```text
relay CPU    one AEAD op per cell per direction. At 100 Mbit/s of cells
             = 12.5 MB/s each way = 25 MB/s of ChaCha20-Poly1305.
             If R_aead ≥ 1 GB/s/core (TO BE MEASURED, §21), crypto ≤ 2.5 %
             of one core. CPU is dominated by QUIC packet handling, not by
             the onion crypto.

relay RAM    per circuit: ~0.5 KiB fixed state + a queue capped at 32 cells
             per direction (64 KiB worst case, ~8 KiB typical)
             + QUIC per-stream state, estimated 2 KiB (R12's stated cost).
             10,000 circuits ≈ 10,000 × 10.5 KiB ≈ 105 MB + runtime.

client pad   §16.3 floor padding at R_floor = 0.5 → 6.4 GB/month.
```

| Topology | Roles | Inbound reachability | CPU | RAM | Disk | Bandwidth | Dominant risk / constraint |
|---|---|---|---|---|---|---|---|
| **Home client behind NAT** | CLIENT | none — outbound only | < 5 % of one core | 128–256 MB | ~200 MB (peerbook, descriptor cache) | user traffic + **6.4 GB/mo** padding floor | Padding cost on a metered link; the ISP knows you run AXON |
| **Home relay, port forwarded** | CLIENT + RELAY + DHT | one UDP port, forwarded; **not CGNAT** | 10–30 % of one core at 100 Mbit/s | 512 MB–1 GB | ~1 GB | 100 Mbit/s symmetric preferred; existing gateway floor is `MinimumUploadMbps: 10` | ISP terms; upload caps; C4 distinguishability between own and relayed traffic |
| **VPS relay, guard-eligible** | RELAY + DHT + RENDEZVOUS + INTRO | static v4 **and** v6, verified independently per family (`GATEWAY.md`) | 1–2 vCPU | 2 GB | 10 GB | 1 Gbit/s port, 5–20 TB/month | Bond (§15, amount is policy — not stated here); 45-day guard stability is a *commitment*, not a setting |
| **Cloud storage node** | STORAGE + DHT (+ RELAY optional) | inbound strongly preferred | 1 vCPU + I/O headroom | 2 GB (bbolt page cache) | ≥ `CapacityBytes`; existing default **20 GiB**, realistic 1–10 TB; `DataShards 6 / ParityShards 3`, `ChunkBytes 1 MiB` | egress-dominated; repair and rebalance are bursty | Cloud **egress pricing** is the real constraint, not disk. Repair traffic is not user-visible and is billed anyway |
| **Dedicated bootstrap** | BOOTSTRAP + DHT | static, stable, published | < 1 core | 512 MB | 1 GB | low steady, spiky during an outage or a censorship event | It is a censorship and eclipse target **by design** (§17.4). Operator is publicly identified |
| **Service behind CGNAT** | SERVICE (+ CLIENT) | **none whatsoever** — rendezvous only | 5–15 % of one core | 512 MB + the service's own needs | service-dependent | ≈ 3× the service's own byte volume (3 hops each way) plus tunnel maintenance | This is the *best* topology for a service: no inbound port, no reachability record, nothing to probe. Intersection exposure (§16.6) is unchanged |
| **Exit gateway** | RELAY + EXIT | inbound port + permissive egress | 1 vCPU | 2 GB | 20 GB (no connection logging by default) | ISP-dependent; expect abuse-driven variance | **Legal, not technical** (§17.5). Never co-resident with SERVICE (C2) |
| **Inbound content gateway** | GATEWAY | public 443 + 80 for ACME (`GATEWAY.md`) | 1 vCPU | 2 GB | cache-sized | high, browser-facing | Operator is publicly identified by DNS and certificate, and is serving content they did not select |

The existing eligibility gate (`config.go:592-596`) is the right shape for all
public roles and should be reused rather than re-derived per role:
`MinimumUploadMbps: 10`, `MinimumFreeMemoryMB: 512`, `MinimumFreeDiskMB: 1024`,
`MaximumCPUPercent: 90`, `RequirePublicAddress: true`, `RejectCGNAT: true`.

### 17.7 Decisions

| Decision | Problem it solves | Derived from Tor/I2P/Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| RELAY is the only forwarding role; ROUTER retired (R-17.1) | Two names for one thing in every future document and config file | Tor says "relay"; I2P says "router" | Separated *role* (configured, advertised) from *position* (per-circuit, client-chosen) | Keeping both names with a subtle distinction nobody would maintain | None. It is a naming ruling |
| Capability = config **∧** measured reachability **∧** bond (R-17.2) | Self-asserted capacity and Sybil relays claiming roles they cannot serve | Tor's bandwidth authorities measure; I2P trusts self-report | Measurement is peer-distributed, not authoritative (R14), reusing the existing probe-quorum discipline | A central measurement authority (R14 refuses it); pure self-report (I2P's known weakness) | Peer measurement is itself Sybil-attackable; the probe quorum must require distinct operators, not distinct signatures |
| AXON bits at `1<<7`+, `CAP_ALL` widened to `(1<<13)-1` | Advertising overlay roles on-chain at all | Neither Tor nor I2P has an on-chain registry | Kept every existing bit at its existing position, because `ServiceType` index arithmetic depends on it | Renumbering into a clean layout (breaks receipt attribution silently) | **Requires a `NodeRegistry` redeploy and re-registration.** Until then no AXON capability can be registered |
| No `CAP_SERVICE`; services advertise nothing | Publishing "this bonded node hosts a service" | Tor hidden services are likewise not in the consensus as services | Made it explicit and permanent rather than incidental | A service bit for "discoverability" | Services get no accounting credit for hosting; §14 must credit them another way or not at all |
| Process + UID + guard-set separation for co-resident roles (C1–C10) | The relay role revealing the service; originated traffic distinguishable from relayed | Tor's guidance against co-locating a relay with a hidden service | Made it structural (separate processes and disjoint guard sets) rather than advisory | A single process with internal isolation — one memory disclosure loses everything | Three processes is a harder deployment, more IPC surface, and more ways to misconfigure |
| Chain-anchored seed root + m-of-k independent signers | Bootstrap authority centralised in one signing key | Tor's hardcoded directory authorities; I2P's reseed hosts (both single-operator sets) | Anchored the seed list on-chain through the light client that already exists, so seeds can withhold but not invent | Trusting the existing single coordinator key; a pure DNS seed list; DHT-only bootstrap (circular) | Weak subjectivity moves into bootstrap: the light client's checkpoint is a subjective input, and a chain outage must not block joining (R7 applies) |
| No exit by default; opt-in, allowlist policy, mandatory implicit `reject *:*` (R-17.3) | Volunteers becoming exits without understanding the exposure | Tor's exit policy, which defaults to a *permissive* policy | Inverted the default to deny; made the private-range rejections non-editable and shared with the existing `PublicAddress` check | A default-permissive policy; a network-wide mandatory exit policy (re-centralisation, R5's reasoning) | A network with few exits has poor clearnet reach, and the few exits that exist carry concentrated traffic and concentrated legal risk |
| Inbound gateway and outbound exit are different roles with different bits | The existing gateway is safe; an exit is not, and one word covered both | The existing `internal/gateway` | Split the concept before anyone builds the dangerous half by analogy with the safe half | One `CAP_GATEWAY` covering both | Two roles to document, and operators will still conflate them |

### What this section does NOT establish

- **It does not state a bond amount for any capability.** `StakeVault.sol`
  contains no minimum-bond constant; the threshold is a versioned policy value in
  `ServicePolicyRegistry`. Any number here would be invented. §15 owns it.
- **No CPU, RAM or bandwidth figure in §17.6 is measured.** They are arithmetic
  from stated assumptions — notably an unmeasured `R_aead` and an estimated 2 KiB
  of QUIC per-stream state — plus values read from the existing config defaults.
  A relay operator must not be given these numbers until §21 has measured them.
- **It does not solve bootstrap.** Every mitigation in §17.4 raises the cost of
  censorship, eclipse and identification of joiners. None removes any of the
  three, and the first-minutes eclipse window remains open.
- **It does not resolve the R14 partition risk.** Seeds serve samples, and
  different clients therefore see different networks. That is the deliberate
  consequence of having no consensus document and it remains one of the hardest
  unsolved problems in the design.
- **It does not make co-residency safe.** C1–C10 remove the implementation-level
  mistakes. They do not remove the induced-load and uptime-correlation attacks
  against a host running both a public relay and a hidden service; those are
  properties of sharing a machine, and the only real mitigation is not to.
- **It does not settle the exit's legal position in any jurisdiction.** §17.5
  states the exposure categorically because it is categorical. It is not legal
  advice and the roadmap must not pretend to give any.

> **Objection to Constitution §5, two items.**
>
> **(a) Content chunk = 256 KiB.** The existing code defaults to
> `ChunkBytes: 1 << 20` (1 MiB) at `internal/config/config.go:574`, with
> `DataShards: 6, ParityShards: 3`. The Constitution's own note says "Confirm
> against existing `internal/store` before asserting" — this is that confirmation,
> and the value is 1 MiB. §10 should either adopt 1 MiB or state why migrating to
> 256 KiB is worth breaking existing manifests for. §17.6 uses the real value.
>
> **(b) Cell size and `H_max`.** A 1024 B cell in a 1200 B datagram floor costs
> 30.1 % of link bandwidth relative to payload, and reserving 4 × 16 B AEAD tags
> for a default 3-hop path wastes 16 B per cell on every circuit that is not 4
> hops. Fixing `H_max = 3` would recover 1.6 % of link bandwidth at the cost of
> leaking that no path is ever longer than 3 hops. The Constitution's choice is
> defensible; this records the price so the synthesis pass can weigh it.
