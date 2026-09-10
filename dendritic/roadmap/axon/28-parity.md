## 76. Method — What "Equivalent or Better" Has to Mean

**The requirement this part answers: AXON must be equivalent or better than both
Tor and I2P. Where either system has solved something we have not, we adopt
their answer rather than inventing a worse one.**

That requirement is easy to state and easy to fake. A comparison table with
green ticks proves nothing, because the interesting differences are not features
— they are *properties that survive an adversary*, and most of them are held up
by mechanisms neither system advertises on a front page. So this part fixes a
method before it fixes anything else.

### 76.1 The three axes, kept separate

Conflating these is how a design claims parity it does not have.

| Axis | Question | Can engineering close it? |
|---|---|---|
| **Construction** | Is the cryptographic and protocol construction at least as strong? | Yes. This is what a roadmap can promise. |
| **Mechanism** | Are the defences that surround the construction — guards, padding, measurement, censorship resistance — present and as mature? | Yes, but each is a phase, not a paragraph. |
| **Population** | Is the anonymity set, the relay count, and the adversarial attention comparable? | **No.** Not by any amount of code. |

AXON can reach parity on axes 1 and 2. It cannot reach parity on axis 3 by
building anything, and §83 states what that means for every claim in this
document. **A design that is stronger on axes 1 and 2 and empty on axis 3 is
weaker in practice than a weaker design with two million users,** and pretending
otherwise would be the single most dishonest thing this roadmap could do.

### 76.2 How a parity claim is judged

Each gap in §80's register carries:

```text
ID          PAR-nn
Axis        construction | mechanism | population
Who is ahead  Tor | I2P | both
The gap     what they have that we do not, in mechanism terms
Why it matters  the concrete attack it changes
Our answer  adopt / adapt / decline-with-reason / [UNSOLVED]
Owner       the phase that closes it, or the reason none can
Severity    critical | high | medium | low
```

**"Decline with reason" is a permitted answer and is used four times.** A design
that adopts everything both systems do inherits both systems' costs, and some of
those costs are ones AXON's threat model does not need to pay. But declining
requires a stated reason, and the reason must survive being read by somebody who
disagrees.

### 76.3 What this part is not

It is not a security proof, a benchmark, or a claim that AXON is ready. It is a
register of known deficits against two systems that have been attacked for two
decades, plus the phases that close them. Every row is a commitment to build
something or an admission that we will not.

---

## 77. Where Tor Is Stronger

Nine mechanisms, in rough order of how much damage the gap does.

### 77.1 A signed consensus, and therefore a shared view of the network

**Tor:** nine directory authorities vote hourly and publish a signed consensus.
Every client that verifies it has *the same list of relays, the same flags, and
the same weights as every other client*. This is the mechanism that makes the
epistemic-partition attack hard: to show one client a different network you must
compromise a threshold of authorities, and the document is signed, dated, and
publicly archived, so the attack leaves evidence.

**AXON:** Constitution R14 refuses a consensus document outright, and §18's
T-L3-04 names the consequence as "the single largest unsolved problem in the
design". A client's view of the relay population is whatever its DHT lookups and
its bootstrap set produced. There is no ground truth to compare against, and
§7.7's eclipse row says so.

**Why it matters, concretely.** Without a consensus, an adversary who controls a
client's bootstrap set and enough DHT positions can show that client a relay
population consisting largely of its own nodes — and the client cannot detect
this, because it has nothing to compare its view to. Every path it builds is
then drawn from a poisoned set. Tor's answer is not clever; it is a signed
document. Ours is currently nothing.

> **This is the one gap where the honest answer may be that R14 is wrong.**
> §81.3 puts the options on the table rather than assuming the ruling holds.

### 77.2 Bandwidth measurement without trusting self-reports

**Tor:** bandwidth authorities actively measure relays by downloading through
them and publish weights in the consensus. Path selection is capacity-weighted,
so the network's throughput is usable and a relay cannot attract traffic by
lying about its capacity.

**AXON:** R14 forbids a measurement authority, and §25(c) marks bandwidth
measurement as an open problem. `RelayDescriptor.claimed_bw` (§7.1) is
**self-reported**, and P3's "must NOT be built yet" explicitly bars weighting.
So today's options are both bad: select uniformly and get a network as slow as
its slowest relay, or trust `claimed_bw` and hand an adversary a free way to
attract every circuit by claiming a terabit.

**I2P has solved this without an authority,** which is why §78.3 exists. This is
the clearest case in the whole register where the right answer is to adopt
somebody else's design.

### 77.3 The guard algorithm, in its full form

**Tor:** guard selection is a layered state machine — a large *sampled* set
persisted for months, a *filtered* subset that meets current constraints, a
*confirmed* list of guards actually used successfully, and a small *primary*
set tried in order. It is designed so that an adversary who can make a client's
guards fail cannot walk it onto a guard of the adversary's choosing, and so that
the sampled set does not silently drift toward whatever the adversary keeps
reachable.

**AXON:** §8.5 specifies primary guards, a rotation period and the rule that
failure must never drive guard selection. That is the right shape and a
materially thinner mechanism, and P7 has not been built. The specific property
Tor's sampled set buys — bounding *how much* of the relay population a client
will ever have tried, so a long-running adversary cannot enumerate the client by
attrition — is not in §8.5 at all.

### 77.4 Vanguards — layered guards for services

**Tor:** onion services can pin second- and third-layer guards, not just the
first hop. This exists because a service builds circuits continuously and to
attacker-chosen rendezvous points, so an adversary who can cause repeated builds
eventually observes enough paths to locate the service's guard. Vanguards bound
that by pinning the next layers too, with staggered rotation.

**AXON:** nothing. §9's tunnel design and P7 specify a guard at the first hop
and free selection thereafter. **This is the most serious mechanism gap for the
thing AXON exists to host** — anonymous services are the product, and the
guard-discovery attack is the attack that finds them.

### 77.5 The `RELAY_EARLY` discipline

**Tor:** extension requests may travel only in `RELAY_EARLY` cells, a relay
decrements a counter and refuses to forward more than a fixed small number, and
a relay must refuse `EXTEND` arriving in a non-early cell. This exists because a
real attack used the early/normal distinction as a side channel to signal
between a hostile entry and a hostile HSDir.

**AXON:** §8.1 defines `RELAY_BUILD` as "budget-limited; the `RELAY_EARLY`
equivalent" and §8.1's `RELAY` row says `EXTEND` inside a plain `RELAY` "MUST be
rejected". **The budget is never given a number anywhere in the document.** A
budget that is not a number is not a budget, and the two-sided nature of the
rule — cap the count *and* refuse extension outside the class — must both be
tested. This is the cheapest fix in the register.

### 77.6 Deployed padding

**Tor:** connection-level padding to break netflow-record correlation, and
circuit-level padding machines with negotiated state machines aimed at specific
traffic-fingerprinting attacks.

**AXON:** §8.10 defers all padding to v2, and `LINK_PAD_NEG` / `PADDING_NEGOTIATE`
have codes allocated and no implementation. §16's defences are described as MVP
only. So a website-fingerprinting adversary at the guard faces AXON's raw traffic
shape.

### 77.7 Congestion control that has been deployed and tuned

**Tor:** a real, measured congestion-control algorithm with RTT-based signalling,
replacing fixed windows.

**AXON:** §8.8's windows are "specified defaults with the right shape; **none has
been measured on AXON**", and P5 marks flow control `[NEEDS RESEARCH]`. This is a
performance gap, and performance is an anonymity property: a network too slow to
use has no users, and a network with no users has no anonymity set.

### 77.8 Bridges and pluggable transports

**Tor:** an ecosystem — unlisted bridges, several transports that make traffic
resemble something else or nothing at all, domain fronting, and a distribution
system that makes harvesting the bridge list expensive.

**AXON:** §6.8 states a censorship posture. There is no bridge concept, no
unlisted-relay concept, no transport obfuscation, and R4(a) makes DHT membership
*public by design* — so the relay list is not merely discoverable, it is
published. **A censor blocks AXON by enumerating the DHT and null-routing it,
and today nothing in the design makes that harder.**

### 77.9 Denial-of-service defence at the relay, as a subsystem

**Tor:** a dedicated DoS-mitigation subsystem — per-client-IP connection caps,
circuit-creation rate limits with a token bucket, and refusal responses that cost
the relay less than the attack costs the attacker. Separately, per-relay
bandwidth rate and burst limits bound how much any relay will carry.

**AXON:** §7.8 rate-limits the DHT. §8.4 names "circuit-table exhaustion at a
popular relay" as a failure mode and stops there. **There is no relay-side
admission control anywhere in the design**, no bandwidth cap, and no phase owning
either. A relay's `MaxCircuitsPerLink = 1000` in `internal/axon/link` is the only
limit that exists, and it is per link rather than per attacker.

### 77.10 Proof-of-work admission for services under flood

**Tor:** onion services under attack can require clients to solve a proof-of-work
puzzle whose difficulty rises with load, so a flood costs the attacker CPU
proportional to the pressure it applies.

**AXON:** R10 *requires* intro points to be rate-limited by a PoW or token
puzzle, §7.1 carries `pow_seed` and `pow_difficulty` in `IntroPointRecord` for
exactly this, and P6 marks the puzzle `[NEEDS RESEARCH]`. So the data structure
exists, the requirement exists, and the mechanism does not. **This is the defence
that decides whether an AXON service survives its first serious flood.**

### 77.11 Relay family declarations

**Tor:** relays declare which other relays they are operated alongside, and path
selection refuses to use two relays from one declared family in one circuit.

**AXON:** §7.5's diversity ladder has a fourth rung — operator, from
`NodeRegistry.Node.owner` — and §7.2 states plainly why it matters: *"ASN
diversity is not operator diversity"*, since one cloud provider spans many ASNs.
No phase owns that rung. P3 implements prefix and ASN; operator is unimplemented
and unscheduled. AXON's version is in fact **stronger in principle** than Tor's,
because a declared family is voluntary and self-reported while a bonded on-chain
owner is neither — which makes leaving it unbuilt the more wasteful gap.

### 77.12 Side-channel counters for dropped and injected cells

**Tor:** relays count cells that arrive for circuits or streams in states where
they should not exist and tear down on excess, because a relay that can make a
peer silently drop a cell has a signalling channel that survives every
integrity check — the class of attack that motivated the counters.

**AXON:** §8.9 argues injection is detected and localised, which is true for
cells that must be *decrypted*. It says nothing about cells that are structurally
valid and simply arrive when they should not: a `SENDME` for a closed stream, a
`DATA` cell for a stream that never opened, a `TRUNCATED` for a hop that is
already gone. Each is a droppable, countable event, and a channel if nobody
counts.

### 77.13 Traffic splitting across circuits

**Tor:** a deployed mechanism that splits one stream across two circuits sharing
an exit, improving throughput and reducing the value of observing one path.

**AXON:** Part VI specifies a full multipath substrate, in more depth than Tor's
mechanism, and none of it is built (sections 41–51, all `SPEC`). This is a gap of
*schedule*, not of design — recorded so it is not mistaken for an oversight.

### 77.14 A frozen specification and a second implementation

**Tor:** a written protocol specification independent of any implementation, and
more than one implementation of it.

**AXON:** this roadmap, one Go implementation, and no frozen wire spec. Every
"the code is the spec" system eventually discovers that a bug is now protocol.

---

## 78. Where I2P Is Stronger

Five mechanisms. Two of them are answers AXON should simply take.

### 78.1 Unidirectional tunnels

**I2P:** inbound and outbound tunnels are *separate paths with separate hops*. A
router that carries your outbound traffic does not carry your inbound traffic,
and the reply comes back through a path you chose independently.

**AXON:** bidirectional circuits, as Tor has. One compromised path carries both
directions, so a single hostile relay positioned on a circuit sees both halves of
a conversation's timing pattern.

**Why it matters.** Correlation of a request with its response is easier when one
node sees both. Unidirectional paths mean an adversary needs presence on two
independently-chosen paths to see what one circuit position gives it in AXON.
The cost is real — twice the tunnels, twice the build cost, and a harder story
for congestion control, which is why Tor has never adopted it — but it is a
genuine anonymity advantage and §81 treats it as an option to *offer*, not a
default to impose.

### 78.2 Everyone is a router

**I2P:** the default install participates in routing. The population of routers
and the population of users are nearly the same set, so "this node is relaying"
carries almost no information about whether it is also originating.

**AXON:** R3 gates the relay role on inbound reachability, and P3 implements that
gate ([internal/axon/peer/reach.go](../../dendritic-node/internal/axon/peer/reach.go)).
That is correct engineering — a relay nobody can reach is a black hole — but it
has an anonymity consequence nobody wrote down: **an unreachable node is visibly
a pure client.** Tor has the same property and the same weakness; I2P does not.

### 78.3 Local peer profiling instead of a measurement authority

**I2P:** every router continuously measures the peers it actually uses — how fast
they respond, how many of its tunnel builds they accept, how reliably they
deliver — and sorts them into capacity tiers locally. There is no authority, no
published weights, and no global measurement to game, because *each router's
profile is its own and is built from its own observations*.

**This is the answer to §77.2.** AXON has an R14-shaped hole where bandwidth
measurement should be, and I2P has been running without a measurement authority
for two decades by making measurement local. The design imports cleanly: P3's
peerbook already records observations and deliberately does not score them, which
is exactly the right foundation — the scoring layer goes on top, per-node, and
never leaves the node.

The honest caveat, which I2P also has: local profiling is only as good as the
sample, a new node's profile is empty, and an adversary who behaves well toward
the nodes measuring it and badly toward everyone else is invisible to profiling.
That is a real limit and §80 records it rather than hiding it inside an adopted
design.

### 78.4 Tunnel pools with pre-built spares

**I2P:** tunnels are built ahead of demand and kept in pools, so building is off
the critical path and expiry does not stall traffic.

**AXON:** §8.5 mentions pool spares and P7 owns pools, but the current state
machine (§8.4) has a client building on demand with a 35-second worst case. A
user's first request paying a 35-second build is a user who leaves.

### 78.5 Garlic routing — bundling

**I2P:** several messages, possibly for different destinations, travel inside one
encrypted unit with independent delivery instructions and optional per-clove
delays.

**AXON:** one relay message per cell, one destination per stream. There is no
bundling primitive, so there is no way to make "one message" and "three messages"
look the same, and no place to put a delay that is not a per-cell decision.

---

### 78.6 Variable path length

**I2P:** tunnel length varies, with a configurable random component, so a
participating router cannot infer tunnel length or its own position from length
alone, and different tunnels of the same client differ.

**AXON:** three hops, fixed. §8.3's rotating tag stack was designed specifically
so the *cell format* carries no length evidence — an effort that is largely wasted
if every circuit is the same length anyway, because then length is known a priori
to everyone. Fixed length also means a relay that determines it is at position 2
knows it is the middle, always.

### 78.7 Build messages that hide tunnel length

**I2P:** a tunnel build message is a fixed-size set of records, one per hop, each
encrypted to its hop. A participant decrypts its own record and learns nothing
about how many other records are real.

**AXON:** telescoping. §8.4 concedes the consequence in its own comparison table:
the client extends hop by hop, so **hop *k* observes that it was asked to extend,
which tells it it is not the terminal, and the guard sees every extension pass
through it.** Telescoping was chosen for good reasons — forward secrecy per hop,
no filler hazard, failure attribution by position — and it costs this. I2P pays
the opposite price. The honest position is that neither is dominant, and AXON
should recover what it can (§81.7) rather than pretend the cost is not there.

### 78.8 Ratcheting sessions between endpoints

**I2P:** repeated messages between the same two destinations use a ratcheting
session with forward secrecy and cheap subsequent messages, rather than a fresh
public-key operation each time.

**AXON:** circuit keys are forward-secret per circuit and die with it. There is
no session layer *above* the circuit, so a client reconnecting to a service after
circuit death redoes the full rendezvous. R9 says streams bind to sessions rather
than circuits and that "the session layer above L4 owns resumption" — **and no
phase owns that session layer.**

### 78.9 Obfuscation as the default transport, not an add-on

**I2P:** its transports are obfuscated by design. There is no "normal mode" that
looks like a recognisable protocol and an "obfuscated mode" for censored users;
everyone's traffic looks the same, so using the obfuscation is not itself a
signal.

**AXON:** QUIC with TLS 1.3 raw public keys (§6.1). Raw public keys are a
comparatively rare TLS extension, and the handshake is fingerprintable.
**PAR-06's bridges do not fix this**: a pluggable transport used only by censored
users partitions the population into "normal" and "suspicious", which is a
weakness I2P avoided by never creating the distinction.

### 78.10 Testing your own tunnels

**I2P:** routers periodically send test messages through their own tunnels and
retire ones that stop working, so a tunnel does not fail for the first time when
real traffic needs it.

**AXON:** §8.4's state machine detects failure when a build or a stream fails.
There is no liveness probe for an idle `C_OPEN` circuit held as a pool spare,
which means a pool of spares can be a pool of dead circuits.

---

## 79. Where AXON Is Stronger, and What Each Advantage Costs

Stated with costs, because an advantage whose cost is unstated is a marketing
claim.

| Advantage | Over | What it buys | What it costs |
|---|---|---|---|
| **Per-hop AEAD on every layer** (§8.3) | Both. Tor's deployed relay crypto is an unauthenticated stream cipher with an end-to-end digest; I2P's layered construction is also not per-hop authenticated | Bit-level tagging collapses: a flip at hop 1 kills the cell at hop 2 instead of delivering a mark to hop 3 | 5.5 points of goodput (91.4 % vs Tor's 96.9 %), one AEAD op per relay per cell — **and, as specified, it does not actually close the channel; see §81.1** |
| **Corruption localisation** | Both | The client learns the deepest layer at which the chain broke, which upper-bounds the forger's position and feeds an attributable observation to the weighting function | Nothing, beyond the AEAD already paid for |
| **One QUIC stream per circuit** (R12) | Tor, which multiplexes every circuit onto one TLS connection | No cross-circuit head-of-line blocking; ordered delivery turns replay defence into an assertion rather than a window | A relay with 10,000 circuits holds 10,000 QUIC stream states; stream-open rate is metadata tracking circuit-build activity; UDP is more blockable than TCP 443 |
| **Bonded identities** (PoF) | Both. Tor vets relays through directory authorities; I2P has no admission cost at all | Sybil has a price, and the price is slashable | A blockchain dependency, and §7.7 is explicit that a price is not a barrier — a funded adversary buys their share |
| **Perishable keyspace positions** (§7.2) | Both | A DHT position cannot be ground and held: it expires every epoch and re-grinding needs new bonds | RANDAO last-revealer bias multiplies the eclipse probability by up to 2^k; a beacon outage stalls rotation |
| **On-chain naming with real ownership** | Both. Tor and I2P addresses are key hashes with no ownership semantics | Names are transferable, governed, and disputes have a venue | Enumeration is total — §7.7 says so plainly — and blinding buys nothing against an adversary who reads the chain |
| **Integrated erasure-coded storage** | Tor entirely; I2P mostly | Content survives its publisher going offline | An entire second attack surface, and shard IDs are a global correlation index |

**Four of these seven are real and hold today. One (per-hop AEAD) is
compromised by a defect found while implementing it. Two (bonded identities,
perishable positions) rest on a blockchain the network does not yet touch.**

---

## 80. The Parity Register

Severity is the damage if the gap is never closed, not the effort to close it.

| ID | Axis | Ahead | The gap | Our answer | Owner | Sev |
|---|---|---|---|---|---|---|
| **PAR-01** | construction | — | The §8.3 tag stack carries 16 unauthenticated attacker-chosen bytes per cell downstream, recreating the tagging channel the AEAD was adopted to remove | **Adopt** a non-malleable construction with no mutable unauthenticated field | **P5a** | **critical** |
| **PAR-02** | mechanism | Tor | No signed consensus, therefore no shared view of the relay population and no ground truth to detect an epistemic partition against | **Decline-with-reason on the authority model, adopt the property**: build a verifiable, diversity-anchored network view (§81.3). If that fails, revisit R14 rather than ship the gap | **P19** | **critical** |
| **PAR-03** | mechanism | I2P | No capacity measurement, so path selection is uniform (slow) or self-reported (gameable) | **Adopt I2P's local peer profiling.** No authority, no published weights, per-node observations only | **P12a** | high |
| **PAR-04** | mechanism | Tor | No vanguards; a service's second and third hops are freely reselected on every build, which is the guard-discovery attack | **Adopt** layered guards with staggered rotation | **P7a** | high |
| **PAR-05** | mechanism | Tor | Guard algorithm lacks a bounded *sampled* set, so a long-running adversary can enumerate a client by attrition | **Adopt** the sampled/filtered/confirmed/primary structure | **P7** (amended) | high |
| **PAR-06** | mechanism | Tor | No bridges, no unlisted relays, no transport obfuscation; R4(a) *publishes* the relay list | **Adopt** bridges and pluggable transports; carve an explicit exception to R4(a) for unlisted entry points | **P18** | high |
| **PAR-07** | construction | I2P | Bidirectional circuits: one hostile position sees both directions of a conversation | **Adapt** — offer directional separation as a per-isolation-context option, not a default | **P17** | high |
| **PAR-08** | mechanism | Tor | `RELAY_BUILD` budget is specified as "budget-limited" with no number | **Adopt** Tor's discipline: a fixed small cap, decremented per hop, plus refusal of `EXTEND` outside the class | **P5** (amended) | high |
| **PAR-09** | mechanism | Tor | No padding of any kind; codes allocated, nothing implemented | **Adopt** netflow padding first, then negotiated circuit padding | **P13** (amended) | medium |
| **PAR-10** | mechanism | I2P | No pre-built tunnel pools; a first request can pay a 35 s build | **Adopt** pre-building with spares | **P7** (amended) | medium |
| **PAR-11** | mechanism | Tor | Congestion control unmeasured and `[NEEDS RESEARCH]` | **Adopt** an RTT-signalled algorithm; measure before claiming | **P5b** | medium |
| **PAR-12** | mechanism | I2P | No message bundling, so message-count patterns are exposed and there is nowhere to put a delay | **Adapt** — bundling for control and service traffic; explicitly *not* a mixnet claim | **P20** | medium |
| **PAR-13** | mechanism | I2P | Unreachable nodes are visibly pure clients (R3's cost) | **Decline-with-reason**: R3 exists because unreachable relays black-hole circuits. Mitigate instead — see §81.5 | **P17** | medium |
| **PAR-14** | mechanism | Tor | No frozen wire specification, one implementation | **Adopt** a spec freeze; a second implementation is aspirational | **P21** | medium |
| **PAR-15** | population | both | No relays, no users, no external review | **Cannot be closed by building.** §83 | — | **critical** |
| **PAR-16** | mechanism | Tor | No proof-of-work admission for services under flood. R10 requires it, `IntroPointRecord` carries `pow_seed`/`pow_difficulty` for it, and the mechanism does not exist | **Adopt** a load-adaptive client puzzle at the intro point | **P6a** | **critical** |
| **PAR-17** | mechanism | Tor | The §7.5 diversity ladder's fourth rung — operator — is specified and unimplemented. "ASN diversity is not operator diversity" (§7.2) | **Adopt, and improve**: a bonded on-chain owner is not self-reported, unlike a declared family | **P12b** | high |
| **PAR-18** | mechanism | I2P | Fixed 3-hop paths, so length is known a priori and a relay at position 2 always knows it is the middle | **Adopt** variable length with a random component | **P22** | high |
| **PAR-19** | construction | I2P | Telescoping tells hop *k* it is not the terminal, and shows the guard every extension | **Adapt** — recover what telescoping permits (§81.7); the rest is an accepted cost of a construction chosen for other reasons | **P22** | high |
| **PAR-20** | mechanism | I2P | No session layer above the circuit, so circuit death costs a full rendezvous. R9 requires one and no phase owns it | **Adopt** a ratcheting session with forward secrecy | **P23** | high |
| **PAR-21** | mechanism | Tor | No relay-side admission control, no bandwidth caps, no circuit-creation rate limit. §8.4 names circuit-table exhaustion and stops there | **Adopt** a DoS-mitigation subsystem as a first-class component | **P24** | **critical** |
| **PAR-22** | mechanism | Tor | No process sandboxing. A relay compromise is total | **Adopt** syscall filtering and privilege separation | **P25** | high |
| **PAR-23** | mechanism | Tor | No client authorisation for services. `identity.BlindWithAuth` exists as a primitive and nothing uses it | **Adopt** — the primitive is already built | **P26** | medium |
| **PAR-24** | mechanism | Tor | No traffic splitting. Part VI specifies more than Tor deploys, and none of it is built | **Adopt** — a schedule gap, not a design gap | **Part VI** | medium |
| **PAR-25** | mechanism | I2P | No liveness probing of idle pool spares, so a pool of spares can be a pool of dead circuits | **Adopt** periodic self-testing | **P7** (amended) | medium |
| **PAR-26** | mechanism | I2P | QUIC + TLS 1.3 raw public keys is fingerprintable, and PAR-06's bridges make obfuscation a minority signal rather than the norm | **Adopt I2P's posture**: obfuscation is the default transport for everyone, not a mode for the censored | **P18** (amended) | high |
| **PAR-27** | mechanism | both | No bandwidth rate/burst limits, so an operator cannot bound what they contribute and a relay cannot bound what it absorbs | **Adopt** | **P24** | medium |
| **PAR-28** | mechanism | Tor | No counters for structurally valid cells arriving in impossible states — a signalling channel that survives every integrity check | **Adopt** drop counters with teardown thresholds | **P5** (amended) | high |

**Counts: 5 critical, 12 high, 9 medium, 1 population-bound — 27 gaps.**

Twenty-four of the twenty-seven are closed by adopting or adapting a mechanism
that already exists in a deployed system. **That is the finding of this whole
part: almost none of the deficit requires research. It requires building things
other people have already shown work.** Only PAR-02 is genuinely open, and PAR-19
is the one place where AXON's own construction choice imposes a cost that cannot
be fully recovered.

### 80.1 Coverage check

Every mechanism named in §77 and §78 appears in the register above. The check
matters because the failure mode of a parity audit is a list that stops when the
author runs out of memory rather than when the systems run out of mechanisms.

| Source | Mechanisms enumerated | Registered |
|---|---|---|
| §77 (Tor) | 14 | PAR-02, 03, 04, 05, 06, 08, 09, 11, 14, 16, 17, 21, 24, 28 |
| §78 (I2P) | 10 | PAR-03, 07, 10, 12, 13, 18, 19, 20, 25, 26 |
| Found in AXON's own code | 1 | PAR-01 |
| Not closable | 1 | PAR-15 |

Where a mechanism appears in both columns (local profiling, PAR-03) it is
registered once, against whichever system's design is being adopted.

---

## 81. Rulings

### 81.1 PAR-01 — the cell format must change `[BUILD NOW]`

**The defect, restated exactly.** §8.3 has each hop shift the tag stack left one
slot and write 16 random bytes into `TAG[H_max-1]`. Those bytes are not covered
by any AEAD — they cannot be, since the stack is rewritten in transit — and the
shift carries them downstream unchanged:

```text
a value written by hop i at TAG[3]
      appears at TAG[2] on the link hop i+1 → hop i+2
      appears at TAG[1] on the link hop i+2 → hop i+3
```

So any hop can write 16 attacker-chosen bytes per cell that every downstream hop
reads verbatim. **That is the tagging channel §8.3 claims to have removed**, in a
form that is narrower than Tor's (16 bytes, not arbitrary payload manipulation)
and *stealthier*, because it corrupts nothing and so triggers no integrity
failure at any intermediate hop. The claim in §8.3 that "the tagging channel
collapses" is false as specified.

It is not repairable by refreshing more slots. A hop does not know `H`, so it
cannot distinguish a filler slot from a live tag belonging to a hop beyond it.
Any construction in which a hop supplies unauthenticated bytes that survive to a
later hop has this channel, and any construction in which a downstream hop's tag
is visible upstream in cleartext has its mirror image.

> **RULING.** The rotating tag stack is **withdrawn**. Two constructions remain
> admissible, and P5a selects between them on evidence:
>
> **(a) Wide-block / tweakable-PRP over the payload.** No tags at all: the whole
> relay payload is a strong pseudorandom permutation under each hop's key, so any
> modification randomises the block and there is no unauthenticated field to
> abuse. §8.3's own alternatives table already calls this "the right long-term
> answer" and defers it to v2 on the grounds that it needs a cipher outside the
> Go standard library and its own security argument. **PAR-01 makes it a v1
> requirement**, because the construction it was deferred in favour of does not
> work. Tor's own published proposals are moving toward this class.
>
> **(b) Sphinx-style precomputed filler.** Constant-size cells with per-hop MACs
> covering the downstream material, using filler the client computes at build
> time. §8.3 declined this on the grounds that `internal/channel/onion.go`
> identified "filler must be computable at build time" as a hazard. The hazard is
> real; it is also a solved problem with two decades of literature.
>
> **What is NOT admissible:** shipping the tag stack and documenting the channel.
> A 16-byte-per-cell confirmation oracle between colluding relays is not a
> residual risk, it is the attack the layer exists to prevent.

#### 81.1.1 Decision: (a), and why (b) was not a real alternative `[BUILT]`

Working the two options through collapsed them into one, and turned up a third
that looked obvious and is worse than either.

**The third option, and why it fails.** Nest the AEADs: let layer *i* cover layer
*i+1*'s ciphertext **and its tag**, so there is no external field at all. The
channel closes. But an AEAD expands by 16 bytes per layer, so the ciphertext
length differs at every layer — hop 1 opens over 992 bytes, hop 2 over 976, hop 3
over 960 — and **each hop must know its own index to know how many bytes to
open.** That is a position leak at every hop, which is worse than the defect
being repaired. Padding back to a fixed size does not save it: the padding a hop
appends is then visible to the next hop, and while that particular channel is
only one hop deep and therefore harmless between peers who already know they are
adjacent, the length-dependent open is not repairable at all.

**Why (b) is not an alternative to (a).** Sphinx's precomputed filler solves the
**header** — the per-hop MACs and routing material. Its **payload** is handled by
a wide-block permutation (LIONESS) for exactly the reason above: nothing else
gives non-malleability at zero expansion. Sphinx does not avoid the primitive
(a) needs; it contains it.

> **RULING. Option (a). Zero expansion, per-hop non-malleability and no external
> mutable field are jointly satisfiable only by a wide-block PRP, and both roads
> arrive there.**
>
> **Construction: LIONESS** (Anderson & Biham, 1996) — an unbalanced four-round
> Feistel network over an arbitrary-length block, built from a stream cipher and
> a keyed hash. Four Feistel rounds with independent pseudorandom round functions
> give a **strong** pseudorandom permutation, secure against chosen-ciphertext
> attack, by the Luby–Rackoff result. That is E5a.2's security argument, and it
> is a citation rather than an assertion. The same construction is used by Sphinx
> and Mixminion. Built from ChaCha20 and HMAC-SHA256 — both already dependencies,
> neither invented here.
>
> **Tweak: the per-direction cell counter**, which is not optional. Without it
> the permutation is fixed for the circuit's life, identical plaintexts give
> identical ciphertexts, and a relay recognises a repeated cell — a correlation
> channel of exactly the kind being removed.
>
> **Authentication: end-to-end, inside the innermost plaintext.** A tag outside
> the permutation would be a mutable unauthenticated field, which is the defect.
> Inside, any modification by any hop randomises the whole block and the
> terminal's check fails.

**What it buys.**

| Property | Withdrawn tag stack | LIONESS |
|---|---|---|
| Cross-hop channel | **16 bytes/cell, every downstream hop** | none — E5a.1 measured **0 hits over 10⁶ cells** |
| Position evidence in the format | slot index hidden by rotation | **none** — every hop runs the identical operation over the identical 1008 bytes, with no index available to it |
| Expansion | 64 B tag stack (6.25 %) | **zero** |
| Relay payload | 944 B | **990 B** — the tag stack is reclaimed |
| Randomness a hop supplies | 16 B/cell — *the channel* | **none** |

**What it costs, stated because it retracts two published claims.**

> **AMENDMENT to §8.3.** The sentence *"hop i+1 finds out immediately and tears
> the circuit down"* **no longer holds.** A PRP has no authenticator, so an
> intermediate hop cannot detect that a cell was corrupted upstream; it forwards
> randomised bytes and the terminal's end-to-end check catches it. §8.3's
> tagging-channel argument survives — a flip at hop 1 still cannot deliver a mark
> to hop 3 — but it now survives because the flip randomises the block, not
> because hop 2 notices.

> **AMENDMENT to §8.9.** The property that *"the client learns the deepest layer
> index at which the chain broke, which UPPER-BOUNDS the position of the
> forger"* **is withdrawn.** There are no per-layer checks to fail, so the client
> learns that the chain broke and not where. The attributable observation §8.7's
> weighting function was promised is no longer available from this source.

Both losses are real. The trade is taken because **a tagging channel is a
confirmation oracle between colluding relays and per-hop detection is a
diagnostic**: the first breaks anonymity, the second improves attribution. When
they conflict, anonymity wins. `TestEndToEndAuthCatchesTampering` asserts the
regression — that no intermediate hop notices — so the retraction lives in the
suite and not only here.

**Consequential change to §8.1.** The tag stack is removed from the cell. The
body is one 1008-byte permuted block, and the relay payload grows from 944 to
990 bytes once the end-to-end tag and length prefix are accounted for. §8.1's
goodput arithmetic improves from 91.4 % to **96.7 %**, which is within a rounding
error of Tor's 96.9 % — so the 5.5 points §8.3 gave up to get per-hop
authentication are returned, and the property is stronger than what they bought.

**Consequences.** §8.1's cell diagram changes; `link.Cell`'s `Tags` field and
`TagStackSize` are provisional until P5a rules. The payload arithmetic is
unaffected in the wide-block case (944 bytes of relay payload, since the 64 tag
bytes become part of the permuted block or are reclaimed). P6 and P7 must not be
built against the current format.

### 81.2 The defect's origin, recorded

The tag stack was specified to give position-hiding: every hop reads `TAG[0]`,
so no hop learns its index from which slot verified. That goal is real and
§8.3's reasoning for it is sound. **The error was solving position-hiding with a
mutable unauthenticated field, and then not asking what else that field could
carry.** It is the same class of defect as the cell-padding covert channel found
by `FuzzDecode` during P2 — attacker-chosen bytes forwarded by every relay —
and it was found the same way: by writing the test that tries to abuse the
mechanism rather than the test that confirms it works.

Both constructions in §81.1 preserve position-hiding: a PRP has no slots at all,
and Sphinx's filler is indistinguishable from real material by construction.

### 81.3 PAR-02 — the consensus question, with R14 on the table

R14 refuses a consensus document. Tor's consensus is what makes epistemic
partition hard. Both cannot be true at once, and §18's T-L3-04 already concedes
the problem is unsolved.

The options, honestly:

| Option | What it gives | What it costs |
|---|---|---|
| **Keep R14, solve it** | No authority to capture, coerce, or subpoena | It is `[UNSOLVED]` in §18 and across Part V. A roadmap cannot schedule a solution to an open problem |
| **Keep R14, bound it** | Cross-check views obtained through *independently chosen* circuits and *different* bootstrap sources, and alarm on divergence. Detects partition without a ground truth | Detection, not prevention. A fully consistent adversary is undetectable. This is P19's actual deliverable |
| **Revisit R14: a threshold-signed, diversity-anchored network document** | Tor's property. A client compares its view against a signed artefact and a partition needs a threshold compromise | Reintroduces exactly the authority R14 exists to refuse, and every governance failure that comes with it |

> **RULING.** P19 builds the *bounding* option, because it is buildable and
> because detection is strictly better than the nothing we have. **R14 is not
> repealed, and it is not defended either** — it is marked as the one ruling in
> the Constitution that a parity requirement puts under genuine pressure. If P19
> demonstrates that detection without a ground truth cannot reach a useful
> false-negative rate, the honest conclusion is that R14 costs more than it buys,
> and the Constitution changes rather than the claim being quietly softened.

### 81.4 PAR-03 — adopt local profiling, and keep P3's separation

I2P's answer to measurement-without-authority is imported wholesale. The design
constraint that makes it safe is one AXON already has: **P3's peerbook records
observations and explicitly does not score them.** The scoring layer sits above,
per node, and its inputs never leave the node — no published weights, nothing to
game globally, and a raw observation that still exists to disagree with.

The limits, adopted along with the design: a fresh node's profile is empty and
must fall back to uniform selection; profiling measures only peers you use, so it
cannot see a peer that is good to you and hostile to everyone else; and a
capacity tier derived from your own traffic is a fingerprint of your own traffic
if it ever escapes the node.

### 81.5 PAR-07 and PAR-13 — directional separation as an option, not a default

I2P's unidirectional tunnels are a real advantage and a real cost. The ruling
splits the difference rather than pretending there is no trade:

> **RULING.** Directional separation is available per isolation context, off by
> default, and **mandatory for anonymous services** — the role where an adversary
> gets to induce arbitrary circuit builds and therefore benefits most from seeing
> both directions. `INTERACTIVE` client browsing keeps bidirectional circuits by
> default because doubling build cost and latency for that path buys less than
> it costs, and a network people will not use protects nobody.

On PAR-13: R3's reachability gate stands, because a relay nobody can reach is a
path that fails silently. The mitigation is to stop making the client/relay
distinction *observable from the outside*: an unreachable node still advertises
`client` and `storage-tunnel` roles, still maintains tunnels, and still carries
other nodes' traffic through those tunnels, so "does not accept inbound" stops
implying "originates everything it sends".

### 81.6 What we decline, and why

| Declined | Reason |
|---|---|
| An exit role to clearnet | §18.3. Not a parity gap — a deliberate scope choice. Every exit-related abuse, legal, and blocking problem Tor carries is one AXON does not |
| Directory authorities as Tor operates them | §81.3. Under review rather than declined outright |
| Everyone-relays-by-default (I2P) | R3. A relay that cannot accept inbound is a black hole; the anonymity benefit is real but is bought by degrading routing for everyone. Mitigated per §81.5 instead |
| Full mixnet delays | Constitution §7 scopes the end-to-end correlating adversary out. Claiming mixnet properties without mixnet delays is the specific dishonesty this document exists to avoid |

---

## 82. New and Amended Phases

### 82.1 New phases

| Phase | Closes | Depends on | Status |
|---|---|---|---|
| **P5a — Non-malleable cell construction** | PAR-01 | P2 | `[BUILD NOW]` — **blocks P5 completion, P6 and P7** |
| **P5b — Measured congestion control** | PAR-11 | P5 | `[NEEDS RESEARCH]` then build |
| **P7a — Vanguards and guard-discovery resistance** | PAR-04 | P7 | `[BUILD NOW]` after P7 |
| **P12a — Local peer profiling** | PAR-03 | P3, P12 | `[BUILD NOW]` |
| **P17 — Directional path separation** | PAR-07, PAR-13 | P7 | `[BUILD NOW]` |
| **P18 — Bridges and pluggable transports** | PAR-06 | P2, P3 | `[BUILD NOW]` |
| **P19 — Partition detection without a consensus** | PAR-02 | P4, P12a | `[NEEDS RESEARCH]`, bounded deliverable |
| **P20 — Message bundling** | PAR-12 | P5a, P6 | `[BUILD NOW]` |
| **P21 — Wire specification freeze** | PAR-14 | P5a, P16 | `[BUILD NOW]` |

### 82.2 Amendments to existing phases

| Phase | Amendment |
|---|---|
| **P5** | Add T5.8: `RELAY_BUILD` cells are capped at a fixed count per circuit, decremented at every hop, and an `EXTEND` arriving in a plain `RELAY` is refused (PAR-08). The cap is a number in `params`, not a word in prose |
| **P7** | Add the bounded *sampled* guard set with the filtered/confirmed/primary structure (PAR-05), and pre-built pool spares so a first request never pays a cold build (PAR-10) |
| **P13** | Netflow-level link padding is promoted ahead of circuit padding machines: it is simpler, it defends a real and currently undefended observation, and it does not need negotiation (PAR-09) |
| **P16** | Release signing gains a second signer and a published, verifiable key set. One signer is one subpoena |

### 82.3 Sequencing

```text
P5a  ──blocks──▶  P5 (completion) ──▶ P6 ──▶ P7 ──▶ P7a
                                              │
                                              ├──▶ P17
                                              └──▶ P20
P3 ──▶ P12a ──▶ P12 (weighting)  ──▶ P19
P2 ──▶ P18                       ──▶ P16 ──▶ P21
```

**P5a is the only item that blocks work already in progress.** Every other row
can be scheduled without stalling the build, which is why PAR-01 is the one gap
this document treats as urgent rather than merely important.

---

## 83. What Parity Does NOT Buy

Closing every row in §80 leaves AXON with a construction at least as strong as
Tor's, mechanisms comparable to both systems, and **no users.**

```text
Tor      ~8,000 relays, millions of daily users, 20+ years of published attacks
I2P      tens of thousands of routers, two decades of operation
AXON     9 nodes, none carrying anonymous traffic, zero external review
```

Anonymity is a property of a crowd. A perfect construction with one user
anonymises nobody, and every claim this document makes about circuits, blinding,
diversity, or padding is bounded by that. **Nothing in Part IX changes it, and no
phase in Part IX should be read as making AXON safe to rely on.**

Three specific things that remain true after full parity:

1. **An adversary observing both ends still wins.** Neither Tor nor I2P nor AXON
   defends against this, Constitution §7 scopes it out, and parity does not
   change it.
2. **Nobody hostile has looked at this.** Tor's strength is substantially the
   accumulated result of published attacks and the fixes they forced. AXON has
   had none of that. The three adversarial review passes commissioned over
   Parts I–VIII have never run, and PAR-01 — a defect in the layer the whole
   design rests on, found by writing one test — is a fair estimate of what a
   real review would surface.
3. **The population gap may be permanent.** Most anonymity networks never
   acquire a crowd. A design that is honest about this is more useful than one
   that assumes users arrive because the cryptography is good.

> **The standard this part sets: AXON may claim parity of *construction* and
> *mechanism* once §80 is discharged, and must never claim parity of
> *protection* until it has a population and an adversarial history. The first
> two are engineering. The third is not for sale.**
