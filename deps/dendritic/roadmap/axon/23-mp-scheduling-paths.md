## 44. Packet Scheduling

### 44.1 The scheduler is a fingerprint before it is an optimiser

A scheduler that reacts to path conditions **encodes those conditions into the
traffic pattern**, and an observer on one path can infer the state of the others
from the gaps it sees. A perfectly adaptive scheduler is a side channel that
reports the network's condition to every observer simultaneously.

This inverts the usual design order. The scheduler is chosen first for what it
leaks, then tuned for throughput within that constraint:

| Strategy | Throughput | Latency | What it leaks to a single-path observer |
|---|---|---|---|
| **Round-robin** (fixed) | Poor — slow path throttles all | Poor | **Nothing.** Gap structure is deterministic and independent of other paths |
| **Weighted, static** | Fair | Fair | Almost nothing; weights are fixed at session start |
| **Weighted, slowly adapted** | Good | Good | Path capacity ratios, at the adaptation timescale |
| **RTT-aware (lowest-RTT-first)** | Good | **Best** | Relative RTTs of all paths, continuously |
| **Fully adaptive / learned** | Best | Best | **The full state of every path**, continuously |

**Ruling (R21): the adaptation timescale is a privacy parameter and is bounded by
the mode (§49), not by the optimiser.** `PRIVACY` mode uses static weights fixed
at session establishment. `PERFORMANCE` mode adapts freely. The rate of
adaptation is the dial, and it is exposed to the user as a mode rather than as a
number.

### 44.2 The scheduling algorithm

Within the timescale the mode allows:

```text
   for each cell to send:
     eligible = { p ∈ paths : cwnd_p > in_flight_p ∧ state_p = READY }
     if eligible = ∅: block (backpressure to the stream, §45.3)

     PRIVACY:      choose p by static weight wᵢ, refreshed only on path-set change
     BALANCED:     choose p minimising  in_flight_p / rate_p     (est. drain time)
     PERFORMANCE:  choose p minimising  in_flight_p / rate_p + RTT_p / 2
     RELIABILITY:  as BALANCED, plus duplicate the cell on the next-best path
                   when flags & CRITICAL (session setup, retransmission of a
                   range already stalled once)
```

`in_flight/rate` is the standard drain-time heuristic and it degenerates
gracefully: with equal paths it is round-robin, with one dead path it stops
selecting it without needing a separate failure signal.

**Redundant scheduling is deliberately narrow.** Duplicating everything doubles
relay consumption for a latency gain, which R20 forbids as a default. Duplication
applies to session-setup cells and to a range that has already stalled once —
the cases where the latency cost of loss is highest and the volume is lowest.

### 44.3 Experimental comparison

The four strategies are compared under a common matrix — path count `{1,2,4,8}`,
heterogeneity `{uniform, 2:1, 10:1}`, loss `{0, 0.1 %, 1 %}`, and a path-failure
event — reporting goodput, p50/p99 latency, buffer occupancy, cells wasted to
duplication, and **the leak metric**: how accurately an observer on one path can
estimate the other paths' capacities from its own gap structure. A strategy that
wins on goodput and loses on the leak metric does not win.

---

## 45. Congestion Control and Fairness

### 45.1 Paths are not independent, and naive multipath is an attack on the network

The assumption that N paths are N independent bottlenecks is false in an onion
network. Paths share relays by construction — a shared guard set (§42.4) means
**every path shares its first hop** — and relay capacity is the scarce resource.
Running N uncoupled congestion controllers over paths that share a bottleneck
takes N times the share of that bottleneck that a single flow would get.

```text
   Uncoupled:   N flows across a shared relay  →  N× the fair share
                A user who raises N takes capacity from everyone else,
                and the network rewards the most aggressive client.

   Coupled:     the controllers share a congestion window budget, so
                total aggressiveness ≈ that of one flow, while still
                shifting traffic toward the less congested path.
```

**Ruling (R22): congestion control is coupled across the paths of a logical
session.** This is the MPTCP coupled-congestion-control result (the LIA/OLIA/
BALIA family) adapted to cells over circuits; it is adopted rather than
reinvented, per §42.2. The design goals it must preserve are the standard three:
do no harm at a shared bottleneck, take as much as the best single path would,
and shift traffic away from congestion.

### 45.2 Two control loops, and the interaction is a real hazard

§8.8 already specifies circuit-level flow control. Adding L4.5 congestion control
means two loops:

| Loop | Scope | Signal | Purpose |
|---|---|---|---|
| Circuit flow control (§8.8) | One circuit, hop to hop | Circuit-level acknowledgement | Stops a fast sender overrunning a relay |
| Multipath congestion control (§45) | The logical session | Loss, delay, per-path drain rate | Allocates across paths, bounds aggregate rate |

The hazard is the same one that rules out QUIC-over-QUIC (§42.2): the outer loop
reads the inner loop's backpressure as congestion and backs off twice.
Mitigation: L4.5 treats circuit-level backpressure as an **explicit capacity
signal, not a loss signal** — the path is marked `not READY` and skipped by the
scheduler without shrinking `cwnd`. This must be tested explicitly (MP3, §50),
because the failure mode is a slow collapse in throughput that looks like
congestion and is actually two controllers arguing.

### 45.3 Backpressure to the application

When no path is eligible, the substrate blocks the logical stream rather than
buffering without bound. Unbounded sender-side buffering is how a multipath layer
turns a network problem into a memory-exhaustion problem, and §43.3 has already
shown the receive side is memory-constrained.

### 45.4 Fairness between users, and the accounting hook

Coupled congestion control gives one *session* the share of one flow. It does not
stop one user opening many sessions. That is the same commons problem as R20 and
it has the same answer: the number of concurrent multipath sessions and their
path counts are resources the accounting plane (§14) can price, and until that
exists they are bounded by conservative local defaults. **A network with no
accounting and unbounded multipath is a network where the greediest client wins**,
and that should be stated in the operator documentation rather than discovered.

---

## 46. Path Lifecycle and Diversity

### 46.1 Diversity is a joint constraint, not a per-path one

The brief's point is correct and the specification already has the machinery:
§8.7's path selection applies diversity constraints within a circuit, and
`internal/placement` applies failure-domain diversity to storage. Multipath needs
those constraints applied **across** the path set:

```text
   Within one path (existing, §8.7):   no relay repeated; distinct /16; distinct ASN
   Across the path set (new):
     ├── no middle or terminal relay shared between two paths
     ├── no two paths sharing an ASN at the middle or terminal position
     ├── no two paths sharing a /24 (v4) or /48 (v6) at any position
     ├── no two paths sharing an operator, where operator is known
     └── guards ARE shared, deliberately (§42.4) — the one exception
   Soft preferences:
     └── geographic and data-centre spread, best-effort, never a hard constraint
         because it degrades to nothing in a small network
```

**The small-network problem, stated rather than hidden:** these constraints are
unsatisfiable below a few hundred relays with adequate ASN spread. The path
builder must degrade *explicitly* — returning fewer paths than requested, with a
reason — rather than silently relaxing diversity to fill the quota. A multipath
session with 4 paths that share an ASN provides the throughput of 4 paths and the
failure and correlation domain of 1, and a substrate that does this quietly is
worse than one that returns 2 paths and says so.

### 46.2 Lifecycle

```text
   REQUESTED ──► BUILDING ──► PROBING ──► READY ⇄ DEGRADED ──► DRAINING ──► DEAD
                     │            │          │                      ▲
                     └── fail ────┴──────────┴──── quarantine ──────┘
```

| State | Meaning | Scheduler behaviour |
|---|---|---|
| `PROBING` | Circuit built, capacity unknown | Small share only, to measure without committing |
| `READY` | Measured and healthy | Full participation |
| `DEGRADED` | Loss or RTT beyond threshold | Share reduced; not yet removed |
| `DRAINING` | Being replaced; no new cells | Outstanding ranges retransmitted elsewhere |
| `QUARANTINED` | Failed recently | Not reselected for a back-off interval; the relay set is remembered so the replacement does not rebuild the same path |

Replacement is **build-ahead**, reusing §9.2's tunnel-pool discipline: a spare
path is maintained warm so that a failure is a promotion rather than a
construction. Since §9.2 already builds ahead at 70 % of a 10-minute lifetime,
multipath adds a spare per session rather than a new mechanism.

### 46.3 Path replacement is an observable event

When a path fails, the traffic it carried moves to the others. **An observer on a
surviving path sees its own share rise**, which reveals that a sibling path
failed, and — over repeated failures — how many siblings there are. Combined with
the substrate's response timing, this is a channel that leaks the path count.

Mitigations, none complete: rate-limit the redistribution so the shift is gradual
rather than a step; keep total send rate flat during transition by drawing down
the spare's `PROBING` traffic; and in `PRIVACY` mode, **drop the session's
aggregate rate to the surviving capacity rather than redistributing**, accepting
the throughput loss to avoid the signal. Residual: repeated path churn under an
adversary who can cause failures is a reliable path-count oracle, and this is an
accepted cost recorded in §48.

### 46.4 Simultaneous failure

If all paths fail, the `LogicalSession` survives — it holds keys and sequence
state independent of any path (§47) — and enters `RECOVERING`: rebuild from the
guard set, resume from the last acknowledged `global_seq`. §9.8's session
resumption already specifies the replay and hijack protections this needs, and
the multipath case adds only that the resume must be idempotent across a partial
path set. Bounded by a session timeout, after which the application sees a
connection failure rather than an indefinite stall.

---

## 47. Path-Level Cryptography

### 47.1 Two independent key hierarchies, and why the separation is required

```text
   SESSION LAYER (L4.5)        one key set per LogicalSession
      │   established once, at rendezvous (§9.5) or exit handshake
      │   independent of every path; survives all path churn
      │   provides end-to-end confidentiality and integrity
      ▼
   PATH LAYER (L4)             one key set per circuit, per hop
          ntor-style per-hop keys (§8.2); per-hop AEAD (§8.3)
          rotates with the circuit; never shared between paths
```

The separation is what makes path addition and removal safe. If the session key
were derived from path keys, adding a path would require rekeying the session and
removing one would strand the material — and an adversary who compromised one
path's keys would gain a foothold on the logical stream. With the hierarchy
above, **a fully compromised path yields the adversary exactly what that path
carried: ciphertext under a session key it does not hold.**

### 47.2 The nonce hazard, which is the one thing that will be got wrong

One session key used across N paths means N senders drawing from one nonce space.
Nonce reuse under a single AEAD key is catastrophic, and concurrency across paths
is exactly the condition that produces it.

**Requirement, non-negotiable: the session AEAD nonce is partitioned by
`path_id`.**

```text
   nonce = path_id (8 bits) ‖ per_path_counter (88 bits)

   ├── each path draws from a disjoint region; no coordination needed
   ├── path_id is never reused within a session, even after a path dies —
   │   the counter of retired ids is never reset and the id is retired with it
   └── exhaustion of a path's counter forces a session rekey, not an id reuse
```

The retired-id rule is the subtle half: a naive implementation reassigns
`path_id` 3 to a replacement path and resumes the counter at zero, which is nonce
reuse under the same key. **This must be a test, not a comment** — it belongs in
§21's security-property table with a negative test that fails the build.

### 47.3 Forward secrecy across path-set change

| Event | Session key | Path keys | Exposure |
|---|---|---|---|
| Path added | Unchanged | New, from a fresh handshake | New path cannot read prior traffic on other paths |
| Path removed | Unchanged | Discarded | Nothing retained on that path |
| Path compromised | Unchanged, **and this is a deliberate choice** | Adversary holds that path's keys | Only the cells that path carried, still under the session key |
| Session rekey (periodic, or on counter exhaustion) | New | Unchanged | Prior traffic unreadable with the new key |

The deliberate choice is not rekeying the session on every path change: doing so
would make path churn — which is frequent and adversary-inducible (§46.3) — into
a rekey oracle and a performance cost. Instead the session ratchets on a timer
and on counter exhaustion, and the residual is that a session key compromise
exposes the whole session rather than one path's worth. That is the correct trade
only because path compromise is far more likely than endpoint compromise, and if
that assumption fails the trade should be revisited.

### 47.4 What relays can and cannot see

| Party | Sees | Does not see |
|---|---|---|
| A relay on one path | Cells; their timing and volume on that path | `session_id`, `global_seq`, `path_id`, payload — all inside the session layer (§43.2) |
| All relays on one path, colluding | That path's full cell flow | The other paths; the logical stream's content or extent |
| Relays on two paths, colluding | Two cell flows | **That they belong to the same session — except by timing and volume correlation**, which is §48's subject and the reason multipath is a privacy question |
| The exit (clearnet only) | The reassembled stream and the destination | The client's identity, subject to §48 |
| The service (overlay-internal) | The reassembled stream | Path structure, beyond path count |
