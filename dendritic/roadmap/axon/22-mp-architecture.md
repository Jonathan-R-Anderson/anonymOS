# Part VI — Multipath Transport and Traffic Aggregation

**A substrate that distributes one logical connection across several independent
overlay paths — and an honest account of what that costs.**

---

## 41. The Finding That Shapes Part VI

**Multipath is two mechanisms with opposite privacy signs, and they must never be
evaluated together.**

```text
   Against a SINGLE-POINT observer          Against a MULTI-POINT observer
   (website fingerprinting, §32.1a)         (flow correlation, §32.1b)
   ────────────────────────────────         ──────────────────────────────
   Each observer sees only 1/N of the       The adversary now has N chances
   trace. Burst structure, volume and       to be on a path instead of one,
   timing are all fragmented.               and the N sub-flows share a
                                            global sequence structure that
   MULTIPATH HELPS — and it is one of       LINKS them to each other.
   the few defences that helps here
   without paying padding overhead.         MULTIPATH HURTS.
```

The second effect deserves emphasis because it is a *new* primitive rather than a
quantitative worsening: splitting one logical stream across N paths creates N
flows that an adversary can **confirm belong together** from their interleaved
global sequence numbers and their complementary gap structure. A single-path
design offers no such confirmation. An adversary sitting on two of four paths
learns not only that it holds two flows, but that those two flows are the same
user's — which is exactly the linkage the anonymity layer exists to prevent.

Two consequences bind the rest of Part VI:

1. **Performance aggregation and anonymity are separate optimisation objectives**
   and are given separate metrics, separate targets and separate modes (§49).
   The roadmap must never report a throughput gain as though it were free.
2. **The relay-exposure arithmetic changes.** With `N` paths of 3 hops and pinned
   guards shared across paths, the client's traffic passes through `1 + 2N`
   distinct relays instead of 3:

   | `N` | Distinct relays touched | `P(≥1 hostile relay)` at `f = 0.05` | at `f = 0.10` |
   |---|---|---|---|
   | 1 | 3 | 0.143 | 0.271 |
   | 2 | 5 | 0.226 | 0.410 |
   | 4 | 9 | 0.370 | 0.613 |
   | 8 | 17 | 0.582 | 0.833 |

   Each hostile relay sees only `1/N` of the stream, which is the §41 trade in
   numbers: **more observers, each with less.** Whether that is a net gain
   depends entirely on which adversary is being modelled, and §48 is where it is
   settled rather than asserted.

### 41.1 What is actually gained, and it is not linear bandwidth

The brief's framing — 50 + 30 + 20 Mbps ≈ 100 Mbps — is the outcome multipath
almost never delivers in an onion network. The binding constraints, in the order
they usually bind:

| Constraint | Why it binds | Does adding paths help? |
|---|---|---|
| **Client uplink** | All paths share it | **No.** If the client's own link is the bottleneck, aggregation gains exactly zero |
| **Exit / far-side capacity** | For clearnet, all paths converge (§42) | **No**, when one exit terminates the connection |
| **Reassembly buffer** | Buffer ≥ `RTT_max × Σ rᵢ` | No — it is a *cost* that grows with paths |
| **Slowest-path head-of-line blocking** | One stalled path blocks the receive window | No, and it can make throughput *worse* than single-path |
| **Per-relay share** | Volunteer relays are the scarce resource | Yes — this is the real source of gain |
| **Per-path latency** | Scheduler can pick the faster path per chunk | **Yes — and this is the most reliable gain of all** |

**The honest expectation: the dependable wins from multipath are latency,
resilience and tail-behaviour, not throughput multiplication.** Throughput gain
is real only when the per-relay share is the binding constraint and the client
uplink is not — which in a bandwidth-starved volunteer network is common enough
to be worth building for, but is not the default case and must be measured
(MP6, §50).

This is the same conclusion Tor's deployed traffic-splitting work reached: the
benefit is dominated by choosing the better path per chunk rather than by summing
capacity, and the design there deliberately keeps a *shared exit* for reasons
§42.3 develops.

### 41.2 The capacity-ethics problem, stated early

A client using `N` paths consumes `N` relays' scarce capacity for one user's
traffic. In a volunteer network this is a commons problem, and an aggressive
default turns AXON into a system where the users who configure the most paths
receive the most of a donated resource.

**Ruling (R20): path count is a policy the accounting plane may price, and the
default is conservative.** `N = 2` for interactive, `N ≤ 4` for bulk, higher only
where §14's accounting exists to charge for it. A performance mode that consumes
8 relay-paths per connection is a mode for a paying user or a well-provisioned
private deployment, not a default.

---

## 42. Architecture and Layer Placement

### 42.1 The new layer

Multipath goes **above the circuit layer and below the stream API** — a new L4.5
in §3's stack, and it is genuinely a separate layer rather than a feature of L4:

```text
  L8   INFRASTRUCTURE API        one logical connection, N is not visible
  ─────────────────────────────────────────────────────────────────
  L4.5 MULTIPATH TRANSPORT       split · schedule · reassemble · recover
         │   global sequence space, one logical session
         │
  L4   TUNNEL / CIRCUIT          N independent circuits, each 3+ hops
         │   per-circuit cells, per-hop AEAD, per-circuit keys (§8.3)
  L3   DHT · L2 PEER · L1 TRANSPORT · L0 INTERNET
```

The separation the brief asks for, stated as the rule §3's layer contract already
implies: **routing decides how traffic moves; the multipath substrate decides how
it is distributed.** L4.5 may ask L4 for a path with stated properties; it may
not choose relays, see IP addresses, or influence circuit construction beyond a
diversity request. L4 may report a path's observed capacity and liveness; it may
not see the logical stream.

### 42.2 Why not simply run multipath QUIC end-to-end

The obvious implementation — run Multipath QUIC between client and exit, over
circuits — is rejected, and the reason is worth stating because it will be
proposed again:

| Approach | Verdict | Reason |
|---|---|---|
| Multipath QUIC end-to-end over circuits | `REJECTED` | **Nested congestion control.** L1 links are already QUIC (§6.1). QUIC-over-QUIC gives two loss-recovery loops per hop, and the outer loop interprets inner-loop retransmission as congestion. This is a known pathology and the overhead compounds per hop |
| MPTCP | `REJECTED` | Needs kernel support and TCP options on the wire; incompatible with fixed 1024 B cells (§8.1); leaks a distinctive option fingerprint |
| Custom transport over the existing circuit abstraction | **`ADOPTED`** | Cells are already the unit; circuits already provide ordered, authenticated delivery per path; only sequencing, scheduling and reassembly need adding |
| Custom congestion control | `REJECTED` | §13's rule against inventing primitives extends here. The coupled-congestion-control literature from MPTCP (the LIA/OLIA/BALIA family) is adapted, not replaced — §45 |

So: **a purpose-built multipath layer over AXON circuits, reusing published
scheduling and coupled-congestion-control algorithms.** New code, no new
algorithms.

### 42.3 The topologies, and which are architecturally sound

This is the part of the brief that needs the sharpest answer, because two of the
three proposed topologies have a structural problem.

**(a) Overlay-internal: client ↔ anonymous service. `SOUND`.**

```text
            ┌─ G ─ M₁ ─ RP₁ ─┐
  Client ───┼─ G ─ M₂ ─ RP₂ ─┼─── Service        both ends are the endpoints
            └─ G ─ M₃ ─ RP₃ ─┘                    reassembly happens AT them
```

The service is the endpoint, so it reassembles. **No aggregator node exists, and
therefore no node sees the whole flow.** This is the clean case and it is the one
AXON should build first — it is also the case that matters most, since AXON's
purpose is anonymous services rather than clearnet exit.

**(b) Clearnet exit, single exit. `SOUND BUT LIMITED`.**

```text
            ┌─ G ─ M₁ ─┐
  Client ───┼─ G ─ M₂ ─┼─ Exit ─── Internet
            └─ G ─ M₃ ─┘
```

The exit terminates the TCP/QUIC connection to the destination, so it must
reassemble. It therefore sees the entire logical flow — which means **path
diversity buys nothing against the exit.** The N paths defend against middle
relays and against network observers on individual paths, and against nothing
else. This is the deployed-Tor shape and it is honest as long as its limit is
stated: multipath here is a defence against *middles and observers*, never
against the exit.

**(c) Clearnet exit, multiple exits with a separate aggregator. `REJECTED`.**

```text
            ┌─ … ─ Exit A ─┐
  Client ───┼─ … ─ Exit B ─┼─ Aggregator ─── Internet     ← the super-node
            └─ … ─ Exit C ─┘
```

The aggregator sees the full logical flow *and* the identity of every exit. It is
precisely the "centralised super-node that sees all traffic" the brief warns
against, and it is strictly worse than (b): (b)'s exit sees the flow, and (c)'s
aggregator sees the flow *plus* the path structure, while adding a node whose
compromise is catastrophic and whose operation is a standing correlation point.
**A separate aggregator node is not adopted in any mode.**

The general rule, which is the answer to the brief's §10 question:
**aggregation must happen at an endpoint, never at an intermediary.** Where both
ends are inside the overlay, that is free. Where one end is the clearnet, the
exit is the endpoint and the limit in (b) applies.

### 42.4 Decision table

| Decision | Problem it solves | Derived from | What we changed | Alternatives rejected | New vulnerability |
|---|---|---|---|---|---|
| Multipath at L4.5, above circuits | Aggregation without coupling to routing | Tor's circuit-splitting work; MPTCP's layering | Operates on cells over circuits rather than packets over IP | Multipath QUIC end-to-end (nested CC); MPTCP (kernel, fingerprint) | A new layer with its own state, its own bugs, and its own fingerprint |
| Endpoint-only aggregation | Avoids a super-node | Tor's shared-exit approach | Stated as a general rule and applied to the overlay-internal case, which Tor has no analogue for | Separate aggregator node (§42.3c) | For clearnet, the exit still sees everything |
| Shared guard set across paths | Stops entry exposure multiplying by N | §28's layered guards | Guards pinned per isolation context, not per path | Independent guards per path (multiplies §28.1's exposure by N) | Concentrates all paths' entry at one or two relays — a shared failure and correlation point |
| Conservative default `N` (R20) | Volunteer capacity is a commons | None — this is an AXON-specific consequence of §14 | Path count becomes an accounted resource | Unbounded client-chosen N | Users perceive the default as slow and raise it, defeating the policy |

---

## 43. The Multipath Transport Substrate

### 43.1 Object model

```text
  LogicalSession        one per (client, destination) — survives path churn
     ├── session key material, independent of any path (§47)
     ├── global sequence space
     ├── reassembly buffer + receive window
     ├── retransmission state
     └── PathSet
          ├── Path 1 { circuit_id, per-path seq, cwnd, RTT est, loss est, state }
          ├── Path 2 { … }
          └── Path N { … }
```

The `LogicalSession` is the §9.8 session object extended, not a new concept:
sessions already survive circuit death, and multipath is that property
generalised from "replace the circuit" to "use several at once".

### 43.2 Frame format

Carried in the payload of the standard 1024 B cell (§8.1), so no change to the
cell or to any relay:

```text
  offset  size  field
  0       8     session_id          logical session, opaque to relays
  8       6     global_seq          48-bit, over the logical stream
  14      2     path_seq            per-path, for loss detection on that path
  16      1     flags               DATA | RETX | PROBE | FIN | DUP
  17      1     path_id             sender's local index, NOT a network identity
  18      2     length
  20      …     payload             up to 924 B after §8.1's per-hop tag reserve
```

Two properties that matter for §48: `path_id` is **local to the sender and never
carried outside the end-to-end encrypted payload**, so a relay cannot read it;
and `global_seq` is likewise inside the end-to-end layer. A relay sees cells, not
sequence numbers. **An adversary correlating sub-flows must do so from timing and
volume, not by reading the sequence space** — which is what makes §48's analysis
a traffic-analysis question rather than a trivial one.

### 43.3 Reassembly, and the buffer arithmetic that constrains everything

The receiver must hold out-of-order data until gaps fill. The standard multipath
result applies:

```text
   buffer  ≥  RTT_max × Σᵢ rᵢ
```

For AXON's latency profile this is not a footnote:

| Config | `RTT_max` | `Σ r` | Buffer per session |
|---|---|---|---|
| 2 paths, interactive | 400 ms | 4 Mbps | **200 KB** |
| 4 paths, bulk | 800 ms | 20 Mbps | **2 MB** |
| 8 paths, bulk | 1 200 ms | 80 Mbps | **12 MB** |

At an anonymous service handling 1 000 concurrent sessions, the 4-path row is
2 GB of reassembly buffer. **This, not bandwidth, is the reason `N` is bounded**
(R20), and it is why §50's MP6 measures memory per session as a first-class
result rather than an afterthought.

Mechanisms, all standard and none invented here: global sequence numbers with a
sliding receive window; per-path sequence numbers for per-path loss detection;
selective acknowledgement; duplicate detection by `global_seq`; and a
**head-of-line stall guard** — if a path's outstanding gap exceeds a threshold,
the scheduler re-sends the missing range on a healthy path rather than waiting,
accepting duplicate delivery to avoid a stall. That last mechanism is what stops
the slowest path dictating the connection's throughput, which is the failure mode
the brief specifically names.

### 43.4 What the substrate does NOT do

- It does not provide reliability the circuit layer already provides. Circuits
  deliver in order per path; L4.5 handles *cross-path* ordering and *path loss*,
  not per-hop loss.
- It does not do forward error correction in v1. FEC trades bandwidth for
  latency-under-loss and is a plausible MP5 addition, but on a volunteer network
  it spends the scarce resource (relay capacity) to save the abundant one (client
  patience), and §41.2 says that is the wrong trade by default.
- It does not expose path count, path identity, or path performance to the
  application. §49's modes are the only user-visible control, deliberately.
