## 48. Privacy Analysis of Multipath

### 48.1 The net sign depends entirely on the adversary

Multipath is not "more private" or "less private". It is a redistribution of
exposure whose sign flips between adversary classes, and the only honest
presentation is per-class:

| Adversary (§4 class) | Effect | Why |
|---|---|---|
| Single hostile relay | **Improves** | Sees `1/N` of the stream instead of all of it |
| Single-point WF observer at the client link | **Neutral** | The client link carries every path; splitting downstream changes nothing upstream |
| Single-point WF observer at one middle relay | **Improves substantially** | The trace it can classify is a fraction, with gaps — this is the traffic-splitting defence and it is real |
| Colluding relays on ≥ 2 paths | **Worsens — new attack** | §48.2's sub-flow linkage |
| The exit (clearnet) | **Neutral** | It reassembles everything (§42.3b) |
| The service (overlay-internal) | **Neutral** | It is the endpoint |
| AS-level observer near the client | **Worsens slightly** | More flows to observe, all from one origin |
| Long-term intersection adversary (§28) | **Worsens** | `1 + 2N` relays touched instead of 3 (§41) |
| Global passive | Unchanged | Already outside the model (§4) |

**Ruling (R23): multipath is enabled per traffic class and per mode, and the
default for `INTERACTIVE` is `N = 2`, not `N = 1` and not `N = 8`.** Two paths
capture most of the latency and resilience gain (§41.1) at the smallest
exposure increment, and the marginal analysis in MP6 (§50) is what would justify
moving off that default.

### 48.2 Sub-flow linkage — the new attack multipath introduces

An adversary holding relays on two paths of the same session wants to confirm
they are the same session. It cannot read `session_id` or `global_seq` — both are
inside the session layer (§43.2, §47.4) — so it must infer from observable
structure. Three signals, in increasing order of strength:

| Signal | How it works | Strength |
|---|---|---|
| **Complementary gaps** | The scheduler sends each cell down exactly one path. Where path A has a gap, some other path has traffic. Two sub-flows of one session are *anti-correlated* in fine-grained timing in a way two unrelated flows are not | **Strong** with an adaptive scheduler |
| **Aggregate envelope** | The sum of the two observed rates tracks a single application's demand curve — start, burst, idle, teardown — more closely than two independent flows would | Moderate |
| **Simultaneous lifecycle** | Both sub-flows begin and end within a narrow window, and both react to a third path's failure at the same instant (§46.3) | Moderate, and **strong under induced failure** |

This is a genuinely new linkability primitive: a single-path design gives an
adversary holding two relays no way to tell whether it holds one user's traffic
twice. Multipath does, and no amount of encryption removes it because the signal
is in the scheduling, not the bytes.

**Mitigations and their residuals:**

| Mitigation | Effect | Residual |
|---|---|---|
| Static weights in `PRIVACY` mode (R21) | Removes the *adaptive* component of the gap signal | Complementarity remains: the cells still go down exactly one path each |
| Per-path padding to a constant rate | Removes gap structure entirely | Costs `N ×` the padding overhead — the multiplication that makes constant-rate multipath impractical (§32.4) |
| Independent random delay per path | Blurs fine-grained anti-correlation | Adds latency; partially defeats the point of multipath |
| Fewer paths | Reduces the number of adversary relay pairs from `C(N,2)` to `C(2,2) = 1` | The reason R23 defaults to 2 |
| Disjoint ASN/operator across paths (§46.1) | Raises the cost of holding two paths | Unsatisfiable in a small network (§46.1) |

**No mitigation is complete, and one is quantifiable:** the number of adversary
opportunities for this attack grows as `C(N,2)` — 1 pair at `N = 2`, 6 at
`N = 4`, 28 at `N = 8`. Combined with §41's per-relay exposure table, the
probability an adversary holds at least one linkable pair rises steeply with `N`,
and computing that curve is an explicit MP5 deliverable.

### 48.3 What multipath does to the Part V metrics

| Part V metric | Effect of multipath | Where it must be re-measured |
|---|---|---|
| `P_dea` (§28) | Rises — `1 + 2N` relays touched | §28's topology sweep gains `N` as a dimension |
| `A_eff` (§34) | Falls — mode and path count partition the population (§49.3) | §34's tool gains mode/`N` as candidate-set conditions |
| WF precision (§32.1a) | **Falls (good)** at a middle observer; unchanged at the client link | §32's Engine B gains split traces |
| Correlation TPR (§32.1b) | Rises — more observation points, plus §48.2 | Already expected `IMPOSSIBLE`; multipath makes it more so |
| `γ`, bandwidth (§35) | Multipath makes per-path capacity estimation easier and more necessary | §35's estimator consumes multipath probe data |

**Multipath is therefore not an addition to Part V's programme; it is a parameter
in it.** Every Part V sweep gains an `N` dimension, and §50's MP5 is scheduled to
run inside P25's simulator rather than beside it.

### 48.4 Threat-model rows

In §18's four-column form:

| Attack | Component | Mitigation | Residual risk |
|---|---|---|---|
| Sub-flow linkage by complementary timing | L4.5 scheduler | Static weights in `PRIVACY`; low default `N`; per-path padding where affordable | **Not eliminated.** Complementarity is inherent to splitting. `C(N,2)` pairs of opportunity |
| Path-count inference via induced failure | Path lifecycle | Gradual redistribution; rate hold-down in `PRIVACY` (§46.3) | An adversary who can induce failures repeatedly learns `N` |
| Mode inference | Scheduler behaviour | Few modes, strong default (§49.3) | Mode partitions the anonymity set; inference is likely |
| Aggregator compromise | — | **Removed by construction**: no aggregator node exists (§42.3c) | For clearnet, the exit is still a full-flow observer |
| Shared-guard correlation | Guard set | Deliberate: shared guards prevent entry exposure multiplying (§42.4) | All paths share a first hop, so a hostile guard sees all sub-flows and §48.2 becomes trivial for it |
| Memory exhaustion via many sessions | Reassembly buffers | Bounded `N`, session caps, backpressure (§43.3, §45.3) | A service with many clients is memory-constrained before it is bandwidth-constrained |
| Capacity monopolisation | Relay commons | R20 conservative defaults; accounting-plane pricing (§45.4) | Without §14, the greediest client wins |

The shared-guard row deserves attention: it is a deliberate trade in which
**§48.2's attack becomes free for a hostile guard**, since the guard sees every
sub-flow by construction. Multipath therefore raises the value of guard
compromise, which couples it back to §28 and is a further argument for the
layered guard sets that workstream recommends.

---

## 49. Performance Modes, Clearnet Aggregation, and the Virtual Interface

### 49.1 Modes

| Mode | `N` default | Scheduler | Adaptation | Duplication | Diversity | Intended for |
|---|---|---|---|---|---|---|
| `PRIVACY` | 2 | Static weighted | Only on path-set change | None | Hard constraints; fail rather than relax | The default for `INTERACTIVE` |
| `BALANCED` | 2–3 | Drain-time | Slow (≥ 10 s) | Critical cells only | Hard constraints | General use |
| `PERFORMANCE` | 4 | Drain-time + RTT | Fast (≥ 500 ms) | Critical cells only | Soft; may relax ASN | Bulk transfer, storage (§10) |
| `RELIABILITY` | 3 + 1 spare | Drain-time | Slow | Critical + stalled ranges | Hard, plus warm spare | Long-lived sessions that must not break |

### 49.2 The user picks a policy, not relays

The brief's requirement is met: a mode is a single selection, and the substrate
derives path count, scheduler, adaptation rate, diversity policy and duplication
from it. No relay is ever named by a user. The mode is also the *only* multipath
control exposed at L8 — §43.4 — so that the visible configuration space stays
small, which §49.3 explains is a security requirement rather than a simplification.

### 49.3 Modes partition the anonymity set — the cost of configurability

Every user-visible mode is a distinguisher. If an adversary can infer the mode
from traffic behaviour (and §48.4 says it likely can), then the candidate set for
any observation is not all users but **users in that mode**:

```text
   A_eff(observed)  ≈  A_eff(total) × share of the observed mode

   4 modes, evenly used   →  up to 4× reduction
   4 modes, one at 90 %   →  the three rare modes are ~1/30 the set of the common one
```

A user who selects `PRIVACY` mode to be safer may end up in a smaller and more
distinctive population than the default — the classic configuration paradox.
**Ruling (R24): the number of modes is capped at four, `BALANCED` is the shipped
default, and §34's tool must report `A_eff` per mode so the cost of choosing a
rare one is measurable rather than assumed.** If the measurement shows `PRIVACY`
mode is rare enough to be self-defeating, the correct response is to remove the
mode, not to document the hazard.

### 49.4 Clearnet aggregation and protocol compatibility

The destination is an unmodified Internet host that expects one connection, so
the exit terminates and reassembles (§42.3b). What the client-side interface
should be is a separate question, and the answer differs by ambition:

| Interface | What the app sees | Verdict | Reasoning |
|---|---|---|---|
| **SOCKS5 stream proxy** | One TCP stream | **v1** | Works with unmodified applications today; the app opens one connection and the substrate splits below it; no kernel component; matches §13.7's existing integration surface |
| Native L8 API | One logical session | **v1** | For applications built on AXON; already specified in §20 |
| Multipath QUIC to the exit | One QUIC connection | Deferred | Nested congestion control (§42.2); revisit only if the circuit layer gains a datagram mode |
| **TUN virtual interface** | An IP interface | **Deferred, with prejudice** | See below |

**On the virtual interface.** A TUN device is what the brief's §3 diagram
implies, and it is the wrong v1 goal. It turns the exit into a general IP gateway
and NAT, which: contradicts §17's ruling that no node is an Internet exit by
default and that exit policy is explicit; multiplies the abuse and legal surface
for exit operators from "some TCP ports" to "all IP traffic"; captures DNS, which
becomes a leak channel requiring its own handling (§13.7's classic failure); and
presents a large new fingerprinting surface in IP and transport headers the
substrate would have to normalise. It is a coherent long-term goal and it is a
programme of its own, not a phase of this one.

### 49.5 Where the two topologies leave the design

```text
  OVERLAY-INTERNAL (client ↔ service)        the case AXON exists for
     multipath is architecturally clean: both ends are endpoints,
     no aggregator, no exit, no clearnet. BUILD THIS FIRST.

  CLEARNET EXIT (client ↔ Internet)          the case the brief emphasises
     multipath works, with a stated limit: the exit sees everything,
     so the gain is against middles and network observers only.
```

The brief's framing centres the clearnet case; the architecture is better suited
to the overlay-internal one, and §50 sequences accordingly.

---

## 50. Multipath Phases MP1–MP6

| Phase | Prerequisites | Deliverables | Effort | Conf. | Exit criteria | Does NOT establish |
|---|---|---|---|---|---|---|
| **MP1** Transport prototype | §8 circuits, §9.8 sessions | `LogicalSession`; frame format (§43.2); global/per-path sequencing; reassembly with SACK and duplicate detection; HoL stall guard; nonce partitioning (§47.2) | 3–5 em | High | Two circuits between two nodes carry one logical stream; a deliberately stalled path does not stall the connection; **a negative test proves a retired `path_id` is never reused** | Anything about performance or privacy |
| **MP2** Multiple overlay circuits | MP1, §9.2 pools | Path set over N independent 3-hop circuits; shared guard set; cross-path diversity constraints (§46.1) with **explicit degradation** | 3–5 em | High | 4 paths built with no shared middle/terminal relay and no shared ASN; when constraints are unsatisfiable the builder returns fewer paths **with a reason**, never a silently relaxed set | That diversity is achievable in a real network |
| **MP3** Scheduling, congestion control, recovery | MP2 | Four schedulers (§44.2); coupled congestion control (R22); two-loop interaction handling (§45.2); path lifecycle and build-ahead replacement (§46.2) | 6–10 em | Medium | Coupled CC takes no more than a single flow at a shared bottleneck — falsified by any excess; a path failure is survived without connection loss; the §45.2 double-backoff pathology is demonstrated absent | Fairness in the wild; behaviour at scale |
| **MP4** Endpoint aggregation | MP3, §9.5 rendezvous | Overlay-internal aggregation (service side); then exit-side termination for clearnet with SOCKS5 client interface | 5–8 em | Medium | A client reaches an anonymous service over 4 paths with reassembly at the service and **no aggregator node in the path**; an unmodified application works through SOCKS with splitting active | IP-level tunnelling; TUN; multipath QUIC |
| **MP5** Privacy evaluation | MP4, P23 (§34), P25 Engine B | Sub-flow linkage experiment; `C(N,2)` opportunity curve; path-count inference under induced failure; mode-inference classifier; `A_eff` per mode; re-run of §28's sweep with `N` as a dimension | 8–14 em | **Low** | The linkage attack's success rate is measured at `N ∈ {2,4,8}` and published; `A_eff` per mode published; **the result may be that `PRIVACY` mode should be removed (R24), and that outcome must be actionable** | That the defences work; the expected result is partial |
| **MP6** Scale and marginal-benefit measurement | MP5 | Throughput, p50/p99 latency, CPU, memory per session, relay overhead at `N ∈ {1,2,4,8}`; the shared-bottleneck cases; the marginal curve | 5–8 em | Medium | The `N` beyond which marginal throughput gain falls below a pre-registered threshold is identified **and the marginal privacy cost from MP5 is placed on the same axis** — the deliverable is the crossing point, not a maximum throughput number | Behaviour on a real network with real relay capacity |

**Total: 30–50 engineer-months.** MP1–MP4 are ordinary engineering with good
confidence. MP5 is research and carries the same low confidence as Part V's P21,
for the same reason: it is a traffic-analysis result, and traffic-analysis
results age badly.

### 50.1 Sequencing against the rest of the roadmap

MP1–MP2 require only §8 and §9 and can run in parallel with Part IV's P10–P12.
**MP5 must not run before P23** (§34's anonymity model), because without `A_eff`
there is no way to price the exposure multipath buys, and a throughput result
without that price is exactly the "performance win reported as free" that §41
forbids. MP6's crossing point is undefined until MP5 has produced the privacy
axis.

### 50.2 What Part VI does NOT establish

- **That multipath improves anonymity.** §48.1 shows the sign is per-adversary,
  and against the two-path-collusion adversary it is negative.
- **That bandwidth aggregates.** §41.1 argues the reliable gains are latency and
  resilience; throughput multiplication requires the per-relay share to be the
  binding constraint, which is a measurement (MP6) and not an assumption.
- **That the diversity constraints are satisfiable.** In a network of a few
  hundred relays they are not, and the substrate's honest behaviour is to return
  fewer paths.
- **That the exit-side case is worth building.** §49.5 sequences it second, and
  if MP5 shows the middles-and-observers gain is small, the clearnet case may not
  justify its complexity at all.
- **Anything about IP-level tunnelling.** §49.4 defers it as a separate
  programme with a much larger abuse and legal surface.

---

## 51. Adjacent Primitive — Time-Triggered Dead Drops

The brief's closing list includes *cryptographically controlled time-triggered
dead drops*, which appears nowhere else in the specification. It is recorded here
rather than dropped, and it is **not** part of the multipath work — it belongs to
the storage layer (§10).

**What it means:** an object published now that becomes retrievable only at or
after a future time `T`, without the publisher being online at `T` and without a
trusted party holding the key.

**Why it is hard.** Encryption is easy; *release* is the problem. The candidates,
with honest assessments:

| Mechanism | How | Verdict |
|---|---|---|
| **Chain-triggered release** | A contract holds the key and publishes it at block height `H`; or a threshold committee is contractually obliged and bonded to release at `T` | **Most practical for AXON.** Reuses §12's chain plane and §14's bonding. Trust is distributed across a bonded committee, and misbehaviour is slashable rather than merely detectable |
| **Threshold committee with bonded release** | `k`-of-`n` shares; slashing for early release or non-release | Practical; inherits the committee-selection and collusion problems of §15 |
| **Time-lock puzzles (sequential work)** | Retriever performs inherently sequential computation | Works without any party, but the cost is paid by *every* retriever, is hardware-dependent, and calibrating "one year of sequential work" across unknown future hardware is unsolved |
| **Verifiable delay functions** | Sequential work with efficient verification | Better verification, same calibration problem |
| **Witness encryption** | Decryptable on a public event | Not practical with deployed constructions |

**Assessment: `[NEEDS RESEARCH]`, and the chain-triggered variant is the one
worth prototyping** because AXON already has a verified chain path (§31), a
bonding and slashing system (§14), and content-addressed encrypted storage
(§10). The honest residual is that every practical construction replaces "trust a
party" with "trust a bonded committee not to collude", which is a weaker but real
assumption — and that early release is undetectable if the colluding committee
simply uses the key quietly rather than publishing it. That last point is the
one that would need solving before the primitive could be advertised as
time-*guaranteed* rather than time-*incentivised*.
