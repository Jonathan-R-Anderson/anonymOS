## 26. The Eight Problems: Definitions and Measurable Properties

**The finding that shapes this entire programme: seven of the eight problems are
not independent, and four of them are the same problem measured from different
angles.** Intersection resistance, traffic analysis, anonymity-set size and
bandwidth-driven path selection all resolve to one quantity — the posterior
probability an adversary assigns to the correct endpoint after observing for a
period — and optimising any one of them in isolation moves the others, usually in
the wrong direction. Guards cut intersection exposure and shrink the anonymity
set. Padding raises the correlation cost and creates a distinguishable traffic
class. Bandwidth weighting improves performance and hands the network to whoever
can fake capacity most cheaply.

This section fixes the definitions so the eight workstreams in §28–§35 can be
judged rather than admired. §25 marked these `[UNSOLVED]`; the programme's job is
to convert each one into exactly one of four outcomes:

```text
  DEPLOYED     a mechanism is implemented and its security property is measured
  BOUNDED      a mechanism is implemented and the residual risk is quantified
  IMPOSSIBLE   a trade-off or impossibility is demonstrated under AXON's assumptions
  REFUTED      the research shows the mechanism does not work, and the roadmap says so
```

A fifth outcome — the metric was weakened until the mechanism passed — is a
programme failure and §15's rule applies to it: *never silently turn an unsolved
problem into an assumed solution.*

---

### 26.1 What "measurable" means here

Every workstream states its objective as a probability, a cost, a time, an error
bound, or an information-theoretic quantity. The following are banned as
objectives because they cannot be falsified: "more anonymous", "more
decentralised", "better Sybil resistance", "harder to attack", "significantly
improved".

The eleven quantities the programme uses, with their symbols, fixed here so the
workstreams do not each invent their own notation:

| Symbol | Quantity | Units | Where it is used |
|---|---|---|---|
| `f` | Adversary's fraction of **relay-selection probability** — not of node count. The distinction matters: a bandwidth-weighted network gives a well-provisioned adversary `f ≫ n/N` | fraction | WS1, WS3, WS6, WS7 |
| `P_dea(T, f)` | Probability the adversary identifies both ends of a target's communication within `T` | probability | WS1, WS5, WS7 |
| `T_obs` | Expected observation time before correlation succeeds | days | WS1, WS5 |
| `P_ecl` | Probability a node's network view is materially adversary-controlled | probability | WS3 |
| `T_det` | Time from eclipse onset to detection by the victim | epochs | WS3 |
| `S_max` | Maximum tolerated resolver staleness | seconds | WS4 |
| `k_src` | Number of independent chain data sources required for liveness | count | WS4 |
| `H`, `H∞` | Shannon and min-entropy of the adversary's posterior over candidate endpoints | bits | WS5, WS7 |
| `A_eff` | Effective anonymity-set size, `2^H` (average case) or `2^H∞` (worst case) | count | WS7 |
| `C(x, y)` | Cost to obtain fraction `x` of relay-selection probability for `y` consecutive epochs | currency | WS6 |
| `ε_bw` | Bandwidth-estimation error, and `γ` the maximum inflation factor an adversary can achieve | ratio | WS8 |

**On `f` versus node count.** Every workstream must state whether its adversary
fraction is of nodes, of stake, or of selection probability, because the three
diverge sharply under bandwidth weighting. An adversary with 2 % of nodes and
30 % of advertised capacity has `f = 0.30`, and that is the number that appears
in the security calculations. WS6 and WS8 exist because that conversion rate —
capital and lies into `f` — is the network's real attack surface.

---

### 26.2 The eight problems, defined

Each entry states: what AXON does now, why it is insufficient, the adversary, the
security property wanted, what a successful mitigation looks like, and what
cannot be guaranteed afterwards.

#### P1 — Long-term intersection attacks

| | |
|---|---|
| **What AXON does now** | 2 primary guards per isolation context, 45-day rotation (§8.5); 10-minute tunnel lifetime with guard-constrained pools (R1); per-destination circuit isolation (§8.6); intro-point rotation on descriptor republish (§9.4) |
| **Why it is insufficient** | Guard rotation is repeated sampling from a population containing `f` hostile weight. Over a year the client draws roughly `2 × 365/45 ≈ 16` guard slots. `P(at least one hostile) = 1 − (1−f)^16`, which at `f = 0.05` is **56 %** and at `f = 0.10` is **81 %**. A hostile guard is not deanonymisation on its own, but for a persistently-online *service* it is the first half of guard discovery, and the service cannot go offline to break the intersection |
| **Adversary** | Runs relays totalling `f` of selection probability; persistent across months; logs every circuit it participates in; correlates by client identity at the guard position and by service identity at the intro/rendezvous position |
| **Information possessed** | Its own relays' logs; public relay descriptors; DHT descriptor fetch timing; the fact that a target service is reachable at time `t` |
| **Security property wanted** | `P_dea(T=365 days, f=0.05) < 0.05` for a service, and a stated bound for clients |
| **Successful mitigation** | A guard topology and rotation schedule whose simulated `P_dea` curve stays under target for a year at `f = 0.05`, with the overhead stated |
| **Cannot be guaranteed** | A service that is always online and always reachable leaks its availability pattern by definition. Intersection resistance can slow discovery; it cannot make a permanently-present entity indistinguishable from an absent one |

#### P2 — Global abuse handling without re-centralisation

| | |
|---|---|
| **What AXON does now** | R5: no node caches plaintext it did not request; storage holders cannot read shards; local operator blocklists supported; a global blocklist is explicitly refused (§10.4, §17) |
| **Why it is insufficient** | "Refuse to build the censorship mechanism" is a coherent position but it is not an abuse-handling design. Operators facing legal demands have no mechanism, no evidence format, and no way to act on a report without either doing nothing or building the global authority the architecture forbids |
| **Adversary** | Two, in opposition: an abuser exploiting the absence of enforcement, and a censor exploiting the presence of it. Any mechanism that helps the first defeat is available to the second |
| **Security property wanted** | An operator can enforce a policy on their own resources within a bounded latency, **and** no coalition below a stated fraction of the network can remove content or a service globally |
| **Successful mitigation** | Subscribable, signed policy assertions with per-operator composition; a measured "policy propagation latency"; and a proof that global removal requires controlling a stated fraction of storage or relay capacity |
| **Cannot be guaranteed** | That abuse is prevented. That operators are shielded from legal liability by encryption — they are not, in most jurisdictions. That policy subscription does not converge on a de-facto global list if one publisher becomes dominant, which is re-centralisation by market share rather than by protocol |

#### P3 — Network-view partitioning and eclipse

| | |
|---|---|
| **What AXON does now** | `KadID = H(NodeIdentity ‖ SRV_epoch ‖ prefix)` with epoch rotation (§7.2); `d = 3` disjoint lookup paths; `r = 8` replication across distinct /24, /48 and ASN; no consensus document by construction (R14) |
| **Why it is insufficient** | R14 is honest that clients can be given different views and calls it unsolved. Without a consensus there is no reference against which a node can ask *is my view the same as everyone else's?*, so eclipse is not merely possible, it is **undetectable** |
| **Adversary** | Controls a fraction of a victim's peer-selection opportunities — through position in the keyspace, through bootstrap, or through network position; wants the victim to select only adversary relays |
| **Security property wanted** | `P_ecl < 0.01` at `f = 0.20`, and `T_det ≤ 2` epochs when eclipse occurs anyway |
| **Successful mitigation** | A view-consistency mechanism that detects material divergence, plus an out-of-band anchor a fully-eclipsed node can still reach |
| **Cannot be guaranteed** | Recovery without an anchor. A node whose every path is adversary-controlled cannot learn that fact from inside the partition; detection ultimately requires a channel the adversary does not control, and identifying that channel is the workstream's real problem |

#### P4 — Decentralized blockchain access

| | |
|---|---|
| **What AXON does now** | A mainnet-verified light client (`internal/ethproof`, `doc/trust-anchor.md`) gives *correctness* for reads. But the PoF architecture routes node chain access through a **website-run pruned External Node, paymaster and relayer**, and the resolver still needs a beacon source and an RPC for *liveness* |
| **Why it is insufficient** | The light client makes a lying provider detectable, not avoidable. A provider can still refuse, stall, censor selectively, or simply be the only one — and the PoF relayer/paymaster is a single operator on the path of every node's registration and claim. That is a centralised observation point inside a design whose premise is not having one |
| **Adversary** | The RPC or relayer operator; a network position that can block access to it; and Ethereum itself as a systemic dependency |
| **Security property wanted** | No single source can cause an incorrect answer (already true), **and** no single source can cause unavailability: `k_src ≥ 3` independent sources, `S_max` bounded and declared |
| **Successful mitigation** | Multi-source proof-carrying reads with the light client as the correctness anchor; chain evidence distributed over AXON's own DHT so reads do not require an RPC at all; the relayer made optional and non-observing |
| **Cannot be guaranteed** | Independence from Ethereum. While ownership is on-chain, an Ethereum-level censorship or consensus failure is an AXON namespace failure. The workstream must bound this, and must not pretend to remove it |

#### P5 — Traffic-analysis resistance

| | |
|---|---|
| **What AXON does now** | Fixed 1024 B cells, per-destination circuit isolation, circuit rotation, link padding; R2 declares `INTERACTIVE` explicitly undefended against end-to-end correlation |
| **Why it is insufficient** | Fixed cells remove per-message length leakage and nothing else. Flow-level volume, timing and burst structure survive intact, and modern classifiers operate on exactly those features |
| **Adversary** | Observes packet timing, size, direction, volume, duration, burst structure, circuit creation, and endpoint availability, at one or both ends |
| **Security property wanted** | Two separate properties, and conflating them is the standard error: **(a)** website-fingerprinting resistance at a single observation point — target a stated classifier precision at a realistic open-world base rate; **(b)** flow-correlation resistance with both ends observed |
| **Successful mitigation** | For (a), a padding design with measured classifier degradation at stated overhead. For (b), the honest expected result is a demonstrated impossibility at acceptable latency |
| **Cannot be guaranteed** | (b). The literature is consistent that end-to-end flow correlation succeeds at high true-positive and low false-positive rates against low-latency systems, and that padding raises the cost far less than it raises the overhead |

#### P6 — Economic / Sybil calibration

| | |
|---|---|
| **What AXON does now** | §15's layered defence: prefix-bound `KadID`, diversity constraints, bonded stake via the existing `StakeVault`, proof of work for cheap admission, contribution weighting, randomised selection. §15 marks the whole area `[UNSOLVED]` |
| **Why it is insufficient** | The design has never been calibrated. Nobody has computed what a bond must be worth for the scheme to raise `f` acquisition cost above a stated threshold, and the interaction between stake weighting and Sybil resistance is not merely uncalibrated, it is **directionally unexamined** — §33 shows that sublinear weighting actively rewards identity splitting |
| **Adversary** | Large capital; many small identities; borrowed or flash capital; cartels; compromised legitimate nodes |
| **Security property wanted** | `C(x=0.20, y=30 epochs)` stated in currency, with the derivation |
| **Successful mitigation** | A weighting function, bond floor, lock period and diversity cap whose joint `C(x,y)` surface is computed and defended |
| **Cannot be guaranteed** | That the result is not plutocratic. §33's core finding is that stake weighting converts Sybil resistance into capital cost; the question is only the exchange rate |

#### P7 — Anonymity-set size

| | |
|---|---|
| **What AXON does now** | Nothing. The specification never defines an anonymity set, never measures one, and — like most systems in this space — implicitly invites the reader to treat node count as the set size |
| **Why it is insufficient** | Node count is not anonymity. A user pinned to 2 guards is anonymous only among users sharing those guards, which in a bandwidth-weighted network of 10⁵ users and 10³ relays is a set of hundreds, not 10⁵. Guards **shrink** the anonymity set by design, and this cost has never been stated against the intersection benefit that motivates them |
| **Adversary** | Any of the above; the metric is defined relative to a stated observation |
| **Security property wanted** | `A_eff` computed per role (user, service, operator, request, domain, session) and per adversary class, with `H∞` reported alongside `H` because worst-case is what a targeted user experiences |
| **Successful mitigation** | A published model and a measurement harness, plus mechanisms with a demonstrated effect on `A_eff` |
| **Cannot be guaranteed** | Anonymity in a small network. A network with 200 users has `A_eff ≤ 200` under any design, and the early network's honest `A_eff` is close to 1 |

#### P8 — Bandwidth measurement without a central authority

| | |
|---|---|
| **What AXON does now** | R14: bounded self-report plus delivery receipts plus bond, with no measurement authority, and the residual named as unsolved |
| **Why it is insufficient** | Self-report is a claim. Receipts signed by adjacent relays are forgeable by colluding pairs at zero marginal cost — reciprocal inflation is the dominant attack and the current design has no answer to it |
| **Adversary** | Colluding measurers; fake capacity; Sybil measurers; selective service to measurers; strategic throttling of real traffic |
| **Security property wanted** | Inflation factor `γ` bounded — an adversary spending `C` cannot obtain more than `γ ×` its true capacity in selection weight — and `ε_bw` characterised |
| **Successful mitigation** | A measurement combining client-attested delivery (clients have no incentive to inflate a relay), stake-bounded claims, and outlier rejection, with `γ` measured under collusion |
| **Cannot be guaranteed** | Accurate measurement under majority collusion. Tor's own history with bandwidth authorities shows this is hard even *with* a central authority, and removing the authority removes the one party with no incentive to lie |

---

### 26.3 The four problems that are one problem

`P1`, `P5`, `P7` and the path-selection half of `P6`/`P8` all reduce to the
adversary's posterior over endpoints. Stating that explicitly prevents the
programme from double-counting a defence or missing a regression:

```text
                        P7  Anonymity-set model
                     (the measuring instrument;
                      nothing below is meaningful
                      until this exists)
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   P1 Intersection      P5 Traffic          Path selection
   (exposure over        analysis            = f(P6 stake,
    time)               (exposure per            P8 bandwidth)
        │                observation)                │
        └─────────────────────┼─────────────────────┘
                              ▼
                    posterior P_dea(T, f)
```

**Consequences, and they are binding on the workstreams:**

1. **P7 is a prerequisite, not a peer.** Any claim in P1 or P5 that a mechanism
   improves anonymity is unmeasurable until `A_eff` is defined. §34 is therefore
   scheduled first (P23 in §38's ordering, despite its number).
2. **A P1 improvement can be a P7 regression.** Narrowing guard sets lowers
   `P_dea` and lowers `A_eff` simultaneously. Neither workstream may report a
   win without the other's number.
3. **P6 and P8 do not defend anything directly.** They set `f` — the input to
   every other calculation. An error in bandwidth measurement is an error in
   every anonymity claim in the document.

The remaining three — `P2` abuse, `P3` eclipse, `P4` chain access — are
genuinely separate, and `P3` and `P4` are coupled in the opposite direction from
what one would expect: **the chain is the natural out-of-band anchor for eclipse
detection** (§30.5), and eclipse of chain access is what `P4` must prevent. They
are scheduled together for that reason.

---

## 27. Status Matrix and How This Programme Is Judged

### 27.1 The matrix

Current status, target outcome, and the single number each workstream must
produce. "Expected outcome" is the honest prediction, recorded now so that the
programme cannot later present a weaker result as a success.

| # | Problem | Now | Target outcome | The number it must produce | Expected outcome |
|---|---|---|---|---|---|
| P1 | Long-term intersection | `[UNSOLVED]` | BOUNDED | `P_dea(365 d, f=0.05)` for client and service, per guard topology | BOUNDED for services via layered guards; clients remain exposed to long-term observation |
| P2 | Abuse without re-centralisation | `[UNSOLVED]` | BOUNDED + IMPOSSIBLE | Fraction of storage/relay capacity required for global removal; policy propagation latency | Partly IMPOSSIBLE: technical enforcement provably stops at the operator boundary (§29.6) |
| P3 | View partitioning / eclipse | `[UNSOLVED]` | DEPLOYED | `P_ecl` and `T_det` at `f ∈ {0.05 … 0.50}` | DEPLOYED for detection; recovery BOUNDED and anchor-dependent |
| P4 | Decentralized chain access | `[UNSOLVED]` | DEPLOYED + BOUNDED | `k_src`, `S_max`, and time-to-recovery after isolation | DEPLOYED for correctness and liveness; dependency on Ethereum itself BOUNDED, never removed |
| P5 | Traffic analysis | `[UNSOLVED]` | BOUNDED + IMPOSSIBLE | Classifier precision at realistic base rate, per overhead level | Website fingerprinting BOUNDED; end-to-end correlation IMPOSSIBLE at acceptable latency |
| P6 | Economic / Sybil calibration | `[UNSOLVED]` | BOUNDED | `C(x, y)` surface | BOUNDED, and the bound is plutocratic — the honest result is a price, not a defence |
| P7 | Anonymity-set size | not modelled | DEPLOYED | `A_eff` and `H∞` per role per adversary class | DEPLOYED as a measurement capability; the values it reports for a small network will be poor |
| P8 | Bandwidth measurement | `[UNSOLVED]` | BOUNDED | `γ` under collusion, `ε_bw` | BOUNDED under minority collusion; REFUTED under majority collusion |

**Three of the eight are expected to produce a negative or partial result.** That
is the programme working correctly. §40.4 collects them.

### 27.2 The rule against moving the goalposts

Every workstream registers its metric, target, adversary and measurement
procedure **before** the mechanism is built, in the same commit as the
experiment harness. A target may be changed only by a recorded amendment stating
the old target, the new target, the evidence, and the reason. An experiment that
fails its pre-registered target is reported as a failure in §40.4 and the
mechanism is either revised or abandoned.

Failure statements the programme must be willing to publish verbatim:

- "This mechanism does not work."
- "This attack remains practical at the deployment parameters."
- "The overhead is unacceptable for the security gain."
- "The decentralised solution performs worse than the centralised baseline."
- "This problem is fundamentally constrained by the threat model and will not be solved."

### 27.3 The imported-mechanism rule

For every mechanism drawn from another system, the workstream states four things
in a table before adopting it. **Importing a mechanism does not import its
security properties**, and the fourth column is where that usually shows up:

| Column | Question |
|---|---|
| Source | Which system, and what it does there |
| Classification | `BORROWED` (unchanged) · `MODIFIED` (changed, and how) · `NEW` (AXON-originated) · `REJECTED` (and why AXON's architecture forbids it) |
| What changes in AXON | The architectural difference that alters the mechanism's behaviour |
| Property that does **not** transfer | The security property it has at the source and lacks here |

The recurring reason a property fails to transfer, and it applies to at least
four of the eight workstreams: **Tor's mechanisms assume a consensus document
produced by directory authorities.** AXON refuses that (R14). Guard selection,
bandwidth weighting, path diversity and relay-set agreement all rest on it at the
source, so each must be re-derived rather than copied. Where a mechanism cannot
be re-derived without a consensus, the workstream must say so and treat the
consensus-free requirement as the thing under test.

### 27.4 What this section does NOT establish

- **No mechanism is validated here.** §26–§27 define the measuring instruments
  and the rules of evidence. Every claim about whether something works belongs
  to §28–§35 and, ultimately, to the simulator in §36.
- **The metrics are not yet calibrated.** Several targets in §27.1 are stated as
  round numbers (`P_dea < 0.05`, `P_ecl < 0.01`) chosen because they are
  falsifiable, not because a defensible derivation exists. §37 marks these
  `RESEARCH REQUIRED` and defines the experiment that would justify them.
- **The expected-outcome column is a prediction, not a result.** It is recorded
  to prevent retrospective optimism, and it may be wrong in either direction.
- **The reduction in §26.3 is an argument, not a proof.** That P1, P5 and P7
  share a posterior is a modelling claim; a formal statement would require the
  anonymity model of §34 to exist first, which is precisely why §34 is
  scheduled before the mechanisms that depend on it.
- **Nothing here addresses whether the programme is affordable.** §38 gives
  effort estimates with confidence intervals, and several workstreams are
  research with genuinely unbounded tails.
