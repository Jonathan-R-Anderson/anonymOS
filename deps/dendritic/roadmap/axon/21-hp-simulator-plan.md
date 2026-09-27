## 36. The Unified Adversarial Simulator

### 36.1 One simulator is the wrong answer

The brief asks for a simulator spanning millions of nodes *and* packet-level
traffic analysis. Those are incompatible fidelities, and building one tool that
claims both produces a tool that is trusted for neither. The programme builds
**two engines with one configuration language, one adversary specification, and
one result format**, and is explicit about which questions each may answer.

```text
   ENGINE A — POPULATION            ENGINE B — PACKET
   ────────────────────             ─────────────────
   10³ – 10⁶ nodes                  10² – 10³ nodes
   event/epoch granularity          packet granularity, real cell codec
   Monte-Carlo + analytic           discrete-event, real timing
   answers: P_dea, P_ecl, T_det,    answers: classifier precision, overhead,
            C(x,y), γ, A_eff                 latency, correlation TPR/FPR
   CANNOT answer: anything about    CANNOT answer: anything about population
            packet timing                     scale or long horizons
```

A result from Engine A about traffic analysis, or from Engine B about network
scale, is inadmissible. §36.5's cross-validation is how the two are kept honest
where their domains overlap.

### 36.2 Shared substrate

| Component | Contents |
|---|---|
| **Topology model** | Node population with bandwidth distribution, ASN and prefix assignment, geographic placement, churn process. Distributions are either measured (and cited) or synthetic (and flagged in every result that uses them) |
| **Adversary specification** | Declarative: budget, strategy, `f` target, collusion structure, observation points, adaptivity. **Strategies must optimise**, not follow a script — a fixed naive adversary produces a flattering number and §33.3 and §35.3 both require the optimising form |
| **Configuration** | A single declarative file per experiment: topology, adversary, mechanism parameters, horizon, trial count, and a **seed**. Reproducibility is a hard requirement, not a nicety — a result that cannot be regenerated bit-for-bit from its config is not a result |
| **Result format** | JSONL, one record per trial or per cell, with the config hash embedded. Aggregation is a separate step so raw output can be re-analysed without re-running |
| **Sweep harness** | `f ∈ {0.01, 0.05, 0.10, 0.20, 0.30, 0.40, 0.50}` × `T ∈ {1 d, 1 w, 1 m, 3 m, 1 y}` as the default grid, with per-workstream extensions |

### 36.3 What each engine models

**Engine A** — path selection under the §33 weighting; guard topologies including
layered sets; tunnel-pool construction and rotation; DHT keyspace, `KadID`
rotation and lookup with `d` disjoint paths; churn; eclipse strategies; chain
availability as an on/off resource; storage placement and repair; the accounting
plane as a weight input. It does **not** model bytes.

**Engine B** — the real cell codec and framing from §8.1, real padding machines,
real QUIC stream behaviour where feasible, and trace capture at configurable
observation points. It reuses the §21 local multi-node environment rather than
reimplementing the protocol, which is the only way its results say anything about
the actual implementation.

### 36.4 The honesty requirements

1. **Synthetic distributions are labelled in the output**, not only in the
   documentation, so a plot cannot be lifted out of context.
2. **Every published result carries its config hash and seed.**
3. **Negative results are published in the same format as positive ones**, in the
   same repository, with equal prominence.
4. **The adversary model is versioned.** Improving the adversary invalidates
   earlier results, and the invalidation is recorded rather than the old numbers
   silently remaining.
5. **No result is reported without its uncertainty.** Monte-Carlo output gets
   confidence intervals; a point estimate from 100 trials is not a finding.

### 36.5 Cross-validation

Where the engines overlap — circuit lifetime effects, multiplexing, the observable
consequences of guard topology — both must produce compatible answers on a shared
scenario, and a discrepancy blocks publication until it is explained. Where an
analytic model exists (§28.1, §33.2, §34.1), it is checked against Engine A on
the same scenario, and the analytic form is preferred for reporting because it
generalises.

---

## 37. Quantitative Security Targets

Targets, with the rationale for each. **Where no defensible rationale exists the
row is marked `RESEARCH REQUIRED` and the establishing experiment is named** —
inventing a number would be worse than admitting there is not one.

| # | Metric | Target | Adversary | Measurement | Rationale |
|---|---|---|---|---|---|
| P1 | `P_dea(365 d)` for a service | < 0.05 | `f = 0.05` persistent, active forced sampling | Engine A, topology sweep | Chosen so that a service surviving a year at a 5 % adversary is the design point; the 5 % figure is itself `RESEARCH REQUIRED` — it is a plausible relay-population share for a funded adversary, not a measured one |
| P1 | `P_dea(365 d)` for a client | `RESEARCH REQUIRED` | — | Engine A curve published | §28.6: a universal client target is false precision. Experiment: characterise the curve and let deployments choose |
| P2 | Storage capacity fraction for global removal of one object | > `(n−k)/n` of holders, i.e. **> 3 of 8** at RS 6+3 | Coalition of storage operators | Analytic from the deployed coding parameters | Follows directly from erasure coding; it is the one abuse-related number that is exactly computable |
| P2 | Policy propagation latency | < 1 h to subscribed operators | — | Engine A, issuer-subscription graph | Matches DHT record propagation; no stronger claim is defensible |
| P2 | Issuer concentration (top-1 subscription share) | `RESEARCH REQUIRED` | Dominant-issuer adversary | Engine A over simulated time | No defensible threshold exists — the question is whether concentration occurs at all (E2.4) |
| P3 | `P_ecl` | < 0.01 | `f = 0.20` of selection opportunities | Engine A eclipse sweep | Two orders of magnitude below the adversary's share; chosen as falsifiable, and `RESEARCH REQUIRED` on whether it is achievable |
| P3 | `T_det` | ≤ 2 epochs (48 h) | `f ≤ 0.30` | Engine A | Two epochs allows one full SRV rotation before an alarm, avoiding churn false positives |
| P4 | `k_src` | ≥ 3 independent (operator, ASN, ideally implementation) | Provider censorship | Code audit + fault injection | Three is the minimum that survives one failure and one lie while leaving a majority; the independence definition matters more than the count |
| P4 | `S_max` | FULL: 19.2 min (finality). SNAPSHOT: declared per deployment, hard refusal at expiry | Stalling provider | §13.3 modes, fault injection | Finality is Ethereum's, not a choice. The snapshot bound is a deployment parameter and §12.6 already carries the machinery |
| P4 | Recovery after 1 week isolation | Verified head restored, no incorrect answer served during isolation | Total chain isolation | Fault injection | Correctness must never degrade; only freshness may |
| P5 | WF classifier precision at `p = 10⁻³` | `RESEARCH REQUIRED` — baseline must be measured first | Single-point observer with a retrained classifier | Engine B, open-world | Setting a target before the undefended baseline exists would be arbitrary. Experiment: M5.2 |
| P5 | Padding overhead | ≤ 50 % bandwidth, ≤ 100 ms added median latency | — | Engine B | The budget beyond which `INTERACTIVE` stops being interactive; a design constraint rather than a security target |
| P5 | Flow-correlation TPR at FPR = 10⁻³ | **No target.** Expected result: correlation succeeds | Two-ended observer | Engine B | §32.1: the honest expected outcome is IMPOSSIBLE, and a target would imply a defence that is not being claimed |
| P6 | `C(0.20, 30 epochs)` | Published as a formula in `S_h`, `r`, `c_infra`, with worked values | Optimising adversary across stake, identities, prefixes | Engine A optimiser | No absolute currency target is defensible when `S_h` is unknown; the deliverable is the function, not a number |
| P6 | Splitting gain under chosen `w`, `B_min` | ≤ 1.2× | Sybil-splitting adversary | Analytic + Engine A | §33.1 shows splitting gain is the failure mode of concave weighting; 1.2× is a pre-registered tolerance, `RESEARCH REQUIRED` on whether it is achievable at acceptable `B_min` |
| P7 | `A_eff`, `A_eff∞` per role | Measured and published; **no threshold** | Per adversary class | §34 tool | §34.5: a single headline figure would be a misuse of the work. The target is the instrument existing and being used |
| P8 | `γ` (inflation factor) | ≤ 2 | 20 % colluding clients, colluding relay pairs | Engine A + ground-truth harness | Beyond 2×, selection weight stops tracking capacity usefully; the threshold is engineering judgement and is marked as such |
| P8 | `ε_bw` vs ground truth | `RESEARCH REQUIRED` | — | Local network with known capacity | No prior exists for a composite decentralised estimator; M8.1 establishes it |

**Seven of nineteen rows are `RESEARCH REQUIRED`.** That is the accurate state of
the design, and §27.2 forbids replacing them with plausible-looking numbers.

---

## 38. Phases P17–P26

### 38.1 Ordering, and why it is not the brief's order

The brief's numbering implies intersection resistance first. **§26.3 requires the
anonymity model first**: P1, P5 and P7 share a posterior, and mechanisms cannot be
evaluated before the instrument that measures them exists. The programme
therefore reorders, keeping the brief's phase numbers so cross-references remain
usable:

```text
   P23 Anonymity measurement ──────────────┐  the instrument; everything
        │                                  │  downstream reports its numbers
        ├──────────────┬──────────────┐    │
        ▼              ▼              ▼    │
   P17 Intersection  P21 Traffic   P22 Economic ◄── sets f, the input to all
        │              analysis      calibration    of the above
        │              │              │
        │              │              ▼
        │              │         P24 Bandwidth measurement
        │              │              │  (P22 and P24 jointly determine
        │              │              │   selection weight, hence f)
        └──────────────┴──────────────┘
                       │
   P19 Eclipse ◄───────┼───────► P20 Chain access
    (mutually dependent: the chain anchors eclipse detection;
     eclipse of chain access is what P20 must prevent)
                       │
   P18 Abuse governance (independent of all of the above)
                       │
                       ▼
   P25 Unified simulation ──► P26 Integrated validation
```

### 38.2 The phases

Effort is engineer-months with a confidence rating. **Research phases have
unbounded tails**; the ranges below are for reaching a *reportable result*,
including a negative one, not for reaching success.

| Phase | Prerequisites | Deliverables | Effort | Conf. | Risk |
|---|---|---|---|---|---|
| **P23** Anonymity measurement | §21 test env | Formal model; measurement tool; per-role baseline at three network sizes; audit of every anonymity claim in the specification | 3–6 em | **High** | Low — mathematics and tooling, no protocol change |
| **P22** Economic / Sybil calibration | P9b, `StakeVault` | §33.1 analysis reviewed; parameter search; adversary optimiser; `C(x,y)` surface; recommended `w`, `B_min`, `L`, caps | 6–12 em | Medium | Medium — the result may be that the price is low |
| **P24** Bandwidth measurement | P22, §14 blind tokens | Ground-truth harness; composite weight; blind attestation; collusion sweep; central-authority comparison | 10–20 em | **Low** | **High** — may not reach `γ ≤ 2`; shares a primitive with §14 |
| **P17** Intersection resistance | P23 | Analytic model; layered guards; forced-sampling limits; topology sweep with joint `P_dea`/`A_eff` frontier | 6–12 em | Medium | Medium — service side likely succeeds, client side likely does not |
| **P21** Traffic-analysis defence | P23, Engine B | Trace harness; baseline attacks; padding machines; defended evaluation; §32.3 dual-use experiment; correlation study | 12–24 em | **Low** | **High** — the field's results age badly and the correlation result is expected negative |
| **P19** Eclipse resistance | P20 (anchor), §7 | Eclipse simulator; view digests; SRV-seeded sampling; bootstrap diversity; chain anchor or its abandonment | 8–15 em | Medium | Medium — anchor design is unresolved (§30.2c) |
| **P20** Decentralized chain access | §12, light client | Multi-source with independence policy; DHT-carried evidence; relayer plurality; isolation recovery | 10–18 em | Medium | Medium — 2.7 GB/yr in the DHT is a real load |
| **P18** Abuse governance | §10, §12 | Taxonomy; five local mechanisms; assertion format and composition; removal-cost figure; concentration simulation; the §29.6 statement | 6–12 em | Medium | Medium — the honest outcome is partly a refusal to build |
| **P25** Unified simulation | P17–P24 | Engines A and B; shared config and adversary language; sweep harness; cross-validation | 12–20 em | Medium | Medium — scope creep is the main risk; the two-engine split is the mitigation |
| **P26** Integrated validation | P25 | Joint sweeps; interaction study; updated threat model; updated production criteria; the §40 answer | 6–12 em | Medium | Medium — interactions may undo individual results |

**Programme total: 79–151 engineer-months**, with the wide range driven almost
entirely by P21 and P24. A realistic reading is that this is a multi-year effort
for a small team, and that P23 and P22 — the two cheapest and highest-confidence
phases — should be done first regardless of whether the rest is funded, because
they produce the numbers that tell you whether the rest is worth funding.

### 38.3 Per-phase exit criteria and non-establishment

Each phase's falsifiable exit criteria are given in its workstream: E1.x §28.3,
E2.x §29.4, E3.x §30.3, E4.x §31.3, E5.x §32.4, E6.x §33.3, E7.x §34.4, E8.x
§35.3. P25's exit is §36.4's five honesty requirements being enforced by the
harness rather than by convention. P26's exit is §40 being written with every
row of §27.1 resolved to one of the four outcomes.

**What every phase does NOT establish, stated once because it applies to all of
them:** simulation results are not deployment results. Every number in this
programme is produced against modelled populations with assumed distributions,
and the relationship between those and a real network is itself unestablished.
§26.3's reduction, §33.1's concavity argument and §34.1's guard arithmetic are
analytic and will survive; everything measured in a simulator is provisional
until a real network exists to check it against.

### 38.4 Interactions that must be tested jointly

| Interaction | Why it matters |
|---|---|
| P22 ↔ P24 | Together they determine selection weight, hence `f`, hence every other result. An error here propagates everywhere |
| P17 ↔ P23 | Guards trade `P_dea` against `A_eff`; neither may be reported alone |
| P19 ↔ P20 | The chain anchors eclipse detection; eclipse can target chain access |
| P21 ↔ P23 | Padding changes the observation, hence the posterior, hence `A_eff` |
| P18 ↔ P12/P22 | Bonded complaints make abuse response a wealth test; the abuse design must not inherit the plutocracy of the economic design |
| P21 ↔ P22 | Padding costs bandwidth the accounting plane pays for; relays have an incentive to disable it |

---

## 39. Risk Register and New Attacks Introduced

### 39.1 Programme risks

| # | Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|---|
| R-1 | The programme produces mostly negative results | The network ships with quantified weaknesses rather than fixes | **High** | This is an acceptable outcome by design (§27.1). The deliverable is knowledge, and quantified weakness is better than assumed strength |
| R-2 | Simulation results do not reflect reality | Confident numbers that are wrong | **High** | Analytic models preferred where they exist; synthetic distributions labelled in output; §38.3's blanket caveat |
| R-3 | P21 never converges | Traffic-analysis defence indefinitely open | Medium | Pre-registered overhead budget; ship the measurement and the honest statement rather than an ineffective defence |
| R-4 | `C(x,y)` turns out low | The economic layer does not buy security | Medium | Report it; feed back into §15 and R14 rather than adjusting the metric |
| R-5 | Blind-token sharing between §14 and §35 breaks unlinkability | Payment/attestation correlation deanonymises | Medium | E8.5's companion test; separate issuance epochs; specified once in one place |
| R-6 | Chain-evidence load makes the DHT unusable | P20 fails on cost, not on design | Medium | Retention and pruning policy specified against real coding parameters before build |
| R-7 | Policy subscription converges on one issuer | Voluntary re-centralisation | **High** | E2.4 measures it; no shipped default; but no technical prevention exists |
| R-8 | The measurement tooling becomes an attacker's tool | §34's instrument computes what an adversary wants | Certain | Accepted; the alternative is not knowing |
| R-9 | Effort exceeds the estimate by more than 2× | Programme abandoned mid-way | Medium | P23 and P22 first, so partial funding still yields the decision-relevant numbers |

### 39.2 New attack surface created by the mitigations

Collected from the workstreams so a reader sees the aggregate rather than eight
scattered lists. **Every mitigation in this programme adds attack surface**, and
several add more than they remove in specific configurations.

| From | New attack | Severity |
|---|---|---|
| §28 layered guards | Layer-targeting; L1 concentration; guard-set file theft; bond-gated layers concentrate the most critical role among the wealthiest | **High** |
| §29 policy assertions | Assertion flooding; subscription inference revealing operator politics; quarantine as a denial primitive | Medium |
| §30 view digests | Digest poisoning to trigger false alarms; alarm-driven repartition; sampling-privacy leak | Medium |
| §31 multi-source | Endpoint-discovery manipulation; evidence-store poisoning; independence-policy gaming | Medium |
| §32 padding | Padding-machine fingerprinting; class distinguishability; padding as a resource-exhaustion vector | **High** |
| §33 economic parameters | Bond-driven centralisation; slashing weaponised against honest operators; lock periods deterring honest participation more than adversaries | **High** |
| §34 measurement tool | Provides an adversary a ready-made target-population analysis | Low |
| §35 attestation | Attestation withholding; aggregator observation; blind-token linkage with §14 | **High** |

---

## 40. Updated Threat Model, Readiness Criteria, and the Answer

### 40.1 Threat-model deltas

§18 is amended, not replaced. Each mitigation gets a row stating what it
addresses, what it does not, what it assumes, and what it introduces — the
existing four-column discipline extended:

| Mitigation | Addresses | Does **not** address | Assumes | Introduces |
|---|---|---|---|---|
| Layered guards (§28) | Guard discovery against services | Client-side long-term exposure; availability leakage | `f` is correctly measured (§35) | Layer-targeting; L1 concentration |
| Policy assertions (§29) | Operator-local enforcement for nine abuse classes | Global removal; legal exposure | Operators choose issuers independently | Subscription inference; concentration |
| View digests + anchor (§30) | Eclipse detection | Eclipse recovery without any honest channel | Chain access survives (§31) | Digest poisoning; false-alarm steering |
| Multi-source chain access (§31) | Provider censorship, stalling, unavailability | Broadcast verification; Ethereum-level failure | ≥ 3 genuinely independent sources exist | Endpoint-discovery manipulation |
| Padding machines (§32) | Website fingerprinting, bounded | End-to-end correlation | Classifier evaluation is done on defended traces | Machine fingerprinting; class leakage |
| Calibrated bonds (§33) | Cheap mass Sybil creation | Wealthy adversaries; plutocracy | `S_h` is substantial | Bond centralisation; slashing abuse |
| Anonymity measurement (§34) | Unquantified claims | Any actual anonymity | Model priors approximate reality | An adversary's analysis tool |
| Composite bandwidth weight (§35) | Reciprocal inflation, capital inflation | Majority collusion; selective service | Clients attest honestly and are numerous | Withholding; aggregator observation; token linkage |

**The rule from §7 of the Constitution stands unchanged**: every anonymity claim
is quantified and scoped, and the words *perfect anonymity*, *untraceable*,
*impossible to block* and *unbreakable* do not appear.

### 40.2 Updated MVP definition

§24's ladder (M1–M6) tests function. This programme adds a rung that tests
*knowledge*, and it should gate any public deployment:

> **M7 — The instrumented network.** On the local test network at ≥ 500 simulated
> nodes: `A_eff` and `A_eff∞` are computed and published for all eight roles;
> `P_ecl` and `T_det` are measured at `f = 0.20`; a verified chain read completes
> with all but one source hostile; the WF baseline is measured with precision
> reported at `p = 10⁻³`; and `C(0.20, 30)` is published as a formula.
> **Pass condition: the numbers exist and are published — not that they are good.**
> M7 is a knowledge gate, not a security gate.

### 40.3 Updated production-readiness criteria

Added to §22's existing gates, and all four are falsifiable:

1. Every `[UNSOLVED]` in §25 resolves to DEPLOYED, BOUNDED, IMPOSSIBLE or REFUTED
   in §27.1's matrix, with evidence.
2. No anonymity claim in the user-facing documentation lacks a scope and a number.
3. The quantified residual risks are stated in the operator documentation, in
   plain language, where an operator will actually read them — specifically that
   `INTERACTIVE` traffic is vulnerable to end-to-end correlation, that `A_eff` is
   in the hundreds rather than the network size, and that storage and gateway
   operators carry legal exposure that encryption does not remove.
4. The negative results are published alongside the positive ones.

### 40.4 What remains fundamentally unsolved

After this entire programme, on the honest expectation recorded in §27.1:

| Problem | Expected residual state |
|---|---|
| **End-to-end flow correlation** | Not solved and not solvable at interactive latency. Bounded only by the adversary's coverage |
| **Anonymity in a small network** | `A_eff` is bounded by the user population. The early network provides very little anonymity to anyone, and no mechanism changes this |
| **Sybil resistance without capital** | Converted to a price, not removed. Plutocratic by construction (§33.1) |
| **Global abuse response** | Deliberately absent. §29.6 makes it a permanent architectural property |
| **Eclipse recovery in a total partition** | Requires a channel the adversary does not control; the design makes that conjunction expensive, not impossible |
| **Ethereum as a systemic dependency** | Bounded (§31.5), never removed, while ownership is on-chain |
| **Bandwidth measurement under majority collusion** | Not solvable by peer measurement |
| **Long-term intersection against an always-online service** | Slowed by orders of magnitude, never eliminated |
| **The user's own behaviour** | Dominates every protocol property and is outside the system entirely (§18.21) |

### 40.5 The answer to the question the brief asks

> *Can AXON move from a network that openly acknowledges eight major weaknesses
> to one where each has a demonstrated mitigation, a quantified residual risk, or
> a demonstrated reason it cannot be solved?*

**Yes for six, partly for one, and no for one — and the distribution is the
finding.**

- **Demonstrated mitigation is plausible for three**: eclipse detection (P3),
  decentralized chain access (P4), and the local-enforcement half of abuse
  handling (P2). These are engineering, and the engineering is tractable.
- **Quantified residual risk is the realistic outcome for four**: intersection
  resistance (P1), economic Sybil cost (P6), anonymity-set size (P7), and
  bandwidth measurement (P8). Each ends with a number rather than a defence, and
  in at least two cases — plutocratic Sybil pricing and small-network anonymity —
  the number will be unflattering.
- **Demonstrated impossibility is the expected outcome for one**: end-to-end
  correlation of interactive traffic (P5), which no deployed low-latency system
  prevents and which AXON should stop implying it might.
- **The partial case is global abuse response**, which is half engineering and
  half a permanent architectural refusal (§29.6).

The programme's real value is not that it makes AXON safe. It is that it replaces
eight unquantified weaknesses with eight measured ones, and a system whose
weaknesses are measured can be deployed deliberately — matched to threat models
it actually serves, and honestly declined for those it does not. **That is a
better outcome than a system that believes it solved them.**

### 40.6 What this section does NOT establish

- That the programme will be executed. It is 79–151 engineer-months and the
  expected outcome for several phases is a negative result.
- That the expected outcomes in §27.1 are correct. They are predictions recorded
  to prevent retrospective optimism, and they may be wrong in either direction —
  including optimistically.
- That resolving all eight makes AXON safe to use for a targeted individual
  facing a state adversary. It does not, and §4's refusals stand unchanged.
- That the numbers, once produced, will be acted on. §27.2's rule against moving
  goalposts is a discipline, not a mechanism, and nothing in the architecture
  enforces it.
