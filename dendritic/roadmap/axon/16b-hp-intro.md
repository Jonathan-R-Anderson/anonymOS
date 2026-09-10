# Part V — The Eight Hard Problems

**A research-and-engineering programme to convert §25's `[UNSOLVED]` list into
measured outcomes.**

Part V extends the specification; it replaces nothing. Sections 1–25 describe a
network that openly acknowledges eight major unresolved weaknesses. This part
asks whether each can be resolved, defines how the answer would be recognised,
and schedules the work — under one rule carried over from the rest of the
document: *never silently turn an unsolved problem into an assumed solution.*

---

## Executive summary

Every workstream must end in exactly one of four states — `DEPLOYED`, `BOUNDED`,
`IMPOSSIBLE`, `REFUTED` — and a fifth outcome, *the metric was weakened until the
mechanism passed*, is defined as a programme failure (§27.2). Targets are
pre-registered before mechanisms are built. Seven of nineteen quantitative
targets are marked `RESEARCH REQUIRED` rather than filled with plausible numbers.

**Eight findings, produced by writing this part, that change the existing
specification:**

**1. Four of the eight problems are one problem.** Intersection resistance,
traffic analysis, anonymity-set size and path selection all reduce to the
adversary's posterior over endpoints. The anonymity model is therefore an
*instrument*, not a peer workstream, and it must be built first — §26.3 reorders
the brief's phases accordingly.

**2. AXON's current guard parameters are at a bad point on the curve.** With
`g = 2` guards rotating every 45 days, a client passes through a hostile guard
within a year with probability **0.56 at a 5 % adversary** and **0.82 at 10 %**
(§28.1). §8.5 described this choice as "deliberately between Tor and I2P"; the
arithmetic that would have justified it was never done, and it does not.

**3. Guards cut the anonymity set to hundreds.** A user is anonymous among those
sharing their guard — roughly `U·g/R`, which is **200 users** at 10⁵ users and
1 000 relays, not 100 000 (§34.1). Guards reduce exposure probability and reduce
the anonymity set *with the same mechanism*, so no configuration optimises both.
The two workstreams are now required to report each other's number.

**4. Stake weighting cannot be both Sybil-resistant and anti-plutocratic.**
Concave weighting — the natural anti-whale choice — pays an adversary to split
into many identities; convex weighting suppresses splitting and amplifies
concentration; linear is neutral on both (§33.1). The escape is a per-identity
minimum bond, and without it §15's "bonded stake" is not a Sybil defence.

**5. Attacking the economic layer is cheaper than it sounds.** The cost of 20 %
of selection probability for a year is an *opportunity* cost of roughly **1.25 %
of honest stake**, principal recoverable (§33.2) — not "acquire 25 % of the
stake". Security also scales with honest stake, a quantity the protocol does not
control and a new network does not have.

**6. Relay-signed delivery receipts are worthless.** Two colluding relays sign
each other's receipts at the cost of two signatures and gain weight for capacity
neither has (§35.1). The only incentive-aligned attester is the client, which
forces blind-signed attestation and shares a primitive — and a risk — with §14's
payment tokens.

**7. AXON has a cover-traffic source no other system has.** It carries bulk,
latency-tolerant storage traffic *and* interactive traffic in one network. Bulk
flows can carry interactive cells as cover that is simultaneously doing real work
— roughly 2.7 GB/year per node of chain evidence alone (§32.3). Cover traffic
everywhere else is pure waste; here it may be free. This is the programme's most
promising original idea and it may also fail outright.

**8. The chain is the natural anchor for eclipse detection.** A fully eclipsed
node cannot detect its own eclipse from inside the partition — it needs a channel
the adversary does not control, and the light client already is one (§30.2c). An
eclipsing adversary must therefore also eclipse chain access, which is exactly
what the chain-access workstream prevents. The two problems defend each other.

**The answer to the brief's central question** (§40.5): yes for six of the eight,
partly for one, no for one. Three end in demonstrated mitigations, four end in
quantified residual risk rather than a defence, one ends in demonstrated
impossibility. The programme's value is not that it makes AXON safe — it is that
it replaces eight unquantified weaknesses with eight measured ones, and a system
whose weaknesses are measured can be deployed deliberately.

**Cost: 79–151 engineer-months**, dominated by traffic analysis and bandwidth
measurement. If only part is funded, §38.2 recommends the anonymity model and the
economic calibration first — the two cheapest, highest-confidence phases, and the
ones that produce the numbers telling you whether the rest is worth funding.

---
