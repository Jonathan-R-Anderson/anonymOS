# Part X — Decentralized Content Governance and Reputation Routing

**The organising principle, in one sentence:** the DAO determines what the
network considers unacceptable; reputation determines who should be trusted;
each node determines what it personally wants to facilitate; and the routing
layer learns which paths are useful from those decisions.

That principle is sound and this Part builds it. But it collides with Parts I–IV
in one specific place, and everything here is shaped by that collision, so it is
stated first rather than discovered in §92.

---

## 84. The finding that shapes this Part: a relay cannot filter what it cannot see

**Policy needs visibility. Anonymity is the deliberate absence of visibility.
They are the same variable pulled in opposite directions, and no amount of
engineering makes both true at once.**

§8 exists so that a middle relay does not know what it is carrying. The wide-block
permutation (§8.3, as amended by §81.1.1), the fixed cell size (§16.3 M1), the
per-hop key schedule — their entire purpose is that a relay forwards bytes it
cannot interpret. That is not a side effect to be worked around. It is the
product.

A content-policy engine at relay position asks that relay to decide whether it is
willing to carry `malware`. To decide, it must know. To know, the traffic must
tell it — and a relay that learns the category of the traffic it carries has
learned something about the endpoints, in a network whose whole claim is that it
learns nothing. Worse, it is a *queryable* channel: an adversary who controls a
relay and can observe which categories it declines has a probe for what its
neighbours are carrying.

So the design cannot be "every node filters everything". It has to be split by
**where the node already knows what it is handling anyway.**

> ### Ruling R-84.1 — the three points where policy applies, and the one where it does not
>
> A node may apply content policy at exactly three positions, because at each of
> them it already holds or can see the thing it is deciding about:
>
> | Position | What it already knows | Policy it may apply |
> |---|---|---|
> | **HOST** | it holds the object and can read its manifest and labels | refuse to store; refuse to serve; drop what it holds |
> | **EXIT / GATEWAY** | the destination is in the clear by construction (§17.1) | refuse to egress; refuse a destination class |
> | **PUBLISH / REGISTRAR** | it is being asked to bind a name to content (§11, §12) | refuse to register; honour a prune record |
>
> At **RELAY** position a node applies **no content policy of any kind**, because
> it has no content to have a policy about. It may still refuse traffic on
> grounds it can see without breaking anything: cell rate, circuit count
> (`MaxCircuitsPerRelay`, §5), bond, and its own resource limits. Those are
> properties of the *flow*, not of the *content*, and they are already built.
>
> **This is not a limitation to be lifted later.** A future version that lets
> relays filter by category has abandoned §8, and should say so in those words
> rather than describing it as an enhancement.

**The consequence for the design as proposed.** Phase 2's classifications,
Phase 7's policy engine and Phase 11's pruning all survive intact — they operate
on *content the node holds*, which is the HOST position. Phase 8's path
reinforcement does **not** survive in the form proposed, and §92 rebuilds it.

---

## 85. Content identity — the layer everything else keys on

> **BUILT (2026-08-17) — G1.** `internal/axon/content`, 6 tests. **E-G1 holds:**
> a report survives a content republish and still names the version it was made
> against.
>
> **§11 forced a ruling this section did not anticipate.** Only a REGISTRABLE
> name has an on-chain namehash — `NameHash()` refuses a subordinate rather than
> inventing one. But §85 requires reports to accumulate against a name hash, so
> a subordinate would accumulate against nothing.
>
> > **Ruling R-85.2 — a subordinate's reports count against its REGISTRABLE
> > PARENT.** The chain is what governance can act on: §93 can prune or seize a
> > registered name and has no handle on `blog.acme.lab.axon`. The registrant
> > controls their own subordinates, so attributing them upward is where the
> > responsibility already sits — and the alternative is a namespace where
> > anyone sheds a report history by publishing under a fresh subdomain.
> >
> > The full name is not lost: `ZoneID` is computed over the name AS GIVEN, so
> > two subordinates of one parent share a subject and stay distinguishable
> > within it. A report can still say which page.
>
> **`For` takes a `name.Name`, never a string**, so an unnormalised name cannot
> reach a report — otherwise `ACME.LAB.AXON` and `acme.lab.axon` would be two
> subjects and a publisher could shed a history by changing case.
>
> **The owner is recorded per observation, not resolved at read time.** R-93.3
> keeps a seizure in a name's history precisely so a new owner is judged on
> their own content; an identity that looked the owner up later would silently
> re-attribute every old report to whoever holds the name now.
>
> `Superseded()` makes the appeal's defence computable — *"that CID is not what
> this name serves now"* — and deliberately does **not** discard the report: a
> system that dropped reports whenever content changed would let a publisher
> clear its record by republishing. It answers whether the defence is
> **available**, which is a governance question under §93.

**The requirement, restated:** a domain must not escape moderation by moving to
another host. That means the identity being reported, reputed and pruned is the
*content*, not the *location*.

§10 already supplies most of this and it should not be redesigned. An object is
addressed by a BLAKE3 CID over its bytes; a site is an `ObjectManifest`; a
mutable site is a `MutableRef` with a blinded key and a `seq` ratchet; a name is
bound to content on chain (§12). What is missing is the **join**: a stable
identity that survives a content update, so that a report against a site is not
voided by publishing one new byte.

```text
NameRecord (§12, on chain)          the anchor. Survives content changes.
   │  nameHash ── owner ── seq
   ▼
ContentIdentity                     what reports, labels and prunes attach to
   │
   ├── name_hash        keccak namehash, from §11.3
   ├── zone_id          SHA-256, from §11.3.2's normalisation
   ├── owner            the on-chain owner at time of observation
   ├── manifest_cid     BLAKE3 CID of the version observed
   ├── service_type     site | api | stream | store | other
   └── observed_at      block height, so a claim is anchored in time
```

> ### Ruling R-85.1 — a report names a VERSION and inherits to the NAME
>
> A report carries `manifest_cid`, because evidence about content that cannot
> name the content is not evidence. But it accumulates against `name_hash`,
> because otherwise every report is voided by a republish and the system does
> nothing.
>
> The two are kept distinct so that an **appeal can point at the difference**:
> "that CID is no longer what this name serves" is a real and checkable defence,
> and a design that only tracked the name could not express it.

**Not solved here, and it is the hard case:** content that is legitimate at
publication and abusive afterwards, under an unchanged CID, because the abuse is
in what the site *does* rather than in what it *is*. The identity layer cannot
see behaviour. §91's confidence estimates are the partial answer and they are
not a good one.

---

## 86. Classification: labels, not verdicts

> **BUILT (2026-08-17) — G2.** `internal/axon/content/label.go`, 7 tests. **E-G2
> holds in both halves**: behaviourally, an unattributed or unsigned label is
> refused; and by schema audit, the `Label` type cannot express one.
>
> **The schema audit was too weak on first writing.** It counted
> `func Sign(` occurrences, so a second constructor named `SignSkipped` sailed
> straight past — found by adding one and watching the audit stay green. It now
> walks every top-level function returning a `Label` and requires an
> `ed25519.Sign` in its body. Removing the `Claimant` field is caught by the
> compiler, which is stronger still.
>
> **The signature covers BOTH of §85's keys plus the category and confidence.**
> Signing the category alone would let a label be moved from one name to another
> — or re-pointed at a different version — with its signature intact. Tested in
> all three directions.
>
> **`unknown` is not signable.** It is the absence of a claim, and signing one
> would assert that content *is* unclassified, which is different and
> unfalsifiable. It is also the zero value, so an uninitialised `Category` can
> never be mistaken for a real claim.
>
> **§94's rule is in the type**: `Jurisdictional()` marks `ILLEGAL`,
> `EXTREMIST` and `COPYRIGHT`; `PruneEligible()` returns true for **only**
> `MALWARE` and `PHISHING`. A test asserts the jurisdictional three are never
> prune-eligible, and that taste (`ADULT`, `GAMBLING`, `POLITICAL`, `SOCIAL`)
> is not either.
>
> **`LabelSet` deliberately does not reduce claims to a verdict**, and reports
> distinct **claimants** separately from claim count — ten labels from one
> claimant are one opinion. §90's corroboration factor must be sublinear in
> identity count, and a set that conflated the two would defeat that before the
> weighting ran.

The proposed categories are adopted as-is:

```text
GENERAL  TECHNOLOGY  SOCIAL  POLITICAL  ADULT  GAMBLING
MALWARE  PHISHING  SPAM  ILLEGAL  EXTREMIST  COPYRIGHT  UNKNOWN
```

> ### Ruling R-86.1 — a label is a claim by an identified party, never a fact
>
> Every label is stored as `(subject, category, confidence, claimant, signature,
> at)`. There is no unattributed label anywhere in the system, and no field
> anywhere that says "this content IS malware" without saying who says so.
>
> The reason is not epistemic tidiness. An unattributed label is a censorship
> primitive with no accountability: whoever can write it can suppress content and
> nobody can be held to it. Attribution is what makes §90's reporter reputation
> possible at all — you cannot score the accuracy of an anonymous claim.

**`UNKNOWN` is not a category, it is the absence of one**, and the distinction
matters for the policy engine: `DEFAULT: unknown -> don't relay` in the proposal
would, under R-84.1, become `unknown -> don't HOST`, and a node that refuses to
host anything unlabelled is a node that hosts nothing on a young network. §87
gives it a different default and says why.

**Three of these categories are not like the others.** `ILLEGAL`, `EXTREMIST`
and `COPYRIGHT` are jurisdiction-dependent: the same bytes are lawful in one
place and not in another, and no vote makes that untrue. They are retained as
labels, and §94 rules that the DAO may **not** treat them as grounds for a global
prune — only `MALWARE` and `PHISHING`, which are attacks on the network's own
users and are not a matter of opinion.

---

## 87. Node policy: what a node is willing to facilitate

> **BUILT (2026-08-17) — G3.** `internal/axon/content/policy.go`, 8 tests.
> **E-G3 holds**: a node with `host_block: malware` refuses to store the object
> and **relays normally for every category**.
>
> **There is no relay-position API, and that absence is the feature.** Not a flag
> defaulting to off, not a method returning "allow" — nothing to call. An
> unimplemented option is a request to implement it. `Position` has no relay
> member, so a relay decision is not expressible, and `DecideRelay` exists only
> to **fail loudly** at the call site somebody would naturally reach for. A
> package that simply omitted it would leave the next person to write their own
> filter, which is the outcome R-84.1 forbids.
>
> **R-87.1 is the zero value.** A fresh `NodePolicy{}` hosts unlabelled content.
> The permissive default fails toward "the network works"; the strict one fails
> toward "the network is empty and nobody can tell why".
>
> **Only TRUSTED issuers count**, which is R-88.1's local reducer one layer down.
> A stranger's signed `malware` claim is not false — it is not this node's
> evidence. Without that rule, **anyone could make any node drop any content by
> signing a claim about it**, which would make labelling an attack.
>
> Two smaller rulings: **block beats allow** (an operator who wrote a category
> into the block list meant to refuse it), and an allow-list governs **claims**
> rather than absence, so it does not silently convert the unknown default into
> a refusal.
>
> **The policy is never serialised**, enforced by an audit — a published policy
> is a search index for whoever wants to seize a host. That audit first matched
> the substring `Publish` inside `PositionPublish`, a legitimate position under
> R-84.1; it now matches methods, because an audit that fails on correct code
> gets deleted.

```text
NodePolicy
  ├── host_allow      [category]      what it will store and serve
  ├── host_block      [category]
  ├── exit_allow      [category]      what it will egress, if it is an EXIT
  ├── exit_block      [category]
  ├── min_label_conf  0.0–1.0         below this, treat as UNKNOWN
  ├── unknown         host | refuse   default: HOST
  ├── prune_policy    enforce | ignore | quarantine
  └── trusted_issuers [identity]      whose labels this node believes (§88)
```

> ### Ruling R-87.1 — the default for `UNKNOWN` is HOST, not refuse
>
> The proposal's `unknown -> don't relay` inverts on a young network into "store
> nothing", because almost nothing is labelled yet. Worse, it makes labelling a
> *gate*: content becomes hostable only once somebody has classified it, and
> whoever classifies first controls what exists.
>
> The default is therefore to host unlabelled content, and an operator who wants
> the strict reading sets `unknown: refuse` explicitly. The permissive default is
> the one that fails toward "the network works"; the strict default fails toward
> "the network is empty and nobody can tell why".

**The policy is local and is never published.** A node that advertised its policy
vector would be advertising what it holds, which is a search index for anyone
looking for a host to seize. What a node publishes is its *prices and
capabilities* (§95), not its refusals.

---

## 88. Reputation — and the collision with R14

**This is the second collision and it is as sharp as §84's.**

R14 forbids a consensus document and forbids any party measuring the network on
everyone else's behalf. §23's P12a is built on that: profiles are first-hand,
never transmitted, never gossiped, because *"a capacity tier derived from your
own traffic is a fingerprint of your own traffic if it ever escapes the node"*.

A network-wide node reputation vector is precisely the global metric R14 rules
out. It cannot simply be added.

> ### Ruling R-88.1 — reputation is a set of signed attestations plus a LOCAL reducer
>
> There is no network-wide reputation score, and no query that returns one. What
> exists is:
>
> ```text
> Attestation {
>   subject     node id or content identity
>   dimension   uptime | bandwidth | routing | hosting | reporting |
>               governance | classification | economic
>   value       [-1, 1]
>   basis       what the issuer OBSERVED, and over what window
>   issuer      identity, bonded (§15)
>   signature
>   at
> }
> ```
>
> and each node computes its own view by reducing the attestations it chooses to
> trust. Two nodes with different `trusted_issuers` legitimately reach different
> conclusions, and **that is the design rather than a defect** — it is what makes
> this a pluralistic network instead of a consensus one.
>
> Three properties follow and each is a test in §97:
>
> - **A node's own first-hand observations always outrank attestations.** P12a's
>   ordering, extended: what you saw yourself cannot be overridden by what you
>   were told.
> - **An attestation is evidence about the ISSUER as much as the subject.** An
>   issuer whose attestations disagree with a node's own observations loses
>   weight *with that node*, locally, without any global consequence.
> - **There is no bootstrap by declaration.** A new node has no attestations and
>   is treated as UNKNOWN, which by R-87.1 is workable rather than excluded.

**Dimensions are separate, per the proposal, and the reason is worth keeping:**
someone can be an excellent malware reporter and a poor governance participant,
and a single score forces the network to choose which of those to be wrong
about.

**Decay.** `R(t) = R(t-1) × 2^(-Δt/halflife) + evidence`, the same exponential
form as P12a's profiles, applied on read for the same reason (T12a.5): a score
that only decays on write freezes when observation stops, and asserts a stale
figure with undiminished confidence.

---

## 89. The reporting protocol

> **BUILT (2026-08-17) — G4.** `internal/axon/dht/report.go`, 6 tests. A new DHT
> record class `report`, alongside the six §7 already defines. **E-G4 holds**:
> three nodes decode the record, derive the key from **the record's own fields**,
> check it against the key it arrived under, and verify the signature — none of
> them having contacted the reporter.
>
> **The key is `subject ‖ reporter`, and the order is load-bearing.** Subject
> first, so every report about one name shares a pre-image prefix and the
> neighbourhood is about the SUBJECT. Reporter second, so **one identity filing
> repeatedly rewrites its own record rather than filling the neighbourhood with
> copies** — a correction, not a second voice. Two different reporters land on
> two keys, or the second would silently overwrite the first.
>
> **R-89.1 is enforced, not documented.** Evidence entries that look like a URL
> — `http:`, `https`, `ipfs:`, `//` — are refused at signing time, as is anything
> that is not exactly 32 bytes. That second rule matters as much: without it
> "evidence" becomes a payload channel smuggled inside a governance record.
>
> **The signature binds the evidence LIST, order-sensitively.** Reordering it or
> **trimming the inconvenient half** both invalidate the report. Without that,
> "the first piece of evidence" means nothing and a report can be quietly
> weakened after filing.
>
> **A deliberate non-property: the validator makes no moderation decisions.** A
> report naming an undefined category or an unregistered name is still stored. A
> validator that dropped reports it disagreed with would be moderating at the
> **storage layer**, where nobody can see it happen and no vote is involved.
> §90 weighs; §93 decides.

```text
Report {
  subject      ContentIdentity (§85) — name_hash AND manifest_cid
  category     §86
  reason       bounded free text
  evidence     [CID]  — stored in the DCS (§10), not in the report
  reporter     identity
  stake        bonded amount (§15)
  at
  signature
}
```

Reports are DHT records (§7), not submissions to a server. A report is a
**publication**, and it is public: a private report is a denunciation nobody can
audit, and §90 cannot score the accuracy of a claim it cannot see.

> ### Ruling R-89.1 — evidence is content-addressed and stored, not linked
>
> `evidence` is a list of CIDs in the network's own store, never a URL. A report
> whose evidence lives at an external URL is a report whose evidence can be
> withdrawn after the vote, and the record then says a thing happened with
> nothing behind it.

**The privacy cost, stated.** A report identifies the reporter to everyone. That
is deliberate — §90's entire mechanism needs accountable reporters — but it means
**reporting is not an anonymous act**, and a user in a jurisdiction where
reporting certain content is itself dangerous should not use this system. §96's
anonymous credentials are the eventual answer and they are not built.

---

## 90. Reporter reputation and Sybil resistance

> **BUILT (2026-08-17) — G5.** `internal/axon/content/reputation.go`, 9 tests.
> **E-G5 holds**: one reporter at maximum reputation, flawless history and a
> proven bond cannot reach the prune threshold — and cannot get there by filing
> fifty times either.
>
> **The E-G5 test asserts the RELATIONSHIP, not the numbers.** `weight < 1.0`
> would pass by coincidence after a recalibration that raised the cap and the
> threshold together; `MaxSingleReporterWeight < PruneThreshold` cannot. R-90.1
> is what stops the system converging on a small number of trusted denouncers —
> the failure mode every reputation-weighted moderation system has actually
> exhibited — so a perfect history must never be a veto.
>
> **CORROBORATION MUST BE SUBLINEAR, and §90's draft did not say so.** That is
> the difference between "several people saw this" and "someone bought several
> identities": under a linear factor, `k` identities buy `k×` influence and §17's
> Sybil analysis applies unchanged, so the whole weighting is decorative. `sqrt`
> is used — doubling influence costs **four** identities. `log` is also sublinear
> and so flat that fifty genuine reporters barely outweigh five, which punishes
> the case the system exists to reward. **The exponent is provisional; the
> sublinearity is not.**
>
> **Corroboration scales the MEAN, not the sum.** Summing weights and then
> multiplying by `sqrt(n)` lets 200 zero-reputation identities outweigh one
> credible reporter — the exact attack the factor was meant to price. Injecting
> that change fails two tests.
>
> **Independence is P12b's, and `peer.DomainKeys` is not reimplemented here.**
> That function already carries the rule that matters: an unknown domain yields
> **no key at all**, so two unknowns never collide. A second copy in this package
> would be a second place to get it wrong, and the two would drift the first time
> the ladder gained a rung. Grouping is transitive union-find — if B can be
> compelled alongside both A and C, all three fall together. Twenty identities
> under one on-chain operator are **one voice**.
>
> **The flattering case is reported, not buried.** A reporter who cannot be
> placed in any domain counts as its own group, so on a young network
> corroboration looks better than it is; `Result.Undetermined` says by how much.
>
> **Accuracy is Laplace-smoothed** — an unsmoothed rate makes a first report
> either worthless (0/0) or perfect (1/1), and one outcome is not a history.
>
> **Every figure inherits P14's `[UNSOLVED]` calibration in full.** There is no
> bond amount known to make governance capture infeasible, because that depends
> on a token price and a population that do not exist. What is *not* provisional
> is the shape: the cap and the sublinearity are structural and no parameter set
> switches them off. All four properties were verified by injection.

The proposed weight, made precise:

```text
weight(report) = clamp(reporter_rep[category], 0, 1)
               × accuracy[category]
               × sybil_factor(reporter)
               × corroboration_factor(report)
```

where `accuracy[category]` is the reporter's historical rate of reports in that
category that survived challenge, and `corroboration_factor` counts
*independent* corroborating reports — independent in the §12/P12b sense of
distinct prefix, ASN and **on-chain operator**, because ten reports from one
operator are one report.

> ### Ruling R-90.1 — no reporter can carry a prune alone, at any reputation
>
> `weight` is capped so that a single reporter, however perfect their history,
> cannot reach the threshold in §93 unaided. The cap is not a tuning parameter;
> it is the thing that stops the system from converging on a small number of
> trusted denouncers, which is the failure mode every reputation-weighted
> moderation system has actually exhibited.
>
> A corollary the proposal does not draw: **`corroboration_factor` must be
> sublinear**, or an adversary with `k` operator identities buys `k×` influence
> and §17's Sybil analysis applies unchanged. Sublinear corroboration is the
> difference between "several people saw this" and "someone bought several
> identities".

**Sybil resistance reuses P14 rather than inventing a second system.** Identity
age, bond via `StakeVault`, per-prefix/ASN/operator caps at every selection point
(`sybil.CapsFor`), and proof-of-work for cheap roles all exist. **P14's
calibration is `[UNSOLVED]`** and that unsolvedness is inherited here in full:
there is no bond amount known to make governance capture infeasible, because
that depends on a token price and a population neither of which exists.

---

## 91. Automatic categorization: confidence, never truth

The classification engine combines DAO classifications, human reports, node
labels, metadata and content fingerprints into a per-category confidence.

> ### Ruling R-91.1 — a confidence estimate may inform a HOST decision and may never inform a PRUNE
>
> §93's prune path requires human reports with evidence and a vote. An automatic
> classifier may feed a node's own hosting policy, where a false positive costs
> one node's storage and is reversible, and may not feed a network-level record,
> where a false positive is a censorship event with a governance record behind
> it.
>
> The asymmetry is the point: the two errors are not comparable, so they do not
> get the same evidentiary standard.

**The classifier is `[NEEDS RESEARCH]` and should stay that way for a long time.**
Its inputs are adversarial by construction — anything an attacker can influence
becomes an attack surface for mislabelling a competitor — and there is no corpus
to validate it against, because there is no content on the network.

---

## 92. Reputation-aware routing, rebuilt

The proposal's path reinforcement learns *"traffic through this neighbour tends
to lead to content I want to facilitate"*. Under R-84.1 a relay cannot know what
content its traffic leads to, so that signal does not exist at relay position and
the mechanism cannot be built as described.

**And the goal it describes is one the architecture actively refuses.**
"Specialized routing regions — a technology-heavy network, a media-heavy network"
is a partitioned anonymity set. §12's whole apparatus exists to keep the
candidate set wide; a network that sorts itself into regions has given each user
a smaller crowd to hide in, and the region a user's traffic sits in is itself an
identifier.

> ### Ruling R-92.1 — path reinforcement is by DELIVERY, never by CONTENT
>
> A node reinforces a neighbour on evidence it can observe without breaking
> anything: cells delivered versus sent, extension round-trip time, build
> accept/refuse ratio, reachability. **That mechanism already exists** — it is
> P12a, `internal/axon/profile`, and it is exactly "which paths are useful"
> measured the only way a relay can measure it.
>
> So Phases 8 and 10 are **already built**, in the only form compatible with §8.
> What this Part adds to routing is nothing at relay position.
>
> Content preference reaches routing at exactly one place: a client choosing
> **which HOST** to fetch from, where the client knows what it is asking for and
> the host knows what it holds. That is host selection, not path selection, and
> it is §95's market.

> ### Ruling R-92.2 — reputation may reorder the admissible set and may never widen it
>
> P12's rule 1, restated for this Part: diversity constraints are applied first,
> weights second. A reputation score can change which of several admissible
> relays is drawn. It can never admit a relay the constraints excluded, and it
> can never be a filter. `E12a.2` is the existing test and it extends unchanged.

**Multipath (Phase 9) is already Part VI** and needs nothing from this Part
except a candidate ordering, which R-92.2 supplies.

---

## 93. The DAO as authoritative state oracle

**Revised 2026-08-16.** The first version of this section ruled that *"a prune
is a record, not an enforcement"*. That was the right ruling for a
recommendation model and it is the wrong one for this architecture. The revised
model is stronger and the difference is worth stating exactly.

### 93.1 One correction to the proposal, which the proposal already makes

An Ethereum contract cannot hold or use a private key. There is no `DAO contract
→ owns key → signs oracle message` path, and the proposal says so.

Two clean options follow, and they are not alternatives — the first is the
architecture and the second is an accessory to it.

> ### Ruling R-93.1 — the CHAIN STATE is the oracle; a signing key is only ever a cache
>
> **Option A is the architecture.** The DAO contract holds `domainState` and
> `tldState` as ordinary contract storage. A node learns the state by reading the
> chain through `internal/ethproof`'s light client, which already proves storage
> slots against a sync-committee-verified state root (P14's `VerifyBond` does
> exactly this for `StakeVault`). There is no oracle key, nothing to compromise,
> and nothing to rotate.
>
> **Option B exists only for readers who cannot reach the chain**, and what it
> distributes is a *signed cache of a state that is already authoritative
> on-chain*. It is therefore not a second source of truth, and any disagreement
> between a signed statement and the chain resolves to the chain, always,
> without a vote.
>
> **If Option B is built, the key is threshold-held, M-of-N, or it is not built.**
> A single machine that can fabricate a network-wide seizure is a more attractive
> target than anything else in the system, and it would sit outside the
> governance the seizure is supposed to come from. The proposal is right about
> this and it is a hard requirement rather than a preference.

### 93.2 The state machine

```text
                    ┌──────────────────────────────────────┐
                    ▼                                      │
   ACTIVE ──report──▶ REPORTED ──weight ≥ θ──▶ UNDER_REVIEW│
      ▲                                            │       │
      │                                    challenge period│
      │                                            │       │
      │                                        DAO VOTE     │
      │                             ┌──────────────┴──────┐ │
      └───────── REJECTED ──────────┘                     │ │
                                                          ▼ │
                                                    PRUNED / SEIZED
                                                          │ │
                                              APPEAL ─────┘ │
                                             (bonded)       │
                                                  │         │
                                            RESTORED ───────┘
                                                  
   SEIZED ──quarantine period──▶ RECYCLABLE ──registrar──▶ REASSIGNED
```

`PRUNED` and `SEIZED` differ in what happens to the name, and conflating them
would be a real loss:

| State | Content | Name | Owner |
|---|---|---|---|
| `PRUNED` | refused by compliant nodes | stays with its owner | unchanged |
| `SEIZED` | refused | **taken from the owner** | DAO |
| `RECYCLABLE` | n/a | available for reassignment | DAO |
| `REASSIGNED` | judged afresh | new owner | new owner |

> ### Ruling R-93.2 — what a DAO state transition binds, restated precisely
>
> A DAO prune or seizure is an **authoritative state transition on Ethereum**.
> Nodes cannot be compelled to delete data they already hold — no party in this
> architecture can reach into a disk, and building one would be building the
> central authority the document exists to avoid. But a protocol-compliant node
> **must refuse to publish, host, resolve, advertise, route-advertise or
> otherwise facilitate** an identifier the chain marks `PRUNED` or `SEIZED`.
>
> | Operation | `PRUNED` / `SEIZED` |
> |---|---|
> | name resolution (§13) | refuse |
> | new publication (§10) | refuse |
> | hosting assignment (§95) | refuse |
> | DHT descriptor publication (§7) | refuse |
> | appearing in the offer market (§95) | refuse |
> | registrar transfer (§12) | refuse |
> | **relaying cells** | **unaffected — see R-84.1** |
>
> The last row is the one that does not move. A relay does not know which name
> its cells belong to, and a network where it did would have traded §8 for a
> blacklist. Enforcement lives at the positions R-84.1 already identified, and
> the chain gives those positions an authority a signed file never could.
>
> **What this means plainly:** the DAO can make an identifier unusable across
> every compliant node, verifiably, without trusting any node's word for it. It
> still cannot make bytes disappear from a machine whose operator keeps them.

### 93.3 Why this is stronger than distributing signed blacklists

A node does not have to trust another node saying *"the DAO banned foo.axon"*.
It reads the state itself and can prove it: chain → DAO contract → storage slot
→ Merkle proof → verified against the light client's state root. That is the
same mechanism `sybil.VerifyBond` already uses, and it inherits the property
that made T14.2 worth building — **there is no path by which a provider's word
substitutes for a proof.**

It also means the enforcement surface is auditable after the fact. Every
transition is a transaction with a block number, so *"when was this seized, by
which vote, and what was the tally"* has an answer nobody can revise.

### 93.4 Recycling, and why history is retained

A seized name must be reusable, or the namespace is a ratchet that only ever
shrinks. But reassignment must not erase what happened:

```text
example.axon
  Owner #1  ──SEIZED(block 21,400,112, proposal #88)──▶ DAO
            ──QUARANTINE(90 days)──▶ RECYCLABLE
            ──REASSIGNED(block 21,900,004)──▶ Owner #2
```

> ### Ruling R-93.3 — reassignment moves the name; it never rewrites the record
>
> `NameRecord` gains an append-only `history` of `(state, block, proposal_id,
> previous_owner)`. The current owner is the head; the record is the whole chain.
>
> Two reasons, and the second is the one that bites. First, a new owner must be
> judged on their own content, and a resolver that could not tell Owner #1's
> seizure from Owner #2's tenure would be enforcing a prune against someone who
> had nothing to do with it. Second, **the mandatory quarantine before
> `RECYCLABLE` exists to break the association**: a name released the instant it
> is seized can be re-registered by the seized party through a fresh wallet
> within a block, and the seizure accomplishes nothing.
>
> **RULING R-93.3a — the quarantine floor is `2 x votingPeriod`, and it is
> derived rather than chosen.** The first version of this section left the length
> `[NEEDS RESEARCH]` and derived only that it cannot be zero. More than that is
> available, and it does not come from the association-breaking argument above --
> that one bounds nothing, because a fresh wallet is unlinkable at any delay, so
> no quarantine length prevents the seized party re-registering later. What it
> stops is the *automated same-block re-grab*, and that needs only a few blocks.
>
> **The binding constraint is the APPEAL, not the association.** An appeal is
> itself a governance proposal (SS94 puts appeal procedure in scope), so it costs
> one filing interval plus one full `votingPeriod` to decide. If the quarantine
> expires first, the name reaches `RECYCLABLE` and the registrar may reassign it
> **while the appeal is still open** -- and once a third party holds it, a
> successful appeal cannot be honoured without taking the name from someone who
> did nothing wrong. The seizure would then be effectively irreversible by
> accident of timing, which is precisely what an appeal path exists to prevent.
>
> So: `SEIZE_QUARANTINE >= 2 x votingPeriod` -- one period for the owner to
> notice and file, one for the vote. At `AxonGovernance`'s 7-day default that is
> a **14-day floor**. Descriptor propagation (SS7's 3 h lifetime) is three orders
> of magnitude smaller and does not bind.
>
> The deployed default is **30 days**, about 4.3x `votingPeriod`, which clears
> the floor with margin. THE MARGIN IS POLICY AND THE FLOOR IS NOT: raising
> `votingPeriod` without raising the quarantine walks into the reassign-during-
> appeal case, so the two move together or the relationship is checked at deploy.
> A test asserts the shipped console defaults satisfy it.

### 93.5 Seizure by key rotation — the mechanism, and the one reading of it that must be refused

**The proposal:** the DAO submits the signing key of a domain in order to prune
it, which is what makes the name recyclable. The instinct is right and it is a
material improvement on the flag model, for a reason worth naming before the
mechanism: **it converts compliance from a policy question into a signature
question.** But the literal reading has a failure mode that would be
catastrophic, so the refusal comes first.

> ### Ruling R-93.4 — the DAO never possesses a domain's signing key. Seizure ROTATES it.
>
> Three readings of "submit the signing key", two of which are refused:
>
> **(a) ESCROW — refused permanently.** For the DAO to submit a domain's key it
> must hold it, which means every registrant surrenders their publishing key at
> registration. That is one compromise away from impersonating **every domain in
> the network**, it puts the key outside the governance that is supposed to
> authorise its use, and it destroys the only property that makes a name
> meaningful — that its owner alone can publish under it. No threshold scheme
> rescues this: M-of-N escrow is still escrow, and the thing being protected is
> every name at once.
>
> **(b) DISCLOSURE — refused, and it fails in the opposite direction.**
> Publishing a private key does not disable it. It hands it to everyone, and the
> seized name becomes publishable by anybody rather than by nobody.
>
> **(c) ROTATION — this is the mechanism.** Seizure sets the on-chain
> `domainKey` to zero and bumps `version`. No key validates for the name, so
> nobody can publish under it — not the seized owner, not the DAO, not an
> attacker. **The DAO never holds a key**, which keeps R-93.1 intact: there is
> still no oracle key anywhere in the system.
>
> Recycling then needs nothing new. A name whose `domainKey` is zero and whose
> quarantine has expired is a name the registrar can reassign, and the new owner
> sets their own key on registration exactly as any registrant does.

**`AxonRegistry.sol` already has the fields.** `Name.domainKey` is the Ed25519
`DomainIdentity` verbatim, `Name.keyValidFrom` bounds when it took effect,
`Name.version` is bumped on every mutation for anti-rollback (§11.7), and
`flags` bit 1 is `revoked`. Seizure is a governance-only function that zeroes
`domainKey`, sets the state and starts the quarantine clock — not a new
subsystem.

### 93.6 Why rotation is stronger than a flag: it removes the choice

§93's honest limit was that **compliance is unobservable** — R-93.2 says a
compliant node refuses to facilitate a pruned identifier, and nothing detects
one that quietly does not.

Key rotation closes most of that gap, and not by adding enforcement:

```text
FLAG MODEL          node checks state → decides whether to honour it → POLICY
ROTATION MODEL      node checks signature against the current domainKey
                    → no key validates → there is nothing to decide
```

A node that ignores the prune flag entirely, out of principle or malice, still
cannot resolve the name, because resolution verifies the descriptor's signature
against the `domainKey` the chain currently holds — and verifying signatures is
not a policy setting, it is how resolution works at all. The `version` bump is
what stops a cached older descriptor being replayed (§11.7's anti-rollback,
reused unchanged).

> ### Ruling R-93.5 — seizure propagates at the speed of a node's CHAIN VIEW, and that is a real limit
>
> §13's resolver has `SNAPSHOT-WARM` and `SNAPSHOT-COLD`, and a `COLD` node
> reports staleness `-1` because it genuinely does not know how old its view is.
> Such a node enforces **the last state it saw**, so a seizure is invisible to it
> until it reconnects.
>
> This is not fixable and must not be papered over: a network that could push a
> revocation to a disconnected node would have a push channel to every node,
> which is a far worse property than delayed revocation. What it means in
> practice is that **seizure is eventually consistent**, its latency is a node's
> chain-sync interval, and any claim that a name is "removed from the network"
> is true only of nodes with a current view.
>
> It also means a node deliberately staying `COLD` is the residual
> non-compliance case. It is narrower than the flag model's — that node must
> refuse to sync the chain at all, rather than merely ignoring one field — but
> it is not zero.

> ### Ruling R-93.6 — `release()` is immediate; SEIZURE is not, and the registry must not treat them alike
>
> `AxonRegistry.release()` makes a name available **immediately**, and its
> comment gives the reason: grace protects an owner who forgot to renew, while
> release is that owner choosing to let go, so withholding it protects nobody.
> That reasoning is correct for a voluntary release and **inverts for a
> seizure**: a seized name that becomes available at once is re-registered by the
> seized party from a fresh wallet within a block, and the seizure has
> accomplished nothing but a gas fee.
>
> So the two paths must not share code. Seizure sets `SEIZED`, zeroes
> `domainKey`, and only reaches `RECYCLABLE` after the quarantine of R-93.3.

**A TLD is the same machine one level up.** `.axon` and any DAO-facilitated TLD
carry the same states, and a seized TLD recycles the same way. §12's registry
already namespaces by `nameHash`, so this is one state field and one history
array on a record that exists, not a second system.

## 94. Governance scope: what the DAO may and may not decide

> ### Ruling R-94.1 — the DAO governs the PROTOCOL and the NETWORK RECORD; it does not govern nodes
>
> **In scope:** category definitions; reporting rules; the reputation algorithm's
> published form; quorum and thresholds; appeal procedure; economic parameters;
> Sybil parameters; and prune records against content identities.
>
> **Out of scope, permanently:** what any individual node hosts, relays or
> refuses. A vote that instructed nodes would be unenforceable — see R-93.1 —
> and a governance system that routinely issues unenforceable instructions
> teaches everyone to ignore it.
>
> **Out of scope, specifically:** global prunes on `ILLEGAL`, `EXTREMIST` or
> `COPYRIGHT` grounds (§86). Those are jurisdictional, the network spans
> jurisdictions, and a majority vote does not resolve a conflict of laws — it
> just exports one jurisdiction's answer to everyone. They remain available as
> labels and as local policy, which is where they belong.

**Voting weight is DEFINED, and the first version of this Part was wrong to call
it unsolved.** `model/Dao.py`'s `SCORE_WEIGHTS` is the scheme, kept as data so
the split is auditable:

| Component | Weight | Live today? |
|---|---|---|
| Verified infrastructure contribution | 40 | **No** — no epoch has settled |
| Reputation from honest participation | 30 | **No** — §88 is not built |
| Governance participation | 20 | Yes, capped at 10 votes |
| Stake bonded in `StakeVault` | 10 | **No** — nothing is bonded (OUTSTANDING A4) |

It is a stake/reputation hybrid weighted toward *contribution*, which is the
right family, and stake is deliberately the smallest term — the wealthiest party
does not decide what the network suppresses. That answers the objection the
first version of this section raised.

> ### Finding F-94.1 — the scheme is defined; three of its four inputs are dark, and there is no contract
>
> Two facts about the DAO as it stands today, and the roadmap must not paper over
> either:
>
> 1. **Only `participation` is measurable.** The other three report
>    `available: False`, and `governance_score` ends `total = max(1, ...)`, whose
>    own comment reads *"One member, one vote until the real inputs come online"*.
>    So the deployed system is **one-member-one-vote** — the Sybil-bait case §94
>    warned about — not because the scheme is wrong but because 75 % of it is
>    unmeasurable until A4 and §88 land.
>
> 2. **There is no Governance contract on Ethereum.** `DaoProposal` and `DaoVote`
>    are tables in the web server's database. `onchain_ref` is nullable and its
>    comment says *"Set once the Governance contract exists"*. It does not exist.
>
> **This is load-bearing for §93.** If the chain state is authoritative and the
> vote that produces it is a row in one server's Postgres, then "the blockchain
> is authoritative" means "whatever that server writes is authoritative" — a
> centralised oracle in a blockchain costume, and precisely what Option B's
> threshold requirement exists to prevent one machine from becoming.
>
> **Sequencing ruling: the Governance contract must be on chain BEFORE any
> `PRUNED` or `SEIZED` state is written.** Until then §93's machine may be built
> and tested, and must not be given authority over anything.

---

## 95. The economic layer

> **BUILT (2026-08-17) — G11.** `internal/placement/reputation.go`, 7 tests.
> **R-92.2 holds**: a host with a perfect record that shares a failure domain
> with an existing holder is refused, and the slot goes to an *unknown* host in a
> distinct domain.
>
> **The first version was a silent no-op, and every set-based test passed it.**
> `PlanWithReputation` ranked the candidates and called `Plan` — which applies
> its own emptiest-first sort and overrode the ranking whenever `FreeBytes`
> differed. Comparing which hosts were *selectable* cannot detect this, because
> the selectable set is exactly what reputation must not change. It was caught
> only by a test asserting reputation **does** reorder. The gate is now extracted
> into `planOrdered`, which tries candidates in the order given; `Plan` and
> `PlanWithReputation` each sort and then share that one copy of the constraint.
>
> **Reputation is never an admission test** — not a floor, not a threshold. It
> cannot widen (R-92.2) and it must not narrow either, for two reasons and the
> second is the one that bites:
> - A floor makes dispersal **fail** where nobody has a history yet — R-87.1's
>   shape arriving at the storage layer.
> - It would **starve new hosts permanently**. A host with no history can never
>   earn one if it is never selected, so the ranking freezes current membership
>   and no operator can ever join. A reputation system that cannot onboard is a
>   cartel with extra steps.
>
> **Unknown is the neutral prior, not last.** Sorting unknown hosts to the back
> is the same starvation by a quieter route, so G5's Laplace 0.5 is reused: a new
> operator is tried ahead of hosts that have actually failed and behind hosts
> that have actually delivered. `Observed` is a separate field because "scored 0"
> and "never seen" are different facts.
>
> **Scores are bucketed to one decimal place.** Raw float comparison makes a 0.71
> host strictly beat a 0.70 one — a precision the attestation counts do not have,
> and an order that thrashes on noise. Within a bucket the existing
> emptiest-first rule decides, so a node with no reputation data behaves exactly
> as before.
>
> Scores are **LOCAL** (R-88.1): this node's reducer over attestations it chose
> to believe, never a network-wide figure, because a global host score would be
> the measurement authority R14 forbids. An audit asserts this file contains no
> second copy of the domain gate. Three injections verified: bypassing the gate,
> truncating the ranking, and sorting unknown last.

Nodes advertise what they will do and what they charge:

```text
HostOffer { node, price_per_gb_month, categories_hosted,
            availability_claim, bond, endpoint }
RelayOffer { node, price_per_gb, bond }
```

A publisher selects a hosting set from the offers. §10's placement engine already
enforces the diversity that makes a hosting set survivable, and P12b's operator
rung already stops one owner holding every replica — `placement.Candidate.Domains`
is built for exactly this and **is not yet populated by any caller** (OUTSTANDING
E1), which this Part depends on.

> ### Ruling R-95.1 — the relay market is priced by BYTES, never by content
>
> A relay offer names a price and a bond and says nothing about categories,
> because under R-84.1 a relay has no category to price. Only host offers carry
> `categories_hosted`.

**Reputation affects economics** (Phase 16) through offer *ranking*, not through
eligibility: a new node with no history is ranked lower and is never excluded,
because exclusion-by-default is the bootstrap problem the proposal correctly
identifies and it has no solution that does not reduce to "pay to enter".

---

## 96. Privacy-preserving reputation

The mature requirement: prove *"I have sufficient reputation in category X"*
without revealing activity. Anonymous credentials, threshold signatures, Merkle
commitments and ZK proofs are the candidate families.

**None of this is v1.** It is listed because the ordering matters: a reputation
system deployed without it publishes, for every node, a history of what it hosted
and relayed. On a network of nine nodes that history identifies the operator
completely. **Deploying §88 at current scale is a privacy regression**, and §97
sequences it accordingly.

---

## 97. Phases G1–G20

Numbered `G` so they do not collide with §23's `P` phases. Dependencies are on
existing phases where they exist.

| # | Phase | Depends on | Status | Exit criterion |
|---|---|---|---|---|
| **G1** | Content identity (§85) | P8, P9, P10 | `[BUILD NOW]` | **E-G1** A report survives a content republish and still names the version it was made against — falsified by a report voided by a `seq` bump. |
| **G2** | Category vocabulary + signed labels (§86) | G1 | `[BUILD NOW]` | **E-G2** No label exists anywhere without an issuer and a signature, by schema audit. |
| **G3** | Node policy engine, HOST position only (§87) | G2, P11 | `[BUILD NOW]` | **E-G3** A node with `host_block: malware` refuses to store a labelled object and still **relays normally** for every category — falsified by any relay-position filtering (R-84.1). |
| **G4** | Report protocol as DHT records (§89) | G1, P4 | `[BUILD NOW]` | **E-G4** A report is retrievable from the DHT by three nodes that never contacted the reporter. |
| **G5** | Reporter reputation (§90) | G4, P14 | `[NEEDS RESEARCH]` | **E-G5** One reporter at maximum reputation cannot reach the prune threshold alone (R-90.1) — falsified by any parameter set where they can. |
| **G6** | Node reputation as signed attestations (§88) | P12a, P14 | `[NEEDS RESEARCH]` | **E-G6** A node's own first-hand observation outranks a contradicting attestation from any issuer — falsified by an attestation overriding measurement. |
| **G7** | Local reducer + trusted-issuer sets | G6 | `[BUILD NOW]` | **E-G7** Two nodes with disjoint `trusted_issuers` reach different conclusions about the same subject and **both keep routing** — this is the pluralism test, and a network that converges here has built a consensus document (R14). |
| **G8** | **Governance contract on chain** | A1, A2 deployed | `[BUILD NOW]` | **E-G8** A vote tally is reconstructible from chain state alone, with the web server stopped — falsified by any tally that needs `DaoVote` rows. F-94.1 makes this a **prerequisite for G9**, not a peer of it. |
| **G9** | `domainState` / `tldState` on chain (§93) | G8 | `[BUILD NOW]` | **E-G9a** A node determines the state of a name from a **light-client-verified storage proof**, with no node's word involved — the T14.2 property, reused. **E-G9b** A `PRUNED` name is refused at resolve, publish, host-assign and registrar-transfer, and **relays normally** (R-93.2). |
| **G10** | Appeals, seizure by key rotation, quarantine, recycling (§93) | G9 | `[BUILD NOW]` | **E-G10a** A successful appeal lowers the original reporters' accuracy and returns the bond. **E-G10b** A seized name cannot be re-registered before its quarantine expires — falsified by same-block re-registration. **E-G10c** Reassignment leaves the seizure in `history`. **E-G10d** A node that ignores the prune state entirely **still cannot resolve** a seized name, because no key validates (R-93.4) — falsified by any resolution path that accepts a descriptor signed by the pre-seizure key. **E-G10e** The DAO holds no domain key at any point, by source audit — falsified by any escrow field. |
| **G11** | Reputation-aware **host** selection (§95) | G6, P12 | `[BUILD NOW]` | **E-G11** Host ranking never excludes an unrated node — falsified by a new node receiving zero offers. |
| **G12** | Path reinforcement | — | **ALREADY BUILT** | P12a. R-92.1: delivery-based reinforcement is the only form compatible with §8, and it exists. |
| **G13** | Multipath | Part VI | Existing | R-92.2 supplies the ordering; nothing new. |
| **G14** | Host/relay offer market (§95) | A1, G3 | `[BUILD NOW]` | **E-G14** A relay offer carries no category field, by schema audit (R-95.1). |
| **G15** | Reputation-weighted markets (§95) | G14, G6 | `[NEEDS RESEARCH]` | **E-G15** The bootstrap path is demonstrated: a node with no history reaches a working reputation without buying it. |
| **G16** | Sybil resistance for governance | P14 | `[UNSOLVED]` calibration | **E-G16** Corroboration is sublinear in identity count — falsified by `k` identities buying `k×` weight. |
| **G17** | Privacy-preserving reputation (§96) | G6 | `[NEEDS RESEARCH]` | **E-G17** A node proves a category threshold without revealing which objects it hosted. |
| **G18** | Emergency quarantine (§93) | G9 | `[BUILD NOW]` | **E-G18** An unconfirmed quarantine **lapses** at its expiry without any action — falsified by one that persists. |
| **G19** | Cross-network governance interop | G8 | `[NEEDS RESEARCH]` | — |
| **G20** | Adaptive network | everything | aspirational | Not an engineering phase; do not schedule it. |

**Build order, and it differs from the proposal's in one important way.** G6 and
G17 are transposed relative to Phases 3 and 19: §96 establishes that deploying
node reputation *without* privacy-preserving proofs, at nine nodes, publishes
each operator's complete hosting and relaying history. So the ordering here is
**G1 → G2 → G3 → G4 → G8 → G9 → G10 → G18 → G14 → G5 → G11 → G6/G7 → G15 →
G16 → G17**: the governance record and the local policy engine come first
because they need no reputation to be useful, and node reputation waits for
either §96 or a population large enough that a history is not an identity.

> **RULING R-97.1 (2026-08-19) — G6 and G17 are a CYCLE, and it is broken by
> distinguishing a build dependency from a deployment one.**
>
> As written, §97 says three things that cannot all hold. The dependency table
> gives **G17 depends on G6**. The build order puts **G6/G7 before G17**. And the
> justification immediately after says node reputation **"waits for either §96 or
> a population large enough"** — and §96 *is* G17. So G6 waits for G17 while G17
> waits for G6.
>
> The `or` was the intended escape, and **it is closed today**: the deployed
> population is nine nodes (PAR-15), which §96 names as exactly the scale at
> which "that history identifies the operator completely". So the cycle is live,
> not hypothetical, and anyone following §97 literally stalls.
>
> **The two dependencies are not the same kind.** G17's need for G6 is a
> *schema* dependency — proving "I have sufficient reputation in category X"
> requires the attestation format and the category vocabulary to be fixed, not
> for any reputation to have been accumulated. G6's need for G17 is a
> *deployment* dependency — the schema can exist and be tested with synthetic
> attestations; what must not happen at nine nodes is publishing real ones.
>
> **So: G17 is BUILDABLE FIRST against G6's schema, and G6 is DEPLOYABLE ONLY
> AFTER G17.** The build order stands; what changes is that G6/G7 in that
> sequence means *implemented and tested*, not *published to the network*. A
> reading that treats reaching G6/G7 as permission to publish attestations is the
> privacy regression §96 exists to prevent.

---

## What this Part does NOT establish

- **It does not establish that a relay can enforce content policy**, and R-84.1
  rules that it never will. Any reading of this Part as "nodes filter what they
  relay" is a misreading, and §92 is where the proposal's Phase 8 was rebuilt
  rather than adopted.
- **It does not establish that the DAO is decentralised enough to hold this
  authority yet.** The weighting scheme is defined and sound (§94), but three of
  its four inputs are unmeasurable today, the deployed system is therefore
  one-member-one-vote, and **there is no Governance contract on chain** —
  proposals and votes are rows in one server's database. §93's authority is only
  as decentralised as the vote behind it, and F-94.1 rules that no `PRUNED` or
  `SEIZED` state may be written until G8 lands.
- **It does not establish full compliance observability, though R-93.4 narrows
  it sharply.** Key rotation means a non-compliant node cannot resolve a seized
  name however much it wants to — there is no valid signature to accept. What
  remains is a node that refuses to sync the chain at all (R-93.5) and one that
  serves bytes it already holds, which no mechanism in this architecture can
  reach. That is a much smaller residue than the flag model's, and it is not
  nothing.
- **It does not establish that the classification engine works.** There is no
  corpus, the inputs are adversarial, and R-91.1 confines it to reversible
  decisions for that reason.
- **It does not quantify any reputation parameter.** Half-lives, thresholds,
  weight caps and quorums are all unset, and P14's `[UNSOLVED]` calibration is
  inherited: there is no token price and no population to derive them from.
- **It does not make the network censorship-proof, and it does not make it
  moderatable.** It makes content *findable-or-not* by willing hosts, which is a
  weaker and more honest claim than either. A determined publisher with willing
  hosts cannot be stopped by any mechanism here; a publisher with no willing
  hosts was never hosted in the first place.
- **It does not address the jurisdictional problem** (§86, §94). The network
  spans legal systems that disagree, no vote resolves that, and this Part
  deliberately declines to pretend otherwise.
