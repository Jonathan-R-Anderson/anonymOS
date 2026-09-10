# Incident response

**Status: published, and exercised once against a simulated relay compromise
(2026-08-20). The exercise is `internal/axon/incident`, and it is a test you can
run — `go test ./internal/axon/incident/ -v`. It is not a narrative.**

E16.4 asks for a procedure that exists and has been exercised. This document is
the first half. The second half found three things the procedure could not
actually do, and they are recorded here rather than smoothed over, because a
runbook whose steps do not execute is worse than none: it is read under pressure
by someone who believes it.

---

## Scope

One incident class is covered in full: **a relay this node routes through is
compromised** — its operator is hostile, or its host is. That is E16.4's named
case and the one the exercise drives.

Two are sketched and NOT exercised, because exercising them needs something this
tree does not have. They are listed so the gap is visible rather than implied:

| Class | Why not exercised |
|---|---|
| Release-signing key compromise | The verifier exists and is tested (T16.1); no key has been generated and none is pinned in any client, so there is nothing live to rotate. Item 2.2. |
| Coordinator key compromise | Retiring that trust root is item 4.8b, blocked on 2.7. Until then the procedure is "rotate at the coordinator and restart nodes", which is a deployment step, not a protocol one. |

## The standing constraint

**§25(c) and S13 govern what is said publicly during an incident.** An incident
report is documentation. It may not contain the four banned words, and it may not
make an anonymity claim without a stated adversary and a stated bound. "Users
were not deanonymised" is exactly the sentence that is forbidden, and it is the
sentence everyone wants to write on day one. What is sayable is what was
observed, against whom, and what remains unknown.

`roadmap/check-claims.py` is the check. Run it on any incident write-up before
publishing:

```sh
python3 roadmap/check-claims.py path/to/report.md
```

---

## Relay compromise

### 0. Before anything: decide whether this is an incident

A relay behaving badly is not automatically a compromise. `internal/axon/profile`
tiers peers on first-hand observation, and a relay that is merely slow, or newly
unreachable, is an ordinary event the path selector already routes around. Escalate
when there is evidence of the operator or host being controlled by someone else —
not when a metric moved.

Recording this step because the failure mode it prevents is real: treating churn as
compromise means ejecting honest relays, which is a partition you performed on
yourself, and on a network of nine nodes it is a partition that ends the network.

### 1. Detect and record

Write down, before touching anything:

- the relay's `NodeID` and the address it was reached at;
- when it was last believed good, and what changed that;
- which of this node's structures it appears in.

The last one is the part the exercise checks, because it is the part that decides
the blast radius. A relay can be in the DHT routing table (`dht.Table`), the
peerbook (`peer.Peerbook`), the path selector's candidate pool, and the local
profile store, and those are four separate memberships with four separate
lifetimes.

### 2. Assess the blast radius — with a number, not an adjective

`path.ExactCompromise` enumerates every path the selector could draw and sums the
exact probability of each, given a `hostile` predicate. Mark the compromised relay
hostile and read three figures:

- **FirstAndLast** — P(entry and exit both hostile). This is the correlation case
  and the one that matters most.
- **AnyHop** — P(at least one hop hostile). Reported because a reader shown only
  FirstAndLast will read it as the whole exposure.
- **NoPath** — probability mass from which no complete path exists. On a small or
  concentrated network this is not zero, and folding it into the other two would
  understate them.

**Do this before containment, not after.** Removing the relay changes the pool,
and the number you need is the one that was true while it was in.

### 3. Contain

Deny the peer, then sweep. **Both, in that order** — removal alone is theatre:
`Table.Admit` re-inserts on the next FIND_NODE that mentions the peer and
`Peerbook.Observe` re-creates the entry on the next probe, so a responder who
only ejected would watch the relay walk back in while believing it contained.

```go
list, err := contain.Load(dataDir)      // the operator's list
list.Deny(id, "why, in your words", time.Now())
list.Save(dataDir)                       // survives the restart
table.SweepContained()                   // retroactive: drops what is already in
peerbook.SweepContained()
node.SetContainment(list)                // bootstrap + storage
```

The path selector takes it as policy rather than needing a sweep:

```go
src := &path.Source{Peers: peerbook, Policy: path.PoolPolicy{Contained: list}}
sel := &path.Selector{Candidates: src.Candidates}
```

`src.LastReport()` says why a pool was thin — how many were contained, how many
unreachable, how many had no address. `ErrNoPath` on its own cannot distinguish
"no path exists on this network" from "no path exists because this node
contained or failed to probe everybody", and a responder who cannot tell those
apart will report the first while looking at the second.

`Deny` **requires a reason** and refuses without one. Six months on, the only
person who knows why a relay is contained is the person who typed it, and an
entry nobody can explain is an entry nobody can safely remove.

| Structure | How | Note |
|---|---|---|
| `dht.Table` | `SetContainment` + `SweepContained` | `Admit` then returns `ErrContained`, distinct from every cap error — a cap refusal describes the network, this one describes a decision somebody made |
| `peer.Peerbook` | `SetContainment` + `SweepContained` | `Observe` returns `ErrContained`, checked **before** the quorum: the quorum decides whether evidence is believable, containment decides whether you will act on it at all |
| `path.Selector` | `path.Source` + `PoolPolicy{Contained: list}` | Supplies `Candidates`. Also re-checks containment itself, so a node that loaded a list and forgot to sweep still keeps contained relays out of paths |
| bootstrap / storage | `Node.SetContainment` | Checked by the **libp2p** id, not the AXON one — see below |
| `profile.Profiles` | `Forget(nodeID)` | Drops observations, **not** membership |

**The list is yours and it is local.** Nothing in this tree may add to it from
observed behaviour — see step 0. It is not a reputation system, not shared, and
not evidence. `Allow` reverses it.

**A restart is no longer required for the table or the peerbook**, which is the
substantive change from the first version of this procedure: containment is on
disk and survives one.

**One call contains the host everywhere.** A node has two identities — its AXON
`NodeIdentity` (hex, what `dht.Table` and `peer.Peerbook` check) and its libp2p
peer id (base58, what the bootstrap path and storage use). They derive from the
same key but they are different strings, and the containment list stores opaque
strings, so denying one spelling used to contain the host in some structures and
not others.

```go
ids, err := link.ContainmentIDs(pub)     // both spellings of one node
list.DenyAll(ids, "why, in your words", time.Now())
```

`DenyAll` is **all or nothing**. A partial containment is the worst outcome
available here: no error is reported, you believe the host is contained, and it
keeps returning through whichever structure got the id that did not land.

This page previously told you to type both `Deny` calls yourself. That was a
paragraph, not a mechanism — read under pressure, by somebody who has never done
this before, at the one moment a half-applied containment costs most. The two
spellings collapse into one when item 2.9 moves storage onto the AXON transport.

The line to look for reports what was actually dialled rather than what was in
the file:

```
bootstrap: joining from 1 of 2 cached peers … 1 withheld by containment
```

### 4. Recover

- **Descriptors.** If this node publishes a service descriptor, its positions
  move at the next period boundary anyway (`hsdir_index` binds `period_num` and
  `SRV`). A compromised HSDir holds a descriptor that expires in at most 3 h.
  Republishing early does not move the positions and does not help; wait.
- **Guards.** Do NOT hand-pick replacements. §7's guard set is pinned precisely so
  that a node under pressure does not choose new first hops, and an incident is
  exactly the pressure that rule anticipates. If both guards are gone, the correct
  state is a reported hard guard failure and no tunnel — E7.4 — not a new guard.
- **Identity.** A relay compromise is not a reason to rotate this node's identity.
  Rotation without a plausible gap in publication is cosmetic against an observer
  who can correlate on uptime (§16, `[UNSOLVED]`), so it costs the node's
  reputation and buys little.

### 5. Report

Say what was observed, against whom, and what is unknown. Do not say what was not
deanonymised — you do not know, and S13 forbids the sentence.

Run `check-claims.py` before publishing.

---

## What the exercise found

Run: `go test ./internal/axon/incident/ -v`

1. **Containment had no API in three of four structures**, and step 3 was
   written around that. **All three closed 2026-08-20**: `internal/axon/contain`
   for the routing table and the peerbook (4.10b), the bootstrap path (4.10e),
   and `path.Source` for the selector's candidate pool (4.10c), which until then
   had no supplier at all — `SelectPath` has no production caller, so the pool
   was nobody's.

   The follow-up found a second defect, in the drill itself: it recorded the
   missing API with a log line and **passed**, so when the API landed it went on
   reporting that it did not exist. A log line is not a guard. It asserts now.
2. **The blast-radius step works and gives real numbers.** On a 24-relay pool with
   one relay hostile over 3 hops: `AnyHop=0.1250`, `FirstAndLast=0.0000` — one
   relay cannot be both entry and exit. With two hostile: `AnyHop=0.2391`,
   `FirstAndLast=0.0036`. This is the one part of the procedure that needed no
   prose to be useful.
3. **The bootstrap peer cache survives the restart** that step 3 relies on, so the
   restart alone did not clear every view. Found by the exercise, not by reading.
   **Closed 2026-08-20 by item 4.10e**: the bootstrap path now consults the
   containment list on all three of its callers, and a contained peer is neither
   dialled nor cached. It left behind the two-identity caveat in step 3, which is
   a real trap rather than a footnote.

   Closing it also turned up a misleading log line: the cache path reported
   `joining from 2 cached peers` while joining one. That is the line an operator
   reads during an incident to confirm a containment took effect, so it now
   reports the number actually dialled and how many were withheld.
4. **The exercise got the failure domain wrong on its first run, and that is the
   most useful thing in this document.** It built a pool of relays in
   `198.51.x.10` — twenty-four distinct /24s — and no path could be drawn at all.
   §8.7 gives PATHS a /16 failure domain while the annotation stores §7.5's /24
   replication width: *the same relay is a /24 to the placement planner and a /16
   to the path selector*. Twenty-four /24s are one /16.

   The failure was silent in the direction that matters. `ExactCompromise`
   correctly put all the mass in `NoPath`, and a responder reading only `AnyHop`
   would have seen `0.0000` and reported **no exposure** — from a pool where no
   path existed at all. If you take one number from step 2, take `NoPath` first;
   if it is high, the other two mean nothing yet.
