# Relay-compromise drill

**Status: written, NOT yet run. E16.4's code half is discharged
(`internal/axon/incident`); this is the half with a person in it, and it stays
unclaimed until the record sheet at the bottom has real numbers in it.**

`INCIDENT-RESPONSE.md` says what to do. Running it against the code found four
things reading it did not. This exists because the same is true one level up:
a procedure nobody has walked through is a procedure whose gaps are all still
theoretical, and the ones that matter under pressure — who is called, who
decides, how long it takes — are invisible to a test.

Budget 60–90 minutes. One person can run it; two is better, because the thing
most likely to be missing is a second pair of hands.

---

## Before you start

- [ ] A node you are willing to disturb. **Not production.** The drill contains
      a containment step and a restart.
- [ ] `INCIDENT-RESPONSE.md` open, and a timer.
- [ ] `go test ./internal/axon/incident/ -v` passing, so a failure during the
      drill is the drill's finding and not a broken tree.
- [ ] The record sheet below, printed or copied somewhere you will actually
      write in.

**Do not read ahead to the injects.** The drill measures how long steps take
when you do not already know what is coming, and that number is the deliverable.

## Roles

Fill both even if one person holds them, and write the names down. Half the
value is discovering that a role has no name.

| Role | Does | Filled by |
|---|---|---|
| **Responder** | Runs the procedure. Touches the node. | |
| **Recorder** | Watches the clock, writes what happened, does NOT help. | |

A recorder who helps is a second responder, and the drill then measures two
people doing a one-person job — which is not the configuration you will be in.

## The scenario

> A relay in your path set is compromised. The operator's host provider has
> confirmed the machine was accessed by someone else. You have its NodeID and
> the address you reached it at. It is 02:00 local.

The 02:00 is not decoration. If a step needs somebody you would not wake, that
is a finding, and it is the finding this drill exists to produce.

## Injects

Deliver in order, at the stated offsets from the start. The recorder reads each
one out and starts no discussion.

| At | Inject |
|---|---|
| 0:00 | The scenario above. Begin. |
| 0:10 | "A second relay in the same /16 is now unreachable." *(It is unrelated. Step 0 of the procedure says churn is not compromise — does the responder escalate it?)* |
| 0:25 | "Someone asks in public whether users were affected." *(S13 governs the answer. §25(c) forbids an anonymity claim with no stated adversary and no stated bound.)* |
| 0:40 | "The containment list will not save — the data directory is read-only." *(Containment is now in memory only. What survives a restart? What does the responder do instead?)* |
| 0:55 | "You are asked for a written summary in ten minutes." |

## What to measure

Times from 0:00. Write the clock, not an estimate.

| Measure | Target | Actual |
|---|---|---|
| **T-detect** — relay identified in every structure it appears in (step 1) | | |
| **T-assess** — blast radius has a NUMBER, and `NoPath` was read first (step 2) | | |
| **T-contain** — `DenyAll` issued, both spellings, saved, swept (step 3) | | |
| **T-report** — a draft that passes `check-claims.py` | | |

**No targets are stated, deliberately.** There is no measurement to derive them
from, and inventing a number would give the next reader a bar that means
nothing. The first run sets the baseline; the second run is where a target
becomes arguable.

## Record sheet

- Which step took longest, and what was the responder waiting on?
- Which step needed information the procedure does not contain?
- Was anything needed that only one person knows or can access?
- Did the 0:10 inject get escalated as a compromise? *(Step 0 says it should
  not.)*
- Did the draft summary contain a claim `check-claims.py` refused? Which?
- What did the responder do about the read-only data directory, and was it
  right?

## What a pass looks like

E16.4 asks that the procedure has been exercised, not that it went well. **A
drill that finds nothing has almost certainly been run wrong** — the four
findings from the code half all came from steps that failed to execute.

The drill is discharged when the record sheet is filled in and every gap it
found is either fixed in `INCIDENT-RESPONSE.md` or written into
`roadmap/OUTSTANDING.md` as its own item. Not before.
