package compute

// M9 — fault tolerance: what happens when a volunteer's machine goes away.
//
// On a network of desktops and laptops, a node vanishing mid-unit is the NORMAL
// case, not the exception. Someone closes a lid, loses wifi, or reboots for an
// update. So the interesting question is not how to prevent it — it cannot be
// prevented — but how to tell the difference between the three things that look
// identical from outside:
//
//   1. a SLOW node, which will finish if left alone
//   2. a DEAD node, whose unit must be given to someone else
//   3. a POISON unit, which will fail on whoever receives it next
//
// Confusing (1) with (2) wastes the work already done and doubles the cost of
// every slow machine. Confusing (3) with (2) is worse: the unit is handed to
// node after node, each one fails, and every one of them takes a reputation
// hit for a defect in the work itself. A network that does that will
// systematically punish its most willing volunteers, because they are the ones
// who accept the most units.
//
// Telling them apart is what this file is for.

import (
	"time"
)

// Attempt is one node's try at one unit.
type Attempt struct {
	Node   string
	Device string
	// Domain is the fault domain (see schedule.go). Recorded because a unit
	// that failed three times in the SAME domain has not been shown to be
	// poison — it may have met the same broken driver three times.
	Domain    string
	StartedAt time.Time
	// LastHeartbeat is when the node last said it was still working. Distinct
	// from StartedAt: a long unit with recent heartbeats is healthy, and a
	// short unit with none is not, so elapsed time alone cannot decide.
	LastHeartbeat time.Time
	Outcome       AttemptOutcome
	// Checkpoint is resumable state the attempt got far enough to emit. Its
	// presence is what makes a reassignment cheap rather than a restart.
	Checkpoint string
	// Reason is why it failed, verbatim from the runtime. Grouped across
	// attempts to detect poison — three nodes reporting the same error is a
	// very different signal from three nodes reporting three errors.
	Reason string
}

// AttemptOutcome is how one try ended.
type AttemptOutcome string

const (
	OutcomeRunning   AttemptOutcome = "running"
	OutcomeCompleted AttemptOutcome = "completed"
	// OutcomeFailed — the unit ran and did not produce a result. Evidence
	// about the UNIT as much as about the node.
	OutcomeFailed AttemptOutcome = "failed"
	// OutcomeAbandoned — the node stopped reporting. Evidence about the NODE,
	// and almost none about the unit: a closed laptop says nothing about
	// whether the work was valid.
	OutcomeAbandoned AttemptOutcome = "abandoned"
)

// HeartbeatGrace is how long a running attempt may go quiet before it is
// treated as gone.
//
// Generous on purpose. Reassigning early is not free — it discards the work in
// flight and pays for the unit twice — and a laptop that suspends for two
// minutes on a train is not a failed node. The cost of waiting is latency; the
// cost of not waiting is duplicated work on every flaky connection in the
// network, which is most of them.
const HeartbeatGrace = 3 * time.Minute

// MaxAttempts bounds how many nodes may try one unit before it is set aside.
//
// Four, and the reason it is not larger: past this point the evidence says the
// unit is the problem, and continuing to hand it out converts one bad unit into
// an unbounded number of damaged reputations.
const MaxAttempts = 4

// PoisonThreshold is how many INDEPENDENT failures make a unit suspect.
//
// Independent means distinct fault domains. Three failures inside one domain is
// one observation repeated, and treating it as three is how a single bad driver
// gets a valid unit blacklisted.
const PoisonThreshold = 3

// Disposition is what to do with a unit next.
type Disposition string

const (
	// DispositionWait — an attempt is live and within its grace period.
	DispositionWait Disposition = "wait"
	// DispositionReassign — give it to another node, resuming from a
	// checkpoint if one exists.
	DispositionReassign Disposition = "reassign"
	// DispositionPoison — the unit itself looks defective. Stop spending
	// nodes on it and tell the submitter.
	DispositionPoison Disposition = "poison"
	// DispositionDone — completed.
	DispositionDone Disposition = "done"
	// DispositionExhausted — too many tries without the pattern that proves
	// poison. Set aside for a human rather than looped forever.
	DispositionExhausted Disposition = "exhausted"
)

// Decision is the outcome of assessing a unit, with the reasoning kept.
//
// Why carries the evidence, because "reassign" and "poison" are decisions
// somebody will eventually dispute — a node that lost reputation, or a
// submitter told their unit is defective — and a verdict that cannot explain
// itself is one that cannot be appealed.
type Decision struct {
	Disposition Disposition
	Why         string
	// ResumeFrom is the newest checkpoint available, empty if none. Carried so
	// a reassignment does not silently restart work that was nearly finished.
	ResumeFrom string
}

// Assess decides what to do with a unit given everything tried so far.
//
// Order matters: completion first, then a live attempt, then the poison test,
// then exhaustion. Checking poison BEFORE exhaustion is deliberate — a unit
// that is both is poison, and that is the more useful thing to tell somebody.
func Assess(attempts []Attempt, now time.Time) Decision {
	if now.IsZero() {
		now = time.Now()
	}

	for _, a := range attempts {
		if a.Outcome == OutcomeCompleted {
			return Decision{Disposition: DispositionDone, Why: "an attempt completed"}
		}
	}

	// A live attempt within its grace period: leave it alone. This is the
	// branch that stops a slow node being treated as a dead one.
	for _, a := range attempts {
		if a.Outcome != OutcomeRunning {
			continue
		}
		last := a.LastHeartbeat
		if last.IsZero() {
			last = a.StartedAt
		}
		if now.Sub(last) <= HeartbeatGrace {
			return Decision{
				Disposition: DispositionWait,
				Why:         "an attempt is running and was heard from recently",
			}
		}
	}

	resume := newestCheckpoint(attempts)

	// Poison: enough failures, across enough DISTINCT domains, with the same
	// reported reason. All three conditions matter —
	//   - failures rather than abandonments, because a closed laptop says
	//     nothing about the unit
	//   - distinct domains, or one broken driver convicts a good unit
	//   - the same reason, because unrelated errors on unrelated machines are
	//     what a flaky network looks like, not what a bad unit looks like
	if reason, domains := failurePattern(attempts); domains >= PoisonThreshold {
		return Decision{
			Disposition: DispositionPoison,
			Why: "failed the same way (" + reason + ") on " +
				itoa(domains) + " independent fault domains",
			ResumeFrom: resume,
		}
	}

	if len(attempts) >= MaxAttempts {
		return Decision{
			Disposition: DispositionExhausted,
			Why:         itoa(len(attempts)) + " attempts without a consistent failure",
			ResumeFrom:  resume,
		}
	}

	return Decision{
		Disposition: DispositionReassign,
		Why:         "no attempt is live",
		ResumeFrom:  resume,
	}
}

// failurePattern reports the most common failure reason among genuine failures,
// and how many DISTINCT fault domains reported it.
//
// Abandonments are excluded entirely. They are evidence about a node's
// connection, and counting them toward a poison verdict would let a network of
// flaky laptops condemn perfectly good work.
func failurePattern(attempts []Attempt) (string, int) {
	domainsByReason := map[string]map[string]bool{}
	for _, a := range attempts {
		if a.Outcome != OutcomeFailed || a.Reason == "" {
			continue
		}
		domain := a.Domain
		if domain == "" {
			// No domain recorded: count it as its own, keyed by node. Assuming
			// unknown domains are the SAME domain would suppress real poison;
			// assuming they are all different would manufacture it. Keying by
			// node is the closest available truth.
			domain = "node:" + a.Node
		}
		if domainsByReason[a.Reason] == nil {
			domainsByReason[a.Reason] = map[string]bool{}
		}
		domainsByReason[a.Reason][domain] = true
	}

	bestReason, best := "", 0
	for reason, domains := range domainsByReason {
		// Ties broken by reason string so the verdict is deterministic — two
		// verifiers assessing the same attempts must reach the same decision,
		// or the decision cannot be audited.
		if len(domains) > best || (len(domains) == best && reason < bestReason) {
			bestReason, best = reason, len(domains)
		}
	}
	return bestReason, best
}

// newestCheckpoint returns the checkpoint from the furthest-along attempt.
//
// Newest by start time, not by list order: attempts may be recorded out of
// order, and resuming from an older checkpoint than one already available
// silently repeats work somebody already paid for.
func newestCheckpoint(attempts []Attempt) string {
	var newest time.Time
	var out string
	for _, a := range attempts {
		if a.Checkpoint == "" {
			continue
		}
		if out == "" || a.StartedAt.After(newest) {
			newest, out = a.StartedAt, a.Checkpoint
		}
	}
	return out
}

// Blame reports whether an attempt should count against the node's reputation.
//
// The rule this file exists to enforce: a node is not blamed for a defective
// unit. If the unit was ultimately judged poison, every node that tried it was
// doing the right thing and failing, and scoring them for it would penalise the
// volunteers who accept the most work.
func Blame(a Attempt, final Disposition) bool {
	if final == DispositionPoison {
		return false
	}
	switch a.Outcome {
	case OutcomeAbandoned:
		// Accepting work and going silent is a real cost to the requester,
		// so it counts — but see reputation.go, where abandoning is weighted
		// far below returning a confidently wrong answer.
		return true
	case OutcomeFailed:
		return true
	default:
		return false
	}
}
