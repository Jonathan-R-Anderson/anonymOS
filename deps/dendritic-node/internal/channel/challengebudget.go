package channel

// Deriving challengePeriod — roadmap P10.
//
// WHY THIS IS CODE AND NOT A PARAGRAPH
// ------------------------------------
// challengePeriod is a constructor argument to ChannelManagerV2 and it is
// IMMUTABLE. Once deployed, every channel that contract will ever hold is
// defended for exactly as long as the number chosen here — so it has to be a
// number somebody can re-derive, argue with, and recompute when an assumption
// changes. A figure written into a design document becomes folklore within a
// year; this can be re-run.
//
// THE QUESTION IT ANSWERS
// -----------------------
//	Can an honest participant reliably get the latest valid state on chain
//	before a stale one becomes final?
//
// Which decomposes into a chain of delays, each of which must be paid for:
//
//	stale close happens
//	      |  detection            the watchtower has not looked yet
//	      |  outage               ...or was not running at all
//	      |  retrieval + signing  local work: read the state, encode, sign
//	      |  broadcast + inclusion  get it into a block
//	      |  repricing             ...and again, if the fee was too low
//	      |  reorg                 ...and the block might not survive
//	      v
//	challenge is final
//
// SAFETY DIRECTION
// ----------------
// Every term is an upper bound and they are ADDED, not combined statistically.
// A budget built on expected values is a budget that fails whenever two things
// go wrong at once, which is the situation it exists for. Overshooting costs a
// recipient a longer wait for a unilateral close — an inconvenience. Falling
// short costs somebody their money, permanently.
//
// The cooperative close is unaffected: both parties sign and settle at once,
// with no challenge window at all. This number is the price of the path taken
// when cooperation has already broken down.

import (
	"fmt"
	"time"
)

// ChallengeBudget is the worst-case time to land a challenge, by term.
//
// Every field is a duration this component might lose. Named individually
// because the argument about the total is always an argument about one term,
// and a single opaque number cannot be argued with.
type ChallengeBudget struct {
	// Detection is how long a stale close can sit unnoticed. Bounded by the
	// watchtower's sweep interval, which is why the sweep is polled rather than
	// event-driven: a missed websocket message has no bound at all.
	Detection time.Duration

	// Outage is how long the watchtower itself may be down — deploys, crashes,
	// a host reboot, a cloud provider incident. The largest single term, and
	// rightly: it is the only one that covers "nobody was watching".
	Outage time.Duration

	// Local is reading the state, encoding the calldata and signing. Measured,
	// not guessed — see TestLocalPathFitsItsBudget.
	Local time.Duration

	// Inclusion is broadcast to first confirmation at a fee that is expected to
	// work.
	Inclusion time.Duration

	// Repricing is the extra time for a transaction that was underpriced and
	// has to be replaced. Counted separately from Inclusion because it is a
	// second full wait, not a longer first one.
	Repricing time.Duration

	// RPCFailure is time lost to an endpoint that is down or lying, before a
	// fallback succeeds.
	RPCFailure time.Duration

	// Reorg is how deep a reorganisation must be survived before the challenge
	// is really final. A challenge in a block that is later orphaned did not
	// happen.
	Reorg time.Duration

	// Safety is unmodelled failure. Not padding for its own sake: every incident
	// worth the name involves something nobody had a term for.
	Safety time.Duration
}

// Terms lists the budget in order, for a table an operator can read.
func (b ChallengeBudget) Terms() []struct {
	Name string
	Dur  time.Duration
} {
	return []struct {
		Name string
		Dur  time.Duration
	}{
		{"detection", b.Detection},
		{"watchtower outage", b.Outage},
		{"local work", b.Local},
		{"inclusion", b.Inclusion},
		{"repricing", b.Repricing},
		{"rpc failure", b.RPCFailure},
		{"reorg depth", b.Reorg},
		{"safety", b.Safety},
	}
}

// Total is the sum. Added rather than combined statistically — see the header.
func (b ChallengeBudget) Total() time.Duration {
	var sum time.Duration
	for _, t := range b.Terms() {
		sum += t.Dur
	}
	return sum
}

// Recommend rounds the total UP to the next whole hour.
//
// Up, always: rounding a safety margin down is how a margin stops being one.
// Whole hours because the number ends up in a deployment script and in a
// sentence explaining to a recipient how long a contested close takes, and
// "6h" survives both better than "5h47m".
func (b ChallengeBudget) Recommend() time.Duration {
	total := b.Total()
	if total <= 0 {
		return 0
	}
	hours := total / time.Hour
	if total%time.Hour != 0 {
		hours++
	}
	return hours * time.Hour
}

// String renders the derivation, so a log or a doc shows the reasoning and not
// just the answer.
func (b ChallengeBudget) String() string {
	out := ""
	for _, t := range b.Terms() {
		out += fmt.Sprintf("  %-18s %s\n", t.Name, t.Dur)
	}
	out += fmt.Sprintf("  %-18s %s\n", "TOTAL", b.Total())
	out += fmt.Sprintf("  %-18s %s\n", "RECOMMENDED", b.Recommend())
	return out
}

// MainnetChallengeBudget is the proposed budget for an Ethereum L1 deployment.
//
// EVERY NUMBER HERE IS AN ASSUMPTION AND IS WRITTEN DOWN AS ONE. They are
// stated so they can be disputed; a budget nobody can argue with is a budget
// nobody has checked.
//
//	detection    30m   DefaultWatchInterval is 30s, so this is 60x headroom.
//	                   Deliberately not 30s: the sweep can be slow when a node
//	                   tracks thousands of channels, and the interval is a
//	                   floor on detection, not a ceiling.
//
//	outage       4h    A watchtower may be down for a deploy, a crash loop, or
//	                   an unattended weekend incident. Four hours assumes
//	                   somebody is paged and responds, which is an operational
//	                   commitment this number is making on the operator's
//	                   behalf. A hobbyist watchtower should assume more.
//
//	local        1m    Measured at ~microseconds even with a full lock set
//	                   (TestLocalPathFitsItsBudget). A minute is four orders of
//	                   magnitude of headroom, which costs nothing to grant and
//	                   covers a node under severe IO pressure.
//
//	inclusion    30m   Ethereum L1 at a fee chosen to confirm. Ordinary
//	                   inclusion is ~12s; 30m covers sustained congestion.
//
//	repricing    30m   One full replacement cycle at a higher fee, because the
//	                   first estimate can be wrong in a rising market — which is
//	                   exactly the market condition during the congestion the
//	                   previous term assumes.
//
//	rpc failure  30m   A dead or lying endpoint, plus failover. Assumes more
//	                   than one endpoint is configured; with a single provider
//	                   this term is unbounded and the budget does not hold.
//
//	reorg        30m   Far beyond any reorg L1 has sustained post-merge, where
//	                   finality is ~13 minutes. Cheap insurance.
//
//	safety       1h    Unmodelled failure.
//
// Totalling 7h31m, recommended as 8h.
//
// WHAT WOULD CHANGE THIS
//   - A chain with slower or less certain finality raises inclusion and reorg.
//   - A single RPC provider makes the rpc term unbounded; fix the deployment
//     rather than the number.
//   - A watchtower with no on-call raises outage to the real detection time for
//     an unattended service, which is days, not hours.
func MainnetChallengeBudget() ChallengeBudget {
	return ChallengeBudget{
		Detection:  30 * time.Minute,
		Outage:     4 * time.Hour,
		Local:      1 * time.Minute,
		Inclusion:  30 * time.Minute,
		Repricing:  30 * time.Minute,
		RPCFailure: 30 * time.Minute,
		Reorg:      30 * time.Minute,
		Safety:     1 * time.Hour,
	}
}

// RecommendedChallengePeriod is the value to deploy ChannelManagerV2 with.
//
// Seconds, because that is what the constructor takes.
func RecommendedChallengePeriod() int64 {
	return int64(MainnetChallengeBudget().Recommend() / time.Second)
}

// WatchMarginFor is how much runway a watchtower should demand before it
// bothers to try, given a challenge period.
//
// Derived from the budget rather than picked: the terms that remain once
// detection and outage have already been spent are the ones still ahead of a
// watchtower that has just noticed. Trying with less than that left is spending
// gas on a transaction that will not arrive in time.
func WatchMarginFor(period time.Duration) time.Duration {
	b := MainnetChallengeBudget()
	remaining := b.Local + b.Inclusion + b.Repricing + b.RPCFailure + b.Reorg
	if remaining >= period {
		// The period is too short for the assumptions. Returning the whole
		// period makes the watchtower refuse every challenge loudly, which is
		// the correct behaviour for a deployment that cannot be defended.
		return period
	}
	return remaining
}
