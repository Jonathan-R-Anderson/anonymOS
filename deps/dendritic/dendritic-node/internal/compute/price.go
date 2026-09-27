package compute

// M7 — what a unit costs, what a provider earns, and how the money is held in
// between.
//
// PRICED IN WORK, NOT WALL-CLOCK TIME
// -----------------------------------
// Every figure here is computed from `Unit.RefSeconds` — the cost of the work on
// a reference machine — and never from how long a node actually took.
//
// Paying for elapsed time is the obvious design and the wrong one, twice over.
// It rewards slow hardware: the same unit pays a struggling laptop four times
// what it pays a workstation, so the network's incentive is to be slow. And it
// pays for idling, because a node that sits blocked on I/O bills the same as
// one computing. Pricing the WORK means a fast node earns the same per unit and
// simply gets through more of them, which is the incentive that should exist.
//
// The knock-on is that a submitter's bill is knowable before the work starts.
// A quote is exact, not an estimate, and a budget ceiling can therefore be a
// hard stop rather than a hope.
//
// MULTIPLICATIVE FORMULAS HAVE SHARP EDGES
// -----------------------------------------
// The reward is reputation-weighted, and any multiplicative factor near zero
// zeroes the whole thing. A new node has no reputation. If that multiplies out
// to nothing, nobody can ever start earning, the network cannot grow, and the
// formula has quietly become a closed shop.
//
// So reputation is clamped to [MinReputationFactor, 1.0] — a newcomer earns
// half rate, never nothing. Half is a real penalty and a real invitation at the
// same time, which is what that factor has to be.

import (
	"errors"
	"fmt"
)

// Rates are in the token's smallest unit per reference-second. CPU and GPU are
// priced separately and are not interchangeable: an hour of GPU is not an hour
// of CPU and a single blended rate would systematically overpay one and
// underpay the other.
type Rates struct {
	CPUPerRefSecond int64 `json:"cpu_per_ref_second"`
	GPUPerRefSecond int64 `json:"gpu_per_ref_second"`
}

// MinReputationFactor is the floor under the reward multiplier. See the
// module comment: without it a new node multiplies to zero and can never earn
// its way out of having no reputation.
const MinReputationFactor = 0.5

var (
	ErrNoCost        = errors.New("compute: unit has no reference cost to price")
	ErrOverBudget    = errors.New("compute: quote exceeds the submitter's ceiling")
	ErrNothingHeld   = errors.New("compute: nothing is held in escrow for this job")
	ErrOverRelease   = errors.New("compute: release would exceed what is held")
	ErrAlreadyClosed = errors.New("compute: escrow is already closed")
)

// rateFor picks the rate a unit is priced at.
func rateFor(u Unit, rates Rates) int64 {
	if len(u.Needs) >= 3 && u.Needs[:3] == "gpu" {
		return rates.GPUPerRefSecond
	}
	return rates.CPUPerRefSecond
}

// Quote is what a submitter pays to have a unit done, including replicas.
//
// Replicas are charged for, and that is not a markup. Verification IS the
// product: a result nobody checked is worth less than one two independent nodes
// agreed on, and the second node's work is real work somebody has to be paid
// for. Hiding that cost would mean either underpaying providers or pretending
// verification is free.
func Quote(u Unit, rates Rates, quorum Quorum) (int64, error) {
	if u.RefSeconds <= 0 {
		// Refusing beats guessing. A unit priced from its deadline would charge
		// for the time it was ALLOWED rather than the work it contains, which
		// is the wall-clock mistake wearing a different hat.
		return 0, ErrNoCost
	}
	rate := rateFor(u, rates)
	if rate <= 0 {
		return 0, fmt.Errorf("compute: no rate set for %q work", u.Needs)
	}
	return int64(u.RefSeconds) * rate * int64(Replicas(u, quorum)), nil
}

// QuoteWithin is Quote plus the budget ceiling, which is a hard stop rather
// than a hint: a runaway loop should exhaust its own ceiling and stop, not the
// submitter's wallet.
func QuoteWithin(u Unit, rates Rates, quorum Quorum, ceiling int64) (int64, error) {
	cost, err := Quote(u, rates, quorum)
	if err != nil {
		return 0, err
	}
	if ceiling > 0 && cost > ceiling {
		return cost, fmt.Errorf("%w: %d > %d", ErrOverBudget, cost, ceiling)
	}
	return cost, nil
}

// Reward is what ONE provider earns for one verified result.
//
// Not a share of the quote divided by replicas: each replica did the whole unit
// and is paid for the whole unit. The submitter pays for N executions because N
// executions happened.
//
// `reputation` is 0..1 and is clamped, never floored to zero — see the module
// comment. A node that has just joined is unproven, not worthless.
func Reward(u Unit, rates Rates, reputation float64) (int64, error) {
	if u.RefSeconds <= 0 {
		return 0, ErrNoCost
	}
	rate := rateFor(u, rates)
	if rate <= 0 {
		return 0, fmt.Errorf("compute: no rate set for %q work", u.Needs)
	}
	base := float64(u.RefSeconds) * float64(rate)
	return int64(base * clampReputation(reputation)), nil
}

// clampReputation maps any input into [MinReputationFactor, 1.0].
//
// Tolerates nonsense deliberately: a NaN or a negative from an upstream
// reputation service must not become a negative payment or a panic in a
// settlement path. Out-of-range high is clamped too — a bug that inflates
// reputation must not be able to mint money.
func clampReputation(value float64) float64 {
	if !(value == value) { // NaN
		return MinReputationFactor
	}
	if value < MinReputationFactor {
		return MinReputationFactor
	}
	if value > 1.0 {
		return 1.0
	}
	return value
}

// Escrow holds a submitter's funds between submission and settlement.
//
// Modelled on the bounty system's shape, and for the same reason: money that
// moves on submission can be taken back before the work is done, and money that
// moves only on completion gives a provider no assurance the payer is good for
// it. Holding is what makes both sides safe to start.
//
// Amounts are the token's smallest unit and integer throughout. Money in
// floating point accumulates rounding that shows up as unexplained dust in
// somebody's balance.
type Escrow struct {
	Job      string `json:"job"`
	Held     int64  `json:"held"`
	Released int64  `json:"released"`
	Refunded int64  `json:"refunded"`
	Closed   bool   `json:"closed"`
}

// Hold opens an escrow for a job.
func Hold(job string, amount int64) (*Escrow, error) {
	if amount <= 0 {
		return nil, ErrNothingHeld
	}
	return &Escrow{Job: job, Held: amount}, nil
}

// Available is what has not yet been paid out or returned.
func (e *Escrow) Available() int64 { return e.Held - e.Released - e.Refunded }

// Release pays a provider for a VERIFIED result.
//
// Verification is the caller's job (M5) and deliberately not re-done here, but
// the invariant this enforces is the one that matters: never pay out more than
// was held. Without it, a duplicate settlement message — which a distributed
// system will produce — mints money.
func (e *Escrow) Release(amount int64) error {
	if e.Closed {
		return ErrAlreadyClosed
	}
	if amount <= 0 {
		return ErrNothingHeld
	}
	if amount > e.Available() {
		return fmt.Errorf("%w: %d > %d available", ErrOverRelease, amount, e.Available())
	}
	e.Released += amount
	return nil
}

// Refund returns the unspent remainder to the submitter and closes the escrow.
//
// Called when a job is cancelled or finishes under quote — a unit that needed
// fewer replicas than were paid for, or one nobody could complete. The
// submitter gets back exactly what was not earned, and the escrow closes so a
// late settlement cannot draw on money that has already gone home.
func (e *Escrow) Refund() (int64, error) {
	if e.Closed {
		return 0, ErrAlreadyClosed
	}
	amount := e.Available()
	e.Refunded += amount
	e.Closed = true
	return amount, nil
}

// Settle pays every agreeing provider and refunds the rest.
//
// Takes the verification Check rather than a list of winners, so payment cannot
// be authorised by anything weaker than the thing that decided the result was
// right. The verdict does the gating:
//
//   - Agreed: the agreeing nodes are paid; dissenters are not. Being wrong is
//     not paid for, and is not punished here either — slashing belongs to a
//     dispute process that can be appealed (M8/M9).
//   - Failed: everyone is refunded. Nodes did work and got nothing, which is
//     harsh but correct: paying for agreed failure makes submitting impossible
//     work profitable.
//   - Disagreed / Insufficient / Undecidable: nothing moves. The money stays
//     held, because the question of who was right is still open and paying
//     early forecloses it.
func (e *Escrow) Settle(u Unit, check Check, rates Rates,
	reputation map[string]float64) (map[string]int64, error) {

	if e.Closed {
		return nil, ErrAlreadyClosed
	}
	paid := map[string]int64{}

	switch check.Verdict {
	case VerdictAgreed:
		for _, node := range check.Agreeing {
			amount, err := Reward(u, rates, reputation[node])
			if err != nil {
				return paid, err
			}
			// Pay what is left rather than failing the whole settlement: a
			// short escrow is a pricing bug, and stranding the money while it
			// is investigated helps nobody who did the work.
			if amount > e.Available() {
				amount = e.Available()
			}
			if amount <= 0 {
				break
			}
			if err := e.Release(amount); err != nil {
				return paid, err
			}
			paid[node] = amount
		}
		if _, err := e.Refund(); err != nil {
			return paid, err
		}
	case VerdictFailed:
		if _, err := e.Refund(); err != nil {
			return paid, err
		}
	default:
		// Undecided. Deliberately no movement and no error — "not yet" is a
		// normal state, not a failure, and returning an error here would make
		// callers treat an open question as a broken job.
	}
	return paid, nil
}
