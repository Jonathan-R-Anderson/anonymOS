package channel

// Operating a live channel network: watching whether privacy is real, and
// getting out safely when it is not.

import (
	"errors"
	"sort"
	"strconv"
	"time"
)

// ---------------------------------------------------------------- diversity

// DiversityAlarm is what an operator is told when privacy stops being real.
//
// Reported as a LEVEL rather than a boolean because the middle case is the
// dangerous one: a network that briefly drops to two operators is not broken,
// and one that has been at two for a week is not private and nobody noticed.
type DiversityAlarm uint8

const (
	DiversityHealthy  DiversityAlarm = iota
	DiversityDegraded                // above the floor, trending wrong
	DiversityBroken                  // below the floor: routing must refuse
)

// DiversityReading is one observation.
type DiversityReading struct {
	At        time.Time
	Operators int
	Nodes     int
}

// DiversityMonitor tracks whether three-hop routing means anything.
//
// WHY THIS IS MONITORED RATHER THAN CHECKED ONCE
// ----------------------------------------------
// SelectRoute already refuses when diversity is too low, so payments fail
// safely. But a failing payment tells the PAYER something is wrong and tells
// the operator nothing — and the operator is the only one who can fix it by
// recruiting. Worse, the dangerous state is not "routing refused" but "routing
// succeeded through three nodes one person happens to own", which no single
// payment can detect.
//
// So diversity is sampled over time and its TREND is reported, because the
// question that matters is not "is it three right now" but "has it been three
// for long enough to trust".
type DiversityMonitor struct {
	// Floor is the minimum operators for private routing. Three by default.
	Floor int
	// Window is how much history to consider.
	Window   time.Duration
	readings []DiversityReading
}

func NewDiversityMonitor(floor int, window time.Duration) *DiversityMonitor {
	if floor <= 0 {
		floor = 3
	}
	if window <= 0 {
		window = 24 * time.Hour
	}
	return &DiversityMonitor{Floor: floor, Window: window}
}

// Observe records the current candidate set.
func (m *DiversityMonitor) Observe(candidates []Candidate, now time.Time) DiversityReading {
	r := DiversityReading{At: now, Operators: DiversityOf(candidates), Nodes: len(candidates)}
	m.readings = append(m.readings, r)
	// Drop readings outside the window so the trend reflects now, not launch.
	cutoff := now.Add(-m.Window)
	kept := m.readings[:0]
	for _, x := range m.readings {
		if !x.At.Before(cutoff) {
			kept = append(kept, x)
		}
	}
	m.readings = kept
	return r
}

// Level reports the current alarm state.
//
// Uses the WORST reading in the window, not the latest. A network that dipped
// below the floor an hour ago routed payments during that dip, and reporting
// "healthy" because it recovered would hide exactly the interval where users
// were told they had privacy they did not have.
func (m *DiversityMonitor) Level() (DiversityAlarm, string) {
	if len(m.readings) == 0 {
		return DiversityBroken, "no observations yet — assume no diversity until measured"
	}
	worst := m.readings[0].Operators
	latest := m.readings[len(m.readings)-1].Operators
	for _, r := range m.readings {
		if r.Operators < worst {
			worst = r.Operators
		}
	}
	switch {
	case latest < m.Floor:
		return DiversityBroken, plural(latest) +
			" — below the floor of " + strconv.Itoa(m.Floor) + "; private routing must refuse"
	case worst < m.Floor:
		return DiversityDegraded, plural(latest) +
			" now, but dropped to " + strconv.Itoa(worst) + " within the window; payments routed during that dip were not private"
	case latest == m.Floor:
		return DiversityDegraded, plural(latest) +
			" — exactly at the floor, so one operator leaving breaks private routing"
	default:
		return DiversityHealthy, plural(latest)
	}
}

func plural(n int) string {
	if n == 1 {
		return "1 operator"
	}
	return strconv.Itoa(n) + " operators"
}

// ---------------------------------------------------------------- mass close

var ErrNothingToClose = errors.New("ops: no open channels")

// CloseUrgency selects between two genuinely different procedures.
type CloseUrgency uint8

const (
	// CloseOrderly staggers closes over time. The default.
	CloseOrderly CloseUrgency = iota
	// CloseEmergency closes everything immediately, accepting the correlation.
	CloseEmergency
)

// CloseStep is one channel's exit.
type CloseStep struct {
	Channel ChannelID
	// Cooperative is instant and cheap; unilateral costs a challenge period.
	Cooperative bool
	// NotBefore staggers on-chain closes.
	NotBefore time.Time
	Why       string
}

// PlanMassClose orders an exit from every open channel.
//
// WHY ORDERLY CLOSES ARE STAGGERED
// --------------------------------
// Closing every channel in one block is a correlating event: an observer sees N
// channels settle together and learns they belonged to one operator — which is
// precisely the linkage the routing layer spent all its effort preventing, given
// away at the exit. So orderly closes are spread out.
//
// Emergency skips that, deliberately. If keys are compromised, the correlation
// is a smaller loss than the funds, and pretending otherwise would be privacy
// theatre at the moment it costs the most.
func PlanMassClose(channels map[ChannelID]bool, cooperative map[ChannelID]bool,
	urgency CloseUrgency, start time.Time, stagger time.Duration) ([]CloseStep, error) {
	if len(channels) == 0 {
		return nil, ErrNothingToClose
	}
	if stagger <= 0 {
		stagger = 15 * time.Minute
	}

	ids := make([]ChannelID, 0, len(channels))
	for id := range channels {
		ids = append(ids, id)
	}
	// Sorted so the plan is reproducible; an operator re-running it mid-exit
	// must not get a different order and close something twice.
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	steps := make([]CloseStep, 0, len(ids))
	// Cooperative first: they settle instantly, so doing them first shrinks the
	// window in which anything can go wrong, and they cost no challenge period.
	for _, id := range ids {
		if cooperative[id] {
			steps = append(steps, CloseStep{Channel: id, Cooperative: true,
				NotBefore: start, Why: "counterparty cooperating — instant, no challenge period"})
		}
	}
	n := 0
	for _, id := range ids {
		if cooperative[id] {
			continue
		}
		at := start
		why := "counterparty unresponsive — unilateral close, challenge period applies"
		if urgency == CloseOrderly {
			at = start.Add(time.Duration(n) * stagger)
			why += "; staggered so simultaneous settlement does not link these channels"
		} else {
			why += "; EMERGENCY — not staggered, accepting that these closes are linkable"
		}
		steps = append(steps, CloseStep{Channel: id, Cooperative: false, NotBefore: at, Why: why})
		n++
	}
	return steps, nil
}

// UnilateralCount is how many closes will need a challenge period, which is the
// number that decides how long an exit takes.
func UnilateralCount(steps []CloseStep) int {
	n := 0
	for _, s := range steps {
		if !s.Cooperative {
			n++
		}
	}
	return n
}
