// Package padding is P13's link-padding machinery: §16.3's M6a and M6b.
//
// WHAT IT DOES, AND THE HONEST LIMIT.
//
// M6a keeps an idle link from being idle-looking. M6b holds a client↔guard link
// at a constant floor whether or not the user is doing anything, and continues
// that floor for a random tail past the end of real activity. Together they hide
// three things and §16.3 lists them: daemon-idle from daemon-trickling, the
// precise instant a flow starts and stops, and any flow whose entire rate is
// below the floor.
//
// They hide NOTHING above the floor. A 2 Mbit/s download is 2 Mbit/s of visible
// cells with a 4 kbit/s floor underneath it. They do not hide that the host
// speaks AXON, which is §6's problem and a different threat model. And they say
// nothing whatever about website fingerprinting: §16 states, and this package
// repeats, that fixed cells plus link padding are known to be insufficient
// against modern classifiers, and that AXON makes no claim in that direction.
//
// §23's P13 card names the failure mode this package is most likely to produce:
// "a padding machine whose own state is a distinguisher". Three consequences
// follow and each is a property of the code rather than a note:
//
//   - every interval is drawn from crypto/rand, never from a fixed schedule,
//     because a metronome's phase identifies the link that beats it;
//   - the schedule is identical for INTERACTIVE and BULK, because a padding
//     rate that varied by traffic class would make the class inferable from the
//     padding — reintroducing the leak the classes were separated to bound;
//   - a padding cell never extends the floor's tail, only a real cell does,
//     because a self-sustaining floor is both unbounded in cost and a signal
//     that the machine, rather than the user, is driving the link.
package padding

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// Role is which of §16.3's two mechanisms a link runs.
//
// M6b is client↔guard ONLY. Running the floor on every relay↔relay link would
// multiply its cost by the number of links in the network while defending an
// observation point — the access link — that only the client has.
type Role uint8

const (
	// RoleRelay runs M6a alone: keepalive padding on an idle link.
	RoleRelay Role = iota
	// RoleGuardLink runs M6a and M6b: keepalive plus the floor.
	RoleGuardLink
)

func (r Role) String() string {
	if r == RoleGuardLink {
		return "guard-link"
	}
	return "relay"
}

// Machine is one direction of one link's padding schedule.
//
// One direction, not one link: §16.3's floor is "per direction", and a machine
// shared across both would let inbound traffic satisfy an outbound floor, which
// is exactly the case an access-link observer can separate.
type Machine struct {
	role    Role
	enabled bool

	// rnd returns a uniform float in [0,1). Nil means crypto/rand. It is
	// injectable ONLY so a test can pin a schedule; production has no seed.
	rnd func() float64

	// lastCell is the last cell of ANY kind. It is what the next interval is
	// measured from, because an observer sees cells, not their provenance.
	lastCell time.Time
	// lastReal is the last cell carrying real traffic. Only this extends the
	// floor's tail.
	lastReal time.Time
	// floorUntil is when the current floor EPOCH ends. It is not an on/off
	// switch; see floorActive.
	floorUntil time.Time
	// floorStart and floorSent are the floor's DEFICIT accounting: when the
	// current floor epoch began, and how many cells OF ANY KIND have crossed
	// since. Padding is due when the cells sent fall behind R_floor x elapsed.
	//
	// This replaced a gap-based schedule -- "emit if the last cell was more than
	// 1/R_floor ago" -- which is not the same mechanism and does not hold the
	// property. Under gap scheduling, real traffic at 0.4 cells/s against a 0.5
	// floor produced 0.8 cells/s total, because each real cell reset the gap and
	// the padding fired in between. The total rate was therefore a FUNCTION OF
	// THE REAL RATE, which is precisely the leak the floor exists to remove.
	// E13.2 measured 0.19 vs 0.80 cells/s for idle vs lightly-loaded and failed.
	floorStart time.Time
	floorSent  uint64
	// nextKeepalive is the drawn deadline for the next M6a cell.
	nextKeepalive time.Time

	sentPadding uint64
	sentReal    uint64
}

// New builds a machine for one direction of one link.
//
// enabled is T13.3's single bit. It is a constructor argument rather than a
// field so that turning padding off is one visible decision at one call site,
// and it defaults to params.PaddingEnabledByDefault at every caller.
func New(role Role, enabled bool, start time.Time, rnd func() float64) *Machine {
	m := &Machine{role: role, enabled: enabled, rnd: rnd, lastCell: start, lastReal: start}
	m.armKeepalive(start)
	if m.floorActive(start) {
		// The floor starts with the LINK, not with the first byte of user
		// traffic. Starting it on first use would make the moment a client
		// first did anything the one moment the padding did not cover.
		m.floorStart = start
		m.floorUntil = start.Add(m.between(params.FloorTailMin, params.FloorTailMax))
	}
	return m
}

func (m *Machine) uniform() float64 {
	if m.rnd != nil {
		return m.rnd()
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A padding schedule drawn from a broken entropy source is a predictable
		// schedule, which is the distinguisher this package exists to avoid.
		// There is no degraded mode worth having here.
		panic("axon/padding: crypto/rand unavailable: " + err.Error())
	}
	return float64(binary.BigEndian.Uint64(b[:])>>11) / float64(1<<53)
}

func (m *Machine) between(lo, hi time.Duration) time.Duration {
	return lo + time.Duration(m.uniform()*float64(hi-lo))
}

func (m *Machine) armKeepalive(from time.Time) {
	m.nextKeepalive = from.Add(m.between(params.KeepaliveMin, params.KeepaliveMax))
}

// Real records that a real cell crossed the link in this direction.
//
// It resets the keepalive, counts toward the floor, and — uniquely — extends
// the floor's tail.
func (m *Machine) Real(at time.Time) {
	if at.Before(m.lastCell) {
		at = m.lastCell
	}
	m.sentReal++
	m.lastCell = at
	m.lastReal = at
	if m.floorActive(at) {
		m.advance(at)
		// A real cell EXTENDS the epoch. A padding cell does not, which is what
		// keeps the epoch rolling and the phase re-randomising during idleness.
		m.floorUntil = at.Add(m.between(params.FloorTailMin, params.FloorTailMax))
		m.floorSent++ // a real cell counts toward the floor (§16.3)
	}
	m.armKeepalive(at)
}

// floorActive reports whether M6b's floor is running.
//
// A CONTRADICTION INSIDE §16.3, AND THE RULING THAT RESOLVES IT.
//
// §16.3's table says the floor "continue[s] at the floor for U(5 s, 30 s)"
// after the last real cell, which reads as an on/off switch driven by activity.
// §16.3's PROSE, three paragraphs later, says the mechanism "makes the link
// between a client and its guard carry a constant floor of traffic WHETHER OR
// NOT THE USER IS DOING ANYTHING", and lists "hides daemon-running-but-idle
// from daemon-running-and-trickling" as the property it buys. Those are not the
// same mechanism, and the switch reading does not deliver that property: a
// daemon idle for ten minutes falls back to M6a's 0.18 cells/s while a
// trickling one sits at the 0.5 floor, and the two are separable by counting.
// E13.2 measured exactly that -- 0.18 against 0.50 -- and failed.
//
// §16.3's own COST FIGURE settles it. 6.4 GB/month at R_floor = 0.5 is
// 0.5 cells/s x 1228 B x 2 directions x 2 guards x 30 days, which is arithmetic
// for a floor that never stops. The table's tail clause is not the switch; it is
// the EPOCH window, and its job is to randomise the phase at which post-activity
// padding resumes so that the instant activity stopped is not marked by a
// deterministic offset.
//
// So: the floor runs for the life of a client<->guard link, and the U(5 s, 30 s)
// draw rolls the deficit epoch. Both readings of §16.3 are then satisfied and
// the property it claims is the one that holds.
func (m *Machine) floorActive(time.Time) bool {
	return m.enabled && m.role == RoleGuardLink
}

// advance rolls the floor epoch forward to `at`.
//
// Rolling matters because the deficit is measured within an epoch. Without it,
// a burst of real traffic would leave the machine in credit for as long as the
// burst was large, and the link would then go quiet for exactly that long --
// which marks the end of the burst precisely, in a mechanism whose stated
// purpose is to blur it.
func (m *Machine) advance(at time.Time) {
	if !m.floorActive(at) {
		return
	}
	if m.floorStart.IsZero() {
		m.floorStart = at
	}
	for i := 0; i < maxCatchUp && !m.floorUntil.IsZero() && !at.Before(m.floorUntil); i++ {
		m.floorStart, m.floorSent = m.floorUntil, 0
		m.floorUntil = m.floorStart.Add(m.between(params.FloorTailMin, params.FloorTailMax))
	}
	if m.floorUntil.IsZero() || at.Sub(m.floorStart) > time.Duration(maxCatchUp)*params.FloorTailMax {
		// Far out of date -- a caller that has not run for hours. Resynchronise
		// rather than walking every intervening epoch.
		m.floorStart, m.floorSent = at, 0
		m.floorUntil = at.Add(m.between(params.FloorTailMin, params.FloorTailMax))
	}
}

// floorDeadline is when the (floorSent+1)-th cell falls due under the floor.
//
// It is derived from the EPOCH, not from the last cell: the floor is a rate over
// a window, and scheduling from the last cell turns it into a minimum gap, which
// is a different and weaker thing. See floorStart.
func (m *Machine) floorDeadline() time.Time {
	secs := float64(m.floorSent+1) / params.FloorRateCellsPerSec
	return m.floorStart.Add(time.Duration(secs * float64(time.Second)))
}

// Deadline is the instant at which a padding cell becomes due if nothing else
// crosses the link first. A zero time means padding is disabled.
//
// Callers schedule a timer on this rather than polling. Polling on a fixed
// tick would quantise every interval to the tick, and a quantised interval is
// a coarser but perfectly usable metronome.
func (m *Machine) Deadline(at time.Time) time.Time {
	if !m.enabled {
		return time.Time{}
	}
	m.advance(at)
	if m.floorActive(at) {
		// The earlier of the two. Taking the minimum means the machine never
		// emits LESS than either mechanism alone would -- and because a
		// keepalive cell also counts toward floorSent, a burst of keepalives
		// SATISFIES the floor rather than adding to it.
		if floor := m.floorDeadline(); floor.Before(m.nextKeepalive) {
			return floor
		}
	}
	return m.nextKeepalive
}

// Due returns how many padding cells are owed at `at`, and records them as
// sent.
//
// It can exceed one: a caller that was blocked for several floor intervals owes
// the whole gap. Returning only one would let a stalled writer silently drop
// below the floor, and the floor is the only thing an access-link observer
// measures.
func (m *Machine) Due(at time.Time) int {
	if !m.enabled {
		return 0
	}
	n := 0
	for {
		d := m.Deadline(at)
		if d.IsZero() || at.Before(d) {
			return n
		}
		n++
		m.sentPadding++
		// A padding cell resets the keepalive and counts toward the floor --
		// but does NOT touch lastReal or floorUntil. That asymmetry is the
		// whole reason the floor terminates.
		m.lastCell = d
		if m.floorActive(d) {
			m.floorSent++
		}
		m.armKeepalive(d)
		if n > maxCatchUp {
			// A caller that has been blocked for hours does not owe hours of
			// padding: the link was not carrying it, so emitting it now is a
			// burst, and a burst is a signal. Cap and resynchronise.
			m.lastCell = at
			m.floorStart, m.floorSent = at, 0
			m.armKeepalive(at)
			return n
		}
	}
}

// maxCatchUp bounds one Due call. It exists for the stalled-writer case above;
// at the default floor it is just over two minutes of arrears.
const maxCatchUp = 64

// Stats is what the machine has emitted. It is local telemetry and is never
// transmitted: a padding count is a description of this link's activity.
type Stats struct {
	Padding uint64
	Real    uint64
}

// Stats returns the counters.
func (m *Machine) Stats() Stats { return Stats{Padding: m.sentPadding, Real: m.sentReal} }

// Enabled reports T13.3's bit.
func (m *Machine) Enabled() bool { return m.enabled }

// Role reports which mechanisms are running.
func (m *Machine) Role() Role { return m.role }
