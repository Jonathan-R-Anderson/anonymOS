package intro

import "math"

// The difficulty controller — §9.6's, for the reasons argued in the package
// comment (conflicts 1 and 2).
//
//	every 10 s at the SERVICE, with q = INTRODUCE2 queue depth, q_target = 6:
//	  q > q_target      → effort ← min(effort × 1.5 + 1, effort_ceiling)
//	  q < q_target/4    → effort ← max(effort × 0.75, 0)
//	  otherwise         → unchanged
//
// IT RUNS AT THE SERVICE, NOT THE INTRO POINT. Only the service knows whether
// the introductions arriving are turning into work it cannot do. The intro point
// reports load and publishes the result.

const (
	// QueueTarget is §9.6's q_target.
	QueueTarget = 6
	// ControlInterval is how often the controller ticks, in seconds. §9.6's 10 s.
	ControlInterval = 10
	// EffortCeiling bounds what an honest client can be asked to pay.
	//
	// §23.6 gives PuzzleDifficultyMax = 24 bits, so 2^24. §9.6 instead defines
	// the ceiling as "the largest effort whose MEASURED solve time on the
	// declared reference hardware is acceptable" -- which cannot be computed
	// without a scheme, and the scheme is [NEEDS RESEARCH]. So this is §23.6's
	// number, held as a HARD BACKSTOP rather than a calibrated value, and it
	// stays until a scheme exists to measure. It is deliberately not called
	// anything that suggests it was measured.
	EffortCeiling uint64 = 1 << 24
)

// Controller holds the continuous effort state.
//
// CONTINUOUS, while the wire value is quantised to quarter bits. Quantising the
// STATE would compound rounding every tick and let the controller stick: a x0.75
// fall that rounds back up to where it started never falls at all.
type Controller struct {
	effort float64
}

// NewController starts at effort 1 — PuzzleDifficultyMin, no puzzle.
func NewController() *Controller { return &Controller{effort: 1} }

// Tick advances the controller by one ControlInterval given the queue depth.
func (c *Controller) Tick(queueDepth int) {
	switch {
	case queueDepth > QueueTarget:
		c.effort = c.effort*1.5 + 1
		if c.effort > float64(EffortCeiling) {
			c.effort = float64(EffortCeiling)
		}
	case queueDepth < QueueTarget/4:
		c.effort *= 0.75
		if c.effort < 1 {
			c.effort = 1
		}
	}
}

// Effort is the current linear effort.
func (c *Controller) Effort() uint64 {
	if c.effort < 1 {
		return 1
	}
	return uint64(c.effort + 0.5)
}

// Difficulty is the value to publish in IntroPointRecord.PoWDifficulty.
func (c *Controller) Difficulty() uint8 { return DifficultyFor(c.Effort()) }

// RisesFasterThanItFalls reports whether the controller is asymmetric in the
// direction §23.6 requires.
//
// Exported because it is the PROPERTY, not an implementation detail, and because
// §23.6's own stated parameter (±1 bit) fails it. A future recalibration that
// makes the fall match the rise reintroduces exactly the pulsing attack the
// asymmetry exists to prevent, and this is what catches it.
//
// MEASURED IN LOG SPACE, WHICH IS THE ONLY PLACE IT MEANS ANYTHING. The first
// version compared linear deltas and was wrong in a way that would have passed
// silently: for a MULTIPLICATIVE controller, ×2 up gains 1000 from a base of
// 1000 while ÷2 down loses only 500, so ±1 bit -- the symmetric step this
// function exists to reject -- scored as asymmetric. Effort is a cost the client
// pays, and doubling it is the same size of change wherever you start; the
// question is how many ticks it takes to get somewhere, which is a distance in
// bits.
func RisesFasterThanItFalls() bool {
	up := NewController()
	up.effort = 1000
	up.Tick(QueueTarget + 1)
	gained := math.Log2(up.effort / 1000)

	down := NewController()
	down.effort = 1000
	down.Tick(0)
	lost := math.Log2(1000 / down.effort)

	return gained > lost
}
