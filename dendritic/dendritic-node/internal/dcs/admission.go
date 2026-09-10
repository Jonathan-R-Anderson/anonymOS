package dcs

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// AdmissionController is the worker's gatekeeper. It enforces four rules the
// operator and the network need, all in one place so they cannot drift:
//
//  1. A cap on SIMULTANEOUS containers (operator-set), so a volunteer's machine
//     is never bogged down beyond what they agreed to donate.
//  2. ONE running instance per owner, so a single user cannot occupy a worker.
//     (Different users running the SAME image as separate instances is fine --
//     that is many owners, one image, which this explicitly allows.)
//  3. A queue when the worker is full, instead of a bare rejection. A queued
//     requester gets a ticket, a position, and an ETA countdown that refreshes
//     on every poll.
//  4. A hard TTL so every instance auto-spins-down (the reaper enforces the
//     destroy; this records the expiry the ETA is computed from).
//
// It is poll-friendly on purpose: there is no central scheduler to push a
// "your turn" event, so a queued client re-sends its Launch periodically and
// each Admit call returns a fresh position/ETA until a slot is free.
type AdmissionController struct {
	maxSlots    int
	instanceTTL time.Duration
	// reservationTTL reclaims a slot when a client is admitted but never starts
	// (it crashed between Admit and Started). Without this a dead client leaks a
	// slot forever, and no coordinator exists to notice.
	reservationTTL time.Duration
	now            func() time.Time

	mu        sync.Mutex
	running   map[string]instanceState // containerID -> state
	reserved  map[string]reservation   // slotToken -> reservation
	queue     []*queueEntry            // FIFO
	nextToken uint64
}

type instanceState struct {
	owner     string
	expiresAt time.Time
}

type reservation struct {
	owner     string
	expiresAt time.Time // reservation timeout, not the instance TTL
}

type queueEntry struct {
	ticket     string
	owner      string
	enqueuedAt time.Time
}

// AdmissionConfig comes from the operator's DCSLimits.
type AdmissionConfig struct {
	MaxSlots       int
	InstanceTTL    time.Duration // 24h general default; a lab ceiling may be stricter
	ReservationTTL time.Duration // default 2m
}

func NewAdmissionController(cfg AdmissionConfig) *AdmissionController {
	if cfg.MaxSlots <= 0 {
		cfg.MaxSlots = 1
	}
	if cfg.InstanceTTL <= 0 {
		cfg.InstanceTTL = DefaultInstanceTTL
	}
	if cfg.ReservationTTL <= 0 {
		cfg.ReservationTTL = 2 * time.Minute
	}
	return &AdmissionController{
		maxSlots: cfg.MaxSlots, instanceTTL: cfg.InstanceTTL,
		reservationTTL: cfg.ReservationTTL, now: time.Now,
		running: map[string]instanceState{}, reserved: map[string]reservation{},
	}
}

// DefaultInstanceTTL is the hard auto-spin-down for any instance. A lab
// workload's ceiling (4h) is stricter and wins where it applies.
const DefaultInstanceTTL = 24 * time.Hour

// Decision is the outcome of an admission attempt.
type Decision struct {
	Admitted  bool
	SlotToken string // present when Admitted; pass to Started/Release
	// Queue fields, present when not Admitted and not rejected:
	Queued      bool
	Ticket      string
	Position    int   // 1-based place in line
	ETASeconds  int64 // estimated seconds until a slot frees for this position
	InstanceTTL int64 // seconds this worker will run an instance before spin-down
}

var (
	ErrOwnerHasInstance = errors.New("dcs: this owner already has a running or queued instance on this worker")
)

// Admit is the single entry point. Call it on a first Launch (ticket == "") and
// on every retry (ticket == the previously returned ticket). It reclaims expired
// reservations first, so a crashed client never permanently holds a slot.
func (a *AdmissionController) Admit(owner, ticket string) (Decision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reclaimLocked()

	// Rule 2, part 1: a RUNNING or RESERVED instance for this owner blocks any
	// new work. (Being in the QUEUE is handled below, because retrying your own
	// queue ticket must NOT count as "already have one".)
	if a.ownerActiveLocked(owner) {
		return Decision{}, ErrOwnerHasInstance
	}

	// A retry carrying a ticket that is this owner's own queue entry: refresh or
	// promote it.
	if ticket != "" {
		idx := a.queueIndexLocked(ticket)
		if idx >= 0 && a.queue[idx].owner == owner {
			if idx == 0 && a.freeSlotsLocked() > 0 {
				a.queue = a.queue[1:] // promote the head
				return a.reserveLocked(owner), nil
			}
			return a.queuedDecisionLocked(idx), nil
		}
		// Unknown ticket, or someone else's: fall through as a fresh request.
	}

	// Rule 2, part 2: an owner already waiting in the queue cannot open a second
	// request. Their own ticket retry was handled above; anything else is a
	// double-queue attempt.
	if a.ownerQueuedLocked(owner) {
		return Decision{}, ErrOwnerHasInstance
	}

	// New request. A slot free AND nobody ahead -> admit immediately.
	if a.freeSlotsLocked() > 0 && len(a.queue) == 0 {
		return a.reserveLocked(owner), nil
	}

	// Otherwise join the back of the queue.
	entry := &queueEntry{ticket: a.newTokenLocked("q"), owner: owner, enqueuedAt: a.now()}
	a.queue = append(a.queue, entry)
	return a.queuedDecisionLocked(len(a.queue) - 1), nil
}

// Started converts a reservation into a running instance once the container is
// up. expiresAt is min(now+InstanceTTL, any stricter caller ceiling).
func (a *AdmissionController) Started(slotToken, containerID string, expiresAt time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	res, ok := a.reserved[slotToken]
	if !ok {
		return errors.New("dcs: unknown or expired slot token")
	}
	delete(a.reserved, slotToken)
	// Clamp to the worker's own TTL: a caller cannot ask for longer than the
	// operator allows.
	hardStop := a.now().Add(a.instanceTTL)
	if expiresAt.IsZero() || expiresAt.After(hardStop) {
		expiresAt = hardStop
	}
	a.running[containerID] = instanceState{owner: res.owner, expiresAt: expiresAt}
	return nil
}

// Release frees a slot when a container stops/destroys or a reservation is
// abandoned. Safe to call with either a containerID or a slotToken.
func (a *AdmissionController) Release(idOrToken string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.running, idOrToken)
	delete(a.reserved, idOrToken)
}

// Expired returns the container IDs whose TTL has passed. The reaper destroys
// them; destroying calls Release, which frees the slot for the queue.
func (a *AdmissionController) Expired() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	var out []string
	for id, st := range a.running {
		if !st.expiresAt.After(now) {
			out = append(out, id)
		}
	}
	return out
}

// QueueStatus refreshes a waiting ticket's position and ETA without attempting
// promotion -- for a status poll that is not also a Launch retry.
func (a *AdmissionController) QueueStatus(ticket string) (Decision, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reclaimLocked()
	idx := a.queueIndexLocked(ticket)
	if idx < 0 {
		return Decision{}, false
	}
	return a.queuedDecisionLocked(idx), true
}

// ---- internals (all called with a.mu held) ----

func (a *AdmissionController) freeSlotsLocked() int {
	used := len(a.running) + len(a.reserved)
	if used >= a.maxSlots {
		return 0
	}
	return a.maxSlots - used
}

// ownerActiveLocked reports a running or reserved instance for the owner --
// i.e. one that is (about to be) consuming a slot. Queue membership is separate.
func (a *AdmissionController) ownerActiveLocked(owner string) bool {
	for _, st := range a.running {
		if st.owner == owner {
			return true
		}
	}
	for _, res := range a.reserved {
		if res.owner == owner {
			return true
		}
	}
	return false
}

func (a *AdmissionController) ownerQueuedLocked(owner string) bool {
	for _, e := range a.queue {
		if e.owner == owner {
			return true
		}
	}
	return false
}

func (a *AdmissionController) reserveLocked(owner string) Decision {
	token := a.newTokenLocked("r")
	a.reserved[token] = reservation{owner: owner, expiresAt: a.now().Add(a.reservationTTL)}
	return Decision{
		Admitted: true, SlotToken: token,
		InstanceTTL: int64(a.instanceTTL / time.Second),
	}
}

func (a *AdmissionController) queuedDecisionLocked(idx int) Decision {
	return Decision{
		Queued: true, Ticket: a.queue[idx].ticket, Position: idx + 1,
		ETASeconds:  a.etaForPositionLocked(idx + 1),
		InstanceTTL: int64(a.instanceTTL / time.Second),
	}
}

// etaForPositionLocked estimates seconds until enough slots free for a queue
// position. To reach the front and be admitted, `position` slots must free. The
// soonest that happens is when the position-th soonest-expiring running
// instance hits its TTL (someone spinning down early only helps). This is an
// upper-bound estimate, and labelled as such to the user.
func (a *AdmissionController) etaForPositionLocked(position int) int64 {
	if a.freeSlotsLocked() >= position {
		return 0
	}
	expiries := make([]time.Time, 0, len(a.running))
	for _, st := range a.running {
		expiries = append(expiries, st.expiresAt)
	}
	sort.Slice(expiries, func(i, j int) bool { return expiries[i].Before(expiries[j]) })
	// We need `position` slots. Free slots already count; the rest come from
	// expiries.
	need := position - a.freeSlotsLocked()
	now := a.now()
	if need <= 0 {
		return 0
	}
	if need <= len(expiries) {
		secs := int64(expiries[need-1].Sub(now) / time.Second)
		if secs < 0 {
			secs = 0
		}
		return secs
	}
	// More people ahead than running instances (deep queue). Estimate the first
	// wave by the last expiry, then add whole-TTL waves for the overflow.
	base := int64(0)
	if len(expiries) > 0 {
		base = int64(expiries[len(expiries)-1].Sub(now) / time.Second)
		if base < 0 {
			base = 0
		}
	}
	extraWaves := int64((need - len(expiries) + a.maxSlots - 1) / a.maxSlots)
	return base + extraWaves*int64(a.instanceTTL/time.Second)
}

func (a *AdmissionController) queueIndexLocked(ticket string) int {
	for i, e := range a.queue {
		if e.ticket == ticket {
			return i
		}
	}
	return -1
}

func (a *AdmissionController) reclaimLocked() {
	now := a.now()
	for token, res := range a.reserved {
		if !res.expiresAt.After(now) {
			delete(a.reserved, token)
		}
	}
}

func (a *AdmissionController) newTokenLocked(prefix string) string {
	a.nextToken++
	return prefix + "-" + formatUint(a.nextToken)
}

func formatUint(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
