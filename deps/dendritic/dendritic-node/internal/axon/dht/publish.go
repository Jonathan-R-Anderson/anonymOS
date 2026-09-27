package dht

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// Descriptor publication (T7.5, E7.3, §9.4).
//
// HSDirPositions says WHERE a descriptor goes for one period. This file says
// WHICH PERIODS are live right now, and drives the writes.
//
// TWO PERIODS ARE LIVE AT ONCE, which is the whole reason this is not a loop
// over one period's eight keys. §9.4 fixes it:
//
//	period_len  86400 s; overlap 43200 s  →  two periods valid at once
//
// A client derives K_blind from ITS OWN clock. A client whose clock is slightly
// behind is still in the previous period after a boundary, computes the
// previous period's blinded key, and looks at eight positions the publisher has
// no reason to still be writing. So for the first PeriodOverlap of every period
// the publisher writes BOTH -- 16 positions, and at r=8 holders each that is
// 128 holders rather than 64. §9.4 states the same doubling at its own
// superseded two-replica figure ("16 holders per period, up to 32 during the
// 12 h overlap"); the shape is what carries over, not the number.
//
// THE OVERLAP IS ONE-DIRECTIONAL AND THAT IS A REAL GAP, stated rather than
// quietly widened. §9.4's overlap covers a client whose clock is BEHIND. A
// client whose clock is AHEAD, in the last moments before a boundary, computes
// period P+1 -- which no publisher is writing, because "two periods valid at
// once" means P-1 and P. Publishing P+1 as well would make three periods live
// and cost another 64 holders, and it is not what the specification says, so it
// is not done here. The exposure is bounded by clock skew, not by the overlap:
// a client δ ahead has no descriptor for the δ before each boundary. Recorded
// in the roadmap rather than fixed by inventing a third period.
//
// REPUBLISH CADENCE IS SEPARATE FROM PERIOD LENGTH. §9.4 gives the descriptor a
// 3 h lifetime and republishes hourly, so a publisher that dies has a 3 h
// outage budget before its service falls out of the DHT -- §9.9: "Publication
// stops; service does not."

// ErrNoRecord is returned when there is nothing to publish.
var ErrNoRecord = errors.New("axon/dht: no descriptor to publish")

// ErrNoStore is returned when a Publisher has no way to write.
var ErrNoStore = errors.New("axon/dht: publisher has no store RPC")

// StoreRPC writes one record to one holder.
//
// Injected for the same reason Lookup's RPC is: the FIND_NODE/STORE wire over a
// circuit is its own item, and the publication SCHEDULE is testable without it.
// A nil error means the holder accepted the record.
type StoreRPC func(ctx context.Context, to Contact, key Key, record []byte) error

// Target is one (period, replica position) pair that must currently be live.
type Target struct {
	Period   uint64
	Position uint8
	Key      Key
	// Current is false for the outgoing period still inside its overlap. Carried
	// so a caller can report a partial publish of the OLD period differently
	// from a partial publish of the current one -- the first degrades a stale
	// client's fetch, the second degrades everyone's.
	Current bool
}

// PeriodStart is when a period began.
func PeriodStart(period uint64) time.Time {
	return time.Unix(int64(period*params.PeriodLengthSeconds), 0).UTC()
}

// InOverlap reports whether `now` is inside the window where the PREVIOUS
// period's descriptor must still be published.
func InOverlap(now time.Time, period uint64) bool {
	return now.Sub(PeriodStart(period)) < params.PeriodOverlap
}

// PublishPlan is every position that must hold a descriptor at `now`.
//
// Returns 8 targets outside the overlap and 16 inside it. Ordered
// current-period-first so a publisher that is rate-limited or interrupted has
// written the positions everyone uses before the ones only a stale client does.
//
// kBlindFor supplies the blinded key for a period, because K_blind is
// period-scoped: the caller owns the blinding (internal/axon/identity) and this
// package must not re-derive it from a key it should never see.
func PublishPlan(kBlindFor func(period uint64) ([]byte, error), srv []byte, now time.Time) ([]Target, error) {
	if kBlindFor == nil {
		return nil, ErrNoBlindedKey
	}
	current := periodNumber(now)

	periods := []struct {
		num     uint64
		current bool
	}{{current, true}}
	// The previous period stays live for the first PeriodOverlap. Guarded on
	// current > 0 so period 0 does not underflow into 2^64-1 and ask for a
	// blinded key that cannot exist.
	if current > 0 && InOverlap(now, current) {
		periods = append(periods, struct {
			num     uint64
			current bool
		}{current - 1, false})
	}

	out := make([]Target, 0, len(periods)*DescriptorReplicaPositions)
	for _, p := range periods {
		kBlind, err := kBlindFor(p.num)
		if err != nil {
			return nil, fmt.Errorf("axon/dht: blinded key for period %d: %w", p.num, err)
		}
		keys, err := HSDirPositions(kBlind, p.num, srv)
		if err != nil {
			return nil, err
		}
		for j, k := range keys {
			out = append(out, Target{
				Period: p.num, Position: uint8(j), Key: k, Current: p.current,
			})
		}
	}
	return out, nil
}

// periodNumber mirrors identity.PeriodNumber without importing it.
//
// Duplicated deliberately: internal/axon/identity imports nothing from here and
// the reverse edge would make the two mutually dependent for one division. The
// constant they divide by is params.PeriodLengthSeconds in both, which is what
// actually has to agree -- and TestPeriodNumberMatchesIdentity checks it does.
func periodNumber(t time.Time) uint64 {
	if t.Unix() < 0 {
		return 0
	}
	return uint64(t.Unix()) / params.PeriodLengthSeconds
}

// PositionReport is how one replica position fared.
type PositionReport struct {
	Target Target
	// Holders the record was offered to, and how many accepted.
	Offered  int
	Accepted int
	// Err is the first failure, kept for the log. A position can be short of
	// holders without any error at all, when the table simply does not know
	// r=8 verified contacts near that key.
	Err error
}

// Reached reports whether this position holds the descriptor at all.
//
// ONE HOLDER IS "REACHED", not r=8. T7.5 asks that publication reach all 8
// POSITIONS and that a client fetching any one of them succeeds; a position
// with a single holder still answers that client. Replication below r is a
// durability problem, reported separately in Underreplicated, not a failure to
// reach the position -- conflating them would turn a thin routing table into a
// publication failure and hide the real one.
func (p PositionReport) Reached() bool { return p.Accepted > 0 }

// Report is one publication round.
type Report struct {
	At        time.Time
	Positions []PositionReport
}

// ReachedAll is T7.5's property: every position of every live period holds it.
func (r Report) ReachedAll() bool {
	if len(r.Positions) == 0 {
		return false
	}
	for _, p := range r.Positions {
		if !p.Reached() {
			return false
		}
	}
	return true
}

// Missing lists positions no holder accepted.
func (r Report) Missing() []Target {
	var out []Target
	for _, p := range r.Positions {
		if !p.Reached() {
			out = append(out, p.Target)
		}
	}
	return out
}

// Underreplicated lists positions that were reached but hold fewer than r
// copies, which is a durability warning rather than a publication failure.
func (r Report) Underreplicated() []PositionReport {
	var out []PositionReport
	for _, p := range r.Positions {
		if p.Reached() && p.Accepted < params.ReplicationFactor {
			out = append(out, p)
		}
	}
	return out
}

// Publisher writes a descriptor to every live position.
type Publisher struct {
	Table *Table
	Store StoreRPC
	// Replication is r. Zero means params.ReplicationFactor.
	Replication int
	// Logger is optional.
	Logger interface{ Printf(string, ...interface{}) }
}

// PublishOnce writes `record` to every position PublishPlan names.
//
// Every position is attempted even after one fails. A publisher that stopped at
// the first error would leave the remaining positions holding a STALE
// descriptor rather than none -- which is worse, because a client fetching one
// of them succeeds and gets the old intro points, so the failure presents as a
// service that is up and broken instead of one that is down.
func (p *Publisher) PublishOnce(ctx context.Context,
	kBlindFor func(period uint64) ([]byte, error), srv, record []byte,
	now time.Time) (Report, error) {

	if len(record) == 0 {
		return Report{}, ErrNoRecord
	}
	if p.Store == nil {
		return Report{}, ErrNoStore
	}
	if p.Table == nil {
		return Report{}, errors.New("axon/dht: publisher has no routing table")
	}
	targets, err := PublishPlan(kBlindFor, srv, now)
	if err != nil {
		return Report{}, err
	}
	r := p.Replication
	if r <= 0 {
		r = params.ReplicationFactor
	}

	report := Report{At: now, Positions: make([]PositionReport, 0, len(targets))}
	for _, t := range targets {
		// verifiedOnly: §7.3 rule (c). A contact learned only by being
		// mentioned in a FIND_NODE may make routing progress but may never be
		// counted toward a replica set, or a peer puts itself in the holder set
		// of every descriptor by being talked about.
		holders := p.Table.Closest(t.Key, r, true)
		pr := PositionReport{Target: t, Offered: len(holders)}
		for _, h := range holders {
			if err := p.Store(ctx, h, t.Key, record); err != nil {
				if pr.Err == nil {
					pr.Err = err
				}
				continue
			}
			pr.Accepted++
		}
		if p.Logger != nil && !pr.Reached() {
			p.Logger.Printf("axon/dht: descriptor position %d of period %d "+
				"reached no holder (%d offered): %v",
				t.Position, t.Period, pr.Offered, pr.Err)
		}
		report.Positions = append(report.Positions, pr)
	}
	return report, nil
}

// NextRepublish is when the next round is due.
//
// §9.4 republishes hourly against a 3 h lifetime, so two consecutive rounds can
// fail before the descriptor expires. Jitter is NOT added: `published_at` is
// rounded down to the hour precisely so publish timing does not leak, and
// spreading rounds inside the hour would put the jitter back into the arrival
// times an HSDir sees.
func NextRepublish(now time.Time) time.Time {
	return now.Add(params.DescriptorRepublish)
}

// FetchPositions is the client side of T7.5: "a client fetching any 1 of 8
// succeeds".
//
// ONE POSITION, CHOSEN AT RANDOM, then the rest as fallbacks in a random order.
// Random rather than fixed because a client that always tried position 0 would
// make position 0's holders the only ones that matter, which is the standing
// target the eight positions exist to deny -- and it would make the other seven
// unobservably broken.
//
// The order is returned rather than fetched here: this package does not own the
// circuit the fetch goes over.
func FetchPositions(kBlind []byte, period uint64, srv []byte, rng *rand.Rand) ([]Key, error) {
	keys, err := HSDirPositions(kBlind, period, srv)
	if err != nil {
		return nil, err
	}
	if rng == nil {
		return keys, nil
	}
	rng.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
	return keys, nil
}

// FetchPeriods is which periods a client should try, best first.
//
// Mirrors PublishPlan so the two cannot drift: a client inside the overlap
// falls back to the previous period, because the publisher is still writing it
// and because the client's own clock may be the thing that is wrong.
func FetchPeriods(now time.Time) []uint64 {
	current := periodNumber(now)
	if current > 0 && InOverlap(now, current) {
		return []uint64{current, current - 1}
	}
	return []uint64{current}
}

// SortTargets orders targets for a stable report.
func SortTargets(in []Target) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Period != in[j].Period {
			return in[i].Period > in[j].Period
		}
		return in[i].Position < in[j].Position
	})
}
