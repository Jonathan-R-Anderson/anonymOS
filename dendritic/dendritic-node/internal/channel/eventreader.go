package channel

// The event-driven chain reader — roadmap P14.5.
//
// WHAT THIS REPLACES AND WHAT IT DOES NOT
// ---------------------------------------
// The watchtower is UNCHANGED. It still calls ReadChannel once per channel per
// sweep and still knows nothing about blocks, receipts or logs. This is another
// ChainReader substitution, exactly as EvidenceChainReader was — which is the
// whole reason that interface exists.
//
// What changes is what a ReadChannel costs. Measured, the old answer was one RPC
// round trip per channel per sweep: 10,000 of them at 34 ms is 344 seconds
// against a 30-second interval. Here almost all of them are answered from local
// state, and the chain is consulted only for channels an AUTHENTICATED event
// says have changed.
//
// WHY ANSWERING FROM A CACHE IS SOUND
// -----------------------------------
// Only because of a contract invariant, and it is worth being exact about it:
//
//	every function in ChannelManagerV2 that writes ch.* emits an event
//	carrying `bytes32 indexed id`
//
// Given that, "no authenticated event named this channel between block B and the
// finalised head" is a PROOF that its on-chain state is unchanged since B — not
// an optimistic assumption. The proof is only as good as the invariant, which is
// why a test pins the invariant in the contract repository. If somebody adds a
// mutator that does not emit, this reader goes silently blind, and no amount of
// correct verification downstream would notice.
//
// THE FAIL-CLOSED RULES
// ---------------------
//	no checkpoint            -> refuse. We cannot tell quiet from not-watching.
//	an advance failed        -> refuse. The cache is not known to be current.
//	receipts do not verify   -> refuse, upstream, before any log is read.
//	a bloom said "maybe"     -> go and look. Never evidence on its own.
//
// None of these degrade to an RPC. There is no fallback in this file, for the
// reason evidencereader.go gives: a "temporary" shortcut to eth_call would
// become the path that actually protects money.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/ethproof"
)

// ErrFollowerNotReady means the authenticated chain follower has no usable
// position, so no channel question can be answered.
//
// Deliberately in the ErrNoVerifiedEvidence family rather than the
// ErrChannelNotOnChain one: it says "we cannot see", which is a different fact
// from "the chain proved there is nothing there".
var ErrFollowerNotReady = errors.New(
	"channel: the authenticated chain follower is not caught up; " +
		"no channel state can be served")

// ---- ChannelManagerV2 events -----------------------------------------------

// ChannelEventKind names a ChannelManagerV2 event.
type ChannelEventKind string

const (
	EventChannelOpened       ChannelEventKind = "ChannelOpened"
	EventDeposited           ChannelEventKind = "Deposited"
	EventCheckpointApplied   ChannelEventKind = "CheckpointApplied"
	EventClosedCooperatively ChannelEventKind = "ClosedCooperatively"
	EventCloseStarted        ChannelEventKind = "CloseStarted"
	EventChallenged          ChannelEventKind = "Challenged"
	EventLockClaimed         ChannelEventKind = "LockClaimed"
	EventLockExpired         ChannelEventKind = "LockExpired"
	EventSettled             ChannelEventKind = "Settled"
)

// channelEventSignatures maps topic0 to the event it identifies.
//
// The signatures are written out and hashed here rather than copied as
// constants: a hex constant cannot be checked against the contract by reading
// it, and a wrong one produces a watchtower that silently sees no events of that
// kind. The completeness test in the contract repository cross-checks this list
// against the ABI.
var channelEventSignatures = func() map[[32]byte]ChannelEventKind {
	sigs := map[string]ChannelEventKind{
		"ChannelOpened(bytes32,address,address,uint256)":    EventChannelOpened,
		"Deposited(bytes32,address,uint256)":                EventDeposited,
		"CheckpointApplied(bytes32,uint64,uint256,uint256)": EventCheckpointApplied,
		"ClosedCooperatively(bytes32,uint256,uint256)":      EventClosedCooperatively,
		"CloseStarted(bytes32,address,uint64,uint256)":      EventCloseStarted,
		"Challenged(bytes32,uint64)":                        EventChallenged,
		"LockClaimed(bytes32,bytes32,bytes32)":              EventLockClaimed,
		"LockExpired(bytes32,bytes32)":                      EventLockExpired,
		"Settled(bytes32,uint256,uint256)":                  EventSettled,
	}
	out := make(map[[32]byte]ChannelEventKind, len(sigs))
	for sig, kind := range sigs {
		var topic [32]byte
		copy(topic[:], keccak([]byte(sig)))
		out[topic] = kind
	}
	return out
}()

// ChannelEvent is one decoded, ALREADY AUTHENTICATED event.
//
// There is no constructor from raw JSON. A ChannelEvent can only be produced by
// DecodeChannelEvent from a log that came out of an authenticated block, which
// is what keeps "the provider said so" from ever reaching a decision.
type ChannelEvent struct {
	Kind      ChannelEventKind
	ChannelID [32]byte
	Block     uint64
	BlockHash [32]byte

	// CloseStarted carries both of these, which is what lets a deadline be
	// scheduled locally instead of discovered by polling.
	Nonce         uint64
	ChallengeEnds int64
}

// DecodeChannelEvent interprets an authenticated log.
//
// Returns ok=false for a log this contract did not emit or an event this system
// does not model — not an error, because a bloom false positive legitimately
// delivers other contracts' logs and an unknown event is not a failure.
func DecodeChannelEvent(l ethproof.Log, block uint64, blockHash [32]byte) (ChannelEvent, bool) {
	if len(l.Topics) < 2 {
		return ChannelEvent{}, false
	}
	kind, known := channelEventSignatures[l.Topics[0]]
	if !known {
		return ChannelEvent{}, false
	}
	// topics[1] is `bytes32 indexed id` for every event in the contract. It is
	// read only here, AFTER the receipt carrying it has been authenticated.
	ev := ChannelEvent{
		Kind: kind, ChannelID: l.Topics[1], Block: block, BlockHash: blockHash,
	}
	if kind == EventCloseStarted && len(l.Data) >= 64 {
		// CloseStarted(bytes32 indexed id, address indexed by, uint64 nonce,
		// uint256 challengeEnds) — two non-indexed words, each right-aligned.
		ev.Nonce = binary.BigEndian.Uint64(l.Data[24:32])
		ev.ChallengeEnds = int64(binary.BigEndian.Uint64(l.Data[56:64]))
	}
	if kind == EventChallenged && len(l.Data) >= 32 {
		ev.Nonce = binary.BigEndian.Uint64(l.Data[24:32])
	}
	return ev, true
}

// ---- the reader ------------------------------------------------------------

// EventChainReader answers ReadChannel from authenticated events plus a cache.
//
// Inner is consulted ONLY for channels an authenticated event has touched, or
// which have never been read. It must itself be a verifying reader — in
// production, EvidenceChainReader — because this changes how OFTEN the chain is
// asked, never how much it is believed.
type EventChainReader struct {
	Inner    ChainReader
	Follower *ethproof.ChainFollower
	Contract Address

	// RefreshInterval bounds how often Advance runs. The watchtower calls
	// ReadChannel once per channel per sweep, and advancing on each of ten
	// thousand calls would replace the problem this file exists to solve.
	//
	// Finality moves once an epoch, so anything at or below the sweep interval
	// is far more often than the data can change.
	RefreshInterval time.Duration

	// OnEvent, if set, is told about every authenticated channel event. This is
	// how a deadline is scheduled locally from CloseStarted rather than found by
	// polling for it.
	OnEvent func(ChannelEvent)

	mu          sync.Mutex
	cache       map[[32]byte]cachedChannel
	head        uint64
	lastAdvance time.Time
	advanceErr  error
	started     bool
}

type cachedChannel struct {
	occ     OnChainChannel
	validAt uint64 // the authenticated head when this was read
}

func (r *EventChainReader) refreshInterval() time.Duration {
	if r.RefreshInterval > 0 {
		return r.RefreshInterval
	}
	return DefaultWatchInterval
}

// ReadChannel answers from authenticated local state where it can, and from
// Inner where it must.
func (r *EventChainReader) ReadChannel(ctx context.Context,
	contract Address, id [32]byte) (OnChainChannel, error) {

	if err := r.ensureCurrent(ctx); err != nil {
		return OnChainChannel{}, err
	}

	r.mu.Lock()
	entry, cached := r.cache[id]
	head := r.head
	r.mu.Unlock()

	if cached && entry.validAt == head {
		// PROVEN unchanged: every block from entry.validAt to head was
		// authenticated, and none of them carried an event naming this channel.
		return entry.occ, nil
	}

	occ, err := r.Inner.ReadChannel(ctx, contract, id)
	if err != nil {
		return OnChainChannel{}, err
	}
	r.mu.Lock()
	if r.cache == nil {
		r.cache = make(map[[32]byte]cachedChannel)
	}
	// Only cache against the head that was current when the read was issued. If
	// an advance landed in between, this read is already potentially stale and
	// caching it at the new head would claim more than was established.
	if r.head == head {
		r.cache[id] = cachedChannel{occ: occ, validAt: head}
	}
	r.mu.Unlock()
	return occ, nil
}

// ensureCurrent advances the follower if it is due, and fails closed otherwise.
func (r *EventChainReader) ensureCurrent(ctx context.Context) error {
	r.mu.Lock()
	due := !r.started || time.Since(r.lastAdvance) >= r.refreshInterval()
	if !due {
		err := r.advanceErr
		r.mu.Unlock()
		return err
	}
	r.mu.Unlock()

	if r.Follower == nil {
		return ErrFollowerNotReady
	}

	// Collected under no lock; applied under one. Advance does network work and
	// holding the cache lock across it would serialise every reader behind it.
	var touched [][32]byte
	var events []ChannelEvent
	prog, err := r.Follower.Advance(ctx, func(b ethproof.AuthenticatedBlock, logs []ethproof.Log) error {
		for _, l := range logs {
			ev, ok := DecodeChannelEvent(l, b.Number, b.Hash)
			if !ok {
				continue
			}
			touched = append(touched, ev.ChannelID)
			events = append(events, ev)
		}
		return nil
	})

	r.mu.Lock()
	r.started = true
	r.lastAdvance = time.Now()
	if err != nil {
		// Do NOT serve the cache after a failed advance. We no longer know that
		// nothing happened, and a cache served on that basis is the silent
		// blindness this design is supposed to remove.
		r.advanceErr = fmt.Errorf("%w: %v", ErrFollowerNotReady, err)
		r.mu.Unlock()
		return r.advanceErr
	}
	r.advanceErr = nil
	if r.cache == nil {
		r.cache = make(map[[32]byte]cachedChannel)
	}
	for _, id := range touched {
		// An event means this channel MIGHT have changed. The cached answer is
		// dropped and the next read goes to the chain — the event's contents are
		// never substituted for the chain's own answer.
		delete(r.cache, id)
	}
	if prog.To > r.head {
		r.head = prog.To
	}
	// Every channel not touched is still valid at the new head; re-stamp rather
	// than re-read, which is the entire saving.
	for id, entry := range r.cache {
		entry.validAt = r.head
		r.cache[id] = entry
	}
	r.mu.Unlock()

	if r.OnEvent != nil {
		for _, ev := range events {
			r.OnEvent(ev)
		}
	}
	return nil
}

// Head reports the authenticated block this reader's answers are current as of.
func (r *EventChainReader) Head() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.head
}
