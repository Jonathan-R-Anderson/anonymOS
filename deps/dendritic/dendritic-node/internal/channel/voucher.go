package channel

// Streaming payments: paying a streamer continuously while watching.
//
// WHY NOT ONE PAYMENT PER SECOND
// ------------------------------
// The obvious design routes an independent payment every second. At a thousand
// viewers that is a thousand proofs and three thousand hop forwardings per
// second — and the traffic pattern itself becomes a beacon, since a steady
// one-per-second stream from one payer to one destination is trivially
// recognisable however well each individual payment is hidden.
//
// CUMULATIVE, NOT INCREMENTAL
// ---------------------------
// The property that makes this work: voucher n states the session TOTAL, not
// the amount since voucher n-1.
//
// Incremental vouchers have to arrive, all of them, in order. A dropped voucher
// is money lost and has to be retried, which means tracking which ones landed —
// per viewer, per session, forever. Cumulative vouchers self-heal: if voucher 7
// is lost, voucher 8 says the total anyway and nothing needs retrying. Only the
// newest matters, so a router forwards one value and forgets the rest.
//
// It also removes an attack. With increments, replaying an old voucher ADDS to
// the total again. With cumulative totals a replayed voucher is either stale
// (and rejected) or identical to what is already held (and a no-op).
//
// THE ORDERING RULE IS THE WHOLE SAFETY ARGUMENT
// ----------------------------------------------
// A newer voucher must always win, and an older one must never override it.
// Accepting a lower sequence for a session already seen would let a router — or
// a viewer — roll the total backwards and un-pay work already delivered. That
// is checked here on every accept, not left to callers.

import (
	"errors"
	"time"
)

var (
	ErrVoucherStale     = errors.New("channel: voucher is older than the one already held")
	ErrVoucherRegressed = errors.New("channel: cumulative total decreased")
	ErrVoucherSession   = errors.New("channel: voucher belongs to a different session")
	ErrVoucherExceeds   = errors.New("channel: cumulative total exceeds the session deposit")
	ErrSessionClosed    = errors.New("channel: session is closed")
)

// SessionID identifies one viewing session. Distinct from the stream id and
// from any invoice id — see blinded.go on why roles never share identifiers.
type SessionID [32]byte

// Voucher is one cumulative statement of what a session owes.
type Voucher struct {
	Session SessionID
	// Sequence is strictly increasing within a session. The ordering rule
	// depends on it and nothing else — timestamps are not trustworthy across
	// machines and cannot be used to decide which voucher is newer.
	Sequence uint64
	// CumulativeAmount is the session TOTAL so far, never a delta.
	CumulativeAmount Amount
	// Commitment binds the fields so a router cannot alter the total in transit.
	Commitment [32]byte
	IssuedAt   uint64
}

// Session is the receiving side's view: a prepaid ceiling and the newest
// voucher seen.
type Session struct {
	ID SessionID
	// Deposit bounds the session. A viewer commits this much up front, and the
	// running total may never exceed it — which is what stops a session
	// accumulating a debt nobody can pay.
	Deposit Amount

	newest Voucher
	seen   bool
	closed bool
}

const domainVoucher = "syndichan/voucher/commit/v1"

// NewSession opens a receiving session against a prepaid deposit.
func NewSession(id SessionID, deposit Amount) (*Session, error) {
	if deposit <= 0 {
		return nil, ErrVoucherExceeds
	}
	return &Session{ID: id, Deposit: deposit}, nil
}

// NewVoucher issues the next cumulative voucher for a session.
func NewVoucher(session SessionID, sequence uint64, total Amount, now time.Time) Voucher {
	v := Voucher{
		Session:          session,
		Sequence:         sequence,
		CumulativeAmount: total,
		IssuedAt:         uint64(now.Unix()),
	}
	v.Commitment = v.commit()
	return v
}

func (v Voucher) commit() [32]byte {
	return derive(domainVoucher,
		v.Session[:], uint64Bytes(v.Sequence), amountBytes(v.CumulativeAmount))
}

// Valid checks a voucher's own integrity, before any session context.
func (v Voucher) Valid() bool { return v.Commitment == v.commit() }

// Accept takes a voucher if it genuinely supersedes what is held.
//
// Returns the amount NEWLY earned by this voucher — the delta the recipient can
// actually count as new revenue. Returning the delta rather than the total is
// deliberate: a caller that added the cumulative figure to a running balance
// would double-count every voucher, and that is an easy mistake to make with an
// API that hands back a total.
func (s *Session) Accept(v Voucher) (Amount, error) {
	if s.closed {
		return 0, ErrSessionClosed
	}
	if v.Session != s.ID {
		return 0, ErrVoucherSession
	}
	if !v.Valid() {
		// The commitment did not match: the total or sequence was altered after
		// issue. Rejected rather than clamped — a tampered voucher is not a
		// smaller valid one.
		return 0, ErrVoucherRegressed
	}
	if v.CumulativeAmount < 0 || v.CumulativeAmount > s.Deposit {
		return 0, ErrVoucherExceeds
	}

	if s.seen {
		// The ordering rule. Equal sequence is not an error — a retransmitted
		// voucher is normal on a lossy link — but it earns nothing.
		if v.Sequence < s.newest.Sequence {
			return 0, ErrVoucherStale
		}
		if v.Sequence == s.newest.Sequence {
			if v.CumulativeAmount != s.newest.CumulativeAmount {
				// Same sequence, different total: two conflicting statements
				// signed for one position. Refused rather than picking one.
				return 0, ErrVoucherRegressed
			}
			return 0, nil
		}
		// A newer sequence may not lower the total. Cumulative means monotonic;
		// a decrease is either a bug or an attempt to un-pay delivered work.
		if v.CumulativeAmount < s.newest.CumulativeAmount {
			return 0, ErrVoucherRegressed
		}
	}

	previous := Amount(0)
	if s.seen {
		previous = s.newest.CumulativeAmount
	}
	s.newest = v
	s.seen = true
	return v.CumulativeAmount - previous, nil
}

// Total is the session's settled figure so far.
func (s *Session) Total() Amount {
	if !s.seen {
		return 0
	}
	return s.newest.CumulativeAmount
}

// Remaining is what the deposit still covers — what the UI shows a viewer as
// their balance for this session.
func (s *Session) Remaining() Amount { return s.Deposit - s.Total() }

// Newest returns the voucher that would be used to settle right now.
//
// Only this one is kept. Retaining the history would be a per-second record of
// exactly when somebody was watching, which is the metadata this design exists
// to avoid producing in the first place.
func (s *Session) Newest() (Voucher, bool) { return s.newest, s.seen }

// Close ends a session and returns the final total to settle on-chain.
func (s *Session) Close() Amount {
	s.closed = true
	return s.Total()
}

// NeedsProof reports whether a session has accumulated enough to be worth an
// aggregate proof.
//
// Proofs are per EPOCH, not per voucher: at a voucher every few seconds, one
// proof each would cost more than the payments are worth. The decision is by
// elapsed time or accumulated value, whichever comes first — value alone would
// leave a slow session unproven indefinitely, and time alone would prove a
// session that earned nothing.
func NeedsProof(s *Session, lastProofAt time.Time, now time.Time,
	epoch time.Duration, sinceProof Amount, threshold Amount) bool {
	if !s.seen || s.closed {
		return s.seen && s.closed
	}
	if now.Sub(lastProofAt) >= epoch {
		return true
	}
	return sinceProof >= threshold
}
