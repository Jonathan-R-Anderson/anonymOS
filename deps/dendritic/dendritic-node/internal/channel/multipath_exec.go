package channel

// Executing a SplitPlan — the P13 multi-path executor.
//
// THE ONE DESIGN DECISION EVERYTHING ELSE FOLLOWS FROM
// ----------------------------------------------------
// This keeps NO record of who is owed what. It cannot: a second place that
// believes it knows the money is a second thing to be wrong, and the first
// symptom of divergence is a payment that exists in one and not the other.
//
//	channels          the ONLY source of truth for money
//	journal (here)    what was ATTEMPTED — never what succeeded
//
// The journal records the fragments of one payment and the intent bytes each
// leg will carry. Nothing else. Status is always DERIVED by asking each channel
// whether it applied that intent, so a crashed process cannot mislead its
// successor: the successor never reads a belief, it re-reads the chain of
// signed states.
//
// That is what makes recovery honest rather than hopeful. A journal saying
// "fragment 2 settled" would be a claim; Channel.AppliedAt(intent) is a fact.
//
// IDEMPOTENCY AND ISOLATION COME FROM THE SAME PLACE
// ---------------------------------------------------
// Every leg's intent is derived deterministically:
//
//	intent_i = H(domain || paymentID || i || channel || amount)
//
// Retrying produces identical bytes, so Coordinator.Pay answers from its record
// instead of paying again — the engine was already idempotent on intent and
// this inherits it rather than reimplementing it. Two different fragments
// derive different intents, so no leg's authorisation can move another.
//
// PER-FRAGMENT PREIMAGES, BOUND TO THE FRAGMENT
// ---------------------------------------------
// One payment secret, but each fragment locks a DIFFERENT hash:
//
//	preimage_i = H(domain || secret || intent_i)
//	hash_i     = keccak(preimage_i)
//
// The recipient holds the secret, so it can open every fragment — which is what
// makes the payment atomic from their side. But preimage_i opens only fragment
// i, so revealing one does not drain the rest.
//
// THE INTENT, NOT JUST THE INDEX. An earlier version derived this from
// (secret, index) alone, and adversarial review broke it twice:
//
//   - ACROSS PAYMENTS. Two payments sharing a secret produced the SAME hash for
//     fragment i, because the payment id lived in the intent but not in the
//     hash. A counterparty that legitimately learned preimage_0 from one payment
//     could settle fragment 0 of another. Verified as working theft.
//   - ACROSS RE-SPLITS. unevenSplit draws fresh random weights every call, so
//     retrying a payment after a refused leg yields different amounts. The amount
//     is in the intent, so intents and lock ids changed — but the hash did not,
//     leaving two same-hash locks the payee could settle twice. Nothing dedupes
//     HTLC.Hash: state.go permits two locks sharing one deliberately, for
//     exactly the multipath case.
//
// intent_i already commits to payment id, index, channel and amount, so binding
// the preimage to it closes both. The recipient can still derive every preimage:
// it knows the channel and amount of any leg it is party to.
//
// WHAT THIS DELIBERATELY DOES NOT DO
// -----------------------------------
// It does not sign, does not touch balances, and does not construct states. It
// composes StateTransitions and hands them to Coordinator.Pay, which goes
// through the session, the store and Channel.Accept exactly as a direct payment
// does. There is no aggregate write path, and row 25 of the security table
// stays true by construction rather than by care.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
)

var (
	// ErrPlanNotConserving means the fragments do not sum to the total. Checked
	// before anything is sent, because afterwards it is somebody's missing money.
	ErrPlanNotConserving = errors.New("multipath: fragments do not sum to the payment total")
	// ErrFragmentExpiryUnsafe means a fragment would outlive the payment deadline.
	ErrFragmentExpiryUnsafe = errors.New("multipath: fragment expiry is unsafe relative to the payment")
	// ErrNoFragments is an empty or single-legged payment, which is not a split.
	ErrNoFragments = errors.New("multipath: a split needs at least two fragments")
	// ErrDuplicateFragmentChannel means two fragments name one channel.
	ErrDuplicateFragmentChannel = errors.New("multipath: two fragments share a channel")
)

// MultipathLeg is one fragment, bound to the channel that will carry it.
type MultipathLeg struct {
	Index   int      `json:"index"`
	Channel [32]byte `json:"channel"`
	Amount  *big.Int `json:"-"`
	// Expiry is this leg's HTLC deadline.
	Expiry int64 `json:"expiry"`

	// Intent and Hash are DERIVED, never supplied. Stored so a recovering
	// process can re-ask the channel about the same intent without needing the
	// payment secret.
	Intent [32]byte `json:"intent"`
	Hash   [32]byte `json:"hash"`
	// LockID is the HTLC id inside the channel. Derived from the intent so it
	// is stable across retries.
	LockID [32]byte `json:"lock_id"`
}

// MultipathPayment is one payment split across channels.
type MultipathPayment struct {
	// ID is the payment's identity, and the aggregate replay guard: the same ID
	// re-derives the same intents, which every channel then refuses to apply
	// twice.
	ID    [32]byte `json:"id"`
	Total *big.Int `json:"-"`
	// Deadline bounds the payer's exposure across ALL fragments. Every leg must
	// expire at or before it.
	Deadline int64          `json:"deadline"`
	Legs     []MultipathLeg `json:"legs"`
}

// FragmentIntent derives a leg's intent. Deterministic in every input, so a
// retry is byte-identical and a different fragment is never confusable.
func FragmentIntent(paymentID [32]byte, index int, channel [32]byte, amount *big.Int) [32]byte {
	return derive("syndichan/multipath/intent/v1",
		paymentID[:], u64(uint64(index)), channel[:], orZero(amount).Bytes())
}

// FragmentPreimage derives the secret that opens ONE fragment of ONE payment.
//
// Keyed by the leg's intent rather than its index — see the file header for the
// two attacks that (secret, index) allowed.
func FragmentPreimage(secret [32]byte, intent [32]byte) [32]byte {
	return derive("syndichan/multipath/preimage/v2", secret[:], intent[:])
}

// FragmentHash is what the lock commits to, hashed exactly as the contract
// hashes it — see HTLC.Matches.
func FragmentHash(secret [32]byte, intent [32]byte) [32]byte {
	p := FragmentPreimage(secret, intent)
	var h [32]byte
	copy(h[:], keccak(p[:]))
	return h
}

// BuildPayment turns amounts and channels into a validated payment.
//
// Every check here happens BEFORE anything is sent, because each one describes
// a way the payment could be wrong in a manner nobody notices until they count.
func BuildPayment(id [32]byte, secret [32]byte, total *big.Int, deadline int64,
	channels [][32]byte, amounts []*big.Int, expiries []int64) (*MultipathPayment, error) {

	if len(channels) < 2 || len(channels) != len(amounts) || len(channels) != len(expiries) {
		return nil, ErrNoFragments
	}
	seen := map[[32]byte]bool{}
	sum := new(big.Int)
	pay := &MultipathPayment{ID: id, Total: new(big.Int).Set(orZero(total)), Deadline: deadline}

	for i := range channels {
		amt := orZero(amounts[i])
		if amt.Sign() <= 0 {
			return nil, fmt.Errorf("%w: fragment %d is %s", ErrNegative, i, amt)
		}
		if seen[channels[i]] {
			return nil, ErrDuplicateFragmentChannel
		}
		seen[channels[i]] = true

		// Cross-fragment expiry ordering. A leg outliving the payment deadline
		// leaves the payer exposed after they believe the payment is over, and
		// an unset expiry is a lock nobody can ever reclaim.
		if expiries[i] <= 0 || expiries[i] > deadline {
			return nil, fmt.Errorf("%w: fragment %d expires %d, deadline %d",
				ErrFragmentExpiryUnsafe, i, expiries[i], deadline)
		}

		intent := FragmentIntent(id, i, channels[i], amt)
		pay.Legs = append(pay.Legs, MultipathLeg{
			Index: i, Channel: channels[i], Amount: new(big.Int).Set(amt),
			Expiry: expiries[i], Intent: intent,
			Hash:   FragmentHash(secret, intent),
			LockID: derive("syndichan/multipath/lock/v1", intent[:]),
		})
		sum.Add(sum, amt)
	}

	// Conservation, exactly. Not "close enough": a fragment set that does not
	// sum to the total means the recipient is short-paid or the payer
	// over-charged, and both are silent until somebody reconciles.
	if sum.Cmp(pay.Total) != 0 {
		return nil, fmt.Errorf("%w: fragments sum to %s, total is %s",
			ErrPlanNotConserving, sum, pay.Total)
	}
	return pay, nil
}


// asLegError turns a Pay outcome into an error for the leg.
//
// Coordinator.Pay returns a REFUSAL as (result, nil): the round trip succeeded,
// the peer simply said no. A caller that only inspects err therefore cannot
// distinguish "settled" from "refused", and would report a payment complete
// because nothing went wrong at the transport. A refusal is not a success, so
// it becomes an error here — at the one place every leg passes through.
func asLegError(res PaymentResult, err error) error {
	if err != nil {
		return err
	}
	if res.Rejected != "" {
		return fmt.Errorf("leg refused: %s: %s", res.Rejected, res.Detail)
	}
	return nil
}

// LegState is what a channel says about one fragment. Derived, never stored.
type LegState struct {
	Index int
	// Locked is true once the LOCK_ADD intent is applied in the channel.
	Locked bool
	// Settled is true once the lock is gone AND the settle intent applied.
	Settled bool
	// Refunded is true once the refund intent applied.
	Refunded bool
	Nonce    uint64
}

// Terminal reports whether this leg can no longer change by itself.
func (l LegState) Terminal() bool { return l.Settled || l.Refunded }

// MultipathExecutor drives a payment across channels.
type MultipathExecutor struct {
	coord *Coordinator
	dir   string
	// metrics is aggregate-only. The executor knows every identifier a payment
	// has — payment id, per-leg intents, channels — and passes NONE of them: the
	// only things it supplies are a leg COUNT and a total VALUE.
	metrics *Metrics
}

// SetMetrics attaches an aggregate collector.
func (e *MultipathExecutor) SetMetrics(m *Metrics) { e.metrics = m }

// NewMultipathExecutor builds one. dir holds the attempt journal.
func NewMultipathExecutor(coord *Coordinator, dir string) (*MultipathExecutor, error) {
	if coord == nil {
		return nil, errors.New("multipath: no coordinator")
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return &MultipathExecutor{coord: coord, dir: dir}, nil
}

// journalPath is where one payment's attempt record lives.
func (e *MultipathExecutor) journalPath(id [32]byte) string {
	return filepath.Join(e.dir, hex.EncodeToString(id[:])+".json")
}

// Journal persists the ATTEMPT before any leg commits.
//
// This is the crash-recovery hinge. Without it, a process that dies after
// locking one fragment leaves that money committed with nothing recording which
// payment it belonged to — the funds are not lost, but nobody knows they are
// half of something.
//
// It is written before the first Pay and never updated with outcomes, so it
// cannot become a competing account of what happened.
func (e *MultipathExecutor) Journal(pay *MultipathPayment) error {
	if e.dir == "" {
		return nil
	}
	type wire struct {
		MultipathPayment
		TotalDec  string   `json:"total"`
		AmountDec []string `json:"amounts"`
	}
	w := wire{MultipathPayment: *pay, TotalDec: decString(pay.Total)}
	for _, l := range pay.Legs {
		w.AmountDec = append(w.AmountDec, decString(l.Amount))
	}
	b, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	tmp := e.journalPath(pay.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.journalPath(pay.ID))
}

// LoadJournal reads back an attempt record after a restart.
func (e *MultipathExecutor) LoadJournal(id [32]byte) (*MultipathPayment, error) {
	b, err := os.ReadFile(e.journalPath(id))
	if err != nil {
		return nil, err
	}
	var w struct {
		MultipathPayment
		TotalDec  string   `json:"total"`
		AmountDec []string `json:"amounts"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	pay := w.MultipathPayment
	total, err := parseDec(w.TotalDec)
	if err != nil {
		return nil, err
	}
	pay.Total = total
	for i := range pay.Legs {
		if i < len(w.AmountDec) {
			amt, err := parseDec(w.AmountDec[i])
			if err != nil {
				return nil, err
			}
			pay.Legs[i].Amount = amt
		}
	}
	return &pay, nil
}

// settleIntent and refundIntent are distinct from the lock intent, so settling
// is not confusable with locking and a replay of one cannot pass for the other.
func settleIntent(lockIntent [32]byte) [32]byte {
	return derive("syndichan/multipath/settle/v1", lockIntent[:])
}
func refundIntent(lockIntent [32]byte) [32]byte {
	return derive("syndichan/multipath/refund/v1", lockIntent[:])
}

// Status asks the CHANNELS what happened. It never consults the journal for
// outcomes, which is the whole point: a recovering process must discover the
// real state rather than inherit its predecessor's intentions.
func (e *MultipathExecutor) Status(pay *MultipathPayment) []LegState {
	out := make([]LegState, 0, len(pay.Legs))
	for _, leg := range pay.Legs {
		st := LegState{Index: leg.Index}
		if ch, ok := e.coord.Channel(leg.Channel); ok {
			if nonce, applied := ch.AppliedAt(leg.Intent); applied {
				st.Locked, st.Nonce = true, nonce
			}
			if _, applied := ch.AppliedAt(settleIntent(leg.Intent)); applied {
				st.Settled = true
			}
			if _, applied := ch.AppliedAt(refundIntent(leg.Intent)); applied {
				st.Refunded = true
			}
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// Outcome summarises a payment across its legs.
type Outcome struct {
	Locked, Settled, Refunded, Pending int
	// SettledAmount is the value actually delivered, summed from legs the
	// CHANNELS confirm settled.
	SettledAmount *big.Int
	Legs          []LegState
}

// Complete is true when every leg settled — the only state in which the
// recipient has the whole payment.
func (o Outcome) Complete(pay *MultipathPayment) bool {
	return o.Settled == len(pay.Legs) && o.SettledAmount.Cmp(pay.Total) == 0
}

// Summarise derives an Outcome. SettledAmount is summed from confirmed legs
// only, so a partially settled payment reports what was really delivered rather
// than what was intended.
func (e *MultipathExecutor) Summarise(pay *MultipathPayment) Outcome {
	legs := e.Status(pay)
	out := Outcome{SettledAmount: new(big.Int), Legs: legs}
	for i, st := range legs {
		switch {
		case st.Settled:
			out.Settled++
			out.SettledAmount.Add(out.SettledAmount, pay.Legs[i].Amount)
		case st.Refunded:
			out.Refunded++
		case st.Locked:
			out.Locked++
		default:
			out.Pending++
		}
	}
	return out
}

// PeerFor supplies the transport for a channel.
type PeerFor func(channel [32]byte) (Peer, error)

// Lock places every fragment's HTLC, and reports per-leg errors without
// abandoning the rest.
//
// Fragments are independent by construction, so one failing must not prevent
// the others from resolving — a caller that stopped at the first error would
// leave earlier legs locked with nothing driving them to a terminal state.
func (e *MultipathExecutor) Lock(ctx context.Context, pay *MultipathPayment, peers PeerFor) ([]error, error) {
	if err := e.Journal(pay); err != nil {
		return nil, fmt.Errorf("multipath: could not journal the attempt: %w", err)
	}
	// ONE payment, N legs. Recorded here, once, at the moment the split is
	// actually attempted — not per leg, which would make a 4-way split look like
	// four payments, and not with any leg's channel or intent, which the
	// collector could not accept.
	e.metrics.MultipathPayment(len(pay.Legs))

	errs := make([]error, len(pay.Legs))
	for i, leg := range pay.Legs {
		peer, err := peers(leg.Channel)
		if err != nil {
			errs[i] = err
			e.metrics.ExecutorFailure()
			continue
		}
		tr := StateTransition{
			Kind: KindLockAdd, Amount: new(big.Int).Set(leg.Amount),
			LockID: leg.LockID, Hash: leg.Hash, Expiry: leg.Expiry,
		}
		// Coordinator.Pay is idempotent on the intent, so a retry after an
		// ambiguous outcome converges instead of paying twice.
		errs[i] = asLegError(e.coord.Pay(ctx, leg.Channel, leg.Intent, tr, peer))
		if errs[i] != nil {
			e.metrics.ExecutorFailure()
		}
	}
	return errs, nil
}

// Settle claims every locked fragment using its own preimage.
//
// Requires the payment secret, which only the recipient has. Each leg is
// settled with FragmentPreimage(secret, i) — leg i's preimage and no other's,
// so a leaked preimage opens exactly one fragment.
func (e *MultipathExecutor) Settle(ctx context.Context, pay *MultipathPayment,
	secret [32]byte, peers PeerFor) ([]error, error) {

	errs := make([]error, len(pay.Legs))
	status := e.Status(pay)
	for i, leg := range pay.Legs {
		if !status[i].Locked || status[i].Terminal() {
			continue // nothing to settle, or already resolved
		}
		peer, err := peers(leg.Channel)
		if err != nil {
			errs[i] = err
			continue
		}
		tr := StateTransition{
			Kind: KindLockSettle, LockID: leg.LockID,
			Preimage: FragmentPreimage(secret, leg.Intent),
		}
		errs[i] = asLegError(e.coord.Pay(ctx, leg.Channel, settleIntent(leg.Intent), tr, peer))
		if errs[i] != nil {
			e.metrics.ExecutorFailure()
		}
	}
	// The VALUE actually delivered, summed from what the channels confirm — one
	// number for the whole payment. Summarise reads per-leg state to compute it,
	// and that state stays inside Summarise; only the total crosses the boundary.
	if out := e.Summarise(pay); out.Settled > 0 {
		e.metrics.TipCompleted(out.SettledAmount)
	}
	return errs, nil
}

// Refund returns every locked-but-unsettled fragment to its payer.
//
// Used when the payment cannot complete. Legs that already settled are left
// alone: refunding a settled leg would be the double-spend this whole design
// exists to prevent, and skipping them here is not an optimisation.
func (e *MultipathExecutor) Refund(ctx context.Context, pay *MultipathPayment, peers PeerFor) ([]error, error) {
	errs := make([]error, len(pay.Legs))
	status := e.Status(pay)
	for i, leg := range pay.Legs {
		if !status[i].Locked || status[i].Terminal() {
			continue
		}
		peer, err := peers(leg.Channel)
		if err != nil {
			errs[i] = err
			continue
		}
		tr := StateTransition{Kind: KindLockRefund, LockID: leg.LockID}
		errs[i] = asLegError(e.coord.Pay(ctx, leg.Channel, refundIntent(leg.Intent), tr, peer))
		if errs[i] != nil {
			e.metrics.ExecutorFailure()
		}
	}
	return errs, nil
}

// Resume re-drives a payment after a crash or an ambiguous outcome.
//
// It reads the journal ONLY to learn which fragments belong together, then asks
// the channels what actually happened and acts on that. A leg the previous
// process believed it had settled but had not is simply an unsettled leg here;
// there is no state in which this trusts the earlier intention over the signed
// record.
//
// `settle` decides the direction: with the secret the payment is driven
// forward, without it the locked legs are unwound.
func (e *MultipathExecutor) Resume(ctx context.Context, id [32]byte,
	secret *[32]byte, peers PeerFor) (Outcome, []error, error) {

	pay, err := e.LoadJournal(id)
	if err != nil {
		return Outcome{}, nil, fmt.Errorf("multipath: no attempt journal for %s: %w", hex.EncodeToString(id[:])[:12], err)
	}
	var errs []error
	if secret != nil {
		// Any fragment not yet locked must be locked before it can settle —
		// the crash may have landed between two legs.
		if lockErrs, err := e.Lock(ctx, pay, peers); err != nil {
			return Outcome{}, nil, err
		} else {
			errs = append(errs, lockErrs...)
		}
		settleErrs, err := e.Settle(ctx, pay, *secret, peers)
		if err != nil {
			return Outcome{}, nil, err
		}
		errs = append(errs, settleErrs...)
	} else {
		refundErrs, err := e.Refund(ctx, pay, peers)
		if err != nil {
			return Outcome{}, nil, err
		}
		errs = append(errs, refundErrs...)
	}
	return e.Summarise(pay), errs, nil
}

// ---- making the existing SplitPlan executable -------------------------------

// ErrPlanChannelMismatch means the channel assignment does not match the plan.
var ErrPlanChannelMismatch = errors.New(
	"multipath: one channel must be assigned per fragment, in fragment order")

// PaymentFromSplitPlan turns a real SplitPlan into an executable payment.
//
// WHY THIS IS A CONVERSION AND NOT A MERGE
// ----------------------------------------
// A SplitPlan and a MultipathPayment describe different halves of the same
// payment, in different vocabularies, and collapsing them would lose something:
//
//	SplitPlan       amounts, routes, and a per-fragment point-based LockChain.
//	                The LockChain is ROUTING machinery — adaptor points unwound
//	                hop by hop so an intermediary learns its scalar only once it
//	                has been paid downstream.
//	MultipathLeg    a channel, an amount, an expiry, and a hash-based HTLC.
//	                That is what ChannelManagerV2 settles.
//
// Both are real and neither replaces the other. The plan says how value travels;
// the leg says what the contract will enforce. So the LockChain rides alongside
// as routing metadata and the HTLC is the settlement lock — rather than one
// being rewritten into the other, which would either put adaptor points somewhere
// the contract cannot check them, or throw away the per-hop unwinding that makes
// routed payments safe for intermediaries.
//
// EXPIRIES COME FROM THE ROUTE, NOT FROM A CONSTANT
// -------------------------------------------------
// Each fragment's window is sized by ITS OWN hop count, because a longer route
// genuinely needs longer: every hop must be able to claim upstream after paying
// downstream, and a uniform expiry would starve the longest route while
// over-exposing the shortest. `deadline` then bounds the whole payment, so the
// payer's exposure is one number they chose rather than the maximum of whatever
// the router happened to pick.
func PaymentFromSplitPlan(plan *SplitPlan, id, secret [32]byte,
	channels [][32]byte, now, perHopSeconds, deadline int64) (*MultipathPayment, error) {

	// The plan must be internally consistent BEFORE it is turned into money
	// movements. Verify checks the fragment sum and cross-route operator
	// disjointness; skipping it here would mean a tampered plan becomes a set of
	// signed channel states.
	if err := plan.Verify(); err != nil {
		return nil, fmt.Errorf("multipath: plan does not verify: %w", err)
	}
	if len(channels) != len(plan.Fragments) {
		return nil, fmt.Errorf("%w: %d channels for %d fragments",
			ErrPlanChannelMismatch, len(channels), len(plan.Fragments))
	}
	if perHopSeconds <= 0 {
		return nil, fmt.Errorf("%w: per-hop window must be positive", ErrFragmentExpiryUnsafe)
	}

	amounts := make([]*big.Int, len(plan.Fragments))
	expiries := make([]int64, len(plan.Fragments))
	total := new(big.Int)
	for i, frag := range plan.Fragments {
		amounts[i] = new(big.Int).SetInt64(int64(frag.Amount))
		total.Add(total, amounts[i])

		// One window per hop, plus one for the recipient's own claim.
		hops := len(frag.Route)
		if hops == 0 {
			return nil, fmt.Errorf("%w: fragment %d has no route", ErrPlanChannelMismatch, i)
		}
		expiries[i] = now + perHopSeconds*int64(hops+1)
	}

	// BuildPayment re-checks conservation against this total, rejects duplicate
	// channels, and rejects any expiry beyond the deadline. Deliberately not
	// bypassed: it is the one place those three rules live.
	return BuildPayment(id, secret, total, deadline, channels, amounts, expiries)
}

// RoutingLocksFor returns the plan's point-based LockChain for a fragment.
//
// Exposed so a router can drive the onion unwinding alongside the channel
// settlement, and separate from the leg so nothing can mistake an adaptor point
// for something the contract will check.
func RoutingLocksFor(plan *SplitPlan, index int) (*LockChain, error) {
	if plan == nil || index < 0 || index >= len(plan.Fragments) {
		return nil, fmt.Errorf("multipath: no fragment %d", index)
	}
	return plan.Fragments[index].Locks, nil
}
