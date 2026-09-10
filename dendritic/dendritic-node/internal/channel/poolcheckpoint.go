package channel

// Executing a pooled-tip withdrawal — roadmap P15 phase 5.
//
// WHAT THIS ADDS: ORCHESTRATION, AND NOTHING ELSE
// -----------------------------------------------
// The checkpoint machinery already exists and is not touched here:
//
//	KindCheckpoint          the transition                  transition.go:201
//	StateTransition.Apply   builds the next state           transition.go
//	PeerSession.Propose     signs it, checks I4 timing      session.go:151
//	Store.Accept            records the co-signed state     store.go
//	CheckpointCalldata      encodes the contract call       chainwriter.go:149
//	ChainWriter.Checkpoint  broadcasts it                   chainwriter.go:364
//
// This file only decides WHICH channel and HOW MUCH, and then drives those in
// order. It constructs no state, computes no digest, chooses no nonce and signs
// nothing itself. Every one of those would be a second implementation of a rule
// that already has one, and the second implementation is the one that is wrong.
//
// THE REQUEST IS NOT THE AUTHORITY
// --------------------------------
// A caller may NAME a channel — this is the recipient's own authenticated node,
// so it is theirs to name. It may not DESCRIBE one. The amount, the nonce, both
// balances and which side the recipient is on all come from the co-signed state
// in the Store. A request saying "withdraw 5000" cannot manufacture 5000; it is
// checked against what the bilateral state actually holds and refused if it
// exceeds it.
//
// That distinction is the same one Coordinator.Adopt makes about collateral: a
// peer may name a channel, never describe one.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

var (
	// ErrCheckpointNotEligible means the channel holds nothing the recipient
	// could withdraw. Distinct from an error: it is the ordinary state of a
	// channel nobody has tipped through yet.
	ErrCheckpointNotEligible = errors.New("channel: nothing to withdraw from this channel")
	// ErrCheckpointTooLarge means the request asked for more than the co-signed
	// state holds. THE REQUEST IS REFUSED RATHER THAN CLAMPED: silently
	// withdrawing less than asked would report success for something that did
	// not happen.
	ErrCheckpointTooLarge = errors.New("channel: requested more than the channel's withdrawable balance")
	// ErrCheckpointNoPeer means the counterparty could not be reached to
	// co-sign. A checkpoint needs both signatures — the contract verifies them —
	// so there is no path that completes without the contributor.
	ErrCheckpointNoPeer = errors.New("channel: the contributor could not be reached to co-sign")
)

// CheckpointOutcome is what happened. Deliberately three-valued for the same
// reason a payment is: "broadcast then the network died" is not failure, and
// reporting it as failure invites a second withdrawal attempt.
type CheckpointOutcome string

const (
	// CheckpointSigned means both parties signed the withdrawal state. Value has
	// left the recipient's channel balance and is recorded as a withdrawal; the
	// chain has not paid it out yet.
	CheckpointSigned CheckpointOutcome = "SIGNED"
	// CheckpointBroadcast means the transaction was sent and accepted by the
	// node. Not "confirmed" — see payout.go on why those are separate.
	CheckpointBroadcast CheckpointOutcome = "BROADCAST"
	// CheckpointUnknown means it may or may not have happened. The only honest
	// answer after a transport failure, and the caller must re-read state
	// rather than retry.
	CheckpointUnknown CheckpointOutcome = "UNKNOWN"
	// CheckpointContributorOffline means the value is there but the other party
	// could not be reached to co-sign it.
	//
	// DISTINCT FROM UNKNOWN, and the distinction is worth the extra state. The
	// dial never connected, so nothing was proposed and nothing can have been
	// signed — the recipient can be told plainly that their money is fine and
	// the withdrawal simply needs the contributor online. Folding this into
	// UNKNOWN would make an ordinary, recoverable situation read like a
	// possible loss.
	//
	// DISTINCT FROM "nothing to withdraw" for the opposite reason: that one
	// says there is no money, and saying it here would be false.
	CheckpointContributorOffline CheckpointOutcome = "CONTRIBUTOR_OFFLINE"
)

// CheckpointResult describes one withdrawal attempt.
type CheckpointResult struct {
	Outcome CheckpointOutcome
	// Amount actually taken out, read back from the signed state rather than
	// echoed from the request.
	Amount *big.Int
	Nonce  uint64
	TxHash string
}

// CheckpointIntent derives the idempotence key for withdrawing from a channel
// at a particular state.
//
// Derived, never supplied. A caller-chosen intent would let a second request
// present itself as new work and withdraw the same value twice; deriving it
// from the state being withdrawn FROM means a repeat of the same request is
// recognised by the existing AppliedAt machinery and answered from the record.
//
// sha256 rather than keccak because this is a LOCAL key, not a protocol digest —
// nothing on chain or in a signature depends on it.
func CheckpointIntent(id [32]byte, nonce uint64, amount *big.Int) [32]byte {
	h := sha256.New()
	h.Write([]byte("syndichan/p15/checkpoint\x00"))
	h.Write(id[:])
	var n [8]byte
	for i := 0; i < 8; i++ {
		n[7-i] = byte(nonce >> (8 * i))
	}
	h.Write(n[:])
	h.Write(orZero(amount).Bytes())

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// CheckpointEligible reports what the recipient could withdraw from a channel.
//
// Reads the co-signed state and works out which side is theirs. NOTHING here
// assumes party A: the recipient is whichever side the chain assigned, and a
// version of this that hardcoded WithdrawA would silently withdraw against the
// contributor's balance whenever addresses happened to sort the other way.
func (c *Coordinator) CheckpointEligible(id [32]byte) (*big.Int, error) {
	ch, ok := c.store.Get(id)
	if !ok {
		return nil, ErrNoSuchChannel
	}
	if ch.PartyA != c.self && ch.PartyB != c.self {
		// Not ours. Refused rather than reported as zero: zero would read as
		// "nothing there yet" for a channel this node may not ask about at all.
		return nil, ErrNotAParty
	}
	if ch.Conflict != nil {
		return nil, ErrConflicted
	}
	if ch.Status != StatusOpen {
		return nil, ErrCheckpointNotEligible
	}
	if !ch.Latest.Complete() {
		// No fully co-signed state. There is nothing both parties agreed to,
		// so there is nothing the contract would accept.
		return nil, ErrCheckpointNotEligible
	}
	mine := recipientBalance(ch.Latest.State, ch.PartyA == c.self)
	if orZero(mine).Sign() <= 0 {
		return nil, ErrCheckpointNotEligible
	}
	return new(big.Int).Set(mine), nil
}

// Checkpoint co-signs a withdrawal of `requested` from one channel.
//
// A nil `requested` means "everything eligible", which is what the dashboard
// asks for. A non-nil one is VALIDATED against the state, never trusted.
//
// This does not broadcast. Signing and sending are separate because they fail
// separately: a signed state that was never broadcast is safe and re-sendable,
// whereas conflating them makes an unsent transaction look like a lost one.
func (c *Coordinator) Checkpoint(ctx context.Context, id [32]byte,
	requested *big.Int, peer Peer) (CheckpointResult, error) {

	eligible, err := c.CheckpointEligible(id)
	if err != nil {
		return CheckpointResult{}, err
	}

	amount := eligible
	if requested != nil {
		if requested.Sign() <= 0 {
			return CheckpointResult{}, ErrAmountNotPositive
		}
		if requested.Cmp(eligible) > 0 {
			// The whole point of the check. A request cannot invent value that
			// the bilateral state does not hold.
			return CheckpointResult{}, fmt.Errorf("%w: asked %s, holds %s",
				ErrCheckpointTooLarge, requested, eligible)
		}
		amount = new(big.Int).Set(requested)
	}

	ch, ok := c.store.Get(id)
	if !ok {
		return CheckpointResult{}, ErrNoSuchChannel
	}
	intent := CheckpointIntent(id, ch.Latest.State.Nonce, amount)

	// IDEMPOTENCE, from the existing machinery. A repeat of the same withdrawal
	// against the same state is answered from the record instead of signing a
	// second one.
	if nonce, applied := ch.AppliedAt(intent); applied {
		return CheckpointResult{
			Outcome: CheckpointSigned,
			Amount:  new(big.Int).Set(amount),
			Nonce:   nonce,
		}, nil
	}

	tr := StateTransition{Kind: KindCheckpoint, Amount: amount}

	// Propose runs Apply, the I4 timing rules and this node's signature. If it
	// refuses, nothing was sent and nothing was signed.
	propose, err := c.sess.Propose(id, intent, tr)
	if err != nil {
		return CheckpointResult{}, err
	}
	if peer == nil {
		return CheckpointResult{
			Outcome: CheckpointContributorOffline,
			// The eligible amount travels with the refusal so the UI can say
			// "your funds are there" rather than showing a bare error.
			Amount: new(big.Int).Set(amount),
		}, ErrCheckpointNoPeer
	}

	reply, err := peer.Exchange(ctx, propose)
	if err != nil {
		if errors.Is(err, ErrPeerUnreachable) {
			// NOT AMBIGUOUS. The connection was never established, so the
			// proposal was never written and the contributor cannot have
			// signed. Nothing is recorded as unknown, because nothing is.
			return CheckpointResult{
				Outcome: CheckpointContributorOffline,
				Amount:  new(big.Int).Set(amount),
			}, err
		}
		// Past the dial, the contributor may or may not have signed. Recorded
		// as unknown for the same reason Pay does: resync establishes what
		// happened, a guess here does not.
		_ = c.store.Update(id, func(ch *Channel) error {
			rec := recordFor(intent, tr, false, PayUnknown, c.clock())
			rec.Detail = err.Error()
			ch.NotePayment(rec)
			return nil
		})
		return CheckpointResult{Outcome: CheckpointUnknown}, err
	}

	switch reply.Type {
	case MsgStateAccept:
		// HandleAccept verifies the counterparty's signature and calls
		// Store.Accept. This node never writes a state it did not verify.
		if err := c.sess.HandleAccept(reply); err != nil {
			return CheckpointResult{}, err
		}
		fresh, _ := c.store.Get(id)
		return CheckpointResult{
			Outcome: CheckpointSigned,
			// READ BACK from the signed state, not echoed from the request, so
			// the caller is told what was actually agreed.
			Amount: withdrawnBy(fresh.Latest.State, fresh.PartyA == c.self),
			Nonce:  fresh.Latest.State.Nonce,
		}, nil

	case MsgStateReject:
		if _, err := c.sess.HandleReject(reply); err != nil {
			return CheckpointResult{}, err
		}
		return CheckpointResult{}, errors.New("channel: the contributor refused the withdrawal")
	}
	return CheckpointResult{}, fmt.Errorf("channel: unexpected reply %q", reply.Type)
}

// withdrawnBy reads the recipient's side of a checkpoint state.
//
// Side-aware for the same reason CheckpointEligible is: which of WithdrawA and
// WithdrawB belongs to the recipient depends on how the two addresses sorted
// when the channel was opened, and that is not something to assume.
func withdrawnBy(s State, recipientIsA bool) *big.Int {
	if recipientIsA {
		return new(big.Int).Set(orZero(s.WithdrawA))
	}
	return new(big.Int).Set(orZero(s.WithdrawB))
}

// BroadcastCheckpoint sends the channel's current co-signed checkpoint state.
//
// The same call trySubmit makes, exposed so a recipient can withdraw on demand
// rather than waiting for the interval policy. It builds no calldata of its own:
// ChainWriter.Checkpoint uses CheckpointCalldata, which reads the stored state.
func (w *PayoutWorker) BroadcastCheckpoint(ctx context.Context, id [32]byte) (string, error) {
	ch, ok := w.store.Get(id)
	if !ok {
		return "", ErrNoSuchChannel
	}
	if !ch.Latest.Complete() {
		return "", ErrNothingToSubmit
	}
	if !hasWithdrawal(ch.Latest.State) {
		// Broadcasting a state with no withdrawal would spend gas to move
		// nothing, and would look like a withdrawal in the recipient's history.
		return "", ErrCheckpointNotEligible
	}
	return w.writer.Checkpoint(ctx, w.contract, ch)
}
