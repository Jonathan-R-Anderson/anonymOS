package channel

// Restoring a backup without double-signing — roadmap P11-4.
//
// THE PROBLEM
// -----------
// A backup is not another copy of the channel database. It is a ROLLBACK, and
// the store's monotonicity guarantee does not survive one:
//
//	node, running:      nonce 43     the counterparty holds this, co-signed
//	backup, taken at:   nonce 40
//	                       |
//	                    restore
//	                       v
//	node now believes:  nonce 40     and will sign 41 again, differently
//
// The second signature at 41 is a double-spend the node cannot see, because
// everything it can see is internally consistent. The file verifies. The
// digests match. The signatures recover. Nothing is corrupt — it is simply a
// coherent version of a past that has been overtaken.
//
// WHY IT CANNOT BE DETECTED LOCALLY
// ---------------------------------
// Every local signal was rolled back with the data. A high-water file, a
// counter, a "last nonce" marker: the restore restores those too. There is no
// arrangement of local state that survives its own restoration.
//
// So the node has to ASK SOMEBODY ELSE. The counterparty holds the states it
// co-signed, and a vault holds them too, and either can answer "is there
// something newer than what I have".
//
// WHY THE ANSWER CAN BE TRUSTED FROM AN UNTRUSTED SOURCE
// ------------------------------------------------------
// The counterparty might be the one attacking. It does not matter:
//
//	a node can recognise its OWN signature on a state it does not remember
//	making, because signatures recover to an address
//
// So a claimed newer state is adopted only if this node's own key signed it. A
// hostile peer can therefore only ever confront a restored node with states it
// genuinely produced — which is exactly the set it must not sign against again.
// It cannot invent one, and withholding one leaves the node no worse off than
// it already was.
//
// THE RULE
// --------
//	A restored channel MUST NOT be signed for until it has been reconciled.
//
// Refusing to pay is an outage. Signing twice at one nonce is a loss that
// cannot be undone, and the counterparty gets to choose which of the two states
// to settle. The outage is the right trade, and it is short: reconciliation is
// one round trip.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// RestoreMarker is the file a restore procedure leaves in the store directory.
//
// A FILE rather than an inference, because the store cannot tell a restore from
// an ordinary start — that is the whole problem. Whoever performs the restore
// knows, and this is how they say so.
//
// Its presence makes every channel unsignable until reconciled. It is removed
// once they all are.
const RestoreMarker = "RESTORED"

// ErrNeedsReconcile is returned when a restored channel is asked to sign.
//
// Deliberately not retryable in the payment sense: waiting will not fix it, and
// a caller that treated it as transient would spin. Something has to reconcile.
var ErrNeedsReconcile = errors.New(
	"channel: restored from backup and not yet reconciled; signing is refused")

// MarkRestored writes the marker into a store directory.
//
// For a restore procedure to call BEFORE the node starts. Calling it on a
// running node is meaningless: the channels are already loaded.
func MarkRestored(dir string) error {
	return os.WriteFile(filepath.Join(dir, RestoreMarker),
		[]byte("this node was restored from a backup and may hold stale states\n"), 0o600)
}

// wasRestored reports whether the marker is present.
func wasRestored(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, RestoreMarker))
	return err == nil
}

// NeedsReconcile reports whether a channel is still quarantined.
func (s *Store) NeedsReconcile(id [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.unreconciled[id]
	return ok
}

// Unreconciled lists every quarantined channel, for an operator or a startup
// routine that has to work through them.
func (s *Store) Unreconciled() [][32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][32]byte, 0, len(s.unreconciled))
	for id := range s.unreconciled {
		out = append(out, id)
	}
	return out
}

// clearReconcile releases one channel, and removes the marker once none remain.
//
// The marker goes only when the last channel is released, so a node that
// reconciled half its channels and then crashed comes back still quarantined
// for the other half.
func (s *Store) clearReconcile(id [32]byte) error {
	s.mu.Lock()
	delete(s.unreconciled, id)
	empty := len(s.unreconciled) == 0
	dir := s.dir
	s.mu.Unlock()

	if !empty {
		return nil
	}
	if err := os.Remove(filepath.Join(dir, RestoreMarker)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("channel: clearing the restore marker: %w", err)
	}
	return nil
}

// StateSource is anything that can be asked for its best state for a channel.
//
// A peer satisfies it, and so does a vault. Neither is trusted: what makes an
// answer usable is this node's own signature on it, not the honesty of whoever
// produced it.
type StateSource interface {
	Best(id [32]byte) (SignedState, bool)
}

// Reconcile releases a restored channel, adopting anything newer that this node
// really signed.
//
// Every source is asked, not just the first to answer. A peer may be offline
// while a vault is not, and the point of reconciling is to find the highest
// state that exists anywhere — settling for the first answer would leave a
// higher one unaccounted for and the node signing against it.
func (c *Coordinator) Reconcile(ctx context.Context, id [32]byte, sources ...StateSource) error {
	if !c.store.NeedsReconcile(id) {
		return nil
	}
	// The chain first, so the parties and deposits used to check any candidate
	// come from the contract rather than from whoever offered it.
	if err := c.Adopt(ctx, id); err != nil {
		return fmt.Errorf("channel: reconciling %x: %w", id[:4], err)
	}
	ch, ok := c.store.Get(id)
	if !ok {
		return ErrChannelNotAdopted
	}

	best := ch.Latest
	for _, source := range sources {
		candidate, ok := source.Best(id)
		if !ok || !candidate.Complete() {
			continue
		}
		if best.Complete() && candidate.State.Nonce <= best.State.Nonce {
			continue
		}
		if err := c.usable(ch, candidate); err != nil {
			// A source offering something this node cannot verify is a source
			// that is wrong or hostile, and neither is a reason to stop asking
			// the others.
			continue
		}
		best = candidate
	}

	if best.Complete() && (!ch.Latest.Complete() || best.State.Nonce > ch.Latest.State.Nonce) {
		if err := c.store.Update(id, func(live *Channel) error {
			// Through Accept, the one door: it re-checks conservation, the
			// nonce rule and both signatures against the live record rather
			// than against the snapshot this function has been reasoning about.
			return live.Accept(best)
		}); err != nil {
			return fmt.Errorf("channel: adopting the reconciled state: %w", err)
		}
	}
	return c.store.clearReconcile(id)
}

// usable reports whether a candidate is a state this node may adopt.
//
// The load-bearing check is the last one: THIS NODE'S OWN SIGNATURE. Without
// it, a peer could hand a restored node any co-signed-looking state and have it
// adopted; with it, the only states a peer can confront the node with are ones
// the node actually produced — which is precisely the set it must not sign
// against a second time.
func (c *Coordinator) usable(ch *Channel, candidate SignedState) error {
	if !candidate.State.Conserved(ch.DepositA, ch.DepositB) {
		return errors.New("candidate does not conserve the deposits")
	}
	digest := candidate.State.Digest(ch.ChainID, ch.Contract)
	if err := requireBothParties(digest, candidate, ch.PartyA, ch.PartyB); err != nil {
		return err
	}

	mine := candidate.SigA
	if ch.PartyB == c.self {
		mine = candidate.SigB
	}
	signer, err := RecoverSigner(digest, mine)
	if err != nil {
		return fmt.Errorf("candidate's signature for this node is unreadable: %w", err)
	}
	if signer != c.self {
		return fmt.Errorf("this node did not sign the candidate; %s did", signer)
	}
	return nil
}

// ReconcileAll works through every quarantined channel.
//
// Returns the first error but attempts them all: one unreachable counterparty
// must not leave the other channels quarantined for no reason.
func (c *Coordinator) ReconcileAll(ctx context.Context, sources ...StateSource) error {
	var first error
	for _, id := range c.store.Unreconciled() {
		if err := c.Reconcile(ctx, id, sources...); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Best makes a *Vault a StateSource.
//
// Already the right shape — which is not a coincidence. A vault exists to hold
// the newest state somebody can prove, and that is exactly what a restored node
// needs to ask for.
var _ StateSource = (*Vault)(nil)
