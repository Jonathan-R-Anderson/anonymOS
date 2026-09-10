package channel

// Many-to-one tipping pools — roadmap P15.
//
// A POOL IS A DERIVED VIEW, NOT A LEDGER
// --------------------------------------
// The obvious implementation records
//
//	Alice = 1     Bob = 5     Carol = 2
//
// and promises to pay the recipient. That is a custodian with extra steps: the
// numbers can be wrong, and somebody has to be trusted not to make them wrong.
//
// So nothing here stores a balance. A pool is a NAME and a SET OF CHANNEL IDS.
// The aggregate is a sum over co-signed bilateral states the recipient already
// holds, recomputed on every read. Delete the view and nothing is lost; corrupt
// it and the next call corrects it.
//
//	Alice ──[channel]──┐
//	Bob   ──[channel]──┼──► recipient's store ──► View() ──► Σ recipient balance
//	Carol ──[channel]──┘         (the money)        (a sum, computed)
//
// That is what makes "non-custodial" structural rather than a promise: there is
// no balance to manufacture because none is kept. A test pins it — Pool may not
// grow a field that could hold value.
//
// WHAT IT IS NOT
// --------------
// Not an N-party channel. Not a new transition, message or contract function.
// Not a coordinator: "what if the pool operator disappears" has no subject,
// because the pool is the recipient's view of their own store.
//
// OPTIONAL MEANS OPTIONAL
// -----------------------
// The zero value is DISABLED and bilateral tipping is untouched. A recipient who
// never turns this on never encounters it, and no payment is routed through a
// pool because one happens to exist.

import (
	"errors"
	"fmt"
	"math/big"
)

var (
	// ErrPoolDisabled means the recipient has not turned pooling on. Bilateral
	// tipping is the default and remains the path.
	ErrPoolDisabled = errors.New("channel: pooling is not enabled for this recipient")
	// ErrPoolOverlap means two pools claim the same channel. Value could then be
	// counted twice, and only one of the two views could ever be withdrawn.
	ErrPoolOverlap = errors.New("channel: a channel belongs to more than one pool")
	// NOTE: a pool listing a channel its recipient is not part of reuses the
	// EXISTING ErrNotAParty from transition.go rather than defining a second
	// error for one concept. It is refused rather than skipped: silently
	// dropping it would under-report the aggregate and look like a payment
	// that vanished.
	// ErrPoolEmpty means a pool names no channels.
	ErrPoolEmpty = errors.New("channel: the pool has no member channels")
)

// PoolPolicy is what a recipient chooses. The zero value is disabled.
type PoolPolicy struct {
	// Enabled turns pooling on for this recipient. Off by default, deliberately.
	Enabled bool

	// MinCheckpoint is the smallest balance worth an on-chain checkpoint.
	//
	// A pool cannot batch: ChannelManagerV2.checkpoint takes ONE channel id and
	// both parties' signatures, so N contributors is N transactions. Below some
	// amount a checkpoint costs more gas than it moves, and this is where the
	// recipient states that threshold. Nil means "no minimum".
	MinCheckpoint *big.Int
}

// Pool names a set of channels one recipient aggregates over.
//
// It holds NO VALUE. Members are ids; the money lives in the co-signed states
// those ids refer to.
type Pool struct {
	Name      string
	Recipient Address
	Members   [][32]byte
	Policy    PoolPolicy
}

// PoolView is the computed aggregate. It is a return value, never persisted.
type PoolView struct {
	Pool string
	// Members counted, and the distinct counterparties behind them.
	Members      int
	Contributors int

	// Withdrawable is the sum of the recipient's balance across member
	// channels. Value in live locks is NOT here — KindLockAdd already takes it
	// out of the payer's balance, and it belongs to neither party until the lock
	// resolves.
	Withdrawable *big.Int
	// InFlight is the total committed to live locks across the members.
	// Reported so it is visible, never counted as spendable.
	InFlight *big.Int

	// Excluded records members that could not contribute to the sum, with the
	// reason. A pool that quietly dropped them would under-report.
	Excluded []PoolExclusion
}

// PoolExclusion says why a member did not count.
type PoolExclusion struct {
	Channel [32]byte
	Reason  string
}

// CheckpointCandidate is one channel worth taking value out of.
//
// It carries no signature and authorises nothing. Producing the state is the
// existing KindCheckpoint transition's job, and it is co-signed like any other.
type CheckpointCandidate struct {
	Channel [32]byte
	// Amount the recipient could withdraw — their whole balance.
	Amount *big.Int
	// LocksLive is true when the channel still has pending HTLCs. The contract
	// ALLOWS a checkpoint with locks outstanding (it conserves them in the
	// balance check), unlike closeCooperative which refuses any non-zero root.
	LocksLive bool
}

// View recomputes the aggregate from the recipient's own store.
//
// Nothing is cached, and there is no incremental update path. The whole point is
// that this can be wrong only if the signed states are wrong, in which case
// everything else is wrong too.
func (p Pool) View(src ChannelSource) (PoolView, error) {
	if !p.Policy.Enabled {
		return PoolView{}, ErrPoolDisabled
	}
	if len(p.Members) == 0 {
		return PoolView{}, ErrPoolEmpty
	}
	if src == nil {
		return PoolView{}, errors.New("channel: pool view needs a channel source")
	}

	view := PoolView{
		Pool:         p.Name,
		Withdrawable: new(big.Int),
		InFlight:     new(big.Int),
	}
	counterparties := make(map[Address]struct{}, len(p.Members))

	for _, id := range p.Members {
		ch, ok := src.Get(id)
		if !ok {
			view.Excluded = append(view.Excluded, PoolExclusion{
				Channel: id, Reason: "not held by this node",
			})
			continue
		}

		mine, other, err := p.side(ch)
		if err != nil {
			// A membership error is the pool being wrong about itself, which is
			// not something to paper over with a smaller number.
			return PoolView{}, fmt.Errorf("%w: channel %x", err, id[:4])
		}

		if ch.Status != StatusOpen {
			view.Excluded = append(view.Excluded, PoolExclusion{
				Channel: id,
				Reason:  fmt.Sprintf("status %d: checkpoint requires an open channel", int(ch.Status)),
			})
			continue
		}
		if !ch.Latest.Complete() {
			view.Excluded = append(view.Excluded, PoolExclusion{
				Channel: id, Reason: "no fully signed state",
			})
			continue
		}

		balance := recipientBalance(ch.Latest.State, mine)
		if balance == nil {
			view.Excluded = append(view.Excluded, PoolExclusion{
				Channel: id, Reason: "state carries no balance",
			})
			continue
		}
		view.Withdrawable.Add(view.Withdrawable, balance)
		for _, lock := range ch.Latest.State.Pending {
			if lock.Amount != nil {
				view.InFlight.Add(view.InFlight, lock.Amount)
			}
		}
		view.Members++
		counterparties[other] = struct{}{}
	}
	view.Contributors = len(counterparties)
	return view, nil
}

// CheckpointPlan lists the members worth checkpointing, largest first is NOT
// imposed — the order is the pool's own, because a policy that silently
// reordered would make two calls disagree about what "the first one" is.
//
// It authorises nothing. Each candidate still needs a KindCheckpoint transition
// co-signed by that contributor, exactly as a bilateral withdrawal does.
func (p Pool) CheckpointPlan(src ChannelSource) ([]CheckpointCandidate, error) {
	if !p.Policy.Enabled {
		return nil, ErrPoolDisabled
	}
	if src == nil {
		return nil, errors.New("channel: checkpoint plan needs a channel source")
	}
	var out []CheckpointCandidate
	for _, id := range p.Members {
		ch, ok := src.Get(id)
		if !ok || ch.Status != StatusOpen || !ch.Latest.Complete() {
			continue
		}
		mine, _, err := p.side(ch)
		if err != nil {
			return nil, fmt.Errorf("%w: channel %x", err, id[:4])
		}
		balance := recipientBalance(ch.Latest.State, mine)
		if balance == nil || balance.Sign() <= 0 {
			continue
		}
		if min := p.Policy.MinCheckpoint; min != nil && balance.Cmp(min) < 0 {
			// Below the threshold the transaction costs more than it moves.
			continue
		}
		out = append(out, CheckpointCandidate{
			Channel:   id,
			Amount:    new(big.Int).Set(balance),
			LocksLive: len(ch.Latest.State.Pending) > 0,
		})
	}
	return out, nil
}

// side reports whether the recipient is party A, and who the counterparty is.
func (p Pool) side(ch *Channel) (recipientIsA bool, other Address, err error) {
	switch p.Recipient {
	case ch.PartyA:
		return true, ch.PartyB, nil
	case ch.PartyB:
		return false, ch.PartyA, nil
	default:
		return false, Address{}, ErrNotAParty
	}
}

// recipientBalance reads the side of the state that belongs to the recipient.
//
// Locked value is already absent: KindLockAdd takes it out of the payer's
// balance and puts it in neither, so a live lock cannot be double-counted as
// spendable here.
func recipientBalance(s State, recipientIsA bool) *big.Int {
	if recipientIsA {
		return s.BalanceA
	}
	return s.BalanceB
}

// CheckDisjoint refuses a set of pools that share a channel.
//
// A channel's value can be checkpointed ONCE. Two pools listing it would both
// count it, the recipient would believe they hold more than they can withdraw,
// and only one of the two views could ever be realised. Nothing structural
// prevents the overlap, so it is checked.
func CheckDisjoint(pools []Pool) error {
	owner := make(map[[32]byte]string)
	for _, p := range pools {
		for _, id := range p.Members {
			if prev, taken := owner[id]; taken {
				return fmt.Errorf("%w: channel %x is in both %q and %q",
					ErrPoolOverlap, id[:4], prev, p.Name)
			}
			owner[id] = p.Name
		}
	}
	return nil
}
