package ui

// The only file in this package that knows what a channel is.
//
// Everything else in the dashboard works against the Receiving interface, so
// the payment machinery has exactly one door into the UI and it is this one.
// If a panel ever needs something the interface does not offer, the right move
// is to widen the interface here rather than to import the channel package
// somewhere else — the second import is how a view becomes a participant.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/channel"
)

var errNoSuchChannel = errors.New("receiving: no such channel")

// PaymentNode is the payment side of a recipient's node, as this adapter needs
// it. Satisfied by wiring a *channel.Coordinator and a *channel.PayoutWorker
// together; an interface so the dashboard can be exercised without one.
type PaymentNode struct {
	Coord  *channel.Coordinator
	Payout *channel.PayoutWorker
	// Collect is the mailbox side, optional. Nil means this node does not use a
	// volunteer, which is a different statement from "no tips waiting".
	Collect *Collector
}

// NewPaymentNode wires the adapter.
func NewPaymentNode(coord *channel.Coordinator, payout *channel.PayoutWorker) *PaymentNode {
	return &PaymentNode{Coord: coord, Payout: payout}
}

// Channels renders every tracked channel for the panel.
func (p *PaymentNode) Channels(_ context.Context) ([]ReceivingChannel, error) {
	if p.Coord == nil {
		return nil, errors.New("receiving: no payment coordinator")
	}
	out := []ReceivingChannel{}
	for _, id := range p.Coord.Channels() {
		bal, err := p.Coord.Balances(id)
		if err != nil {
			// One unreadable channel must not blank the whole panel: an
			// operator with five channels and one problem needs to see the
			// other four.
			continue
		}
		row := ReceivingChannel{
			ID:         hex.EncodeToString(id[:]),
			Mine:       bal.Mine.String(),
			Theirs:     bal.Theirs.String(),
			Locked:     bal.Locked.String(),
			Nonce:      bal.Nonce,
			Conflicted: bal.Conflicted,
			Mode:       string(channel.PayoutOnClose),
			Phase:      string(channel.PhaseNone),
		}
		// The node works out what is claimable and what is merely in flight —
		// this only renders the answer. See internal/channel/locks.go for why
		// that decision does not live here.
		if exp, err := p.Coord.Exposure(id); err == nil {
			row.Mine, row.Incoming = exp.Available, exp.Incoming
			row.Outgoing, row.Total = exp.Outgoing, exp.Total
		}
		if locks, err := p.Coord.Locks(id); err == nil {
			for _, l := range locks {
				direction := "outgoing"
				if l.Incoming {
					direction = "incoming"
				}
				row.Locks = append(row.Locks, PendingLock{
					ID:        hex.EncodeToString(l.ID[:]),
					Direction: direction,
					Amount:    l.Amount,
					Status:    string(l.Status),
					Expiry:    l.Expiry,
					ExpiresIn: l.ExpiresIn,
				})
			}
		}
		if p.Payout != nil {
			if st, err := p.Payout.Status(id); err == nil {
				row.Mode = string(st.Mode)
				row.Phase = string(st.Phase)
				row.TxHash = st.TxHash
				row.DueAt = st.DueAt
				row.Attempts = st.Attempts
				row.LastError = st.LastError
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// SetPolicy records when the recipient wants value on chain.
//
// The mode strings are the dashboard's, validated here rather than trusted:
// a radio button is not an authorisation, and this is the boundary where a
// form value becomes a decision about money.
func (p *PaymentNode) SetPolicy(_ context.Context, id, mode string, intervalSeconds int64) error {
	if p.Payout == nil {
		return errors.New("receiving: no settlement worker")
	}
	parsed, err := parseChannelID(id)
	if err != nil {
		return err
	}

	policy := channel.PayoutPolicy{}
	switch channel.PayoutMode(mode) {
	case channel.PayoutOnClose:
		policy.Mode = channel.PayoutOnClose
	case channel.PayoutOnInterval:
		if intervalSeconds <= 0 {
			return errors.New("receiving: an interval policy needs a positive interval")
		}
		policy.Mode = channel.PayoutOnInterval
		policy.IntervalSeconds = intervalSeconds
	default:
		return fmt.Errorf("receiving: unknown settlement mode %q", mode)
	}
	return p.Payout.SetPolicy(parsed, policy)
}

// SettleNow advances a channel's settlement one step.
//
// Returns the OUTCOME as well as any error, because "not due yet" and "the RPC
// is unreachable" are both non-completions and an operator needs to tell them
// apart.
func (p *PaymentNode) SettleNow(ctx context.Context, id string) (string, error) {
	if p.Payout == nil {
		return "", errors.New("receiving: no settlement worker")
	}
	parsed, err := parseChannelID(id)
	if err != nil {
		return "", err
	}
	outcome, err := p.Payout.Settle(ctx, parsed)
	return string(outcome), err
}

// Close asks for the money now, whatever the schedule says.
func (p *PaymentNode) Close(ctx context.Context, id string) (string, error) {
	if p.Payout == nil {
		return "", errors.New("receiving: no settlement worker")
	}
	parsed, err := parseChannelID(id)
	if err != nil {
		return "", err
	}
	if err := p.Payout.RequestClose(parsed); err != nil {
		return "", err
	}
	outcome, err := p.Payout.Settle(ctx, parsed)
	return string(outcome), err
}

func parseChannelID(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return out, fmt.Errorf("receiving: channel id must be 32 hex bytes")
	}
	copy(out[:], raw)
	return out, nil
}

var _ Receiving = (*PaymentNode)(nil)

// ---- mailbox collection (P15) ------------------------------------------------
//
// The node is the state machine. These three methods do the looking, the
// verifying-and-signing and the publishing; the console only renders what they
// return and passes back which tip the recipient clicked.

// Collector is the mailbox side of a recipient's node. Separate from the
// payment fields above because a node can receive tips directly without ever
// using a volunteer, and one that does should say "not configured" rather than
// "nothing waiting".
type Collector struct {
	Discovery *channel.MailboxDiscovery
	Endpoint  string
	NodeID    string
}

// SetCollector attaches the mailbox. Without one the collection methods report
// that this node is not configured to collect — which is a different statement
// from an empty mailbox, and the console says so.
func (p *PaymentNode) SetCollector(c *Collector) { p.Collect = c }

var errNoCollector = errors.New(
	"this node is not configured to collect from a mailbox: set channels.volunteer")

func (p *PaymentNode) collector() (*Collector, error) {
	if p.Collect == nil || p.Collect.Discovery == nil || p.Collect.Endpoint == "" {
		return nil, errNoCollector
	}
	return p.Collect, nil
}

// WaitingTips reads the volunteer without consuming anything.
func (p *PaymentNode) WaitingTips(ctx context.Context) ([]WaitingTip, error) {
	c, err := p.collector()
	if err != nil {
		return nil, err
	}
	frames, err := c.Discovery.Waiting(ctx, c.Endpoint, c.NodeID)
	if err != nil {
		// Passed up, not swallowed. The caller must be able to tell "I could not
		// look" from "I looked and it was empty".
		return nil, err
	}
	out := []WaitingTip{}
	for _, env := range frames {
		tip, ok := p.describe(env)
		if ok {
			out = append(out, tip)
		}
	}
	return out, nil
}

// describe turns a frame into something a person can read, or drops it.
//
// A frame carrying BOTH signatures is an already-accepted state being cached
// for the contributor, not something to accept again — offering it would ask
// the recipient to agree to what they already agreed to.
func (p *PaymentNode) describe(env channel.Envelope) (WaitingTip, bool) {
	sum, ok := channel.DescribeFrame(env)
	if !ok || sum.CoSigned {
		return WaitingTip{}, false
	}
	tip := WaitingTip{
		Channel: sum.Channel,
		Nonce:   sum.Nonce,
		State:   TipWaiting,
		Amount:  formatANON(sum.Amount),
	}
	// The contributor comes from the CHAIN, through the coordinator's own
	// tracked record. NEVER from the frame: the volunteer wrote that, and a
	// volunteer that could name the parties could name itself.
	if p.Coord != nil {
		if id, err := parseChannelID(sum.Channel); err == nil {
			if ch, ok := p.Coord.Channel(id); ok {
				me := p.Coord.Self()
				other := ch.PartyA
				if ch.PartyA == me {
					other = ch.PartyB
				}
				tip.From = other.Hex()
			}
			// ALREADY ACCEPTED?
			//
			// A volunteer's queue is a cache, and nothing removes the original
			// proposal from it when the recipient accepts — peek does not
			// consume, and the contributor may still be collecting the
			// co-signed reply. So the frame stays there afterwards, and a
			// console that took the queue at face value would keep offering an
			// accepted tip as though it were still waiting.
			//
			// THE NODE'S OWN STORED STATE decides. If it holds a state at this
			// update number or later, this proposal is history.
			if bal, err := p.Coord.Balances(id); err == nil && bal.Nonce >= sum.Nonce {
				tip.State = TipAccepted
			}
		}
	}
	return tip, true
}

// AcceptTip runs one waiting proposal through the node's ordinary acceptance
// path — the same one a directly-connected contributor reaches over SCPP/1.
//
// Nothing about the state is rebuilt here. The frame the contributor signed is
// handed to the coordinator verbatim, because a state re-encoded on the way
// would have a different digest and the signature would then cover something
// else.
func (p *PaymentNode) AcceptTip(ctx context.Context, id string, nonce uint64) (string, error) {
	c, err := p.collector()
	if err != nil {
		return "", err
	}
	if p.Coord == nil {
		return "", errors.New("receiving: no payment coordinator")
	}
	env, err := p.waitingFrame(ctx, c, id, nonce)
	if err != nil {
		return TipUnreachable, err
	}

	// Adopt, chain-derived parties, contributor signature, transition, I4,
	// countersign, Store.Accept — all of it inside the coordinator, where it
	// already is and already tested.
	reply, err := p.Coord.Handle(ctx, env)
	if err != nil {
		return TipUnreachable, err
	}
	if reply == nil {
		return TipRefused, errors.New("the node had nothing to say about that tip")
	}
	if reply.Type == channel.MsgStateReject {
		code := channel.RejectionCode(*reply)
		if code == "conflicting_states" {
			// I4. Two different states at one update number means somebody
			// signed twice; nothing here can know which is real.
			return TipConflict, fmt.Errorf("two conflicting tips arrived for update %d", nonce)
		}
		return TipRefused, fmt.Errorf("the node declined this tip (%s)", code)
	}
	if reply.Type == channel.MsgStateResponse {
		// The node answered a stale proposal with its OWN current state — that
		// is the protocol resyncing a peer, and it means this tip has already
		// been superseded by a later one. Reported as its own outcome because
		// "your node already has a newer state" and "your node declined this
		// tip" call for completely different reactions, and the raw message
		// type means nothing to the person reading it.
		return TipSuperseded, errors.New(
			"your node already holds a newer state for this channel, so this " +
				"tip has already been included")
	}
	if reply.Type != channel.MsgStateAccept {
		return TipRefused, fmt.Errorf("unexpected answer %q", reply.Type)
	}
	return TipAccepted, nil
}

// PublishTip makes an accepted state findable by the contributor.
//
// Its failure is reported as TipUnpublished, never as a failed acceptance: the
// value is already committed and asking the recipient to accept again would
// discard a completed acceptance to fix a cache miss.
func (p *PaymentNode) PublishTip(ctx context.Context, id string, nonce uint64) (string, error) {
	c, err := p.collector()
	if err != nil {
		return "", err
	}
	if p.Coord == nil {
		return "", errors.New("receiving: no payment coordinator")
	}
	parsed, err := parseChannelID(id)
	if err != nil {
		return "", err
	}
	// Asked for through the node's ordinary state-request path, so what gets
	// published is the stored co-signed state itself rather than something
	// reassembled here. Reassembly would change the digest and the signatures
	// on it would then cover a different state.
	req, err := channel.StateRequestEnvelope(parsed)
	if err != nil {
		return TipUnpublished, err
	}
	reply, err := p.Coord.Handle(ctx, req)
	if err != nil {
		return TipUnpublished, err
	}
	if reply == nil || reply.Type != channel.MsgStateResponse {
		return TipUnpublished, errors.New("the node has no stored state for that channel")
	}
	if err := c.Discovery.PublishAccepted(ctx, c.Endpoint, c.NodeID, id, *reply); err != nil {
		return TipUnpublished, err
	}
	return TipPublished, nil
}

// waitingFrame finds the frame the recipient clicked, by channel AND update
// number.
//
// Both, because a volunteer may hold several states for one channel and the
// recipient agreed to a particular one. Matching on the channel alone would
// accept whichever the volunteer happened to list first.
func (p *PaymentNode) waitingFrame(ctx context.Context, c *Collector,
	id string, nonce uint64) (channel.Envelope, error) {

	frames, err := c.Discovery.Waiting(ctx, c.Endpoint, c.NodeID)
	if err != nil {
		return channel.Envelope{}, err
	}
	for _, env := range frames {
		sum, ok := channel.DescribeFrame(env)
		if ok && sum.Channel == id && sum.Nonce == nonce {
			return env, nil
		}
	}
	return channel.Envelope{}, errors.New("that tip is no longer waiting at your mailbox")
}

// formatANON renders wei as ANON for a person to read.
//
// Exact, by integer division and a padded remainder. A float here would round
// somebody's tip: 1e18 wei does not survive float64 intact, and a display that
// is off in the last place invites an argument about a number that is actually
// correct. Trailing zeroes are trimmed so "5" reads as 5 rather than
// 5.000000000000000000.
func formatANON(wei *big.Int) string {
	if wei == nil {
		return "0"
	}
	unit := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	whole, frac := new(big.Int).QuoRem(wei, unit, new(big.Int))
	if frac.Sign() == 0 {
		return whole.String()
	}
	digits := strings.TrimRight(fmt.Sprintf("%018s", frac.String()), "0")
	return whole.String() + "." + digits
}
