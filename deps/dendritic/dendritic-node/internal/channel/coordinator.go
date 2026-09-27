package channel

// The payment coordinator — roadmap invariant P5-2.
//
// ONE COMPONENT TURNS A MESSAGE INTO MONEY
// ----------------------------------------
//	SCPP frame ─┐
//	            ├─▶ COORDINATOR ─▶ state machine ─▶ store
//	HTTP call ──┘
//
// Both entry points arrive here and nowhere else. That matters less for the two
// that exist today than for the five that will: HTTP, SCPP/1, HTLC routing, the
// settlement worker and the browser all end up touching the same channels, and
// a second path that commits state is a second set of payment semantics nobody
// meant to write.
//
// WHAT IT OWNS
// ------------
// Channel lookup, confirming a channel is real on chain, obtaining the
// authoritative deposit, intent idempotency, driving PeerSession, choosing
// direct versus routed, and returning a definitive result.
//
// WHAT IT MUST NOT DO
// -------------------
// Implement cryptographic validation. That is Channel.Accept's, and a second
// implementation of a money rule is two rules that will disagree eventually.
// Touch persisted maps. That is the store's.
//
// So this file contains no signature checking, no conservation arithmetic and
// no map writes. It decides WHICH operation is being asked for; the layers below
// decide whether it is legal and record it.
//
// WHY IT IS ALSO THE Committer
// ----------------------------
// PeerSession reaches persistence through the Committer interface. In production
// the coordinator is that interface, so a protocol message cannot reach the
// store without passing the check that the channel was established from a chain
// read. Handing PeerSession the store directly is legal — the protocol tests do
// it — but then nothing is enforcing where the collateral came from.

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

var (
	ErrChannelNotAdopted = errors.New("coordinator: channel is not tracked; adopt it from the chain first")
	ErrNotAParticipant   = errors.New("coordinator: this node is not a party to that channel")
)

// Coordinator is the single entry point for money-bearing operations.
type Coordinator struct {
	store    *Store
	chain    ChainReader
	chainID  *big.Int
	contract Address
	self     Address

	sess *PeerSession

	// metrics is optional and aggregate-only. Nil is a working collector, so no
	// call site below needs a guard.
	metrics *Metrics

	// vault answers "does this node hold the secret for that lock", which is
	// what separates a claimable payment from one still in flight. Optional.
	vault *PreimageVault
	// now is the coordinator's clock, for expiry reasoning.
	now func() int64

	// adopting serialises chain reads per channel so two concurrent messages
	// about an unknown channel do not both go and fetch it.
	adopting sync.Mutex
}

// NewCoordinator wires the stack. The PeerSession it builds commits through the
// coordinator, not through the store, so every protocol-driven write passes the
// adoption check.
func NewCoordinator(store *Store, chain ChainReader, chainID *big.Int,
	contract, self Address, sign StateSigner) *Coordinator {

	c := &Coordinator{
		store: store, chain: chain,
		chainID:  new(big.Int).Set(orZero(chainID)),
		contract: contract, self: self,
	}
	c.sess = NewPeerSession(c, self, sign)
	return c
}

// Session exposes the protocol engine for clock configuration. It is not a way
// to bypass the coordinator: the session commits through it either way.
func (c *Coordinator) Session() *PeerSession { return c.sess }

// SetMetrics attaches an aggregate collector.
//
// A setter rather than a constructor argument, deliberately: instrumentation
// must never be something a caller has to supply to get a working payment path,
// and nil is a working collector.
func (c *Coordinator) SetMetrics(m *Metrics) { c.metrics = m }

// ---- Committer, for PeerSession --------------------------------------------

// Channel returns a tracked channel snapshot.
func (c *Coordinator) Channel(id [32]byte) (*Channel, bool) { return c.store.Get(id) }

// Commit is the ONE path that writes a money-bearing change.
//
// Everything else in this system proposes, transports or observes. When a
// second caller for this appears, it is worth asking what makes it different
// rather than adding it.
func (c *Coordinator) Commit(id [32]byte, mutate func(*Channel) error) error {
	return c.store.Update(id, mutate)
}

// ---- adoption ---------------------------------------------------------------

// Adopt makes a channel known to this node, using the chain as the authority.
//
// A peer may name a channel. It may not describe one. Everything that decides
// what the channel IS — the parties, and above all the deposits every later
// conservation check is measured against — comes from ChannelManagerV2.
//
// Idempotent: adopting an already-tracked channel is a no-op, because a peer
// re-announcing is ordinary and re-reading the chain for it is not free.
func (c *Coordinator) Adopt(ctx context.Context, id [32]byte) error {
	if _, ok := c.store.Get(id); ok {
		return nil
	}

	c.adopting.Lock()
	defer c.adopting.Unlock()
	// Re-check under the lock: another message about the same channel may have
	// adopted it while this one waited.
	if _, ok := c.store.Get(id); ok {
		return nil
	}

	occ, err := c.chain.ReadChannel(ctx, c.contract, id)
	if err != nil {
		return err
	}
	// A channel this node is not part of is not this node's business, and
	// tracking one would let a stranger fill the store with channels.
	if occ.PartyA != c.self && occ.PartyB != c.self {
		return ErrNotAParticipant
	}
	if err := c.store.TrackFromChain(c.chainID, c.contract, occ); err != nil {
		if errors.Is(err, ErrChannelExists) {
			return nil
		}
		return err
	}
	return nil
}

// Refresh re-reads a tracked channel's collateral and status from the chain.
//
// Call after anything that could have changed the collateral — a checkpoint, a
// further deposit, a settlement. Cheap to call when nothing moved, and the
// alternative is a node that quietly refuses every payment after a checkpoint
// because it is measuring conservation against collateral that no longer
// exists.
func (c *Coordinator) Refresh(ctx context.Context, id [32]byte) error {
	if _, ok := c.store.Get(id); !ok {
		return ErrChannelNotAdopted
	}
	occ, err := c.chain.ReadChannel(ctx, c.contract, id)
	if err != nil {
		return err
	}
	return c.store.RefreshFromChain(occ)
}

// AdoptAnnounced handles a peer's CHANNEL_ANNOUNCE.
//
// Note what is taken from the message: the channel id, and nothing else. The
// body also carries parties and deposits — they are read past deliberately, and
// the chain is asked instead. A peer's figures are a claim; the contract's are
// the fact.
func (c *Coordinator) AdoptAnnounced(ctx context.Context, env Envelope) error {
	id, err := parseBytes32(env.Channel)
	if err != nil {
		return err
	}
	return c.Adopt(ctx, id)
}

// ---- the payment result -----------------------------------------------------

// PaymentResult is the definitive answer to "did this payment happen".
type PaymentResult struct {
	// Done is true only when a fully signed state is persisted here.
	Done bool
	// Nonce carries the payment, when Done.
	Nonce uint64
	// Route says how it went. Direct today; routed once P6 lands.
	Route string
	// Rejected is set when the peer refused, with the reason it gave.
	Rejected RejectCode
	// Detail is the peer's explanation, for a human. Never parsed.
	Detail string
}

// Retryable reports whether this payment is worth attempting again later.
func (r PaymentResult) Retryable() bool { return r.Rejected != "" && r.Rejected.Retryable() }

// ---- outgoing payments -------------------------------------------------------

// Peer is however a message reaches the other node. Supplied by P5's transport;
// this layer only needs request/response.
type Peer interface {
	Exchange(ctx context.Context, out Envelope) (Envelope, error)
}

// Pay runs a payment to completion and returns a definitive result.
//
// Direct or routed is decided here — the choice belongs to the coordinator, not
// to the protocol engine, because it depends on what channels exist rather than
// on what a state says. Today there is one answer; P6 adds the other, and it
// changes nothing below this function.
func (c *Coordinator) Pay(ctx context.Context, id [32]byte, intent [32]byte,
	tr StateTransition, peer Peer) (PaymentResult, error) {

	if err := c.Adopt(ctx, id); err != nil {
		return PaymentResult{}, err
	}
	ch, ok := c.store.Get(id)
	if !ok {
		return PaymentResult{}, ErrChannelNotAdopted
	}
	if ch.Conflict != nil {
		return PaymentResult{}, ErrConflicted
	}

	// Already applied: answer from the record rather than paying again. The
	// protocol is idempotent underneath as well, but a caller asking twice
	// deserves the same answer without a round trip.
	//
	// NOT COUNTED. This is a retry of something already recorded, and counting
	// it would inflate both attempts and completions every time a caller asked
	// twice — which is the ordinary case after an ambiguous outcome.
	if nonce, applied := ch.AppliedAt(intent); applied {
		return PaymentResult{Done: true, Nonce: nonce, Route: "direct"}, nil
	}

	// One attempt, counted once, at the point past which a payment is genuinely
	// being tried. `tr` is in scope and carries an amount; nothing here needs the
	// channel id, the intent or either party, so none is available to pass.
	c.metrics.TipAttempted()

	propose, err := c.sess.Propose(id, intent, tr)
	if err != nil {
		// Refused by THIS node, before the peer was asked — a non-conserving
		// amount, a lock past its expiry, a nonce already signed. Still a
		// terminal outcome of the attempt counted above, and omitting it left
		// attempted > completed + failed with nothing to show where the
		// difference went.
		c.metrics.TipFailed()
		return PaymentResult{}, err
	}

	reply, err := peer.Exchange(ctx, propose)
	if err != nil {
		// The message may or may not have arrived. Resolving that is resync's
		// job, not a guess made here — see Recover.
		//
		// Recorded as UNKNOWN rather than failed, and deliberately not as a
		// terminal state: the record is expected to change once Recover
		// establishes what actually happened.
		_ = c.store.Update(id, func(ch *Channel) error {
			rec := recordFor(intent, tr, false, PayUnknown, c.clock())
			rec.Detail = err.Error()
			ch.NotePayment(rec)
			return nil
		})
		c.metrics.TipFailed()
		return PaymentResult{}, err
	}

	switch reply.Type {
	case MsgStateAccept:
		if err := c.sess.HandleAccept(reply); err != nil {
			return PaymentResult{}, err
		}
		fresh, _ := c.store.Get(id)
		// The AMOUNT and the KIND, nothing else. Which channel carried it and who
		// the parties are stay here; the collector could not accept them anyway.
		c.recordCompletion(tr)
		return PaymentResult{Done: true, Nonce: fresh.Latest.State.Nonce, Route: "direct"}, nil

	case MsgStateReject:
		code, err := c.sess.HandleReject(reply)
		if err != nil {
			return PaymentResult{}, err
		}
		var body StateRejectBody
		_ = reply.Body_(&body)
		// A refusal is a failure. The REASON is not recorded: reject codes are a
		// small enum today, but a code plus a timestamp narrows which payment
		// failed, and the aggregate question ("how many fail") does not need it.
		c.metrics.TipFailed()
		return PaymentResult{Rejected: code, Detail: body.Detail}, nil

	case MsgStateResponse:
		// The peer answered a proposal with its latest state, which is what it
		// does when the intent already landed and the channel moved on.
		if _, err := c.sess.HandleResponse(reply); err != nil {
			return PaymentResult{}, err
		}
		fresh, _ := c.store.Get(id)
		if nonce, applied := fresh.AppliedAt(intent); applied {
			return PaymentResult{Done: true, Nonce: nonce, Route: "direct"}, nil
		}
		return PaymentResult{}, nil

	default:
		return PaymentResult{}, fmt.Errorf("coordinator: unexpected reply %s", reply.Type)
	}
}

// recordCompletion turns an applied transition into aggregate counters.
//
// The transition is already in hand at the call site, so this needs nothing
// fetched and nothing looked up — which matters, because a lookup is where an
// identifier would have to be handled in order to be discarded, and the rule is
// that identifiers never reach this layer at all.
func (c *Coordinator) recordCompletion(tr StateTransition) {
	switch tr.Kind {
	case KindPay:
		c.metrics.TipCompleted(tr.Amount)
	case KindLockAdd:
		// Counted on APPLICATION, not on attempt. A lock the peer refused was
		// never created, and counting it at the attempt made a 3-leg split with
		// one dead counterparty report three HTLCs where two exist.
		//
		// No value moves yet either — a lock is out of the payer's balance and
		// into neither party's, so it becomes a tip only when it settles.
		c.metrics.HTLCCreated()
	case KindLockSettle:
		c.metrics.HTLCSettled()
	case KindLockRefund:
		c.metrics.HTLCRefunded()
	case KindCheckpoint, KindClose:
		// Value leaving the channel, not a tip.
	}
}

// ---- incoming messages -------------------------------------------------------

// Handle processes one inbound SCPP/1 message and returns the reply, if any.
//
// The single door for the protocol. A transport reads a frame and hands it
// here; it never reaches into the session or the store itself.
func (c *Coordinator) Handle(ctx context.Context, env Envelope) (*Envelope, error) {
	switch env.Type {
	case MsgChannelAnnounce:
		return nil, c.AdoptAnnounced(ctx, env)

	case MsgStatePropose:
		// Adopt first: a proposal about a channel we have not seen is normal
		// when the peer opened it, and the chain settles whether it is real.
		id, err := parseBytes32(env.Channel)
		if err != nil {
			return nil, err
		}
		if err := c.Adopt(ctx, id); err != nil {
			return nil, err
		}
		reply, err := c.sess.HandlePropose(env)
		if err != nil {
			return nil, err
		}
		return &reply, nil

	case MsgStateRequest:
		// Adopt first, for the same reason MsgStatePropose does: a question
		// about a channel we have not seen is NORMAL when the peer opened it,
		// and under D3 the peer is exactly who opens it. A recipient's node
		// hears about most of its channels this way — a tipper funds one and
		// then asks what state it is in.
		//
		// Refusing here would have made the first tip on every new channel
		// impossible: the tipper cannot learn the opening state, and the node
		// cannot tell it, though the chain has the answer all along.
		//
		// Adoption reads the CHAIN, so this cannot be used to invent a channel;
		// an id that is not really there fails against the chain, which is
		// precisely invariant P5-1 doing its job.
		id, err := parseBytes32(env.Channel)
		if err != nil {
			return nil, err
		}
		if err := c.Adopt(ctx, id); err != nil {
			return nil, err
		}
		reply, err := c.sess.HandleRequest(env)
		if err != nil {
			return nil, err
		}
		return &reply, nil

	case MsgStateResponse:
		if _, err := c.sess.HandleResponse(env); err != nil {
			return nil, err
		}
		return nil, nil

	case MsgStateAccept:
		return nil, c.sess.HandleAccept(env)

	case MsgStateReject:
		_, err := c.sess.HandleReject(env)
		return nil, err

	case MsgConflict:
		_, err := c.sess.HandleConflict(env)
		return nil, err

	case MsgHello, MsgClosing, MsgError:
		// Informational. Nothing money-bearing, so nothing to commit.
		return nil, nil
	}
	return nil, fmt.Errorf("coordinator: unhandled message %s", env.Type)
}

// ---- recovery ----------------------------------------------------------------

// Recover resolves a channel left mid-payment by a crash or a dropped
// connection, by asking the peer (§7) rather than guessing locally.
//
// Safe to call at any time. Adoption only ever moves forward: a strictly higher
// nonce that passes the complete validation, or nothing.
func (c *Coordinator) Recover(ctx context.Context, id [32]byte, peer Peer) (ResyncOutcome, error) {
	request, resync, err := c.sess.Resume(id)
	if err != nil {
		return "", err
	}
	if !resync {
		return ResyncSame, nil
	}
	reply, err := peer.Exchange(ctx, request)
	if err != nil {
		return "", err
	}
	if reply.Type != MsgStateResponse {
		return "", fmt.Errorf("coordinator: peer answered a state request with %s", reply.Type)
	}
	return c.sess.HandleResponse(reply)
}

// RecoverAll resolves every tracked channel. What a node does on startup.
func (c *Coordinator) RecoverAll(ctx context.Context, peer Peer) map[[32]byte]ResyncOutcome {
	out := map[[32]byte]ResyncOutcome{}
	for _, id := range c.store.IDs() {
		outcome, err := c.Recover(ctx, id, peer)
		if err != nil {
			// One unreachable peer must not stop the rest from recovering.
			out[id] = ResyncOutcome("ERROR: " + err.Error())
			continue
		}
		out[id] = outcome
	}
	return out
}

// ---- observation --------------------------------------------------------------

// Balances is what a caller may safely be told about a channel. Read-only, and
// derived from the persisted state rather than recomputed.
type Balances struct {
	ChannelID [32]byte
	// PartyA and PartyB are the channel's two parties, as the CHAIN recorded
	// them — TrackFromChain wrote them from ChannelManagerV2 and nothing else
	// may set them.
	//
	// Reported so the operator's own browser can verify signatures on a state
	// it was handed by a volunteer. It cannot learn the parties any other way:
	// a channel id is keccak(sorted(a,b)) and does not run backwards, and
	// taking them from the volunteer would make the verification circular —
	// the thing being checked would be supplying the answer.
	//
	// This is an INPUT to verification, never a substitute for it. The browser
	// still recomputes the digest and recovers both signatures itself.
	PartyA     Address
	PartyB     Address
	Mine       *big.Int
	Theirs     *big.Int
	Locked     *big.Int
	Nonce      uint64
	Conflicted bool
}

// Balances reports a channel's position. The HTTP layer's read path, so that it
// never needs the store.
func (c *Coordinator) Balances(id [32]byte) (Balances, error) {
	ch, ok := c.store.Get(id)
	if !ok {
		return Balances{}, ErrChannelNotAdopted
	}
	other := ch.PartyA
	if other == c.self {
		other = ch.PartyB
	}
	return Balances{
		ChannelID: id,
		// Straight from the tracked channel, which TrackFromChain filled from
		// ChannelManagerV2. Never derived from Mine/Theirs, which are amounts.
		PartyA:     ch.PartyA,
		PartyB:     ch.PartyB,
		Mine:       ch.BalanceOf(c.self),
		Theirs:     ch.BalanceOf(other),
		Locked:     ch.Latest.State.lockedTotal(),
		Nonce:      ch.Latest.State.Nonce,
		Conflicted: ch.Conflict != nil,
	}, nil
}

// Channels lists what this node tracks.
func (c *Coordinator) Channels() [][32]byte { return c.store.IDs() }

// ---- opening a channel ---------------------------------------------------------

// Allowance reads how much the token lets a spender move on someone's behalf.
//
// Needed because funding a channel is TWO transactions and this is what makes
// the pair recoverable: a node that died between them cannot know whether the
// approval landed, but it can ask — the same rule as everywhere else here.
type Allowance interface {
	Allowance(ctx context.Context, token, owner, spender Address) (*big.Int, error)
}

// OpenResult is what an attempt to open a channel produced.
type OpenResult struct {
	// ChannelID is the channel this would create. Deterministic from the two
	// addresses, so it is known BEFORE anything is sent.
	ChannelID [32]byte
	// ApprovalTx is set when an approval had to be sent first.
	ApprovalTx string
	// OpenTx is the openChannel broadcast.
	OpenTx string
	// AlreadyOpen is true when the chain already had this channel, in which
	// case nothing was sent and the channel was simply adopted.
	AlreadyOpen bool
}

// OpenChannel funds a channel with a partner.
//
// THE TIPPER SENDS THIS. Roadmap D3 puts channel funding on the tipper, and the
// deposit rides along in the same transaction — so a recipient spends no gas to
// be tipped, and "open a receiving channel" on their dashboard is an invitation
// rather than a transaction.
//
// Two transactions, and it says so: `openChannel` calls `safeTransferFrom`, and
// ERC-20 moves nothing without an allowance. The approval goes to the TOKEN, the
// open goes to ChannelManagerV2.
//
//	allowance? ──insufficient──▶ approve(token) ──▶ openChannel(manager)
//	     └──sufficient──────────────────────────────▶ openChannel(manager)
//
// Crash-safe by asking rather than remembering: the channel id is derivable
// before anything is sent, so a node that died mid-sequence re-reads the chain,
// finds the channel already there, and adopts it instead of opening a second
// one. There is no second one to open — `openChannel` reverts on a channel that
// exists.
func (c *Coordinator) OpenChannel(ctx context.Context, writer ChainWriter, allow Allowance,
	token Address, partner Address, deposit *big.Int) (OpenResult, error) {

	if partner == c.self {
		return OpenResult{}, errors.New("coordinator: cannot open a channel with yourself")
	}
	if deposit == nil || deposit.Sign() < 0 {
		return OpenResult{}, ErrAmountNotPositive
	}
	out := OpenResult{ChannelID: DeriveChannelID(c.self, partner)}

	// Ask the chain first, exactly as settlement does. A channel that already
	// exists is adopted, not opened again — and this is also the recovery path
	// for a node that crashed after broadcasting.
	if _, err := c.chain.ReadChannel(ctx, c.contract, out.ChannelID); err == nil {
		out.AlreadyOpen = true
		return out, c.Adopt(ctx, out.ChannelID)
	} else if !errors.Is(err, ErrChannelNotOnChain) {
		return out, err
	}

	// The approval is skipped when one already covers this, so a retry after a
	// crash does not spend gas re-approving.
	if deposit.Sign() > 0 && allow != nil {
		current, err := allow.Allowance(ctx, token, c.self, c.contract)
		if err != nil {
			return out, err
		}
		if current.Cmp(deposit) < 0 {
			tx, err := writer.Approve(ctx, token, c.contract, deposit)
			if err != nil {
				return out, fmt.Errorf("coordinator: approval failed: %w", err)
			}
			out.ApprovalTx = tx
		}
	}

	tx, err := writer.OpenChannel(ctx, c.contract, partner, deposit)
	if err != nil {
		return out, err
	}
	out.OpenTx = tx

	// NOT adopted here. A broadcast is not a channel — the same rule the
	// settlement worker follows. The caller adopts once the chain shows it,
	// which Adopt does by reading rather than believing.
	return out, nil
}

// Deposit tops up a channel that already exists.
func (c *Coordinator) Deposit(ctx context.Context, writer ChainWriter, allow Allowance,
	token Address, id [32]byte, amount *big.Int) (string, error) {

	if amount == nil || amount.Sign() <= 0 {
		return "", ErrAmountNotPositive
	}
	if _, ok := c.store.Get(id); !ok {
		return "", ErrChannelNotAdopted
	}
	if allow != nil {
		current, err := allow.Allowance(ctx, token, c.self, c.contract)
		if err != nil {
			return "", err
		}
		if current.Cmp(amount) < 0 {
			if _, err := writer.Approve(ctx, token, c.contract, amount); err != nil {
				return "", fmt.Errorf("coordinator: approval failed: %w", err)
			}
		}
	}
	return writer.Deposit(ctx, c.contract, id, amount)
}
