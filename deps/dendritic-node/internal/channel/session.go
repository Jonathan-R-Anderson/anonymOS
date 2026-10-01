package channel

// The SCPP/1 protocol engine — doc/channel-payment-protocol.md §6, §7, §8.
//
// This is the layer that moves states between two participants and survives a
// crash at any point while doing it. It transports and sequences; it does not
// decide whether a state is legal. That is Channel.Accept's job and it is not
// reimplemented here.
//
// THE ORDERING THAT MAKES CRASHES SURVIVABLE
// ------------------------------------------
// Invariant I5: persist before transmitting. Both sides.
//
//	payer:  build → check I4 → sign → PERSIST pending → send
//	payee:  validate → check I4 → sign → PERSIST complete state → send
//
// Reversed, either side can put a signature on the wire that it has no record
// of making. The peer can then prove a state the signer cannot, and there is no
// recovery from that except their goodwill.
//
// The payee reaches a complete state one round trip before the payer does.
// That gap is where most of the crash table lives and it is unavoidable —
// somebody has to be second. What makes it safe is that the payer can always
// recover the completed state by asking (§7), and can recognise its own
// signature on a state it does not remember making, because signatures recover
// to an address rather than being looked up.
//
// WHAT THIS LAYER OWNS THAT THE STATE MACHINE DOES NOT
// ----------------------------------------------------
// A clock. Channel.Accept is pure and deliberately does not know the time, so
// "has this lock expired" and "is this expiry far enough out to be worth
// accepting" are answered here, where a clock and a skew tolerance exist.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var (
	ErrConflicted     = errors.New("scpp: channel stopped after a same-nonce conflict")
	ErrNoPending      = errors.New("scpp: no pending proposal")
	ErrIntentMismatch = errors.New("scpp: reply does not match the pending proposal")
	ErrAlreadySigned  = errors.New("scpp: already signed a different state at that nonce")
)

// signFor is the ONE place this node's key is applied to a digest.
//
// Both signing paths go through it — proposing and accepting — because the
// quarantine it enforces has to cover both. A restored node that refused to
// propose but happily countersigned would double-sign just as thoroughly, and
// from the side where the counterparty chose the nonce.
//
// See reconcile.go: after a backup restore a channel may be stale in a way
// nothing local can detect, and signing against a rolled-back nonce produces
// two different states at one nonce with the counterparty holding both.
func (s *PeerSession) signFor(ch *Channel, raw [32]byte) ([]byte, error) {
	if ch.NeedsReconcile {
		return nil, fmt.Errorf("%w (channel %x)", ErrNeedsReconcile, ch.ID[:4])
	}
	return s.sign(raw)
}

// StateSigner produces this party's 65-byte signature over a raw digest, applying
// EIP-191 exactly as RecoverSigner expects. In production this is a wallet; in
// tests it is a key.
type StateSigner func(raw [32]byte) ([]byte, error)

// Committer is the only way this layer reaches persisted state.
//
// Deliberately two methods and no more. PeerSession decodes, sequences and
// signs; it does not decide what a channel is, does not read the chain, and
// cannot reach past this interface to a map. In production the Coordinator
// implements it and adds the checks that make a channel real — see roadmap
// invariant P5-2, one component turns a message into money.
//
// *Store satisfies it too, which is what keeps the protocol tests able to run
// without a coordinator or a chain.
type Committer interface {
	// Channel returns a snapshot. A copy, never the live record.
	Channel(id [32]byte) (*Channel, bool)
	// Commit applies a change atomically, or applies none of it.
	Commit(id [32]byte, mutate func(*Channel) error) error
}

// Channel makes *Store a Committer.
func (s *Store) Channel(id [32]byte) (*Channel, bool) { return s.Get(id) }

// Commit makes *Store a Committer.
func (s *Store) Commit(id [32]byte, mutate func(*Channel) error) error {
	return s.Update(id, mutate)
}

// PeerSession drives the protocol for one node.
type PeerSession struct {
	store Committer
	self  Address
	sign  StateSigner

	// now and skew are the clock this layer owns. Injectable because a test
	// that cannot control time cannot test an expiry.
	now  func() int64
	skew int64

	// minLockWindow is how long a proposed lock must have left before this node
	// will accept it. A lock expiring in four seconds is structurally valid and
	// worthless — see §4.2 check 11 and §9.
	minLockWindow int64

	// vault remembers preimages this node learns. Optional for a leaf that
	// never forwards; REQUIRED for a hub, because a forwarded payment's only
	// route to being made whole upstream is the secret it learned downstream.
	vault *PreimageVault
}

// SetPreimageVault gives this session somewhere durable to remember secrets.
//
// Without one a node still pays and gets paid; it just cannot safely FORWARD,
// because forwarding means being owed upstream on a secret learned downstream.
func (s *PeerSession) SetPreimageVault(v *PreimageVault) { s.vault = v }

// NewPeerSession builds an engine. self must be a party to every channel it is used
// with, and sign must produce that party's signatures.
func NewPeerSession(store Committer, self Address, sign StateSigner) *PeerSession {
	return &PeerSession{
		store: store, self: self, sign: sign,
		now:           func() int64 { return time.Now().Unix() },
		skew:          30,
		minLockWindow: 600,
	}
}

// SetClock replaces the clock and tolerances. For tests and for operators who
// know their own network.
func (s *PeerSession) SetClock(now func() int64, skew, minLockWindow int64) {
	s.now, s.skew, s.minLockWindow = now, skew, minLockWindow
}

// ---- payer side ------------------------------------------------------------

// Propose builds, signs and records a payment, returning the message to send.
//
// Nothing is transmitted here — the caller sends it — because the persist must
// happen first and a function that both writes and sends cannot guarantee the
// order to its caller.
//
// Calling Propose twice with the same intent against an unchanged channel
// returns byte-identical messages (§5), which is what makes a retry a retry
// rather than a second payment.
func (s *PeerSession) Propose(id [32]byte, intent [32]byte, tr StateTransition) (Envelope, error) {
	ch, ok := s.store.Channel(id)
	if !ok {
		return Envelope{}, ErrNoSuchChannel
	}
	if ch.Conflict != nil {
		return Envelope{}, ErrConflicted
	}

	// A retry of an intent this node already has outstanding re-sends exactly
	// what it sent before. Rebuilding would produce the same bytes anyway; using
	// the stored copy means it is the same even if the channel moved under us,
	// in which case the peer's rejection is what tells us so.
	if p := ch.Pending; p != nil && p.Intent == intent {
		return s.proposalEnvelope(ch, p)
	}
	if p := ch.Pending; p != nil {
		return Envelope{}, fmt.Errorf("scpp: a different proposal is already pending at nonce %d",
			p.State.Nonce)
	}

	next, err := tr.Apply(ch, s.self)
	if err != nil {
		return Envelope{}, err
	}

	// The timing rules apply to what this node SIGNS, not only to what it
	// accepts. checkTiming used to run on the inbound path alone, so a node
	// would sign and send a transition its own rules forbid — and signing is
	// where the damage is done, because I4 then records that signature at that
	// nonce forever.
	//
	// The cost is not the wasted round trip. A doomed proposal POISONS THE
	// NONCE: the peer's later, legitimate transition at the same nonce is
	// refused with ALREADY_SIGNED_NONCE, and the channel can make no further
	// cooperative progress. An expired lock whose payee first tried a late
	// settlement became unrefundable off-chain — recoverable only by closing on
	// chain, which is safe but is not the cooperative path anyone wanted.
	//
	// Checking here costs one comparison and keeps a node from signing its own
	// channel into a corner.
	// SETTLEMENT ONLY, and deliberately so.
	//
	// A lock's expiry is a FACT both parties read from the same state, so a node
	// can apply the settle rule to itself and get the same answer the peer will.
	// The other two timing rules are not like that:
	//
	//	minLockWindow (LOCK_ADD)  the ACCEPTOR's policy — "I will not hold a lock
	//	                          shorter than X". A proposer cannot know it, and
	//	                          applying it locally would refuse proposals the
	//	                          peer would have taken.
	//	LOCK_REFUND               objective too, but its wire-level rejection is
	//	                          existing documented behaviour with a test that
	//	                          pins it. Changing that belongs to whoever
	//	                          revisits it, not to this fix.
	if tr.Kind == KindLockSettle {
		if code, detail := s.checkTiming(ch, tr, next); code != "" {
			return Envelope{}, fmt.Errorf("scpp: refusing to sign: %s: %s", code, detail)
		}
	}

	// I4, before signing anything.
	if digest, signed := ch.HasSigned(next.Nonce); signed {
		if digest != next.Digest(ch.ChainID, ch.Contract) {
			return Envelope{}, ErrAlreadySigned
		}
	}

	raw := next.Digest(ch.ChainID, ch.Contract)
	sig, err := s.signFor(ch, raw)
	if err != nil {
		return Envelope{}, err
	}

	pending := &PendingProposal{Intent: intent, Transition: tr, State: next, Sig: sig}

	// Persisted BEFORE the caller can send it (I5).
	if err := s.store.Commit(id, func(c *Channel) error {
		c.Pending = pending
		c.NoteSigned(next.Nonce, raw)
		// Recorded as INITIATED, not as anything better: this node has signed
		// its half and knows nothing about the other. History follows the
		// engine rather than anticipating it.
		c.NotePayment(recordFor(intent, tr, false, PayInitiated, nowOr(s.now)))
		return nil
	}); err != nil {
		return Envelope{}, err
	}
	return s.proposalEnvelope(ch, pending)
}

func (s *PeerSession) proposalEnvelope(ch *Channel, p *PendingProposal) (Envelope, error) {
	return newEnvelope(MsgStatePropose, ch.ID, StateProposeBody{
		Intent:     hex.EncodeToString(p.Intent[:]),
		Transition: encodeTransitionWire(p.Transition),
		State:      encodeStateWire(p.State),
		Sig:        hex.EncodeToString(p.Sig),
	})
}

// HandleAccept completes a payment with the payee's counter-signature.
func (s *PeerSession) HandleAccept(env Envelope) error {
	id, err := parseBytes32(env.Channel)
	if err != nil {
		return err
	}
	var body StateAcceptBody
	if err := env.Body_(&body); err != nil {
		return err
	}
	ch, ok := s.store.Channel(id)
	if !ok {
		return ErrNoSuchChannel
	}
	p := ch.Pending
	if p == nil {
		// Not an error worth panicking over: the payment may have completed
		// through a resync already. Idempotent by design.
		if _, applied := ch.AppliedAt(intentOf(body.Intent)); applied {
			return nil
		}
		return ErrNoPending
	}
	if hex.EncodeToString(p.Intent[:]) != body.Intent {
		return ErrIntentMismatch
	}

	theirs, err := parseSig(body.Sig)
	if err != nil {
		return err
	}
	complete := assemble(ch, p.State, p.Sig, s.self, theirs)

	return s.store.Commit(id, func(c *Channel) error {
		if err := c.Accept(complete); err != nil {
			return err
		}
		c.NoteApplied(p.Intent, p.State.Nonce)
		c.Pending = nil
		c.NotePayment(outcomeRecord(p.Intent, p.Transition, false, p.State.Nonce, nowOr(s.now)))
		return nil
	})
}

// HandleReject drops a pending proposal.
//
// A rejection changes no state — that is what makes it safe to send — so this
// only clears the pending record. The intent is dead; reusing it with different
// contents is what §5 forbids.
func (s *PeerSession) HandleReject(env Envelope) (RejectCode, error) {
	id, err := parseBytes32(env.Channel)
	if err != nil {
		return "", err
	}
	var body StateRejectBody
	if err := env.Body_(&body); err != nil {
		return "", err
	}
	err = s.store.Commit(id, func(c *Channel) error {
		if c.Pending != nil && hex.EncodeToString(c.Pending.Intent[:]) == body.Intent {
			rec := recordFor(c.Pending.Intent, c.Pending.Transition, false, PayRejected, nowOr(s.now))
			rec.ResolvedAt, rec.Detail = nowOr(s.now), string(body.Code)
			c.NotePayment(rec)
			// The signed-nonce record deliberately SURVIVES. This node signed
			// that state; forgetting it would let it sign a different one at the
			// same nonce later, which is exactly what I4 forbids.
			c.Pending = nil
		}
		return nil
	})
	return body.Code, err
}

// ---- payee side ------------------------------------------------------------

// HandlePropose runs the whole of §4 and answers with STATE_ACCEPT or
// STATE_REJECT. It returns a message in both cases: a refusal the payer never
// receives is a payer that retries forever.
func (s *PeerSession) HandlePropose(env Envelope) (Envelope, error) {
	id, err := parseBytes32(env.Channel)
	if err != nil {
		return Envelope{}, err
	}
	var body StateProposeBody
	if err := env.Body_(&body); err != nil {
		return Envelope{}, err
	}
	intent := intentOf(body.Intent)

	ch, ok := s.store.Channel(id)
	if !ok {
		return s.reject(id, body.Intent, RejectUnknownChannel, "no such channel")
	}
	if ch.Conflict != nil {
		return s.reject(id, body.Intent, RejectConflicted, "channel stopped after a conflict")
	}
	if ch.Status != StatusOpen {
		return s.reject(id, body.Intent, RejectClosing, "channel is not open")
	}

	// §5 idempotence: an intent already applied is answered with the same
	// counter-signature, not applied a second time.
	if nonce, applied := ch.AppliedAt(intent); applied {
		if ch.Latest.State.Nonce == nonce {
			return s.acceptEnvelope(ch, body.Intent, nonce)
		}
		// The channel has moved on. Tell them where it is; they will adopt it
		// and see their payment already reflected.
		return s.stateResponse(ch)
	}

	proposed, err := decodeStateWire(body.State)
	if err != nil {
		return s.reject(id, body.Intent, RejectLocksMalformed, err.Error())
	}
	tr, err := decodeTransitionWire(body.Transition)
	if err != nil {
		return s.reject(id, body.Intent, RejectLocksMalformed, err.Error())
	}
	theirSig, err := parseSig(body.Sig)
	if err != nil {
		return s.reject(id, body.Intent, RejectBadSignature, err.Error())
	}

	// Who proposed it: the party that is not us.
	proposer := ch.PartyA
	if proposer == s.self {
		proposer = ch.PartyB
	}

	// Check 7: the state must be exactly what the stated transition produces.
	// This is also what enforces check 8, since Apply only ever takes from the
	// proposer.
	if err := tr.Matches(ch, proposer, proposed); err != nil {
		return s.reject(id, body.Intent, RejectTransitionMismatch, err.Error())
	}

	// Checks 10 and 11: the ones that need a clock, which the state machine
	// deliberately does not have.
	if code, detail := s.checkTiming(ch, tr, proposed); code != "" {
		return s.reject(id, body.Intent, code, detail)
	}

	// THE SECRET GOES TO DISK BEFORE THIS NODE SIGNS ANYTHING AWAY.
	//
	// Signing a LOCK_SETTLE is paying out downstream. If the preimage were only
	// remembered after — or in the same write that could fail halfway — a crash
	// here would leave this node having paid and unable to claim upstream, which
	// nothing later can repair. Preimage first, deliberately: a secret stored
	// for a lock that never settles costs nothing.
	if tr.Kind == KindLockSettle && s.vault != nil {
		if err := s.vault.Learn(tr.Preimage); err != nil {
			return Envelope{}, fmt.Errorf("scpp: refusing to settle a lock this node cannot remember the secret for: %w", err)
		}
	}

	// I4 before signing.
	raw := proposed.Digest(ch.ChainID, ch.Contract)
	if digest, signed := ch.HasSigned(proposed.Nonce); signed && digest != raw {
		return s.reject(id, body.Intent, RejectAlreadySignedNonce,
			"already signed a different state at that nonce")
	}

	mySig, err := s.signFor(ch, raw)
	if err != nil {
		return Envelope{}, err
	}
	complete := assemble(ch, proposed, theirSig, proposer, mySig)

	// Persist the COMPLETE state before the signature leaves (I5). Accept runs
	// the §4.1 checks; a failure here is a refusal, mapped to its code.
	if err := s.store.Commit(id, func(c *Channel) error {
		if err := c.Accept(complete); err != nil {
			return err
		}
		c.NoteApplied(intent, proposed.Nonce)
		c.NoteSigned(proposed.Nonce, raw)
		// From this side the value came inward, so the record is the mirror of
		// the payer's.
		c.NotePayment(outcomeRecord(intent, tr, true, proposed.Nonce, nowOr(s.now)))
		return nil
	}); err != nil {
		return s.reject(id, body.Intent, codeFor(err), err.Error())
	}

	fresh, _ := s.store.Channel(id)
	return s.acceptEnvelope(fresh, body.Intent, proposed.Nonce)
}

// checkTiming is §4.2 checks 10 and 11 — everything that needs to know what
// time it is.
func (s *PeerSession) checkTiming(ch *Channel, tr StateTransition, proposed State) (RejectCode, string) {
	switch tr.Kind {
	case KindLockAdd:
		if tr.Expiry < s.now()+s.minLockWindow {
			return RejectLocksMalformed, fmt.Sprintf(
				"lock expires in %ds; this node requires at least %ds",
				tr.Expiry-s.now(), s.minLockWindow)
		}
	case KindLockSettle:
		i := findLock(ch.Latest.State.Pending, tr.LockID)
		if i < 0 {
			return RejectTransitionMismatch, "no such lock"
		}
		// A PREIMAGE IS WORTHLESS AT OR AFTER EXPIRY, BECAUSE THE CONTRACT SAYS SO.
		//
		//	ChannelManagerV2.claimLock  : if (block.timestamp >= lock.expiry) revert LockHasExpired();
		//	ChannelManagerV2.expireLock : if (block.timestamp <  lock.expiry) revert LockNotExpired();
		//
		// So on chain the boundary is exact and the two paths never overlap. This
		// case was ABSENT, and its absence let the off-chain machine co-sign a
		// settlement the chain would have reverted — a signed state strictly more
		// generous to the payee than the contract's own rule.
		//
		// The loss it enables is the intermediary's, and it is the one routing.go
		// declares impossible. A hop holds an incoming lock expiring at E_in and
		// wrote an outgoing one at E_out = E_in - margin. Let the downstream settle
		// LATE, after E_out: the hop's node signs, pays downstream, learns the
		// preimage — and then cannot claim upstream, because on chain claimLock
		// reverts once E_in has passed and the upstream party may expireLock. The
		// margin was enforced at lock CREATION and nothing enforced it at
		// RESOLUTION, which is where the money actually moves.
		//
		// Skew works AGAINST the settler, mirroring the refund rule below: their
		// clock being slow must not let them claim a lock the payer is already
		// entitled to reclaim. The two rules together leave a 2*skew band in which
		// NEITHER side may act, which is deliberate — a window where both are valid
		// is a race over the same value.
		if ch.Latest.State.Pending[i].Expiry <= s.now()+s.skew {
			return RejectLockExpired, fmt.Sprintf(
				"lock expired %ds ago; it is refund-only", s.now()-ch.Latest.State.Pending[i].Expiry)
		}
	case KindLockRefund:
		i := findLock(ch.Latest.State.Pending, tr.LockID)
		if i < 0 {
			return RejectTransitionMismatch, "no such lock"
		}
		// Skew works AGAINST the refunder: their clock being fast must not let
		// them reclaim a lock the payee could still legitimately settle.
		if ch.Latest.State.Pending[i].Expiry > s.now()-s.skew {
			return RejectLockNotExpired, "the lock has not expired yet"
		}
	}
	return "", ""
}

func (s *PeerSession) acceptEnvelope(ch *Channel, intentHex string, nonce uint64) (Envelope, error) {
	sig := ch.Latest.SigA
	if !ch.IsA(s.self) {
		sig = ch.Latest.SigB
	}
	return newEnvelope(MsgStateAccept, ch.ID, StateAcceptBody{
		Intent: intentHex, Nonce: nonce, Sig: hex.EncodeToString(sig),
	})
}

func (s *PeerSession) reject(id [32]byte, intentHex string, code RejectCode, detail string) (Envelope, error) {
	return newEnvelope(MsgStateReject, id, StateRejectBody{
		Intent: intentHex, Code: code, Detail: detail,
	})
}

// codeFor maps a state-machine refusal to the closed set a payer can act on.
func codeFor(err error) RejectCode {
	switch {
	case errors.Is(err, ErrNonceRegressed):
		return RejectNonceStale
	case errors.Is(err, ErrNotConserved):
		return RejectNotConserved
	case errors.Is(err, ErrBadStateSignature), errors.Is(err, ErrHighS):
		return RejectBadSignature
	case errors.Is(err, ErrDuplicateHTLC), errors.Is(err, ErrHTLCExpiryPast), errors.Is(err, ErrNegative):
		return RejectLocksMalformed
	case errors.Is(err, ErrInsufficient):
		return RejectInsufficient
	case errors.Is(err, ErrPreimageBad):
		return RejectPreimageBad
	}
	return RejectTransitionMismatch
}

// ---- resynchronisation (§7) -------------------------------------------------

// RequestState asks a peer for its latest signed state.
func (s *PeerSession) RequestState(id [32]byte) (Envelope, error) {
	return newEnvelope(MsgStateRequest, id, StateRequestBody{})
}

// HandleRequest answers with this node's latest.
func (s *PeerSession) HandleRequest(env Envelope) (Envelope, error) {
	id, err := parseBytes32(env.Channel)
	if err != nil {
		return Envelope{}, err
	}
	ch, ok := s.store.Channel(id)
	if !ok {
		return Envelope{}, ErrNoSuchChannel
	}
	return s.stateResponse(ch)
}

func (s *PeerSession) stateResponse(ch *Channel) (Envelope, error) {
	body := StateResponseBody{}
	if ch.Latest.Complete() {
		body.Have = true
		body.State = encodeStateWire(ch.Latest.State)
		body.SigA = hex.EncodeToString(ch.Latest.SigA)
		body.SigB = hex.EncodeToString(ch.Latest.SigB)
	}
	return newEnvelope(MsgStateResponse, ch.ID, body)
}

// ResyncOutcome is what HandleResponse did.
type ResyncOutcome string

const (
	ResyncAdopted  ResyncOutcome = "ADOPTED"
	ResyncStale    ResyncOutcome = "PEER_IS_STALE"
	ResyncSame     ResyncOutcome = "IN_STEP"
	ResyncNone     ResyncOutcome = "PEER_HAS_NONE"
	ResyncConflict ResyncOutcome = "CONFLICT"
	ResyncRejected ResyncOutcome = "REJECTED"
)

// HandleResponse applies §7's three outcomes, and the fourth that is not a tie.
//
// Adoption happens ONLY on a strictly higher nonce that passes the complete
// §4.1 validation. Two signatures recovering correctly proves authorship, not
// legality, and a peer offering a higher-but-invalid state is either broken or
// probing.
func (s *PeerSession) HandleResponse(env Envelope) (ResyncOutcome, error) {
	id, err := parseBytes32(env.Channel)
	if err != nil {
		return "", err
	}
	var body StateResponseBody
	if err := env.Body_(&body); err != nil {
		return "", err
	}
	ch, ok := s.store.Channel(id)
	if !ok {
		return "", ErrNoSuchChannel
	}
	if !body.Have {
		return ResyncNone, nil
	}

	theirs, err := decodeSignedWire(body.State, body.SigA, body.SigB)
	if err != nil {
		return "", err
	}

	switch {
	case theirs.State.Nonce > ch.Latest.State.Nonce:
		// The whole §4.1 validation, inside Accept. Not just the signatures.
		if err := s.store.Commit(id, func(c *Channel) error {
			if err := c.Accept(theirs); err != nil {
				return err
			}
			// A pending proposal at or below the adopted nonce is answered:
			// either it completed and this IS it, or it lost to another state.
			if c.Pending != nil && c.Pending.State.Nonce <= theirs.State.Nonce {
				c.NoteApplied(c.Pending.Intent, c.Pending.State.Nonce)
				// THE POINT OF THE HISTORY PHASE: an unknown becomes what it
				// really was. The state this node just adopted is the evidence,
				// and it says the payment landed — so the record stops saying
				// nobody knows.
				c.NotePayment(outcomeRecord(c.Pending.Intent, c.Pending.Transition,
					false, c.Pending.State.Nonce, nowOr(s.now)))
				c.Pending = nil
			}
			return nil
		}); err != nil {
			return ResyncRejected, err
		}
		return ResyncAdopted, nil

	case theirs.State.Nonce < ch.Latest.State.Nonce:
		return ResyncStale, nil
	}

	// Same nonce. Identical is the ordinary result of a retry; different is a
	// conflict, and there is no rule that could pick correctly between them.
	if err := ch.Latest.State.Equal(theirs.State); err == nil {
		return ResyncSame, nil
	}
	mine := ch.Latest
	if err := s.store.Commit(id, func(c *Channel) error {
		c.Conflict = &ConflictRecord{Nonce: theirs.State.Nonce, Mine: mine, Theirs: theirs}
		c.Pending = nil
		return nil
	}); err != nil {
		return "", err
	}
	return ResyncConflict, nil
}

// ConflictMessage builds the evidence to send a peer after detecting a
// same-nonce conflict. Both states travel because together they are the proof;
// either alone is just a state.
func (s *PeerSession) ConflictMessage(id [32]byte) (Envelope, error) {
	ch, ok := s.store.Channel(id)
	if !ok {
		return Envelope{}, ErrNoSuchChannel
	}
	if ch.Conflict == nil {
		return Envelope{}, errors.New("scpp: no conflict recorded on that channel")
	}
	c := ch.Conflict
	return newEnvelope(MsgConflict, id, ConflictBody{
		Nonce:  c.Nonce,
		Mine:   encodeStateWire(c.Mine.State),
		MineA:  hex.EncodeToString(c.Mine.SigA),
		MineB:  hex.EncodeToString(c.Mine.SigB),
		Yours:  encodeStateWire(c.Theirs.State),
		YoursA: hex.EncodeToString(c.Theirs.SigA),
		YoursB: hex.EncodeToString(c.Theirs.SigB),
	})
}

// HandleConflict stops this channel on a peer's evidence.
//
// The evidence is CHECKED, not taken on trust: two states at one nonce, both
// different, both carrying signatures that recover to this channel's parties. A
// peer cannot stop a channel by asserting a conflict, only by demonstrating one
// — otherwise "claim a conflict" becomes a denial of service against any
// channel a stranger knows the id of.
//
// Note whose position it takes: the peer's "mine" is this node's "theirs". The
// labels are relative to the sender.
func (s *PeerSession) HandleConflict(env Envelope) (bool, error) {
	id, err := parseBytes32(env.Channel)
	if err != nil {
		return false, err
	}
	var body ConflictBody
	if err := env.Body_(&body); err != nil {
		return false, err
	}
	theirs, err := decodeSignedWire(body.Mine, body.MineA, body.MineB)
	if err != nil {
		return false, err
	}
	ours, err := decodeSignedWire(body.Yours, body.YoursA, body.YoursB)
	if err != nil {
		return false, err
	}
	if theirs.State.Nonce != ours.State.Nonce {
		return false, errors.New("scpp: the two states are not at one nonce; not a conflict")
	}
	if err := theirs.State.Equal(ours.State); err == nil {
		return false, errors.New("scpp: the two states are identical; not a conflict")
	}

	ch, ok := s.store.Channel(id)
	if !ok {
		return false, ErrNoSuchChannel
	}
	if ch.Conflict != nil {
		return true, nil // already stopped
	}
	for _, ss := range []SignedState{theirs, ours} {
		if err := s.verifyBothParties(ch, ss); err != nil {
			return false, err
		}
	}

	if err := s.store.Commit(id, func(c *Channel) error {
		c.Conflict = &ConflictRecord{Nonce: theirs.State.Nonce, Mine: ours, Theirs: theirs}
		c.Pending = nil
		return nil
	}); err != nil {
		return false, err
	}
	return true, nil
}

// verifyBothParties checks that a state really was signed by this channel's two
// parties. Used where a state arrives as evidence rather than as a proposal, so
// Channel.Accept's nonce rule would reject it before its signatures were ever
// looked at.
func (s *PeerSession) verifyBothParties(ch *Channel, ss SignedState) error {
	if !ss.Complete() {
		return ErrBadStateSignature
	}
	raw := ss.State.Digest(ch.ChainID, ch.Contract)
	a, err := RecoverSigner(raw, ss.SigA)
	if err != nil {
		return err
	}
	b, err := RecoverSigner(raw, ss.SigB)
	if err != nil {
		return err
	}
	if a != ch.PartyA || b != ch.PartyB {
		return fmt.Errorf("%w: evidence not signed by both parties", ErrBadStateSignature)
	}
	return nil
}

// ---- restart (§8) -----------------------------------------------------------

// Resume decides what to do about a channel after a restart.
//
// A pending proposal means this node signed something and does not know whether
// the peer completed it. It cannot simply retry into the void and it must not
// abandon it: the peer may hold a fully signed state. So it asks — which is
// safe, because adoption only ever moves forward.
func (s *PeerSession) Resume(id [32]byte) (Envelope, bool, error) {
	ch, ok := s.store.Channel(id)
	if !ok {
		return Envelope{}, false, ErrNoSuchChannel
	}
	if ch.Conflict != nil {
		return Envelope{}, false, ErrConflicted
	}
	if ch.Pending == nil {
		return Envelope{}, false, nil
	}
	env, err := s.RequestState(id)
	return env, true, err
}

// ---- helpers ---------------------------------------------------------------

// assemble places two signatures into the A/B slots by ADDRESS, never by role.
//
// Named for who signed rather than for "mine" and "theirs" on purpose: which
// slot a signature belongs in is decided by whether that signer is the lower
// address, and a parameter called "mine" invites the reader to assume it is
// always A.
func assemble(ch *Channel, state State, sig []byte, signer Address, otherSig []byte) SignedState {
	out := SignedState{State: state}
	if ch.IsA(signer) {
		out.SigA, out.SigB = sig, otherSig
	} else {
		out.SigA, out.SigB = otherSig, sig
	}
	return out
}

func intentOf(s string) [32]byte {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err == nil && len(raw) == 32 {
		copy(out[:], raw)
	}
	return out
}
