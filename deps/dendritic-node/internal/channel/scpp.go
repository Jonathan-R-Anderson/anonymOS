package channel

// SCPP/1 wire format — doc/channel-payment-protocol.md §3.
//
// ONE ENCODER FOR DISK AND WIRE
// -----------------------------
// The state encoding here is store.go's storedState/storedHTLC, reused rather
// than reimplemented. The spec says the wire form matches the on-disk form
// exactly; sharing the types makes that true by construction instead of true
// until somebody edits one of them.
//
// The rules that matter, and why:
//
//   - Amounts are decimal STRINGS. A JSON number cannot carry 1e20 through
//     every parser that will read this, and 100 ANON is 1e20 wei. The same
//     hazard as computing wei in floating point.
//   - 32-byte values are lowercase hex with no 0x; addresses are lowercase hex
//     WITH 0x. Inconsistent, and deliberately so: it matches how each already
//     appears on disk, and a value that changes shape between layers is a value
//     somebody will re-encode wrongly.
//   - Locks arrive sorted by id with no duplicates, and a receiver REJECTS an
//     unsorted set rather than sorting it. One lock set must have exactly one
//     encoding, or two nodes compute two roots for the same locks.
//
// FRAMING
// -------
// A 4-byte big-endian length, then that many bytes of JSON. Frames over 1 MiB
// are refused before parsing: a channel state is small, and an unbounded read
// from a peer is a trivial denial of service.

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// MaxFrameBytes bounds one message. A state with even a hundred locks is a few
// kilobytes; anything approaching this is a peer doing something else.
const MaxFrameBytes = 1 << 20

// ProtocolVersion is SCPP/1. A receiver that does not implement the version it
// is sent replies ERROR and closes rather than guessing.
const ProtocolVersion = 1

var (
	ErrSCPPFrameTooLarge = errors.New("scpp: frame exceeds the maximum size")
	ErrBadVersion        = errors.New("scpp: unsupported protocol version")
	ErrMalformed         = errors.New("scpp: malformed message")
	ErrLocksUnsorted     = errors.New("scpp: locks are not in canonical id order")
	ErrWrongBodyType     = errors.New("scpp: message body does not match its type")
)

// MessageType is the wire discriminator. These strings are fixed by §3.3.
type MessageType string

const (
	MsgHello           MessageType = "HELLO"
	MsgChannelAnnounce MessageType = "CHANNEL_ANNOUNCE"
	MsgStatePropose    MessageType = "STATE_PROPOSE"
	MsgStateAccept     MessageType = "STATE_ACCEPT"
	MsgStateReject     MessageType = "STATE_REJECT"
	MsgStateRequest    MessageType = "STATE_REQUEST"
	MsgStateResponse   MessageType = "STATE_RESPONSE"
	MsgConflict        MessageType = "CONFLICT"
	MsgClosing         MessageType = "CLOSING"
	MsgError           MessageType = "ERROR"
)

// RejectCode is the closed set from §10. A payer distinguishes "try again
// later" from "never do that again" by this and nothing else, so the set is
// closed on purpose — a free-text reason would be read by a human and ignored
// by the retry logic.
type RejectCode string

const (
	RejectNonceStale         RejectCode = "NONCE_STALE"
	RejectAlreadySignedNonce RejectCode = "ALREADY_SIGNED_NONCE"
	RejectNotConserved       RejectCode = "NOT_CONSERVED"
	RejectBadSignature       RejectCode = "BAD_SIGNATURE"
	RejectLocksMalformed     RejectCode = "LOCKS_MALFORMED"
	RejectTransitionMismatch RejectCode = "TRANSITION_MISMATCH"
	RejectPreimageBad        RejectCode = "PREIMAGE_BAD"
	RejectLockNotExpired     RejectCode = "LOCK_NOT_EXPIRED"
	// RejectLockExpired is a settlement offered at or after the lock's expiry.
	// Deliberately NOT retryable: an expired lock never becomes settleable again,
	// so a retry can only waste both nodes' time. An older peer that does not know
	// this code falls through Retryable()'s default of false, which is the same
	// answer.
	RejectLockExpired        RejectCode = "LOCK_EXPIRED"
	RejectInsufficient       RejectCode = "INSUFFICIENT_CAPACITY"
	RejectConflicted         RejectCode = "CHANNEL_CONFLICTED"
	RejectClosing            RejectCode = "CHANNEL_CLOSING"
	RejectUnknownChannel     RejectCode = "UNKNOWN_CHANNEL"
)

// Retryable reports whether a payer may sensibly try this payment again. §10.
func (c RejectCode) Retryable() bool {
	switch c {
	case RejectNonceStale, RejectLockNotExpired, RejectInsufficient:
		return true
	}
	return false
}

// Envelope is every message. §3.2.
type Envelope struct {
	V       int             `json:"v"`
	Type    MessageType     `json:"type"`
	Channel string          `json:"channel,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
}

// ---- bodies ----------------------------------------------------------------

type HelloBody struct {
	Version int    `json:"version"`
	Address string `json:"address"`
}

type ChannelAnnounceBody struct {
	ID       string `json:"id"`
	PartyA   string `json:"party_a"`
	PartyB   string `json:"party_b"`
	DepositA string `json:"deposit_a"`
	DepositB string `json:"deposit_b"`
	ChainID  string `json:"chain_id"`
	Contract string `json:"contract"`
}

type wireTransition struct {
	Kind     TransitionKind `json:"kind"`
	Amount   string         `json:"amount,omitempty"`
	LockID   string         `json:"lock_id,omitempty"`
	Hash     string         `json:"hash,omitempty"`
	Expiry   int64          `json:"expiry,omitempty"`
	Preimage string         `json:"preimage,omitempty"`
}

type StateProposeBody struct {
	Intent     string         `json:"intent"`
	Transition wireTransition `json:"transition"`
	State      storedState    `json:"state"`
	Sig        string         `json:"sig"`
}

type StateAcceptBody struct {
	Intent string `json:"intent"`
	Nonce  uint64 `json:"nonce"`
	Sig    string `json:"sig"`
}

type StateRejectBody struct {
	Intent string     `json:"intent"`
	Code   RejectCode `json:"code"`
	Detail string     `json:"detail,omitempty"`
}

type StateRequestBody struct{}

// StateResponseBody carries a complete signed state, or Have=false when the
// channel has none yet. "None" is a real answer, not an error: a channel that
// was opened and never used is in exactly that position.
type StateResponseBody struct {
	Have  bool        `json:"have"`
	State storedState `json:"state,omitempty"`
	SigA  string      `json:"sig_a,omitempty"`
	SigB  string      `json:"sig_b,omitempty"`
}

// ConflictBody carries both states at the disputed nonce. Both are the
// evidence — together they prove a party signed twice at one nonce, which is
// why they travel rather than a complaint about them.
type ConflictBody struct {
	Nonce  uint64      `json:"nonce"`
	Mine   storedState `json:"mine"`
	MineA  string      `json:"mine_sig_a,omitempty"`
	MineB  string      `json:"mine_sig_b,omitempty"`
	Yours  storedState `json:"yours"`
	YoursA string      `json:"yours_sig_a,omitempty"`
	YoursB string      `json:"yours_sig_b,omitempty"`
}

type ClosingBody struct {
	Nonce uint64 `json:"nonce"`
}

type ErrorBody struct {
	Detail string `json:"detail"`
}

// ---- conversions ------------------------------------------------------------

func encodeStateWire(s State) storedState {
	out := storedState{
		Channel:  hex.EncodeToString(s.Channel[:]),
		Nonce:    s.Nonce,
		BalanceA: decString(s.BalanceA),
		BalanceB: decString(s.BalanceB),
	}
	// Withdrawals are inside the digest, so a state that arrives without them is
	// a DIFFERENT state carrying a signature that no longer covers it. Omitted
	// when zero — which is every ordinary payment — so records written before
	// checkpoints existed still encode byte for byte as they did.
	if s.Op != 0 && s.Op != OpState {
		out.Op = s.Op
	}
	if orZero(s.WithdrawA).Sign() > 0 {
		out.WithdrawA = decString(s.WithdrawA)
	}
	if orZero(s.WithdrawB).Sign() > 0 {
		out.WithdrawB = decString(s.WithdrawB)
	}
	for _, h := range s.Pending {
		out.Pending = append(out.Pending, storedHTLC{
			ID:       hex.EncodeToString(h.ID[:]),
			Hash:     hex.EncodeToString(h.Hash[:]),
			Amount:   decString(h.Amount),
			Expiry:   h.Expiry,
			PayerIsA: h.PayerIsA,
		})
	}
	return out
}

// decodeStateWire is strict about lock order. Sorting here would be friendlier
// and wrong: the contract requires the canonical order, so a peer that sends
// another one is a peer whose root will not match, and discovering that at
// settlement is far worse than discovering it now.
func decodeStateWire(w storedState) (State, error) {
	channel, err := parseBytes32(w.Channel)
	if err != nil {
		return State{}, err
	}
	balanceA, err := parseDec(w.BalanceA)
	if err != nil {
		return State{}, err
	}
	balanceB, err := parseDec(w.BalanceB)
	if err != nil {
		return State{}, err
	}
	// An absent withdrawal is zero, not an error: only a checkpoint state has
	// one, and every payment before the first checkpoint legitimately has none.
	// A NEGATIVE one is refused here rather than later — the contract's field is
	// uint256, so such a state could never settle, and the useful moment to say
	// so is before it is stored as though it could.
	withdrawA, err := parseUnsignedDec(w.WithdrawA, "withdraw_a")
	if err != nil {
		return State{}, err
	}
	withdrawB, err := parseUnsignedDec(w.WithdrawB, "withdraw_b")
	if err != nil {
		return State{}, err
	}
	// An absent domain is the ordinary one. A peer that names a domain is not
	// trusted on it: tr.Matches recomputes the state from the transition it
	// claimed and State.Equal compares the domain, so a lie is caught before
	// this node signs anything.
	op := w.Op
	if op == 0 {
		op = OpState
	}
	if op != OpState && op != OpCoopClose && op != OpCheckpoint {
		return State{}, fmt.Errorf("scpp: unknown operation domain %d", op)
	}
	out := State{
		Channel: channel, Nonce: w.Nonce,
		BalanceA: balanceA, BalanceB: balanceB,
		WithdrawA: withdrawA, WithdrawB: withdrawB,
		Op: op,
	}

	var previous [32]byte
	for i, h := range w.Pending {
		id, err := parseBytes32(h.ID)
		if err != nil {
			return State{}, err
		}
		if i > 0 && !lessID(previous, id) {
			return State{}, ErrLocksUnsorted
		}
		previous = id
		hash, err := parseBytes32(h.Hash)
		if err != nil {
			return State{}, err
		}
		amount, err := parseDec(h.Amount)
		if err != nil {
			return State{}, err
		}
		out.Pending = append(out.Pending, HTLC{
			ID: id, Hash: hash, Amount: amount,
			Expiry: h.Expiry, PayerIsA: h.PayerIsA,
		})
	}
	return out, nil
}

func encodeTransitionWire(t StateTransition) wireTransition {
	out := wireTransition{Kind: t.Kind, Expiry: t.Expiry}
	if t.Amount != nil && t.Amount.Sign() != 0 {
		out.Amount = t.Amount.String()
	}
	if t.LockID != ([32]byte{}) {
		out.LockID = hex.EncodeToString(t.LockID[:])
	}
	if t.Hash != ([32]byte{}) {
		out.Hash = hex.EncodeToString(t.Hash[:])
	}
	if t.Preimage != ([32]byte{}) {
		out.Preimage = hex.EncodeToString(t.Preimage[:])
	}
	return out
}

func decodeTransitionWire(w wireTransition) (StateTransition, error) {
	out := StateTransition{Kind: w.Kind, Expiry: w.Expiry}
	if w.Amount != "" {
		n, err := parseDec(w.Amount)
		if err != nil {
			return StateTransition{}, err
		}
		out.Amount = n
	} else {
		out.Amount = new(big.Int)
	}
	for _, f := range []struct {
		s   string
		dst *[32]byte
	}{{w.LockID, &out.LockID}, {w.Hash, &out.Hash}, {w.Preimage, &out.Preimage}} {
		if f.s == "" {
			continue
		}
		v, err := parseBytes32(f.s)
		if err != nil {
			return StateTransition{}, err
		}
		*f.dst = v
	}
	return out, nil
}

func parseSig(s string) ([]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 65 {
		return nil, fmt.Errorf("%w: signature must be 65 hex-encoded bytes", ErrMalformed)
	}
	return raw, nil
}

// ---- framing ----------------------------------------------------------------

// WriteFrame frames one message onto w.
func WriteFrame(w io.Writer, msg Envelope) error {
	if msg.V == 0 {
		msg.V = ProtocolVersion
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(raw) > MaxFrameBytes {
		return ErrSCPPFrameTooLarge
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

// ReadFrame reads one framed message.
//
// The length is checked BEFORE allocating, so an oversized frame costs four
// bytes rather than a gigabyte.
func ReadFrame(r io.Reader) (Envelope, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Envelope{}, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxFrameBytes {
		return Envelope{}, ErrSCPPFrameTooLarge
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(r, raw); err != nil {
		return Envelope{}, err
	}
	var msg Envelope
	if err := json.Unmarshal(raw, &msg); err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if msg.V != ProtocolVersion {
		return Envelope{}, fmt.Errorf("%w: %d", ErrBadVersion, msg.V)
	}
	return msg, nil
}

// Body decodes an envelope's body into dst.
func (e Envelope) Body_(dst any) error {
	if len(e.Body) == 0 {
		return fmt.Errorf("%w: %s has no body", ErrMalformed, e.Type)
	}
	if err := json.Unmarshal(e.Body, dst); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return nil
}

func newEnvelope(t MessageType, channel [32]byte, body any) (Envelope, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		V: ProtocolVersion, Type: t,
		Channel: hex.EncodeToString(channel[:]),
		Body:    raw,
	}, nil
}
