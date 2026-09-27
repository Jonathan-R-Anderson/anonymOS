package channel

// What a console may know about a mailbox frame — roadmap P15.5.
//
// The recipient's console has to show what is waiting before the recipient
// agrees to it, which means something outside this package needs to read a
// frame. This file is the whole of what it is allowed to learn, and it is
// deliberately narrow: enough to render a sentence a person can consent to,
// and not enough to assemble a payment.
//
// It lives here rather than in the UI because decoding a frame means knowing
// the wire types, and the moment a view imports those it stops being a view.
// Everything below is READ-ONLY: nothing here signs, stores or accepts.

import (
	"encoding/json"
	"math/big"
)

// TipSummary is one waiting proposal, as far as a console needs it.
type TipSummary struct {
	// Channel and Nonce identify WHICH state. Both travel because a volunteer
	// may hold several states for one channel, and the recipient agrees to a
	// particular one.
	Channel string
	Nonce   uint64
	// Amount is what this transition moves, in wei.
	Amount *big.Int
	// CoSigned is true when both parties already signed. Such a frame is an
	// ACCEPTED state being cached for the contributor, not something for the
	// recipient to accept again.
	CoSigned bool
}

// DescribeFrame reads a proposal frame, or reports that it is not one.
//
// Returns false rather than an error for anything it does not recognise: a
// volunteer is allowed to hold frames this node has no opinion about, and that
// is not a fault to report to the recipient.
func DescribeFrame(env Envelope) (TipSummary, bool) {
	if env.Type != MsgStatePropose || len(env.Body) == 0 {
		return TipSummary{}, false
	}
	// Decoded into the real wire type, so a frame that would not parse for the
	// acceptance path does not parse here either. A console that could display
	// something the coordinator will later reject would be inviting the
	// recipient to consent to a tip that cannot exist.
	var body StateProposeBody
	if err := json.Unmarshal(env.Body, &body); err != nil {
		return TipSummary{}, false
	}
	if body.State.Channel == "" {
		return TipSummary{}, false
	}
	amount, ok := new(big.Int).SetString(body.Transition.Amount, 10)
	if !ok {
		amount = new(big.Int)
	}
	// A proposal carries ONE signature — the contributor's. Both means it has
	// already been accepted.
	var both struct {
		SigA string `json:"sig_a"`
		SigB string `json:"sig_b"`
	}
	_ = json.Unmarshal(env.Body, &both)

	return TipSummary{
		Channel:  body.State.Channel,
		Nonce:    body.State.Nonce,
		Amount:   amount,
		CoSigned: both.SigA != "" && both.SigB != "",
	}, true
}

// RejectionCode reads why a node declined, for wording that says which problem
// it was. Empty when the frame is not a rejection.
func RejectionCode(env Envelope) string {
	if env.Type != MsgStateReject || len(env.Body) == 0 {
		return ""
	}
	var body StateRejectBody
	if err := json.Unmarshal(env.Body, &body); err != nil {
		return ""
	}
	return string(body.Code)
}

// StateRequestEnvelope asks a node for its own latest co-signed state.
//
// Used to fetch what to publish after an acceptance, rather than rebuilding it:
// a state re-encoded on the way out would have a different digest, and the
// signatures already on it would then cover something else.
func StateRequestEnvelope(id [32]byte) (Envelope, error) {
	return newEnvelope(MsgStateRequest, id, StateRequestBody{})
}

// Self is the address this coordinator signs as.
//
// Exposed so a console can say which side of a channel its operator is on. It
// is an address, not a key: nothing about it lets a caller sign.
func (c *Coordinator) Self() Address { return c.self }
