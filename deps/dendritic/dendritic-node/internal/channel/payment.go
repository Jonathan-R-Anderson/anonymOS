package channel

// Composing a private payment out of the pieces.
//
// WHY THIS EXISTS SEPARATELY
// --------------------------
// Route selection, locks, the onion and the invoice were each built and tested
// alone. Alone is not the hard part: the ordering between them is. The locks
// must be built before the onion because each hop's instruction carries its own
// commitment; the route must be chosen before the locks because the lock count
// depends on the hop count; and the invoice must be validated before any of it,
// because an expired invoice discovered after three hops of work is three hops
// wasted and a lock chain to unwind.
//
// So the ordering lives here once, rather than in every caller.
//
// PLAN, THEN SEND
// ---------------
// Plan() does everything that can fail cheaply and locally: validating the
// invoice, drawing a diverse route, checking the amount, building locks and
// sealing the onion. It touches no network and moves no money.
//
// That split is deliberate. Every reason a private payment cannot be made —
// no diverse operators, expired invoice, amount out of range — is knowable
// BEFORE anything is committed, and a caller that learns them one hop at a time
// leaks its intent to each hop it asks.

import (
	"encoding/hex"
	"errors"
	"time"
)

var ErrNoPrivacy = errors.New("channel: cannot make this payment privately")

// Plan is a fully-formed private payment, ready to send.
type Plan struct {
	Amount Amount
	Route  []Candidate
	Locks  *LockChain
	Packet *Packet
	// Secret is the recipient's z. Held by the PAYER only until the recipient
	// releases it — carried here because a caller must be able to verify the
	// settlement it receives, not because it should be transmitted.
	Secret  []byte
	Invoice *BlindedInvoice
}

// HopSharedSecret derives the secret a hop uses to peel its own instruction.
//
// Exported and named so the binding can be asserted directly, and so callers
// stop open-coding the derivation — five sites did, and a change to the inputs
// silently broke none of them because they all repeated the same wrong thing.
//
// A PLACEHOLDER, and it says so: production replaces this with ECDH between the
// packet's ephemeral key and the router's own key. What must survive that
// substitution is the binding — per payment (via ephemeral), per hop (via the
// node id), and not derivable by an observer (via the seed).
func HopSharedSecret(seed, ephemeral [32]byte, node NodeID) [32]byte {
	return derive("syndichan/payment/hopsecret/v2", seed[:], ephemeral[:], []byte(node))
}

// PlanRequest is what a caller supplies.
type PlanRequest struct {
	Invoice    *BlindedInvoice
	Amount     Amount
	Candidates []Candidate
	Routing    RouteRequest
	// Curve MUST be the settlement chain's. Defaulting is deliberately not done
	// here: a payment planned on the wrong curve produces locks no contract can
	// settle, and a silent default is how that reaches mainnet.
	Curve Curve
	Seed  [32]byte
	Now   time.Time
}

// Plan assembles a private payment without sending anything.
//
// Fails fast and in a fixed order: cheapest checks first, so a caller learns
// "this invoice expired" without having drawn a route, and "no diverse route"
// without having built locks.
func PlanPayment(req PlanRequest) (*Plan, error) {
	if req.Curve == nil {
		return nil, errors.New("channel: no curve supplied — the settlement chain's curve is required")
	}
	if req.Invoice == nil {
		return nil, ErrInvoiceMalformed
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}

	// 1. The invoice, because it is free to check and invalidates everything.
	if err := req.Invoice.Validate(now); err != nil {
		return nil, err
	}
	if err := req.Invoice.AcceptsAmount(req.Amount); err != nil {
		return nil, err
	}

	// 2. The route. Refuses on insufficient operator diversity, and that
	// refusal is passed through unchanged — a caller must be able to tell it
	// from an ordinary failure and say so to the user.
	route, err := SelectRoute(req.Candidates, req.Routing, req.Seed)
	if err != nil {
		return nil, err
	}

	// 3. Locks, sized to the route.
	z, Z, err := NewSecret(req.Curve)
	if err != nil {
		return nil, err
	}
	locks, err := BuildLocks(req.Curve, Z, len(route))
	if err != nil {
		return nil, err
	}

	// 4. Hop instructions, expiries strictly decreasing outward. Built here
	// rather than by the caller because BuildLocks and Build must agree on the
	// hop count and the ordering, and two callers doing it independently would
	// eventually disagree.
	base := uint64(now.Add(10 * time.Minute).Unix())
	hops := make([]HopInstruction, len(route))
	for i := range route {
		hop := HopInstruction{
			// Commit to this hop's lock POINT, so the instruction a router
			// receives is bound to the lock it must satisfy. Derived from both
			// coordinates: X alone has two valid Y values, and committing to
			// half a point commits to two of them.
			OutgoingCommitment: Commitment(derive("syndichan/payment/hopcommit/v1",
				locks.Locks[i].X.Bytes(), locks.Locks[i].Y.Bytes())),
			OutgoingExpiry: base - uint64(i*60),
		}
		if i+1 < len(route) {
			hop.NextHop = route[i+1].NodeID
		} else {
			// HEX, not string(rawBytes). Raw bytes placed in a Go string and
			// then JSON-encoded are interpreted as UTF-8: any invalid sequence
			// becomes U+FFFD, silently corrupting the endpoint so the exit
			// delivers to nowhere. The bug survives every test that does not
			// round-trip through JSON, which is why it appeared only once the
			// modules were composed.
			hop.BlindedEndpoint = hex.EncodeToString(req.Invoice.BlindedEndpoint[:])
		}
		hops[i] = hop
	}

	// 5. Per-hop shared secrets. Supplied by ECDH with each router's key in a
	// real deployment; derived here from the seed, the EPHEMERAL KEY and the
	// node id so the plan is reproducible in tests and the curve choice stays
	// out of the packet.
	//
	// THE EPHEMERAL KEY IS LOAD-BEARING, NOT DECORATION.
	//
	// This used to be derive(seed, nodeID) — no ephemeral, so the shared secret
	// was a pure function of the payer's seed and the hop's identity. A payer
	// that reused a seed therefore handed the same hop the SAME secret on two
	// different payments, and that hop could peel an onion it was never given:
	// correlating the two payments, and reading the second's routing
	// instruction. Verified by constructing two payments under one seed.
	//
	// That defeats precisely the property the ephemeral key exists to provide.
	// Packet says it plainly: "EphemeralPublicKey is fresh per payment. Reusing
	// one links every payment sent under it, which would undo the whole
	// construction in a single field." The key was fresh — and the secrets that
	// actually gate peeling ignored it, so freshness bought nothing.
	//
	// The ephemeral key is derived from z, drawn from crypto/rand per plan, so
	// it is per-payment even when the seed is not. Binding to it makes the shim
	// payment-bound and matches the shape of the ECDH that replaces it: in
	// production a router derives its secret from the ephemeral key in the
	// packet and its own key, which is per-payment for the same reason.
	//
	// The seed stays in the derivation so the secret is not computable by
	// somebody who merely observes the packet.
	ephemeral := derive("syndichan/payment/ephemeral/v1", req.Seed[:], z.Bytes())

	secrets := make([][32]byte, len(route))
	for i, c := range route {
		secrets[i] = HopSharedSecret(req.Seed, ephemeral, c.NodeID)
	}

	packet, err := Build(ephemeral, hops, secrets)
	if err != nil {
		return nil, err
	}
	packet.Expiry = base

	return &Plan{
		Amount: req.Amount, Route: route, Locks: locks,
		Packet: packet, Secret: z.Bytes(), Invoice: req.Invoice,
	}, nil
}

// Hops is the route length actually planned.
func (p *Plan) Hops() int {
	if p == nil {
		return 0
	}
	return len(p.Route)
}

// Operators lists the distinct operators this payment will cross. The number a
// user should be shown when told how private a payment is — three hops through
// two operators is not three-party privacy, and saying "3 hops" would imply it.
func (p *Plan) Operators() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range p.Route {
		if c.Operator != "" && !seen[c.Operator] {
			seen[c.Operator] = true
			out = append(out, c.Operator)
		}
	}
	return out
}
