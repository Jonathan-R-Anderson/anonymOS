package facilitation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// Collecting attestations.
//
// A receipt with no witnesses is not a claim, it is a diary entry: the provider
// signing its own statement that it did some work. Settlement requires
// signatures from the specific nodes the protocol drew for that claim, which is
// what makes a receipt evidence rather than an assertion.
//
// So after answering a challenge, the provider works out who those nodes are —
// the same draw settlement will perform — and asks each of them. The witness
// does NOT take the provider's word for anything: it rebuilds the receipt from
// the challenge and the response, re-verifies the Merkle proof itself, and
// checks that it really was drawn before signing. A witness that signs on
// request is a witness whose signature means nothing.

// ChallengeIndexOf mirrors the aggregator's derivation exactly. It picks which
// draw within an epoch a claim belongs to, so two receipts from the same
// provider in the same epoch get different witness sets and one draw cannot be
// replayed onto another claim.
func ChallengeIndexOf(r ServiceReceipt) uint32 {
	h := keccak32(r.JobID[:], be64(r.Nonce))
	return uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
}

// Message kinds on the shared p2p protocol. One protocol id carries both
// conversations; a second would need every node to dial twice to do one job.
const (
	KindChallenge = "challenge"
	KindAttest    = "attest"
)

// Envelope wraps a facilitation message so one handler can serve both.
type Envelope struct {
	Kind string          `json:"kind"`
	Body json.RawMessage `json:"body"`
}

// AttestRequest is a provider asking a drawn witness to countersign.
//
// It carries the evidence, not a conclusion. The witness rebuilds the receipt
// from Challenge/Response/ProvenBytes rather than being handed one, because a
// provider that could name its own Quantity would be paid for work it did not
// do — and the signature it collects would be the network's own endorsement of
// that number.
type AttestRequest struct {
	Challenge   StorageChallenge `json:"challenge"`
	Response    StorageResponse  `json:"response"`
	ProvenBytes uint64           `json:"proven_bytes"`
	ProviderPub []byte           `json:"provider_pub"`
	ProviderSig []byte           `json:"provider_sig"`
}

// AttestResponse is the witness's signature over the receipt it rebuilt.
type AttestResponse struct {
	WitnessPub []byte `json:"witness_pub"`
	Sig        []byte `json:"sig"`
}

var (
	ErrNotDrawn      = errors.New("facilitation: this node was not drawn to witness that claim")
	ErrNoWitnessPool = errors.New("facilitation: the witness pool is unknown")
)

// EpochView is everything needed to reproduce a witness draw for one epoch.
type EpochView struct {
	Randomness [32]byte
	Candidates []Candidate
}

// EpochViews caches per-epoch witness pools.
//
// Cached because both sides of every attestation need it and it changes only
// when the epoch does; fetched rather than assumed because a node that guessed
// the pool would compute a draw nobody else agrees with.
type EpochViews struct {
	Gateway *GatewayClient
	mu      sync.Mutex
	byEpoch map[uint64]EpochView
}

func NewEpochViews(gateway *GatewayClient) *EpochViews {
	return &EpochViews{Gateway: gateway, byEpoch: map[uint64]EpochView{}}
}

func (v *EpochViews) For(ctx context.Context, epoch uint64) (EpochView, error) {
	v.mu.Lock()
	if view, ok := v.byEpoch[epoch]; ok {
		v.mu.Unlock()
		return view, nil
	}
	v.mu.Unlock()

	if v.Gateway == nil {
		return EpochView{}, ErrNoWitnessPool
	}
	randomness, err := v.Gateway.EpochRandomness(ctx, epoch)
	if err != nil {
		return EpochView{}, err
	}
	candidates, err := v.Gateway.FetchCandidates(ctx)
	if err != nil {
		return EpochView{}, err
	}
	view := EpochView{Randomness: randomness, Candidates: candidates}

	v.mu.Lock()
	if v.byEpoch == nil {
		v.byEpoch = map[uint64]EpochView{}
	}
	v.byEpoch[epoch] = view
	v.mu.Unlock()
	return view, nil
}

// WitnessesFor draws the witness set for a receipt.
func WitnessesFor(view EpochView, r ServiceReceipt) []Candidate {
	return SelectWitnesses(view.Randomness, r.ProviderNodeID, r.ServiceType,
		ChallengeIndexOf(r), ThresholdFor(r.ServiceType), view.Candidates)
}

// CollectAttestations is the provider side: ask every drawn witness to sign.
//
// Failures are counted, not fatal. A witness that is offline costs this receipt
// one signature, and the threshold exists precisely so that a few absent
// witnesses do not destroy a claim; abandoning the receipt would throw away
// proof of work that genuinely happened.
func CollectAttestations(ctx context.Context, sr *SignedReceipt, c StorageChallenge,
	resp StorageResponse, provenBytes uint64, view EpochView, send SendFunc) (int, error) {
	if send == nil {
		return 0, ErrNoTransport
	}
	drawn := WitnessesFor(view, sr.Receipt)
	if len(drawn) == 0 {
		return 0, ErrNoWitnessPool
	}
	request, err := json.Marshal(AttestRequest{
		Challenge:   c,
		Response:    resp,
		ProvenBytes: provenBytes,
		ProviderPub: sr.ProviderPub,
		ProviderSig: sr.ProviderSig,
	})
	if err != nil {
		return 0, err
	}
	payload, err := json.Marshal(Envelope{Kind: KindAttest, Body: request})
	if err != nil {
		return 0, err
	}

	collected := 0
	for _, witness := range drawn {
		answer, err := send(ctx, witness.NodeID, payload)
		if err != nil {
			continue
		}
		var out AttestResponse
		if err := json.Unmarshal(answer, &out); err != nil {
			continue
		}
		// AddWitness verifies the signature before storing it. An attestation
		// that does not check out is worse than a missing one: it would make
		// the receipt look forged at settlement.
		if sr.AddWitness(out.WitnessPub, out.Sig) {
			collected++
		}
	}
	return collected, nil
}

// AnswerAttestRequest is the witness side.
//
// Every check here exists because skipping it turns this node into a rubber
// stamp: it rebuilds the receipt from the evidence rather than accepting one,
// re-runs the proof rather than believing the provider verified it, and refuses
// to sign for a claim it was not drawn for — signing one anyway would mark the
// receipt as carrying witnesses nobody selected, which settlement treats as
// fraud by the PROVIDER.
func AnswerAttestRequest(ctx context.Context, a *Agent, views *EpochViews,
	req AttestRequest) (AttestResponse, error) {
	var out AttestResponse
	if a == nil {
		return out, ErrNoTransport
	}
	receipt := ReceiptFor(req.Challenge, req.Response, req.ProvenBytes)
	if receipt.ProviderNodeID == a.NodeID() {
		return out, ErrSelfWitness
	}
	if !VerifyReceiptSignature(req.ProviderPub, receipt, req.ProviderSig) {
		// Either the provider did not sign this receipt, or it signed different
		// numbers than the evidence supports.
		return out, ErrProviderSignature
	}
	if views != nil {
		view, err := views.For(ctx, receipt.Epoch)
		if err != nil {
			return out, err
		}
		if !IsSelectedWitness(view.Randomness, receipt.ProviderNodeID, receipt.ServiceType,
			ChallengeIndexOf(receipt), ThresholdFor(receipt.ServiceType),
			view.Candidates, a.NodeID()) {
			return out, ErrNotDrawn
		}
	}
	sig, err := a.AttestationFor(req.Challenge, req.Response, req.ProvenBytes)
	if err != nil {
		return out, err
	}
	return AttestResponse{WitnessPub: a.Pub, Sig: sig}, nil
}

// FacilitationResponder handles both message kinds on the one protocol.
//
// A payload with no envelope is treated as a bare challenge, so a node running
// the older build — which sent challenges unwrapped — is still answered rather
// than being told its messages are undecodable.
func FacilitationResponder(s *Scheduler, views *EpochViews,
	load ShardLoader) func(ctx context.Context, payload []byte) ([]byte, error) {
	challenge := ChallengeResponder(s, load)
	return func(ctx context.Context, payload []byte) ([]byte, error) {
		var env Envelope
		if err := json.Unmarshal(payload, &env); err != nil || env.Kind == "" {
			return challenge(ctx, payload)
		}
		switch env.Kind {
		case KindChallenge:
			return challenge(ctx, env.Body)
		case KindAttest:
			var req AttestRequest
			if err := json.Unmarshal(env.Body, &req); err != nil {
				return nil, fmt.Errorf("facilitation: undecodable attestation request: %w", err)
			}
			out, err := AnswerAttestRequest(ctx, s.Agent, views, req)
			if err != nil {
				return nil, err
			}
			return json.Marshal(out)
		default:
			return nil, fmt.Errorf("facilitation: unknown message kind %q", env.Kind)
		}
	}
}
