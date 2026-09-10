package facilitation

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"math/big"
	"testing"
)

func testAgent(t *testing.T, seed byte) *Agent {
	t.Helper()
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(raw)
	return NewAgent(priv.Public().(ed25519.PublicKey), priv)
}

// exchange sets up a provider holding data and a witness, and produces the
// challenge/response pair an attestation would be requested over.
func exchange(t *testing.T, provider, verifier *Agent) (StorageChallenge, StorageResponse, SignedReceipt) {
	t.Helper()
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i)
	}
	const chunkSize = 512
	root := ShardRoot(data, chunkSize)
	var seed [32]byte
	seed[0] = 9
	c := verifier.IssueStorageChallenge(provider.NodeID(), [32]byte{1}, root, seed, 4,
		len(data)/chunkSize, 2)
	resp, err := provider.AnswerStorageChallenge(c, data, chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	sr, err := provider.BuildReceipt(c, resp, uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return c, resp, sr
}

func poolOf(agents ...*Agent) []Candidate {
	out := make([]Candidate, 0, len(agents))
	for _, a := range agents {
		out = append(out, Candidate{NodeID: a.NodeID(), Stake: big.NewInt(0), ReputationBps: 10000})
	}
	return out
}

func TestWitnessRefusesWhenItWasNotDrawn(t *testing.T) {
	// The check that makes an attestation worth anything. A witness that signs
	// whatever it is sent lets a provider assemble a set of signatures the
	// protocol never selected — and settlement reads that as fraud BY THE
	// PROVIDER, so a helpful witness would be framing the node it meant to help.
	provider, verifier := testAgent(t, 1), testAgent(t, 2)
	outsider := testAgent(t, 3)
	c, resp, sr := exchange(t, provider, verifier)

	// A pool large enough that the outsider is not in every draw.
	pool := poolOf(verifier, outsider,
		testAgent(t, 4), testAgent(t, 5), testAgent(t, 6), testAgent(t, 7),
		testAgent(t, 8), testAgent(t, 9), testAgent(t, 10), testAgent(t, 11))
	view := EpochView{Candidates: pool}
	view.Randomness[0] = 0x5A

	drawn := map[[32]byte]bool{}
	for _, c := range WitnessesFor(view, sr.Receipt) {
		drawn[c.NodeID] = true
	}
	var absent *Agent
	for _, a := range []*Agent{outsider, testAgent(t, 4), testAgent(t, 5), testAgent(t, 6),
		testAgent(t, 7), testAgent(t, 8), testAgent(t, 9), testAgent(t, 10), testAgent(t, 11)} {
		if !drawn[a.NodeID()] {
			absent = a
			break
		}
	}
	if absent == nil {
		t.Skip("every candidate was drawn; nothing to test refusal with")
	}

	views := &EpochViews{byEpoch: map[uint64]EpochView{sr.Receipt.Epoch: view}}
	_, err := AnswerAttestRequest(context.Background(), absent, views, AttestRequest{
		Challenge: c, Response: resp, ProvenBytes: uint64(4096),
		ProviderPub: sr.ProviderPub, ProviderSig: sr.ProviderSig,
	})
	if err != ErrNotDrawn {
		t.Fatalf("an undrawn node returned %v; it must refuse with ErrNotDrawn", err)
	}
}

func TestDrawnWitnessSignsAReceiptItRebuiltItself(t *testing.T) {
	provider, verifier := testAgent(t, 1), testAgent(t, 2)
	c, resp, sr := exchange(t, provider, verifier)

	pool := poolOf(verifier, testAgent(t, 3), testAgent(t, 4))
	view := EpochView{Candidates: pool}
	view.Randomness[0] = 0x5A
	drawn := WitnessesFor(view, sr.Receipt)
	if len(drawn) == 0 {
		t.Fatal("nobody was drawn")
	}

	// Find the agent behind the first drawn candidate.
	agents := map[[32]byte]*Agent{}
	for _, a := range []*Agent{verifier, testAgent(t, 3), testAgent(t, 4)} {
		agents[a.NodeID()] = a
	}
	witness := agents[drawn[0].NodeID]
	views := &EpochViews{byEpoch: map[uint64]EpochView{sr.Receipt.Epoch: view}}

	out, err := AnswerAttestRequest(context.Background(), witness, views, AttestRequest{
		Challenge: c, Response: resp, ProvenBytes: uint64(4096),
		ProviderPub: sr.ProviderPub, ProviderSig: sr.ProviderSig,
	})
	if err != nil {
		t.Fatalf("a drawn witness refused: %v", err)
	}
	if !sr.AddWitness(out.WitnessPub, out.Sig) {
		t.Fatal("the attestation did not verify against the receipt")
	}
}

func TestAnInflatedClaimIsAttestedOnlyAtTheProvenAmount(t *testing.T) {
	// The provider is not asked what the receipt says — it is asked for
	// evidence, and the witness rebuilds the receipt from that. A provider
	// asking for a terabyte gets an attestation over the honest figure instead,
	// so the lie costs it nothing and gains it nothing.
	provider, verifier := testAgent(t, 1), testAgent(t, 2)
	c, resp, _ := exchange(t, provider, verifier)

	sr, err := provider.BuildReceipt(c, resp, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	view := EpochView{Candidates: poolOf(verifier)}
	views := &EpochViews{byEpoch: map[uint64]EpochView{sr.Receipt.Epoch: view}}

	out, err := AnswerAttestRequest(context.Background(), verifier, views, AttestRequest{
		Challenge: c, Response: resp,
		ProvenBytes: 1 << 40, // claims a terabyte for a 4 KiB proof
		ProviderPub: sr.ProviderPub, ProviderSig: sr.ProviderSig,
	})
	if err != nil {
		t.Fatalf("the witness refused an otherwise valid receipt: %v", err)
	}
	if sr.Receipt.Quantity > ProvableBytes(c, resp) {
		t.Fatalf("the signed receipt still claims %d bytes", sr.Receipt.Quantity)
	}
	if !sr.AddWitness(out.WitnessPub, out.Sig) {
		t.Fatal("the attestation did not verify against the clamped receipt")
	}
}

func TestAWitnessRefusesAForgedProviderSignature(t *testing.T) {
	// Signature checking still matters: a receipt nobody signed is not a claim,
	// and attesting to one would put this witness's name on it.
	provider, verifier := testAgent(t, 1), testAgent(t, 2)
	c, resp, sr := exchange(t, provider, verifier)

	view := EpochView{Candidates: poolOf(verifier)}
	views := &EpochViews{byEpoch: map[uint64]EpochView{sr.Receipt.Epoch: view}}

	forged := append([]byte(nil), sr.ProviderSig...)
	forged[0] ^= 0xFF
	_, err := AnswerAttestRequest(context.Background(), verifier, views, AttestRequest{
		Challenge: c, Response: resp, ProvenBytes: 4096,
		ProviderPub: sr.ProviderPub, ProviderSig: forged,
	})
	if err != ErrProviderSignature {
		t.Fatalf("a forged provider signature returned %v", err)
	}
}

func TestResponderRoutesBothMessageKinds(t *testing.T) {
	provider := testAgent(t, 1)
	s := &Scheduler{Agent: provider}
	handler := FacilitationResponder(s, nil, func([32]byte) ([]byte, int, bool) {
		return nil, 0, false
	})

	// An unknown kind is refused rather than guessed at.
	payload, _ := json.Marshal(Envelope{Kind: "nonsense", Body: json.RawMessage(`{}`)})
	if _, err := handler(context.Background(), payload); err == nil {
		t.Fatal("an unknown message kind was accepted")
	}

	// A bare challenge with no envelope still reaches the challenge path, so a
	// peer running the older build is answered rather than rejected.
	var c StorageChallenge
	c.TargetNodeID = provider.NodeID()
	bare, _ := json.Marshal(c)
	_, err := handler(context.Background(), bare)
	if err == nil {
		t.Fatal("expected the not-held error from the challenge path")
	}
	if err == ErrNotForUs {
		t.Fatal("a bare challenge was not routed to the challenge handler")
	}
}

func TestQuantityIsClampedToWhatTheProofShows(t *testing.T) {
	// A provider that names its own Quantity is paid out of a fixed epoch budget
	// weighted linearly by that number, against a per-node cap. One receipt
	// claiming a terabyte for a 4 KiB proof took the whole cap and left every
	// honest node with a rounding error. The claim is now cut to what the
	// evidence supports, in the derivation BOTH sides run.
	provider, verifier := testAgent(t, 1), testAgent(t, 2)
	c, resp, _ := exchange(t, provider, verifier)

	honest := ReceiptFor(c, resp, 4096)
	if honest.Quantity != 4096 {
		t.Fatalf("an honest 4096-byte claim became %d", honest.Quantity)
	}

	inflated := ReceiptFor(c, resp, 1<<40)
	if inflated.Quantity > ProvableBytes(c, resp) {
		t.Fatalf("a terabyte claim survived as %d; the proof supports at most %d",
			inflated.Quantity, ProvableBytes(c, resp))
	}

	// And both sides agree on the clamped figure, so the provider's signature
	// still verifies for the witness — clamping must not break honest receipts.
	sr, err := provider.BuildReceipt(c, resp, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyReceiptSignature(sr.ProviderPub, ReceiptFor(c, resp, 1<<40), sr.ProviderSig) {
		t.Fatal("provider and witness derived different receipts after clamping")
	}
}
