package facilitation

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

// Wires the responder to the transport through a byte pipe — the same path the
// p2p layer takes, minus the network.
func pipeTransport(t *testing.T, responders map[[32]byte]func(context.Context, []byte) ([]byte, error)) P2PTransport {
	t.Helper()
	return P2PTransport{Send: func(ctx context.Context, target [32]byte, payload []byte) ([]byte, error) {
		fn, ok := responders[target]
		if !ok {
			return nil, ErrPeerUnreachable
		}
		return fn(ctx, payload)
	}}
}

// End to end over the wire encoding: challenge marshalled, delivered, answered,
// unmarshalled, verified, and the receipt spooled on the provider.
func TestTransportRoundTripSpoolsAMatchingReceipt(t *testing.T) {
	net, agents, _, assignments := buildNet(t, 4)
	provider, challenger := agents[1], agents[0]
	a := assignments[1]

	store, err := OpenReceiptStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	providerSched := &Scheduler{Agent: provider, Store: store}
	responder := ChallengeResponder(providerSched, func(id [32]byte) ([]byte, int, bool) {
		data, ok := net.data[id]
		return data, net.chunk, ok
	})
	transport := pipeTransport(t, map[[32]byte]func(context.Context, []byte) ([]byte, error){
		provider.NodeID(): responder,
	})

	c := challenger.IssueStorageChallenge(a.NodeID, a.AssignmentID, a.ShardRoot,
		seedFrom(0x91), 12, a.NumChunks, ChunksPerChallenge)
	resp, err := transport.Challenge(context.Background(), provider.NodeID(), c)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if err := challenger.VerifyStorageResponse(c, resp); err != nil {
		t.Fatalf("challenger rejected the answer: %v", err)
	}

	// The receipt the provider spooled must correspond to the response the
	// challenger just verified. If the provider answered twice, AnsweredAt (and
	// so ResultHash) would differ and any attestation would sign a hash nobody
	// else derives — silently unpayable work.
	spooled, err := store.ListEpoch(12)
	if err != nil {
		t.Fatal(err)
	}
	if len(spooled) != 1 {
		t.Fatalf("expected 1 spooled receipt, got %d", len(spooled))
	}
	if spooled[0].Receipt.ResultHash != resp.ResultHash() {
		t.Fatal("spooled receipt does not match the response that was sent back")
	}
	want := CanonicalReceiptHash(ReceiptFor(c, resp, uint64(len(net.data[a.AssignmentID]))))
	if spooled[0].Hash() != want {
		t.Fatal("a witness rebuilding this receipt would derive a different hash")
	}
}

// A challenge for someone else must be refused, not answered helpfully.
func TestResponderRefusesChallengesForOtherNodes(t *testing.T) {
	net, agents, _, assignments := buildNet(t, 3)
	provider, other, challenger := agents[1], agents[2], agents[0]

	s := &Scheduler{Agent: provider}
	responder := ChallengeResponder(s, func(id [32]byte) ([]byte, int, bool) {
		data, ok := net.data[id]
		return data, net.chunk, ok
	})
	// Addressed to `other`, delivered to `provider`.
	c := challenger.IssueStorageChallenge(other.NodeID(), assignments[2].AssignmentID,
		assignments[2].ShardRoot, seedFrom(0x92), 3, assignments[2].NumChunks, ChunksPerChallenge)
	payload, _ := json.Marshal(c)
	if _, err := responder(context.Background(), payload); err != ErrNotForUs {
		t.Fatalf("answered another node's challenge: %v", err)
	}
}

// Not holding the shard is reported as absence, not as a broken proof.
func TestResponderSaysWhenItDoesNotHoldTheShard(t *testing.T) {
	agents := []*Agent{}
	for i := 0; i < 2; i++ {
		pub, priv, _ := ed25519.GenerateKey(nil)
		agents = append(agents, NewAgent(pub, priv))
	}
	provider, challenger := agents[1], agents[0]
	s := &Scheduler{Agent: provider}
	responder := ChallengeResponder(s, func(id [32]byte) ([]byte, int, bool) {
		return nil, 0, false // holds nothing
	})
	var assignment, root [32]byte
	assignment[0] = 9
	c := challenger.IssueStorageChallenge(provider.NodeID(), assignment, root,
		seedFrom(0x93), 4, 8, ChunksPerChallenge)
	payload, _ := json.Marshal(c)
	_, err := responder(context.Background(), payload)
	if err == nil {
		t.Fatal("claimed to prove a shard it does not hold")
	}
	if !strings.Contains(err.Error(), "not held here") {
		t.Fatalf("unclear error for a missing shard: %v", err)
	}
}

// An unreachable peer is not a failed audit — the distinction decides whether
// an offline node merely goes unpaid or gets treated as having lost data.
func TestUnreachablePeerIsNotAFailedProof(t *testing.T) {
	_, agents, ids, assignments := buildNet(t, 5)
	transport := pipeTransport(t, map[[32]byte]func(context.Context, []byte) ([]byte, error){})
	s := &Scheduler{Agent: agents[0], Transport: transport}
	results, err := s.RunEpoch(context.Background(), seedFrom(0x94), 6, assignments, ids)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Passed {
			t.Fatal("an unreachable peer passed")
		}
		if r.Err != ErrPeerUnreachable {
			t.Fatalf("expected unreachable, got %v", r.Err)
		}
	}
}
