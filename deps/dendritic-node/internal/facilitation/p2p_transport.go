package facilitation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Wire format for challenges carried over the p2p layer.
//
// The transport moves opaque bytes, so the encoding lives here rather than in
// internal/p2p — that package should not gain an opinion about how earnings are
// proven, and this one stays testable with no network at all.

var (
	ErrPeerUnreachable = errors.New("facilitation: peer is not reachable")
	ErrNotForUs        = errors.New("facilitation: challenge is addressed to another node")
)

// SendFunc delivers challenge bytes to a node id and returns its answer.
// Returning ErrPeerUnreachable (or wrapping it) means "could not audit", which
// is different from "failed the audit" — an offline node must not be recorded
// as one that lost its data.
type SendFunc func(ctx context.Context, target [32]byte, payload []byte) ([]byte, error)

// P2PTransport adapts any SendFunc to the scheduler's Transport interface.
type P2PTransport struct{ Send SendFunc }

func (t P2PTransport) Challenge(ctx context.Context, target [32]byte, c StorageChallenge) (StorageResponse, error) {
	var out StorageResponse
	if t.Send == nil {
		return out, ErrNoTransport
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return out, err
	}
	answer, err := t.Send(ctx, target, payload)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(answer, &out); err != nil {
		return out, fmt.Errorf("facilitation: peer sent an undecodable proof: %w", err)
	}
	return out, nil
}

// ShardLoader returns the bytes this node holds for an assignment, and the
// chunk size they were committed with.
type ShardLoader func(assignmentID [32]byte) (data []byte, chunkSize int, ok bool)

// ChallengeResponder builds the handler a node installs to answer incoming
// challenges: decode, prove, spool the receipt, and return the proof.
//
// It answers only challenges addressed to this node. A challenge naming someone
// else is refused rather than answered helpfully — proving possession on
// another node's behalf is precisely the confusion the target binding prevents.
func ChallengeResponder(s *Scheduler, load ShardLoader) func(ctx context.Context, payload []byte) ([]byte, error) {
	return func(ctx context.Context, payload []byte) ([]byte, error) {
		var c StorageChallenge
		if err := json.Unmarshal(payload, &c); err != nil {
			return nil, fmt.Errorf("facilitation: undecodable challenge: %w", err)
		}
		if c.TargetNodeID != s.Agent.NodeID() {
			return nil, ErrNotForUs
		}
		data, chunkSize, ok := load(c.AssignmentID)
		if !ok {
			// We are not holding it. Say so plainly instead of returning a
			// proof over empty bytes, which would fail verification anyway and
			// look like corruption rather than absence.
			return nil, fmt.Errorf("facilitation: shard %x is not held here", c.AssignmentID[:8])
		}
		// Return the SAME response the receipt was built from. Re-answering
		// would stamp a later AnsweredAt, changing the ResultHash, and the
		// challenger would verify a proof belonging to no spooled receipt.
		_, resp, err := s.AnswerChallenge(ctx, c, data, chunkSize, uint64(len(data)))
		if err != nil {
			return nil, err
		}
		return json.Marshal(resp)
	}
}
