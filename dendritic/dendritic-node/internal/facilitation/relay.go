package facilitation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

// Talking to the relay.
//
// A node publishes what it holds so challengers know what to test, reads the
// network's advertisements so it can do its own auditing, and uploads the
// receipts it earned so the aggregator can settle them. None of it is trusted
// on either side: the relay stores blobs, the aggregator verifies signatures,
// and a node verifies every proof it is given before attesting to anything.

type wireAssignment struct {
	AssignmentID string `json:"assignment_id"`
	ShardRoot    string `json:"shard_root"`
	NumChunks    int    `json:"num_chunks"`
	Bytes        uint64 `json:"bytes"`
}

type assignmentsPayload struct {
	P2PPublicKey string           `json:"p2p_public_key"`
	Assignments  []wireAssignment `json:"assignments"`
}

type assignmentsListing struct {
	Nodes []assignmentsPayload `json:"nodes"`
}

func (c *GatewayClient) postJSON(ctx context.Context, path string, body any, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := strings.TrimSuffix(c.BaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("facilitation: %s unreachable: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		msg := errBody.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("facilitation: %s refused: %s", path, msg)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// PublishAssignments advertises what this node is holding.
func (c *GatewayClient) PublishAssignments(ctx context.Context, pub []byte, assignments []Assignment) error {
	wire := make([]wireAssignment, 0, len(assignments))
	for _, a := range assignments {
		wire = append(wire, wireAssignment{
			AssignmentID: hex.EncodeToString(a.AssignmentID[:]),
			ShardRoot:    hex.EncodeToString(a.ShardRoot[:]),
			NumChunks:    a.NumChunks,
			Bytes:        a.Bytes,
		})
	}
	return c.postJSON(ctx, "/api/v1/pof/assignments", assignmentsPayload{
		P2PPublicKey: hex.EncodeToString(pub), Assignments: wire,
	}, nil)
}

// FetchAssignments reads the network's advertisements and returns them as
// scheduler assignments.
//
// Each node id is DERIVED from the advertising key rather than read from the
// payload, so a node cannot advertise shards on someone else's behalf — which
// would let it nominate a victim for audits it is certain to fail.
func (c *GatewayClient) FetchAssignments(ctx context.Context) ([]Assignment, [][32]byte, error) {
	url := strings.TrimSuffix(c.BaseURL, "/") + "/api/v1/pof/assignments"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("facilitation: assignment directory unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("facilitation: assignment directory returned HTTP %d", resp.StatusCode)
	}
	var listing assignmentsListing
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		return nil, nil, err
	}

	var out []Assignment
	var nodes [][32]byte
	for _, entry := range listing.Nodes {
		raw, err := hex.DecodeString(strings.TrimPrefix(entry.P2PPublicKey, "0x"))
		if err != nil || len(raw) != 32 {
			continue
		}
		nodeID := NodeID(raw)
		nodes = append(nodes, nodeID)
		for _, w := range entry.Assignments {
			assignmentID, err := ShardIDToAssignment(w.AssignmentID)
			if err != nil {
				continue
			}
			rootBytes, err := hex.DecodeString(strings.TrimPrefix(w.ShardRoot, "0x"))
			if err != nil || len(rootBytes) != 32 {
				continue
			}
			var root [32]byte
			copy(root[:], rootBytes)
			if w.NumChunks <= 0 {
				continue
			}
			out = append(out, Assignment{
				NodeID: nodeID, AssignmentID: assignmentID, ShardRoot: root,
				NumChunks: w.NumChunks, Bytes: w.Bytes,
			})
		}
	}
	return out, nodes, nil
}

type wireReceipt struct {
	Hash        string        `json:"hash"`
	Epoch       uint64        `json:"epoch"`
	ProviderKey string        `json:"provider_key"`
	Body        SignedReceipt `json:"body"`
}

// UploadReceipts hands spooled receipts to the aggregator's relay.
//
// Uploading is idempotent — the relay dedups on the canonical hash — so a node
// may simply re-send its whole epoch after a restart rather than tracking what
// it has already sent.
func (c *GatewayClient) UploadReceipts(ctx context.Context, receipts []SignedReceipt) (int, error) {
	if len(receipts) == 0 {
		return 0, nil
	}
	items := make([]wireReceipt, 0, len(receipts))
	for _, sr := range receipts {
		h := sr.Hash()
		items = append(items, wireReceipt{
			Hash:        hex.EncodeToString(h[:]),
			Epoch:       sr.Receipt.Epoch,
			ProviderKey: hex.EncodeToString(sr.ProviderPub),
			Body:        sr,
		})
	}
	var out struct {
		Stored  int `json:"stored"`
		Skipped int `json:"skipped"`
	}
	if err := c.postJSON(ctx, "/api/v1/pof/receipts", map[string]any{"receipts": items}, &out); err != nil {
		return 0, err
	}
	return out.Stored, nil
}

type candidatesListing struct {
	Candidates []struct {
		P2PPublicKey  string `json:"p2p_public_key"`
		NodeID        string `json:"node_id"`
		StakeWei      string `json:"stake_wei"`
		ReputationBps uint32 `json:"reputation_bps"`
		Group         string `json:"group"`
	} `json:"candidates"`
	BootstrapStakeFloorWei string `json:"bootstrap_stake_floor_wei"`
}

// FetchCandidates reads the witness pool: every registered node, with the
// weights it is drawn on.
//
// Node ids are DERIVED from the published keys rather than read from the
// node_id field, for the same reason assignments are: a directory that could
// name a node id independently of the key behind it could put a victim in a
// draw it has no way to answer.
func (c *GatewayClient) FetchCandidates(ctx context.Context) ([]Candidate, error) {
	url := strings.TrimSuffix(c.BaseURL, "/") + "/api/v1/pof/candidates"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facilitation: witness pool unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("facilitation: witness pool returned HTTP %d", resp.StatusCode)
	}
	var listing candidatesListing
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		return nil, err
	}

	out := make([]Candidate, 0, len(listing.Candidates))
	for _, entry := range listing.Candidates {
		raw, err := hex.DecodeString(strings.TrimPrefix(entry.P2PPublicKey, "0x"))
		if err != nil || len(raw) != 32 {
			continue
		}
		stake, ok := new(big.Int).SetString(strings.TrimSpace(entry.StakeWei), 10)
		if !ok {
			// An unparseable stake is treated as none rather than skipped: the
			// node is registered, and dropping it here would give this node a
			// smaller pool than settlement uses.
			stake = big.NewInt(0)
		}
		reputation := entry.ReputationBps
		if reputation == 0 {
			reputation = 10000
		}
		out = append(out, Candidate{
			NodeID:        NodeID(raw),
			Stake:         stake,
			ReputationBps: reputation,
			Group:         entry.Group,
		})
	}
	return out, nil
}
