package aggregator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// A whole settlement, end to end.
//
// Pulls the epoch's receipts from the relay, resolves who gets paid from the
// chain and the nodes' own declarations, takes the epoch randomness from the
// chain, and runs SettleEpoch. The result is the four values EpochManager wants
// plus a claimable row per node.
//
// Every input that decides money comes from somewhere the aggregator cannot
// quietly choose: randomness from EpochManager, recipients from NodeRegistry
// and signed declarations, receipts from the nodes that signed them. The
// aggregator's only real power is arithmetic, and a challenger re-running this
// with the same inputs gets the same roots — which is what the bond is for.

// SettlementInputs is everything a run needs that is not fetched.
type SettlementInputs struct {
	SiteBaseURL string
	Chain       *ChainClient
	Epoch       uint64
	Policy      Policy
}

// ClaimRow is what a node needs to call RewardDistributor.claim.
type ClaimRow struct {
	NodeID    string   `json:"node_id"`
	Recipient string   `json:"recipient"`
	Amount    string   `json:"amount"`
	Service   string   `json:"service_breakdown_hash"`
	Proof     []string `json:"proof"`
}

// SettlementResult is the run's output, ready to post on-chain and publish.
type SettlementResult struct {
	Epoch         uint64 `json:"epoch"`
	ReceiptRoot   string `json:"receipt_root"`
	RewardRoot    string `json:"reward_root"`
	NodeStateRoot string `json:"node_state_root"`
	Randomness    string `json:"randomness"`
	// Where the randomness came from. Published because it changes what the
	// value means: on-chain is a fact anyone can re-read, derived is a
	// commitment this run is about to make.
	RandomnessSource string     `json:"randomness_source"`
	TotalRewards     string     `json:"total_rewards"`
	Accepted         int        `json:"accepted"`
	Rejected         int        `json:"rejected"`
	Rejections       []string   `json:"rejections"`
	Claims           []ClaimRow `json:"claims"`
	WithinBudget     bool       `json:"within_budget"`
}

// SettleEpochFromRelay runs one epoch's settlement.
func SettleEpochFromRelay(ctx context.Context, in SettlementInputs) (*SettlementResult, error) {
	if in.Chain == nil {
		return nil, fmt.Errorf("aggregator: no chain client")
	}
	// Randomness first: without it there is no legitimate witness draw, so
	// there is nothing worth computing. An epoch being settled for the FIRST
	// time has none on-chain yet — submitEpoch is what writes it — so the
	// derived value is used, and the same value is what gets submitted.
	randomness, randomnessSource, err := EpochRandomness(ctx, in.Chain, in.SiteBaseURL, in.Epoch)
	if err != nil {
		return nil, fmt.Errorf("aggregator: could not determine epoch randomness: %w", err)
	}
	var zero [32]byte
	if randomness == zero {
		return nil, fmt.Errorf("aggregator: epoch %d has no usable randomness", in.Epoch)
	}

	receipts, err := fetchReceipts(ctx, in.SiteBaseURL, in.Epoch)
	if err != nil {
		return nil, err
	}

	// Who is even eligible: the nodes that advertised work this epoch.
	_, candidateIDs, err := fetchAssignmentNodes(ctx, in.SiteBaseURL)
	if err != nil {
		return nil, err
	}
	providers := make(map[[32]byte]bool, len(receipts))
	for _, sr := range receipts {
		providers[sr.Receipt.ProviderNodeID] = true
	}
	for _, id := range candidateIDs {
		providers[id] = true
	}
	nodeIDs := make([][32]byte, 0, len(providers))
	for id := range providers {
		nodeIDs = append(nodeIDs, id)
	}

	registryRecipients, err := in.Chain.RecipientsFor(ctx, nodeIDs)
	if err != nil {
		return nil, fmt.Errorf("aggregator: could not resolve registry owners: %w", err)
	}
	declared, err := FetchDeclaredPayouts(ctx, in.SiteBaseURL)
	if err != nil {
		// A node with no declaration still has its registry owner, so this is
		// degraded rather than fatal.
		declared = map[[32]byte][20]byte{}
	}
	recipients := ResolveRecipients(registryRecipients, declared)

	candidates, err := in.Chain.CandidatesFor(ctx, candidateIDs)
	if err != nil {
		return nil, fmt.Errorf("aggregator: could not build the witness pool: %w", err)
	}

	commitment := SettleEpoch(EpochInput{
		Epoch:      in.Epoch,
		Randomness: randomness,
		Receipts:   receipts,
		Candidates: candidates,
		Policy:     in.Policy,
		Recipients: recipients,
	})

	result := &SettlementResult{
		Epoch:            commitment.Epoch,
		ReceiptRoot:      "0x" + hex.EncodeToString(commitment.ReceiptRoot[:]),
		RewardRoot:       "0x" + hex.EncodeToString(commitment.RewardRoot[:]),
		NodeStateRoot:    "0x" + hex.EncodeToString(commitment.NodeStateRoot[:]),
		Randomness:       "0x" + hex.EncodeToString(commitment.Randomness[:]),
		RandomnessSource: randomnessSource,
		TotalRewards:     commitment.TotalRewards.String(),
		Accepted:         len(commitment.Accepted),
		Rejected:         len(commitment.Rejections),
		WithinBudget:     commitment.WithinBudget(in.Policy),
	}
	// Rejections are published, not swallowed: an operator whose work was not
	// paid is owed the reason, and a spike in one reason is the first sign of
	// an attack.
	seen := map[string]int{}
	for _, r := range commitment.Rejections {
		seen[string(r.Reason)]++
	}
	for reason, count := range seen {
		result.Rejections = append(result.Rejections, fmt.Sprintf("%s (%d)", reason, count))
	}

	for _, row := range commitment.Rows {
		_, proof, ok := commitment.ProofForNode(row.NodeID)
		if !ok {
			continue
		}
		hexProof := make([]string, 0, len(proof))
		for _, p := range proof {
			hexProof = append(hexProof, "0x"+hex.EncodeToString(p[:]))
		}
		amount := row.Amount
		if amount == nil {
			amount = big.NewInt(0)
		}
		result.Claims = append(result.Claims, ClaimRow{
			NodeID:    "0x" + hex.EncodeToString(row.NodeID[:]),
			Recipient: "0x" + hex.EncodeToString(row.Recipient[:]),
			Amount:    amount.String(),
			Service:   "0x" + hex.EncodeToString(row.Service[:]),
			Proof:     hexProof,
		})
	}
	return result, nil
}

func httpGetJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("aggregator: %s unreachable: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("aggregator: %s returned HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func fetchReceipts(ctx context.Context, siteBaseURL string, epoch uint64) ([]SignedReceipt, error) {
	var body struct {
		Receipts []SignedReceipt `json:"receipts"`
	}
	url := fmt.Sprintf("%s/api/v1/pof/receipts/%d", strings.TrimSuffix(siteBaseURL, "/"), epoch)
	if err := httpGetJSON(ctx, url, &body); err != nil {
		return nil, err
	}
	return body.Receipts, nil
}

func fetchAssignmentNodes(ctx context.Context, siteBaseURL string) ([]string, [][32]byte, error) {
	var body struct {
		Nodes []struct {
			P2PPublicKey string `json:"p2p_public_key"`
		} `json:"nodes"`
	}
	url := strings.TrimSuffix(siteBaseURL, "/") + "/api/v1/pof/assignments"
	if err := httpGetJSON(ctx, url, &body); err != nil {
		return nil, nil, err
	}
	keys := make([]string, 0, len(body.Nodes))
	ids := make([][32]byte, 0, len(body.Nodes))
	for _, n := range body.Nodes {
		raw, err := hex.DecodeString(strings.TrimPrefix(n.P2PPublicKey, "0x"))
		if err != nil || len(raw) != 32 {
			continue
		}
		keys = append(keys, n.P2PPublicKey)
		// Derived, never taken from the payload — the same rule as everywhere
		// else a node id appears.
		ids = append(ids, keccak(raw))
	}
	return keys, ids, nil
}
