package aggregator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Where rewards are actually sent.
//
// NodeRegistry's `owner` is whoever signed the registration — useful for
// ownership and stake, but not necessarily where an operator wants credits. A
// node therefore publishes a payout address signed by its p2p identity key, and
// that declaration wins over the registry owner.
//
// The signature is checked by the site before it is stored, and it covers the
// address itself, so a declaration cannot be re-pointed in transit. What this
// function must still enforce is that a declaration only ever affects ITS OWN
// node: the key it is keyed by is hashed here to derive the node id rather than
// trusting any node id supplied alongside it.

type declaredPayout struct {
	P2PPublicKey string `json:"p2p_public_key"`
	Payout       string `json:"payout"`
	Sequence     uint64 `json:"sequence"`
}

// FetchDeclaredPayouts reads node-declared payout addresses from the site.
func FetchDeclaredPayouts(ctx context.Context, siteBaseURL string) (map[[32]byte][20]byte, error) {
	url := strings.TrimSuffix(siteBaseURL, "/") + "/api/v1/pof/payouts"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("aggregator: payout directory unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("aggregator: payout directory returned HTTP %d", resp.StatusCode)
	}
	var body struct {
		Payouts []declaredPayout `json:"payouts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	out := make(map[[32]byte][20]byte, len(body.Payouts))
	for _, p := range body.Payouts {
		raw, err := hex.DecodeString(strings.TrimPrefix(p.P2PPublicKey, "0x"))
		if err != nil || len(raw) != 32 {
			continue
		}
		// The node id is DERIVED from the key, never taken on trust: a
		// declaration must not be able to name a node other than its own.
		nodeID := keccak(raw)
		addr, ok := parseAddress20(p.Payout)
		if !ok {
			continue
		}
		out[nodeID] = addr
	}
	return out, nil
}

func parseAddress20(value string) ([20]byte, bool) {
	var out [20]byte
	v := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	if len(v) != 40 {
		return out, false
	}
	raw, err := hex.DecodeString(v)
	if err != nil {
		return out, false
	}
	copy(out[:], raw)
	var zero [20]byte
	return out, out != zero
}

// ResolveRecipients combines the two sources, declaration winning.
//
// A node with neither is omitted entirely rather than defaulted to the zero
// address: SettleEpoch rejects receipts from providers it cannot pay, and a
// zero recipient would burn the reward instead of withholding it.
func ResolveRecipients(registry map[[32]byte][20]byte, declared map[[32]byte][20]byte) map[[32]byte][20]byte {
	out := make(map[[32]byte][20]byte, len(registry)+len(declared))
	for node, addr := range registry {
		out[node] = addr
	}
	for node, addr := range declared {
		out[node] = addr
	}
	return out
}
