package facilitation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Fetching epoch randomness.
//
// The node deliberately does not speak to a chain — it holds no ETH, encodes no
// transactions, and runs no RPC client. So it asks the website, which reads
// EpochManager and serves the value.
//
// That is a trust question worth being explicit about: a lying server could
// hand a node a seed that skews which chunks it is asked to prove. It cannot
// forge earnings with it — receipts still need signatures from independently
// selected witnesses, and every one of those witnesses recomputes the same
// derivation — but a node that wants to verify can read
// EpochManager.randomnessOf(epoch) itself and compare. The endpoint exists for
// convenience, not as an authority, which is why the response says where the
// value came from.

type randomnessResponse struct {
	Epoch      uint64 `json:"epoch"`
	Randomness string `json:"randomness"`
	Exists     bool   `json:"exists"`
	Source     string `json:"source"`
	Error      string `json:"error"`
}

// ParseSeed accepts a 0x-prefixed 32-byte hex string.
func ParseSeed(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) != 64 {
		return out, fmt.Errorf("facilitation: %q is not a 32-byte seed", s)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("facilitation: seed is not hex: %w", err)
	}
	copy(out[:], raw)
	return out, nil
}

// EpochRandomness fetches the seed for an epoch from the website.
//
// A zero seed is returned as an error rather than a value: zero means the epoch
// was never submitted, and using it would make every challenge and witness draw
// predictable — the one failure this whole mechanism exists to avoid.
func (c *GatewayClient) EpochRandomness(ctx context.Context, epoch uint64) ([32]byte, error) {
	var zero [32]byte
	url := fmt.Sprintf("%s/api/v1/pof/randomness/%d", strings.TrimSuffix(c.BaseURL, "/"), epoch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return zero, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return zero, fmt.Errorf("facilitation: randomness unreachable: %w", err)
	}
	defer resp.Body.Close()

	var out randomnessResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 400 || out.Error != "" {
		msg := out.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return zero, fmt.Errorf("facilitation: no randomness for epoch %d: %s", epoch, msg)
	}
	if !out.Exists {
		return zero, fmt.Errorf("facilitation: epoch %d has not been submitted on-chain", epoch)
	}
	seed, err := ParseSeed(out.Randomness)
	if err != nil {
		return zero, err
	}
	if seed == zero {
		return zero, ErrNoSeed
	}
	return seed, nil
}
