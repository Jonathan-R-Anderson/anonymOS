package facilitation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Which epoch is "now".
//
// A node cannot answer that from its clock alone. EpochManager counts epochs
// from the genesis epoch it was given — 0 — while unix/3600 is a number in the
// hundreds of thousands. Both are "the current epoch" under a different origin,
// and they never meet: a node counting from the clock asks the chain for the
// randomness of an epoch that will not exist for fifty years, gets nothing, and
// sits out every pass while looking perfectly healthy in its logs.
//
// So the origin is published once, by the site, and everyone counts from it.
// The anchor is not a trust concession: it names a public on-chain fact (the
// epoch genesis was submitted as, and when) that any node can check against
// EpochManager itself.

// EpochAnchor pins epoch numbers to the chain's own numbering.
type EpochAnchor struct {
	// Epoch is the number the chain gave the genesis epoch.
	Epoch uint64 `json:"epoch"`
	// At is when that epoch began, in unix seconds.
	At int64 `json:"epoch_anchor"`
	// Seconds is how long one epoch lasts.
	Seconds uint64 `json:"epoch_seconds"`
}

// Valid reports whether this anchor can place a time on the epoch line. An
// anchor missing any part is unusable rather than partially usable: a zero
// length would divide by zero and a zero timestamp would put genesis in 1970,
// which is worse than waiting for a good answer.
func (a EpochAnchor) Valid() bool { return a.At > 0 && a.Seconds > 0 }

// EpochAt maps wall-clock time onto the chain's epoch numbering.
//
// Times before the anchor return the genesis epoch rather than counting
// backwards: a node whose clock is behind should audit the first epoch, not an
// epoch that never existed.
func (a EpochAnchor) EpochAt(t time.Time) uint64 {
	if !a.Valid() {
		return 0
	}
	now := t.Unix()
	if now <= a.At {
		return a.Epoch
	}
	return a.Epoch + uint64(now-a.At)/a.Seconds
}

// StartOf returns when an epoch began, which is what a node needs to know how
// long it has left to finish its duties.
func (a EpochAnchor) StartOf(epoch uint64) time.Time {
	if !a.Valid() || epoch < a.Epoch {
		return time.Unix(a.At, 0)
	}
	return time.Unix(a.At+int64((epoch-a.Epoch)*a.Seconds), 0)
}

type anchorResponse struct {
	Armed   bool   `json:"armed"`
	Epoch   uint64 `json:"epoch"`
	At      int64  `json:"epoch_anchor"`
	Seconds uint64 `json:"epoch_seconds"`
	Error   string `json:"error"`
}

// FetchEpochAnchor reads the published anchor.
//
// Returns an error while genesis is unarmed rather than a default anchor: a
// network with no genesis has no epochs, and inventing one locally would put
// this node on a timeline of its own.
func (c *GatewayClient) FetchEpochAnchor(ctx context.Context) (EpochAnchor, error) {
	var zero EpochAnchor
	url := strings.TrimSuffix(c.BaseURL, "/") + "/api/v1/pof/genesis-seed"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return zero, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return zero, fmt.Errorf("facilitation: epoch anchor unreachable: %w", err)
	}
	defer resp.Body.Close()

	var out anchorResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 400 || !out.Armed {
		msg := out.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return zero, fmt.Errorf("facilitation: no epoch anchor yet: %s", msg)
	}
	anchor := EpochAnchor{Epoch: out.Epoch, At: out.At, Seconds: out.Seconds}
	if !anchor.Valid() {
		return zero, fmt.Errorf("facilitation: epoch anchor is incomplete (at=%d seconds=%d)",
			anchor.At, anchor.Seconds)
	}
	return anchor, nil
}
