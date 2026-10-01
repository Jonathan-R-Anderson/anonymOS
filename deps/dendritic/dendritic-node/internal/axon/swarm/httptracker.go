package swarm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// HTTPTracker is the origin server's tracker (cmd/hos-origin swarm.go), spoken
// over whatever Client carries it -- in the OS, an http.Client whose transport
// dials a stream on the session to the origin's AXON service.
type HTTPTracker struct {
	Client *http.Client
	Base   string // e.g. "http://origin.anonymous.axon"
}

func (h HTTPTracker) url(root [32]byte, tail string) string {
	return h.Base + "/api/v1/swarm/" + hex.EncodeToString(root[:]) + tail
}

func (h HTTPTracker) Announce(ctx context.Context, root [32]byte, self PeerAddr, complete bool) error {
	body, _ := json.Marshal(map[string]any{"addr": self, "complete": complete})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url(root, "/announce"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("axon/swarm: announce: %s", resp.Status)
	}
	return nil
}

func (h HTTPTracker) Peers(ctx context.Context, root [32]byte, max int) ([]PeerAddr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url(root, "/peers?max="+strconv.Itoa(max)), nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("axon/swarm: peers: %s", resp.Status)
	}
	var out struct {
		Peers []PeerAddr `json:"peers"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Peers) > max {
		out.Peers = out.Peers[:max]
	}
	return out.Peers, nil
}
