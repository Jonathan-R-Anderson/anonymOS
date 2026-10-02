package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// The coordinator: what a dendritic node asks its coordinator for -- the signed bootstrap
// document, the heartbeat that is answered with live peers, the peer list.  Formats and checks
// follow the node's own client (internal/bootstrap, internal/heartbeat) so the node needs only
// its endpoints and pinned coordinator key changed.

const (
	storageUserAgent  = "Rabbiit-Storage-Client/1.0"
	bootstrapPrefix   = "rabbiit-storage-bootstrap-v1"
	activeWindow      = 15 * time.Minute
	bootstrapLifetime = 20 * time.Minute
	maxClockSkew      = 300 // seconds
	maxCapacityBytes  = int64(8) << 50
	maxHeartbeatBytes = 65536
)

var (
	reDestination = regexp.MustCompile(`^[a-z2-7]{52}$`)
	rePlatform    = regexp.MustCompile(`^[a-z0-9_-]{1,24}/[a-z0-9_-]{1,24}$`)
	reBootstrap   = regexp.MustCompile(`^/garlic32/[a-z2-7]{52}/p2p/[1-9A-HJ-NP-Za-km-z]+$`)
)

// NodeRecord is what the coordinator remembers about a node: its own heartbeat, nothing else.
// Nodes reach the origin over I2P, so there is no IP address to remember.
type NodeRecord struct {
	NodeID         string    `json:"node_id"`
	Destination    string    `json:"i2p_destination,omitempty"`
	CapacityBytes  int64     `json:"capacity_bytes"`
	UsedBytes      *int64    `json:"used_bytes,omitempty"`
	Platform       string    `json:"platform"`
	GatewayEnabled bool      `json:"gateway_enabled"`
	CPUCompute     bool      `json:"cpu_compute"`
	GPUCompute     bool      `json:"gpu_compute"`
	MicroVM        bool      `json:"microvm"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
}

type Coordinator struct {
	key   ed25519.PrivateKey
	seeds []string // configured bootstrap multiaddrs (the origin's own node, at least)

	mu     sync.Mutex
	nodes  map[string]*NodeRecord
	nonces map[string]time.Time // replay guard: nonce -> when seen
	store  *Store
	now    func() time.Time
}

func NewCoordinator(key ed25519.PrivateKey, seeds []string, store *Store) *Coordinator {
	c := &Coordinator{key: key, seeds: seeds, nodes: map[string]*NodeRecord{}, nonces: map[string]time.Time{},
		store: store, now: time.Now}
	if store != nil {
		var saved []*NodeRecord
		if store.LoadJSON("nodes.json", &saved) == nil {
			for _, n := range saved {
				c.nodes[n.NodeID] = n
			}
		}
	}
	return c
}

func (c *Coordinator) PublicKeyB64() string {
	return strings.TrimRight(base64.StdEncoding.EncodeToString(c.key.Public().(ed25519.PublicKey)), "=")
}

// heartbeat is the node's beacon (internal/heartbeat.Payload), only the fields the coordinator uses.
type heartbeat struct {
	Version        int    `json:"version"`
	NodeID         string `json:"node_id"`
	Timestamp      *int64 `json:"timestamp"`
	Nonce          string `json:"nonce"`
	CapacityBytes  *int64 `json:"capacity_bytes"`
	UsedBytes      *int64 `json:"used_bytes"`
	Platform       string `json:"platform"`
	GatewayEnabled bool   `json:"gateway_enabled"`
	CPUCompute     bool   `json:"cpu_compute"`
	GPUCompute     bool   `json:"gpu_compute"`
	MicroVM        bool   `json:"microvm"`
	I2PDestination string `json:"i2p_destination"`
}

var (
	errForbidden = errors.New("forbidden")
)

type httpError struct {
	status int
	msg    string
}

func (e httpError) Error() string { return e.msg }

// ValidateHeartbeat checks a signed beacon as the original coordinator did: the user agent, the
// node's Ed25519 signature over the raw body (the key is the peer ID), clock skew, nonce replay
// and value ranges.
func (c *Coordinator) ValidateHeartbeat(body []byte, nodeHeader, sigHeader, userAgent string) (*heartbeat, error) {
	if userAgent != storageUserAgent {
		return nil, httpError{403, "invalid storage client user agent"}
	}
	if len(body) > maxHeartbeatBytes {
		return nil, httpError{400, "heartbeat is too large"}
	}
	var hb heartbeat
	if err := json.Unmarshal(body, &hb); err != nil {
		return nil, httpError{400, "heartbeat is not valid JSON"}
	}
	if hb.Version != 1 {
		return nil, httpError{400, "unsupported heartbeat version"}
	}
	if hb.NodeID == "" || hb.NodeID != nodeHeader {
		return nil, httpError{403, "heartbeat node identity mismatch"}
	}
	pub, err := peerPublicKey(hb.NodeID)
	if err != nil {
		return nil, httpError{403, "invalid heartbeat identity signature"}
	}
	sig, err := decodeB64(sigHeader)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, body, sig) {
		return nil, httpError{403, "invalid heartbeat identity signature"}
	}
	now := c.now().Unix()
	if hb.Timestamp == nil || abs64(now-*hb.Timestamp) > maxClockSkew {
		return nil, httpError{400, "heartbeat timestamp is outside the allowed clock skew"}
	}
	if len(hb.Nonce) < 16 || len(hb.Nonce) > 128 {
		return nil, httpError{400, "invalid heartbeat nonce"}
	}
	if hb.CapacityBytes == nil {
		return nil, httpError{400, "invalid storage capacity"}
	}
	if capB := *hb.CapacityBytes; capB != 0 && (capB < 64<<20 || capB > maxCapacityBytes) {
		return nil, httpError{400, "invalid storage capacity"}
	}
	if hb.UsedBytes != nil && *hb.UsedBytes < 0 {
		hb.UsedBytes = nil
	}
	if !rePlatform.MatchString(hb.Platform) {
		return nil, httpError{400, "invalid storage platform"}
	}
	if hb.I2PDestination != "" && !reDestination.MatchString(hb.I2PDestination) {
		return nil, httpError{400, "invalid i2p destination"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := hb.NodeID + "\x00" + hb.Nonce
	if _, seen := c.nonces[key]; seen {
		return nil, httpError{400, "heartbeat nonce replayed"}
	}
	c.nonces[key] = c.now()
	for k, t := range c.nonces {
		if c.now().Sub(t) > 2*maxClockSkew*time.Second {
			delete(c.nonces, k)
		}
	}
	return &hb, nil
}

// Record stores a validated heartbeat.
func (c *Coordinator) Record(hb *heartbeat) {
	c.mu.Lock()
	n := c.nodes[hb.NodeID]
	now := c.now().UTC()
	if n == nil {
		n = &NodeRecord{NodeID: hb.NodeID, FirstSeen: now}
		c.nodes[hb.NodeID] = n
	}
	if hb.I2PDestination != "" {
		n.Destination = hb.I2PDestination
	}
	n.CapacityBytes = *hb.CapacityBytes
	n.UsedBytes = hb.UsedBytes
	n.Platform = hb.Platform
	n.GatewayEnabled = hb.GatewayEnabled
	n.CPUCompute, n.GPUCompute, n.MicroVM = hb.CPUCompute, hb.GPUCompute, hb.MicroVM
	n.LastSeen = now
	snapshot := c.snapshotLocked()
	c.mu.Unlock()
	if c.store != nil {
		_ = c.store.SaveJSON("nodes.json", snapshot)
	}
}

func (c *Coordinator) snapshotLocked() []*NodeRecord {
	out := make([]*NodeRecord, 0, len(c.nodes))
	for _, n := range c.nodes {
		cp := *n
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// LivePeers returns up to limit bootstrap multiaddrs of nodes heartbeating now, random order,
// excluding one node (the requester).
func (c *Coordinator) LivePeers(limit int, exclude string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := c.now().Add(-activeWindow)
	var peers []string
	for _, n := range c.nodes {
		if n.NodeID == exclude || n.Destination == "" || n.LastSeen.Before(cutoff) {
			continue
		}
		peers = append(peers, "/garlic32/"+n.Destination+"/p2p/"+n.NodeID)
	}
	rand.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
	if len(peers) > limit {
		peers = peers[:limit]
	}
	return peers
}

// ActiveCount is how many nodes heartbeated within the active window.
func (c *Coordinator) ActiveCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := c.now().Add(-activeWindow)
	k := 0
	for _, n := range c.nodes {
		if !n.LastSeen.Before(cutoff) {
			k++
		}
	}
	return k
}

// BootstrapMessage is the exact byte string signed over a bootstrap document (the node rebuilds
// it from the parsed fields; anything not in it is not covered).
func BootstrapMessage(peers []string, publicKey, expiresAt string) []byte {
	lines := []string{bootstrapPrefix, "expires_at: " + expiresAt, "coordinator: " + publicKey,
		fmt.Sprintf("peers: %d", len(peers))}
	lines = append(lines, peers...)
	return []byte(strings.Join(lines, "\n"))
}

type bootstrapDocument struct {
	Version              int           `json:"version"`
	Peers                []string      `json:"peers"`
	Compute              []computePeer `json:"compute"`
	CoordinatorPublicKey string        `json:"coordinator_public_key"`
	ExpiresAt            string        `json:"expires_at"`
	Signature            string        `json:"signature"`
}

type computePeer struct {
	NodeID      string `json:"node_id"`
	Destination string `json:"destination"`
	CPU         bool   `json:"cpu"`
	GPU         bool   `json:"gpu"`
	MicroVM     bool   `json:"microvm"`
}

// BootstrapDocument builds the signed document: live peers first, then the configured seeds
// (deduplicated, order preserved -- the order is signed).
func (c *Coordinator) BootstrapDocument() bootstrapDocument {
	peers := dedupe(append(c.LivePeers(8, ""), c.seeds...))
	expires := c.now().UTC().Add(bootstrapLifetime).Format("2006-01-02T15:04:05.000000Z")
	pub := c.PublicKeyB64()
	doc := bootstrapDocument{Version: 1, Peers: peers, Compute: c.computePeers(), CoordinatorPublicKey: pub,
		ExpiresAt: expires}
	if doc.Peers == nil {
		doc.Peers = []string{}
	}
	sig := ed25519.Sign(c.key, BootstrapMessage(doc.Peers, pub, expires))
	doc.Signature = base64.StdEncoding.EncodeToString(sig)
	return doc
}

func (c *Coordinator) computePeers() []computePeer {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := c.now().Add(-activeWindow)
	out := []computePeer{}
	for _, n := range c.nodes {
		if n.LastSeen.Before(cutoff) || n.Destination == "" || !(n.CPUCompute || n.GPUCompute) {
			continue
		}
		out = append(out, computePeer{NodeID: n.NodeID, Destination: n.Destination, CPU: n.CPUCompute,
			GPU: n.GPUCompute, MicroVM: n.MicroVM})
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// ── HTTP ────────────────────────────────────────────────────────────────────────────────────

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	noStore(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (c *Coordinator) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/rabbiit/storage-node.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, c.BootstrapDocument())
	})
	mux.HandleFunc("POST /api/v1/storage/nodes/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r, maxHeartbeatBytes)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		hb, err := c.ValidateHeartbeat(body, r.Header.Get("X-Rabbiit-Node"), r.Header.Get("X-Rabbiit-Signature"),
			r.Header.Get("User-Agent"))
		if err != nil {
			status := 400
			var he httpError
			if errors.As(err, &he) {
				status = he.status
			}
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		c.Record(hb)
		writeJSON(w, 200, map[string]any{
			"ok":                    true,
			"active_nodes":          c.ActiveCount(),
			"active_window_seconds": int(activeWindow / time.Second),
			"bootstrap_peers":       c.LivePeers(3, hb.NodeID),
		})
	})
	mux.HandleFunc("GET /api/v1/network/peers", func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		cutoff := c.now().Add(-activeWindow)
		type peerView struct {
			NodeID   string `json:"node_id"`
			Platform string `json:"platform"`
			Capacity int64  `json:"capacity_bytes"`
			Gateway  bool   `json:"gateway"`
		}
		var out []peerView
		for _, n := range c.nodes {
			if n.LastSeen.Before(cutoff) {
				continue
			}
			out = append(out, peerView{n.NodeID, n.Platform, n.CapacityBytes, n.GatewayEnabled})
		}
		c.mu.Unlock()
		sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
		writeJSON(w, 200, map[string]any{"peers": out, "active_window_seconds": int(activeWindow / time.Second)})
	})
}
