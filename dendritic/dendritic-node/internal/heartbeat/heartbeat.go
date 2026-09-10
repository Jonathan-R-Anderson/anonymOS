// Package heartbeat sends the node's signed presence beacon to the Syndichan
// frontend.
//
// It is deliberately the one connection that does not go through I2P: the
// frontend has to see a real source address to count unique nodes and to place
// them on the operator's map. That is the same address the web server already
// logs when the operator visits the site.
//
// Every role that has a persistent node identity sends it -- a storage node, a
// dedicated gateway, or a probe. A gateway that stores nothing reports zero
// capacity, which is how the frontend tells "gateway" apart from "storage"
// rather than a separate message type.
package heartbeat

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/gateway"
)

const (
	// UserAgent identifies the client to the frontend, which rejects anything
	// else on the heartbeat endpoint.
	UserAgent = "Syndichan-Storage-Client/1.0"
	// Interval matches the five-minute presence window the frontend documents.
	Interval = 5 * time.Minute
	// Endpoint is the production presence endpoint.
	Endpoint = "https://syndichan.org/api/v1/storage/nodes/heartbeat"

	maxResponseBytes = 64 << 10
)

// Signer is the persistent node identity. Both a full p2p node and a
// standalone gateway identity satisfy it.
type Signer interface {
	ID() string
	Sign([]byte) ([]byte, error)
}

type logf interface{ Printf(string, ...any) }

// State is what the node currently is, sampled fresh on every send so a
// gateway that gains or loses verification is reflected within one interval.
type State struct {
	CapacityBytes int64
	// UsedBytes is how much this node is ACTUALLY holding, not how much it
	// offered. The coordinator had capacity and no usage, so it could see how
	// big each pool was and nothing about how full -- which makes levelling the
	// pools impossible to even plan, let alone verify. See
	// roadmap/dht-storage-roadmap.md phase 2b.
	//
	// Measured from disk rather than from the placement ledger: the ledger
	// records intent and disk records fact, they diverge on a failed delete or a
	// manual removal, and levelling toward a fiction moves real bytes.
	UsedBytes int64
	// Draining is true when the operator is retiring this machine. The DHT
	// capacity record is what makes OWNERS act on it (they are the ones that can
	// move a shard); this copy is so the coordinator's own report does not go on
	// proposing a node as a destination while the fleet has stopped using it as
	// one, and so the operator of the site can see which machines are leaving.
	Draining        bool
	GatewayEnabled  bool
	GatewayVerified bool
	Registration    *gateway.Registration
	// DCSWorker is true when this node accepts container deployments (dcs.enabled
	// + role.worker). It is what makes the node draw its yellow role on the
	// operator's map and marks it as a container host on the network.
	DCSWorker bool
	// Monitor is true when this node runs the status monitor. Reported so the
	// operator's map can draw the role, and so they can see how many vantage
	// points the status page actually has -- a page measured from one place
	// cannot tell "the site is down" from "unreachable from that machine".
	Monitor bool

	// GPUCompute and CPUCompute are the operator's two compute switches, as
	// configured — not whether a job happens to be running right now. See the
	// payload fields for why availability rather than activity.
	GPUCompute bool
	CPUCompute bool
	// MicroVM is measured, never configured: an operator cannot declare
	// hardware isolation they do not have.
	MicroVM bool
	// I2PDestination is the node's own base32 garlic destination. Reported so the
	// coordinator can hand this node out to others as a LIVE bootstrap peer,
	// instead of the network relying on a single hardcoded one.
	I2PDestination string
	// Traffic this node moved since the last beacon. Summed across nodes to
	// give the public status page a network throughput figure -- which the
	// frontend cannot measure itself, because it never sees peer-to-peer shard
	// transfers at all.
	Traffic Traffic
	// Placement is whether dispersal is WORKING on this node, as opposed to what
	// it holds. NIL when the node has nothing to say -- no pass has completed, or
	// this build has no storage role -- and nil is sent as an absent field, never
	// as zeros. See the Placement type.
	Placement *Placement
}

// Placement is this node's account of whether dispersal is working.
//
// WHY THE HEARTBEAT AND NOT A NEW ENDPOINT
// ----------------------------------------
// The alternative is the gateway's SigV4 ?placement surface, which already
// answers all of this per object. But the coordinator would then have to ask
// nine nodes over I2P to draw one admin page, inside a request handler, on a
// panel that polls every three seconds -- and this site has already taken a 504
// from exactly that shape (an inline sync in GET /). The heartbeat is a
// background push that is already signed, already arrives every five minutes
// from every node, and already carries capacity and usage. Putting a summary on
// it means the admin request path reads a database row and nothing else.
//
// ?placement stays where per-object detail belongs. This is the summary; that is
// the drill-down. Nothing new was invented for either.
//
// KEPT SMALL DELIBERATELY: every node on the network signs and sends this every
// five minutes. Counters, and at most maxReportedRefusals refusing peers.
type Placement struct {
	Objects         int `json:"objects"`
	UnderReplicated int `json:"under_replicated"`
	LocalOnly       int `json:"local_only"`
	FullyDispersed  int `json:"fully_dispersed"`
	// The last pass, shard by shard. "placed 0, failed 9" was the signature of
	// lease requests dying before they left the box, and it never reached anyone
	// who was not tailing a journal.
	Placed       int `json:"placed"`
	Failed       int `json:"failed"`
	Unassignable int `json:"unassignable"`
	Attempted    int `json:"attempted"`
	// Connected peers at the time of the pass. Zero placements with no peers is
	// an isolated node; zero placements with nine peers is a node being refused.
	Peers int `json:"peers"`
	// How long ago the pass ran. Sent as an age rather than a timestamp so it
	// needs no agreement about clocks: the node's own clock measures its own
	// interval, and a node that has stopped passing goes visibly stale.
	AgeSeconds int `json:"age_seconds"`
	// Pointers, and omitted when nil: the recall ledger may not be readable, and
	// "unreadable" must not arrive as "nothing outstanding".
	RecallsOutstanding *int `json:"recalls_outstanding,omitempty"`
	RecallsDeferred    *int `json:"recalls_deferred,omitempty"`
	RecallsUnreadable  *int `json:"recalls_unreadable,omitempty"`
	// Who is refusing, and WHAT THEY SAID. The reason is the entire point: "3
	// failures" sends an operator to a journal, "3 failures: storage capacity
	// exceeded" is a fix. Omitted when nobody is refusing.
	Refusals []Refusal `json:"refusals,omitempty"`
}

// Refusal is one peer that answered no, and its answer.
type Refusal struct {
	Peer   string `json:"peer"`
	Count  int    `json:"count"`
	Reason string `json:"reason"`
}

// Traffic is a WINDOW, never a lifetime counter.
//
// A cumulative counter has to be differenced against the previous beacon to
// become a rate, and it resets to zero when the node restarts -- which reads as
// a large negative delta, i.e. as an enormous burst of traffic at exactly the
// moment a node is flapping. Reporting "what moved in the last N seconds" makes
// a restart worth nothing instead of worth a spike.
type Traffic struct {
	Bytes         int64 `json:"bytes"`
	Requests      int   `json:"requests"`
	WindowSeconds int   `json:"window_seconds"`
}

type request struct {
	Version       int    `json:"version"`
	NodeID        string `json:"node_id"`
	Timestamp     int64  `json:"timestamp"`
	Nonce         string `json:"nonce"`
	CapacityBytes int64  `json:"capacity_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
	// Omitted when false so a node that is not retiring puts exactly the bytes on
	// the wire it always has. The signature covers the marshalled body, so an
	// added field is safe in both directions: a coordinator that does not know it
	// still verifies, and simply ignores the key.
	Draining            bool                  `json:"draining,omitempty"`
	Platform            string                `json:"platform"`
	GatewayEnabled      bool                  `json:"gateway_enabled"`
	GatewayVerified     bool                  `json:"gateway_verified"`
	GatewayRegistration *gateway.Registration `json:"gateway_registration,omitempty"`
	DCSWorker           bool                  `json:"dcs_worker"`
	Monitor             bool                  `json:"monitor"`
	// What this node lends to the compute network. Reported separately because
	// they are separate offers, and because the coordinator draws them as
	// separate roles — a machine lending both should show as both rather than
	// be collapsed into one "compute" dot.
	//
	// AVAILABLE, not busy. A node paused by its own governor because the owner
	// started a game is still a provider, and dropping it while paused would
	// make the network look like it collapses every evening.
	GPUCompute bool `json:"gpu_compute"`
	CPUCompute bool `json:"cpu_compute"`
	// MicroVM decides whether ARBITRARY submitted code may be placed here. A
	// container node runs signed catalogue images only, and spare capacity does
	// not change that — so it is a capability, not a compute detail.
	MicroVM        bool   `json:"microvm"`
	I2PDestination string `json:"i2p_destination,omitempty"`
	// Omitted entirely when the window is zero: the coordinator distinguishes
	// "not reporting" from "reported nothing", and sending zeros would claim
	// the second when the first is true.
	Traffic *Traffic `json:"traffic,omitempty"`
	// Omitted for exactly the same reason, and it matters more here. A node with
	// no completed dispersal pass sends no block at all, so the coordinator can
	// render "not reporting" -- drawing an unmeasured node as one with zero
	// failures is the single failure shape this whole field exists to end.
	Placement *Placement `json:"placement,omitempty"`
}

// Client posts the signed beacon. Endpoint and HTTP are injected so tests can
// point at a local server and so the caller controls the transport -- in
// particular that it has no proxy configured.
type Client struct {
	Signer   Signer
	Endpoint string
	HTTP     *http.Client
	Logger   logf
	// Snapshot reports the current state at send time.
	Snapshot func() State
	// OnPeers, if set, receives the bootstrap peer multiaddrs the coordinator
	// returns in the heartbeat response. This is the live bootstrap service: the
	// node reports its own destination and is handed a few reachable peers back,
	// so it can keep heartbeating until it joins the DHT and stay joined after.
	OnPeers func([]string)
}

// DirectHTTPClient is the transport a heartbeat must use: no proxy, so neither
// I2P nor HTTP(S)_PROXY environment variables can redirect the one request
// whose whole purpose is to originate from the node's real address.
func DirectHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// Run sends immediately, then every Interval until ctx is cancelled. Sending
// at once means a freshly started gateway appears on the operator's map
// without waiting out a full interval.
func (c *Client) Run(ctx context.Context) {
	c.Send(ctx)
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Send(ctx)
		}
	}
}

// Send posts one beacon. Failures are logged and swallowed: presence
// reporting is never allowed to take down a running node.
func (c *Client) Send(ctx context.Context) {
	if c.Signer == nil {
		return
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return
	}
	state := State{}
	if c.Snapshot != nil {
		state = c.Snapshot()
	}
	payload := request{
		Version: 1, NodeID: c.Signer.ID(), Timestamp: time.Now().UTC().Unix(),
		Nonce:          base64.RawURLEncoding.EncodeToString(nonceBytes),
		CapacityBytes:  state.CapacityBytes,
		UsedBytes:      state.UsedBytes,
		Draining:       state.Draining,
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
		GatewayEnabled: state.GatewayEnabled,
		// A registration is attached only when the node genuinely holds one;
		// the frontend re-validates it before showing a gateway role.
		GatewayVerified:     state.GatewayVerified,
		GatewayRegistration: state.Registration,
		DCSWorker:           state.DCSWorker,
		GPUCompute:          state.GPUCompute,
		CPUCompute:          state.CPUCompute,
		MicroVM:             state.MicroVM,
		Monitor:             state.Monitor,
		I2PDestination:      state.I2PDestination,
	}
	// Sent only when there is a window to divide by. A zero window is not a
	// rate of zero -- it is the absence of a measurement, and the coordinator
	// draws them differently on the status page.
	if state.Traffic.WindowSeconds > 0 {
		traffic := state.Traffic
		payload.Traffic = &traffic
	}
	// Attached only when the node has actually observed a pass. A nil State
	// field stays a missing JSON key; see the field comment on request.Placement.
	payload.Placement = state.Placement
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	signature, err := c.Signer.Sign(body)
	if err != nil {
		c.logf("heartbeat signing failed: %v", err)
		return
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = Endpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Syndichan-Node", payload.NodeID)
	req.Header.Set("X-Syndichan-Signature", base64.RawStdEncoding.EncodeToString(signature))
	client := c.HTTP
	if client == nil {
		client = DirectHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		c.logf("heartbeat unavailable: %v", err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		c.logf("heartbeat returned HTTP %d", resp.StatusCode)
		return
	}
	// The response carries the bootstrap peers the coordinator picked for us.
	// It is fine for this list to be short or empty -- the coordinator returns
	// whatever live peers it can find, and we simply try again next interval.
	if c.OnPeers != nil {
		var reply struct {
			BootstrapPeers []string `json:"bootstrap_peers"`
		}
		if err := json.Unmarshal(respBody, &reply); err == nil && len(reply.BootstrapPeers) > 0 {
			c.OnPeers(reply.BootstrapPeers)
		}
	}
}

func (c *Client) logf(format string, args ...any) {
	if c.Logger != nil {
		c.Logger.Printf(format, args...)
	}
}
