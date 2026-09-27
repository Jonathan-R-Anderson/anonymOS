package main

// Compute across the peer network, from both ends.
//
// TWO HALVES, AND THEY RUN ON DIFFERENT MACHINES
// ----------------------------------------------
// peerComputeHandler is the RECEIVING half, installed on a volunteer that lends
// a device: it answers a compute frame that arrived over libp2p/I2P.
//
// handleComputePeer is the RELAYING half, served on the same loopback listener
// as everything else in dcsapi.go: it takes a target peer plus a job from the
// co-located site and carries it over libp2p, returning that peer's answer.
//
// The two are here together because they are one path, and the path exists
// because the site cannot speak libp2p and a volunteer cannot be dialled. What
// runs in production is:
//
//	site --plain HTTP--> its own node --libp2p/I2P--> volunteer node
//	   handleComputePeer  ^                            ^ peerComputeHandler
//
// The relay is registered whether or not this node lends compute itself. The
// node the site talks to is a relay, not a worker: it typically has compute
// switched off entirely, and gating the relay on that would disable the feature
// on precisely the machine that has to provide it.
//
// WHY THE RECEIVER REPLAYS ITS OWN HTTP HANDLERS
// ----------------------------------------------
// Rather than a second implementation of admit/submit/result, a compute frame
// is served through the exact handlers /compute/admit|submit|result serve, with
// an in-memory ResponseWriter collecting the answer. The catalogue rule, the
// operator's workload consent, the isolation rule, the governor and the memory
// cap are then not "also applied" on the peer path — they are the same code,
// and cannot drift from it. The status code is carried through for the same
// reason: the site already distinguishes a 503 decline from a 400 bad request
// from a 404 unknown job, and re-deriving those from an error string would lose
// exactly the distinctions it acts on.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/p2p"
)

// peerHeader names the peer a compute request arrived from, on the synthetic
// request handed to the HTTP handlers. Absent for loopback callers, which is
// what keeps the site's own behaviour exactly as it was.
const peerHeader = "X-Syndichan-Peer"

// computeRelayTimeout bounds one relayed exchange at this node.
//
// The site has its own, shorter timeout and will give up first; this one exists
// so a peer that accepts a stream and then goes quiet cannot hold a relay
// goroutine for ever after the site has already stopped listening.
const computeRelayTimeout = 2 * time.Minute

// relayOperations maps the URL a site calls to the verb that goes on the wire.
// A closed table: an unknown suffix is a 404 here rather than an operation name
// forwarded to a peer.
var relayOperations = map[string]string{
	"admit":  p2p.ComputeAdmit,
	"submit": p2p.ComputeSubmit,
	"result": p2p.ComputeResult,
}

// startComputePeerService builds this node's compute API and makes it reachable
// from OTHER NODES, returning the API so the loopback bridge can serve the same
// object rather than construct a second one (which would mean a second Docker
// client and two independent result maps).
//
// Deliberately not inside startDCSBridge: that runs only when dcs.api_listen is
// set, and a volunteer lending a CPU has no reason to have configured a bridge
// for a site it does not host. Gating peer-reachable compute on it would leave
// such a node advertising a device nothing could ever dispatch to.
func startComputePeerService(cfg config.Config, node *p2p.Node, logger *log.Logger) *computeAPI {
	api := newComputeAPI(cfg, logger)
	if api == nil || node == nil {
		return api
	}
	node.SetComputeHandler(api.peerComputeHandler())
	logger.Printf("compute: reachable from peers over the storage protocol (cpu=%v gpu=%v)",
		cfg.Compute.OfferCPU, cfg.Compute.OfferGPU)
	return api
}

// peerComputeHandler answers a compute frame by serving it through this node's
// own HTTP handlers. See the file comment for why it replays them rather than
// reimplementing them.
func (c *computeAPI) peerComputeHandler() p2p.ComputeHandler {
	routes := map[string]http.HandlerFunc{
		p2p.ComputeAdmit:  c.handleAdmit,
		p2p.ComputeSubmit: c.handleSubmit,
		p2p.ComputeResult: c.handleResult,
	}
	return func(ctx context.Context, from peer.ID, operation string, payload []byte) (int, []byte) {
		route, known := routes[operation]
		if !known {
			return http.StatusBadRequest, refusalJSON("unsupported compute operation: " + operation)
		}
		// A synthetic request, POST because that is what these handlers require.
		// The host is never resolved -- nothing dials it -- it exists so the URL
		// parses and so a log line naming it cannot be mistaken for a real one.
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"http://peer.invalid/"+operation, bytes.NewReader(payload))
		if err != nil {
			return http.StatusBadRequest, refusalJSON("malformed compute request: " + err.Error())
		}
		req.Header.Set("Content-Type", "application/json")
		// Who asked. Read by submitterKey so one peer cannot poll another's job
		// id and collect its result -- job ids are the site's small integers, so
		// without this a stranger guessing "11" would be handed whatever job 11
		// produced for somebody else.
		if id := from.String(); id != "" {
			req.Header.Set(peerHeader, id)
		}
		rec := &bufferedResponse{headers: http.Header{}, status: http.StatusOK}
		route(rec, req)
		return rec.status, rec.body.Bytes()
	}
}

// bufferedResponse is an http.ResponseWriter that keeps the answer instead of
// sending it. Small on purpose: the handlers use only Header, WriteHeader and
// Write, and anything more would be inventing behaviour the real server has.
type bufferedResponse struct {
	headers http.Header
	status  int
	body    bytes.Buffer
	written bool
}

func (b *bufferedResponse) Header() http.Header { return b.headers }

func (b *bufferedResponse) WriteHeader(code int) {
	// First call wins, as net/http does: a handler that writes a body and then
	// tries to set a status must not silently change the answer already given.
	if b.written {
		return
	}
	b.written = true
	b.status = code
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	if !b.written {
		b.WriteHeader(http.StatusOK)
	}
	return b.body.Write(p)
}

// refusalJSON is the shape the site reads off every declined compute answer.
func refusalJSON(reason string) []byte {
	body, err := json.Marshal(map[string]any{
		"admitted": false, "accepted": false, "reason": reason, "retryable": false,
	})
	if err != nil {
		return []byte(`{"admitted":false,"accepted":false,"retryable":false,` +
			`"reason":"the node refused the request"}`)
	}
	return body
}

// computeRelayRequest is what the site posts to the relay.
//
// The job itself is carried OPAQUELY in Request, forwarded byte for byte. The
// relay does not parse it, which means the site can add a field the relay has
// never heard of and the receiving node will still see it -- the same property
// that let workloads reach nodes built before workloads existed.
type computeRelayRequest struct {
	// Peer is the target node's libp2p id: the identity the Noise handshake
	// proves, and therefore the only part of this that decides WHO runs the job.
	Peer string `json:"peer"`
	// Destination is that node's garlic address, from its own heartbeat. A
	// dialling hint only -- a wrong one produces a failed dial, never a
	// conversation with the wrong node -- and omitted when the relay is already
	// connected to the peer.
	Destination string `json:"destination"`
	// Request is the exact body the peer's /compute/<verb> endpoint would take.
	Request json.RawMessage `json:"request"`
}

// handleComputePeer relays one compute request to a named peer.
//
// THE ONE THING THIS MUST NOT GET WRONG: a peer that declined and a peer that
// could not be reached are different facts, and the site charges a job
// differently for each. Everything the peer says comes back with the peer's own
// status. A failure to reach it comes back marked `"unreachable": true`,
// because a status alone cannot carry it -- the site reads 5xx as "the node
// declined", so a bare 502 here would silently convert every dial failure into
// a refusal and leave the job looking answered.
func (api *bridgeAPI) handleComputePeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	verb := strings.Trim(strings.TrimPrefix(r.URL.Path, "/compute/peer"), "/")
	operation, known := relayOperations[verb]
	if !known {
		writeErr(w, http.StatusNotFound, "unknown compute relay operation: "+verb)
		return
	}
	// Read with its own limit rather than through decode(), whose 1 MB ceiling
	// is right for a deploy request and wrong for a job carrying files.
	raw, err := io.ReadAll(io.LimitReader(r.Body, p2p.MaxComputePayload+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if int64(len(raw)) > p2p.MaxComputePayload {
		writeErr(w, http.StatusRequestEntityTooLarge, "compute request too large")
		return
	}
	var req computeRelayRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	target, err := peer.Decode(strings.TrimSpace(req.Peer))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid peer id: "+err.Error())
		return
	}
	if len(req.Request) == 0 {
		req.Request = json.RawMessage("{}")
	}
	// Checked HERE, before the dial. An oversized job will not fit however many
	// times it is asked, so it must reach the site as a request error it will
	// not retry -- reporting it as unreachability would queue it for ever.
	if limit := p2p.MaxComputeRequest(operation); int64(len(req.Request)) > limit {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
			"compute %s payload is %d bytes, over the %d byte limit",
			verb, len(req.Request), limit))
		return
	}
	if dest := strings.TrimSpace(req.Destination); dest != "" {
		if err := api.peers.AddPeerDestination(target, dest); err != nil {
			// Not fatal: the relay may already be connected to this peer, in
			// which case the dial works and the bad hint never mattered.
			api.logger.Printf("dcs-bridge: compute relay: %s advertised an undialable destination: %v",
				target, err)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), computeRelayTimeout)
	defer cancel()
	status, body, err := api.peers.SendCompute(ctx, target, operation, req.Request)
	if err != nil {
		writeJSON(w, http.StatusGatewayTimeout, map[string]any{
			"unreachable": true,
			"error": "could not reach " + target.String() +
				" over the peer network: " + err.Error(),
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
