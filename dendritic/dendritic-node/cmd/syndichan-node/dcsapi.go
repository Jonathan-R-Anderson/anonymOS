package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/dcs"
	"github.com/syndichan/maniwani/storage-client/internal/p2p"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// This file is the BRIDGE: a small, loopback-only HTTP API that a website runs
// against so its users can deploy containers to the network without every user
// running a node. The site's backend (services/attack_range.py's NodeBridgeClient)
// is the only caller.
//
// Why a bridge and not one-node-per-user: the site has thousands of users and one
// I2P node. The node deploys on each user's behalf, sub-accounting them by an
// opaque "on_behalf_of" tag so the worker's one-container-per-user rule keys on
// the real user, not on the shared bridge identity. The worker trusts this node
// to name its sub-owners honestly because the operator put the bridge node's ID
// in the worker's TrustedBrokers list -- exactly the same trust boundary as a
// company deploying for its employees through one service account.
//
// It binds loopback (or a cluster-internal address the operator chooses) and is
// NOT authenticated at the HTTP layer: the deployment model is that only the
// co-located site process can reach it. Do not expose cfg.DCS.APIListen publicly.

// bridgeAPI holds the long-lived node substrate the HTTP handlers deploy through.
type bridgeAPI struct {
	node    *p2p.Node
	store   *store.Store
	manager *dcs.Manager
	blobs   dcs.BlobStore
	logger  *log.Logger
	// peers carries compute to ANOTHER node. It is the node itself in
	// production. An interface because the compute relay is almost entirely
	// about what it does with the two possible outcomes — the peer answered, the
	// peer could not be reached — and proving it keeps those apart should not
	// require an I2P router and two garlic tunnels.
	peers computePeer
}

// computePeer is the part of the node the compute relay uses.
type computePeer interface {
	AddPeerDestination(peer.ID, string) error
	SendCompute(ctx context.Context, target peer.ID, operation string, payload []byte) (int, []byte, error)
}

// startDCSBridge opens (reuses) the node and serves the loopback deploy API. It
// runs only when cfg.DCS.APIListen is set. Unlike the worker, the bridge does
// not need Docker -- it never runs a container itself; it asks workers to.
func startDCSBridge(ctx context.Context, cfg config.Config, node *p2p.Node, storage *store.Store, compute *computeAPI, logger *log.Logger) {
	if cfg.DCS.APIListen == "" {
		return
	}
	if node == nil || storage == nil {
		logger.Printf("dcs-bridge: API requires full storage mode (host + DHT + store); not started")
		return
	}
	if err := node.ConfigureDCSRecords(dcs.WorkerDHTValidator{}); err != nil {
		// Harmless if the worker path already registered it; only the first wins.
		logger.Printf("dcs-bridge: worker record validator: %v", err)
	}

	blobs := NewStoreBlobStore(storage)
	// Peer placement: capacity becomes a property of the network rather than of
	// whichever node received the write. Without this a full local store fails
	// the write outright, which is what made the DHT a directory of independent
	// disks instead of pooled storage.
	startBlobPlacement(ctx, node, storage, blobs, logger)

	api := &bridgeAPI{
		node:    node,
		store:   storage,
		manager: dcs.NewManager(node, dcs.NewStreamTransport(node.Host())),
		blobs:   blobs,
		logger:  logger,
		peers:   node,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", api.handleHealth)
	mux.HandleFunc("/dcs/blob", api.handleBlob) // PUT publish, GET/HEAD fetch
	// The trailing-slash pattern is what makes /dcs/blob/<digest> reach the
	// handler; "/dcs/blob" alone matches only the exact path.
	mux.HandleFunc("/dcs/blob/", api.handleBlob)
	mux.HandleFunc("/dcs/deploy", api.handleDeploy) // POST: deploy for a user
	mux.HandleFunc("/dcs/status", api.handleStatus) // POST: poll a queued deploy
	mux.HandleFunc("/dcs/destroy", api.handleDestroy)

	// Compute endpoints ride the same listener. Registered only when the
	// operator actually lends a device — a node that lends nothing should not
	// answer "would you take this?" at all, rather than answering "no" forever.
	// The API object is built by startComputePeerService and shared, so the
	// loopback caller and a peer see one node with one result map rather than
	// two independent ones that disagree about what is running.
	if compute != nil {
		mux.HandleFunc("/compute/admit", compute.handleAdmit)
		mux.HandleFunc("/compute/submit", compute.handleSubmit)
		mux.HandleFunc("/compute/result", compute.handleResult)
		logger.Printf("dcs-bridge: compute endpoints enabled (cpu=%v gpu=%v)",
			cfg.Compute.OfferCPU, cfg.Compute.OfferGPU)
	}
	// The compute RELAY: the same three verbs, aimed at a named peer and carried
	// over libp2p/I2P. This is how the site dispatches to volunteers, which it
	// cannot do itself — it speaks no libp2p, and a volunteer behind home NAT
	// has no address it could dial if it did.
	//
	// Registered UNCONDITIONALLY, unlike the endpoints above. The node the site
	// talks to is a relay, not a worker: it usually lends no device at all, and
	// gating the relay on `compute != nil` would switch the feature off on
	// exactly the machine that has to provide it.
	//
	// Authorisation is the listener's, not its own. Its neighbours here —
	// /dcs/deploy, which starts containers on remote workers, and /dcs/blob,
	// which writes to the DHT — are unauthenticated at the HTTP layer because
	// the deployment model is that only the co-located site process can reach
	// this address. Compute is a strictly weaker verb than deploy (it asks a
	// remote node to run a catalogue image its own policy already agreed to),
	// so a token here would protect nothing its neighbours do not already hand
	// out, while adding a second trust model to keep correct. Do not expose
	// dcs.api_listen publicly; that rule was already load-bearing.
	mux.HandleFunc("/compute/peer/", api.handleComputePeer)

	srv := &http.Server{
		Addr:              cfg.DCS.APIListen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", cfg.DCS.APIListen)
	if err != nil {
		logger.Printf("dcs-bridge: cannot listen on %s: %v", cfg.DCS.APIListen, err)
		return
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	go func() {
		logger.Printf("dcs-bridge: deploy API listening on %s (loopback/cluster-internal only)", cfg.DCS.APIListen)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Printf("dcs-bridge: serve: %v", err)
		}
	}()
}

func (api *bridgeAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"node": api.node.ID(),
	})
}

// handleBlob stores a pre-packed build context (a gzip tar produced by the site's
// lab_registry.pack_build_context) in the shard store and returns its digest. The
// blob is opaque, content-addressed bytes; storing it announces this node as a
// DHT provider so any worker can fetch it later by digest.
func (api *bridgeAPI) handleBlob(w http.ResponseWriter, r *http.Request) {
	// GET and HEAD complete the other half of a content-addressed store. Without
	// them a publisher can only assert that it once called PUT: nothing can read
	// a blob back to confirm it is still there and still correct. That gap is
	// why the site cannot reclaim the local copy of a build context it has
	// already published — it would be trading a copy it can verify for one it
	// cannot. HEAD exists so that check costs a lookup rather than a transfer.
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		api.serveBlob(w, r)
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use PUT, GET or HEAD")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, dcs.MaxBuildContextBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if int64(len(body)) > dcs.MaxBuildContextBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "build context too large")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	digest, err := api.blobs.PutBlob(ctx, body)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "store blob: "+err.Error())
		return
	}
	api.logger.Printf("dcs-bridge: published build context %s (%d bytes)", digest, len(body))
	writeJSON(w, http.StatusOK, map[string]any{"digest": digest, "size": len(body)})
}

// serveBlob answers GET and HEAD for a published build context.
//
// The digest is REVERIFIED against the bytes before they are returned. This is a
// content-addressed store, so handing back bytes that do not hash to what was
// asked for is worse than a miss: the caller would trust them. A mismatch means
// local corruption and is reported as such rather than as a 404, because the two
// need different responses from an operator.
//
// HEAD returns the same status and Content-Length with no body, so "is this
// still stored?" costs a lookup instead of a transfer — which is what makes it
// usable as a pre-flight check before reclaiming a local copy.
func (api *bridgeAPI) serveBlob(w http.ResponseWriter, r *http.Request) {
	digest := strings.TrimSpace(r.URL.Query().Get("digest"))
	if digest == "" {
		// Also accept /dcs/blob/<digest>, which is the friendlier shape for a
		// human with curl.
		digest = strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/dcs/blob"), "/")
	}
	if digest == "" {
		writeErr(w, http.StatusBadRequest, "digest required: /dcs/blob?digest=sha256:...")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	body, err := api.blobs.GetBlob(ctx, digest)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such blob: "+err.Error())
		return
	}
	if actual := dcs.BlobDigest(body); actual != digest {
		api.logger.Printf("dcs-bridge: blob %s hashes to %s — stored copy is corrupt",
			digest, actual)
		writeErr(w, http.StatusInternalServerError, "stored blob does not match its digest")
		return
	}

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("ETag", `"`+digest+`"`)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := w.Write(body); err != nil {
		api.logger.Printf("dcs-bridge: writing blob %s failed: %v", digest, err)
	}
}

// deployBody is the site's deploy request. Exactly one of image / build_context_digest
// is set. on_behalf_of is the site user id the worker sub-accounts by.
type deployBody struct {
	DeploymentID       string `json:"deployment_id"`
	Image              string `json:"image,omitempty"`
	BuildContextDigest string `json:"build_context_digest,omitempty"`
	Lab                bool   `json:"lab,omitempty"`
	Kind               string `json:"kind,omitempty"` // "" | "dockerfile" | "compose"
	PrimaryPort        int    `json:"primary_port,omitempty"`
	RuntimeSecs        int    `json:"runtime_secs,omitempty"`
	OnBehalfOf         string `json:"on_behalf_of"`
	Ticket             string `json:"ticket,omitempty"` // set when re-polling a queued deploy
	// When re-polling a queued deploy, the site names the worker its ticket is
	// held on so promotion returns to that exact worker (a reservation lives on
	// one worker, not the whole network). A first deploy leaves these empty and
	// the bridge picks a random worker.
	WorkerNode        string `json:"worker_node,omitempty"`
	WorkerDestination string `json:"worker_destination,omitempty"`
	// ContentKey is the base64 per-object content key for an encrypted build
	// context. Only the coordinator (site) can produce it; the bridge seals it to
	// the chosen worker's content key so the raw key never leaves this host.
	ContentKey string `json:"content_key,omitempty"`
	// Env is per-boot environment injected into the container (e.g. a random
	// LAB_SECRET the researcher must retrieve). Each entry is "KEY=value".
	Env []string `json:"env,omitempty"`
}

// deployResult is DeployReply plus which worker handled it, so the site can
// persist the (worker, container) pair and later poll or destroy it.
type deployResult struct {
	dcs.DeployReply
	WorkerNode        string `json:"worker_node"`
	WorkerDestination string `json:"worker_destination"`
}

func (api *bridgeAPI) handleDeploy(w http.ResponseWriter, r *http.Request) {
	var body deployBody
	if !decode(w, r, &body) {
		return
	}
	if body.Image == "" && body.BuildContextDigest == "" {
		writeErr(w, http.StatusBadRequest, "pass image or build_context_digest")
		return
	}
	if body.OnBehalfOf == "" {
		writeErr(w, http.StatusBadRequest, "on_behalf_of is required (the site user id)")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	req := dcs.DeployRequest{
		DeploymentID:       body.DeploymentID,
		Image:              body.Image,
		BuildContextDigest: body.BuildContextDigest,
		Lab:                body.Lab,
		Kind:               body.Kind,
		PrimaryPort:        body.PrimaryPort,
		RuntimeSecs:        body.RuntimeSecs,
		OnBehalfOf:         body.OnBehalfOf,
		Ticket:             body.Ticket,
		Env:                body.Env,
	}
	if req.DeploymentID == "" {
		req.DeploymentID = "bridge-" + short(api.node.ID()) + "-" + shortTime()
	}

	// The per-object content key, if this is an encrypted build context. It never
	// reaches a worker raw -- DeployTo seals it to the chosen worker.
	var contentKey []byte
	if body.ContentKey != "" {
		decoded, derr := base64.StdEncoding.DecodeString(body.ContentKey)
		if derr != nil {
			writeErr(w, http.StatusBadRequest, "content_key is not valid base64")
			return
		}
		contentKey = decoded
	}

	// Inline the (encrypted) build context so the worker need not fetch it from
	// the DHT -- a remote worker's DHT connectivity over I2P is not guaranteed,
	// and the context is small. The bridge already holds it (the site published
	// it here first). The worker verifies its digest and decrypts it as usual.
	if req.BuildContextDigest != "" {
		if blob, berr := api.blobs.GetBlob(ctx, req.BuildContextDigest); berr == nil {
			req.BuildContext = blob
		} else {
			api.logger.Printf("dcs-bridge: could not inline build context %s: %v", req.BuildContextDigest, berr)
		}
	}

	// Re-poll of a queued deploy: go back to the exact worker holding the ticket.
	if body.WorkerNode != "" && body.Ticket != "" {
		worker := dcs.WorkerRecord{NodeID: body.WorkerNode, Destination: body.WorkerDestination}
		// Sealing the grant needs the worker's content key, which the minimal
		// re-poll record lacks -- fetch the full record for it.
		if len(contentKey) > 0 {
			if full, lerr := api.node.LookupDCSWorker(ctx, body.WorkerNode); lerr == nil {
				worker = full
			} else {
				writeErr(w, http.StatusBadGateway, "deploy: could not recover worker content key: "+lerr.Error())
				return
			}
		}
		reply, err := api.manager.DeployTo(ctx, worker, req, contentKey)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "deploy: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, deployResult{
			DeployReply:       reply,
			WorkerNode:        worker.NodeID,
			WorkerDestination: worker.Destination,
		})
		return
	}

	// First deploy: pick a random eligible worker.
	workers, err := api.node.FindDCSWorkers(ctx, 32)
	if err != nil || len(workers) == 0 {
		writeErr(w, http.StatusServiceUnavailable, "no container workers on the network")
		return
	}
	reply, worker, err := api.manager.DeployToRandom(ctx, workers, req, contentKey)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "deploy: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, deployResult{
		DeployReply:       reply,
		WorkerNode:        worker.NodeID,
		WorkerDestination: worker.Destination,
	})
}

// workerRef targets a specific worker for status/destroy. The site persisted
// these from the deploy reply.
type workerRef struct {
	WorkerNode        string `json:"worker_node"`
	WorkerDestination string `json:"worker_destination"`
	Ticket            string `json:"ticket,omitempty"`
	ContainerID       string `json:"container_id,omitempty"`
}

func (ref workerRef) record() dcs.WorkerRecord {
	return dcs.WorkerRecord{NodeID: ref.WorkerNode, Destination: ref.WorkerDestination}
}

func (api *bridgeAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	var ref workerRef
	if !decode(w, r, &ref) {
		return
	}
	if ref.WorkerNode == "" || ref.Ticket == "" {
		writeErr(w, http.StatusBadRequest, "worker_node and ticket are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	reply, err := api.manager.Status(ctx, ref.record(), ref.Ticket)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "status: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reply)
}

func (api *bridgeAPI) handleDestroy(w http.ResponseWriter, r *http.Request) {
	var ref workerRef
	if !decode(w, r, &ref) {
		return
	}
	if ref.WorkerNode == "" || ref.ContainerID == "" {
		writeErr(w, http.StatusBadRequest, "worker_node and container_id are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if err := api.manager.Destroy(ctx, ref.record(), ref.ContainerID); err != nil {
		writeErr(w, http.StatusBadGateway, "destroy: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- helpers ----

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return false
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
