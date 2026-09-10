package dcs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// DeployRequest is the payload of a Launch envelope: what the deployer wants
// run, and under what constraints. It is signed inside the envelope by the
// owner, so the worker's audit log records exactly who asked for what.
type DeployRequest struct {
	DeploymentID string   `json:"deployment_id"`
	Image        string   `json:"image"` // digest-pinned reference
	Cmd          []string `json:"cmd,omitempty"`
	Env          []string `json:"env,omitempty"`
	Lab          bool     `json:"lab"`          // deliberately-vulnerable workload
	RuntimeSecs  int      `json:"runtime_secs"` // requested; ceiling-clamped for lab

	MemoryLimitBytes int64 `json:"memory_limit_bytes,omitempty"`
	NanoCPUs         int64 `json:"nano_cpus,omitempty"`
	// PrimaryPort is where a portless inbound I2P stream is routed -- the
	// container's main service. Defaults to DefaultLabPort when unset.
	PrimaryPort int `json:"primary_port,omitempty"`
	// Ticket carries a queue position across Launch retries. Empty on the first
	// attempt; set to the previous reply's Ticket when polling a queued slot.
	Ticket string `json:"ticket,omitempty"`
	// BuildContextDigest references a build-context blob in the shard store. Its
	// meaning depends on Kind: for "dockerfile" it is a Dockerfile+files context
	// the worker builds; for "compose" it is a docker-compose project the worker
	// runs, pulling the images from the registry.
	BuildContextDigest string `json:"build_context_digest,omitempty"`
	// Kind selects how the build context becomes a running service:
	// "" or "dockerfile" -> build a Dockerfile and run one container;
	// "compose"          -> `docker compose up` the project (vulhub-style),
	//                        images pulled from the registry.
	Kind string `json:"kind,omitempty"`
	// GrantedContentKey, when set, is the coordinator's per-object content key
	// SEALED to THIS worker's Curve25519 content key (libsodium sealed box,
	// base64). The worker opens it to decrypt an encrypted build context. It is
	// never the raw key -- only the named worker can open it.
	GrantedContentKey string `json:"granted_content_key,omitempty"`
	// BuildContext, when set, is the (encrypted) build-context blob inlined by the
	// bridge, so the worker need not fetch it from the DHT. A worker's DHT
	// connectivity over I2P is not guaranteed, and the context is small; the
	// bridge already holds it. It is verified against BuildContextDigest and
	// decrypted with GrantedContentKey exactly like a fetched blob.
	BuildContext []byte `json:"build_context,omitempty"`
	// OnBehalfOf lets a TRUSTED broker (a website's bridge node, in the worker's
	// broker allowlist) deploy for many users through one node identity: the
	// one-instance-per-user rule then keys on this sub-owner, not the shared
	// broker identity, so the site is not capped to one container per worker.
	// Ignored from untrusted owners.
	OnBehalfOf string `json:"on_behalf_of,omitempty"`

	// These say what the deployer wants the container REACHABLE as. For a lab
	// workload every one of them is refused (see AdmitLab), so a researcher who
	// ticks the wrong box is told, not silently given a public box.
	RequestPublish bool `json:"request_publish,omitempty"`
	RequestEgress  bool `json:"request_egress,omitempty"`
	RequestGateway bool `json:"request_gateway,omitempty"`
}

// DeployReply is what the owner gets back. For a lab deployment the Destination
// is the whole point: it is the private I2P address of the container, disclosed
// to the owner alone, which the owner then uses to reach the box (port scan,
// exploit, whatever the research is).
type DeployReply struct {
	DeploymentID string `json:"deployment_id"`
	ContainerID  string `json:"container_id"`
	Destination  string `json:"destination"` // <b32>.i2p — reach the container here
	Private      bool   `json:"private"`     // true: never published anywhere else
	ExpiresAt    int64  `json:"expires_at"`  // agent destroys it at this time
	Note         string `json:"note,omitempty"`

	// Queue fields, set instead of a container when the worker is full. The
	// client re-sends Launch with Ticket until Queued is false.
	Queued      bool   `json:"queued,omitempty"`
	Ticket      string `json:"ticket,omitempty"`
	Position    int    `json:"position,omitempty"`     // 1-based place in line
	ETASeconds  int64  `json:"eta_seconds,omitempty"`  // countdown to a free slot
	InstanceTTL int64  `json:"instance_ttl,omitempty"` // seconds before auto spin-down
}

// Runtime is the container backend the agent drives. *DockerClient satisfies
// it; the interface exists so the agent is testable without a docker daemon.
type Runtime interface {
	Create(ctx context.Context, spec ContainerSpec) (string, error)
	Start(ctx context.Context, id string) error
	Remove(ctx context.Context, id string, force bool) error
}

// Allocator gives a container its own I2P destination. *AddressAllocator
// satisfies it.
type Allocator interface {
	Allocate(ctx context.Context, containerID string, private bool) (*ContainerAddress, error)
	Release(containerID string, purge bool) error
}

// NetworkAttacher bridges a started container's I2P destination to its network
// namespace, so the returned address actually reaches the container. It is
// injected so the agent stays testable without root, docker or a SAM bridge;
// the production wiring is BuildContainerNetwork (network_attach.go).
//
// primaryPort is the container's main service port -- where a portless inbound
// stream is routed. The attacher returns a handle the agent keeps for teardown.
type NetworkAttacher interface {
	Attach(ctx context.Context, containerID string, primaryPort int) (NetworkHandle, error)
}

// NetworkHandle detaches a container's network on stop/destroy.
type NetworkHandle interface {
	Detach()
}

// Builder builds an image from a packed build context. *DockerClient satisfies
// it. Used when a deploy references a DHT-sharded build context instead of a
// prebuilt image.
type Builder interface {
	BuildImage(ctx context.Context, contextBlob []byte, tag string) error
}

// AuditSink records what strangers did with the worker's hardware. The agent
// never proceeds without logging the decision first, so a crash mid-launch
// still leaves a record of what was attempted.
type AuditSink interface {
	Record(entry AuditEntry)
}

type AuditEntry struct {
	At           time.Time
	Requester    string // owner node ID
	DeploymentID string
	Method       string
	Decision     string // "admitted" | "refused"
	Reason       string
	ContainerID  string
	Destination  string // recorded locally; this is the operator's own log
}

// AgentConfig is the worker operator's policy. These are the consent knobs no
// deployer can override.
type AgentConfig struct {
	AcceptsLab     bool
	LabMaxRuntime  time.Duration
	OwnerAllowlist []string // empty = any owner
	// TrustedBrokers are node IDs allowed to deploy on behalf of sub-owners via
	// DeployRequest.OnBehalfOf. A website's bridge node goes here.
	TrustedBrokers []string
	NodeID         string // this worker's identity, == envelope ToNode
}

func (c AgentConfig) trustsBroker(owner string) bool {
	for _, b := range c.TrustedBrokers {
		if b == owner {
			return true
		}
	}
	return false
}

func (c AgentConfig) ownerAllowed(owner string) bool {
	if len(c.OwnerAllowlist) == 0 {
		return true
	}
	for _, allowed := range c.OwnerAllowlist {
		if allowed == owner {
			return true
		}
	}
	return false
}

// Agent is the worker side. It admits a deploy request, creates the container
// with a hardened profile, gives it a private I2P destination, attaches that
// destination to the container's network namespace, and returns the address to
// the owner alone.
type Agent struct {
	cfg         AgentConfig
	runtime     Runtime
	alloc       Allocator
	audit       AuditSink
	network     NetworkAttacher              // optional; nil means "address allocated but not bridged"
	builder     Builder                      // optional; required only for build-context deploys
	blobs       BlobStore                    // optional; the DHT-backed build-context store
	compose     ComposeRunner                // optional; required only for kind=compose deploys
	openContent func([]byte) ([]byte, error) // optional; opens a sealed content-key grant
	admission   *AdmissionController         // optional; nil means unlimited (no cap, no queue)
	instanceTTL time.Duration                // general auto-spin-down; 0 -> DefaultInstanceTTL
	now         func() time.Time

	mu        sync.Mutex
	attached  map[string]NetworkHandle // containerID → its network, for teardown
	owners    map[string]string        // containerID → the envelope owner (for destroy auth)
	composeOf map[string]string        // primary containerID → compose project id, for teardown

	// Durable mirror of owners/composeOf. Held in memory alone, a restart made
	// every running container un-destroyable forever; see ownership.go.
	ownership *ownershipStore
}

// ComposeRunner runs a docker-compose project (a vulhub-style challenge). Unlike
// the single-container path, the images are PULLED FROM THE REGISTRY at
// `compose up`; only the small project text came off the DHT. It returns the id
// of the PRIMARY service's container so the agent can give that container a
// private I2P destination and attach it exactly like any other container.
//
// An implementation MUST run the project WITHOUT publishing ports to the host
// (a lab must never be reachable on the worker's clearnet) -- the only path in
// is the I2P destination the agent attaches to the primary container.
type ComposeRunner interface {
	Up(ctx context.Context, project string, files []BuildFile, primaryPort int, env []string) (primaryContainerID string, err error)
	Down(ctx context.Context, project string) error
}

// SetComposeRunner wires docker-compose execution. Without it, a kind=compose
// deploy is refused with a clear message rather than silently mis-run.
func (a *Agent) SetComposeRunner(c ComposeRunner) { a.compose = c }

// SetContentOpener wires the node's ability to open a sealed content-key grant
// (its Curve25519 content key). Without it, a worker can still run unencrypted
// build contexts but refuses encrypted ones.
func (a *Agent) SetContentOpener(open func([]byte) ([]byte, error)) { a.openContent = open }

// fetchContext retrieves the build context for a deploy and decrypts it when the
// deployer granted a content key. The digest is verified on the fetched
// (ciphertext) bytes -- exactly what the coordinator addressed -- before any
// decryption, so a tampered blob is rejected first.
func (a *Agent) fetchContext(ctx context.Context, req DeployRequest) ([]byte, error) {
	var blob []byte
	if len(req.BuildContext) > 0 {
		// Inlined by the bridge -- no DHT fetch, so it works even if this worker's
		// DHT connectivity over I2P is momentarily down.
		blob = req.BuildContext
	} else {
		if a.blobs == nil {
			return nil, errors.New("dcs: no build-context store on this worker")
		}
		var err error
		blob, err = a.blobs.GetBlob(ctx, req.BuildContextDigest)
		if err != nil {
			return nil, err
		}
	}
	if got := BlobDigest(blob); got != req.BuildContextDigest {
		return nil, fmt.Errorf("%w: got %s want %s", ErrDigestMismatch, got, req.BuildContextDigest)
	}
	if req.GrantedContentKey == "" {
		return blob, nil // unencrypted context (no grant issued)
	}
	if a.openContent == nil {
		return nil, errors.New("dcs: this worker cannot open content grants")
	}
	sealed, err := base64.StdEncoding.DecodeString(req.GrantedContentKey)
	if err != nil {
		return nil, fmt.Errorf("dcs: invalid content grant: %w", err)
	}
	contentKey, err := a.openContent(sealed)
	if err != nil {
		return nil, err
	}
	plaintext, err := DecryptContent(blob, contentKey)
	if err != nil {
		return nil, fmt.Errorf("dcs: decrypt build context: %w", err)
	}
	return plaintext, nil
}

func NewAgent(cfg AgentConfig, runtime Runtime, alloc Allocator, audit AuditSink) *Agent {
	return &Agent{
		cfg: cfg, runtime: runtime, alloc: alloc, audit: audit,
		now: time.Now, attached: map[string]NetworkHandle{},
		owners: map[string]string{}, composeOf: map[string]string{},
	}
}

// SetStatePath makes container ownership survive a restart. Without it the
// agent still works, but every container it launched becomes un-destroyable the
// moment it restarts — so a deployment that runs containers people care about
// should always set this.
func (a *Agent) SetStatePath(path string) {
	store := newOwnershipStore(path)
	a.mu.Lock()
	a.ownership = store
	for containerID, record := range store.records {
		a.owners[containerID] = record.Owner
		if record.Compose != "" {
			a.composeOf[containerID] = record.Compose
		}
	}
	recovered := len(store.records)
	a.mu.Unlock()
	if recovered > 0 {
		a.audit.Record(AuditEntry{
			At: a.now(), Method: MethodDestroy, Decision: "recovered",
			Reason: fmt.Sprintf("restored ownership of %d container(s) from %s",
				recovered, path),
		})
	}
}

// rememberOwner records who deployed a container, durably.
func (a *Agent) rememberOwner(containerID, owner string) {
	a.mu.Lock()
	a.owners[containerID] = owner
	compose := a.composeOf[containerID]
	store := a.ownership
	a.mu.Unlock()
	if store != nil {
		store.set(containerID, owner, compose)
		_ = store.flush()
	}
}

// forgetOwner drops a container from both the map and the file.
func (a *Agent) forgetOwner(containerID string) {
	a.mu.Lock()
	store := a.ownership
	a.mu.Unlock()
	if store != nil {
		store.forget(containerID)
		_ = store.flush()
	}
}

// SetNetworkAttacher wires the container-netns bridge. Without it the agent
// still allocates and returns a destination, but the container is not reachable
// at it -- useful for tests and for a dry run, honest about the difference.
func (a *Agent) SetNetworkAttacher(n NetworkAttacher) { a.network = n }

// SetAdmission wires the simultaneous-container cap, the one-instance-per-owner
// rule and the queue. Without it the worker accepts unlimited containers.
func (a *Agent) SetAdmission(admission *AdmissionController, instanceTTL time.Duration) {
	a.admission = admission
	a.instanceTTL = instanceTTL
}

// SetBuilder wires the image builder and the DHT-backed build-context store, so
// a deploy that references a build-context digest is fetched from the shard
// store, verified, and built locally rather than pulled as a prebuilt image.
func (a *Agent) SetBuilder(builder Builder, blobs BlobStore) {
	a.builder = builder
	a.blobs = blobs
}

// DefaultLabPort is where a portless inbound stream is routed when the deploy
// request does not name a primary port. 80 is the common case for a web-facing
// vulnerable box; a request can override it via DeployRequest.PrimaryPort.
const DefaultLabPort = 80

var (
	ErrOwnerNotAllowed = errors.New("dcs: this worker does not accept deployments from that owner")
	ErrBadRequest      = errors.New("dcs: malformed deploy request")
)

// HandleLaunch processes a verified Launch envelope. The envelope MUST already
// have passed Envelope.Verify -- HandleLaunch trusts env.FromNode as the
// authenticated owner and does not re-check the signature.
func (a *Agent) HandleLaunch(ctx context.Context, env Envelope) (DeployReply, error) {
	owner := env.FromNode
	var req DeployRequest
	if err := env.Bind(&req); err != nil {
		a.refuse(owner, "", "bind", err.Error())
		return DeployReply{}, ErrBadRequest
	}
	if req.DeploymentID == "" || (req.Image == "" && req.BuildContextDigest == "") {
		a.refuse(owner, req.DeploymentID, "validate", "missing image/build context or deployment id")
		return DeployReply{}, ErrBadRequest
	}
	if !a.cfg.ownerAllowed(owner) {
		a.refuse(owner, req.DeploymentID, "authorize", "owner not on allowlist")
		return DeployReply{}, ErrOwnerNotAllowed
	}

	dep := Deployment{
		ID: req.DeploymentID, Owner: owner, Image: req.Image, Lab: req.Lab,
		RequestedRuntime: time.Duration(req.RuntimeSecs) * time.Second,
		RequestPublish:   req.RequestPublish,
		RequestEgress:    req.RequestEgress,
		RequestGateway:   req.RequestGateway,
	}

	// Lab workloads go through the containment gate; everything it refuses is
	// refused here, with the reason, before any container exists.
	var containment LabContainment
	if req.Lab {
		c, err := AdmitLab(dep, a.cfg.AcceptsLab, a.cfg.LabMaxRuntime)
		if err != nil {
			a.refuse(owner, req.DeploymentID, "admit_lab", err.Error())
			return DeployReply{}, err
		}
		containment = c
	}

	// The identity the one-instance-per-user rule keys on. For a trusted broker
	// that names a sub-owner, it is that sub-owner; otherwise the envelope owner.
	effectiveOwner := owner
	if req.OnBehalfOf != "" && a.cfg.trustsBroker(owner) {
		effectiveOwner = req.OnBehalfOf
	}

	// Admission: the operator's simultaneous-container cap, one-instance-per-owner
	// rule, and the queue. When admission is not wired (nil), the worker is
	// unlimited -- the previous behaviour, kept for tests and dry runs.
	var slotToken string
	if a.admission != nil {
		decision, admitErr := a.admission.Admit(effectiveOwner, req.Ticket)
		if admitErr != nil {
			// One instance per owner: told plainly, not as a generic failure.
			a.refuse(owner, req.DeploymentID, "admission", admitErr.Error())
			return DeployReply{}, admitErr
		}
		if decision.Queued {
			// The worker is full. Hand back a place in line and a countdown; the
			// client re-sends Launch with this Ticket until a slot frees. No
			// container is created for a queued request.
			return DeployReply{
				DeploymentID: req.DeploymentID, Queued: true,
				Ticket: decision.Ticket, Position: decision.Position,
				ETASeconds: decision.ETASeconds, InstanceTTL: decision.InstanceTTL,
				Note: "queued: the worker is at capacity",
			}, nil
		}
		slotToken = decision.SlotToken
	}
	// From here a failure must release the reserved slot, or the worker leaks
	// capacity that no coordinator exists to reclaim.
	releaseSlot := func() {
		if a.admission != nil && slotToken != "" {
			a.admission.Release(slotToken)
		}
	}

	// A lab container's destination is private and never leaves the agent
	// except to this owner; a normal one may later be advertised.
	private := req.Lab

	// Turn the request into a RUNNING container with an allocated destination.
	// Two shapes: a compose project (`compose up`, images from the registry), or
	// a single container (build/pull -> create -> allocate-before-start -> start).
	var containerID string
	var address *ContainerAddress
	if req.Kind == "compose" {
		cid, addr, cerr := a.launchCompose(ctx, owner, req, private)
		if cerr != nil {
			releaseSlot()
			return DeployReply{}, cerr // launchCompose audited the refusal
		}
		containerID, address = cid, addr
	} else {
		// Build from a DHT-sharded build context when one is referenced: fetch the
		// Dockerfile+files blob by digest, verify it, and build the image locally.
		// This is the registry-free path -- the worker reproduces the image from
		// source rather than pulling prebuilt layers.
		image := req.Image
		if req.BuildContextDigest != "" {
			if a.builder == nil || a.blobs == nil {
				releaseSlot()
				a.refuse(owner, req.DeploymentID, "build", "this worker cannot build from a context")
				return DeployReply{}, errors.New("dcs: build-context deploys are not enabled on this worker")
			}
			raw, ferr := a.fetchContext(ctx, req)
			var files []BuildFile
			if ferr == nil {
				files, ferr = UnpackBuildContext(raw)
			}
			if ferr != nil {
				releaseSlot()
				a.refuse(owner, req.DeploymentID, "fetch_build_context", ferr.Error())
				return DeployReply{}, fmt.Errorf("fetch build context: %w", ferr)
			}
			blob, perr := PackBuildContext(files) // re-pack the VALIDATED files only
			if perr != nil {
				releaseSlot()
				a.refuse(owner, req.DeploymentID, "pack_build_context", perr.Error())
				return DeployReply{}, perr
			}
			image = "dcs-build-" + shortDigest(req.BuildContextDigest)
			if berr := a.builder.BuildImage(ctx, blob, image); berr != nil {
				releaseSlot()
				a.refuse(owner, req.DeploymentID, "build", berr.Error())
				return DeployReply{}, fmt.Errorf("build image: %w", berr)
			}
		}

		cid, err := a.runtime.Create(ctx, ContainerSpec{
			Name:  "dcs-" + req.DeploymentID,
			Image: image, Cmd: req.Cmd, Env: req.Env,
			MemoryLimitBytes: req.MemoryLimitBytes, NanoCPUs: req.NanoCPUs,
			Lab: req.Lab,
		})
		if err != nil {
			releaseSlot()
			a.refuse(owner, req.DeploymentID, "create", err.Error())
			return DeployReply{}, fmt.Errorf("create container: %w", err)
		}

		// Address BEFORE start: the container must not run for even an instant
		// without its network identity in place.
		addr, err := a.alloc.Allocate(ctx, cid, private)
		if err != nil {
			releaseSlot()
			_ = a.runtime.Remove(ctx, cid, true)
			a.refuse(owner, req.DeploymentID, "allocate_address", err.Error())
			return DeployReply{}, fmt.Errorf("allocate destination: %w", err)
		}

		if err := a.runtime.Start(ctx, cid); err != nil {
			releaseSlot()
			_ = a.alloc.Release(cid, true)
			_ = a.runtime.Remove(ctx, cid, true)
			a.refuse(owner, req.DeploymentID, "start", err.Error())
			return DeployReply{}, fmt.Errorf("start container: %w", err)
		}
		containerID, address = cid, addr
	}

	// Attach the container's destination to its network namespace so the
	// address we are about to hand back actually reaches the container. If no
	// attacher is wired (a dry run, or a non-Linux host), the address is still
	// returned but the note says it is not yet reachable, rather than implying
	// a connection that will not work.
	reachable := false
	if a.network != nil {
		primary := req.PrimaryPort
		if primary <= 0 {
			primary = DefaultLabPort
		}
		handle, attachErr := a.network.Attach(ctx, containerID, primary)
		if attachErr != nil {
			_ = a.alloc.Release(containerID, true)
			a.teardownRuntime(ctx, containerID)
			a.refuse(owner, req.DeploymentID, "attach_network", attachErr.Error())
			return DeployReply{}, fmt.Errorf("attach network: %w", attachErr)
		}
		a.mu.Lock()
		a.attached[containerID] = handle
		a.mu.Unlock()
		reachable = true
	}

	// Disclose the destination to the owner -- the single, audited revelation.
	destination, err := address.Disclose(owner, "launch result", a.now())
	if err != nil {
		return DeployReply{}, err
	}

	reply := DeployReply{
		DeploymentID: req.DeploymentID,
		ContainerID:  containerID,
		Destination:  destination,
		Private:      private,
	}
	// The instance's auto-spin-down time. A lab ceiling (4h) is stricter than
	// the general TTL and wins; otherwise the general TTL applies.
	ttl := a.instanceTTL
	if ttl <= 0 {
		ttl = DefaultInstanceTTL
	}
	expiresAt := a.now().Add(ttl)
	if req.Lab {
		labStop := containment.ExpiresAt(a.now())
		if labStop.Before(expiresAt) {
			expiresAt = labStop
		}
		reply.Note = "lab workload: no egress, no gateway, destroyed at expiry"
	}
	reply.ExpiresAt = expiresAt.Unix()
	reply.InstanceTTL = int64(ttl / time.Second)

	// Register the running instance so the admission cap, the queue ETA and the
	// reaper all see it. Do this AFTER a successful start so a failed launch
	// never counts against capacity.
	if a.admission != nil && slotToken != "" {
		if err := a.admission.Started(slotToken, containerID, expiresAt); err != nil {
			// The reservation expired mid-launch (very slow start). The container
			// is up but unaccounted; destroy it rather than run something the cap
			// does not know about.
			_ = a.Destroy(ctx, containerID)
			a.refuse(owner, req.DeploymentID, "slot_expired", err.Error())
			return DeployReply{}, err
		}
	}
	if !reachable {
		reply.Note = strings.TrimSpace(reply.Note + " (address allocated but not yet bridged on this host)")
	}

	a.rememberOwner(containerID, owner)
	a.audit.Record(AuditEntry{
		At: a.now(), Requester: owner, DeploymentID: req.DeploymentID,
		Method: MethodLaunch, Decision: "admitted",
		ContainerID: containerID, Destination: destination,
	})
	return reply, nil
}

// HandleDestroy processes a verified Destroy envelope: only the node that
// deployed a container may tear it down. The container id is in the payload.
func (a *Agent) HandleDestroy(ctx context.Context, env Envelope) error {
	owner := env.FromNode
	var req struct {
		ContainerID string `json:"container_id"`
	}
	if err := env.Bind(&req); err != nil || req.ContainerID == "" {
		return ErrBadRequest
	}
	a.mu.Lock()
	recordedOwner, known := a.owners[req.ContainerID]
	a.mu.Unlock()
	if !known || recordedOwner != owner {
		// Either not ours, or a different node is trying to destroy it. Refuse
		// rather than let one deployer kill another's container.
		a.refuse(owner, "", "destroy", "not the owner of that container")
		return errors.New("dcs: not authorized to destroy that container")
	}
	if err := a.Destroy(ctx, req.ContainerID); err != nil {
		return err
	}
	a.mu.Lock()
	delete(a.owners, req.ContainerID)
	a.mu.Unlock()
	a.forgetOwner(req.ContainerID)
	return nil
}

// HandleQueueStatus answers a queued client's poll for its place in line
// without attempting a launch, so a UI can show a live countdown cheaply.
func (a *Agent) HandleQueueStatus(ticket string) (DeployReply, bool) {
	if a.admission == nil {
		return DeployReply{}, false
	}
	decision, ok := a.admission.QueueStatus(ticket)
	if !ok {
		return DeployReply{}, false
	}
	return DeployReply{
		Queued: true, Ticket: decision.Ticket, Position: decision.Position,
		ETASeconds: decision.ETASeconds, InstanceTTL: decision.InstanceTTL,
	}, true
}

func shortDigest(digest string) string {
	d := strings.TrimPrefix(digest, "sha256:")
	if len(d) > 16 {
		return d[:16]
	}
	return d
}

func (a *Agent) refuse(owner, deployment, phase, reason string) {
	a.audit.Record(AuditEntry{
		At: a.now(), Requester: owner, DeploymentID: deployment,
		Method: MethodLaunch, Decision: "refused",
		Reason: phase + ": " + reason,
	})
}

// Destroy tears a container down completely: detach its network (so it is
// reachable by nothing), release its I2P destination and purge its key (so its
// address can never be reused), then remove the container. Order matters -- the
// network comes down first so no new connection can land mid-teardown.
func (a *Agent) Destroy(ctx context.Context, containerID string) error {
	a.mu.Lock()
	handle := a.attached[containerID]
	delete(a.attached, containerID)
	a.mu.Unlock()

	if handle != nil {
		handle.Detach()
	}
	// Free the admission slot so the queue advances and the reaper stops
	// tracking it.
	if a.admission != nil {
		a.admission.Release(containerID)
	}
	a.mu.Lock()
	delete(a.owners, containerID)
	project, isCompose := a.composeOf[containerID]
	if isCompose {
		delete(a.composeOf, containerID)
	}
	a.mu.Unlock()
	a.forgetOwner(containerID)
	// purge=true: a destroyed container's address must not survive it, or a
	// later container could inherit an address someone was told about.
	_ = a.alloc.Release(containerID, true)
	if isCompose {
		// The whole compose project comes down, not just the primary container --
		// its backing services (a DB, a cache) must not outlive the challenge.
		if a.compose != nil {
			if err := a.compose.Down(ctx, project); err != nil {
				return fmt.Errorf("compose down: %w", err)
			}
		}
	} else if err := a.runtime.Remove(ctx, containerID, true); err != nil {
		return fmt.Errorf("remove container: %w", err)
	}
	a.audit.Record(AuditEntry{
		At: a.now(), Method: MethodDestroy, Decision: "admitted",
		ContainerID: containerID,
	})
	return nil
}

// teardownRuntime removes a running container mid-launch, routing a compose
// project to `compose down` and a single container to runtime.Remove.
func (a *Agent) teardownRuntime(ctx context.Context, containerID string) {
	a.mu.Lock()
	project, isCompose := a.composeOf[containerID]
	if isCompose {
		delete(a.composeOf, containerID)
	}
	a.mu.Unlock()
	if isCompose {
		if a.compose != nil {
			_ = a.compose.Down(ctx, project)
		}
		return
	}
	_ = a.runtime.Remove(ctx, containerID, true)
}

// launchCompose fetches a compose project from the shard store, `compose up`s it
// (images pulled from the registry), and allocates a private destination for the
// PRIMARY service's container. On any failure it audits the refusal and tears
// down whatever came up, so a partial project never lingers.
func (a *Agent) launchCompose(ctx context.Context, owner string, req DeployRequest, private bool) (string, *ContainerAddress, error) {
	if a.compose == nil || a.blobs == nil {
		a.refuse(owner, req.DeploymentID, "compose", "this worker does not run compose projects")
		return "", nil, errors.New("dcs: compose deploys are not enabled on this worker")
	}
	if req.BuildContextDigest == "" {
		a.refuse(owner, req.DeploymentID, "compose", "compose deploy without a build context")
		return "", nil, ErrBadRequest
	}
	raw, ferr := a.fetchContext(ctx, req)
	var files []BuildFile
	if ferr == nil {
		files, ferr = UnpackComposeContext(raw)
	}
	if ferr != nil {
		a.refuse(owner, req.DeploymentID, "fetch_compose_context", ferr.Error())
		return "", nil, fmt.Errorf("fetch compose context: %w", ferr)
	}
	primary := req.PrimaryPort
	if primary <= 0 {
		primary = DefaultLabPort
	}
	project := composeProjectName(req.DeploymentID)
	containerID, uerr := a.compose.Up(ctx, project, files, primary, req.Env)
	if uerr != nil {
		_ = a.compose.Down(ctx, project) // clean any partial bring-up
		a.refuse(owner, req.DeploymentID, "compose_up", uerr.Error())
		return "", nil, fmt.Errorf("compose up: %w", uerr)
	}
	address, aerr := a.alloc.Allocate(ctx, containerID, private)
	if aerr != nil {
		_ = a.compose.Down(ctx, project)
		a.refuse(owner, req.DeploymentID, "allocate_address", aerr.Error())
		return "", nil, fmt.Errorf("allocate destination: %w", aerr)
	}
	a.mu.Lock()
	a.composeOf[containerID] = project
	store := a.ownership
	a.mu.Unlock()
	// Persisted with the project name: tearing down a compose challenge means
	// `compose down` on the whole project, and a restart that forgot the
	// project name would leave the backing services (a database, a cache)
	// running even if the primary container were removed by hand.
	if store != nil {
		store.setCompose(containerID, project)
		_ = store.flush()
	}
	return containerID, address, nil
}

// composeProjectName derives a docker-compose project name (lowercase, safe
// charset) from a deployment id.
func composeProjectName(deploymentID string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(deploymentID) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	name := strings.Trim(b.String(), "-_")
	if name == "" {
		name = "dcs"
	}
	return "dcs-" + name
}

// ---------------------------------------------------------------------------
// Manager (deployer side)
// ---------------------------------------------------------------------------

// Transport sends a signed envelope to a worker and returns its reply envelope.
// A libp2p-stream implementation opens /syndichan/dcs/1.0.0 to the worker's
// destination; the interface keeps the deploy flow testable without I2P.
type Transport interface {
	RoundTrip(ctx context.Context, worker WorkerRecord, env Envelope) ([]byte, error)
}

// Manager runs on the deployer's node. DeployToRandom is the function behind
// "deploy to a random peer and give me its address".
type Manager struct {
	signer    EnvelopeSigner
	transport Transport
	now       func() time.Time
	rand      func() uint64
}

func NewManager(signer EnvelopeSigner, transport Transport) *Manager {
	return &Manager{signer: signer, transport: transport, now: time.Now, rand: RandUint64}
}

// DeployToRandom picks a random worker from the supplied records (already read
// from the DHT by the caller), sends it a signed Launch, and returns the
// container's I2P destination.
//
// The records are passed in rather than fetched here so the DHT dependency
// stays at the edges and this core is pure. For a lab deployment the returned
// DeployReply.Destination is the private address the caller wanted -- the thing
// to point a port scanner at.
func (m *Manager) DeployToRandom(ctx context.Context, records []WorkerRecord, req DeployRequest, contentKey []byte) (DeployReply, WorkerRecord, error) {
	capabilities := []string{"worker"}
	if req.Lab {
		// A lab workload must land on a worker whose operator opted into lab
		// hosting; a plain worker never sees it.
		capabilities = []string{"worker", "lab"}
	}
	candidates := FilterWorkers(records, Requirement{
		Capabilities: capabilities,
		MinRAMBytes:  req.MemoryLimitBytes,
	}, m.now())
	if len(candidates) == 0 {
		// Distinguish "nobody offered" from "nobody qualified".
		if len(records) == 0 {
			return DeployReply{}, WorkerRecord{}, ErrEmptyCandidate
		}
		return DeployReply{}, WorkerRecord{}, ErrNoWorkerMatched
	}
	// Stable order, then shuffle with the caller's source. Try a few in turn: a
	// single unreachable/flaky worker (e.g. an I2P dial timeout) must not fail the
	// whole launch when another worker could run it.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].NodeID < candidates[j].NodeID })
	for i := len(candidates) - 1; i > 0; i-- {
		j := int(m.rand() % uint64(i+1))
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}
	attempts := len(candidates)
	if attempts > maxDeployAttempts {
		attempts = maxDeployAttempts // don't hammer the whole fleet on a bad request
	}
	var lastErr error
	for _, worker := range candidates[:attempts] {
		reply, err := m.DeployTo(ctx, worker, req, contentKey)
		if err == nil {
			return reply, worker, nil
		}
		lastErr = err
	}
	return DeployReply{}, WorkerRecord{}, lastErr
}

// maxDeployAttempts caps how many workers a single launch tries before giving up,
// so a genuinely bad request does not stampede the fleet.
const maxDeployAttempts = 3

// DeployTo sends a Launch to a SPECIFIC worker. It is how a queued deployment is
// re-polled for promotion: the ticket reserves a place on one worker, so the
// retry must return to that same worker rather than picking a new random one.
// (A first deploy goes through DeployToRandom, which picks then calls this.)
func (m *Manager) DeployTo(ctx context.Context, worker WorkerRecord, req DeployRequest, contentKey []byte) (DeployReply, error) {
	// Seal the per-object content key to THIS worker before the envelope is
	// built, so the raw key never travels and only this worker can decrypt.
	if len(contentKey) > 0 {
		sealed, err := SealContentKey(contentKey, worker.ContentPubKey)
		if err != nil {
			return DeployReply{}, fmt.Errorf("grant content key to %s: %w", worker.NodeID, err)
		}
		req.GrantedContentKey = sealed
	}
	env, err := NewEnvelope(m.signer, worker.NodeID, MethodLaunch, req, m.now())
	if err != nil {
		return DeployReply{}, err
	}
	raw, err := m.transport.RoundTrip(ctx, worker, env)
	if err != nil {
		return DeployReply{}, fmt.Errorf("launch on %s: %w", worker.NodeID, err)
	}
	var reply DeployReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return DeployReply{}, fmt.Errorf("decode reply: %w", err)
	}
	if reply.Destination == "" && !reply.Queued {
		return DeployReply{}, errors.New("dcs: worker returned no destination")
	}
	return reply, nil
}

// sendTo sends a signed method to a specific worker and returns the raw payload.
func (m *Manager) sendTo(ctx context.Context, worker WorkerRecord, method string, payload any) ([]byte, error) {
	env, err := NewEnvelope(m.signer, worker.NodeID, method, payload, m.now())
	if err != nil {
		return nil, err
	}
	return m.transport.RoundTrip(ctx, worker, env)
}

// Destroy spins down a container on the worker that runs it.
func (m *Manager) Destroy(ctx context.Context, worker WorkerRecord, containerID string) error {
	_, err := m.sendTo(ctx, worker, MethodDestroy, map[string]string{"container_id": containerID})
	return err
}

// Status polls a queued deployment's place in line on its worker.
func (m *Manager) Status(ctx context.Context, worker WorkerRecord, ticket string) (DeployReply, error) {
	raw, err := m.sendTo(ctx, worker, MethodStatus, map[string]string{"ticket": ticket})
	if err != nil {
		return DeployReply{}, err
	}
	var reply DeployReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return DeployReply{}, err
	}
	return reply, nil
}
