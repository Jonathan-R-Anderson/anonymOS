package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/runtime"
	"github.com/rabbiit/maniwani/storage-client/internal/compute"
	"github.com/rabbiit/maniwani/storage-client/internal/config"
	"github.com/rabbiit/maniwani/storage-client/internal/dcs"
	"github.com/rabbiit/maniwani/storage-client/internal/p2p"
	"github.com/rabbiit/maniwani/storage-client/internal/place"
	"github.com/rabbiit/maniwani/storage-client/internal/store"
)

// This file wires the Distributed Container Service into the node binary. It is
// the seam the README's "run a container worker" instructions describe: with
// dcs.enabled and role.worker set, a storage node also becomes a DCS worker.
//
// DCS reuses the storage node wholesale -- its libp2p host for RPC over AXON,
// its DHT for worker records, its overlay runtime for per-container addresses,
// and its shard store for build contexts. It is not a second network; it is one more
// protocol on the node already running.

// startDCSWorker assembles and starts the worker. It returns without error when
// DCS is disabled or the role is not worker, so main can call it unconditionally.
// A failure to reach Docker is logged, not fatal: a node that cannot run
// containers is still a perfectly good storage node.
func startDCSWorker(ctx context.Context, cfg config.Config, node *p2p.Node, storage *store.Store, logger *log.Logger) {
	if !cfg.DCS.Enabled || !cfg.DCS.Role.Worker {
		return
	}
	if node == nil || storage == nil {
		// DCS needs the full storage node (host + DHT + overlay + store). A
		// gateway-only or probe-only process has none of these.
		logger.Printf("dcs: worker role requires full storage mode; not started")
		return
	}

	docker, err := dcs.NewDockerClient(cfg.DCS.DockerEndpoint)
	if err != nil {
		logger.Printf("dcs: worker disabled: %v", err)
		return
	}
	if err := docker.Ping(ctx); err != nil {
		logger.Printf("dcs: Docker is not reachable at %s (%v); worker not started. "+
			"The node continues as a storage node.", cfg.DCS.DockerEndpoint, err)
		return
	}

	// Per-container AXON addresses are hidden services on the same overlay
	// runtime the node already runs.
	allocator := dcs.NewAddressAllocator(&axonOpener{rt: node.Overlay()}, filepath.Join(cfg.DataDir, "dcs"))

	admission := dcs.NewAdmissionController(dcs.AdmissionConfig{
		MaxSlots:    cfg.DCS.Limits.MaxContainers,
		InstanceTTL: instanceTTL(cfg),
	})

	agentCfg := dcs.AgentConfig{
		AcceptsLab:     cfg.DCS.Role.Lab,
		LabMaxRuntime:  time.Duration(cfg.DCS.Limits.LabMaxRuntimeSeconds) * time.Second,
		OwnerAllowlist: cfg.DCS.Policy.OwnerAllowlist,
		TrustedBrokers: cfg.DCS.Policy.TrustedBrokers,
		NodeID:         node.ID(),
	}
	agent := dcs.NewAgent(agentCfg, docker, allocator, &logAudit{logger: logger})
	// Container ownership on disk, not just in memory. Without it a restart
	// orphans every running container permanently: only the node that deployed
	// one may destroy it, and after a restart the agent could attribute none of
	// them — leaving deliberately vulnerable boxes running with nobody able to
	// take them down.
	agent.SetStatePath(filepath.Join(cfg.DataDir, "dcs", "ownership.json"))
	agent.SetAdmission(admission, instanceTTL(cfg))
	// Build-context deploys: fetch the Dockerfile+files from the shard store and
	// build locally, registry-free.
	agent.SetBuilder(docker, NewStoreBlobStore(storage))
	// Open per-object content-key grants the coordinator sealed to this node, so
	// an encrypted build context can be decrypted before it is run.
	agent.SetContentOpener(node.OpenSealedContentKey)
	agent.SetNetworkAttacher(dcs.NewNetworkAttacher(
		&containerSessions{alloc: allocator},
		docker, dcs.NewNamespaceDialer,
		func(format string, args ...any) { logger.Printf(format, args...) },
	))
	// Compose challenges (vulhub-style): run `docker compose up` for a project
	// whose files came off the DHT, pulling the images from the registry. Needs
	// the Compose CLI on the host; without it, compose deploys are refused with a
	// clear message rather than mis-run.
	composeRunner, cerr := newDockerComposeRunner(
		filepath.Join(cfg.DataDir, "dcs", "compose"), cfg.DCS.DockerEndpoint,
		func(format string, args ...any) { logger.Printf(format, args...) },
	)
	if cerr != nil {
		logger.Printf("dcs: docker compose not available; compose challenges will be refused: %v", cerr)
	} else {
		agent.SetComposeRunner(composeRunner)
		logger.Printf("dcs: docker compose runner ready")
	}

	// Register the DCS record validator and the RPC handler on the node's host.
	if err := node.ConfigureDCSRecords(dcs.WorkerDHTValidator{}); err != nil {
		logger.Printf("dcs: could not register worker record validator: %v", err)
		return
	}
	server := dcs.NewStreamServer(node.Host(), agent, node.ID())
	server.Start()

	// Auto-spin-down reaper: destroys instances past their TTL.
	reaper := dcs.NewReaper(admission, agent.Destroy,
		func(format string, args ...any) { logger.Printf(format, args...) })
	go reaper.Run(ctx)

	// Tell the heartbeat this node is now a container host, so the operator's map
	// draws its yellow role and the site sees it as DCS-capable.
	node.SetDCSWorker(true)

	// Publish the capability record, and republish on the advertise interval so
	// the record never expires while the worker is alive.
	go advertiseWorker(ctx, cfg, node, admission, logger)

	logger.Printf("dcs: container worker started (slots=%d, lab=%t, ttl=%s)",
		cfg.DCS.Limits.MaxContainers, cfg.DCS.Role.Lab, instanceTTL(cfg))
}

func instanceTTL(cfg config.Config) time.Duration {
	if cfg.DCS.Limits.MaxRuntimeSeconds > 0 {
		return time.Duration(cfg.DCS.Limits.MaxRuntimeSeconds) * time.Second
	}
	return dcs.DefaultInstanceTTL
}

// advertiseWorker publishes and periodically refreshes this node's worker record.
func advertiseWorker(ctx context.Context, cfg config.Config, node *p2p.Node, admission *dcs.AdmissionController, logger *log.Logger) {
	interval := time.Duration(cfg.DCS.AdvertiseIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ttl := int64(cfg.DCS.RecordTTLSeconds)
	if ttl <= 0 {
		ttl = 900
	}
	var sequence uint64

	// Probe ONCE, here, rather than inside publish().
	//
	// The benchmark runs the CPU flat out for the best part of a second. That
	// is unremarkable at startup and would be rude every advertisement
	// interval, for a number that does not change — the machine's hardware is
	// not going to differ between one publish and the next. Re-probing belongs
	// on a long timer or a config reload, not on the heartbeat.
	//
	// Detection never fails (see compute.Probe), so there is no error path.
	profile := compute.Probe(compute.DefaultOptions())
	logger.Printf("dcs: compute profile: %s", profile.Summary())

	publish := func() {
		sequence++
		caps := []string{"worker"}
		// What the machine can actually do, alongside what its operator opted
		// into. Detection adds "cpu" — which every machine is, and which is the
		// broad base the compute network is built on — and adds "gpu" only when
		// a card reports a WORKING DRIVER. The config flag below is consent;
		// this is capability, and a job needs both.
		for _, detected := range profile.Capabilities() {
			caps = append(caps, detected)
		}
		if cfg.DCS.Role.GPU {
			caps = append(caps, "gpu")
		}
		if cfg.DCS.Role.Volumes {
			caps = append(caps, "volumes")
		}
		if cfg.DCS.Role.Lab {
			caps = append(caps, "lab")
		}
		// The record MUST carry the node's own AXON address -- it is the only
		// address a deployer can dial the worker at. Without it the bridge finds
		// the worker but has nothing to connect to ("invalid AXON address"). It
		// is the service behind the node's /axon/<addr> multiaddr, which exists
		// as soon as the node is on the overlay (well before this runs).
		destination := node.AxonAddress()
		if destination == "" {
			logger.Printf("dcs: worker not advertised yet -- AXON address not ready")
			return
		}
		now := time.Now()
		rec := dcs.WorkerRecord{
			RecordType: "dcs_worker", ProtocolVer: 1, AgentVersion: "1.0.0",
			Destination: destination, ContentPubKey: node.ContentPublicKey(),
			Arch: config.PlatformLabel(), Capabilities: dedupe(caps),
			// CPUCores was MaxContainers — the number of containers this node
			// will run, which is not a core count and is not what a scheduler
			// sizing a parallel job needs. Physical cores, because two SMT
			// threads on one core do not deliver two cores of throughput for
			// compute-bound work, so logical count systematically overcommits.
			CPUCores: profile.CPU.PhysicalCores, RAMBytes: cfg.DCS.Limits.RAMBytes,
			Compute: &profile,
			Slots:   cfg.DCS.Limits.MaxContainers, Region: cfg.DCS.Region,
			Sequence: sequence, IssuedAt: now.Unix(), ExpiresAt: now.Unix() + ttl,
		}
		signed, err := dcs.SignWorkerRecord(node, rec)
		if err != nil {
			logger.Printf("dcs: sign worker record: %v", err)
			return
		}
		pubCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := node.PublishDCSWorker(pubCtx, signed); err != nil {
			logger.Printf("dcs: publish worker record: %v", err)
		}
	}
	publish()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publish()
		}
	}
}

// ---- the deploy client (-dcs-deploy) ----

type dcsDeployOptions struct {
	image       string
	buildDir    string
	lab         bool
	runtimeSecs int
	primaryPort int
}

// runDCSDeploy is the client side end to end: open a node, discover workers,
// deploy to a random one, poll while queued, and print the container's private
// AXON address. It is what the README's "deploy a container" instructions call.
func runDCSDeploy(cfg config.Config, opts dcsDeployOptions, logger *log.Logger) {
	if opts.image == "" && opts.buildDir == "" {
		logger.Fatal("dcs-deploy: pass -dcs-image or -dcs-build-context")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A deploy needs the full node substrate: the overlay, the DHT, the shard
	// store (for a build context). Open it the same way the storage path does.
	storage, err := store.Open(
		filepath.Join(cfg.DataDir, "storage"),
		cfg.DataShards, cfg.ParityShards, cfg.ChunkBytes, cfg.CapacityBytes,
	)
	if err != nil {
		logger.Fatalf("dcs-deploy: open store: %v", err)
	}
	defer storage.Close()

	logger.Printf("dcs-deploy: joining AXON and the DHT (this can take a minute)…")
	overlay, origin, err := startOverlay(ctx, cfg, false, logger)
	if err != nil {
		logger.Fatalf("dcs-deploy: join the overlay: %v", err)
	}
	defer overlay.Close()
	node, err := p2p.Open(ctx, cfg.DataDir, p2p.Overlay{Runtime: overlay, Origin: origin}, storage, logger)
	if err != nil {
		logger.Fatalf("dcs-deploy: open node: %v", err)
	}
	defer node.Close()
	if err := node.ConfigureDCSRecords(dcs.WorkerDHTValidator{}); err != nil {
		logger.Fatalf("dcs-deploy: %v", err)
	}

	req := dcs.DeployRequest{
		DeploymentID: "cli-" + short(node.ID()) + "-" + shortTime(),
		Image:        opts.image, Lab: opts.lab,
		RuntimeSecs: opts.runtimeSecs, PrimaryPort: opts.primaryPort,
	}

	// A build context: pack the directory, store it on the DHT as shards, and
	// reference it by digest so the worker builds it.
	if opts.buildDir != "" {
		files, err := loadBuildDir(opts.buildDir)
		if err != nil {
			logger.Fatalf("dcs-deploy: build context: %v", err)
		}
		digest, err := dcs.StoreBuildContext(ctx, NewStoreBlobStore(storage), files)
		if err != nil {
			logger.Fatalf("dcs-deploy: store build context: %v", err)
		}
		req.BuildContextDigest = digest
		logger.Printf("dcs-deploy: build context stored on the DHT (%s)", digest)
	}

	logger.Printf("dcs-deploy: discovering workers…")
	workers, err := node.FindDCSWorkers(ctx, 32)
	if err != nil || len(workers) == 0 {
		logger.Fatalf("dcs-deploy: no container workers found on the network")
	}
	logger.Printf("dcs-deploy: %d worker(s) available", len(workers))

	manager := dcs.NewManager(node, dcs.NewStreamTransport(node.Host()))

	// Deploy, polling through any queue. The manager picks a random worker; a
	// queued reply carries a countdown that we surface each poll.
	deadline := time.Now().Add(30 * time.Minute)
	var reply dcs.DeployReply
	var worker dcs.WorkerRecord
	for {
		reply, worker, err = manager.DeployToRandom(ctx, workers, req, nil)
		if err != nil {
			logger.Fatalf("dcs-deploy: %v", err)
		}
		if !reply.Queued {
			break
		}
		fmt.Printf("Queued on %s — position %d, about %s until a slot frees.\n",
			short(worker.NodeID), reply.Position, humaneDuration(reply.ETASeconds))
		if time.Now().After(deadline) {
			logger.Fatal("dcs-deploy: still queued after 30m; giving up")
		}
		req.Ticket = reply.Ticket
		// Refresh the worker view and wait before retrying.
		time.Sleep(15 * time.Second)
		if refreshed, rerr := node.FindDCSWorkers(ctx, 32); rerr == nil && len(refreshed) > 0 {
			workers = refreshed
		}
	}

	fmt.Println()
	fmt.Println("Container deployed.")
	fmt.Printf("  worker:       %s\n", worker.NodeID)
	fmt.Printf("  container:    %s\n", reply.ContainerID)
	fmt.Printf("  AXON address: %s\n", reply.Destination)
	if reply.Private {
		fmt.Println("  visibility:   PRIVATE — only you were told this address")
	}
	if reply.ExpiresAt > 0 {
		fmt.Printf("  auto-expires: %s\n", time.Unix(reply.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
	if reply.Note != "" {
		fmt.Printf("  note:         %s\n", reply.Note)
	}
	fmt.Println()
	proxy := cfg.Axon.ProxyListen
	if proxy == "" {
		proxy = config.DefaultProxyListen + " (enable axon.proxy_listen)"
	}
	fmt.Printf("Reach it through this node's AXON proxy, http://%s, at the address above.\n", proxy)
	fmt.Println("It spins down on its own.")
}

func loadBuildDir(dir string) ([]dcs.BuildFile, error) {
	var files []dcs.BuildFile
	root := filepath.Clean(dir)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, _ := d.Info()
		mode := int64(0o644)
		if info != nil {
			mode = int64(info.Mode().Perm())
		}
		files = append(files, dcs.BuildFile{Path: filepath.ToSlash(rel), Mode: mode, Data: data})
		return nil
	})
	return files, err
}

func humaneDuration(seconds int64) string {
	if seconds <= 0 {
		return "moments"
	}
	d := time.Duration(seconds) * time.Second
	return d.Round(time.Second).String()
}

func shortTime() string {
	// A short, monotone-ish suffix for a deployment id. time.Now is fine here:
	// this is a CLI invocation, not one of the deterministic build paths.
	return short(dcs.BlobDigest([]byte(time.Now().UTC().Format(time.RFC3339Nano))))
}

// ---- adapters between the node's primitives and the dcs interfaces ----

// axonOpener starts a container's AXON hidden service from its key file, which
// is what keeps the container's address stable across a restart.
type axonOpener struct{ rt *runtime.Runtime }

func (o *axonOpener) Open(_ context.Context, keyPath string) (dcs.Session, error) {
	if o.rt == nil {
		return nil, errors.New("dcs: the node is not on the AXON overlay")
	}
	seed, err := p2p.LoadOrCreateServiceSeed(keyPath)
	if err != nil {
		return nil, err
	}
	service, err := o.rt.Listen(seed)
	if err != nil {
		return nil, err
	}
	return axonSession{service}, nil
}

// axonSession is a container's service as the DCS package sees it.
type axonSession struct{ *runtime.Service }

func (s axonSession) Address() string { return s.Service.Addr() }

// AcceptStreamPort reports the port a caller dialed: runtime.DialContext sends
// the port of "<addr>.key.axon:8080" as the stream's metadata. A stream that
// names none (or something else) reports 0, and the proxy uses its default.
func (s axonSession) AcceptStreamPort() (net.Conn, int, error) {
	conn, err := s.Service.Accept()
	if err != nil {
		return nil, 0, err
	}
	port := 0
	if m, ok := conn.(interface{ Meta() []byte }); ok {
		if p, perr := strconv.Atoi(string(m.Meta())); perr == nil && p > 0 && p < 65536 {
			port = p
		}
	}
	return conn, port, nil
}

// containerSessions supplies the accepting session a container's inbound proxy
// runs on. It REUSES the service the address allocator already started for the
// container rather than starting a second one: a container has a single AXON
// address, and a second service on the same key would compete with the first
// for its intro points. Reusing it also guarantees the proxy accepts on the
// very address the deployer was handed -- otherwise ports read closed.
type containerSessions struct {
	alloc *dcs.AddressAllocator
}

// sharedAccepter hands the proxy the allocator-owned session but neutralises
// Close: the allocator's Release owns the session's lifecycle (it must outlive a
// proxy restart), so the proxy tearing down must not close the address's session.
type sharedAccepter struct{ dcs.SessionAccepter }

func (sharedAccepter) Close() error { return nil }

func (c *containerSessions) OpenForContainer(_ context.Context, containerID string) (dcs.SessionAccepter, error) {
	sess, ok := c.alloc.AcceptSession(containerID)
	if !ok {
		return nil, fmt.Errorf("dcs: no allocated AXON service for container %s", containerID)
	}
	return sharedAccepter{sess}, nil
}

// storeBlobStore stores build-context blobs in the shard store, content-addressed.
type storeBlobStore struct {
	store *store.Store
	// placer is set when the node has a p2p host, and is what makes a full
	// local store stop being a hard failure: the blob goes to a peer with room
	// and that peer announces itself as its provider. Nil on a node with no
	// network, where local-or-nothing is the only honest behaviour.
	placer *place.Placer
}

// SetPlacer enables peer placement for blobs this node cannot hold itself.
func (b *storeBlobStore) SetPlacer(p *place.Placer) { b.placer = p }

// NewStoreBlobStore adapts the shard store to dcs.BlobStore. Build contexts land
// in a dedicated bucket keyed by their digest, so the store's chunking,
// Reed-Solomon coding and DHT provider announcements carry them like any object.
//
// The bucket is (idempotently) created here: putObject refuses to write to a
// bucket that does not exist, so on a fresh or wiped store a PutBlob would fail
// with "file does not exist" until something created it.
func NewStoreBlobStore(s *store.Store) dcs.BlobStore {
	_ = s.CreateBucket(buildContextBucket)
	return &storeBlobStore{store: s}
}

const buildContextBucket = "dcs-buildctx"

func (b *storeBlobStore) PutBlob(ctx context.Context, data []byte) (string, error) {
	digest := dcs.BlobDigest(data)
	_, err := b.store.PutObject(buildContextBucket, digest, "application/x-tar", bytes.NewReader(data))
	if err == nil {
		return digest, nil
	}
	// Local first, peer second. A node with room keeps its own writes, so the
	// common path is unchanged and no traffic is generated for it.
	//
	// Being FULL is different from being broken: it is the one failure the
	// network can answer, and answering it is the difference between a DHT that
	// pools capacity and a directory of independent disks. Any other error —
	// permissions, corruption, a bad bucket — is this node's problem and is
	// returned unchanged rather than quietly shipped elsewhere.
	if b.placer == nil || !isCapacityError(err) {
		return "", err
	}
	_, placeErr := b.placer.Place(ctx, digest, data)
	if placeErr != nil {
		// Both failures are reported. "Full here AND nowhere to put it" is a
		// different operational problem from either half alone.
		return "", fmt.Errorf("local store full (%v) and placement failed: %w", err, placeErr)
	}
	return digest, nil
}

// isCapacityError matches the store's out-of-room condition. Compared on the
// message because store.ensureCapacity returns errors.New; a sentinel there
// would be better and is a change to that package rather than this one.
func isCapacityError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "storage capacity exceeded")
}

func (b *storeBlobStore) GetBlob(_ context.Context, digest string) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := b.store.GetObject(buildContextBucket, digest, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// logAudit writes the worker's audit trail to the node log. It is the operator's
// record of what strangers did with their hardware.
type logAudit struct{ logger *log.Logger }

func (a *logAudit) Record(e dcs.AuditEntry) {
	a.logger.Printf("dcs audit: %s %s owner=%s deployment=%s container=%s %s",
		e.Method, e.Decision, short(e.Requester), e.DeploymentID, e.ContainerID, e.Reason)
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// dedupe keeps the first occurrence of each capability.
//
// Needed because two sources now contribute: what was detected, and what the
// operator opted into in config. Both legitimately say "gpu" on a machine with
// a working card whose owner has also enabled it, and a record listing it twice
// is not wrong so much as sloppy — it inflates a record the DHT has to carry
// and reads as a bug to anyone looking at one.
func dedupe(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := items[:0:0]
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
