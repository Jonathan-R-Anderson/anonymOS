package p2p

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	coretransport "github.com/libp2p/go-libp2p/core/transport"
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"

	"github.com/syndichan/maniwani/storage-client/internal/bootstrap"
	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/dcs"
	"github.com/syndichan/maniwani/storage-client/internal/gateway"
	"github.com/syndichan/maniwani/storage-client/internal/heartbeat"
	syndii2p "github.com/syndichan/maniwani/storage-client/internal/i2p"
	"github.com/syndichan/maniwani/storage-client/internal/place"
	"github.com/syndichan/maniwani/storage-client/internal/placement"
	"github.com/syndichan/maniwani/storage-client/internal/store"
	"github.com/syndichan/maniwani/storage-client/internal/traffic"
)

const (
	ProtocolID       = protocol.ID("/syndichan/storage/1.0.0")
	maxHeaderBytes   = 64 << 10
	maxNetworkShard  = 32 << 20
	bootstrapRefresh = 15 * time.Minute
	heartbeatRefresh = heartbeat.Interval
	// An I2P dial is nothing like a TCP dial. Before libp2p's Noise handshake
	// can even begin, the router must look the destination's LeaseSet up from
	// the floodfills, build or reuse a tunnel pair, and complete several
	// garlic-encrypted round trips -- each hop adding its own latency. A cold
	// dial routinely takes 20-60 seconds.
	//
	// This was 10 seconds for both cases, which expired during the LeaseSet
	// lookup. Every bootstrap attempt failed with "all dials failed" no matter
	// how healthy both routers were: correct destination, established tunnels,
	// unfirewalled router, and still no peer ever connected.
	i2pDialTimeout    = 2 * time.Minute
	directDialTimeout = 10 * time.Second
	// Retry cadence WHILE STILL PEERLESS. A freshly installed I2P router needs
	// 10-30 minutes to integrate into the network, so the first attempts are
	// expected to fail. At the 15-minute steady-state cadence that is roughly
	// one doomed attempt per 15 minutes, and a new node can sit peerless for
	// hours. Retry quickly until the first peer sticks, then back off.
	bootstrapRetry = 60 * time.Second
	// Backfill cadence for shards stored before any peer existed.
	//
	// Sized against the backlog it has to clear, not against a single object.
	// Measured on production once dispersal started working: 12,639 objects had
	// no remote copy, and 5 per 5-minute pass drains that in about twelve DAYS
	// -- during which every one of those objects is a single copy on one disk,
	// which is the exact condition this whole subsystem exists to end.
	//
	// The old comment called it "a trickle, not a flush" because each shard
	// needs a coordinator lease over I2P first. That cost is real but it is
	// per-shard and concurrent, not per-object and serial, so the batch was
	// throttling the wrong thing. 40 keeps a pass bounded while cutting the
	// drain to well under a day.
	//
	// Raise further only with evidence: the ceiling is the lease service and
	// the peers' willingness to accept shards, and a batch that outruns either
	// converts a slow backlog into a loud one.
	replicateInterval = 5 * time.Minute
	replicateBatch    = 40
	StorageUserAgent  = heartbeat.UserAgent
)

var heartbeatEndpoint = heartbeat.Endpoint

// SetHeartbeatEndpoint points presence beacons at a non-default origin. Called
// once at startup from the config; a no-op when the config leaves it empty.
func SetHeartbeatEndpoint(url string) {
	if url != "" {
		heartbeatEndpoint = url
	}
}

// A var, like heartbeatEndpoint above, so tests can point the lease exchange at
// a local server instead of reaching the production coordinator.
var leaseURL = "https://syndichan.org/api/v1/storage/leases"

type BootstrapDocument struct {
	Version              int       `json:"version"`
	Peers                []string  `json:"peers"`
	CoordinatorPublicKey string    `json:"coordinator_public_key"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type Lease struct {
	Version   int    `json:"version"`
	ObjectID  string `json:"object_id"`
	ShardID   string `json:"shard_id"`
	Size      int64  `json:"size"`
	Recipient string `json:"recipient"`
	ExpiresAt int64  `json:"expires_at"`
	Signature string `json:"signature"`
}

type requestHeader struct {
	Operation string `json:"operation"`
	ShardID   string `json:"shard_id"`
	ObjectID  string `json:"object_id,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Lease     *Lease `json:"lease,omitempty"`
	// Revocation authorises the "delete" operation and nothing else. A separate
	// field from Lease on purpose -- see internal/p2p/recall.go for why the two
	// tokens must never be interchangeable.
	Revocation *Revocation `json:"revocation,omitempty"`
}

type responseHeader struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Present bool   `json:"present,omitempty"`
	Size    int64  `json:"size,omitempty"`
	// Deleted answers the "delete" operation: the shard was here and is gone.
	Deleted bool `json:"deleted,omitempty"`
	// Refused marks an answer that was an explicit no rather than a failure. The
	// purge report treats "the holder refused" and "the holder never answered"
	// as different, true outcomes, so the wire has to keep them apart too.
	Refused bool `json:"refused,omitempty"`
	// Status carries a compute answer's result code, in the HTTP vocabulary the
	// node's own /compute/* endpoints already speak. Present on compute frames
	// and absent everywhere else.
	//
	// It is on the wire rather than being reconstructed from Error and Refused
	// because it is the thing that keeps a refusal a refusal all the way to the
	// site: "busy, ask again" and "you named a workload I do not have" are both
	// declines and the site does different things with them. A zero Status on a
	// compute frame therefore means the peer did not answer AS a compute node --
	// see SendCompute in compute.go, which is the only place that reads it.
	Status int `json:"status,omitempty"`
}

type leaseRequest struct {
	Version   int    `json:"version"`
	Requester string `json:"requester"`
	Recipient string `json:"recipient"`
	ObjectID  string `json:"object_id"`
	ShardID   string `json:"shard_id"`
	Size      int64  `json:"size"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
}

type Node struct {
	// meter counts bytes this node served to others, drained once per
	// heartbeat. Optional: a node with none reports an absent traffic block,
	// which the coordinator reads as "not measuring" rather than "measured
	// zero" -- the status page draws those differently.
	meter *traffic.Meter
	// monitorEnabled mirrors the config so the heartbeat can report the role.
	monitorEnabled bool

	// The operator's two compute switches, mirrored for the heartbeat. Both
	// must be true-by-configuration AND compute enabled before the node claims
	// the role — the same rule the gpu capability already follows, so a
	// capability is advertised only when the mechanism behind it is real.
	gpuCompute bool
	cpuCompute bool
	microVM    bool
	// computeCatalogueReady is the MEASURED half of the compute claim: this node
	// holds every image the catalogue names, so any workload it is sent can
	// actually be run.
	//
	// Both switches above are ANDed with it, because a node that offers compute
	// does not get to pick which catalogue workloads it takes — so "I lend CPU"
	// and "I can run the catalogue" are one claim, not two, and a node that
	// cannot make the second must stop making the first. False until something
	// checks, which is the right way round: a node fetching its images has not
	// yet earned the advertisement, and a node with no container runtime never
	// will.
	//
	// Atomic because it is written by the image loader's goroutine minutes after
	// start and read by the heartbeat's, where every other field here is written
	// once before either exists.
	computeCatalogueReady atomic.Bool

	// computePeers is what this node knows about where compute lives, refreshed
	// from the signed bootstrap document. Held locally so a node can ask "who
	// else can run this" without asking the site first — otherwise the site is
	// the network.
	computePeers *bootstrap.ComputeRegistry
	// challengeMu guards challengeHandler. Per-node, not package-level:
	// a process can run more than one Node (tests do), and a shared
	// handler would answer challenges with the wrong node's data.
	challengeMu      sync.RWMutex
	challengeHandler func(ctx context.Context, payload []byte) ([]byte, error)
	// computeHandler answers compute frames from peers, and is nil on every node
	// that lends no compute -- which is most of them, and why the handler is
	// checked rather than assumed. Its own mutex for the same reason the
	// challenge handler has one: a process can run more than one Node.
	computeMu      sync.RWMutex
	computeHandler ComputeHandler
	host           host.Host
	dht            *dht.IpfsDHT
	store          *store.Store
	logger         *log.Logger
	bootstrap      string
	// bootstrapConfig is nil until SetBootstrapConfig is called, which is what
	// keeps an upgraded node on its existing behaviour instead of refusing the
	// only source it has.
	bootstrapMu     sync.RWMutex
	bootstrapConfig *bootstrap.Config
	// dataDir is where node state lives, and is what the bootstrap peer cache
	// is written into. Held rather than passed down because the cache is
	// written from the refresh path, which runs on a timer and has no caller
	// to take it from.
	dataDir string
	// contained is the operator's containment list, or nil.
	//
	// The bootstrap path needs it for a reason the incident drill found the
	// hard way: the peer cache is on DISK, so a host an operator contained came
	// back on the next restart through a path that consulted nothing --
	// containment that lapses across exactly the restart it was built to
	// survive. See INCIDENT-RESPONSE.md step 3.
	containMu sync.RWMutex
	contained interface{ Denied(id string) bool }

	http           *http.Client
	directHTTP     *http.Client
	keyMu          sync.RWMutex
	coordKey       ed25519.PublicKey
	peerMu         sync.RWMutex
	bootstrapPeers map[peer.ID]struct{}
	i2pOnly        bool
	// candidateCache holds the storage peers the last discovery found, so one
	// dispersal pass does not issue a DHT capacity query per chunk.
	// refusals tracks peers that answered "no" to a shard, so the planner stops
	// spending one of a chunk's nine slots on a peer that will refuse again. See
	// noteRefusal in disperse.go for why it is neither permanent nor persisted.
	refusalMu sync.Mutex
	refusals  map[string]*peerRefusal
	// placementHealth is the last completed replicate pass, and nil until there
	// has been one. Nil rather than a zero struct on purpose -- the heartbeat
	// omits the block entirely so the coordinator can say "not reporting"
	// instead of drawing an unmeasured node as a healthy one. See health.go.
	healthMu        sync.RWMutex
	placementHealth *PlacementHealth
	candidateMu     sync.Mutex
	candidateCache  []placement.Candidate
	// capacityRecords is the UNFILTERED half of the same discovery: every fresh
	// capacity record, including peers this node will not currently write to.
	// Levelling reads occupancy from here rather than from candidateCache; see
	// occupancyRecords in disperse.go for why the difference matters.
	capacityRecords []place.Record
	candidateAt     time.Time
	// repairing is the single-flight set for repair. Keyed by shard id, so two
	// passes -- or a pass overlapping the one before it -- can never regenerate
	// and re-place the same shard twice at once. See repair.go.
	repairMu  sync.Mutex
	repairing map[string]struct{}
	// placing serialises placement rounds per object, so two overlapping rounds
	// cannot each hand the same peer a different shard of one chunk. See
	// lockPlacement in disperse.go.
	placingMu sync.Mutex
	placing   map[string]*placementGate
	// shardMoves is the rate limit repair and levelling SHARE. Both move shards
	// and both draw on the same coordinator; unbounded they fight over the leases
	// placement needs. Repair records against it and is never refused, levelling
	// is refused as soon as the window is spent. See rebalance.go.
	shardMoves *shardMoveBudget
	// cacheOnly nodes serve their own content but host nothing for anyone
	// else; see the "store" branch of handleStream.
	cacheOnly bool
	// draining marks this node as being retired: it accepts no new shards and
	// says so in its capacity record, so owners move what it already holds off it.
	// Atomic rather than plain, unlike cacheOnly, because the management page can
	// flip it while the node is running -- an operator deciding to retire a
	// machine should not have to restart it to start the drain.
	draining atomic.Bool
	// drainingPeers is what OTHER nodes have said about themselves, with the
	// deadline their record stops being trusted at. See markDraining.
	drainingMu    sync.Mutex
	drainingUntil map[string]time.Time

	gatewayEnabled      atomic.Bool
	gatewayVerified     atomic.Bool
	dcsWorker           atomic.Bool
	gatewayMu           sync.RWMutex
	gatewayRegistration *gateway.Registration
	// Curve25519 keypair for receiving sealed per-object content keys from the
	// coordinator. Separate from the ed25519 libp2p identity, which cannot do
	// ECDH. Zero on nodes that never load one (they simply cannot open a grant).
	contentPriv [32]byte
	contentPub  [32]byte
}

// SetCacheOnly makes this node refuse to host other peers' shards. Set once at
// startup, before the stream handler can see traffic.
func (n *Node) SetCacheOnly(value bool) { n.cacheOnly = value }

// SetDraining retires (or un-retires) this node. See config.Config.Draining and
// drain.go; the persistent copy of the intent is the config file, this is the
// running node acting on it.
func (n *Node) SetDraining(value bool) { n.draining.Store(value) }

// Draining reports whether this node is being retired.
func (n *Node) Draining() bool { return n.draining.Load() }

// SetDCSWorker marks the node as accepting container deployments, so its
// heartbeat reports the DCS role and the operator's map draws it yellow.
func (n *Node) SetDCSWorker(on bool) { n.dcsWorker.Store(on) }

func (n *Node) SetGatewayState(enabled, verified bool) {
	n.gatewayEnabled.Store(enabled)
	n.gatewayVerified.Store(enabled && verified)
}

func (n *Node) SetGatewayRegistration(registration *gateway.Registration) {
	n.gatewayMu.Lock()
	defer n.gatewayMu.Unlock()
	if registration == nil {
		n.gatewayRegistration = nil
		return
	}
	copy := *registration
	n.gatewayRegistration = &copy
}

func (n *Node) RefreshHeartbeat(ctx context.Context) {
	n.sendHeartbeat(ctx, heartbeatEndpoint)
}

func Open(ctx context.Context, dataDir, samAddr, httpProxy string, storage *store.Store, logger *log.Logger) (*Node, error) {
	return openI2PNode(ctx, dataDir, samAddr, httpProxy, storage, logger, true)
}

// OpenGateway creates the identity and I2P DHT transport needed to publish
// independently verified gateway records, but deliberately does not install
// the shard protocol, advertise/replicate stored data, or send storage-node
// heartbeats. It is the networking substrate for the command's gateway-only
// mode, not a storage peer with its UI hidden.
func OpenGateway(ctx context.Context, dataDir, samAddr, httpProxy string, logger *log.Logger) (*Node, error) {
	return openI2PNode(ctx, dataDir, samAddr, httpProxy, nil, logger, false)
}

func openI2PNode(
	ctx context.Context,
	dataDir, samAddr, httpProxy string,
	storage *store.Store,
	logger *log.Logger,
	storageEnabled bool,
) (*Node, error) {
	identity, err := loadOrCreateIdentity(filepath.Join(dataDir, "p2p.key"))
	if err != nil {
		return nil, err
	}
	session, err := syndii2p.Open(ctx, samAddr, filepath.Join(dataDir, "i2p.destination"))
	if err != nil {
		return nil, err
	}
	local, err := syndii2p.Multiaddr(session.Base32())
	if err != nil {
		session.Close()
		return nil, err
	}
	h, err := libp2p.New(
		libp2p.Identity(identity),
		libp2p.NoTransports,
		libp2p.Transport(func(upgrader coretransport.Upgrader, rcmgr network.ResourceManager) (coretransport.Transport, error) {
			return syndii2p.NewTransport(upgrader, rcmgr, session)
		}),
		libp2p.ListenAddrs(local),
		libp2p.DisableRelay(),
		libp2p.AddrsFactory(i2pAddressesOnly),
	)
	if err != nil {
		session.Close()
		return nil, err
	}
	proxyURL, err := url.Parse(httpProxy)
	if err != nil {
		h.Close()
		return nil, err
	}
	httpClient := &http.Client{
		Timeout: 75 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	directHTTP := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			// Intentionally direct: heartbeat presence is the one connection the
			// user explicitly requires to bypass I2P. A nil Proxy also prevents
			// HTTP_PROXY/HTTPS_PROXY environment variables from changing that.
			Proxy:           nil,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	return finishNode(ctx, h, dataDir, storage, logger, httpClient, directHTTP, true, true, storageEnabled)
}

func openNode(ctx context.Context, dataDir string, listen []string, storage *store.Store, logger *log.Logger, useCoordinatorBootstrap bool) (*Node, error) {
	identity, err := loadOrCreateIdentity(filepath.Join(dataDir, "p2p.key"))
	if err != nil {
		return nil, err
	}
	h, err := libp2p.New(
		libp2p.Identity(identity),
		libp2p.ListenAddrStrings(listen...),
		libp2p.NATPortMap(),
		libp2p.EnableHolePunching(),
	)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
	}
	return finishNode(ctx, h, dataDir, storage, logger, httpClient, httpClient, useCoordinatorBootstrap, false, true)
}

func finishNode(
	ctx context.Context,
	h host.Host,
	dataDir string,
	storage *store.Store,
	logger *log.Logger,
	httpClient *http.Client,
	directHTTP *http.Client,
	useCoordinatorBootstrap bool,
	i2pOnly bool,
	storageEnabled bool,
) (*Node, error) {
	kad, err := dht.New(h, dht.Mode(dht.ModeAutoServer))
	if err != nil {
		h.Close()
		return nil, err
	}
	n := &Node{
		host: h, dht: kad, store: storage, logger: logger, bootstrap: config.BootstrapURL,
		bootstrapPeers: make(map[peer.ID]struct{}), http: httpClient, dataDir: dataDir,
		directHTTP: directHTTP, i2pOnly: i2pOnly,
		repairing: make(map[string]struct{}), shardMoves: newShardMoveBudget(),
		// Empty until the first bootstrap fetch, and empty reports STALE — so a
		// node that has not yet learned the network offers no candidates rather
		// than silently offering none and looking healthy.
		computePeers: bootstrap.NewComputeRegistry(),
	}
	// The content key persists beside the identity so the same node keeps the
	// same address workers' grants are sealed to across restarts.
	contentPriv, contentPub, err := loadOrCreateContentKey(filepath.Join(dataDir, "content.key"))
	if err != nil {
		h.Close()
		return nil, err
	}
	n.contentPriv, n.contentPub = contentPriv, contentPub
	if storageEnabled {
		h.SetStreamHandler(ProtocolID, n.handleStream)
	}
	// Object manifests are how one node reassembles another's object by content;
	// register their validator before any put/get can occur.
	if err := n.configureObjectManifestRecords(); err != nil {
		h.Close()
		return nil, err
	}
	if err := kad.Bootstrap(ctx); err != nil {
		h.Close()
		return nil, err
	}
	if useCoordinatorBootstrap {
		go n.bootstrapLoop(ctx)
	}
	if i2pOnly && storageEnabled {
		go n.heartbeatLoop(ctx)
	}
	if storageEnabled {
		go n.ReplicateStored(ctx)
		// Dispersal makes an object redundant once. Repair keeps it that way
		// when a holder goes away, which is the half that did not exist at all.
		go n.RepairStored(ctx)
		// Recall is the reverse of dispersal: holders that were unreachable when
		// an object was purged are chased until they answer, so a partial recall
		// finishes itself instead of quietly stopping.
		go n.RecallStored(ctx)
		// Levelling is last, in the list and in priority. It moves shards off
		// nodes holding more than their share onto nodes holding less, and it
		// yields to both of the loops above -- per object (never levels one that
		// is under-replicated) and per half hour (a rate limit it shares with
		// repair).
		go n.RebalanceStored(ctx)
		// Draining is levelling with a target of zero, for a machine that is
		// leaving. It runs whether or not THIS node is being retired: the mover
		// belongs to the OWNER of the shards, and the node being retired is
		// somebody else's peer. Both loops are no-ops until some peer says it is
		// draining, or until this one is told it is.
		go n.DrainStored(ctx)
		go n.ReportDrainStatus(ctx)
	}
	return n, nil
}

func i2pAddressesOnly(values []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	result := make([]multiaddr.Multiaddr, 0, len(values))
	for _, value := range values {
		if syndii2p.IsI2PAddr(value) {
			result = append(result, value)
		}
	}
	return result
}

func (n *Node) Close() error {
	_ = n.dht.Close()
	return n.host.Close()
}

func (n *Node) ID() string { return n.host.ID().String() }

// Sign and PublicKey expose only the public operations needed by the gateway
// protocol. The persistent libp2p private key never leaves the peerstore.
func (n *Node) Sign(message []byte) ([]byte, error) {
	key := n.host.Peerstore().PrivKey(n.host.ID())
	if key == nil {
		return nil, errors.New("node identity unavailable")
	}
	return key.Sign(message)
}

func (n *Node) PublicKey() ([]byte, error) {
	key := n.host.Peerstore().PubKey(n.host.ID())
	if key == nil {
		return nil, errors.New("node public key unavailable")
	}
	return crypto.MarshalPublicKey(key)
}

func (n *Node) DHTReady() bool {
	return n.dht != nil && len(n.host.Network().Peers()) > 0
}

// ConfigureGatewayRecords installs the signed registration validator before
// any gateway record is read or published. DHT values remain untrusted until
// this validator verifies candidate identity and the admitted-probe quorum.
func (n *Node) ConfigureGatewayRecords(validator gateway.DHTValidator) error {
	namespaces, ok := n.dht.Validator.(record.NamespacedValidator)
	if !ok {
		return errors.New("DHT does not use namespaced validation")
	}
	namespaces[gateway.DHTNamespace] = validator
	return nil
}

// Host exposes the libp2p host so the DCS subsystem can register its stream
// protocol and open streams to workers over the SAME I2P transport the storage
// protocol uses. DCS reuses this host rather than opening a second network.
func (n *Node) Host() host.Host { return n.host }

// ConfigureDCSRecords registers the validator for dcs_worker DHT records, so a
// worker's capability advertisement is validated and selected-by-sequence just
// like a gateway registration.
func (n *Node) ConfigureDCSRecords(validator dcs.WorkerDHTValidator) error {
	namespaces, ok := n.dht.Validator.(record.NamespacedValidator)
	if !ok {
		return errors.New("DHT does not use namespaced validation")
	}
	namespaces[dcs.DHTWorkerNamespace] = validator
	return nil
}

// PublishDCSWorker stores this node's signed worker record in the DHT under its
// own key AND advertises it at the worker rendezvous point, so deployers can
// enumerate workers (Kademlia cannot list a namespace by itself). Republished
// on the DCS advertise interval, expired-not-deleted, so a crashed worker
// vanishes on its own.
func (n *Node) PublishDCSWorker(ctx context.Context, record dcs.WorkerRecord) error {
	value, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := n.dht.PutValue(ctx, dcs.WorkerDHTKey(record.NodeID), value); err != nil {
		return err
	}
	// Rendezvous: every worker provides the same well-known CID, so a deployer
	// finds all of them with one FindProviders and then reads each record.
	rendezvous, err := dcsRendezvousCID()
	if err != nil {
		return err
	}
	return n.dht.Provide(ctx, rendezvous, true)
}

// FindDCSWorkers discovers container workers: find the providers of the
// rendezvous CID, read each one's signed capability record, and return the
// valid, unexpired ones. This is the deployer's view of available capacity.
func (n *Node) FindDCSWorkers(ctx context.Context, limit int) ([]dcs.WorkerRecord, error) {
	rendezvous, err := dcsRendezvousCID()
	if err != nil {
		return nil, err
	}
	validator := dcs.WorkerDHTValidator{}
	seen := map[peer.ID]struct{}{}
	var workers []dcs.WorkerRecord
	for provider := range n.dht.FindProvidersAsync(ctx, rendezvous, limit) {
		if provider.ID == n.host.ID() {
			continue // do not schedule onto ourselves
		}
		if _, dup := seen[provider.ID]; dup {
			continue
		}
		seen[provider.ID] = struct{}{}

		value, err := n.dht.GetValue(ctx, dcs.WorkerDHTKey(provider.ID.String()))
		if err != nil {
			continue
		}
		// Validate the record itself (signature, freshness, self-key) before
		// trusting anything it claims.
		if validator.Validate(dcs.WorkerDHTKey(provider.ID.String()), value) != nil {
			continue
		}
		var rec dcs.WorkerRecord
		if json.Unmarshal(value, &rec) != nil {
			continue
		}
		// Teach the host how to reach this worker for the later DCS stream.
		if len(provider.Addrs) > 0 {
			n.host.Peerstore().AddAddrs(provider.ID, provider.Addrs, 30*time.Minute)
		}
		workers = append(workers, rec)
		if limit > 0 && len(workers) >= limit {
			break
		}
	}
	return workers, nil
}

// LookupDCSWorker fetches and validates one worker's record by node id. Used to
// recover a worker's content key on a re-poll, where the caller knows only the
// worker id it was queued on.
func (n *Node) LookupDCSWorker(ctx context.Context, nodeID string) (dcs.WorkerRecord, error) {
	key := dcs.WorkerDHTKey(nodeID)
	value, err := n.dht.GetValue(ctx, key)
	if err != nil {
		return dcs.WorkerRecord{}, err
	}
	if err := (dcs.WorkerDHTValidator{}).Validate(key, value); err != nil {
		return dcs.WorkerRecord{}, err
	}
	var rec dcs.WorkerRecord
	if err := json.Unmarshal(value, &rec); err != nil {
		return dcs.WorkerRecord{}, err
	}
	return rec, nil
}

// dcsRendezvousCID is the well-known content id every DCS worker provides. It is
// the SHA-256 of a fixed label, so any node computes the same CID without
// coordination.
func dcsRendezvousCID() (cid.Cid, error) {
	digest := sha256.Sum256([]byte("syndichan-dcs-worker-rendezvous/1"))
	mh, err := multihash.Encode(digest[:], multihash.SHA2_256)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, mh), nil
}

func (n *Node) PublishGatewayRegistration(ctx context.Context, registration gateway.Registration) error {
	value, err := json.Marshal(registration)
	if err != nil {
		return err
	}
	return n.dht.PutValue(ctx, gateway.DHTKey(registration.NodeID), value)
}

func (n *Node) GatewayRegistration(ctx context.Context, nodeID string) (gateway.Registration, error) {
	value, err := n.dht.GetValue(ctx, gateway.DHTKey(nodeID))
	if err != nil {
		return gateway.Registration{}, err
	}
	var registration gateway.Registration
	if err := json.Unmarshal(value, &registration); err != nil {
		return gateway.Registration{}, err
	}
	return registration, nil
}

// PeerCount is how many peers this node is connected to RIGHT NOW. Volunteers
// are dial-in only behind NAT, so this drops to zero whenever the connection
// lapses and recovers on the next bootstrap retry -- it is a live gauge, not a
// count of everyone who has ever joined.
func (n *Node) PeerCount() int { return len(n.host.Network().Peers()) }

func (n *Node) Addresses() []string {
	result := make([]string, 0, len(n.host.Addrs()))
	for _, addr := range n.host.Addrs() {
		result = append(result, addr.String()+"/p2p/"+n.host.ID().String())
	}
	return result
}

// I2PDestination returns this node's own base32 garlic destination -- the <b32>
// in its /garlic32/<b32> address -- or "" before the I2P session is up. It is
// what another peer dials to reach this node. The node reports it in its
// heartbeat so the coordinator can hand it out as a live bootstrap peer.
func (n *Node) I2PDestination() string {
	for _, addr := range n.host.Addrs() {
		for _, part := range strings.Split(addr.String(), "/") {
			// a garlic32 host is 52 base32 chars; the multiaddr is /garlic32/<b32>.
			if len(part) == 52 && isBase32Lower(part) {
				return part
			}
		}
	}
	return ""
}

func isBase32Lower(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			return false
		}
	}
	return true
}

func loadOrCreateIdentity(path string) (crypto.PrivKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return crypto.UnmarshalPrivateKey(raw)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		return nil, err
	}
	raw, err = crypto.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func (n *Node) bootstrapLoop(ctx context.Context) {
	for {
		n.refreshBootstrap(ctx)
		// Pace on OUTCOME, not on a fixed clock. While the node has no live
		// bootstrap peer it has no network at all, so retrying is the only
		// useful thing it can do; once a peer sticks, the document only needs
		// an occasional refresh.
		delay := bootstrapRefresh
		if n.liveBootstrapPeers() == 0 {
			delay = bootstrapRetry
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// liveBootstrapPeers counts bootstrap peers there is currently a connection to.
// Membership in n.bootstrapPeers only records that a dial once succeeded, which
// stays true long after the connection has dropped -- so it cannot be used to
// decide whether the node still has a network.
func (n *Node) liveBootstrapPeers() int {
	n.peerMu.Lock()
	ids := make([]peer.ID, 0, len(n.bootstrapPeers))
	for id := range n.bootstrapPeers {
		ids = append(ids, id)
	}
	n.peerMu.Unlock()
	live := 0
	for _, id := range ids {
		if n.host.Network().Connectedness(id) == network.Connected {
			live++
		}
	}
	return live
}

func (n *Node) heartbeatLoop(ctx context.Context) {
	n.sendHeartbeat(ctx, heartbeatEndpoint)
	ticker := time.NewTicker(heartbeatRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.sendHeartbeat(ctx, heartbeatEndpoint)
		}
	}
}

// SetMeter attaches the shared traffic meter. One meter per process, so the
// S3 gateway and the shard store add to the same total rather than each
// keeping a count nobody sums.
func (n *Node) SetMeter(m *traffic.Meter) { n.meter = m }

// SetMonitorEnabled records that this node runs the status monitor, so the
// heartbeat reports the role and the operator's map can draw it.
func (n *Node) SetMonitorEnabled(on bool) { n.monitorEnabled = on }

// SetComputeRoles records what the operator agreed to lend.
//
// Takes `enabled` separately and ANDs it in, so that turning compute off stops
// the node advertising either device without silently clearing the operator's
// per-device choices — they are still there when compute is switched back on.
func (n *Node) SetComputeRoles(enabled, cpu, gpu bool) {
	n.cpuCompute = enabled && cpu
	n.gpuCompute = enabled && gpu
}

// SetComputeCatalogueReady records whether this node holds every catalogue
// image, which is what decides whether the compute switches above are a claim
// it can honour.
//
// Called by the image loader, and called with FALSE as readily as with true: an
// image that disappears between sweeps takes the advertisement down with it,
// because the alternative is a node that keeps being chosen for work it will
// fail. Withdrawing a capability is the correct response to losing it.
func (n *Node) SetComputeCatalogueReady(ready bool) {
	n.computeCatalogueReady.Store(ready)
}

// ComputeCatalogueReady reports the last thing the loader said.
func (n *Node) ComputeCatalogueReady() bool { return n.computeCatalogueReady.Load() }

// computeClaim is what this node may honestly advertise about compute.
//
// One function rather than two expressions in the heartbeat snapshot, because
// this is the rule the whole D.2 change exists to state: an operator who offers
// compute does not choose which catalogue workloads they take, so being unable
// to run the catalogue is being unable to offer compute. Any future field that
// affects that belongs here, where it is one rule, and not beside a struct
// literal where it would be two.
func (n *Node) computeClaim() (cpu, gpu bool) {
	ready := n.computeCatalogueReady.Load()
	return n.cpuCompute && ready, n.gpuCompute && ready
}

// SetMicroVM records MEASURED hardware isolation.
//
// Takes the probe's verdict, not a config flag: an operator cannot declare
// isolation they do not have, because the whole point is that arbitrary code is
// placed only where the boundary is real.
func (n *Node) SetMicroVM(usable bool) { n.microVM = usable }

// sendHeartbeat delegates to the shared client so a storage node and a
// dedicated gateway put exactly the same signed document on the wire.
func (n *Node) sendHeartbeat(ctx context.Context, endpoint string) {
	client := &heartbeat.Client{
		Signer: n, Endpoint: endpoint, HTTP: n.directHTTP, Logger: n.logger,
		Snapshot: func() heartbeat.State {
			n.gatewayMu.RLock()
			registration := n.gatewayRegistration
			n.gatewayMu.RUnlock()
			// Read fresh on every beat rather than latched at start, so a node
			// whose images arrive five minutes in begins advertising on the next
			// beat without a restart, and one that loses them stops on the next
			// beat too.
			cpuCompute, gpuCompute := n.computeClaim()
			state := heartbeat.State{
				CapacityBytes:   n.store.Capacity(),
				UsedBytes:       usedBytesOrZero(n.store),
				Draining:        n.draining.Load(),
				GatewayEnabled:  n.gatewayEnabled.Load(),
				GatewayVerified: n.gatewayVerified.Load(),
				Registration:    registration,
				DCSWorker:       n.dcsWorker.Load(),
				Monitor:         n.monitorEnabled,
				GPUCompute:      gpuCompute,
				CPUCompute:      cpuCompute,
				MicroVM:         n.microVM,
				I2PDestination:  n.I2PDestination(),
				// Read from the cached last pass -- no ledger walk and no peer
				// contact on the heartbeat path. Nil until a pass has completed,
				// and nil is sent as an absent field.
				Placement: placementBeacon(n.PlacementHealth(), time.Now()),
			}
			// The ONE legitimate drain. Window() resets, so a second caller
			// would silently take a slice of this one's interval and the
			// traffic would simply vanish -- no error, just a number quietly
			// too low. Everything else reads the meter by adding to it.
			if n.meter != nil {
				w := n.meter.Window(time.Now())
				state.Traffic = heartbeat.Traffic{
					Bytes: w.Bytes, Requests: w.Requests, WindowSeconds: w.WindowSeconds,
				}
			}
			return state
		},
		// The heartbeat doubles as the live bootstrap exchange: we report our
		// destination and the coordinator answers with a few reachable peers to
		// dial into the DHT. Dialling can block on I2P tunnel build, so run it
		// off the heartbeat goroutine.
		OnPeers: func(peers []string) {
			go n.connectBootstrapPeers(ctx, peers)
		},
	}
	client.Send(ctx)
}

// SetBootstrapConfig switches this node onto discovered, verified bootstrap.
//
// Opt-in on purpose. A node whose config has no `bootstrap` section keeps the
// old single-URL behaviour, because the new rules would REFUSE a lone
// unverifiable source — correct for a fresh install that was given a pinned
// coordinator key, and fatal for an existing node that was not. Silently
// applying them on upgrade would take those nodes off the DHT entirely, which
// is a worse outcome than the weaker trust they have today.
func (n *Node) SetBootstrapConfig(cfg bootstrap.Config) {
	n.bootstrapMu.Lock()
	defer n.bootstrapMu.Unlock()
	n.bootstrapConfig = &cfg
}

// SetContainment wires the operator's containment list into the bootstrap path.
//
// Bootstrap peers are named by their LIBP2P peer id and the containment list
// stores opaque strings, so a denial only bites here if that spelling is in the
// list. An operator containing an AXON relay must deny BOTH spellings --
// link.NodeIDFromPublic derives the libp2p id from the AXON identity key, and
// the runbook gives the one-liner. Two identities for one host is a sharp edge,
// and it closes when item 2.9 moves storage onto the AXON transport and there
// is only one left.
func (n *Node) SetContainment(d interface{ Denied(id string) bool }) {
	n.containMu.Lock()
	n.contained = d
	n.containMu.Unlock()
}

func (n *Node) denied(id string) bool {
	n.containMu.RLock()
	d := n.contained
	n.containMu.RUnlock()
	return d != nil && d.Denied(id)
}

// admissibleBootstrapPeers drops peers the operator contained.
//
// Applied BEFORE the cache is written as well as before dialling, so a denied
// host is not merely skipped this round but never persisted -- otherwise the
// cache quietly carries it to the next restart, to be re-applied by somebody
// who has forgotten about it.
func (n *Node) admissibleBootstrapPeers(peers []string) []string {
	out := make([]string, 0, len(peers))
	for _, value := range peers {
		address, err := multiaddr.NewMultiaddr(value)
		if err != nil {
			// Left in: an unparseable entry is the dial path's problem to
			// report, and dropping it silently here would hide it.
			out = append(out, value)
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(address)
		if err != nil {
			out = append(out, value)
			continue
		}
		if n.denied(info.ID.String()) {
			n.logger.Printf("bootstrap: peer %s is contained by operator "+
				"decision; not dialled and not cached", info.ID)
			continue
		}
		out = append(out, value)
	}
	return out
}

func (n *Node) bootstrapCfg() *bootstrap.Config {
	n.bootstrapMu.RLock()
	defer n.bootstrapMu.RUnlock()
	return n.bootstrapConfig
}

// refreshDiscoveredBootstrap is the path for nodes that were configured for it:
// several sources, a signature checked against a pinned key, and agreement as a
// second layer when there is no key to check against.
func (n *Node) refreshDiscoveredBootstrap(ctx context.Context, cfg *bootstrap.Config) {
	now := time.Now()
	result, err := bootstrap.Fetch(ctx, n.http, nil, *cfg, n.logger, now)
	if err != nil {
		// T16.2. Every source is unreachable, so there is no document to
		// verify and no coordinator key to refresh -- but joining the DHT does
		// not need either, and a node that gives up here is a node an outage
		// at the gateways has taken off the network entirely.
		n.logger.Printf("bootstrap: no usable document (%v); trying cached peers",
			err)
		n.joinFromCache(ctx, now)
		return
	}
	// Contained peers are dropped before anything else sees them, so they are
	// neither dialled nor written to the cache.
	result.Document.Peers = n.admissibleBootstrapPeers(result.Document.Peers)
	// Cache BEFORE acting on it. The peers are worth keeping whether or not
	// the coordinator key that travelled with them turns out to be usable,
	// and the key check below returns early on failure.
	if err := bootstrap.SaveCache(n.dataDir, result, now); err != nil {
		n.logger.Printf("bootstrap: could not cache peers: %v", err)
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(
		result.Document.CoordinatorPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		n.logger.Printf("bootstrap coordinator key rejected")
		return
	}
	n.keyMu.Lock()
	n.coordKey = append(ed25519.PublicKey(nil), publicKey...)
	n.keyMu.Unlock()
	// Compute peers travel in the same signed document as storage peers, so a
	// node learns where compute lives from something it already verified —
	// rather than from a configured address, which names one machine and fails
	// with it.
	n.computePeers.Update(*result.Document, now)
	n.connectBootstrapPeers(ctx, result.Document.Peers)
}

// joinFromCache is T16.2: the bootstrap document is unreachable, so dial the
// peers the last reachable one named.
//
// THE COORDINATOR KEY IS NOT RESTORED HERE, and that asymmetry is the point.
// Peers are a routing hint whose worst case is a dial that finds nobody -- the
// same outcome as not trying. The coordinator key is a trust root, and reading
// one back from a file is not the same act as verifying a signature: it would
// convert "verified once, possibly months ago" into "trusted now", across a
// restart, with nothing able to tell the difference afterwards. So a node
// running on cache keeps whatever key it already holds and refreshes nothing;
// if it holds none, storage leases stay unavailable until a real document is
// verified. It joins the DHT either way, which is what T16.2 asks for.
func (n *Node) joinFromCache(ctx context.Context, now time.Time) {
	cache, err := bootstrap.LoadCache(n.dataDir, now)
	switch {
	case errors.Is(err, bootstrap.ErrNoCache):
		// A first run with the network down. Ordinary, and not the cache's
		// fault, so it is not reported as a failure.
		n.logger.Printf("bootstrap: no cached peers yet; local services " +
			"remain active")
		return
	case errors.Is(err, bootstrap.ErrCacheStale):
		// Deliberately NOT dialled. A cache this old describes a network the
		// node has been absent from for longer than peer churn takes, so the
		// addresses are likelier to be wrong than right -- and dialling them
		// would look like a partitioned view rather than an offline one.
		n.logger.Printf("bootstrap: cached peers are too old to use (%v); "+
			"local services remain active", err)
		return
	case err != nil:
		n.logger.Printf("bootstrap: cached peers unusable (%v); local services "+
			"remain active", err)
		return
	}
	// Filtered BEFORE the log line, not after. A peer cached before the
	// operator contained it is still in the file -- the cache must not be a way
	// back in -- and the count reported has to be the count actually dialled.
	//
	// It said "joining from 2 cached peers" while joining one, which a test
	// caught. That is the line an operator reads DURING AN INCIDENT to confirm
	// a containment took effect, so a number that silently means something else
	// is worse here than almost anywhere.
	admissible := n.admissibleBootstrapPeers(cache.Peers)
	withheld := len(cache.Peers) - len(admissible)

	// Said plainly and every time, because a node running on cache is running
	// on a view nothing has corroborated since it was written, and an operator
	// reading a log should not have to infer that from silence.
	n.logger.Printf("bootstrap: joining from %d of %d cached peers saved %v ago "+
		"by %s (%s); %d withheld by containment; the coordinator key is NOT "+
		"restored from cache and is not being refreshed",
		len(admissible), len(cache.Peers), cache.Age(now).Round(time.Minute),
		cacheSourceName(cache.Source), verifiedWord(cache.Verified), withheld)

	if len(admissible) == 0 {
		n.logger.Printf("bootstrap: every cached peer is contained; local " +
			"services remain active")
		return
	}
	n.connectBootstrapPeers(ctx, admissible)
}

func cacheSourceName(source string) string {
	if source == "" {
		return "an unrecorded source"
	}
	return source
}

// verifiedWord keeps the weaker provenance visible in the log line rather than
// letting "cached" imply the stronger one.
func verifiedWord(verified bool) string {
	if verified {
		return "signature was verified against the pinned key when cached"
	}
	return "corroborated across sources only, never signature-verified"
}

// ComputePeers returns nodes currently offering a kind of work.
//
// Empty when the listing has expired, deliberately: a node dispatching on a
// stale directory sends work confidently to peers that may be long gone, and
// the failure reads as "compute is broken" rather than "my directory is old".
func (n *Node) ComputePeers(device string, arbitrary bool) []bootstrap.ComputePeer {
	return n.computePeers.Candidates(device, arbitrary, time.Now())
}

// ComputeSummary is what the node UI shows: counts, never the peer list.
func (n *Node) ComputeSummary() bootstrap.Summary {
	return n.computePeers.Summarise(time.Now())
}

func (n *Node) refreshBootstrap(ctx context.Context) {
	if cfg := n.bootstrapCfg(); cfg != nil {
		n.refreshDiscoveredBootstrap(ctx, cfg)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.bootstrap, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/json")
	resp, err := n.http.Do(req)
	if err != nil && n.directHTTP != nil {
		// The proxied attempt failed. Retry DIRECT rather than give up.
		//
		// n.http routes through the I2P HTTP proxy, which reaches clearnet only
		// via an outproxy. Measured on every node in this network: the proxied
		// fetch fails (000) while the same URL answers 200 directly, because a
		// young router has no addressbook entry for any outproxy -- and
		// exit.stormycloud.i2p, false.i2p, purokishi.i2p and
		// outproxy.acetone.i2p all failed. Without the document a node learns no
		// peers at all, so this one failure kept the whole network unformed.
		//
		// Falling back leaks nothing new: the heartbeat at
		// internal/heartbeat already POSTs to syndichan.org over clearnet by
		// deliberate design, so the site knows this node's address regardless.
		// NOT gated on i2pOnly, and that is deliberate rather than an oversight.
		// Open() passes i2pOnly=true for every storage node, so gating on it
		// disables this fallback in precisely the configuration that needs it --
		// measured: the flag was set, the fallback never ran, and the node sat
		// logging "bootstrap unavailable" forever. The flag is also already
		// inconsistent with the heartbeat, which goes direct on these same
		// nodes; it describes PEER TRAFFIC staying inside I2P, which this fetch
		// is not.
		directReq, rerr := http.NewRequestWithContext(ctx, http.MethodGet, n.bootstrap, nil)
		if rerr == nil {
			directReq.Header.Set("Accept", "application/json")
			if dresp, derr := n.directHTTP.Do(directReq); derr == nil {
				n.logger.Printf("bootstrap over I2P failed (%v); fetched it directly instead", err)
				resp, err = dresp, nil
			}
		}
	}
	if err != nil {
		n.logger.Printf("bootstrap unavailable; local services remain active: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		n.logger.Printf("bootstrap returned HTTP %d", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return
	}
	var document BootstrapDocument
	if err := json.Unmarshal(body, &document); err != nil || document.Version != 1 {
		n.logger.Printf("bootstrap document rejected")
		return
	}
	if !document.ExpiresAt.IsZero() && time.Now().After(document.ExpiresAt) {
		n.logger.Printf("bootstrap document expired")
		return
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(document.CoordinatorPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		n.logger.Printf("bootstrap coordinator key rejected")
		return
	}
	n.keyMu.Lock()
	n.coordKey = append(ed25519.PublicKey(nil), publicKey...)
	n.keyMu.Unlock()
	n.connectBootstrapPeers(ctx, document.Peers)
}

// connectBootstrapPeers dials each multiaddr and records the ones that stick as
// protected bootstrap peers. It is the shared sink for both bootstrap sources:
// the well-known document (refreshBootstrap) and the peers returned in each
// heartbeat response (the live bootstrap service). A short or empty list is
// normal -- a young network may only know one other node, or none.
func (n *Node) connectBootstrapPeers(ctx context.Context, peers []string) {
	for _, value := range peers {
		address, err := multiaddr.NewMultiaddr(value)
		if err != nil || n.i2pOnly && !syndii2p.IsI2PAddr(address) {
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(address)
		if err != nil || info.ID == n.host.ID() {
			continue
		}
		// Checked HERE and not only in admissibleBootstrapPeers, because this
		// function has a third caller: the heartbeat's OnPeers, where the
		// coordinator hands peers back directly. A containment enforced on two
		// of three paths is one an operator cannot rely on.
		if n.denied(info.ID.String()) {
			n.logger.Printf("bootstrap: peer %s is contained by operator "+
				"decision; not dialled", info.ID)
			continue
		}
		// Skip peers already connected: heartbeats fire every few minutes and
		// would otherwise re-dial the same handful of nodes on every beat.
		if n.host.Network().Connectedness(info.ID) == network.Connected {
			continue
		}
		info.Addrs = n.acceptablePeerAddrs(info.Addrs)
		if len(info.Addrs) == 0 {
			continue
		}
		dialTimeout := directDialTimeout
		if n.i2pOnly {
			dialTimeout = i2pDialTimeout
		}
		connectCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		err = n.host.Connect(connectCtx, *info)
		cancel()
		if err != nil {
			n.logger.Printf("bootstrap peer %s unavailable: %v", info.ID, err)
			continue
		}
		// Worth a line of its own: until this appears, nothing can be stored on
		// or fetched from the network, and the only other evidence was the
		// absence of a message.
		n.logger.Printf("bootstrap peer %s connected", info.ID)
		n.host.ConnManager().Protect(info.ID, "syndichan-bootstrap")
		n.peerMu.Lock()
		n.bootstrapPeers[info.ID] = struct{}{}
		n.peerMu.Unlock()
	}
}

func leaseMessage(lease Lease) []byte {
	return []byte(fmt.Sprintf(
		"syndichan-storage-lease-v1\n%d\n%s\n%s\n%d\n%s\n%d",
		lease.Version, lease.ObjectID, lease.ShardID, lease.Size, lease.Recipient, lease.ExpiresAt,
	))
}

func (n *Node) validateLease(lease *Lease, header requestHeader) error {
	if lease == nil || lease.Version != 1 {
		return errors.New("coordinator lease required")
	}
	if lease.ObjectID != header.ObjectID || lease.ShardID != header.ShardID || lease.Size != header.Size {
		return errors.New("lease does not match shard request")
	}
	if lease.Recipient != "" && lease.Recipient != n.host.ID().String() {
		return errors.New("lease was issued to another node")
	}
	now := time.Now().Unix()
	if lease.ExpiresAt <= now || lease.ExpiresAt > now+3600 {
		return errors.New("lease is expired or excessively long")
	}
	signature, err := base64.RawStdEncoding.DecodeString(lease.Signature)
	if err != nil {
		return errors.New("invalid lease signature encoding")
	}
	n.keyMu.RLock()
	key := append(ed25519.PublicKey(nil), n.coordKey...)
	n.keyMu.RUnlock()
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, leaseMessage(*lease), signature) {
		return errors.New("invalid coordinator lease signature")
	}
	return nil
}

func (n *Node) handleStream(stream network.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(stream)
	var header requestHeader
	if err := readJSONFrame(reader, &header); err != nil {
		writeJSONFrame(stream, responseHeader{Error: "invalid request"})
		return
	}
	switch header.Operation {
	case "have":
		_, err := n.store.ReadShard(header.ShardID)
		writeJSONFrame(stream, responseHeader{OK: true, Present: err == nil})
	case "get":
		value, err := n.store.ReadShard(header.ShardID)
		if err != nil {
			writeJSONFrame(stream, responseHeader{Error: "not found"})
			return
		}
		if err := writeJSONFrame(stream, responseHeader{OK: true, Size: int64(len(value))}); err == nil {
			_, _ = stream.Write(value)
		}
	case "pof-challenge":
		// Proof-of-Facilitation audit. Answering costs a Merkle proof over
		// chunks we already hold, so it is served regardless of cacheOnly.
		n.handleChallengeFrame(stream, reader, header.Size)
	case ComputeAdmit, ComputeSubmit, ComputeResult:
		// Compute, riding this protocol as three more operations for the same
		// reason pof-challenge does: a second protocol ID means a second I2P
		// tunnel to build and keep alive, reaching strictly fewer peers.
		//
		// Listed as exact cases, not matched by prefix. A prefix test would pull
		// every "compute-*" name out of the default branch below, so a peer
		// speaking a verb this build has never heard of would get silence-shaped
		// nonsense instead of "unsupported operation".
		//
		// Nothing about storage is reachable from here. The branch reads its own
		// bounded payload off this stream and writes its own answer; a malformed
		// or hostile compute frame costs this one stream and nothing else.
		//
		// The remote peer is passed down from the CONNECTION, the same way the
		// delete verb takes it: it is the one identity on this stream libp2p has
		// proved, and nothing in the frame may be substituted for it.
		n.handleComputeFrame(stream, reader, header, stream.Conn().RemotePeer())
	case "store":
		if n.cacheOnly {
			// This node contributes no storage to the network. It keeps only
			// what it caches of its OWN content, so it must not become a host
			// for other peers' shards -- accepting them would make its disk
			// grow with the network rather than with the site.
			writeJSONFrame(stream, responseHeader{Error: "node is cache-only and does not host shards"})
			return
		}
		if n.draining.Load() {
			// This machine is being retired. The capacity record already says so,
			// and every owner running this build has dropped it from their
			// candidate sets -- but the record has a ten-minute TTL, an owner on an
			// older build ignores the field entirely, and none of that is a reason
			// to accept bytes onto a disk that is about to be switched off. The
			// refusal here is the guarantee; the advertisement is only the polite
			// way to avoid spending a lease to reach it.
			//
			// ONLY the "store" branch. "have", "get" and "delete" must keep
			// working, and are exactly what a drain runs on: the owner fetches the
			// shard bytes from this node to copy them elsewhere, probes the
			// destination, and then recalls from here.
			writeJSONFrame(stream, responseHeader{Error: "node is draining and does not accept new shards"})
			return
		}
		if header.Size <= 0 || header.Size > maxNetworkShard || len(header.ShardID) != 64 {
			writeJSONFrame(stream, responseHeader{Error: "invalid shard size or ID"})
			return
		}
		if err := n.validateLease(header.Lease, header); err != nil {
			writeJSONFrame(stream, responseHeader{Error: err.Error()})
			return
		}
		if err := writeJSONFrame(stream, responseHeader{OK: true}); err != nil {
			return
		}
		value := make([]byte, header.Size)
		if _, err := io.ReadFull(reader, value); err != nil {
			return
		}
		err := n.store.PutRemoteShard(store.RemoteShard{
			ID: header.ShardID, ObjectID: header.ObjectID, Size: header.Size,
		}, value)
		if err != nil {
			writeJSONFrame(stream, responseHeader{Error: err.Error()})
			return
		}
		writeJSONFrame(stream, responseHeader{OK: true})
		go n.Provide(context.Background(), header.ShardID)
	case "delete":
		// Recall. Authorised by a coordinator-signed revocation bound to this
		// exact shard, this exact holder, AND the peer presenting it; see
		// recall.go. That last binding is why the connection's remote peer is
		// passed down: it is the one identity on this stream libp2p has actually
		// proved, and nothing in the frame may be substituted for it.
		//
		// cacheOnly is NOT consulted here -- a node that has stopped accepting
		// shards may still be holding ones it accepted earlier, and those are
		// exactly the ones an owner needs back.
		n.handleDelete(stream, header, stream.Conn().RemotePeer())
	default:
		writeJSONFrame(stream, responseHeader{Error: "unsupported operation"})
	}
}

func cidForShard(id string) (cid.Cid, error) {
	digest, err := hex.DecodeString(id)
	if err != nil || len(digest) != 32 {
		return cid.Undef, errors.New("invalid shard ID")
	}
	mh, err := multihash.Encode(digest, multihash.SHA2_256)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, mh), nil
}

func (n *Node) Provide(ctx context.Context, shardID string) error {
	contentID, err := cidForShard(shardID)
	if err != nil {
		return err
	}
	return n.dht.Provide(ctx, contentID, true)
}

// advertiseInterval re-announces stored shards periodically. DHT provider
// records expire anyway, so a one-shot announce would go stale even in the
// happy case.
const advertiseInterval = 10 * time.Minute

// AdvertiseStored announces every locally stored shard to the DHT, and keeps
// doing so.
//
// It used to run exactly once, at startup, and return. That is precisely when it
// cannot work: I2P tunnels take minutes to build, so the routing table is still
// empty and every announce fails with "failed to find any peer in table". The
// backlog was then never advertised again for the lifetime of the process, so a
// node that had accumulated shards before meeting a peer stayed invisible --
// peers could not discover the content it was holding no matter how healthy the
// network later became.
func (n *Node) AdvertiseStored(ctx context.Context) {
	for {
		n.advertiseOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(advertiseInterval):
		}
	}
}

func (n *Node) advertiseOnce(ctx context.Context) {
	ids, err := n.store.ListShardIDs()
	if err != nil {
		n.logger.Printf("could not enumerate stored shards: %v", err)
		return
	}
	if len(n.host.Network().Peers()) == 0 {
		// Nothing to announce to. Say so ONCE rather than emitting a line per
		// shard -- the old behaviour buried every other message under thousands
		// of identical "failed to find any peer in table" errors.
		n.logger.Printf("advertise: %d shard(s) pending, no peers connected yet", len(ids))
		return
	}
	announced, failed := 0, 0
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		provideCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := n.Provide(provideCtx, id)
		cancel()
		if err != nil {
			failed++
			if failed <= 3 {
				n.logger.Printf("could not advertise shard %s: %v", id[:12], err)
			}
			continue
		}
		announced++
	}
	n.logger.Printf("advertise: %d announced, %d failed, of %d stored", announced, failed, len(ids))
}

// ReplicateStored pushes the shards of objects that were stored while this node
// had no peers.
//
// DistributeManifest only ever runs at PUT time. Anything written before a peer
// connected -- which, on the server's own node, was every single object -- took
// the "retained locally; no storage peers are connected" branch and was never
// sent anywhere afterwards. AdvertiseStored does NOT make up for that: it
// publishes DHT provider records saying "I have this shard", not the bytes.
//
// The visible consequence was a node that looked entirely healthy -- peered,
// advertising, heartbeating -- while every volunteer's shard directory stayed
// empty, because no code path existed that would ever push an already-stored
// shard to a peer that showed up later.
func (n *Node) ReplicateStored(ctx context.Context) {
	for {
		timer := time.NewTimer(replicateInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		n.replicateOnce(ctx)
	}
}

// dispersalCooldown is the minimum gap between dispersal attempts on the same
// object. It is what makes the pass ROTATE instead of grinding: the queue is
// ordered by last attempt, so five objects are tried, stamped, and stand aside
// while the next five come forward. Without it a batch of five under-replicated
// objects that never reach durability would be retried forever and the other
// 11,635 would never be looked at once.
const dispersalCooldown = 30 * time.Minute

// enrolBatch bounds how many pre-ledger objects are enrolled per pass. One bolt
// transaction, so the cost is one fsync rather than one per object.
const enrolBatch = 1000

func (n *Node) replicateOnce(ctx context.Context) {
	peers := len(n.host.Network().Peers())
	if peers == 0 {
		// RECORDED, not skipped. "Nowhere to push" is a diagnosis in its own
		// right -- it is what an i2pd that has core-dumped looks like from here,
		// and it is the difference between a node being refused and a node that
		// is alone. Returning silently would leave this node reporting nothing,
		// which the coordinator draws identically to a build too old to report.
		if summary, err := n.store.PlacementStatus(); err == nil {
			n.recordPlacementHealth(PlacementHealth{
				Objects: summary.Objects, UnderReplicated: summary.UnderReplicated,
				LocalOnly: summary.LocalOnly, FullyDispersed: summary.FullyDispersed,
				Recalls: recallSummaryOrNil(n.store),
			})
		}
		return
	}
	// Objects written before the ledger existed have no row, so they are
	// invisible to the queue. Give them one.
	if enrolled, pending, err := n.store.EnrolMissingPlacements(enrolBatch); err != nil {
		n.logger.Printf("replicate: cannot enrol objects in the placement ledger: %v", err)
	} else if enrolled > 0 {
		n.logger.Printf("replicate: enrolled %d object(s) in the placement ledger, %d still to enrol",
			enrolled, pending)
	}

	// The queue is now the LEDGER, not a rescan of every manifest in bolt
	// filtered through an in-memory set. Two things change as a result: the
	// order is least-recently-attempted first, so nothing starves; and the
	// "done" state survives a restart, so a process bounce no longer replays
	// the entire catalogue from the top of bolt key order.
	candidates, err := n.store.DispersalCandidates(replicateBatch, dispersalCooldown)
	if err != nil {
		n.logger.Printf("replicate: cannot read the placement ledger: %v", err)
		return
	}
	pushed, underReplicated := 0, 0
	// Shard-level totals over the whole pass. The same arithmetic as the
	// per-object "placed N, failed N" line, summed, because that line is what an
	// operator greps for and it is the one number that would have shown the
	// backfill counter was measuring attempts.
	placed, failed, unassignable := 0, 0, 0
	for _, row := range candidates {
		if ctx.Err() != nil {
			return
		}
		manifest, err := n.store.HeadObject(row.Bucket, row.Key)
		if err != nil {
			// Ghost row: the object is gone but its holders are not. Capture
			// them into a recall tombstone before the row is dropped, or the
			// shards stay on peers with nothing left that can name them.
			_ = n.store.RetirePlacement(row.ObjectID, "object missing at replicate pass")
			continue
		}
		result := n.DisperseObject(ctx, *manifest)
		// ONLY a durable result retires the object.
		//
		// Whether the object is retired from the queue is now decided ONLY by
		// the ledger: DispersalCandidates skips a row once every shard has a
		// confirmed holder, and nothing else can take an object out.
		//
		// There used to be an in-memory `replicated` set, marked after a
		// DistributeManifest that returned nothing and merely logged its
		// failures -- so an object whose every push was refused went into it
		// anyway, and stayed there for the life of the process. That is the
		// whole explanation for the production symptom: "pushed 5 object(s),
		// 11640 awaiting backfill" draining steadily while every volunteer's
		// shard directory held zero files. "pushed" counted attempts, and
		// "awaiting backfill" was a per-pass skip count over that set, so it
		// fell by exactly replicateBatch every pass no matter what happened on
		// the wire. Neither number ever referred to bytes arriving anywhere.
		// The set is gone; the queue is durable and success-only.
		if !result.Durable {
			underReplicated++
		}
		placed += result.Placed
		failed += result.Failed
		unassignable += result.Unassignable
		pushed++
	}
	summary, summaryErr := n.store.PlacementStatus()
	if summaryErr != nil {
		// Logged rather than swallowed. This used to fall through silently, so a
		// ledger that would not open looked exactly like a node with nothing to
		// report -- and the placement line simply stopped appearing.
		n.logger.Printf("replicate: cannot summarise the placement ledger: %v", summaryErr)
	} else {
		// Published BEFORE the early return below, because "nothing to do" is a
		// measurement: a node whose whole corpus is dispersed must report that
		// it looked and found nothing wrong, not go quiet and be indistinguishable
		// from one that never ran a pass at all.
		n.recordPlacementHealth(PlacementHealth{
			Objects: summary.Objects, UnderReplicated: summary.UnderReplicated,
			LocalOnly: summary.LocalOnly, FullyDispersed: summary.FullyDispersed,
			Placed: placed, Failed: failed, Unassignable: unassignable,
			Attempted: pushed, Peers: peers,
			Recalls: recallSummaryOrNil(n.store),
		})
	}
	if pushed == 0 && summaryErr == nil && summary.UnderReplicated == 0 {
		return
	}
	n.logger.Printf("replicate: %d object(s) attempted, %d still under-replicated afterwards",
		pushed, underReplicated)
	if summaryErr == nil {
		// The only honest headline number. Every one of these is measured from
		// confirmed holders, so an object counted as fully dispersed is one that
		// dataShards+parityShards distinct peers each acknowledged a shard of.
		n.logger.Printf(
			"placement: %d object(s) tracked, %d under-replicated, %d with no remote copy at all, %d fully dispersed",
			summary.Objects, summary.UnderReplicated, summary.LocalOnly, summary.FullyDispersed)
	}
}

func (n *Node) requestLease(ctx context.Context, target peer.ID, objectID, shardID string, size int64) (*Lease, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	payload := leaseRequest{
		Version: 1, Requester: n.host.ID().String(), Recipient: target.String(),
		ObjectID: objectID, ShardID: shardID, Size: size,
		Timestamp: time.Now().UTC().Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	privateKey := n.host.Peerstore().PrivKey(n.host.ID())
	if privateKey == nil {
		return nil, errors.New("node identity unavailable")
	}
	signature, err := privateKey.Sign(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, leaseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Syndichan-Node", n.host.ID().String())
	req.Header.Set("X-Syndichan-Signature", base64.RawStdEncoding.EncodeToString(signature))
	resp, err := n.http.Do(req)
	if err != nil && n.directHTTP != nil {
		// Same fallback as refreshBootstrap, and needed for the same reason.
		// EVERY shard placement asks the site for a lease first, so when this
		// call fails nothing disperses at all -- measured on production:
		//   shard dafcbae37ed8 not placed on 12D3KooWArj768...:
		//   proxyconnect tcp: dial tcp 127.0.0.1:4444: connect: connection refused
		// with "placed 0, failed 9" for every chunk, against nine peers the
		// planner had already chosen correctly. The peers were fine; the lease
		// request never left the machine.
		//
		// n.http goes through the I2P HTTP proxy, which is absent in the
		// container deployment and reaches clearnet only via an outproxy
		// elsewhere. Falling back direct leaks nothing new: this is a SIGNED
		// request to syndichan.org naming this node, sent to the same host the
		// heartbeat already contacts directly.
		directReq, rerr := http.NewRequestWithContext(ctx, http.MethodPost, leaseURL, bytes.NewReader(body))
		if rerr == nil {
			directReq.Header = req.Header.Clone()
			if dresp, derr := n.directHTTP.Do(directReq); derr == nil {
				resp, err = dresp, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lease service returned HTTP %d", resp.StatusCode)
	}
	var lease Lease
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHeaderBytes)).Decode(&lease); err != nil {
		return nil, err
	}
	header := requestHeader{ObjectID: objectID, ShardID: shardID, Size: size}
	if err := n.validateLeaseForRecipient(&lease, header, target.String()); err != nil {
		return nil, err
	}
	return &lease, nil
}

func (n *Node) validateLeaseForRecipient(lease *Lease, header requestHeader, recipient string) error {
	if lease == nil || lease.Version != 1 || lease.ObjectID != header.ObjectID ||
		lease.ShardID != header.ShardID || lease.Size != header.Size ||
		lease.Recipient != recipient {
		return errors.New("lease fields do not match storage request")
	}
	now := time.Now().Unix()
	if lease.ExpiresAt <= now || lease.ExpiresAt > now+3600 {
		return errors.New("lease is expired or excessively long")
	}
	signature, err := base64.RawStdEncoding.DecodeString(lease.Signature)
	if err != nil {
		return err
	}
	n.keyMu.RLock()
	key := append(ed25519.PublicKey(nil), n.coordKey...)
	n.keyMu.RUnlock()
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, leaseMessage(*lease), signature) {
		return errors.New("invalid coordinator signature")
	}
	return nil
}

func (n *Node) storeOnPeer(ctx context.Context, target peer.ID, objectID, shardID string, value []byte, lease *Lease) error {
	stream, err := n.host.NewStream(ctx, target, ProtocolID)
	if err != nil {
		return err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeJSONFrame(stream, requestHeader{
		Operation: "store", ObjectID: objectID, ShardID: shardID,
		Size: int64(len(value)), Lease: lease,
	}); err != nil {
		return err
	}
	reader := bufio.NewReader(stream)
	var ready responseHeader
	if err := readJSONFrame(reader, &ready); err != nil {
		return err
	}
	if !ready.OK {
		return errors.New(ready.Error)
	}
	if _, err := stream.Write(value); err != nil {
		return err
	}
	var stored responseHeader
	if err := readJSONFrame(reader, &stored); err != nil {
		return err
	}
	if !stored.OK {
		return errors.New(stored.Error)
	}
	return nil
}

// FetchShard retrieves a shard, trying the peers most likely to have it first.
//
// hints are the holders the placement ledger recorded for this shard. They come
// first, ahead of the bootstrap set, and that ordering matters more than it
// looks: n.bootstrapPeers is append-only and never pruned, and this file says
// so itself ("it only records that a dial once succeeded... it cannot be used to
// decide whether the node still has a network"). Every stale entry in it is a
// fresh I2P dial worth up to i2pDialTimeout (2 minutes) charged against the
// caller's 3-minute budget, so the provider lookup that actually knows the
// answer was regularly never reached. A recorded holder is a node that
// confirmed these exact bytes, which is the strongest evidence available.
func (n *Node) FetchShard(ctx context.Context, shardID string, hints []string) ([]byte, error) {
	if value, err := n.store.ReadShard(shardID); err == nil {
		return value, nil
	}
	seen := make(map[peer.ID]struct{})
	for _, hint := range hints {
		candidate, err := peer.Decode(hint)
		if err != nil || candidate == n.host.ID() {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		if value, err := n.fetchFromPeer(ctx, candidate, shardID); err == nil {
			return value, nil
		}
	}
	n.peerMu.RLock()
	var trusted []peer.ID
	for candidate := range n.bootstrapPeers {
		trusted = append(trusted, candidate)
	}
	n.peerMu.RUnlock()
	for _, candidate := range trusted {
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		if value, err := n.fetchFromPeer(ctx, candidate, shardID); err == nil {
			return value, nil
		}
	}
	for _, candidate := range n.host.Network().Peers() {
		if _, exists := seen[candidate]; exists || candidate == n.host.ID() {
			continue
		}
		seen[candidate] = struct{}{}
		if value, err := n.fetchFromPeer(ctx, candidate, shardID); err == nil {
			return value, nil
		}
	}
	contentID, err := cidForShard(shardID)
	if err != nil {
		return nil, err
	}
	for provider := range n.dht.FindProvidersAsync(ctx, contentID, 20) {
		if provider.ID == n.host.ID() {
			continue
		}
		if _, exists := seen[provider.ID]; exists {
			continue
		}
		seen[provider.ID] = struct{}{}
		provider.Addrs = n.acceptablePeerAddrs(provider.Addrs)
		if len(provider.Addrs) == 0 {
			continue
		}
		if err := n.host.Connect(ctx, provider); err != nil {
			continue
		}
		if value, err := n.fetchFromPeer(ctx, provider.ID, shardID); err == nil {
			return value, nil
		}
	}
	return nil, errors.New("no peer supplied a valid shard")
}

func (n *Node) acceptablePeerAddrs(values []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	if !n.i2pOnly {
		return values
	}
	return i2pAddressesOnly(values)
}

func (n *Node) fetchFromPeer(ctx context.Context, candidate peer.ID, shardID string) ([]byte, error) {
	stream, err := n.host.NewStream(ctx, candidate, ProtocolID)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	// Honour the caller's budget: over I2P even a small shard's round trip
	// exceeds a few seconds, and the old fixed 5s deadline aborted the read
	// mid-transfer. Fall back to a generous ceiling only when unbounded.
	deadline := time.Now().Add(2 * time.Minute)
	if dl, ok := ctx.Deadline(); ok {
		deadline = dl
	}
	_ = stream.SetDeadline(deadline)
	if err := writeJSONFrame(stream, requestHeader{Operation: "get", ShardID: shardID}); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(stream)
	var response responseHeader
	if err := readJSONFrame(reader, &response); err != nil || !response.OK ||
		response.Size <= 0 || response.Size > maxNetworkShard {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("peer does not have shard")
	}
	value := make([]byte, response.Size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return nil, err
	}
	if fmt.Sprintf("%x", sha256Sum(value)) != shardID {
		return nil, errors.New("peer returned corrupt shard")
	}
	return value, nil
}

func sha256Sum(value []byte) [32]byte {
	return sha256.Sum256(value)
}

func readJSONFrame(reader *bufio.Reader, target any) error {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return err
	}
	if size == 0 || size > maxHeaderBytes {
		return errors.New("invalid frame size")
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return err
	}
	return json.Unmarshal(value, target)
}

func writeJSONFrame(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) > maxHeaderBytes {
		return errors.New("frame too large")
	}
	if err := binary.Write(writer, binary.BigEndian, uint32(len(encoded))); err != nil {
		return err
	}
	_, err = writer.Write(encoded)
	return err
}

// usedBytesOrZero reports what the store is holding, or zero if it cannot say.
//
// Cheap because Store caches the figure; it was once a full directory walk per
// call, which is why several callers avoided asking. A read error yields zero
// rather than failing the heartbeat -- a node that cannot measure itself should
// still report presence, and the coordinator draws a zero as "not measured"
// rather than "empty" (the status page distinguishes those the same way it does
// for traffic).
func usedBytesOrZero(s *store.Store) int64 {
	if s == nil {
		return 0
	}
	used, err := s.UsedBytes()
	if err != nil {
		return 0
	}
	return used
}
