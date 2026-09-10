package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
)

// Peer discovery starts at the dedicated data-node edge. That edge exposes only
// this well-known document over publicly trusted TLS; coordinator leases and
// the direct five-minute presence heartbeat remain separate concerns.
const BootstrapURL = "https://node.syndichan.org/.well-known/syndichan/storage-node.json"

// Role is the runtime role selected on the command line. It is resolved before
// the configuration is read, so validation only ever demands settings the role
// will actually use. A dedicated gateway has no shard store, no S3 service and
// no dashboard, so it must not be asked for S3 credentials, an erasure layout,
// a capacity, or an I2P bridge.
type Role string

const (
	// RoleStorage is the default full node: shard storage, S3, dashboard and
	// I2P, plus the gateway/probe services if the config enables them.
	RoleStorage Role = "storage"
	// RoleGatewayOnly runs the gateway and/or probe services alone (-gateway-only).
	RoleGatewayOnly Role = "gateway-only"
	// RoleProbeOnly runs only the signed verification probe (-probe-only).
	RoleProbeOnly Role = "probe-only"
	// RoleManagement inspects or edits the config file and exits
	// (-gateway-status, -gateway-enable, -gateway-disable, -show-credentials).
	// It starts nothing, so it checks the gateway settings it may touch and
	// demands neither storage settings nor a startable runtime role.
	RoleManagement Role = "config-management"
)

// NeedsStorage reports whether the role initializes any storage subsystem. It
// is the single switch that decides both what gets validated and what gets
// started, so the two can never drift apart.
func (r Role) NeedsStorage() bool { return r == RoleStorage }

func (r Role) Description() string {
	switch r {
	case RoleStorage:
		return "shard storage, S3, dashboard, I2P, heartbeat; gateway/probe if configured"
	case RoleGatewayOnly:
		return "gateway/probe services and presence heartbeat; no storage, S3, dashboard, or I2P"
	case RoleProbeOnly:
		return "signed verification probe and presence heartbeat; no storage, S3, dashboard, or I2P"
	case RoleManagement:
		return "inspect or update the configuration file; no subsystem is started"
	}
	return string(r)
}

// NetworkDirectiveConfig is how this node learns that the network has moved --
// a new domain, a new origin server, or a new signing key -- and who is allowed
// to tell it.
//
// WHY THE WALLET IS HERE AND NOT FETCHED
// It is written when the node is downloaded and never updated from the network.
// A node that asked the origin which address may replace the origin would be
// asking the thing being replaced: whoever seized the domain would serve their
// own address alongside their own directive, and the check would pass while
// proving nothing.
//
// An empty Wallet is valid and means this node follows no directives at all.
// That is the safe direction -- it keeps pointing where it was told at install
// rather than following whoever answers first.
type NetworkDirectiveConfig struct {
	Wallet string `json:"wallet,omitempty"`
	// Sources serving /.well-known/syndichan/network.json. More than one on
	// purpose: the source reached through the CURRENT domain is exactly the one
	// that fails in the situation a directive exists for.
	Sources []string `json:"sources,omitempty"`
	// PollSeconds between checks. Rarely, because this changes almost never and
	// every check is a request to a host that may no longer be ours.
	PollSeconds int `json:"poll_seconds,omitempty"`
}

// BootstrapConfig decides how this node joins the DHT, and — more importantly —
// whom it believes about the coordinator key.
//
// The bootstrap document names which peers to dial AND which coordinator key to
// accept for storage leases. A node that takes that key out of the document is
// trusting whoever served it, which was tolerable while exactly one host under
// our own TLS did, and is not once volunteer gateways share the job. So the key
// is pinned here, at install, and the document's signature is checked against
// it.
//
// An ABSENT section keeps the old single-URL behaviour on purpose. The new
// rules refuse a lone unverifiable source, which is right for a fresh install
// that was given a pinned key and fatal for an existing node that was not —
// applying them on upgrade would take those nodes off the DHT entirely.
type BootstrapConfig struct {
	// CoordinatorKey, base64. Empty falls back to requiring agreement.
	CoordinatorKey string `json:"coordinator_key,omitempty"`
	// SRVName is resolved to find gateways serving the document, so one host
	// being offline costs nothing — the node simply tries the next.
	SRVName string `json:"srv_name,omitempty"`
	// URLs tried in addition to whatever SRV turns up.
	URLs []string `json:"urls,omitempty"`
	// MinimumAgreement when no key is pinned. Zero takes the package default.
	MinimumAgreement int `json:"minimum_agreement,omitempty"`
}

// Configured reports whether this node was told to use discovered bootstrap.
func (b BootstrapConfig) Configured() bool {
	return b.SRVName != "" || len(b.URLs) > 0 || b.CoordinatorKey != ""
}

type Config struct {
	DataDir  string `json:"data_dir"`
	S3Listen string `json:"s3_listen"`
	// CacheOnly: serve our own content but host nothing for other peers.
	CacheOnly bool `json:"cache_only"`
	// Draining retires this machine: stop accepting new shards, tell the network
	// so, and let the owners of everything already here move it off. Set it, wait
	// for the node to report that it holds nothing for anybody else, then switch
	// the machine off.
	//
	// IT LIVES IN THE CONFIG, and that is the whole of the persistence a drain
	// needs on this side. A drain runs for hours across restarts -- the operator
	// is by definition about to restart or power down this machine -- so an
	// in-memory flag or a runtime-only API call would silently un-drain the node
	// on the next start, at which point owners would resume writing to a disk
	// that is on its way out. There is no progress to keep here beyond the
	// intent: what is left to move is measured from the disk, not remembered.
	//
	// NO omitempty, like PayoutAddress and for the same reason: a field an
	// operator has to go and find is a field that has to be visible in the file.
	Draining bool   `json:"draining"`
	UIListen string `json:"ui_listen"`
	// UIUsername / UIPassword guard the management dashboard. They are only
	// consulted -- and only REQUIRED -- when ui_listen is not loopback, because
	// a loopback page is already limited to whoever is sitting at the machine.
	// The moment the page is reachable from the local network it can change the
	// payout address, the storage paths and the compute switches for anyone who
	// finds the port, so a credential stops being optional.
	//
	// The password is stored as typed, in a file that is already mode 0600 and
	// already holds secret_key. Hashing it would protect nothing here: anyone
	// who can read this file can read the S3 secret, or simply write a password
	// of their own and restart the node. What it would cost is a key-derivation
	// run on every request -- HTTP Basic re-sends the credential on each poll of
	// /api/status, so a KDF would hand any unauthenticated LAN host a cheap way
	// to burn this node's CPU. Use a password you do not use anywhere else.
	UIUsername    string   `json:"ui_username"`
	UIPassword    string   `json:"ui_password"`
	P2PListen     []string `json:"p2p_listen"`
	I2PSAM        string   `json:"i2p_sam"`
	I2PHTTPProxy  string   `json:"i2p_http_proxy"`
	AccessKey     string   `json:"access_key"`
	SecretKey     string   `json:"secret_key"`
	CapacityBytes int64    `json:"capacity_bytes"`
	// PayoutAddress is where this node's CREDIT earnings are sent — an
	// address the operator controls, typically their MetaMask. Empty means
	// the node does the work but is never paid for it, so the dashboard
	// nags until it is set.
	// NO omitempty, deliberately. This is where the operator's earnings go, and
	// with omitempty an unset address is simply ABSENT from the written config
	// -- so the one field somebody most needs to fill in is the one field they
	// cannot see. Always writing it, empty, makes it self-documenting: open the
	// file and there is a labelled blank waiting.
	PayoutAddress string        `json:"payout_address"`
	DataShards    int           `json:"data_shards"`
	ParityShards  int           `json:"parity_shards"`
	ChunkBytes    int           `json:"chunk_bytes"`
	TLSCert       string        `json:"tls_cert,omitempty"`
	TLSKey        string        `json:"tls_key,omitempty"`
	Gateway       GatewayConfig `json:"gateway"`
	DCS           DCSConfig     `json:"dcs"`
	// Compute is the local resource manager (roadmap M3): whether this machine
	// offers CPU/GPU cycles, and the limits its owner set. Absent means OFF —
	// the zero value never runs work, so a node that upgrades into a build with
	// this feature does not silently start donating cycles.
	Compute ComputeConfig `json:"compute"`

	// Channels is the payment-channel node: SCPP/1 to strangers, a loopback
	// operator API, and optionally a volunteer mailbox or delegate signer.
	//
	// OFF BY DEFAULT. A node that has not been configured to handle money
	// should not be listening for it, and the zero value must therefore be
	// "no payment surface at all" rather than "a payment surface with no key".
	Channels ChannelsConfig `json:"channels"`

	// Router is the payment-channel routing role: forwarding other people's
	// payments for a fee. Absent means OFF.
	Router RouterConfig `json:"router"`
	// NetworkDirective is how this node learns the network has moved.
	NetworkDirective NetworkDirectiveConfig `json:"network_directive"`

	// HeartbeatEndpoint overrides the compiled-in presence endpoint.
	//
	// It exists because the endpoint was a const in internal/heartbeat, so a
	// deployment on a different origin could repoint every other URL in this
	// config and still send its presence beacon to the old domain -- silently,
	// since a heartbeat that 404s is logged and retried rather than fatal. The
	// node then runs correctly and is invisible to its own network.
	//
	// Empty means "use the compiled-in default", so existing configs are
	// unaffected. A NetworkDirective still overrides this at runtime; this is
	// the install-time value, not a way to escape a directive.
	HeartbeatEndpoint string `json:"heartbeat_endpoint,omitempty"`
	// Bootstrap is how this node finds its way into the DHT, and who it
	// believes about it. Absent means the old single-URL behaviour.
	Bootstrap BootstrapConfig `json:"bootstrap"`
	// RunMode selects what this node runs, IN THE CONFIG rather than on the
	// command line: "storage" (default full node), "gateway-only", or
	// "probe-only". It is edited on the management page, so the node launches
	// with no flags -- only the config file decides its posture. An empty value
	// means "storage" for backward compatibility with older config files.
	RunMode string `json:"run_mode,omitempty"`
	// Monitor is the status-page role: check that Syndichan answers from where
	// this node is, and publish the result. Absent means off, which is the
	// right default -- a node should not start making outbound requests on a
	// schedule because it was upgraded.
	Monitor MonitorConfig `json:"monitor"`
}

// MonitorConfig configures the status monitor.
//
// The check LIST is not here on purpose: it is fetched from TargetsURL, so a
// monitoring fleet is not limited to whatever its slowest operator last
// installed. What lives in the config is only what a person chooses.
type MonitorConfig struct {
	Enabled bool `json:"enabled"`
	// Where to ask what to check. The response also names where to report, so
	// there is one source of truth rather than two URLs to keep in step.
	TargetsURL string `json:"targets_url,omitempty"`
	ReportURL  string `json:"report_url,omitempty"`
	// IntervalSeconds is a floor the coordinator can raise; it is jittered so a
	// fleet started by one rollout does not arrive in lockstep forever.
	IntervalSeconds int `json:"interval_seconds,omitempty"`
}

// ResolvedRole maps the config's RunMode to a runtime Role. An unset or unknown
// value is the full storage node -- the safe default a fresh install starts as.
func (c Config) ResolvedRole() Role {
	switch c.RunMode {
	case string(RoleGatewayOnly), "gateway":
		return RoleGatewayOnly
	case string(RoleProbeOnly), "probe":
		return RoleProbeOnly
	default:
		return RoleStorage
	}
}

// DCSConfig is the optional Distributed Container Service. Every default is the
// refusing one: a node that merely sets enabled=true advertises nothing and
// accepts nothing until an operator also picks a role. See DCS.md.
type DCSConfig struct {
	Enabled bool          `json:"enabled"`
	Role    DCSRoleConfig `json:"role"`
	Limits  DCSLimits     `json:"limits"`
	Policy  DCSPolicy     `json:"policy"`

	Labels                   map[string]string `json:"labels,omitempty"`
	Region                   string            `json:"region,omitempty"`
	DockerEndpoint           string            `json:"docker_endpoint"`
	AdvertiseIntervalSeconds int               `json:"advertise_interval_seconds"`
	RecordTTLSeconds         int               `json:"record_ttl_seconds"`
	// APIListen, when set, runs a LOOPBACK/cluster-internal HTTP API the website
	// bridge calls to publish challenge blobs, deploy on a user's behalf, and
	// read back addresses/queue status. It lets a container run through the site
	// can deploy them anywhere; keep it off a public interface.
	APIListen string `json:"api_listen"`
}

type DCSRoleConfig struct {
	Worker  bool `json:"worker"`
	GPU     bool `json:"gpu"`
	Volumes bool `json:"volumes"`
	// Lab accepts DELIBERATELY VULNERABLE workloads (Attack Range and similar).
	// Separate from Worker on purpose: a plain worker must never be handed one.
	// A lab container is unreachable except through an I2P destination that is
	// never published anywhere -- see dcs.LabContainment.
	Lab bool `json:"lab"`
}

// ComputeConfig is the M3 policy: what this machine will lend, and when.
//
// Separate from DCSConfig on purpose. A DCS worker runs CONTAINERS somebody
// deployed; a compute provider runs WORK UNITS from a signed catalogue with no
// network access. They have different consent, different risk, and an operator
// may well want one and not the other — collapsing them into one flag would
// make enabling the safer thing require accepting the riskier one.
type ComputeConfig struct {
	// Policy fields are inlined so the config file reads as one block rather
	// than compute.policy.enabled.
	compute.Policy

	// MicroVMKernel and MicroVMRootFS are the guest artifacts. Both are
	// required before this node will run ARBITRARY code: without them there is
	// no VM to run it in, and the container fallback is exactly the boundary
	// the arbitrary-code rule refuses.
	//
	// Supplied by the operator rather than downloaded automatically. A node
	// that fetched and booted a kernel somebody else chose would have handed
	// over the machine in the act of protecting it.
	MicroVMKernel string `json:"microvm_kernel"`
	MicroVMRootFS string `json:"microvm_rootfs,omitempty"`

	// ImageBaseURL is where published catalogue-image artifacts are fetched
	// from. Empty means computeimage.DefaultBaseURL, which is the ordinary case
	// — this exists for a fork or a test origin, not for tuning.
	//
	// Note what it does NOT decide: whether a downloaded image is loaded. That
	// is settled by a SHA-256 compiled into the binary (see
	// internal/compute/catalogue.go), so pointing this somewhere else does not
	// let anything new onto the machine — it only changes where the node looks
	// for bytes it already knows the hash of. Which is why this is allowed to be
	// a config field at all, where MicroVMKernel above deliberately is not.
	ImageBaseURL string `json:"image_base_url,omitempty"`
}

// CanRunArbitrary reports whether this node may accept arbitrary code.
//
// Requires BOTH the measured capability and the artifacts. A node with KVM but
// no kernel image would advertise isolation it cannot actually provide, and the
// first arbitrary job placed on it would fail at boot — after the submitter had
// been told it was accepted.
func (c ComputeConfig) CanRunArbitrary(probeUsable bool) (bool, string) {
	if !c.Enabled {
		return false, "compute is switched off"
	}
	if !probeUsable {
		return false, "this machine cannot host a microVM (see the compute panel for why)"
	}
	if c.MicroVMKernel == "" || c.MicroVMRootFS == "" {
		return false, "no guest kernel or root filesystem configured — set both to run arbitrary code"
	}
	return true, ""
}

type DCSLimits struct {
	MaxContainers     int   `json:"max_containers"`
	CPUSharePct       int   `json:"cpu_share_pct"`
	RAMBytes          int64 `json:"ram_bytes"`
	DiskBytes         int64 `json:"disk_bytes"`
	ImageCacheBytes   int64 `json:"image_cache_bytes"`
	BandwidthKbps     int   `json:"bandwidth_kbps"`
	MaxRuntimeSeconds int   `json:"max_runtime_seconds"`
	// LabMaxRuntimeSeconds is a hard ceiling the agent enforces for lab
	// workloads whatever the deployer asked for. A forgotten vulnerable
	// container is the failure mode this exists to prevent.
	LabMaxRuntimeSeconds int `json:"lab_max_runtime_seconds"`
}

// DCSPolicy is the worker operator's SAFETY policy. Note what is deliberately
// absent: there is NO image allowlist. A worker does not decide which images it
// runs -- that is the job of the site's challenge catalog (the admin registry),
// not of every volunteer node. The worker's job is to run whatever build
// context it is handed, SAFELY: the hardened sandbox, the lab opt-in, the
// resource limits and the owner allowlist below are safety boundaries, not a
// say over which challenges exist.
type DCSPolicy struct {
	AllowExec           bool `json:"allow_exec"`
	ExecRecording       bool `json:"exec_recording"`
	AllowClearnetEgress bool `json:"allow_clearnet_egress"`
	AllowGatewayPublish bool `json:"allow_gateway_publish"`
	// OwnerAllowlist restricts WHO may deploy, not WHAT they deploy. Empty means
	// any authenticated owner.
	OwnerAllowlist []string `json:"owner_allowlist,omitempty"`
	// TrustedBrokers are node IDs permitted to deploy on behalf of sub-owners
	// (DeployRequest.OnBehalfOf). A website's bridge node deploys for thousands
	// of users through one identity; listing it here lets the worker's
	// one-container-per-user rule key on the real end user rather than capping
	// the whole site to a single container. Empty means no broker is trusted and
	// every deployer is accounted for by its own node id.
	TrustedBrokers []string `json:"trusted_brokers,omitempty"`
}

type GatewayConfig struct {
	Enabled        bool                `json:"enabled"`
	ProbeEnabled   bool                `json:"probe_enabled"`
	ListenAddress  string              `json:"listen_address"`
	ListenPort     int                 `json:"listen_port"`
	PublicHostname string              `json:"public_hostname"`
	AdvertiseIPv4  bool                `json:"advertise_ipv4"`
	AdvertiseIPv6  bool                `json:"advertise_ipv6"`
	ReverseProxy   bool                `json:"reverse_proxy"`
	TLS            GatewayTLSConfig    `json:"tls"`
	Verification   VerificationConfig  `json:"external_verification"`
	Health         GatewayHealthConfig `json:"health"`
	Eligibility    EligibilityConfig   `json:"eligibility"`
	// TrustedProbes maps node IDs to base64-encoded public keys. An empty map
	// admits no probes; a candidate can never authorize itself.
	TrustedProbes   map[string]string `json:"trusted_probes,omitempty"`
	ProbeURLs       []string          `json:"probe_urls,omitempty"`
	PublicAddresses []string          `json:"public_addresses,omitempty"`
	ProbeNetwork    string            `json:"probe_network,omitempty"`
	// RegistrationAPI is a public, credential-free HTTPS endpoint. The node
	// authenticates requests with its existing Ed25519 identity; authoritative
	// DNS credentials exist only on that server.
	RegistrationAPI string                 `json:"registration_api"`
	Frontend        GatewayFrontendConfig  `json:"frontend"`
	Content         GatewayContentConfig   `json:"content"`
	Validator       GatewayValidatorConfig `json:"validator"`
}

// GatewayValidatorConfig audits OTHER gateways and reports what they served,
// signed with this node's registered identity.
//
// Independent of every other role: a validator needs no storage, serves no
// content, and gains nothing from the gateways it audits. Running one is a
// contribution to the network's ability to check itself.
//
// Running several does not multiply anyone's voice. The origin weighs receipts
// by distinct operator and network rather than by count, so a fleet under one
// owner is one opinion however large it grows.
type GatewayValidatorConfig struct {
	Enabled bool `json:"enabled"`
	// OriginURL publishes the signing key, the gateway directory and the
	// spot-check feed.
	OriginURL string `json:"origin_url,omitempty"`
	// IntervalSeconds between rounds; each round audits one gateway.
	IntervalSeconds int `json:"interval_seconds,omitempty"`
	// SampleSize caps objects checked per round, so a validator stays a
	// background contributor rather than a load generator.
	SampleSize int `json:"sample_size,omitempty"`
}

// GatewayContentConfig serves site content under the gateway's OWN hostname.
//
// Distinct from Frontend, which forwards encrypted bytes it cannot read. This
// one decrypts, fetches and re-serves, so the gateway becomes a party a reader
// can name — and, necessarily, one that could lie. That is the trade: a
// passthrough gateway is harmless and unmeasurable, and only a gateway that
// could tamper can be shown not to have. See internal/gateway/contentproxy.go.
//
// Off by default. Donating transport must not silently enrol an operator in
// handling other people's reads.
type GatewayContentConfig struct {
	Enabled bool `json:"enabled"`
	// OriginURL is the site being served, e.g. https://syndichan.org.
	OriginURL string `json:"origin_url,omitempty"`
	// OriginAddress pins the origin to a literal host:port. DNS for the site
	// points at gateways too, so resolving the name here could send this
	// gateway's fetch to another gateway: a loop, and a way for one volunteer's
	// answer to be laundered through another's identity.
	OriginAddress string `json:"origin_address,omitempty"`
	MaxBytes      int64  `json:"max_bytes,omitempty"`

	// Emergency keeps a verified read-only copy of the site so this gateway can
	// answer when the origin cannot. See internal/gateway/snapshot.go.
	Emergency GatewayEmergencyConfig `json:"emergency"`
}

// GatewayEmergencyConfig is the read-only fallback copy.
//
// The publisher key is REQUIRED and is not defaulted. A gateway that would serve
// an unverified snapshot is one whose operator decides what syndichan says
// during an outage — the precise thing this whole design exists to prevent — so
// an absent key disables the feature rather than relaxing it.
type GatewayEmergencyConfig struct {
	Enabled bool `json:"enabled"`
	// PublisherKey is the base64 Ed25519 key from
	// /.well-known/syndichan/snapshot-key.json. NOT the origin content key.
	PublisherKey string `json:"publisher_key,omitempty"`
	// CacheDir holds the copy between restarts, so a gateway that reboots
	// mid-outage is useful immediately rather than after reaching a dead origin.
	CacheDir string `json:"cache_dir,omitempty"`
	// PollSeconds between checks for a newer snapshot.
	PollSeconds int `json:"poll_seconds,omitempty"`
	// MaxObjectBytes bounds one object, so a hostile manifest cannot ask this
	// gateway to buy a disk.
	MaxObjectBytes int64 `json:"max_object_bytes,omitempty"`
	// Offload serves publisher-approved routes from the snapshot even while the
	// origin is HEALTHY, taking read traffic off it entirely.
	//
	// Off by default and separate from Enabled, because it changes what a
	// reader gets during ordinary operation rather than only during an outage.
	// The publisher still decides WHICH routes; this only says whether this
	// gateway participates.
	Offload bool `json:"offload,omitempty"`
}

type GatewayFrontendConfig struct {
	Enabled          bool     `json:"enabled"`
	OriginAddress    string   `json:"origin_address"`
	OriginServerName string   `json:"origin_server_name"`
	SNIAllowlist     []string `json:"sni_allowlist"`
	// SNIRoutes forwards specific names to a co-tenant service on this host
	// instead of to the origin, without decrypting them. Lets a gateway take
	// public 443 on a machine that already terminates an unrelated name.
	SNIRoutes               map[string]string `json:"sni_routes,omitempty"`
	MaxConnections          int               `json:"max_connections"`
	MaxBytesPerSecond       int64             `json:"max_bytes_per_second"`
	HandshakeTimeoutSeconds int               `json:"handshake_timeout_seconds"`
	DialTimeoutSeconds      int               `json:"dial_timeout_seconds"`
	IdleTimeoutSeconds      int               `json:"idle_timeout_seconds"`
	DrainSeconds            int               `json:"drain_seconds"`
	ProxyProtocol           bool              `json:"proxy_protocol"`
	// AllowPrivateOrigin is an explicit development escape hatch. Production
	// configurations must never silently turn a volunteer into a route to its
	// loopback or private network.
	AllowPrivateOrigin bool `json:"allow_private_origin,omitempty"`
}

type GatewayTLSConfig struct {
	Mode               string `json:"mode"`
	CertificatePath    string `json:"certificate_path,omitempty"`
	PrivateKeyPath     string `json:"private_key_path,omitempty"`
	ACMEEmail          string `json:"acme_email,omitempty"`
	ACMEHTTPAddress    string `json:"acme_http_address,omitempty"`
	ACMECacheDirectory string `json:"acme_cache_directory,omitempty"`
}

type VerificationConfig struct {
	Enabled                     bool `json:"enabled"`
	MinimumSuccessfulProbes     int  `json:"minimum_successful_probes"`
	MinimumDistinctNetworks     int  `json:"minimum_distinct_networks"`
	VerificationTimeoutSeconds  int  `json:"verification_timeout_seconds"`
	RegistrationValiditySeconds int  `json:"registration_validity_seconds"`
	ProbeResultValiditySeconds  int  `json:"probe_result_validity_seconds"`
	ReverifyIntervalSeconds     int  `json:"reverify_interval_seconds"`
}

type GatewayHealthConfig struct {
	FailureThreshold     int `json:"failure_threshold"`
	RecoveryThreshold    int `json:"recovery_threshold"`
	CheckIntervalSeconds int `json:"check_interval_seconds"`
	DrainSeconds         int `json:"drain_seconds"`
}

type EligibilityConfig struct {
	MinimumUploadMbps    int   `json:"minimum_upload_mbps"`
	MinimumFreeMemoryMB  int64 `json:"minimum_free_memory_mb"`
	MinimumFreeDiskMB    int64 `json:"minimum_free_disk_mb"`
	MaximumCPUPercent    int   `json:"maximum_cpu_percent"`
	RequirePublicAddress bool  `json:"require_public_address"`
	RejectCGNAT          bool  `json:"reject_cgnat"`
}

func DefaultDataDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "Syndichan", "storage-node"), nil
}

func Default() (Config, error) {
	dir, err := DefaultDataDir()
	if err != nil {
		return Config{}, err
	}
	return Config{
		DataDir:  dir,
		RunMode:  "storage",
		S3Listen: "127.0.0.1:9000",
		// Every interface, not loopback. A node is usually a headless box, a VM
		// or a Pi that the operator administers from their laptop, so a
		// loopback-only dashboard is one they cannot reach at all without
		// knowing to change this first -- and they cannot know, because the
		// page that would tell them is the page they cannot open.
		//
		// This is only safe because validateDashboard REQUIRES a password for
		// any non-loopback bind, and the generated password below satisfies it.
		// Do not change one of these without the other.
		UIListen: "0.0.0.0:9090",
		// Generated, not blank: a blank password with the bind above would fail
		// validation and the node would refuse to start out of the box. Printed
		// at startup so the operator can read it out of the journal, and it is
		// theirs to replace with something memorable.
		UIUsername: DefaultDashboardUsername,
		UIPassword: generatedDashboardPassword(),
		// P2PListen is retained only so old configuration files still parse. The
		// production node never uses these clearnet addresses.
		P2PListen:     nil,
		I2PSAM:        "127.0.0.1:7656",
		I2PHTTPProxy:  "http://127.0.0.1:4444",
		CapacityBytes: 20 << 30,
		DataShards:    6,
		ParityShards:  3,
		ChunkBytes:    1 << 20,
		Gateway: GatewayConfig{
			ListenAddress: "0.0.0.0", ListenPort: 443,
			AdvertiseIPv4: true, AdvertiseIPv6: true,
			RegistrationAPI: "https://syndichan.org/api/v1/gateways",
			TLS: GatewayTLSConfig{
				Mode: "existing", ACMEHTTPAddress: "0.0.0.0:80",
			},
			Verification: VerificationConfig{
				Enabled: true, MinimumSuccessfulProbes: 3,
				MinimumDistinctNetworks: 2, VerificationTimeoutSeconds: 15,
				RegistrationValiditySeconds: 300, ProbeResultValiditySeconds: 120,
				ReverifyIntervalSeconds: 60,
			},
			Health: GatewayHealthConfig{
				FailureThreshold: 3, RecoveryThreshold: 2,
				CheckIntervalSeconds: 30, DrainSeconds: 60,
			},
			Eligibility: EligibilityConfig{
				MinimumUploadMbps: 10, MinimumFreeMemoryMB: 512,
				MinimumFreeDiskMB: 1024, MaximumCPUPercent: 90,
				RequirePublicAddress: true, RejectCGNAT: true,
			},
			Frontend: GatewayFrontendConfig{
				Enabled: false, OriginAddress: "",
				OriginServerName: "syndichan.org",
				SNIAllowlist:     []string{"syndichan.org"},
				MaxConnections:   1024, MaxBytesPerSecond: 16 << 20,
				HandshakeTimeoutSeconds: 10,
				DialTimeoutSeconds:      10, IdleTimeoutSeconds: 300,
				DrainSeconds: 60, ProxyProtocol: true,
			},
		},
		DCS: DCSConfig{
			Enabled:                  false,
			DockerEndpoint:           "unix:///var/run/docker.sock",
			AdvertiseIntervalSeconds: 300,
			RecordTTLSeconds:         900,
			Limits: DCSLimits{
				MaxContainers: 8, CPUSharePct: 50,
				RAMBytes: 4 << 30, DiskBytes: 50 << 30,
				ImageCacheBytes: 20 << 30,
				// 4 hours. A vulnerable container that outlives its operator's
				// attention is the failure mode this ceiling exists to kill.
				LabMaxRuntimeSeconds: 4 * 60 * 60,
			},
			// Every policy default is a refusal. Turning DCS on must not
			// silently hand a stranger a shell, an exit node, or a public
			// address on the operator's machine.
			Policy: DCSPolicy{},
		},
	}, nil
}

// LoadOrCreate reads the config at path, or creates a default one if it is
// missing, and validates it for the caller's runtime role. The role must be
// resolved from the command line before this is called: validating a
// gateway-only node as if it were a storage node is what used to reject a
// perfectly good gateway config for having no S3 credentials.
func LoadOrCreate(path string, role Role) (Config, bool, error) {
	cfg, err := Default()
	if err != nil {
		return Config{}, false, err
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return Config{}, false, fmt.Errorf("parse config: %w", err)
		}
		return cfg, false, cfg.ValidateForRole(role)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Config{}, false, err
	}
	cfg.DataDir = filepath.Dir(path)
	// Generated regardless of role so a freshly created file is a complete,
	// reusable storage config. A storage-free role validates and starts
	// without them; it simply never reads them.
	cfg.AccessKey = "SYN" + randomToken(12)
	cfg.SecretKey = randomToken(32)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return Config{}, false, err
	}
	raw, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return Config{}, false, err
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		return Config{}, false, err
	}
	return cfg, true, cfg.ValidateForRole(role)
}

// Validate checks a full storage node. It is the RoleStorage case of
// ValidateForRole; anything that selects a role must call ValidateForRole so a
// storage-free role is never held to storage requirements.
func (c Config) Validate() error {
	return c.ValidateForRole(RoleStorage)
}

// ValidateForRole checks only the configuration the given role consumes.
func (c Config) ValidateForRole(role Role) error {
	if err := c.validateRole(role); err != nil {
		return err
	}
	// Checked for EVERY role, not only storage: main starts the management page
	// in every mode -- it is where a gateway-only node is configured at all --
	// so a gateway host that binds it to the world is exactly as exposed as a
	// storage host that does.
	if err := c.validateDashboard(); err != nil {
		return err
	}
	if role.NeedsStorage() {
		if err := c.validateStorage(); err != nil {
			return err
		}
	}
	return c.validateGateway()
}

// validateRole checks that the config actually supports the requested role.
func (c Config) validateRole(role Role) error {
	switch role {
	case RoleStorage, RoleManagement:
		return nil
	case RoleGatewayOnly:
		if !c.Gateway.Enabled && !c.Gateway.ProbeEnabled {
			return errors.New("gateway-only mode requires gateway.enabled or gateway.probe_enabled")
		}
		return nil
	case RoleProbeOnly:
		if !c.Gateway.ProbeEnabled || c.Gateway.Enabled {
			return errors.New("probe-only mode requires gateway.probe_enabled=true and gateway.enabled=false")
		}
		return nil
	default:
		return fmt.Errorf("unknown runtime role %q", role)
	}
}

// DefaultDashboardUsername is the Basic-auth user the management page asks for
// when ui_username is left blank. The username is not the secret; naming it
// saves the operator from having to guess what to type into the browser.
const DefaultDashboardUsername = "admin"

// minDashboardPasswordLength is deliberately longer than a person's habitual
// password. The page is reachable from a whole network the moment it leaves
// loopback, there is no lockout, and a short password on an admin panel is
// found by a script long before it is found by a person.
const minDashboardPasswordLength = 12

// DashboardUsername is the credential the dashboard actually demands, with the
// default filled in. Read this rather than UIUsername so the config file and
// the running server can never disagree about who may log in.
func (c Config) DashboardUsername() string {
	if name := strings.TrimSpace(c.UIUsername); name != "" {
		return name
	}
	return DefaultDashboardUsername
}

// ListenIsLoopback reports whether a host:port listen address is reachable only
// from this machine. An address it cannot parse is reported as NOT loopback:
// every caller uses this to decide whether to demand a password, and the safe
// answer to "I do not know where this is bound" is "ask for the password".
func ListenIsLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	return isLoopback(host)
}

// validateDashboard covers ui_listen and the credential that guards it.
//
// The management page can change the payout address, the storage paths and the
// compute switches, so the question is never "may it be reachable" on its own
// but "reachable by whom, and holding what". Three rules answer that:
//
//   - Loopback stays exactly as it was, credential-free. Whoever reaches it is
//     already sitting at the machine, and every existing config keeps working.
//   - Off (empty ui_listen) stays valid. A rented server administered over SSH
//     should be able to not run the page at all rather than run something the
//     operator cannot reach and would not want reachable.
//   - Anything else must be a private address AND carry a password.
func (c Config) validateDashboard() error {
	if c.UIListen == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(c.UIListen)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", c.UIListen, err)
	}
	if isLoopback(host) {
		return nil
	}
	// 0.0.0.0 and :: are ALLOWED, and this is a deliberate reversal. Naming one
	// private address is safer in the abstract -- it binds only the interface
	// you meant -- but it also breaks on DHCP, on a machine with two NICs, and
	// on every VM whose address the operator does not know in advance. The
	// operator asked for all interfaces, and an installer that refuses the
	// obvious thing to type is not one people use.
	//
	// The password requirement below is what carries the weight now, and it
	// applies to every non-loopback bind including this one. Note what that
	// does NOT cover: this is cleartext HTTP, so on a machine with a public
	// address the dashboard is exposed to the internet behind one password.
	// Bind a private address, or firewall the port, if that machine is not
	// yours alone.
	if address := net.ParseIP(strings.Trim(host, "[]")); address != nil && address.IsUnspecified() {
		if len(c.UIPassword) < minDashboardPasswordLength {
			return fmt.Errorf("ui_listen %q binds every interface, including any public one, so it "+
				"must have a password: set \"ui_password\" in the config file to at least %d "+
				"characters (\"ui_username\" is optional and defaults to %q)",
				c.UIListen, minDashboardPasswordLength, DefaultDashboardUsername)
		}
		return nil
	}
	if !isLANOnly(host) {
		return fmt.Errorf("ui_listen %q is publicly routable; the management dashboard may only "+
			"be bound to loopback or a private address (10.x, 172.16-31.x, 192.168.x, "+
			"169.254.x, or an IPv6 unique-local fc00::/7 address)", c.UIListen)
	}
	if strings.ContainsAny(c.UIUsername, ":\r\n") {
		return errors.New("ui_username must not contain a colon or a newline")
	}
	if len(c.UIPassword) < minDashboardPasswordLength {
		return fmt.Errorf("ui_listen %q makes the management dashboard reachable from your local "+
			"network, so it must have a password: set \"ui_password\" in the config file to at "+
			"least %d characters (\"ui_username\" is optional and defaults to %q)",
			c.UIListen, minDashboardPasswordLength, DefaultDashboardUsername)
	}
	return nil
}

// validateStorage covers every setting that only a storage node consumes: the
// loopback S3 gateway and its credentials, the erasure layout, the donated
// capacity, and the I2P control endpoints. A gateway-only or probe-only process
// starts none of these and must never reach this function.
func (c Config) validateStorage() error {
	if c.AccessKey == "" || len(c.SecretKey) < 32 {
		return errors.New("S3 credentials are missing or too short")
	}
	if c.DataShards < 2 || c.ParityShards < 1 || c.DataShards+c.ParityShards > 64 {
		return errors.New("erasure coding must use 2-63 data shards and at least one parity shard")
	}
	if c.ChunkBytes < 64<<10 || c.ChunkBytes > 16<<20 {
		return errors.New("chunk_bytes must be between 64 KiB and 16 MiB")
	}
	if c.CapacityBytes < 64<<20 {
		return errors.New("capacity_bytes must be at least 64 MiB")
	}
	if c.CapacityBytes > 8<<50 {
		return errors.New("capacity_bytes must not exceed 8 PiB")
	}
	s3Host, _, err := net.SplitHostPort(c.S3Listen)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", c.S3Listen, err)
	}
	if !isLoopback(s3Host) && (c.TLSCert == "" || c.TLSKey == "") {
		return fmt.Errorf("%s is non-loopback; TLS certificate and key are required", c.S3Listen)
	}
	samHost, _, err := net.SplitHostPort(c.I2PSAM)
	if err != nil {
		return fmt.Errorf("invalid I2P SAM address %q: %w", c.I2PSAM, err)
	}
	if !isLoopback(samHost) {
		return errors.New("the I2P SAM bridge must be on loopback")
	}
	proxy, err := url.Parse(c.I2PHTTPProxy)
	if err != nil || proxy.Scheme != "http" || proxy.User != nil || proxy.Path != "" ||
		proxy.RawQuery != "" || proxy.Fragment != "" {
		return errors.New("i2p_http_proxy must be an unauthenticated loopback HTTP proxy URL")
	}
	proxyHost, _, err := net.SplitHostPort(proxy.Host)
	if err != nil || !isLoopback(proxyHost) {
		return errors.New("i2p_http_proxy must point to a loopback address")
	}
	return nil
}

func (c Config) validateGateway() error {
	g := c.Gateway
	if g.ListenPort < 1 || g.ListenPort > 65535 {
		return errors.New("gateway listen_port must be between 1 and 65535")
	}
	if g.Enabled || g.ProbeEnabled {
		if strings.ContainsAny(g.PublicHostname, "/:@") {
			return errors.New("gateway public_hostname is required and must be a hostname")
		}
		if g.PublicHostname == "" && (!g.Enabled || g.TLS.Mode != "acme") {
			return errors.New("gateway public_hostname is required unless ACME uses controller reservation")
		}
		if g.TLS.Mode != "existing" && g.TLS.Mode != "acme" &&
			g.TLS.Mode != "reverse_proxy" {
			return errors.New("gateway tls mode must be existing, acme, or reverse_proxy")
		}
		if g.TLS.Mode == "existing" &&
			(g.TLS.CertificatePath == "" || g.TLS.PrivateKeyPath == "") {
			return errors.New("gateway existing TLS mode requires certificate and private key paths")
		}
		if g.TLS.Mode == "acme" {
			if g.PublicHostname != "" && !validLiteralHostname(g.PublicHostname) {
				return errors.New("gateway ACME mode requires a literal public hostname")
			}
			if _, _, err := net.SplitHostPort(g.TLS.ACMEHTTPAddress); err != nil {
				return errors.New("gateway ACME HTTP address must be host:port")
			}
			// Catch the shipped placeholder here rather than letting it surface
			// four steps later as an opaque "registry returned HTTP 422". Let's
			// Encrypt rejects reserved example domains, so no certificate is
			// issued, so the controller's TLS connect-back fails, so
			// registration is refused -- and none of those messages mention the
			// email that actually caused it.
			if reservedEmailDomain(g.TLS.ACMEEmail) {
				return fmt.Errorf(
					"gateway tls.acme_email is still the placeholder %q; Let's Encrypt "+
						"refuses reserved example domains. Put a real address there -- it is "+
						"used only for certificate expiry warnings and is never published",
					g.TLS.ACMEEmail)
			}
		}
		if g.Frontend.Enabled && g.TLS.Mode == "reverse_proxy" {
			return errors.New("gateway frontend requires existing or ACME TLS for its local identity endpoint")
		}
	}
	if g.Content.Enabled {
		if !g.Enabled {
			return errors.New("gateway.content requires gateway.enabled: content is served under the gateway's own hostname")
		}
		origin, err := url.Parse(g.Content.OriginURL)
		if err != nil || origin.Scheme != "https" || origin.Host == "" {
			return errors.New("gateway.content.origin_url must be an HTTPS URL, e.g. https://syndichan.org")
		}
		if g.Content.OriginAddress != "" {
			if _, _, err := net.SplitHostPort(g.Content.OriginAddress); err != nil {
				return errors.New("gateway.content.origin_address must be host:port")
			}
		}
		// Serving content under a hostname the operator does not hold a
		// certificate for cannot work, and the failure would look like a
		// TLS error four steps later rather than a configuration mistake.
		if g.TLS.Mode == "reverse_proxy" && g.PublicHostname == "" {
			return errors.New("gateway.content needs a public_hostname readers can reach")
		}
		if g.Content.Emergency.Enabled {
			// Refused rather than defaulted. Without the key this gateway would
			// either serve an unverified snapshot -- letting its operator decide
			// what syndichan says during an outage -- or silently do nothing,
			// and an emergency feature that silently does nothing is worse than
			// one that is plainly off.
			if strings.TrimSpace(g.Content.Emergency.PublisherKey) == "" {
				return errors.New(
					"gateway.content.emergency needs publisher_key: copy it from " +
						"/.well-known/syndichan/snapshot-key.json (it is NOT the " +
						"origin content-signing key)")
			}
			if strings.TrimSpace(g.Content.Emergency.CacheDir) == "" {
				return errors.New("gateway.content.emergency needs a cache_dir")
			}
		}
	}
	if g.Enabled {
		registry, err := url.Parse(g.RegistrationAPI)
		if err != nil || registry.Scheme != "https" || registry.Host == "" ||
			registry.User != nil || registry.RawQuery != "" || registry.Fragment != "" {
			return errors.New("gateway registration_api must be a credential-free HTTPS URL")
		}
		if registry.Path == "" || registry.Path == "/" {
			return errors.New("gateway registration_api must include its API path")
		}
	}
	if g.ProbeEnabled && strings.TrimSpace(g.ProbeNetwork) == "" {
		return errors.New("probe_network is required when probe mode is enabled")
	}
	if g.Enabled {
		// Needed for the registration itself, quorum or not: the node has to
		// declare which address it is claiming.
		if len(g.PublicAddresses) == 0 {
			return errors.New(
				"gateway public_addresses is empty: list this host's literal public IP, e.g. [\"203.0.113.10\"]")
		}
	}
	// probe_urls are OTHER volunteers running -probe-only who connect back to
	// this host and independently confirm it is reachable.
	//
	// NOT CONFIGURED is not the same as MISCONFIGURED. A stock config enables
	// external_verification and lists no probes, because there may be no probe
	// fleet to list yet -- the first gateway on a network cannot have one, and
	// probes are themselves gateways someone has to stand up first. Refusing to
	// start over that made the shipped example unbootable and the whole role
	// unreachable to a new operator.
	//
	// So: no probes configured at all means "verify through the controller
	// alone", which it does anyway before publishing DNS. Such a node never
	// reports gateway_verified, so nothing overstates its trust. But a
	// PARTIALLY configured quorum -- some probes, fewer than the threshold --
	// is a genuine mistake and still refuses to start.
	if g.Enabled && g.Verification.Enabled && ProbeQuorumConfigured(g) {
		if len(g.ProbeURLs) < g.Verification.MinimumSuccessfulProbes {
			return fmt.Errorf(
				"gateway.external_verification needs %d probe_urls but only %d are configured; "+
					"add the missing probe origins, or clear probe_urls/trusted_probes to "+
					"verify through the controller alone",
				g.Verification.MinimumSuccessfulProbes, len(g.ProbeURLs))
		}
	}
	v := g.Verification
	if v.MinimumSuccessfulProbes < 1 || v.MinimumDistinctNetworks < 1 ||
		v.MinimumDistinctNetworks > v.MinimumSuccessfulProbes {
		return errors.New("invalid gateway verification quorum")
	}
	if v.VerificationTimeoutSeconds < 1 || v.ProbeResultValiditySeconds < 1 ||
		v.RegistrationValiditySeconds < 1 || v.ReverifyIntervalSeconds < 1 {
		return errors.New("gateway verification durations must be positive")
	}
	if err := validateGatewayFrontend(g.Frontend); err != nil {
		return err
	}
	return nil
}

// reservedEmailDomain reports whether an ACME contact address sits in a domain
// RFC 2606/6761 reserves for documentation. An empty address is fine -- Let's
// Encrypt allows an account with no contact, it just cannot warn you before a
// certificate lapses.
func reservedEmailDomain(email string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	switch domain {
	case "example.com", "example.org", "example.net", "example.edu":
		return true
	}
	return domain == "example" || domain == "invalid" || domain == "test" ||
		strings.HasSuffix(domain, ".example") || strings.HasSuffix(domain, ".invalid") ||
		strings.HasSuffix(domain, ".test")
}

// ProbeQuorumConfigured reports whether the operator has actually named a peer
// probe fleet. It is the single definition of "a quorum is in play", shared by
// validation and by startup, so the checks and the runtime can never disagree
// about which verification mode this node is in.
func ProbeQuorumConfigured(g GatewayConfig) bool {
	return len(g.ProbeURLs) > 0 || len(g.TrustedProbes) > 0
}

func validateGatewayFrontend(frontend GatewayFrontendConfig) error {
	if !frontend.Enabled {
		return nil
	}
	host, port, err := net.SplitHostPort(frontend.OriginAddress)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return errors.New("gateway frontend origin_address must be host:port")
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return errors.New("gateway frontend origin_address has an invalid port")
	}
	originHost := strings.Trim(strings.ToLower(host), "[]")
	if !frontend.AllowPrivateOrigin && isPrivateOrLocalHost(originHost) {
		return errors.New("gateway frontend origin is loopback/private; set allow_private_origin only for development")
	}
	if !validLiteralHostname(frontend.OriginServerName) {
		return errors.New("gateway frontend origin_server_name must be a literal hostname")
	}
	if len(frontend.SNIAllowlist) == 0 {
		return errors.New("gateway frontend sni_allowlist must not be empty")
	}
	for _, hostname := range frontend.SNIAllowlist {
		if !validLiteralHostname(hostname) {
			return fmt.Errorf("gateway frontend SNI entry %q must be a literal hostname", hostname)
		}
	}
	if frontend.MaxConnections < 1 {
		return errors.New("gateway frontend max_connections must be positive")
	}
	if frontend.MaxBytesPerSecond < 1 {
		return errors.New("gateway frontend max_bytes_per_second must be positive")
	}
	if frontend.HandshakeTimeoutSeconds < 1 || frontend.DialTimeoutSeconds < 1 ||
		frontend.IdleTimeoutSeconds < 1 || frontend.DrainSeconds < 0 {
		return errors.New("gateway frontend timeouts must be positive and drain_seconds non-negative")
	}
	return nil
}

func validLiteralHostname(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "* /:@[]") ||
		net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func isPrivateOrLocalHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && (address.IsLoopback() || address.IsPrivate() ||
		address.IsLinkLocalUnicast() || address.IsUnspecified())
}

func isLoopback(host string) bool {
	host = strings.Trim(host, "[]")
	return host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

// isLANOnly extends isLoopback to the rest of the operator's own network:
// RFC1918, IPv4 link-local and IPv6 unique-local. A packet addressed to one of
// these cannot be routed to this machine from the internet, so binding here
// widens the audience from "this machine" to "this network" and no further.
//
// 100.64.0.0/10 is deliberately NOT included. Some readers know it as their
// Tailscale range, but it is carrier-grade NAT space, and on an ISP that uses
// it the "local network" is every other subscriber on that carrier. When the
// two meanings cannot be told apart from the address, the one that would be
// embarrassing to be wrong about wins.
func isLANOnly(host string) bool {
	if isLoopback(host) {
		return true
	}
	address := net.ParseIP(strings.Trim(host, "[]"))
	return address != nil && (address.IsPrivate() || address.IsLinkLocalUnicast())
}

func randomToken(bytes int) string {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

// Save writes the config back atomically at mode 0600. Used when a flag such
// as -data-dir changes a persisted value, so the setting survives restarts
// instead of having to be repeated on every launch.
func Save(path string, cfg Config, role Role) error {
	if err := cfg.ValidateForRole(role); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	// Write-then-rename so an interrupted save cannot leave a truncated config
	// that would lose the S3 credentials and master key references.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func ConfigPath(override string) (string, error) {
	if override != "" {
		return filepath.Abs(override)
	}
	dir, err := DefaultDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func PlatformLabel() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// RouterConfig is the payment-channel routing role.
//
// NOT "Lightning". The mechanism is the same family Lightning proved — channels,
// conditional locks, unilateral close with a challenge period — but Lightning is
// Bitcoin and this settles on Ethereum. Naming it Lightning in a config file
// would be the sort of small untruth that later has to be explained to somebody
// who trusted it.
//
// WHY A ROUTER NEEDS ITS OWN SETTINGS
// -----------------------------------
// A storage node lends disk it was not using. A router lends LIQUIDITY — money
// locked in channels that cannot be spent elsewhere while it is committed. That
// is a materially different thing to ask of somebody, and the settings below
// exist so an operator can bound it precisely rather than agreeing to an
// open-ended commitment.
type RouterConfig struct {
	Enabled bool `json:"enabled"`

	// Operator and FaultDomain are how this node DECLARES its independence, and
	// they feed route diversity: a private route must cross three distinct
	// operators, and a node that leaves these blank cannot be counted toward
	// that. Self-declared and unverifiable — used to exclude, never to prove.
	Operator    string `json:"operator,omitempty"`
	FaultDomain string `json:"fault_domain,omitempty"`

	// MaxChannels bounds how many peers this node will open with. Each channel
	// is an on-chain transaction to open and another to close, so this is a fee
	// budget as much as a resource limit.
	MaxChannels int `json:"max_channels"`

	// MinChannelCapacity and MaxChannelCapacity bound each channel, in the
	// token's smallest unit. The minimum exists because a channel too small to
	// route anything still costs two on-chain transactions.
	MinChannelCapacity int64 `json:"min_channel_capacity"`
	MaxChannelCapacity int64 `json:"max_channel_capacity"`

	// TotalCommittedMax is the hard ceiling across ALL channels. The one number
	// an operator most needs: it answers "how much of my money can this tie up
	// at once" without them having to multiply the others together.
	TotalCommittedMax int64 `json:"total_committed_max"`

	// BaseFeeMilli is charged per forwarded payment, ProportionalFeePPM per
	// unit forwarded. Both, because a tiny payment costs the same work as a
	// large one while a large one ties up more liquidity.
	BaseFeeMilli       int64 `json:"base_fee_milli"`
	ProportionalFeePPM int64 `json:"proportional_fee_ppm"`

	// MaxInFlight bounds concurrent locked payments. This is the channel-jamming
	// defence: without a cap, a peer opens many small locks it never settles and
	// this node's liquidity is stuck until they expire.
	MaxInFlight int `json:"max_in_flight"`

	// MaxHTLCValue bounds any single forwarded payment, so one large transfer
	// cannot consume the whole outbound balance.
	MaxHTLCValue int64 `json:"max_htlc_value"`

	// MinTimelockBlocks is the safety margin demanded on an incoming lock. Too
	// small and this node can be left unable to claim upstream after paying
	// downstream — the one routing failure that actually loses money.
	MinTimelockBlocks int `json:"min_timelock_blocks"`

	// PrivateRoutingOnly refuses to forward payments that are not privately
	// routed. An operator who does not want to know who is paying whom can
	// arrange not to be able to find out.
	PrivateRoutingOnly bool `json:"private_routing_only"`

	// WatchtowerEnabled offers this node as a watchtower for others.
	WatchtowerEnabled bool `json:"watchtower_enabled"`

	// AutoRebalance lets the node move liquidity between its own channels.
	// Off by default: rebalancing costs fees and an operator should opt into
	// spending money automatically.
	AutoRebalance bool `json:"auto_rebalance"`
}

// Normalise applies safe defaults without silently widening anything the
// operator narrowed.
func (r RouterConfig) Normalise() RouterConfig {
	if r.MaxChannels <= 0 {
		r.MaxChannels = 10
	}
	if r.MaxInFlight <= 0 {
		r.MaxInFlight = 20
	}
	if r.MinTimelockBlocks <= 0 {
		// Enough for a dispute to be noticed and answered. Deliberately not
		// zero: a zero margin is the setting that loses money.
		r.MinTimelockBlocks = 40
	}
	if r.MinChannelCapacity < 0 {
		r.MinChannelCapacity = 0
	}
	return r
}

// CanRoute reports whether this node may take routing work, and why not.
//
// Diversity comes first because it is the answer an operator is least likely to
// predict: a router with no operator label cannot be counted toward the three
// independent operators a private route needs, so it would be selected for
// nothing and never learn why.
func (r RouterConfig) CanRoute() (bool, string) {
	if !r.Enabled {
		return false, "routing is switched off"
	}
	if r.Operator == "" {
		return false, "set an operator name — a router that does not declare who " +
			"runs it cannot count toward the independent operators a private route needs"
	}
	if r.TotalCommittedMax <= 0 {
		return false, "set a total liquidity ceiling before routing"
	}
	if r.MaxChannelCapacity > 0 && r.MaxChannelCapacity > r.TotalCommittedMax {
		return false, "a single channel may not exceed the total liquidity ceiling"
	}
	return true, ""
}

// generatedDashboardPassword returns a random password for a fresh config.
//
// A default node binds its dashboard to every interface, which validateDashboard
// only permits with a password -- so the alternative to generating one is a node
// that will not start until the operator edits a file they cannot yet reach the
// page to be told about. Random beats a fixed default for the obvious reason: a
// shipped constant is not a password, it is a published one.
//
// Base64 of 18 bytes, comfortably past the 12-character minimum. On the
// vanishingly unlikely failure of the system RNG this returns empty, which makes
// validation refuse the config loudly rather than silently install a node whose
// admin page has no password at all.
func generatedDashboardPassword() string {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}


// ChannelsConfig turns this node into a payment-channel node — roadmap P15.
//
// WHY THE TWO LISTENERS ARE SEPARATE FIELDS
// -----------------------------------------
// They have opposite audiences and the difference is load-bearing:
//
//	PeerListen  SCPP/1 for STRANGERS. Unauthenticated by design — a tipper has
//	            no token and must never be given one — and authorised instead by
//	            the signature inside every message. Public.
//
//	APIListen   the OPERATOR's own API. It can move this node's money and change
//	            its payout policy, so it is loopback and bearer-token gated. It
//	            must never be reachable from a web page.
//
// One field for both would be one edit away from serving the operator API to
// the internet, so they are named apart and documented apart.
type ChannelsConfig struct {
	// Enabled turns the payment stack on. Everything below is ignored when false.
	Enabled bool `json:"enabled"`

	// PeerListen is the public SCPP/1 address, e.g. ":8547". Empty disables it,
	// which makes this node unable to receive tips at all.
	PeerListen string `json:"peer_listen,omitempty"`
	// APIListen is the operator API, e.g. "127.0.0.1:8548". Refused below if it
	// is not loopback.
	APIListen string `json:"api_listen,omitempty"`
	// APIToken gates the operator API. Required whenever APIListen is set.
	APIToken string `json:"api_token,omitempty"`

	// Volunteer is the mailbox this node COLLECTS FROM, as opposed to Mailbox
	// below, which is the mailbox this node RUNS FOR OTHERS. The two are
	// separate because most nodes are one or the other, and a node that
	// confused them would go looking for its own tips in its own queue.
	//
	// It lives in the config rather than arriving with a request because the
	// browser must never choose which volunteer the node talks to: a caller who
	// could name the volunteer could name their own and feed this node frames
	// of their choosing.
	Volunteer VolunteerConfig `json:"volunteer,omitempty"`

	// PeerTLSCert/PeerTLSKey serve the PUBLIC peer surface over HTTPS.
	//
	// NOT OPTIONAL IN PRACTICE, even though they are optional fields. A
	// contributor's browser refuses to hand a signed proposal to a mailbox that
	// is not https (tip-channel.js, "insecure_endpoint"), because a plain-http
	// mailbox could be rewritten in flight by anyone on the path. Without these
	// the peer surface listens on http and no browser will ever talk to it, so
	// a volunteer configured without them is a volunteer nobody can use.
	//
	// Named apart from the node's other TLS fields because this listener has a
	// different audience: strangers, not the operator.
	PeerTLSCert string `json:"peer_tls_cert,omitempty"`
	PeerTLSKey  string `json:"peer_tls_key,omitempty"`

	// RPC is the execution endpoint used to read channel state and delegations.
	RPC string `json:"rpc,omitempty"`
	// Manager is the AxonChannels address.
	Manager string `json:"manager,omitempty"`
	// ChainID guards against a state signed for one deployment being replayed
	// against another; it is inside every digest.
	ChainID int64 `json:"chain_id,omitempty"`

	// KeyFile holds this node's channel key, hex, no 0x. Derived from the node
	// seed under its own domain rather than reusing the payout key — see
	// internal/channel/keys.go on why one leaked hot key should cost what is in
	// open channels and not the address earnings accumulate in.
	KeyFile string `json:"key_file,omitempty"`

	// Mailbox makes this node a VOLUNTEER: it holds frames for recipients who
	// authorized it, and holds no key for any of them.
	Mailbox MailboxConfig `json:"mailbox"`
	// Delegate makes this node an authorized signer for recipients who opted in
	// on chain. Strictly more powerful than a mailbox, and separate so that
	// running one can never turn into running the other by accident.
	Delegate DelegateConfig `json:"delegate"`
}

// MailboxConfig configures volunteer mailbox service.
// VolunteerConfig names the mailbox holding this node's incoming tips.
//
// Both fields or neither: the node id is half of every mailbox challenge, so an
// endpoint without one produces a signature the volunteer cannot match and a
// refusal that reads like a permission problem.
type VolunteerConfig struct {
	// Endpoint is the volunteer's public mailbox, e.g. "https://vol.example".
	Endpoint string `json:"endpoint,omitempty"`
	// NodeID is the volunteer's identifier, as named in the authorization the
	// recipient signed.
	NodeID string `json:"node_id,omitempty"`
}

// Configured reports whether this node can go looking for tips at all.
func (v VolunteerConfig) Configured() bool { return v.Endpoint != "" && v.NodeID != "" }

type MailboxConfig struct {
	Enabled bool `json:"enabled"`
	// NodeID is what recipients name in their authorizations. An authorization
	// for another node is refused, so this cannot be used to poach recipients.
	NodeID string `json:"node_id,omitempty"`
	// Depth caps undelivered frames per recipient. Zero uses the default.
	Depth int `json:"depth,omitempty"`
}

// DelegateConfig configures delegated signing.
//
// The node holds a delegate key. It is NOT any recipient's wallet key, it
// receives nothing, and the contract still pays the channel party.
type DelegateConfig struct {
	Enabled bool `json:"enabled"`
	// KeyFile holds the delegate key, hex. Separate from the channel key: a
	// delegate acts for other people, and the two roles should not share a
	// secret.
	KeyFile string `json:"key_file,omitempty"`
}

// Validate refuses configurations that would expose the operator API.
func (c ChannelsConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.APIListen != "" {
		if c.APIToken == "" {
			return errors.New("channels.api_token is required whenever channels.api_listen is set")
		}
		host, _, err := net.SplitHostPort(c.APIListen)
		if err != nil {
			return fmt.Errorf("channels.api_listen is not host:port: %w", err)
		}
		// THE CHECK THAT MATTERS. The operator API can move this node's money;
		// a config typo that put it on 0.0.0.0 would publish that ability.
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("channels.api_listen must be loopback, got %q — "+
				"the operator API can move this node's funds", c.APIListen)
		}
	}
	if c.Delegate.Enabled && c.Delegate.KeyFile == "" {
		return errors.New("channels.delegate.key_file is required when delegation is enabled")
	}
	if (c.Volunteer.Endpoint == "") != (c.Volunteer.NodeID == "") {
		return fmt.Errorf("channels.volunteer needs both endpoint and node_id, " +
			"or neither: a half-configured volunteer cannot be queried")
	}
	// https only, for the same reason the website refuses a plain-http mailbox:
	// anyone on the path could substitute the proposals this node is about to
	// verify. It would still refuse the forged ones, but a volunteer that can be
	// rewritten in flight can also silently withhold real tips.
	if c.Volunteer.Endpoint != "" && !strings.HasPrefix(c.Volunteer.Endpoint, "https://") {
		return fmt.Errorf("channels.volunteer.endpoint must be https, got %q", c.Volunteer.Endpoint)
	}
	if c.Mailbox.Enabled && c.Mailbox.NodeID == "" {
		return errors.New("channels.mailbox.node_id is required when the mailbox is enabled")
	}
	if c.RPC == "" || c.Manager == "" {
		return errors.New("channels.rpc and channels.manager are required when channels are enabled")
	}
	return nil
}
