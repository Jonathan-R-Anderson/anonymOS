package dcs

import (
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
)

// DHTWorkerNamespace mirrors gateway.DHTNamespace. A worker publishes its
// capability record under /syndichan-dcs-worker/<node-id>, validated and
// selected-by-sequence exactly like a gateway registration.
const DHTWorkerNamespace = "syndichan-dcs-worker"

func WorkerDHTKey(nodeID string) string { return "/" + DHTWorkerNamespace + "/" + nodeID }

// WorkerRecord is the capability advertisement (DCS.md §3). Utilisation is
// bucketed, never exact, so the record is not a side channel for when the
// host's operator is using the machine.
type WorkerRecord struct {
	RecordType   string `json:"record_type"` // "dcs_worker"
	NodeID       string `json:"node_id"`
	PublicKey    string `json:"public_key"`
	Destination  string `json:"destination"` // <b32>.i2p of the agent itself
	ProtocolVer  int    `json:"protocol_version"`
	AgentVersion string `json:"agent_version"`
	// ContentPubKey is the worker's base64 Curve25519 content key. The coordinator
	// seals a per-object content key to it so only this worker can decrypt the one
	// build context it was granted. Covered by Signature, so it cannot be swapped.
	ContentPubKey string `json:"content_pubkey,omitempty"`

	Arch         string   `json:"arch"`
	Capabilities []string `json:"capabilities"` // worker,gpu,volumes,gateway,lab

	CPUCores int   `json:"cpu_cores"`
	RAMBytes int64 `json:"ram_bytes"`
	Slots    int   `json:"slots"`
	Running  int   `json:"running"`

	// Compute is the M1 capability profile: what this machine can compute
	// with, and a measured figure for how fast, from a kernel any other node
	// can reproduce. Optional — a node that predates this, or one that could
	// not probe, simply does not carry it, and a scheduler treats its absence
	// as "unknown" rather than "none".
	//
	// Covered by Signature like everything else here, because SignWorkerRecord
	// marshals the whole struct. That matters: an unsigned performance claim
	// is one any relay could inflate on the node's behalf.
	Compute *compute.Profile `json:"compute,omitempty"`

	HealthScore int    `json:"health_score"`
	Region      string `json:"region,omitempty"`

	Sequence  uint64 `json:"sequence"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	Signature string `json:"signature"`
}

// HasCapability reports whether the worker claims a capability. A claim is
// cheap; proof happens at admission (a GPU worker is probed, a lab worker's
// own operator must have opted in).
func (r WorkerRecord) HasCapability(name string) bool {
	for _, c := range r.Capabilities {
		if c == name {
			return true
		}
	}
	return false
}

func (r WorkerRecord) expired(now time.Time) bool { return r.ExpiresAt <= now.Unix() }

var (
	ErrNoWorkerMatched = errors.New("dcs: no worker matched the requirement")
	ErrEmptyCandidate  = errors.New("dcs: empty candidate set")
)

// Requirement is what a deployment needs from a worker.
type Requirement struct {
	Capabilities []string // ALL must be present, e.g. ["worker","lab"]
	MinRAMBytes  int64
	Arch         string // empty = any
}

func (r WorkerRecord) satisfies(req Requirement, now time.Time) bool {
	if r.expired(now) || r.RecordType != "dcs_worker" {
		return false
	}
	// A worker with no I2P destination cannot be dialed -- an older agent that
	// advertised itself without one. Never pick it: doing so fails the whole
	// deploy with "invalid I2P base32 destination" instead of trying a worker
	// that actually has an address.
	if strings.TrimSpace(r.Destination) == "" {
		return false
	}
	if r.Slots <= 0 {
		return false
	}
	if req.MinRAMBytes > 0 && r.RAMBytes < req.MinRAMBytes {
		return false
	}
	if req.Arch != "" && r.Arch != req.Arch {
		return false
	}
	for _, need := range req.Capabilities {
		if !r.HasCapability(need) {
			return false
		}
	}
	return true
}

// FilterWorkers returns the workers that satisfy req.
func FilterWorkers(records []WorkerRecord, req Requirement, now time.Time) []WorkerRecord {
	var out []WorkerRecord
	for _, r := range records {
		if r.satisfies(req, now) {
			out = append(out, r)
		}
	}
	return out
}

// PickRandom chooses one satisfying worker uniformly at random.
//
// "Random" is a real scheduling policy here, not a placeholder: it is the
// simplest decorrelating choice, so two independent deployers do not both
// stampede the single "best" worker (DCS.md §4.2). Randomness is drawn from the
// caller-supplied source rather than math/rand's global, because this binary
// forbids Math.random-style nondeterminism in some build paths and because a
// test must be able to make the choice deterministic.
//
// The source returns a uniform uint64; entropy comes from crypto/rand in
// production (see RandUint64).
func PickRandom(records []WorkerRecord, req Requirement, now time.Time, rand func() uint64) (WorkerRecord, error) {
	candidates := FilterWorkers(records, req, now)
	if len(candidates) == 0 {
		// Distinguish "nobody offered" from "nobody qualified" -- the CLI shows
		// the reason, and they are different problems to fix.
		if len(records) == 0 {
			return WorkerRecord{}, ErrEmptyCandidate
		}
		return WorkerRecord{}, ErrNoWorkerMatched
	}
	// Stable order first, so the same seed picks the same worker regardless of
	// DHT iteration order.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].NodeID < candidates[j].NodeID })
	idx := int(rand() % uint64(len(candidates)))
	return candidates[idx], nil
}

// RandUint64 draws a uniform uint64 from crypto/rand. It is the production
// source for PickRandom.
func RandUint64() uint64 {
	var b [8]byte
	// crypto/rand.Read never returns a short read without an error; if it does
	// fail, a zero pick is still a valid (if not uniform) choice rather than a
	// crash in a deploy path.
	_, _ = randRead(b[:])
	return binary.BigEndian.Uint64(b[:])
}
