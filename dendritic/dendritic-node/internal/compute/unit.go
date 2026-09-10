package compute

// M4 — the work-unit format.
//
// ONE FORMAT FOR CPU AND GPU, DELIBERATELY
// ----------------------------------------
// A unit declares the capability it NEEDS (`cpu`, `gpu:cuda`, `gpu:rocm`) and
// is otherwise identical either way. Forking the format per device class would
// mean two schedulers, two verifiers and two sets of bugs, for a difference
// that is one string.
//
// THE THREE PROPERTIES, AND WHY THEY ARE HERE RATHER THAN LATER
// -------------------------------------------------------------
// 1. INDEPENDENTLY VERIFIABLE. A unit carries everything needed to check it —
//    the runtime image digest, the input digests, the seed. A verifier fetches
//    the unit and nothing else. If verification needed side information from
//    the submitter, the submitter could withhold it and no result could ever be
//    disputed.
//
// 2. CHECKPOINTABLE. A four-hour render lost at 90% is lost entirely, and a
//    format that did not anticipate checkpoints cannot be given them
//    afterwards: the format IS the decision. So a unit declares its checkpoint
//    interval and a result may carry resumable state, even for work that will
//    never use it.
//
// 3. IDEMPOTENT. Redistribution after a false failure must not double-count.
//    A slow node is indistinguishable from a dead one, so the scheduler WILL
//    hand the same unit to somebody else while the first is still working, and
//    both will return. Identity is therefore the unit's content digest, not an
//    assignment id — two executions of the same unit are the same fact, and
//    recording it twice is the bug this prevents.
//
// Everything is content-addressed: units, inputs and results are blobs
// identified by digest, which the store and internal/place already handle. That
// is not tidiness. It is what lets a verifier fetch exactly what the worker saw
// and be certain of it, and what makes a result's identity independent of who
// produced it.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Unit is one piece of work. Immutable once created: its digest is its
// identity, so any change makes it a different unit rather than a new version
// of this one.
type Unit struct {
	// Runtime identifies the signed catalogue image. NOT submitter-supplied —
	// the submitter chooses a workload NAME from the closed table and the node
	// fills this in. That single fact is the difference between running
	// operator-chosen code on attacker-chosen data and running attacker-chosen
	// code in a sandbox, and nearly every sandbox escape starts from the latter.
	//
	// TWO PINNING MODELS LIVE IN THIS FIELD, AND THEY DISAGREE
	// --------------------------------------------------------
	// Validate accepts either of two shapes, and it is worth being honest about
	// why there are two:
	//
	//  1. A CONTENT DIGEST — bare 64-hex, or "sha256:<64hex>". Self-describing:
	//     a verifier fetching the unit knows exactly which bytes ran, and two
	//     nodes cannot resolve it to different code. This is what the format was
	//     designed for.
	//
	//  2. A CATALOGUE REFERENCE — the exact pinned reference of a workload in
	//     catalogue.go, e.g. "registry.local/compute-embed:latest". This is a
	//     TAG, and a tag is mutable. Two nodes that pulled it a week apart can be
	//     running different code while agreeing about the unit's digest, and M5
	//     would score their honest disagreement as a fault.
	//
	// The second is admitted because the catalogue images are built and tagged
	// locally (compute-images/build.sh) and no digest exists to pin until they
	// are. It is narrow on purpose: only strings that appear verbatim in the
	// catalogue table pass, so "ubuntu:latest" is refused exactly as before —
	// what is relaxed is which OPERATOR-CHOSEN images may be named, never
	// whether a submitter may name one.
	//
	// WHAT WOULD CLOSE THE GAP: have build.sh record each image's repo digest
	// and store "sha256:<hex>" in Workloads[...].Image. Validate needs no change
	// for that — the digest branch already accepts it — and the mutable-tag hole
	// closes the day the catalogue carries digests. Until then a node runs
	// whatever its own registry holds under that tag, which is a trust
	// assumption about the operator's machine rather than about the submitter.
	Runtime string `json:"runtime"`

	// Inputs are blob digests, fetched BY THE NODE before the container starts.
	// The container has no network, so it cannot fetch them itself — which is
	// the point, and why these are digests rather than URLs.
	Inputs []string `json:"inputs,omitempty"`

	// Params are the knobs the runtime exposes. Values only: no command, no
	// entrypoint, no environment the image did not declare. A param that could
	// name an executable would reintroduce the arbitrary-payload problem the
	// catalogue exists to solve.
	Params map[string]string `json:"params,omitempty"`

	// Needs is the capability required — "cpu", "gpu:cuda", "gpu:rocm",
	// "gpu:vulkan". A scheduler matches this against what a node advertises.
	Needs string `json:"needs"`

	// MinCores and MinRAMBytes are sizing, not entitlement: a node grants what
	// its own policy allows (M3) and refuses the unit if that is less.
	MinCores    int   `json:"min_cores,omitempty"`
	MinRAMBytes int64 `json:"min_ram_bytes,omitempty"`

	// Seed makes a unit's randomness reproducible. A runtime that draws from
	// the system RNG cannot be verified by re-execution, so seeded randomness
	// is the only kind a deterministic unit may use.
	Seed int64 `json:"seed"`

	// CheckpointSeconds asks the runtime to emit resumable state at this
	// interval. 0 means the unit is short enough not to bother — but the field
	// exists on every unit, because retrofitting it later would change the
	// digest of every unit ever issued.
	CheckpointSeconds int `json:"checkpoint_seconds,omitempty"`

	// RefSeconds is how long this unit takes on a reference machine
	// (ReferenceOpsPerSecond). The scheduler scales it by a node's MEASURED
	// throughput to predict completion, which is what makes deadline-aware
	// placement possible: a slow reliable node is right for a loose deadline
	// and wrong for a tight one, and that is the same node either way.
	//
	// Quoted against a fixed constant rather than the network average, because
	// an average moves as nodes join — a unit's declared cost would drift after
	// it was issued, and two schedulers would estimate differently.
	RefSeconds int `json:"ref_seconds,omitempty"`

	// DeadlineSeconds is a hard ceiling. A unit without one can occupy a
	// volunteer's machine forever, which is a promise this network cannot make.
	DeadlineSeconds int `json:"deadline_seconds"`

	// Class is what this work IS — media, index, train, infer, science. Nodes
	// accept classes rather than all-or-nothing (roadmap threat 4: legal code,
	// toxic purpose), and it is what "what has my machine been doing" answers
	// with.
	Class string `json:"class"`

	// Deterministic declares that two correct executions produce identical
	// bytes. True for CPU work, false for most GPU work, and it decides which
	// verification method applies — so it is part of the unit rather than
	// guessed by the verifier.
	Deterministic bool `json:"deterministic"`
}

// UnitResult is what a worker returns. Named apart from Result, which is the
// benchmark's, because confusing a measurement with a work product would be an
// easy and expensive mistake to make in a payment path.
type UnitResult struct {
	// Unit is the digest of the unit this answers. The link is by content, so
	// a result cannot be re-attributed to a different unit.
	Unit string `json:"unit"`

	// Output is the digest of the result blob. The bytes go to the store; this
	// is what gets compared, signed and paid on.
	Output string `json:"output"`

	// Checkpoint, when present, is resumable state — a partial result that
	// another node can continue from rather than restart.
	Checkpoint string `json:"checkpoint,omitempty"`

	// Progress is 0-100 for a checkpoint; 100 for a finished unit.
	Progress int `json:"progress"`

	// Node and RanSeconds are for scheduling and payment, NOT for verification.
	// Two honest nodes disagree about how long the work took; they cannot
	// disagree about what the answer was.
	Node       string `json:"node,omitempty"`
	RanSeconds int    `json:"ran_seconds,omitempty"`

	// Failed and Error report a unit that could not be completed. A failure is
	// a legitimate result: hiding it as a timeout costs the scheduler the
	// chance to stop reissuing work that cannot succeed anywhere.
	Failed bool   `json:"failed,omitempty"`
	Error  string `json:"error,omitempty"`
}

var (
	ErrNoRuntime  = errors.New("compute: unit names no runtime image")
	ErrNoClass    = errors.New("compute: unit declares no job class")
	ErrNoDeadline = errors.New("compute: unit has no deadline")
	ErrBadNeeds   = errors.New("compute: unit requires an unknown capability")
)

// knownNeeds is the closed set a unit may require. Closed on purpose: an
// unrecognised requirement must be a validation error rather than something a
// scheduler silently fails to match, which would leave the unit queued forever
// with no explanation.
var knownNeeds = map[string]bool{
	"cpu": true, "gpu": true,
	"gpu:cuda": true, "gpu:rocm": true, "gpu:vulkan": true, "gpu:opencl": true,
}

// Validate rejects a unit that cannot be run or cannot be checked.
//
// Called before a unit is published rather than when a worker picks it up. A
// malformed unit that reaches a worker has already cost a scheduling round trip
// and will fail identically on every node it is offered to.
func (u Unit) Validate() error {
	if strings.TrimSpace(u.Runtime) == "" {
		return ErrNoRuntime
	}
	if strings.TrimSpace(u.Class) == "" {
		// Not cosmetic: it is what a node's operator filters on and what the
		// "what did my machine run" history is written from.
		return ErrNoClass
	}
	if u.DeadlineSeconds <= 0 {
		return ErrNoDeadline
	}
	if !knownNeeds[u.Needs] {
		return fmt.Errorf("%w: %q", ErrBadNeeds, u.Needs)
	}
	// Runtime and Inputs are checked SEPARATELY, and only Runtime is relaxed.
	// Inputs are blobs the node fetches from the store, which is content
	// addressed and has nothing to resolve a name against — a non-digest input
	// is unfetchable rather than merely imprecise.
	if !looksLikeRuntimeRef(u.Runtime) {
		return fmt.Errorf("compute: %q is neither a content digest nor a catalogue image", u.Runtime)
	}
	for _, digest := range u.Inputs {
		if !looksLikeDigest(digest) {
			return fmt.Errorf("compute: %q is not a content digest", digest)
		}
	}
	return nil
}

// looksLikeRuntimeRef implements the two pinning models documented on
// Unit.Runtime: a content digest (bare or sha256-prefixed), or the verbatim
// pinned reference of a workload in the closed catalogue table.
//
// The catalogue branch is membership, not pattern matching. A regex for
// "looks like a registry reference" would accept every image on the volunteer's
// machine, which is the whole thing the digest rule was there to prevent.
func looksLikeRuntimeRef(s string) bool {
	if looksLikeDigest(s) {
		return true
	}
	if rest, found := strings.CutPrefix(s, "sha256:"); found {
		return looksLikeDigest(rest)
	}
	return IsCatalogueRuntime(s)
}

func looksLikeDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Digest is the unit's identity: the hash of its canonical encoding.
//
// This is what makes redistribution idempotent. A slow node is
// indistinguishable from a dead one, so the scheduler WILL hand the same unit
// to a second worker while the first is still going, and both will return. If
// identity were an assignment id those would be two facts; by content they are
// one, recorded once and paid once.
func (u Unit) Digest() string {
	body, err := canonicalJSON(u)
	if err != nil {
		// Unit contains only strings, ints, bools and a string map — none of
		// which can fail to marshal. A panic here would mean the type changed
		// under this function.
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// canonicalJSON encodes with map keys sorted, so two structurally identical
// units hash the same.
//
// Go's encoding/json already sorts map keys, which makes this look redundant.
// It is written explicitly anyway because the digest is a consensus value: if
// that behaviour ever changed, every node would silently disagree about unit
// identity, and "the standard library used to sort these" is not a bug anyone
// would find quickly.
func canonicalJSON(u Unit) ([]byte, error) {
	type alias Unit // no methods, so no custom marshaller can interfere
	if u.Params != nil {
		keys := make([]string, 0, len(u.Params))
		for k := range u.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(map[string]string, len(keys))
		for _, k := range keys {
			ordered[k] = u.Params[k]
		}
		u.Params = ordered
	}
	return json.Marshal(alias(u))
}

// FitsOn reports whether a unit can run on a node with this profile and grant.
//
// Both are consulted because they answer different questions. The profile is
// what the machine CAN do; the grant is what its owner is lending right now
// (M3). A unit needing eight cores does not fit a machine that has sixteen and
// is offering two, and taking it anyway is how a node misses a deadline it
// accepted.
func (u Unit) FitsOn(profile Profile, grant Grant, policy Policy) (bool, string) {
	if !grant.Allowed() {
		return false, grant.Reason
	}
	if !policy.AcceptsClass(u.Class) {
		return false, "this node does not accept " + u.Class + " work"
	}
	if u.MinCores > grant.Cores {
		return false, fmt.Sprintf("needs %d cores, %d on offer", u.MinCores, grant.Cores)
	}
	if u.MinRAMBytes > 0 && profile.CPU.RAMBytes > 0 && u.MinRAMBytes > profile.CPU.RAMBytes {
		return false, "not enough memory"
	}
	if strings.HasPrefix(u.Needs, "gpu") {
		api := strings.TrimPrefix(strings.TrimPrefix(u.Needs, "gpu"), ":")
		for _, gpu := range profile.GPU {
			if !gpu.DriverOK {
				continue
			}
			if api == "" {
				return true, ""
			}
			for _, have := range gpu.APIs {
				if have == api {
					return true, ""
				}
			}
		}
		return false, "no usable GPU for " + u.Needs
	}
	return true, ""
}

// Deadline is when a unit issued now must be abandoned.
func (u Unit) Deadline(start time.Time) time.Time {
	return start.Add(time.Duration(u.DeadlineSeconds) * time.Second)
}
