// Package dcs implements the Distributed Container Service: optional,
// off-by-default container hosting between peers over I2P. See DCS.md.
//
// This file is the containment for LAB workloads -- deliberately vulnerable
// hosts (Attack Range and similar) run for academic and security-research
// purposes.
//
// # THE SECURITY MODEL, PLAINLY
//
// A vulnerable host is only safe to run on someone else's hardware if nobody
// can reach it except the one researcher who asked for it. That is achieved
// with the I2P destination itself rather than with a firewall:
//
//   - Every container gets its OWN I2P destination, generated at launch from a
//     fresh key the agent stores under the container's private state.
//   - A destination is 52 characters of base32 over a 256-bit hash. It cannot
//     be guessed, scanned for, or enumerated -- I2P has no address-space sweep
//     the way IPv4 does.
//   - For a lab container that destination is NEVER PUBLISHED. Not in the
//     worker's capability record, not in a service record, not in the DHT, not
//     in the gateway, not in any log line that leaves the host.
//   - It is returned exactly once, over the signed and encrypted RPC, to the
//     owner who deployed it.
//
// So the destination IS the capability. Knowing it is the entire access
// control mechanism, which is why DisclosureLog exists: the agent records every
// party the address was ever revealed to, so "only one other person knows" is
// an auditable claim rather than an assumption.
//
// Everything else here exists because that one property is not sufficient on
// its own: an unreachable-but-outbound-capable vulnerable box is still a launch
// platform, and a forgotten one is still a liability.
package dcs

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// LabContainment is the set of rules the agent applies to a lab workload.
// These are refusals, not preferences: no grant, permission, owner, or config
// flag can turn any of them off. A worker that would relax them is handing a
// stranger an exploitable service on its own machine.
type LabContainment struct {
	// PublishDestination is always false. Stated as a field rather than
	// implied so a future edit that tries to set it true fails a test.
	PublishDestination bool
	// AllowClearnetEgress is always false. A vulnerable box that can reach the
	// internet is a launch platform for whoever exploits it.
	AllowClearnetEgress bool
	// AllowGatewayPublish is always false. The gateway is the one place that
	// deliberately makes a service reachable by the whole world.
	AllowGatewayPublish bool
	// AllowInboundFromNetwork is always false: the destination is disclosed to
	// the owner, and only the owner may dial it.
	AllowInboundFromNetwork bool
	// MaxRuntime is a hard ceiling enforced by the agent regardless of what
	// the deployer requested.
	MaxRuntime time.Duration
}

// DefaultLabMaxRuntime bounds how long a vulnerable container may exist.
const DefaultLabMaxRuntime = 4 * time.Hour

// LabContainmentFor returns the containment for a lab workload. There is
// deliberately no variant that returns anything weaker.
func LabContainmentFor(maxRuntime time.Duration) LabContainment {
	if maxRuntime <= 0 || maxRuntime > DefaultLabMaxRuntime {
		maxRuntime = DefaultLabMaxRuntime
	}
	return LabContainment{
		PublishDestination:      false,
		AllowClearnetEgress:     false,
		AllowGatewayPublish:     false,
		AllowInboundFromNetwork: false,
		MaxRuntime:              maxRuntime,
	}
}

// Errors a caller can test for.
var (
	ErrLabNotEnabled      = errors.New("dcs: this worker does not accept lab workloads")
	ErrLabPublishRefused  = errors.New("dcs: a lab container's destination is never published")
	ErrLabEgressRefused   = errors.New("dcs: lab containers are denied clearnet egress unconditionally")
	ErrLabGatewayRefused  = errors.New("dcs: lab containers are never published through the gateway")
	ErrLabNoOwner         = errors.New("dcs: a lab deployment must name exactly one owner")
	ErrPrivilegedRefused  = errors.New("dcs: privileged execution is refused for every workload")
	ErrDestinationUnknown = errors.New("dcs: container has no destination yet")
)

// Deployment is the subset of a deployment spec these rules care about.
type Deployment struct {
	ID    string
	Owner string // node ID of the deployer; for a lab workload, the sole party
	Image string
	Lab   bool

	RequestedRuntime time.Duration
	// RequestPublish / RequestEgress / RequestGateway are what the DEPLOYER
	// asked for. For a lab workload they are recorded and then refused, so the
	// audit log shows what was attempted.
	RequestPublish bool
	RequestEgress  bool
	RequestGateway bool
	Privileged     bool
}

// Disclosure records one revelation of a container's destination.
type Disclosure struct {
	To     string // node ID told
	When   time.Time
	Reason string
}

// ContainerAddress is a container's I2P identity plus who has been told it.
//
// The zero value is deliberately useless: a destination must be set explicitly
// by the launcher after the SAM session exists.
type ContainerAddress struct {
	ContainerID string
	Destination string // <52 chars>.b32.i2p
	Private     bool   // true for lab: never published anywhere

	disclosures []Disclosure
}

// Disclose records that the destination was revealed to a node, and returns
// the destination. For a private address this is the ONLY way the address
// legitimately leaves the agent.
func (a *ContainerAddress) Disclose(to, reason string, at time.Time) (string, error) {
	if a.Destination == "" {
		return "", ErrDestinationUnknown
	}
	a.disclosures = append(a.disclosures, Disclosure{To: to, When: at, Reason: reason})
	return a.Destination, nil
}

// Disclosures returns everyone the address was revealed to. For a lab
// container this is the evidence for "only one other person knows about it";
// if it ever holds more than the owner, that is a finding, not a detail.
func (a *ContainerAddress) Disclosures() []Disclosure {
	out := make([]Disclosure, len(a.disclosures))
	copy(out, a.disclosures)
	return out
}

// DisclosedTo reports the distinct set of node IDs told the address.
func (a *ContainerAddress) DisclosedTo() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, d := range a.disclosures {
		if _, dup := seen[d.To]; dup {
			continue
		}
		seen[d.To] = struct{}{}
		out = append(out, d.To)
	}
	return out
}

// AdmitLab decides whether this worker may run a lab deployment at all, and
// with what containment. Every refusal names the rule so the deployer gets a
// reason rather than a bare failure.
func AdmitLab(dep Deployment, workerAcceptsLab bool, ceiling time.Duration) (LabContainment, error) {
	var zero LabContainment
	if !dep.Lab {
		return zero, fmt.Errorf("dcs: AdmitLab called for a non-lab deployment %q", dep.ID)
	}
	// The worker's own operator decides. No grant from a deployer can create
	// this consent.
	if !workerAcceptsLab {
		return zero, ErrLabNotEnabled
	}
	if strings.TrimSpace(dep.Owner) == "" {
		return zero, ErrLabNoOwner
	}
	if dep.Privileged {
		return zero, ErrPrivilegedRefused
	}
	// These three are refusals rather than silent downgrades: a researcher who
	// asked for a public vulnerable box has misunderstood something, and should
	// be told so instead of quietly getting a private one.
	if dep.RequestPublish {
		return zero, ErrLabPublishRefused
	}
	if dep.RequestEgress {
		return zero, ErrLabEgressRefused
	}
	if dep.RequestGateway {
		return zero, ErrLabGatewayRefused
	}
	if ceiling <= 0 || ceiling > DefaultLabMaxRuntime {
		ceiling = DefaultLabMaxRuntime
	}
	runtime := dep.RequestedRuntime
	if runtime <= 0 || runtime > ceiling {
		runtime = ceiling
	}
	return LabContainmentFor(runtime), nil
}

// AudienceFor returns the node IDs allowed to learn a container's destination.
// For a lab workload that is exactly one: the owner. This is the function that
// enforces "only one other person knows about it".
func AudienceFor(dep Deployment) []string {
	if dep.Lab {
		return []string{dep.Owner}
	}
	// Non-lab containers may be advertised in a service record, so their
	// audience is open. Callers must still respect the deployment's own
	// visibility setting.
	return nil
}

// ExpiresAt is when the agent destroys the container regardless of owner state.
func (c LabContainment) ExpiresAt(start time.Time) time.Time {
	return start.Add(c.MaxRuntime)
}
