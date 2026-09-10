package directive

import "strings"

// Working out whether THIS node is the origin the network is pointed at.
//
// After an emergency, a gateway may have been promoted to serve as the origin.
// When the operator later names a permanent server, that node has to step back
// down — and nothing tells it to. It has to notice, from the same directive
// everyone else is reading, that the origin is now somebody else.
//
// A node that fails to notice keeps running as an origin nobody is pointed at:
// it holds an origin's configuration and, if it was promoted with one, an
// origin's signing key. A machine that can sign as the site, still running,
// with nobody watching it, is the thing to avoid here.

// Role is what a directive says this node should be doing.
type Role string

const (
	// RoleOrigin — the directive names this node.
	RoleOrigin Role = "origin"
	// RoleGateway — the directive names somebody else, so this node is
	// transport and nothing more.
	RoleGateway Role = "gateway"
	// RoleUnknown — nothing is pinned, or the directive does not identify an
	// origin at all. Deliberately NOT the same as gateway: a node that has
	// never seen a directive must not conclude it has been demoted.
	RoleUnknown Role = "unknown"
)

// Identity is how a node recognises itself in a directive.
type Identity struct {
	// Hostname this node serves under, if any.
	Hostname string
	// Addresses this node listens on, as host:port or bare host.
	Addresses []string
}

// RoleFor reports what `held` says this node should be.
//
// Matching is on the origin ADDRESS first and the domain second. The address is
// the stronger signal: several nodes can legitimately answer for one domain
// during a move — the old origin, the new one, and whatever DNS still points at
// — and a node deciding it is the origin because it recognises the domain would
// have two of them both believing it.
func RoleFor(held *Directive, self Identity) Role {
	if held == nil || held.Kind != KindMove {
		return RoleUnknown
	}
	if held.OriginAddress == "" && held.OriginDomain == "" {
		return RoleUnknown
	}

	if held.OriginAddress != "" {
		if matchesAddress(self, held.OriginAddress) {
			return RoleOrigin
		}
		// An address was named and it is not this node. That is conclusive:
		// whoever is at that address is the origin and this node is not,
		// whatever domain it happens to answer for.
		return RoleGateway
	}

	if held.OriginDomain != "" && strings.EqualFold(
		strings.TrimSpace(self.Hostname), held.OriginDomain) {
		return RoleOrigin
	}
	return RoleGateway
}

func matchesAddress(self Identity, address string) bool {
	want := strings.ToLower(strings.TrimSpace(address))
	if want == "" {
		return false
	}
	wantHost := hostPart(want)
	for _, candidate := range self.Addresses {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == "" {
			continue
		}
		if candidate == want {
			return true
		}
		// Host-only comparison as well: a node knows its address as
		// "203.0.113.9" while the directive names "203.0.113.9:443", and
		// failing to match those would leave the real origin demoting itself.
		if hostPart(candidate) == wantHost && wantHost != "" {
			return true
		}
	}
	return false
}

func hostPart(value string) string {
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.Index(value, "]"); end > 0 {
			return value[1:end]
		}
		return value
	}
	// Only split on the last colon when there is exactly one, so a bare IPv6
	// address is not mangled into its own prefix.
	if strings.Count(value, ":") == 1 {
		return value[:strings.Index(value, ":")]
	}
	return value
}

// Demotion describes a node stepping back from origin to gateway.
type Demotion struct {
	Was      Role
	Now      Role
	Sequence uint64
	// Why is written for a person reading a log during a handover.
	Why string
}

// CheckDemotion compares the role a node was running as against the role the
// newly adopted directive gives it.
//
// Returns nil when nothing changed. A promotion (gateway -> origin) is NOT
// reported here: standing a node up as an origin needs a human with a
// passphrase, so a node must never conclude from a directive alone that it has
// become one. Only the step DOWN is automatic, because the step down is the
// safe direction.
func CheckDemotion(was Role, held *Directive, self Identity) *Demotion {
	now := RoleFor(held, self)
	if was != RoleOrigin || now != RoleGateway {
		return nil
	}
	return &Demotion{
		Was: was, Now: now, Sequence: held.Sequence,
		Why: "directive sequence " + itoa(held.Sequence) + " names " +
			describeOrigin(held) + " as the origin, which is not this node. " +
			"Stepping down to gateway: this machine holds an origin's " +
			"configuration and may hold an origin's signing key, and leaving " +
			"it running as one that nothing points at is how a machine that " +
			"can sign as the site keeps going unwatched.",
	}
}

func describeOrigin(held *Directive) string {
	if held.OriginAddress != "" {
		return held.OriginAddress
	}
	if held.OriginDomain != "" {
		return held.OriginDomain
	}
	return "another node"
}

func itoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
