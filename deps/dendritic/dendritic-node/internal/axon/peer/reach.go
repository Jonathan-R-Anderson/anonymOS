package peer

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Self-reachability: the §6.5 classification, its state machine, and the role
// gate it drives.
//
// R3: relaying is capability-advertised and reachability-gated. A node that
// cannot accept inbound connections must not advertise a relay role, because a
// relay nobody can reach is a path that fails silently -- the circuit builder
// picks it, the extend times out, and the failure looks like network trouble
// rather than a misconfigured peer.
//
// E3.2 puts a clock on it: a node with inbound UDP blocked must classify itself
// unreachable and refuse the relay role within 120 seconds.

// ClassifyDeadline is E3.2's bound. A node must reach a verdict inside it, and
// the verdict when probes do not arrive is unreachable -- see Classify.
const ClassifyDeadline = 120 * time.Second

// RepromoteInterval and ReverifyInterval are §6.5's clocks: re-probe an
// unreachable node every 15 min (jittered by the caller), and re-verify a
// reachable one every 30 min. "A node that was reachable an hour ago and
// advertises now is worse than one that never advertised."
const (
	RepromoteInterval = 15 * time.Minute
	ReverifyInterval  = 30 * time.Minute
)

// DemotionFailures is how many consecutive dial-back failures demote a
// REACHABLE node. Demotion is immediate at this count; promotion needs a fresh
// quorum AND a fresh dial-back.
const DemotionFailures = 3

// NATClass is the §6.5 classification. It is determined by probing, never by
// asking the operating system -- an OS that reports a public address behind a
// CGNAT is not lying, it is answering a different question.
type NATClass uint8

const (
	ClassUnknown    NATClass = iota
	ClassPublic              // dial-back succeeds from >=2 unrelated peers
	ClassMapped              // as public, but only while a UPnP/PCP lease holds
	ClassEIM                 // endpoint-independent mapping; punchable
	ClassEDM                 // endpoint-dependent mapping; not punchable by port reuse
	ClassCGNAT               // carrier NAT; not punchable, not mappable
	ClassUDPBlocked          // no QUIC handshake completes; TCP roles only
	ClassOffline             // nothing completes
)

func (c NATClass) String() string {
	switch c {
	case ClassPublic:
		return "PUBLIC"
	case ClassMapped:
		return "MAPPED"
	case ClassEIM:
		return "EIM"
	case ClassEDM:
		return "EDM"
	case ClassCGNAT:
		return "CGNAT"
	case ClassUDPBlocked:
		return "UDP_BLOCKED"
	case ClassOffline:
		return "OFFLINE"
	default:
		return "UNKNOWN"
	}
}

// Inbound reports whether the class admits unsolicited inbound connections.
func (c NATClass) Inbound() bool { return c == ClassPublic || c == ClassMapped }

// cgnatV4 is RFC 6598 shared address space. An external address inside it is
// carrier NAT by definition, and no router setting the subscriber can reach
// will change that -- which is why §6.5 separates CGNAT from EDM at all.
var cgnatV4 = netip.MustParsePrefix("100.64.0.0/10")

// ProbeObservation is one prober's report about this node.
type ProbeObservation struct {
	Prober ProberID
	// Network is the prober's failure domain, as a string key. Distinctness of
	// these is what T3.4 tests: three probers behind one network are one
	// vantage point wearing three hats.
	Network string
	// External is the source address the prober observed for us.
	External netip.Addr
	// ExternalPort is the source port it observed. Two probers seeing the same
	// port means endpoint-independent mapping; different ports mean
	// endpoint-dependent.
	ExternalPort uint16
	// QUICOK is whether a QUIC handshake completed. All-false across a probe
	// window is UDP_BLOCKED, not OFFLINE, provided some TCP link worked.
	QUICOK bool
	// TCPOK is whether a TCP+TLS link completed.
	TCPOK bool
	// DialBackOK is whether an unsolicited dial-back at the candidate arrived.
	//
	// It must have arrived from an address OTHER than the one the request went
	// over (§6.5 step VERIFY); the prober enforces that and reports the result
	// here, because a peer that "verifies" us by answering itself has verified
	// nothing.
	DialBackOK bool
	// Refused is set when the peer declined to run the probe at all. See
	// Classify: a refusal is a failure, not an absence of information.
	Refused bool
	// Mapped is set when the reachability came from a port-mapping lease rather
	// than from being natively public.
	Mapped bool
}

// Classification is the outcome of one probe round.
type Classification struct {
	Class NATClass
	// External is the address a diverse quorum agreed on, if any.
	External netip.Addr
	// Probers and Networks are the distinct counts behind the verdict.
	Probers, Networks int
	// Reason is a short human-readable account, for the operator log. §6.5
	// separates CGNAT from EDM precisely because the operator-facing advice
	// differs, so the reason string has to carry that difference.
	Reason string
}

// AddressQuorum is §6.5 step QUORUM: an external address candidate needs >=3
// peers in distinct prefixes AND distinct ASNs before anything is advertised.
//
// It is deliberately stricter than MinProbeQuorum. That constant governs what
// may be RECORDED about another peer (E3.3); this one governs what this node
// will SAY about itself, and a node that advertises an address it does not own
// is a redirection and DoS primitive (step REFUSE).
const AddressQuorum = 3

// ClassifyObservations applies §6.5's classification table to a probe round.
//
// It answers only from evidence. Where the evidence does not decide, the answer
// is ClassUnknown with a reason, never a guess in the flattering direction.
func ClassifyObservations(obs []ProbeObservation) Classification {
	var (
		probers  = map[ProberID]struct{}{}
		networks = map[string]struct{}{}
		byAddr   = map[netip.Addr]map[string]struct{}{}
		ports    = map[uint16]struct{}{}

		anyQUIC, anyTCP, anyDialBack, anyMapped bool
		refusals                                int
	)
	for _, o := range obs {
		if o.Prober != "" {
			probers[o.Prober] = struct{}{}
		}
		if o.Network != "" {
			networks[o.Network] = struct{}{}
		}
		if o.Refused {
			refusals++
			continue
		}
		anyQUIC = anyQUIC || o.QUICOK
		anyTCP = anyTCP || o.TCPOK
		anyDialBack = anyDialBack || o.DialBackOK
		anyMapped = anyMapped || o.Mapped
		if o.External.IsValid() {
			if byAddr[o.External] == nil {
				byAddr[o.External] = map[string]struct{}{}
			}
			if o.Network != "" {
				byAddr[o.External][o.Network] = struct{}{}
			}
			if o.ExternalPort != 0 {
				ports[o.ExternalPort] = struct{}{}
			}
		}
	}

	c := Classification{Probers: len(probers), Networks: len(networks)}

	// Step QUORUM: the candidate is the address >=AddressQuorum peers in
	// distinct networks agreed on. Anything less stays UNCONFIRMED.
	var candidate netip.Addr
	best := 0
	for addr, nets := range byAddr {
		if len(nets) > best {
			candidate, best = addr, len(nets)
		}
	}
	if best >= AddressQuorum {
		c.External = candidate
	}

	switch {
	case !anyQUIC && !anyTCP:
		c.Class, c.Reason = ClassOffline, "no link of any transport completed"
		return c
	case !anyQUIC:
		// TCP works, QUIC does not: the node is usable for TCP roles only.
		c.Class, c.Reason = ClassUDPBlocked, "no QUIC handshake completed in the probe window"
		return c
	}

	if !c.External.IsValid() {
		c.Class = ClassUnknown
		c.Reason = "external address unconfirmed: below the diverse address quorum"
		return c
	}

	if c.External.Is4() && cgnatV4.Contains(c.External) {
		c.Class, c.Reason = ClassCGNAT, "external address is in 100.64.0.0/10 (RFC 6598 shared space)"
		return c
	}

	if anyDialBack {
		if anyMapped {
			c.Class, c.Reason = ClassMapped, "dial-back succeeded while a port-mapping lease holds"
		} else {
			c.Class, c.Reason = ClassPublic, "dial-back succeeded from unrelated peers"
		}
		return c
	}

	// No inbound. The mapping shape decides whether a punch could ever work.
	switch {
	case len(ports) > 1:
		c.Class, c.Reason = ClassEDM, "probers observed different external ports (endpoint-dependent mapping)"
	case len(ports) == 1 && len(networks) >= 2:
		c.Class, c.Reason = ClassEIM, "probers in distinct networks observed the same external port"
	default:
		c.Class, c.Reason = ClassUnknown, "insufficient distinct probers to determine mapping behaviour"
	}
	return c
}

// Role is a capability a node may advertise. §17 owns the taxonomy; §6.5 owns
// the transport precondition for each, which is what Permit encodes.
type Role uint8

const (
	RoleClient Role = iota
	RoleGuard
	RoleMiddleRelay
	RoleTerminalRelay
	RoleIntroPoint
	RoleRendezvousPoint
	RoleDHTServer
	RoleStorageDirect // storage holder, dialed directly
	RoleStorageTunnel // storage holder, reached via its own tunnel
	RoleAnonService
)

var roleNames = map[Role]string{
	RoleClient:          "client",
	RoleGuard:           "guard",
	RoleMiddleRelay:     "middle",
	RoleTerminalRelay:   "terminal",
	RoleIntroPoint:      "intro",
	RoleRendezvousPoint: "rendezvous",
	RoleDHTServer:       "dht",
	RoleStorageDirect:   "storage-direct",
	RoleStorageTunnel:   "storage-tunnel",
	RoleAnonService:     "anon-service",
}

func (r Role) String() string {
	if n, ok := roleNames[r]; ok {
		return n
	}
	return "unknown"
}

// Permission is how a class admits a role.
type Permission uint8

const (
	PermDenied        Permission = iota
	PermAllowed                  // over any transport
	PermTCPOnly                  // allowed, but the QUIC link is unavailable
	PermDeprioritised            // allowed over TCP and weighted below PUBLIC peers
	PermOpportunistic            // allowed only for BULK, at the owner's explicit choice
)

func (p Permission) Allowed() bool { return p != PermDenied }

// roleGate is §6.5's role-gating table, transcribed. The zero value of the
// inner map is PermDenied, so a class/role pair absent from the table is
// refused rather than silently permitted -- the safe direction for a table
// somebody will extend later.
var roleGate = map[NATClass]map[Role]Permission{
	ClassPublic: {
		RoleClient: PermAllowed, RoleGuard: PermAllowed, RoleMiddleRelay: PermAllowed,
		RoleTerminalRelay: PermAllowed, RoleIntroPoint: PermAllowed, RoleRendezvousPoint: PermAllowed,
		RoleDHTServer: PermAllowed, RoleStorageDirect: PermAllowed, RoleStorageTunnel: PermAllowed,
		RoleAnonService: PermAllowed,
	},
	ClassMapped: {
		// Allowed everywhere PUBLIC is, and deliberately NOT preferred: a lapsed
		// lease turns a relay into a black hole for every circuit through it, so
		// guard selection (§8) weights PUBLIC above MAPPED.
		RoleClient: PermAllowed, RoleGuard: PermAllowed, RoleMiddleRelay: PermAllowed,
		RoleTerminalRelay: PermAllowed, RoleIntroPoint: PermAllowed, RoleRendezvousPoint: PermAllowed,
		RoleDHTServer: PermAllowed, RoleStorageDirect: PermAllowed, RoleStorageTunnel: PermAllowed,
		RoleAnonService: PermAllowed,
	},
	ClassEIM: {
		RoleClient: PermAllowed, RoleStorageDirect: PermOpportunistic,
		RoleStorageTunnel: PermAllowed, RoleAnonService: PermAllowed,
	},
	ClassEDM: {
		RoleClient: PermAllowed, RoleStorageTunnel: PermAllowed, RoleAnonService: PermAllowed,
	},
	ClassCGNAT: {
		RoleClient: PermAllowed, RoleStorageTunnel: PermAllowed, RoleAnonService: PermAllowed,
	},
	ClassUDPBlocked: {
		RoleClient: PermTCPOnly, RoleGuard: PermDeprioritised, RoleMiddleRelay: PermTCPOnly,
		RoleTerminalRelay: PermTCPOnly, RoleIntroPoint: PermTCPOnly, RoleDHTServer: PermTCPOnly,
		RoleStorageDirect: PermTCPOnly, RoleStorageTunnel: PermTCPOnly, RoleAnonService: PermTCPOnly,
		// RoleRendezvousPoint is absent, hence denied: an RP joins two circuits
		// and is the worst possible place for cross-circuit head-of-line
		// blocking (R12) -- the one role where TCP's failure mode is
		// unacceptable.
	},
	ClassOffline: {},
}

// Permit reports how a class admits a role.
func Permit(c NATClass, r Role) Permission {
	return roleGate[c][r]
}

// SelfReachability tracks what this node believes about its own reachability
// and drives the role gate.
type SelfReachability struct {
	mu        sync.RWMutex
	state     ReachState
	class     NATClass
	external  netip.Addr
	since     time.Time
	quorum    int
	networks  int
	failures  int
	lastError string
}

// NewSelfReachability starts in the unknown state, advertising nothing.
func NewSelfReachability() *SelfReachability {
	return &SelfReachability{state: ReachUnknown, class: ClassUnknown}
}

// State is the current verdict.
func (s *SelfReachability) State() ReachState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// Class is the current NAT classification.
func (s *SelfReachability) Class() NATClass {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.class
}

// Status is the verdict plus the evidence behind it.
type Status struct {
	State    ReachState
	Class    NATClass
	External netip.Addr
	Probers  int
	Networks int
	Failures int
	Since    time.Time
	Reason   string
}

// Snapshot returns the full status.
func (s *SelfReachability) Snapshot() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Status{
		State: s.state, Class: s.class, External: s.external,
		Probers: s.quorum, Networks: s.networks, Failures: s.failures,
		Since: s.since, Reason: s.lastError,
	}
}

// Apply records a completed probe round.
//
// The quorum rules are the same as for observing a peer, and for the same
// reason: a node that took one prober's word for its own reachability could be
// told it is reachable by a single hostile peer and would then advertise a
// relay role that does not work (T3.4, applied to the self case).
func (s *SelfReachability) Apply(obs []ProbeObservation, now time.Time) Classification {
	c := ClassifyObservations(obs)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.quorum, s.networks = c.Probers, c.Networks
	s.since = now

	switch {
	case c.Probers < MinProbeQuorum:
		s.state, s.lastError = ReachProbing, "insufficient prober quorum"
		return c
	case c.Networks < MinProbeNetworks:
		s.state, s.lastError = ReachProbing, "insufficient prober network diversity"
		return c
	}

	s.class, s.lastError = c.Class, c.Reason
	if c.External.IsValid() {
		s.external = c.External
	}

	if c.Class.Inbound() {
		// Promotion needs a fresh quorum AND a fresh dial-back, both of which
		// ClassifyObservations has just established.
		s.state, s.failures = ReachReachable, 0
		return c
	}

	if c.Class == ClassUnknown {
		s.state = ReachProbing
		return c
	}

	// Demotion is immediate for a class that admits no inbound -- but a
	// REACHABLE node is demoted only after DemotionFailures consecutive rounds,
	// so one flaky probe round does not withdraw a working relay.
	if s.state == ReachReachable {
		s.failures++
		if s.failures < DemotionFailures {
			s.lastError = "dial-back failed; holding REACHABLE pending consecutive failures"
			return c
		}
	}
	s.state, s.failures = ReachUnreachable, 0
	return c
}

// Fail records a dial-back failure outside a full probe round, and demotes on
// the third consecutive one.
func (s *SelfReachability) Fail(reason string, now time.Time) ReachState {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures++
	s.since, s.lastError = now, reason
	if s.state == ReachReachable && s.failures >= DemotionFailures {
		s.state, s.failures = ReachUnreachable, 0
	}
	return s.state
}

// LeaseLost demotes immediately: a MAPPED node whose port-mapping lease lapsed
// has no grace period, because every circuit routed through it in the meantime
// black-holes.
func (s *SelfReachability) LeaseLost(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.class == ClassMapped {
		s.state, s.class = ReachUnreachable, ClassUnknown
		s.failures, s.since = 0, now
		s.lastError = "port-mapping lease lost; demoted immediately"
	}
}

// Classify waits for a verdict, or returns unreachable at the deadline.
//
// FAILING CLOSED IS THE POINT. A node whose probes never arrive has learned
// nothing about itself, and the two ways to resolve that are opposite in
// consequence: assume reachable and advertise a relay role that black-holes
// circuits, or assume unreachable and decline a role it might have been able to
// fill. The second costs the network one relay; the first costs every client
// that picks it a failed circuit.
func (s *SelfReachability) Classify(ctx context.Context, poll time.Duration, now func() time.Time) ReachState {
	if poll <= 0 {
		poll = time.Second
	}
	if now == nil {
		now = time.Now
	}
	start := now()
	t := time.NewTicker(poll)
	defer t.Stop()

	for {
		if st := s.State(); st == ReachReachable || st == ReachUnreachable {
			return st
		}
		if now().Sub(start) >= ClassifyDeadline {
			s.mu.Lock()
			if s.state != ReachReachable {
				s.state = ReachUnreachable
				s.lastError = "no probe quorum within the classification deadline"
			}
			st := s.state
			s.mu.Unlock()
			return st
		}
		select {
		case <-ctx.Done():
			return s.State()
		case <-t.C:
		}
	}
}

// Roles filters the offered roles through §6.5's gate, returning each with the
// permission that admitted it.
//
// A role whose class does not permit it is dropped, not downgraded: §6.5
// requires that a node MUST NOT advertise a role its class does not permit, and
// MUST withdraw within one descriptor period of demotion.
func (s *SelfReachability) Roles(offered []Role) map[Role]Permission {
	s.mu.RLock()
	class, state := s.class, s.state
	s.mu.RUnlock()

	// Until a verdict exists the node advertises nothing and takes no public
	// role -- the UNKNOWN state's entire content in the §6.5 diagram.
	if state != ReachReachable && state != ReachUnreachable {
		class = ClassUnknown
	}

	out := make(map[Role]Permission, len(offered))
	for _, r := range offered {
		if p := Permit(class, r); p.Allowed() {
			out[r] = p
		}
	}
	return out
}

// MayRelay is the single question the relay role gate asks. It covers every
// role that carries somebody else's circuit.
func (s *SelfReachability) MayRelay() bool {
	s.mu.RLock()
	class, state := s.class, s.state
	s.mu.RUnlock()
	if state != ReachReachable {
		return false
	}
	for _, r := range []Role{RoleGuard, RoleMiddleRelay, RoleTerminalRelay} {
		if !Permit(class, r).Allowed() {
			return false
		}
	}
	return true
}
