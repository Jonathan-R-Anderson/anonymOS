package peer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Port mapping: UPnP-IGD and NAT-PMP/PCP, off by default.
//
// §6.5: "UPnP-IGD and NAT-PMP/PCP are attempted, in that order of decreasing
// awfulness, only on operator opt-in. Off by default: a node that silently
// reconfigures the user's router is not a node an operator can reason about.
// Success yields MAPPED, refreshed at half the lease, demoted the moment a
// refresh fails."
//
// Two rules follow from that sentence and are enforced here rather than left to
// the caller:
//
//  1. A zero-valued MappingConfig maps nothing. Opting in is an explicit act.
//  2. A refresh failure demotes IMMEDIATELY -- no grace, no retry-then-demote.
//     A lapsed lease turns a relay into a black hole for every circuit already
//     routed through it, and the cost of a spurious demotion is one relay
//     re-probing in 15 minutes.

// ErrMappingDisabled is returned when mapping is attempted without opt-in.
var ErrMappingDisabled = errors.New("axon/peer: port mapping is disabled (operator opt-in required)")

// ErrNoMapper is returned when every configured protocol failed.
var ErrNoMapper = errors.New("axon/peer: no port-mapping protocol succeeded")

// DefaultLease is the mapping lifetime requested. Short by intent: an abandoned
// node's mapping should expire on the router rather than persist as a hole the
// operator did not know was open.
const DefaultLease = 30 * time.Minute

// MappingProtocol names a mapping mechanism.
type MappingProtocol uint8

const (
	MappingUPnP   MappingProtocol = iota // UPnP-IGD (no RFC; UPnP Forum)
	MappingNATPMP                        // NAT-PMP, RFC 6886
	// MappingPCP is declared in pcp.go, where the protocol lives.
)

// String names the protocol.
//
// NAT-PMP AND PCP ARE NOT THE SAME PROTOCOL and this used to say they were: one
// constant, commented "NAT-PMP / PCP", stringified "nat-pmp". They are RFC 6886
// and RFC 6887, sharing UDP port 5351 and a lineage and nothing else -- a
// gateway answering one need not answer the other. The conflation meant an
// operator reading a log could not tell which had been spoken, and it let the
// roadmap describe PCP as covered by a constant that never implemented it.
func (m MappingProtocol) String() string {
	switch m {
	case MappingNATPMP:
		return "nat-pmp"
	case MappingPCP:
		return "pcp"
	default:
		return "upnp"
	}
}

// Mapping is one established port mapping.
type Mapping struct {
	Protocol     MappingProtocol
	InternalPort uint16
	ExternalPort uint16
	External     netip.Addr
	Lease        time.Duration
	Acquired     time.Time
}

// Expiry is when the lease runs out.
func (m Mapping) Expiry() time.Time { return m.Acquired.Add(m.Lease) }

// RefreshAt is the halfway point, per §6.5.
func (m Mapping) RefreshAt() time.Time { return m.Acquired.Add(m.Lease / 2) }

// Mapper establishes and renews a mapping over one protocol.
type Mapper interface {
	Protocol() MappingProtocol
	// Map requests a UDP mapping for internalPort with the given lease.
	Map(ctx context.Context, internalPort uint16, lease time.Duration) (Mapping, error)
	// Unmap releases it. Best-effort; a router that has forgotten the mapping
	// is not an error worth propagating.
	Unmap(ctx context.Context, m Mapping) error
}

// MappingConfig is the operator's opt-in. Its zero value maps nothing.
type MappingConfig struct {
	// Enabled must be set explicitly. This is the opt-in.
	Enabled bool
	// Protocols to attempt, in order. Empty means UPnP, then PCP, then NAT-PMP
	// -- §6.5's "order of decreasing awfulness", with PCP inserted AHEAD of
	// NAT-PMP because it is NAT-PMP's successor and the two share a port: a
	// gateway that speaks both should be spoken to in the one that can express
	// IPv6, a requested external address, and a mapping nonce. RFC 6887 §16
	// specifies exactly this fallback direction. Only if Enabled.
	Protocols []MappingProtocol
	// Lease is the requested lifetime; DefaultLease if zero.
	Lease time.Duration
	// InternalPort is the local UDP port to map.
	InternalPort uint16
}

func (c MappingConfig) protocols() []MappingProtocol {
	if len(c.Protocols) > 0 {
		return c.Protocols
	}
	return []MappingProtocol{MappingUPnP, MappingPCP, MappingNATPMP}
}

func (c MappingConfig) lease() time.Duration {
	if c.Lease > 0 {
		return c.Lease
	}
	return DefaultLease
}

// MappingManager acquires a mapping, refreshes it at half the lease, and
// notifies the reachability state machine the moment a refresh fails.
type MappingManager struct {
	cfg     MappingConfig
	mappers map[MappingProtocol]Mapper
	self    *SelfReachability
	now     func() time.Time

	mu      sync.RWMutex
	current *Mapping
	lastErr string
}

// NewMappingManager builds a manager. `self` may be nil in tests; when present
// it is demoted on refresh failure.
func NewMappingManager(cfg MappingConfig, self *SelfReachability, mappers ...Mapper) *MappingManager {
	m := &MappingManager{
		cfg:     cfg,
		mappers: make(map[MappingProtocol]Mapper, len(mappers)),
		self:    self,
		now:     time.Now,
	}
	for _, mp := range mappers {
		m.mappers[mp.Protocol()] = mp
	}
	return m
}

// Current returns the live mapping, if any.
func (m *MappingManager) Current() (Mapping, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.current == nil {
		return Mapping{}, false
	}
	return *m.current, true
}

// LastError is the most recent failure reason, for the operator log.
func (m *MappingManager) LastError() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastErr
}

// Acquire attempts each configured protocol in order and keeps the first that
// succeeds.
func (m *MappingManager) Acquire(ctx context.Context) (Mapping, error) {
	if !m.cfg.Enabled {
		return Mapping{}, ErrMappingDisabled
	}
	var errs []error
	for _, proto := range m.cfg.protocols() {
		mp, ok := m.mappers[proto]
		if !ok {
			continue
		}
		got, err := mp.Map(ctx, m.cfg.InternalPort, m.cfg.lease())
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", proto, err))
			continue
		}
		got.Acquired = m.now()
		m.mu.Lock()
		m.current, m.lastErr = &got, ""
		m.mu.Unlock()
		return got, nil
	}
	err := fmt.Errorf("%w: %v", ErrNoMapper, errors.Join(errs...))
	m.mu.Lock()
	m.lastErr = err.Error()
	m.mu.Unlock()
	return Mapping{}, err
}

// Refresh renews the current mapping.
//
// A failure demotes immediately and drops the mapping, so no caller can observe
// a MAPPED class backed by a lease that is no longer known to hold.
func (m *MappingManager) Refresh(ctx context.Context) error {
	m.mu.RLock()
	cur := m.current
	m.mu.RUnlock()
	if cur == nil {
		return ErrNoMapper
	}
	mp, ok := m.mappers[cur.Protocol]
	if !ok {
		m.demote("mapper for the active protocol is gone")
		return ErrNoMapper
	}
	got, err := mp.Map(ctx, m.cfg.InternalPort, m.cfg.lease())
	if err != nil {
		m.demote(fmt.Sprintf("%s refresh failed: %v", cur.Protocol, err))
		return err
	}
	// A router that hands back a DIFFERENT external port has silently moved the
	// mapping, and every descriptor advertising the old one is now wrong. Treat
	// it as a demotion: the descriptor republish path re-promotes with the new
	// port after a fresh dial-back.
	if got.ExternalPort != cur.ExternalPort {
		m.demote(fmt.Sprintf("%s renewed on a different external port (%d -> %d)",
			cur.Protocol, cur.ExternalPort, got.ExternalPort))
		return fmt.Errorf("axon/peer: mapping moved from port %d to %d", cur.ExternalPort, got.ExternalPort)
	}
	got.Acquired = m.now()
	m.mu.Lock()
	m.current, m.lastErr = &got, ""
	m.mu.Unlock()
	return nil
}

func (m *MappingManager) demote(reason string) {
	m.mu.Lock()
	m.current, m.lastErr = nil, reason
	m.mu.Unlock()
	if m.self != nil {
		m.self.LeaseLost(m.now())
	}
}

// Release drops the mapping. Always call it on shutdown: a mapping left behind
// is a hole in the operator's router that outlives the process that asked for
// it, which is exactly the surprise the opt-in default exists to prevent.
func (m *MappingManager) Release(ctx context.Context) {
	m.mu.Lock()
	cur := m.current
	m.current = nil
	m.mu.Unlock()
	if cur == nil {
		return
	}
	if mp, ok := m.mappers[cur.Protocol]; ok {
		_ = mp.Unmap(ctx, *cur)
	}
	if m.self != nil {
		m.self.LeaseLost(m.now())
	}
}

// Run acquires a mapping and refreshes it at half the lease until ctx ends.
func (m *MappingManager) Run(ctx context.Context) error {
	if !m.cfg.Enabled {
		return ErrMappingDisabled
	}
	if _, err := m.Acquire(ctx); err != nil {
		return err
	}
	defer m.Release(context.WithoutCancel(ctx))

	for {
		cur, ok := m.Current()
		if !ok {
			return ErrNoMapper
		}
		wait := cur.RefreshAt().Sub(m.now())
		if wait < time.Second {
			wait = time.Second
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		if err := m.Refresh(ctx); err != nil {
			return err
		}
	}
}
