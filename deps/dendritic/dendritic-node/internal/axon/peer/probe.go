package peer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Probing peers, and what a refusal means.
//
// T3.2 is the whole point of this file: a peer CLAIMING reachability that
// REFUSES the probe is marked unreachable within one probe interval. The
// tempting implementation treats a refusal as an absent measurement and leaves
// the old verdict standing, which hands every peer a way to keep a reachable
// mark forever by never being tested. A refusal is a failed probe.

// DefaultProbeInterval is one probe round. T3.2's deadline is one interval, so
// a refusal must produce the unreachable mark inside a single round -- which it
// does here, because Round records the verdict before it returns.
const DefaultProbeInterval = 15 * time.Minute

// ErrProbeRefused is what a ProbeFunc returns when the peer declined the probe.
var ErrProbeRefused = errors.New("axon/peer: peer refused the probe")

// ProbeFunc runs one prober's probe against a peer. It reports whether the peer
// answered the dial-back, and errors otherwise. A ProbeFunc that returns
// ErrProbeRefused is reporting a refusal specifically; any other error is a
// failure with the same consequence but a different operator message.
type ProbeFunc func(ctx context.Context, nodeID string, addrs []netip.Addr) (ok bool, err error)

// ProberRef is one prober available to run probes on our behalf.
type ProberRef struct {
	ID ProberID
	// Network is the prober's failure domain. Distinctness across these is what
	// MinProbeNetworks counts.
	Network string
	Probe   ProbeFunc
}

// Prober runs probe rounds against peers and records the verdicts.
type Prober struct {
	Book     *Peerbook
	Interval time.Duration
	// Probers is the set this node can ask. It must span at least
	// MinProbeNetworks distinct networks or no round can produce a verdict.
	Probers []ProberRef
	// Now is injectable for tests.
	Now func() time.Time
}

// ProbeOutcome is what one round concluded about one peer.
type ProbeOutcome struct {
	NodeID string
	// Claimed is what the peer said about itself before the probe.
	Claimed bool
	// Reachable is what the probers found.
	Reachable bool
	// Refusals counts probers the peer declined.
	Refusals int
	// Probers and Networks are the distinct counts behind the verdict.
	Probers, Networks int
	// Recorded is whether the verdict made it into the peerbook. A verdict from
	// too few or too-correlated probers is NOT recorded -- E3.3 holds by
	// construction, so a thin round leaves the peerbook untouched rather than
	// writing a weak entry.
	Recorded bool
	Reason   string
}

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Round runs every prober against one peer and records the verdict.
//
// `claimed` is the peer's own advertisement. It is carried into the outcome for
// the operator log and is never allowed to influence the verdict: the entire
// value of probing is that it does not take the probed node's word.
func (p *Prober) Round(ctx context.Context, nodeID string, addrs []netip.Addr, claimed bool) (ProbeOutcome, error) {
	out := ProbeOutcome{NodeID: nodeID, Claimed: claimed}
	if nodeID == "" {
		return out, ErrUnknownNodeID
	}
	if len(addrs) == 0 {
		return out, ErrNoAddresses
	}

	type result struct {
		ref     ProberRef
		ok      bool
		refused bool
	}
	results := make([]result, len(p.Probers))

	var wg sync.WaitGroup
	for i, ref := range p.Probers {
		if ref.Probe == nil {
			results[i] = result{ref: ref, ok: false, refused: false}
			continue
		}
		wg.Add(1)
		go func(i int, ref ProberRef) {
			defer wg.Done()
			ok, err := ref.Probe(ctx, nodeID, addrs)
			results[i] = result{
				ref:     ref,
				ok:      ok && err == nil,
				refused: errors.Is(err, ErrProbeRefused),
			}
		}(i, ref)
	}
	wg.Wait()

	ev := Evidence{At: p.now()}
	successes := 0
	for _, r := range results {
		ev.Probers = append(ev.Probers, r.ref.ID)
		ev.Networks = append(ev.Networks, r.ref.Network)
		if r.refused {
			out.Refusals++
		}
		if r.ok {
			successes++
		}
	}
	out.Probers, out.Networks = ev.Quorum()

	// A REFUSAL IS A FAILED PROBE, NOT A MISSING ONE. The peer had its chance
	// inside this interval and declined it; leaving a stale reachable mark
	// standing would let any peer keep one indefinitely by never being tested.
	ev.Reachable = successes > 0
	out.Reachable = ev.Reachable

	switch {
	case out.Probers < MinProbeQuorum:
		out.Reason = fmt.Sprintf("prober quorum %d < %d; verdict not recorded", out.Probers, MinProbeQuorum)
		return out, nil
	case out.Networks < MinProbeNetworks:
		out.Reason = fmt.Sprintf("prober networks %d < %d; verdict not recorded", out.Networks, MinProbeNetworks)
		return out, nil
	}

	if err := p.Book.Observe(nodeID, addrs, ev); err != nil {
		return out, err
	}
	out.Recorded = true
	switch {
	case out.Refusals > 0 && !out.Reachable:
		out.Reason = fmt.Sprintf("peer refused %d of %d probes; marked unreachable", out.Refusals, len(results))
	case out.Reachable:
		out.Reason = "dial-back succeeded"
	default:
		out.Reason = "no prober completed a dial-back"
	}
	return out, nil
}

// Interval is the configured probe interval, or the default.
func (p *Prober) interval() time.Duration {
	if p.Interval > 0 {
		return p.Interval
	}
	return DefaultProbeInterval
}
