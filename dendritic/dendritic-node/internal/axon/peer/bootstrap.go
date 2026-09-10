package peer

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Bootstrap partition detection.
//
// T3.5: an adversarial bootstrap set is DETECTED -- the node emits a partition
// warning rather than proceeding silently.
//
// WHAT THIS CANNOT DO, STATED FIRST. P3's own security note calls bootstrap the
// worst case: "a node whose first view is adversarial is adversarially
// bootstrapped, and nothing later fixes it (§7, [UNSOLVED])." Nothing in this
// file fixes it either. A node with no prior view has no independent reference
// to check the bootstrap set against, so it cannot distinguish a hostile set
// from a small honest one -- both look like a handful of peers who agree.
//
// What it CAN do is refuse to be silent. Every check here is a structural one:
// concentration in one prefix, one AS, or one operator string; a peer set that
// never widens past the seeds; a view that disagrees with a previously
// persisted one. Each is a property an adversary can defeat by spreading their
// seeds across networks, and an honest small deployment can trip by accident.
// The output is therefore a WARNING with its evidence, not a verdict, and the
// exit criterion is detection and emission -- not prevention.

// PartitionSeverity ranks a warning.
type PartitionSeverity uint8

const (
	SeverityInfo PartitionSeverity = iota
	SeverityWarn
	SeverityCritical
)

func (s PartitionSeverity) String() string {
	switch s {
	case SeverityWarn:
		return "warn"
	case SeverityCritical:
		return "critical"
	default:
		return "info"
	}
}

// PartitionWarning is one detected indicator.
type PartitionWarning struct {
	Severity PartitionSeverity
	Code     string
	Detail   string
}

func (w PartitionWarning) String() string {
	return fmt.Sprintf("[%s] %s: %s", w.Severity, w.Code, w.Detail)
}

// BootstrapPeer is one seed as configured.
type BootstrapPeer struct {
	NodeID string
	Addr   netip.Addr
	// Operator is an optional operator string from the seed list, used only to
	// notice that every seed names the same one. It is self-declared and
	// trivially forged; it is evidence for a warning, never for a verdict.
	Operator string
}

// BootstrapAudit is the full result of auditing a bootstrap set.
type BootstrapAudit struct {
	Seeds int
	// DistinctPrefixes and DistinctASNs are the observed diversity.
	DistinctPrefixes int
	DistinctASNs     int
	// ASNUnavailable counts seeds whose ASN could not be resolved, so the ASN
	// concentration check could not be applied to them. See annotate.go's IPv4
	// note: for IPv4 seeds this is normally all of them.
	ASNUnavailable int
	Warnings       []PartitionWarning
}

// Partitioned reports whether any warning reached the given severity.
func (a BootstrapAudit) Partitioned(min PartitionSeverity) bool {
	for _, w := range a.Warnings {
		if w.Severity >= min {
			return true
		}
	}
	return false
}

// MinBootstrapSeeds and MinBootstrapPrefixes are the structural floor. Three
// seeds in three prefixes is not safety -- it is the minimum below which the
// question is not even worth asking.
const (
	MinBootstrapSeeds    = 3
	MinBootstrapPrefixes = 3
)

// AuditBootstrap checks a bootstrap set for the structural signs of a partition
// and returns every indicator it found.
//
// It never returns an error for a hostile-looking set: the caller decides
// whether to refuse to start, and P3's ruling is that the node emits the
// warning rather than proceeding silently -- proceeding loudly is still
// permitted, because an operator running a small private deployment will trip
// every check here legitimately.
func AuditBootstrap(a *Annotator, seeds []BootstrapPeer, priorView []string) BootstrapAudit {
	if a == nil {
		a = &Annotator{}
	}
	audit := BootstrapAudit{Seeds: len(seeds)}

	prefixes := map[netip.Prefix]int{}
	asns := map[uint32]int{}
	operators := map[string]int{}
	ids := map[string]struct{}{}

	for _, s := range seeds {
		if s.NodeID != "" {
			ids[s.NodeID] = struct{}{}
		}
		if op := strings.TrimSpace(strings.ToLower(s.Operator)); op != "" {
			operators[op]++
		}
		if !s.Addr.IsValid() {
			continue
		}
		ann, err := a.Annotate(s.Addr)
		if err != nil {
			continue
		}
		prefixes[ann.Prefix]++
		if ann.ASN == ASNUnknown {
			audit.ASNUnavailable++
		} else {
			asns[ann.ASN]++
		}
	}
	audit.DistinctPrefixes = len(prefixes)
	audit.DistinctASNs = len(asns)

	warn := func(sev PartitionSeverity, code, detail string) {
		audit.Warnings = append(audit.Warnings, PartitionWarning{sev, code, detail})
	}

	if len(seeds) < MinBootstrapSeeds {
		warn(SeverityCritical, "too-few-seeds",
			fmt.Sprintf("%d bootstrap seeds configured, below the floor of %d; the first view of the network comes from too few sources to cross-check",
				len(seeds), MinBootstrapSeeds))
	}
	if len(ids) < len(seeds) {
		warn(SeverityWarn, "duplicate-seed-identity",
			fmt.Sprintf("%d seeds resolve to %d distinct node identities; duplicates inflate an apparent quorum without adding a vantage point",
				len(seeds), len(ids)))
	}

	// Concentration. One prefix, or one AS, holding the whole bootstrap set
	// means one operator can decide what this node's first view of the network
	// looks like -- which is exactly the adversarial-bootstrap condition.
	if len(seeds) >= 2 && audit.DistinctPrefixes == 1 {
		warn(SeverityCritical, "single-prefix",
			fmt.Sprintf("all %d seeds share one %s; a single network operator controls this node's entire first view", len(seeds), soloPrefix(prefixes)))
	} else if audit.DistinctPrefixes > 0 && audit.DistinctPrefixes < MinBootstrapPrefixes {
		warn(SeverityWarn, "few-prefixes",
			fmt.Sprintf("seeds span %d distinct prefixes, below the recommended %d", audit.DistinctPrefixes, MinBootstrapPrefixes))
	}
	if audit.DistinctASNs == 1 && len(seeds) >= 2 && audit.ASNUnavailable == 0 {
		warn(SeverityCritical, "single-asn",
			fmt.Sprintf("all %d seeds are in AS%d", len(seeds), soloASN(asns)))
	}
	if audit.ASNUnavailable == len(seeds) && len(seeds) > 0 {
		// Honest about the gap rather than reporting a check that did not run.
		warn(SeverityInfo, "asn-unavailable",
			fmt.Sprintf("no ASN resolved for any of %d seeds; AS-concentration was NOT checked and prefix distinctness is the only diversity actually verified", len(seeds)))
	}
	if len(seeds) >= 2 {
		for op, n := range operators {
			if n == len(seeds) {
				warn(SeverityWarn, "single-operator",
					fmt.Sprintf("all %d seeds declare operator %q; self-declared and forgeable, but it is what the configuration says", len(seeds), op))
			}
		}
	}

	// Disagreement with a previously persisted view. A node that knew peers
	// yesterday and shares none of them with today's bootstrap answer has
	// either been offline a long time or is being handed a different network.
	if len(priorView) > 0 {
		prior := map[string]struct{}{}
		for _, id := range priorView {
			prior[id] = struct{}{}
		}
		overlap := 0
		for id := range ids {
			if _, ok := prior[id]; ok {
				overlap++
			}
		}
		if overlap == 0 {
			warn(SeverityCritical, "disjoint-from-prior-view",
				fmt.Sprintf("none of the %d bootstrap seeds appear in the %d peers known from the previous run; this node may be being handed a different network",
					len(seeds), len(priorView)))
		}
	}

	return audit
}

// AuditDiscovered checks what bootstrap actually produced: a peer set that
// never widens past the seeds is a partition symptom the seed list alone cannot
// show.
func AuditDiscovered(seeds []BootstrapPeer, discovered []PeerEntry) []PartitionWarning {
	seedIDs := map[string]struct{}{}
	for _, s := range seeds {
		seedIDs[s.NodeID] = struct{}{}
	}
	beyond := 0
	prefixes := map[netip.Prefix]struct{}{}
	for _, d := range discovered {
		if _, isSeed := seedIDs[d.NodeID]; !isSeed {
			beyond++
		}
		if ann, ok := d.Primary(); ok {
			prefixes[ann.Prefix] = struct{}{}
		}
	}

	var out []PartitionWarning
	if beyond == 0 && len(seeds) > 0 {
		out = append(out, PartitionWarning{SeverityCritical, "no-peers-beyond-seeds",
			fmt.Sprintf("discovery returned %d peers and none outside the %d configured seeds; the reachable network may consist only of the bootstrap set",
				len(discovered), len(seeds))})
	}
	if len(discovered) >= MinBootstrapSeeds && len(prefixes) == 1 {
		out = append(out, PartitionWarning{SeverityCritical, "discovered-single-prefix",
			fmt.Sprintf("all %d discovered peers are in one prefix", len(discovered))})
	}
	return out
}

func soloPrefix(m map[netip.Prefix]int) string {
	for p := range m {
		return p.String()
	}
	return "prefix"
}

func soloASN(m map[uint32]int) uint32 {
	keys := make([]uint32, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	if len(keys) == 0 {
		return 0
	}
	return keys[0]
}
