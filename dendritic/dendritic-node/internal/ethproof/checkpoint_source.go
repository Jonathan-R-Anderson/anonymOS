package ethproof

// Acquiring a mainnet checkpoint independently — roadmap P12-5.9.
//
// THE PROBLEM THIS SOLVES
// -----------------------
// The anchor must not come from the endpoint being verified, or the chain of
// trust is provider -> checkpoint -> provider and proves nothing. But asking an
// operator to paste a hex string is its own failure mode: nobody re-derives it,
// and a stale or mistyped value is indistinguishable from a correct one.
//
// So: ask SEVERAL INDEPENDENT OPERATORS and require unanimity.
//
//	Sigma Prime  ┐
//	Attestant    ├─ all must return the same finalised root
//	EthStaker    ┘
//	                      │
//	                      ▼
//	              anchor, with provenance
//
// One operator lying is caught. All of them lying in the same way requires a
// conspiracy among organisations with no reason to cooperate, which is a
// materially different proposition from trusting one endpoint.
//
// DISAGREEMENT IS A HARD FAILURE
// ------------------------------
// Not a majority vote, not "most agree". Checkpoint sources disagreeing means
// either a real chain split or a compromised source, and both are situations
// where proceeding is exactly wrong. Unanimity or nothing.
//
// A brief disagreement is also the NORMAL case near a boundary: finality
// advances every epoch, and two providers sampled seconds apart can legitimately
// report adjacent checkpoints. That is why the acquirer reports the mismatch
// rather than retrying until it gets agreement — a retry loop would eventually
// paper over a real split.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrCheckpointDisagreement means the sources did not agree.
var ErrCheckpointDisagreement = errors.New(
	"checkpoint: independent sources disagree; refusing to anchor")

// CheckpointSource is one operator's endpoint plus why it counts as independent.
type CheckpointSource struct {
	// Name is the operator, not the hostname. Two hostnames run by one
	// organisation are one source.
	Name string
	URL  string
	// Rationale records WHY this is independent of the others, for whoever
	// audits the anchor later. "different hostname" is not a rationale.
	Rationale string
}

// MainnetCheckpointSources are three operators with no common control.
//
// Chosen because each runs its own infrastructure for its own reasons: Sigma
// Prime builds Lighthouse, Attestant runs staking infrastructure, EthStaker is
// a community project. None is the beacon provider used for light client data,
// and none is the execution RPC.
var MainnetCheckpointSources = []CheckpointSource{
	{
		Name: "Sigma Prime", URL: "https://mainnet.checkpoint.sigp.io",
		Rationale: "Lighthouse client team; independent org, own infrastructure",
	},
	{
		Name: "Attestant", URL: "https://mainnet-checkpoint-sync.attestant.io",
		Rationale: "institutional staking operator; unrelated to Sigma Prime and EthStaker",
	},
	{
		Name: "EthStaker", URL: "https://beaconstate.ethstaker.cc",
		Rationale: "community-run; unrelated to the two commercial operators above",
	},
}

// AcquiredCheckpoint is a checkpoint plus the provenance to reproduce it.
type AcquiredCheckpoint struct {
	Root string
	Slot uint64
	// Agreed lists every source that returned this root. All configured
	// sources must appear, or the acquisition failed.
	Agreed []CheckpointSource
	// RetrievedAt is when, so a reader can judge staleness.
	RetrievedAt time.Time
}

// String renders the provenance for a fixture or an operator to check by hand.
func (a AcquiredCheckpoint) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "checkpoint %s\n  slot        %d\n  retrieved   %s\n",
		a.Root, a.Slot, a.RetrievedAt.UTC().Format(time.RFC3339))
	for _, s := range a.Agreed {
		fmt.Fprintf(&b, "  agreed      %-14s %s\n              %s\n", s.Name, s.URL, s.Rationale)
	}
	return b.String()
}

// AcquireCheckpoint asks every source and requires unanimity.
//
// `exclude` is the beacon endpoint that will later supply light client data.
// A source sharing its provider is dropped BEFORE the vote — including it would
// let the endpoint being verified vote on its own anchor.
func AcquireCheckpoint(ctx context.Context, sources []CheckpointSource,
	exclude string, now func() time.Time) (AcquiredCheckpoint, error) {

	if now == nil {
		now = time.Now
	}
	usable := make([]CheckpointSource, 0, len(sources))
	for _, s := range sources {
		if exclude != "" && sameProvider(s.URL, exclude) {
			continue // the endpoint under test does not vote on its own anchor
		}
		usable = append(usable, s)
	}
	if len(usable) < 3 {
		return AcquiredCheckpoint{}, fmt.Errorf(
			"checkpoint: %d independent sources after excluding %q; need at least 3",
			len(usable), providerOf(exclude))
	}

	type answer struct {
		source CheckpointSource
		root   string
		err    error
	}
	answers := make([]answer, 0, len(usable))
	for _, s := range usable {
		root, err := fetchFinalizedRoot(ctx, s.URL)
		answers = append(answers, answer{source: s, root: root, err: err})
	}

	roots := map[string][]CheckpointSource{}
	for _, a := range answers {
		if a.err != nil {
			return AcquiredCheckpoint{}, fmt.Errorf(
				"checkpoint: %s (%s) unreachable: %w — a source that cannot be asked "+
					"cannot agree, and unanimity is required", a.source.Name, a.source.URL, a.err)
		}
		key := strings.ToLower(strings.TrimPrefix(a.root, "0x"))
		roots[key] = append(roots[key], a.source)
	}

	if len(roots) != 1 {
		var detail []string
		for root, srcs := range roots {
			names := make([]string, 0, len(srcs))
			for _, s := range srcs {
				names = append(names, s.Name)
			}
			sort.Strings(names)
			detail = append(detail, fmt.Sprintf("%s: %s", root[:16], strings.Join(names, ", ")))
		}
		sort.Strings(detail)
		return AcquiredCheckpoint{}, fmt.Errorf("%w: %s",
			ErrCheckpointDisagreement, strings.Join(detail, " | "))
	}

	var root string
	var agreed []CheckpointSource
	for r, srcs := range roots {
		root, agreed = r, srcs
	}
	return AcquiredCheckpoint{
		Root: "0x" + root, Agreed: agreed, RetrievedAt: now(),
	}, nil
}

// fetchFinalizedRoot reads one source's finalised block root.
//
// /eth/v1/beacon/blocks/finalized/root is used because checkpoint-sync
// providers serve it while many do not serve /eth/v1/beacon/headers/finalized —
// established by probing, and recorded in doc/trust-anchor.md.
func fetchFinalizedRoot(ctx context.Context, endpoint string) (string, error) {
	c := NewBeaconClient(endpoint)
	var wrapper struct {
		Data struct {
			Root string `json:"root"`
		} `json:"data"`
	}
	if err := c.get(ctx, "/eth/v1/beacon/blocks/finalized/root", &wrapper); err != nil {
		return "", err
	}
	if wrapper.Data.Root == "" {
		return "", errors.New("empty root")
	}
	return wrapper.Data.Root, nil
}
