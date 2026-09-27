package content

import (
	"errors"
	"fmt"
	"sort"
)

// G3 — what a node is willing to facilitate (§87).
//
// R-84.1 IS THE SHAPE OF THIS FILE. Policy applies at exactly three positions,
// because at each the node already holds or can see the thing it is deciding
// about: HOST, EXIT and PUBLISH. At RELAY position a node applies NO CONTENT
// POLICY OF ANY KIND, because it has no content to have a policy about — §8
// exists so a middle relay cannot interpret what it forwards, and a relay that
// could decide whether to carry `malware` would be a relay that knows.
//
// So there is no relay-position API here. Not a flag defaulting to off, not a
// method that returns "allow" — nothing to call. That is deliberate: an
// unimplemented option is a request to implement it, and E-G3's whole content is
// that relaying is unaffected by any of this.
//
// THE POLICY IS LOCAL AND IS NEVER PUBLISHED. A node that advertised what it
// refuses would be advertising what it holds, which is a search index for
// anyone looking for a host to seize. What a node publishes is prices and
// capabilities (§95), never refusals.

// Position is where a decision is being made.
type Position uint8

const (
	// PositionHost: the node holds the object and can read its labels.
	PositionHost Position = iota + 1
	// PositionExit: the destination is in the clear by construction (§17.1).
	PositionExit
	// PositionPublish: the node is being asked to bind a name to content.
	PositionPublish
)

func (p Position) String() string {
	switch p {
	case PositionHost:
		return "host"
	case PositionExit:
		return "exit"
	case PositionPublish:
		return "publish"
	default:
		return "invalid"
	}
}

// UnknownPolicy is what to do with content nothing has claimed anything about.
type UnknownPolicy uint8

const (
	// UnknownHost is the DEFAULT and the zero value (R-87.1).
	//
	// §87's draft said `unknown -> don't relay`. Under R-84.1 that becomes
	// `unknown -> don't HOST`, and on a young network it inverts into "store
	// nothing": almost nothing is labelled yet. Worse, it makes labelling a
	// GATE — content becomes hostable only once somebody has classified it, and
	// whoever classifies first controls what exists.
	//
	// The permissive default fails toward "the network works". The strict one
	// fails toward "the network is empty and nobody can tell why".
	UnknownHost UnknownPolicy = iota
	// UnknownRefuse is the strict reading, set explicitly by an operator.
	UnknownRefuse
)

// PrunePolicy is how strongly a node honours a §93 prune record.
type PrunePolicy uint8

const (
	// PruneEnforce is the conformant default.
	PruneEnforce PrunePolicy = iota
	// PruneQuarantine keeps the object but stops serving it.
	PruneQuarantine
	// PruneIgnore is non-conformant and permitted (R-93.1): a node that
	// ignores every prune record must remain routable, or the network has
	// gained an expulsion mechanism.
	PruneIgnore
)

// NodePolicy is one operator's answer to "what will I facilitate".
type NodePolicy struct {
	// HostAllow, if non-empty, is a whitelist: nothing outside it is stored.
	HostAllow []Category
	// HostBlock is refused whatever HostAllow says.
	HostBlock []Category
	// ExitAllow / ExitBlock are the same for an EXIT node (§17.1).
	ExitAllow []Category
	ExitBlock []Category
	// MinConfidence is the floor below which a label is treated as if it were
	// not there. A 0.05 claim that something is malware is not a reason to
	// refuse it, and treating it as one hands a veto to the least confident
	// claimant anybody trusts.
	MinConfidence float32
	// Unknown is R-87.1's default.
	Unknown UnknownPolicy
	// Prune is how §93 records are honoured.
	Prune PrunePolicy
	// TrustedIssuers is whose labels this node believes. Empty means "believe
	// nobody", which combined with UnknownHost means "host everything" -- the
	// state a fresh node is in, and a working one.
	TrustedIssuers []ClaimantID
}

// Decision is the outcome, with the reason attached.
type Decision struct {
	Allow bool
	// Category is what drove the refusal, or CategoryUnknown.
	Category Category
	// Reason is for the operator's log, never for the network.
	Reason string
}

var (
	// ErrRelayPositionHasNoPolicy is returned if anybody asks this package to
	// make a relay-position decision. It exists to be a loud, specific refusal
	// rather than a silent "allow" that would look like the feature working.
	ErrRelayPositionHasNoPolicy = errors.New(
		"axon/content: a relay applies no content policy (R-84.1); a relay that could " +
			"decide whether to carry a category is a relay that knows the category")
	ErrBadPosition = errors.New("axon/content: not a policy position")
)

// trusts reports whether a claimant's labels count for this node.
func (p NodePolicy) trusts(c ClaimantID) bool {
	for _, t := range p.TrustedIssuers {
		if t == c {
			return true
		}
	}
	return false
}

// effectiveCategories reduces a label set to the categories this node believes
// are claimed about the subject.
//
// Only labels from TRUSTED issuers, at or above MinConfidence. Everything else
// is not "false" -- it is simply not this node's evidence, which is R-88.1's
// local-reducer rule applied one layer down.
func (p NodePolicy) effectiveCategories(set *LabelSet) []Category {
	seen := map[Category]bool{}
	if set != nil {
		for _, l := range set.labels {
			if !p.trusts(l.Claimant) {
				continue
			}
			if l.Confidence < p.MinConfidence {
				continue
			}
			seen[l.Category] = true
		}
	}
	out := make([]Category, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Decide answers whether this node will facilitate a subject at a position.
//
// It takes a Position and REFUSES the relay one. There is deliberately no way
// to express a relay decision, and asking is an error rather than an allow.
func (p NodePolicy) Decide(pos Position, set *LabelSet) (Decision, error) {
	switch pos {
	case PositionHost, PositionExit, PositionPublish:
	default:
		return Decision{}, fmt.Errorf("%w: %d", ErrBadPosition, pos)
	}

	block, allow := p.HostBlock, p.HostAllow
	if pos == PositionExit {
		block, allow = p.ExitBlock, p.ExitAllow
	}

	cats := p.effectiveCategories(set)

	// Nothing claimed, or nothing claimed by anyone this node trusts.
	if len(cats) == 0 {
		if p.Unknown == UnknownRefuse {
			return Decision{Allow: false, Category: CategoryUnknown,
				Reason: "no trusted label and this node refuses unknown content"}, nil
		}
		return Decision{Allow: true, Category: CategoryUnknown,
			Reason: "no trusted label; hosting unknown content is the default (R-87.1)"}, nil
	}

	// Block wins over allow, always. An operator who lists a category in both
	// meant to refuse it -- the alternative reading lets a permissive entry
	// silently override an explicit refusal.
	for _, c := range cats {
		for _, b := range block {
			if c == b {
				return Decision{Allow: false, Category: c,
					Reason: "category is blocked by this node"}, nil
			}
		}
	}

	if len(allow) > 0 {
		for _, c := range cats {
			for _, a := range allow {
				if c == a {
					return Decision{Allow: true, Category: c,
						Reason: "category is allowed by this node"}, nil
				}
			}
		}
		return Decision{Allow: false, Category: cats[0],
			Reason: "this node hosts only an allow-list and no claimed category is on it"}, nil
	}

	return Decision{Allow: true, Category: cats[0], Reason: "no rule refuses it"}, nil
}

// DecideRelay always fails. See ErrRelayPositionHasNoPolicy.
//
// It EXISTS so the refusal is discoverable at the call site somebody would
// naturally reach for. A package that simply had no such function would leave
// the next person to write their own filter, which is the outcome R-84.1
// forbids.
func (p NodePolicy) DecideRelay(*LabelSet) (Decision, error) {
	return Decision{}, ErrRelayPositionHasNoPolicy
}
