package reputation

import (
	"math"
	"sort"
	"sync"
	"time"
)

// The LOCAL reducer (G7, §88).
//
// There is no query that returns "the network's opinion" because there is no
// such object. A View is one node's conclusion from the attestations IT chose to
// trust, and two nodes with disjoint trusted-issuer sets reaching different
// conclusions is the pluralism E-G7 requires -- a network that converged here
// would have built the consensus document R14 forbids.

// Two provisional parameters, stated with their derivation because E14.3
// requires it: "Every provisional parameter is documented with its derivation
// and marked provisional — falsified by one with no stated derivation."
//
// NOTHING MEASURES EITHER OF THESE, and nothing can yet: the deployed
// population is nine nodes and no attestation has ever been issued, so there is
// no distribution of issuer behaviour to fit. They are policy, not findings.
const (
	// DefaultHalfLife is how fast an attestation ages.
	//
	// DELIBERATELY NOT params.ProfileHalfLife (1 h). A profile metric is a
	// measurement of a circuit that just happened, and a relay that was fast an
	// hour ago should not coast on it. An attestation is a SUMMARY of a stated
	// observation window, made by somebody else, and it is a governance
	// artefact rather than a live measurement -- ageing it out in an hour would
	// mean no attestation ever survives long enough to be worth issuing.
	//
	// Seven days: long enough that a weekly issuer's word stays current between
	// issues, short enough that a year-old opinion is worth nothing. PROVISIONAL.
	DefaultHalfLife = 7 * 24 * time.Hour

	// DefaultMinWeight is the floor below which trusted evidence has aged out
	// and the view returns to UNKNOWN.
	//
	// This is the direct analogue of params.ProfileMinSamples, which is a floor
	// on DECAYED samples rather than raw ones because the question it answers is
	// "how much do I currently know about this peer" -- and the answer to that
	// decays like everything else. Without such a floor a NORMALISED weighted
	// mean never decays at all: scaling every weight by the same factor cancels,
	// so a single attestation from a year ago yields exactly the conclusion it
	// did when fresh. That is precisely T12a.5's failure -- "a score that only
	// decays on write freezes when observation stops, and asserts a stale figure
	// with undiminished confidence" -- and this floor is what stops it.
	//
	// 0.25 is one lone issuer at two half-lives, i.e. a single voice stops
	// supporting a conclusion a fortnight after it spoke, while two issuers hold
	// it up for three weeks. PROVISIONAL, and the number ProfileMinSamples = 10
	// is NOT reusable here: attestations are orders of magnitude scarcer than
	// circuit observations, and a floor of 10 would mean none ever counted.
	DefaultMinWeight = 0.25
)

// Confidence is how much a view is worth acting on.
type Confidence uint8

const (
	// Unknown means no trusted attestation and no first-hand observation.
	//
	// §88: "There is no bootstrap by declaration. A new node has no attestations
	// and is treated as UNKNOWN, which by R-87.1 is workable rather than
	// excluded." Unknown is an absence of evidence, NOT evidence of badness, and
	// every consumer must treat it as such or a new node can never start.
	Unknown Confidence = iota
	// FromAttestations means trusted issuers spoke and this node has not
	// measured the subject itself.
	FromAttestations
	// FirstHand means this node measured the subject. It outranks everything.
	FirstHand
)

func (c Confidence) String() string {
	switch c {
	case FirstHand:
		return "first-hand"
	case FromAttestations:
		return "attested"
	default:
		return "unknown"
	}
}

// View is this node's conclusion about one subject in one dimension.
type View struct {
	Subject   string
	Dimension Dimension
	// Value in [-1, 1]. Meaningless when Confidence is Unknown.
	Value      float64
	Confidence Confidence
	// Issuers is how many trusted attestations contributed.
	Issuers int
	// Weight is the total DECAYED weight behind Value.
	//
	// Reported even when Confidence is Unknown, so a caller can tell "nobody
	// ever said anything" from "what was said has aged out" -- the second is a
	// reason to go looking for a fresher issuer and the first is not.
	Weight float64
	// Contradicted is how many trusted attestations disagreed in SIGN with this
	// node's own measurement. Kept because §88 makes an attestation "evidence
	// about the ISSUER as much as the subject".
	Contradicted int
}

// FirstHandSource is this node's own measurement, or nothing.
//
// An interface rather than a concrete profile store because first-hand evidence
// is not only P12a's profiles -- a hosting or reporting dimension is measured
// elsewhere -- and because this package must not acquire a dependency on
// everything that can observe.
//
// Returning ok=false is the ordinary case and means "I have not measured this",
// which is different from measuring it as zero.
type FirstHandSource interface {
	FirstHand(subject string, d Dimension) (value float64, at time.Time, ok bool)
}

// Reducer holds one node's trusted issuers and its own measurements.
type Reducer struct {
	// HalfLife is the decay applied ON READ. Zero means DefaultHalfLife.
	//
	// §88: "R(t) = R(t-1) × 2^(-Δt/halflife) + evidence, the same exponential
	// form as P12a's profiles, applied on read for the same reason (T12a.5): a
	// score that only decays on write freezes when observation stops, and
	// asserts a stale figure with undiminished confidence."
	HalfLife time.Duration
	// MinWeight is the floor below which evidence has aged out. Zero means
	// DefaultMinWeight; a negative value disables the floor, which is available
	// for tests and is not a sensible production setting.
	MinWeight float64
	// FirstHand is this node's own measurements, or nil.
	FirstHand FirstHandSource
	// Now is injectable for tests. Nil means time.Now.
	Now func() time.Time

	mu      sync.RWMutex
	trusted map[string]struct{}
	// attestations is subject -> dimension -> issuer -> attestation. Keyed by
	// issuer LAST so a second attestation from one issuer about one subject and
	// dimension REPLACES the first -- a correction, not a second voice. §89's
	// report keys are built on the same reasoning.
	attestations map[string]map[Dimension]map[string]Attestation
}

// NewReducer builds a reducer trusting the given issuers.
func NewReducer(trusted ...string) *Reducer {
	r := &Reducer{
		trusted:      make(map[string]struct{}, len(trusted)),
		attestations: map[string]map[Dimension]map[string]Attestation{},
	}
	for _, id := range trusted {
		r.trusted[id] = struct{}{}
	}
	return r
}

func (r *Reducer) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reducer) halfLife() time.Duration {
	if r.HalfLife > 0 {
		return r.HalfLife
	}
	return DefaultHalfLife
}

func (r *Reducer) minWeight() float64 {
	if r.MinWeight != 0 {
		return r.MinWeight
	}
	return DefaultMinWeight
}

// Trust adds an issuer to the trusted set.
func (r *Reducer) Trust(issuerID string) {
	r.mu.Lock()
	r.trusted[issuerID] = struct{}{}
	r.mu.Unlock()
}

// Distrust removes one. Attestations already accepted from it stop counting
// immediately, because the set is consulted at REDUCE time rather than at
// ingest -- an operator revoking trust should not have to also remember what
// they accepted while it was granted.
func (r *Reducer) Distrust(issuerID string) {
	r.mu.Lock()
	delete(r.trusted, issuerID)
	r.mu.Unlock()
}

// TrustedIssuers lists the set.
func (r *Reducer) TrustedIssuers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.trusted))
	for id := range r.trusted {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Accept stores a verified attestation.
//
// UNTRUSTED ISSUERS ARE STORED, NOT REFUSED, and that is deliberate: trust is
// applied when reducing, so granting trust to an issuer later makes what it
// already said count, without it having to say everything again. Refusing at
// ingest would make the trusted set a filter on HISTORY rather than on belief.
//
// The signature is checked here regardless, because storing an unverifiable
// record is how a store becomes a place unverifiable records live.
func (r *Reducer) Accept(a Attestation) error {
	if err := a.Verify(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	byDim := r.attestations[a.Subject]
	if byDim == nil {
		byDim = map[Dimension]map[string]Attestation{}
		r.attestations[a.Subject] = byDim
	}
	byIssuer := byDim[a.Dimension]
	if byIssuer == nil {
		byIssuer = map[string]Attestation{}
		byDim[a.Dimension] = byIssuer
	}
	id := IssuerID(a.Issuer)
	// A correction, not a second voice: an older attestation from the same
	// issuer is replaced, and a stale one cannot overwrite a fresher one.
	if prev, ok := byIssuer[id]; ok && prev.At.After(a.At) {
		return nil
	}
	byIssuer[id] = a
	return nil
}

// Reduce is this node's view of one subject in one dimension.
//
// E-G6 LIVES HERE. §88: "A node's own first-hand observations always outrank
// attestations. P12a's ordering, extended: what you saw yourself cannot be
// overridden by what you were told." So a first-hand measurement is returned AS
// IS -- not blended, not averaged, not weighted against the attestations. A
// weighted average would let enough issuers outvote a measurement, which is
// exactly the falsifier E-G6 names.
//
// The attestations are still read when a measurement exists, because they are
// evidence about the ISSUER: Contradicted counts the trusted issuers whose sign
// disagrees with what this node saw.
func (r *Reducer) Reduce(subject string, d Dimension) View {
	now := r.now()
	v := View{Subject: subject, Dimension: d}

	// SNAPSHOT under the lock, iterate the snapshot after. Capturing the inner
	// map reference and iterating it once the lock is released is a concurrent
	// read against Accept's write to that same map -- a data race, and a
	// "concurrent map iteration and map write" panic under load. Found by
	// TestReduceRaceAgainstAccept, which no earlier test exercised.
	//
	// The copy is of at most one issuer per trusted party for one subject and
	// dimension, so it is small, and it lets the weighted sum below run without
	// holding the lock across floating-point work.
	r.mu.RLock()
	trusted := make(map[string]struct{}, len(r.trusted))
	for id := range r.trusted {
		trusted[id] = struct{}{}
	}
	byIssuer := make(map[string]Attestation, len(r.attestations[subject][d]))
	for id, a := range r.attestations[subject][d] {
		byIssuer[id] = a
	}
	r.mu.RUnlock()

	// Decay applied ON READ, per T12a.5.
	half := r.halfLife().Seconds()
	var sum, weight float64
	for id, a := range byIssuer {
		if _, ok := trusted[id]; !ok {
			continue
		}
		age := now.Sub(a.At).Seconds()
		if age < 0 {
			// An attestation from the future is a clock that moved, not fresh
			// evidence. Treated as brand new rather than amplified.
			age = 0
		}
		w := math.Exp2(-age / half)
		sum += a.Value * w
		weight += w
		v.Issuers++
	}

	v.Weight = weight

	if r.FirstHand != nil {
		if own, at, ok := r.FirstHand.FirstHand(subject, d); ok {
			v.Value = own
			v.Confidence = FirstHand
			_ = at
			for id, a := range byIssuer {
				if _, t := trusted[id]; !t {
					continue
				}
				if disagrees(own, a.Value) {
					v.Contradicted++
				}
			}
			return v
		}
	}

	if weight < r.minWeight() {
		// Either no trusted issuer ever spoke, or what they said has aged out.
		// UNKNOWN either way, and the value is left at zero rather than being
		// reported as neutral -- a consumer must branch on Confidence, not on
		// Value. Weight and Issuers still distinguish the two cases.
		return v
	}
	v.Value = sum / weight
	v.Confidence = FromAttestations
	return v
}

// disagrees reports whether two values point opposite ways.
//
// SIGN, not distance. §88 makes an attestation evidence about the issuer, and
// the useful signal is an issuer saying "good" about a peer this node measured
// as bad -- not one saying 0.7 where this node saw 0.5. A distance threshold
// would need a number nobody can derive yet, and inventing one would make
// issuer weighting look more principled than it is.
func disagrees(own, attested float64) bool {
	return (own > 0 && attested < 0) || (own < 0 && attested > 0)
}

// IssuerAgreement is how one issuer's attestations compare with this node's own
// measurements, for an operator deciding whether to keep trusting it.
//
// LOCAL AND WITHOUT GLOBAL CONSEQUENCE, per §88: "An issuer whose attestations
// disagree with a node's own observations loses weight WITH THAT NODE, locally,
// without any global consequence." Reported rather than acted on: this package
// does not silently drop an issuer's weight, because a reducer that quietly
// re-weighted its inputs would make the resulting view unauditable -- the same
// reason P3's peerbook records observations without scoring them.
type IssuerAgreement struct {
	IssuerID string
	// Comparable is how many of the issuer's attestations this node can check
	// against a first-hand measurement.
	Comparable int
	// Agreed and Disagreed partition Comparable by sign.
	Agreed    int
	Disagreed int
}

// AuditIssuer compares one issuer against this node's own measurements.
func (r *Reducer) AuditIssuer(issuerID string) IssuerAgreement {
	out := IssuerAgreement{IssuerID: issuerID}
	if r.FirstHand == nil {
		return out
	}
	r.mu.RLock()
	type pair struct {
		subject string
		dim     Dimension
		att     Attestation
	}
	var pairs []pair
	for subject, byDim := range r.attestations {
		for dim, byIssuer := range byDim {
			if a, ok := byIssuer[issuerID]; ok {
				pairs = append(pairs, pair{subject, dim, a})
			}
		}
	}
	r.mu.RUnlock()

	for _, p := range pairs {
		own, _, ok := r.FirstHand.FirstHand(p.subject, p.dim)
		if !ok {
			continue
		}
		out.Comparable++
		if disagrees(own, p.att.Value) {
			out.Disagreed++
		} else {
			out.Agreed++
		}
	}
	return out
}

// Subjects lists every subject held, for tests and for an operator.
func (r *Reducer) Subjects() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.attestations))
	for s := range r.attestations {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
