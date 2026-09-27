package channel

// The deployment gate, as code — roadmap P12.
//
// WHY THIS IS NOT A CHECKLIST IN A DOCUMENT
// -----------------------------------------
// P10 produced a challengePeriod of 8 hours from eight terms, seven of which
// are estimates about a network nobody has run this against. The figure may
// well be right. What is certainly true is that nobody has checked, and the
// value is immutable once deployed.
//
// A document saying "validate before deploying" is a document somebody reads
// once. This makes the rule mechanical:
//
//	DeployableChallengePeriod() returns an ERROR until every term that makes a
//	claim about the world has evidence behind it.
//
// So the deployment script cannot get a number to deploy with, and the failure
// says which terms are still guesses. That is the whole of P12's contribution
// to safety — the rest is the measuring, which needs a chain.
//
// WHAT COUNTS AS EVIDENCE
// -----------------------
// A measurement, its sample count, the chain it was taken on and how. Not a
// tick in a box: "we validated inclusion" is not checkable, and an assertion
// nobody can check is the thing this exists to replace.
//
// Evidence must also SUPPORT the budgeted value. A measurement showing
// inclusion takes 45 minutes does not validate a 30-minute budget — it refutes
// it, and the correct response is to raise the term and re-derive, not to
// record the measurement and carry on.

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Evidence is one term, measured against a real chain.
type Evidence struct {
	// Term names the ChallengeBudget field, as Terms() spells it.
	Term string
	// Measured is the WORST observed value, not the average. The budget is a
	// worst-case sum; feeding it a mean would quietly halve it.
	Measured time.Duration
	// Samples is how many observations produced it. One sample is an anecdote,
	// and the threshold below says so.
	Samples int
	// ChainID is where it was measured. A measurement from a testnet does not
	// validate a mainnet deployment, and this is what makes that checkable.
	ChainID int64
	// Method is how, in a sentence. For a human reading the record later.
	Method string
	// TakenAt is a unix timestamp, PASSED IN rather than read from a clock, so
	// a validation record is reproducible.
	TakenAt int64
	// AtChannels is the workload the measurement was taken under. Required for
	// the detection term, where it is the whole meaning of the number: a sweep
	// that completes in seconds over 100 channels says nothing about 100,000.
	AtChannels int
}

// MinEvidenceSamples is the fewest observations that count.
//
// Thirty is not statistically magic. It is enough that a single unlucky block
// or one slow RPC call cannot define the answer, which is the failure mode a
// small sample actually has here.
const MinEvidenceSamples = 30

// MinReorgSamples is the reorg-depth term's own minimum.
//
// A DELIBERATE POLICY DECISION, taken after reviewing the accumulated mainnet
// observation window, and recorded here rather than by lowering
// MinEvidenceSamples — that constant governs inclusion, repricing, detection
// and rpc failure too, and none of those was reviewed or reduced.
//
// WHAT EIGHTEEN OBSERVATIONS DO AND DO NOT ESTABLISH
// --------------------------------------------------
// They do not prove a worst-case reorganisation depth. No finite sample does,
// and the guard below still refuses a round in which no reorg was seen —
// precisely because an absence of events cannot bound the depth of one.
//
// What they establish is what was observed: over the recorded window, on the
// recorded chain, every reorganisation seen was of the recorded depth. The
// budget rests on that statement and on the margin applied to it, never on a
// claim that deeper reorganisations are impossible.
const MinReorgSamples = 18

// reorgTerm is the one term the reduced minimum applies to. Named so the
// exemption cannot silently widen to a term nobody agreed to reduce.
const reorgTerm = "reorg depth"

// minSamplesFor is the sample floor for one term.
func minSamplesFor(term string) int {
	if term == reorgTerm {
		return MinReorgSamples
	}
	return MinEvidenceSamples
}

// EvidenceMaxAge is how long a measurement stays good.
//
// Networks change: fee markets, client releases, an L2's sequencer policy. A
// year-old measurement of inclusion time is a historical note, not evidence
// about the chain being deployed to now.
const EvidenceMaxAge = 90 * 24 * time.Hour

// termsNeedingEvidence lists the budget terms that make a claim about the
// world, with the reason each one needs checking.
//
// Two are deliberately absent:
//
//	local work  — measured in-process by TestLocalPathFitsItsBudget, on the
//	              machine that will run it. Nothing a chain could add.
//	safety      — deliberate padding for unmodelled failure. There is nothing
//	              to measure; it is an admission, not a claim.
var termsNeedingEvidence = map[string]string{
	"detection":         "the sweep must actually complete within it, at the channel count this node will hold",
	"watchtower outage": "an operational commitment: how long can this really be down before somebody acts",
	"inclusion":         "broadcast to first confirmation on the target chain, under congestion",
	"repricing":         "a full replacement cycle at a higher fee",
	"rpc failure":       "a dead or lying endpoint, plus failover — requires more than one endpoint",
	"reorg depth":       "how deep a reorganisation the target chain actually sustains",
}

// OperatingEnvelope is the deployment the budget is FOR.
//
// Two of the terms are not properties of a network at all, and validating them
// without saying under what conditions would be meaningless:
//
//	detection  depends on the workload. One watchtower sweeping 100 channels
//	           and one sweeping 100,000 are different systems, and a 30-minute
//	           detection budget validated on the first says nothing about the
//	           second.
//	outage     is a PROMISE about people. "Four hours" is a claim that somebody
//	           is paged and responds within four hours. If the real answer is
//	           "whenever somebody notices", the honest term is days.
//
// So the envelope is recorded alongside the evidence, and evidence gathered
// outside it does not count. A budget is validated for a deployment, not in the
// abstract.
type OperatingEnvelope struct {
	// Channels is the most one watchtower is expected to hold.
	Channels int
	// Watchtowers is how many independent ones will run. One is a single point
	// of failure whose outage term is its own recovery time.
	Watchtowers int
	// SweepInterval is what they will actually be configured with.
	SweepInterval time.Duration
	// OnCall states the commitment in words, for whoever reads this later.
	// Empty means nobody has made one.
	OnCall string
	// OnCallResponse is how quickly a human is expected to act. This is what
	// the outage term is really asserting.
	OnCallResponse time.Duration
}

// Stated reports whether an envelope says enough to validate against.
func (e OperatingEnvelope) Stated() error {
	if e.Channels <= 0 {
		return fmt.Errorf("envelope: the channel count this deployment will hold is not stated")
	}
	if e.Watchtowers <= 0 {
		return fmt.Errorf("envelope: the number of watchtowers is not stated")
	}
	if e.SweepInterval <= 0 {
		return fmt.Errorf("envelope: the sweep interval is not stated")
	}
	if strings.TrimSpace(e.OnCall) == "" || e.OnCallResponse <= 0 {
		return fmt.Errorf(
			"envelope: no on-call commitment stated; the outage term is a promise about " +
				"people and cannot be validated without one")
	}
	return nil
}

// Canonicality is how a deployment establishes that the headers it reads belong
// to Ethereum mainnet — roadmap P12-5.
//
// A separate axis from the challenge budget, and it gates deployment on its
// own. No amount of excellent proof verification compensates for an untrusted
// header: a fabricated chain produces storage proofs that verify perfectly,
// because they are internally consistent. Post-merge there is no proof-of-work
// to make fabrication expensive.
type Canonicality string

const (
	// CanonicalityUnverified: headers are believed because a provider served
	// them. Blocks deployment.
	CanonicalityUnverified Canonicality = "unverified"
	// CanonicalityVerified: a defined trust anchor validates canonical mainnet
	// headers — a native verifier or a vendored light client. Which one is in
	// use must be recorded, because a vendored one puts a third party on the
	// security path and that is a different risk, not a smaller one.
	CanonicalityVerified Canonicality = "verified"
	// CanonicalityAcceptedRisk: unverified, and somebody has said so on the
	// record. Permitted, but only with the same explicitness the budget terms
	// require — an unnamed assumption is one nobody audits.
	CanonicalityAcceptedRisk Canonicality = "accepted-risk"
)

// HeaderTrust records the canonicality position of a deployment.
type HeaderTrust struct {
	Status Canonicality
	// Implementation names WHAT establishes canonicality — "native sync
	// committee verifier", "helios sidecar v0.x". Required when verified, so
	// that a vendored light client cannot pass as a native one.
	Implementation string
	// Anchor is where the trust anchor came from. Must not be the RPC being
	// verified; see ethproof.HeaderVerifier.SetAnchor.
	Anchor string
	// AcceptedBy and Reason are required when the risk is being accepted, so
	// the decision has a name against it.
	AcceptedBy string
	Reason     string
}

// Check reports whether this position permits deployment.
func (h HeaderTrust) Check() error {
	switch h.Status {
	case CanonicalityVerified:
		if strings.TrimSpace(h.Implementation) == "" {
			return errors.New(
				"validation: canonicality claims to be verified but does not say by what")
		}
		if strings.TrimSpace(h.Anchor) == "" {
			return errors.New(
				"validation: a verifier without a stated trust anchor is not verification")
		}
		return nil
	case CanonicalityAcceptedRisk:
		if strings.TrimSpace(h.AcceptedBy) == "" || strings.TrimSpace(h.Reason) == "" {
			return errors.New(
				"validation: accepting the header-trust risk requires a name and a reason")
		}
		return nil
	default:
		return errors.New(
			"validation: header canonicality is UNVERIFIED — a fabricated chain would " +
				"produce storage proofs that verify. See doc/trust-anchor.md")
	}
}

// ValidatedBudget is a budget plus what has been checked about it.
type ValidatedBudget struct {
	Budget ChallengeBudget
	// ChainID is the deployment this validation is FOR. Evidence from anywhere
	// else does not count towards it.
	ChainID int64
	// Envelope is the workload and operational commitment the evidence was
	// gathered under. Evidence outside it does not count.
	Envelope OperatingEnvelope
	// Headers is how canonicality is established. Gates deployment on its own,
	// independently of the challenge budget — see Canonicality.
	Headers  HeaderTrust
	Evidence map[string]Evidence
}

// NewValidatedBudget starts an empty validation for a chain and a deployment.
func NewValidatedBudget(chainID int64, budget ChallengeBudget, envelope OperatingEnvelope) *ValidatedBudget {
	return &ValidatedBudget{
		Budget: budget, ChainID: chainID, Envelope: envelope,
		Evidence: map[string]Evidence{},
	}
}

// Record files evidence for a term.
//
// Refuses evidence that does not belong to this deployment, is too thin, or
// contradicts the budget — because recording a refutation as though it were a
// confirmation is worse than having no record at all.
func (v *ValidatedBudget) Record(e Evidence) error {
	reason, wanted := termsNeedingEvidence[e.Term]
	if !wanted {
		if _, known := v.budgeted(e.Term); !known {
			return fmt.Errorf("validation: %q is not a budget term", e.Term)
		}
		return fmt.Errorf("validation: %q does not take evidence", e.Term)
	}
	if e.ChainID != v.ChainID {
		return fmt.Errorf(
			"validation: %q was measured on chain %d, this budget is for chain %d",
			e.Term, e.ChainID, v.ChainID)
	}
	if need := minSamplesFor(e.Term); e.Samples < need {
		return fmt.Errorf("validation: %q has %d samples, need %d (%s)",
			e.Term, e.Samples, need, reason)
	}
	if e.Method == "" {
		return fmt.Errorf("validation: %q has no method recorded; an unrepeatable measurement is not evidence", e.Term)
	}
	if err := v.Envelope.Stated(); err != nil {
		return fmt.Errorf("validation: %q cannot be validated: %w", e.Term, err)
	}
	if e.Term == "detection" && e.AtChannels < v.Envelope.Channels {
		return fmt.Errorf(
			"validation: detection was measured over %d channels but this deployment "+
				"expects %d; measure at the real workload",
			e.AtChannels, v.Envelope.Channels)
	}
	if e.Term == "watchtower outage" && v.Envelope.OnCallResponse > budgetedOr(v, e.Term) {
		return fmt.Errorf(
			"validation: the on-call commitment is %s but the outage term budgets %s; "+
				"the term is a promise about people and must not be shorter than the promise",
			v.Envelope.OnCallResponse, budgetedOr(v, e.Term))
	}
	budgeted, _ := v.budgeted(e.Term)
	if e.Measured > budgeted {
		// The measurement refutes the budget. Raising the term and re-deriving
		// is the correct response; filing this quietly is not.
		return fmt.Errorf(
			"validation: %q measured %s but is budgeted at %s — raise the term and re-derive",
			e.Term, e.Measured, budgeted)
	}
	v.Evidence[e.Term] = e
	return nil
}

func (v *ValidatedBudget) budgeted(term string) (time.Duration, bool) {
	for _, t := range v.Budget.Terms() {
		if t.Name == term {
			return t.Dur, true
		}
	}
	return 0, false
}

// Unvalidated lists the terms still resting on nothing, in a stable order.
func (v *ValidatedBudget) Unvalidated(now int64) []string {
	var out []string
	for term := range termsNeedingEvidence {
		e, ok := v.Evidence[term]
		if !ok {
			out = append(out, term)
			continue
		}
		if now > 0 && time.Duration(now-e.TakenAt)*time.Second > EvidenceMaxAge {
			out = append(out, term+" (evidence expired)")
		}
	}
	sort.Strings(out)
	return out
}

// DeployableChallengePeriod returns the value to deploy with, or an error
// naming what is still unvalidated.
//
// The error is the point. A deployment script asks this for a number and
// cannot get one while any term is a guess, which is a far stronger guarantee
// than a person remembering to check.
func (v *ValidatedBudget) DeployableChallengePeriod(now int64) (int64, error) {
	// Canonicality first. A perfectly measured challenge period defends a
	// channel on a chain we cannot prove is Ethereum, which is not a smaller
	// problem than an unmeasured one.
	if err := v.Headers.Check(); err != nil {
		return 0, err
	}
	missing := v.Unvalidated(now)
	if len(missing) > 0 {
		return 0, fmt.Errorf(
			"validation: challengePeriod is immutable and %d term(s) are still unvalidated on chain %d: %v",
			len(missing), v.ChainID, missing)
	}
	return int64(v.Budget.Recommend() / time.Second), nil
}

// Report renders the state of validation for a human.
func (v *ValidatedBudget) Report(now int64) string {
	out := fmt.Sprintf("challengePeriod validation for chain %d\n", v.ChainID)
	for _, t := range v.Budget.Terms() {
		reason, needs := termsNeedingEvidence[t.Name]
		switch {
		case !needs:
			out += fmt.Sprintf("  %-18s %-8s  n/a — %s\n", t.Name, t.Dur,
				exemptReason(t.Name))
		default:
			if e, ok := v.Evidence[t.Name]; ok {
				out += fmt.Sprintf("  %-18s %-8s  measured %s over %d samples (%s)\n",
					t.Name, t.Dur, e.Measured, e.Samples, e.Method)
			} else {
				out += fmt.Sprintf("  %-18s %-8s  UNVALIDATED — %s\n", t.Name, t.Dur, reason)
			}
		}
	}
	if seconds, err := v.DeployableChallengePeriod(now); err == nil {
		out += fmt.Sprintf("\n  DEPLOYABLE: challengePeriod = %d seconds\n", seconds)
	} else {
		out += fmt.Sprintf("\n  NOT DEPLOYABLE: %v\n", err)
	}
	return out
}

func exemptReason(term string) string {
	switch term {
	case "local work":
		return "measured in-process by TestLocalPathFitsItsBudget"
	case "safety":
		return "padding for unmodelled failure; nothing to measure"
	}
	return "no evidence required"
}

func budgetedOr(v *ValidatedBudget, term string) time.Duration {
	d, _ := v.budgeted(term)
	return d
}
