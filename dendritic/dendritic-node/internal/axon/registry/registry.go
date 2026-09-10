// Package registry is the grammar-to-chain binding: it turns a normalised name
// into the claim a contract enforces, and models the acquisition rules of
// §12.4a so they can be tested before any contract is deployed.
//
// NOTHING HERE TALKS TO A CHAIN. The registry, the registrar and the token are
// undeployed -- AxonToken.sol is written, the registry is not written at all --
// so this package is the specification the contract must mirror, expressed in a
// form that can be executed and tested today. Where a rule is enforced on chain
// (§12.3), the comment says so, and the Go copy exists to be compared against
// it, not to substitute for it.
package registry

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/name"
)

var (
	ErrNotRegistrable  = errors.New("axon/registry: only a registrable name has an on-chain claim")
	ErrLabelRefused    = errors.New("axon/registry: label refused by the registry rules")
	ErrConfusableHeld  = errors.New("axon/registry: confusable skeleton is held by another owner")
	ErrCommitUnknown   = errors.New("axon/registry: no commitment for that reveal")
	ErrCommitTooYoung  = errors.New("axon/registry: commitment has not aged")
	ErrCommitExpired   = errors.New("axon/registry: commitment has expired")
	ErrRevealRateLimit = errors.New("axon/registry: reveal rate limit reached for this block")
	ErrAlreadyHeld     = errors.New("axon/registry: name is held and not expired")
	ErrNotOwner        = errors.New("axon/registry: caller does not hold the name")
	ErrBondTooSmall    = errors.New("axon/registry: bond below the required amount")
)

// Account is an acquirer. Opaque: the registry never learns anything about it
// beyond the fact that transactions came from it, and §12.3 is explicit that
// this does NOT make ownership anonymous.
type Account [20]byte

// Claim is a name's on-chain identity.
//
// It carries the NAME HASH and not the name. The contract stores a hash because
// storing the string would put every registered name in calldata forever for no
// benefit -- the chain is already public, and §7.7 concedes enumeration, but
// there is no reason to make it cheaper than it has to be.
type Claim struct {
	NameHash [32]byte
	// Skeleton is the confusable representative (§11.3.3), stored so the
	// registry can refuse a label whose skeleton another owner holds.
	Skeleton [32]byte
}

// ClaimFor derives the on-chain claim for a normalised name.
//
// It refuses anything but a registrable name: subordinate labels are delegated
// off chain and have a zone id, not a claim. That refusal is the grammar-to-chain
// boundary, and it is the one place the two hash functions meet -- keccak for the
// chain, SHA-256 for the overlay (§11.3.2).
func ClaimFor(n name.Name) (Claim, error) {
	if !n.IsRegistrable() {
		return Claim{}, fmt.Errorf("%w: %q", ErrNotRegistrable, n)
	}
	nh, err := n.NameHash()
	if err != nil {
		return Claim{}, err
	}
	// The skeleton is hashed under the SAME scheme as the name, so the contract
	// can compare skeletons without ever holding a label.
	skelName, err := name.Normalise(
		name.Skeleton(n.Registrable()) + "." + n.Namespace() + "." + n.Root())
	if err != nil {
		// A skeleton that does not itself normalise cannot be compared. That is
		// a refusal, not a fallback: silently skipping the check would make the
		// confusable rule depend on the shape of the input.
		return Claim{}, fmt.Errorf("%w: skeleton of %q is not a valid label: %v",
			ErrLabelRefused, n.Registrable(), err)
	}
	sh, err := skelName.NameHash()
	if err != nil {
		return Claim{}, err
	}
	return Claim{NameHash: nh, Skeleton: sh}, nil
}

// Registration is a held name.
type Registration struct {
	Claim    Claim
	Owner    Account
	Acquired time.Time
	Expires  time.Time
	// Bond is the capital locked by this registration (§12.4a). Released on
	// transfer or expiry, never on demand.
	Bond *big.Int
}

// Held reports whether the registration is live at t.
func (r Registration) Held(t time.Time) bool { return t.Before(r.Expires) }

// -----------------------------------------------------------------------------
// Acquisition (§12.4a)
// -----------------------------------------------------------------------------

// Route is how a name was acquired. There are exactly two, and no third.
type Route uint8

const (
	// RoutePrimary is first issuance, from the DAO.
	RoutePrimary Route = iota + 1
	// RouteSecondary is transfer from the current owner.
	RouteSecondary
)

func (r Route) String() string {
	if r == RouteSecondary {
		return "secondary"
	}
	return "primary"
}

// Valid reports whether a route was actually chosen. The zero value is not a
// route: a registration that did not say how it was acquired has not said
// anything.
func (r Route) Valid() bool { return r == RoutePrimary || r == RouteSecondary }

// Policy holds the acquisition parameters.
//
// EVERY VALUE HERE IS `[NEEDS RESEARCH]` AND NONE IS DEFENSIBLE YET. They exist
// so the mechanism can be exercised and its shape tested; §12.4a says the decay
// curve in particular "decides whether this is a squatting deterrent or a tax on
// ordinary transfer, and it cannot be picked from an armchair".
type Policy struct {
	// BasePrice is the primary-issuance price for a 6+ character label.
	BasePrice *big.Int
	// LengthMultiplier maps label length to a multiple of BasePrice.
	LengthMultiplier map[int]int64
	// Term is one registration period.
	Term time.Duration
	// BondPerName is locked at registration and released on transfer or expiry.
	BondPerName *big.Int

	// TransferLevyBps is the DAO's share of a secondary sale, in basis points,
	// at zero holding time. §12.4a's load-bearing member: it prices the EXIT,
	// which is the one thing a squatter cannot split.
	TransferLevyBps int64
	// LevyHalfLife is how long holding halves the levy. A squatter selling
	// within months forfeits most of the spread; a genuine holder selling after
	// years does not.
	LevyHalfLife time.Duration

	// EpochBurstFree is how many names one account may take in an epoch before
	// the superlinear surcharge starts.
	EpochBurstFree int
	// EpochLength bounds the burst window.
	EpochLength time.Duration

	// RevealsPerBlock caps reveals per account per block, turning a dictionary
	// into a queue.
	RevealsPerBlock int
	// CommitMinAge and CommitMaxAge bound a commitment's validity.
	CommitMinAge, CommitMaxAge time.Duration
}

// PriceOf is the primary-issuance price for a label.
//
// Denominated in the network token (§12.4a), which supersedes §12.4's ETH
// ruling. The circularity that ruling objected to is an accepted cost, not an
// oversight.
func (p Policy) PriceOf(label string) *big.Int {
	mult, ok := p.LengthMultiplier[len(label)]
	if !ok {
		mult = 1
	}
	return new(big.Int).Mul(p.BasePrice, big.NewInt(mult))
}

// BurstSurcharge is the superlinear cost of the n-th name an account takes
// within one epoch.
//
// It is kept despite §12.4a.1's negative result -- a prepared adversary splits
// across accounts and pays nothing extra -- because it costs an UNPREPARED
// adversary something and costs an honest registrant, who takes one name,
// exactly nothing. It is not load-bearing and must not be described as though it
// were.
func (p Policy) BurstSurcharge(base *big.Int, nthInEpoch int) *big.Int {
	if nthInEpoch <= p.EpochBurstFree {
		return new(big.Int).Set(base)
	}
	over := int64(nthInEpoch - p.EpochBurstFree)
	// Quadratic in the overage: the 1st extra costs 2x, the 2nd 5x, the 3rd 10x.
	mult := big.NewInt(over*over + 1)
	return new(big.Int).Mul(base, mult)
}

// TransferLevy is the DAO's cut of a secondary sale, decaying with holding time.
//
// THIS IS THE GUARD. §12.4a.2: per-acquirer counters price the ACT of
// registering and are defeated by splitting; a levy prices the EXIT, and there
// is nothing to split because the tax attaches to the name's transfer rather
// than to anyone's identity.
//
// It is close to free for the legitimate holder, who rarely sells, which is the
// discrimination every other mechanism failed to achieve.
func (p Policy) TransferLevy(salePrice *big.Int, held time.Duration) *big.Int {
	if salePrice == nil || salePrice.Sign() <= 0 || p.TransferLevyBps <= 0 {
		return big.NewInt(0)
	}
	bps := big.NewInt(p.TransferLevyBps)
	if p.LevyHalfLife > 0 && held > 0 {
		// Halve per half-life, integer-only so the contract can reproduce it
		// exactly -- a levy computed with floating point on chain is a levy two
		// implementations disagree about.
		halvings := int64(held / p.LevyHalfLife)
		if halvings > 62 {
			return big.NewInt(0)
		}
		bps.Rsh(bps, uint(halvings))
	}
	out := new(big.Int).Mul(salePrice, bps)
	return out.Div(out, big.NewInt(10_000))
}

// LevyFreeAfter is how long a holder must keep a name for the levy to reach
// zero basis points, for a caller that wants to state the number plainly.
func (p Policy) LevyFreeAfter() time.Duration {
	if p.TransferLevyBps <= 0 || p.LevyHalfLife <= 0 {
		return 0
	}
	n := 0
	for bps := p.TransferLevyBps; bps > 0; bps >>= 1 {
		n++
	}
	return time.Duration(n) * p.LevyHalfLife
}
