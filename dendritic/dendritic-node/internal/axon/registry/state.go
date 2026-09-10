package registry

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// The registry's state machine: commit-reveal, the reveal-rate limit, the
// confusable check and the bond.
//
// This mirrors §12.3's contract. Where the two could disagree, the CONTRACT is
// the authority and this is the specification it must satisfy -- which is the
// only defensible arrangement while the contract is unwritten.

// Commitment is a hashed intent to register.
//
// commit = SHA-256(nameHash ‖ owner ‖ secret). The name never appears until the
// reveal, which is what stops an observer front-running the registration.
type Commitment [32]byte

// MakeCommitment computes the commitment for an intent.
func MakeCommitment(c Claim, owner Account, secret [32]byte) Commitment {
	h := sha256.New()
	h.Write(c.NameHash[:])
	h.Write(owner[:])
	h.Write(secret[:])
	var out Commitment
	copy(out[:], h.Sum(nil))
	return out
}

// Registry is the in-memory model of the contract's state.
type Registry struct {
	mu sync.Mutex

	policy Policy
	now    func() time.Time

	names       map[[32]byte]*Registration
	skeletons   map[[32]byte]Account
	commitments map[Commitment]time.Time

	// epochTakes counts registrations per account per epoch, for the burst
	// surcharge.
	epochTakes map[Account]map[int64]int
	// blockReveals counts reveals per account per block height.
	blockReveals map[Account]map[uint64]int

	// levyPool is the DAO's accumulated take. Held here so a test can assert
	// the guard actually collects rather than merely computing a number.
	levyPool *big.Int
}

// New builds an empty registry.
func New(p Policy, now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{
		policy: p, now: now,
		names:        map[[32]byte]*Registration{},
		skeletons:    map[[32]byte]Account{},
		commitments:  map[Commitment]time.Time{},
		epochTakes:   map[Account]map[int64]int{},
		blockReveals: map[Account]map[uint64]int{},
		levyPool:     big.NewInt(0),
	}
}

// LevyPool is the DAO's accumulated transfer levy.
func (r *Registry) LevyPool() *big.Int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return new(big.Int).Set(r.levyPool)
}

// Commit records an intent.
func (r *Registry) Commit(c Commitment) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commitments[c] = r.now()
}

// Register reveals a commitment and takes the name.
//
// Returns the price actually paid, which is the base price plus any burst
// surcharge. The bond is separate and is LOCKED, not spent.
func (r *Registry) Register(claim Claim, owner Account, secret [32]byte,
	label string, bond *big.Int, block uint64) (*big.Int, error) {

	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()

	// 1. Reveal-rate limit FIRST, before any state is read. A dictionary sweep
	//    must be stopped before it can cost the registry a lookup per word.
	if r.policy.RevealsPerBlock > 0 {
		byBlock := r.blockReveals[owner]
		if byBlock == nil {
			byBlock = map[uint64]int{}
			r.blockReveals[owner] = byBlock
		}
		if byBlock[block] >= r.policy.RevealsPerBlock {
			return nil, fmt.Errorf("%w: %d reveals in block %d",
				ErrRevealRateLimit, byBlock[block], block)
		}
		byBlock[block]++
	}

	// 2. The commitment must exist and be the right age.
	com := MakeCommitment(claim, owner, secret)
	at, ok := r.commitments[com]
	if !ok {
		return nil, ErrCommitUnknown
	}
	age := now.Sub(at)
	if age < r.policy.CommitMinAge {
		return nil, fmt.Errorf("%w: %s < %s", ErrCommitTooYoung, age, r.policy.CommitMinAge)
	}
	if r.policy.CommitMaxAge > 0 && age > r.policy.CommitMaxAge {
		return nil, fmt.Errorf("%w: %s > %s", ErrCommitExpired, age, r.policy.CommitMaxAge)
	}

	// 3. The name must be free.
	if held, ok := r.names[claim.NameHash]; ok && held.Held(now) {
		return nil, ErrAlreadyHeld
	}

	// 4. The confusable skeleton must not be held by ANOTHER owner (§11.3.3).
	//    Held by the same owner is fine and is the point: defensive registration
	//    of your own variants must be affordable.
	if h, taken := r.skeletons[claim.Skeleton]; taken && h != owner {
		return nil, fmt.Errorf("%w: skeleton held by %x", ErrConfusableHeld, h[:4])
	}

	// 5. The bond.
	if r.policy.BondPerName != nil && r.policy.BondPerName.Sign() > 0 {
		if bond == nil || bond.Cmp(r.policy.BondPerName) < 0 {
			return nil, fmt.Errorf("%w: need %s", ErrBondTooSmall, r.policy.BondPerName)
		}
	}

	// 6. Price, including the burst surcharge.
	epoch := int64(0)
	if r.policy.EpochLength > 0 {
		epoch = now.Unix() / int64(r.policy.EpochLength/time.Second)
	}
	takes := r.epochTakes[owner]
	if takes == nil {
		takes = map[int64]int{}
		r.epochTakes[owner] = takes
	}
	takes[epoch]++
	price := r.policy.BurstSurcharge(r.policy.PriceOf(label), takes[epoch])

	delete(r.commitments, com)
	r.names[claim.NameHash] = &Registration{
		Claim: claim, Owner: owner, Acquired: now,
		Expires: now.Add(r.policy.Term), Bond: new(big.Int).Set(bond),
	}
	r.skeletons[claim.Skeleton] = owner
	return price, nil
}

// Transfer moves a name to a new owner and takes the DAO's levy.
//
// This is the SECONDARY route, and it is the only one. §12.4a permits exactly
// two ways to acquire a name and this is the second; there is no path that moves
// a name without passing through here, which is what makes the levy
// unavoidable.
func (r *Registry) Transfer(nameHash [32]byte, from, to Account, salePrice *big.Int) (levy *big.Int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()

	reg, ok := r.names[nameHash]
	if !ok || !reg.Held(now) {
		return nil, ErrAlreadyHeld
	}
	if reg.Owner != from {
		return nil, ErrNotOwner
	}

	held := now.Sub(reg.Acquired)
	levy = r.policy.TransferLevy(salePrice, held)
	r.levyPool.Add(r.levyPool, levy)

	reg.Owner = to
	// Holding time resets on transfer: the new owner has not held it, and a
	// levy that inherited the previous holder's clock would let a squatter
	// launder the decay by selling to themselves.
	reg.Acquired = now
	r.skeletons[reg.Claim.Skeleton] = to
	return levy, nil
}

// Owner returns the current holder.
func (r *Registry) Owner(nameHash [32]byte) (Account, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	reg, ok := r.names[nameHash]
	if !ok || !reg.Held(r.now()) {
		return Account{}, false
	}
	return reg.Owner, true
}

// Count is the number of live registrations.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, reg := range r.names {
		if reg.Held(r.now()) {
			n++
		}
	}
	return n
}
