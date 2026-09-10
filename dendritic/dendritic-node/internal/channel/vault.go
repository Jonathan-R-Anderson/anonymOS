package channel

// State availability for a watchtower — roadmap P11.
//
// A watchtower can only submit a state it holds. P10 answered "how fast can a
// stale close be beaten"; this answers "with what", and the answer has to
// arrive continuously, from a party, to a service that is not one.
//
// THE INVARIANT: EVIDENCE, NOT AUTHORITY
// --------------------------------------
// A vault holds enough to DEFEND a channel and nothing that could be used to
// change it:
//
//	holds:      fully co-signed states, which anyone may verify and submit
//	never has:  a private key, the ability to alter a state, the ability to
//	            sign one, or any say in what a channel is worth
//
// This is not a matter of the vault choosing to behave. It is structural: the
// only thing it stores is a state both parties already signed, and the only
// thing it can do with one is hand it to a contract that checks those
// signatures. A hostile vault's entire power is to do nothing — which is what
// happens with no vault at all.
//
// So a party may hand their states to a stranger's watchtower and be no worse
// off than keeping them to themselves. That property is what makes the whole
// delegation model workable, and every check below exists to preserve it.
//
// WHY IT VERIFIES INSTEAD OF TRUSTING
// -----------------------------------
// "Here is the latest state" is a claim. A vault that stored claims would be a
// vault that could be filled with garbage by anyone who found its address, and
// would then have nothing to submit when it mattered.
//
// It cannot ask a party to vouch for a state — the party who submits it may be
// the one attacking. So the deposits and the parties come from the CHAIN, which
// is invariant P5-1 arriving at a third component for the same reason it
// applied to the first two: a channel's collateral is never established from
// peer-provided data.
//
// WHY IT ONLY EVER MOVES FORWARD
// ------------------------------
// A vault that accepted a lower nonce could be walked backwards by an attacker
// who replayed an old state just before closing on it. Monotonic per channel,
// strictly — which is the same rule the contract's `challenge` applies, and for
// the same reason.

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

var (
	// ErrStaleDeposit is returned when a submitted state is not newer than the
	// one already held. Not a failure: a party re-sending its latest state, or
	// two sources sending the same one, is the ordinary case.
	ErrStaleDeposit = errors.New("vault: not newer than the state already held")

	// ErrNotVerifiable is returned when a state cannot be checked at all —
	// usually because the chain does not know this channel.
	ErrNotVerifiable = errors.New("vault: cannot verify this state")
)

// VaultEntry is one channel's best known state, plus what was checked.
type VaultEntry struct {
	Channel [32]byte
	Signed  SignedState
	// PartyA and PartyB are from the CHAIN, not from the submission. Kept so a
	// later submission can be checked against them without another chain read.
	PartyA, PartyB     Address
	DepositA, DepositB *big.Int
	// Accepted counts submissions that advanced this entry, and Rejected those
	// that did not. An operator watching Rejected climb on one channel is
	// watching somebody probe the vault.
	Accepted, Rejected int
}

// Nonce is the state this entry would challenge with.
func (e VaultEntry) Nonce() uint64 { return e.Signed.State.Nonce }

// Vault stores co-signed states on behalf of parties who are not watching.
//
// Deliberately NOT a *Store. The store is a node's own record and is written by
// a participant; this is a third party's, is written by strangers, and must
// verify everything. Sharing the type would eventually share a code path, and
// the code path that trusts its input is the one that must not be reachable
// from here.
type Vault struct {
	// Chain is the authority on parties and deposits. Required: without it
	// nothing can be verified and the vault refuses everything, which is the
	// correct behaviour for a vault that cannot tell truth from noise.
	Chain    ChainReader
	Contract Address
	ChainID  *big.Int

	mu      sync.RWMutex
	entries map[[32]byte]*VaultEntry
	// backend is durable custody, optional. Without it the vault is in-memory
	// and a restart loses everything it was defending with — see vaultstore.go.
	backend VaultBackend
	aead    cipher.AEAD
}

// NewVault builds one.
func NewVault(chain ChainReader, chainID *big.Int, contract Address) *Vault {
	return &Vault{
		Chain: chain, ChainID: chainID, Contract: contract,
		entries: map[[32]byte]*VaultEntry{},
	}
}

// Submit verifies a state and keeps it if it beats what is held.
//
// Everything is checked, every time. The submitter is not identified and does
// not need to be: a valid state is valid whoever carried it, and an invalid one
// is refused whoever carried it. That is what lets this endpoint be open.
func (v *Vault) Submit(ctx context.Context, signed SignedState) (VaultEntry, error) {
	entry, err := v.submitVerified(ctx, signed)
	if err != nil {
		return entry, err
	}
	return entry, nil
}

// submitVerified is Submit's body, shared with Load.
//
// Load goes through exactly this path rather than a shortcut for records the
// vault wrote itself: same verification, same chain read, same monotonic rule.
// A "trusted" path for one's own storage is how a store quietly becomes an
// authority.
func (v *Vault) submitVerified(ctx context.Context, signed SignedState) (VaultEntry, error) {
	if v.Chain == nil {
		return VaultEntry{}, fmt.Errorf("%w: no chain reader", ErrNotVerifiable)
	}
	id := signed.State.Channel

	// 1. Shape. Cheap, and it fails for a reason a log can act on.
	if !signed.Complete() {
		return VaultEntry{}, errors.New("vault: a state must carry both signatures")
	}

	// 2. The chain. Parties and deposits from the contract, never from the
	//    submission — the submitter may be the attacker.
	v.mu.RLock()
	held := v.entries[id]
	v.mu.RUnlock()

	var onChain OnChainChannel
	if held == nil {
		var err error
		onChain, err = v.Chain.ReadChannel(ctx, v.Contract, id)
		if err != nil {
			return VaultEntry{}, fmt.Errorf("%w: %v", ErrNotVerifiable, err)
		}
	} else {
		// Already established for this channel. Re-reading on every submission
		// would let anyone with the address make this vault hammer its RPC.
		onChain = OnChainChannel{
			ID: id, PartyA: held.PartyA, PartyB: held.PartyB,
			DepositA: held.DepositA, DepositB: held.DepositB,
		}
	}

	// 3. Ordering, before the expensive checks. Strictly greater, matching the
	//    contract: an equal nonce is not better, and accepting a lower one would
	//    let an attacker walk this vault backwards before closing on it.
	if held != nil && signed.State.Nonce <= held.Nonce() {
		v.mu.Lock()
		held.Rejected++
		v.mu.Unlock()
		return *held, fmt.Errorf("%w: held %d, offered %d",
			ErrStaleDeposit, held.Nonce(), signed.State.Nonce)
	}

	// 4. Conservation, against the CHAIN's deposits. A state that creates value
	//    is one the contract would refuse, so holding it would mean holding
	//    something unusable and believing otherwise.
	if !signed.State.Conserved(onChain.DepositA, onChain.DepositB) {
		return VaultEntry{}, errors.New("vault: the state does not conserve the deposited value")
	}

	// 5. The digest, rebuilt from the parts — which covers the nonce, both
	//    balances, the lock root and the withdrawals in one step, because all of
	//    them are inside it. Then both signatures, each to the party the CHAIN
	//    named.
	digest := signed.State.Digest(v.ChainID, v.Contract)
	if err := requireBothParties(digest, signed, onChain.PartyA, onChain.PartyB); err != nil {
		return VaultEntry{}, err
	}

	// Persist BEFORE activating. Crashing between them leaves a state in the
	// store that memory has not adopted, and Load finds it; the reverse order
	// leaves a vault claiming a state it cannot produce, which nobody discovers
	// until a channel needed defending and was not.
	//
	// So a storage failure is a submission failure. Telling the submitter their
	// state was accepted when this vault cannot keep it is the one outcome that
	// must not happen.
	if err := v.persist(ctx, signed); err != nil {
		return VaultEntry{}, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	entry := v.entries[id]
	if entry == nil {
		entry = &VaultEntry{
			Channel: id, PartyA: onChain.PartyA, PartyB: onChain.PartyB,
			DepositA: onChain.DepositA, DepositB: onChain.DepositB,
		}
		v.entries[id] = entry
	} else if signed.State.Nonce <= entry.Nonce() {
		// Another submission won the race between the check above and this
		// lock. Losing it is correct: the higher state is already held.
		entry.Rejected++
		return *entry, fmt.Errorf("%w: held %d, offered %d",
			ErrStaleDeposit, entry.Nonce(), signed.State.Nonce)
	}
	entry.Signed = cloneSigned(signed)
	entry.Accepted++
	return *entry, nil
}

// requireBothParties checks a digest carries both parties' signatures.
//
// Both, and each to the right side. One signature proves somebody PROPOSED a
// state; value moves when both agree, and the contract will only honour a state
// where both did.
func requireBothParties(digest [32]byte, signed SignedState, partyA, partyB Address) error {
	gotA, err := RecoverSigner(digest, signed.SigA)
	if err != nil {
		return fmt.Errorf("vault: signature A is unreadable: %w", err)
	}
	gotB, err := RecoverSigner(digest, signed.SigB)
	if err != nil {
		return fmt.Errorf("vault: signature B is unreadable: %w", err)
	}
	if gotA != partyA {
		return fmt.Errorf("vault: signature A is %s, not party A %s", gotA, partyA)
	}
	if gotB != partyB {
		return fmt.Errorf("vault: signature B is %s, not party B %s", gotB, partyB)
	}
	return nil
}

// Best returns the state this vault would challenge a channel with.
func (v *Vault) Best(id [32]byte) (SignedState, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	entry, ok := v.entries[id]
	if !ok {
		return SignedState{}, false
	}
	return cloneSigned(entry.Signed), true
}

// Entry returns what is held for a channel, for an operator or a status page.
func (v *Vault) Entry(id [32]byte) (VaultEntry, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	entry, ok := v.entries[id]
	if !ok {
		return VaultEntry{}, false
	}
	return *entry, true
}

// IDs lists every channel with something held.
func (v *Vault) IDs() [][32]byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([][32]byte, 0, len(v.entries))
	for id := range v.entries {
		out = append(out, id)
	}
	return out
}

// ---- serving a vault to a watchtower ----------------------------------------

// VaultStore adapts a Vault to what a Watchtower reads.
//
// The watchtower was written against a node's own store, because in the simple
// case a recipient defends its own channels. A vault defends somebody else's,
// and this is the whole difference — which is the point: the watchtower did not
// have to learn about vaults, and a vault did not have to become a store.
type VaultStore struct{ Vault *Vault }

// IDs lists the channels to sweep.
func (v VaultStore) IDs() [][32]byte { return v.Vault.IDs() }

// Get returns a channel shaped as the watchtower expects.
//
// Only the fields the watchtower reads are populated, and that is deliberate: a
// Channel assembled here must never be mistaken for one a node owns. It carries
// no key, no pending proposal and no history, because a vault has none of those
// things and manufacturing empty ones would make it look as though it did.
func (v VaultStore) Get(id [32]byte) (*Channel, bool) {
	entry, ok := v.Vault.Entry(id)
	if !ok {
		return nil, false
	}
	return &Channel{
		ID: id, PartyA: entry.PartyA, PartyB: entry.PartyB,
		DepositA: entry.DepositA, DepositB: entry.DepositB,
		ChainID: v.Vault.ChainID, Contract: v.Vault.Contract,
		Latest: entry.Signed,
	}, true
}
