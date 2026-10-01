package channel

// The volunteer's delegate signer — roadmap P15, Mode B.
//
// WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT
// ---------------------------------------------
// A recipient who wants tips to land while they are asleep authorises a
// volunteer ON CHAIN (ChannelManagerV2.setDelegate) to co-sign ordinary states
// for them. This type is the node's side of that: a key, and a refusal to use
// it for anything the chain would not accept.
//
//	recipient's wallet ──setDelegate(volunteer, expiry, OP_STATE)──► contract
//	                                                                    │
//	volunteer node ──signs OP_STATE only──────────────────────────────►─┘
//
// THE AUTHORIZATION IS NOT REIMPLEMENTED HERE. The contract decides what a
// delegate may do; `_maySign` is the only judge and it runs on chain. What this
// file adds is a node that refuses EARLY rather than producing a signature the
// chain will reject — a courtesy, not a security boundary, and it is important
// to keep those apart. If this check and the contract ever disagree, the
// contract is right.
//
// NEVER THE RECIPIENT'S WALLET KEY
// --------------------------------
// The delegate key signs states. It is not the recipient's wallet, it receives
// nothing, and every payout in the contract goes to the channel party. A node
// that treated the two as interchangeable would be reintroducing exactly the
// custody this design removes, so the type keeps the recipient's ADDRESS and
// never a key for it.

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

var (
	// ErrNotDelegated means this node holds no delegate authority for that
	// recipient — or holds one the chain no longer honours.
	ErrNotDelegated = errors.New("delegate: this node is not an active delegate for that recipient")
	// ErrOperationNotDelegated means the state is one this delegate may not
	// sign. Checkpoints and cooperative closes are never delegated.
	ErrOperationNotDelegated = errors.New("delegate: that operation is not delegated")
)

// DelegateAuthority answers, from the chain, whether this node may sign.
//
// An interface with one method so the node cannot be tempted to cache the
// answer: a delegation can be revoked at any moment and a node that remembered
// "yes" would keep signing states the contract has already stopped accepting.
type DelegateAuthority interface {
	// CanSign mirrors ChannelManagerV2.canSign(party, signer, op).
	CanSign(ctx context.Context, contract, party, signer Address, op uint8) (bool, error)
}

// DelegateSigner signs OP_STATE on behalf of recipients that authorized it.
type DelegateSigner struct {
	// Address is this delegate's own address — the one the recipient named in
	// setDelegate. NOT a recipient address, and never a party to anything.
	Address Address
	// Sign produces a signature over a raw digest with the delegate key.
	Sign StateSigner
	// Authority is the chain. Required: without it there is no way to know
	// whether an authorization is still live, and assuming it is would be the
	// one assumption this design cannot make.
	Authority DelegateAuthority
	// Contract is the ChannelManagerV2 the delegation lives in.
	Contract Address

	mu sync.Mutex
	// served is who this node believes it is a delegate for. Advisory only —
	// every signature still asks the chain.
	served map[Address]struct{}
}

// NewDelegateSigner wires one. It refuses to exist without an authority, for
// the same reason NewAPI refuses to exist without a token.
func NewDelegateSigner(addr Address, sign StateSigner, authority DelegateAuthority,
	contract Address) (*DelegateSigner, error) {

	if sign == nil {
		return nil, errors.New("delegate: refusing to run without a signing key")
	}
	if authority == nil {
		return nil, errors.New("delegate: refusing to run without a chain to ask")
	}
	return &DelegateSigner{
		Address: addr, Sign: sign, Authority: authority, Contract: contract,
		served: make(map[Address]struct{}),
	}, nil
}

// Adopt records that a recipient has (or claims to have) delegated to this node.
//
// Checked against the chain immediately rather than taken on the recipient's
// word, so an operator sees the refusal at configuration time instead of
// discovering it when the first tip fails.
func (d *DelegateSigner) Adopt(ctx context.Context, recipient Address) error {
	ok, err := d.Authority.CanSign(ctx, d.Contract, recipient, d.Address, OpState)
	if err != nil {
		return fmt.Errorf("delegate: could not read the delegation: %w", err)
	}
	if !ok {
		return ErrNotDelegated
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.served[recipient] = struct{}{}
	return nil
}

// Forget drops a recipient locally. Revocation itself is the recipient's
// on-chain act; this only stops the node offering to act.
func (d *DelegateSigner) Forget(recipient Address) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.served, recipient)
}

// Serves reports whether this node has adopted a recipient. Local belief, not
// authority — SignState re-asks the chain regardless.
func (d *DelegateSigner) Serves(recipient Address) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.served[recipient]
	return ok
}

// SignState signs a state on a recipient's behalf.
//
// Two refusals, in this order, and the order matters:
//
//  1. the operation must be OP_STATE — checked from the STATE ITSELF, not from
//     anything a caller said it was, so a checkpoint cannot be relabelled into
//     something signable;
//  2. the chain must still say this delegation is live — asked every time,
//     because revocation is instant and a cached yes is a signature the
//     recipient has already withdrawn consent for.
func (d *DelegateSigner) SignState(ctx context.Context, recipient Address,
	chainID *big.Int, contract Address, state State) ([]byte, error) {

	// The domain comes off the state, so a state carrying withdrawals cannot be
	// presented as an ordinary payment: Apply set the domain and the digest
	// covers it.
	if state.op() != OpState {
		return nil, fmt.Errorf("%w: domain %d", ErrOperationNotDelegated, state.op())
	}
	// Belt and braces on the same point. A state with a withdrawal is a
	// checkpoint whatever its domain claims, and this node signs neither.
	if orZero(state.WithdrawA).Sign() > 0 || orZero(state.WithdrawB).Sign() > 0 {
		return nil, fmt.Errorf("%w: the state withdraws value", ErrOperationNotDelegated)
	}

	ok, err := d.Authority.CanSign(ctx, d.Contract, recipient, d.Address, OpState)
	if err != nil {
		return nil, fmt.Errorf("delegate: could not confirm the delegation: %w", err)
	}
	if !ok {
		// Revoked, expired, or never granted. The node stops believing it too,
		// so an operator's console reflects reality rather than its last hope.
		d.Forget(recipient)
		return nil, ErrNotDelegated
	}

	return d.Sign(state.Digest(chainID, contract))
}

// RPCDelegateAuthority reads canSign from a live contract.
type RPCDelegateAuthority struct {
	Chain ChainReader
}

// CanSign asks ChannelManagerV2. Note there is no cache and no fallback: if the
// chain cannot be reached the answer is an error, never an optimistic yes.
func (r RPCDelegateAuthority) CanSign(ctx context.Context, contract, party, signer Address,
	op uint8) (bool, error) {

	caller, ok := r.Chain.(interface {
		CallCanSign(ctx context.Context, contract, party, signer Address, op uint8) (bool, error)
	})
	if !ok {
		return false, errors.New("delegate: this chain reader cannot query canSign")
	}
	return caller.CallCanSign(ctx, contract, party, signer, op)
}
