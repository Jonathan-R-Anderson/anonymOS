package channel

// The channel state that both a direct tip and a routed one agree on, in
// exactly the form ChannelManager verifies.
//
// WHY THIS IS SEPARATE FROM native.go's channelState
// --------------------------------------------------
// That struct is a NODE'S VIEW: outbound, inbound, "what I can still send".
// Useful locally and wrong as a settlement record, because the chain has no
// concept of "me". On chain there is party A, party B, and two balances, and
// which of the two you are is decided by your address, not your role.
//
// A state that cannot be handed to the contract verbatim is not a state, it is
// a note about one. This type is the handable form.
//
// THE ORDERING TRAP
// -----------------
// ChannelManager sorts: partyA is the NUMERICALLY LOWER address, partyB the
// higher, in both channelId() and openChannel(). It is never "the opener" or
// "the tipper". Code that assumes the tipper is A pays the wrong party for
// roughly half of all address pairs, and does so silently — the signatures
// verify, the conservation check passes, and the money goes backwards.
//
// So balances are stored as A/B, exactly as the chain holds them, and roles are
// resolved through the address ordering every time they are needed. There is no
// "tipper balance" field to get wrong.
//
// WHY BALANCES ARE *big.Int AND NOT Amount
// ----------------------------------------
// Amount is int64. On-chain balances are uint256 wei, and one gold award is
// 100 * 1e18 = 1e20 — an order of magnitude past int64's ~9.2e18 ceiling. An
// int64 here would not merely truncate the top tier, it would wrap it. The same
// hazard as the browser computing wei in floating point, which services/
// post_awards.py already avoids by pricing tiers server-side.
//
// Amount stays for the local accounting the Adapter interface speaks. Anything
// that will be shown to the contract is *big.Int.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

var (
	ErrBadAddress        = errors.New("channel: malformed address")
	ErrBadStateSignature = errors.New("channel: state signature does not recover to the expected party")
	ErrHighS             = errors.New("channel: signature has a high s value")
	ErrNotConserved      = errors.New("channel: balances do not conserve the deposits")
	ErrNegative          = errors.New("channel: negative amount")
	ErrWrongChannel      = errors.New("channel: state belongs to a different channel")
	ErrDuplicateHTLC     = errors.New("channel: duplicate HTLC identifier")
	ErrHTLCExpiryPast    = errors.New("channel: HTLC expires in the past")
	ErrNotOpen           = errors.New("channel: channel is not open")
)

// Address is an Ethereum account.
type Address [20]byte

// ParseAddress reads "0x…" or bare hex.
func ParseAddress(s string) (Address, error) {
	var a Address
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 20 {
		return a, ErrBadAddress
	}
	copy(a[:], raw)
	return a, nil
}

func (a Address) Hex() string { return "0x" + hex.EncodeToString(a[:]) }

// Less orders addresses the way the contract does: as big-endian integers.
func (a Address) Less(b Address) bool { return bytes.Compare(a[:], b[:]) < 0 }

// IsZero reports the zero address, which ecrecover returns on failure and which
// is therefore never a legitimate party.
func (a Address) IsZero() bool { return a == Address{} }

// SortParties returns the pair in the contract's A, B order.
func SortParties(x, y Address) (Address, Address) {
	if x.Less(y) {
		return x, y
	}
	return y, x
}

func keccak(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// word left-pads to the 32 bytes abi.encode uses for every value, whatever its
// declared width. uint64 and address are padded here exactly as Solidity pads
// them; getting this wrong produces a digest that verifies nowhere.
func word(b []byte) []byte {
	out := make([]byte, 32)
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	copy(out[32-len(b):], b)
	return out
}

func u256(n *big.Int) []byte {
	if n == nil {
		return make([]byte, 32)
	}
	return word(n.Bytes())
}

func u64(n uint64) []byte { return word(new(big.Int).SetUint64(n).Bytes()) }

// DeriveChannelID reproduces ChannelManager.channelId: keccak256 over the
// sorted pair, so open(a,b) and open(b,a) name the same channel. Without the
// sort a pair could hold two channels and each party could settle whichever
// suited them.
func DeriveChannelID(x, y Address) [32]byte {
	a, b := SortParties(x, y)
	var id [32]byte
	copy(id[:], keccak(word(a[:]), word(b[:])))
	return id
}

// StateDigestV1 reproduces the DEPLOYED ChannelManager's stateDigest:
//
//	keccak256(abi.encode(block.chainid, address(this), id, nonce, balanceA, balanceB))
//
// Kept because it is the only encoding in this package that has been checked
// against a real chain, which makes it the anchor for the one below: V2 adds a
// single word using the same machinery, so if this matches mainnet and V2
// matches the compiler, both are right.
//
// Nothing signs with this. Use StateDigest.
func StateDigestV1(chainID *big.Int, contract Address, id [32]byte,
	nonce uint64, balanceA, balanceB *big.Int) [32]byte {

	var out [32]byte
	copy(out[:], keccak(
		u256(chainID),
		word(contract[:]),
		id[:],
		u64(nonce),
		u256(balanceA),
		u256(balanceB),
	))
	return out
}

// StateDigest reproduces ChannelManagerV2.stateDigest exactly:
//
//	keccak256(abi.encode(block.chainid, address(this), id, nonce, balanceA, balanceB, htlcRoot))
//
// The chain id and the contract address are inside the digest on purpose: a
// state signed for one deployment cannot be replayed against another. That
// means this function needs both, and a caller that hardcodes them will produce
// signatures valid against a contract nobody is using.
//
// The root is inside for the same class of reason. A digest that did not cover
// the locks would let a party sign a state and then present it with the locks
// stripped: the signature verifies, the two balances appear to conserve on their
// own, and the locked value is simply gone. There is deliberately no second,
// lock-free digest to choose between — with no locks the root is zero.
//
// The withdrawal amounts are in for the same reason again: a checkpoint takes
// value OUT of the channel, and a state separated from the amount leaving under
// it could be submitted asking for a different one. An ordinary payment signs
// zeros, which is not a special case but the true statement that it moves
// nothing out of the contract.
func StateDigest(op uint8, chainID *big.Int, contract Address, id [32]byte,
	nonce uint64, balanceA, balanceB *big.Int, htlcRoot [32]byte,
	withdrawA, withdrawB *big.Int) [32]byte {

	var out [32]byte
	copy(out[:], keccak(
		// abi.encode pads a uint8 to a full word, exactly like every other
		// argument. The domain is FIRST so that no shorter prefix of a digest
		// for one operation can be a valid digest for another.
		u256(new(big.Int).SetUint64(uint64(op))),
		u256(chainID),
		word(contract[:]),
		id[:],
		u64(nonce),
		u256(balanceA),
		u256(balanceB),
		htlcRoot[:],
		u256(withdrawA),
		u256(withdrawB),
	))
	return out
}

// PersonalDigest applies EIP-191, which ChannelManager._recover applies before
// ecrecover. This is what makes a browser's personal_sign acceptable on chain,
// and it is the step most easily forgotten: signatures over the raw digest
// verify perfectly in Go and are rejected by the contract.
func PersonalDigest(raw [32]byte) [32]byte {
	var out [32]byte
	copy(out[:], keccak([]byte("\x19Ethereum Signed Message:\n32"), raw[:]))
	return out
}

// secp256k1n/2. The contract rejects s above this, so a signature this package
// accepts but the contract does not would be a state that settles nowhere.
var halfOrder = new(big.Int).SetBytes([]byte{
	0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
	0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
})

// RecoverSigner returns the address that produced sig over raw, applying the
// same EIP-191 wrapping, low-s rule and 65-byte layout as the contract.
//
// sig is r || s || v, which is what MetaMask returns. v may arrive as 27/28 or
// as a bare 0/1 recovery id; both are accepted because wallets differ and a
// user cannot be asked to care.
func RecoverSigner(raw [32]byte, sig []byte) (Address, error) {
	if len(sig) != 65 {
		return Address{}, ErrBadStateSignature
	}
	s := new(big.Int).SetBytes(sig[32:64])
	if s.Cmp(halfOrder) > 0 {
		return Address{}, ErrHighS
	}

	v := sig[64]
	switch v {
	case 0, 1:
		v += 27
	case 27, 28:
	default:
		return Address{}, ErrBadStateSignature
	}

	// dcrd wants the recovery byte FIRST; MetaMask puts it last.
	compact := make([]byte, 65)
	compact[0] = v
	copy(compact[1:33], sig[0:32])
	copy(compact[33:65], sig[32:64])

	digest := PersonalDigest(raw)
	pub, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return Address{}, ErrBadStateSignature
	}

	uncompressed := pub.SerializeUncompressed() // 0x04 || X || Y
	var addr Address
	copy(addr[:], keccak(uncompressed[1:])[12:])
	if addr.IsZero() {
		return Address{}, ErrBadStateSignature
	}
	return addr, nil
}

// HTLC is a conditional payment in flight.
//
// Present in the state model from the start, not bolted on later: a direct tip
// does not need one, but the routed path does, and a state model that has to
// grow a new shape to carry locks forces every signature format, every
// persisted record and every verifier to change at exactly the moment real
// money is already in channels.
//
// A direct tip simply carries none.
type HTLC struct {
	// ID distinguishes two locks that share a hash, which happens whenever one
	// payment is split across paths.
	ID [32]byte `json:"id"`
	// Hash is H(preimage). Revealing the preimage claims the amount.
	Hash [32]byte `json:"hash"`
	// Amount is held out of the payer's balance while the lock is live. It is
	// in NEITHER balance: see Conserved.
	Amount *big.Int `json:"amount"`
	// Expiry is a unix time after which the payer may reclaim. Every hop on a
	// route needs a shorter window than the hop before it, or an intermediary
	// can be left having paid downstream with no way to claim upstream.
	Expiry int64 `json:"expiry"`
	// PayerIsA says which side is out of pocket while this lock is live.
	PayerIsA bool `json:"payer_is_a"`
}

// Matches reports whether a preimage opens this lock, hashed exactly as
// ChannelManagerV2.claimLock hashes it: keccak256 of the 32 bytes.
//
// Constant time is not required and would be misleading here — the preimage
// becomes public the moment it is used, which is the mechanism the whole route
// depends on.
func (h HTLC) Matches(preimage [32]byte) bool {
	var got [32]byte
	copy(got[:], keccak(preimage[:]))
	return got == h.Hash
}

// State is one point in a channel's life, in the contract's terms.
type State struct {
	Channel  [32]byte `json:"channel"`
	Nonce    uint64   `json:"nonce"`
	BalanceA *big.Int `json:"balance_a"`
	BalanceB *big.Int `json:"balance_b"`
	// Pending are the locks live at this nonce. Covered by the digest through
	// HTLCRoot, so a signed state cannot be presented with its locks removed.
	Pending []HTLC `json:"pending,omitempty"`

	// WithdrawA and WithdrawB are value leaving the channel under this state —
	// a checkpoint (ChannelManagerV2.checkpoint). Nil or zero on an ordinary
	// payment, which is what every state carries until P6's payout path uses
	// them. Covered by the digest, so a state cannot be submitted asking for a
	// different amount than was agreed.
	WithdrawA *big.Int `json:"withdraw_a,omitempty"`
	WithdrawB *big.Int `json:"withdraw_b,omitempty"`

	// Op is the OPERATION DOMAIN this state was agreed for, and it is the first
	// word of the digest.
	//
	// It exists because three different contract calls used to accept the same
	// bytes: with no live locks, an ordinary agreed state hashed identically to
	// a cooperative close, so a signature meaning "I agree the balance is
	// 400/100" was also a signature meaning "settle this channel now". Between
	// two honest parties that was only a surprise. Once a DELEGATE may sign,
	// it is an authority nobody granted.
	//
	// Set by Apply from the transition kind and by nothing else. A peer sends
	// this field like any other, and a peer that lies about it is caught by the
	// existing check that the received digest equals the one Apply recomputes.
	Op uint8 `json:"op,omitempty"`
}

// Digest is the value both parties sign.
//
// One digest for both cases. A state with no locks hashes a zero root, which is
// what ChannelManagerV2 computes for an empty lock set — so there is no second
// encoding to pick between and no path where the locks are silently left out.
func (s State) Digest(chainID *big.Int, contract Address) [32]byte {
	return StateDigest(s.op(), chainID, contract, s.Channel, s.Nonce,
		s.BalanceA, s.BalanceB, s.HTLCRoot(), s.WithdrawA, s.WithdrawB)
}

// Operation domains. Must match the OP_* constants in ChannelManagerV2.
//
// Numbered from 1 so that a zero value — an uninitialised struct, a state
// decoded from JSON written before this field existed — never names a real
// operation by accident.
const (
	OpState      uint8 = 1 // an ordinary agreed state: pay, challenge, unilateral exit
	OpCoopClose  uint8 = 2 // settle now, no challenge window
	OpCheckpoint uint8 = 3 // take value out, channel stays open
)

// op is the domain to hash under, defaulting to OpState.
//
// The default is the ordinary case and the least powerful one: a state that
// somehow arrived without a domain is treated as a payment, never as an
// authority to close or to withdraw.
func (s State) op() uint8 {
	if s.Op == 0 {
		return OpState
	}
	return s.Op
}

// HTLCRoot commits to the pending locks in a canonical order.
//
// Must agree byte-for-byte with ChannelManagerV2.htlcRoot: each lock as
// id || hash || amount || expiry || payerIsA, concatenated in id order, hashed
// once. The contract REQUIRES the set to arrive sorted rather than sorting it,
// so that one lock set has exactly one encoding; this sorts because it owns the
// canonical order. A contract and a node that disagree here disagree about
// money.
func (s State) HTLCRoot() [32]byte {
	if len(s.Pending) == 0 {
		return [32]byte{}
	}
	sorted := make([]HTLC, len(s.Pending))
	copy(sorted, s.Pending)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].ID[:], sorted[j].ID[:]) < 0
	})
	parts := make([][]byte, 0, len(sorted)*4)
	for _, h := range sorted {
		flag := byte(0)
		if h.PayerIsA {
			flag = 1
		}
		parts = append(parts, h.ID[:], h.Hash[:], u256(h.Amount),
			word(big.NewInt(h.Expiry).Bytes()), []byte{flag})
	}
	var out [32]byte
	copy(out[:], keccak(parts...))
	return out
}

// lockedTotal is value committed to pending locks.
func (s State) lockedTotal() *big.Int {
	sum := new(big.Int)
	for _, h := range s.Pending {
		if h.Amount != nil {
			sum.Add(sum, h.Amount)
		}
	}
	return sum
}

// Conserved reports whether this state creates or destroys value.
//
// balanceA + balanceB + everything locked == depositA + depositB.
//
// Locked value is counted OUTSIDE both balances, which is the only arrangement
// that makes a lock mean anything: while a payment is in flight the payer can
// no longer spend it and the payee cannot yet, so it belongs to neither side.
// Folding it into the payer's balance would let them sign it away twice.
func (s State) Conserved(depositA, depositB *big.Int) bool {
	total := new(big.Int).Add(orZero(s.BalanceA), orZero(s.BalanceB))
	total.Add(total, s.lockedTotal())
	// Value leaving under a checkpoint is neither a balance nor a lock, and the
	// contract counts it the same way: old collateral == new collateral + what
	// leaves. Omitting it here would make every checkpoint look unconserved.
	total.Add(total, orZero(s.WithdrawA))
	total.Add(total, orZero(s.WithdrawB))
	want := new(big.Int).Add(orZero(depositA), orZero(depositB))
	return total.Cmp(want) == 0
}

func orZero(n *big.Int) *big.Int {
	if n == nil {
		return new(big.Int)
	}
	return n
}

func anyNegative(ns ...*big.Int) bool {
	for _, n := range ns {
		if n != nil && n.Sign() < 0 {
			return true
		}
	}
	return false
}

// SignedState is a state with the two signatures that make it binding.
//
// A state signed by one party is that party's CLAIM, not an agreement. Both
// signatures mean the balance was accepted by the person it takes from, which
// is what makes a stale-state attack detectable rather than a dispute about who
// is telling the truth.
type SignedState struct {
	State State  `json:"state"`
	SigA  []byte `json:"sig_a,omitempty"`
	SigB  []byte `json:"sig_b,omitempty"`
}

// Complete reports whether both parties have signed.
func (ss SignedState) Complete() bool { return len(ss.SigA) == 65 && len(ss.SigB) == 65 }

// Status mirrors the contract's channel lifecycle.
type Status uint8

const (
	StatusNone Status = iota
	StatusOpen
	StatusClosing
	StatusSettled
)

// Channel is everything known about one channel, on chain and off.
type Channel struct {
	ID       [32]byte `json:"id"`
	PartyA   Address  `json:"party_a"` // the LOWER address. Not a role.
	PartyB   Address  `json:"party_b"`
	DepositA *big.Int `json:"deposit_a"`
	DepositB *big.Int `json:"deposit_b"`
	Status   Status   `json:"status"`
	ChainID  *big.Int `json:"chain_id"`
	Contract Address  `json:"contract"`
	// Latest is the newest fully signed state. This is the money. Everything
	// else in this struct can be re-read from the chain; this cannot.
	Latest SignedState `json:"latest"`

	// ---- SCPP/1 protocol state. Persisted with the channel because it must
	// land in the SAME atomic write as the state it describes.

	// Signed records the digest this node has signed at each nonce ABOVE
	// Latest. Invariant I4: never sign two different states at one nonce, not
	// even after a crash. Entries at or below Latest.Nonce are dropped, because
	// Accept's monotonicity already refuses those nonces — so this stays small
	// rather than growing for the life of the channel.
	Signed map[uint64][32]byte `json:"signed,omitempty"`

	// Applied maps a payment intent to the nonce that carried it (§5). It is
	// what makes a retry idempotent instead of a second payment, and it cannot
	// be pruned by nonce the way Signed can: a stale intent retried after the
	// channel moved on would otherwise be applied again at a fresh nonce.
	Applied map[[32]byte]uint64 `json:"applied,omitempty"`

	// Pending is a proposal this node has signed and not yet seen completed.
	// Persisted BEFORE the proposal goes out, so a crash in between leaves
	// evidence rather than a signature only the peer can prove.
	Pending *PendingProposal `json:"pending,omitempty"`

	// Conflict, once set, stops this channel permanently (§7). Two fully signed
	// states at one nonce cannot be reconciled by any rule, so the protocol does
	// not have one — it stops and preserves the evidence.
	Conflict *ConflictRecord `json:"conflict,omitempty"`

	// History is the payment log — observability, never authority. See
	// history.go: a balance is never computed from it.
	History []PaymentRecord `json:"history,omitempty"`

	// Payout is this node's record of turning off-chain value into on-chain
	// value. OBSERVABILITY, NOT AUTHORITY: the chain decides what settled, and
	// the worker asks it rather than trusting this. See settlement.go.
	Payout *PayoutRecord `json:"payout,omitempty"`

	// NeedsReconcile marks a channel restored from a backup and not yet checked
	// against an outside source. While it is true this node MUST NOT sign for
	// the channel — see reconcile.go.
	//
	// NOT PERSISTED, and the json tag says so. Writing it down would be
	// pointless in the exact case it exists for: a restore rolls back whatever
	// was written, including this. It is set on each snapshot from the store's
	// quarantine set, which is built at load time from a marker the restore
	// procedure leaves behind.
	NeedsReconcile bool `json:"-"`
}

// PendingProposal is the payer's half-finished payment.
type PendingProposal struct {
	Intent     [32]byte        `json:"intent"`
	Transition StateTransition `json:"transition"`
	State      State           `json:"state"`
	Sig        []byte          `json:"sig"`
}

// ConflictRecord is the evidence that a party signed twice at one nonce.
//
// Both states are kept because together they are the proof; either alone is
// just a state. Nothing in this package resolves a conflict — the resolution is
// on chain, by force-closing with the best state held, promptly.
type ConflictRecord struct {
	Nonce  uint64      `json:"nonce"`
	Mine   SignedState `json:"mine"`
	Theirs SignedState `json:"theirs"`
}

// Clone is a deep copy.
//
// Shallow copying a Channel shares its maps, so a caller could add a signed
// nonce or an applied intent to the store's own record without going through
// Accept — which is the one door every state is meant to come through.
func (c *Channel) Clone() *Channel {
	out := *c
	out.Latest = cloneSigned(c.Latest)
	out.DepositA = new(big.Int).Set(orZero(c.DepositA))
	out.DepositB = new(big.Int).Set(orZero(c.DepositB))
	out.ChainID = new(big.Int).Set(orZero(c.ChainID))

	if c.Signed != nil {
		out.Signed = make(map[uint64][32]byte, len(c.Signed))
		for k, v := range c.Signed {
			out.Signed[k] = v
		}
	}
	if c.Applied != nil {
		out.Applied = make(map[[32]byte]uint64, len(c.Applied))
		for k, v := range c.Applied {
			out.Applied[k] = v
		}
	}
	if c.Pending != nil {
		p := *c.Pending
		p.State = cloneState(c.Pending.State)
		p.Sig = append([]byte(nil), c.Pending.Sig...)
		if c.Pending.Transition.Amount != nil {
			p.Transition.Amount = new(big.Int).Set(c.Pending.Transition.Amount)
		}
		out.Pending = &p
	}
	if c.Conflict != nil {
		k := *c.Conflict
		k.Mine = cloneSigned(c.Conflict.Mine)
		k.Theirs = cloneSigned(c.Conflict.Theirs)
		out.Conflict = &k
	}
	if c.History != nil {
		out.History = append([]PaymentRecord(nil), c.History...)
	}
	if c.Payout != nil {
		// Copied like everything else here. Sharing the pointer would let
		// Store.Update's trial mutate the live record before the write it is
		// trialling has succeeded — the same failure the deep copy exists to
		// prevent, arriving through a field added later.
		p := *c.Payout
		out.Payout = &p
	}
	return &out
}

func cloneState(s State) State {
	out := s
	out.BalanceA = new(big.Int).Set(orZero(s.BalanceA))
	out.BalanceB = new(big.Int).Set(orZero(s.BalanceB))
	out.Pending = clonePending(s.Pending)
	return out
}

// HasSigned reports the digest this node signed at a nonce, if any.
func (c *Channel) HasSigned(nonce uint64) ([32]byte, bool) {
	d, ok := c.Signed[nonce]
	return d, ok
}

// NoteSigned records a signature at a nonce, and drops entries the nonce rule
// now covers.
func (c *Channel) NoteSigned(nonce uint64, digest [32]byte) {
	if c.Signed == nil {
		c.Signed = map[uint64][32]byte{}
	}
	c.Signed[nonce] = digest
	for n := range c.Signed {
		if n <= c.Latest.State.Nonce {
			delete(c.Signed, n)
		}
	}
}

// NoteApplied records that an intent produced the state at a nonce.
func (c *Channel) NoteApplied(intent [32]byte, nonce uint64) {
	if c.Applied == nil {
		c.Applied = map[[32]byte]uint64{}
	}
	c.Applied[intent] = nonce
}

// AppliedAt reports the nonce an intent produced, if it has been applied.
func (c *Channel) AppliedAt(intent [32]byte) (uint64, bool) {
	n, ok := c.Applied[intent]
	return n, ok
}

// NewChannel builds the record for a pair, putting the parties in the
// contract's order so callers cannot get it wrong.
func NewChannel(chainID *big.Int, contract Address, x, y Address) *Channel {
	a, b := SortParties(x, y)
	return &Channel{
		ID: DeriveChannelID(a, b), PartyA: a, PartyB: b,
		DepositA: new(big.Int), DepositB: new(big.Int),
		Status: StatusOpen, ChainID: chainID, Contract: contract,
	}
}

// IsA reports whether addr is party A of this channel.
func (c *Channel) IsA(addr Address) bool { return addr == c.PartyA }

// Party returns the address holding the given role.
func (c *Channel) Party(isA bool) Address {
	if isA {
		return c.PartyA
	}
	return c.PartyB
}

// BalanceOf returns what addr holds in the latest state.
func (c *Channel) BalanceOf(addr Address) *big.Int {
	if c.IsA(addr) {
		return orZero(c.Latest.State.BalanceA)
	}
	return orZero(c.Latest.State.BalanceB)
}

// Accept validates a candidate state and, if it is good, makes it the latest.
//
// THIS IS THE RULE THE WHOLE SYSTEM RESTS ON: a node never invents a state. It
// accepts one only when every check below passes, and it accepts nothing else,
// ever — not to unstick a test, not to recover from a crash, not because the
// counterparty says so.
//
// A node that will write a state it made up is a node that can steal, and no
// amount of care elsewhere compensates for it.
func (c *Channel) Accept(candidate SignedState) error {
	if c.Status != StatusOpen {
		return ErrNotOpen
	}
	st := candidate.State

	// 1. It is about this channel. A valid signature over another channel's
	//    state is still a valid signature.
	if st.Channel != c.ID {
		return ErrWrongChannel
	}

	// 2. Monotonic, strictly. Equal nonces are the interesting case: two
	//    different states at the same nonce are exactly what a double-spend
	//    looks like, so "not greater" is refused rather than "less".
	if st.Nonce <= c.Latest.State.Nonce && !(c.Latest.State.Nonce == 0 && !c.Latest.Complete()) {
		return ErrNonceRegressed
	}

	// 3. No negative anything. big.Int is signed; uint256 is not. A negative
	//    balance would satisfy conservation arithmetic while meaning nothing
	//    the chain could represent.
	if anyNegative(st.BalanceA, st.BalanceB) {
		return ErrNegative
	}
	for _, h := range st.Pending {
		if h.Amount == nil || h.Amount.Sign() <= 0 {
			return ErrNegative
		}
	}

	// 4. Locks are well formed: unique ids, and an expiry actually set.
	//
	//    NOT "an expiry in the future" — deliberately. This function is pure and
	//    must stay pure: consulting a clock would let two nodes with a little
	//    skew disagree about whether the same signed state is valid, and would
	//    make a state that validated when signed stop validating while sitting
	//    on disk, which turns the load-time check in store.go into a time bomb.
	//    Freshness is policy and belongs to the protocol layer, which has a
	//    clock and a skew tolerance. See doc/channel-payment-protocol.md §4.
	seen := make(map[[32]byte]bool, len(st.Pending))
	for _, h := range st.Pending {
		if seen[h.ID] {
			return ErrDuplicateHTLC
		}
		seen[h.ID] = true
		if h.Expiry <= 0 {
			return ErrHTLCExpiryPast
		}
	}

	// 5. Value is conserved against the deposits actually on chain.
	if !st.Conserved(c.DepositA, c.DepositB) {
		return ErrNotConserved
	}

	// 6. Both signatures recover to the two parties. Checked last because it is
	//    the expensive one and every cheap reason to reject should have fired
	//    already.
	if !candidate.Complete() {
		return ErrBadStateSignature
	}
	// Digest covers the lock root, so this signature check is also what proves
	// the locks validated above are the ones the parties actually agreed to.
	raw := st.Digest(c.ChainID, c.Contract)
	signerA, err := RecoverSigner(raw, candidate.SigA)
	if err != nil {
		return err
	}
	signerB, err := RecoverSigner(raw, candidate.SigB)
	if err != nil {
		return err
	}
	if signerA != c.PartyA || signerB != c.PartyB {
		return fmt.Errorf("%w: got %s/%s, want %s/%s", ErrBadStateSignature,
			signerA.Hex(), signerB.Hex(), c.PartyA.Hex(), c.PartyB.Hex())
	}

	c.Latest = candidate

	// Nonces at or below the new latest can never be signed again — Accept
	// refuses them on the nonce rule alone — so the I4 ledger drops them rather
	// than growing for the life of the channel.
	for n := range c.Signed {
		if n <= c.Latest.State.Nonce {
			delete(c.Signed, n)
		}
	}
	return nil
}

// ReplayKey identifies a state for replay protection.
//
// The award path currently keys on a unique on-chain tx_hash. A channel payment
// has no transaction, so this is what takes its place: channel id and nonce,
// which is unique by construction because Accept refuses a non-increasing
// nonce. Do not synthesise a fake tx hash to reuse the old column.
func ReplayKey(id [32]byte, nonce uint64) string {
	return fmt.Sprintf("%s:%d", hex.EncodeToString(id[:]), nonce)
}
