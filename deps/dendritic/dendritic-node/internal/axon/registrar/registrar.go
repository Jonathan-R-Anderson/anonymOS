// Package registrar drives registration of an AXON name (alice.lab.axon)
// against the contracts that hold it on chain: TLDRegistry (the root, §12.0),
// which says which registrar serves the namespace `lab`, and that registrar --
// AxonRegistry, the reference implementation (§12.3) -- which holds `alice`.
//
// IT BUILDS BYTES. IT DOES NOT TALK TO A CHAIN, AND IT DOES NOT SIGN.
//
//   - No RPC. Chain state the plan depends on -- the namespace binding, the
//     registrar's immutables -- arrives through a seam the caller fills (a
//     NamespaceLookup, a RegistrarParams table). This package supplies the
//     calldata to read them with and the decoders to parse the answers, and
//     nothing else.
//   - No keys. Signing belongs to the user's wallet. A Plan is an ordered list
//     of unsigned transactions a wallet or CLI can show, review and send; a
//     component that only needs to describe a registration should not be handed
//     the ability to pay for one (the rule internal/channel's ChainWriter
//     states for the same reason).
//
// THE CONTRACT IS THE AUTHORITY, AND THE CROSS-CHECK IS MECHANICAL. Every hash,
// commitment, calldata byte and decoded return value below is pinned in
// registrar_test.go to a vector PRODUCED BY THE CONTRACTS in
// proof-of-facilitation/test/TLDRegistry.test.ts ("test vector for the Go
// registrar client"): the Solidity test sends these exact bytes, raw, and they
// register a name. Change either side and one of the two tests fails.
//
// WHAT AxonRegistry.register TRUSTS THE CALLER FOR, stated because this
// package is where that trust is discharged. register() takes
// (nameHash, skeleton, labelLen, secret, domainKey) and never sees the label:
//
//   - nameHash is not recomputed (the label is never revealed on chain), so a
//     client that hashed the wrong string registers a name nobody can resolve;
//   - skeleton is not recomputed, so the confusable-class rule (§11.3.3) holds
//     only if every client derives it the same way -- here, through
//     registry.ClaimFor, the house's single derivation;
//   - labelLen is not checked against anything, and it sets the PRICE (3 chars
//     100x, 4 chars 20x, 5 chars 5x). An honest client sends the true length;
//     the contract cannot tell. [KNOWN GAP in the deployed AxonRegistry.]
//
// AND ONE DISAGREEMENT IN THE TREE, recorded rather than papered over:
// registry.MakeCommitment models the commitment as SHA-256(nameHash ‖ owner ‖
// secret). The deployed contract computes keccak256(abi.encode(nameHash,
// msg.sender, secret, domainKey)) -- a different hash over a different
// pre-image. registry's own rule ("where the two disagree, the contract wins")
// applies, so Commitment below is the contract's, and registry's model is the
// thing that is wrong.
package registrar

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/axon/name"
	"github.com/syndichan/maniwani/storage-client/internal/axon/registry"
	"github.com/syndichan/maniwani/storage-client/internal/ethproof"
)

var (
	ErrNotRegistrable = errors.New("axon/registrar: not a registrable name (label.namespace.root)")
	ErrBadReturn      = errors.New("axon/registrar: malformed ABI return data")
	ErrBadAddress     = errors.New("axon/registrar: malformed address")
)

// Address is a 20-byte Ethereum address.
type Address [20]byte

// Hex is the EIP-55 mixed-case form. Checksummed because an address that is
// printed to be copied into a wallet is exactly where a wrong nibble costs
// money.
func (a Address) Hex() string {
	lower := hex.EncodeToString(a[:])
	sum := hex.EncodeToString(ethproof.Keccak256([]byte(lower)))
	var b strings.Builder
	b.WriteString("0x")
	for i, c := range lower {
		if c >= 'a' && c <= 'f' && sum[i] >= '8' {
			b.WriteRune(c - 32)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (a Address) IsZero() bool { return a == Address{} }

// ParseAddress accepts a 0x-prefixed 40-hex-digit address. A mixed-case input
// must be a valid EIP-55 checksum; an all-lower or all-upper one is accepted as
// unchecksummed, which is what EIP-55 specifies.
func ParseAddress(s string) (Address, error) {
	var a Address
	if len(s) != 42 || !strings.HasPrefix(s, "0x") {
		return a, fmt.Errorf("%w: %q", ErrBadAddress, s)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return a, fmt.Errorf("%w: %q: %v", ErrBadAddress, s, err)
	}
	copy(a[:], b)
	body := s[2:]
	if body != strings.ToLower(body) && body != strings.ToUpper(body) && a.Hex() != s {
		return Address{}, fmt.Errorf("%w: %q fails its EIP-55 checksum", ErrBadAddress, s)
	}
	return a, nil
}

// MustAddress is ParseAddress for constants.
func MustAddress(s string) Address {
	a, err := ParseAddress(s)
	if err != nil {
		panic(err)
	}
	return a
}

// ---------------------------------------------------------------- hashing

func keccak(parts ...[]byte) (out [32]byte) {
	copy(out[:], ethproof.Keccak256(parts...))
	return out
}

// LabelHash is keccak256(label): TLDRegistry's key for a namespace, and the
// last link of every namehash.
func LabelHash(label string) [32]byte { return keccak([]byte(label)) }

// RootNode is namehash(name.RootSuffix) = keccak256(0x00*32 ‖ keccak256(root))
// (§11.3.2). TLDRegistry.ROOT_NODE.
func RootNode() [32]byte {
	var zero [32]byte
	rh := LabelHash(name.RootSuffix)
	return keccak(zero[:], rh[:])
}

// NamespaceNode is namehash(namespace.root): TLDRegistry.namespaceNode, and the
// `tldNode` an AxonRegistry for that namespace is deployed with.
func NamespaceNode(namespace string) [32]byte {
	root := RootNode()
	nh := LabelHash(namespace)
	return keccak(root[:], nh[:])
}

// Claim is everything the chain needs to know about one registrable name.
type Claim struct {
	// Name is the canonical form, e.g. "alice.lab.axon".
	Name string
	// Label is the registrable label ("alice"), Namespace the governed one
	// ("lab").
	Label, Namespace string
	// NamespaceHash = keccak256(Namespace): the TLDRegistry.namespaceOf key.
	NamespaceHash [32]byte
	// NameHash = namehash(Name) (§11.3.2), the registrar's key. From
	// name.Name.NameHash, so there is one implementation in the tree.
	NameHash [32]byte
	// Skeleton is the confusable class (§11.3.3), from registry.ClaimFor:
	// namehash(skeleton(label).namespace.root). AxonRegistry stores whatever
	// it is given, so the derivation must be the one every client uses.
	Skeleton [32]byte
	// LabelLen is the registrable label's length in bytes, which AxonRegistry
	// prices by and takes on trust (see the package comment).
	LabelLen uint8
}

// ClaimOf normalises input (§11.3.2) and derives its on-chain claim. Only a
// registrable name -- exactly label.namespace.root -- has one; a subordinate
// name is delegated off chain (§11.4) and is refused.
func ClaimOf(input string) (Claim, error) {
	n, err := name.Normalise(input)
	if err != nil {
		return Claim{}, err
	}
	if !n.IsRegistrable() {
		return Claim{}, fmt.Errorf("%w: %q", ErrNotRegistrable, n)
	}
	c, err := registry.ClaimFor(n)
	if err != nil {
		return Claim{}, err
	}
	label := n.Registrable()
	return Claim{
		Name:          n.String(),
		Label:         label,
		Namespace:     n.Namespace(),
		NamespaceHash: LabelHash(n.Namespace()),
		NameHash:      c.NameHash,
		Skeleton:      c.Skeleton,
		LabelLen:      uint8(len(label)), // <= name.MaxRegistrableLen (63)
	}, nil
}

// Commitment is AxonRegistry's commit-reveal commitment, exactly as register()
// recomputes it:
//
//	keccak256(abi.encode(nameHash, msg.sender, secret, domainKey))
//
// owner IS msg.sender: AxonRegistry has no owner argument, so the account that
// commits must be the account that registers, and it becomes the owner. A
// relayer cannot submit on the owner's behalf through this path.
func Commitment(nameHash [32]byte, owner Address, secret, domainKey [32]byte) [32]byte {
	return keccak(nameHash[:], wordAddress(owner), secret[:], domainKey[:])
}

// ---------------------------------------------------------------- selectors

// Selectors, COMPUTED from the signature rather than pasted, and pinned to the
// compiled contracts in the test -- a signature change shows up as a failing
// test, not as calldata that silently calls nothing.
var (
	selNamespaceOf = selector("namespaceOf(bytes32)")
	selCommit      = selector("commit(bytes32)")
	selRegister    = selector("register(bytes32,bytes32,uint8,bytes32,bytes32)")
	selNameOf      = selector("nameOf(bytes32)")
	selApprove     = selector("approve(address,uint256)")
)

func selector(sig string) []byte { return ethproof.Keccak256([]byte(sig))[:4] }

// ---------------------------------------------------------------- calldata

// Hand-rolled, as internal/channel's encoder is and for its reason: this has
// to agree with the contract to the byte, and every argument here is a static
// 32-byte word, so there is no offset arithmetic to get wrong. The module has
// no go-ethereum dependency and this does not need one.

func wordAddress(a Address) []byte {
	w := make([]byte, 32)
	copy(w[12:], a[:])
	return w
}

func wordUint(v uint64) []byte {
	w := make([]byte, 32)
	for i := 0; i < 8; i++ {
		w[31-i] = byte(v >> (8 * i))
	}
	return w
}

func wordBig(v *big.Int) ([]byte, error) {
	if v == nil || v.Sign() < 0 || v.BitLen() > 256 {
		return nil, fmt.Errorf("axon/registrar: %v is not a uint256", v)
	}
	w := make([]byte, 32)
	v.FillBytes(w)
	return w, nil
}

func call(sel []byte, words ...[]byte) []byte {
	out := make([]byte, 0, 4+32*len(words))
	out = append(out, sel...)
	for _, w := range words {
		out = append(out, w...)
	}
	return out
}

// NamespaceOfCalldata reads TLDRegistry.namespaceOf(keccak256(namespace)).
func NamespaceOfCalldata(namespaceHash [32]byte) []byte {
	return call(selNamespaceOf, namespaceHash[:])
}

// NameOfCalldata reads AxonRegistry.nameOf(nameHash).
func NameOfCalldata(nameHash [32]byte) []byte { return call(selNameOf, nameHash[:]) }

// CommitCalldata is AxonRegistry.commit(commitment).
func CommitCalldata(commitment [32]byte) []byte { return call(selCommit, commitment[:]) }

// RegisterCalldata is AxonRegistry.register(nameHash, skeleton, labelLen,
// secret, domainKey).
func RegisterCalldata(c Claim, secret, domainKey [32]byte) []byte {
	return call(selRegister, c.NameHash[:], c.Skeleton[:], wordUint(uint64(c.LabelLen)),
		secret[:], domainKey[:])
}

// ApproveCalldata is ERC20 approve(spender, amount) on the token.
func ApproveCalldata(spender Address, amount *big.Int) ([]byte, error) {
	w, err := wordBig(amount)
	if err != nil {
		return nil, err
	}
	return call(selApprove, wordAddress(spender), w), nil
}

// ---------------------------------------------------------------- decoding

// NsStatus is TLDRegistry's NsStatus, in on-chain order.
type NsStatus uint8

const (
	StatusNone NsStatus = iota
	StatusProposed
	StatusActive
	StatusFrozen
	StatusRetiring
	StatusRetired
)

func (s NsStatus) String() string {
	switch s {
	case StatusNone:
		return "NONE"
	case StatusProposed:
		return "PROPOSED"
	case StatusActive:
		return "ACTIVE"
	case StatusFrozen:
		return "FROZEN"
	case StatusRetiring:
		return "RETIRING"
	case StatusRetired:
		return "RETIRED"
	}
	return fmt.Sprintf("NsStatus(%d)", uint8(s))
}

// RegClass is TLDRegistry's RegClass, in on-chain order.
type RegClass uint8

const (
	ClassImmutable RegClass = iota
	ClassUpgradeable
	ClassStewarded
)

func (c RegClass) String() string {
	switch c {
	case ClassImmutable:
		return "IMMUTABLE"
	case ClassUpgradeable:
		return "UPGRADEABLE"
	case ClassStewarded:
		return "STEWARDED"
	}
	return fmt.Sprintf("RegClass(%d)", uint8(c))
}

// Namespace is TLDRegistry's Namespace struct, IN ITS DECLARATION ORDER --
// which is the ABI tuple order and is NOT §12.0's listing order (the contract
// reorders fields for storage packing and adds frozenAt; see TLDRegistry.sol).
type Namespace struct {
	Registrar      Address
	RegistrarClass RegClass
	Status         NsStatus
	RecordSchema   uint16
	ActivatedAt    uint64
	RetiresAt      uint64
	FrozenAt       uint64
	Steward        Address
	Charter        [32]byte
	Bond           *big.Int
}

// EffectiveStatus applies the rule TLDRegistry.namespaceOf documents: a
// RETIRING namespace whose retiresAt has passed is RETIRED, whether or not
// anyone has executed the RETIRE action yet (it can no longer be cancelled).
func (ns Namespace) EffectiveStatus(now uint64) NsStatus {
	if ns.Status == StatusRetiring && ns.RetiresAt != 0 && now >= ns.RetiresAt {
		return StatusRetired
	}
	return ns.Status
}

// NameRecord is AxonRegistry's Name struct as nameOf returns it, in
// declaration order.
type NameRecord struct {
	Owner        Address
	ExpiresAt    uint64
	Version      uint32
	DomainKey    [32]byte
	Resolver     [32]byte
	Skeleton     [32]byte
	RegisteredAt uint64
	AcquiredAt   uint64
	KeyValidFrom uint64
	Bond         *big.Int
	Flags        uint8
}

// words splits return data into exactly n words. Both structs are STATIC
// tuples (every member is a value type), so the ABI encodes them inline with no
// offset word -- n*32 bytes, no more and no less.
func words(ret []byte, n int) ([][]byte, error) {
	if len(ret) != 32*n {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrBadReturn, len(ret), 32*n)
	}
	out := make([][]byte, n)
	for i := range out {
		out[i] = ret[32*i : 32*i+32]
	}
	return out, nil
}

// narrow reads a word as an unsigned integer of `bytes` width, refusing any
// set bit above it. Strict on purpose: a word with high bits set is not
// something solc produces, so it is a corrupt or hostile answer and is refused
// rather than truncated into a plausible one.
func narrow(w []byte, bytes int) (uint64, error) {
	for _, b := range w[:32-bytes] {
		if b != 0 {
			return 0, fmt.Errorf("%w: value wider than %d bytes", ErrBadReturn, bytes)
		}
	}
	var v uint64
	for _, b := range w[32-bytes:] {
		v = v<<8 | uint64(b)
	}
	return v, nil
}

func address(w []byte) (Address, error) {
	var a Address
	for _, b := range w[:12] {
		if b != 0 {
			return a, fmt.Errorf("%w: dirty address word", ErrBadReturn)
		}
	}
	copy(a[:], w[12:])
	return a, nil
}

// DecodeNamespace parses TLDRegistry.namespaceOf return data.
func DecodeNamespace(ret []byte) (Namespace, error) {
	w, err := words(ret, 10)
	if err != nil {
		return Namespace{}, err
	}
	var ns Namespace
	var v uint64
	if ns.Registrar, err = address(w[0]); err != nil {
		return Namespace{}, err
	}
	if v, err = narrow(w[1], 1); err != nil || v > uint64(ClassStewarded) {
		return Namespace{}, fmt.Errorf("%w: registrarClass %d (%v)", ErrBadReturn, v, err)
	}
	ns.RegistrarClass = RegClass(v)
	if v, err = narrow(w[2], 1); err != nil || v > uint64(StatusRetired) {
		return Namespace{}, fmt.Errorf("%w: status %d (%v)", ErrBadReturn, v, err)
	}
	ns.Status = NsStatus(v)
	if v, err = narrow(w[3], 2); err != nil {
		return Namespace{}, err
	}
	ns.RecordSchema = uint16(v)
	if ns.ActivatedAt, err = narrow(w[4], 8); err != nil {
		return Namespace{}, err
	}
	if ns.RetiresAt, err = narrow(w[5], 8); err != nil {
		return Namespace{}, err
	}
	if ns.FrozenAt, err = narrow(w[6], 8); err != nil {
		return Namespace{}, err
	}
	if ns.Steward, err = address(w[7]); err != nil {
		return Namespace{}, err
	}
	copy(ns.Charter[:], w[8])
	ns.Bond = new(big.Int).SetBytes(w[9])
	return ns, nil
}

// DecodeName parses AxonRegistry.nameOf return data.
func DecodeName(ret []byte) (NameRecord, error) {
	w, err := words(ret, 11)
	if err != nil {
		return NameRecord{}, err
	}
	var n NameRecord
	var v uint64
	if n.Owner, err = address(w[0]); err != nil {
		return NameRecord{}, err
	}
	if n.ExpiresAt, err = narrow(w[1], 8); err != nil {
		return NameRecord{}, err
	}
	if v, err = narrow(w[2], 4); err != nil {
		return NameRecord{}, err
	}
	n.Version = uint32(v)
	copy(n.DomainKey[:], w[3])
	copy(n.Resolver[:], w[4])
	copy(n.Skeleton[:], w[5])
	if n.RegisteredAt, err = narrow(w[6], 8); err != nil {
		return NameRecord{}, err
	}
	if n.AcquiredAt, err = narrow(w[7], 8); err != nil {
		return NameRecord{}, err
	}
	if n.KeyValidFrom, err = narrow(w[8], 8); err != nil {
		return NameRecord{}, err
	}
	n.Bond = new(big.Int).SetBytes(w[9])
	if v, err = narrow(w[10], 1); err != nil {
		return NameRecord{}, err
	}
	n.Flags = uint8(v)
	return n, nil
}
