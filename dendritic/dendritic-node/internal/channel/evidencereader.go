package channel

// The watchtower's chain, made of verified evidence — roadmap P12-6.
//
// WHAT THIS REPLACES
// ------------------
// RPCChainReader answers ReadChannel with an eth_call and believes the reply.
// This answers the same question from evidence that has been through the whole
// pipeline:
//
//	acquisition -> HeaderVerifier -> Evidence.Verify -> DHT -> Index -> here
//
// The watchtower is unchanged and does not know the difference. That is the
// point of having had a ChainReader interface: swapping what "the chain says"
// means is a substitution, not a redesign, and the same substitution will carry
// a native verifier or a vendored one when P12-5 is closed.
//
// THERE IS NO FALLBACK, DELIBERATELY
// ----------------------------------
// No path here reaches an RPC. A "temporary" shortcut to eth_call would become
// the path that actually protects money — it would work, it would be faster,
// and nothing would ever fail to make anyone remove it. The only place raw RPC
// belongs is the acquisition layer that MAKES evidence, upstream of
// verification.
//
// NO EVIDENCE IS NOT NO CHANNEL
// -----------------------------
// The distinction this file exists to preserve:
//
//	ErrChannelNotOnChain    the chain PROVED there is no such channel
//	ErrNoVerifiedEvidence   we do not know, and must not act as though we do
//
// Collapsing them would let a watchtower with an empty store conclude that
// every channel it protects has ceased to exist — and do nothing about all of
// them, quietly. Absence of evidence gets its own error and its own loud
// failure.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/ethproof"
)

// ErrNoVerifiedEvidence means nothing usable is held for a channel.
//
// NOT "the channel does not exist". The watchtower must treat it as a failure
// to see, not as a fact about the world.
var ErrNoVerifiedEvidence = errors.New(
	"channel: no verified evidence for this channel; the chain has not been read, not read as empty")

// EvidenceChainReader answers ReadChannel from stored, verified evidence.
type EvidenceChainReader struct {
	Index    *ethproof.Index
	Store    *ethproof.EvidenceStore
	Verifier *ethproof.HeaderVerifier
	ChainID  uint64
}

// The slots of AxonChannels's Channel struct, in declaration order.
//
// From solc's storage layout: `channels` is at position 0, so a channel begins
// at keccak256(id ‖ uint256(0)) and its members occupy the ten slots after.
const (
	slotPartyA = iota
	slotPartyB
	slotDepositA
	slotDepositB
	slotStatus
	slotBalanceA
	slotBalanceB
	slotNonce
	slotChallengeEnds
	slotHTLCRoot
	slotLockedTotal
	slotCount
)

// ChannelSlots returns the eleven trie keys for a channel.
//
// Exported so the acquisition layer asks for exactly what this decodes, and the
// two cannot drift into disagreeing about which slot is which.
func ChannelSlots(id [32]byte) [][32]byte {
	base := ethproof.StorageSlotKey(id, 0)
	out := make([][32]byte, slotCount)
	for i := range out {
		out[i] = ethproof.SlotAt(base, uint64(i))
	}
	return out
}

// ReadChannel returns what the verified evidence says.
//
// Every failure is an error. There is no branch that returns a partially
// populated channel, because a watchtower comparing nonces against a struct
// that was half-decoded would make a confident decision on nothing.
func (r *EvidenceChainReader) ReadChannel(ctx context.Context, contract Address, id [32]byte) (OnChainChannel, error) {
	if r.Index == nil || r.Store == nil || r.Verifier == nil {
		return OnChainChannel{}, errors.New("channel: evidence reader is not configured")
	}

	e, err := r.Index.Lookup(ctx, r.Store, r.Verifier,
		r.ChainID, contract.Hex(), hex.EncodeToString(id[:]))
	switch {
	case errors.Is(err, ethproof.ErrNoEvidence):
		return OnChainChannel{}, ErrNoVerifiedEvidence
	case err != nil:
		// Includes ErrNoTrustAnchor, which is the state today: the evidence may
		// be internally perfect and still not be known to be Ethereum's.
		return OnChainChannel{}, fmt.Errorf("channel: reading verified evidence: %w", err)
	}

	if len(e.Values) != slotCount {
		return OnChainChannel{}, fmt.Errorf(
			"channel: evidence carries %d slots, want %d", len(e.Values), slotCount)
	}

	words := make([][32]byte, slotCount)
	for i, v := range e.Values {
		w, err := parseWord(v)
		if err != nil {
			return OnChainChannel{}, fmt.Errorf("channel: slot %d: %w", i, err)
		}
		words[i] = w
	}

	out := OnChainChannel{
		ID:            id,
		PartyA:        addressFromWord(words[slotPartyA]),
		PartyB:        addressFromWord(words[slotPartyB]),
		DepositA:      new(big.Int).SetBytes(words[slotDepositA][:]),
		DepositB:      new(big.Int).SetBytes(words[slotDepositB][:]),
		Status:        Status(new(big.Int).SetBytes(words[slotStatus][:]).Uint64()),
		BalanceA:      new(big.Int).SetBytes(words[slotBalanceA][:]),
		BalanceB:      new(big.Int).SetBytes(words[slotBalanceB][:]),
		Nonce:         new(big.Int).SetBytes(words[slotNonce][:]).Uint64(),
		ChallengeEnds: new(big.Int).SetBytes(words[slotChallengeEnds][:]).Int64(),
		LockedTotal:   new(big.Int).SetBytes(words[slotLockedTotal][:]),
		// The guard. Set here because this value came from a proof against a
		// state root, which is what fromChain has always meant — not because
		// the code path happens to live in this package.
		fromChain: true,
	}

	// The same two checks decodeChannelsReturn makes of an eth_call, for the
	// same reasons: an unopened channel must not read as a real one with zero
	// deposits, and the parties must derive the id that was asked about.
	if out.Status == StatusNone || (out.PartyA.IsZero() && out.PartyB.IsZero()) {
		return OnChainChannel{}, ErrChannelNotOnChain
	}
	if DeriveChannelID(out.PartyA, out.PartyB) != id {
		return OnChainChannel{}, errors.New(
			"channel: the evidence's parties do not derive the channel id asked for")
	}
	return out, nil
}

func parseWord(hexValue string) ([32]byte, error) {
	var out [32]byte
	text := strings.TrimPrefix(strings.TrimPrefix(hexValue, "0x"), "0X")
	if len(text)%2 == 1 {
		text = "0" + text
	}
	raw, err := hex.DecodeString(text)
	if err != nil {
		return out, err
	}
	if len(raw) > 32 {
		return out, fmt.Errorf("value is %d bytes", len(raw))
	}
	copy(out[32-len(raw):], raw)
	return out, nil
}

// addressFromWord takes the low 20 bytes, which is how the EVM stores one.
func addressFromWord(w [32]byte) Address {
	var a Address
	copy(a[:], w[12:])
	return a
}

var _ ChainReader = (*EvidenceChainReader)(nil)
