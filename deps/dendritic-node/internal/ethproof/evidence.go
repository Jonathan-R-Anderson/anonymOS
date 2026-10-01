package ethproof

// Verified Ethereum evidence, and its durable form — roadmap P12-3.
//
// THE RULE
// --------
//	Only VERIFIED Ethereum evidence may enter the persistent dataset.
//
// Enforced by construction rather than by discipline. Evidence carries an
// unexported `verified` flag that nothing outside this package can set, and the
// only way to obtain one is Verify, which walks the whole proof chain. A
// hand-built Evidence value is refused by Put — the same guard
// OnChainChannel.fromChain uses in internal/channel, for the same reason: a
// rule that depends on every future caller remembering it is not a rule.
//
// WHY THE PROOF TRAVELS WITH THE VALUE
// ------------------------------------
// A record stores the proof nodes, not just the answer. That makes it
// SELF-VERIFYING OFFLINE: anybody holding the record can re-walk the proof
// against the header's stateRoot with no network at all, and reach the same
// value or none.
//
// It costs a few kilobytes and buys the property the whole architecture rests
// on — a DHT holder cannot alter what a record says, because altering it breaks
// the proof. Storing only the value would make every reader trust whoever
// stored it, which is precisely the trust this phase is removing.
//
//	record  ──►  re-verify against its own header  ──►  value
//	                     │
//	                     └── fails ⇒ discard. Never "probably fine".
//
// WHAT IS STILL MISSING
// ---------------------
// The header. A record proves its value is consistent with SOME header; that
// the header belongs to Ethereum mainnet is P12-5's job. Until then this
// narrows the trust rather than eliminating it, and the ChainID and ParentHash
// fields are here so P12-5 can chain records together without a format change.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	// ErrNotVerified is returned when unverified evidence is offered for
	// storage. It means the caller skipped Verify, which is a programming
	// mistake rather than a data problem.
	ErrNotVerified = errors.New("ethproof: refusing to store unverified evidence")
	// ErrEvidenceMalformed means a stored record is not one.
	ErrEvidenceMalformed = errors.New("ethproof: stored evidence is malformed")
)

// Evidence is one channel's on-chain state at one block, with the proof.
type Evidence struct {
	ChainID     uint64 `json:"chain_id"`
	BlockNumber uint64 `json:"block_number"`
	BlockHash   string `json:"block_hash"`
	ParentHash  string `json:"parent_hash"`
	StateRoot   string `json:"state_root"`
	Contract    string `json:"contract"`
	ChannelID   string `json:"channel_id"`

	// AccountProof and StorageProofs are the raw nodes, hex-encoded. They are
	// what makes a record re-verifiable without a network.
	AccountProof  []string   `json:"account_proof"`
	StorageProofs [][]string `json:"storage_proofs"`
	// Slots are the trie keys the storage proofs answer, in order.
	Slots []string `json:"slots"`
	// Values are what the proofs COMMIT TO — recovered by walking them, never
	// copied from an RPC's convenience field.
	Values []string `json:"values"`
	// Absent marks slots the proof shows were never written. Distinct from a
	// zero value, and distinct again from a proof that did not verify.
	Absent []bool `json:"absent"`

	// verified is the guard. Unexported, so only Verify can set it and no
	// caller outside this package can forge one.
	verified bool
}

// Verified reports whether this record has been through Verify.
func (e Evidence) Verified() bool { return e.verified }

// Verify re-walks the proof chain and returns evidence marked verified.
//
// Works offline: everything it needs is in the record. A record that fails here
// is discarded, never stored, and never returned to a caller — there is no
// "probably fine" branch, because a watchtower acting on probably-fine evidence
// is a watchtower making an irreversible decision on a guess.
func (e Evidence) Verify() (Evidence, error) {
	e.verified = false

	stateRoot, err := decodeHex32(e.StateRoot)
	if err != nil {
		return e, fmt.Errorf("%w: stateRoot: %v", ErrEvidenceMalformed, err)
	}
	contract, err := decodeHexBytes(e.Contract)
	if err != nil || len(contract) != 20 {
		return e, fmt.Errorf("%w: contract is not an address", ErrEvidenceMalformed)
	}
	if len(e.Slots) != len(e.StorageProofs) ||
		len(e.Slots) != len(e.Values) || len(e.Slots) != len(e.Absent) {
		return e, fmt.Errorf("%w: slots, proofs, values and absence disagree in length",
			ErrEvidenceMalformed)
	}

	accountNodes, _, err := decodeNodes(e.AccountProof)
	if err != nil {
		return e, fmt.Errorf("%w: account proof: %v", ErrEvidenceMalformed, err)
	}
	accountRLP, err := VerifyProof(stateRoot[:], contract, accountNodes)
	if err != nil {
		return e, fmt.Errorf("account proof: %w", err)
	}
	storageRoot, err := AccountStorageRoot(accountRLP)
	if err != nil {
		return e, err
	}

	for i := range e.Slots {
		slot, err := decodeHex32(e.Slots[i])
		if err != nil {
			return e, fmt.Errorf("%w: slot %d: %v", ErrEvidenceMalformed, i, err)
		}
		nodes, _, err := decodeNodes(e.StorageProofs[i])
		if err != nil {
			return e, fmt.Errorf("%w: storage proof %d: %v", ErrEvidenceMalformed, i, err)
		}
		raw, err := VerifyProof(storageRoot, slot[:], nodes)
		if err != nil {
			return e, fmt.Errorf("storage proof %d: %w", i, err)
		}
		value, err := DecodeSlotValue(raw)
		if err != nil {
			return e, err
		}
		// The recorded value must be what the proof commits to. A record whose
		// stated value disagrees with its own proof is the exact forgery this
		// design exists to catch, and it is caught here rather than trusted.
		recorded, err := decodeHex32(e.Values[i])
		if err != nil {
			return e, fmt.Errorf("%w: value %d: %v", ErrEvidenceMalformed, i, err)
		}
		if recorded != value {
			return e, fmt.Errorf(
				"%w: slot %d records %x but its proof commits to %x",
				ErrEvidenceMalformed, i, recorded[:8], value[:8])
		}
		if e.Absent[i] != (raw == nil) {
			return e, fmt.Errorf("%w: slot %d disagrees about absence",
				ErrEvidenceMalformed, i)
		}
	}

	e.verified = true
	return e, nil
}

// EvidenceFrom turns a live verified read into a storable record.
//
// The Measurement it takes has already been verified against a header by
// VerifiedRead; this re-verifies anyway. Cheap, offline, and it means there is
// exactly one path by which a record becomes storable rather than two.
func EvidenceFrom(chainID uint64, header BlockHeader, channelID string,
	address string, slots [][32]byte, proof ProofResult, m Measurement) (Evidence, error) {

	e := Evidence{
		ChainID: chainID, BlockNumber: header.BlockNumber(),
		BlockHash: header.Hash, StateRoot: header.StateRoot,
		Contract: strings.ToLower(address), ChannelID: strings.ToLower(channelID),
		AccountProof: proof.AccountProof,
	}
	for i, sp := range proof.StorageProof {
		e.StorageProofs = append(e.StorageProofs, sp.Proof)
		e.Slots = append(e.Slots, "0x"+hex.EncodeToString(slots[i][:]))
		e.Values = append(e.Values, "0x"+hex.EncodeToString(m.Slots[i].Value[:]))
		e.Absent = append(e.Absent, m.Slots[i].Absent)
	}
	return e.Verify()
}

// EvidenceKeyPrefix namespaces Ethereum evidence in the store.
const EvidenceKeyPrefix = "eth/"

// Key names a record immutably.
//
//	eth/<chainid>/<contract>/<channel>/<block>/<blockhash>
//
// The block hash is last so that two records for one height — which is what a
// reorg produces — are two objects rather than one replacing the other. Losing
// the losing side of a reorg would destroy the evidence that the reorg happened.
//
// The block number is zero-padded so a prefix listing sorts numerically.
//
// Addresses and ids are LOWERCASED here rather than relying on the caller. A
// key built from a mixed-case address does not match the prefix ChannelPrefix
// produces, so the record files somewhere Latest can never list it — present in
// the store, invisible to the watchtower, which is the worst way to lose
// evidence.
func (e Evidence) Key() string {
	return fmt.Sprintf("%s%d/%s/%s/%020d/%s", EvidenceKeyPrefix, e.ChainID,
		strings.ToLower(strip0x(e.Contract)), strings.ToLower(strip0x(e.ChannelID)),
		e.BlockNumber, strings.ToLower(strip0x(e.BlockHash)))
}

// ChannelPrefix is every record for one channel, oldest block first.
func ChannelPrefix(chainID uint64, contract, channelID string) string {
	return fmt.Sprintf("%s%d/%s/%s/", EvidenceKeyPrefix, chainID,
		strings.ToLower(strip0x(contract)), strings.ToLower(strip0x(channelID)))
}

func strip0x(s string) string {
	return strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
}

// EvidenceBackend is durable custody, in the shape the vault already uses.
type EvidenceBackend interface {
	Put(ctx context.Context, key string, blob []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	List(ctx context.Context, prefix string) ([]string, error)
}

// EvidenceMetrics receives aggregate counts about evidence-store traffic.
//
// Defined HERE, in primitives, rather than importing the channel package's
// collector: ethproof must not depend on channel, and a narrow interface of
// ints is also the strongest possible statement of what may cross. There is no
// method that could carry a key, an evidence id, a channel id or a hash — the
// interface cannot express them.
type EvidenceMetrics interface {
	EvidenceRead(bytes int)
	EvidenceWrite(bytes int)
	EvidenceFailure()
}

// EvidenceStore keeps verified evidence durably.
//
// Sealing is supplied by the caller rather than built in, so this file has one
// job. The vault already owns an AEAD and a key; wiring the same one here keeps
// one secret to manage rather than two.
type EvidenceStore struct {
	Backend EvidenceBackend
	// Seal and Open are the encryption boundary. Required: the store holds
	// ciphertext it cannot read, which is its own rule and what makes it safe
	// to disperse a record across nodes nobody here controls.
	Seal func([]byte) ([]byte, error)
	Open func([]byte) ([]byte, error)

	// Metrics is optional and aggregate-only. Every call below has the key in
	// hand and passes only a byte count.
	Metrics EvidenceMetrics
}

// Put stores verified evidence. Refuses anything else.
func (s *EvidenceStore) Put(ctx context.Context, e Evidence) error {
	if !e.verified {
		return ErrNotVerified
	}
	if s.Backend == nil || s.Seal == nil {
		return errors.New("ethproof: evidence store is not configured")
	}
	plain, err := json.Marshal(e)
	if err != nil {
		return err
	}
	blob, err := s.Seal(plain)
	if err != nil {
		return err
	}
	// The KEY is right here — e.Key() names the chain, contract and channel — and
	// it goes to the backend, never to the collector. Only the size crosses.
	if err := s.Backend.Put(ctx, e.Key(), blob); err != nil {
		if s.Metrics != nil {
			s.Metrics.EvidenceFailure()
		}
		return err
	}
	if s.Metrics != nil {
		s.Metrics.EvidenceWrite(len(blob))
	}
	return nil
}

// Get fetches a record and RE-VERIFIES it before returning.
//
// Storage is custody, not authority — the same rule the vault follows. A record
// that does not re-verify is an error, never a value, however it came to be in
// the store.
func (s *EvidenceStore) Get(ctx context.Context, key string) (Evidence, error) {
	blob, err := s.Backend.Get(ctx, key)
	if err != nil {
		if s.Metrics != nil {
			s.Metrics.EvidenceFailure()
		}
		return Evidence{}, err
	}
	// `key` is a parameter of this function and is not forwarded: the collector
	// learns that a read happened and how big it was.
	if s.Metrics != nil {
		s.Metrics.EvidenceRead(len(blob))
	}
	plain, err := s.Open(blob)
	if err != nil {
		return Evidence{}, fmt.Errorf("%w: %v", ErrEvidenceMalformed, err)
	}
	var e Evidence
	if err := json.Unmarshal(plain, &e); err != nil {
		return Evidence{}, fmt.Errorf("%w: %v", ErrEvidenceMalformed, err)
	}
	// The key must name the record inside it. A record moved to another key is
	// not evidence about that key.
	if key != e.Key() {
		return Evidence{}, fmt.Errorf("%w: record is filed under %q but names %q",
			ErrEvidenceMalformed, key, e.Key())
	}
	return e.Verify()
}

// Latest returns the highest-block verified evidence for a channel.
//
// Skips records that fail to verify rather than failing the call: one corrupt
// object must not hide the twenty good ones behind it. Returns false when
// nothing usable is held, which is a real answer and not an error.
func (s *EvidenceStore) Latest(ctx context.Context, chainID uint64, contract, channelID string) (Evidence, bool, error) {
	keys, err := s.Backend.List(ctx, ChannelPrefix(chainID, contract, channelID))
	if err != nil {
		return Evidence{}, false, err
	}
	if len(keys) == 0 {
		return Evidence{}, false, nil
	}
	// Zero-padded block numbers make lexical order numeric order.
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, key := range keys {
		e, err := s.Get(ctx, key)
		if err != nil {
			continue
		}
		return e, true, nil
	}
	return Evidence{}, false, nil
}
