package channel

// The durable home for money-bearing channel state.
//
// ONE INTERPRETATION OF STATE, NOT TWO
// ------------------------------------
// This package contains an older local ledger — native.go's channelState, signed
// with the node's own key over proofDigest, in int64 Amounts. That is NOT this.
// It is a domain-separated digest of its own invention, it has no relationship
// to anything the chain will accept, and int64 cannot even hold one gold award
// in wei.
//
// Everything here goes through Channel.Accept, which digests exactly what
// ChannelManagerV2.stateDigest digests. If a state is good enough to store, it
// is good enough to settle, and there is no second opinion about what a channel
// currently holds.
//
// WHAT PERSISTENCE HAS TO BE SUFFICIENT FOR
// -----------------------------------------
// Not "the balances". The complete signed state, including every pending lock.
// Consider what a lossy record does:
//
//	on chain, in the state both parties signed:   100 ANON locked
//	this node, after a restart:                   100 ANON unlocked
//
// The node now believes it can spend value that is committed to somebody else's
// preimage, will happily sign a state doing so, and the counterparty holds the
// signature proving it. That is not a display bug, it is money.
//
// So the check at load is deliberately harsh: every stored state has its digest
// RECOMPUTED and both signatures RE-RECOVERED. The digest covers the lock root,
// so if persistence dropped a lock, changed an amount, lost an expiry or muddled
// which party is the payer, the signatures stop verifying and the node refuses
// to start. A record that cannot reproduce the signed digest is not a record of
// that state.
//
// WHY AMOUNTS ARE STORED AS STRINGS
// ---------------------------------
// encoding/json renders *big.Int as a bare JSON number. Go reads that back
// exactly; JavaScript does not — 100 ANON is 1e20, well past
// Number.MAX_SAFE_INTEGER, and this file is the same state the payment node's
// HTTP surface will eventually hand a browser. A balance that silently rounds
// on its way through a JSON parser is the same class of bug as computing wei in
// floating point, which the site already avoids elsewhere.
//
// WHY A FAILED WRITE IS A FAILED PAYMENT
// --------------------------------------
// Accept advances in-memory state only after the write is on disk and fsynced.
// The reverse order works perfectly until the machine loses power between the
// write and the flush, which is exactly the moment it matters: the counterparty
// holds a signed state this node cannot prove, and there is no recovery from
// that except their goodwill.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

var (
	ErrNoSuchChannel   = errors.New("channel: no such channel in the store")
	ErrChannelExists   = errors.New("channel: already in the store")
	ErrStateUnreadable = errors.New("channel: stored state does not reproduce its signatures")
)

// Store holds V2 channel state durably.
type Store struct {
	dir      string
	mu       sync.Mutex
	channels map[[32]byte]*Channel
	// unreconciled holds channels loaded from a RESTORED backup. They may be
	// stale in a way nothing local can detect, so they are unsignable until
	// reconciled against an outside source — see reconcile.go.
	unreconciled map[[32]byte]struct{}
}

// OpenStore loads every channel under dir, or creates it.
//
// An unreadable or unverifiable channel file STOPS the node. It is tempting to
// skip the bad file and carry on — that is right for a cache and wrong for
// money, because carrying on means operating with a balance that is missing or
// stale, and the first thing the node does with it is sign something.
func OpenStore(dir string) (*Store, error) {
	s := &Store{
		dir: dir, channels: map[[32]byte]*Channel{},
		unreconciled: map[[32]byte]struct{}{},
	}
	// A restore rolls back every local signal, including any this store might
	// have written to detect one. The marker is left by whoever performed the
	// restore, because they are the only party who knows.
	restored := wasRestored(dir)
	if err := os.MkdirAll(filepath.Join(dir, "channels"), 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(dir, "channels"))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, "channels", e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("channel: %s unreadable, refusing to start: %w", path, err)
		}
		ch, err := decodeChannel(raw)
		if err != nil {
			return nil, fmt.Errorf("channel: %s malformed, refusing to start: %w", path, err)
		}
		if err := verifyLoaded(ch); err != nil {
			return nil, fmt.Errorf("channel: %s: %w", path, err)
		}
		s.channels[ch.ID] = ch
		if restored {
			s.unreconciled[ch.ID] = struct{}{}
		}
	}
	if restored && len(s.unreconciled) == 0 {
		// Restored with nothing in it. Nothing can be stale, so the marker has
		// no work to do and leaving it would quarantine channels opened later.
		_ = os.Remove(filepath.Join(dir, RestoreMarker))
	}
	return s, nil
}

// verifyLoaded re-derives the digest of the stored state and recovers both
// signatures from it.
//
// This is the whole persistence guarantee in one function. Anything the digest
// covers — nonce, both balances, and through the root every lock's id, hash,
// amount, expiry and payer — must have survived the round trip exactly, or the
// recovered addresses will not be the channel's parties.
func verifyLoaded(ch *Channel) error {
	if !ch.Latest.Complete() {
		// A channel opened but never used has no state to check. Its deposits
		// come from the chain, not from here.
		return nil
	}
	raw := ch.Latest.State.Digest(ch.ChainID, ch.Contract)
	a, err := RecoverSigner(raw, ch.Latest.SigA)
	if err != nil {
		return fmt.Errorf("%w: sigA: %v", ErrStateUnreadable, err)
	}
	b, err := RecoverSigner(raw, ch.Latest.SigB)
	if err != nil {
		return fmt.Errorf("%w: sigB: %v", ErrStateUnreadable, err)
	}
	if a != ch.PartyA || b != ch.PartyB {
		return fmt.Errorf("%w: recovered %s/%s, parties are %s/%s",
			ErrStateUnreadable, a.Hex(), b.Hex(), ch.PartyA.Hex(), ch.PartyB.Hex())
	}
	return nil
}

// TrackFromChain registers a channel using facts the blockchain established.
//
// The ONLY way to create a channel record. Invariant P5-1: a peer may name a
// channel, it may not declare its own collateral — so the deposits here arrive
// in an OnChainChannel, which nothing outside this package can forge, rather
// than as two *big.Ints a caller pulled from a message.
//
// It does not open anything. No transaction is sent from here; this records
// what a chain read found.
func (s *Store) TrackFromChain(chainID *big.Int, contract Address, occ OnChainChannel) error {
	if !occ.fromChain {
		return ErrNotFromChain
	}
	if occ.Status != StatusOpen {
		return fmt.Errorf("channel: on-chain status is %d, not open", occ.Status)
	}
	// Belt and braces: the id must derive from the parties the chain reported.
	if DeriveChannelID(occ.PartyA, occ.PartyB) != occ.ID {
		return errors.New("channel: on-chain parties do not derive the channel id")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.channels[occ.ID]; exists {
		return ErrChannelExists
	}

	ch := &Channel{
		ID: occ.ID, PartyA: occ.PartyA, PartyB: occ.PartyB,
		DepositA: new(big.Int).Set(orZero(occ.DepositA)),
		DepositB: new(big.Int).Set(orZero(occ.DepositB)),
		Status:   StatusOpen,
		ChainID:  new(big.Int).Set(orZero(chainID)),
		Contract: contract,
	}
	if err := s.persist(ch); err != nil {
		return err
	}
	s.channels[occ.ID] = ch
	return nil
}

// RefreshFromChain updates a tracked channel's collateral and status from a
// chain read.
//
// NEEDED BECAUSE OF CHECKPOINTS. A checkpoint takes value out and reduces the
// deposits on chain while the channel stays open. A node that did not notice
// would keep checking conservation against the OLD collateral, and every state
// after the checkpoint would look unconserved — the payments would be correct
// and the node would refuse them all.
//
// Only the deposits and the status move. The signed state is not touched: the
// chain knows what collateral exists and what has settled, and this node knows
// what the parties have signed. Those stay separate sources for separate facts
// — letting a chain read overwrite `Latest` would put the last SETTLED state in
// the place the newest SIGNED one belongs.
func (s *Store) RefreshFromChain(occ OnChainChannel) error {
	if !occ.fromChain {
		return ErrNotFromChain
	}
	return s.Update(occ.ID, func(c *Channel) error {
		if occ.PartyA != c.PartyA || occ.PartyB != c.PartyB {
			return errors.New("channel: on-chain parties do not match the stored record")
		}
		c.DepositA = new(big.Int).Set(orZero(occ.DepositA))
		c.DepositB = new(big.Int).Set(orZero(occ.DepositB))
		c.Status = occ.Status
		return nil
	})
}

// Get returns a COPY of a channel's record.
//
// A copy because a caller holding a pointer into the store could mutate a
// balance without going through Accept, which is the one door every state is
// supposed to come through.
func (s *Store) Get(id [32]byte) (*Channel, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.channels[id]
	if !ok {
		return nil, false
	}
	out := ch.Clone()
	// Stamped on every snapshot rather than stored on the record, so there is
	// no way to read a channel without also learning whether it may be stale.
	_, out.NeedsReconcile = s.unreconciled[id]
	return out, true
}

// IDs lists tracked channels, in a stable order.
func (s *Store) IDs() [][32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][32]byte, 0, len(s.channels))
	for id := range s.channels {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		return hex.EncodeToString(out[i][:]) < hex.EncodeToString(out[j][:])
	})
	return out
}

// Accept validates a state and, if it is good, makes it this channel's latest —
// on disk first, then in memory.
//
// The validation is Channel.Accept's, unchanged and unduplicated: right channel,
// strictly increasing nonce, no negatives, well-formed locks, conservation, and
// both signatures over the V2 digest. Because that digest covers the lock root,
// a state cannot be accepted with somebody else's locks attached to it, nor with
// its own removed.
//
// The nonce rule is what makes stored state monotonic across restarts as well as
// within a run: the stored nonce is loaded back, and 99 or 100 against a stored
// 100 are both refused. Only 101 is even considered, and only then is the
// expensive signature work done.
func (s *Store) Accept(id [32]byte, candidate SignedState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.channels[id]
	if !ok {
		return ErrNoSuchChannel
	}

	// Applied to a copy: Channel.Accept mutates on success, and a state that
	// validates but cannot be written must leave nothing behind.
	// A deep copy, not a shallow one: Accept prunes the signed-nonce ledger on
	// success, and a shallow copy shares that map — so a state that validated
	// but failed to persist would still have mutated the live record.
	trial := ch.Clone()
	if err := trial.Accept(candidate); err != nil {
		return err
	}
	if err := s.persist(trial); err != nil {
		// NOT advanced. Reporting success for a payment that is not on disk is
		// the bug the whole write ordering exists to prevent.
		return err
	}
	*ch = *trial
	return nil
}

// Update applies a change to a channel's record atomically: on a deep copy, then
// to disk, then in memory.
//
// Protocol bookkeeping — the signed-nonce ledger, applied intents, a pending
// proposal, a conflict — is money-adjacent and gets the same discipline as the
// state itself. A signature recorded in memory but not on disk is exactly the
// crash that invariant I4 exists to survive.
//
// The mutation runs against a copy, so a function that fails halfway leaves the
// live record untouched.
func (s *Store) Update(id [32]byte, mutate func(*Channel) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.channels[id]
	if !ok {
		return ErrNoSuchChannel
	}
	trial := ch.Clone()
	if err := mutate(trial); err != nil {
		return err
	}
	if err := s.persist(trial); err != nil {
		return err
	}
	*ch = *trial
	return nil
}

// persist writes one channel durably.
//
// Temp file, fsync, rename, then fsync the DIRECTORY. The last step is the one
// usually omitted: without it the rename itself can be lost and the file
// reappears with its old contents after a crash — an older state, which is
// precisely what everything else here works to prevent.
func (s *Store) persist(ch *Channel) error {
	raw, err := encodeChannel(ch)
	if err != nil {
		return err
	}
	dir := filepath.Join(s.dir, "channels")
	name := hex.EncodeToString(ch.ID[:])
	tmp := filepath.Join(dir, "."+name+".tmp")
	final := filepath.Join(dir, name+".json")

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func cloneSigned(ss SignedState) SignedState {
	out := ss
	out.SigA = append([]byte(nil), ss.SigA...)
	out.SigB = append([]byte(nil), ss.SigB...)
	out.State.Pending = append([]HTLC(nil), ss.State.Pending...)
	return out
}

// ---- the on-disk form ------------------------------------------------------

// Amounts are decimal strings. See the file header: a JSON number cannot carry
// 1e20 through every parser that will read this.

type storedHTLC struct {
	ID       string `json:"id"`
	Hash     string `json:"hash"`
	Amount   string `json:"amount"`
	Expiry   int64  `json:"expiry"`
	PayerIsA bool   `json:"payer_is_a"`
}

type storedState struct {
	Channel  string       `json:"channel"`
	Nonce    uint64       `json:"nonce"`
	BalanceA string       `json:"balance_a"`
	BalanceB string       `json:"balance_b"`
	Pending  []storedHTLC `json:"pending,omitempty"`
	// Withdrawals are part of the signed digest. They live here rather than
	// only on State because this type is what both the disk and the wire carry,
	// and a state whose withdrawals did not survive that trip would verify
	// against nothing.
	WithdrawA string `json:"withdraw_a,omitempty"`
	WithdrawB string `json:"withdraw_b,omitempty"`
	// Op is the operation domain, and it is the first word of the digest — so
	// like the withdrawals it must survive the disk and the wire, or a state
	// verifies against nothing. Omitted when it is the ordinary OpState, which
	// keeps records written before domains existed encoding byte for byte.
	Op uint8 `json:"op,omitempty"`
}

type storedPending struct {
	Intent     string         `json:"intent"`
	Transition wireTransition `json:"transition"`
	State      storedState    `json:"state"`
	Sig        string         `json:"sig"`
}

type storedConflict struct {
	Nonce   uint64      `json:"nonce"`
	Mine    storedState `json:"mine"`
	MineA   string      `json:"mine_sig_a,omitempty"`
	MineB   string      `json:"mine_sig_b,omitempty"`
	Theirs  storedState `json:"theirs"`
	TheirsA string      `json:"theirs_sig_a,omitempty"`
	TheirsB string      `json:"theirs_sig_b,omitempty"`
}

// storedPayment is one history entry on disk. Same encoding rules as
// everything else here: amounts are decimal strings, 32-byte values are hex.
type storedPayment struct {
	Intent     string `json:"intent"`
	Kind       string `json:"kind,omitempty"`
	Route      string `json:"route,omitempty"`
	Incoming   bool   `json:"incoming,omitempty"`
	Amount     string `json:"amount,omitempty"`
	Status     string `json:"status"`
	LockID     string `json:"lock_id,omitempty"`
	Nonce      uint64 `json:"nonce,omitempty"`
	CreatedAt  int64  `json:"created_at,omitempty"`
	ResolvedAt int64  `json:"resolved_at,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type storedChannel struct {
	Version  int         `json:"version"`
	ID       string      `json:"id"`
	PartyA   string      `json:"party_a"`
	PartyB   string      `json:"party_b"`
	DepositA string      `json:"deposit_a"`
	DepositB string      `json:"deposit_b"`
	Status   uint8       `json:"status"`
	ChainID  string      `json:"chain_id"`
	Contract string      `json:"contract"`
	State    storedState `json:"state"`
	SigA     string      `json:"sig_a,omitempty"`
	SigB     string      `json:"sig_b,omitempty"`

	// SCPP/1 protocol state, in the same record so it lands in the same write.
	Signed   map[string]string `json:"signed,omitempty"`
	Applied  map[string]uint64 `json:"applied,omitempty"`
	Pending  *storedPending    `json:"pending,omitempty"`
	Conflict *storedConflict   `json:"conflict,omitempty"`
	History  []storedPayment   `json:"history,omitempty"`
}

func decString(n *big.Int) string {
	if n == nil {
		return "0"
	}
	return n.String()
}

func parseDec(s string) (*big.Int, error) {
	if s == "" {
		return new(big.Int), nil
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("channel: %q is not a decimal amount", s)
	}
	return n, nil
}

// parseUnsignedDec is parseDec for a field the contract stores as uint256.
func parseUnsignedDec(s, field string) (*big.Int, error) {
	n, err := parseDec(s)
	if err != nil {
		return nil, err
	}
	if n.Sign() < 0 {
		return nil, fmt.Errorf("channel: %s may not be negative", field)
	}
	return n, nil
}

func parseBytes32(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return out, fmt.Errorf("channel: %q is not 32 hex bytes", s)
	}
	copy(out[:], raw)
	return out, nil
}

func encodeChannel(ch *Channel) ([]byte, error) {
	rec := storedChannel{
		Version:  2,
		ID:       hex.EncodeToString(ch.ID[:]),
		PartyA:   ch.PartyA.Hex(),
		PartyB:   ch.PartyB.Hex(),
		DepositA: decString(ch.DepositA),
		DepositB: decString(ch.DepositB),
		Status:   uint8(ch.Status),
		ChainID:  decString(ch.ChainID),
		Contract: ch.Contract.Hex(),
		SigA:     hex.EncodeToString(ch.Latest.SigA),
		SigB:     hex.EncodeToString(ch.Latest.SigB),
		State:    encodeStateWire(ch.Latest.State),
	}

	for nonce, digest := range ch.Signed {
		if rec.Signed == nil {
			rec.Signed = map[string]string{}
		}
		rec.Signed[fmt.Sprintf("%d", nonce)] = hex.EncodeToString(digest[:])
	}
	for intent, nonce := range ch.Applied {
		if rec.Applied == nil {
			rec.Applied = map[string]uint64{}
		}
		rec.Applied[hex.EncodeToString(intent[:])] = nonce
	}
	if p := ch.Pending; p != nil {
		rec.Pending = &storedPending{
			Intent:     hex.EncodeToString(p.Intent[:]),
			Transition: encodeTransitionWire(p.Transition),
			State:      encodeStateWire(p.State),
			Sig:        hex.EncodeToString(p.Sig),
		}
	}
	for _, h := range ch.History {
		rec.History = append(rec.History, storedPayment{
			Intent: hex.EncodeToString(h.Intent[:]),
			Kind:   string(h.Kind), Route: string(h.Route),
			Incoming: h.Incoming, Amount: h.Amount, Status: string(h.Status),
			LockID: hex.EncodeToString(h.LockID[:]),
			Nonce:  h.Nonce, CreatedAt: h.CreatedAt,
			ResolvedAt: h.ResolvedAt, Detail: h.Detail,
		})
	}
	if c := ch.Conflict; c != nil {
		rec.Conflict = &storedConflict{
			Nonce:   c.Nonce,
			Mine:    encodeStateWire(c.Mine.State),
			MineA:   hex.EncodeToString(c.Mine.SigA),
			MineB:   hex.EncodeToString(c.Mine.SigB),
			Theirs:  encodeStateWire(c.Theirs.State),
			TheirsA: hex.EncodeToString(c.Theirs.SigA),
			TheirsB: hex.EncodeToString(c.Theirs.SigB),
		}
	}
	return json.MarshalIndent(rec, "", "  ")
}

func decodeChannel(raw []byte) (*Channel, error) {
	var rec storedChannel
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	if rec.Version != 2 {
		return nil, fmt.Errorf("channel: unknown record version %d", rec.Version)
	}
	id, err := parseBytes32(rec.ID)
	if err != nil {
		return nil, err
	}
	partyA, err := ParseAddress(rec.PartyA)
	if err != nil {
		return nil, err
	}
	partyB, err := ParseAddress(rec.PartyB)
	if err != nil {
		return nil, err
	}
	contract, err := ParseAddress(rec.Contract)
	if err != nil {
		return nil, err
	}
	depositA, err := parseDec(rec.DepositA)
	if err != nil {
		return nil, err
	}
	depositB, err := parseDec(rec.DepositB)
	if err != nil {
		return nil, err
	}
	chainID, err := parseDec(rec.ChainID)
	if err != nil {
		return nil, err
	}
	sigA, err := hex.DecodeString(rec.SigA)
	if err != nil {
		return nil, err
	}
	sigB, err := hex.DecodeString(rec.SigB)
	if err != nil {
		return nil, err
	}

	ch := &Channel{
		ID: id, PartyA: partyA, PartyB: partyB,
		DepositA: depositA, DepositB: depositB,
		Status: Status(rec.Status), ChainID: chainID, Contract: contract,
		Latest: SignedState{SigA: sigA, SigB: sigB},
	}
	// decodeStateWire, not a second loop: the lock-order check lives there, and
	// a record whose locks are out of order would hash to a root the signatures
	// were never made over.
	latest, err := decodeStateWire(rec.State)
	if err != nil {
		return nil, err
	}
	ch.Latest.State = latest

	for k, v := range rec.Signed {
		var nonce uint64
		if _, err := fmt.Sscanf(k, "%d", &nonce); err != nil {
			return nil, fmt.Errorf("channel: bad signed-nonce key %q", k)
		}
		digest, err := parseBytes32(v)
		if err != nil {
			return nil, err
		}
		if ch.Signed == nil {
			ch.Signed = map[uint64][32]byte{}
		}
		ch.Signed[nonce] = digest
	}
	for k, v := range rec.Applied {
		intent, err := parseBytes32(k)
		if err != nil {
			return nil, err
		}
		if ch.Applied == nil {
			ch.Applied = map[[32]byte]uint64{}
		}
		ch.Applied[intent] = v
	}
	if p := rec.Pending; p != nil {
		intent, err := parseBytes32(p.Intent)
		if err != nil {
			return nil, err
		}
		tr, err := decodeTransitionWire(p.Transition)
		if err != nil {
			return nil, err
		}
		state, err := decodeStateWire(p.State)
		if err != nil {
			return nil, err
		}
		sig, err := hex.DecodeString(p.Sig)
		if err != nil {
			return nil, err
		}
		ch.Pending = &PendingProposal{Intent: intent, Transition: tr, State: state, Sig: sig}
	}
	for _, h := range rec.History {
		intent, err := parseBytes32(h.Intent)
		if err != nil {
			return nil, err
		}
		lockID, err := parseBytes32(h.LockID)
		if err != nil {
			return nil, err
		}
		ch.History = append(ch.History, PaymentRecord{
			Intent: intent, Kind: TransitionKind(h.Kind), Route: PayRoute(h.Route),
			Incoming: h.Incoming, Amount: h.Amount, Status: PayStatus(h.Status),
			LockID: lockID, Nonce: h.Nonce, CreatedAt: h.CreatedAt,
			ResolvedAt: h.ResolvedAt, Detail: h.Detail,
		})
	}
	if c := rec.Conflict; c != nil {
		mine, err := decodeSignedWire(c.Mine, c.MineA, c.MineB)
		if err != nil {
			return nil, err
		}
		theirs, err := decodeSignedWire(c.Theirs, c.TheirsA, c.TheirsB)
		if err != nil {
			return nil, err
		}
		ch.Conflict = &ConflictRecord{Nonce: c.Nonce, Mine: mine, Theirs: theirs}
	}
	return ch, nil
}

func decodeSignedWire(w storedState, sigA, sigB string) (SignedState, error) {
	state, err := decodeStateWire(w)
	if err != nil {
		return SignedState{}, err
	}
	a, err := hex.DecodeString(sigA)
	if err != nil {
		return SignedState{}, err
	}
	b, err := hex.DecodeString(sigB)
	if err != nil {
		return SignedState{}, err
	}
	return SignedState{State: state, SigA: a, SigB: b}, nil
}
