package channel

// A native channel backend: the first thing in this package that actually
// holds state, signs it, and can lose money if it is wrong.
//
// WHY fsync BEFORE ACKNOWLEDGING
// ------------------------------
// A balance proof is the only evidence a node has that value moved. If the
// counterparty holds a signed state this node did not persist, the money is
// theirs and there is no recovery except their goodwill. So the ordering is:
//
//	1. write the new state to disk
//	2. fsync
//	3. ONLY THEN report the payment as successful
//
// Reversing steps 2 and 3 is the single highest-consequence bug available here,
// and it is invisible in testing: everything works until the machine loses power
// between the write and the flush, which is exactly when it matters.
//
// WHY THE NULLIFIER SET IS ON DISK TOO
// ------------------------------------
// Double-spend prevention that lives in memory forgets everything on restart,
// and a note spent before a crash becomes spendable again after it. The set is
// append-only and fsynced for the same reason as the proofs: it is a claim
// about money that must survive the process.
//
// WHAT THIS IS NOT
// ----------------
// Not a settlement layer. It maintains and signs channel state locally; it does
// not open channels on-chain, does not talk to a peer, and does not verify a ZK
// proof. Those are the rest of Phase 1 and they need a contract and a circuit
// respectively. What this does is make the state machine real, durable and
// testable — so the parts that follow have something correct to build on.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	ErrChannelUnknown = errors.New("channel: no such channel")
	ErrInsufficient   = errors.New("channel: insufficient outbound balance")
	ErrNonceRegressed = errors.New("channel: nonce did not increase")
	ErrDoubleSpend    = errors.New("channel: nullifier already spent")
	ErrChannelClosed  = errors.New("channel: channel is closed")
)

// channelState is what is persisted per channel.
type channelState struct {
	ID       ChannelID `json:"id"`
	Peer     NodeID    `json:"peer"`
	Deposit  Amount    `json:"deposit"`
	Outbound Amount    `json:"outbound"`
	Inbound  Amount    `json:"inbound"`
	Locked   Amount    `json:"locked"`
	Nonce    uint64    `json:"nonce"`
	Closed   bool      `json:"closed"`
	// LatestProof is the counter-signed state. Persisted WITH the balances it
	// covers, because a proof without them cannot be verified later — see
	// VerifyBalance on why the balances are supplied rather than carried.
	LatestProof []byte `json:"latest_proof,omitempty"`
}

// Native is a local channel backend.
type Native struct {
	dir    string
	key    *Key
	mu     sync.Mutex
	states map[ChannelID]*channelState
	spent  map[Nullifier]bool
}

// OpenNative loads or creates a backend rooted at dir.
func OpenNative(dir string, key *Key) (*Native, error) {
	if key == nil {
		return nil, ErrNoKey
	}
	if err := os.MkdirAll(filepath.Join(dir, "channels"), 0o700); err != nil {
		return nil, err
	}
	n := &Native{dir: dir, key: key,
		states: map[ChannelID]*channelState{}, spent: map[Nullifier]bool{}}
	if err := n.load(); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *Native) load() error {
	entries, err := os.ReadDir(filepath.Join(n.dir, "channels"))
	if err != nil {
		return nil // nothing yet
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(n.dir, "channels", e.Name()))
		if err != nil {
			continue
		}
		var st channelState
		if json.Unmarshal(raw, &st) == nil && st.ID != "" {
			n.states[st.ID] = &st
		}
	}
	// The nullifier set. A read failure here is NOT ignored the way a missing
	// channel file is: forgetting spent notes silently re-enables double
	// spending, so an unreadable set must stop the node rather than start it
	// with an empty one.
	raw, err := os.ReadFile(filepath.Join(n.dir, "nullifiers"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("channel: nullifier set unreadable, refusing to start: %w", err)
	}
	for i := 0; i+32 <= len(raw); i += 32 {
		var nf Nullifier
		copy(nf[:], raw[i:i+32])
		n.spent[nf] = true
	}
	return nil
}

// persist writes one channel's state durably.
//
// Write to a temp file, fsync it, rename, then fsync the DIRECTORY. The last
// step is the one people omit: without it the rename itself can be lost, and
// the file reappears at its old contents after a crash.
func (n *Native) persist(st *channelState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	dir := filepath.Join(n.dir, "channels")
	tmp := filepath.Join(dir, "."+string(st.ID)+".tmp")
	final := filepath.Join(dir, string(st.ID)+".json")

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

// Spend records a nullifier, refusing a repeat.
//
// Persisted BEFORE returning success, for the same reason as a balance proof:
// a note reported spent but not durably recorded is one that can be spent again
// after a restart.
func (n *Native) Spend(nf Nullifier) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.spent[nf] {
		return ErrDoubleSpend
	}
	f, err := os.OpenFile(filepath.Join(n.dir, "nullifiers"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(nf[:]); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	n.spent[nf] = true
	return nil
}

// Spent reports whether a nullifier has been used.
func (n *Native) Spent(nf Nullifier) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.spent[nf]
}

// Open creates a channel locally.
//
// NOT an on-chain open: no transaction is sent. Named to match the interface,
// and the gap is why Capabilities reports no chain.
func (n *Native) Open(_ contextLike, peer NodeID, deposit Amount) (ChannelID, error) {
	if deposit <= 0 {
		return "", ErrInsufficient
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	id := ChannelID(fmt.Sprintf("ch-%s-%d", peer, len(n.states)+1))
	st := &channelState{ID: id, Peer: peer, Deposit: deposit, Outbound: deposit}
	n.states[id] = st
	if err := n.persist(st); err != nil {
		delete(n.states, id)
		return "", err
	}
	return id, nil
}

// Pay moves value and returns a signed proof.
//
// The proof is persisted BEFORE this returns. A caller that receives a proof
// this node has not durably recorded would treat a payment as complete that
// cannot be proven after a crash.
func (n *Native) Pay(_ contextLike, ch ChannelID, amount Amount, ref string) (BalanceProof, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	st, ok := n.states[ch]
	if !ok {
		return BalanceProof{}, ErrChannelUnknown
	}
	if st.Closed {
		return BalanceProof{}, ErrChannelClosed
	}
	if amount <= 0 {
		return BalanceProof{}, ErrInsufficient
	}
	// Locked value is already excluded from Outbound, so this is the whole
	// check — subtracting Locked again here would under-spend by exactly the
	// amount in flight.
	if amount > st.Outbound {
		return BalanceProof{}, ErrInsufficient
	}

	next := *st
	next.Outbound -= amount
	next.Inbound += amount
	next.Nonce++

	proof, err := n.key.SignBalance(ch, next.Nonce, next.Outbound, next.Inbound)
	if err != nil {
		return BalanceProof{}, err
	}
	next.LatestProof = proof.Signature

	if err := n.persist(&next); err != nil {
		// State is NOT advanced on a persistence failure. Reporting success
		// here would be the exact bug this ordering exists to prevent.
		return BalanceProof{}, err
	}
	*st = next
	return proof, nil
}

func (n *Native) Balance(ch ChannelID) (Balance, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	st, ok := n.states[ch]
	if !ok {
		return Balance{}, ErrChannelUnknown
	}
	return Balance{Outbound: st.Outbound, Inbound: st.Inbound,
		Locked: st.Locked, Nonce: st.Nonce}, nil
}

func (n *Native) Close(_ contextLike, ch ChannelID, _ bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	st, ok := n.states[ch]
	if !ok {
		return ErrChannelUnknown
	}
	st.Closed = true
	return n.persist(st)
}

// Capabilities reports what this backend can honestly do.
//
// Almost nothing, and that is the point: no HTLCs, no adaptor signatures, no
// chain. The capability checks then refuse every privacy claim automatically,
// so a UI built on this cannot say "private" until a backend arrives that
// earns it.
func (n *Native) Capabilities() Capabilities {
	return Capabilities{
		MediatedTransfers: false,
		HTLC:              false,
		AdaptorSignatures: false,
		Watchtower:        false,
		Chain:             0,
	}
}

// contextLike keeps this file free of a context import while matching the
// Adapter shape; the real backend takes a context.Context.
type contextLike = interface{}
