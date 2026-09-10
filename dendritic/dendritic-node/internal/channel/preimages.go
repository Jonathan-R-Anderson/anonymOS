package channel

// The preimage vault — roadmap P7-b.
//
// THE FAILURE THIS EXISTS TO PREVENT
// ----------------------------------
// A hub forwards a payment: it owes B downstream, and A owes it upstream, both
// locked on the same hash. B settles by revealing the preimage. The hub is now
// out of pocket downstream and its ONLY route to being made whole is to present
// that same preimage upstream.
//
//	learn the preimage → CRASH → restart → the secret is gone
//	                                     → paid downstream
//	                                     → cannot claim upstream
//	                                     → the lock expires against it
//
// Nothing else in the system can recover from that. The upstream lock refunds to
// A on expiry, the downstream payment stands, and the hub has simply lost the
// money. It is not a state that can be repaired by asking a peer, because the
// secret was never theirs to give back — B has no reason to reveal it twice and
// may be gone.
//
// WHY PREIMAGE-FIRST RATHER THAN ATOMIC
// -------------------------------------
// The vault is written BEFORE the settlement that revealed the secret is
// accepted. That ordering does not need the two writes to be atomic, and is
// stronger than making them so:
//
//	preimage stored, settle not accepted  →  a secret for a lock still live.
//	                                         Harmless: knowing it early costs
//	                                         nothing and the settle retries.
//	settle accepted, preimage lost        →  the catastrophe above.
//
// One of those is a shrug and the other is unrecoverable, so the order is fixed.
//
// WHY IT IS KEYED BY HASH AND NOT BY CHANNEL
// ------------------------------------------
// The secret is learned on the DOWNSTREAM channel and needed on the UPSTREAM
// one. Storing it against the channel it arrived on would put it in the wrong
// record; the hash is what the two locks share, and it is what a hub looks up.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

var ErrPreimageUnknown = errors.New("channel: no preimage known for that hash")

// PreimageVault durably remembers secrets this node has learned.
type PreimageVault struct {
	path string
	mu   sync.Mutex
	// known maps H(preimage) to the preimage.
	known map[[32]byte][32]byte
}

// OpenPreimageVault loads the vault under dir, or creates it.
//
// An unreadable vault STOPS the node, like an unreadable channel record. Coming
// up with an empty one would silently discard every claim this node is holding
// upstream — the money would look fine right until something needed claiming.
func OpenPreimageVault(dir string) (*PreimageVault, error) {
	v := &PreimageVault{
		path:  filepath.Join(dir, "preimages.json"),
		known: map[[32]byte][32]byte{},
	}
	raw, err := os.ReadFile(v.path)
	if err != nil {
		if os.IsNotExist(err) {
			return v, nil
		}
		return nil, err
	}
	var stored map[string]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, err
	}
	for hashHex, preimageHex := range stored {
		hash, err := parseBytes32(hashHex)
		if err != nil {
			return nil, err
		}
		preimage, err := parseBytes32(preimageHex)
		if err != nil {
			return nil, err
		}
		// Verified on the way in. A vault entry that does not hash to its own
		// key is a corrupted record, and using it would produce a claim the
		// contract rejects at the worst possible moment.
		if !(HTLC{Hash: hash}).Matches(preimage) {
			return nil, errors.New("channel: preimage vault entry does not match its hash")
		}
		v.known[hash] = preimage
	}
	return v, nil
}

// Learn records a preimage durably, and returns only once it is on disk.
//
// Call this BEFORE accepting the state that revealed it. Idempotent: learning a
// secret twice is ordinary, because a retried settlement carries it again.
func (v *PreimageVault) Learn(preimage [32]byte) error {
	var hash [32]byte
	copy(hash[:], keccak(preimage[:]))

	v.mu.Lock()
	defer v.mu.Unlock()
	if existing, ok := v.known[hash]; ok && existing == preimage {
		return nil
	}
	next := make(map[[32]byte][32]byte, len(v.known)+1)
	for k, val := range v.known {
		next[k] = val
	}
	next[hash] = preimage

	if err := v.persist(next); err != nil {
		return err
	}
	v.known = next
	return nil
}

// Lookup returns the preimage for a hash, if this node knows one.
func (v *PreimageVault) Lookup(hash [32]byte) ([32]byte, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	p, ok := v.known[hash]
	return p, ok
}

// All returns every known secret, keyed by hash. For the settlement worker,
// which resolves locks it can open.
func (v *PreimageVault) All() map[[32]byte][32]byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make(map[[32]byte][32]byte, len(v.known))
	for k, val := range v.known {
		out[k] = val
	}
	return out
}

// persist writes the vault with the same discipline as a channel record: temp
// file, fsync, rename, fsync the directory.
func (v *PreimageVault) persist(known map[[32]byte][32]byte) error {
	stored := make(map[string]string, len(known))
	for hash, preimage := range known {
		stored[hex.EncodeToString(hash[:])] = hex.EncodeToString(preimage[:])
	}
	raw, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(v.path)
	tmp := v.path + ".tmp"
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
	if err := os.Rename(tmp, v.path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
