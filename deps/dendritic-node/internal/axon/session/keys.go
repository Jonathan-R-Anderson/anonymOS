package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Key schedule (§9.5 "SESSION KEYS", §9.8).
//
//	session_root      = HKDF-SHA256(0, KEY_SEED, "axon:sess:root:v1" ‖ session_id, 32)
//	K_f ‖ K_b ‖ resume_secret
//	                  = HKDF-SHA256(0, session_root, "axon:sess:keys:v1", 96)
//	rp_resume_id      = HKDF-SHA256(0, session_root, "axon:sess:rpid:v1", 32)
//	rekey (epoch e)   K ← HKDF-SHA256(0, K, "axon:sess:rekey:v1" ‖ LE32(e), 32)
//	ratchet (case B)  session_root ← HKDF-SHA256(session_root, KEY_SEED',
//	                                             "axon:sess:ratchet:v1", 32)
//
// §9.8 writes rp_resume_id as "HKDF(session_root, label, 32)" without saying
// which argument is the salt. It is read here as the IKM with a zero salt, the
// same shape as every other derivation in the schedule; the alternative (root
// as salt, empty IKM) is an HKDF misuse, so the reading is not a coin toss.
//
// K_f protects client → service, K_b service → client. A session's two
// directions never share a key, so a reflected packet fails authentication
// rather than being read as the peer's.

const (
	labelRoot     = "axon:sess:root:v1"
	labelKeys     = "axon:sess:keys:v1"
	labelRPID     = "axon:sess:rpid:v1"
	labelRekey    = "axon:sess:rekey:v1"
	labelRatchet  = "axon:sess:ratchet:v1"
	labelResumeSv = "axon:sess:resume-svc:v1"
	labelRPResume = "axon:rp:resume:v1"
)

// ID is a session identifier: 16 bytes, chosen by the client, never reused.
type ID [16]byte

// keyState is everything derived from one session_root.
type keyState struct {
	root   [32]byte
	kf, kb [32]byte // epoch-0 keys; the live per-epoch keys live in dirKeys
	resume [32]byte // resume_secret: keys the case-B proof
	rpid   [32]byte // rp_resume_id: the case-A preimage
}

var errShortRead = errors.New("axon/session: key derivation ran short")

func hkdf32(salt, ikm []byte, info ...[]byte) (out [32]byte) {
	var in []byte
	for _, p := range info {
		in = append(in, p...)
	}
	r := hkdf.New(sha256.New, ikm, salt, in)
	if _, err := io.ReadFull(r, out[:]); err != nil {
		panic(errShortRead) // HKDF-SHA256 yields up to 8160 bytes; 32 cannot fail
	}
	return out
}

// deriveKeys expands a session_root into the keys §9.5 names.
func deriveKeys(root [32]byte) keyState {
	ks := keyState{root: root}
	var buf [96]byte
	r := hkdf.New(sha256.New, root[:], nil, []byte(labelKeys))
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		panic(errShortRead)
	}
	copy(ks.kf[:], buf[0:32])
	copy(ks.kb[:], buf[32:64])
	copy(ks.resume[:], buf[64:96])
	ks.rpid = hkdf32(nil, root[:], []byte(labelRPID))
	wipe(buf[:])
	return ks
}

// rootFromSeed derives session_root from the rendezvous KEY_SEED.
func rootFromSeed(keySeed [32]byte, id ID) [32]byte {
	return hkdf32(nil, keySeed[:], []byte(labelRoot), id[:])
}

// ratchetRoot mixes a fresh KEY_SEED into an existing root (case B).
//
// This is the ONLY post-compromise security the session has: an adversary who
// held the old keys does not hold the new root without the new DH. Case A
// contributes no DH and therefore no ratchet, and §9.8 insists that be said
// rather than implied away.
func ratchetRoot(root, newSeed [32]byte) [32]byte {
	return hkdf32(root[:], newSeed[:], []byte(labelRatchet))
}

// rekey derives the key for the next epoch of one direction.
func rekey(k [32]byte, epoch uint16) [32]byte {
	var e [4]byte
	binary.LittleEndian.PutUint32(e[:], uint32(epoch))
	return hkdf32(nil, k[:], []byte(labelRekey), e[:])
}

// ResumeCommit is the commitment a client registers with its rendezvous point
// for case-A resumption: SHA256("axon:rp:resume:v1" ‖ rp_resume_id ‖ LE32(n)).
//
// The RP stores only this and the counter. It learns rp_resume_id when the
// client reveals it to resume, by which time the commitment is burned.
func ResumeCommit(preimage [32]byte, counter uint32) [32]byte {
	h := sha256.New()
	h.Write([]byte(labelRPResume))
	h.Write(preimage[:])
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], counter)
	h.Write(c[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// resumeProof is the case-B proof carried inside INTRODUCE1:
//
//	HMAC-SHA256(resume_secret, "axon:sess:resume-svc:v1" ‖ session_id
//	            ‖ LE32(counter) ‖ new_rend_cookie ‖ rp_routing_id)
//
// The new cookie and the RP's identity are inside the MAC, so a replayed
// introduction names an RP the replayer does not control.
func resumeProof(secret [32]byte, id ID, counter uint32, cookie [20]byte, rpRoutingID [32]byte) [32]byte {
	m := hmac.New(sha256.New, secret[:])
	m.Write([]byte(labelResumeSv))
	m.Write(id[:])
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], counter)
	m.Write(c[:])
	m.Write(cookie[:])
	m.Write(rpRoutingID[:])
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (ks *keyState) wipe() {
	wipe(ks.root[:])
	wipe(ks.kf[:])
	wipe(ks.kb[:])
	wipe(ks.resume[:])
	wipe(ks.rpid[:])
}
