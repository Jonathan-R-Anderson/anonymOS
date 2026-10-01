package dcs

import (
	"encoding/base64"
	"time"
)

func mustB64(b []byte) []byte {
	out := make([]byte, base64.RawStdEncoding.EncodedLen(len(b)))
	base64.RawStdEncoding.Encode(out, b)
	return out
}

// newMemReplay returns a replay guard pinned to the tests' fixed clock, so its
// pruning matches the fixed `now` the envelopes are signed at.
func newMemReplay() *MemReplayGuard {
	g := NewMemReplayGuard()
	g.SetClock(func() time.Time { return time.Unix(1700000000, 0) })
	return g
}
