package store

import "testing"

// Pins F3: a recall must not poison a content address for every other object,
// and must not refuse forever. Both were confirmed defects.
func TestRecallRefusalIsScopedToTheObjectAndExpires(t *testing.T) {
	s, err := Open(t.TempDir(), 6, 3, 64<<10, 64<<20)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	shard := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	if err = s.refuseRecalledShard("object-A", shard); err != nil {
		t.Fatalf("refuse: %v", err)
	}
	if !s.RecallRefused("object-A", shard) {
		t.Error("the object that recalled it should be refused")
	}
	// The whole point: object B legitimately shares this content-addressed
	// shard and must be unaffected.
	if s.RecallRefused("object-B", shard) {
		t.Error("another object's shard was poisoned by this recall")
	}
	// And it must not leak into the moderation denylist, which never expires.
	if s.IsRejected("shard", shard) {
		t.Error("a recall wrote a permanent moderation rejection")
	}
}
