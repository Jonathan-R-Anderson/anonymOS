package store

import "testing"

// Pins the fix for the confirmed arbitrary-file-unlink: a 64-character path
// traversal passed the old length-only check and reached os.Remove.
func TestContentIDRejectsTraversalAndNonHex(t *testing.T) {
	traversal := ".././././././././././././././././././././././././././././p2p.key"
	if len(traversal) != 64 {
		t.Fatalf("fixture must be 64 chars to prove length alone is insufficient, got %d", len(traversal))
	}
	for _, bad := range []string{
		traversal,
		"../../../../../../../../../../../../../../../../../../../etc/pass",
		"ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"[:64], // uppercase
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
	} {
		if IsContentID(bad) {
			t.Errorf("accepted a non-content id: %q", bad)
		}
	}
	good := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if !IsContentID(good) {
		t.Error("rejected a legitimate content address")
	}
}
