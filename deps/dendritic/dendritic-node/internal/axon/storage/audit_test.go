// Package storage carries P11's audits: properties of the storage path that are
// about what the code MAY do, which no runtime test of the store itself can
// establish.
//
// It is a test-only package on purpose. The storage layer is already written,
// tested and transport-agnostic (§1.4: 0 of 210 test files import internal/i2p),
// so P11's work is not new storage code — it is proving the transport swap did
// not leave the old assumptions behind in comments, constants and prose.
package storage

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoFile reads a file relative to the module root.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// TestE113NoStoragePathTimeoutReferencesI2P is E11.3.
//
// The failure this guards against is a timeout that was sized for an I2P dial
// surviving the transport swap: it would be too long, so nothing would break,
// and a latency regression could hide underneath it indefinitely.
func TestE113NoStoragePathTimeoutReferencesI2P(t *testing.T) {
	// A timeout constant plus the comment block immediately above it.
	decl := regexp.MustCompile(`(?s)((?://[^\n]*\n)*)\s*const (\w*[Tt]imeout\w*)\s*=`)
	for _, rel := range []string{
		"internal/store/store.go",
		"internal/p2p/objmanifest.go",
	} {
		src := repoFile(t, rel)
		for _, m := range decl.FindAllStringSubmatch(src, -1) {
			comment, name := m[1], m[2]
			if strings.Contains(strings.ToLower(comment), "i2p") &&
				!strings.Contains(comment, "no longer") &&
				!strings.Contains(comment, "RE-DERIVED") {
				t.Errorf("E11.3 violated: %s in %s is still justified by I2P:\n%s",
					name, rel, comment)
			}
		}
	}
}

// TestT112TimeoutsAreDerivedNotRelaxed is T11.2.
//
// It checks the DERIVATION is present and that the figure did not simply grow.
// §P11's failure mode is "timeouts relaxed rather than re-derived, hiding a
// latency regression", and a test that only checked for the absence of the word
// "I2P" would pass a comment that deleted the reasoning along with the reference.
func TestT112TimeoutsAreDerivedNotRelaxed(t *testing.T) {
	src := repoFile(t, "internal/store/store.go")

	i := strings.Index(src, "const shardFetchTimeout")
	if i < 0 {
		t.Fatal("shardFetchTimeout is gone")
	}
	head := src[max0(i-2000):i]
	for _, want := range []string{"RE-DERIVED", "§8.4", "worst-case 3-hop build"} {
		if !strings.Contains(head, want) {
			t.Errorf("the derivation is missing %q — a timeout without a derivation "+
				"is a number somebody will relax", want)
		}
	}
	// It must have SHRUNK. The I2P figure was 3 minutes; an AXON build is
	// specified at 35 s worst case, so a value at or above the old one means the
	// budget was inherited rather than re-derived.
	if strings.Contains(src[i:i+120], "3 * time.Minute") {
		t.Error("T11.2 violated: the I2P-era 3-minute budget survived")
	}

	// And the honesty requirement: this is derived from SPECIFIED budgets, not
	// measured, and the source has to say so.
	if !strings.Contains(head, "NOT A MEASUREMENT") {
		t.Error("the derivation does not admit that it is not a measurement")
	}
}

// TestT115WhoHoldsPlaintextIsUnambiguous is T11.5.
//
// §1 flagged a direct contradiction: SECURITY.md said the local gateway was
// "trusted with plaintext because it is the encryption origin", while
// internal/store/types.go said "the node no longer encrypts objects". Both
// cannot be true, and a reader had no way to tell which was current.
func TestT115WhoHoldsPlaintextIsUnambiguous(t *testing.T) {
	sec := repoFile(t, "SECURITY.md")
	types := repoFile(t, "internal/store/types.go")

	// The stale claim must be gone.
	if strings.Contains(sec, "trusted with plaintext because it is the encryption") {
		t.Error("T11.5 violated: SECURITY.md still calls the gateway the encryption origin")
	}
	// And the resolution must be stated, not merely implied by deletion.
	if !strings.Contains(sec, "COORDINATOR holds plaintext") {
		t.Error("T11.5 violated: SECURITY.md does not say who holds plaintext")
	}
	// The two documents must now agree.
	if !strings.Contains(types, "node no longer encrypts objects") {
		t.Fatal("types.go's statement changed; re-check that SECURITY.md still agrees")
	}
	if !strings.Contains(sec, "cannot decrypt what it") {
		t.Error("SECURITY.md does not state that the node cannot decrypt what it stores")
	}
}

// TestT116NodeHoldsNoObjectKey is T11.6 and E11.4, established structurally.
//
// A holder cannot read a shard it holds without the CID and key — and the reason
// is not that decryption is refused, it is that THE KEY IS NOT THERE. That is a
// property of what the storage package contains, so it is checked by looking.
func TestT116NodeHoldsNoObjectKey(t *testing.T) {
	types := repoFile(t, "internal/store/types.go")

	// The manifest must carry no per-object key.
	for _, bad := range []string{"ObjectKey", "WrappedKey", "KeyWrap", "MasterKey", "Nonce "} {
		if strings.Contains(types, bad) {
			t.Errorf("E11.4 at risk: the manifest carries %q; a holder with the "+
				"manifest would hold key material", bad)
		}
	}
	if !strings.Contains(types, "no per-object key here to wrap") {
		t.Error("types.go no longer states that there is no key in the manifest")
	}
	// PlainSHA256 is a digest of CIPHERTEXT despite its name, and that trap is
	// worth keeping documented: a reader who assumes otherwise concludes the
	// node can verify plaintext, which would mean it had plaintext.
	if !strings.Contains(types, "digest of the STORED (ciphertext) bytes") {
		t.Error("the PlainSHA256 naming trap is no longer documented")
	}
}

func max0(i int) int {
	if i < 0 {
		return 0
	}
	return i
}
